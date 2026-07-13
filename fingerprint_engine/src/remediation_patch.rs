//! Autonomous patch regeneration for the self-repair loop.
//!
//! When a candidate fix fails sandbox verification (the exploit still succeeds, the app broke,
//! or the diff didn't apply), the healer feeds the failure back to the LLM and asks for a
//! corrected unified diff, then re-verifies. This mirrors the proven self-correction shape of
//! `exploit_synthesis_engine::synthesize_safe_poc_with_self_correction_async` (temperature bump
//! per attempt + previous failed output carried into context), but is driven by `HealVerdict`.

use serde::Deserialize;
use weissman_engines::deserialize_llm_json;
use weissman_engines::openai_chat::{self, LlmError};

use crate::council::CouncilConfig;

const SYS_REPAIR: &str = "You are a principal application-security engineer fixing a vulnerability by \
editing source code. A previous patch FAILED verification. Output ONE minified JSON object ONLY, no prose \
outside JSON, of the exact form {\"remediation_patch\":string,\"rationale\":string}. `remediation_patch` MUST be \
a valid unified diff (git/`patch -p1` compatible, with `--- a/path` / `+++ b/path` and `@@` hunks) that \
actually fixes the vulnerability while keeping the application fully functional. Do NOT disable, delete, or \
crash the endpoint to make the exploit stop — that is a failure, not a fix. Address the specific failure \
reason given. Keep the change minimal and targeted. No exploit payloads in the output.";

#[derive(Debug, Deserialize, Default)]
struct PatchOut {
    #[serde(default)]
    remediation_patch: String,
    #[serde(default)]
    #[allow(dead_code)]
    rationale: String,
}

/// Temperature schedule: start low, climb with each failed attempt to escape a stuck local fix.
fn attempt_temperature(attempt: u32) -> f64 {
    (0.25 + attempt as f64 * 0.15).min(0.85)
}

/// Ask the LLM for a corrected unified diff given the failure of the previous attempt.
/// Returns the new diff text (already length/basic-sanity checked by the caller via
/// `security_hardening::validate_remediation_patch`).
#[allow(clippy::too_many_arguments)]
pub async fn regenerate_patch(
    cfg: &CouncilConfig,
    tenant_id: i64,
    attempt: u32,
    title: &str,
    description: &str,
    severity: &str,
    poc_curl: &str,
    previous_patch: &str,
    failure_reason: &str,
    changed_paths: &[String],
) -> Result<String, String> {
    let client = cfg.http_client();
    let files_touched = if changed_paths.is_empty() {
        "(the previous patch changed no files — it likely did not apply)".to_string()
    } else {
        changed_paths.join(", ")
    };
    let user = format!(
        "Vulnerability: {title}\nSeverity: {severity}\n\nDescription:\n{desc}\n\n\
         Reproduction (PoC):\n{poc}\n\n\
         The PREVIOUS patch FAILED. Failure reason:\n{reason}\n\n\
         Files the previous patch touched: {files}\n\n\
         Previous patch (that failed):\n{prev}\n\n\
         Produce a corrected unified diff that fixes the vulnerability AND keeps the app healthy.",
        title = title.chars().take(600).collect::<String>(),
        severity = severity,
        desc = description.chars().take(3500).collect::<String>(),
        poc = poc_curl.chars().take(2000).collect::<String>(),
        reason = failure_reason.chars().take(1500).collect::<String>(),
        files = files_touched.chars().take(1000).collect::<String>(),
        prev = previous_patch.chars().take(6000).collect::<String>(),
    );

    // sanitize_user_input=true: title/description/PoC/previous-patch are attacker-influenced.
    let raw = openai_chat::chat_completion_text_json_object(
        &client,
        cfg.base_url.as_str(),
        cfg.model_synthesizer.as_str(),
        Some(SYS_REPAIR),
        &user,
        attempt_temperature(attempt),
        2200,
        Some(tenant_id),
        "heal_self_repair",
        true,
    )
    .await
    .map_err(|e: LlmError| format!("self-repair LLM error: {e}"))?;

    let out: PatchOut =
        deserialize_llm_json(&raw).map_err(|e| format!("self-repair parse error: {e}"))?;
    let patch = out.remediation_patch.trim().to_string();
    if patch.is_empty() {
        return Err("self-repair produced an empty patch".into());
    }
    Ok(patch)
}

/// Distinct fix strategies used to generate a diverse candidate field for the tournament — each
/// asks the model to approach the same vulnerability from a different angle.
pub const CANDIDATE_STRATEGIES: &[&str] = &[
    "Apply the MINIMAL, most surgical code change that closes the vulnerability.",
    "Fix the ROOT CAUSE with strict input validation / allow-listing at the entry point.",
    "Fix by switching to a SAFE API for this vulnerability class (parameterized query, safe \
     deserializer, proper output encoding, path canonicalization, etc.).",
    "Apply DEFENSE-IN-DEPTH: fix the vulnerable sink AND harden the surrounding code path.",
    "Fix at the FRAMEWORK/config layer (middleware, security headers, framework guard) without \
     changing business logic.",
];

const SYS_CANDIDATE: &str = "You are a principal application-security engineer. Produce a code fix for \
the given vulnerability, following the requested strategy. Output ONE minified JSON object ONLY, of the \
form {\"remediation_patch\":string,\"rationale\":string}. `remediation_patch` MUST be a valid unified diff \
(git/`patch -p1` compatible, `--- a/path` / `+++ b/path` / `@@` hunks) that closes the vulnerability while \
keeping the application fully functional. Never disable, delete, or crash the endpoint to make the exploit \
stop. Keep the change minimal and targeted. No exploit payloads in the output.";

/// Generate one tournament candidate for a given strategy. Temperature varies with the strategy
/// index to widen the search.
#[allow(clippy::too_many_arguments)]
pub async fn generate_candidate(
    cfg: &CouncilConfig,
    tenant_id: i64,
    strategy_index: u32,
    strategy: &str,
    title: &str,
    description: &str,
    severity: &str,
    poc_curl: &str,
) -> Result<String, String> {
    let client = cfg.http_client();
    let user = format!(
        "Vulnerability: {title}\nSeverity: {severity}\n\nDescription:\n{desc}\n\n\
         Reproduction (PoC):\n{poc}\n\n\
         REQUIRED FIX STRATEGY: {strategy}\n\n\
         Produce a unified diff implementing this strategy.",
        title = title.chars().take(600).collect::<String>(),
        severity = severity,
        desc = description.chars().take(3500).collect::<String>(),
        poc = poc_curl.chars().take(2000).collect::<String>(),
        strategy = strategy,
    );
    let raw = openai_chat::chat_completion_text_json_object(
        &client,
        cfg.base_url.as_str(),
        cfg.model_synthesizer.as_str(),
        Some(SYS_CANDIDATE),
        &user,
        attempt_temperature(strategy_index),
        2200,
        Some(tenant_id),
        "heal_tournament_candidate",
        true,
    )
    .await
    .map_err(|e: LlmError| format!("candidate LLM error: {e}"))?;
    let out: PatchOut =
        deserialize_llm_json(&raw).map_err(|e| format!("candidate parse error: {e}"))?;
    let patch = out.remediation_patch.trim().to_string();
    if patch.is_empty() {
        return Err("candidate produced an empty patch".into());
    }
    Ok(patch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategies_are_distinct_and_nonempty() {
        assert!(CANDIDATE_STRATEGIES.len() >= 4);
        for s in CANDIDATE_STRATEGIES {
            assert!(!s.trim().is_empty());
        }
    }

    #[test]
    fn temperature_climbs_and_caps() {
        assert!(attempt_temperature(0) < attempt_temperature(1));
        assert!(attempt_temperature(1) < attempt_temperature(2));
        assert!(attempt_temperature(50) <= 0.85);
    }

    #[test]
    fn parses_patch_out() {
        let raw = r#"{"remediation_patch":"--- a/x\n+++ b/x\n@@ -1 +1 @@\n-bad\n+good\n","rationale":"use param query"}"#;
        let out: PatchOut = deserialize_llm_json(raw).expect("parse");
        assert!(out.remediation_patch.contains("@@"));
        assert_eq!(out.rationale, "use param query");
    }
}
