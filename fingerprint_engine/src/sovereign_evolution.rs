//! **Sovereign Evolution Mode** — learning buffer (recursive Critic→Hacker feedback), shadow pre-flight
//! simulation (Tokio-parallel “strategic thinking”), and hooks for cognitive/OSINT-weighted fuzzing.
//!
//! Hardware: use [`strategic_thinking_concurrency`] (default **32**) with `buffer_unordered` over LLM calls
//! (Ryzen-class parallelism). Ray is Python-only; this crate uses **Tokio** + **futures**.

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::info;
use weissman_engines::openai_chat::{self, LlmError};

/// Bounded concurrent vLLM “thought” tasks (shadow sims, batch what-if). Default 32 for Ryzen 9-class hosts.
#[must_use]
pub fn strategic_thinking_concurrency() -> usize {
    std::env::var("WEISSMAN_STRATEGIC_THINKING_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32)
        .clamp(1, 128)
}

#[must_use]
pub fn sovereign_evolution_enabled() -> bool {
    matches!(
        std::env::var("WEISSMAN_SOVEREIGN_EVOLUTION").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

#[must_use]
pub fn evolution_target_fingerprint(seed: &str) -> String {
    let norm = seed.trim().to_lowercase();
    let hash = Sha256::digest(norm.as_bytes());
    hex::encode(hash)
}

fn extract_json_object(text: &str) -> Option<&str> {
    let t = text.trim();
    let start = t.find('{')?;
    let end = t.rfind('}')?;
    (end >= start).then_some(&t[start..=end])
}

// --- Recursive learning (Mistral critic → DeepSeek hacker) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriticWafAnalysis {
    pub filtering_logic_summary: String,
    pub signature_markers: Vec<String>,
    pub normalization_assumptions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HackerPolymorphicSynthesis {
    pub polymorphic_payload_hex: String,
    pub transform_rationale: String,
    pub bypass_claims: Vec<String>,
}

const SYS_RECURSIVE_CRITIC: &str = "You are Mistral-class defensive analyst. A probe FAILED (WAF/block). Output ONE minified JSON object ONLY with keys: filtering_logic_summary, signature_markers (array of strings), normalization_assumptions. Infer rules from status + response. No prose outside JSON.";

const SYS_RECURSIVE_HACKER: &str = "You are DeepSeek-class offensive engineer. Given the defender's inferred WAF logic, output ONE minified JSON object ONLY: polymorphic_payload_hex (hex-encoded safe test bytes or empty), transform_rationale, bypass_claims (array). Design encoding/transform chain to evade stated filters. Authorized testing only. No prose outside JSON.";

/// Generic critic used when the LLM is unreachable — keeps the loop moving so a payload is
/// still synthesized (via [`grammar_mutate`]) instead of the whole flow erroring out.
fn default_critic() -> CriticWafAnalysis {
    CriticWafAnalysis {
        filtering_logic_summary:
            "LLM unavailable — assuming a generic signature/keyword WAF with input normalization."
                .to_string(),
        signature_markers: vec![
            "sql keywords".to_string(),
            "angle brackets".to_string(),
            "encoded payloads".to_string(),
        ],
        normalization_assumptions:
            "URL-decoding + case-folding + whitespace collapse before matching.".to_string(),
    }
}

fn toggle_ascii_case(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Deterministic, LLM-free polymorphic mutation. Used as a graceful fallback when the vLLM
/// backend is unreachable (or Sovereign Evolution is gated off) so "surprise generation"
/// degrades to a real, if simpler, transform chain instead of producing nothing. The chain
/// is chosen from a stable hash of `seed`, so it is deterministic per target and always
/// differs from the input.
pub fn grammar_mutate(seed: &str) -> HackerPolymorphicSynthesis {
    // Base probe: reuse the seed if it already looks like a payload, else a canonical,
    // authorized-test injection string.
    let base = if seed.contains(|c| matches!(c, '\'' | '<' | '=' | ' ' | '(')) {
        seed.to_string()
    } else {
        "1' OR '1'='1' -- ".to_string()
    };
    let selector = Sha256::digest(seed.as_bytes())[0];
    let mut out = base.clone();
    let mut claims: Vec<String> = Vec::new();

    if selector & 0b0001 != 0 {
        out = toggle_ascii_case(&out);
        claims.push("case-toggling to evade case-sensitive signatures".to_string());
    }
    if selector & 0b0010 != 0 {
        out = out.replace("OR", "O/**/R").replace("or", "o/**/r");
        claims.push("inline /**/ comment insertion to break keyword matching".to_string());
    }
    if selector & 0b0100 != 0 {
        out = out.replace(' ', "/**/");
        claims.push("whitespace -> /**/ substitution".to_string());
    }
    if selector & 0b1000 != 0 {
        out = percent_encode(&out);
        claims.push("percent-encoding to bypass literal-string filters".to_string());
    }
    // Guarantee the output is distinct from the input and always carries a rationale.
    if claims.is_empty() || out == base {
        out = percent_encode(&toggle_ascii_case(&base));
        claims.push("case-toggle + percent-encoding (guaranteed-distinct chain)".to_string());
    }

    HackerPolymorphicSynthesis {
        polymorphic_payload_hex: hex::encode(out.as_bytes()),
        transform_rationale: format!(
            "Deterministic grammar fallback (no LLM): {} transform(s) seeded by target fingerprint.",
            claims.len()
        ),
        bypass_claims: claims,
    }
}

async fn llm_json_for_evolution(
    client: &reqwest::Client,
    cfg: &crate::council::CouncilConfig,
    model: &str,
    system: &str,
    user: &str,
    temp: f64,
    max_tokens: u32,
    tenant_id: i64,
    op: &'static str,
) -> Result<String, LlmError> {
    openai_chat::chat_completion_text_json_object(
        client,
        cfg.base_url.as_str(),
        model,
        Some(system),
        user,
        temp,
        max_tokens,
        Some(tenant_id),
        op,
        false,
    )
    .await
}

/// Insert pending row, run Critic → Hacker, persist structured JSON. Used after a **failed** attack / block.
pub async fn run_recursive_waf_feedback(
    pool: &PgPool,
    tenant_id: i64,
    cfg: &crate::council::CouncilConfig,
    target_seed: &str,
    failure_context: &Value,
) -> Result<(i64, CriticWafAnalysis, HackerPolymorphicSynthesis), LlmError> {
    let fp = evolution_target_fingerprint(target_seed);
    let client = cfg.http_client();
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| LlmError::Decode(format!("learning tx: {e}")))?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO sovereign_learning_buffer (tenant_id, target_fingerprint, failure_context, status)
           VALUES ($1, $2, $3, 'pending') RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&fp)
    .bind(failure_context)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| LlmError::Decode(format!("learning insert: {e}")))?;
    let _ = tx
        .commit()
        .await
        .map_err(|e| LlmError::Decode(e.to_string()))?;

    let critic_user = format!(
        "FAILURE_CONTEXT:\n{}\n\nEmit CriticWafAnalysis JSON only.",
        serde_json::to_string(failure_context)
            .unwrap_or_default()
            .chars()
            .take(12_000)
            .collect::<String>()
    );
    // Critic (WAF analysis): try the LLM; fall back to a generic default when it is down so
    // the loop still completes and yields a payload rather than erroring out.
    let critic: CriticWafAnalysis = match llm_json_for_evolution(
        &client,
        cfg,
        cfg.model_generalist.as_str(),
        SYS_RECURSIVE_CRITIC,
        &critic_user,
        cfg.temperature_beta,
        cfg.max_tokens_beta,
        tenant_id,
        "sovereign_learning_critic",
    )
    .await
    .ok()
    .and_then(|raw_c| extract_json_object(&raw_c).map(str::to_string))
    .and_then(|slice| serde_json::from_str::<CriticWafAnalysis>(&slice).ok())
    {
        Some(c) => c,
        None => default_critic(),
    };
    let critic_v = serde_json::to_value(&critic).map_err(|e| LlmError::Decode(e.to_string()))?;

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| LlmError::Decode(e.to_string()))?;
    sqlx::query(
        r#"UPDATE sovereign_learning_buffer SET critic_waf_analysis = $1, updated_at = now() WHERE id = $2 AND tenant_id = $3"#,
    )
    .bind(&critic_v)
    .bind(id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| LlmError::Decode(format!("learning critic update: {e}")))?;
    let _ = tx
        .commit()
        .await
        .map_err(|e| LlmError::Decode(e.to_string()))?;

    let hacker_user = format!(
        "CRITIC_WAF_ANALYSIS:\n{}\n\nORIGINAL_FAILURE:\n{}\n\nEmit HackerPolymorphicSynthesis JSON only.",
        serde_json::to_string(&critic).unwrap_or_default(),
        serde_json::to_string(failure_context).unwrap_or_default().chars().take(8000).collect::<String>()
    );
    // Hacker synthesis: try the LLM; on any failure (vLLM down, non-JSON, parse error) fall
    // back to a deterministic grammar so surprise-generation degrades gracefully instead of
    // producing nothing.
    let hacker: HackerPolymorphicSynthesis = match llm_json_for_evolution(
        &client,
        cfg,
        cfg.model_coder.as_str(),
        SYS_RECURSIVE_HACKER,
        &hacker_user,
        cfg.temperature_alpha,
        cfg.max_tokens_alpha,
        tenant_id,
        "sovereign_learning_hacker",
    )
    .await
    .ok()
    .and_then(|raw_h| extract_json_object(&raw_h).map(str::to_string))
    .and_then(|slice_h| serde_json::from_str::<HackerPolymorphicSynthesis>(&slice_h).ok())
    {
        Some(h) => h,
        None => {
            tracing::info!(
                target: "sovereign_evolution",
                "hacker LLM unavailable/unparseable — using deterministic grammar fallback"
            );
            grammar_mutate(target_seed)
        }
    };
    let hacker_v = serde_json::to_value(&hacker).map_err(|e| LlmError::Decode(e.to_string()))?;

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| LlmError::Decode(e.to_string()))?;
    sqlx::query(
        r#"UPDATE sovereign_learning_buffer SET hacker_polymorphic_payload = $1, status = 'synthesized', updated_at = now() WHERE id = $2 AND tenant_id = $3"#,
    )
    .bind(&hacker_v)
    .bind(id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| LlmError::Decode(format!("learning hacker update: {e}")))?;
    let _ = tx
        .commit()
        .await
        .map_err(|e| LlmError::Decode(e.to_string()))?;

    info!(target: "sovereign_evolution", tenant_id, row_id = id, "recursive WAF feedback synthesized");
    Ok((id, critic, hacker))
}

// --- Shadow pre-flight (hallucinated defender response) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowPreflightOutput {
    pub detection_risk_0_100: u32,
    pub predicted_response_class: String,
    pub reroute_recommended: bool,
    pub rationale: String,
}

const SYS_SHADOW: &str = "You simulate the target edge (WAF/app) given tech stack + planned probe. Output ONE minified JSON only: detection_risk_0_100 (0-100), predicted_response_class (short string), reroute_recommended (boolean), rationale (short). No markdown.";

fn parse_shadow_json(text: &str) -> Result<ShadowPreflightOutput, LlmError> {
    let slice =
        extract_json_object(text).ok_or_else(|| LlmError::Decode("shadow: no JSON".into()))?;
    let mut v: ShadowPreflightOutput =
        serde_json::from_str(slice).map_err(|e| LlmError::Decode(format!("shadow: {e}")))?;
    v.detection_risk_0_100 = v.detection_risk_0_100.min(100);
    Ok(v)
}

/// Single shadow simulation (vLLM). Caller may throttle with [`strategic_thinking_concurrency`].
pub async fn shadow_preflight(
    cfg: &crate::council::CouncilConfig,
    tenant_id: i64,
    target_url: &str,
    tech_stack_hint: &str,
    planned_attack_summary: &str,
) -> Result<ShadowPreflightOutput, LlmError> {
    let client = cfg.http_client();
    let user = format!(
        "target_url: {}\ntech_stack: {}\nplanned_attack: {}\nJSON only.",
        target_url.chars().take(2048).collect::<String>(),
        tech_stack_hint.chars().take(4000).collect::<String>(),
        planned_attack_summary
            .chars()
            .take(6000)
            .collect::<String>()
    );
    let raw = llm_json_for_evolution(
        &client,
        cfg,
        cfg.model_synthesizer.as_str(),
        SYS_SHADOW,
        &user,
        (cfg.temperature_gamma * 0.85).clamp(0.0, 1.5),
        cfg.max_tokens_gamma.min(2048),
        tenant_id,
        "sovereign_shadow_preflight",
    )
    .await?;
    parse_shadow_json(&raw)
}

#[derive(Clone, Debug)]
pub struct ShadowBatchItem {
    pub target_url: String,
    pub tech_stack_hint: String,
    pub planned_attack_summary: String,
}

/// Run many shadow sims with **Tokio**-bounded parallelism (default 32).
pub async fn shadow_preflight_batch(
    cfg: Arc<crate::council::CouncilConfig>,
    tenant_id: i64,
    items: Vec<ShadowBatchItem>,
) -> Vec<Result<ShadowPreflightOutput, String>> {
    let n = strategic_thinking_concurrency();
    stream::iter(items)
        .map(|item| {
            let cfg = cfg.clone();
            async move {
                shadow_preflight(
                    cfg.as_ref(),
                    tenant_id,
                    &item.target_url,
                    &item.tech_stack_hint,
                    &item.planned_attack_summary,
                )
                .await
                .map_err(|e| e.to_string())
            }
        })
        .buffer_unordered(n)
        .collect()
        .await
}

// --- Autonomous pivot (low-level credential → credential hunt job) ---

#[must_use]
pub fn payload_suggests_readonly_credential_surface(json: &Value) -> bool {
    let s = json.to_string().to_lowercase();
    (s.contains("api_key") || s.contains("apikey") || s.contains("bearer"))
        && (s.contains("read")
            || s.contains("readonly")
            || s.contains("read-only")
            || s.contains("scope"))
}

/// If findings look like a low-privilege secret, enqueue `command_center_engine` / `leak_hunter` for escalation hunting.
pub async fn maybe_enqueue_credential_hunt(
    pool: &PgPool,
    tenant_id: i64,
    target_url: &str,
    findings_blob: &Value,
) -> Result<Option<uuid::Uuid>, sqlx::Error> {
    if !sovereign_evolution_enabled() {
        return Ok(None);
    }
    if !payload_suggests_readonly_credential_surface(findings_blob) {
        return Ok(None);
    }
    let t = target_url.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let payload = json!({
        "engine": "leak_hunter",
        "target": t,
    });
    let payload = crate::job_envelope::seal_job_payload_sqlx(payload, tenant_id)?;
    let id =
        weissman_db::job_queue::enqueue(pool, tenant_id, "command_center_engine", payload, None)
            .await?;
    info!(target: "sovereign_evolution", tenant_id, %id, "autonomous credential-hunt pivot enqueued");
    Ok(Some(id))
}

/// On engine execution failure, enqueue sovereign learning feedback (closed learning loop).
pub async fn maybe_enqueue_learning_on_failure(
    pool: &PgPool,
    tenant_id: i64,
    target_seed: &str,
    failure_context: &Value,
) -> Result<Option<uuid::Uuid>, sqlx::Error> {
    if !sovereign_evolution_enabled() {
        return Ok(None);
    }
    let seed = target_seed.trim();
    if seed.is_empty() {
        return Ok(None);
    }
    let payload = json!({
        "target_seed": seed,
        "failure_context": failure_context,
    });
    let payload = crate::job_envelope::seal_job_payload_sqlx(payload, tenant_id)?;
    let id = weissman_db::job_queue::enqueue(
        pool,
        tenant_id,
        "sovereign_learning_feedback",
        payload,
        Some("sovereign-learning-loop"),
    )
    .await?;
    info!(
        target: "sovereign_evolution",
        tenant_id,
        %id,
        "sovereign learning feedback enqueued after engine failure"
    );
    Ok(Some(id))
}

#[cfg(test)]
mod grammar_tests {
    use super::grammar_mutate;

    #[test]
    fn grammar_mutate_is_deterministic_distinct_and_nonempty() {
        let a = grammar_mutate("example.com");
        let b = grammar_mutate("example.com");
        // Deterministic for a given seed.
        assert_eq!(a.polymorphic_payload_hex, b.polymorphic_payload_hex);
        assert!(!a.polymorphic_payload_hex.is_empty());
        assert!(!a.bypass_claims.is_empty());
        assert!(!a.transform_rationale.is_empty());
        // Valid hex that decodes to a payload distinct from the untransformed base.
        let decoded = hex::decode(&a.polymorphic_payload_hex).expect("valid hex");
        assert!(!decoded.is_empty());
        assert_ne!(
            decoded.as_slice(),
            b"1' OR '1'='1' -- ",
            "fallback must transform the base payload"
        );
    }

    #[test]
    fn grammar_mutate_varies_by_seed() {
        // Different seeds should generally produce different chains; assert at least one
        // of several distinct seeds differs from the first (guards against a constant output).
        let a = grammar_mutate("alpha-target.example");
        let differs = [
            "beta.example",
            "gamma.example",
            "delta.example",
            "omega.example",
        ]
        .iter()
        .any(|s| grammar_mutate(s).polymorphic_payload_hex != a.polymorphic_payload_hex);
        assert!(differs, "grammar output must vary across seeds");
    }
}
