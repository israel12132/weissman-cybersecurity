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
    let _ = tx.commit().await.map_err(|e| LlmError::Decode(e.to_string()))?;

    let critic_user = format!(
        "FAILURE_CONTEXT:\n{}\n\nEmit CriticWafAnalysis JSON only.",
        serde_json::to_string(failure_context).unwrap_or_default().chars().take(12_000).collect::<String>()
    );
    let raw_c = llm_json_for_evolution(
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
    .await?;
    let slice = extract_json_object(&raw_c).ok_or_else(|| LlmError::Decode("critic: no JSON".into()))?;
    let critic: CriticWafAnalysis = serde_json::from_str(slice)
        .map_err(|e| LlmError::Decode(format!("critic parse: {e}")))?;
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
    let _ = tx.commit().await.map_err(|e| LlmError::Decode(e.to_string()))?;

    let hacker_user = format!(
        "CRITIC_WAF_ANALYSIS:\n{}\n\nORIGINAL_FAILURE:\n{}\n\nEmit HackerPolymorphicSynthesis JSON only.",
        serde_json::to_string(&critic).unwrap_or_default(),
        serde_json::to_string(failure_context).unwrap_or_default().chars().take(8000).collect::<String>()
    );
    let raw_h = llm_json_for_evolution(
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
    .await?;
    let slice_h =
        extract_json_object(&raw_h).ok_or_else(|| LlmError::Decode("hacker: no JSON".into()))?;
    let hacker: HackerPolymorphicSynthesis = serde_json::from_str(slice_h)
        .map_err(|e| LlmError::Decode(format!("hacker parse: {e}")))?;
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
    let _ = tx.commit().await.map_err(|e| LlmError::Decode(e.to_string()))?;

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
    let slice = extract_json_object(text).ok_or_else(|| LlmError::Decode("shadow: no JSON".into()))?;
    let mut v: ShadowPreflightOutput = serde_json::from_str(slice)
        .map_err(|e| LlmError::Decode(format!("shadow: {e}")))?;
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
        planned_attack_summary.chars().take(6000).collect::<String>()
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
        && (s.contains("read") || s.contains("readonly") || s.contains("read-only") || s.contains("scope"))
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
    let id = weissman_db::job_queue::enqueue(pool, tenant_id, "command_center_engine", payload, None).await?;
    info!(target: "sovereign_evolution", tenant_id, %id, "autonomous credential-hunt pivot enqueued");
    Ok(Some(id))
}
