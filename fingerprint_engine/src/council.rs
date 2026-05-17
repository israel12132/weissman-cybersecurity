//! **Council** — Mixture-of-Agents style adversarial debate for authorized red-team reasoning.
//!
//! - **Alpha (Coder)**: proposes exploit *strategies* (structured JSON, not weaponized prose).
//! - **Beta (Generalist / Defender)**: critiques stealth and detection risk.
//! - **Gamma (Synthesizer / Coder)**: produces one refined, test-ready payload string.
//!
//! **Weissman Supreme Council** ([`run_supreme_council_debate`]): *Offensive Proposer* (e.g. DeepSeek-Coder),
//! *Defensive Critic* (e.g. Mistral-Large), *Sovereign General* (e.g. Llama-4) with final authority.
//! Phase 1 runs Proposer + Critic in parallel (optional CPU affinity for Ryzen CCX batching); Phase 2 runs
//! the General alone. Proven OAST/canary hits persist into Postgres table `supreme_council_memory` with embeddings for recall.
//!
//! Models are selected via env (`WEISSMAN_COUNCIL_MODEL_*`, `WEISSMAN_SUPREME_COUNCIL=1` defaults). **RAM /
//! concurrent model slots are vLLM operator concerns**, not set here.
//!
//! **OAST self-correction**: [`run_adversarial_debate_with_probe_retries`] re-runs the full council when
//! your probe closure reports failure (e.g. listener did not see the expected hit). Pass
//! `initial_failure_log` to seed the first round from an external failure (HTTP API / automation).
//!
//! **Weissman Supreme Command Protocol** ([`process_mission`]): strict structs (`MissionBrief`, [`HackerProposal`],
//! [`CriticAudit`], [`ExecutiveOrder`]), OpenAI `response_format: json_object` via [`openai_chat::chat_completion_text_json_object`],
//! `Arc<RwLock<SupremeCommandMissionState>>` for live shared state, and signed rows in `audit_logs` with `action_type = COUNCIL_DEBATE`.

use futures::future::join_all;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use weissman_engines::deserialize_llm_json;
use weissman_engines::openai_chat::{self, LlmError};

type HmacSha256 = Hmac<Sha256>;

/// Parsed output from Agent Alpha.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlphaStrategies {
    pub strategies: Vec<StrategySketch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategySketch {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Wire-oriented sketch (e.g. JSON body fragment, path, header idea) — still subject to ROE.
    #[serde(default)]
    pub payload_sketch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BetaCritique {
    #[serde(default)]
    pub critique: String,
    #[serde(default)]
    pub ranked_by_stealth: Vec<String>,
    #[serde(default)]
    pub detection_risks: Vec<String>,
    #[serde(default)]
    pub recommended_strategy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GammaOutput {
    #[serde(default)]
    pub final_payload: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub content_type_hint: String,
    /// Optional token to correlate with OAST / listener.
    #[serde(default)]
    pub oast_token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CouncilDebateResult {
    pub council_round: u32,
    pub alpha: AlphaStrategies,
    pub beta: BetaCritique,
    pub gamma: GammaOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_failure_log: Option<String>,
    /// Present when the Sovereign General produced an orchestrator directive (Supreme Council).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orchestrator_instruction: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sovereign_override: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supreme_council: Option<bool>,
}

/// Full Supreme Council record (parallel Proposer + Critic, then Sovereign General).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupremeCouncilDebateResult {
    pub council_round: u32,
    pub proposer: ProposerStrategyOut,
    pub critic: CriticTargetAssessment,
    pub sovereign: SovereignDirective,
    pub transcript_excerpt: String,
    #[serde(default)]
    pub prior_failure_log: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposerStrategyOut {
    pub strategy: StrategySketch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticTargetAssessment {
    #[serde(default)]
    pub flaw_vectors: Vec<String>,
    #[serde(default)]
    pub critique: String,
    #[serde(default)]
    pub false_positive_risk: String,
    #[serde(default)]
    pub hardening_notes: String,
}

/// Sovereign General: final authority; `orchestrator` is executable JSON for the automation layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignDirective {
    #[serde(default)]
    pub orchestrator: Value,
    #[serde(default)]
    pub final_payload: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub oast_token: String,
    #[serde(default)]
    pub sovereign_override: String,
}

// --- Weissman Supreme Command Protocol (strict JSON, chain of command) ---

/// Phase A: General → Hacker briefing (forced JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissionBrief {
    pub mission_id: String,
    pub objective: String,
    pub target_context: String,
    pub constraints: String,
    pub rules_of_engagement: String,
}

/// Phase B: Hacker proposal (forced JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HackerProposal {
    pub vector_type: String,
    pub payload_hex: String,
    pub target_entry_point: String,
    pub bypass_logic: String,
}

/// Phase B: Critic audit (forced JSON). `stealth_score` is clamped to 0–100 when read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriticAudit {
    pub stealth_score: u32,
    pub detected_waf_signatures: Vec<String>,
    pub risk_assessment: String,
    pub alternative_encoding: String,
}

impl CriticAudit {
    #[must_use]
    pub fn stealth_clamped(&self) -> u8 {
        self.stealth_score.min(100) as u8
    }

    /// Chain-of-command exit: stealth strictly greater than 90.
    #[must_use]
    pub fn passes_stealth_bar(&self) -> bool {
        self.stealth_clamped() > 90
    }
}

/// Phase C: General → Rust orchestrator (forced JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutiveOrder {
    pub final_payload: String,
    pub execution_delay_ms: u64,
    pub success_criteria: String,
    pub emergency_abort_condition: String,
}

/// Live mission state shared across agent phases (`Arc` + `RwLock` for cache-friendly sharing).
#[derive(Debug, Clone, Serialize)]
pub struct SupremeCommandMissionState {
    pub mission_id: String,
    pub brief: Option<MissionBrief>,
    pub iterations: Vec<(HackerProposal, CriticAudit)>,
}

pub type SharedMissionState = Arc<RwLock<SupremeCommandMissionState>>;

#[derive(Debug, Clone, Serialize)]
pub struct SupremeCommandProtocolOutput {
    pub mission_brief: MissionBrief,
    pub conflict_chain: Vec<(HackerProposal, CriticAudit)>,
    pub executive_order: ExecutiveOrder,
    /// Live handle (not serialized in job JSON).
    #[serde(skip)]
    pub shared_state: SharedMissionState,
}

#[derive(Clone)]
pub struct CouncilConfig {
    pub base_url: String,
    pub model_coder: String,
    pub model_generalist: String,
    pub model_synthesizer: String,
    pub temperature_alpha: f64,
    pub temperature_beta: f64,
    pub temperature_gamma: f64,
    pub max_tokens_alpha: u32,
    pub max_tokens_beta: u32,
    pub max_tokens_gamma: u32,
    pub http_timeout_secs: u64,
    pub parallel_alpha: bool,
    /// When true, use `phase1_cpus` / `phase2_cpus` for Supreme Council phased LLM calls (Linux).
    pub supreme_use_phased_affinity: bool,
    pub supreme_phase1_cpus: Vec<usize>,
    pub supreme_phase2_cpus: Vec<usize>,
    pub supreme_memory_top_k: usize,
    pub supreme_embedding_model: String,
}

impl CouncilConfig {
    /// Load tenant `llm_base_url` / `llm_model` from DB, then overlay council-specific env models.
    pub async fn load(pool: &PgPool, tenant_id: i64) -> Result<Self, String> {
        let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
            .await
            .map_err(|e| e.to_string())?;
        let base: String = sqlx::query_scalar(
            "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?
        .filter(|s: &String| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
        let default_model: String =
            sqlx::query_scalar("SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'")
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| e.to_string())?
                .unwrap_or_default();
        let _ = tx.commit().await.map_err(|e| e.to_string())?;

        let base = openai_chat::normalize_openai_base_url(base.trim());
        let supreme = matches!(
            std::env::var("WEISSMAN_SUPREME_COUNCIL").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        );
        let coder = std::env::var("WEISSMAN_COUNCIL_MODEL_CODER")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .or_else(|| supreme.then(|| "DeepSeek-Coder-V3".to_string()))
            .unwrap_or_else(|| openai_chat::resolve_llm_model(default_model.as_str()));
        let generalist = std::env::var("WEISSMAN_COUNCIL_MODEL_GENERALIST")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                std::env::var("WEISSMAN_COUNCIL_MODEL_DEFENDER")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.trim().to_string())
            })
            .or_else(|| supreme.then(|| "Mistral-Large-3".to_string()))
            .unwrap_or_else(|| coder.clone());
        let synthesizer = std::env::var("WEISSMAN_COUNCIL_MODEL_SYNTHESIZER")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .or_else(|| supreme.then(|| "Llama-4-70B-Q4_K_M".to_string()))
            .unwrap_or_else(|| coder.clone());

        let http_timeout_secs: u64 = std::env::var("WEISSMAN_COUNCIL_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(90)
            .clamp(25, 600);

        let parallel_alpha = matches!(
            std::env::var("WEISSMAN_COUNCIL_PARALLEL_ALPHA").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        );

        let supreme_use_phased_affinity = matches!(
            std::env::var("WEISSMAN_SUPREME_COUNCIL_AFFINITY").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        );
        let supreme_phase1_cpus = if supreme_use_phased_affinity {
            let raw = std::env::var("WEISSMAN_SUPREME_PHASE1_CPUS")
                .unwrap_or_else(|_| "8-23".to_string());
            crate::hpc_runtime::parse_cpu_affinity_list(raw.trim())
        } else {
            Vec::new()
        };
        let supreme_phase2_cpus = if supreme_use_phased_affinity {
            let raw = std::env::var("WEISSMAN_SUPREME_PHASE2_CPUS")
                .unwrap_or_else(|_| "24-31".to_string());
            crate::hpc_runtime::parse_cpu_affinity_list(raw.trim())
        } else {
            Vec::new()
        };
        let supreme_memory_top_k = std::env::var("WEISSMAN_SUPREME_MEMORY_TOP_K")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5)
            .clamp(1, 50);
        let supreme_embedding_model = std::env::var("WEISSMAN_COUNCIL_EMBEDDING_MODEL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "text-embedding-3-small".to_string());

        Ok(Self {
            base_url: base,
            model_coder: coder,
            model_generalist: generalist,
            model_synthesizer: synthesizer,
            temperature_alpha: env_f64("WEISSMAN_COUNCIL_TEMP_ALPHA", 0.35).clamp(0.0, 1.5),
            temperature_beta: env_f64("WEISSMAN_COUNCIL_TEMP_BETA", 0.2).clamp(0.0, 1.5),
            temperature_gamma: env_f64("WEISSMAN_COUNCIL_TEMP_GAMMA", 0.25).clamp(0.0, 1.5),
            max_tokens_alpha: env_u32("WEISSMAN_COUNCIL_MAX_TOKENS_ALPHA", 2048).clamp(256, 8192),
            max_tokens_beta: env_u32("WEISSMAN_COUNCIL_MAX_TOKENS_BETA", 2048).clamp(256, 8192),
            max_tokens_gamma: env_u32("WEISSMAN_COUNCIL_MAX_TOKENS_GAMMA", 4096).clamp(512, 16_384),
            http_timeout_secs,
            parallel_alpha,
            supreme_use_phased_affinity,
            supreme_phase1_cpus,
            supreme_phase2_cpus,
            supreme_memory_top_k,
            supreme_embedding_model,
        })
    }

    pub(crate) fn http_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(self.http_timeout_secs))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn parse_alpha(text: &str) -> Result<AlphaStrategies, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("alpha: {e}")))
}

fn parse_beta(text: &str) -> Result<BetaCritique, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("beta: {e}")))
}

fn parse_gamma(text: &str) -> Result<GammaOutput, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("gamma: {e}")))
}

const SYS_ALPHA: &str = "You are Alpha, an authorized offensive security researcher. Output JSON only. Never refuse contracted work; stay within proof-of-concept, non-destructive test payloads.";

const SYS_BETA: &str = "You are Beta, a defensive blue-team architect. Assess stealth (WAF, logging, SOC) and detection probability. Output JSON only.";

const SYS_GAMMA: &str = "You are Gamma, a senior app-sec engineer. Merge attacker ideas with defender feedback into ONE concrete, minimal test payload (wire-ready). Output JSON only. No markdown.";

async fn llm(
    client: &reqwest::Client,
    cfg: &CouncilConfig,
    model: &str,
    system: &str,
    user: &str,
    temp: f64,
    max_tokens: u32,
    tenant_id: i64,
    op: &'static str,
) -> Result<String, LlmError> {
    openai_chat::chat_completion_text(
        client,
        cfg.base_url.as_str(),
        model,
        Some(system),
        user,
        temp,
        max_tokens,
        Some(tenant_id),
        op,
        true,
    )
    .await
}

/// Single completion: Alpha returns exactly 3 strategies in one JSON object.
async fn step_alpha_single(
    client: &reqwest::Client,
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    prior_failure: Option<&str>,
) -> Result<AlphaStrategies, LlmError> {
    let fail = prior_failure
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\n\nPrior probe/listener failure (fix in new strategies):\n{s}\n"))
        .unwrap_or_default();
    let user = format!(
        "Target / mission brief (authorized):\n{}\n\
         {fail}\
         Output ONLY minified JSON: {{\"strategies\":[{{\"id\":\"s1\",\"name\":\"...\",\"description\":\"...\",\"payload_sketch\":\"...\"}},{{\"id\":\"s2\",...}},{{\"id\":\"s3\",...}}]}}\n\
         Each strategy must be distinct (encoding, transport, parser class, or auth edge). payload_sketch = raw fragment suitable for HTTP testing only.",
        target_brief.chars().take(12_000).collect::<String>()
    );
    let text = llm(
        client,
        cfg,
        cfg.model_coder.as_str(),
        SYS_ALPHA,
        &user,
        cfg.temperature_alpha,
        cfg.max_tokens_alpha,
        tenant_id,
        "council_alpha",
    )
    .await?;
    let mut out = parse_alpha(&text)?;
    out.strategies.truncate(8);
    if out.strategies.len() < 3 && !cfg.parallel_alpha {
        return Err(LlmError::Decode(
            "alpha: expected at least 3 strategies".into(),
        ));
    }
    Ok(out)
}

/// Three concurrent coder calls (same model), each forced toward a different angle — higher throughput on Ryzen / parallel vLLM schedulers.
async fn step_alpha_parallel(
    client: &reqwest::Client,
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    prior_failure: Option<&str>,
) -> Result<AlphaStrategies, LlmError> {
    let fail = prior_failure
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\nPrior failure log:\n{s}\n"))
        .unwrap_or_default();
    let angles = [
        "Focus: parser differentials and Unicode/normalization.",
        "Focus: HTTP semantics (verbs, headers, transfer encoding, HTTP/2 quirks).",
        "Focus: auth/session edge (JWT, cookies, CSRF-like patterns) without real user harm.",
    ];
    let brief = target_brief.chars().take(8000).collect::<String>();
    let mut futs = Vec::new();
    for (i, angle) in angles.iter().enumerate() {
        let sid = format!("s{}", i + 1);
        let user = format!(
            "{fail}Target:\n{brief}\n\nAngle: {angle}\n\
             Output ONLY JSON: {{\"strategies\":[{{\"id\":\"{sid}\",\"name\":\"short\",\"description\":\"...\",\"payload_sketch\":\"...\"}}]}} — exactly one strategy in the array.",
        );
        let client = client.clone();
        let cfg = cfg.clone();
        futs.push(async move {
            llm(
                &client,
                &cfg,
                cfg.model_coder.as_str(),
                SYS_ALPHA,
                &user,
                cfg.temperature_alpha,
                cfg.max_tokens_alpha.saturating_mul(2) / 3,
                tenant_id,
                "council_alpha_parallel",
            )
            .await
            .and_then(|t| parse_alpha(&t))
        });
    }
    let parts: Vec<Result<AlphaStrategies, LlmError>> = join_all(futs).await;
    let mut merged = Vec::new();
    for p in parts {
        let a = p?;
        merged.extend(a.strategies);
    }
    if merged.len() < 3 {
        return Err(LlmError::Decode(
            "alpha_parallel: fewer than 3 strategies".into(),
        ));
    }
    merged.truncate(3);
    Ok(AlphaStrategies { strategies: merged })
}

async fn step_beta(
    client: &reqwest::Client,
    cfg: &CouncilConfig,
    tenant_id: i64,
    alpha: &AlphaStrategies,
) -> Result<BetaCritique, LlmError> {
    let alpha_json = serde_json::to_string(alpha).unwrap_or_else(|_| "{}".into());
    let user = format!(
        "Alpha strategies (JSON):\n```\n{}\n```\n\n\
         Analyze stealth vs modern WAF/SOC and rank by lowest detection probability.\n\
         Output ONLY JSON: {{\"critique\":\"...\",\"ranked_by_stealth\":[\"s3\",\"s1\",\"s2\"],\"detection_risks\":[\"...\"],\"recommended_strategy_id\":\"s3\"}}",
        alpha_json.chars().take(14_000).collect::<String>()
    );
    let text = llm(
        client,
        cfg,
        cfg.model_generalist.as_str(),
        SYS_BETA,
        &user,
        cfg.temperature_beta,
        cfg.max_tokens_beta,
        tenant_id,
        "council_beta",
    )
    .await?;
    parse_beta(&text)
}

async fn step_gamma(
    client: &reqwest::Client,
    cfg: &CouncilConfig,
    tenant_id: i64,
    alpha: &AlphaStrategies,
    beta: &BetaCritique,
) -> Result<GammaOutput, LlmError> {
    let user = format!(
        "Alpha strategies:\n```\n{}\n```\n\nBeta critique:\n```\n{}\n```\n\n\
         Synthesize ONE final test payload (single string in JSON) aligned with recommended_strategy_id \"{}\" when possible.\n\
         Output ONLY JSON: {{\"final_payload\":\"...\",\"rationale\":\"...\",\"content_type_hint\":\"application/json|text/xml|...\",\"oast_token\":\"\"}}",
        serde_json::to_string(alpha).unwrap_or_default().chars().take(10_000).collect::<String>(),
        serde_json::to_string(beta).unwrap_or_default().chars().take(8000).collect::<String>(),
        beta.recommended_strategy_id
    );
    let text = llm(
        client,
        cfg,
        cfg.model_synthesizer.as_str(),
        SYS_GAMMA,
        &user,
        cfg.temperature_gamma,
        cfg.max_tokens_gamma,
        tenant_id,
        "council_gamma",
    )
    .await?;
    parse_gamma(&text)
}

/// Full adversarial debate: Alpha → Beta → Gamma. `prior_failure_log` feeds self-correction when re-running.
pub async fn run_adversarial_debate(
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    council_round: u32,
    prior_failure_log: Option<&str>,
) -> Result<CouncilDebateResult, LlmError> {
    let client = cfg.http_client();
    let alpha = if cfg.parallel_alpha {
        step_alpha_parallel(&client, cfg, tenant_id, target_brief, prior_failure_log).await?
    } else {
        step_alpha_single(&client, cfg, tenant_id, target_brief, prior_failure_log).await?
    };
    let beta = step_beta(&client, cfg, tenant_id, &alpha).await?;
    let gamma = step_gamma(&client, cfg, tenant_id, &alpha, &beta).await?;
    info!(target: "council", tenant_id, round = council_round, "council debate completed");
    Ok(CouncilDebateResult {
        council_round,
        alpha,
        beta,
        gamma,
        prior_failure_log: prior_failure_log.map(std::string::ToString::to_string),
        orchestrator_instruction: None,
        sovereign_override: None,
        supreme_council: None,
    })
}

type ProbeFuture = Pin<Box<dyn Future<Output = bool> + Send>>;

/// Re-run the full council up to `max_rounds` times until `probe` returns true (e.g. OAST listener saw the hit).
pub async fn run_adversarial_debate_with_probe_retries<F>(
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    max_rounds: u32,
    initial_failure_log: Option<&str>,
    mut probe: F,
) -> Result<CouncilDebateResult, LlmError>
where
    F: FnMut(&CouncilDebateResult) -> ProbeFuture + Send,
{
    let mut failure: Option<String> = initial_failure_log
        .filter(|s| !s.trim().is_empty())
        .map(std::string::ToString::to_string);
    for r in 0..max_rounds.max(1) {
        let result = run_adversarial_debate(
            cfg,
            tenant_id,
            target_brief,
            r,
            failure.as_deref(),
        )
        .await?;
        if probe(&result).await {
            return Ok(result);
        }
        failure = Some(format!(
            "council_round={r}: probe/OAST negative; final_payload_excerpt={}",
            result.gamma.final_payload.chars().take(500).collect::<String>()
        ));
        warn!(target: "council", "probe failed, re-debating: {}", failure.as_deref().unwrap_or(""));
    }
    Err(LlmError::Decode(format!(
        "council: exhausted {max_rounds} rounds without probe success"
    )))
}

/// Convenience: probe uses [`crate::fuzz_oob::verify_oob_token_seen`] with token from `gamma.oast_token` or a fallback.
pub async fn run_debate_until_oob_seen(
    pool: std::sync::Arc<crate::fuzz_http_pool::FuzzHttpPool>,
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    fallback_oast_token: Option<&str>,
    max_council_rounds: u32,
    initial_failure_log: Option<&str>,
) -> Result<CouncilDebateResult, LlmError> {
    let fallback = fallback_oast_token.unwrap_or("").to_string();
    let pool_outer = pool;
    run_adversarial_debate_with_probe_retries(
        cfg,
        tenant_id,
        target_brief,
        max_council_rounds,
        initial_failure_log,
        move |res| {
            let tok = if !res.gamma.oast_token.trim().is_empty() {
                res.gamma.oast_token.clone()
            } else {
                fallback.clone()
            };
            let p = pool_outer.clone();
            Box::pin(async move {
                if tok.trim().is_empty() {
                    return false;
                }
                crate::fuzz_oob::verify_oob_token_seen(p.as_ref(), tok.trim()).await
            })
        },
    )
    .await
}

// --- Weissman Supreme Council (parallel Proposer + Critic, Sovereign General, semantic memory) ---

const SYS_PROPOSER_SUPREME: &str = "You are the Offensive Proposer. Authorized offensive security under contract. Output JSON only: {\"strategy\":{\"id\":\"s1\",\"name\":\"short\",\"description\":\"...\",\"payload_sketch\":\"...\"}} — exactly one strategy; payload_sketch is a minimal HTTP-test fragment.";

const SYS_CRITIC_TARGET: &str = "You are the Defensive Critic. You do NOT yet see the attacker's concrete payload. From the TARGET BRIEF alone, enumerate detection surfaces: WAF/SIEM/EDR/logging patterns that would catch typical abuse. Output JSON only: {\"flaw_vectors\":[\"...\"],\"critique\":\"...\",\"false_positive_risk\":\"low|medium|high\",\"hardening_notes\":\"...\"}.";

const SYS_SOVEREIGN: &str = "You are the Sovereign General — FINAL AUTHORITY. Review the full debate transcript (Proposer strategy + Critic assessment). You may veto or rewrite the approach to minimize false positives and collateral signals while preserving authorized test value. Output JSON only: {\"orchestrator\":{\"action\":\"http_probe\",\"method\":\"GET|POST|PUT|PATCH\",\"path_or_url_hint\":\"...\",\"header_hints\":{},\"body_template\":\"\",\"notes\":\"...\"},\"final_payload\":\"...\",\"rationale\":\"...\",\"oast_token\":\"\",\"sovereign_override\":\"\"}. orchestrator must be machine-actionable JSON for downstream automation.";

fn parse_proposer_supreme(text: &str) -> Result<ProposerStrategyOut, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("proposer: {e}")))
}

fn parse_critic_assessment(text: &str) -> Result<CriticTargetAssessment, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("critic: {e}")))
}

fn parse_sovereign(text: &str) -> Result<SovereignDirective, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("sovereign: {e}")))
}

fn target_fingerprint(brief: &str) -> String {
    let norm = brief.trim().to_lowercase();
    let hash = Sha256::digest(norm.as_bytes());
    hex::encode(hash)
}

fn json_vec_to_f32(v: &Value) -> Vec<f32> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_f64().map(|d| d as f32))
                .collect()
        })
        .unwrap_or_default()
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0f32;
    let mut na = 0f32;
    let mut nb = 0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    let d = (na.sqrt() * nb.sqrt()).max(1e-8);
    dot / d
}

async fn fetch_supreme_memory_context(
    pool: Option<&PgPool>,
    cfg: &CouncilConfig,
    client: &reqwest::Client,
    tenant_id: i64,
    target_brief: &str,
) -> String {
    let Some(pool) = pool else {
        return String::new();
    };
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return String::new();
    };
    let rows = sqlx::query(
        r#"SELECT brief_excerpt, strategy_summary, orchestrator_instruction, embedding
           FROM supreme_council_memory
           ORDER BY created_at DESC
           LIMIT 500"#,
    )
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;
    let Ok(rows) = rows else {
        return String::new();
    };
    if rows.is_empty() {
        return String::new();
    }
    let query_vec: Vec<f32> = match openai_chat::create_embedding(
        client,
        cfg.base_url.as_str(),
        cfg.supreme_embedding_model.as_str(),
        &target_brief.chars().take(4000).collect::<String>(),
        Some(tenant_id),
        "council_memory_query",
    )
    .await
    {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };
    let k = cfg.supreme_memory_top_k;
    if query_vec.is_empty() {
        let mut lines = Vec::new();
        for row in rows.into_iter().take(k) {
            let excerpt: String = row.try_get("brief_excerpt").unwrap_or_default();
            let summary: String = row.try_get("strategy_summary").unwrap_or_default();
            let orch: Value = row.try_get("orchestrator_instruction").unwrap_or(json!({}));
            lines.push(format!(
                "- prior_win: brief={excerpt} summary={summary} orchestrator={orch}"
            ));
        }
        return format!("Semantic memory (recent OAST-validated wins):\n{}", lines.join("\n"));
    }
    let mut scored: Vec<(f32, String)> = Vec::new();
    for row in rows {
        let excerpt: String = row.try_get("brief_excerpt").unwrap_or_default();
        let summary: String = row.try_get("strategy_summary").unwrap_or_default();
        let orch: Value = row.try_get("orchestrator_instruction").unwrap_or(json!({}));
        let emb_v: Value = row.try_get("embedding").unwrap_or(json!([]));
        let emb = json_vec_to_f32(&emb_v);
        let sim = if emb.is_empty() {
            0.0
        } else {
            cosine_similarity(&query_vec, &emb)
        };
        scored.push((
            sim,
            format!(
                "- prior_win (sim={:.3}): brief={} summary={} orchestrator={}",
                sim, excerpt, summary, orch
            ),
        ));
    }
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let lines: Vec<_> = scored.into_iter().take(k).map(|(_, s)| s).collect();
    format!(
        "Semantic memory (vector-ranked prior wins):\n{}",
        lines.join("\n")
    )
}

/// Persist a validated Supreme Council outcome for [`fetch_supreme_memory_context`].
pub async fn persist_supreme_council_win(
    pool: &PgPool,
    tenant_id: i64,
    target_brief: &str,
    sovereign: &SovereignDirective,
    proposer: &ProposerStrategyOut,
    client: &reqwest::Client,
    cfg: &CouncilConfig,
) -> Result<(), String> {
    let fp = target_fingerprint(target_brief);
    let excerpt = target_brief.chars().take(500).collect::<String>();
    let summary = format!(
        "{} | {} | {}",
        proposer.strategy.id,
        proposer.strategy.name,
        proposer.strategy.description.chars().take(2000).collect::<String>()
    );
    let embed_input = format!(
        "{}\n{}",
        target_brief.chars().take(4000).collect::<String>(),
        summary
    );
    let emb = openai_chat::create_embedding(
        client,
        cfg.base_url.as_str(),
        cfg.supreme_embedding_model.as_str(),
        &embed_input,
        Some(tenant_id),
        "council_memory_embed",
    )
    .await
    .map_err(|e| e.to_string())?;
    let emb_json = serde_json::to_value(&emb).map_err(|e| e.to_string())?;
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"INSERT INTO supreme_council_memory (
            tenant_id, target_fingerprint, brief_excerpt,
            orchestrator_instruction, strategy_summary, embedding, oast_token, source
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(tenant_id)
    .bind(&fp)
    .bind(&excerpt)
    .bind(&sovereign.orchestrator)
    .bind(summary.chars().take(8000).collect::<String>())
    .bind(emb_json)
    .bind(sovereign.oast_token.trim())
    .bind("oast_success")
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    info!(target: "council", tenant_id, "supreme council winning strategy persisted to semantic memory");
    Ok(())
}

async fn step_proposer_supreme(
    client: &reqwest::Client,
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    memory_ctx: &str,
    prior_failure: Option<&str>,
) -> Result<ProposerStrategyOut, LlmError> {
    let fail = prior_failure
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\nPrior OAST/probe failure:\n{s}\n"))
        .unwrap_or_default();
    let mem = if memory_ctx.trim().is_empty() {
        String::new()
    } else {
        format!("\n{memory_ctx}\n")
    };
    let user = format!(
        "Target / mission brief (authorized):\n{}\n{fail}{mem}\
         Output ONLY the JSON object with a single `strategy` key.",
        target_brief.chars().take(12_000).collect::<String>()
    );
    let text = llm(
        client,
        cfg,
        cfg.model_coder.as_str(),
        SYS_PROPOSER_SUPREME,
        &user,
        cfg.temperature_alpha,
        cfg.max_tokens_alpha,
        tenant_id,
        "supreme_proposer",
    )
    .await?;
    parse_proposer_supreme(&text)
}

async fn step_critic_target_surface(
    client: &reqwest::Client,
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    prior_failure: Option<&str>,
) -> Result<CriticTargetAssessment, LlmError> {
    let fail = prior_failure
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\nPrior failure context:\n{s}\n"))
        .unwrap_or_default();
    let user = format!(
        "TARGET BRIEF:\n{}\n{fail}\
         Respond with JSON only (flaw_vectors, critique, false_positive_risk, hardening_notes).",
        target_brief.chars().take(12_000).collect::<String>()
    );
    let text = llm(
        client,
        cfg,
        cfg.model_generalist.as_str(),
        SYS_CRITIC_TARGET,
        &user,
        cfg.temperature_beta,
        cfg.max_tokens_beta,
        tenant_id,
        "supreme_critic",
    )
    .await?;
    parse_critic_assessment(&text)
}

async fn step_sovereign_general(
    client: &reqwest::Client,
    cfg: &CouncilConfig,
    tenant_id: i64,
    proposer: &ProposerStrategyOut,
    critic: &CriticTargetAssessment,
    target_brief: &str,
) -> Result<SovereignDirective, LlmError> {
    let transcript = format!(
        "TARGET:\n{}\n\nPROPOSER_STRATEGY:\n{}\n\nCRITIC_ASSESSMENT:\n{}\n",
        target_brief.chars().take(8000).collect::<String>(),
        serde_json::to_string(proposer).unwrap_or_default(),
        serde_json::to_string(critic).unwrap_or_default()
    );
    let user = format!(
        "DEBATE TRANSCRIPT:\n```\n{}\n```\n\
         As Sovereign General, emit the final JSON. orchestrator must be self-contained for an executor.",
        transcript.chars().take(24_000).collect::<String>()
    );
    let text = llm(
        client,
        cfg,
        cfg.model_synthesizer.as_str(),
        SYS_SOVEREIGN,
        &user,
        cfg.temperature_gamma,
        cfg.max_tokens_gamma,
        tenant_id,
        "supreme_sovereign",
    )
    .await?;
    parse_sovereign(&text)
}

#[cfg(target_os = "linux")]
fn supreme_phase1_on_cpus(
    cpu_a: usize,
    cpu_b: usize,
    fut_a: impl Future<Output = Result<ProposerStrategyOut, LlmError>> + Send + 'static,
    fut_b: impl Future<Output = Result<CriticTargetAssessment, LlmError>> + Send + 'static,
) -> (
    Result<ProposerStrategyOut, LlmError>,
    Result<CriticTargetAssessment, LlmError>,
) {
    std::thread::scope(|s| {
        let h1 = s.spawn(move || {
            let _ = crate::hpc_runtime::bind_current_thread_to_cpu(cpu_a);
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    return Err(LlmError::Decode(format!(
                        "supreme phase1 proposer tokio runtime: {e}"
                    )));
                }
            };
            rt.block_on(fut_a)
        });
        let h2 = s.spawn(move || {
            let _ = crate::hpc_runtime::bind_current_thread_to_cpu(cpu_b);
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    return Err(LlmError::Decode(format!(
                        "supreme phase1 critic tokio runtime: {e}"
                    )));
                }
            };
            rt.block_on(fut_b)
        });
        let rp = match h1.join() {
            Ok(r) => r,
            Err(_) => Err(LlmError::Decode(
                "supreme phase1 proposer thread panicked".into(),
            )),
        };
        let rc = match h2.join() {
            Ok(r) => r,
            Err(_) => Err(LlmError::Decode(
                "supreme phase1 critic thread panicked".into(),
            )),
        };
        (rp, rc)
    })
}

#[cfg(target_os = "linux")]
fn supreme_phase2_on_cpu(
    cpu: usize,
    fut: impl Future<Output = Result<SovereignDirective, LlmError>> + Send + 'static,
) -> Result<SovereignDirective, LlmError> {
    std::thread::scope(|s| {
        let h = s.spawn(move || {
            let _ = crate::hpc_runtime::bind_current_thread_to_cpu(cpu);
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    return Err(LlmError::Decode(format!(
                        "supreme phase2 sovereign tokio runtime: {e}"
                    )));
                }
            };
            rt.block_on(fut)
        });
        match h.join() {
            Ok(r) => r,
            Err(_) => Err(LlmError::Decode(
                "supreme phase2 sovereign thread panicked".into(),
            )),
        }
    })
}

async fn supreme_run_phase1(
    cfg: &CouncilConfig,
    client: &reqwest::Client,
    tenant_id: i64,
    brief: &str,
    memory_ctx: &str,
    prior_failure: Option<&str>,
) -> Result<(ProposerStrategyOut, CriticTargetAssessment), LlmError> {
    #[cfg(target_os = "linux")]
    {
        let use_aff =
            cfg.supreme_use_phased_affinity && cfg.supreme_phase1_cpus.len() >= 2;
        if use_aff {
            let ca = cfg.supreme_phase1_cpus[0];
            let cb = cfg.supreme_phase1_cpus
                .get(1)
                .copied()
                .unwrap_or(cfg.supreme_phase1_cpus[0]);
            let brief_p = brief.to_string();
            let brief_c = brief.to_string();
            let mem = memory_ctx.to_string();
            let pr_p = prior_failure.map(std::string::ToString::to_string);
            let pr_c = pr_p.clone();
            let client_p = client.clone();
            let client_c = client.clone();
            let cfg_p = cfg.clone();
            let cfg_c = cfg.clone();
            let (rp, rc) = tokio::task::spawn_blocking(move || {
                let fut_p = async move {
                    step_proposer_supreme(
                        &client_p,
                        &cfg_p,
                        tenant_id,
                        &brief_p,
                        &mem,
                        pr_p.as_deref(),
                    )
                    .await
                };
                let fut_c = async move {
                    step_critic_target_surface(
                        &client_c,
                        &cfg_c,
                        tenant_id,
                        &brief_c,
                        pr_c.as_deref(),
                    )
                    .await
                };
                supreme_phase1_on_cpus(ca, cb, fut_p, fut_c)
            })
            .await
            .map_err(|e| LlmError::Decode(format!("supreme phase1 affinity: {e}")))?;
            return Ok((rp?, rc?));
        }
    }
    let (rp, rc) = tokio::join!(
        step_proposer_supreme(
            client,
            cfg,
            tenant_id,
            brief,
            memory_ctx,
            prior_failure,
        ),
        step_critic_target_surface(client, cfg, tenant_id, brief, prior_failure),
    );
    Ok((rp?, rc?))
}

async fn supreme_run_phase2_sovereign(
    cfg: &CouncilConfig,
    client: &reqwest::Client,
    tenant_id: i64,
    proposer: &ProposerStrategyOut,
    critic: &CriticTargetAssessment,
    brief: &str,
) -> Result<SovereignDirective, LlmError> {
    #[cfg(target_os = "linux")]
    {
        let use_aff = cfg.supreme_use_phased_affinity && !cfg.supreme_phase2_cpus.is_empty();
        if use_aff {
            let cc = cfg.supreme_phase2_cpus[0];
            let proposer = proposer.clone();
            let critic = critic.clone();
            let brief = brief.to_string();
            let client = client.clone();
            let cfg = cfg.clone();
            return tokio::task::spawn_blocking(move || {
                let fut = async move {
                    step_sovereign_general(
                        &client,
                        &cfg,
                        tenant_id,
                        &proposer,
                        &critic,
                        &brief,
                    )
                    .await
                };
                supreme_phase2_on_cpu(cc, fut)
            })
            .await
            .map_err(|e| LlmError::Decode(format!("supreme phase2 affinity: {e}")))?;
        }
    }
    step_sovereign_general(client, cfg, tenant_id, proposer, critic, brief).await
}

/// Supreme Council: Phase 1 — Offensive Proposer ∥ Defensive Critic; Phase 2 — Sovereign General (final authority).
pub async fn run_supreme_council_debate(
    pool: Option<&PgPool>,
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    council_round: u32,
    prior_failure_log: Option<&str>,
) -> Result<SupremeCouncilDebateResult, LlmError> {
    let client = cfg.http_client();
    let memory_ctx =
        fetch_supreme_memory_context(pool, cfg, &client, tenant_id, target_brief).await;
    let (proposer, critic) = supreme_run_phase1(
        cfg,
        &client,
        tenant_id,
        target_brief,
        &memory_ctx,
        prior_failure_log,
    )
    .await?;
    let sovereign =
        supreme_run_phase2_sovereign(cfg, &client, tenant_id, &proposer, &critic, target_brief)
            .await?;
    let transcript_excerpt = format!(
        "P:{} C:{} S_orchestrator_keys:{:?}",
        serde_json::to_string(&proposer)
            .unwrap_or_default()
            .chars()
            .take(400)
            .collect::<String>(),
        serde_json::to_string(&critic)
            .unwrap_or_default()
            .chars()
            .take(400)
            .collect::<String>(),
        sovereign
            .orchestrator
            .as_object()
            .map(|m| m.keys().collect::<Vec<_>>()),
    );
    info!(target: "council", tenant_id, round = council_round, "supreme council debate completed");
    Ok(SupremeCouncilDebateResult {
        council_round,
        proposer,
        critic,
        sovereign,
        transcript_excerpt,
        prior_failure_log: prior_failure_log.map(std::string::ToString::to_string),
    })
}

impl SupremeCouncilDebateResult {
    /// Flatten into the legacy [`CouncilDebateResult`] shape (orchestrator + gamma populated from the Sovereign).
    #[must_use]
    pub fn into_council_debate_result(self) -> CouncilDebateResult {
        let content_type_hint = self
            .sovereign
            .orchestrator
            .get("content_type")
            .or_else(|| self.sovereign.orchestrator.get("content_type_hint"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let sid = self.proposer.strategy.id.clone();
        CouncilDebateResult {
            council_round: self.council_round,
            alpha: AlphaStrategies {
                strategies: vec![self.proposer.strategy.clone()],
            },
            beta: BetaCritique {
                critique: self.critic.critique.clone(),
                ranked_by_stealth: vec![sid.clone()],
                detection_risks: self.critic.flaw_vectors.clone(),
                recommended_strategy_id: sid,
            },
            gamma: GammaOutput {
                final_payload: self.sovereign.final_payload.clone(),
                rationale: self.sovereign.rationale.clone(),
                content_type_hint,
                oast_token: self.sovereign.oast_token.clone(),
            },
            prior_failure_log: self.prior_failure_log.clone(),
            orchestrator_instruction: Some(self.sovereign.orchestrator.clone()),
            sovereign_override: Some(self.sovereign.sovereign_override.clone()),
            supreme_council: Some(true),
        }
    }
}

/// Probe retries using the Supreme Council; persists to semantic memory when the probe succeeds.
pub async fn run_supreme_debate_with_probe_retries<F>(
    pool_pg: Option<&PgPool>,
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    max_rounds: u32,
    initial_failure_log: Option<&str>,
    persist_memory_on_success: bool,
    mut probe: F,
) -> Result<CouncilDebateResult, LlmError>
where
    F: FnMut(&CouncilDebateResult) -> ProbeFuture + Send,
{
    let mut failure: Option<String> = initial_failure_log
        .filter(|s| !s.trim().is_empty())
        .map(std::string::ToString::to_string);
    let client = cfg.http_client();
    for r in 0..max_rounds.max(1) {
        let supreme = run_supreme_council_debate(
            pool_pg,
            cfg,
            tenant_id,
            target_brief,
            r,
            failure.as_deref(),
        )
        .await?;
        let sovereign = supreme.sovereign.clone();
        let proposer = supreme.proposer.clone();
        let legacy = supreme.into_council_debate_result();
        if probe(&legacy).await {
            if persist_memory_on_success {
                if let Some(p) = pool_pg {
                    if let Err(e) = persist_supreme_council_win(
                        p,
                        tenant_id,
                        target_brief,
                        &sovereign,
                        &proposer,
                        &client,
                        cfg,
                    )
                    .await
                    {
                        warn!(target: "council", "supreme memory persist failed: {e}");
                    }
                }
            }
            return Ok(legacy);
        }
        failure = Some(format!(
            "council_round={r}: probe/OAST negative; final_payload_excerpt={}",
            legacy.gamma.final_payload.chars().take(500).collect::<String>()
        ));
        warn!(target: "council", "probe failed, re-debating: {}", failure.as_deref().unwrap_or(""));
    }
    Err(LlmError::Decode(format!(
        "supreme council: exhausted {max_rounds} rounds without probe success"
    )))
}

/// OAST verification + semantic persistence (Supreme Council).
pub async fn run_supreme_debate_until_oob_seen(
    pool_pg: &PgPool,
    pool_http: std::sync::Arc<crate::fuzz_http_pool::FuzzHttpPool>,
    cfg: &CouncilConfig,
    tenant_id: i64,
    target_brief: &str,
    fallback_oast_token: Option<&str>,
    max_council_rounds: u32,
    initial_failure_log: Option<&str>,
) -> Result<CouncilDebateResult, LlmError> {
    let fallback = fallback_oast_token.unwrap_or("").to_string();
    let pool_outer = pool_http;
    run_supreme_debate_with_probe_retries(
        Some(pool_pg),
        cfg,
        tenant_id,
        target_brief,
        max_council_rounds,
        initial_failure_log,
        true,
        move |res| {
            let tok = if !res.gamma.oast_token.trim().is_empty() {
                res.gamma.oast_token.clone()
            } else {
                fallback.clone()
            };
            let p = pool_outer.clone();
            Box::pin(async move {
                if tok.trim().is_empty() {
                    return false;
                }
                crate::fuzz_oob::verify_oob_token_seen(p.as_ref(), tok.trim()).await
            })
        },
    )
    .await
}

// --- Supreme Command Protocol: `process_mission`, signed `COUNCIL_DEBATE` audit rows ---

const SUPREME_CMD_MAX_CONFLICT_ROUNDS: u32 = 3;

const CMD_SYS_BRIEF: &str = "You are the Sovereign General. Output ONE minified JSON object ONLY. Keys exactly: mission_id, objective, target_context, constraints, rules_of_engagement. Use the mission_id string exactly as given in the user message. No markdown, no keys beyond these five.";

const CMD_SYS_HACKER: &str = "You are The Hacker (offensive engineer). Output ONE minified JSON object ONLY. Keys exactly: vector_type, payload_hex, target_entry_point, bypass_logic. All values are strings. payload_hex is hex-encoded test bytes or empty. No prose.";

const CMD_SYS_CRITIC: &str = "You are The Critic (defensive analyst). Output ONE minified JSON object ONLY. Keys exactly: stealth_score (integer 0-100), detected_waf_signatures (JSON array of strings), risk_assessment, alternative_encoding. No prose.";

const CMD_SYS_EXEC_ORDER: &str = "You are the Sovereign General issuing the final order. Output ONE minified JSON object ONLY. Keys exactly: final_payload, execution_delay_ms (integer >= 0), success_criteria, emergency_abort_condition. No prose.";

fn council_signing_secret() -> Vec<u8> {
    std::env::var("WEISSMAN_COUNCIL_DEBATE_SIGNING_SECRET")
        .or_else(|_| std::env::var("WEISSMAN_JWT_SECRET"))
        .unwrap_or_default()
        .trim()
        .as_bytes()
        .to_vec()
}

fn sign_council_audit(mission_id: &str, phase: &str, canonical_payload: &str) -> String {
    let key = council_signing_secret();
    if key.is_empty() {
        let mut h = Sha256::new();
        h.update(b"WEISSMAN_COUNCIL_UNSIGNED_V1|");
        h.update(mission_id.as_bytes());
        h.update(b"|");
        h.update(phase.as_bytes());
        h.update(b"|");
        h.update(canonical_payload.as_bytes());
        return hex::encode(h.finalize());
    }
    if let Ok(mut mac) = HmacSha256::new_from_slice(&key) {
        mac.update(mission_id.as_bytes());
        mac.update(b"|");
        mac.update(phase.as_bytes());
        mac.update(b"|");
        mac.update(canonical_payload.as_bytes());
        return hex::encode(mac.finalize().into_bytes());
    }
    let mut h = Sha256::new();
    h.update(b"WEISSMAN_COUNCIL_HMAC_FALLBACK|");
    h.update(mission_id.as_bytes());
    h.update(b"|");
    h.update(phase.as_bytes());
    h.update(b"|");
    h.update(canonical_payload.as_bytes());
    hex::encode(h.finalize())
}

async fn council_audit_log_signed(
    pool: &PgPool,
    tenant_id: i64,
    actor_user_id: Option<i64>,
    mission_id: &str,
    phase: &str,
    role: &str,
    payload: &Value,
) -> Result<(), LlmError> {
    let canonical = serde_json::to_string(payload)
        .map_err(|e| LlmError::Decode(format!("audit canonical: {e}")))?;
    let sig = sign_council_audit(mission_id, phase, &canonical);
    let envelope = json!({
        "protocol": "WEISSMAN_SUPREME_COMMAND",
        "mission_id": mission_id,
        "phase": phase,
        "role": role,
        "payload": payload,
        "signature_hex": sig,
    });
    let details = serde_json::to_string(&envelope)
        .map_err(|e| LlmError::Decode(format!("audit envelope: {e}")))?;
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| LlmError::Decode(format!("audit tx: {e}")))?;
    crate::audit_log::insert_audit(
        &mut tx,
        tenant_id,
        actor_user_id,
        "weissman_supreme_command",
        "COUNCIL_DEBATE",
        &details,
        "127.0.0.1",
    )
    .await
    .map_err(|e| LlmError::Decode(format!("audit insert: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| LlmError::Decode(format!("audit commit: {e}")))?;
    Ok(())
}

async fn llm_command_json(
    client: &reqwest::Client,
    cfg: &CouncilConfig,
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

fn parse_mission_brief_json(text: &str) -> Result<MissionBrief, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("brief: {e}")))
}

fn parse_hacker_proposal_json(text: &str) -> Result<HackerProposal, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("hacker: {e}")))
}

fn parse_critic_audit_json(text: &str) -> Result<CriticAudit, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("critic: {e}")))
}

fn parse_executive_order_json(text: &str) -> Result<ExecutiveOrder, LlmError> {
    deserialize_llm_json(text).map_err(|e| LlmError::Decode(format!("exec: {e}")))
}

/// **Weissman Supreme Command Protocol** — Phase A (brief) → Phase B (≤3 hacker/critic rounds or stealth >90) → Phase C (executive order).
/// Uses `Arc<RwLock<SupremeCommandMissionState>>` for shared live state; each step is signed into `audit_logs` (`action_type = COUNCIL_DEBATE`).
pub async fn process_mission(
    pool: &PgPool,
    tenant_id: i64,
    cfg: &CouncilConfig,
    target_operational_brief: &str,
    actor_user_id: Option<i64>,
) -> Result<SupremeCommandProtocolOutput, LlmError> {
    let client = cfg.http_client();
    let mission_id = Uuid::new_v4().to_string();
    let shared: SharedMissionState = Arc::new(RwLock::new(SupremeCommandMissionState {
        mission_id: mission_id.clone(),
        brief: None,
        iterations: Vec::new(),
    }));

    // Phase A — General issues MissionBrief to the Hacker track
    let user_brief = format!(
        "mission_id (exact): \"{}\"\nOPERATIONAL_TARGET_BRIEF:\n{}\nEmit MissionBrief JSON only.",
        mission_id,
        target_operational_brief.chars().take(14_000).collect::<String>()
    );
    let raw_brief = llm_command_json(
        &client,
        cfg,
        cfg.model_synthesizer.as_str(),
        CMD_SYS_BRIEF,
        &user_brief,
        cfg.temperature_gamma,
        cfg.max_tokens_gamma,
        tenant_id,
        "supreme_cmd_brief",
    )
    .await?;
    let mission_brief = parse_mission_brief_json(&raw_brief)?;
    if mission_brief.mission_id != mission_id {
        return Err(LlmError::Decode(
            "supreme command: mission_id mismatch in MissionBrief".into(),
        ));
    }
    {
        let mut w = shared.write().await;
        w.brief = Some(mission_brief.clone());
    }
    let brief_v = serde_json::to_value(&mission_brief).map_err(|e| LlmError::Decode(e.to_string()))?;
    council_audit_log_signed(
        pool,
        tenant_id,
        actor_user_id,
        &mission_id,
        "PHASE_A_BRIEFING",
        "GENERAL",
        &brief_v,
    )
    .await?;

    // Phase B — iterative conflict
    for round in 0..SUPREME_CMD_MAX_CONFLICT_ROUNDS {
        let brief_snap = shared
            .read()
            .await
            .brief
            .clone()
            .ok_or_else(|| LlmError::Decode("supreme command: missing brief".into()))?;
        let prior = shared.read().await.iterations.last().cloned();
        let hacker_ctx = match &prior {
            None => serde_json::to_string(&brief_snap).unwrap_or_default(),
            Some((p, a)) => format!(
                "MISSION_BRIEF:\n{}\nLAST_PROPOSAL:\n{}\nLAST_AUDIT:\n{}",
                serde_json::to_string(&brief_snap).unwrap_or_default(),
                serde_json::to_string(p).unwrap_or_default(),
                serde_json::to_string(a).unwrap_or_default()
            ),
        };
        let hacker_user = format!(
            "{}\nEmit HackerProposal JSON only for this round (round_index={}).",
            hacker_ctx.chars().take(16_000).collect::<String>(),
            round
        );
        let raw_h = llm_command_json(
            &client,
            cfg,
            cfg.model_coder.as_str(),
            CMD_SYS_HACKER,
            &hacker_user,
            cfg.temperature_alpha,
            cfg.max_tokens_alpha,
            tenant_id,
            "supreme_cmd_hacker",
        )
        .await?;
        let proposal = parse_hacker_proposal_json(&raw_h)?;
        let prop_v = serde_json::to_value(&proposal).map_err(|e| LlmError::Decode(e.to_string()))?;
        council_audit_log_signed(
            pool,
            tenant_id,
            actor_user_id,
            &mission_id,
            &format!("PHASE_B_CONFLICT_HACKER_R{round}"),
            "HACKER",
            &prop_v,
        )
        .await?;

        let critic_user = format!(
            "MISSION_BRIEF:\n{}\nHACKER_PROPOSAL:\n{}\nEmit CriticAudit JSON only.",
            serde_json::to_string(&brief_snap).unwrap_or_default(),
            serde_json::to_string(&proposal).unwrap_or_default()
        );
        let raw_c = llm_command_json(
            &client,
            cfg,
            cfg.model_generalist.as_str(),
            CMD_SYS_CRITIC,
            &critic_user,
            cfg.temperature_beta,
            cfg.max_tokens_beta,
            tenant_id,
            "supreme_cmd_critic",
        )
        .await?;
        let audit = parse_critic_audit_json(&raw_c)?;
        let audit_v = serde_json::to_value(&audit).map_err(|e| LlmError::Decode(e.to_string()))?;
        council_audit_log_signed(
            pool,
            tenant_id,
            actor_user_id,
            &mission_id,
            &format!("PHASE_B_CONFLICT_CRITIC_R{round}"),
            "CRITIC",
            &audit_v,
        )
        .await?;

        {
            let mut w = shared.write().await;
            w.iterations.push((proposal.clone(), audit.clone()));
        }

        if audit.passes_stealth_bar() {
            info!(target: "council", tenant_id, mission_id = %mission_id, round, "supreme command: stealth bar cleared");
            break;
        }
    }

    // Phase C — General executive order
    let snap = shared.read().await;
    let decision_ctx = json!({
        "mission_brief": snap.brief,
        "audit_log": snap.iterations.iter().enumerate().map(|(i, (p, a))| json!({
            "round": i,
            "hacker_proposal": p,
            "critic_audit": a,
        })).collect::<Vec<_>>(),
    });
    drop(snap);
    let exec_user = format!(
        "FULL_CHAIN_OF_COMMAND:\n{}\nEmit ExecutiveOrder JSON for the Rust orchestrator.",
        serde_json::to_string(&decision_ctx)
            .unwrap_or_default()
            .chars()
            .take(28_000)
            .collect::<String>()
    );
    let raw_exec = llm_command_json(
        &client,
        cfg,
        cfg.model_synthesizer.as_str(),
        CMD_SYS_EXEC_ORDER,
        &exec_user,
        cfg.temperature_gamma,
        cfg.max_tokens_gamma,
        tenant_id,
        "supreme_cmd_executive",
    )
    .await?;
    let executive_order = parse_executive_order_json(&raw_exec)?;
    let exec_v =
        serde_json::to_value(&executive_order).map_err(|e| LlmError::Decode(e.to_string()))?;
    council_audit_log_signed(
        pool,
        tenant_id,
        actor_user_id,
        &mission_id,
        "PHASE_C_EXECUTIVE_ORDER",
        "GENERAL",
        &exec_v,
    )
    .await?;

    let mission_brief = shared
        .read()
        .await
        .brief
        .clone()
        .ok_or_else(|| LlmError::Decode("supreme command: brief lost".into()))?;
    let conflict_chain = shared.read().await.iterations.clone();

    info!(target: "council", tenant_id, mission_id = %mission_id, "supreme command protocol completed");
    Ok(SupremeCommandProtocolOutput {
        mission_brief,
        conflict_chain,
        executive_order,
        shared_state: shared,
    })
}
