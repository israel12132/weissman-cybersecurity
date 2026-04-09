//! **Genesis — Council Synthesis**: war-room conflict (propose chain → defense constraint → bypass).
//! Validated chains persist to `genesis_vaccine_vault` and optionally enqueue PoE / alerts.

use crate::ceo::war_room::WarRoomContext;
use crate::eternal_fuzz::SimFeedbackStep;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use weissman_engines::openai_chat::{self, LlmError};
use weissman_engines::deserialize_llm_json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAttackChain {
    #[serde(default)]
    pub chain_steps: Vec<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub estimated_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseConstraint {
    #[serde(default)]
    pub constraint_description: String,
    #[serde(default)]
    pub breaks_chain: bool,
    #[serde(default)]
    pub mitigation_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassResponse {
    #[serde(default)]
    pub bypass_exists: bool,
    #[serde(default)]
    pub revised_chain_steps: Vec<String>,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaccineArtifacts {
    #[serde(default)]
    pub remediation_patch: String,
    #[serde(default)]
    pub detection_signature: String,
    #[serde(default)]
    pub severity: String,
}

fn llm_client(cfg: &crate::council::CouncilConfig) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.http_timeout_secs))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn chat_json(
    cfg: &crate::council::CouncilConfig,
    client: &reqwest::Client,
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

const SYS_PROPOSER: &str = "You are DeepSeek-class offensive researcher. Given simulated attack-graph context, output ONE minified JSON only: chain_steps (string array), summary, estimated_severity (low|medium|high|critical). Authorized lab research. No prose outside JSON.";

const SYS_CRITIC: &str = "You are Mistral-class defender. Given an attack chain, output ONE minified JSON only: constraint_description, breaks_chain (boolean), mitigation_hint. Challenge feasibility and name defenses that block the chain. No prose outside JSON.";

const SYS_BYPASS: &str = "You are DeepSeek-class researcher. Given a chain and a defense constraint, output ONE minified JSON only: bypass_exists (boolean), revised_chain_steps (array), rationale. If you cannot bypass, bypass_exists=false. No prose outside JSON.";

const SYS_VACCINE: &str = "You are Llama-class security architect. Given a validated attack chain, output ONE minified JSON only: remediation_patch (code or config diff text), detection_signature (safe HTTP/log rule description), severity (low|medium|high|critical). No weaponized exploit prose. JSON only.";

fn norm_sev(s: &str) -> String {
    s.trim().to_lowercase().chars().take(32).collect()
}

/// Run proposer → critic → bypass; if validated, synthesize patch+signature and insert vault row.
/// When `war_room` is set, each model JSON decision is persisted for CEO SSE (`ceo_war_room_events`).
/// Hard wall-clock limit so sequential LLM rounds cannot block the worker unbounded (`WEISSMAN_GENESIS_WALL_SECS`).
pub async fn run_genesis_war_room(
    pool: Arc<PgPool>,
    tenant_id: i64,
    cfg: &crate::council::CouncilConfig,
    eternal_context: &Value,
    simulation_feedback: &[SimFeedbackStep],
    war_room: Option<&WarRoomContext>,
) -> Result<Value, LlmError> {
    let wall_secs: u64 = std::env::var("WEISSMAN_GENESIS_WALL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            cfg.http_timeout_secs
                .saturating_mul(8)
                .max(240)
                .min(2700)
        });
    tokio::time::timeout(
        Duration::from_secs(wall_secs),
        run_genesis_war_room_inner(
            pool,
            tenant_id,
            cfg,
            eternal_context,
            simulation_feedback,
            war_room,
        ),
    )
    .await
    .map_err(|_| {
        warn!(
            target: "genesis_war_room",
            tenant_id,
            wall_secs,
            "Genesis council synthesis exceeded wall-clock budget (set WEISSMAN_GENESIS_WALL_SECS)"
        );
        LlmError::Timeout
    })?
}

async fn run_genesis_war_room_inner(
    pool: Arc<PgPool>,
    tenant_id: i64,
    cfg: &crate::council::CouncilConfig,
    eternal_context: &Value,
    simulation_feedback: &[SimFeedbackStep],
    war_room: Option<&WarRoomContext>,
) -> Result<Value, LlmError> {
    info!(
        target: "genesis_war_room",
        tenant_id,
        llm_base = %cfg.base_url,
        model_coder = %cfg.model_coder,
        model_generalist = %cfg.model_generalist,
        model_synthesizer = %cfg.model_synthesizer,
        feedback_steps = simulation_feedback.len(),
        "council synthesis: LLM chain proposer → critic → bypass → vaccine (consulting local OpenAI-compatible API)"
    );
    let client = llm_client(cfg);
    let ctx = eternal_context.to_string().chars().take(14_000).collect::<String>();
    let fb = serde_json::to_string(&simulation_feedback)
        .unwrap_or_default()
        .chars()
        .take(8000)
        .collect::<String>();

    let u1 = format!("CONTEXT:\n{ctx}\n\nSIMULATION_FEEDBACK:\n{fb}\n\nJSON only.");
    let raw1 = chat_json(
        cfg,
        &client,
        cfg.model_coder.as_str(),
        SYS_PROPOSER,
        &u1,
        cfg.temperature_alpha,
        cfg.max_tokens_alpha,
        tenant_id,
        "genesis_chain_proposer",
    )
    .await?;
    let proposal: ProposedAttackChain = deserialize_llm_json(&raw1)
        .map_err(|e| LlmError::Decode(format!("proposer: {e}")))?;
    if let Some(w) = war_room {
        let sev = norm_sev(proposal.estimated_severity.as_str());
        let sev = if sev.is_empty() { "medium".into() } else { sev };
        w.emit(
            "proposer",
            sev.as_str(),
            &json!({
                "model": cfg.model_coder,
                "role": "proposer",
                "decision": proposal,
            }),
        )
        .await;
    }

    let u2 = format!(
        "ATTACK_CHAIN:\n{}\n\nJSON only.",
        serde_json::to_string(&proposal).unwrap_or_default()
    );
    let raw2 = chat_json(
        cfg,
        &client,
        cfg.model_generalist.as_str(),
        SYS_CRITIC,
        &u2,
        cfg.temperature_beta,
        cfg.max_tokens_beta,
        tenant_id,
        "genesis_chain_critic",
    )
    .await?;
    let defense: DefenseConstraint = deserialize_llm_json(&raw2)
        .map_err(|e| LlmError::Decode(format!("critic: {e}")))?;
    if let Some(w) = war_room {
        let sev = if defense.breaks_chain { "high" } else { "medium" };
        w.emit(
            "critic",
            sev,
            &json!({
                "model": cfg.model_generalist,
                "role": "critic",
                "decision": defense,
            }),
        )
        .await;
    }

    let u3 = format!(
        "CHAIN:\n{}\n\nDEFENSE:\n{}\n\nJSON only.",
        serde_json::to_string(&proposal).unwrap_or_default(),
        serde_json::to_string(&defense).unwrap_or_default()
    );
    let raw3 = chat_json(
        cfg,
        &client,
        cfg.model_coder.as_str(),
        SYS_BYPASS,
        &u3,
        cfg.temperature_alpha,
        cfg.max_tokens_alpha,
        tenant_id,
        "genesis_chain_bypass",
    )
    .await?;
    let bypass: BypassResponse = deserialize_llm_json(&raw3)
        .map_err(|e| LlmError::Decode(format!("bypass: {e}")))?;
    if let Some(w) = war_room {
        let sev = if bypass.bypass_exists { "high" } else { "low" };
        w.emit(
            "bypass",
            sev,
            &json!({
                "model": cfg.model_coder,
                "role": "bypass",
                "decision": bypass,
            }),
        )
        .await;
    }

    let validated = if defense.breaks_chain {
        bypass.bypass_exists && !bypass.revised_chain_steps.is_empty()
    } else {
        true
    };

    let mut transcript = json!({
        "proposal": proposal,
        "defense": defense,
        "bypass": bypass,
        "validated": validated,
    });

    if !validated {
        if let Some(w) = war_room {
            w.emit(
                "council",
                "warning",
                &json!({
                    "validated": false,
                    "council_transcript": transcript,
                }),
            )
            .await;
        }
        return Ok(json!({
            "validated": false,
            "council_transcript": transcript,
        }));
    }

    let u4 = format!(
        "VALIDATED_CHAIN:\n{}\n\nREVISED_STEPS:\n{}\n\nJSON only.",
        proposal.summary,
        serde_json::to_string(&bypass.revised_chain_steps).unwrap_or_default()
    );
    let raw4 = chat_json(
        cfg,
        &client,
        cfg.model_synthesizer.as_str(),
        SYS_VACCINE,
        &u4,
        cfg.temperature_gamma,
        cfg.max_tokens_gamma.min(4096),
        tenant_id,
        "genesis_vaccine_synth",
    )
    .await?;
    let vaccine: VaccineArtifacts = deserialize_llm_json(&raw4)
        .map_err(|e| LlmError::Decode(format!("vaccine: {e}")))?;
    if let Some(w) = war_room {
        let sev = norm_sev(vaccine.severity.as_str());
        let sev = if sev.is_empty() { "medium".into() } else { sev };
        w.emit(
            "vaccine",
            sev.as_str(),
            &json!({
                "model": cfg.model_synthesizer,
                "role": "vaccine",
                "decision": vaccine,
            }),
        )
        .await;
    }

    if let Some(o) = transcript.as_object_mut() {
        o.insert(
            "vaccine".into(),
            serde_json::to_value(&vaccine).unwrap_or_default(),
        );
    }

    let tech_fp = eternal_context
        .get("tech_fingerprint")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let component_ref = eternal_context
        .get("component_ref")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let chain_json = json!({
        "original": proposal.chain_steps,
        "revised": bypass.revised_chain_steps,
        "summary": proposal.summary,
    });
    let sim_v = serde_json::to_value(simulation_feedback).unwrap_or(json!([]));

    let mut tx = crate::db::begin_tenant_tx(pool.as_ref(), tenant_id)
        .await
        .map_err(|e| LlmError::Decode(e.to_string()))?;
    let row_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO genesis_vaccine_vault (
            tenant_id, tech_fingerprint, component_ref, attack_chain_json,
            remediation_patch, detection_signature, severity, preemptive_validated,
            simulation_feedback, council_transcript
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, $9)
        RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&tech_fp)
    .bind(&component_ref)
    .bind(&chain_json)
    .bind(&vaccine.remediation_patch)
    .bind(&vaccine.detection_signature)
    .bind(vaccine.severity.trim())
    .bind(&sim_v)
    .bind(&transcript)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| LlmError::Decode(format!("vault insert: {e}")))?;
    let _ = tx.commit().await.map_err(|e| LlmError::Decode(e.to_string()))?;

    crate::genesis_vault_cache::vault_cache_put(
        tenant_id,
        &tech_fp,
        json!({
            "id": row_id,
            "severity": vaccine.severity,
            "component_ref": component_ref,
            "detection_signature": vaccine.detection_signature,
        }),
    );

    info!(target: "genesis", tenant_id, row_id, "preemptive chain validated and stored");

    genesis_autonomous_followup(
        pool.clone(),
        tenant_id,
        row_id,
        vaccine.severity.as_str(),
        component_ref.as_str(),
        &vaccine,
    )
    .await;

    Ok(json!({
        "validated": true,
        "vault_id": row_id,
        "severity": vaccine.severity,
        "council_transcript": transcript,
    }))
}

/// Post-persist automation: audit log, webhook/Telegram, optional PoE job, optional heal hint row.
pub async fn genesis_autonomous_followup(
    pool: std::sync::Arc<PgPool>,
    tenant_id: i64,
    vault_id: i64,
    severity: &str,
    component_ref: &str,
    vaccine: &VaccineArtifacts,
) {
    if let Ok(mut tx) = crate::db::begin_tenant_tx(pool.as_ref(), tenant_id).await {
        let detail = format!(
            "genesis_vault_id={} severity={} component={} patch_len={} sig_len={}",
            vault_id,
            severity,
            component_ref.chars().take(200).collect::<String>(),
            vaccine.remediation_patch.len(),
            vaccine.detection_signature.len()
        );
        let _ = crate::audit_log::insert_audit(
            &mut tx,
            tenant_id,
            None,
            "genesis_protocol",
            "GENESIS_PREEMPTIVE_VALIDATED",
            &detail,
            "127.0.0.1",
        )
        .await;
        let _ = tx.commit().await;
    }

    let sev = severity.trim().to_lowercase();
    if sev == "critical" {
        crate::notifications::spawn_critical_poe_alert(
            pool.clone(),
            tenant_id,
            "genesis_vault",
            &format!("genesis-{vault_id}"),
            "Genesis Protocol preemptive chain",
            "critical",
            "curl -sS -o /dev/null -w '%{http_code}' https://example.invalid/genesis-health",
        );
        crate::notifications::spawn_genesis_telegram_alert(&format!(
            "[Genesis] CRITICAL preemptive chain stored vault_id={} ref={}",
            vault_id,
            component_ref.chars().take(120).collect::<String>()
        ));
    }

    if matches!(
        std::env::var("WEISSMAN_GENESIS_AUTO_POE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) {
        let target = component_target_url(component_ref);
        if !target.is_empty() {
            let payload = json!({ "target": target });
            if let Err(e) = crate::async_jobs::enqueue(
                pool.as_ref(),
                tenant_id,
                "poe_synthesis_run",
                payload,
                Some("genesis-vaccine-poe".to_string()),
            )
            .await
            {
                warn!(target: "genesis", "PoE enqueue failed: {}", e);
            }
        }
    }
}

/// Match client tech fingerprint against preemptive vault (DB + in-process cache).
pub async fn genesis_knowledge_match(
    pool: &PgPool,
    tenant_id: i64,
    tech_fingerprint: &str,
) -> Result<Value, sqlx::Error> {
    let fp = tech_fingerprint.trim();
    if fp.is_empty() {
        return Ok(json!({ "matches": [], "source": "empty_query" }));
    }
    if let Some(cached) = crate::genesis_vault_cache::vault_cache_get(tenant_id, fp) {
        return Ok(json!({ "matches": cached, "source": "cache" }));
    }
    let rows = sqlx::query(
        r#"SELECT id, component_ref, severity, detection_signature,
                  length(remediation_patch)::bigint AS patch_len
           FROM genesis_vaccine_vault
           WHERE tenant_id = $1 AND tech_fingerprint = $2 AND preemptive_validated = true
           ORDER BY id DESC LIMIT 64"#,
    )
    .bind(tenant_id)
    .bind(fp)
    .fetch_all(pool)
    .await?;
    let mut matches = Vec::with_capacity(rows.len());
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let component_ref: String = r.try_get("component_ref").unwrap_or_default();
        let severity: String = r.try_get("severity").unwrap_or_default();
        let detection_signature: String = r.try_get("detection_signature").unwrap_or_default();
        let patch_len: i64 = r.try_get("patch_len").unwrap_or(0);
        matches.push(json!({
            "id": id,
            "component_ref": component_ref,
            "severity": severity,
            "detection_signature": detection_signature,
            "remediation_patch_len": patch_len,
        }));
    }
    crate::genesis_vault_cache::vault_cache_replace(tenant_id, fp, matches.clone());
    Ok(json!({ "matches": matches, "source": "database" }))
}

fn component_target_url(component_ref: &str) -> String {
    let s = component_ref.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        return s.to_string();
    }
    if let Some(rest) = s.strip_prefix("WEISSMAN_GENESIS_SEED_REPOS:") {
        let r = rest.trim();
        if r.contains("github.com") {
            return r.to_string();
        }
        return format!("https://github.com/{r}");
    }
    String::new()
}
