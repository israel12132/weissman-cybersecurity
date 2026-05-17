//! Background scan cycle: reads clients from DB, runs ALL 5 engines per client, writes findings. Live only; no dummy.
//! After each cycle, computes Audit Root Hash from live vulnerabilities and stores in report_runs.
//! Pushes live "info" telemetry per engine so all Engine Cards show progress (no dead terminals).
//! P0: Re-verification before insert; circuit breaker for LLM; attack chain persisted. No panic paths.

use crate::ai_redteam_engine;
use crate::ceo::war_room::WarRoomMirror;
use crate::archival_engine;
use crate::asm_engine;
use crate::bola_idor_engine;
use crate::crypto_engine;
use crate::dag_pipeline;
use crate::discovery_engine;
use crate::exploit_synthesis_engine;
use crate::identity_engine;
use crate::leak_hunter_engine;
use crate::notifications;
use crate::llm_path_fuzz_engine;
use crate::osint_engine;
use crate::pipeline_context;
use crate::resilience;
use crate::semantic_fuzzer;
use crate::stealth_engine;
use crate::strategic_analyzer;
use crate::supply_chain_engine;
use crate::threat_intel_engine;
use crate::timing_engine;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

mod discovery_ui_snapshot;

pub(crate) use weissman_core::{finding_description, finding_title_and_severity, infer_poc_exploit};

static SCANNING_ACTIVE: AtomicBool = AtomicBool::new(false);
static ACTIVE_TENANT_CYCLES: AtomicUsize = AtomicUsize::new(0);

/// Number of `run_cycle_for_tenant` executions currently in flight (nested-safe via RAII guard).
pub fn active_tenant_scan_count() -> usize {
    ACTIVE_TENANT_CYCLES.load(Ordering::Relaxed)
}

struct TenantScanCounterGuard;

impl TenantScanCounterGuard {
    fn new() -> Self {
        ACTIVE_TENANT_CYCLES.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for TenantScanCounterGuard {
    fn drop(&mut self) {
        ACTIVE_TENANT_CYCLES.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn set_scanning_active(v: bool) {
    SCANNING_ACTIVE.store(v, Ordering::SeqCst);
}

pub fn is_scanning_active() -> bool {
    SCANNING_ACTIVE.load(Ordering::SeqCst)
}

/// Read a string config for this tenant. Returns None if missing or empty.
async fn get_config_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    key: &str,
) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = $2",
    )
    .bind(tenant_id)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten()
    .filter(|s: &String| !s.is_empty())
}

/// PoE is NOT in this list: it runs only when fuzzer/semantic_fuzzer logged a crash (or via UI).
const ALL_ENGINES: [&'static str; 9] = [
    "osint",
    "asm",
    "supply_chain",
    "leak_hunter",
    "bola_idor",
    "llm_path_fuzz",
    "semantic_ai_fuzz",
    "microsecond_timing",
    "ai_adversarial_redteam",
];

fn engine_display_label(source: &str) -> &'static str {
    match source {
        "osint" => "OSINT",
        "asm" => "ASM",
        "supply_chain" => "Supply Chain",
        "leak_hunter" => "Leak Hunter",
        "bola_idor" => "BOLA/IDOR",
        "llm_path_fuzz" => "LLM Path Fuzz",
        "semantic_ai_fuzz" => "Semantic AI Fuzz",
        "microsecond_timing" => "Microsecond Timing",
        "ai_adversarial_redteam" => "AI Adversarial Red Team",
        "zero_day_radar" => "Zero-Day Radar",
        "poe_synthesis" => "PoE Synthesis",
        "pipeline" => "Phantom Pipeline",
        _ => "Engine",
    }
}

fn war_mirror_emit(war: Option<&WarRoomMirror>, phase: &str, severity: &str, payload: Value) {
    if let Some(w) = war {
        w.emit(phase, severity, payload);
    }
}

/// Broadcast progress. client_id: when set, frontend shows this only for that client's view.
fn broadcast_engine_progress(
    tx: Option<&Arc<broadcast::Sender<String>>>,
    engine: &str,
    message: &str,
    client_id: Option<&str>,
    war: Option<&WarRoomMirror>,
) {
    if let Some(t) = tx {
        let mut obj = serde_json::json!({ "event": "progress", "engine": engine, "message": message, "severity": "info" });
        if let Some(cid) = client_id {
            obj["client_id"] = serde_json::Value::String(cid.to_string());
        }
        let _ = t.send(obj.to_string());
    }
    let mut p = serde_json::json!({ "engine": engine, "message": message });
    if let Some(cid) = client_id {
        p["client_id"] = serde_json::Value::String(cid.to_string());
    }
    war_mirror_emit(war, "orchestrator", "info", p);
}

/// Reality handshake: emit when a new target (host) is discovered so the map can drone-zoom.
fn broadcast_new_target(
    tx: Option<&Arc<broadcast::Sender<String>>>,
    client_id: &str,
    host: &str,
    war: Option<&WarRoomMirror>,
) {
    if let Some(t) = tx {
        let obj = serde_json::json!({
            "event": "new_target",
            "client_id": client_id,
            "host": host
        });
        let _ = t.send(obj.to_string());
    }
    war_mirror_emit(
        war,
        "new_target",
        "info",
        serde_json::json!({ "client_id": client_id, "host": host }),
    );
}

/// Reality handshake: emit when a finding is stored so the UI overlay shows real CVE/Proof.
pub(crate) fn broadcast_finding_created(
    tx: Option<&Arc<broadcast::Sender<String>>>,
    client_id: &str,
    finding_id: &str,
    title: &str,
    severity: &str,
    description: &str,
    poc_exploit: &str,
    war: Option<&WarRoomMirror>,
) {
    if let Some(t) = tx {
        let poc_sealed = poc_exploit.contains("[SEALED");
        let obj = serde_json::json!({
            "event": "finding_created",
            "client_id": client_id,
            "finding_id": finding_id,
            "title": title,
            "severity": severity,
            "description": description,
            "poc_exploit": poc_exploit,
            "poc_sealed": poc_sealed
        });
        let _ = t.send(obj.to_string());
    }
    war_mirror_emit(
        war,
        "finding",
        "info",
        serde_json::json!({
            "client_id": client_id,
            "finding_id": finding_id,
            "title": title,
            "severity": severity,
            "message": format!("Finding: {title} ({severity})"),
        }),
    );
}

/// P0: Emit engine failure so UI shows Toast; orchestrator continues (no crash).
/// Auto-Harvest: when backend escalates privileges, notify UI to fill High-Privilege slot and show alert.
fn broadcast_harvested_token(
    tx: Option<&Arc<broadcast::Sender<String>>>,
    client_id: &str,
    role_name: &str,
    context_id: i64,
    war: Option<&WarRoomMirror>,
) {
    if let Some(t) = tx {
        let obj = serde_json::json!({
            "event": "harvested_token",
            "client_id": client_id,
            "role_name": role_name,
            "context_id": context_id,
        });
        let _ = t.send(obj.to_string());
    }
    war_mirror_emit(
        war,
        "harvest",
        "info",
        serde_json::json!({
            "client_id": client_id,
            "role_name": role_name,
            "context_id": context_id,
            "message": format!("Harvested token: {role_name}"),
        }),
    );
}

fn broadcast_engine_error(
    tx: Option<&Arc<broadcast::Sender<String>>>,
    engine: &str,
    message: &str,
    client_id: Option<&str>,
    war: Option<&WarRoomMirror>,
) {
    if let Some(t) = tx {
        let mut obj = serde_json::json!({
            "event": "progress",
            "engine": engine,
            "message": format!("[ERROR] {}", message),
            "severity": "error"
        });
        if let Some(cid) = client_id {
            obj["client_id"] = serde_json::Value::String(cid.to_string());
        }
        let _ = t.send(obj.to_string());
    }
    let mut p = serde_json::json!({
        "engine": engine,
        "message": format!("[ERROR] {message}"),
    });
    if let Some(cid) = client_id {
        p["client_id"] = serde_json::Value::String(cid.to_string());
    }
    war_mirror_emit(war, "orchestrator", "error", p);
}

/// Broadcast pipeline stage transition for Live Pipeline Monitor UI.
fn broadcast_pipeline_stage(
    tx: Option<&Arc<broadcast::Sender<String>>>,
    run_id: i64,
    client_id: &str,
    stage: u8,
    status: &str,
    war: Option<&WarRoomMirror>,
) {
    if let Some(t) = tx {
        let label = dag_pipeline::STAGE_LABELS
            .get(stage as usize)
            .copied()
            .unwrap_or("Unknown");
        let obj = serde_json::json!({
            "event": "pipeline_stage",
            "run_id": run_id,
            "client_id": client_id,
            "stage": stage,
            "stage_label": label,
            "status": status,
        });
        let _ = t.send(obj.to_string());
    }
    let label = dag_pipeline::STAGE_LABELS
        .get(stage as usize)
        .copied()
        .unwrap_or("Unknown");
    war_mirror_emit(
        war,
        "pipeline",
        "info",
        serde_json::json!({
            "run_id": run_id,
            "client_id": client_id,
            "stage": stage,
            "stage_label": label,
            "status": status,
            "message": format!("Pipeline {label}: {status}"),
        }),
    );
}

/// Read pipeline state for (run_id, client_id). Returns (current_stage, paused, skip_to_stage).
async fn pipeline_get_state(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    run_id: i64,
    client_id: &str,
) -> Option<(u8, bool, Option<u8>)> {
    let row = sqlx::query(
        "SELECT current_stage, paused, skip_to_stage FROM pipeline_run_state WHERE tenant_id = $1 AND run_id = $2 AND client_id = $3",
    )
    .bind(tenant_id)
    .bind(run_id)
    .bind(client_id)
    .fetch_optional(&mut **tx)
    .await
    .ok()??;
    let current_stage: i32 = row.try_get("current_stage").ok()?;
    let paused: bool = row.try_get("paused").ok()?;
    let skip_to_stage: Option<i32> = row.try_get("skip_to_stage").ok()?;
    Some((current_stage as u8, paused, skip_to_stage.map(|s| s as u8)))
}

/// Insert or update pipeline state. Sets current_stage; clears skip_to_stage.
async fn pipeline_set_stage(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    run_id: i64,
    client_id: &str,
    stage: u8,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO pipeline_run_state (tenant_id, run_id, client_id, current_stage, paused, skip_to_stage, updated_at)
           VALUES ($1, $2, $3, $4, false, NULL, now())
           ON CONFLICT (tenant_id, run_id, client_id) DO UPDATE SET
             current_stage = EXCLUDED.current_stage,
             skip_to_stage = NULL,
             updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(run_id)
    .bind(client_id)
    .bind(stage as i32)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Initialize pipeline state for a run (global and optionally per-client).
async fn pipeline_init_run(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    run_id: i64,
    client_ids: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO pipeline_run_state (tenant_id, run_id, client_id, current_stage, paused, skip_to_stage, updated_at)
           VALUES ($1, $2, $3, 0, false, NULL, now())
           ON CONFLICT (tenant_id, run_id, client_id) DO UPDATE SET
             current_stage = EXCLUDED.current_stage,
             paused = false,
             skip_to_stage = NULL,
             updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(run_id)
    .bind(dag_pipeline::GLOBAL_SCOPE_ID)
    .execute(&mut **tx)
    .await?;
    let client_ids_owned: Vec<String> = client_ids.to_vec();
    for cid in client_ids_owned {
        sqlx::query(
            r#"INSERT INTO pipeline_run_state (tenant_id, run_id, client_id, current_stage, paused, skip_to_stage, updated_at)
               VALUES ($1, $2, $3, 1, false, NULL, now())
               ON CONFLICT (tenant_id, run_id, client_id) DO UPDATE SET
                 current_stage = EXCLUDED.current_stage,
                 paused = false,
                 skip_to_stage = NULL,
                 updated_at = now()"#,
        )
        .bind(tenant_id)
        .bind(run_id)
        .bind(cid.as_str())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Parse attack chain text into ordered steps (1. STEP 1: ...) and return (step_order, label, payload).
fn parse_attack_chain_steps(chain_text: &str) -> Vec<(u32, String, String)> {
    let mut steps = Vec::new();
    for line in chain_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("CHAIN_PAYLOAD:") {
            steps.push((999, "CHAIN_PAYLOAD".to_string(), rest.trim().to_string()));
            continue;
        }
        if let Some(rest) = line.strip_prefix("EXECUTION_ORDER:") {
            steps.push((1000, "EXECUTION_ORDER".to_string(), rest.trim().to_string()));
            continue;
        }
        let mut it = line.splitn(2, '.');
        if let (Some(num_s), Some(rest)) = (it.next(), it.next()) {
            let rest = rest.trim();
            if let Ok(n) = num_s.trim().parse::<u32>() {
                if n > 0 && n < 100 && !rest.is_empty() {
                    steps.push((n, rest.to_string(), String::new()));
                }
            }
        }
    }
    steps.sort_by_key(|(o, _, _)| *o);
    steps
}

/// DB seeds historically used `ollama_fuzz`; runtime id is `llm_path_fuzz`.
#[inline]
fn canonical_active_engine_id(s: &str) -> &str {
    match s.trim() {
        "ollama_fuzz" => "llm_path_fuzz",
        x => x,
    }
}

/// Parse active_engines JSON array. Defaults to all if missing/invalid. Used as fallback when client has no config.
async fn active_engines_list(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> Vec<String> {
    let json = get_config_tx(tx, tenant_id, "active_engines")
        .await
        .unwrap_or_else(|| {
            r#"["osint","asm","supply_chain","bola_idor","llm_path_fuzz","semantic_ai_fuzz"]"#
                .to_string()
        });
    let arr: Vec<String> = match serde_json::from_str(&json) {
        Ok(a) => a,
        _ => return ALL_ENGINES.iter().map(|s| (*s).to_string()).collect(),
    };
    let allowed: std::collections::HashSet<&str> = ALL_ENGINES.iter().copied().collect();
    arr.iter()
        .filter_map(|s| {
            let c = canonical_active_engine_id(s.as_str());
            if allowed.contains(c) {
                Some(c.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Load identity contexts for a client from DB (used at start and after auto-harvest).
async fn load_identity_contexts(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    client_id: i64,
) -> Vec<identity_engine::AuthContext> {
    let rows = sqlx::query(
        "SELECT role_name, privilege_order, token_type, token_value FROM identity_contexts WHERE client_id = $1 ORDER BY privilege_order DESC",
    )
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await
    .unwrap_or_default();
    rows.into_iter()
        .filter_map(|r| {
            Some(identity_engine::AuthContext {
                role_name: r.try_get("role_name").ok()?,
                privilege_order: r.try_get::<i32, _>("privilege_order").ok()?,
                token_type: r.try_get("token_type").ok()?,
                token_value: r.try_get("token_value").ok()?,
            })
        })
        .collect()
}

fn client_auto_harvest_enabled(client_configs_json: &str) -> bool {
    let json = client_configs_json.trim();
    if json.is_empty() {
        return true;
    }
    if let Ok(v) = serde_json::from_str::<Value>(json) {
        if let Some(b) = v.get("auto_harvest").and_then(Value::as_bool) {
            return b;
        }
    }
    true
}

/// Parse client_configs JSON and return enabled_engines list. If missing/invalid, returns full ALL_ENGINES.
fn client_enabled_engines(client_configs_json: &str) -> Vec<String> {
    let json = client_configs_json.trim();
    if json.is_empty() {
        return ALL_ENGINES.iter().map(|s| (*s).to_string()).collect();
    }
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(x) => x,
        _ => return ALL_ENGINES.iter().map(|s| (*s).to_string()).collect(),
    };
    let arr = match v.get("enabled_engines").and_then(|a| a.as_array()) {
        Some(a) => a,
        _ => return ALL_ENGINES.iter().map(|s| (*s).to_string()).collect(),
    };
    let allowed: std::collections::HashSet<&str> = ALL_ENGINES.iter().copied().collect();
    arr.iter()
        .filter_map(|s| s.as_str().map(|x| x.trim().to_string()))
        .filter(|s| allowed.contains(s.as_str()))
        .collect::<Vec<_>>()
}

/// Parse client_configs JSON and return roe_mode. "weaponized_god_mode" => true, else false.
fn client_roe_weaponized(client_configs_json: &str) -> bool {
    let json = client_configs_json.trim();
    if json.is_empty() {
        return false;
    }
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(x) => x,
        _ => return false,
    };
    v.get("roe_mode")
        .and_then(|m| m.as_str())
        .map(|s| s == "weaponized_god_mode")
        .unwrap_or(false)
}

/// True if client_configs.enabled_engines contains the given engine id (e.g. "zero_day_radar").
fn client_has_engine_enabled(client_configs_json: &str, engine_id: &str) -> bool {
    let json = client_configs_json.trim();
    if json.is_empty() {
        return false;
    }
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(x) => x,
        _ => return false,
    };
    match v.get("enabled_engines").and_then(|a| a.as_array()) {
        Some(arr) => arr
            .iter()
            .any(|s| s.as_str().map(|x| x == engine_id).unwrap_or(false)),
        _ => false,
    }
}

/// Industrial OT/ICS passive engines (Modbus/ENIP/S7) — only when explicitly enabled in client_configs.
fn client_industrial_ot_enabled(client_configs_json: &str) -> bool {
    let json = client_configs_json.trim();
    if json.is_empty() {
        return false;
    }
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return false;
    };
    v.get("industrial_ot_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Parse asm_ports JSON array. Returns None if missing/invalid (caller uses default).
async fn asm_ports_from_config(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> Option<Vec<u16>> {
    let json = get_config_tx(tx, tenant_id, "asm_ports").await?;
    serde_json::from_str::<Vec<u16>>(&json).ok()
}

/// Parse recon_subdomain_prefixes JSON array from system_configs. None = use DEFAULT_SUBDOMAINS in ASM.
async fn recon_subdomain_prefixes_from_config(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> Option<Vec<String>> {
    let json = get_config_tx(tx, tenant_id, "recon_subdomain_prefixes").await?;
    let v: Vec<String> = serde_json::from_str(&json).ok()?;
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Load semantic / OpenAPI fuzzer config from system_configs (Module 4).
async fn load_semantic_config(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> semantic_fuzzer::SemanticConfig {
    let llm_base_url = get_config_tx(tx, tenant_id, "llm_base_url")
        .await
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
    let llm_temperature = get_config_tx(tx, tenant_id, "llm_temperature")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.7);
    let llm_model = get_config_tx(tx, tenant_id, "llm_model")
        .await
        .unwrap_or_default();
    let max_sequence_depth = get_config_tx(tx, tenant_id, "max_sequence_depth")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    semantic_fuzzer::SemanticConfig {
        llm_base_url,
        llm_temperature,
        llm_model,
        max_sequence_depth,
    }
}

/// Load Threat Intel / Zero-Day Radar config from system_configs (Module 7).
async fn load_threat_intel_config(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> threat_intel_engine::ThreatIntelConfig {
    let llm_base_url = get_config_tx(tx, tenant_id, "llm_base_url")
        .await
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
    let llm_model = get_config_tx(tx, tenant_id, "llm_model")
        .await
        .unwrap_or_default();
    let enable = get_config_tx(tx, tenant_id, "enable_zero_day_probing")
        .await
        .map(|s| s.to_lowercase() == "true" || s == "1")
        .unwrap_or(true);
    let urls_json = get_config_tx(tx, tenant_id, "custom_feed_urls")
        .await
        .unwrap_or_else(|| "[]".to_string());
    let custom_feed_urls: Vec<String> = serde_json::from_str(&urls_json).unwrap_or_default();
    threat_intel_engine::ThreatIntelConfig {
        llm_base_url,
        llm_model,
        enable_zero_day_probing: enable,
        custom_feed_urls,
    }
}

/// Load AI Red Team config from system_configs (Module 6).
async fn load_ai_redteam_config(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> ai_redteam_engine::AiRedteamConfig {
    let llm_base_url = get_config_tx(tx, tenant_id, "llm_base_url")
        .await
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
    let llm_temperature = get_config_tx(tx, tenant_id, "llm_temperature")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.7);
    let llm_model = get_config_tx(tx, tenant_id, "llm_model")
        .await
        .unwrap_or_default();
    let ai_redteam_endpoint = get_config_tx(tx, tenant_id, "ai_redteam_endpoint")
        .await
        .unwrap_or_default();
    let adversarial_strategy = get_config_tx(tx, tenant_id, "adversarial_strategy")
        .await
        .unwrap_or_else(|| "data_leak".to_string());
    ai_redteam_engine::AiRedteamConfig {
        llm_base_url,
        llm_temperature,
        llm_model,
        ai_redteam_endpoint,
        adversarial_strategy,
    }
}

/// Load Timing Profiler config from system_configs (Module 5).
async fn load_timing_config(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> timing_engine::TimingConfig {
    let n = get_config_tx(tx, tenant_id, "timing_sample_size")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let n = n.max(50).min(500);
    let z: f64 = get_config_tx(tx, tenant_id, "z_score_sensitivity")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(3.0);
    let z = z.max(2.0).min(5.0);
    timing_engine::TimingConfig {
        baseline_sample_size: n,
        payload_sample_size: n.min(100),
        z_score_threshold: z,
    }
}

/// Load PoE Synthesis config from system_configs (Module 9). `intel_pool` enables ephemeral payloads + global hunt.
async fn load_poe_config(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    intel_pool: Arc<PgPool>,
) -> exploit_synthesis_engine::PoEConfig {
    let llm_base_url = get_config_tx(tx, tenant_id, "llm_base_url")
        .await
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
    let llm_model = get_config_tx(tx, tenant_id, "llm_model")
        .await
        .unwrap_or_default();
    let enable = get_config_tx(tx, tenant_id, "enable_poe_synthesis")
        .await
        .map(|s| s.to_lowercase() == "true" || s == "1")
        .unwrap_or(true);
    let no_shells = get_config_tx(tx, tenant_id, "poe_safety_rails_no_shells")
        .await
        .map(|s| s.to_lowercase() == "true" || s == "1")
        .unwrap_or(true);
    let max_len: usize = get_config_tx(tx, tenant_id, "poe_max_poc_length")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(104857600);
    let use_raw_tcp = get_config_tx(tx, tenant_id, "poe_use_raw_tcp")
        .await
        .map(|s| s.to_lowercase() == "true" || s == "1")
        .unwrap_or(true);
    let entropy_threshold: f64 = get_config_tx(tx, tenant_id, "poe_entropy_leak_threshold")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(7.0);
    let mut gadget_chains: std::collections::HashMap<String, String> =
        get_config_tx(tx, tenant_id, "poe_gadget_chains")
            .await
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
    if let Ok(rows) = sqlx::query(
        "SELECT target_library, payload_data FROM dynamic_payloads WHERE added_at >= now() - interval '60 days'",
    )
    .fetch_all(intel_pool.as_ref())
    .await
    {
        for r in rows {
            if let (Ok(lib), Ok(data)) = (r.try_get::<String, _>("target_library"), r.try_get::<String, _>("payload_data")) {
                gadget_chains.insert(lib, data);
            }
        }
    }
    exploit_synthesis_engine::PoEConfig {
        llm_base_url,
        llm_model,
        enable_poe_synthesis: enable,
        safety_rails_no_shells: no_shells,
        max_poc_length: max_len,
        use_raw_tcp,
        entropy_leak_threshold: entropy_threshold,
        gadget_chains,
        intel_pool: Some(intel_pool),
    }
}

/// Load PoE config for HTTP handlers (short-lived tenant transaction).
pub async fn load_poe_config_http(
    app_pool: &PgPool,
    tenant_id: i64,
    intel_pool: Arc<PgPool>,
) -> Result<exploit_synthesis_engine::PoEConfig, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id).await?;
    let cfg = load_poe_config(&mut tx, tenant_id, intel_pool).await;
    tx.commit().await?;
    Ok(cfg)
}

/// Load Ghost Network / WAF evasion config from system_configs (read dynamically each cycle).
async fn load_stealth_config(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> stealth_engine::StealthConfig {
    let proxy_swarm = get_config_tx(tx, tenant_id, "proxy_swarm")
        .await
        .unwrap_or_default();
    let proxy_list = stealth_engine::StealthConfig::parse_proxy_swarm(&proxy_swarm);
    let jitter_min_ms = get_config_tx(tx, tenant_id, "jitter_min_ms")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let jitter_max_ms = get_config_tx(tx, tenant_id, "jitter_max_ms")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(800);
    let identity_morphing = get_config_tx(tx, tenant_id, "enable_identity_morphing")
        .await
        .map(|s| s.to_lowercase() == "true" || s == "1")
        .unwrap_or(true);
    stealth_engine::StealthConfig {
        proxy_list,
        jitter_min_ms,
        jitter_max_ms,
        identity_morphing,
    }
}

/// Owning wrappers: engine futures must not capture `&[String]` / `&str` from the orchestrator frame
/// (required for `Send` under `catch_unwind_future` / `tokio::spawn`).
async fn engine_bola_multi(
    targets: Vec<String>,
    paths: Vec<String>,
    stealth: stealth_engine::StealthConfig,
    identity_contexts: Option<Vec<identity_engine::AuthContext>>,
    llm_tenant_id: Option<i64>,
) -> crate::engine_result::EngineResult {
    bola_idor_engine::run_bola_idor_result_multi(
        &targets,
        &paths,
        Some(&stealth),
        identity_contexts
            .as_deref()
            .filter(|ctx| ctx.len() >= 2),
        llm_tenant_id,
    )
    .await
}

async fn engine_llm_path_fuzz_multi(
    targets: Vec<String>,
    paths: Vec<String>,
    stealth: stealth_engine::StealthConfig,
    llm_base_url: String,
    llm_model: String,
    llm_tenant_id: Option<i64>,
) -> crate::engine_result::EngineResult {
    llm_path_fuzz_engine::run_llm_path_fuzz_result_multi_cli(
        &targets,
        &paths,
        Some(&stealth),
        llm_base_url.as_str(),
        llm_model.as_str(),
        llm_tenant_id,
    )
    .await
    .into()
}

async fn engine_leak_hunter(
    targets: Vec<String>,
    stealth: stealth_engine::StealthConfig,
) -> crate::engine_result::EngineResult {
    leak_hunter_engine::run_leak_hunter(&targets, Some(&stealth)).await
}

async fn engine_semantic(
    target: String,
    stealth: stealth_engine::StealthConfig,
    config: semantic_fuzzer::SemanticConfig,
    discovered_paths: Vec<String>,
    llm_tenant_id: Option<i64>,
) -> semantic_fuzzer::SemanticFuzzResult {
    semantic_fuzzer::run_semantic_fuzz_result(
        target.as_str(),
        Some(&stealth),
        &config,
        Some(discovered_paths.as_slice()),
        llm_tenant_id,
    )
    .await
}

async fn engine_identity_autoharvest(
    targets: Vec<String>,
    paths: Vec<String>,
    llm_base_h: Option<String>,
    llm_model_h: Option<String>,
    llm_tenant_id: Option<i64>,
) -> (
    Vec<identity_engine::HarvestedToken>,
    Vec<serde_json::Value>,
) {
    identity_engine::run_autonomous_privilege_escalation(
        &targets,
        &paths,
        llm_base_h.as_deref(),
        llm_model_h.as_deref(),
        llm_tenant_id,
    )
    .await
}

/// One full enterprise scan cycle for a **single** tenant (SaaS API path; no cross-tenant work).
pub async fn run_single_tenant_scan_cycle(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    tenant_id: i64,
    telemetry_tx: Option<Arc<broadcast::Sender<String>>>,
    war_mirror: Option<WarRoomMirror>,
) -> Result<(), sqlx::Error> {
    run_cycle_for_tenant(
        app_pool,
        intel_pool,
        tenant_id,
        telemetry_tx,
        war_mirror,
    )
    .await
}

/// One full scan cycle for all active tenants (auth pool lists tenants; app pool + RLS per tenant).
pub async fn run_cycle_async(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    telemetry_tx: Option<Arc<broadcast::Sender<String>>>,
) {
    let tenant_ids: Vec<i64> =
        match sqlx::query_scalar::<_, i64>("SELECT id FROM tenants WHERE active = true")
            .fetch_all(auth_pool.as_ref())
            .await
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[Weissman][Orchestrator] List tenants failed: {}", e);
                return;
            }
        };
    for tenant_id in tenant_ids {
        let app = app_pool.clone();
        let intel = intel_pool.clone();
        let tt = telemetry_tx.clone();
        match crate::panic_shield::catch_unwind_future(
            "orchestrator_tenant_cycle",
            async move {
                run_cycle_for_tenant(app, intel, tenant_id, tt, None).await
            },
        )
        .await
        {
            crate::panic_shield::CatchOutcome::Completed(Ok(())) => {}
            crate::panic_shield::CatchOutcome::Completed(Err(e)) => {
                eprintln!(
                    "[Weissman][Orchestrator] Tenant {} cycle failed: {}",
                    tenant_id, e
                );
            }
            crate::panic_shield::CatchOutcome::Panicked { message, .. } => {
                eprintln!(
                    "[Weissman][Orchestrator] Tenant {} cycle panicked: {}",
                    tenant_id, message
                );
            }
            crate::panic_shield::CatchOutcome::CircuitOpen {
                cooldown_remaining_secs,
            } => {
                eprintln!(
                    "[Weissman][Orchestrator] Tenant {} cycle skipped: panic circuit open ({}s cooldown)",
                    tenant_id, cooldown_remaining_secs
                );
            }
        }
    }
}

/// Per-tenant cycle: tenant-scoped tx + RLS; commit before engine `.await`, then `begin_tenant_tx` again.
async fn run_cycle_for_tenant(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    tenant_id: i64,
    telemetry_tx: Option<Arc<broadcast::Sender<String>>>,
    war_mirror: Option<WarRoomMirror>,
) -> Result<(), sqlx::Error> {
    let wr = war_mirror.as_ref();
    let _tenant_depth = TenantScanCounterGuard::new();
    let mut tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
    let engines = active_engines_list(&mut tx, tenant_id).await;
    let asm_ports = asm_ports_from_config(&mut tx, tenant_id).await;
    let recon_subdomains = recon_subdomain_prefixes_from_config(&mut tx, tenant_id).await;
    let mut stealth_config = load_stealth_config(&mut tx, tenant_id).await;
    let global_safe_mode = get_config_tx(&mut tx, tenant_id, "global_safe_mode")
        .await
        .map(|s| s == "true" || s == "1")
        .unwrap_or(false);
    if global_safe_mode {
        stealth_config.jitter_min_ms = stealth_config.jitter_min_ms.max(800);
        stealth_config.jitter_max_ms = stealth_config
            .jitter_max_ms
            .max(2500)
            .max(stealth_config.jitter_min_ms.saturating_add(200));
        eprintln!(
            "[Weissman][Orchestrator] Global safe mode ON: jitter {}-{}ms, 2.5s gap between engines",
            stealth_config.jitter_min_ms, stealth_config.jitter_max_ms
        );
    }
    let semantic_config = load_semantic_config(&mut tx, tenant_id).await;
    let timing_config = load_timing_config(&mut tx, tenant_id).await;
    let ai_redteam_config = load_ai_redteam_config(&mut tx, tenant_id).await;
    let threat_intel_config = load_threat_intel_config(&mut tx, tenant_id).await;
    let poe_config = load_poe_config(&mut tx, tenant_id, intel_pool.clone()).await;
    eprintln!(
        "[Weissman][Orchestrator] Config tenant={}: engines={}, stealth(jitter={}-{}ms), zero_day={}",
        tenant_id,
        engines.len(),
        stealth_config.jitter_min_ms,
        stealth_config.jitter_max_ms,
        threat_intel_config.enable_zero_day_probing
    );
    let client_rows = sqlx::query(
        "SELECT id, name, domains, COALESCE(NULLIF(trim(ip_ranges),''),'[]') AS ip_ranges, COALESCE(client_configs,'') AS client_configs FROM clients",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let clients: Vec<(i64, String, String, String, String)> = client_rows
        .into_iter()
        .filter_map(|r| {
            Some((
                r.try_get::<i64, _>("id").ok()?,
                r.try_get::<String, _>("name").ok()?,
                r.try_get::<String, _>("domains")
                    .ok()
                    .unwrap_or_else(|| "[]".to_string()),
                r.try_get::<String, _>("ip_ranges")
                    .ok()
                    .unwrap_or_else(|| "[]".to_string()),
                r.try_get::<String, _>("client_configs")
                    .ok()
                    .unwrap_or_else(|| "{}".to_string()),
            ))
        })
        .collect();
    if clients.is_empty() {
        eprintln!(
            "[Weissman][Orchestrator] No clients for tenant {}; skipping.",
            tenant_id
        );
        tx.commit().await?;
        return Ok(());
    }
    eprintln!(
        "[Weissman][Orchestrator] Cycle start tenant={}: {} clients",
        tenant_id,
        clients.len()
    );
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let run_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO report_runs (tenant_id, findings_json, summary, pdf_path)
           VALUES ($1, '[]', '{}', NULL) RETURNING id"#,
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        eprintln!("[Weissman][Orchestrator] Insert report_runs failed: {}", e);
        e
    })?;
    let mut total_findings = 0usize;

    let client_ids: Vec<String> = clients
        .iter()
        .map(|(id, _, _, _, _)| id.to_string())
        .collect();
    if pipeline_init_run(&mut tx, tenant_id, run_id, &client_ids)
        .await
        .is_err()
    {
        eprintln!("[Weissman][Orchestrator] Pipeline init failed (non-fatal)");
    }
    broadcast_pipeline_stage(
        telemetry_tx.as_ref(),
        run_id,
        dag_pipeline::GLOBAL_SCOPE_ID,
        dag_pipeline::STAGE_GLOBAL_INTEL,
        "started",
    wr,
    );

    // Stage 0: Global Intel — Zero-Day Radar run once against all client assets (if any client has it enabled).
    let any_client_has_radar = clients
        .iter()
        .any(|(_, _, _, _, cfg)| client_has_engine_enabled(cfg, "zero_day_radar"));
    if threat_intel_config.enable_zero_day_probing && any_client_has_radar {
        broadcast_engine_progress(
            telemetry_tx.as_ref(),
            "zero_day_radar",
            "[Zero-Day Radar] Scanning all client assets...",
            None,
        wr,
        );
        let mut radar_targets: Vec<threat_intel_engine::RadarTarget> = Vec::new();
        for (cid, _name, domains_json, _ipr, _cfg) in clients.clone() {
            let domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
            for d in domains {
                let d = d.trim();
                if d.is_empty() {
                    continue;
                }
                let base = if d.starts_with("http://") || d.starts_with("https://") {
                    d.to_string()
                } else {
                    format!("https://{}", d)
                };
                radar_targets.push((cid.to_string(), base));
            }
        }
        if !radar_targets.is_empty() {
            eprintln!(
                "[Weissman][Orchestrator] Zero-Day Radar: {} targets",
                radar_targets.len()
            );
            tx.commit().await?;
            let radar_result = threat_intel_engine::run_zero_day_radar(
                &radar_targets,
                Some(&stealth_config),
                &threat_intel_config,
                None,
                Some(tenant_id),
            )
            .await;
            tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
            broadcast_engine_progress(
                telemetry_tx.as_ref(),
                "zero_day_radar",
                "[Zero-Day Radar] Scan complete.",
                None,
            wr,
            );
            for i in 0..radar_result.findings.len() {
                let f = radar_result.findings[i].clone();
                if let Some(obj) = f.as_object() {
                    let (title, severity) = finding_title_and_severity(obj);
                    let radar_cid = obj.get("client_id").and_then(|v| v.as_i64()).or_else(|| {
                        obj.get("client_id")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok())
                    });
                    let Some(radar_cid) = radar_cid else {
                        continue;
                    };
                    let fid = format!("zero_day_radar-{}-{}", run_id, i);
                    let desc = finding_description(obj);
                    let poc_z = infer_poc_exploit(obj, "");
                    let cid_str = radar_cid.to_string();
                    if sqlx::query(
                        r#"INSERT INTO vulnerabilities (run_id, tenant_id, client_id, finding_id, title, severity, source, description, status, poc_exploit, discovered_at)
                           VALUES ($1, $2, $3, $4, $5, $6, 'zero_day_radar', $7, 'OPEN', $8, now())"#,
                    )
                    .bind(run_id)
                    .bind(tenant_id)
                    .bind(radar_cid)
                    .bind(&fid)
                    .bind(&title)
                    .bind(&severity)
                    .bind(&desc)
                    .bind(&poc_z)
                    .execute(&mut *tx)
                    .await
                    .is_ok()
                    {
                        total_findings += 1;
                        notifications::spawn_critical_poe_alert(
                            Arc::clone(&app_pool),
                            tenant_id,
                            &cid_str,
                            &fid,
                            &title,
                            &severity,
                            &poc_z,
                        );
                    }
                }
            }
        }
    }
    broadcast_pipeline_stage(
        telemetry_tx.as_ref(),
        run_id,
        dag_pipeline::GLOBAL_SCOPE_ID,
        dag_pipeline::STAGE_GLOBAL_INTEL,
        "completed",
    wr,
    );
    let _ = pipeline_set_stage(
        &mut tx,
        tenant_id,
        run_id,
        dag_pipeline::GLOBAL_SCOPE_ID,
        dag_pipeline::STAGE_DEEP_DISCOVERY,
    )
    .await;

    let mut run_max_targets = 0usize;
    let mut run_max_paths = 0usize;
    for (db_client_id, name, domains_json, ip_ranges_json, client_configs) in clients.clone() {
        let targets: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
        let target: String = targets.first().cloned().unwrap_or_else(|| name.clone());
        if target.is_empty() {
            continue;
        }
        let client_engines = client_enabled_engines(client_configs.as_str());
        if client_engines.is_empty() {
            eprintln!(
                "[Weissman][Orchestrator] Client id={} has no enabled engines; skipping.",
                db_client_id
            );
            continue;
        }
        eprintln!(
            "[Weissman][Orchestrator] Scanning client id={} name={} target={} (enabled_engines: {:?})",
            db_client_id, name, target, client_engines
        );
        let cid = db_client_id.to_string();
        if let Some((_cur, paused, skip_to_stage)) =
            pipeline_get_state(&mut tx, tenant_id, run_id, &cid).await
        {
            if paused {
                eprintln!("[Weissman][Orchestrator] Client {} paused; skipping.", cid);
                continue;
            }
            if let Some(skip_stage) = skip_to_stage {
                let _ = sqlx::query(
                    r#"UPDATE pipeline_run_state SET current_stage = $1, skip_to_stage = NULL, updated_at = now()
                       WHERE tenant_id = $2 AND run_id = $3 AND client_id = $4"#,
                )
                .bind(skip_stage as i32)
                .bind(tenant_id)
                .bind(run_id)
                .bind(&cid)
                .execute(&mut *tx)
                .await;
            }
        }
        broadcast_pipeline_stage(
            telemetry_tx.as_ref(),
            run_id,
            &cid,
            dag_pipeline::STAGE_DEEP_DISCOVERY,
            "started",
        wr,
        );
        let mut identity_contexts = load_identity_contexts(&mut tx, db_client_id).await;
        let mut client_had_crash = false;
        let mut target_list: Vec<String> = vec![if target.starts_with("http") {
            target.clone()
        } else {
            format!("https://{}", target)
        }];
        let mut discovery_ctx = pipeline_context::DiscoveryContext::new();
        discovery_ctx.merge_paths(pipeline_context::expanded_path_wordlist());
        let llm_base = get_config_tx(&mut tx, tenant_id, "llm_base_url")
            .await
            .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
        let llm_model = get_config_tx(&mut tx, tenant_id, "llm_model")
            .await
            .unwrap_or_default();
        broadcast_engine_progress(
            telemetry_tx.as_ref(),
            "discovery",
            "[Spider-Sense] Initial crawl + Archival + AI path prediction...",
            Some(cid.as_str()),
        wr,
        );
        tx.commit().await?;
        if let Some(edge_meta) = crate::edge_swarm_intel::resolve_edge_swarm_for_target(
            app_pool.as_ref().clone(),
            tenant_id,
            &target_list[0],
            &llm_base,
            llm_model.as_str(),
            Some(tenant_id),
        )
        .await
        {
            tracing::info!(
                target: "edge_swarm",
                tenant_id,
                client_id = %cid,
                edge = %serde_json::to_string(&edge_meta).unwrap_or_default(),
                "smart proximity edge assignment (orchestrator)"
            );
        }
        discovery_engine::run_spider_crawl(
            &target_list,
            Some(&stealth_config),
            &mut discovery_ctx.paths,
            &mut discovery_ctx.paths_403,
        )
        .await;
        let archival_paths =
            archival_engine::run_archival_discovery(&target, Some(&stealth_config)).await;
        discovery_ctx.merge_paths(archival_paths);
        let predicted = discovery_engine::predict_paths_llm(
            &discovery_ctx.all_paths(),
            &llm_base,
            &llm_model,
            Some(tenant_id),
        )
        .await;
        discovery_ctx.merge_paths(predicted);
        tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
        let mut discovered_paths: Vec<String> = discovery_ctx.all_paths();
        eprintln!(
            "[Weissman][Orchestrator] Discovery (initial): {} paths, {} 403 (target for BOLA/fuzz)",
            discovery_ctx.path_count(),
            discovery_ctx.paths_403.len()
        );

        if client_industrial_ot_enabled(client_configs.as_str()) {
            broadcast_engine_progress(
                telemetry_tx.as_ref(),
                "ot_ics",
                "[OT/ICS] Passive fingerprint (Modbus / EtherNet-IP / S7) — short timeouts, bounded IP concurrency, one probe at a time per host…",
                Some(cid.as_str()),
            wr,
            );
            const MAX_OT_HOSTS: usize = 64;
            let hosts = crate::ot_ics_engine::resolve_scan_hosts(
                domains_json.as_str(),
                ip_ranges_json.as_str(),
                MAX_OT_HOSTS,
            );
            tx.commit().await?;
            let fps = if hosts.is_empty() {
                Vec::new()
            } else {
                crate::ot_ics_engine::scan_hosts_passive(&hosts).await
            };
            tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
            let _ = sqlx::query(
                "DELETE FROM ot_ics_fingerprints WHERE tenant_id = $1 AND client_id = $2",
            )
            .bind(tenant_id)
            .bind(db_client_id)
            .execute(&mut *tx)
            .await;
            for fp in fps.clone() {
                let meta = sqlx::types::Json(&fp.metadata);
                let _ = sqlx::query(
                    r#"INSERT INTO ot_ics_fingerprints (tenant_id, client_id, host, port, protocol, vendor_hint, confidence, raw_excerpt_hex, metadata)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
                )
                .bind(tenant_id)
                .bind(db_client_id)
                .bind(&fp.host)
                .bind(i32::from(fp.port))
                .bind(&fp.protocol)
                .bind(&fp.vendor_hint)
                .bind(f64::from(fp.confidence))
                .bind(&fp.raw_excerpt_hex)
                .bind(meta)
                .execute(&mut *tx)
                .await;
            }
            broadcast_engine_progress(
                telemetry_tx.as_ref(),
                "ot_ics",
                &format!("[OT/ICS] Stored {} fingerprint(s).", fps.len()),
                Some(cid.as_str()),
            wr,
            );
        }

        let mut client_findings_context: Vec<String> = Vec::new();
        let mut client_findings_count = 0usize;
        for source in client_engines.clone() {
            stealth_engine::apply_behavioral_jitter();
            let label = engine_display_label(source.as_str());
            broadcast_engine_progress(
                telemetry_tx.as_ref(),
                source.as_str(),
                &format!("[{}] Scanning...", label),
                Some(cid.as_str()),
            wr,
            );
            let (result, semantic_log) = match source.as_str() {
                "osint" => {
                    tx.commit().await?;
                    let r = osint_engine::run_osint_result(&target, Some(&stealth_config)).await;
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    for sub in pipeline_context::subdomains_from_osint_findings(&r.findings) {
                        let u = format!("https://{}", sub);
                        if !target_list.contains(&u) {
                            target_list.push(u);
                            broadcast_new_target(telemetry_tx.as_ref(), &cid, &sub, wr);
                        }
                    }
                    (r, None)
                }
                "asm" => {
                    tx.commit().await?;
                    let ports_slice = asm_ports.as_deref().unwrap_or(&[]);
                    let r = asm_engine::run_asm_result_with_ports_and_subdomains(
                        &target,
                        ports_slice,
                        recon_subdomains.clone(),
                        Some(&stealth_config),
                    )
                    .await;
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    let open_ports = pipeline_context::open_ports_from_asm_findings(&r.findings);
                    let web_bases = pipeline_context::web_bases_for_host(&target, &open_ports);
                    for w in &web_bases {
                        if !target_list.contains(w) {
                            target_list.push(w.clone());
                            let host = w
                                .trim_start_matches("https://")
                                .trim_start_matches("http://")
                                .split('/')
                                .next()
                                .unwrap_or(w);
                            broadcast_new_target(telemetry_tx.as_ref(), &cid, host, wr);
                        }
                    }
                    discovery_ctx.merge_paths(pipeline_context::wordlist_for_tech_stack(
                        &pipeline_context::tech_stack_from_asm_findings(&r.findings),
                    ));
                    let llm_base = get_config_tx(&mut tx, tenant_id, "llm_base_url")
                        .await
                        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
                    let llm_model = get_config_tx(&mut tx, tenant_id, "llm_model")
                        .await
                        .unwrap_or_default();
                    broadcast_engine_progress(
                        telemetry_tx.as_ref(),
                        "discovery",
                        "[Spider-Sense] Crawling + Archival + AI prediction...",
                        Some(cid.as_str()),
                    wr,
                    );
                    tx.commit().await?;
                    discovery_engine::run_spider_crawl(
                        &target_list,
                        Some(&stealth_config),
                        &mut discovery_ctx.paths,
                        &mut discovery_ctx.paths_403,
                    )
                    .await;
                    let archival_paths =
                        archival_engine::run_archival_discovery(&target, Some(&stealth_config))
                            .await;
                    discovery_ctx.merge_paths(archival_paths);
                    let predicted = discovery_engine::predict_paths_llm(
                        &discovery_ctx.all_paths(),
                        &llm_base,
                        &llm_model,
                        Some(tenant_id),
                    )
                    .await;
                    discovery_ctx.merge_paths(predicted);
                    let graphql_paths = discovery_engine::run_graphql_introspection(
                        &target_list,
                        Some(&stealth_config),
                    )
                    .await;
                    discovery_ctx.merge_paths(graphql_paths);
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    discovered_paths = discovery_ctx.all_paths();
                    eprintln!(
                        "[Weissman][Orchestrator] Discovery: {} paths ({} 403 for BOLA/fuzz)",
                        discovery_ctx.path_count(),
                        discovery_ctx.paths_403.len()
                    );
                    discovery_ui_snapshot::publish(
                        app_pool.as_ref().clone(),
                        tenant_id,
                        db_client_id,
                        name.as_str(),
                        target.as_str(),
                        target_list.len(),
                        discovered_paths.len(),
                    )
                    .await;
                    if client_auto_harvest_enabled(client_configs.as_str())
                        && !discovered_paths.is_empty()
                    {
                        let llm_base_h = get_config_tx(&mut tx, tenant_id, "llm_base_url").await;
                        let llm_model_h = get_config_tx(&mut tx, tenant_id, "llm_model").await;
                        tx.commit().await?;
                        let (harvested, harvest_findings) = engine_identity_autoharvest(
                            target_list.clone(),
                            discovered_paths.clone(),
                            llm_base_h,
                            llm_model_h,
                            Some(tenant_id),
                        )
                        .await;
                        tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                        for h in harvested.clone() {
                            if let Ok(Some(ctx_id)) = sqlx::query_scalar::<_, i64>(
                                r#"INSERT INTO identity_contexts (tenant_id, client_id, role_name, privilege_order, token_type, token_value)
                                   VALUES ($1, $2, $3, 999, $4, $5) RETURNING id"#,
                            )
                            .bind(tenant_id)
                            .bind(db_client_id)
                            .bind(&h.role_name)
                            .bind(&h.token_type)
                            .bind(&h.token_value)
                            .fetch_optional(&mut *tx)
                            .await
                            {
                                broadcast_harvested_token(telemetry_tx.as_ref(), &cid, &h.role_name, ctx_id, wr);
                            }
                        }
                        for i in 0..harvest_findings.len() {
                            let f = harvest_findings[i].clone();
                            let title: String = f
                                .get("title")
                                .and_then(Value::as_str)
                                .unwrap_or("Zero-to-Admin Privilege Escalation")
                                .to_string();
                            let poc: String = f
                                .get("poc_exploit")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            let desc: String = f
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            let fid = format!("identity_auto_harvest-{}-{}", run_id, i);
                            if sqlx::query(
                                r#"INSERT INTO vulnerabilities (run_id, tenant_id, client_id, finding_id, title, severity, source, description, status, poc_exploit, discovered_at)
                                   VALUES ($1, $2, $3, $4, $5, 'critical', 'identity_auto_harvest', $6, 'OPEN', $7, now())"#,
                            )
                            .bind(run_id)
                            .bind(tenant_id)
                            .bind(db_client_id)
                            .bind(&fid)
                            .bind(&title)
                            .bind(&desc)
                            .bind(&poc)
                            .execute(&mut *tx)
                            .await
                            .is_ok()
                            {
                                total_findings += 1;
                                notifications::spawn_critical_poe_alert(
                                    Arc::clone(&app_pool),
                                    tenant_id,
                                    &cid,
                                    &fid,
                                    title.as_str(),
                                    "critical",
                                    poc.as_str(),
                                );
                            }
                        }
                        identity_contexts = load_identity_contexts(&mut tx, db_client_id).await;
                        if !harvested.is_empty() {
                            broadcast_engine_progress(
                                telemetry_tx.as_ref(),
                                "identity_auto_harvest",
                                &format!(
                                    "[Auto-Harvest] {} token(s) harvested; High-Privilege slot updated",
                                    harvested.len()
                                ),
                                Some(cid.as_str()),
                                wr,
                            );
                        }
                    }
                    (r, None)
                }
                "supply_chain" => {
                    tx.commit().await?;
                    let r = supply_chain_engine::run_supply_chain_result(
                        &target,
                        Some(&stealth_config),
                    )
                    .await;
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    (r, None)
                }
                "leak_hunter" => {
                    let github_token = get_config_tx(&mut tx, tenant_id, "github_token")
                        .await
                        .unwrap_or_default();
                    tx.commit().await?;
                    let r = engine_leak_hunter(target_list.clone(), stealth_config.clone()).await;
                    let mut all_findings = r.findings.clone();
                    if !github_token.is_empty() {
                        let domain = target.split('/').nth(2).unwrap_or(&target);
                        let gh_findings =
                            leak_hunter_engine::github_leak_search(domain, Some(&github_token))
                                .await;
                        all_findings.extend(gh_findings);
                    }
                    let r = crate::engine_result::EngineResult::ok(all_findings, r.message);
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    (r, None)
                }
                "bola_idor" => {
                    tx.commit().await?;
                    let mut r = engine_bola_multi(
                        target_list.clone(),
                        discovered_paths.clone(),
                        stealth_config.clone(),
                        if identity_contexts.len() >= 2 {
                            Some(identity_contexts.to_vec())
                        } else {
                            None
                        },
                        Some(tenant_id),
                    )
                    .await;
                    let mut kill_chain: Vec<identity_engine::KillChainEvent> = Vec::new();
                    for f in &r.findings {
                        if f.get("subtype").and_then(Value::as_str) != Some("shadow_cross_auth") {
                            continue;
                        }
                        kill_chain.push(identity_engine::KillChainEvent {
                            from_context: f
                                .get("from_context")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                            to_context: f
                                .get("to_context")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                            method: f
                                .get("method")
                                .and_then(Value::as_str)
                                .unwrap_or("GET")
                                .to_string(),
                            url: f
                                .get("url")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                            request_headers_body:
                                "BOLA shadow matrix: cross-context sensitive body overlap"
                                    .to_string(),
                            response_status: f
                                .get("response_status")
                                .and_then(|x| x.as_u64())
                                .unwrap_or(0) as u16,
                        });
                    }
                    if !identity_contexts.is_empty() {
                        let jwt_result =
                            identity_engine::run_jwt_cryptanalysis(&identity_contexts);
                        for f in jwt_result.findings {
                            r.findings.push(f);
                        }
                    }
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    for (step, ev) in kill_chain.clone().into_iter().enumerate() {
                        let _ = sqlx::query(
                            r#"INSERT INTO privilege_escalation_events (tenant_id, run_id, client_id, from_context, to_context, method, url, request_headers_body, response_status, severity, kill_chain_step_order)
                               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'critical', $10)"#,
                        )
                        .bind(tenant_id)
                        .bind(run_id)
                        .bind(db_client_id)
                        .bind(&ev.from_context)
                        .bind(&ev.to_context)
                        .bind(&ev.method)
                        .bind(&ev.url)
                        .bind(ev.request_headers_body.as_str())
                        .bind(Some(i32::from(ev.response_status)))
                        .bind(step as i32)
                        .execute(&mut *tx)
                        .await;
                    }
                    if !kill_chain.is_empty() {
                        broadcast_engine_progress(
                            telemetry_tx.as_ref(),
                            "identity_shadow",
                            &format!(
                                "[Identity] {} privilege escalation event(s) from BOLA shadow matrix",
                                kill_chain.len()
                            ),
                            Some(cid.as_str()),
                        wr,
                        );
                    }
                    (r, None)
                }
                "llm_path_fuzz" => {
                    tx.commit().await?;
                    let llm_base_trim = semantic_config.llm_base_url.trim();
                    let llm_base_owned = if llm_base_trim.is_empty() {
                        "http://127.0.0.1:8000/v1".to_string()
                    } else {
                        llm_base_trim.to_string()
                    };
                    let r = engine_llm_path_fuzz_multi(
                        target_list.clone(),
                        discovered_paths.clone(),
                        stealth_config.clone(),
                        llm_base_owned,
                        semantic_config.llm_model.clone(),
                        Some(tenant_id),
                    )
                    .await
                    .into();
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    (r, None)
                }
                "semantic_ai_fuzz" => {
                    tx.commit().await?;
                    let sem = engine_semantic(
                        target.clone(),
                        stealth_config.clone(),
                        semantic_config.clone(),
                        discovered_paths.clone(),
                        Some(tenant_id),
                    )
                    .await;
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    let log = if sem.reasoning_log.is_empty() {
                        None
                    } else {
                        Some(sem.reasoning_log)
                    };
                    (sem.result, log)
                }
                "microsecond_timing" => {
                    tx.commit().await?;
                    let timing_urls: Vec<String> = target_list
                        .iter()
                        .flat_map(|b| {
                            discovered_paths.iter().take(12).map(move |p| {
                                let b = b.trim_end_matches('/');
                                let p = p.trim();
                                if p.is_empty() || p == "/" {
                                    b.to_string()
                                } else {
                                    format!("{}/{}", b, p.trim_start_matches('/'))
                                }
                            })
                        })
                        .take(80)
                        .collect();
                    let urls_for_timing = if timing_urls.is_empty() {
                        vec![target_list
                            .first()
                            .cloned()
                            .unwrap_or_else(|| target.clone())]
                    } else {
                        timing_urls
                    };
                    let r = timing_engine::run_timing_attack_urls(
                        &urls_for_timing,
                        Some(&stealth_config),
                        &timing_config,
                        None,
                    )
                    .await;
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    (r, None)
                }
                "ai_adversarial_redteam" => {
                    tx.commit().await?;
                    let r = ai_redteam_engine::run_ai_redteam_attack(
                        &target,
                        Some(&stealth_config),
                        &ai_redteam_config,
                        None,
                        Some(tenant_id),
                    )
                    .await;
                    tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                    (r, None)
                }
                _ => continue,
            };
            broadcast_engine_progress(
                telemetry_tx.as_ref(),
                source.as_str(),
                &format!("[{}] Done.", label),
                Some(cid.as_str()),
            wr,
            );
            if source.as_str() == "llm_path_fuzz" || source.as_str() == "semantic_ai_fuzz" {
                let mut text = String::new();
                for f in &result.findings {
                    if let Some(t) = f.get("title").and_then(Value::as_str) {
                        text.push_str(t);
                    }
                    if let Some(d) = f.get("description").and_then(Value::as_str) {
                        text.push_str(d);
                    }
                    if let Some(m) = f.get("message").and_then(Value::as_str) {
                        text.push_str(m);
                    }
                }
                let lower = text.to_lowercase();
                let classic_crash = lower.contains("500")
                    || lower.contains("timeout")
                    || lower.contains("crash")
                    || lower.contains("502")
                    || lower.contains("503");
                let heuristic_trigger = lower.contains("memory leak")
                    || lower.contains("silent")
                    || lower.contains("sql state")
                    || lower.contains("ora-")
                    || lower.contains("stack trace")
                    || lower.contains("exception in thread")
                    || lower.contains("syntax error")
                    || (lower.contains("200")
                        && (lower.contains("elapsed")
                            || lower.contains("5x")
                            || lower.contains("entropy")));
                let any_anomaly = !result.findings.is_empty();
                if classic_crash || heuristic_trigger || any_anomaly {
                    client_had_crash = true;
                    eprintln!("[Weissman][Orchestrator] Crash/heuristic/anomaly from {} for client {} (findings={}) — will run PoE synthesis.", source, cid, result.findings.len());
                }
            }
            if let Some(log) = semantic_log {
                let _ = sqlx::query(
                    "INSERT INTO semantic_fuzz_log (tenant_id, client_id, run_id, log_text) VALUES ($1, $2, $3, $4)",
                )
                .bind(tenant_id)
                .bind(db_client_id)
                .bind(run_id)
                .bind(log)
                .execute(&mut *tx)
                .await;
            }
            for i in 0..result.findings.len() {
                let f = result.findings[i].clone();
                if let Some(obj) = f.as_object() {
                    let (title, severity) = finding_title_and_severity(obj);
                    let fid = format!("{}-{}-{}", source, run_id, i);
                    let desc = finding_description(obj);
                    let poc = infer_poc_exploit(obj, &target);
                    client_findings_context.push(format!(
                        "[{}] {}: {}",
                        source,
                        title,
                        desc.chars().take(250).collect::<String>()
                    ));
                    if sqlx::query(
                        r#"INSERT INTO vulnerabilities (run_id, tenant_id, client_id, finding_id, title, severity, source, description, status, poc_exploit, discovered_at)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'OPEN', $9, now())"#,
                    )
                    .bind(run_id)
                    .bind(tenant_id)
                    .bind(db_client_id)
                    .bind(&fid)
                    .bind(&title)
                    .bind(&severity)
                    .bind(source.as_str())
                    .bind(&desc)
                    .bind(&poc)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                    {
                        eprintln!("[Weissman][Orchestrator] Insert vuln failed");
                    } else {
                        total_findings += 1;
                        client_findings_count += 1;
                        broadcast_finding_created(
                            telemetry_tx.as_ref(),
                            &cid,
                            &fid,
                            &title,
                            &severity,
                            &desc,
                            &poc,
                            wr,
                        );
                        notifications::spawn_critical_poe_alert(
                            Arc::clone(&app_pool),
                            tenant_id,
                            &cid,
                            &fid,
                            &title,
                            &severity,
                            &poc,
                        );
                    }
                }
            }
            // Module 3: persist Attack Surface Graph nodes/edges for ASM
            if source == "asm" {
                if let (Some(ref nodes), Some(ref edges)) =
                    (&result.graph_nodes, &result.graph_edges)
                {
                    for n in nodes.clone() {
                        let raw_json = n
                            .raw_finding
                            .as_ref()
                            .and_then(|v| serde_json::to_string(v).ok())
                            .unwrap_or_default();
                        let _ = sqlx::query(
                            r#"INSERT INTO asm_graph_nodes (tenant_id, run_id, client_id, node_id, label, node_type, status, cname_target, raw_finding)
                               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
                        )
                        .bind(tenant_id)
                        .bind(run_id)
                        .bind(db_client_id)
                        .bind(&n.id)
                        .bind(&n.label)
                        .bind(&n.node_type)
                        .bind(&n.status)
                        .bind(n.cname_target.as_deref())
                        .bind(&raw_json)
                        .execute(&mut *tx)
                        .await;
                    }
                    for e in edges.clone() {
                        let _ = sqlx::query(
                            r#"INSERT INTO asm_graph_edges (tenant_id, run_id, client_id, from_id, to_id, edge_type)
                               VALUES ($1, $2, $3, $4, $5, $6)"#,
                        )
                        .bind(tenant_id)
                        .bind(run_id)
                        .bind(db_client_id)
                        .bind(&e.from_id)
                        .bind(&e.to_id)
                        .bind(&e.edge_type)
                        .execute(&mut *tx)
                        .await;
                    }
                    eprintln!(
                        "[Weissman][Orchestrator] ASM graph: {} nodes, {} edges for client {}",
                        nodes.len(),
                        edges.len(),
                        cid
                    );
                }
            }
            run_max_targets = run_max_targets.max(target_list.len());
            run_max_paths = run_max_paths.max(discovered_paths.len());
            if source.as_str() == "asm" {
                broadcast_pipeline_stage(
                    telemetry_tx.as_ref(),
                    run_id,
                    &cid,
                    dag_pipeline::STAGE_DEEP_DISCOVERY,
                    "completed",
                wr,
                );
                let _ = pipeline_set_stage(
                    &mut tx,
                    tenant_id,
                    run_id,
                    &cid,
                    dag_pipeline::STAGE_VULN_SCANNING,
                )
                .await;
                broadcast_pipeline_stage(
                    telemetry_tx.as_ref(),
                    run_id,
                    &cid,
                    dag_pipeline::STAGE_VULN_SCANNING,
                    "started",
                wr,
                );
            }
            if global_safe_mode {
                tx.commit().await?;
                tokio::time::sleep(Duration::from_millis(2500)).await;
                tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
            }
        }
        broadcast_pipeline_stage(
            telemetry_tx.as_ref(),
            run_id,
            &cid,
            dag_pipeline::STAGE_VULN_SCANNING,
            "completed",
        wr,
        );
        let _ = pipeline_set_stage(
            &mut tx,
            tenant_id,
            run_id,
            &cid,
            dag_pipeline::STAGE_KILL_SHOT,
        )
        .await;
        let run_poe = client_had_crash || client_findings_count > 0;
        if run_poe {
            broadcast_pipeline_stage(
                telemetry_tx.as_ref(),
                run_id,
                &cid,
                dag_pipeline::STAGE_KILL_SHOT,
                "started",
            wr,
            );
            let roe_weaponized = client_roe_weaponized(client_configs.as_str());
            let poe_config_for_client = if roe_weaponized {
                let mut c = poe_config.clone();
                c.safety_rails_no_shells = false;
                c
            } else {
                poe_config.clone()
            };
            let mut poe_ctx: String = client_findings_context.join("\n");
            if client_findings_count > 0 {
                let llm_base = get_config_tx(&mut tx, tenant_id, "llm_base_url")
                    .await
                    .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
                let llm_model = get_config_tx(&mut tx, tenant_id, "llm_model")
                    .await
                    .unwrap_or_default();
                tx.commit().await?;
                let circuit_llm = Arc::clone(&resilience::ResilienceRegistry::default().llm);
                let chain_result = resilience::with_retry_circuit(
                    &circuit_llm,
                    "strategic_analyzer",
                    2,
                    || async {
                        strategic_analyzer::synthesize_attack_chain(
                            &poe_ctx,
                            &target,
                            &llm_base,
                            &llm_model,
                            Some(tenant_id),
                        )
                        .await
                        .ok_or_else(|| "LLM returned no chain".to_string())
                    },
                )
                .await;
                tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
                if let Ok(c) = chain_result {
                    poe_ctx.push_str("\n\n[StrategicAnalyzer Attack Chain]\n");
                    poe_ctx.push_str(&c);
                    for (step_order, step_label, payload_or_action) in parse_attack_chain_steps(&c)
                    {
                        let _ = sqlx::query(
                            r#"INSERT INTO attack_chain (tenant_id, run_id, client_id, step_order, step_label, payload_or_action)
                               VALUES ($1, $2, $3, $4, $5, $6)"#,
                        )
                        .bind(tenant_id)
                        .bind(run_id)
                        .bind(db_client_id)
                        .bind(step_order as i32)
                        .bind(&step_label)
                        .bind(&payload_or_action)
                        .execute(&mut *tx)
                        .await;
                    }
                    eprintln!(
                        "[Weissman][Orchestrator] Attack chain stored for client {} run {}",
                        cid, run_id
                    );
                } else if let Err(e) = chain_result {
                    broadcast_engine_error(
                        telemetry_tx.as_ref(),
                        "strategic_analyzer",
                        &e,
                        Some(cid.as_str()),
                    wr,
                    );
                }
            }
            let poe_ctx_final: Option<String> = if poe_ctx.is_empty() {
                None
            } else {
                Some(poe_ctx)
            };
            broadcast_engine_progress(
                telemetry_tx.as_ref(),
                "poe_synthesis",
                &format!(
                    "[PoE Synthesis] Started ({} findings + attack chain).",
                    client_findings_count
                ),
                Some(cid.as_str()),
            wr,
            );
            tx.commit().await?;
            let poe_result = exploit_synthesis_engine::run_exploit_synthesis_async(
                &target,
                &poe_config_for_client,
                None,
                poe_ctx_final.as_deref(),
                Some(tenant_id),
            )
            .await;
            tx = crate::db::begin_tenant_tx_arc(app_pool.clone(), tenant_id).await?;
            for i in 0..poe_result.findings.len() {
                let f = poe_result.findings[i].clone();
                if let Some(obj) = f.as_object() {
                    let (title, severity) = finding_title_and_severity(obj);
                    let fid = format!("poe_synthesis-{}-{}", run_id, i);
                    let remediation_snippet = obj
                        .get("remediation_snippet")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let generated_patch = obj
                        .get("generated_patch")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let desc_json = serde_json::json!({
                        "footprint": obj.get("footprint").and_then(Value::as_str).unwrap_or(""),
                        "verified": obj.get("verified").and_then(Value::as_bool).unwrap_or(false),
                        "expected_verification": obj.get("expected_verification").and_then(Value::as_str).unwrap_or(""),
                        "weaponization_status": "SAFE (Proof of Exploitability Only)",
                        "trigger_reason": obj.get("trigger_reason").and_then(Value::as_str).unwrap_or(""),
                        "entropy_score": obj.get("entropy_score").and_then(Value::as_f64),
                        "entropy_map": obj.get("entropy_map").cloned(),
                        "bleed_start_offset": obj.get("bleed_start_offset").and_then(Value::as_u64),
                        "response_bleed_preview": obj.get("response_bleed_preview").and_then(Value::as_str),
                        "remediation_snippet": remediation_snippet.as_str(),
                        "generated_patch": generated_patch.as_str(),
                    });
                    let desc = serde_json::to_string(&desc_json).unwrap_or_default();
                    let poc_exploit = obj
                        .get("poc_exploit")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if sqlx::query(
                        r#"INSERT INTO vulnerabilities (run_id, tenant_id, client_id, finding_id, title, severity, source, description, status, poc_exploit, generated_patch, discovered_at)
                           VALUES ($1, $2, $3, $4, $5, $6, 'poe_synthesis', $7, 'OPEN', $8, $9, now())"#,
                    )
                    .bind(run_id)
                    .bind(tenant_id)
                    .bind(db_client_id)
                    .bind(&fid)
                    .bind(&title)
                    .bind(&severity)
                    .bind(&desc)
                    .bind(&poc_exploit)
                    .bind(&generated_patch)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                    {
                        eprintln!("[Weissman][Orchestrator] Insert PoE vuln failed");
                    } else {
                        total_findings += 1;
                        let mut broadcast_poc = poc_exploit.clone();
                        if crate::exploit_crypto::should_seal_poc(poc_exploit.as_str(), &severity) {
                            if let Some(key) = crate::exploit_crypto::master_key_bytes() {
                                match crate::exploit_crypto::seal_poc(
                                    poc_exploit.as_str(),
                                    &key,
                                    &fid,
                                ) {
                                    Ok(seal) => {
                                        let redacted = "[SEALED — use Command Center «Decrypt Exploit Evidence»]";
                                        if sqlx::query(
                                            r#"UPDATE vulnerabilities SET poc_sealed = true, poc_ciphertext_b64 = $1, poc_nonce_b64 = $2, poc_commitment_sha256 = $3, poc_zkp_hmac = $4, poc_exploit = $5
                                               WHERE run_id = $6 AND tenant_id = $7 AND client_id = $8 AND finding_id = $9"#,
                                        )
                                        .bind(&seal.ciphertext_b64)
                                        .bind(&seal.nonce_b64)
                                        .bind(&seal.commitment_sha256_hex)
                                        .bind(&seal.zkp_hmac_hex)
                                        .bind(redacted)
                                        .bind(run_id)
                                        .bind(tenant_id)
                                        .bind(db_client_id)
                                        .bind(&fid)
                                        .execute(&mut *tx)
                                        .await
                                        .is_ok()
                                        {
                                            broadcast_poc = redacted.to_string();
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[Weissman][Orchestrator] seal_poc: {}", e);
                                    }
                                }
                            }
                        }
                        broadcast_finding_created(
                            telemetry_tx.as_ref(),
                            &cid,
                            &fid,
                            &title,
                            &severity,
                            &desc,
                            &broadcast_poc,
                            wr,
                        );
                        notifications::spawn_critical_poe_alert(
                            Arc::clone(&app_pool),
                            tenant_id,
                            &cid,
                            &fid,
                            &title,
                            &severity,
                            &broadcast_poc,
                        );
                    }
                }
            }
            broadcast_pipeline_stage(
                telemetry_tx.as_ref(),
                run_id,
                &cid,
                dag_pipeline::STAGE_KILL_SHOT,
                "completed",
            wr,
            );
            let _ = pipeline_set_stage(
                &mut tx,
                tenant_id,
                run_id,
                &cid,
                dag_pipeline::STAGE_COMPLIANCE,
            )
            .await;
        } else {
            let _ = pipeline_set_stage(
                &mut tx,
                tenant_id,
                run_id,
                &cid,
                dag_pipeline::STAGE_COMPLIANCE,
            )
            .await;
        }
    }
    broadcast_pipeline_stage(
        telemetry_tx.as_ref(),
        run_id,
        dag_pipeline::GLOBAL_SCOPE_ID,
        dag_pipeline::STAGE_COMPLIANCE,
        "started",
    wr,
    );
    let summary = serde_json::json!({
        "by_severity": {},
        "total": total_findings,
        "run_at": now,
        "attack_surface_targets": run_max_targets,
        "attack_surface_paths": run_max_paths.max(1)
    })
    .to_string();
    let _ = sqlx::query(
        "UPDATE report_runs SET findings_json = $1, summary = $2 WHERE id = $3 AND tenant_id = $4",
    )
    .bind(serde_json::json!([]).to_string())
    .bind(&summary)
    .bind(run_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await;

    let audit_raw = sqlx::query(
        r#"SELECT id, run_id, client_id, finding_id, title, severity, source, COALESCE(description,''), status, discovered_at
           FROM vulnerabilities WHERE run_id = $1 AND tenant_id = $2 ORDER BY id"#,
    )
    .bind(run_id)
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let audit_rows: Vec<crypto_engine::AuditFindingRow> = audit_raw
        .into_iter()
        .filter_map(|r| {
            let disc: DateTime<Utc> = r.try_get("discovered_at").ok()?;
            Some(crypto_engine::AuditFindingRow {
                id: r.try_get("id").ok()?,
                run_id: r.try_get("run_id").ok()?,
                client_id: r.try_get::<i64, _>("client_id").ok()?.to_string(),
                finding_id: r.try_get("finding_id").ok()?,
                title: r.try_get("title").ok()?,
                severity: r.try_get("severity").ok()?,
                source: r.try_get("source").ok()?,
                description: r.try_get::<String, _>("description").ok()?,
                status: r.try_get("status").ok()?,
                discovered_at: disc.format("%Y-%m-%d %H:%M:%S").to_string(),
            })
        })
        .collect();
    let audit_root_hash = crypto_engine::compute_audit_root_hash(&audit_rows);
    let _ =
        sqlx::query("UPDATE report_runs SET audit_root_hash = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(&audit_root_hash)
            .bind(run_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await;
    broadcast_pipeline_stage(
        telemetry_tx.as_ref(),
        run_id,
        dag_pipeline::GLOBAL_SCOPE_ID,
        dag_pipeline::STAGE_COMPLIANCE,
        "completed",
    wr,
    );
    eprintln!(
        "[Weissman][Orchestrator] Cycle done tenant={} run_id={} findings={} audit_root_hash={}",
        tenant_id,
        run_id,
        total_findings,
        &audit_root_hash[..audit_root_hash.len().min(16)]
    );
    tx.commit().await?;
    Ok(())
}

/// Spawn the orchestrator as a native Tokio task (no spawn_blocking). Pure async root.
/// telemetry_tx: when Some, progress for each engine is broadcast so all Engine Cards show live status.
pub fn spawn_orchestrator(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    telemetry_tx: Option<Arc<broadcast::Sender<String>>>,
) {
    tokio::spawn(async move {
        let interval_secs: u64 = sqlx::query_scalar::<_, String>(
            r#"SELECT sc.value FROM system_configs sc
               INNER JOIN tenants t ON t.id = sc.tenant_id
               WHERE t.slug = 'default' AND sc.key = 'scan_interval_secs'
               LIMIT 1"#,
        )
        .fetch_optional(auth_pool.as_ref())
        .await
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await;
        loop {
            interval.tick().await;
            if is_scanning_active() {
                let Some(permit) = crate::scan_concurrency::try_acquire_full_scan_permit() else {
                    metrics::counter!("weissman_orchestrator_tick_deferred_total", "reason" => "scan_slots_busy").increment(1);
                    continue;
                };
                let _permit = permit;
                let ap = app_pool.clone();
                let ip = intel_pool.clone();
                let au = auth_pool.clone();
                let tt = telemetry_tx.clone();
                match crate::panic_shield::catch_unwind_future(
                    "scheduled_multi_tenant_cycle",
                    async move {
                        run_cycle_async(ap, ip, au, tt).await;
                    },
                )
                .await
                {
                    crate::panic_shield::CatchOutcome::Completed(()) => {}
                    crate::panic_shield::CatchOutcome::Panicked { message, .. } => {
                        eprintln!(
                            "[Weissman][Orchestrator] Scheduled multi-tenant cycle panicked: {}",
                            message
                        );
                    }
                    crate::panic_shield::CatchOutcome::CircuitOpen {
                        cooldown_remaining_secs,
                    } => {
                        eprintln!(
                            "[Weissman][Orchestrator] Scheduled cycle skipped: panic circuit open ({}s)",
                            cooldown_remaining_secs
                        );
                    }
                }
            }
        }
    });
    eprintln!("[Weissman][Orchestrator] Pure async loop started (interval from system_configs, default 60s).");
}

/// API / UI: bounded concurrency + panic isolation around a single-tenant enterprise cycle.
pub fn spawn_single_tenant_full_scan(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    tenant_id: i64,
    telemetry: Option<Arc<broadcast::Sender<String>>>,
) {
    tokio::spawn(async move {
        let Ok(permit) = crate::scan_concurrency::acquire_full_scan_permit().await else {
            metrics::counter!("weissman_scan_rejected_total", "reason" => "concurrency_timeout").increment(1);
            return;
        };
        let _permit = permit;
        let fut = async move {
            run_single_tenant_scan_cycle(
                app_pool,
                intel_pool,
                tenant_id,
                telemetry,
                None,
            )
            .await
        };
        match crate::panic_shield::catch_unwind_future("single_tenant_full_scan", fut).await {
            crate::panic_shield::CatchOutcome::Completed(Ok(())) => {}
            crate::panic_shield::CatchOutcome::Completed(Err(e)) => {
                eprintln!(
                    "[Weissman][ScanJob] tenant {} cycle db/sqlx error: {}",
                    tenant_id, e
                );
            }
            crate::panic_shield::CatchOutcome::Panicked { message, .. } => {
                eprintln!(
                    "[Weissman][ScanJob] tenant {} cycle panicked: {}",
                    tenant_id, message
                );
            }
            crate::panic_shield::CatchOutcome::CircuitOpen {
                cooldown_remaining_secs,
            } => {
                eprintln!(
                    "[Weissman][ScanJob] tenant {} cycle skipped: panic circuit open ({}s)",
                    tenant_id, cooldown_remaining_secs
                );
            }
        }
    });
}
