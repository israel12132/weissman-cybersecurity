//! God Mode dashboard: engine matrix, default scan interval RPC, discovery snapshot read.

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use weissman_core::models::engine::KNOWN_ENGINE_IDS;

const DISCOVERY_KEY: &str = "orchestrator_discovery_snapshot";

/// Legacy rows still store `ollama_fuzz`; orchestrator + UI use `llm_path_fuzz`.
#[inline]
fn canonical_engine_id(s: &str) -> &str {
    match s.trim() {
        "ollama_fuzz" => "llm_path_fuzz",
        x => x,
    }
}

/// Orchestrator `ALL_ENGINES` — must match `orchestrator/mod.rs`.
const CORE_ENGINES: &[&str] = &[
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

async fn get_config_tx_str(
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
    .filter(|s| !s.trim().is_empty())
}

fn tenant_active_engine_set(json: &str) -> HashSet<String> {
    let json = json.trim();
    if json.is_empty() {
        return CORE_ENGINES.iter().map(|s| (*s).to_string()).collect();
    }
    let arr: Vec<String> = match serde_json::from_str(json) {
        Ok(a) => a,
        _ => return CORE_ENGINES.iter().map(|s| (*s).to_string()).collect(),
    };
    let allowed: HashSet<&str> = CORE_ENGINES.iter().copied().collect();
    arr.into_iter()
        .filter_map(|s| {
            let t = canonical_engine_id(&s).to_string();
            if allowed.contains(t.as_str()) {
                Some(t)
            } else {
                None
            }
        })
        .collect()
}

fn client_enabled_engines(client_configs_json: &str) -> Vec<String> {
    let json = client_configs_json.trim();
    if json.is_empty() {
        return CORE_ENGINES.iter().map(|s| (*s).to_string()).collect();
    }
    let v: Value = match serde_json::from_str(json) {
        Ok(x) => x,
        _ => return CORE_ENGINES.iter().map(|s| (*s).to_string()).collect(),
    };
    let arr = match v.get("enabled_engines").and_then(|a| a.as_array()) {
        Some(a) => a,
        _ => return CORE_ENGINES.iter().map(|s| (*s).to_string()).collect(),
    };
    let allowed: HashSet<&str> = CORE_ENGINES.iter().copied().collect();
    arr.iter()
        .filter_map(|s| s.as_str().map(|x| canonical_engine_id(x).to_string()))
        .filter(|s| allowed.contains(s.as_str()))
        .collect()
}

fn client_has_extra_engine(client_configs_json: &str, engine_id: &str) -> bool {
    let json = client_configs_json.trim();
    if json.is_empty() {
        return false;
    }
    let v: Value = match serde_json::from_str(json) {
        Ok(x) => x,
        _ => return false,
    };
    match v.get("enabled_engines").and_then(|a| a.as_array()) {
        Some(arr) => arr.iter().any(|s| {
            s.as_str()
                .map(|x| canonical_engine_id(x) == engine_id)
                .unwrap_or(false)
        }),
        _ => false,
    }
}

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

/// `scan_interval_secs` row for slug `default` (orchestrator tick), via SECURITY DEFINER RPC.
pub async fn default_scan_interval_secs_get(app_pool: &PgPool) -> u64 {
    let cell: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT public.weissman_default_tenant_scan_interval_get()",
    )
    .fetch_one(app_pool)
    .await
    .ok()
    .flatten();
    cell.and_then(|x| x.parse().ok()).unwrap_or(60).clamp(10, 86_400)
}

pub async fn default_scan_interval_secs_set(app_pool: &PgPool, secs: u64) -> Result<(), String> {
    if !(10..=86_400).contains(&secs) {
        return Err("scan_interval_secs must be between 10 and 86400".into());
    }
    sqlx::query("SELECT public.weissman_default_tenant_scan_interval_set($1)")
        .bind(secs.to_string())
        .execute(app_pool)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// `view_tenant_id`: CEO’s tenant (client rows, discovery snapshot).  
/// `policy_tenant_id`: tenant whose `active_engines` drives orchestrator toggles (typically `slug = default`).
pub async fn build_god_mode_snapshot_json(
    pool: &PgPool,
    view_tenant_id: i64,
    policy_tenant_id: i64,
) -> Result<Value, sqlx::Error> {
    let scan_interval_secs = default_scan_interval_secs_get(pool).await;

    let active_raw = {
        let mut tx = crate::db::begin_tenant_tx(pool, policy_tenant_id).await?;
        let raw = get_config_tx_str(&mut tx, policy_tenant_id, "active_engines")
            .await
            .unwrap_or_else(|| {
                r#"["osint","asm","supply_chain","bola_idor","llm_path_fuzz","semantic_ai_fuzz"]"#
                    .to_string()
            });
        let _ = tx.commit().await;
        raw
    };
    let tenant_engine_set = tenant_active_engine_set(&active_raw);

    let mut tx = crate::db::begin_tenant_tx(pool, view_tenant_id).await?;

    let zero_day_tenant = get_config_tx_str(&mut tx, view_tenant_id, "enable_zero_day_probing")
        .await
        .map(|s| s.to_lowercase() == "true" || s == "1")
        .unwrap_or(false);

    let rows = sqlx::query(
        "SELECT COALESCE(NULLIF(trim(client_configs),''),'{}') AS client_configs FROM clients WHERE tenant_id = $1",
    )
    .bind(view_tenant_id)
    .fetch_all(&mut *tx)
    .await?;

    let n_clients = rows.len() as i64;
    let mut per_engine_clients: Vec<Value> = Vec::new();
    for eid in KNOWN_ENGINE_IDS {
        let mut n = 0i64;
        for r in &rows {
            let cfg: String = r.try_get::<String, _>("client_configs").unwrap_or_default();
            let list = client_enabled_engines(&cfg);
            let set: HashSet<_> = list.into_iter().collect();
            if set.contains(*eid) {
                n += 1;
            }
        }
        per_engine_clients.push(json!({
            "id": eid,
            "label": engine_label(eid),
            "tenant_policy_includes": tenant_engine_set.contains(*eid),
            "clients_enabled_count": n,
            "clients_total": n_clients,
        }));
    }

    let mut zero_day_clients = 0i64;
    let mut ot_clients = 0i64;
    for r in &rows {
        let cfg: String = r.try_get::<String, _>("client_configs").unwrap_or_default();
        if client_has_extra_engine(&cfg, "zero_day_radar") {
            zero_day_clients += 1;
        }
        if client_industrial_ot_enabled(&cfg) {
            ot_clients += 1;
        }
    }

    let disc_raw = get_config_tx_str(&mut tx, view_tenant_id, DISCOVERY_KEY).await;
    let _ = tx.commit().await;

    let discovery = disc_raw.and_then(|s| serde_json::from_str::<Value>(&s).ok());

    Ok(json!({
        "scan_interval_secs": scan_interval_secs,
        "engine_matrix": {
            "core_engines": per_engine_clients,
            "zero_day_radar": {
                "tenant_threat_intel_probing_enabled": zero_day_tenant,
                "clients_with_zero_day_radar_engine": zero_day_clients,
                "clients_total": n_clients,
            },
            "ot_ics": {
                "clients_with_industrial_ot_enabled": ot_clients,
                "clients_total": n_clients,
            },
        },
        "discovery": discovery,
        "scanning_active": crate::orchestrator::is_scanning_active(),
    }))
}

fn engine_label(id: &str) -> &'static str {
    match id {
        "osint" => "OSINT",
        "asm" => "ASM",
        "supply_chain" => "Supply chain",
        "leak_hunter" => "Leak hunter",
        "bola_idor" => "BOLA / IDOR",
        "llm_path_fuzz" => "LLM path fuzz",
        "semantic_ai_fuzz" => "Semantic AI fuzz",
        "microsecond_timing" => "Microsecond timing",
        "ai_adversarial_redteam" => "AI adversarial red team",
        _ => "Engine",
    }
}
