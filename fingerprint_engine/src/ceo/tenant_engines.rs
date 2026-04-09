//! CEO: toggle `system_configs.active_engines` (tenant-wide orchestrator allow-list).

use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashSet;

/// Orchestrator / God Mode policy tenant (`slug = default`). Used for `active_engines` in production Command Center.
pub async fn default_tenant_id(auth_pool: &PgPool) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
    )
    .fetch_optional(auth_pool)
    .await
}

fn canonical_engine_id(s: &str) -> &str {
    match s.trim() {
        "ollama_fuzz" => "llm_path_fuzz",
        x => x,
    }
}

/// Add or remove one engine id in `active_engines` for this tenant. Returns the new ordered list.
pub async fn patch_tenant_active_engine(
    pool: &PgPool,
    tenant_id: i64,
    engine_id: &str,
    enabled: bool,
) -> Result<Vec<String>, String> {
    let canon = canonical_engine_id(engine_id);
    if !weissman_core::models::engine::is_known_engine_id(canon) {
        return Err(format!("unknown engine_id: {engine_id}"));
    }

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let cur: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'active_engines'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let mut set: HashSet<String> = HashSet::new();
    if let Some(raw) = cur {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            if let Ok(arr) = serde_json::from_str::<Vec<String>>(trimmed) {
                for s in arr {
                    let c = canonical_engine_id(&s).to_string();
                    if weissman_core::models::engine::is_known_engine_id(&c) {
                        set.insert(c);
                    }
                }
            }
        }
    }
    if enabled {
        set.insert(canon.to_string());
    } else {
        set.remove(canon);
    }

    let ordered: Vec<String> = weissman_core::models::engine::KNOWN_ENGINE_IDS
        .iter()
        .filter(|e| set.contains(**e))
        .map(|s| (*s).to_string())
        .collect();

    let json = serde_json::to_string(&ordered).map_err(|e| e.to_string())?;

    sqlx::query(
        r#"INSERT INTO system_configs (tenant_id, key, value, description)
           VALUES ($1, 'active_engines', $2, 'JSON array of engine IDs')
           ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value"#,
    )
    .bind(tenant_id)
    .bind(&json)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(ordered)
}

/// Response shape for PUT/PATCH handler.
pub fn active_engines_json_value(engines: &[String]) -> Value {
    json!({ "ok": true, "active_engines": engines })
}
