//! Tenant integration registry — resolves provider adapters from `integrations_registry`.

use serde_json::Value;
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct IntegrationRecord {
    pub id: String,
    pub provider_type: String,
    pub config: Value,
}

pub async fn load_integrations(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<Vec<IntegrationRecord>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|_| "store_down".to_string())?;
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'integrations_registry'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| "store_down".to_string())?;
    if tx.commit().await.is_err() {
        return Err("store_down".to_string());
    }
    let Some(s) = raw.filter(|x| !x.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    let arr = serde_json::from_str::<Vec<Value>>(&s).map_err(|_| "store_down".to_string())?;
    let out = arr
        .into_iter()
        .filter_map(|item| {
            let id = item.get("id").and_then(Value::as_str)?.to_string();
            let provider_type = item
                .get("type")
                .or_else(|| item.get("provider"))
                .and_then(Value::as_str)
                .unwrap_or(&id)
                .to_ascii_lowercase();
            let config = item
                .get("config")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            let decrypted = super::integrations_vault::decrypt_config(&config);
            Some(IntegrationRecord {
                id,
                provider_type,
                config: decrypted,
            })
        })
        .collect();
    Ok(out)
}

#[must_use]
pub fn pick_provider(
    integrations: &[IntegrationRecord],
    prefer: &[&str],
) -> Option<IntegrationRecord> {
    for key in prefer {
        if let Some(r) = integrations
            .iter()
            .find(|i| i.provider_type == *key || i.id == *key)
        {
            return Some(r.clone());
        }
    }
    integrations.first().cloned()
}

pub fn config_str(config: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = config.get(*key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}
