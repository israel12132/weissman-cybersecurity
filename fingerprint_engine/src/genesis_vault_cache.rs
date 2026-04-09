//! In-process hot cache for [`genesis_vaccine_vault`] rows (sub-ms reads on match path).
//! Authoritative store remains PostgreSQL; this mirrors inserts/loads for onboarding throughput.

use dashmap::DashMap;
use serde_json::Value;
use std::sync::{Arc, LazyLock};

static VAULT_CACHE: LazyLock<Arc<DashMap<String, Vec<Value>>>> =
    LazyLock::new(|| Arc::new(DashMap::new()));

#[must_use]
pub fn cache_key(tenant_id: i64, tech_fingerprint: &str) -> String {
    format!("{}:{}", tenant_id, tech_fingerprint.trim().to_lowercase())
}

pub fn vault_cache_put(tenant_id: i64, tech_fingerprint: &str, row: Value) {
    let k = cache_key(tenant_id, tech_fingerprint);
    VAULT_CACHE.entry(k).or_default().push(row);
}

/// Replace the full match list (used after DB warm) to avoid duplicate cache rows.
pub fn vault_cache_replace(tenant_id: i64, tech_fingerprint: &str, rows: Vec<Value>) {
    let k = cache_key(tenant_id, tech_fingerprint);
    VAULT_CACHE.insert(k, rows);
}

pub fn vault_cache_get(tenant_id: i64, tech_fingerprint: &str) -> Option<Vec<Value>> {
    let k = cache_key(tenant_id, tech_fingerprint);
    VAULT_CACHE.get(&k).map(|e| e.value().clone())
}

pub fn vault_cache_clear_tenant(tenant_id: i64) {
    let prefix = format!("{}:", tenant_id);
    VAULT_CACHE.retain(|k, _| !k.starts_with(&prefix));
}
