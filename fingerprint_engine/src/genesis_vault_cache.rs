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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cache_key_trims_and_lowercases() {
        assert_eq!(cache_key(5, "  Apache  "), "5:apache");
        assert_eq!(cache_key(0, "NginX"), "0:nginx");
        assert_eq!(cache_key(-1, "x"), "-1:x");
    }

    #[test]
    fn put_appends_and_get_normalizes_lookup() {
        // Unique tenant id keeps this isolated from other tests sharing the global cache.
        let tid = 990_001;
        assert!(vault_cache_get(tid, "wp").is_none());
        vault_cache_put(tid, "WP", json!({ "a": 1 }));
        vault_cache_put(tid, "wp", json!({ "a": 2 }));
        let got = vault_cache_get(tid, "  Wp ").expect("expected cached rows");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], json!({ "a": 1 }));
        assert_eq!(got[1], json!({ "a": 2 }));
    }

    #[test]
    fn replace_overwrites_existing_rows() {
        let tid = 990_002;
        vault_cache_put(tid, "app", json!({ "x": 1 }));
        vault_cache_replace(tid, "app", vec![json!({ "y": 9 })]);
        assert_eq!(
            vault_cache_get(tid, "app"),
            Some(vec![json!({ "y": 9 })])
        );
    }

    #[test]
    fn clear_tenant_only_removes_matching_tenant() {
        let tid = 990_003;
        let other = 990_004;
        vault_cache_put(tid, "a", json!(1));
        vault_cache_put(other, "a", json!(2));
        vault_cache_clear_tenant(tid);
        assert!(vault_cache_get(tid, "a").is_none());
        assert!(vault_cache_get(other, "a").is_some());
    }
}
