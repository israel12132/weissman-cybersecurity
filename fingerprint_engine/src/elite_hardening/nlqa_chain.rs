//! Ask Weissman audit hash chain (`nlqa1`).
//!
//! Canonical bytes are hashed with SHA-256. The hot Ask path must **not** take
//! a tenant `FOR UPDATE` / advisory lock — enqueue to the background worker
//! which serialises per-tenant appends.

use sha2::{Digest, Sha256};

pub const CHAIN_VERSION: &str = "nlqa1";

/// Canonical payload hashed into `event_hash`. Keep stable for verification.
pub fn canonical_nlqa_payload(
    prev_hash: &str,
    tenant_id: i64,
    user_id: Option<i64>,
    question: &str,
    plan_json: &str,
    compiled_sql: &str,
    rows_returned: i32,
    elapsed_ms: i32,
    error: &str,
    asked_at_rfc3339: &str,
) -> String {
    format!(
        "{CHAIN_VERSION}|{prev_hash}|{tenant_id}|{}|{question}|{plan_json}|{compiled_sql}|{rows_returned}|{elapsed_ms}|{error}|{asked_at_rfc3339}",
        user_id.unwrap_or(0),
    )
}

pub fn event_hash(canonical: &str) -> String {
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_chained() {
        let a = canonical_nlqa_payload(
            "",
            7,
            Some(3),
            "show kev",
            "{}",
            "SELECT 1",
            1,
            12,
            "",
            "2026-08-27T00:00:00+00:00",
        );
        let ha = event_hash(&a);
        assert_eq!(ha.len(), 64);
        let b = canonical_nlqa_payload(
            &ha,
            7,
            Some(3),
            "show kev",
            "{}",
            "SELECT 1",
            1,
            12,
            "",
            "2026-08-27T00:00:00+00:00",
        );
        let hb = event_hash(&b);
        assert_ne!(ha, hb);
        assert!(a.starts_with("nlqa1|"));
    }
}
