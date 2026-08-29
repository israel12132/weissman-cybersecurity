//! Ask Weissman audit hash chain (`nlqa1`).
//!
//! Canonical bytes are hashed with SHA-256. The hot Ask path must **not** take
//! a tenant `FOR UPDATE` / advisory lock — enqueue to the background worker
//! which serialises per-tenant appends.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const CHAIN_VERSION: &str = "nlqa1";

/// Max concurrent nlqa1 DB persists across all tenants. Async tasks wait on
/// this semaphore — they do **not** occupy Tokio worker threads while queued.
/// One noisy tenant therefore cannot starve UEBA / SOAR / scan work.
pub const NLQA_GLOBAL_PERSIST_PERMITS: usize = 4;

/// At most one persist in flight per tenant (hash-chain + advisory lock).
/// Additional events for that tenant stay in the mPSC, then JSON-fallback.
pub const NLQA_TENANT_PERSIST_PERMITS: usize = 1;

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

/// Structured JSON for SIEM / local JSONL when the Ask mPSC cannot accept the row.
/// The HTTP path still never blocks; the event is **not** discarded.
pub fn fallback_audit_json(
    tenant_id: i64,
    user_id: Option<i64>,
    question: &str,
    plan_json: &Value,
    compiled_sql: &str,
    rows_returned: i32,
    elapsed_ms: i32,
    error: &str,
    reason: &str,
) -> Value {
    json!({
        "event": "nlqa1_audit_fallback",
        "compliance": "bank_of_israel_361_audit_trail",
        "reason": reason,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "question": question,
        "plan_json": plan_json,
        "compiled_sql": compiled_sql,
        "rows_returned": rows_returned,
        "elapsed_ms": elapsed_ms,
        "error": error,
        "asked_at": chrono::Utc::now().to_rfc3339(),
    })
}

/// Emit the overflow audit to tracing (Axum/journald → SIEM) and, when configured,
/// append JSONL to a host-local hardened log file. Never silent-drop.
pub fn emit_ask_audit_fallback(payload: &Value, reason: &str) {
    tracing::error!(
        target: "nlqa1_fallback",
        reason = %reason,
        audit_json = %payload,
        "Ask audit channel overflow — JSON fallback for SIEM (event not dropped)"
    );
    if let Some(path) = fallback_log_path() {
        if let Err(e) = append_jsonl(&path, payload) {
            tracing::error!(
                target: "nlqa1_fallback",
                error = %e,
                path = %path.display(),
                "Ask audit fallback file append failed — tracing line above is the surviving copy"
            );
        }
    }
}

fn fallback_log_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("WEISSMAN_NLQA_FALLBACK_LOG") {
        let t = p.trim();
        if !t.is_empty() {
            return Some(PathBuf::from(t));
        }
    }
    let default = PathBuf::from("/var/log/weissman/nlqa1-fallback.jsonl");
    match default.parent() {
        Some(dir) if dir.is_dir() => Some(default),
        _ => None,
    }
}

fn append_jsonl(path: &Path, payload: &Value) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{payload}")?;
    f.flush()
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

    #[test]
    fn fallback_json_is_not_an_empty_drop() {
        let j = fallback_audit_json(
            7,
            Some(3),
            "show kev",
            &serde_json::json!({}),
            "SELECT 1",
            1,
            12,
            "",
            "channel_full",
        );
        assert_eq!(j["event"], "nlqa1_audit_fallback");
        assert_eq!(j["reason"], "channel_full");
        assert_eq!(j["tenant_id"], 7);
        assert_eq!(j["question"], "show kev");
        assert_eq!(j["compliance"], "bank_of_israel_361_audit_trail");
    }

    #[test]
    fn persist_pool_cannot_saturate_the_runtime() {
        assert_eq!(NLQA_GLOBAL_PERSIST_PERMITS, 4);
        assert_eq!(NLQA_TENANT_PERSIST_PERMITS, 1);
        assert!(NLQA_GLOBAL_PERSIST_PERMITS >= NLQA_TENANT_PERSIST_PERMITS);
    }
}
