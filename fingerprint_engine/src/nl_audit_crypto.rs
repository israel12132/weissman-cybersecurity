//! Encryption at rest + tamper-evident hash chain for Ask Weissman audit rows
//! (`nl_query_audit`).
//!
//! Reuses the integrations vault (AES-256-GCM, `wzi1:` prefix) so key rotation
//! (`WEISSMAN_INTEGRATIONS_VAULT_KEY` / `WEISSMAN_VAULT_KEY` / JWT fallback)
//! stays a single operator path. Never writes the raw question or SQL if sealing
//! fails — stores a redaction marker instead.
//!
//! The hash chain covers **sealed** question/SQL (never plaintext) so a DB
//! superuser who rewrites a row breaks `event_hash` / `prev_hash` linkage.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::soar::integrations_vault::{decrypt_secret, encrypt_secret};

const CHAIN_VERSION: &str = "nlqa1";

const ENC_PREFIX: &str = "wzi1:";
const REDACTED: &str = "[encrypted-unavailable]";

/// Seal a UTF-8 string. Returns ciphertext starting with `wzi1:` or a redaction
/// marker when no vault key is available (never returns the plaintext).
#[must_use]
pub fn seal_text(plain: &str) -> String {
    if plain.is_empty() {
        return String::new();
    }
    if plain.starts_with(ENC_PREFIX) {
        return plain.to_string();
    }
    let sealed = encrypt_secret(plain);
    if sealed.starts_with(ENC_PREFIX) {
        sealed
    } else {
        tracing::error!(
            target: "nl_audit",
            "nl_query_audit seal failed — refusing to persist plaintext question/SQL"
        );
        REDACTED.to_string()
    }
}

/// Open a previously sealed string. Legacy plaintext rows pass through.
#[must_use]
pub fn open_text(stored: &str) -> String {
    if stored.starts_with(ENC_PREFIX) {
        decrypt_secret(stored)
    } else {
        stored.to_string()
    }
}

/// Seal a QueryPlan JSON object as `{"_enc":"wzi1:..."}`.
#[must_use]
pub fn seal_plan(plan: &Value) -> Value {
    let raw = serde_json::to_string(plan).unwrap_or_else(|_| "{}".into());
    json!({ "_enc": seal_text(&raw) })
}

/// Reverse of [`seal_plan`]. Accepts legacy plaintext plan objects.
#[must_use]
pub fn open_plan(stored: &Value) -> Value {
    if let Some(enc) = stored.get("_enc").and_then(Value::as_str) {
        match serde_json::from_str(&open_text(enc)) {
            Ok(v) => v,
            Err(_) => json!({}),
        }
    } else {
        stored.clone()
    }
}

/// Canonical bytes hashed into `nl_query_audit.event_hash` (must stay stable).
#[must_use]
pub fn canonical_nl_audit_payload(
    prev_hash: &str,
    tenant_id: i64,
    user_id: Option<i64>,
    sealed_question: &str,
    sealed_sql: &str,
    rows_returned: i32,
    elapsed_ms: i32,
    error: &str,
) -> String {
    format!(
        "{CHAIN_VERSION}|{prev_hash}|{tenant_id}|{}|{sealed_question}|{sealed_sql}|{rows_returned}|{elapsed_ms}|{error}",
        user_id.unwrap_or(0),
    )
}

#[must_use]
pub fn event_hash(canonical: &str) -> String {
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

/// True when `event_hash` matches the canonical payload for `prev_hash`.
#[must_use]
pub fn verify_link(
    prev_hash: &str,
    tenant_id: i64,
    user_id: Option<i64>,
    sealed_question: &str,
    sealed_sql: &str,
    rows_returned: i32,
    elapsed_ms: i32,
    error: &str,
    stored_hash: &str,
) -> bool {
    let canonical = canonical_nl_audit_payload(
        prev_hash,
        tenant_id,
        user_id,
        sealed_question,
        sealed_sql,
        rows_returned,
        elapsed_ms,
        error,
    );
    event_hash(&canonical) == stored_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_never_returns_plaintext_question() {
        let q = "how many criticals on prod?";
        let sealed = seal_text(q);
        assert_ne!(sealed, q);
        assert!(sealed.starts_with(ENC_PREFIX) || sealed == REDACTED);
    }

    #[test]
    fn empty_stays_empty() {
        assert_eq!(seal_text(""), "");
    }

    #[test]
    fn plan_roundtrip_or_redact() {
        let plan = json!({"table":"vulnerabilities","select":["id"]});
        let sealed = seal_plan(&plan);
        assert!(sealed.get("_enc").is_some());
        let opened = open_plan(&sealed);
        // With no vault key in unit tests we may redact; never leak the raw table name
        // inside the stored blob as a top-level key.
        assert!(sealed.get("table").is_none());
        if opened.get("table").is_some() {
            assert_eq!(opened["table"], "vulnerabilities");
        }
    }

    #[test]
    fn hash_chain_links_and_detects_tamper() {
        let genesis = event_hash(&canonical_nl_audit_payload(
            "",
            7,
            Some(3),
            "wzi1:aaa",
            "wzi1:bbb",
            1,
            12,
            "",
        ));
        assert_eq!(genesis.len(), 64);
        assert!(verify_link(
            "",
            7,
            Some(3),
            "wzi1:aaa",
            "wzi1:bbb",
            1,
            12,
            "",
            &genesis
        ));
        let next = event_hash(&canonical_nl_audit_payload(
            &genesis,
            7,
            Some(3),
            "wzi1:ccc",
            "wzi1:ddd",
            2,
            9,
            "",
        ));
        assert!(verify_link(
            &genesis,
            7,
            Some(3),
            "wzi1:ccc",
            "wzi1:ddd",
            2,
            9,
            "",
            &next
        ));
        assert!(!verify_link(
            &genesis,
            7,
            Some(3),
            "wzi1:TAMPERED",
            "wzi1:ddd",
            2,
            9,
            "",
            &next
        ));
    }
}
