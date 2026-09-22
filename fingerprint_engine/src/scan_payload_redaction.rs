//! Redact hydrated scan secrets from async-job payloads returned to HTTP clients.
//! Workers still read the full payload from `weissman_async_jobs`; only API responses are masked.

use serde_json::{json, Value};

pub const MASKED_SECRET: &str = "••••••••";

const EXPLICIT_SECRET_KEYS: &[&str] = &[
    "github_token",
    "gitlab_token",
    "oast_api_key",
    "aws_external_id",
    "smtp_password",
    "censys_api_secret",
    "pagerduty_routing_key",
    "shodan_api_key",
    "authorization",
    "api_key",
    "client_secret",
    "password",
    "private_key",
    "bearer_token",
    "access_token",
    "refresh_token",
    "ebpf_ssh_key_pem",
    "auth_header",
    "basic_auth",
    "auth_cookie",
    "aws_secret_access_key",
    "aws_access_key_id",
    "azure_devops_pat",
];

#[must_use]
pub fn is_sensitive_payload_key(key: &str) -> bool {
    let k = key.trim().to_ascii_lowercase();
    if k.is_empty() {
        return false;
    }
    if EXPLICIT_SECRET_KEYS.iter().any(|&s| k == s) {
        return true;
    }
    k.ends_with("_token")
        || k.ends_with("_secret")
        || k.ends_with("_api_key")
        || k.ends_with("_password")
        || k.ends_with("_pem")
        || k.ends_with("_key_pem")
        || k.ends_with("_private_key")
        || k.contains("password")
        || k.contains("private_key")
}

fn mask_value(v: &Value) -> Value {
    match v {
        Value::String(s) if !s.trim().is_empty() => json!(MASKED_SECRET),
        Value::Number(_) | Value::Bool(_) => json!(MASKED_SECRET),
        _ => json!({ "configured": true, "masked": MASKED_SECRET }),
    }
}

/// Deep-copy `payload` with sensitive string fields replaced by masked placeholders.
#[must_use]
pub fn redact_for_api(payload: &Value) -> Value {
    match payload {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if is_sensitive_payload_key(k) && !value_is_empty(v) {
                    out.insert(k.clone(), mask_value(v));
                } else {
                    out.insert(k.clone(), redact_for_api(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(redact_for_api).collect()),
        other => other.clone(),
    }
}

/// Secrets the worker re-hydrates live from tenant/client DB config at execution
/// (`scan_routing::hydrate_stored_job_payload`). These are always dropped before storage.
const REHYDRATABLE_SECRET_KEYS: &[&str] = &["github_token", "oast_api_key", "aws_external_id"];

fn is_rehydratable_secret_key(key: &str) -> bool {
    let k = key.trim().to_ascii_lowercase();
    REHYDRATABLE_SECRET_KEYS.iter().any(|&s| k == s)
}

/// Remove sensitive fields before persisting job payloads.
///
/// DB-re-hydratable secrets (the worker reloads them at execution) are always dropped.
/// Inline operator secrets (`client_secret`, `bearer_token`, `aws_secret_access_key`, …) have
/// no DB source, so stripping them makes an authenticated scan run unauthenticated — but they
/// are only safe to persist when the row is encrypted at rest. So they are kept ONLY when a
/// vault KEK is installed (`seal_job_payload` then AES-GCMs the payload); without a KEK the
/// payload is stored in cleartext, so every secret is stripped, exactly as before.
#[must_use]
pub fn strip_secrets_for_storage(payload: Value) -> Value {
    let encrypted_at_rest = crate::job_envelope::kek_installed();
    strip_secrets_for_storage_scoped(payload, encrypted_at_rest)
}

fn strip_secrets_for_storage_scoped(payload: Value, encrypted_at_rest: bool) -> Value {
    match payload {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                // When the payload is encrypted at rest, only drop the DB-re-hydratable secrets
                // and let inline operator secrets ride inside the encrypted envelope so the scan
                // stays authenticated. Otherwise drop every secret so none is persisted in clear.
                let strip = if encrypted_at_rest {
                    is_rehydratable_secret_key(&k)
                } else {
                    is_sensitive_payload_key(&k)
                };
                if strip && !value_is_empty(&v) {
                    continue;
                }
                out.insert(k, strip_secrets_for_storage_scoped(v, encrypted_at_rest));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(|v| strip_secrets_for_storage_scoped(v, encrypted_at_rest))
                .collect(),
        ),
        other => other,
    }
}

fn value_is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_hydrated_github_token() {
        let raw = json!({
            "engine": "osint",
            "target": "https://example.com",
            "github_token": "ghp_real_secret_value",
            "depth": "1"
        });
        let red = redact_for_api(&raw);
        assert_eq!(
            red.get("github_token").and_then(Value::as_str),
            Some(MASKED_SECRET)
        );
        assert_eq!(red.get("depth").and_then(Value::as_str), Some("1"));
    }

    #[test]
    fn redacts_aws_external_id() {
        let raw = json!({ "aws_external_id": "ext-from-db-hydration" });
        let red = redact_for_api(&raw);
        assert_eq!(
            red.get("aws_external_id").and_then(Value::as_str),
            Some(MASKED_SECRET)
        );
    }

    #[test]
    fn leaves_non_secrets_intact() {
        let raw = json!({ "engine": "osint", "validated_scope": { "host": "example.com" } });
        let red = redact_for_api(&raw);
        assert_eq!(red, raw);
    }

    #[test]
    fn strip_removes_secrets_for_queue_storage() {
        let raw = json!({
            "engine": "osint",
            "github_token": "ghp_secret",
            "depth": "2"
        });
        let stripped = strip_secrets_for_storage(raw);
        assert!(stripped.get("github_token").is_none());
        assert_eq!(stripped.get("depth").and_then(Value::as_str), Some("2"));
    }

    #[test]
    fn inline_secrets_kept_only_when_encrypted_at_rest() {
        let raw = json!({
            "engine": "osint",
            "client_secret": "cs_inline",     // inline operator secret, no DB source
            "bearer_token": "bt_inline",       // inline operator secret, no DB source
            "github_token": "ghp_rehydratable",// DB-re-hydratable → always dropped
            "depth": "1"
        });
        // Encrypted at rest: inline secrets survive (worker needs them), re-hydratable dropped.
        let enc = strip_secrets_for_storage_scoped(raw.clone(), true);
        assert_eq!(
            enc.get("client_secret").and_then(Value::as_str),
            Some("cs_inline")
        );
        assert_eq!(
            enc.get("bearer_token").and_then(Value::as_str),
            Some("bt_inline")
        );
        assert!(enc.get("github_token").is_none());
        assert_eq!(enc.get("depth").and_then(Value::as_str), Some("1"));
        // No encryption at rest: every secret is stripped so none is persisted in cleartext.
        let plain = strip_secrets_for_storage_scoped(raw, false);
        assert!(plain.get("client_secret").is_none());
        assert!(plain.get("bearer_token").is_none());
        assert!(plain.get("github_token").is_none());
        assert_eq!(plain.get("depth").and_then(Value::as_str), Some("1"));
    }
}
