//! Feed credentials: platform-global, encrypted at rest, DB-first with env
//! fallback.
//!
//! Credentials are stored (encrypted via the shared `soar::integrations_vault`
//! AES-256-GCM envelope) in the global `ioc_feed_credentials` table, editable
//! only through the admin-gated `PUT /api/ioc/credentials` endpoint. A process
//! cache holds the decrypted values so the synchronous feed connectors can read
//! them without a pool. Resolution order for any key:
//!
//!   1. the DB value (via the cache), if non-empty; else
//!   2. the matching environment variable, if non-empty; else
//!   3. unset.
//!
//! This lets an operator paste keys into the dashboard **or** keep them in the
//! environment — both work, DB wins when both are present.

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

/// Metadata for one configurable feed credential. `key` doubles as the storage
/// key and the environment-variable name the connector already reads.
pub struct FeedCredKey {
    pub key: &'static str,
    pub label: &'static str,
    /// Secret values are masked on read (only a suffix hint is returned).
    pub secret: bool,
}

/// The whitelist of keys the credentials API will accept — nothing else can be
/// written to the table through the handler.
pub const FEED_CRED_KEYS: &[FeedCredKey] = &[
    FeedCredKey {
        key: "ABUSECH_AUTH_KEY",
        label: "abuse.ch Auth-Key (ThreatFox + URLhaus)",
        secret: true,
    },
    FeedCredKey {
        key: "OTX_API_KEY",
        label: "AlienVault OTX API key",
        secret: true,
    },
    FeedCredKey {
        key: "MISP_URL",
        label: "MISP base URL",
        secret: false,
    },
    FeedCredKey {
        key: "MISP_API_KEY",
        label: "MISP API key",
        secret: true,
    },
    FeedCredKey {
        key: "IOC_CUSTOM_BLOCKLIST_URLS",
        label: "Custom blocklist URLs (comma-separated)",
        secret: false,
    },
];

/// Metadata for a recognised feed-credential key, if any.
#[must_use]
pub fn meta(key: &str) -> Option<&'static FeedCredKey> {
    FEED_CRED_KEYS.iter().find(|m| m.key == key)
}

/// True when `key` is a recognised, settable feed-credential key.
#[must_use]
pub fn is_allowed(key: &str) -> bool {
    meta(key).is_some()
}

/// Process cache of DECRYPTED, non-empty DB credential values.
fn cache() -> &'static RwLock<HashMap<String, String>> {
    static CACHE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Reload the cache from the global table, decrypting each stored value. Safe to
/// call often (a handful of rows); invoked at startup, before each ingest cycle,
/// and after every write so changes take effect immediately.
pub async fn refresh_from_db(pool: &PgPool) {
    // Distinguish a genuine empty table from a transient query error: on error
    // KEEP the last-known-good cache (a DB blip must not silently blank
    // dashboard-configured keys and skip their feeds for a cycle).
    let rows = match sqlx::query("SELECT key, value_enc FROM ioc_feed_credentials")
        .fetch_all(pool)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(target: "ioc", error = %e, "feed credential refresh failed; keeping cached values");
            return;
        }
    };
    let mut map = HashMap::new();
    for r in rows {
        let key: String = r.try_get("key").unwrap_or_default();
        let enc: String = r.try_get("value_enc").unwrap_or_default();
        if key.is_empty() || enc.is_empty() {
            continue;
        }
        let plain = crate::soar::integrations_vault::decrypt_secret(&enc);
        let plain = plain.trim().to_string();
        if !plain.is_empty() {
            map.insert(key, plain);
        }
    }
    if let Ok(mut w) = cache().write() {
        *w = map;
    }
}

/// Resolve a credential: DB (cache) first, then the environment variable.
#[must_use]
pub fn get(key: &str) -> Option<String> {
    if let Ok(r) = cache().read() {
        if let Some(v) = r.get(key) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// True when the key resolves to a non-empty value from either source.
#[must_use]
pub fn is_set(key: &str) -> bool {
    get(key).is_some()
}

/// Set (or clear, when `plaintext` is empty) a feed credential. Encrypts the
/// value at rest and refreshes the cache. Returns an error for unknown keys.
pub async fn set(
    pool: &PgPool,
    key: &str,
    plaintext: &str,
    updated_by: &str,
) -> Result<(), String> {
    if !is_allowed(key) {
        return Err(format!("unknown feed credential key: {key}"));
    }
    let trimmed = plaintext.trim();
    let value_enc = if trimmed.is_empty() {
        String::new()
    } else {
        crate::soar::integrations_vault::encrypt_secret(trimmed)
    };
    sqlx::query(
        r#"INSERT INTO ioc_feed_credentials (key, value_enc, updated_by, updated_at)
           VALUES ($1, $2, $3, now())
           ON CONFLICT (key) DO UPDATE SET
               value_enc = EXCLUDED.value_enc,
               updated_by = EXCLUDED.updated_by,
               updated_at = now()"#,
    )
    .bind(key)
    .bind(&value_enc)
    .bind(updated_by)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    refresh_from_db(pool).await;
    Ok(())
}

fn masked_hint(value: &str) -> String {
    let n = value.chars().count();
    if n == 0 {
        return String::new();
    }
    // Never reveal a suffix when the secret is short enough that the "hint"
    // would be the whole value — return a fixed all-dots mask instead.
    if n <= 4 {
        return "••••".to_string();
    }
    let last4: String = value.chars().skip(n - 4).collect();
    format!("••••{last4}")
}

/// Masked status of every configurable credential — NEVER returns a secret
/// value. Secrets get a `••••<last4>` hint; non-secret config (URLs) is shown in
/// full. `source` is "db", "env", or "unset".
pub async fn status(pool: &PgPool) -> Vec<Value> {
    refresh_from_db(pool).await;
    FEED_CRED_KEYS
        .iter()
        .map(|m| {
            let db_val = cache()
                .read()
                .ok()
                .and_then(|r| r.get(m.key).cloned())
                .filter(|s| !s.trim().is_empty());
            let env_val = std::env::var(m.key)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let (configured, source, value) = if let Some(v) = db_val {
                (true, "db", Some(v))
            } else if let Some(v) = env_val {
                (true, "env", Some(v))
            } else {
                (false, "unset", None)
            };

            let preview = match &value {
                Some(v) if m.secret => masked_hint(v),
                Some(v) => v.clone(),
                None => String::new(),
            };

            json!({
                "key": m.key,
                "label": m.label,
                "secret": m.secret,
                "configured": configured,
                "source": source,
                "preview": preview,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_gates_unknown_keys() {
        assert!(is_allowed("ABUSECH_AUTH_KEY"));
        assert!(is_allowed("IOC_CUSTOM_BLOCKLIST_URLS"));
        assert!(!is_allowed("DATABASE_URL"));
        assert!(!is_allowed("WEISSMAN_JWT_SECRET"));
    }

    #[test]
    fn masked_hint_shows_only_suffix() {
        assert_eq!(masked_hint("abcd1234"), "••••1234");
        // Short secrets must NOT leak: <= 4 chars returns a fixed mask.
        assert_eq!(masked_hint("xy"), "••••");
        assert_eq!(masked_hint("abcd"), "••••");
        assert_eq!(masked_hint("abcde"), "••••bcde");
        assert_eq!(masked_hint(""), "");
    }

    #[test]
    fn every_key_has_matching_env_semantics() {
        // The storage key IS the env-var name the connector reads.
        for m in FEED_CRED_KEYS {
            assert!(!m.key.is_empty());
            assert!(m.key.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
            assert!(meta(m.key).is_some());
        }
    }

    #[test]
    fn get_prefers_nothing_when_unset() {
        // A key that is neither cached nor in the environment resolves to None.
        // (Use a name that is not a real env var in the test environment.)
        assert!(get("IOC_NONEXISTENT_TEST_KEY_ZZZ").is_none());
    }
}
