//! AES-256-GCM encryption for integration secrets at rest (Vault-compatible envelope).

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const INT_PREFIX: &str = "wzi1:";

const SECRET_KEYS: &[&str] = &[
    "api_key",
    "token",
    "password",
    "secret",
    "routing_key",
    "client_secret",
    "webhook_url",
    "genie_key",
    "bot_token",
];

fn vault_key() -> Option<[u8; 32]> {
    static KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    *KEY.get_or_init(|| {
        if let Ok(raw) = std::env::var("WEISSMAN_INTEGRATIONS_VAULT_KEY") {
            let t = raw.trim();
            if t.len() >= 32 {
                let mut h = Sha256::new();
                h.update(b"weissman-integrations-vault-v1|");
                h.update(t.as_bytes());
                let d = h.finalize();
                let mut k = [0u8; 32];
                k.copy_from_slice(&d);
                return Some(k);
            }
        }
        if let Ok(raw) = std::env::var("WEISSMAN_VAULT_KEY") {
            if let Ok(b) = hex::decode(raw.trim()) {
                if b.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&b);
                    return Some(k);
                }
            }
        }
        let js = std::env::var("WEISSMAN_JWT_SECRET").unwrap_or_default();
        if js.trim().len() < 16 {
            return None;
        }
        let mut h = Sha256::new();
        h.update(b"weissman-integrations-vault-fallback|");
        h.update(js.as_bytes());
        let d = h.finalize();
        let mut k = [0u8; 32];
        k.copy_from_slice(&d);
        Some(k)
    })
}

fn encrypt_with_key(key: &[u8; 32], plaintext: &str) -> Option<String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, plaintext.as_bytes()).ok()?;
    let mut blob = nonce.as_slice().to_vec();
    blob.extend_from_slice(&ct);
    Some(format!(
        "{INT_PREFIX}{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob)
    ))
}

fn decrypt_with_key(key: &[u8; 32], stored: &str) -> Option<String> {
    let rest = stored.strip_prefix(INT_PREFIX)?;
    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, rest).ok()?;
    if blob.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&blob[..12]);
    let pt = cipher.decrypt(nonce, &blob[12..]).ok()?;
    String::from_utf8(pt).ok()
}

#[must_use]
pub fn encrypt_secret(plaintext: &str) -> String {
    if plaintext.starts_with(INT_PREFIX) {
        return plaintext.to_string();
    }
    match vault_key() {
        Some(k) => encrypt_with_key(&k, plaintext).unwrap_or_else(|| plaintext.to_string()),
        None => plaintext.to_string(),
    }
}

#[must_use]
pub fn decrypt_secret(stored: &str) -> String {
    if !stored.starts_with(INT_PREFIX) {
        return stored.to_string();
    }
    match vault_key() {
        Some(k) => decrypt_with_key(&k, stored).unwrap_or_else(|| stored.to_string()),
        None => stored.to_string(),
    }
}

/// True if `stored` is an encrypted envelope produced by [`encrypt_secret`]
/// (as opposed to legacy plaintext). Callers use this to detect rows that
/// still need at-rest migration without hard-coding the envelope prefix.
#[must_use]
pub fn is_encrypted(stored: &str) -> bool {
    stored.starts_with(INT_PREFIX)
}

fn is_secret_field(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEYS
        .iter()
        .any(|s| lower.contains(s) || lower.ends_with("_key"))
}

/// Encrypt sensitive config fields before persisting integrations_registry rows.
pub fn encrypt_config(config: &Value) -> Value {
    let Some(obj) = config.as_object() else {
        return config.clone();
    };
    let mut out = Map::new();
    for (k, v) in obj {
        if let Some(s) = v.as_str() {
            if is_secret_field(k) && !s.is_empty() {
                out.insert(k.clone(), Value::String(encrypt_secret(s)));
            } else {
                out.insert(k.clone(), v.clone());
            }
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    Value::Object(out)
}

/// Decrypt config for adapter execution (server-side only).
pub fn decrypt_config(config: &Value) -> Value {
    let Some(obj) = config.as_object() else {
        return config.clone();
    };
    let mut out = Map::new();
    for (k, v) in obj {
        if let Some(s) = v.as_str() {
            if s.starts_with(INT_PREFIX) {
                out.insert(k.clone(), Value::String(decrypt_secret(s)));
            } else {
                out.insert(k.clone(), v.clone());
            }
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    Value::Object(out)
}

/// Redact secrets for API list responses (never echo credentials to UI).
pub fn redact_config(config: &Value) -> Value {
    let Some(obj) = config.as_object() else {
        return config.clone();
    };
    let mut out = Map::new();
    for (k, v) in obj {
        if let Some(s) = v.as_str() {
            if is_secret_field(k) && !s.is_empty() {
                out.insert(k.clone(), json!("••••••••"));
            } else {
                out.insert(k.clone(), v.clone());
            }
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_when_key_available() {
        std::env::set_var(
            "WEISSMAN_INTEGRATIONS_VAULT_KEY",
            "test-vault-key-for-integrations-32b-minimum!!",
        );
        let enc = encrypt_secret("super-secret-token");
        assert!(enc.starts_with(INT_PREFIX));
        assert_eq!(decrypt_secret(&enc), "super-secret-token");
        std::env::remove_var("WEISSMAN_INTEGRATIONS_VAULT_KEY");
    }

    #[test]
    fn envelope_produces_ciphertext_and_roundtrips_with_explicit_key() {
        // Deterministic (no env / no OnceLock): proves a stored secret is
        // ciphertext at rest and never contains the plaintext.
        let key = [7u8; 32];
        let plaintext = "JBSWY3DPEHPK3PXP"; // sample base32 TOTP seed
        let enc = encrypt_with_key(&key, plaintext).expect("encrypt");
        assert!(enc.starts_with(INT_PREFIX), "must be an encrypted envelope");
        assert!(is_encrypted(&enc));
        assert!(
            !enc.contains(plaintext),
            "plaintext seed must not appear in the at-rest value"
        );
        assert_eq!(
            decrypt_with_key(&key, &enc).as_deref(),
            Some(plaintext),
            "round-trip must recover the original seed"
        );
        assert!(!is_encrypted(plaintext), "bare base32 is not an envelope");
    }

    #[test]
    fn encrypt_config_hides_soar_provider_secrets() {
        // Same key string as `roundtrip_when_key_available` so the process-wide
        // vault-key OnceLock stays consistent regardless of test order.
        std::env::set_var(
            "WEISSMAN_INTEGRATIONS_VAULT_KEY",
            "test-vault-key-for-integrations-32b-minimum!!",
        );
        let payload = json!({
            "device_id": "abc123",
            "base_url": "https://api.crowdstrike.com",
            "client_id": "id-not-secret",
            "client_secret": "SUPER-SECRET-VALUE",  // crowdstrike
            "routing_key": "PD-ROUTING-KEY",        // pagerduty
            "api_key": "OPSGENIE-KEY",              // opsgenie
            "password": "SNOW-PASSWORD",            // servicenow
        });
        let enc = encrypt_config(&payload);
        // Non-secret fields are untouched.
        assert_eq!(enc["device_id"], json!("abc123"));
        assert_eq!(enc["client_id"], json!("id-not-secret"));
        // Every credential is an envelope and its plaintext never appears at rest.
        for (field, plain) in [
            ("client_secret", "SUPER-SECRET-VALUE"),
            ("routing_key", "PD-ROUTING-KEY"),
            ("api_key", "OPSGENIE-KEY"),
            ("password", "SNOW-PASSWORD"),
        ] {
            let v = enc[field].as_str().unwrap_or_default();
            assert!(is_encrypted(v), "{field} must be encrypted at rest, got {v}");
            assert!(!v.contains(plain), "{field} plaintext leaked into the payload");
        }
        // And point-of-use decryption recovers the originals.
        let dec = decrypt_config(&enc);
        assert_eq!(dec["client_secret"], json!("SUPER-SECRET-VALUE"));
        assert_eq!(dec["password"], json!("SNOW-PASSWORD"));
        std::env::remove_var("WEISSMAN_INTEGRATIONS_VAULT_KEY");
    }
}
