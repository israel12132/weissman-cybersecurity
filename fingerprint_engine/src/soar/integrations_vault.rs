//! AES-256-GCM encryption for integration secrets at rest (Vault-compatible envelope).

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

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

fn derive_key(domain: &[u8], material: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(material.as_bytes());
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
}

fn hex32(raw: &str) -> Option<[u8; 32]> {
    let b = hex::decode(raw.trim()).ok()?;
    if b.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&b);
        Some(k)
    } else {
        None
    }
}

/// True when a dedicated (non-JWT-derived) vault key is configured. When false
/// the vault key is derived from `WEISSMAN_JWT_SECRET`, which couples secret
/// rotation to JWT rotation — the startup guard warns operators to set a
/// dedicated key.
#[must_use]
pub fn dedicated_key_configured() -> bool {
    std::env::var("WEISSMAN_INTEGRATIONS_VAULT_KEY")
        .map(|v| v.trim().len() >= 32)
        .unwrap_or(false)
        || std::env::var("WEISSMAN_VAULT_KEY")
            .ok()
            .and_then(|v| hex32(&v))
            .is_some()
}

/// Current (encryption) key, loaded per call so the 32-byte working copy can be
/// zeroized when the caller is done. `None` only when no key material exists at
/// all (dev without a JWT secret) — in production the startup guard requires a
/// dedicated key. Does **not** cache in a `OnceLock` (that would pin the key in
/// RAM for the process lifetime).
fn vault_key() -> Option<crate::vault_config_crypto::VaultKey> {
    match crate::vault_config_crypto::load_integrations_encryption_key() {
        Ok(k) => Some(k),
        Err(crate::vault_config_crypto::VaultCryptoError::Missing { .. }) => {
            let js = std::env::var("WEISSMAN_JWT_SECRET").unwrap_or_default();
            if js.trim().len() < 16 {
                return None;
            }
            Some(crate::vault_config_crypto::VaultKey::from_bytes(derive_key(
                b"weissman-integrations-vault-fallback|",
                js.trim(),
            )))
        }
        Err(_) => None,
    }
}

/// True when a key is available to encrypt secrets at rest. The production
/// startup guard calls this to fail closed rather than silently store plaintext.
#[must_use]
pub fn key_present() -> bool {
    vault_key().is_some()
}

/// Build the decrypt keyring from explicit inputs.
///
/// Split out from [`decrypt_keyring`] so the migration guarantee is testable: keys are
/// loaded per call (no `OnceLock`) so a test that flips environment variables can
/// observe the effect, and working copies can be zeroized after decrypt.
fn build_decrypt_keyring(
    current: Option<[u8; 32]>,
    jwt_secret: &str,
    prev_vault_hex_csv: &str,
    prev_integrations_csv: &str,
    prev_jwt_csv: &str,
    integrations_raw: &str,
) -> Vec<[u8; 32]> {
    let mut v: Vec<[u8; 32]> = Vec::new();
    if let Some(k) = current {
        v.push(k);
    }
    // 64-hex INTEGRATIONS keys are used raw for new writes. Rows encrypted under the
    // historical SHA-256-derived form of the same string must still open.
    if let Some(raw_hex) = hex32(integrations_raw) {
        if !v.contains(&raw_hex) {
            v.push(raw_hex);
        }
        if integrations_raw.trim().len() >= 32 {
            let derived = derive_key(
                b"weissman-integrations-vault-v1|",
                integrations_raw.trim(),
            );
            if !v.contains(&derived) {
                v.push(derived);
            }
        }
    }
    v.extend(prev_vault_hex_csv.split(',').filter_map(hex32));
    for e in prev_integrations_csv.split(',') {
        if e.trim().len() >= 32 {
            v.push(derive_key(b"weissman-integrations-vault-v1|", e.trim()));
        }
        if let Some(k) = hex32(e) {
            if !v.contains(&k) {
                v.push(k);
            }
        }
    }
    // Legacy rows: everything written before a dedicated key existed was encrypted with the key
    // derived from the CURRENT JWT secret. Without this entry, the moment an operator sets
    // WEISSMAN_INTEGRATIONS_VAULT_KEY — exactly what the hardened startup guard now tells them to
    // do — every previously stored MFA seed and SOAR credential becomes undecryptable, because
    // the JWT-derived key only reached this keyring via *_PREVIOUS. Including it makes enabling a
    // dedicated key a safe migration: new writes use the dedicated key, old rows still open. It
    // grants no access the fallback did not already have — this is the key those rows are
    // encrypted with today.
    if jwt_secret.trim().len() >= 16 {
        let legacy = derive_key(b"weissman-integrations-vault-fallback|", jwt_secret.trim());
        if !v.contains(&legacy) {
            v.push(legacy);
        }
    }
    for e in prev_jwt_csv.split(',') {
        if e.trim().len() >= 16 {
            v.push(derive_key(
                b"weissman-integrations-vault-fallback|",
                e.trim(),
            ));
        }
    }
    v
}

/// Decrypt keyring: current key first, then rotated-out previous keys so a key rotation never
/// orphans already-encrypted secrets. Loaded per call so working copies can be zeroized.
fn decrypt_keyring() -> Vec<[u8; 32]> {
    let mut current = vault_key();
    let current_bytes = current.as_ref().map(|k| *k.as_bytes());
    if let Some(k) = current.as_mut() {
        k.zeroize();
    }
    build_decrypt_keyring(
        current_bytes,
        &std::env::var("WEISSMAN_JWT_SECRET").unwrap_or_default(),
        &std::env::var("WEISSMAN_VAULT_KEY_PREVIOUS").unwrap_or_default(),
        &std::env::var("WEISSMAN_INTEGRATIONS_VAULT_KEY_PREVIOUS").unwrap_or_default(),
        &std::env::var("WEISSMAN_JWT_SECRET_PREVIOUS").unwrap_or_default(),
        &std::env::var("WEISSMAN_INTEGRATIONS_VAULT_KEY").unwrap_or_default(),
    )
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
    let mut pt = cipher.decrypt(nonce, &blob[12..]).ok()?;
    let out = String::from_utf8(pt.clone()).ok();
    pt.zeroize();
    out
}

#[must_use]
pub fn encrypt_secret(plaintext: &str) -> String {
    if plaintext.starts_with(INT_PREFIX) {
        return plaintext.to_string();
    }
    match vault_key() {
        Some(mut k) => {
            let out =
                encrypt_with_key(k.as_bytes(), plaintext).unwrap_or_else(|| plaintext.to_string());
            k.zeroize();
            out
        }
        None => plaintext.to_string(),
    }
}

#[must_use]
pub fn decrypt_secret(stored: &str) -> String {
    if !stored.starts_with(INT_PREFIX) {
        return stored.to_string();
    }
    let mut keys = decrypt_keyring();
    let mut recovered = None;
    for k in keys.iter() {
        if let Some(pt) = decrypt_with_key(k, stored) {
            recovered = Some(pt);
            break;
        }
    }
    for k in keys.iter_mut() {
        k.zeroize();
    }
    recovered.unwrap_or_else(|| stored.to_string())
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
        // Same key string as `roundtrip_when_key_available`. Keys are loaded per call
        // (no process-wide OnceLock), so this remains isolated from other tests.
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
            assert!(
                is_encrypted(v),
                "{field} must be encrypted at rest, got {v}"
            );
            assert!(
                !v.contains(plain),
                "{field} plaintext leaked into the payload"
            );
        }
        // And point-of-use decryption recovers the originals.
        let dec = decrypt_config(&enc);
        assert_eq!(dec["client_secret"], json!("SUPER-SECRET-VALUE"));
        assert_eq!(dec["password"], json!("SNOW-PASSWORD"));
        std::env::remove_var("WEISSMAN_INTEGRATIONS_VAULT_KEY");
    }

    #[test]
    fn previous_key_decrypts_after_rotation() {
        // A secret encrypted under the now-previous key must still decrypt when
        // the current key differs — this is exactly what the decrypt keyring does
        // by trying [current, ...previous]. Deterministic: explicit keys, no env.
        let old = [1u8; 32];
        let new = [2u8; 32];
        let enc = encrypt_with_key(&old, "rotated-secret").unwrap();
        assert!(
            decrypt_with_key(&new, &enc).is_none(),
            "the rotated-in key must not decrypt old ciphertext"
        );
        assert_eq!(
            decrypt_with_key(&old, &enc).as_deref(),
            Some("rotated-secret"),
            "the previous key must still recover the secret"
        );
    }

    /// Turning on a dedicated vault key must not orphan secrets already written under the
    /// JWT-derived fallback.
    ///
    /// This is the trap in the obvious reading of the hardening: `security_startup` now refuses to
    /// boot production without `WEISSMAN_INTEGRATIONS_VAULT_KEY`, so an operator sets one — and
    /// every existing MFA seed and SOAR credential was encrypted with a key derived from
    /// `WEISSMAN_JWT_SECRET`. Before this keyring entry, the JWT-derived key was only reachable via
    /// `WEISSMAN_JWT_SECRET_PREVIOUS`, so those rows silently stopped decrypting.
    #[test]
    fn enabling_a_dedicated_key_still_decrypts_legacy_jwt_encrypted_secrets() {
        const JWT: &str = "a-production-length-jwt-secret-value-at-least-48-chars-long";
        const DEDICATED: &str = "a-dedicated-integrations-vault-key-32+";

        // A secret written yesterday, under the fallback.
        let legacy_key = derive_key(b"weissman-integrations-vault-fallback|", JWT);
        let legacy_blob = encrypt_with_key(&legacy_key, "slack-bot-token-xoxb").expect("encrypt");

        // Today: a dedicated key is configured, so it becomes the encryption key.
        let dedicated_key = derive_key(b"weissman-integrations-vault-v1|", DEDICATED);
        assert_ne!(dedicated_key, legacy_key, "test premise: the keys differ");

        let keyring = build_decrypt_keyring(Some(dedicated_key), JWT, "", "", "", "");

        let recovered = keyring
            .iter()
            .find_map(|k| decrypt_with_key(k, &legacy_blob));
        assert_eq!(
            recovered.as_deref(),
            Some("slack-bot-token-xoxb"),
            "a secret encrypted under the JWT-derived fallback must still decrypt after a \
             dedicated key is introduced — otherwise hardening the startup guard destroys every \
             stored MFA seed and SOAR credential"
        );

        // And the dedicated key is still first, so new writes use it.
        assert_eq!(keyring.first(), Some(&dedicated_key));

        // Without the legacy entry the same lookup fails — proves the test is load-bearing.
        let without_legacy: Vec<[u8; 32]> = vec![dedicated_key];
        assert!(
            without_legacy
                .iter()
                .find_map(|k| decrypt_with_key(k, &legacy_blob))
                .is_none(),
            "control: the dedicated key alone must NOT open a legacy blob"
        );
    }
}
