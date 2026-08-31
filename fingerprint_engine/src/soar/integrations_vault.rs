//! AES-256-GCM encryption for integration secrets at rest (Vault-compatible envelope).

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde_json::{json, Map, Value};
use std::sync::OnceLock;
use zeroize::Zeroizing;

use crate::secret_zeroize;

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

fn derive_key(domain: &[u8], material: &[u8]) -> [u8; 32] {
    secret_zeroize::derive_aes256_key(domain, material)
}

fn hex32(raw: &[u8]) -> Option<[u8; 32]> {
    secret_zeroize::hex32(raw)
}

/// True when a dedicated (non-JWT-derived) vault key is configured. When false
/// the vault key is derived from `WEISSMAN_JWT_SECRET`, which couples secret
/// rotation to JWT rotation — the startup guard warns operators to set a
/// dedicated key.
#[must_use]
pub fn dedicated_key_configured() -> bool {
    if let Some(&flag) = DEDICATED_AFTER_SCRUB.get() {
        return flag;
    }
    env_has_dedicated_integrations_key()
}

fn env_has_dedicated_integrations_key() -> bool {
    secret_zeroize::take_env_bytes_locked("WEISSMAN_INTEGRATIONS_VAULT_KEY")
        .is_some_and(|v| v.trim_ascii().len() >= 32)
        || secret_zeroize::env_is_hex32_key("WEISSMAN_VAULT_KEY")
}

static DEDICATED_AFTER_SCRUB: OnceLock<bool> = OnceLock::new();

/// Load the integrations keyring from the environment. Call once at boot before
/// [`scrub_key_env_vars`].
pub fn prime_keys_from_env() {
    let _ = DEDICATED_AFTER_SCRUB.get_or_init(env_has_dedicated_integrations_key);
    let _ = vault_key();
    let _ = decrypt_keyring();
}

/// Wipe vault key env vars after the keyring is resident in process memory.
pub fn scrub_key_env_vars() {
    for name in [
        "WEISSMAN_INTEGRATIONS_VAULT_KEY",
        "WEISSMAN_INTEGRATIONS_VAULT_KEY_PREVIOUS",
        "WEISSMAN_VAULT_KEY",
        "WEISSMAN_VAULT_KEY_PREVIOUS",
    ] {
        secret_zeroize::scrub_env_var(name);
    }
}

/// Current (encryption) key. `None` only when no key material exists at all
/// (dev without a JWT secret) — in production the startup guard requires one.
fn vault_key() -> Option<[u8; 32]> {
    static KEY: OnceLock<Option<Zeroizing<[u8; 32]>>> = OnceLock::new();
    KEY.get_or_init(|| {
        if let Some(raw) = secret_zeroize::take_env_bytes_locked("WEISSMAN_INTEGRATIONS_VAULT_KEY")
        {
            if raw.trim_ascii().len() >= 32 {
                return Some(Zeroizing::new(derive_key(
                    b"weissman-integrations-vault-v1|",
                    raw.trim_ascii(),
                )));
            }
        }
        if let Some(raw) = secret_zeroize::take_env_bytes_locked("WEISSMAN_VAULT_KEY") {
            if let Some(k) = hex32(raw.trim_ascii()) {
                return Some(Zeroizing::new(k));
            }
        }
        if let Some(js) = secret_zeroize::take_env_bytes_locked("WEISSMAN_JWT_SECRET") {
            if js.trim_ascii().len() >= 16 {
                return Some(Zeroizing::new(derive_key(
                    b"weissman-integrations-vault-fallback|",
                    js.trim_ascii(),
                )));
            }
        }
        None
    })
    .as_ref()
    .map(|z| **z)
}

/// True when a key is available to encrypt secrets at rest. The production
/// startup guard calls this to fail closed rather than silently store plaintext.
#[must_use]
pub fn key_present() -> bool {
    vault_key().is_some()
}

/// Build the decrypt keyring from explicit inputs.
///
/// Split out from [`decrypt_keyring`] so the migration guarantee is testable: the real function
/// caches in a `OnceLock`, so a test that flips environment variables cannot observe the effect.
fn build_decrypt_keyring(
    current: Option<[u8; 32]>,
    jwt_secret: &[u8],
    prev_vault_hex_csv: &[u8],
    prev_integrations_csv: &[u8],
    prev_jwt_csv: &[u8],
) -> Vec<[u8; 32]> {
    let mut v: Vec<[u8; 32]> = Vec::new();
    if let Some(k) = current {
        v.push(k);
    }
    v.extend(secret_zeroize::split_csv(prev_vault_hex_csv).filter_map(hex32));
    for e in secret_zeroize::split_csv(prev_integrations_csv) {
        if e.len() >= 32 {
            v.push(derive_key(b"weissman-integrations-vault-v1|", e));
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
    let jwt_trim = secret_zeroize::trim_ascii(jwt_secret);
    if jwt_trim.len() >= 16 {
        let legacy = derive_key(b"weissman-integrations-vault-fallback|", jwt_trim);
        if !v.contains(&legacy) {
            v.push(legacy);
        }
    }
    for e in secret_zeroize::split_csv(prev_jwt_csv) {
        if e.len() >= 16 {
            v.push(derive_key(b"weissman-integrations-vault-fallback|", e));
        }
    }
    v
}

/// Decrypt keyring: current key first, then rotated-out previous keys so a key rotation never
/// orphans already-encrypted secrets.
fn decrypt_keyring() -> &'static [[u8; 32]] {
    static KEYS: OnceLock<Zeroizing<Vec<[u8; 32]>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let prev_vault = secret_zeroize::take_env_bytes_locked("WEISSMAN_VAULT_KEY_PREVIOUS");
        let prev_int =
            secret_zeroize::take_env_bytes_locked("WEISSMAN_INTEGRATIONS_VAULT_KEY_PREVIOUS");
        let jwt = secret_zeroize::take_env_bytes_locked("WEISSMAN_JWT_SECRET");
        let prev_jwt = secret_zeroize::take_env_bytes_locked("WEISSMAN_JWT_SECRET_PREVIOUS");
        Zeroizing::new(build_decrypt_keyring(
            vault_key(),
            jwt.as_ref().map(|z| z.as_bytes()).unwrap_or(b""),
            prev_vault.as_ref().map(|z| z.as_bytes()).unwrap_or(b""),
            prev_int.as_ref().map(|z| z.as_bytes()).unwrap_or(b""),
            prev_jwt.as_ref().map(|z| z.as_bytes()).unwrap_or(b""),
        ))
    })
    .as_slice()
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
    for k in decrypt_keyring() {
        if let Some(pt) = decrypt_with_key(k, stored) {
            return pt;
        }
    }
    // No key (current or rotated-out) matched — return as-is (fail-safe).
    stored.to_string()
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
        let legacy_key = derive_key(b"weissman-integrations-vault-fallback|", JWT.as_bytes());
        let legacy_blob = encrypt_with_key(&legacy_key, "slack-bot-token-xoxb").expect("encrypt");

        // Today: a dedicated key is configured, so it becomes the encryption key.
        let dedicated_key = derive_key(b"weissman-integrations-vault-v1|", DEDICATED.as_bytes());
        assert_ne!(dedicated_key, legacy_key, "test premise: the keys differ");

        let keyring = build_decrypt_keyring(Some(dedicated_key), JWT.as_bytes(), b"", b"", b"");

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

    #[test]
    fn scrub_unsets_integrations_vault_env() {
        std::env::set_var(
            "WEISSMAN_INTEGRATIONS_VAULT_KEY",
            "test-vault-key-for-integrations-32b-minimum!!",
        );
        prime_keys_from_env();
        assert!(dedicated_key_configured());
        scrub_key_env_vars();
        assert!(
            std::env::var("WEISSMAN_INTEGRATIONS_VAULT_KEY").is_err(),
            "integrations vault env must be wiped after boot"
        );
        assert!(dedicated_key_configured());
    }
}
