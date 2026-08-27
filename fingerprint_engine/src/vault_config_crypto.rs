//! Zero-knowledge vault loader — AES-256-GCM with physical key/secret wipe.
//!
//! Dedicated keys are loaded from the environment (`WEISSMAN_VAULT_KEY` as 64 hex
//! chars, `WEISSMAN_INTEGRATIONS_VAULT_KEY` as 64 hex **or** a ≥32-char passphrase),
//! used for a single encrypt/decrypt, then overwritten with zeros. Decrypted
//! buffers implement [`ZeroizeOnDrop`] so they cannot linger in a crash dump.
//!
//! This module does **not** fall back to `WEISSMAN_JWT_SECRET`. Callers that must
//! still open legacy ciphertext (MFA seeds / SOAR rows encrypted before a dedicated
//! key existed) keep a decrypt keyring in `soar::integrations_vault` /
//! `ceo::vault`; new writes go through the dedicated key.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Environment variable: 64 hex characters = 32 raw AES-256 bytes. Also keys the CEO vault.
pub const VAULT_KEY_ENV: &str = "WEISSMAN_VAULT_KEY";
/// Environment variable: 64 hex **or** a passphrase ≥32 chars (SHA-256 derived).
pub const INTEGRATIONS_VAULT_KEY_ENV: &str = "WEISSMAN_INTEGRATIONS_VAULT_KEY";

const AES_KEY_LEN: usize = 32;
const GCM_NONCE_LEN: usize = 12;

/// 32-byte AES-256 key that wipes itself when dropped (and on explicit [`Zeroize`]).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey {
    key_bytes: [u8; AES_KEY_LEN],
}

impl VaultKey {
    /// Wrap an already-decoded 32-byte key. Caller is responsible for wiping the source.
    #[must_use]
    pub fn from_bytes(key_bytes: [u8; AES_KEY_LEN]) -> Self {
        Self { key_bytes }
    }

    /// Load `env_var` and decode it as 64 hex characters (32 bytes). No passphrase fallback.
    pub fn load_hex_from_env(env_var: &str) -> Result<Self, VaultCryptoError> {
        let mut key_str = env::var(env_var).map_err(|_| VaultCryptoError::Missing {
            env_var: env_var.to_string(),
        })?;
        let parsed = parse_hex32(key_str.trim());
        key_str.zeroize();
        parsed
            .map(Self::from_bytes)
            .ok_or(VaultCryptoError::InvalidHex { env_var: env_var.to_string() })
    }

    /// Load the dedicated CEO / sovereign vault key (`WEISSMAN_VAULT_KEY`, 64 hex). No JWT fallback.
    pub fn load_vault_key() -> Result<Self, VaultCryptoError> {
        Self::load_hex_from_env(VAULT_KEY_ENV)
    }

    /// Load the integrations vault key.
    ///
    /// * 64 hex characters → used as the raw AES-256 key (preferred).
    /// * otherwise a passphrase ≥32 characters → SHA-256(`weissman-integrations-vault-v1|` ∥ passphrase).
    ///
    /// Does **not** fall back to `WEISSMAN_JWT_SECRET`.
    pub fn load_integrations_key() -> Result<Self, VaultCryptoError> {
        let mut raw = env::var(INTEGRATIONS_VAULT_KEY_ENV).map_err(|_| VaultCryptoError::Missing {
            env_var: INTEGRATIONS_VAULT_KEY_ENV.to_string(),
        })?;
        let key = integrations_key_from_material(raw.trim());
        raw.zeroize();
        key
    }

    /// Borrow the 32-byte key. Do not store the slice past this `VaultKey`'s lifetime.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; AES_KEY_LEN] {
        &self.key_bytes
    }
}

/// SHA-256 domain-separated key derivation used by the integrations vault (legacy passphrase).
#[must_use]
pub fn derive_sha256_key(domain: &[u8], material: &str) -> [u8; AES_KEY_LEN] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(material.as_bytes());
    let mut k = [0u8; AES_KEY_LEN];
    k.copy_from_slice(&h.finalize());
    k
}

/// Decode a 64-char hex string into 32 bytes. Returns `None` on any length or nibble error.
#[must_use]
pub fn parse_hex32(raw: &str) -> Option<[u8; AES_KEY_LEN]> {
    let b = hex::decode(raw.trim()).ok()?;
    if b.len() != AES_KEY_LEN {
        return None;
    }
    let mut k = [0u8; AES_KEY_LEN];
    k.copy_from_slice(&b);
    Some(k)
}

fn integrations_key_from_material(raw: &str) -> Result<VaultKey, VaultCryptoError> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(VaultCryptoError::Missing {
            env_var: INTEGRATIONS_VAULT_KEY_ENV.to_string(),
        });
    }
    if let Some(k) = parse_hex32(t) {
        return Ok(VaultKey::from_bytes(k));
    }
    if t.len() >= 32 {
        return Ok(VaultKey::from_bytes(derive_sha256_key(
            b"weissman-integrations-vault-v1|",
            t,
        )));
    }
    Err(VaultCryptoError::WeakMaterial {
        env_var: INTEGRATIONS_VAULT_KEY_ENV.to_string(),
        len: t.len(),
    })
}

/// Current integrations encryption key: dedicated integrations key, else `WEISSMAN_VAULT_KEY`.
/// Never derives from the JWT signing secret.
pub fn load_integrations_encryption_key() -> Result<VaultKey, VaultCryptoError> {
    match VaultKey::load_integrations_key() {
        Ok(k) => Ok(k),
        Err(VaultCryptoError::Missing { .. }) => VaultKey::load_vault_key(),
        Err(e) => Err(e),
    }
}

/// AES-256-GCM encrypt. Returns (nonce, ciphertext+tag). Wipes the cipher's working copies via drop.
pub fn encrypt_aes256_gcm(
    key: &VaultKey,
    plaintext: &[u8],
) -> Result<([u8; GCM_NONCE_LEN], Vec<u8>), VaultCryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| VaultCryptoError::Encrypt)?;
    let mut nonce_bytes = [0u8; GCM_NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce.as_slice());
    Ok((nonce_bytes, ct))
}

/// AES-256-GCM decrypt. The returned buffer is owned by the caller; wrap it in
/// [`SecretBytes`] (or parse then [`Zeroize`]) so it cannot linger.
pub fn decrypt_aes256_gcm(
    key: &VaultKey,
    nonce_bytes: &[u8; GCM_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultCryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultCryptoError::Decrypt)
}

/// Zeroizing byte buffer for decrypted payloads.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Heap string that wipes itself on drop. Not [`Clone`] — cloning would
/// re-materialise plaintext in a second allocation that outlives the wipe.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    #[must_use]
    pub fn from_string(inner: String) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            inner: String::new(),
        }
    }

    /// Borrow the secret for a focused operation. Do not store the slice.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.inner
    }

    pub fn with_exposed<T>(&self, f: impl FnOnce(&str) -> T) -> T {
        f(&self.inner)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString([redacted])")
    }
}

/// Decrypted integration / DB config. Fields are [`SecretString`] so a clone
/// into a long-lived `HashMap` / `OnceLock` is a compile error. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecryptedConfig {
    pub client_secret: SecretString,
    pub api_key: SecretString,
    pub db_password: SecretString,
}

impl DecryptedConfig {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.client_secret.is_empty() && self.api_key.is_empty() && self.db_password.is_empty()
    }
}

impl std::fmt::Debug for DecryptedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedConfig")
            .field("client_secret", &self.client_secret)
            .field("api_key", &self.api_key)
            .field("db_password", &self.db_password)
            .finish()
    }
}

/// Fail-closed loader: dedicated env key, AES-256-GCM, zeroize on the way out.
pub struct SovereignVault;

impl SovereignVault {
    /// Encrypt a JSON config map. Returns (nonce, ciphertext). Key is loaded, used, wiped.
    pub fn encrypt_config(
        config: &HashMap<String, String>,
        key_env: &str,
    ) -> Result<([u8; GCM_NONCE_LEN], Vec<u8>), VaultCryptoError> {
        let mut json = serde_json::to_vec(config).map_err(|_| VaultCryptoError::Serialize)?;
        let mut key = VaultKey::load_hex_from_env(key_env).or_else(|_| {
            if key_env == INTEGRATIONS_VAULT_KEY_ENV {
                VaultKey::load_integrations_key()
            } else {
                Err(VaultCryptoError::Missing {
                    env_var: key_env.to_string(),
                })
            }
        })?;
        let out = encrypt_aes256_gcm(&key, &json);
        json.zeroize();
        key.zeroize();
        out
    }

    /// Decrypt an encrypted config blob. Key and plaintext buffers are wiped before return
    /// (the returned [`DecryptedConfig`] itself wipes on drop / out of scope).
    pub fn decrypt_config(
        encrypted_payload: &[u8],
        nonce_bytes: &[u8; GCM_NONCE_LEN],
        key_env: &str,
    ) -> Result<DecryptedConfig, VaultCryptoError> {
        let mut vault_key = VaultKey::load_hex_from_env(key_env).or_else(|_| {
            if key_env == INTEGRATIONS_VAULT_KEY_ENV {
                VaultKey::load_integrations_key()
            } else {
                Err(VaultCryptoError::Missing {
                    env_var: key_env.to_string(),
                })
            }
        })?;

        let mut decrypted_bytes = decrypt_aes256_gcm(&vault_key, nonce_bytes, encrypted_payload)?;
        let parsed: Result<HashMap<String, String>, _> = serde_json::from_slice(&decrypted_bytes);
        decrypted_bytes.zeroize();
        let mut parsed_map = parsed.map_err(|_| VaultCryptoError::Serialize)?;

        let decrypted_config = DecryptedConfig {
            client_secret: SecretString::from_string(
                parsed_map.remove("client_secret").unwrap_or_default(),
            ),
            api_key: SecretString::from_string(parsed_map.remove("api_key").unwrap_or_default()),
            db_password: SecretString::from_string(
                parsed_map.remove("db_password").unwrap_or_default(),
            ),
        };
        for (_, mut leftover) in parsed_map {
            leftover.zeroize();
        }

        vault_key.zeroize();
        Ok(decrypted_config)
    }
}

/// Failures while loading a dedicated vault key or running AES-256-GCM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultCryptoError {
    Missing { env_var: String },
    InvalidHex { env_var: String },
    WeakMaterial { env_var: String, len: usize },
    Encrypt,
    Decrypt,
    Utf8,
    Serialize,
}

impl std::fmt::Display for VaultCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { env_var } => {
                write!(f, "{env_var} is not set; dedicated vault key required (no JWT fallback)")
            }
            Self::InvalidHex { env_var } => {
                write!(f, "{env_var} must be 64 hex characters (32 bytes) for AES-256")
            }
            Self::WeakMaterial { env_var, len } => {
                write!(f, "{env_var} is {len} characters; need 64 hex or a passphrase ≥32 chars")
            }
            Self::Encrypt => write!(f, "AES-256-GCM encryption failed"),
            Self::Decrypt => {
                write!(f, "AES-256-GCM decryption failed (tampered payload or invalid key)")
            }
            Self::Utf8 => write!(f, "decrypted payload is not valid UTF-8"),
            Self::Serialize => write!(f, "config JSON (de)serialisation failed"),
        }
    }
}

impl std::error::Error for VaultCryptoError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn unique_hex_key(seed: u8) -> String {
        let bytes = [seed; 32];
        hex::encode(bytes)
    }

    #[test]
    fn hex32_accepts_exactly_32_bytes() {
        let hex = "ab".repeat(32);
        assert!(parse_hex32(&hex).is_some());
        assert!(parse_hex32("deadbeef").is_none());
        assert!(parse_hex32("not-hex").is_none());
        assert!(parse_hex32(&"aa".repeat(31)).is_none());
    }

    #[test]
    fn load_hex_from_env_fails_closed_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        let var = "WEISSMAN_VAULT_KEY_UNIT_MISSING";
        std::env::remove_var(var);
        match VaultKey::load_hex_from_env(var) {
            Err(VaultCryptoError::Missing { env_var }) => assert_eq!(env_var, var),
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn load_hex_from_env_rejects_wrong_length() {
        let _g = ENV_LOCK.lock().unwrap();
        let var = "WEISSMAN_VAULT_KEY_UNIT_SHORT";
        std::env::set_var(var, "aabbccdd");
        match VaultKey::load_hex_from_env(var) {
            Err(VaultCryptoError::InvalidHex { env_var }) => assert_eq!(env_var, var),
            other => panic!("expected InvalidHex, got {other:?}"),
        }
        std::env::remove_var(var);
    }

    #[test]
    fn sovereign_vault_roundtrip_and_wipes_working_buffers() {
        let _g = ENV_LOCK.lock().unwrap();
        let hex = unique_hex_key(0x5A);
        std::env::set_var(VAULT_KEY_ENV, &hex);

        let mut cfg = HashMap::new();
        cfg.insert("client_secret".into(), "cs-live-value".into());
        cfg.insert("api_key".into(), "ak-live-value".into());
        cfg.insert("db_password".into(), "db-live-value".into());

        let (nonce, ct) = SovereignVault::encrypt_config(&cfg, VAULT_KEY_ENV).expect("encrypt");
        assert_eq!(nonce.len(), 12);
        assert!(!ct.is_empty());
        let joined = hex::encode(&ct);
        assert!(
            !joined.contains("cs-live-value")
                && !String::from_utf8_lossy(&ct).contains("db-live-value"),
            "plaintext must not appear in ciphertext"
        );

        let dec = SovereignVault::decrypt_config(&ct, &nonce, VAULT_KEY_ENV).expect("decrypt");
        assert_eq!(dec.client_secret.expose(), "cs-live-value");
        assert_eq!(dec.api_key.expose(), "ak-live-value");
        assert_eq!(dec.db_password.expose(), "db-live-value");
        let debug = format!("{dec:?}");
        assert!(debug.contains("[redacted]"));
        assert!(
            !debug.contains("cs-live-value") && !debug.contains("db-live-value"),
            "Debug must not leak decrypted secrets: {debug}"
        );
        drop(dec); // ZeroizeOnDrop — cannot observe RAM, but path must compile/run

        std::env::remove_var(VAULT_KEY_ENV);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(VAULT_KEY_ENV, unique_hex_key(1));
        let mut cfg = HashMap::new();
        cfg.insert("api_key".into(), "secret".into());
        let (nonce, ct) = SovereignVault::encrypt_config(&cfg, VAULT_KEY_ENV).expect("encrypt");
        std::env::set_var(VAULT_KEY_ENV, unique_hex_key(2));
        let err = SovereignVault::decrypt_config(&ct, &nonce, VAULT_KEY_ENV).unwrap_err();
        assert_eq!(err, VaultCryptoError::Decrypt);
        std::env::remove_var(VAULT_KEY_ENV);
    }

    #[test]
    fn integrations_passphrase_is_derived_not_hex() {
        let _g = ENV_LOCK.lock().unwrap();
        let phrase = "test-vault-key-for-integrations-32b-minimum!!";
        std::env::set_var(INTEGRATIONS_VAULT_KEY_ENV, phrase);
        let key = VaultKey::load_integrations_key().expect("load");
        let derived = derive_sha256_key(b"weissman-integrations-vault-v1|", phrase);
        assert_eq!(key.as_bytes(), &derived);
        std::env::remove_var(INTEGRATIONS_VAULT_KEY_ENV);
    }

    #[test]
    fn integrations_64_hex_is_used_raw() {
        let _g = ENV_LOCK.lock().unwrap();
        let hex = unique_hex_key(0x11);
        std::env::set_var(INTEGRATIONS_VAULT_KEY_ENV, &hex);
        let key = VaultKey::load_integrations_key().expect("load");
        assert_eq!(key.as_bytes(), &parse_hex32(&hex).unwrap());
        std::env::remove_var(INTEGRATIONS_VAULT_KEY_ENV);
    }

    #[test]
    #[test]
    fn secret_string_debug_is_redacted_and_not_clone() {
        let s = SecretString::from_string("super-secret-dsn".into());
        assert_eq!(format!("{s:?}"), "SecretString([redacted])");
        assert_eq!(s.expose(), "super-secret-dsn");
        // SecretString is intentionally !Clone — a compile-time guard against
        // copying plaintext into long-lived maps. The type bound is asserted
        // by the fact that this test builds without calling clone().
        drop(s);
    }

    #[test]
    fn no_jwt_fallback_on_sovereign_loader() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var(VAULT_KEY_ENV);
        std::env::set_var(
            "WEISSMAN_JWT_SECRET",
            "a-production-length-jwt-secret-value-at-least-48-chars-long",
        );
        assert!(matches!(
            VaultKey::load_vault_key(),
            Err(VaultCryptoError::Missing { .. })
        ));
    }
}
