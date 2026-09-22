//! BYOK / KMS envelope encryption: per-tenant KEK -> DEK hierarchy with a pluggable provider.
//!
//! Replaces the single global vault key for *new* secret writes with a per-tenant
//! Data-Encryption Key (DEK). Each tenant's random 32-byte DEK is stored **wrapped**
//! (never plaintext) in `tenant_dek`, and unwrapped on demand into a short-lived,
//! in-memory TTL cache. Two providers wrap/unwrap the DEK:
//!
//!   * [`LocalKeyProvider`] — wraps the DEK with the process' local KEK
//!     (`WEISSMAN_VAULT_KEY`, via [`crate::ceo::vault`]). Dev / self-host default.
//!   * [`AwsKmsKeyProvider`] — wraps/unwraps the DEK against a per-tenant customer
//!     managed key (CMK) whose ARN lives in `tenant_kms_keys`. Deleting/disabling
//!     that CMK crypto-shreds every `wzt1:`-tagged secret for the tenant.
//!
//! Selection is by `WEISSMAN_KMS_PROVIDER=local|aws` (default `local`).
//!
//! BACKWARD COMPATIBILITY: this module never touches existing ciphertext. Secrets
//! written before BYOK are tagged `wzv1:` (CEO vault) / `wzi1:` (integrations) and
//! keep decrypting through the legacy keyrings in [`crate::ceo::vault`] /
//! [`crate::soar::integrations_vault`]. Only new tenant-DEK ciphertext is tagged
//! `wzt1:`. When no DEK/KEK material is available for a tenant the encrypt path
//! falls back to the legacy global-key path, so nothing breaks.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aws_sdk_kms::primitives::Blob;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// At-rest tag for a secret encrypted under a per-tenant DEK (v1). Distinct from the
/// CEO-vault (`wzv1:`) and integrations (`wzi1:`) legacy global-key envelopes so the
/// read path can dispatch on prefix.
const TENANT_PREFIX: &str = "wzt1:";

/// Default unwrapped-DEK cache TTL when `WEISSMAN_KMS_DEK_TTL_SECS` is unset/invalid.
const DEFAULT_DEK_TTL_SECS: u64 = 300;

// ── Errors ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum KeyProviderError {
    /// No local KEK material (dev without `WEISSMAN_VAULT_KEY` / JWT secret).
    #[error("no key-encryption-key material available")]
    NoKeyMaterial,
    /// The tenant has no `tenant_kms_keys` (CMK) row — not enrolled in BYOK.
    #[error("tenant has no KMS key configured")]
    NoTenantKey,
    /// AES-GCM wrap/unwrap of the DEK failed (bad key, tampered ciphertext).
    #[error("dek wrap/unwrap failed")]
    Crypto,
    /// A KMS call failed.
    #[error("kms error: {0}")]
    Kms(String),
    /// A database call failed.
    #[error("db error: {0}")]
    Db(String),
}

// ── Provider trait ─────────────────────────────────────────────────

/// Pluggable key-encryption provider. Wraps/unwraps a per-tenant DEK.
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    /// Stable provider name, persisted in `tenant_dek.provider` (`local` | `aws`).
    fn name(&self) -> &'static str;

    /// Wrap a plaintext DEK for the tenant.
    ///
    /// # Errors
    /// Returns [`KeyProviderError`] when key material is unavailable or the wrap fails.
    async fn wrap_dek(&self, tenant_id: i64, plaintext_dek: &[u8; 32])
        -> Result<Vec<u8>, KeyProviderError>;

    /// Unwrap a wrapped DEK for the tenant.
    ///
    /// # Errors
    /// Returns [`KeyProviderError`] when key material is unavailable or the unwrap fails.
    async fn unwrap_dek(&self, tenant_id: i64, wrapped: &[u8])
        -> Result<[u8; 32], KeyProviderError>;

    /// Provision a fresh DEK for the tenant, returning `(plaintext_dek, wrapped_dek)`.
    ///
    /// Default: generate a random 32-byte DEK locally and wrap it via [`Self::wrap_dek`].
    /// [`AwsKmsKeyProvider`] overrides this to mint the DEK with `GenerateDataKey`.
    ///
    /// # Errors
    /// Returns [`KeyProviderError`] when the wrap/mint fails.
    async fn provision_dek(&self, tenant_id: i64) -> Result<([u8; 32], Vec<u8>), KeyProviderError> {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let mut dek = [0u8; 32];
        dek.copy_from_slice(key.as_slice());
        let wrapped = self.wrap_dek(tenant_id, &dek).await?;
        Ok((dek, wrapped))
    }
}

// ── LocalKeyProvider (current behavior — local KEK) ─────────────────────────

/// Wraps the DEK with the process-local KEK (`WEISSMAN_VAULT_KEY`, via `ceo::vault`).
/// Unwrap tries the whole KEK ring so a KEK rotation does not orphan wrapped DEKs.
pub struct LocalKeyProvider;

#[async_trait::async_trait]
impl KeyProvider for LocalKeyProvider {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn wrap_dek(
        &self,
        _tenant_id: i64,
        plaintext_dek: &[u8; 32],
    ) -> Result<Vec<u8>, KeyProviderError> {
        let kek = crate::ceo::vault::vault_key().ok_or(KeyProviderError::NoKeyMaterial)?;
        gcm_seal_raw(&kek, plaintext_dek).ok_or(KeyProviderError::Crypto)
    }

    async fn unwrap_dek(
        &self,
        _tenant_id: i64,
        wrapped: &[u8],
    ) -> Result<[u8; 32], KeyProviderError> {
        for kek in crate::ceo::vault::kek_ring() {
            if let Some(dek) = gcm_open_raw(kek, wrapped) {
                return Ok(dek);
            }
        }
        Err(KeyProviderError::Crypto)
    }
}

// ── AwsKmsKeyProvider (per-tenant CMK) ─────────────────────────────────

/// Wraps/unwraps the DEK against a per-tenant CMK (ARN from `tenant_kms_keys`).
pub struct AwsKmsKeyProvider {
    pool: Arc<PgPool>,
    base: tokio::sync::OnceCell<aws_types::SdkConfig>,
    clients: tokio::sync::Mutex<HashMap<String, aws_sdk_kms::Client>>,
}

impl AwsKmsKeyProvider {
    #[must_use]
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self {
            pool,
            base: tokio::sync::OnceCell::new(),
            clients: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn base_config(&self) -> &aws_types::SdkConfig {
        self.base
            .get_or_init(|| async {
                aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await
            })
            .await
    }

    async fn client_for_region(&self, region: &str) -> aws_sdk_kms::Client {
        {
            let guard = self.clients.lock().await;
            if let Some(c) = guard.get(region) {
                return c.clone();
            }
        }
        let base = self.base_config().await;
        let conf = aws_sdk_kms::config::Builder::from(base)
            .region(aws_config::Region::new(region.to_string()))
            .build();
        let client = aws_sdk_kms::Client::from_conf(conf);
        let mut guard = self.clients.lock().await;
        guard
            .entry(region.to_string())
            .or_insert_with(|| client.clone());
        client
    }

    /// A KMS client whose region matches the CMK ARN (`arn:aws:kms:REGION:acct:key/...`),
    /// falling back to the default-chain region when the ARN carries none.
    async fn client_for_arn(&self, arn: &str) -> aws_sdk_kms::Client {
        match arn.split(':').nth(3).filter(|s| !s.is_empty()) {
            Some(region) => self.client_for_region(region).await,
            None => {
                let base = self.base_config().await;
                aws_sdk_kms::Client::new(base)
            }
        }
    }
}

#[async_trait::async_trait]
impl KeyProvider for AwsKmsKeyProvider {
    fn name(&self) -> &'static str {
        "aws"
    }

    async fn wrap_dek(
        &self,
        tenant_id: i64,
        plaintext_dek: &[u8; 32],
    ) -> Result<Vec<u8>, KeyProviderError> {
        let arn = lookup_tenant_cmk_arn(&self.pool, tenant_id).await?;
        let client = self.client_for_arn(&arn).await;
        let out = client
            .encrypt()
            .key_id(&arn)
            .plaintext(Blob::new(plaintext_dek.to_vec()))
            .send()
            .await
            .map_err(|e| KeyProviderError::Kms(format!("encrypt: {e}")))?;
        let blob = out
            .ciphertext_blob()
            .ok_or_else(|| KeyProviderError::Kms("encrypt: empty ciphertext".to_string()))?;
        Ok(blob.as_ref().to_vec())
    }

    async fn unwrap_dek(
        &self,
        tenant_id: i64,
        wrapped: &[u8],
    ) -> Result<[u8; 32], KeyProviderError> {
        let arn = lookup_tenant_cmk_arn(&self.pool, tenant_id).await?;
        let client = self.client_for_arn(&arn).await;
        let out = client
            .decrypt()
            .key_id(&arn)
            .ciphertext_blob(Blob::new(wrapped.to_vec()))
            .send()
            .await
            .map_err(|e| KeyProviderError::Kms(format!("decrypt: {e}")))?;
        let pt = out
            .plaintext()
            .ok_or_else(|| KeyProviderError::Kms("decrypt: empty plaintext".to_string()))?;
        let bytes = pt.as_ref();
        if bytes.len() != 32 {
            return Err(KeyProviderError::Kms(format!(
                "decrypt: expected 32-byte DEK, got {}",
                bytes.len()
            )));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(bytes);
        Ok(dek)
    }

    async fn provision_dek(&self, tenant_id: i64) -> Result<([u8; 32], Vec<u8>), KeyProviderError> {
        let arn = lookup_tenant_cmk_arn(&self.pool, tenant_id).await?;
        let client = self.client_for_arn(&arn).await;
        let out = client
            .generate_data_key()
            .key_id(&arn)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| KeyProviderError::Kms(format!("generate_data_key: {e}")))?;
        let pt = out
            .plaintext()
            .ok_or_else(|| KeyProviderError::Kms("generate_data_key: empty plaintext".to_string()))?;
        let ct = out.ciphertext_blob().ok_or_else(|| {
            KeyProviderError::Kms("generate_data_key: empty ciphertext".to_string())
        })?;
        let pb = pt.as_ref();
        if pb.len() != 32 {
            return Err(KeyProviderError::Kms(format!(
                "generate_data_key: expected 32-byte DEK, got {}",
                pb.len()
            )));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(pb);
        Ok((dek, ct.as_ref().to_vec()))
    }
}

// ── Provider selection (process-global) ─────────────────────────────────

static PROVIDER: OnceLock<Arc<dyn KeyProvider>> = OnceLock::new();

fn provider(pool: &PgPool) -> Arc<dyn KeyProvider> {
    PROVIDER
        .get_or_init(|| build_provider_from_env(pool))
        .clone()
}

fn build_provider_from_env(pool: &PgPool) -> Arc<dyn KeyProvider> {
    let sel = std::env::var("WEISSMAN_KMS_PROVIDER").unwrap_or_default();
    let sel = sel.trim().to_ascii_lowercase();
    if sel == "aws" || sel == "kms" {
        Arc::new(AwsKmsKeyProvider::new(Arc::new(pool.clone())))
    } else {
        Arc::new(LocalKeyProvider)
    }
}

// ── DEK cache (unwrapped DEK, TTL) ────────────────────────────────────

struct DekCacheEntry {
    dek: Zeroizing<[u8; 32]>,
    expires: Instant,
}

static DEK_CACHE: OnceLock<Mutex<HashMap<i64, DekCacheEntry>>> = OnceLock::new();

fn dek_cache() -> &'static Mutex<HashMap<i64, DekCacheEntry>> {
    DEK_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ttl() -> Duration {
    let secs = std::env::var("WEISSMAN_KMS_DEK_TTL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_DEK_TTL_SECS);
    Duration::from_secs(secs)
}

fn cache_get(tenant_id: i64) -> Option<[u8; 32]> {
    let guard = dek_cache().lock().ok()?;
    let entry = guard.get(&tenant_id)?;
    if entry.expires > Instant::now() {
        Some(*entry.dek)
    } else {
        None
    }
}

fn cache_put(tenant_id: i64, dek: [u8; 32]) {
    if let Ok(mut guard) = dek_cache().lock() {
        guard.insert(
            tenant_id,
            DekCacheEntry {
                dek: Zeroizing::new(dek),
                expires: Instant::now() + ttl(),
            },
        );
    }
}

// ── tenant_kms_keys / tenant_dek DB access (RLS: begin_tenant_tx) ─────────────────

async fn lookup_tenant_cmk_arn(pool: &PgPool, tenant_id: i64) -> Result<String, KeyProviderError> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| KeyProviderError::Db(e.to_string()))?;
    let arn: Option<String> =
        sqlx::query_scalar("SELECT kms_key_arn FROM tenant_kms_keys WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| KeyProviderError::Db(e.to_string()))?;
    let _ = tx.commit().await;
    match arn {
        Some(a) if !a.trim().is_empty() => Ok(a),
        _ => Err(KeyProviderError::NoTenantKey),
    }
}

async fn load_wrapped_dek(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<Option<(Vec<u8>, String)>, KeyProviderError> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| KeyProviderError::Db(e.to_string()))?;
    let row = sqlx::query("SELECT wrapped_dek, provider FROM tenant_dek WHERE tenant_id = $1")
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| KeyProviderError::Db(e.to_string()))?;
    let _ = tx.commit().await;
    match row {
        Some(r) => {
            let wrapped: Vec<u8> = r
                .try_get("wrapped_dek")
                .map_err(|e| KeyProviderError::Db(e.to_string()))?;
            let prov: String = r
                .try_get("provider")
                .map_err(|e| KeyProviderError::Db(e.to_string()))?;
            Ok(Some((wrapped, prov)))
        }
        None => Ok(None),
    }
}

/// Insert the wrapped DEK. Returns `true` when this call created the row, `false`
/// when a concurrent writer already created it (`ON CONFLICT DO NOTHING`).
async fn store_wrapped_dek(
    pool: &PgPool,
    tenant_id: i64,
    wrapped: &[u8],
    provider_name: &str,
) -> Result<bool, KeyProviderError> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| KeyProviderError::Db(e.to_string()))?;
    let res = sqlx::query(
        "INSERT INTO tenant_dek (tenant_id, wrapped_dek, provider) VALUES ($1, $2, $3) \
         ON CONFLICT (tenant_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(wrapped.to_vec())
    .bind(provider_name)
    .execute(&mut *tx)
    .await
    .map_err(|e| KeyProviderError::Db(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| KeyProviderError::Db(e.to_string()))?;
    Ok(res.rows_affected() > 0)
}

/// Enroll or update a tenant's KMS CMK ARN (BYOK onboarding / crypto-shred handoff).
///
/// # Errors
/// Propagates the underlying [`sqlx::Error`].
pub async fn set_tenant_kms_key(
    pool: &PgPool,
    tenant_id: i64,
    kms_key_arn: &str,
    provider_name: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    sqlx::query(
        "INSERT INTO tenant_kms_keys (tenant_id, kms_key_arn, provider) VALUES ($1, $2, $3) \
         ON CONFLICT (tenant_id) DO UPDATE SET kms_key_arn = EXCLUDED.kms_key_arn, \
         provider = EXCLUDED.provider",
    )
    .bind(tenant_id)
    .bind(kms_key_arn.trim())
    .bind(provider_name.trim())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

// ── DEK resolution ──────────────────────────────────────────────────

/// Load the tenant DEK, provisioning + persisting one if none exists yet.
async fn get_or_create_dek(pool: &PgPool, tenant_id: i64) -> Result<[u8; 32], KeyProviderError> {
    if let Some(dek) = cache_get(tenant_id) {
        return Ok(dek);
    }
    let prov = provider(pool);
    if let Some((wrapped, _)) = load_wrapped_dek(pool, tenant_id).await? {
        let dek = prov.unwrap_dek(tenant_id, &wrapped).await?;
        cache_put(tenant_id, dek);
        return Ok(dek);
    }
    let (dek, wrapped) = prov.provision_dek(tenant_id).await?;
    if store_wrapped_dek(pool, tenant_id, &wrapped, prov.name()).await? {
        cache_put(tenant_id, dek);
        Ok(dek)
    } else {
        // Concurrent writer won the INSERT — adopt their DEK, discard ours.
        let (wrapped2, _) = load_wrapped_dek(pool, tenant_id)
            .await?
            .ok_or(KeyProviderError::NoTenantKey)?;
        let dek2 = prov.unwrap_dek(tenant_id, &wrapped2).await?;
        cache_put(tenant_id, dek2);
        Ok(dek2)
    }
}

/// Load an EXISTING tenant DEK (never provisions). Used on the decrypt path.
async fn get_existing_dek(pool: &PgPool, tenant_id: i64) -> Result<[u8; 32], KeyProviderError> {
    if let Some(dek) = cache_get(tenant_id) {
        return Ok(dek);
    }
    let prov = provider(pool);
    let (wrapped, _) = load_wrapped_dek(pool, tenant_id)
        .await?
        .ok_or(KeyProviderError::NoTenantKey)?;
    let dek = prov.unwrap_dek(tenant_id, &wrapped).await?;
    cache_put(tenant_id, dek);
    Ok(dek)
}

// ── Public tenant-aware encrypt/decrypt ────────────────────────────────

/// Encrypt a tenant secret under the tenant DEK (`wzt1:` envelope). Falls back to the
/// legacy global-key path ([`crate::ceo::vault::encrypt_secret`]) when no DEK/KEK is
/// available so existing deployments keep working.
pub async fn encrypt_secret_for_tenant(pool: &PgPool, tenant_id: i64, plaintext: &str) -> String {
    match get_or_create_dek(pool, tenant_id).await {
        Ok(dek) => gcm_seal_tagged(&dek, plaintext)
            .unwrap_or_else(|| crate::ceo::vault::encrypt_secret(plaintext)),
        Err(_) => crate::ceo::vault::encrypt_secret(plaintext),
    }
}

/// Transparently decrypt a stored secret. `wzt1:` values use the tenant DEK; everything
/// else (legacy `wzv1:` envelopes, plaintext) is handled by the legacy CEO-vault path.
pub async fn decrypt_secret_for_tenant(pool: &PgPool, tenant_id: i64, stored: &str) -> String {
    if !stored.starts_with(TENANT_PREFIX) {
        return crate::ceo::vault::decrypt_secret(stored);
    }
    match get_existing_dek(pool, tenant_id).await {
        Ok(dek) => gcm_open_tagged(&dek, stored).unwrap_or_else(|| stored.to_string()),
        Err(_) => stored.to_string(),
    }
}

// ── AES-256-GCM helpers ───────────────────────────────────────────

fn gcm_seal_raw(key: &[u8; 32], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, plaintext).ok()?;
    let mut blob = nonce.as_slice().to_vec();
    blob.extend_from_slice(&ct);
    Some(blob)
}

fn gcm_open_raw(key: &[u8; 32], blob: &[u8]) -> Option<[u8; 32]> {
    if blob.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&blob[..12]);
    let pt = cipher.decrypt(nonce, &blob[12..]).ok()?;
    if pt.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&pt);
    Some(k)
}

fn gcm_seal_tagged(key: &[u8; 32], plaintext: &str) -> Option<String> {
    let blob = gcm_seal_raw(key, plaintext.as_bytes())?;
    Some(format!(
        "{TENANT_PREFIX}{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob)
    ))
}

fn gcm_open_tagged(key: &[u8; 32], stored: &str) -> Option<String> {
    let rest = stored.strip_prefix(TENANT_PREFIX)?;
    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, rest).ok()?;
    if blob.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&blob[..12]);
    let pt = cipher.decrypt(nonce, &blob[12..]).ok()?;
    String::from_utf8(pt).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_dek_envelope_roundtrips_and_is_ciphertext() {
        let dek = [9u8; 32];
        let secret = "AKIAIOSFODNN7EXAMPLE/tenant-dek-secret";
        let enc = gcm_seal_tagged(&dek, secret).expect("seal");
        assert!(enc.starts_with(TENANT_PREFIX), "must be tagged wzt1:");
        assert!(!enc.contains(secret), "plaintext must not appear at rest");
        assert_eq!(gcm_open_tagged(&dek, &enc).as_deref(), Some(secret));
    }

    #[test]
    fn tenant_dek_wrong_key_and_wrong_prefix_fail() {
        let enc = gcm_seal_tagged(&[9u8; 32], "topsecret").expect("seal");
        assert!(gcm_open_tagged(&[8u8; 32], &enc).is_none(), "wrong key fails");
        // A wzv1:/plaintext value is not a wzt1: envelope.
        assert!(gcm_open_tagged(&[9u8; 32], "wzv1:abc").is_none());
        assert!(gcm_open_tagged(&[9u8; 32], "legacy-plaintext").is_none());
    }

    #[test]
    fn local_provider_style_raw_wrap_roundtrips() {
        // gcm_seal_raw/open_raw are what LocalKeyProvider uses to wrap the DEK.
        let kek = [3u8; 32];
        let dek = [7u8; 32];
        let wrapped = gcm_seal_raw(&kek, &dek).expect("wrap");
        assert_ne!(wrapped.as_slice(), &dek[..], "wrapped DEK must be ciphertext");
        assert_eq!(gcm_open_raw(&kek, &wrapped), Some(dek));
        assert_eq!(gcm_open_raw(&[4u8; 32], &wrapped), None, "wrong KEK fails");
    }

    struct MockProvider;

    #[async_trait::async_trait]
    impl KeyProvider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn wrap_dek(
            &self,
            _tenant_id: i64,
            plaintext_dek: &[u8; 32],
        ) -> Result<Vec<u8>, KeyProviderError> {
            Ok(plaintext_dek.to_vec())
        }
        async fn unwrap_dek(
            &self,
            _tenant_id: i64,
            wrapped: &[u8],
        ) -> Result<[u8; 32], KeyProviderError> {
            if wrapped.len() != 32 {
                return Err(KeyProviderError::Crypto);
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(wrapped);
            Ok(k)
        }
    }

    #[tokio::test]
    async fn provision_dek_default_generates_random_and_wraps() {
        let p = MockProvider;
        let (dek, wrapped) = p.provision_dek(42).await.expect("provision");
        assert_ne!(dek, [0u8; 32], "DEK must be random, not zeroed");
        assert_eq!(wrapped, dek.to_vec(), "mock wrap is identity");
        assert_eq!(p.unwrap_dek(42, &wrapped).await.expect("unwrap"), dek);
    }
}
