//! CEO CRUD for `genesis_vaccine_vault` / `genesis_suspended_graphs` + remediation match (Rust, same queries as Python module).

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};
use std::sync::OnceLock;
use zeroize::Zeroizing;

// ── Secret-at-rest encryption (AES-256-GCM) ────────────────────────────────────
// Tenant secrets stored in the vault are encrypted at rest. The key is a dedicated
// `WEISSMAN_VAULT_KEY` (64 hex) or, failing that, derived from the managed
// `WEISSMAN_JWT_SECRET` (always present in production). Decryption is transparent
// on authorized read; legacy plaintext rows pass through unchanged (back-compat).

const VAULT_PREFIX: &str = "wzv1:";

fn vault_key() -> Option<[u8; 32]> {
    static KEY: OnceLock<Option<Zeroizing<[u8; 32]>>> = OnceLock::new();
    KEY.get_or_init(|| {
        if let Some(raw) = crate::secret_zeroize::env_zeroizing("WEISSMAN_VAULT_KEY") {
            if let Some(k) = crate::secret_zeroize::hex32(raw.trim()) {
                return Some(Zeroizing::new(k));
            }
            eprintln!(
                "[Weissman][vault] WEISSMAN_VAULT_KEY must be 64 hex chars (32 bytes); ignoring"
            );
        }
        if let Some(js) = crate::secret_zeroize::env_zeroizing("WEISSMAN_JWT_SECRET") {
            if js.trim().len() >= 16 {
                return Some(Zeroizing::new(crate::secret_zeroize::derive_aes256_key(
                    b"weissman-vault-key-v1|",
                    js.trim(),
                )));
            }
        }
        // No key material. In production the startup guard (key_present) refuses
        // boot; in dev the CEO vault stores plaintext (no managed secrets there).
        None
    })
    .as_ref()
    .map(|z| **z)
}

static DEDICATED_AFTER_SCRUB: OnceLock<bool> = OnceLock::new();

/// Load the encryption keyring from the environment. Call once at boot before
/// [`scrub_key_env_vars`] so decrypt still works after the env copies are wiped.
pub fn prime_keys_from_env() {
    let _ = DEDICATED_AFTER_SCRUB
        .get_or_init(|| crate::secret_zeroize::env_is_hex32_key("WEISSMAN_VAULT_KEY"));
    let _ = vault_key();
    let _ = decrypt_keyring();
}

/// Wipe `WEISSMAN_VAULT_KEY*` from the process environment after the keyring is in memory.
pub fn scrub_key_env_vars() {
    for name in ["WEISSMAN_VAULT_KEY", "WEISSMAN_VAULT_KEY_PREVIOUS"] {
        crate::secret_zeroize::scrub_env_var(name);
    }
}

/// True when a key is available to encrypt CEO-vault secrets at rest — including the JWT-derived
/// dev fallback, so this is NOT a useful production guard on its own. Use
/// [`dedicated_key_configured`] for that.
#[must_use]
pub fn key_present() -> bool {
    vault_key().is_some()
}

/// True only when a dedicated `WEISSMAN_VAULT_KEY` (64 hex) was supplied.
///
/// The production startup guard used to call `key_present()`, whose message promised it would
/// refuse to "store vault secrets unencrypted" — but `vault_key()` falls back to a key derived
/// from `WEISSMAN_JWT_SECRET`, and `security_startup` separately rejects any JWT secret shorter
/// than 48 chars, so the fallback's `len() < 16` branch is unreachable in production and the
/// guard was unconditionally true. It never once fired.
#[must_use]
pub fn dedicated_key_configured() -> bool {
    if let Some(&flag) = DEDICATED_AFTER_SCRUB.get() {
        return flag;
    }
    crate::secret_zeroize::env_is_hex32_key("WEISSMAN_VAULT_KEY")
}

/// Decrypt keyring: current key, then rotated-out previous keys
/// (`WEISSMAN_VAULT_KEY_PREVIOUS` hex + the `WEISSMAN_JWT_SECRET_PREVIOUS`
/// rotation keyring) so key rotation never orphans encrypted CEO-vault rows.
fn decrypt_keyring() -> &'static [[u8; 32]] {
    static KEYS: OnceLock<Zeroizing<Vec<[u8; 32]>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut v: Vec<[u8; 32]> = Vec::new();
        if let Some(k) = vault_key() {
            v.push(k);
        }
        if let Some(csv) = crate::secret_zeroize::env_zeroizing("WEISSMAN_VAULT_KEY_PREVIOUS") {
            v.extend(csv.split(',').filter_map(crate::secret_zeroize::hex32));
        }
        // Legacy rows encrypted with the CURRENT JWT secret, before a dedicated WEISSMAN_VAULT_KEY
        // existed. Without this, setting that key — what the hardened startup guard now demands —
        // orphans every existing CEO-vault secret, because the JWT-derived key only reached this
        // keyring via *_PREVIOUS. See the matching note in soar/integrations_vault.rs.
        if let Some(js) = crate::secret_zeroize::env_zeroizing("WEISSMAN_JWT_SECRET") {
            if js.trim().len() >= 16 {
                let legacy =
                    crate::secret_zeroize::derive_aes256_key(b"weissman-vault-key-v1|", js.trim());
                if !v.contains(&legacy) {
                    v.push(legacy);
                }
            }
        }
        if let Some(csv) = crate::secret_zeroize::env_zeroizing("WEISSMAN_JWT_SECRET_PREVIOUS") {
            for e in csv.split(',') {
                if e.trim().len() >= 16 {
                    v.push(crate::secret_zeroize::derive_aes256_key(
                        b"weissman-vault-key-v1|",
                        e.trim(),
                    ));
                }
            }
        }
        Zeroizing::new(v)
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
        "{}{}",
        VAULT_PREFIX,
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob)
    ))
}

fn decrypt_with_key(key: &[u8; 32], stored: &str) -> Option<String> {
    let rest = stored.strip_prefix(VAULT_PREFIX)?;
    let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, rest).ok()?;
    if blob.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&blob[..12]);
    let pt = cipher.decrypt(nonce, &blob[12..]).ok()?;
    String::from_utf8(pt).ok()
}

/// Encrypt a tenant secret for storage. Falls back to plaintext only when no key
/// is available (dev without JWT secret); production always has a key.
pub fn encrypt_secret(plaintext: &str) -> String {
    match vault_key() {
        Some(k) => encrypt_with_key(&k, plaintext).unwrap_or_else(|| plaintext.to_string()),
        None => plaintext.to_string(),
    }
}

/// Transparently decrypt a stored secret. Non-`wzv1:` values (legacy plaintext or
/// genuine vaccine detection signatures) are returned unchanged.
pub fn decrypt_secret(stored: &str) -> String {
    if !stored.starts_with(VAULT_PREFIX) {
        return stored.to_string();
    }
    for k in decrypt_keyring() {
        if let Some(pt) = decrypt_with_key(k, stored) {
            return pt;
        }
    }
    stored.to_string()
}

#[derive(Debug, Serialize)]
pub struct VaultRowOut {
    pub id: i64,
    pub tech_fingerprint: String,
    pub component_ref: String,
    pub attack_chain_json: Value,
    pub remediation_patch: String,
    pub detection_signature: String,
    pub severity: String,
    pub preemptive_validated: bool,
    pub simulation_feedback: Value,
    pub council_transcript: Value,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct VaultInsertBody {
    pub tech_fingerprint: String,
    #[serde(default)]
    pub component_ref: String,
    #[serde(default)]
    pub attack_chain_json: Value,
    #[serde(default)]
    pub remediation_patch: String,
    #[serde(default)]
    pub detection_signature: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub preemptive_validated: bool,
    #[serde(default)]
    pub simulation_feedback: Value,
    #[serde(default)]
    pub council_transcript: Value,
}

fn row_to_vault(r: &PgRow) -> Result<VaultRowOut, sqlx::Error> {
    let created: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
    Ok(VaultRowOut {
        id: r.try_get("id")?,
        tech_fingerprint: r.try_get("tech_fingerprint")?,
        component_ref: r.try_get("component_ref")?,
        attack_chain_json: r.try_get("attack_chain_json")?,
        remediation_patch: r.try_get("remediation_patch")?,
        detection_signature: decrypt_secret(&r.try_get::<String, _>("detection_signature")?),
        severity: r.try_get("severity")?,
        preemptive_validated: r.try_get("preemptive_validated")?,
        simulation_feedback: r.try_get("simulation_feedback")?,
        council_transcript: r.try_get("council_transcript")?,
        created_at: created.to_rfc3339(),
    })
}

pub async fn list_vault_rows(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
    offset: i64,
) -> Result<Vec<VaultRowOut>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, tech_fingerprint, component_ref, attack_chain_json, remediation_patch,
                  detection_signature, severity, preemptive_validated, simulation_feedback,
                  council_transcript, created_at
           FROM genesis_vaccine_vault
           ORDER BY id DESC
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit.min(500).max(1))
    .bind(offset.max(0))
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let mut out = Vec::new();
    for r in rows {
        out.push(row_to_vault(&r)?);
    }
    Ok(out)
}

pub async fn get_vault_row(
    pool: &PgPool,
    tenant_id: i64,
    id: i64,
) -> Result<Option<VaultRowOut>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT id, tech_fingerprint, component_ref, attack_chain_json, remediation_patch,
                  detection_signature, severity, preemptive_validated, simulation_feedback,
                  council_transcript, created_at
           FROM genesis_vaccine_vault WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    row.as_ref().map(row_to_vault).transpose()
}

pub async fn post_vault_row(
    pool: &PgPool,
    tenant_id: i64,
    body: &VaultInsertBody,
) -> Result<i64, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO genesis_vaccine_vault (
            tenant_id, tech_fingerprint, component_ref, attack_chain_json,
            remediation_patch, detection_signature, severity, preemptive_validated,
            simulation_feedback, council_transcript
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(body.tech_fingerprint.trim())
    .bind(body.component_ref.trim())
    .bind(&body.attack_chain_json)
    .bind(body.remediation_patch.trim())
    .bind(body.detection_signature.trim())
    .bind(
        body.severity
            .trim()
            .to_lowercase()
            .chars()
            .take(32)
            .collect::<String>(),
    )
    .bind(body.preemptive_validated)
    .bind(&body.simulation_feedback)
    .bind(&body.council_transcript)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

#[derive(Debug, Deserialize)]
pub struct VaultSecretBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_secret_type")]
    pub r#type: String,
    pub value: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}

fn default_secret_type() -> String {
    "api_key".to_string()
}

pub fn secret_body_to_vault_insert(body: &VaultSecretBody) -> VaultInsertBody {
    VaultInsertBody {
        tech_fingerprint: format!("{}:{}", body.r#type.trim(), body.description.trim()),
        component_ref: body.name.trim().to_string(),
        attack_chain_json: json!({
            "secret_type": body.r#type,
            "expires_at": body.expires_at,
        }),
        remediation_patch: body.description.trim().to_string(),
        detection_signature: encrypt_secret(&body.value),
        severity: body.r#type.trim().to_lowercase(),
        preemptive_validated: false,
        simulation_feedback: json!({}),
        council_transcript: json!({}),
    }
}

pub async fn update_vault_row(
    pool: &PgPool,
    tenant_id: i64,
    id: i64,
    body: &VaultSecretBody,
) -> Result<bool, sqlx::Error> {
    let insert = secret_body_to_vault_insert(body);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let res = sqlx::query(
        r#"UPDATE genesis_vaccine_vault
              SET tech_fingerprint = $1, component_ref = $2, attack_chain_json = $3,
                  remediation_patch = $4, detection_signature = $5, severity = $6
            WHERE id = $7"#,
    )
    .bind(insert.tech_fingerprint.trim())
    .bind(insert.component_ref.trim())
    .bind(&insert.attack_chain_json)
    .bind(insert.remediation_patch.trim())
    .bind(insert.detection_signature.trim())
    .bind(
        insert
            .severity
            .trim()
            .to_lowercase()
            .chars()
            .take(32)
            .collect::<String>(),
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

pub async fn delete_vault_row(pool: &PgPool, tenant_id: i64, id: i64) -> Result<bool, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let res = sqlx::query("DELETE FROM genesis_vaccine_vault WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

/// Same logic as Python `remediation_engine.knowledge_match_sync` — executed in Rust against live DB.
pub async fn match_vault_row(
    pool: &PgPool,
    tenant_id: i64,
    vault_id: i64,
) -> Result<Value, String> {
    let row = get_vault_row(pool, tenant_id, vault_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "vault row not found".to_string())?;
    let fp = row.tech_fingerprint.trim();
    if fp.is_empty() {
        return Err("vault row has empty tech_fingerprint".into());
    }
    crate::council_synthesis::genesis_knowledge_match(pool, tenant_id, fp)
        .await
        .map_err(|e| e.to_string())
}

pub async fn export_vault_criticals_csv(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<String, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, tech_fingerprint, component_ref, severity, detection_signature,
                  LEFT(remediation_patch, 2000) AS patch_excerpt, created_at
           FROM genesis_vaccine_vault
           WHERE lower(trim(severity)) = 'critical'
           ORDER BY id DESC
           LIMIT 2000"#,
    )
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let mut w = String::from(
        "id,tech_fingerprint,component_ref,severity,detection_signature,patch_excerpt,created_at\n",
    );
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let tf: String = r.try_get("tech_fingerprint").unwrap_or_default();
        let cr: String = r.try_get("component_ref").unwrap_or_default();
        let sev: String = r.try_get("severity").unwrap_or_default();
        let det: String = r.try_get("detection_signature").unwrap_or_default();
        let pe: String = r.try_get("patch_excerpt").unwrap_or_default();
        let ct: chrono::DateTime<chrono::Utc> = r
            .try_get("created_at")
            .unwrap_or_else(|_| chrono::Utc::now());
        let esc = |s: &str| {
            let x = s.replace('"', "\"\"");
            format!("\"{}\"", x.replace('\n', " "))
        };
        w.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            id,
            esc(&tf),
            esc(&cr),
            esc(&sev),
            esc(&det),
            esc(&pe),
            esc(&ct.to_rfc3339())
        ));
    }
    Ok(w)
}

#[derive(Debug, Serialize)]
pub struct SuspendedRowOut {
    pub id: i64,
    pub status: String,
    pub max_depth: i64,
    pub root_index: i64,
    pub ram_budget_bytes: i64,
    pub created_at: String,
}

pub async fn list_suspended_graphs(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> Result<Vec<SuspendedRowOut>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, status, max_depth, root_index, ram_budget_bytes, created_at
           FROM genesis_suspended_graphs
           ORDER BY id DESC
           LIMIT $1"#,
    )
    .bind(limit.min(200).max(1))
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let mut out = Vec::new();
    for r in rows {
        let ct: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
        out.push(SuspendedRowOut {
            id: r.try_get("id")?,
            status: r.try_get("status")?,
            max_depth: r.try_get("max_depth")?,
            root_index: r.try_get("root_index")?,
            ram_budget_bytes: r.try_get("ram_budget_bytes")?,
            created_at: ct.to_rfc3339(),
        });
    }
    Ok(out)
}

pub async fn get_suspended_graph(
    pool: &PgPool,
    tenant_id: i64,
    id: i64,
) -> Result<Option<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT id, status, graph_snapshot, dfs_stack, visited_nodes, seeds_json,
                  max_depth, root_index, paths_found_json, ram_budget_bytes, created_at, updated_at
           FROM genesis_suspended_graphs WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let Some(r) = row else {
        return Ok(None);
    };
    let ct: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
    let ut: chrono::DateTime<chrono::Utc> = r.try_get("updated_at")?;
    let idv: i64 = r.try_get("id")?;
    let st: String = r.try_get("status")?;
    let gs: Value = r.try_get("graph_snapshot")?;
    let ds: Value = r.try_get("dfs_stack")?;
    let vn: Value = r.try_get("visited_nodes")?;
    let sj: Value = r.try_get("seeds_json")?;
    let md: i64 = r.try_get("max_depth")?;
    let ri: i64 = r.try_get("root_index")?;
    let pj: Value = r.try_get("paths_found_json")?;
    let rb: i64 = r.try_get("ram_budget_bytes")?;
    Ok(Some(json!({
        "id": idv,
        "status": st,
        "graph_snapshot": gs,
        "dfs_stack": ds,
        "visited_nodes": vn,
        "seeds_json": sj,
        "max_depth": md,
        "root_index": ri,
        "paths_found_json": pj,
        "ram_budget_bytes": rb,
        "created_at": ct.to_rfc3339(),
        "updated_at": ut.to_rfc3339(),
    })))
}

pub async fn post_resume_suspended_job(
    pool: &PgPool,
    tenant_id: i64,
    suspended_id: i64,
    trace: Option<&str>,
) -> Result<uuid::Uuid, String> {
    let body = json!({ "resume_suspended_id": suspended_id });
    weissman_db::job_queue::enqueue(pool, tenant_id, "genesis_eternal_fuzz", body, trace)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_secret_encrypts_and_round_trips() {
        let key = [7u8; 32];
        let secret = "AKIAIOSFODNN7EXAMPLE/secretvalue";
        let enc = encrypt_with_key(&key, secret).expect("encrypt");
        assert!(enc.starts_with(VAULT_PREFIX), "ciphertext must be tagged");
        assert!(
            !enc.contains(secret),
            "plaintext must not appear in ciphertext"
        );
        assert_eq!(decrypt_with_key(&key, &enc).as_deref(), Some(secret));
    }

    #[test]
    fn vault_wrong_key_fails_and_legacy_passes_through() {
        let enc = encrypt_with_key(&[7u8; 32], "topsecret").expect("encrypt");
        assert!(
            decrypt_with_key(&[8u8; 32], &enc).is_none(),
            "wrong key must fail"
        );
        // Legacy plaintext (no wzv1: prefix) returns unchanged.
        assert_eq!(
            decrypt_secret("legacy-plaintext-signature"),
            "legacy-plaintext-signature"
        );
    }

    #[test]
    fn scrub_unsets_vault_key_env_but_keeps_dedicated_flag() {
        let hex: String = "ab".repeat(32);
        std::env::set_var("WEISSMAN_VAULT_KEY", &hex);
        prime_keys_from_env();
        assert!(dedicated_key_configured());
        scrub_key_env_vars();
        assert!(
            std::env::var("WEISSMAN_VAULT_KEY").is_err(),
            "env copy must be gone after boot scrub"
        );
        assert!(
            dedicated_key_configured(),
            "dedicated-key flag must survive env wipe"
        );
        std::env::remove_var("WEISSMAN_VAULT_KEY");
    }
}
