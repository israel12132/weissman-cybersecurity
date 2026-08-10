//! Immutable audit trail (append-only rows) with per-tenant SHA-256 hash chain.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};

const CHAIN_VERSION: &str = "v1";

/// Canonical bytes hashed into `event_hash` (must remain stable for verification).
pub fn canonical_audit_payload(
    prev_hash: &str,
    tenant_id: i64,
    actor_user_id: Option<i64>,
    user_label: &str,
    action_type: &str,
    details: &str,
    ip_address: &str,
    created_at: DateTime<Utc>,
) -> String {
    format!(
        "{CHAIN_VERSION}|{prev_hash}|{tenant_id}|{}|{user_label}|{action_type}|{details}|{ip_address}|{}",
        actor_user_id.unwrap_or(0),
        created_at.to_rfc3339()
    )
}

fn sha256_hex(input: &str) -> String {
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

/// Public digest helper for compliance pack snapshots and exports.
#[must_use]
pub fn digest_hex(input: &str) -> String {
    sha256_hex(input)
}

// ── Keyed chain checkpoints (non-repudiation beyond DB-superuser compromise) ────
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

/// HMAC key for audit checkpoints — held OUTSIDE the DB. Dedicated key preferred; JWT fallback.
fn checkpoint_secret() -> Option<Vec<u8>> {
    std::env::var("WEISSMAN_AUDIT_CHECKPOINT_SECRET")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("WEISSMAN_JWT_SECRET").ok())
        .map(|s| s.trim().as_bytes().to_vec())
        .filter(|b| !b.is_empty())
}

fn checkpoint_hmac_bytes(key: &[u8], canonical: &str) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn checkpoint_canonical(tenant_id: i64, head_id: i64, head_hash: &str) -> String {
    format!("cpv1|{tenant_id}|{head_id}|{head_hash}")
}

/// Write a keyed checkpoint over the current audit-chain head for `tenant_id`.
/// Returns `Ok(false)` when there is no hashed head yet or no checkpoint key is configured.
/// The HMAC is keyed by a secret held outside the DB, so a superuser who rewrites history and
/// recomputes every unkeyed SHA-256 `event_hash` still cannot forge a matching checkpoint.
pub async fn write_chain_checkpoint(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
) -> Result<bool, sqlx::Error> {
    let Some(key) = checkpoint_secret() else {
        return Ok(false);
    };
    let head: Option<(i64, String)> = sqlx::query_as(
        r#"SELECT id, event_hash FROM audit_logs
           WHERE tenant_id = $1 AND event_hash IS NOT NULL
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((head_id, head_hash)) = head else {
        return Ok(false);
    };
    let mac = hex::encode(checkpoint_hmac_bytes(
        &key,
        &checkpoint_canonical(tenant_id, head_id, &head_hash),
    ));
    sqlx::query(
        r#"INSERT INTO audit_chain_checkpoints
           (tenant_id, head_event_id, head_hash, checkpoint_hmac)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(tenant_id)
    .bind(head_id)
    .bind(&head_hash)
    .bind(&mac)
    .execute(&mut **tx)
    .await?;
    Ok(true)
}

/// Verify the latest checkpoint for `tenant_id`. `Ok(None)` = no checkpoint/key;
/// `Ok(Some(true))` = checkpoint HMAC valid AND the referenced audit row still carries that
/// `event_hash`; `Ok(Some(false))` = tamper detected (forged checkpoint or rewritten history).
pub async fn verify_latest_checkpoint(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
) -> Result<Option<bool>, sqlx::Error> {
    let Some(key) = checkpoint_secret() else {
        return Ok(None);
    };
    let cp: Option<(i64, String, String)> = sqlx::query_as(
        r#"SELECT head_event_id, head_hash, checkpoint_hmac FROM audit_chain_checkpoints
           WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((head_id, head_hash, stored_mac)) = cp else {
        return Ok(None);
    };
    let expected =
        checkpoint_hmac_bytes(&key, &checkpoint_canonical(tenant_id, head_id, &head_hash));
    if !crate::security_hardening::constant_time_hmac_hex_eq(&expected, &stored_mac) {
        return Ok(Some(false));
    }
    let current: Option<String> =
        sqlx::query_scalar("SELECT event_hash FROM audit_logs WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(head_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    Ok(Some(current.as_deref() == Some(head_hash.as_str())))
}

pub async fn insert_audit(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_user_id: Option<i64>,
    user_label: &str,
    action_type: &str,
    details: &str,
    ip_address: &str,
) -> Result<(), sqlx::Error> {
    // Serialize hash-chain appends per tenant. BOUNDED (weissman_db::advisory_lock): a bare
    // `pg_advisory_xact_lock` waits forever, and this key is `tenant_id` — the coarsest key in
    // the codebase, taken on every auth and scan-routing path — so one stuck holder wedged every
    // other writer for that tenant. On timeout we return Err and the caller's transaction aborts;
    // the chain is never appended to unserialized.
    weissman_db::advisory_lock::advisory_xact_lock(&mut **tx, tenant_id).await?;

    let prev_hash: String = sqlx::query_scalar(
        r#"SELECT COALESCE(event_hash, '') FROM audit_logs
           WHERE tenant_id = $1 AND event_hash IS NOT NULL
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or_default();

    let created_at = Utc::now();
    let canonical = canonical_audit_payload(
        &prev_hash,
        tenant_id,
        actor_user_id,
        user_label,
        action_type,
        details,
        ip_address,
        created_at,
    );
    let event_hash = sha256_hex(&canonical);

    sqlx::query(
        r#"INSERT INTO audit_logs
           (tenant_id, actor_user_id, user_label, action_type, details, ip_address,
            prev_hash, event_hash, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(tenant_id)
    .bind(actor_user_id)
    .bind(user_label)
    .bind(action_type)
    .bind(details)
    .bind(ip_address)
    .bind(&prev_hash)
    .bind(&event_hash)
    .bind(created_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Best-effort tamper-evident audit row for failed login (does not block auth flow).
pub async fn record_login_failure_audit(
    pool: &PgPool,
    tenant_id: i64,
    email: &str,
    ip: &str,
    detail: &str,
) {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return;
    };
    if insert_audit(&mut tx, tenant_id, None, email, "login_failed", detail, ip)
        .await
        .is_ok()
    {
        let _ = tx.commit().await;
    } else {
        let _ = tx.rollback().await;
    }
}

/// Per-tenant summary of legacy audit rows written **before** the hash chain existed.
///
/// Returns `(tenant_id, unchained_rows, last_unchained_id)` for every tenant that still has rows
/// with a NULL `event_hash`.
///
/// # Why this replaced a backfill
///
/// This module used to expose `backfill_missing_hashes`, which walked those rows and `UPDATE`d a
/// freshly-computed `event_hash` into each one. That was wrong twice over:
///
///  1. **It could never run.** `audit_logs` is deliberately append-only — the `audit_logs_block_update`
///     and `audit_logs_block_delete` triggers reject every mutation, and `weissman_app` is granted
///     only INSERT and SELECT. The call failed at boot with `permission denied for table audit_logs`
///     on every single start, logging a warning forever and repairing nothing.
///  2. **It should never run.** Retro-hashing a row proves nothing: the digest would be computed
///     from whatever the row contains *now*, long after the window in which it could have been
///     altered. Writing it would convert "this row predates tamper-evidence" — a true and auditable
///     statement — into "this row is chain-verified", which is false. Fabricating evidence is a
///     worse outcome than admitting a boundary, especially in the audit log of a security product.
///
/// The honest primitive is therefore to *report* the boundary, not erase it. [`verify_chain_from`]
/// already encodes the matching rule: a NULL `event_hash` is tolerated only in a contiguous prefix
/// before the first hashed row, and is treated as tampering once the chain has started.
pub async fn unchained_legacy_summary(pool: &PgPool) -> Result<Vec<(i64, i64, i64)>, sqlx::Error> {
    // `audit_logs` is tenant-scoped RLS, so a single unscoped sweep would silently return nothing.
    // Enumerate tenants explicitly, then read each one inside its own scoped transaction.
    let mut out = Vec::new();
    for tenant_id in weissman_db::active_tenant_ids(pool).await? {
        let mut tx = weissman_db::begin_tenant_tx(pool, tenant_id).await?;
        let row: Option<(i64, i64)> = sqlx::query_as(
            r#"SELECT count(*)::bigint AS unchained, COALESCE(max(id), 0)::bigint AS last_id
                 FROM audit_logs
                WHERE tenant_id = $1 AND event_hash IS NULL"#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let _ = tx.rollback().await;
        if let Some((unchained, last_id)) = row {
            if unchained > 0 {
                out.push((tenant_id, unchained, last_id));
            }
        }
    }
    Ok(out)
}

/// True when a tenant's NULL-hash rows form a contiguous prefix (legacy, benign) rather than
/// appearing after the chain started (truncation or tampering).
///
/// A NULL hash *after* the first hashed row is the signal an attacker would produce by nulling a
/// digest to make the verifier re-anchor, so it is reported separately and loudly.
pub async fn unchained_rows_are_a_legacy_prefix(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<bool, sqlx::Error> {
    // Scoped transaction: `audit_logs` is tenant-scoped RLS, so an unscoped read returns nothing
    // and would report every tenant as clean.
    let mut tx = weissman_db::begin_tenant_tx(pool, tenant_id).await?;
    let first_hashed: Option<i64> = sqlx::query_scalar(
        "SELECT min(id) FROM audit_logs WHERE tenant_id = $1 AND event_hash IS NOT NULL",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    let Some(first_hashed) = first_hashed else {
        // Nothing hashed yet: every row is legacy, which is a prefix by definition.
        let _ = tx.rollback().await;
        return Ok(true);
    };
    let stragglers: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM audit_logs \
         WHERE tenant_id = $1 AND event_hash IS NULL AND id > $2",
    )
    .bind(tenant_id)
    .bind(first_hashed)
    .fetch_one(&mut *tx)
    .await?;
    let _ = tx.rollback().await;
    Ok(stragglers == 0)
}


#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditExportEntry {
    pub id: i64,
    pub tenant_id: i64,
    pub created_at: String,
    pub actor_user_id: Option<i64>,
    pub user_label: String,
    pub action_type: String,
    pub details: String,
    pub ip_address: String,
    pub prev_hash: String,
    pub event_hash: Option<String>,
    pub chain_valid: bool,
}

/// Verify hash chain for exported rows (ordered ascending by id). Anchors at genesis (empty
/// prev_hash) — correct only for the first page (`offset == 0`).
pub fn verify_chain(entries: &[AuditExportEntry]) -> bool {
    verify_chain_from(entries, "")
}

/// Like [`verify_chain`] but seeds the expected previous hash with `anchor_prev` — the
/// `event_hash` of the row immediately preceding this page. Required for paginated exports
/// (`offset > 0`), whose first row's `prev_hash` is the previous page's last `event_hash`,
/// not the genesis empty string (otherwise every page past the first falsely reports "tamper").
pub fn verify_chain_from(entries: &[AuditExportEntry], anchor_prev: &str) -> bool {
    let mut expected_prev = anchor_prev.to_string();
    let mut chain_started = !anchor_prev.is_empty();
    for entry in entries {
        if entry.prev_hash != expected_prev {
            return false;
        }
        let Some(ref event_hash) = entry.event_hash else {
            // A NULL event_hash is tolerated ONLY for legacy rows that precede any hashed row.
            // Once the chain has started, a NULL hash is a truncation/tamper signal (an attacker
            // could otherwise null a hash to make the verifier re-anchor and pass) — fail closed.
            if chain_started {
                return false;
            }
            expected_prev.clear();
            continue;
        };
        let created_at = match DateTime::parse_from_rfc3339(&entry.created_at) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => return false,
        };
        let canonical = canonical_audit_payload(
            &entry.prev_hash,
            entry.tenant_id,
            entry.actor_user_id,
            &entry.user_label,
            &entry.action_type,
            &entry.details,
            &entry.ip_address,
            created_at,
        );
        if sha256_hex(&canonical) != *event_hash {
            return false;
        }
        expected_prev = event_hash.clone();
        chain_started = true;
    }
    true
}

pub async fn export_for_tenant(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    limit: i64,
    offset: i64,
) -> Result<(Vec<AuditExportEntry>, i64, bool), sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT id, tenant_id, created_at, actor_user_id,
                  COALESCE(user_label, '') AS user_label,
                  COALESCE(action_type, '') AS action_type,
                  COALESCE(details, '') AS details,
                  COALESCE(ip_address, '') AS ip_address,
                  COALESCE(prev_hash, '') AS prev_hash,
                  event_hash
             FROM audit_logs
            WHERE tenant_id = $1
            ORDER BY id ASC
            LIMIT $2 OFFSET $3"#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&mut **tx)
    .await?;

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM audit_logs WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut **tx)
            .await?;

    let mut entries = Vec::with_capacity(rows.len());
    for r in rows {
        let prev_hash: String = r.try_get("prev_hash").unwrap_or_default();
        let event_hash: Option<String> = r.try_get("event_hash").ok();
        let created_at: DateTime<Utc> = r.try_get("created_at").unwrap_or_else(|_| Utc::now());
        let tenant_id_row: i64 = r.try_get("tenant_id").unwrap_or(tenant_id);
        let actor_user_id: Option<i64> = r.try_get("actor_user_id").ok();
        let user_label: String = r.try_get("user_label").unwrap_or_default();
        let action_type: String = r.try_get("action_type").unwrap_or_default();
        let details: String = r.try_get("details").unwrap_or_default();
        let ip_address: String = r.try_get("ip_address").unwrap_or_default();
        let chain_valid = event_hash.as_ref().is_none_or(|eh| {
            let canonical = canonical_audit_payload(
                &prev_hash,
                tenant_id_row,
                actor_user_id,
                &user_label,
                &action_type,
                &details,
                &ip_address,
                created_at,
            );
            sha256_hex(&canonical) == *eh
        });
        entries.push(AuditExportEntry {
            id: r.try_get("id").unwrap_or(0),
            tenant_id: tenant_id_row,
            created_at: created_at.to_rfc3339(),
            actor_user_id,
            user_label,
            action_type,
            details,
            ip_address,
            prev_hash,
            event_hash,
            chain_valid,
        });
    }

    // For a paginated page (offset > 0), anchor verification on the event_hash of the row
    // immediately preceding this page, else the first row's non-genesis prev_hash would falsely
    // report a broken chain on every page past the first.
    let anchor_prev: String = if offset > 0 {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT event_hash FROM audit_logs WHERE tenant_id = $1 ORDER BY id ASC LIMIT 1 OFFSET $2",
        )
        .bind(tenant_id)
        .bind(offset - 1)
        .fetch_optional(&mut **tx)
        .await?
        .flatten()
        .unwrap_or_default()
    } else {
        String::new()
    };
    let chain_intact = verify_chain_from(&entries, &anchor_prev);
    Ok((entries, total, chain_intact))
}

/// Resolve email for audit labels (auth pool; `auth.v_user_lookup` + BYPASSRLS audit).
pub async fn user_email_for_id(auth_pool: &PgPool, user_id: i64) -> String {
    let row = sqlx::query("SELECT tenant_id, email FROM auth.v_user_lookup WHERE id = $1")
        .bind(user_id)
        .fetch_optional(auth_pool)
        .await
        .ok()
        .flatten();
    let Some(r) = row else {
        return format!("user_id:{}", user_id);
    };
    let tid: i64 = r.try_get("tenant_id").unwrap_or(0);
    if tid > 0 {
        let _ =
            weissman_db::auth_access::record_auth_access(auth_pool, tid, "audit_user_email_lookup")
                .await;
    }
    r.try_get::<String, _>("email")
        .unwrap_or_else(|_| format!("user_id:{}", user_id))
}

/// Periodically write a keyed checkpoint over each active tenant's audit-chain head.
/// Spawn once, on the singleton leader only. No-op when no checkpoint key is configured.
pub fn spawn_audit_checkpoint_worker(
    app_pool: std::sync::Arc<PgPool>,
    auth_pool: std::sync::Arc<PgPool>,
) {
    tokio::spawn(async move {
        let interval_secs = std::env::var("WEISSMAN_AUDIT_CHECKPOINT_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(3600)
            .clamp(60, 86_400);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            if checkpoint_secret().is_none() {
                continue;
            }
            let tenants: Vec<i64> =
                sqlx::query_scalar("SELECT id FROM tenants WHERE active = true ORDER BY id")
                    .fetch_all(auth_pool.as_ref())
                    .await
                    .unwrap_or_default();
            for tid in tenants {
                if let Ok(mut tx) = crate::db::begin_tenant_tx(app_pool.as_ref(), tid).await {
                    if let Err(e) = write_chain_checkpoint(&mut tx, tid).await {
                        tracing::warn!(target: "audit_checkpoint", tenant_id = tid, error = %e, "checkpoint write failed");
                    }
                    let _ = tx.commit().await;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_roundtrip() {
        let created = Utc::now();
        let canonical = canonical_audit_payload(
            "",
            1,
            Some(42),
            "admin@example.com",
            "login",
            "success",
            "127.0.0.1",
            created,
        );
        let hash = sha256_hex(&canonical);
        let entry = AuditExportEntry {
            id: 1,
            tenant_id: 1,
            created_at: created.to_rfc3339(),
            actor_user_id: Some(42),
            user_label: "admin@example.com".into(),
            action_type: "login".into(),
            details: "success".into(),
            ip_address: "127.0.0.1".into(),
            prev_hash: String::new(),
            event_hash: Some(hash.clone()),
            chain_valid: true,
        };
        assert!(verify_chain(&[entry]));
    }

    fn make_entry(id: i64, prev: &str) -> AuditExportEntry {
        let created = Utc::now();
        let canonical = canonical_audit_payload(prev, 1, None, "u", "a", "d", "127.0.0.1", created);
        AuditExportEntry {
            id,
            tenant_id: 1,
            created_at: created.to_rfc3339(),
            actor_user_id: None,
            user_label: "u".into(),
            action_type: "a".into(),
            details: "d".into(),
            ip_address: "127.0.0.1".into(),
            prev_hash: prev.to_string(),
            event_hash: Some(sha256_hex(&canonical)),
            chain_valid: true,
        }
    }

    #[test]
    fn null_hash_after_chain_started_is_rejected() {
        let e1 = make_entry(1, "");
        let head = e1.event_hash.clone().unwrap();
        let mut e2 = make_entry(2, &head);
        // Attacker nulls a hash mid-chain to force the verifier to re-anchor.
        e2.event_hash = None;
        assert!(
            !verify_chain(&[e1, e2]),
            "a NULL hash after the chain started must fail (truncation/tamper)"
        );
    }

    #[test]
    fn clean_two_row_chain_verifies() {
        let e1 = make_entry(1, "");
        let head = e1.event_hash.clone().unwrap();
        let e2 = make_entry(2, &head);
        assert!(verify_chain(&[e1, e2]));
    }
}
