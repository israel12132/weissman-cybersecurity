//! Immutable audit trail (append-only rows) with per-tenant SHA-256 hash chain.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
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

pub async fn insert_audit(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_user_id: Option<i64>,
    user_label: &str,
    action_type: &str,
    details: &str,
    ip_address: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;

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

/// Backfill `event_hash` / `prev_hash` for legacy rows missing chain linkage (idempotent).
pub async fn backfill_missing_hashes(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let tenants: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT tenant_id FROM audit_logs WHERE event_hash IS NULL ORDER BY tenant_id",
    )
    .fetch_all(pool)
    .await?;
    let mut updated = 0u64;
    for tenant_id in tenants {
        updated += backfill_tenant_hashes(pool, tenant_id).await?;
    }
    Ok(updated)
}

async fn backfill_tenant_hashes(pool: &PgPool, tenant_id: i64) -> Result<u64, sqlx::Error> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Ok(0);
    };
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    let rows = sqlx::query(
        r#"SELECT id, created_at, actor_user_id,
                  COALESCE(user_label, '') AS user_label,
                  COALESCE(action_type, '') AS action_type,
                  COALESCE(details, '') AS details,
                  COALESCE(ip_address, '') AS ip_address
             FROM audit_logs
            WHERE tenant_id = $1 AND event_hash IS NULL
            ORDER BY id ASC"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await?;

    let mut prev_hash: String = sqlx::query_scalar(
        r#"SELECT COALESCE(event_hash, '') FROM audit_logs
           WHERE tenant_id = $1 AND event_hash IS NOT NULL
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or_default();

    let mut count = 0u64;
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let created_at: DateTime<Utc> = r.try_get("created_at").unwrap_or_else(|_| Utc::now());
        let actor_user_id: Option<i64> = r.try_get("actor_user_id").ok();
        let user_label: String = r.try_get("user_label").unwrap_or_default();
        let action_type: String = r.try_get("action_type").unwrap_or_default();
        let details: String = r.try_get("details").unwrap_or_default();
        let ip_address: String = r.try_get("ip_address").unwrap_or_default();
        let canonical = canonical_audit_payload(
            &prev_hash,
            tenant_id,
            actor_user_id,
            &user_label,
            &action_type,
            &details,
            &ip_address,
            created_at,
        );
        let event_hash = sha256_hex(&canonical);
        sqlx::query(
            "UPDATE audit_logs SET prev_hash = $1, event_hash = $2 WHERE id = $3 AND tenant_id = $4",
        )
        .bind(&prev_hash)
        .bind(&event_hash)
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        prev_hash = event_hash;
        count += 1;
    }
    tx.commit().await?;
    Ok(count)
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

/// Verify hash chain for exported rows (ordered ascending by id).
pub fn verify_chain(entries: &[AuditExportEntry]) -> bool {
    let mut expected_prev = String::new();
    for entry in entries {
        if entry.prev_hash != expected_prev {
            return false;
        }
        let Some(ref event_hash) = entry.event_hash else {
            // Legacy row without hash — chain breaks here unless genesis continues.
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

    let chain_intact = verify_chain(&entries);
    Ok((entries, total, chain_intact))
}

pub async fn list_recent(
    tx: &mut Transaction<'_, Postgres>,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, created_at, actor_user_id, user_label, action_type, details, ip_address, prev_hash, event_hash FROM audit_logs ORDER BY id DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&mut **tx)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let uid: Option<i64> = r.try_get("actor_user_id").ok();
        out.push(json!({
            "id": r.try_get::<i64, _>("id").unwrap_or(0),
            "timestamp": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            "user_id": uid,
            "user": r.try_get::<String, _>("user_label").unwrap_or_default(),
            "action_type": r.try_get::<String, _>("action_type").unwrap_or_default(),
            "details": r.try_get::<String, _>("details").unwrap_or_default(),
            "ip_address": r.try_get::<String, _>("ip_address").unwrap_or_default(),
            "prev_hash": r.try_get::<String, _>("prev_hash").unwrap_or_default(),
            "event_hash": r.try_get::<Option<String>, _>("event_hash").ok().flatten(),
        }));
    }
    Ok(out)
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
}
