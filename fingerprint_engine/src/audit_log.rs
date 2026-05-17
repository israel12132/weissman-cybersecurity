//! Immutable audit trail (append-only rows), tenant-scoped via RLS + explicit tenant_id on insert.

use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};

pub async fn insert_audit(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    actor_user_id: Option<i64>,
    user_label: &str,
    action_type: &str,
    details: &str,
    ip_address: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_logs (tenant_id, actor_user_id, user_label, action_type, details, ip_address) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(tenant_id)
    .bind(actor_user_id)
    .bind(user_label)
    .bind(action_type)
    .bind(details)
    .bind(ip_address)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn list_recent(
    tx: &mut Transaction<'_, Postgres>,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, created_at, actor_user_id, user_label, action_type, details, ip_address FROM audit_logs ORDER BY id DESC LIMIT $1",
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
        }));
    }
    Ok(out)
}

/// Resolve email for audit labels (auth pool; `auth.v_user_lookup` + BYPASSRLS audit).
pub async fn user_email_for_id(auth_pool: &PgPool, user_id: i64) -> String {
    let row = sqlx::query(
        "SELECT tenant_id, email FROM auth.v_user_lookup WHERE id = $1",
    )
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
        let _ = weissman_db::auth_access::record_auth_access(auth_pool, tid, "audit_user_email_lookup").await;
    }
    r.try_get::<String, _>("email")
        .unwrap_or_else(|_| format!("user_id:{}", user_id))
}
