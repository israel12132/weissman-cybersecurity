//! Auth-plane helpers: `auth.audit_auth_access` (BYPASSRLS telemetry) and `auth.auth_insert_user` (no direct `users` DML).

use sqlx::{Executor, Postgres};

/// Record a BYPASSRLS auth operation (triggers `security_events` + optional auto-mitigation).
pub async fn record_auth_access<'e, E>(e: E, tenant_id: i64, context: &str) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("SELECT auth.audit_auth_access($1, $2)")
        .bind(tenant_id)
        .bind(context)
        .execute(e)
        .await?;
    Ok(())
}

/// Insert into `public.users` via `SECURITY DEFINER` (auth role has no direct INSERT on `users`).
pub async fn insert_user_auth<'e, E>(
    e: E,
    tenant_id: i64,
    email: &str,
    password_hash: Option<&str>,
    role: &str,
) -> Result<i64, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar::<_, i64>("SELECT auth.auth_insert_user($1, $2, $3, $4)")
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(role)
        .fetch_one(e)
        .await
}
