//! PostgreSQL: pooled connections, sqlx migrations, RLS session variable `app.current_tenant_id`.
//! App role (`weissman_app`) is subject to RLS. Auth role (`weissman_auth`) bypasses RLS for login / IdP resolution only.
//!
//! [`database_url_from_env`] and pool helpers read configuration from the process environment at runtime.

#![forbid(unsafe_code)]

pub mod auth_access;
pub mod auth_rotation;
pub mod env_bootstrap;
pub mod job_queue;
pub mod llm_usage;

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Executor, Postgres, Transaction};
use std::sync::Arc;
use std::time::Duration;

/// Primary application database URL (role `weissman_app`, RLS). Read from `DATABASE_URL` when the process starts each call.
pub fn database_url_from_env() -> Result<String, std::env::VarError> {
    std::env::var("DATABASE_URL")
}

/// Optional separate auth URL (`weissman_auth`). When unset, callers typically use the same URL as the app pool.
pub fn auth_database_url_from_env() -> Option<String> {
    std::env::var("WEISSMAN_AUTH_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve the URL used for the auth pool: `WEISSMAN_AUTH_DATABASE_URL` or `DATABASE_URL`.
pub fn resolve_auth_database_url() -> Result<String, std::env::VarError> {
    if let Some(u) = auth_database_url_from_env() {
        Ok(u)
    } else {
        database_url_from_env()
    }
}

/// Superuser or owner URL to run embedded migrations (optional at runtime).
pub async fn run_migrations(database_url: &str) -> Result<(), sqlx::migrate::MigrateError> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url)
        .await
        .map_err(sqlx::migrate::MigrateError::from)?;
    sqlx::migrate!("./migrations").run(&pool).await
}

/// App pool: `WEISSMAN_APP_POOL_MAX` (default 48), `WEISSMAN_APP_POOL_MIN` (default 2).
/// Avoid holding a tenant transaction across `.await` to unrelated work — release connections quickly.
pub async fn connect_app(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let max: u32 = std::env::var("WEISSMAN_APP_POOL_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(48);
    let min: u32 = std::env::var("WEISSMAN_APP_POOL_MIN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2)
        .min(max);
    PgPoolOptions::new()
        .max_connections(max)
        .min_connections(min)
        .acquire_timeout(Duration::from_secs(30))
        .connect(database_url)
        .await
}

/// Connect app pool using `DATABASE_URL` from the environment.
pub async fn connect_app_from_env() -> Result<PgPool, sqlx::Error> {
    let url = database_url_from_env().map_err(|e| {
        sqlx::Error::Configuration(format!("DATABASE_URL: {}", e).into())
    })?;
    let t = url.trim();
    if t.is_empty() {
        return Err(sqlx::Error::Configuration(
            "DATABASE_URL is set but empty".into(),
        ));
    }
    connect_app(t).await
}

/// Auth pool: `WEISSMAN_AUTH_POOL_MAX` (default 12). Smaller than app pool; login/bootstrap only.
pub async fn connect_auth(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let max: u32 = std::env::var("WEISSMAN_AUTH_POOL_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    PgPoolOptions::new()
        .max_connections(max)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(15))
        .connect(database_url)
        .await
}

/// Connect auth pool using `WEISSMAN_AUTH_DATABASE_URL` or `DATABASE_URL`.
pub async fn connect_auth_from_env() -> Result<PgPool, sqlx::Error> {
    let url = resolve_auth_database_url().map_err(|e| {
        sqlx::Error::Configuration(format!("auth database URL: {}", e).into())
    })?;
    let t = url.trim();
    if t.is_empty() {
        return Err(sqlx::Error::Configuration(
            "resolved auth database URL is empty".into(),
        ));
    }
    connect_auth(t).await
}

/// URL for the intel / global-payload pool. Defaults to `DATABASE_URL` when unset.
pub fn intel_database_url_from_env() -> Result<String, std::env::VarError> {
    std::env::var("WEISSMAN_INTEL_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))
}

/// Pool with `search_path = intel, public` so global payload tables stay isolated from tenant-heavy `public` usage.
pub async fn connect_intel(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let max: u32 = std::env::var("WEISSMAN_INTEL_POOL_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    PgPoolOptions::new()
        .max_connections(max)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO intel, public")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
}

pub async fn connect_intel_from_env() -> Result<PgPool, sqlx::Error> {
    let url = intel_database_url_from_env().map_err(|e| {
        sqlx::Error::Configuration(format!("WEISSMAN_INTEL_DATABASE_URL / DATABASE_URL: {}", e).into())
    })?;
    let t = url.trim();
    if t.is_empty() {
        return Err(sqlx::Error::Configuration(
            "intel database URL is empty".into(),
        ));
    }
    env_bootstrap::validate_database_url(t).map_err(|msg| {
        sqlx::Error::Configuration(format!("WEISSMAN_INTEL_DATABASE_URL: {}", msg).into())
    })?;
    connect_intel(t).await
}

/// Set RLS GUC for this transaction only (`true` = transaction-local).
pub async fn set_tenant_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Set GUC on a bare connection (use only when the connection is dedicated, e.g. right after acquire, before release).
pub async fn set_tenant_conn<'e, E>(e: E, tenant_id: i64) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(e)
        .await?;
    Ok(())
}

pub async fn begin_tenant_tx(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    set_tenant_tx(&mut tx, tenant_id).await?;
    Ok(tx)
}

/// Like [`begin_tenant_tx`], but takes an owned [`Arc`] so the returned future is [`Send`] when used
/// from long-lived tasks (e.g. panic-shielded orchestrator cycles) without capturing `&PgPool`.
pub async fn begin_tenant_tx_arc(
    pool: Arc<PgPool>,
    tenant_id: i64,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    set_tenant_tx(&mut tx, tenant_id).await?;
    Ok(tx)
}

/// Bootstrap admin from env into `default` tenant (auth pool; BYPASSRLS).
/// Password material is never hardcoded unless `WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=1` (dev only).
pub async fn ensure_admin_user(auth_pool: &PgPool) -> Result<(), sqlx::Error> {
    let email =
        std::env::var("WEISSMAN_ADMIN_EMAIL").unwrap_or_else(|_| "admin@localhost".to_string());
    let hash_opt = std::env::var("WEISSMAN_ADMIN_BCRYPT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("WEISSMAN_ADMIN_PASSWORD")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .and_then(|p| bcrypt::hash(&p, bcrypt::DEFAULT_COST).ok())
        })
        .or_else(|| {
            if matches!(
                std::env::var("WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD").as_deref(),
                Ok("1") | Ok("true") | Ok("yes")
            ) {
                bcrypt::hash("changeme", bcrypt::DEFAULT_COST).ok()
            } else {
                None
            }
        });
    let Some(hash) = hash_opt else {
        tracing::debug!(
            target: "security_audit",
            "ensure_admin_user skipped: set WEISSMAN_ADMIN_PASSWORD, WEISSMAN_ADMIN_BCRYPT, or WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=1 (dev)"
        );
        return Ok(());
    };
    let tid: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
    )
    .fetch_optional(auth_pool)
    .await?;
    let Some(tenant_id) = tid else {
        return Ok(());
    };
    auth_access::record_auth_access(auth_pool, tenant_id, "ensure_admin_user").await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth.v_user_lookup WHERE tenant_id = $1 AND lower(trim(email)) = lower(trim($2)))",
    )
    .bind(tenant_id)
    .bind(&email)
    .fetch_one(auth_pool)
    .await?;
    if exists {
        return Ok(());
    }
    auth_access::insert_user_auth(auth_pool, tenant_id, &email, Some(&hash), "admin").await?;
    Ok(())
}

/// One-time bootstrap admin in `default` tenant when **`WEISSMAN_MASTER_BOOTSTRAP_EMAIL`** is set together with
/// `WEISSMAN_MASTER_BOOTSTRAP_PASSWORD` or `WEISSMAN_MASTER_BOOTSTRAP_BCRYPT`. No hardcoded identity in source.
pub async fn ensure_master_bootstrap_user(auth_pool: &PgPool) -> Result<(), sqlx::Error> {
    let email = std::env::var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(email) = email else {
        tracing::debug!(
            target: "security_audit",
            "master bootstrap skipped: set WEISSMAN_MASTER_BOOTSTRAP_EMAIL (and password or bcrypt hash env)"
        );
        return Ok(());
    };
    let hash_opt = std::env::var("WEISSMAN_MASTER_BOOTSTRAP_BCRYPT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("WEISSMAN_MASTER_BOOTSTRAP_PASSWORD")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .and_then(|p| bcrypt::hash(&p, bcrypt::DEFAULT_COST).ok())
        });
    let Some(hash) = hash_opt else {
        tracing::debug!(
            target: "security_audit",
            "master bootstrap skipped: set WEISSMAN_MASTER_BOOTSTRAP_PASSWORD or WEISSMAN_MASTER_BOOTSTRAP_BCRYPT"
        );
        return Ok(());
    };
    let tid: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
    )
    .fetch_optional(auth_pool)
    .await?;
    let Some(tenant_id) = tid else {
        return Ok(());
    };
    auth_access::record_auth_access(auth_pool, tenant_id, "ensure_master_bootstrap_user").await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth.v_user_lookup WHERE tenant_id = $1 AND lower(trim(email)) = lower(trim($2)))",
    )
    .bind(tenant_id)
    .bind(&email)
    .fetch_one(auth_pool)
    .await?;
    if exists {
        return Ok(());
    }
    auth_access::insert_user_auth(auth_pool, tenant_id, &email, Some(&hash), "admin").await?;
    tracing::info!(
        target: "security_audit",
        email = %email,
        "master bootstrap admin user created (credentials from env only)"
    );
    Ok(())
}
