//! Periodic cleanup for global intel tables and finished async jobs (configurable via env).

use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
        .max(1)
}

async fn run_intel_ephemeral_retention(pool: &PgPool, days: i64) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(r#"DELETE FROM intel.ephemeral_payloads WHERE created_at < now() - make_interval(days => $1)"#)
        .bind(days)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

async fn run_intel_dynamic_retention(pool: &PgPool, days: i64) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(r#"DELETE FROM intel.dynamic_payloads WHERE added_at < now() - make_interval(days => $1)"#)
        .bind(days)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

async fn run_async_job_retention(pool: &PgPool, days: i64) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        r#"DELETE FROM weissman_async_jobs
           WHERE status IN ('completed', 'failed', 'dead')
             AND updated_at < now() - make_interval(days => $1)"#,
    )
    .bind(days)
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

async fn retention_pass(app_pool: &PgPool, intel_pool: &PgPool) {
    let ephemeral_days = env_u64("WEISSMAN_INTEL_EPHEMERAL_RETENTION_DAYS", 7) as i64;
    let dynamic_days = env_u64("WEISSMAN_INTEL_DYNAMIC_RETENTION_DAYS", 90) as i64;
    let job_days = env_u64("WEISSMAN_ASYNC_JOB_RETENTION_DAYS", 30) as i64;

    match run_intel_ephemeral_retention(intel_pool, ephemeral_days).await {
        Ok(n) if n > 0 => tracing::info!(
            target: "data_retention",
            deleted = n,
            table = "intel.ephemeral_payloads",
            "retention pass"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            target: "data_retention",
            error = %e,
            "intel.ephemeral_payloads retention failed"
        ),
    }
    match run_intel_dynamic_retention(intel_pool, dynamic_days).await {
        Ok(n) if n > 0 => tracing::info!(
            target: "data_retention",
            deleted = n,
            table = "intel.dynamic_payloads",
            "retention pass"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            target: "data_retention",
            error = %e,
            "intel.dynamic_payloads retention failed"
        ),
    }
    match run_async_job_retention(app_pool, job_days).await {
        Ok(n) if n > 0 => tracing::info!(
            target: "data_retention",
            deleted = n,
            table = "weissman_async_jobs",
            "retention pass"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            target: "data_retention",
            error = %e,
            "weissman_async_jobs retention failed"
        ),
    }
}

/// Runs once at startup (after a short delay) and every 24h. Set `WEISSMAN_DISABLE_DATA_RETENTION=1` to skip.
pub fn spawn_data_retention_loop(app_pool: Arc<PgPool>, intel_pool: Arc<PgPool>) {
    if std::env::var("WEISSMAN_DISABLE_DATA_RETENTION").is_ok() {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(120)).await;
        retention_pass(app_pool.as_ref(), intel_pool.as_ref()).await;
        let mut interval = tokio::time::interval(Duration::from_secs(86_400));
        interval.tick().await;
        loop {
            interval.tick().await;
            retention_pass(app_pool.as_ref(), intel_pool.as_ref()).await;
        }
    });
}
