//! CEO dashboard: live async jobs + telemetry snapshot (no mock data).

use serde_json::{json, Value};
use sqlx::{PgPool, Row};

#[cfg(target_os = "linux")]
fn resident_set_kb() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let mut it = s.split_whitespace();
    let _vsize = it.next()?;
    let resident_pages: u64 = it.next()?.parse().ok()?;
    Some(resident_pages.saturating_mul(4096) / 1024)
}

#[cfg(not(target_os = "linux"))]
fn resident_set_kb() -> Option<u64> {
    None
}

/// Pending + running jobs for the tenant (Genesis / Council / engines).
/// When `filter_client_id` is set, only rows whose JSON `payload.client_id` matches (numeric or string) are returned.
pub async fn list_live_async_jobs(
    pool: &PgPool,
    tenant_id: i64,
    filter_client_id: Option<i64>,
) -> Result<Vec<Value>, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT id::text AS id, kind, status, worker_id,
                  heartbeat_at, created_at, updated_at, attempt_count, last_error
           FROM weissman_async_jobs
           WHERE tenant_id = $1 AND status IN ('pending', 'running')
             AND ($2::bigint IS NULL OR (
               (payload->>'client_id') ~ '^-?[0-9]+$'
               AND (payload->>'client_id')::bigint = $2
             ))
           ORDER BY created_at DESC
           LIMIT 300"#,
    )
    .bind(tenant_id)
    .bind(filter_client_id)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let hb = r
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("heartbeat_at")
            .ok()
            .flatten()
            .map(|t| t.to_rfc3339());
        let ca = r
            .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .ok()
            .map(|t| t.to_rfc3339());
        let ua = r
            .try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
            .ok()
            .map(|t| t.to_rfc3339());
        out.push(json!({
            "id": r.try_get::<String, _>("id").unwrap_or_default(),
            "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
            "status": r.try_get::<String, _>("status").unwrap_or_default(),
            "worker_id": r.try_get::<Option<String>, _>("worker_id").ok().flatten(),
            "heartbeat_at": hb,
            "created_at": ca,
            "updated_at": ua,
            "attempt_count": r.try_get::<i32, _>("attempt_count").unwrap_or(0),
            "last_error": r.try_get::<Option<String>, _>("last_error").ok().flatten(),
        }));
    }
    Ok(out)
}

/// Aggregated telemetry for CEO UI (DB + process).
pub async fn build_ceo_telemetry_json(
    app_pool: &PgPool,
    tenant_id: i64,
    uptime_secs: u64,
) -> Value {
    let rss = resident_set_kb();
    let scanning = crate::orchestrator::is_scanning_active();

    let strategy = crate::ceo::strategy::get_ceo_strategy_json(app_pool, tenant_id).await;

    let mut global_safe = false;
    if let Ok(mut tx) = crate::db::begin_tenant_tx(app_pool, tenant_id).await {
        if let Ok(Some(s)) = sqlx::query_scalar::<_, String>(
            "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'global_safe_mode'",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        {
            global_safe = s == "true" || s == "1";
        }
        let _ = tx.commit().await;
    }

    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM weissman_async_jobs WHERE tenant_id = $1 AND status = 'pending'",
    )
    .bind(tenant_id)
    .fetch_one(app_pool)
    .await
    .unwrap_or(0);

    let running: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM weissman_async_jobs WHERE tenant_id = $1 AND status = 'running'",
    )
    .bind(tenant_id)
    .fetch_one(app_pool)
    .await
    .unwrap_or(0);

    let distinct_workers: i64 = sqlx::query_scalar(
        r#"SELECT count(DISTINCT worker_id)::bigint FROM weissman_async_jobs
           WHERE tenant_id = $1 AND status = 'running'
             AND worker_id IS NOT NULL AND trim(worker_id) <> ''"#,
    )
    .bind(tenant_id)
    .fetch_one(app_pool)
    .await
    .unwrap_or(0);

    let global_pending: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM weissman_async_jobs WHERE status = 'pending'",
    )
    .fetch_one(app_pool)
    .await
    .unwrap_or(0);

    let global_running: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM weissman_async_jobs WHERE status = 'running'",
    )
    .fetch_one(app_pool)
    .await
    .unwrap_or(0);

    json!({
        "uptime_secs": uptime_secs,
        "server_process_rss_kb": rss,
        "scanning_active": scanning,
        "global_safe_mode": global_safe,
        "strategy": strategy,
        "tenant_jobs_pending": pending,
        "tenant_jobs_running": running,
        "distinct_worker_ids_on_tenant_jobs": distinct_workers,
        "queue_global_pending": global_pending,
        "queue_global_running": global_running,
        "note": "distinct_worker_ids counts unique worker_id strings on running rows for this tenant (proxy for parallel worker processes claiming jobs).",
    })
}
