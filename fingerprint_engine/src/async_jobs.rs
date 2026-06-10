//! Enqueue durable jobs with HTTP trace correlation when present.

use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Enqueue `weissman_async_jobs` row; `trace_id` taken from request extensions when set.
pub async fn enqueue(
    pool: &PgPool,
    tenant_id: i64,
    kind: &str,
    payload: Value,
    trace_id: Option<String>,
) -> Result<Uuid, sqlx::Error> {
    weissman_db::job_queue::enqueue(pool, tenant_id, kind, payload, trace_id.as_deref()).await
}

/// Every 5 minutes, fail `running` jobs whose lock expired or heartbeat is older than 30 minutes.
pub fn spawn_stale_lock_reclaim_loop(pool: Arc<PgPool>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match weissman_db::job_queue::reclaim_stale_running_locks(pool.as_ref()).await {
                Ok(n) if n > 0 => tracing::info!(
                    target: "async_jobs",
                    reclaimed = n,
                    "stale running job locks reclaimed"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    target: "async_jobs",
                    error = %e,
                    "stale lock reclaim failed"
                ),
            }
        }
    });
}
