//! Enqueue durable jobs with HTTP trace correlation when present.

use serde_json::Value;
use sqlx::PgPool;
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
