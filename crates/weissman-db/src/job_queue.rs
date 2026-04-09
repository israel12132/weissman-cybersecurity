//! Durable async jobs (`weissman_async_jobs`): UUID ids, worker claim with `SKIP LOCKED`, retries, dead-letter.

use serde_json::Value;
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AsyncJob {
    pub id: Uuid,
    pub tenant_id: i64,
    pub kind: String,
    pub payload: Value,
    pub attempt_count: i32,
    pub max_attempts: i32,
    /// HTTP edge trace / request id when the job was enqueued.
    pub trace_id: Option<String>,
}

/// Enqueue work; returns the primary key for correlation (HTTP 202, polling, etc.).
pub async fn enqueue(
    pool: &PgPool,
    tenant_id: i64,
    kind: &str,
    payload: Value,
    trace_id: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs (tenant_id, kind, payload, status, trace_id)
           VALUES ($1, $2, $3, 'pending', $4)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(kind)
    .bind(Json(payload))
    .bind(trace_id)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

/// Enqueue with a custom retry cap (e.g. `auto_heal` must not re-run after secrets are cleared).
pub async fn enqueue_with_max_attempts(
    pool: &PgPool,
    tenant_id: i64,
    kind: &str,
    payload: Value,
    trace_id: Option<&str>,
    max_attempts: i32,
) -> Result<Uuid, sqlx::Error> {
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs (tenant_id, kind, payload, status, trace_id, max_attempts)
           VALUES ($1, $2, $3, 'pending', $4, $5)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(kind)
    .bind(Json(payload))
    .bind(trace_id)
    .bind(max_attempts.max(1))
    .fetch_one(pool)
    .await?;
    Ok(id)
}

/// Worker process role for **honest** CPU / capacity splitting: set `WEISSMAN_WORKER_POOL=research|client|mixed`.
/// Research workers only claim LLM-heavy genesis/council jobs; client workers claim everything else. `mixed` = legacy behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum WorkerPoolRole {
    #[default]
    Mixed,
    Research,
    Client,
}

impl WorkerPoolRole {
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("WEISSMAN_WORKER_POOL")
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default()
            .as_str()
        {
            "research" | "genesis" => Self::Research,
            "client" | "scan" => Self::Client,
            _ => Self::Mixed,
        }
    }

    fn sql_mode(self) -> i32 {
        match self {
            WorkerPoolRole::Mixed => 0,
            WorkerPoolRole::Research => 1,
            WorkerPoolRole::Client => 2,
        }
    }
}

/// Claim the next runnable job. Respects `WEISSMAN_WORKER_POOL` when set (`research` / `client` / `mixed`).
pub async fn claim_next(
    pool: &PgPool,
    worker_id: &str,
    lock_secs: i64,
) -> Result<Option<AsyncJob>, sqlx::Error> {
    claim_next_with_role(pool, worker_id, lock_secs, WorkerPoolRole::from_env()).await
}

/// Claim with an explicit pool role (tests / embedding).
pub async fn claim_next_with_role(
    pool: &PgPool,
    worker_id: &str,
    lock_secs: i64,
    role: WorkerPoolRole,
) -> Result<Option<AsyncJob>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        WITH c AS (
            SELECT id FROM weissman_async_jobs
            WHERE status = 'pending'
              AND (run_after IS NULL OR run_after <= now())
              AND (
                $3::int = 0
                OR (
                  $3::int = 1
                  AND kind IN (
                    'genesis_eternal_fuzz',
                    'genesis_knowledge_match',
                    'sovereign_learning_feedback',
                    'council_debate',
                    'poe_synthesis_run'
                  )
                )
                OR (
                  $3::int = 2
                  AND kind NOT IN (
                    'genesis_eternal_fuzz',
                    'genesis_knowledge_match',
                    'sovereign_learning_feedback',
                    'council_debate',
                    'poe_synthesis_run'
                  )
                )
              )
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE weissman_async_jobs j
        SET status = 'running',
            locked_until = now() + ($2::bigint * interval '1 second'),
            worker_id = $1,
            heartbeat_at = now(),
            attempt_count = j.attempt_count + 1,
            updated_at = now()
        FROM c
        WHERE j.id = c.id
        RETURNING j.id, j.tenant_id, j.kind, j.payload, j.attempt_count, j.max_attempts, j.trace_id
        "#,
    )
    .bind(worker_id)
    .bind(lock_secs)
    .bind(role.sql_mode())
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let id: Uuid = row.try_get("id")?;
    let tenant_id: i64 = row.try_get("tenant_id")?;
    let kind: String = row.try_get("kind")?;
    let payload: Json<Value> = row.try_get("payload")?;
    let payload = payload.0;
    let attempt_count: i32 = row.try_get("attempt_count")?;
    let max_attempts: i32 = row.try_get("max_attempts")?;
    let trace_id: Option<String> = row.try_get("trace_id").ok();

    Ok(Some(AsyncJob {
        id,
        tenant_id,
        kind,
        payload,
        attempt_count,
        max_attempts,
        trace_id,
    }))
}

pub async fn heartbeat(pool: &PgPool, job_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE weissman_async_jobs SET heartbeat_at = now(), updated_at = now() WHERE id = $1 AND status = 'running'",
    )
    .bind(job_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn complete_job(pool: &PgPool, job_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE weissman_async_jobs SET status = 'completed', locked_until = NULL, worker_id = NULL, updated_at = now() WHERE id = $1",
    )
    .bind(job_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark completed and store JSON result for `GET /api/jobs/:id`.
pub async fn complete_job_with_result(
    pool: &PgPool,
    job_id: Uuid,
    result: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"UPDATE weissman_async_jobs SET status = 'completed', result_json = $2,
           locked_until = NULL, worker_id = NULL, updated_at = now() WHERE id = $1"#,
    )
    .bind(job_id)
    .bind(Json(result))
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JobStatusView {
    pub id: Uuid,
    pub kind: String,
    pub status: String,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub attempt_count: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub source: &'static str,
}

/// Strict tenant scoping (table has no RLS — application enforces `tenant_id`).
pub async fn get_job_for_tenant(
    pool: &PgPool,
    tenant_id: i64,
    job_id: Uuid,
) -> Result<Option<JobStatusView>, sqlx::Error> {
    let row = sqlx::query(
        r#"SELECT id, kind, status, payload, result_json, last_error, attempt_count, created_at, updated_at, heartbeat_at, trace_id
           FROM weissman_async_jobs WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(job_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id: Uuid = row.try_get("id")?;
    let kind: String = row.try_get("kind")?;
    let status: String = row.try_get("status")?;
    let payload: Json<Value> = row.try_get("payload")?;
    let result_json: Option<Value> = row
        .try_get::<Option<Json<Value>>, _>("result_json")
        .ok()
        .flatten()
        .map(|j| j.0);
    let last_error: Option<String> = row.try_get("last_error").ok();
    let attempt_count: i32 = row.try_get("attempt_count")?;
    let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;
    let updated_at: chrono::DateTime<chrono::Utc> = row.try_get("updated_at")?;
    let heartbeat_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("heartbeat_at").ok();
    let trace_id: Option<String> = row.try_get("trace_id").ok();
    Ok(Some(JobStatusView {
        id,
        kind,
        status,
        payload: payload.0,
        result: result_json,
        last_error,
        attempt_count,
        created_at,
        updated_at,
        heartbeat_at,
        trace_id,
        source: "async_job",
    }))
}

/// Schedule retry with exponential backoff, or mark `dead` when attempts exhausted.
pub async fn fail_job(
    pool: &PgPool,
    job: &AsyncJob,
    err: &str,
    base_backoff_secs: i64,
) -> Result<(), sqlx::Error> {
    let msg: String = err.chars().take(4000).collect();
    if job.attempt_count >= job.max_attempts {
        sqlx::query(
            r#"UPDATE weissman_async_jobs SET status = 'dead', last_error = $2, locked_until = NULL,
               worker_id = NULL, updated_at = now() WHERE id = $1"#,
        )
        .bind(job.id)
        .bind(&msg)
        .execute(pool)
        .await?;
        tracing::error!(
            target: "weissman_worker",
            job_id = %job.id,
            attempts = job.attempt_count,
            "job moved to dead letter queue"
        );
        return Ok(());
    }
    let pow = job.attempt_count.saturating_sub(1).clamp(0, 8);
    let delay = base_backoff_secs.saturating_mul(2_i64.saturating_pow(pow as u32));
    let delay = delay.min(3600);
    sqlx::query(
        r#"UPDATE weissman_async_jobs SET status = 'pending', last_error = $2, locked_until = NULL,
           worker_id = NULL, run_after = now() + ($3::bigint * interval '1 second'), updated_at = now() WHERE id = $1"#,
    )
    .bind(job.id)
    .bind(&msg)
    .bind(delay)
    .execute(pool)
    .await?;
    tracing::warn!(
        target: "weissman_worker",
        job_id = %job.id,
        retry_in_secs = delay,
        error = %msg,
        "job scheduled for retry"
    );
    Ok(())
}

/// When [`complete_job_with_result`] or [`fail_job`] fails (e.g. transient DB error), clear the worker
/// lock and return the row to `pending` so the queue does not stay jammed on `running` forever.
pub async fn force_requeue_running(
    pool: &PgPool,
    job_id: Uuid,
    note: &str,
) -> Result<u64, sqlx::Error> {
    let msg: String = note.chars().take(4000).collect();
    let r = sqlx::query(
        r#"UPDATE weissman_async_jobs SET status = 'pending', locked_until = NULL, worker_id = NULL,
           last_error = $2, run_after = now(), updated_at = now()
           WHERE id = $1 AND status = 'running'"#,
    )
    .bind(job_id)
    .bind(&msg)
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}
