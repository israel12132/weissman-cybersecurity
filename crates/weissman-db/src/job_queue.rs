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

/// Open a transaction with the **worker/queue** RLS posture: `app.current_tenant_id = ''`
/// selects the unrestricted branch of the `weissman_async_jobs` policy
/// (`NULLIF('','') IS NULL`).
///
/// `weissman_app` is `NOBYPASSRLS` and migration `20260602180000` set a database-level
/// default `app.current_tenant_id = '0'`, so an unscoped connection's policy collapses to
/// `tenant_id = 0` and hides/rejects every real tenant's row. Setting the GUC transaction-locally
/// (`SET LOCAL` semantics via `set_config(..., true)`) restores the intended "trusted queue
/// plumbing is unrestricted" branch without leaking scope to the next borrower of the pooled
/// connection. Tenant-scoped operations (`enqueue`, `get_job_for_tenant`) use
/// [`crate::begin_tenant_tx`] with a concrete id instead.
async fn begin_worker_tx(
    pool: &PgPool,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.current_tenant_id', '', true)")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Enqueue work; returns the primary key for correlation (HTTP 202, polling, etc.).
pub async fn enqueue(
    pool: &PgPool,
    tenant_id: i64,
    kind: &str,
    payload: Value,
    trace_id: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let mut tx = crate::begin_tenant_tx(pool, tenant_id).await?;
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs (tenant_id, kind, payload, status, trace_id)
           VALUES ($1, $2, $3, 'pending', $4)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(kind)
    .bind(Json(payload))
    .bind(trace_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Enqueue a job that is NOT yet claimable: it is inserted `pending` but with a
/// future `run_after`, and `reserve_next`/`claim_next` skip rows whose
/// `run_after` is in the future. The caller must finalize it with
/// [`release_hold`] once any post-insert setup is durable (e.g. attaching the
/// zero-trust signed envelope to the payload). This closes the race where a
/// worker could claim a `pending` job in the window between the row insert and
/// a follow-up envelope UPDATE, find no envelope, and permanently dead-letter
/// it ("missing signed envelope — zero-trust claim rejected").
pub async fn enqueue_held(
    pool: &PgPool,
    tenant_id: i64,
    kind: &str,
    payload: Value,
    trace_id: Option<&str>,
    hold_secs: i64,
) -> Result<Uuid, sqlx::Error> {
    let hold = hold_secs.clamp(1, 300);
    let mut tx = crate::begin_tenant_tx(pool, tenant_id).await?;
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs (tenant_id, kind, payload, status, trace_id, run_after)
           VALUES ($1, $2, $3, 'pending', $4, now() + ($5::bigint * interval '1 second'))
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(kind)
    .bind(Json(payload))
    .bind(trace_id)
    .bind(hold)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Finalize a [`enqueue_held`] job: replace its payload (now carrying the signed
/// envelope) and clear `run_after` so it becomes immediately claimable — in one
/// atomic UPDATE, so a worker never observes a claimable job without its
/// envelope. Guarded on the row still being held (`run_after IS NOT NULL`) so a
/// late finalize cannot resurrect a job that was already failed.
pub async fn release_hold(pool: &PgPool, job_id: Uuid, payload: Value) -> Result<u64, sqlx::Error> {
    let mut tx = begin_worker_tx(pool).await?;
    let r = sqlx::query(
        r#"UPDATE weissman_async_jobs
              SET payload = $2, run_after = NULL, updated_at = now()
            WHERE id = $1 AND status = 'pending' AND run_after IS NOT NULL"#,
    )
    .bind(job_id)
    .bind(Json(payload))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.rows_affected())
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
    let mut tx = crate::begin_tenant_tx(pool, tenant_id).await?;
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
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
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

/// Zero-trust reserve: lock row but leave `pending` until cryptographic claim projects `running`.
pub async fn reserve_next(
    pool: &PgPool,
    worker_id: &str,
    lock_secs: i64,
) -> Result<Option<AsyncJob>, sqlx::Error> {
    reserve_next_with_role(pool, worker_id, lock_secs, WorkerPoolRole::from_env()).await
}

pub async fn reserve_next_with_role(
    pool: &PgPool,
    worker_id: &str,
    lock_secs: i64,
    role: WorkerPoolRole,
) -> Result<Option<AsyncJob>, sqlx::Error> {
    let mut tx = begin_worker_tx(pool).await?;
    let row = sqlx::query(
        r#"
        WITH c AS (
            SELECT id FROM weissman_async_jobs
            WHERE status = 'pending'
              AND (run_after IS NULL OR run_after <= now())
              AND (locked_until IS NULL OR locked_until <= now())
              -- max_attempts was enforced ONLY in fail_job, so any path that returned a row to
              -- 'pending' without going through it (a worker that OOMs or stack-overflows before
              -- reporting; force_requeue_running when fail_job itself failed) produced a job that
              -- could never be retired. Observed live: 53,620,122 attempts against max_attempts=5,
              -- one row starving the whole queue. The cap belongs on the claim, where every path
              -- has to pass through it.
              AND attempt_count < max_attempts
              -- Structural gate for the zero-trust path. `enqueue_held` only makes a job
              -- non-claimable for `hold_secs`; it is a timer, not a gate, so when the
              -- envelope attach failed the row became claimable anyway 30s later and was
              -- dead-lettered as "missing signed envelope". Requiring the envelope here
              -- makes an envelope-less row unclaimable outright, so a failed attach can
              -- never be converted into destroyed work by the passage of time.
              -- (`reserve_next` is the bus path; `claim_next` is the non-bus path and has
              -- no envelope to require.)
              AND payload ? '_weissman_job_bus'
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
        SET locked_until = now() + ($2::bigint * interval '1 second'),
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
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;

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
    let mut tx = begin_worker_tx(pool).await?;
    let row = sqlx::query(
        r#"
        WITH c AS (
            SELECT id FROM weissman_async_jobs
            WHERE status = 'pending'
              AND (run_after IS NULL OR run_after <= now())
              AND (locked_until IS NULL OR locked_until <= now())
              -- max_attempts was enforced ONLY in fail_job, so any path that returned a row to
              -- 'pending' without going through it (a worker that OOMs or stack-overflows before
              -- reporting; force_requeue_running when fail_job itself failed) produced a job that
              -- could never be retired. Observed live: 53,620,122 attempts against max_attempts=5,
              -- one row starving the whole queue. The cap belongs on the claim, where every path
              -- has to pass through it.
              AND attempt_count < max_attempts
              -- No envelope predicate here on purpose: `claim_next` is the NON-bus path
              -- (weissman-worker calls it only when the job bus is disabled), so these rows
              -- never carry `_weissman_job_bus`. The zero-trust gate lives in
              -- `reserve_next_with_role`, which is the bus path.
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
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;

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

pub async fn heartbeat(pool: &PgPool, job_id: Uuid, lock_secs: i64) -> Result<(), sqlx::Error> {
    // Extend `locked_until` alongside `heartbeat_at`: the reclaim sweep fails any running
    // job whose `locked_until < now()`, so a long job (> lock window) that is still beating
    // must keep pushing the lock forward or it gets falsely marked failed mid-flight.
    let mut tx = begin_worker_tx(pool).await?;
    sqlx::query(
        "UPDATE weissman_async_jobs
            SET heartbeat_at = now(),
                locked_until = now() + ($2::bigint * interval '1 second'),
                updated_at = now()
          WHERE id = $1 AND status = 'running'",
    )
    .bind(job_id)
    .bind(lock_secs)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn complete_job(pool: &PgPool, job_id: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = begin_worker_tx(pool).await?;
    sqlx::query(
        "UPDATE weissman_async_jobs SET status = 'completed', locked_until = NULL, worker_id = NULL, updated_at = now() WHERE id = $1",
    )
    .bind(job_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Mark completed and store JSON result for `GET /api/jobs/:id`.
pub async fn complete_job_with_result(
    pool: &PgPool,
    job_id: Uuid,
    result: &Value,
) -> Result<(), sqlx::Error> {
    let mut tx = begin_worker_tx(pool).await?;
    sqlx::query(
        r#"UPDATE weissman_async_jobs SET status = 'completed', result_json = $2,
           locked_until = NULL, worker_id = NULL, updated_at = now() WHERE id = $1"#,
    )
    .bind(job_id)
    .bind(Json(result))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
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

/// Strict tenant scoping. Application enforces `tenant_id` in the query; RLS on
/// `weissman_async_jobs` (migration `20260708120000_rls_job_bus_tables`) adds a
/// defense-in-depth filter whenever a tenant GUC is set (worker path is exempt).
pub async fn get_job_for_tenant(
    pool: &PgPool,
    tenant_id: i64,
    job_id: Uuid,
) -> Result<Option<JobStatusView>, sqlx::Error> {
    let mut tx = crate::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT id, kind, status, payload, result_json, last_error, attempt_count, created_at, updated_at, heartbeat_at, trace_id
           FROM weissman_async_jobs WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(job_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
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
    let mut tx = crate::begin_tenant_tx(pool, job.tenant_id).await?;
    if job.attempt_count >= job.max_attempts {
        sqlx::query(
            r#"UPDATE weissman_async_jobs SET status = 'dead', last_error = $2, locked_until = NULL,
               worker_id = NULL, updated_at = now() WHERE id = $1"#,
        )
        .bind(job.id)
        .bind(&msg)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::warn!(
        target: "weissman_worker",
        job_id = %job.id,
        retry_in_secs = delay,
        error = %msg,
        "job scheduled for retry"
    );
    Ok(())
}

/// Mark `running` rows with expired locks or stale heartbeats as retryable pending (worker crash / hung job).
///
/// Rows that have already exhausted `max_attempts` are dead-lettered instead of requeued. This is
/// the only path that can retire a job whose worker died before it could report an outcome, and
/// without it such a job is immortal: nothing else re-checks the cap once the row is back in
/// `pending`. One `tenant_full_scan` in this deployment reached **53,620,122** attempts against
/// `max_attempts = 5`.
pub async fn reclaim_stale_running_locks(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut tx = begin_worker_tx(pool).await?;
    // Retire the exhausted ones first, so the requeue below cannot pick them up.
    sqlx::query(
        r#"UPDATE weissman_async_jobs
              SET status = 'dead',
                  last_error = COALESCE(NULLIF(last_error, ''), 'worker died before reporting an outcome')
                               || ' [dead-lettered by stale-lock reclaim: attempts exhausted]',
                  locked_until = NULL,
                  worker_id = NULL,
                  updated_at = now()
            WHERE status = 'running'
              AND attempt_count >= max_attempts
              AND (heartbeat_at < now() - interval '30 minutes' OR locked_until < now())"#,
    )
    .execute(&mut *tx)
    .await?;

    let r = sqlx::query(
        r#"UPDATE weissman_async_jobs
           SET status = 'pending',
               -- Append rather than overwrite: the previous value is the only record of WHY the
               -- job was running when its worker vanished, and clobbering it with a fixed string
               -- destroyed the diagnostic on exactly the rows that most needed one.
               last_error = CASE
                   WHEN COALESCE(last_error, '') = '' THEN 'stale lock reclaimed'
                   ELSE last_error || ' [stale lock reclaimed]'
               END,
               locked_until = NULL,
               worker_id = NULL,
               run_after = now() + interval '2 seconds',
               updated_at = now()
           WHERE status = 'running'
             AND attempt_count < max_attempts
             AND (
               heartbeat_at < now() - interval '30 minutes'
               OR locked_until < now()
             )"#,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.rows_affected())
}

/// Immediately move a job to dead-letter — no retry (HMAC mismatch, expired envelope, etc.).
pub async fn dead_letter_job(pool: &PgPool, job_id: Uuid, err: &str) -> Result<(), sqlx::Error> {
    let msg: String = err.chars().take(4000).collect();
    let mut tx = begin_worker_tx(pool).await?;
    sqlx::query(
        r#"UPDATE weissman_async_jobs SET status = 'dead', last_error = $2, locked_until = NULL,
           worker_id = NULL, updated_at = now() WHERE id = $1"#,
    )
    .bind(job_id)
    .bind(&msg)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::error!(
        target: "weissman_worker",
        job_id = %job_id,
        error = %msg,
        "job dead-lettered (permanent failure)"
    );
    Ok(())
}

/// Annotate `last_error` on a job row WITHOUT touching `status`. The event-sourced
/// DLQ projection records only the failure *class* (e.g. `execution_failure`) in
/// `last_error`; this overlays the raw error message so a dead job is
/// self-explanatory when inspected via `GET /api/jobs/:id` (the worker log is
/// unreliable — buffered and truncated when the process is killed).
pub async fn annotate_last_error(
    pool: &PgPool,
    job_id: Uuid,
    err: &str,
) -> Result<(), sqlx::Error> {
    let msg: String = err.chars().take(4000).collect();
    let mut tx = begin_worker_tx(pool).await?;
    sqlx::query(
        r#"UPDATE weissman_async_jobs SET last_error = $2, updated_at = now() WHERE id = $1"#,
    )
    .bind(job_id)
    .bind(&msg)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// When zero-trust claim fails after [`reserve_next`], clear the reservation and backoff
/// so workers do not hot-loop the same row (lease storm / stack overflow).
pub async fn release_reserved_job(
    pool: &PgPool,
    job_id: Uuid,
    worker_id: &str,
    note: &str,
    backoff_secs: i64,
) -> Result<u64, sqlx::Error> {
    let msg: String = note.chars().take(4000).collect();
    let backoff = backoff_secs.clamp(1, 300);
    // Ownership predicate: only requeue the row if THIS worker still owns it. Under
    // sustained saturation a lapsed reservation can be re-reserved (or claimed) by
    // another worker; without `worker_id = $4` this release would clobber that
    // worker's freshly-`running` job back to `pending`, discarding its result.
    let mut tx = begin_worker_tx(pool).await?;
    let r = sqlx::query(
        r#"UPDATE weissman_async_jobs SET status = 'pending', locked_until = NULL, worker_id = NULL,
           last_error = $2, run_after = now() + ($3::bigint * interval '1 second'), updated_at = now()
           WHERE id = $1 AND worker_id = $4 AND status IN ('pending', 'running')"#,
    )
    .bind(job_id)
    .bind(&msg)
    .bind(backoff)
    .bind(worker_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.rows_affected())
}

/// When [`complete_job_with_result`] or [`fail_job`] fails (e.g. transient DB error), clear the worker
/// lock and return the row to `pending` so the queue does not stay jammed on `running` forever.
pub async fn force_requeue_running(
    pool: &PgPool,
    job_id: Uuid,
    worker_id: &str,
    note: &str,
) -> Result<u64, sqlx::Error> {
    let msg: String = note.chars().take(4000).collect();
    // Ownership predicate: only requeue a row THIS worker still owns, so a transient
    // cleanup on one worker cannot reset a job another worker is actively running.
    let mut tx = begin_worker_tx(pool).await?;
    let r = sqlx::query(
        r#"UPDATE weissman_async_jobs SET status = 'pending', locked_until = NULL, worker_id = NULL,
           -- Backoff, not now(): this path runs precisely when fail_job itself just failed, so
           -- run_after = now() put the row straight back at the head of the queue with no delay
           -- and the poll loop re-claimed it on the next iteration (POLL_IDLE_MS only applies to
           -- an empty queue). That is the spin that reached 53M attempts.
           last_error = $2, run_after = now() + interval '5 seconds', updated_at = now()
           WHERE id = $1 AND worker_id = $3 AND status IN ('pending', 'running')"#,
    )
    .bind(job_id)
    .bind(&msg)
    .bind(worker_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(r.rows_affected())
}

#[cfg(test)]
mod worker_pool_role_tests {
    use super::WorkerPoolRole;
    use std::collections::HashSet;

    #[test]
    fn sql_mode_is_stable_and_distinct() {
        // These discriminants are persisted / compared against SQL — they must not drift.
        assert_eq!(WorkerPoolRole::Mixed.sql_mode(), 0);
        assert_eq!(WorkerPoolRole::Research.sql_mode(), 1);
        assert_eq!(WorkerPoolRole::Client.sql_mode(), 2);
        let modes: HashSet<i32> = [
            WorkerPoolRole::Mixed.sql_mode(),
            WorkerPoolRole::Research.sql_mode(),
            WorkerPoolRole::Client.sql_mode(),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            modes.len(),
            3,
            "each role maps to a distinct SQL discriminant"
        );
    }

    #[test]
    fn default_is_the_legacy_mixed_pool() {
        assert_eq!(WorkerPoolRole::default(), WorkerPoolRole::Mixed);
        assert_eq!(WorkerPoolRole::default().sql_mode(), 0);
    }

    #[test]
    fn from_env_yields_a_valid_role_regardless_of_environment() {
        // Env-agnostic: whatever WEISSMAN_WORKER_POOL is (or is not) set to in the runner, the
        // classifier must resolve to one of the three known roles and never panic, and the
        // resolved role's SQL discriminant must stay in range.
        let role = WorkerPoolRole::from_env();
        assert!(matches!(
            role,
            WorkerPoolRole::Mixed | WorkerPoolRole::Research | WorkerPoolRole::Client
        ));
        assert!((0..=2).contains(&role.sql_mode()));
    }
}
