//! CQRS projector: immutable events → `weissman_async_jobs` read model.
//! All status mutations flow through here — never bare `UPDATE status=failed` elsewhere.

use crate::error::JobBusError;
use crate::events::{JobEventKind, JobEventRecord};
use serde_json::Value;
use sqlx::PgPool;

/// Project a single event onto the read model (idempotent where possible).
/// `worker_id` from an event payload, when it carries one.
///
/// Returned as `Option` and compared with `($n IS NULL OR worker_id = $n)` so an event that
/// genuinely has no worker attribution still projects, rather than silently matching zero rows.
fn event_worker_id(event: &JobEventRecord) -> Option<String> {
    event
        .payload
        .get("worker_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub async fn project_event(pool: &PgPool, event: &JobEventRecord) -> Result<(), JobBusError> {
    if event.job_id.is_nil() {
        return Ok(());
    }
    // Events that do not mutate the read model — no DB round-trip needed.
    if matches!(
        event.kind,
        JobEventKind::JobDispatched | JobEventKind::ExploitFired | JobEventKind::WorkerTerminated
    ) {
        return Ok(());
    }

    // Scope the projection to the event's tenant. `weissman_async_jobs` is FORCE ROW LEVEL
    // SECURITY and `weissman_app` is NOBYPASSRLS; the database-level default
    // `app.current_tenant_id = '0'` (migration 20260602180000) collapses an unscoped pool's
    // policy to `tenant_id = 0`, so without a tenant GUC every UPDATE below matches 0 rows and
    // silently returns Ok(()) for real tenants — the read model never advances. Mirrors the
    // tenant transaction that `events::append_event` already opens for the write side.
    let mut tx = weissman_db::begin_tenant_tx(pool, event.tenant_id).await?;

    match event.kind {
        JobEventKind::JobDispatched
        | JobEventKind::ExploitFired
        | JobEventKind::WorkerTerminated => {}
        JobEventKind::WorkerClaimed => {
            let worker_id = event
                .payload
                .get("worker_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'running', worker_id = $2, updated_at = now()
                   WHERE id = $1 AND status = 'pending'"#,
            )
            .bind(event.job_id)
            .bind(worker_id)
            .execute(&mut *tx)
            .await?;
        }
        JobEventKind::LeaseAcquired | JobEventKind::LeaseExtended => {
            let lock_secs = event
                .payload
                .get("lock_secs")
                .and_then(Value::as_i64)
                .unwrap_or(300);
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET locked_until = now() + ($2::bigint * interval '1 second'),
                       heartbeat_at = now(), updated_at = now()
                   WHERE id = $1 AND status = 'running'"#,
            )
            .bind(event.job_id)
            .bind(lock_secs)
            .execute(&mut *tx)
            .await?;
        }
        JobEventKind::JobCompleted => {
            let result = event.payload.get("result").cloned().unwrap_or(Value::Null);
            // Ownership fence, not just a status guard. The status-only predicate could not do
            // what its comment claimed: after the coordinator orphans a job, another worker sets
            // it back to `running`, so a late event from the SUPERSEDED worker still matched
            // `status = 'running'` and overwrote the live re-run. Comparing worker_id makes the
            // guard actually mean "this worker still owns the row".
            let worker_id = event_worker_id(event);
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'completed', result_json = $2,
                       last_error = NULL, stuck_reason = NULL,
                       locked_until = NULL, worker_id = NULL, updated_at = now()
                   WHERE id = $1 AND status = 'running'
                     AND ($3::text IS NULL OR worker_id = $3)"#,
            )
            .bind(event.job_id)
            .bind(sqlx::types::Json(result))
            .bind(worker_id)
            .execute(&mut *tx)
            .await?;
        }
        JobEventKind::JobFailed => {
            let err = event
                .payload
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            // Ownership fence, mirroring JobCompleted.
            let worker_id = event_worker_id(event);
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'failed', last_error = $2,
                       stuck_reason = COALESCE($4, stuck_reason),
                       locked_until = NULL, worker_id = NULL, updated_at = now()
                   WHERE id = $1 AND status = 'running'
                     AND ($3::text IS NULL OR worker_id = $3)"#,
            )
            .bind(event.job_id)
            .bind(err)
            .bind(worker_id)
            .bind(event.payload.get("stuck_reason").and_then(Value::as_str))
            .execute(&mut *tx)
            .await?;
        }
        JobEventKind::JobRetryScheduled => {
            let err = event
                .payload
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            // Exponential backoff by attempt (5s, 10s, 20s … capped at 1h), matching the
            // legacy `fail_job` path. A fixed 5s retry in the zero-trust path caused a retry
            // storm for a persistently failing job. Status guard prevents a late retry event
            // from resurrecting an already-completed/dead job.
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'pending', last_error = $2,
                       locked_until = NULL, worker_id = NULL,
                       run_after = now()
                           + (LEAST(3600, 5 * POWER(2, LEAST(GREATEST(attempt_count, 0), 10)))::int
                              * interval '1 second'),
                       updated_at = now()
                   WHERE id = $1 AND status = 'running'"#,
            )
            .bind(event.job_id)
            .bind(err)
            .execute(&mut *tx)
            .await?;
        }
        JobEventKind::JobOrphaned => {
            let reason = event
                .payload
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("worker lost");
            // Two changes. Dead-letter instead of re-queueing once the attempt budget is spent:
            // a poison-pill job that ABORTS its worker (stack overflow, OOM, SIGKILL) never
            // reaches the failure handler, so this projection is the only thing that sees it —
            // and re-queueing unconditionally meant it was handed straight back to the next
            // worker, which died the same way, forever, taking every co-resident job with it
            // each cycle.
            //
            // And fence on the worker that was actually declared dead, so a coordinator tick
            // racing a live worker cannot yank a job the worker still owns and is completing.
            let worker_id = event_worker_id(event);
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = CASE WHEN attempt_count >= max_attempts THEN 'dead' ELSE 'pending' END,
                       last_error = $2,
                       locked_until = NULL, worker_id = NULL,
                       run_after = CASE WHEN attempt_count >= max_attempts
                                        THEN NULL ELSE now() + interval '2 seconds' END,
                       updated_at = now()
                   WHERE id = $1 AND status = 'running'
                     AND ($3::text IS NULL OR worker_id = $3)"#,
            )
            .bind(event.job_id)
            .bind(format!("orphaned: {reason}"))
            .bind(worker_id)
            .execute(&mut *tx)
            .await?;
        }
        JobEventKind::ForensicDlqEnqueued => {
            let err = event
                .payload
                .get("failure_class")
                .and_then(Value::as_str)
                .unwrap_or("forensic_dlq");
            // Status guard: only a `running` job may be dead-lettered, so a late DLQ event from a
            // superseded worker cannot mark another worker's completed run `dead`.
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'dead', last_error = $2,
                       locked_until = NULL, worker_id = NULL, updated_at = now()
                   WHERE id = $1 AND status = 'running'"#,
            )
            .bind(event.job_id)
            .bind(err)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;
    Ok(())
}
