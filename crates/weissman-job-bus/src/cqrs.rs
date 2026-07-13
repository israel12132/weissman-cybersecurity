//! CQRS projector: immutable events → `weissman_async_jobs` read model.
//! All status mutations flow through here — never bare `UPDATE status=failed` elsewhere.

use crate::error::JobBusError;
use crate::events::{JobEventKind, JobEventRecord};
use serde_json::Value;
use sqlx::PgPool;

/// Project a single event onto the read model (idempotent where possible).
pub async fn project_event(pool: &PgPool, event: &JobEventRecord) -> Result<(), JobBusError> {
    if event.job_id.is_nil() {
        return Ok(());
    }
    match event.kind {
        JobEventKind::JobDispatched => Ok(()),
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
            .execute(pool)
            .await?;
            Ok(())
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
            .execute(pool)
            .await?;
            Ok(())
        }
        JobEventKind::ExploitFired => Ok(()),
        JobEventKind::JobCompleted => {
            let result = event.payload.get("result").cloned().unwrap_or(Value::Null);
            // Status guard: only a job still `running` may transition to `completed`.
            // Without it, a late completion from a superseded/orphaned worker could resurrect
            // or overwrite a job another worker already re-ran (or that already failed/died).
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'completed', result_json = $2,
                       locked_until = NULL, worker_id = NULL, updated_at = now()
                   WHERE id = $1 AND status = 'running'"#,
            )
            .bind(event.job_id)
            .bind(sqlx::types::Json(result))
            .execute(pool)
            .await?;
            Ok(())
        }
        JobEventKind::JobFailed => {
            let err = event
                .payload
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'failed', last_error = $2,
                       locked_until = NULL, worker_id = NULL, updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(event.job_id)
            .bind(err)
            .execute(pool)
            .await?;
            Ok(())
        }
        JobEventKind::JobRetryScheduled => {
            let err = event
                .payload
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            // Exponential backoff by attempt (5s, 10s, 20s … capped at 1h), matching the
            // legacy `fail_job` path. A fixed 5s retry in the zero-trust path caused a retry
            // storm for a persistently failing job.
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'pending', last_error = $2,
                       locked_until = NULL, worker_id = NULL,
                       run_after = now()
                           + (LEAST(3600, 5 * POWER(2, LEAST(GREATEST(attempt_count, 0), 10)))::int
                              * interval '1 second'),
                       updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(event.job_id)
            .bind(err)
            .execute(pool)
            .await?;
            Ok(())
        }
        JobEventKind::JobOrphaned => {
            let reason = event
                .payload
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("worker lost");
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'pending', last_error = $2,
                       locked_until = NULL, worker_id = NULL,
                       run_after = now() + interval '2 seconds', updated_at = now()
                   WHERE id = $1 AND status = 'running'"#,
            )
            .bind(event.job_id)
            .bind(format!("orphaned: {reason}"))
            .execute(pool)
            .await?;
            Ok(())
        }
        JobEventKind::ForensicDlqEnqueued => {
            let err = event
                .payload
                .get("failure_class")
                .and_then(Value::as_str)
                .unwrap_or("forensic_dlq");
            sqlx::query(
                r#"UPDATE weissman_async_jobs
                   SET status = 'dead', last_error = $2,
                       locked_until = NULL, worker_id = NULL, updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(event.job_id)
            .bind(err)
            .execute(pool)
            .await?;
            Ok(())
        }
        JobEventKind::WorkerTerminated => Ok(()),
    }
}
