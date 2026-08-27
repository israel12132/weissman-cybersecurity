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
    let r = sqlx::query(
        r#"DELETE FROM intel.ephemeral_payloads WHERE created_at < now() - ($1::bigint * interval '1 day')"#,
    )
        .bind(days)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

async fn run_intel_dynamic_retention(pool: &PgPool, days: i64) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        r#"DELETE FROM intel.dynamic_payloads WHERE added_at < now() - ($1::bigint * interval '1 day')"#,
    )
        .bind(days)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

/// Retire `pending` rows that the claim path can provably NEVER pick up.
///
/// The retention sweep below only deletes rows that already reached a terminal status, so an
/// unrunnable `pending` row is immortal: never claimed, never deleted, forever inflating queue
/// depth. After the 2026-08-06 outage the live queue held 2,973 such rows — all of them repeats
/// of the same `orchestrator_tick` scan — which distorted every queue metric and, until the
/// coalescing predicate was corrected, deadlocked the scheduler outright.
///
/// Two terminal conditions, both mirroring `crates/weissman-db/src/job_queue.rs`:
///
///  * **No zero-trust envelope.** `attach_signed_envelope` runs only at enqueue time; nothing
///    re-signs an existing row, so a row that missed its envelope can never gain one.
///  * **At the attempt ceiling.** The claim predicate skips these, and no path decrements
///    `attempt_count`.
///
/// A row that is merely *not due yet* (`run_after` in the future) is deliberately NOT retired —
/// it becomes claimable on its own. `grace_secs` guards the same hazard from the other side:
/// `enqueue_held` inserts a row WITHOUT an envelope and attaches it moments later, so retiring
/// envelope-less rows on sight would destroy jobs mid-enqueue. The default grace is far longer
/// than the 300s ceiling `enqueue_held` clamps its hold to.
async fn retire_unrunnable_pending_jobs(
    pool: &PgPool,
    grace_secs: i64,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        r#"UPDATE weissman_async_jobs
              SET status = 'dead',
                  last_error = COALESCE(NULLIF(last_error, ''), '')
                      || CASE WHEN payload ? '_weissman_job_bus'
                              THEN '[retired: attempts exhausted; the claim path skips it]'
                              ELSE '[retired: enqueued without a zero-trust envelope; nothing re-signs an existing row, so it could never be claimed]'
                         END,
                  updated_at = now()
            WHERE status = 'pending'
              AND created_at < now() - ($1::bigint * interval '1 second')
              AND (
                    attempt_count >= max_attempts
                    OR NOT (payload ? '_weissman_job_bus')
                  )"#,
    )
    .bind(grace_secs)
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

async fn run_async_job_retention(pool: &PgPool, days: i64) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        r#"DELETE FROM weissman_async_jobs
           WHERE status IN ('completed', 'failed', 'dead', 'blocked')
             AND updated_at < now() - ($1::bigint * interval '1 day')"#,
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
    // Generous by default: `enqueue_held` clamps its envelope-attach hold to 300s, so anything
    // under an hour risks retiring a job that is still being enqueued.
    let unrunnable_grace = env_u64("WEISSMAN_ASYNC_JOB_UNRUNNABLE_GRACE_SECS", 3600) as i64;

    // Retire before deleting: this moves provably-unrunnable rows to a terminal status so the
    // sweep below can age them out normally, instead of leaving them pending forever.
    match retire_unrunnable_pending_jobs(app_pool, unrunnable_grace).await {
        Ok(n) if n > 0 => tracing::warn!(
            target: "data_retention",
            retired = n,
            "retired pending jobs the claim path can never pick up (no zero-trust envelope, or at \
             their attempt ceiling)"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            target: "data_retention",
            error = %e,
            "retiring unrunnable pending jobs failed"
        ),
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_u64_uses_default_when_unset() {
        let key = "WEISSMAN_TEST_DR_ENV_U64_UNSET_UNIQUE_A1";
        std::env::remove_var(key);
        assert_eq!(env_u64(key, 42), 42);
        // default is also clamped to a minimum of 1
        assert_eq!(env_u64(key, 0), 1);
    }

    #[test]
    fn env_u64_parses_and_clamps() {
        let key = "WEISSMAN_TEST_DR_ENV_U64_SET_UNIQUE_B2";
        std::env::set_var(key, "100");
        assert_eq!(env_u64(key, 42), 100);
        // zero is clamped up to the minimum of 1
        std::env::set_var(key, "0");
        assert_eq!(env_u64(key, 42), 1);
        // unparseable value falls back to default
        std::env::set_var(key, "not-a-number");
        assert_eq!(env_u64(key, 42), 42);
        std::env::remove_var(key);
    }
}
