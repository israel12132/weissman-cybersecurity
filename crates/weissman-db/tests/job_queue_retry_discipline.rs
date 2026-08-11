//! `max_attempts` must be enforced where every path has to pass through it: the claim.
//!
//! It used to be checked in exactly one place — `fail_job` — so any route that returned a row to
//! `pending` without going through it produced a job that could never be retired:
//!
//!   * a worker that OOMs or stack-overflows before reporting (a failure mode the worker's own
//!     comments document) leaves the row `running` until `reclaim_stale_running_locks` requeues it
//!     — unconditionally, with no attempt check;
//!   * `force_requeue_running`, which runs precisely when `fail_job` itself just failed, reset
//!     `run_after = now()`, putting the row straight back at the head of the queue with no delay.
//!
//! The poll loop then re-claimed it immediately (`POLL_IDLE_MS` only applies to an empty queue) and
//! spun on that single row, starving everything else. Observed in production:
//!
//! ```text
//! kind             | status | attempt_count | max_attempts
//! tenant_full_scan | dead   |      53620122 |            5
//! ```
//!
//! Fifty-three million attempts against a cap of five. These tests pin the three changes that
//! close it: the cap on both claim predicates, dead-lettering of exhausted rows by the stale-lock
//! reclaim, and a real backoff on `force_requeue_running`.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test job_queue_retry_discipline -- --nocapture
//! ```

mod common;

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use weissman_db::job_queue::{self, WorkerPoolRole};

/// One tenant per test. `cargo test` runs them in parallel and every helper here filters by
/// tenant, so a shared id would mean each test's cleanup deleting the others' fixtures mid-run.
const TENANT_CLAIM_CAP: i64 = 918_275_001;
const TENANT_RECLAIM: i64 = 918_275_002;
const TENANT_REQUEUE: i64 = 918_275_003;
const PROBE_KIND: &str = "__job_queue_retry_discipline__";

fn require_db_tests() -> bool {
    std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn test_database_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => {
            assert!(
                !require_db_tests(),
                "job_queue_retry_discipline requires TEST_DATABASE_URL, but \
                 WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP job_queue_retry_discipline: TEST_DATABASE_URL not set");
            String::new()
        }
    }
}

async fn admin_pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect TEST_DATABASE_URL")
}

/// Pool that is subject to RLS, like the real worker.
async fn worker_pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE weissman_app").execute(conn).await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .expect("connect worker pool as weissman_app")
}

async fn reset(pool: &sqlx::PgPool, tenant: i64) {
    cleanup(pool, tenant).await;
    let _ = sqlx::query(
        "INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'Retry probe') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant)
    .bind(format!("retry-probe-{tenant}"))
    .execute(pool)
    .await;
}

async fn cleanup(pool: &sqlx::PgPool, tenant: i64) {
    let _ = sqlx::query("DELETE FROM weissman_async_jobs WHERE kind = $1 AND tenant_id = $2")
        .bind(PROBE_KIND)
        .bind(tenant)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant)
        .execute(pool)
        .await;
}

/// Insert a probe job in an arbitrary state. `stale` backdates the lock/heartbeat to look like a
/// worker that died mid-run; `worker_id` claims ownership.
async fn insert_job(
    pool: &sqlx::PgPool,
    tenant: i64,
    status: &str,
    attempts: i32,
    max_attempts: i32,
    stale: bool,
    worker_id: Option<&str>,
) -> uuid::Uuid {
    sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs
               (tenant_id, kind, payload, status, attempt_count, max_attempts,
                locked_until, heartbeat_at, worker_id)
           VALUES ($1, $2, '{"_weissman_job_bus": {"envelope": {}}}'::jsonb, $3, $4, $5,
                   CASE WHEN $6 THEN now() - interval '1 hour' ELSE NULL END,
                   CASE WHEN $6 THEN now() - interval '1 hour' ELSE NULL END,
                   $7)
           RETURNING id"#,
    )
    .bind(tenant)
    .bind(PROBE_KIND)
    .bind(status)
    .bind(attempts)
    .bind(max_attempts)
    .bind(stale)
    .bind(worker_id)
    .fetch_one(pool)
    .await
    .expect("insert probe job")
}

async fn status_of(pool: &sqlx::PgPool, id: uuid::Uuid) -> String {
    sqlx::query("SELECT status FROM weissman_async_jobs WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read status")
        .get::<String, _>("status")
}

/// A job at its attempt ceiling must never be handed out again.
#[tokio::test]
async fn an_exhausted_job_is_not_claimable() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    // Claiming is global — see common::lock_claims.
    let _claims = common::lock_claims(&admin).await;
    reset(&admin, TENANT_CLAIM_CAP).await;

    let exhausted = insert_job(&admin, TENANT_CLAIM_CAP, "pending", 5, 5, false, None).await;
    let fresh = insert_job(&admin, TENANT_CLAIM_CAP, "pending", 0, 5, false, None).await;

    let wp = worker_pool(&url).await;
    let mut claimed = Vec::new();
    for _ in 0..4 {
        match job_queue::reserve_next_with_role(&wp, "retry-discipline", 300, WorkerPoolRole::Mixed)
            .await
        {
            Ok(Some(j)) if j.kind == PROBE_KIND => claimed.push(j.id),
            Ok(_) => break,
            Err(e) => {
                cleanup(&admin, TENANT_CLAIM_CAP).await;
                panic!("reserve failed: {e}");
            }
        }
    }
    cleanup(&admin, TENANT_CLAIM_CAP).await;

    assert!(
        claimed.contains(&fresh),
        "a job below its cap must still be claimable"
    );
    assert!(
        !claimed.contains(&exhausted),
        "a job at attempt_count == max_attempts was claimed again — this is the 53,620,122-attempt \
         bug: nothing else re-checks the cap once a row is back in `pending`"
    );
}

/// The stale-lock reclaim is the only path that can retire a job whose worker died mid-run.
#[tokio::test]
async fn stale_reclaim_dead_letters_exhausted_and_requeues_the_rest() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    reset(&admin, TENANT_RECLAIM).await;

    // Both are `running` with a lock that lapsed an hour ago — the worker-died shape.
    let exhausted = insert_job(&admin, TENANT_RECLAIM, "running", 5, 5, true, Some("dead-worker")).await;
    let retryable = insert_job(&admin, TENANT_RECLAIM, "running", 1, 5, true, Some("dead-worker")).await;

    let wp = worker_pool(&url).await;
    job_queue::reclaim_stale_running_locks(&wp)
        .await
        .expect("reclaim");

    let exhausted_status = status_of(&admin, exhausted).await;
    let retryable_status = status_of(&admin, retryable).await;
    let preserved: Option<String> =
        sqlx::query_scalar("SELECT last_error FROM weissman_async_jobs WHERE id = $1")
            .bind(retryable)
            .fetch_one(&admin)
            .await
            .expect("read last_error");
    cleanup(&admin, TENANT_RECLAIM).await;

    assert_eq!(
        exhausted_status, "dead",
        "a `running` job past its cap whose worker vanished must be dead-lettered here — this is \
         the only path that can retire it, and requeuing it made it immortal"
    );
    assert_eq!(
        retryable_status, "pending",
        "a job still under its cap must be requeued, not killed"
    );
    assert!(
        preserved.unwrap_or_default().contains("stale lock reclaimed"),
        "the reclaim marker must be recorded"
    );
}

/// `force_requeue_running` runs when `fail_job` itself failed. Zero backoff there is what let the
/// poll loop re-claim the same row on its very next iteration.
#[tokio::test]
async fn force_requeue_applies_a_backoff() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    reset(&admin, TENANT_REQUEUE).await;

    let id = insert_job(&admin, TENANT_REQUEUE, "running", 1, 5, false, Some("stuck-worker")).await;

    let wp = worker_pool(&url).await;
    job_queue::force_requeue_running(&wp, id, "stuck-worker", "terminal write failed")
        .await
        .expect("force requeue");

    let claimable_now: bool = sqlx::query_scalar(
        "SELECT (run_after IS NULL OR run_after <= now()) FROM weissman_async_jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&admin)
    .await
    .expect("read run_after");
    cleanup(&admin, TENANT_REQUEUE).await;

    assert!(
        !claimable_now,
        "force_requeue_running must schedule the retry into the future; with run_after = now() the \
         worker re-claims the same row immediately and spins on it, starving the queue"
    );
}
