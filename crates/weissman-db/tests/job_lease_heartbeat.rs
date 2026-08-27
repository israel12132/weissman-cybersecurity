//! Lease keep-alive + Force-Abort + cross-tenant claim (Queue Starvation).
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test job_lease_heartbeat -- --nocapture
//! ```

mod common;

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use weissman_db::job_queue::{self, AsyncJob, WorkerPoolRole};

const TENANT_A: i64 = 918_277_001;
const TENANT_B: i64 = 918_277_002;
const KIND: &str = "__job_lease_heartbeat__";

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
                "job_lease_heartbeat requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP job_lease_heartbeat: TEST_DATABASE_URL not set");
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

async fn ensure_tenant(pool: &sqlx::PgPool, tenant: i64) {
    let _ = sqlx::query(
        "INSERT INTO tenants (id, slug, name) VALUES ($1, $2, 'Lease heartbeat probe') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant)
    .bind(format!("lease-hb-{tenant}"))
    .execute(pool)
    .await;
}

async fn cleanup(pool: &sqlx::PgPool, tenant: i64) {
    let _ = sqlx::query("DELETE FROM weissman_async_jobs WHERE kind = $1 AND tenant_id = $2")
        .bind(KIND)
        .bind(tenant)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant)
        .execute(pool)
        .await;
}

async fn insert_running(
    pool: &sqlx::PgPool,
    tenant: i64,
    worker_id: &str,
    lock_secs: i64,
) -> uuid::Uuid {
    sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs
               (tenant_id, kind, payload, status, attempt_count, max_attempts,
                locked_until, heartbeat_at, worker_id)
           VALUES ($1, $2, '{}'::jsonb, 'running', 1, 5,
                   now() + ($4::bigint * interval '1 second'), now(), $3)
           RETURNING id"#,
    )
    .bind(tenant)
    .bind(KIND)
    .bind(worker_id)
    .bind(lock_secs)
    .fetch_one(pool)
    .await
    .expect("insert running job")
}

async fn insert_pending(pool: &sqlx::PgPool, tenant: i64) -> uuid::Uuid {
    sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs
               (tenant_id, kind, payload, status, attempt_count, max_attempts)
           VALUES ($1, $2, '{}'::jsonb, 'pending', 0, 5)
           RETURNING id"#,
    )
    .bind(tenant)
    .bind(KIND)
    .fetch_one(pool)
    .await
    .expect("insert pending job")
}

fn async_job(id: uuid::Uuid, tenant: i64) -> AsyncJob {
    AsyncJob {
        id,
        tenant_id: tenant,
        kind: KIND.into(),
        payload: serde_json::json!({}),
        attempt_count: 1,
        max_attempts: 5,
        trace_id: None,
    }
}

/// Claim until we get our probe kind; put unrelated rows back so we don't steal the fleet queue.
async fn claim_our_kind(pool: &sqlx::PgPool, worker_id: &str) -> Option<AsyncJob> {
    for _ in 0..32 {
        match job_queue::claim_next_with_role(pool, worker_id, 300, WorkerPoolRole::Mixed).await {
            Ok(Some(j)) if j.kind == KIND => return Some(j),
            Ok(Some(j)) => {
                let _ = job_queue::force_requeue_running(
                    pool,
                    j.id,
                    worker_id,
                    "job_lease_heartbeat: not our probe",
                )
                .await;
            }
            Ok(None) => return None,
            Err(e) => panic!("claim failed: {e}"),
        }
    }
    None
}

#[tokio::test]
async fn heartbeat_extends_locked_until() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    let _claims = common::lock_claims(&admin).await;
    cleanup(&admin, TENANT_A).await;
    ensure_tenant(&admin, TENANT_A).await;

    let id = insert_running(&admin, TENANT_A, "hb-worker", 15).await;
    let before: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT locked_until FROM weissman_async_jobs WHERE id = $1")
            .bind(id)
            .fetch_one(&admin)
            .await
            .expect("locked_until before");

    let wp = worker_pool(&url).await;
    job_queue::heartbeat(&wp, id, 300).await.expect("heartbeat");

    let after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT locked_until FROM weissman_async_jobs WHERE id = $1")
            .bind(id)
            .fetch_one(&admin)
            .await
            .expect("locked_until after");
    cleanup(&admin, TENANT_A).await;

    assert!(
        after > before,
        "heartbeat must push locked_until forward (before={before}, after={after})"
    );
    let remaining = (after - chrono::Utc::now()).num_seconds();
    assert!(
        remaining > 60,
        "300s extend should leave well over a minute on the lock, remaining={remaining}"
    );
}

#[tokio::test]
async fn no_progress_force_abort_fails_job_and_frees_the_lease() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    let _claims = common::lock_claims(&admin).await;
    cleanup(&admin, TENANT_A).await;
    cleanup(&admin, TENANT_B).await;
    ensure_tenant(&admin, TENANT_A).await;
    ensure_tenant(&admin, TENANT_B).await;

    let hung = insert_running(&admin, TENANT_A, "w-hung", 300).await;
    let other = insert_pending(&admin, TENANT_B).await;

    let wp = worker_pool(&url).await;
    let n = job_queue::fail_job_stuck(
        &wp,
        &async_job(hung, TENANT_A),
        "w-hung",
        "no_progress_60s",
        "stuck_reason=no_progress_60s: last progress: fuzz_probe",
    )
    .await
    .expect("fail_job_stuck");
    assert_eq!(n, 1, "Force Abort must update the owned running row");

    let row = sqlx::query(
        "SELECT status, stuck_reason, worker_id, locked_until FROM weissman_async_jobs WHERE id = $1",
    )
    .bind(hung)
    .fetch_one(&admin)
    .await
    .expect("read aborted row");
    let status: String = row.get("status");
    let stuck: Option<String> = row.get("stuck_reason");
    let worker: Option<String> = row.get("worker_id");
    let lock: Option<chrono::DateTime<chrono::Utc>> = row.get("locked_until");
    assert_eq!(status, "failed");
    assert_eq!(stuck.as_deref(), Some("no_progress_60s"));
    assert!(worker.is_none(), "lease/worker must be returned");
    assert!(lock.is_none(), "locked_until must be cleared");

    let claimed = claim_our_kind(&wp, "w-free").await;
    cleanup(&admin, TENANT_A).await;
    cleanup(&admin, TENANT_B).await;

    let claimed = claimed.expect("second worker must be able to claim other tenants");
    assert_eq!(
        claimed.id, other,
        "after Force Abort the other tenant's job must be claimable (got {})",
        claimed.id
    );
    assert_eq!(claimed.tenant_id, TENANT_B);
}

#[tokio::test]
async fn running_job_on_tenant_a_does_not_block_claim_of_tenant_b() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    let _claims = common::lock_claims(&admin).await;
    cleanup(&admin, TENANT_A).await;
    cleanup(&admin, TENANT_B).await;
    ensure_tenant(&admin, TENANT_A).await;
    ensure_tenant(&admin, TENANT_B).await;

    let _running = insert_running(&admin, TENANT_A, "w-a", 300).await;
    let pending_b = insert_pending(&admin, TENANT_B).await;

    let wp = worker_pool(&url).await;
    let claimed = claim_our_kind(&wp, "w-b").await;
    cleanup(&admin, TENANT_A).await;
    cleanup(&admin, TENANT_B).await;

    let claimed = claimed.expect("SKIP LOCKED must hand tenant B to the second worker");
    assert_eq!(claimed.id, pending_b);
    assert_eq!(claimed.tenant_id, TENANT_B);
}

#[tokio::test]
async fn heartbeat_does_not_stamp_physical_progress() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    let _claims = common::lock_claims(&admin).await;
    cleanup(&admin, TENANT_A).await;
    ensure_tenant(&admin, TENANT_A).await;

    let id = insert_running(&admin, TENANT_A, "hb-worker", 15).await;
    let wp = worker_pool(&url).await;
    job_queue::heartbeat(&wp, id, 300).await.expect("heartbeat");

    let row =
        sqlx::query("SELECT progress_at, heartbeat_at FROM weissman_async_jobs WHERE id = $1")
            .bind(id)
            .fetch_one(&admin)
            .await
            .expect("read");
    let progress_at: Option<chrono::DateTime<chrono::Utc>> = row.get("progress_at");
    let heartbeat_at: Option<chrono::DateTime<chrono::Utc>> = row.get("heartbeat_at");
    cleanup(&admin, TENANT_A).await;

    assert!(
        progress_at.is_none(),
        "lease keep-alive must not impersonate physical progress"
    );
    assert!(heartbeat_at.is_some(), "heartbeat_at must be set");
}

#[tokio::test]
async fn record_progress_is_distinct_from_heartbeat() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    let _claims = common::lock_claims(&admin).await;
    cleanup(&admin, TENANT_A).await;
    ensure_tenant(&admin, TENANT_A).await;

    let id = insert_running(&admin, TENANT_A, "hb-worker", 15).await;
    let wp = worker_pool(&url).await;
    job_queue::record_progress(&wp, id, "engine:http_feedback_fuzz")
        .await
        .expect("record_progress");

    let row = sqlx::query(
        "SELECT progress_at, progress_note, stuck_reason FROM weissman_async_jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&admin)
    .await
    .expect("read");
    let progress_at: Option<chrono::DateTime<chrono::Utc>> = row.get("progress_at");
    let note: Option<String> = row.get("progress_note");
    let stuck: Option<String> = row.get("stuck_reason");
    cleanup(&admin, TENANT_A).await;

    assert!(
        progress_at.is_some(),
        "physical progress must stamp progress_at"
    );
    assert_eq!(note.as_deref(), Some("engine:http_feedback_fuzz"));
    assert!(stuck.is_none());
}
