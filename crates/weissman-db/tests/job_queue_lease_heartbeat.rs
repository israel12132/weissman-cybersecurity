//! Job lease heartbeat / reclaim / resume — Postgres lock is reclaimable, a living
//! heartbeat cannot be stolen, and a crashed worker's `tenant_full_scan` can resume.
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test job_queue_lease_heartbeat -- --nocapture
//! ```

mod common;

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use weissman_db::job_queue::{self, WorkerPoolRole};

const TENANT_STEAL: i64 = 918_277_001;
const TENANT_HEARTBEAT: i64 = 918_277_002;
const TENANT_RESUME: i64 = 918_277_003;
const PROBE_KIND: &str = "__job_queue_lease_heartbeat__";

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
                "job_queue_lease_heartbeat requires TEST_DATABASE_URL, but \
                 WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP job_queue_lease_heartbeat: TEST_DATABASE_URL not set");
            String::new()
        }
    }
}

async fn admin_pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect TEST_DATABASE_URL")
}

async fn worker_pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(4)
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
        .bind(PROBE_KIND)
        .bind(tenant)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant)
        .execute(pool)
        .await;
}

async fn enqueue(pool: &sqlx::PgPool, tenant: i64) -> uuid::Uuid {
    job_queue::enqueue(
        pool,
        tenant,
        PROBE_KIND,
        serde_json::json!({"_weissman_job_bus": {"envelope": {}}}),
        None,
    )
    .await
    .expect("enqueue")
}

async fn row_owner(pool: &sqlx::PgPool, id: uuid::Uuid) -> (String, Option<String>) {
    let row = sqlx::query("SELECT status, worker_id FROM weissman_async_jobs WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read job");
    (
        row.try_get("status").expect("status"),
        row.try_get("worker_id").ok().flatten(),
    )
}

/// After the lock expires and reclaim runs, a second worker must be able to claim the job.
#[tokio::test]
async fn expired_lock_is_claimed_by_another_worker() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    let _claims = common::lock_claims(&admin).await;
    reset(&admin, TENANT_STEAL).await;
    let wp = worker_pool(&url).await;
    let id = enqueue(&admin, TENANT_STEAL).await;

    let first = job_queue::claim_next_with_role(&wp, "worker-A", 1, WorkerPoolRole::Mixed)
        .await
        .expect("claim A")
        .expect("A got the job");
    assert_eq!(first.id, id);

    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    let reclaimed = job_queue::reclaim_stale_locks(&wp).await.expect("reclaim");
    assert!(
        reclaimed
            .iter()
            .any(|r| r.id == id && r.new_status == "pending"),
        "expired running lock must be requeued, got {reclaimed:?}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;

    let second = job_queue::claim_next_with_role(&wp, "worker-B", 30, WorkerPoolRole::Mixed)
        .await
        .expect("claim B")
        .expect("B must resume the expired job");
    cleanup(&admin, TENANT_STEAL).await;

    assert_eq!(second.id, id, "B must claim the same job A lost");
    assert_eq!(second.attempt_count, 2);
}

/// A living heartbeat keeps `locked_until` in the future so reclaim cannot steal the row.
#[tokio::test]
async fn live_heartbeat_prevents_steal() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    let _claims = common::lock_claims(&admin).await;
    reset(&admin, TENANT_HEARTBEAT).await;
    let wp = worker_pool(&url).await;
    let id = enqueue(&admin, TENANT_HEARTBEAT).await;

    let first = job_queue::claim_next_with_role(&wp, "worker-live", 1, WorkerPoolRole::Mixed)
        .await
        .expect("claim")
        .expect("got job");
    assert_eq!(first.id, id);

    for _ in 0..4 {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let kept = job_queue::heartbeat_owned(&wp, id, "worker-live", 2)
            .await
            .expect("heartbeat");
        assert!(kept, "living worker must still own the row");
    }

    let reclaimed = job_queue::reclaim_stale_locks(&wp).await.expect("reclaim");
    assert!(
        reclaimed.iter().all(|r| r.id != id),
        "a beating job must not be reclaimed, got {reclaimed:?}"
    );

    let stolen = job_queue::claim_next_with_role(&wp, "worker-thief", 30, WorkerPoolRole::Mixed)
        .await
        .expect("claim thief");
    let (status, owner) = row_owner(&admin, id).await;
    cleanup(&admin, TENANT_HEARTBEAT).await;

    assert!(
        stolen.as_ref().map(|j| j.id) != Some(id),
        "thief claimed the beating job"
    );
    assert_eq!(status, "running");
    assert_eq!(owner.as_deref(), Some("worker-live"));
}

/// Reclaim after crash returns the row to pending; the next worker resumes (new attempt).
#[tokio::test]
async fn resume_after_stale_reclaim() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let admin = admin_pool(&url).await;
    let _claims = common::lock_claims(&admin).await;
    reset(&admin, TENANT_RESUME).await;
    let wp = worker_pool(&url).await;
    let id = enqueue(&admin, TENANT_RESUME).await;

    let _ = job_queue::claim_next_with_role(&wp, "crashed-worker", 1, WorkerPoolRole::Mixed)
        .await
        .expect("claim")
        .expect("got job");

    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    job_queue::reclaim_stale_locks(&wp).await.expect("reclaim");

    let still_owned = job_queue::heartbeat_owned(&wp, id, "crashed-worker", 30)
        .await
        .expect("stale heartbeat");
    assert!(
        !still_owned,
        "the crashed worker must not be able to extend a reclaimed lock"
    );

    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    let resumed = job_queue::claim_next_with_role(&wp, "resumer", 30, WorkerPoolRole::Mixed)
        .await
        .expect("resume claim")
        .expect("resumer got the job");
    cleanup(&admin, TENANT_RESUME).await;

    assert_eq!(resumed.id, id);
    assert_eq!(resumed.attempt_count, 2);
}

/// Reserved-but-still-pending (zero-trust) rows with an expired lock are reclaimable.
#[tokio::test]
async fn expired_reservation_is_reclaimed_and_resumed() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    const TENANT_RESERVE: i64 = 918_277_004;
    let admin = admin_pool(&url).await;
    let _claims = common::lock_claims(&admin).await;
    reset(&admin, TENANT_RESERVE).await;
    let wp = worker_pool(&url).await;
    let id = enqueue(&admin, TENANT_RESERVE).await;

    let reserved = job_queue::reserve_next_with_role(&wp, "worker-A", 1, WorkerPoolRole::Mixed)
        .await
        .expect("reserve")
        .expect("reserved");
    assert_eq!(reserved.id, id);
    let (status, owner) = row_owner(&admin, id).await;
    assert_eq!(status, "pending");
    assert_eq!(owner.as_deref(), Some("worker-A"));

    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    let reclaimed = job_queue::reclaim_stale_locks(&wp).await.expect("reclaim");
    assert!(
        reclaimed.iter().any(|r| r.id == id),
        "expired reservation must be reclaimed, got {reclaimed:?}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;

    let second = job_queue::reserve_next_with_role(&wp, "worker-B", 30, WorkerPoolRole::Mixed)
        .await
        .expect("reserve B")
        .expect("B resumes");
    cleanup(&admin, TENANT_RESERVE).await;
    assert_eq!(second.id, id);
}
