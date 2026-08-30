//! Redis job-lease lifecycle: TTL is always set, expired leases are stealable,
//! a living extend prevents steal, immortal (no-TTL) keys are healed.
//!
//! ```text
//! REDIS_URL='redis://127.0.0.1:6379/0' \
//!   cargo test -p weissman-job-bus --test lease_lifecycle -- --nocapture
//! ```

use uuid::Uuid;
use weissman_job_bus::{lease_key, new_claim_token, DistributedLease};

fn require_redis_tests() -> bool {
    std::env::var("WEISSMAN_REQUIRE_REDIS_TESTS")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn redis_url() -> String {
    match std::env::var("REDIS_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => {
            assert!(
                !require_redis_tests(),
                "lease_lifecycle requires REDIS_URL, but WEISSMAN_REQUIRE_REDIS_TESTS is set"
            );
            eprintln!("SKIP lease_lifecycle: REDIS_URL not set");
            String::new()
        }
    }
}

async fn manager(url: &str) -> redis::aio::ConnectionManager {
    let client = redis::Client::open(url).expect("REDIS_URL");
    redis::aio::ConnectionManager::new(client)
        .await
        .expect("connect Redis")
}

async fn del(redis: &redis::aio::ConnectionManager, job_id: Uuid) {
    let mut conn = redis.clone();
    let _: redis::RedisResult<i64> = redis::cmd("DEL")
        .arg(lease_key(job_id))
        .query_async(&mut conn)
        .await;
}

#[tokio::test]
async fn acquire_sets_a_real_ttl() {
    let url = redis_url();
    if url.is_empty() {
        return;
    }
    let redis = manager(&url).await;
    let job = Uuid::new_v4();
    del(&redis, job).await;
    let handle = DistributedLease::acquire(redis.clone(), job, "w-a", &new_claim_token(), 8)
        .await
        .expect("acquire");
    let inspect = DistributedLease::inspect(&redis, job)
        .await
        .expect("inspect");
    let many = DistributedLease::inspect_many(&redis, &[job])
        .await
        .expect("inspect_many");
    handle.release().await.ok();
    assert!(inspect.exists, "lease must exist after acquire");
    assert!(
        inspect.ttl_secs >= 1,
        "SET NX EX must leave a TTL, got {}",
        inspect.ttl_secs
    );
    assert!(!inspect.is_immortal(), "fresh acquire must not be immortal");
    assert_eq!(
        many.get(&job).map(|i| i.exists),
        Some(true),
        "inspect_many must see the same lease"
    );
}

#[tokio::test]
async fn expired_lease_is_claimed_by_another_worker() {
    let url = redis_url();
    if url.is_empty() {
        return;
    }
    let redis = manager(&url).await;
    let job = Uuid::new_v4();
    del(&redis, job).await;
    let a = DistributedLease::acquire(redis.clone(), job, "w-a", &new_claim_token(), 1)
        .await
        .expect("A acquire");
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    let b = DistributedLease::acquire(redis.clone(), job, "w-b", &new_claim_token(), 8)
        .await
        .expect("B must steal expired lease");
    let inspect = DistributedLease::inspect(&redis, job)
        .await
        .expect("inspect");
    let _ = a.release().await;
    b.release().await.ok();
    assert_eq!(inspect.holder_worker_id.as_deref(), Some("w-b"));
}

#[tokio::test]
async fn live_extend_prevents_steal() {
    let url = redis_url();
    if url.is_empty() {
        return;
    }
    let redis = manager(&url).await;
    let job = Uuid::new_v4();
    del(&redis, job).await;
    let a = DistributedLease::acquire(redis.clone(), job, "w-live", &new_claim_token(), 2)
        .await
        .expect("acquire");
    for _ in 0..4 {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        a.extend(2).await.expect("extend");
    }
    let steal =
        DistributedLease::acquire(redis.clone(), job, "w-thief", &new_claim_token(), 8).await;
    a.release().await.ok();
    assert!(
        steal.is_err(),
        "living heartbeat must prevent steal, got ok={ok}",
        ok = steal.is_ok()
    );
}

#[tokio::test]
async fn immortal_key_is_stolen_so_resume_works() {
    let url = redis_url();
    if url.is_empty() {
        return;
    }
    let redis = manager(&url).await;
    let job = Uuid::new_v4();
    del(&redis, job).await;
    let mut conn = redis.clone();
    // The production bug: SET NX with no EX. Crash between SET and EXPIRE.
    let _: redis::RedisResult<Option<String>> = redis::cmd("SET")
        .arg(lease_key(job))
        .arg("dead-worker:deadtoken")
        .arg("NX")
        .query_async(&mut conn)
        .await;
    let inspect_before = DistributedLease::inspect(&redis, job)
        .await
        .expect("inspect");
    assert!(
        inspect_before.is_immortal(),
        "fixture must be immortal, ttl={}",
        inspect_before.ttl_secs
    );

    let b = DistributedLease::acquire(redis.clone(), job, "w-resumer", &new_claim_token(), 8)
        .await
        .expect("acquire must steal immortal key so tenant_full_scan can resume");
    let inspect_after = DistributedLease::inspect(&redis, job)
        .await
        .expect("inspect");
    b.release().await.ok();
    assert_eq!(inspect_after.holder_worker_id.as_deref(), Some("w-resumer"));
    assert!(inspect_after.ttl_secs >= 1, "stolen lease must have a TTL");
}

#[tokio::test]
async fn heal_immortal_leases_deletes_persist_forever_keys() {
    let url = redis_url();
    if url.is_empty() {
        return;
    }
    let redis = manager(&url).await;
    let job = Uuid::new_v4();
    del(&redis, job).await;
    let mut conn = redis.clone();
    let _: redis::RedisResult<Option<String>> = redis::cmd("SET")
        .arg(lease_key(job))
        .arg("ghost:token")
        .query_async(&mut conn)
        .await;
    let n = DistributedLease::heal_immortal_leases(&redis)
        .await
        .expect("heal");
    let inspect = DistributedLease::inspect(&redis, job)
        .await
        .expect("inspect");
    assert!(n >= 1, "heal must delete at least the fixture key");
    assert!(!inspect.exists, "immortal key must be gone after heal");
}
