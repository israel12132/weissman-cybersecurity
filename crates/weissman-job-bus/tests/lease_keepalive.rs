//! Redis lease keep-alive: extend every 10s keeps the key alive (not "increase TTL" forever).

use std::time::Duration;
use uuid::Uuid;
use weissman_job_bus::{evaluate_keepalive, DistributedLease, KeepAliveDecision, StuckReason};

fn redis_url() -> String {
    std::env::var("REDIS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_default()
}

#[tokio::test]
async fn extend_refreshes_ttl_so_the_lease_does_not_lapse() {
    let url = redis_url();
    if url.is_empty() {
        eprintln!("SKIP lease_keepalive: REDIS_URL not set");
        return;
    }
    let client = redis::Client::open(url.as_str()).expect("redis url");
    let conn = redis::aio::ConnectionManager::new(client)
        .await
        .expect("redis connect");
    let job_id = Uuid::new_v4();
    let handle = DistributedLease::acquire(conn.clone(), job_id, "keepalive-test", "token-aa", 2)
        .await
        .expect("acquire");
    tokio::time::sleep(Duration::from_millis(800)).await;
    handle
        .extend(8)
        .await
        .expect("extend must succeed for the holder");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut c = conn.clone();
    let key = format!("weissman:job:lease:{job_id}");
    let ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut c)
        .await
        .expect("TTL");
    handle.release().await.expect("release");
    assert!(
        ttl > 0,
        "extended lease must still exist after the original 2s TTL (ttl={ttl})"
    );
}

#[test]
fn missed_progress_is_force_abort_not_silent_extend() {
    assert_eq!(
        evaluate_keepalive(true, 60, 60),
        KeepAliveDecision::Abort {
            stuck_reason: StuckReason::NoProgress60s
        }
    );
    assert_eq!(
        evaluate_keepalive(false, 1, 60),
        KeepAliveDecision::Abort {
            stuck_reason: StuckReason::LeaseHeartbeatTimeout
        }
    );
}
