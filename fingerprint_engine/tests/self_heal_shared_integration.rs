//! Live DB integration for the durable cross-replica self-heal gate. Exercises the *exact*
//! production SQL (`self_heal_shared::PUBLISH_SQL` / `REFRESH_SQL`) against a real Postgres:
//! the upsert-EXTEND semantics (`GREATEST` never shortens another replica's engagement), the
//! DB-clock remaining-seconds read, and the `expires_at > now()` expiry filter.
//!
//! ```text
//! TEST_DATABASE_URL='postgres://weissman_app:weissman_app@127.0.0.1:5432/weissman' \
//!   cargo test -p fingerprint_engine --test self_heal_shared_integration -- --nocapture
//! ```
//! Skips (not fails) when TEST_DATABASE_URL is unset, unless WEISSMAN_REQUIRE_DB_TESTS=1.

use fingerprint_engine::self_heal_shared::{PUBLISH_SQL, REFRESH_SQL};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

fn test_db_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            assert!(
                !std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
                    .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(false),
                "self_heal_shared_integration requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP self_heal_shared_integration: TEST_DATABASE_URL not set");
            String::new()
        }
    }
}

async fn pool() -> Option<PgPool> {
    let url = test_db_url();
    if url.is_empty() {
        return None;
    }
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect TEST_DATABASE_URL"),
    )
}

/// Each test uses a DISTINCT gate name so they stay independent under parallel `cargo test`
/// (the table PKs on `gate`). Cleaned up before and after so a prior run never bleeds in.
async fn reset(pool: &PgPool, gate: &str) {
    sqlx::query("DELETE FROM weissman_self_heal_gate WHERE gate = $1")
        .bind(gate)
        .execute(pool)
        .await
        .expect("reset gate row");
}

async fn publish(pool: &PgPool, gate: &str, ttl_secs: i64) {
    sqlx::query(PUBLISH_SQL)
        .bind(gate)
        .bind(ttl_secs)
        .bind("itest-replica")
        .execute(pool)
        .await
        .expect("publish gate");
}

async fn secs_left(pool: &PgPool, gate: &str) -> Option<i64> {
    let rows = sqlx::query_as::<_, (String, i64)>(REFRESH_SQL)
        .fetch_all(pool)
        .await
        .expect("refresh gates");
    rows.into_iter().find(|(g, _)| g == gate).map(|(_, s)| s)
}

#[tokio::test]
async fn publish_then_refresh_roundtrips_remaining_ttl() {
    let Some(pool) = pool().await else { return };
    const GATE: &str = "itest_shed_roundtrip";
    reset(&pool, GATE).await;

    publish(&pool, GATE, 30).await;
    let left = secs_left(&pool, GATE)
        .await
        .expect("gate present after publish");
    // DB-computed remaining should be ~30s (allow a small window for round-trip latency + CEIL).
    assert!(
        (28..=31).contains(&left),
        "expected ~30s remaining, got {left}"
    );

    reset(&pool, GATE).await;
}

#[tokio::test]
async fn upsert_extends_but_never_shortens() {
    let Some(pool) = pool().await else { return };
    const GATE: &str = "itest_shed_extend";
    reset(&pool, GATE).await;

    // Engage for 60s.
    publish(&pool, GATE, 60).await;
    let after_long = secs_left(&pool, GATE).await.expect("present");
    assert!((57..=61).contains(&after_long), "got {after_long}");

    // A shorter engagement (10s) from another replica must NOT shorten it (GREATEST keeps 60).
    publish(&pool, GATE, 10).await;
    let after_short = secs_left(&pool, GATE).await.expect("present");
    assert!(
        after_short >= 55,
        "shorter publish must not shorten the gate; got {after_short}"
    );

    // A longer engagement (120s) DOES extend it.
    publish(&pool, GATE, 120).await;
    let after_extend = secs_left(&pool, GATE).await.expect("present");
    assert!(
        (117..=121).contains(&after_extend),
        "longer publish must extend the gate; got {after_extend}"
    );

    reset(&pool, GATE).await;
}

#[tokio::test]
async fn expired_gate_is_filtered_out() {
    let Some(pool) = pool().await else { return };
    const GATE: &str = "itest_shed_expired";
    reset(&pool, GATE).await;

    // Publish already-expired (negative TTL): the row exists but expires_at < now(), so the
    // refresh query must not return it — a drained gate reads "off" fleet-wide.
    publish(&pool, GATE, -5).await;
    assert!(
        secs_left(&pool, GATE).await.is_none(),
        "expired gate must be filtered by `expires_at > now()`"
    );

    reset(&pool, GATE).await;
}
