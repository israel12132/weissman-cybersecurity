//! Live DB integration for per-tenant resource quotas. Exercises the real Postgres
//! round-trip under RLS: atomic upsert-increment, monotonic per-period accounting, and the
//! allow→deny flip at the limit boundary.
//!
//! ```text
//! TEST_DATABASE_URL='postgres://weissman_app:weissman_app@127.0.0.1:5432/weissman' \
//!   cargo test -p fingerprint_engine --test tenant_quota_integration -- --nocapture
//! ```
//! Skips (not fails) when TEST_DATABASE_URL is unset, unless WEISSMAN_REQUIRE_DB_TESTS=1.

use fingerprint_engine::tenant_quota::{enforce, report, QuotaWindow};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

const TENANT: i64 = 1;
// Each test uses a DISTINCT resource so they stay independent under parallel `cargo test`
// (they share tenant + period, so a shared resource row would interleave their increments).
// Delta-based assertions also make each robust to rows left by a previous run this period.

fn test_db_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            assert!(
                !std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
                    .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(false),
                "tenant_quota_integration requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP tenant_quota_integration: TEST_DATABASE_URL not set");
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
            .connect(&url)
            .await
            .expect("connect TEST_DATABASE_URL"),
    )
}

#[tokio::test]
async fn increments_are_atomic_and_monotonic() {
    let Some(pool) = pool().await else { return };
    const RES: &str = "itest_scans_mono";
    // Baseline (unlimited so allowed is always true).
    let base = report(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
        .await
        .expect("report");
    let start = base.used;

    // Three consumptions increment used by exactly one each.
    for i in 1..=3u64 {
        let d = enforce(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
            .await
            .expect("enforce");
        assert_eq!(d.used, start + i, "used must increment by 1 per call");
        assert!(d.allowed, "unlimited quota always allowed");
    }

    // report reflects the accumulated usage without adding to it.
    let after = report(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
        .await
        .expect("report");
    assert_eq!(after.used, start + 3);
}

#[tokio::test]
async fn deny_flips_at_limit_boundary() {
    let Some(pool) = pool().await else { return };
    const RES: &str = "itest_scans_deny";
    // Current usage for this period.
    let now = report(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
        .await
        .expect("report")
        .used;

    // Consume once more with the limit set exactly to the resulting usage → still allowed
    // (usage == limit is the last allowed request).
    let at_limit = enforce(&pool, TENANT, RES, QuotaWindow::Monthly, now + 1)
        .await
        .expect("enforce");
    assert_eq!(at_limit.used, now + 1);
    assert!(at_limit.allowed, "usage == limit is allowed");
    assert_eq!(at_limit.remaining, 0);

    // Next consumption with the same (now-exceeded) limit → denied.
    let over = enforce(&pool, TENANT, RES, QuotaWindow::Monthly, now + 1)
        .await
        .expect("enforce");
    assert_eq!(over.used, now + 2);
    assert!(!over.allowed, "usage > limit must be denied");
    assert_eq!(over.remaining, 0);

    // Unlimited (limit 0) is always allowed regardless of usage.
    let unlimited = enforce(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
        .await
        .expect("enforce");
    assert!(unlimited.allowed);
}
