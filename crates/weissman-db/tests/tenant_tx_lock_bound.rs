//! Contract: a transaction opened with `begin_tenant_tx` never waits on a lock forever.
//!
//! This is the row-lock half of the hang documented in `docs/TECH_DEBT_flaky_db_test_hang.md`.
//! `weissman_db::advisory_lock` bounded advisory locks; `SELECT … FOR UPDATE` is the *same*
//! defect in different syntax — it blocks indefinitely by default, and whether anything bounds it
//! depends on the `lock_timeout` of whichever connection the caller was handed. Under a bare
//! `PgPoolOptions::new()` test pool that is `0`, i.e. infinite.
//!
//! The bound now comes from `set_tenant_tx`, which sets `lock_timeout` alongside the RLS GUC for
//! every tenant transaction. These tests pin both halves of that claim:
//!
//! 1. the bound is actually applied (catches someone dropping the `set_config` from the query);
//! 2. a contended row lock consequently *errors* instead of hanging.
//!
//! Both pools below are deliberately built from a bare `PgPoolOptions::new()` — the exact
//! unbounded shape every test in this workspace uses — so they prove the bound comes from
//! `set_tenant_tx` and not from pool configuration a future refactor could drop.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test tenant_tx_lock_bound -- --nocapture
//! ```

use sqlx::postgres::PgPoolOptions;
use std::time::{Duration, Instant};
use weissman_db::advisory_lock::{bound_lock_wait, is_lock_timeout, lock_timeout};

const TENANT: i64 = 1;

/// Short enough that the suite stays fast, long enough not to trip on a loaded runner.
///
/// Applied by calling `bound_lock_wait` explicitly rather than through the environment: `cargo
/// test` runs a binary's tests on multiple threads and `std::env::set_var` is process-global and
/// races with any concurrent reader.
const TEST_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Independent ceiling for the contended attempt. Without it, a regression back to an unbounded
/// wait would make this test *hang* — reproducing the exact failure it exists to catch — until
/// some far-away job timeout killed it with no output.
const TEST_DEADLINE: Duration = Duration::from_secs(30);

fn require_db_tests() -> bool {
    std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Same contract as `rls_cross_tenant`: a hard failure in CI (so a dropped `TEST_DATABASE_URL`
/// can never masquerade as a green run), a visible skip locally.
fn test_database_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => {
            assert!(
                !require_db_tests(),
                "tenant_tx_lock_bound requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP tenant_tx_lock_bound: TEST_DATABASE_URL not set (no test Postgres)");
            String::new()
        }
    }
}

/// A pool with NO `acquire_timeout`, NO `statement_timeout` and NO `lock_timeout` — the shape
/// that made the hang possible. Two connections: one holder, one waiter.
async fn unbounded_pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("connect TEST_DATABASE_URL")
}

/// Each test gets its own uniquely named probe table, so the two can run concurrently (as `cargo
/// test` does by default) without contending with each other and without leaving shared state
/// behind. `UNLOGGED` because durability is irrelevant here and it keeps the WAL quiet.
async fn make_probe_table(pool: &sqlx::PgPool, suffix: &str) -> String {
    let table = format!("weissman_row_lock_probe_{suffix}");
    sqlx::query(&format!("DROP TABLE IF EXISTS {table}"))
        .execute(pool)
        .await
        .expect("drop stale probe table");
    sqlx::query(&format!(
        "CREATE UNLOGGED TABLE {table} (id bigint PRIMARY KEY)"
    ))
    .execute(pool)
    .await
    .expect("create probe table");
    sqlx::query(&format!("INSERT INTO {table} (id) VALUES (1)"))
        .execute(pool)
        .await
        .expect("seed probe row");
    table
}

async fn drop_probe_table(pool: &sqlx::PgPool, table: &str) {
    let _ = sqlx::query(&format!("DROP TABLE IF EXISTS {table}"))
        .execute(pool)
        .await;
}

/// The mechanism itself: `begin_tenant_tx` must leave the transaction carrying a **finite**
/// `lock_timeout`. This is the test that fails if someone removes the `set_config('lock_timeout',
/// …)` from `set_tenant_tx` — it needs no contention and no waiting, so it can never be flaky.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn begin_tenant_tx_applies_a_finite_lock_timeout() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = unbounded_pool(&url).await;

    // Baseline: the pool really is unbounded, so the assertion below is about `set_tenant_tx`
    // and not about something the connection already had. (In CI the database-level backstop
    // sets a non-zero value, so this only asserts the two differ, not that the baseline is 0.)
    let session: String = sqlx::query_scalar("SHOW lock_timeout")
        .fetch_one(&pool)
        .await
        .expect("read session lock_timeout");

    let mut tx = weissman_db::begin_tenant_tx(&pool, TENANT)
        .await
        .expect("begin tenant tx");
    let in_tx: String = sqlx::query_scalar("SHOW lock_timeout")
        .fetch_one(&mut *tx)
        .await
        .expect("read transaction lock_timeout");

    assert_ne!(
        in_tx.trim(),
        "0",
        "begin_tenant_tx left lock_timeout at 0 — that means WAIT FOREVER, the exact defect this \
         contract exists to prevent. Check set_config('lock_timeout', …) in set_tenant_tx."
    );

    // And it must be the configured bound, not some unrelated inherited value.
    let expected_ms = lock_timeout().as_millis();
    let got_ms = parse_pg_interval_ms(&in_tx);
    assert_eq!(
        got_ms, expected_ms,
        "expected lock_timeout {expected_ms}ms from set_tenant_tx, got {in_tx:?} \
         (session default was {session:?})"
    );

    let _ = tx.rollback().await;
}

/// Postgres renders `lock_timeout` with a unit once it is large enough (`15000` → `15s`).
fn parse_pg_interval_ms(shown: &str) -> u128 {
    let s = shown.trim();
    if let Some(v) = s.strip_suffix("ms") {
        v.trim().parse().unwrap_or(0)
    } else if let Some(v) = s.strip_suffix("min") {
        v.trim().parse::<u128>().unwrap_or(0) * 60_000
    } else if let Some(v) = s.strip_suffix('s') {
        v.trim().parse::<u128>().unwrap_or(0) * 1_000
    } else {
        s.parse().unwrap_or(0)
    }
}

/// The behaviour: a contended `SELECT … FOR UPDATE` must fail with `55P03` instead of blocking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contended_row_lock_times_out_instead_of_hanging_forever() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = unbounded_pool(&url).await;
    let table = make_probe_table(&pool, "contended").await;

    // Holder: lock the row and keep the transaction open for the whole test.
    let mut holder = weissman_db::begin_tenant_tx(&pool, TENANT)
        .await
        .expect("begin holder tx");
    sqlx::query(&format!("SELECT id FROM {table} WHERE id = 1 FOR UPDATE"))
        .fetch_one(&mut *holder)
        .await
        .expect("holder takes the row lock uncontended");

    // Waiter: same row. Tighten the bound first so the test is fast — the default is 15 s, and
    // what is under test is "it returns at all", not the specific number.
    let mut waiter = weissman_db::begin_tenant_tx(&pool, TENANT)
        .await
        .expect("begin waiter tx");
    bound_lock_wait(&mut waiter, TEST_TIMEOUT)
        .await
        .expect("tighten the bound for the test");

    let started = Instant::now();
    let err = tokio::time::timeout(
        TEST_DEADLINE,
        sqlx::query(&format!("SELECT id FROM {table} WHERE id = 1 FOR UPDATE"))
            .fetch_one(&mut *waiter),
    )
    .await
    .expect("the contended row lock never returned — the bound regressed to an unbounded wait")
    .expect_err("a contended row lock must not be granted while the holder is open");
    let waited = started.elapsed();

    assert!(
        is_lock_timeout(&err),
        "expected SQLSTATE 55P03 lock_not_available, got: {err}"
    );
    assert!(
        waited < TEST_TIMEOUT + Duration::from_secs(20),
        "row lock wait took {waited:?}, far beyond the configured {TEST_TIMEOUT:?} bound"
    );

    let _ = waiter.rollback().await;
    let _ = holder.rollback().await;
    drop_probe_table(&pool, &table).await;
}

/// Bounding the wait must not change the success path: an uncontended row lock is still granted,
/// and it is really held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uncontended_row_lock_is_granted_normally() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = unbounded_pool(&url).await;
    let table = make_probe_table(&pool, "uncontended").await;

    let mut tx = weissman_db::begin_tenant_tx(&pool, TENANT)
        .await
        .expect("begin tx");
    let id: i64 = sqlx::query_scalar(&format!("SELECT id FROM {table} WHERE id = 1 FOR UPDATE"))
        .fetch_one(&mut *tx)
        .await
        .expect("uncontended row lock is granted");
    assert_eq!(id, 1);

    // Prove the lock is genuinely held: a second session must not be able to take it.
    let mut probe = weissman_db::begin_tenant_tx(&pool, TENANT)
        .await
        .expect("begin probe tx");
    let contended = sqlx::query(&format!(
        "SELECT id FROM {table} WHERE id = 1 FOR UPDATE NOWAIT"
    ))
    .fetch_one(&mut *probe)
    .await;
    assert!(
        contended.is_err(),
        "the row lock must actually be held after a bounded wait"
    );

    let _ = probe.rollback().await;
    let _ = tx.rollback().await;
    drop_probe_table(&pool, &table).await;
}
