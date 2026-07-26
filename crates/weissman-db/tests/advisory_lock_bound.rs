//! Contract: an advisory lock taken through `weissman_db::advisory_lock` **always terminates**.
//!
//! This is the regression test for the CI hang in `docs/TECH_DEBT_flaky_db_test_hang.md`. The
//! defect was not "a lock was contended" — contention is normal and correct. The defect was that
//! a contended `pg_advisory_xact_lock` on a test pool (no `lock_timeout`, no `statement_timeout`)
//! waits **forever**: Postgres' deadlock detector only breaks true cycles, so a plain
//! "A holds, B waits" chain is never broken and the test binary wedged until the 45-minute
//! GitHub step timeout SIGKILLed it with no output.
//!
//! Each test below deliberately builds its pool from a bare `PgPoolOptions::new()` — i.e. the
//! exact unbounded pool shape every test in this workspace uses — so it proves the bound comes
//! from the helper itself and not from pool configuration a future refactor could drop.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test advisory_lock_bound -- --nocapture
//! ```

use sqlx::postgres::PgPoolOptions;
use std::time::{Duration, Instant};
use weissman_db::advisory_lock::{
    advisory_xact_lock, advisory_xact_lock_text_or_skip, is_lock_timeout, LOCK_TIMEOUT_ENV,
};

/// Distinct per test so a shared CI database cannot make two tests contend with each other.
const KEY_BLOCKS: i64 = -8_070_010_001;
const KEY_SKIPS: &str = "__weissman_advisory_lock_bound_skip__";

/// Short enough that the whole suite stays fast, long enough not to trip on a loaded runner.
const TEST_TIMEOUT_MS: u64 = 1_500;

/// Shrink the helper's bound so a contended lock resolves in ~1.5 s instead of the 15 s default.
///
/// Idempotent on purpose: `cargo test` runs a binary's tests on multiple threads, and
/// `set_var` is process-global. Two tests writing the *same* value cannot race to a different
/// one, and nothing is ever removed — a `remove_var` here would let one test blank the bound out
/// from under a sibling still running.
fn force_short_lock_timeout() {
    std::env::set_var(LOCK_TIMEOUT_ENV, TEST_TIMEOUT_MS.to_string());
}

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
                "advisory_lock_bound requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP advisory_lock_bound: TEST_DATABASE_URL not set (no test Postgres)");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contended_lock_times_out_instead_of_hanging_forever() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    force_short_lock_timeout();
    let pool = unbounded_pool(&url).await;

    // Holder: take the lock and keep the transaction open for the whole test.
    let mut holder = pool.begin().await.expect("begin holder tx");
    advisory_xact_lock(&mut holder, KEY_BLOCKS)
        .await
        .expect("holder takes the lock uncontended");

    // Waiter: the identical call on a second connection must FAIL, not block.
    let mut waiter = pool.begin().await.expect("begin waiter tx");
    let started = Instant::now();
    let err = advisory_xact_lock(&mut waiter, KEY_BLOCKS)
        .await
        .expect_err("a contended advisory lock must not be granted");
    let waited = started.elapsed();

    assert!(
        is_lock_timeout(&err),
        "expected SQLSTATE 55P03 lock_not_available, got: {err}"
    );
    // The point of the test: it *returned*. Assert it returned near the configured bound rather
    // than after some unrelated, much larger timeout — with generous slack for a loaded runner.
    assert!(
        waited < Duration::from_millis(TEST_TIMEOUT_MS) + Duration::from_secs(20),
        "lock wait took {waited:?}, far beyond the configured {TEST_TIMEOUT_MS}ms bound"
    );

    let _ = waiter.rollback().await;
    let _ = holder.rollback().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skip_variant_leaves_the_transaction_usable_after_a_timeout() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    force_short_lock_timeout();
    let pool = unbounded_pool(&url).await;

    let mut holder = pool.begin().await.expect("begin holder tx");
    advisory_xact_lock(&mut holder, i64::from_le_bytes(*b"skipkey0"))
        .await
        .ok();
    // Hold the *text* key the waiter will contend on.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(KEY_SKIPS)
        .execute(&mut *holder)
        .await
        .expect("holder takes the text lock");

    let mut waiter = pool.begin().await.expect("begin waiter tx");
    // Capture rather than hardcode: the CI database carries `ALTER DATABASE … lock_timeout='30s'`
    // (the backstop in ci.yml), so the inherited value is NOT "0" there. The contract is
    // "restored to whatever the caller had", not "restored to zero".
    let before: String = sqlx::query_scalar("SHOW lock_timeout")
        .fetch_one(&mut *waiter)
        .await
        .expect("read inherited lock_timeout");

    let granted = advisory_xact_lock_text_or_skip(&mut waiter, KEY_SKIPS)
        .await
        .expect("the skip variant must not surface the timeout as an error");
    assert!(!granted, "contended lock must report not-granted");

    // The whole reason for the savepoint: without it this statement fails with
    // `25P02 current_transaction_is_aborted` and the caller's documented fail-open fallback —
    // the racy count check in auto_heal_job — is dead code.
    let alive: i64 = sqlx::query_scalar("SELECT 1::bigint")
        .fetch_one(&mut *waiter)
        .await
        .expect("transaction must remain usable after a skipped lock");
    assert_eq!(alive, 1);

    // And `SET LOCAL lock_timeout` must have been rolled back with the savepoint, so the caller's
    // transaction is left exactly as it was found.
    let restored: String = sqlx::query_scalar("SHOW lock_timeout")
        .fetch_one(&mut *waiter)
        .await
        .expect("read lock_timeout");
    assert_eq!(
        restored, before,
        "the skip variant must not leak lock_timeout into the caller's transaction"
    );

    let _ = waiter.rollback().await;
    let _ = holder.rollback().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uncontended_lock_is_granted_normally() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = unbounded_pool(&url).await;
    let mut tx = pool.begin().await.expect("begin tx");
    advisory_xact_lock(&mut tx, KEY_BLOCKS - 1)
        .await
        .expect("uncontended lock is granted");
    // Bounding the wait must not change the success path: the lock is really held, so a second
    // session cannot take it.
    let held: bool = sqlx::query_scalar("SELECT NOT pg_try_advisory_xact_lock($1)")
        .bind(KEY_BLOCKS - 1)
        .fetch_one(&pool)
        .await
        .expect("probe from another session");
    assert!(held, "the lock must actually be held after a bounded wait");
    let _ = tx.rollback().await;
}
