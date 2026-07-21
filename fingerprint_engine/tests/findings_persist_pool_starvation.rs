//! Deterministic DB connection-pool STARVATION contract for the background-task
//! limiter that guards `persist_engine_findings`.
//!
//! Regression target: `persist_engine_findings` used to fire one/two UNBOUNDED
//! detached `tokio::spawn` tasks per finding, each acquiring pooled connections
//! across webhook/embedding I/O. A finding-heavy scan therefore spawned thousands
//! of concurrent connection-hungry tasks that blew past the pool and stayed alive
//! (detached) long enough to starve the worker's claim loop and the job's own
//! completion write — "pool timed out while waiting for an open connection". The
//! fix routes those spawns through [`spawn_bounded_db_task`], a global semaphore.
//!
//! This test proves the bound HOLDS under deliberate starvation: a pool sized to
//! **3** connections is fed **1000** tasks that each hold a connection across a
//! (server-side) I/O wait. With the limiter the tasks queue gracefully — zero pool
//! timeouts — and the observed peak concurrency never exceeds the permit count. If
//! the semaphore is ever removed, `peak_concurrent` jumps toward 1000 and the
//! `peak <= PERMITS` assertion fails, catching the regression.
//!
//! # Running
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5433/weissman' \
//!   cargo test -p fingerprint_engine --test findings_persist_pool_starvation -- --nocapture
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fingerprint_engine::findings_persist::spawn_bounded_db_task;
use sqlx::postgres::PgPoolOptions;

const TASKS: usize = 1000;
const POOL_MAX: u32 = 3; // deliberately starved
const PERMITS: usize = 2; // WEISSMAN_BG_DB_CONCURRENCY for this test (< POOL_MAX)

fn require_test_database_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            let require = std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
                .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false);
            assert!(
                !require,
                "pool starvation test requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!(
                "SKIP findings_persist_pool_starvation: TEST_DATABASE_URL not set (no test Postgres)"
            );
            String::new()
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_background_tasks_survive_starved_pool() {
    let url = require_test_database_url();
    if url.is_empty() {
        return;
    }

    // Pin the limiter BEFORE the first spawn so the semaphore's OnceLock initialises
    // to our starvation-test permit count.
    std::env::set_var("WEISSMAN_BG_DB_CONCURRENCY", PERMITS.to_string());

    // Deliberately starved pool: only 3 connections, short acquire timeout so a
    // genuine pool exhaustion surfaces fast instead of hanging the test.
    let pool = PgPoolOptions::new()
        .max_connections(POOL_MAX)
        .acquire_timeout(Duration::from_secs(4))
        .connect(url.trim())
        .await
        .expect("connect starved pool");

    let ok = Arc::new(AtomicUsize::new(0));
    let err = Arc::new(AtomicUsize::new(0));
    let inflight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    for _ in 0..TASKS {
        let pool = pool.clone();
        let ok = ok.clone();
        let err = err.clone();
        let inflight = inflight.clone();
        let peak = peak.clone();
        // Route through the SAME bounded spawner the persist path now uses.
        spawn_bounded_db_task(async move {
            // Count only tasks that are PAST the semaphore gate — this is the true
            // concurrency the pool sees. With the limiter it can never exceed PERMITS.
            let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);

            // Hold a pooled connection across a server-side I/O wait (models the
            // webhook/embedding hold that used to storm the pool).
            let res = sqlx::query("SELECT pg_sleep(0.02)").execute(&pool).await;

            match res {
                Ok(_) => ok.fetch_add(1, Ordering::SeqCst),
                Err(e) => {
                    eprintln!("pool op failed: {e}");
                    err.fetch_add(1, Ordering::SeqCst)
                }
            };
            inflight.fetch_sub(1, Ordering::SeqCst);
        });
    }

    // Wait for all tasks to drain (bounded wall-clock so a real hang fails loudly).
    let started = Instant::now();
    let deadline = Duration::from_secs(120);
    loop {
        let done = ok.load(Ordering::SeqCst) + err.load(Ordering::SeqCst);
        if done >= TASKS {
            break;
        }
        assert!(
            started.elapsed() < deadline,
            "timed out: only {done}/{TASKS} background tasks completed in {:?} (inflight={}, peak={})",
            started.elapsed(),
            inflight.load(Ordering::SeqCst),
            peak.load(Ordering::SeqCst),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let ok = ok.load(Ordering::SeqCst);
    let err = err.load(Ordering::SeqCst);
    let peak = peak.load(Ordering::SeqCst);
    eprintln!("starvation result: ok={ok} err={err} peak_concurrent={peak} (pool_max={POOL_MAX}, permits={PERMITS})");

    // 1) Not a single pool timeout: 1000 tasks queued gracefully through 3 connections.
    assert_eq!(
        err, 0,
        "background tasks hit {err} pool errors under starvation — the limiter is not bounding connection demand"
    );
    // 2) All work actually ran.
    assert_eq!(ok, TASKS, "expected all {TASKS} tasks to succeed");
    // 3) The bound HELD: concurrency past the gate never exceeded the permit count.
    //    If the semaphore were removed this would approach TASKS and fail.
    assert!(
        peak <= PERMITS,
        "peak concurrency {peak} exceeded permit bound {PERMITS} — fan-out is not bounded"
    );
}
