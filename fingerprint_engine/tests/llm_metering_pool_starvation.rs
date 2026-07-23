//! Starvation contract for the LLM token-metering write path.
//!
//! The real bug behind the smoke's recurring "pool timed out while waiting for an open
//! connection": LLM-heavy engines emit many completions concurrently, and the metering
//! reporter (`observability::register_llm_tenant_metering`) fired a RAW, unbounded
//! `tokio::spawn` per completion, each opening a tenant tx
//! (`weissman_db::llm_usage::log_tenant_llm_usage` → `begin_tenant_tx`) that acquires an
//! app-pool connection. A burst of concurrent completions therefore stormed
//! `pool.acquire()` and drained the whole app pool, starving the worker's shared
//! claim/reserve loop — independent of finding count (which is why bounding the
//! per-finding persistence spawns did not fix it).
//!
//! The fix routes every metering insert through the SAME global `spawn_bounded_db_task`
//! semaphore as persistence. This test proves the metering write itself survives a
//! deliberately starved pool: 1000 concurrent `log_tenant_llm_usage` calls, capped by a
//! semaphore of PERMITS(2) < POOL_MAX(3), must complete with ZERO pool timeouts and peak
//! concurrency never exceeding the permits. Remove the semaphore and 1000 calls storm a
//! 3-slot pool and time out en masse (see `findings_persist_pool_starvation`'s negative
//! control for the same rig proving the unbounded path fails).
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5433/weissman' \
//!   cargo test -p fingerprint_engine --test llm_metering_pool_starvation -- --nocapture
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use tokio::sync::Semaphore;

const N: usize = 1000;
const POOL_MAX: u32 = 3; // deliberately starved
const PERMITS: usize = 2; // mirrors WEISSMAN_BG_DB_CONCURRENCY < POOL_MAX

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_llm_metering_survives_starved_pool() {
    let url = match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            eprintln!("SKIP bounded_llm_metering_survives_starved_pool: TEST_DATABASE_URL not set");
            return;
        }
    };

    let pool = PgPoolOptions::new()
        .max_connections(POOL_MAX)
        .acquire_timeout(Duration::from_secs(4))
        .connect(url.trim())
        .await
        .expect("connect starved pool");

    // Seed tenant as superuser (bypasses RLS); the metering insert runs scoped as
    // weissman_app under this tenant via begin_tenant_tx.
    let tenant_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO tenants (slug, name) VALUES ($1, 'llm meter starve')
           ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id"#,
    )
    .bind("__llm_meter_starve_tenant__")
    .fetch_one(&pool)
    .await
    .expect("seed tenant");

    let sem = Arc::new(Semaphore::new(PERMITS));
    let ok = Arc::new(AtomicUsize::new(0));
    let err = Arc::new(AtomicUsize::new(0));
    let inflight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let pool = pool.clone();
        let sem = sem.clone();
        let (ok, err, inflight, peak) = (ok.clone(), err.clone(), inflight.clone(), peak.clone());
        // Same shape as the fixed reporter: a permit gates the pooled-connection work.
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore open");
            let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(cur, Ordering::SeqCst);
            let res = weissman_db::llm_usage::log_tenant_llm_usage(
                &pool,
                tenant_id,
                (i % 100) as u32,
                (i % 50) as u32,
                "starve-model",
                "chat",
            )
            .await;
            inflight.fetch_sub(1, Ordering::SeqCst);
            match res {
                Ok(_) => ok.fetch_add(1, Ordering::SeqCst),
                Err(_) => err.fetch_add(1, Ordering::SeqCst),
            };
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let ok = ok.load(Ordering::SeqCst);
    let err = err.load(Ordering::SeqCst);
    let peak = peak.load(Ordering::SeqCst);
    eprintln!(
        "llm metering starvation: ok={ok} err={err} peak_concurrent={peak} (pool_max={POOL_MAX}, permits={PERMITS})"
    );

    assert_eq!(
        err, 0,
        "expected ZERO pool timeouts for bounded metering through a starved pool; got {err} errors"
    );
    assert!(
        peak <= PERMITS,
        "bound breached: peak concurrency {peak} exceeded permits {PERMITS}"
    );
    assert_eq!(
        ok, N,
        "expected all {N} metering inserts to succeed; got {ok}"
    );

    // Cleanup (best-effort).
    let _ =
        sqlx::query("DELETE FROM tenant_llm_usage WHERE tenant_id = $1 AND model = 'starve-model'")
            .bind(tenant_id)
            .execute(&pool)
            .await;
}
