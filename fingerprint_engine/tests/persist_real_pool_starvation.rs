//! END-TO-END starvation contract for the REAL `persist_engine_findings` path.
//!
//! Drives the actual persistence function with **1000 findings** through a
//! deliberately starved **max_connections=3** pool. Before the fix this path:
//!   * held one batch transaction open across the whole loop while EACH iteration
//!     opened a SECOND pooled connection (`resolve_internet_exposed`) and, for CVE
//!     findings, performed a FIRST.org network fetch — a connection pinned across
//!     I/O; and
//!   * fired one/two UNBOUNDED detached tasks per finding.
//! Under a 3-slot pool that self-deadlocks ("pool timed out while waiting for an
//! open connection"). After the fix — EPSS pre-warmed before the tx, internet-
//! exposed pre-resolved before the tx, and background dispatch bounded by a global
//! semaphore — the whole batch must queue gracefully through 3 connections.
//!
//! # Running
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5433/weissman' \
//!   cargo test -p fingerprint_engine --test persist_real_pool_starvation -- --nocapture
//! ```

use fingerprint_engine::findings_persist::persist_engine_findings;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

const N: usize = 1000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_persist_survives_starved_pool() {
    let url = match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            eprintln!("SKIP real_persist_survives_starved_pool: TEST_DATABASE_URL not set");
            return;
        }
    };

    // Bound the per-finding background dispatch tasks tightly so the whole real
    // persist path fits a 3-connection pool: batch tx (1) + one bounded bg task (1).
    std::env::set_var("WEISSMAN_BG_DB_CONCURRENCY", "1");

    let pool = PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(Duration::from_secs(5))
        .connect(url.trim())
        .await
        .expect("connect starved pool");

    // Seed tenant + client as superuser (bypasses RLS); persist runs scoped as
    // weissman_app under this tenant.
    let slug = "__persist_starve_tenant__";
    let tenant_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO tenants (slug, name) VALUES ($1, 'persist starve')
           ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id"#,
    )
    .bind(slug)
    .fetch_one(&pool)
    .await
    .expect("seed tenant");

    // Fresh client each run so dedup/counts are deterministic.
    sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND name = $2")
        .bind(tenant_id)
        .bind("persist-starve-client")
        .execute(&pool)
        .await
        .ok();
    let client_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO clients (tenant_id, name) VALUES ($1, $2) RETURNING id"#,
    )
    .bind(tenant_id)
    .bind("persist-starve-client")
    .fetch_one(&pool)
    .await
    .expect("seed client");

    // 1000 distinct, gate-passing findings (info severity + explicit proof).
    let findings: Vec<serde_json::Value> = (0..N)
        .map(|i| {
            json!({
                "title": format!("starve finding {i}"),
                "severity": "info",
                "target_url": format!("https://example.com/p{i}"),
                "description": "starvation contract finding",
                "evidence": { "proof": format!("proof-{i}") },
            })
        })
        .collect();

    // THE CONTRACT: must return Ok (no "pool timed out") through a 3-slot pool.
    let started = std::time::Instant::now();
    let result =
        persist_engine_findings(&pool, tenant_id, Some(client_id), "starve_engine", "https://example.com", &findings)
            .await;
    let elapsed = started.elapsed();

    let inserted = result.unwrap_or_else(|e| {
        panic!("persist_engine_findings failed under starved pool (this is the pool-storm regression): {e}")
    });
    eprintln!("real persist starvation: inserted={inserted}/{N} in {elapsed:?} (pool_max=3, bg=1)");

    assert!(
        inserted > 0,
        "expected persisted rows; got 0 (findings did not gate through?)"
    );

    // Cleanup (best-effort).
    let _ = sqlx::query("DELETE FROM clients WHERE id = $1")
        .bind(client_id)
        .execute(&pool)
        .await;
}
