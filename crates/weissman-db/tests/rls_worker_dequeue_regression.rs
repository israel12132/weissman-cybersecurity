//! Regression lock-in for the four-day production outage of 2026-08-06 → 2026-08-10, in which the
//! worker could not claim a single job and `/api/health` reported `scanning_active: true` the
//! whole time.
//!
//! # What broke
//!
//! The worker dequeues across tenants by setting the RLS GUC to the **empty string** inside its
//! transaction ([`weissman_db::job_queue`]'s `begin_worker_tx`, and `swarm.rs::tick`). Every
//! tenant policy in the tree was written as
//!
//! ```sql
//! tenant_id = current_setting('app.current_tenant_id', true)::bigint
//! ```
//!
//! and the three job-bus tables guarded that with an OR branch intended to make the empty string
//! mean "unrestricted":
//!
//! ```sql
//! NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
//! OR tenant_id = current_setting('app.current_tenant_id', true)::bigint
//! ```
//!
//! **The guard does not work.** Postgres does not guarantee short-circuit evaluation of `OR`; on a
//! real table scan the planner evaluates the stable `current_setting(...)::bigint` subexpression
//! eagerly and `''::bigint` raises `invalid input syntax for type bigint: ""` before the `NULLIF`
//! branch can spare it. Every `claim/reserve` call failed, 2111 jobs piled up `pending`, and zero
//! scans ran for four days.
//!
//! Migration `20260811000000_rls_tenant_guc_cast_safety` fixes it by moving the cast inside the
//! `NULLIF`, behind the helper `public.app_current_tenant_id()`, and rewriting every policy to use
//! it.
//!
//! # Why the existing tests did not catch it
//!
//! `rls_tenant_guc_regression.rs` creates its **own scratch table** with its own policy and never
//! exercises `weissman_async_jobs` under the worker's empty-string GUC posture — so it stayed
//! green while the real dequeue path was dead in production. These tests close that gap by
//! driving the **real** `job_queue` API against the **real** table, and by asserting a schema-wide
//! invariant that fails the moment any migration reintroduces the unsafe cast.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test rls_worker_dequeue_regression -- --nocapture
//! ```
//!
//! Same env/skip contract as the sibling DB tests: a hard failure when
//! `WEISSMAN_REQUIRE_DB_TESTS=1` (CI) so a dropped URL cannot masquerade as green, a visible skip
//! locally. `TEST_DATABASE_URL` must be a superuser (or a role granted `weissman_app`) so the
//! tests can `SET LOCAL ROLE weissman_app` and exercise real RLS.

mod common;

use sqlx::postgres::PgPoolOptions;
use weissman_db::job_queue::{self, WorkerPoolRole};

/// Two distinct, non-zero tenant ids, well outside any seeded range.
const TENANT_A: i64 = 918_274_001;
const TENANT_B: i64 = 918_274_002;
/// A second, disjoint pair for the enumeration test. `cargo test` runs these in parallel, so two
/// tests sharing tenant ids would delete each other's fixtures mid-run.
const TENANT_C: i64 = 918_274_003;
const TENANT_D: i64 = 918_274_004;
/// Job kind used only by this test, so the cross-tenant assertions cannot latch onto real jobs.
const PROBE_KIND: &str = "__rls_worker_dequeue_regression__";
/// A distinct kind for the zero-trust gate test. Cleanup is tenant-scoped, but *claiming* is not:
/// two tests running in parallel against the same kind will dequeue each other's fixtures.
const GATE_KIND: &str = "__rls_zero_trust_gate_probe__";

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
                "rls_worker_dequeue_regression requires TEST_DATABASE_URL, but \
                 WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!(
                "SKIP rls_worker_dequeue_regression: TEST_DATABASE_URL not set (no test Postgres)"
            );
            String::new()
        }
    }
}

async fn connect(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect TEST_DATABASE_URL")
}

/// Seed one tenant row and `count` pending jobs for it. Idempotent across reruns.
async fn seed_tenant_jobs(pool: &sqlx::PgPool, tenant_id: i64, count: i32) {
    sqlx::query(
        "INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(format!("rls-worker-probe-{tenant_id}"))
    .bind(format!("RLS worker probe {tenant_id}"))
    .execute(pool)
    .await
    .expect("seed tenant");

    for _ in 0..count {
        // Stamp epoch so these rows sort ahead of leftover pending work from earlier
        // CI steps (API smoke enqueues command_center_engine jobs). claim_next is
        // global FIFO by created_at; a 64-claim drain lost that race in CI.
        sqlx::query(
            "INSERT INTO weissman_async_jobs (tenant_id, kind, payload, status, created_at) \
             VALUES ($1, $2, '{}'::jsonb, 'pending', TIMESTAMPTZ '1970-01-01+00')",
        )
        .bind(tenant_id)
        .bind(PROBE_KIND)
        .execute(pool)
        .await
        .expect("seed job");
    }
}

async fn cleanup(pool: &sqlx::PgPool, tenants: &[i64]) {
    let _ = sqlx::query("DELETE FROM weissman_async_jobs WHERE kind = $1 AND tenant_id = ANY($2)")
        .bind(PROBE_KIND)
        .bind(tenants)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = ANY($1)")
        .bind(tenants)
        .execute(pool)
        .await;
}

/// **Schema invariant.** No RLS policy anywhere may cast the raw GUC to `bigint`.
///
/// This is the assertion that actually generalises: it fails for *any* table, present or future,
/// whose policy reintroduces `current_setting('app.current_tenant_id', true)::bigint` — including
/// the `NULLIF(...) IS NULL OR ...` form, which looks guarded but is not, because the cast is
/// still reachable eagerly. The only accepted form is `public.app_current_tenant_id()`.
#[tokio::test]
async fn no_rls_policy_casts_the_raw_tenant_guc() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;

    let offenders: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT c.relname::text, p.polname::text
        FROM pg_policy p
        JOIN pg_class c ON c.oid = p.polrelid
        WHERE coalesce(pg_get_expr(p.polqual, p.polrelid), '')
                  LIKE '%current_setting(''app.current_tenant_id''::text, true))::bigint%'
           OR coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')
                  LIKE '%current_setting(''app.current_tenant_id''::text, true))::bigint%'
        ORDER BY 1, 2
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("scan pg_policy");

    assert!(
        offenders.is_empty(),
        "these RLS policies cast the raw tenant GUC to bigint, which raises \
         `invalid input syntax for type bigint: \"\"` the moment the worker sets an empty scope \
         (this took production down for four days): {offenders:?}. \
         Use public.app_current_tenant_id() — see migration 20260811000000_rls_tenant_guc_cast_safety."
    );

    // And the helper those policies are supposed to be using must exist and be empty-safe.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('app.current_tenant_id', '', true)")
        .execute(&mut *tx)
        .await
        .expect("set empty scope");
    let empty_scope: Option<i64> = sqlx::query_scalar("SELECT public.app_current_tenant_id()")
        .fetch_one(&mut *tx)
        .await
        .expect("app_current_tenant_id() must not raise on an empty GUC");
    let _ = tx.rollback().await;
    assert_eq!(
        empty_scope, None,
        "app_current_tenant_id() must map an empty GUC to NULL, not raise and not coerce to 0"
    );
}

/// **The production path.** The real `job_queue` dequeue API, against the real table, under the
/// real worker GUC posture — claiming a job that belongs to a *different* tenant than any scope
/// the connection ever set.
#[tokio::test]
async fn worker_dequeues_across_tenants_with_empty_scope() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;
    // Claiming is global — hold the serializer so a concurrent claim test cannot take our jobs.
    let _claims = common::lock_claims(&pool).await;

    cleanup(&pool, &[TENANT_A, TENANT_B]).await;
    seed_tenant_jobs(&pool, TENANT_A, 2).await;
    seed_tenant_jobs(&pool, TENANT_B, 2).await;

    // Everything below runs as weissman_worker (BYPASSRLS, job-bus GRANT only).
    // weissman_app is fail-closed on this table; a superuser pool would mask both contracts.
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE weissman_worker")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("connect worker pool as weissman_worker");

    // This is the exact call the worker makes every poll. Before the fix it returned
    // Err(invalid input syntax for type bigint: "").
    //
    // `claim_next_with_role` claims GLOBALLY: across every tenant AND every kind, in `created_at`
    // FIFO order (see the query in job_queue.rs — there is no priority column, and `Mixed` accepts
    // every non-research kind). A shared CI database therefore hands back whatever pending job is
    // oldest first — e.g. a `command_center_engine` job left pending by the API-smoke step that
    // runs earlier in the same engine-wiring job. The invariant under test is that the empty-scope
    // claim (a) never errors, and (b) crosses the tenant boundary for OUR probe jobs — NOT that our
    // freshly-seeded jobs happen to sort ahead of that pre-existing noise. So we drain the queue
    // like a real worker, account only our probe jobs, and let unrelated claims fall through.
    let mut seen_tenants = std::collections::HashSet::new();
    let mut claimed_probe = false;
    // 4 probe jobs are stamped at epoch so they sort first. Keep a drain bound anyway in
    // case another test also backdated rows; each claim flips a distinct row to `running`.
    for _ in 0..16 {
        match job_queue::claim_next_with_role(
            &worker_pool,
            "rls-worker-dequeue-regression",
            300,
            WorkerPoolRole::Mixed,
        )
        .await
        {
            Ok(Some(job)) if job.kind == PROBE_KIND => {
                claimed_probe = true;
                assert!(
                    job.tenant_id == TENANT_A || job.tenant_id == TENANT_B,
                    "claimed probe job must belong to one of the probe tenants, got {}",
                    job.tenant_id
                );
                seen_tenants.insert(job.tenant_id);
                // Once we've proven the empty scope crosses the boundary, stop draining.
                if seen_tenants.contains(&TENANT_A) && seen_tenants.contains(&TENANT_B) {
                    break;
                }
            }
            // Unrelated job from the shared queue (not ours) — keep draining toward our probes.
            Ok(Some(_)) => continue,
            // Empty queue: nothing (more) left to claim.
            Ok(None) => break,
            Err(e) => {
                cleanup(&pool, &[TENANT_A, TENANT_B]).await;
                panic!(
                    "claim_next_with_role failed under the worker's empty-scope posture: {e}. \
                     This is the four-day production outage: every worker poll errored while \
                     /api/health still reported scanning_active: true. \
                     Check migration 20260811000000_rls_tenant_guc_cast_safety is applied."
                );
            }
        }
    }

    cleanup(&pool, &[TENANT_A, TENANT_B]).await;

    assert!(
        claimed_probe,
        "the worker claimed no probe job under the empty scope — either the seeded jobs were not \
         claimable (RLS hiding them / empty-GUC cast raising swallowed as Ok(None)), or claim_next \
         never reached the epoch-stamped probes"
    );
    assert!(
        seen_tenants.contains(&TENANT_A) && seen_tenants.contains(&TENANT_B),
        "the worker must dequeue across tenants (that is the whole point of the empty scope); \
         only saw {seen_tenants:?}"
    );
}

/// **Cross-tenant enumeration.** `active_tenant_ids` must see every active tenant from an
/// RLS-subject connection, where the naive `SELECT id FROM tenants WHERE active = true` sees none.
#[tokio::test]
async fn active_tenant_ids_enumerates_across_tenants_on_an_rls_pool() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;
    cleanup(&pool, &[TENANT_C, TENANT_D]).await;
    seed_tenant_jobs(&pool, TENANT_C, 0).await;
    seed_tenant_jobs(&pool, TENANT_D, 0).await;

    let app_pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE weissman_app").execute(conn).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("connect app pool as weissman_app");

    // The shape that looks right and silently returns nothing.
    let naive: Vec<i64> = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true")
        .fetch_all(&app_pool)
        .await
        .expect("naive enumeration query");

    let helper = weissman_db::active_tenant_ids(&app_pool)
        .await
        .expect("active_tenant_ids");

    cleanup(&pool, &[TENANT_C, TENANT_D]).await;

    assert!(
        helper.contains(&TENANT_C) && helper.contains(&TENANT_D),
        "active_tenant_ids must return every active tenant from an RLS-subject pool; got {helper:?}"
    );
    assert!(
        !naive.contains(&TENANT_C) || !naive.contains(&TENANT_D),
        "reading `tenants` directly off an RLS pool returned every tenant ({naive:?}) — either RLS \
         is not enforced on this database or the pool is BYPASSRLS, and this test is not proving \
         what it claims"
    );
}

/// **The zero-trust claim gate.** `reserve_next` (the job-bus path) must refuse a job that has no
/// signed envelope, and must still serve one that has.
///
/// `enqueue_held` only holds a row for `hold_secs` — a timer, not a gate. When the envelope attach
/// failed, the row became claimable anyway 30 seconds later and the worker dead-lettered it as
/// "missing signed envelope". That converted a recoverable enqueue-side failure into destroyed
/// customer work: 3,319 tenant scans in this deployment. The predicate this test pins makes an
/// envelope-less row structurally unclaimable, so the passage of time can no longer destroy it.
///
/// This also exercises the raw `?` jsonb key-exists operator through sqlx, which is worth pinning:
/// `?` is a placeholder character in several drivers, and a mis-bound query here would silently
/// match nothing and stall the whole bus queue.
#[tokio::test]
async fn reserve_next_refuses_a_job_with_no_signed_envelope() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;
    let _claims = common::lock_claims(&pool).await;
    const TENANT_E: i64 = 918_274_005;
    let _ = sqlx::query("DELETE FROM weissman_async_jobs WHERE kind = $1")
        .bind(GATE_KIND)
        .execute(&pool)
        .await;
    cleanup(&pool, &[TENANT_E]).await;
    seed_tenant_jobs(&pool, TENANT_E, 0).await;

    // One envelope-less job (what a failed attach leaves behind) and one properly signed.
    for payload in [
        serde_json::json!({ "trigger": "test" }),
        serde_json::json!({ "trigger": "test", "_weissman_job_bus": { "envelope": { "v": 1 } } }),
    ] {
        sqlx::query(
            "INSERT INTO weissman_async_jobs (tenant_id, kind, payload, status) \
             VALUES ($1, $2, $3, 'pending')",
        )
        .bind(TENANT_E)
        .bind(GATE_KIND)
        .bind(sqlx::types::Json(payload))
        .execute(&pool)
        .await
        .expect("seed job");
    }

    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE weissman_worker")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("connect worker pool as weissman_worker");

    let mut claimed = Vec::new();
    for _ in 0..4 {
        match job_queue::reserve_next_with_role(
            &worker_pool,
            "zero-trust-gate-test",
            300,
            WorkerPoolRole::Mixed,
        )
        .await
        {
            Ok(Some(j)) if j.kind == GATE_KIND => claimed.push(j),
            Ok(_) => break,
            Err(e) => {
                cleanup(&pool, &[TENANT_E]).await;
                panic!("reserve_next_with_role failed: {e}");
            }
        }
    }

    let _ = sqlx::query("DELETE FROM weissman_async_jobs WHERE kind = $1")
        .bind(GATE_KIND)
        .execute(&pool)
        .await;
    cleanup(&pool, &[TENANT_E]).await;

    assert_eq!(
        claimed.len(),
        1,
        "reserve_next must serve exactly the enveloped job and refuse the envelope-less one; \
         claimed {} (0 = the `?` jsonb operator is not reaching Postgres and the bus queue is \
         stalled; 2 = the zero-trust gate is missing and a failed attach will be dead-lettered)",
        claimed.len()
    );
    assert!(
        claimed[0].payload.get("_weissman_job_bus").is_some(),
        "the claimed job must be the one carrying the signed envelope"
    );
}

/// **Fail-closed job-bus.** `weissman_app` with an empty/unset GUC must see zero rows,
/// even when jobs exist. Cross-tenant visibility is `weissman_worker` only.
#[tokio::test]
async fn weissman_app_empty_guc_cannot_read_job_bus() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;
    const TENANT_F: i64 = 918_274_006;
    cleanup(&pool, &[TENANT_F]).await;
    seed_tenant_jobs(&pool, TENANT_F, 3).await;

    let app_pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE weissman_app").execute(conn).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("connect as weissman_app");

    let mut tx = app_pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('app.current_tenant_id', '', true)")
        .execute(&mut *tx)
        .await
        .expect("empty GUC");
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM weissman_async_jobs WHERE tenant_id = $1 AND kind = $2",
    )
    .bind(TENANT_F)
    .bind(PROBE_KIND)
    .fetch_one(&mut *tx)
    .await
    .expect("count under empty GUC");
    let _ = tx.rollback().await;

    cleanup(&pool, &[TENANT_F]).await;
    assert_eq!(
        n, 0,
        "weissman_app with empty GUC must not read job-bus rows (queue hijack)"
    );
}

/// **The drift that inverts fail-closed into fail-open.**
///
/// `20260809120000_reset_tenant_guc_default` runs `ALTER DATABASE ... RESET`, which clears only
/// the row in `pg_db_role_setting` whose `setrole = 0`. Production was found carrying
/// `ALTER ROLE weissman_app IN DATABASE weissman SET app.current_tenant_id = '1'` — a separate row
/// that takes precedence at login. Every unscoped connection therefore started already scoped to
/// tenant 1, so a handler that forgot `begin_tenant_tx` read tenant 1's rows instead of none.
///
/// `20260811000100_reset_role_tenant_guc_defaults` clears those rows; this test keeps them gone.
#[tokio::test]
async fn no_role_level_tenant_guc_default_survives() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;

    let defaults: Vec<(Option<String>, Vec<String>)> = sqlx::query_as(
        r#"
        SELECT rol.rolname::text, s.setconfig::text[]
        FROM pg_db_role_setting s
        LEFT JOIN pg_roles rol   ON rol.oid = s.setrole
        LEFT JOIN pg_database d  ON d.oid   = s.setdatabase
        WHERE (s.setdatabase = 0 OR d.datname = current_database())
          AND EXISTS (
              SELECT 1 FROM unnest(s.setconfig) AS cfg
              WHERE cfg LIKE 'app.current_tenant_id=%'
          )
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("scan pg_db_role_setting");

    assert!(
        defaults.is_empty(),
        "a default app.current_tenant_id is set at the database or role level: {defaults:?}. \
         This makes tenant tables fail OPEN into that tenant instead of returning no rows, and \
         hides every missing-scope bug. Keep the RESET from \
         20260811000100_reset_role_tenant_guc_defaults."
    );
}
