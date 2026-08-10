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

use sqlx::postgres::PgPoolOptions;
use weissman_db::job_queue::{self, WorkerPoolRole};

/// Two distinct, non-zero tenant ids, well outside any seeded range.
const TENANT_A: i64 = 918_274_001;
const TENANT_B: i64 = 918_274_002;
/// Job kind used only by this test, so the cross-tenant assertions cannot latch onto real jobs.
const PROBE_KIND: &str = "__rls_worker_dequeue_regression__";

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
        sqlx::query(
            "INSERT INTO weissman_async_jobs (tenant_id, kind, payload, status) \
             VALUES ($1, $2, '{}'::jsonb, 'pending')",
        )
        .bind(tenant_id)
        .bind(PROBE_KIND)
        .execute(pool)
        .await
        .expect("seed job");
    }
}

async fn cleanup(pool: &sqlx::PgPool) {
    let _ = sqlx::query("DELETE FROM weissman_async_jobs WHERE kind = $1")
        .bind(PROBE_KIND)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = ANY($1)")
        .bind(vec![TENANT_A, TENANT_B])
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

    cleanup(&pool).await;
    seed_tenant_jobs(&pool, TENANT_A, 2).await;
    seed_tenant_jobs(&pool, TENANT_B, 2).await;

    // Everything below runs as weissman_app (NOBYPASSRLS), the role the worker actually uses.
    // A superuser pool would bypass every policy and mask the bug entirely.
    let worker_pool = PgPoolOptions::new()
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
        .expect("connect worker pool as weissman_app");

    // This is the exact call the worker makes every poll. Before the fix it returned
    // Err(invalid input syntax for type bigint: "").
    let claimed = job_queue::claim_next_with_role(
        &worker_pool,
        "rls-worker-dequeue-regression",
        300,
        WorkerPoolRole::Mixed,
    )
    .await;

    let claimed = match claimed {
        Ok(job) => job,
        Err(e) => {
            cleanup(&pool).await;
            panic!(
                "claim_next_with_role failed under the worker's empty-scope posture: {e}. \
                 This is the four-day production outage: every worker poll errored while \
                 /api/health still reported scanning_active: true. \
                 Check migration 20260811000000_rls_tenant_guc_cast_safety is applied."
            );
        }
    };

    let job = claimed.expect("worker must claim a pending job, not see an empty queue");
    assert_eq!(job.kind, PROBE_KIND, "claimed an unrelated job");
    assert!(
        job.tenant_id == TENANT_A || job.tenant_id == TENANT_B,
        "claimed job must belong to one of the probe tenants, got {}",
        job.tenant_id
    );

    // Claim the rest and prove the worker really crosses the tenant boundary — a policy that
    // silently collapsed to a single tenant would still pass the first assertion.
    let mut seen_tenants = std::collections::HashSet::from([job.tenant_id]);
    for _ in 0..3 {
        match job_queue::claim_next_with_role(
            &worker_pool,
            "rls-worker-dequeue-regression",
            300,
            WorkerPoolRole::Mixed,
        )
        .await
        {
            Ok(Some(j)) if j.kind == PROBE_KIND => {
                seen_tenants.insert(j.tenant_id);
            }
            Ok(_) => break,
            Err(e) => {
                cleanup(&pool).await;
                panic!("subsequent claim failed: {e}");
            }
        }
    }

    cleanup(&pool).await;

    assert!(
        seen_tenants.contains(&TENANT_A) && seen_tenants.contains(&TENANT_B),
        "the worker must dequeue across tenants (that is the whole point of the empty scope); \
         only saw {seen_tenants:?}"
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
