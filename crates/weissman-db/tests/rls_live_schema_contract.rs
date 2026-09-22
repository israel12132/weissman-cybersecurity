//! Live, per-table RLS + client-scope contract — the enforcement backbone of the
//! platform's headline "every tenant table is isolated" / "every customer is walled
//! off inside a tenant" guarantees.
//!
//! # Why this exists
//!
//! The pre-existing guard `fingerprint_engine/tests/rls_policy_contract.rs` is a
//! *static text scan* over migration `.sql` files. It proves a `CREATE TABLE` is
//! accompanied by the words `FORCE ROW LEVEL SECURITY`, but it can NOT see:
//!   * whether RLS is actually ENABLED (`relrowsecurity`) — `FORCE` without
//!     `ENABLE` leaves RLS unenforced in Postgres;
//!   * whether a policy's predicate actually scopes by tenant/customer, or is a
//!     `USING (true)` no-op / references the wrong column;
//!   * tables/policies created or altered by dynamic `DO $$ … $$` DDL.
//!
//! This test closes that gap by introspecting the **live, fully-migrated schema**
//! (`pg_class`, `pg_policy`, `information_schema.columns`) and asserting, per table:
//!   1. every base table with a `tenant_id` column has RLS ENABLED **and** FORCED
//!      and at least one policy whose predicate references the tenant GUC
//!      (`app_current_tenant_id()` / `app.current_tenant_id`), and none of its
//!      policies is a bare `USING (true)`;
//!   2. every base table with a `client_id` column (bar documented globals) has a
//!      policy that references the customer-visibility predicate
//!      (`weissman_client_row_visible*` / `app_current_client_id`) — so a portal
//!      customer cannot read a sibling customer's rows inside the same tenant;
//!   3. behaviourally, a `weissman_app` session scoped to customer A cannot see
//!      customer B's rows and an unscoped (staff) session sees both.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test rls_live_schema_contract -- --nocapture
//! ```
//!
//! `TEST_DATABASE_URL` must be a superuser (or a role granted `weissman_app`) so
//! the behavioural test can `SET LOCAL ROLE weissman_app` and exercise real RLS.
//! The database must already have Weissman migrations applied (the `run_migrate`
//! example). Same env/skip contract as the sibling `rls_cross_tenant` /
//! `rls_tenant_guc_regression` tests: a hard failure in CI
//! (`WEISSMAN_REQUIRE_DB_TESTS=1`) so a dropped URL can't masquerade as green, a
//! visible skip locally.

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

/// Base tables that carry a `tenant_id` column but are intentionally NOT tenant-RLS
/// protected. Customer data must NEVER be added here. Empty today — every
/// `tenant_id` table forces RLS and scopes by the tenant GUC.
const TENANT_RLS_ALLOWLIST: &[&str] = &[];

/// Base tables that carry a `client_id` column but are intentionally NOT
/// customer-scoped. Only genuinely global/platform tables belong here.
const CLIENT_SCOPE_ALLOWLIST: &[&str] = &[
    // Global corrupt-telemetry quarantine: no tenant_id, no RLS at all — rows have
    // no customer identity (see 20260827... cem_dago telemetry quarantine and the
    // RLS_FORCE_ALLOWLIST entry cem_dago_telemetry_quarantine_global).
    "cem_dago_telemetry_quarantine_global",
];

const PROBE_TABLE: &str = "weissman_client_scope_contract_probe";
const PROBE_MARKER: &str = "__client_scope_contract_row__";
const TENANT_ID: i64 = 771_001_501;
const CLIENT_A: i64 = 771_001_601;
const CLIENT_B: i64 = 771_001_602;

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
                "rls_live_schema_contract requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!(
                "SKIP rls_live_schema_contract: TEST_DATABASE_URL not set (no test Postgres)"
            );
            String::new()
        }
    }
}

async fn connect(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect TEST_DATABASE_URL")
}

/// Contract 1: every base table with a `tenant_id` column ENABLES + FORCES RLS and
/// carries at least one tenant-GUC-scoped policy, and none is a bare `USING (true)`.
#[tokio::test]
async fn every_tenant_id_table_enables_forces_rls_and_scopes_by_tenant_guc() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;

    // One row per base table that HAS a tenant_id column, with the three facts we
    // enforce. `has_true` = at least one policy whose USING predicate is literally
    // `true` (a no-op that defeats isolation).
    let rows = sqlx::query(
        r#"
        WITH t AS (
            SELECT c.oid, n.nspname AS schema_name, c.relname AS table_name,
                   c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r'
              -- Ignore transient unlogged *_probe fixtures that sibling live tests
              -- (rls_tenant_guc_regression, this file's behavioural test) create and
              -- drop concurrently on the same database — mid-build they would look like
              -- a policy-less offender. Real app tables are permanent; the one unlogged
              -- real table, fuzz_candidate_staging, ends in _staging and stays covered.
              AND NOT (c.relpersistence = 'u' AND right(c.relname, 6) = '_probe')
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND EXISTS (
                  SELECT 1 FROM information_schema.columns col
                  WHERE col.table_schema = n.nspname
                    AND col.table_name = c.relname
                    AND col.column_name = 'tenant_id')
        ), pol AS (
            SELECT polrelid,
                   bool_or(pg_get_expr(polqual, polrelid) ILIKE '%app_current_tenant_id%'
                        OR pg_get_expr(polqual, polrelid) ILIKE '%app.current_tenant_id%') AS has_guc,
                   bool_or(btrim(coalesce(pg_get_expr(polqual, polrelid), '')) = 'true') AS has_true
            FROM pg_policy GROUP BY polrelid
        )
        SELECT t.schema_name, t.table_name, t.enabled, t.forced,
               coalesce(p.has_guc, false) AS has_guc,
               coalesce(p.has_true, false) AS has_true
        FROM t LEFT JOIN pol p ON p.polrelid = t.oid
        ORDER BY 1, 2
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("introspect tenant_id tables");

    assert!(
        !rows.is_empty(),
        "no tenant_id tables found — schema not migrated? refusing to pass vacuously"
    );

    let mut offenders: Vec<String> = Vec::new();
    for row in &rows {
        let table: String = row.get("table_name");
        if TENANT_RLS_ALLOWLIST.contains(&table.as_str()) {
            continue;
        }
        let schema: String = row.get("schema_name");
        let enabled: bool = row.get("enabled");
        let forced: bool = row.get("forced");
        let has_guc: bool = row.get("has_guc");
        let has_true: bool = row.get("has_true");
        if !enabled || !forced || !has_guc || has_true {
            offenders.push(format!(
                "{schema}.{table} (enabled={enabled} forced={forced} tenant_guc_policy={has_guc} using_true={has_true})"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "{} of {} tenant_id tables fail the live RLS contract (must ENABLE+FORCE RLS \
         with a tenant-GUC policy and no USING(true)); add FORCE RLS + a \
         `tenant_id = app_current_tenant_id()` policy, or justify a TENANT_RLS_ALLOWLIST \
         entry:\n  {}",
        offenders.len(),
        rows.len(),
        offenders.join("\n  ")
    );
}

/// Contract 2: every base table with a `client_id` column (bar documented globals)
/// carries the customer-visibility predicate, so a portal customer cannot read a
/// sibling customer's rows inside the same tenant.
#[tokio::test]
async fn every_client_id_table_scopes_by_client_visibility() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;

    let rows = sqlx::query(
        r#"
        WITH t AS (
            SELECT c.oid, n.nspname AS schema_name, c.relname AS table_name
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r'
              -- Ignore transient unlogged *_probe fixtures created concurrently by
              -- sibling live tests (see the tenant query above for the rationale).
              AND NOT (c.relpersistence = 'u' AND right(c.relname, 6) = '_probe')
              AND n.nspname = 'public'
              AND c.relname <> 'tenant_idps'   -- client_id here is an OAuth client id, not a customer
              AND EXISTS (
                  SELECT 1 FROM information_schema.columns col
                  WHERE col.table_schema = n.nspname
                    AND col.table_name = c.relname
                    AND col.column_name = 'client_id')
        ), pol AS (
            SELECT polrelid,
                   bool_or(pg_get_expr(polqual, polrelid) ILIKE '%weissman_client_row_visible%'
                        OR pg_get_expr(polqual, polrelid) ILIKE '%app_current_client_id%'
                        OR pg_get_expr(polwithcheck, polrelid) ILIKE '%weissman_client_row_visible%'
                        OR pg_get_expr(polwithcheck, polrelid) ILIKE '%app_current_client_id%') AS has_vis
            FROM pg_policy GROUP BY polrelid
        )
        SELECT t.schema_name, t.table_name, coalesce(p.has_vis, false) AS has_vis
        FROM t LEFT JOIN pol p ON p.polrelid = t.oid
        ORDER BY 1, 2
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("introspect client_id tables");

    assert!(
        !rows.is_empty(),
        "no client_id tables found — schema not migrated? refusing to pass vacuously"
    );

    let mut offenders: Vec<String> = Vec::new();
    for row in &rows {
        let table: String = row.get("table_name");
        if CLIENT_SCOPE_ALLOWLIST.contains(&table.as_str()) {
            continue;
        }
        let has_vis: bool = row.get("has_vis");
        if !has_vis {
            let schema: String = row.get("schema_name");
            offenders.push(format!("{schema}.{table}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "{} of {} client_id tables have no customer-visibility predicate — a portal-scoped \
         customer could read a SIBLING customer's rows inside the same tenant. AND \
         `weissman_client_row_visible(client_id)` onto the table's policy (see \
         20260920120000_client_scope_backfill_new_tables.sql), or justify a \
         CLIENT_SCOPE_ALLOWLIST entry:\n  {}",
        offenders.len(),
        rows.len(),
        offenders.join("\n  ")
    );
}

/// Contract 3: the customer-visibility predicate actually isolates customers.
/// A `weissman_app` session scoped to customer A must not see customer B's row;
/// an unscoped (staff/owner) session sees both. Uses a self-contained probe table
/// carrying the canonical `tenant_id = app_current_tenant_id() AND
/// weissman_client_row_visible(client_id)` policy, so it depends on no app schema.
#[tokio::test]
async fn portal_client_scope_isolates_customers_behaviorally() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;
    let mut conn = pool.acquire().await.expect("acquire dedicated connection");

    // Build a probe table owned by the connecting superuser. FORCE binds RLS even
    // for the owner once SET ROLE drops the superuser bypass.
    sqlx::query(&format!("DROP TABLE IF EXISTS {PROBE_TABLE}"))
        .execute(&mut *conn)
        .await
        .expect("drop stale probe table");
    // Build the probe atomically. The two introspection tests in this binary run
    // concurrently against the same database; without a transaction they could observe
    // the probe mid-build (table present, policy not yet created) and false-flag it. Once
    // committed the probe is fully tenant+client compliant, so a concurrent introspection
    // sees either nothing or a compliant table — never an offender.
    sqlx::query("BEGIN")
        .execute(&mut *conn)
        .await
        .expect("begin probe DDL");
    sqlx::query(&format!(
        "CREATE UNLOGGED TABLE {PROBE_TABLE} \
         (tenant_id bigint NOT NULL, client_id bigint NOT NULL, marker text NOT NULL)"
    ))
    .execute(&mut *conn)
    .await
    .expect("create probe table");
    sqlx::query(&format!(
        "ALTER TABLE {PROBE_TABLE} ENABLE ROW LEVEL SECURITY"
    ))
    .execute(&mut *conn)
    .await
    .expect("enable RLS");
    sqlx::query(&format!(
        "ALTER TABLE {PROBE_TABLE} FORCE ROW LEVEL SECURITY"
    ))
    .execute(&mut *conn)
    .await
    .expect("force RLS");
    sqlx::query(&format!(
        "CREATE POLICY {PROBE_TABLE}_scope ON {PROBE_TABLE} FOR ALL \
         USING (tenant_id = public.app_current_tenant_id() \
                AND public.weissman_client_row_visible(client_id)) \
         WITH CHECK (tenant_id = public.app_current_tenant_id() \
                AND public.weissman_client_row_visible(client_id))"
    ))
    .execute(&mut *conn)
    .await
    .expect("create tenant+client policy");
    sqlx::query(&format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON {PROBE_TABLE} TO weissman_app"
    ))
    .execute(&mut *conn)
    .await
    .expect("grant to weissman_app");
    sqlx::query("COMMIT")
        .execute(&mut *conn)
        .await
        .expect("commit probe DDL");

    // Seed one row per customer as the (superuser) connecting role — RLS bypassed,
    // so both rows definitely exist regardless of any GUC.
    sqlx::query(&format!(
        "INSERT INTO {PROBE_TABLE} (tenant_id, client_id, marker) VALUES ($1, $2, $3), ($1, $4, $3)"
    ))
    .bind(TENANT_ID)
    .bind(CLIENT_A)
    .bind(PROBE_MARKER)
    .bind(CLIENT_B)
    .execute(&mut *conn)
    .await
    .expect("seed customer A + B rows");

    // Helper: run a scoped count on this pinned connection inside one transaction.
    async fn scoped_count(
        conn: &mut sqlx::PgConnection,
        tenant: i64,
        client: Option<i64>,
        target_client: i64,
    ) -> i64 {
        sqlx::query("BEGIN")
            .execute(&mut *conn)
            .await
            .expect("begin");
        sqlx::query("SET LOCAL ROLE weissman_app")
            .execute(&mut *conn)
            .await
            .expect(
                "SET LOCAL ROLE weissman_app (GRANT weissman_app TO the test role if this fails)",
            );
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *conn)
            .await
            .expect("scope tenant GUC");
        // Empty string => unset (staff/owner): app_current_client_id() returns NULL.
        sqlx::query("SELECT set_config('app.current_client_id', $1, true)")
            .bind(client.map(|c| c.to_string()).unwrap_or_default())
            .execute(&mut *conn)
            .await
            .expect("scope client GUC");
        let n: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*)::bigint FROM {PROBE_TABLE} WHERE marker = $1 AND client_id = $2"
        ))
        .bind(PROBE_MARKER)
        .bind(target_client)
        .fetch_one(&mut *conn)
        .await
        .expect("scoped count");
        sqlx::query("ROLLBACK").execute(&mut *conn).await.ok();
        n
    }

    // Customer A session: sees its own row, NOT customer B's.
    let a_sees_a = scoped_count(&mut conn, TENANT_ID, Some(CLIENT_A), CLIENT_A).await;
    let a_sees_b = scoped_count(&mut conn, TENANT_ID, Some(CLIENT_A), CLIENT_B).await;
    assert_eq!(a_sees_a, 1, "customer A must see its own row");
    assert_eq!(
        a_sees_b, 0,
        "customer A (app.current_client_id=A) must NOT see customer B's row — client isolation broke"
    );

    // Customer B session: mirror image.
    let b_sees_b = scoped_count(&mut conn, TENANT_ID, Some(CLIENT_B), CLIENT_B).await;
    let b_sees_a = scoped_count(&mut conn, TENANT_ID, Some(CLIENT_B), CLIENT_A).await;
    assert_eq!(b_sees_b, 1, "customer B must see its own row");
    assert_eq!(b_sees_a, 0, "customer B must NOT see customer A's row");

    // Unscoped (staff/owner) session: client GUC unset ⇒ sees BOTH customers.
    let staff_sees_a = scoped_count(&mut conn, TENANT_ID, None, CLIENT_A).await;
    let staff_sees_b = scoped_count(&mut conn, TENANT_ID, None, CLIENT_B).await;
    assert_eq!(
        staff_sees_a + staff_sees_b,
        2,
        "unscoped staff/owner session must see both customers' rows"
    );

    // Cleanup as the connecting (superuser) role.
    sqlx::query(&format!("DROP TABLE IF EXISTS {PROBE_TABLE}"))
        .execute(&mut *conn)
        .await
        .expect("drop probe table");
    drop(conn);
}
