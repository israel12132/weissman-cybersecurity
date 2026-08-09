//! Regression lock-in for THE headline multi-tenant bug of the audit: `set_tenant_conn` used to
//! set the RLS GUC `app.current_tenant_id` **transaction-local** (`set_config(..., true)`) on a
//! **bare pooled connection with no open transaction**. Postgres discards a transaction-local GUC
//! at the end of the (implicit, autocommit) statement that set it, so the tenant scope was gone
//! before the *next* query ran — and, with the old `ALTER DATABASE ... SET app.current_tenant_id
//! = '0'` default, every query then silently fell back to tenant `0` and returned 0 rows for any
//! real tenant.
//!
//! The fix routes every tenant query through [`weissman_db::begin_tenant_tx`], which opens a
//! transaction *first* and only then sets the GUC transaction-local, so the scope lives exactly as
//! long as the queries that rely on it; and migration `20260809120000_reset_tenant_guc_default`
//! RESETs the database default so an unset GUC is NULL (tenant tables fail CLOSED) rather than `0`.
//!
//! These tests fail if either half of that regresses:
//!
//! * `begin_tenant_tx_scopes_rls_and_the_bare_connection_pattern_sees_nothing` proves the correct
//!   primitive isolates tenants (A inserts, B sees 0, A sees its 1) **and** pins the failure mode:
//!   the old bare-connection + transaction-local-GUC pattern cannot see even its own tenant's row.
//! * `db_default_tenant_guc_is_not_zero` proves the database default is unset (NULL), not `'0'` —
//!   it fails the moment someone reintroduces `ALTER DATABASE ... SET app.current_tenant_id = '0'`.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test rls_tenant_guc_regression -- --nocapture
//! ```
//!
//! `TEST_DATABASE_URL` must be a **superuser** (or a role granted `weissman_app`) so the test can
//! `SET [LOCAL] ROLE weissman_app` and exercise real RLS — superuser bypasses RLS until the role
//! is switched. The database must already have Weissman migrations applied (the `run_migrate`
//! example creates the `weissman_app` role NOSUPERUSER/NOBYPASSRLS and the reset-default
//! migration). Same env/skip contract as `rls_cross_tenant` and `tenant_tx_lock_bound`: a hard
//! failure in CI (`WEISSMAN_REQUIRE_DB_TESTS=1`) so a dropped URL can't masquerade as green, a
//! visible skip locally.

use sqlx::postgres::PgPoolOptions;

/// Uniquely named scratch table — never a real app table. Created + dropped by the test.
const PROBE_TABLE: &str = "weissman_rls_guc_regression_probe";
/// Marker so the row is unmistakably this test's, independent of any pre-existing rows.
const PROBE_MARKER: &str = "__rls_guc_regression_row__";
/// Two distinct, non-zero tenant ids. Non-zero on purpose: the old default fell back to tenant 0,
/// so a leak that returned the "tenant 0" bucket must not accidentally match these rows.
const TENANT_A: i64 = 918_273_001;
const TENANT_B: i64 = 918_273_002;

fn require_db_tests() -> bool {
    std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Same contract as the sibling DB tests: hard failure in CI, visible skip locally.
fn test_database_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => {
            assert!(
                !require_db_tests(),
                "rls_tenant_guc_regression requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!(
                "SKIP rls_tenant_guc_regression: TEST_DATABASE_URL not set (no test Postgres)"
            );
            String::new()
        }
    }
}

/// A small pool with an explicit (not sqlx's 30 s default) acquire timeout so an accidental
/// self-contention surfaces promptly instead of reading as a hang. See
/// `docs/TECH_DEBT_flaky_db_test_hang.md`.
async fn connect(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect TEST_DATABASE_URL")
}

/// Count rows this test can see for its marker, under whatever tenant scope / role is currently
/// active on `executor`.
async fn count_probe_rows<'e, E>(executor: E) -> i64
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_scalar::<_, i64>(&format!(
        "SELECT count(*)::bigint FROM {PROBE_TABLE} WHERE marker = $1"
    ))
    .bind(PROBE_MARKER)
    .fetch_one(executor)
    .await
    .expect("count probe rows")
}

/// The isolation contract + the locked-in failure mode.
///
/// Every data statement runs as `weissman_app` (NOSUPERUSER/NOBYPASSRLS) so RLS is actually
/// enforced — the connecting test role is a superuser and would otherwise bypass every policy.
#[tokio::test]
async fn begin_tenant_tx_scopes_rls_and_the_bare_connection_pattern_sees_nothing() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;

    // --- Scratch table with the canonical tenant-isolation policy (owner = superuser, so FORCE
    // is required for RLS to bind even the owner; superuser still bypasses until SET ROLE). ---
    sqlx::query(&format!("DROP TABLE IF EXISTS {PROBE_TABLE}"))
        .execute(&pool)
        .await
        .expect("drop stale probe table");
    sqlx::query(&format!(
        "CREATE UNLOGGED TABLE {PROBE_TABLE} (tenant_id bigint NOT NULL, marker text NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create probe table");
    sqlx::query(&format!(
        "ALTER TABLE {PROBE_TABLE} ENABLE ROW LEVEL SECURITY"
    ))
    .execute(&pool)
    .await
    .expect("enable RLS");
    sqlx::query(&format!("ALTER TABLE {PROBE_TABLE} FORCE ROW LEVEL SECURITY"))
        .execute(&pool)
        .await
        .expect("force RLS");
    sqlx::query(&format!(
        "CREATE POLICY {PROBE_TABLE}_tenant ON {PROBE_TABLE} FOR ALL \
         USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint) \
         WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint)"
    ))
    .execute(&pool)
    .await
    .expect("create tenant policy");
    sqlx::query(&format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON {PROBE_TABLE} TO weissman_app"
    ))
    .execute(&pool)
    .await
    .expect("grant to weissman_app");

    // --- 1) Insert one row under tenant A via the CORRECT primitive. begin_tenant_tx opens the
    // transaction, then sets the GUC transaction-local; SET LOCAL ROLE drops superuser bypass so
    // the WITH CHECK actually runs. ---
    {
        let mut tx = weissman_db::begin_tenant_tx(&pool, TENANT_A)
            .await
            .expect("begin tenant A tx");
        sqlx::query("SET LOCAL ROLE weissman_app")
            .execute(&mut *tx)
            .await
            .expect("SET LOCAL ROLE weissman_app (GRANT weissman_app TO the test role if this fails)");
        sqlx::query(&format!(
            "INSERT INTO {PROBE_TABLE} (tenant_id, marker) VALUES ($1, $2)"
        ))
        .bind(TENANT_A)
        .bind(PROBE_MARKER)
        .execute(&mut *tx)
        .await
        .expect("insert tenant A row (WITH CHECK must pass under tenant A scope)");
        tx.commit().await.expect("commit tenant A insert");
    }

    // --- 2) A transaction scoped to tenant B must see ZERO rows (cross-tenant isolation). ---
    {
        let mut tx = weissman_db::begin_tenant_tx(&pool, TENANT_B)
            .await
            .expect("begin tenant B tx");
        sqlx::query("SET LOCAL ROLE weissman_app")
            .execute(&mut *tx)
            .await
            .expect("SET LOCAL ROLE weissman_app");
        let seen = count_probe_rows(&mut *tx).await;
        let _ = tx.rollback().await;
        assert_eq!(
            seen, 0,
            "tenant B (begin_tenant_tx) must NOT see tenant A's row — RLS isolation broke"
        );
    }

    // --- 3) A transaction scoped to tenant A must see EXACTLY its one row. ---
    {
        let mut tx = weissman_db::begin_tenant_tx(&pool, TENANT_A)
            .await
            .expect("begin tenant A tx (read)");
        sqlx::query("SET LOCAL ROLE weissman_app")
            .execute(&mut *tx)
            .await
            .expect("SET LOCAL ROLE weissman_app");
        let seen = count_probe_rows(&mut *tx).await;
        let _ = tx.rollback().await;
        assert_eq!(
            seen, 1,
            "tenant A (begin_tenant_tx) must see exactly its own row"
        );
    }

    // --- 4) THE BUG, pinned: the old broken pattern. A bare pooled connection (no open
    // transaction), set the GUC transaction-local, then run a SEPARATE query. Postgres discards a
    // transaction-local GUC at the end of the (autocommit) statement that set it, so the scope is
    // already gone by the next statement — its reset value is '' (empty), never the tenant we
    // asked for. That is the exact defect `begin_tenant_tx` fixed by opening the transaction
    // FIRST. If someone reverts begin_tenant_tx to a bare-connection set_config, assertion 3 above
    // starts behaving like this: no tenant scope. ---
    let mut conn = pool.acquire().await.expect("acquire bare connection");
    // Drop superuser bypass on this pinned connection so RLS is genuinely enforced (a superuser
    // bypasses every policy and would see the row regardless — masking the bug).
    sqlx::query("SET ROLE weissman_app")
        .execute(&mut *conn)
        .await
        .expect("SET ROLE weissman_app on bare connection");
    // Broken: transaction-local set_config on an autocommit connection — reverted immediately.
    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(TENANT_A.to_string())
        .execute(&mut *conn)
        .await
        .expect("broken bare-connection set_config");

    // 4a) Mechanism, deterministic: a SEPARATE statement no longer sees the value we set — the
    // transaction-local scope did not survive. This is the root cause, asserted with no dependency
    // on the RLS policy or the database default.
    let surviving_scope: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_tenant_id', true)")
            .fetch_one(&mut *conn)
            .await
            .expect("read surviving scope");
    assert_ne!(
        surviving_scope.as_deref(),
        Some(TENANT_A.to_string().as_str()),
        "a transaction-local GUC set on a bare connection must NOT survive to a separate query; \
         if it does, begin_tenant_tx's transaction boundary is being bypassed"
    );

    // 4b) Visibility: consequently the SEPARATE query cannot surface tenant A's own row. With the
    // scope discarded, the policy sees the '' reset value and its `::bigint` cast errors (the real
    // production policy shape); on a database whose default is a valid integer it would instead
    // return 0. Either way the row is NOT visible — never `Ok(n>=1)`. `Ok(1)` here would mean the
    // transaction-local GUC leaked onto a pooled connection: the opposite failure, still a leak.
    let broken_visibility: Result<i64, sqlx::Error> = sqlx::query_scalar::<_, i64>(&format!(
        "SELECT count(*)::bigint FROM {PROBE_TABLE} WHERE marker = $1"
    ))
    .bind(PROBE_MARKER)
    .fetch_one(&mut *conn)
    .await;
    assert!(
        !matches!(broken_visibility, Ok(n) if n >= 1),
        "the bare-connection + transaction-local-GUC pattern must NOT see tenant A's own row; \
         got {broken_visibility:?} (Ok(0) or a cast error = scope discarded, the bug being \
         locked in; Ok(>=1) = a transaction-local GUC leaked onto a pooled connection)"
    );

    // Restore the session role, then clean up on THIS same connection (as the connecting superuser
    // role — RLS bypassed) so the DROP can never land on a still-`weissman_app` pooled connection.
    // The failed cast above left no open transaction to abort, so the connection is still usable.
    sqlx::query("RESET ROLE")
        .execute(&mut *conn)
        .await
        .expect("reset role on bare connection");
    sqlx::query(&format!("DROP TABLE IF EXISTS {PROBE_TABLE}"))
        .execute(&mut *conn)
        .await
        .expect("drop probe table");
    drop(conn);
}

/// The database-level default for `app.current_tenant_id` must be unset (NULL), NOT `'0'`.
///
/// This is the other half of the headline bug: with `ALTER DATABASE ... SET app.current_tenant_id
/// = '0'`, an unscoped connection reads tenant `0` instead of NULL, so tenant tables fail OPEN to
/// the tenant-0 bucket and the cross-tenant job-bus escape hatch (which keys off "GUC unset")
/// collapses to `tenant_id = 0`. Migration `20260809120000_reset_tenant_guc_default` RESET it;
/// this test fails if that default ever comes back.
#[tokio::test]
async fn db_default_tenant_guc_is_not_zero() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;

    // Fresh connection, no transaction, no GUC set by us: this reflects the database/role default.
    // missing_ok=true form returns NULL when the GUC is unset rather than erroring.
    let default_guc: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_tenant_id', true)")
            .fetch_one(&pool)
            .await
            .expect("read default app.current_tenant_id");

    assert_ne!(
        default_guc.as_deref(),
        Some("0"),
        "database default app.current_tenant_id = '0' is back — this is the headline RLS bug. \
         An unscoped connection now reads tenant 0 instead of NULL. Keep the RESET from \
         migration 20260809120000_reset_tenant_guc_default."
    );
    assert!(
        default_guc.as_deref().map(str::trim).unwrap_or("").is_empty(),
        "database default app.current_tenant_id must be UNSET (NULL) so tenant tables fail closed \
         and the job-bus 'GUC unset' escape hatch works; got {default_guc:?}"
    );
}
