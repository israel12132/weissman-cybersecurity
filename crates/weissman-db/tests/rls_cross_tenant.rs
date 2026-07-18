//! Live RLS contract: `weissman_app` must not read another tenant's rows when
//! `app.current_tenant_id` is scoped to tenant A.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:...@localhost:5432/weissman?sslmode=disable' \
//!   cargo test -p weissman-db --test rls_cross_tenant -- --nocapture
//! ```
//!
//! The URL should be a **superuser** (or any role granted `weissman_app`) so the test can
//! `SET ROLE weissman_app` and exercise real RLS (superuser bypass is dropped after `SET ROLE`).
//! The database must already have Weissman migrations applied.

use sqlx::postgres::PgPoolOptions;

const T1_SLUG: &str = "__rls_contract_tenant_a__";
const T2_SLUG: &str = "__rls_contract_tenant_b__";
const PROBE_NAME: &str = "__rls_contract_probe_client__";

fn require_test_database_url() -> String {
    // Live-DB RLS contract: runs only where a test database is provided. The
    // engine-wiring CI job sets TEST_DATABASE_URL and a migrated Postgres (see
    // ci.yml) and enforces this test there; the lint/audit job runs
    // `cargo test --workspace` with no database, so skip there instead of
    // hard-failing the whole suite.
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            // In CI (WEISSMAN_REQUIRE_DB_TESTS=1) a missing DB is a hard failure, so a
            // dropped TEST_DATABASE_URL can never masquerade as a green run. Locally it
            // stays a visible skip.
            assert!(
                !require_db_tests(),
                "rls_cross_tenant requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP rls_cross_tenant: TEST_DATABASE_URL not set (no test Postgres)");
            String::new()
        }
    }
}

fn require_db_tests() -> bool {
    std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

#[tokio::test]
async fn weissman_app_cannot_read_other_tenant_clients() {
    let url = require_test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(url.trim())
        .await
        .expect("connect TEST_DATABASE_URL");
    // Pin the whole contract to ONE connection. `SET ROLE weissman_app` and the
    // `app.current_tenant_id` GUC are per-connection session state; running the
    // seed / role / GUC / SELECT statements over a multi-connection pool let the
    // SELECT land on a still-superuser connection and bypass RLS (flaky under the
    // full `cargo test --workspace` connection contention). Hold one connection
    // explicitly and run every statement on it.
    let mut conn = pool.acquire().await.expect("acquire dedicated connection");

    sqlx::query(
        r#"INSERT INTO tenants (slug, name) VALUES ($1, 'rls_contract_a'), ($2, 'rls_contract_b')
           ON CONFLICT (slug) DO NOTHING"#,
    )
    .bind(T1_SLUG)
    .bind(T2_SLUG)
    .execute(&mut *conn)
    .await
    .expect("seed tenants");

    let t1: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1")
        .bind(T1_SLUG)
        .fetch_one(&mut *conn)
        .await
        .expect("resolve t1 id");
    let t2: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1")
        .bind(T2_SLUG)
        .fetch_one(&mut *conn)
        .await
        .expect("resolve t2 id");

    sqlx::query("SET ROLE weissman_app")
        .execute(&mut *conn)
        .await
        .expect("SET ROLE weissman_app (GRANT weissman_app TO your test role if this fails)");

    sqlx::query("SELECT set_config('app.current_tenant_id', $1, false)")
        .bind(t2.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC t2");

    sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND name = $2")
        .bind(t2)
        .bind(PROBE_NAME)
        .execute(&mut *conn)
        .await
        .ok();

    sqlx::query(r#"INSERT INTO clients (tenant_id, name) VALUES ($1, $2)"#)
        .bind(t2)
        .bind(PROBE_NAME)
        .execute(&mut *conn)
        .await
        .expect("insert probe client under tenant B");

    sqlx::query("SELECT set_config('app.current_tenant_id', $1, false)")
        .bind(t1.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC t1");

    let cross: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM clients WHERE tenant_id = $1 AND name = $2",
    )
    .bind(t2)
    .bind(PROBE_NAME)
    .fetch_one(&mut *conn)
    .await
    .expect("count cross-tenant");

    assert_eq!(
        cross, 0,
        "weissman_app with app.current_tenant_id=A must not see tenant B rows"
    );

    sqlx::query("SELECT set_config('app.current_tenant_id', $1, false)")
        .bind(t2.to_string())
        .execute(&mut *conn)
        .await
        .expect("set GUC t2 again");

    let same: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM clients WHERE tenant_id = $1 AND name = $2",
    )
    .bind(t2)
    .bind(PROBE_NAME)
    .fetch_one(&mut *conn)
    .await
    .expect("count same-tenant");

    assert_eq!(same, 1, "sanity: same tenant must still see its own row");

    let _ = sqlx::query("RESET ROLE").execute(&mut *conn).await;
    let _ = sqlx::query("DELETE FROM clients WHERE name = $1")
        .bind(PROBE_NAME)
        .execute(&mut *conn)
        .await;
}
