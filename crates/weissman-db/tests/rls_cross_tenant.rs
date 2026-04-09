//! Live RLS contract: `weissman_app` must not read another tenant's rows when
//! `app.current_tenant_id` is scoped to tenant A.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:...@localhost:5432/weissman?sslmode=disable' \
//!   cargo test -p weissman-db rls_cross_tenant -- --ignored --nocapture
//! ```
//!
//! The URL should be a **superuser** (or any role granted `weissman_app`) so the test can
//! `SET ROLE weissman_app` and exercise real RLS (superuser bypass is dropped after `SET ROLE`).
//! The database must already have Weissman migrations applied.

use sqlx::postgres::PgPoolOptions;

const T1_SLUG: &str = "__rls_contract_tenant_a__";
const T2_SLUG: &str = "__rls_contract_tenant_b__";
const PROBE_NAME: &str = "__rls_contract_probe_client__";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL (Postgres superuser or role that can SET ROLE weissman_app); DB must be migrated"]
async fn weissman_app_cannot_read_other_tenant_clients() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set for this test");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(url.trim())
        .await
        .expect("connect TEST_DATABASE_URL");

    sqlx::query(
        r#"INSERT INTO tenants (slug, name) VALUES ($1, 'rls_contract_a'), ($2, 'rls_contract_b')
           ON CONFLICT (slug) DO NOTHING"#,
    )
    .bind(T1_SLUG)
    .bind(T2_SLUG)
    .execute(&pool)
    .await
    .expect("seed tenants");

    let t1: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1")
        .bind(T1_SLUG)
        .fetch_one(&pool)
        .await
        .expect("resolve t1 id");
    let t2: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1")
        .bind(T2_SLUG)
        .fetch_one(&pool)
        .await
        .expect("resolve t2 id");

    sqlx::query("SET ROLE weissman_app")
        .execute(&pool)
        .await
        .expect("SET ROLE weissman_app (GRANT weissman_app TO your test role if this fails)");

    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(t2.to_string())
        .execute(&pool)
        .await
        .expect("set GUC t2");

    sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND name = $2")
        .bind(t2)
        .bind(PROBE_NAME)
        .execute(&pool)
        .await
        .ok();

    sqlx::query(r#"INSERT INTO clients (tenant_id, name) VALUES ($1, $2)"#)
        .bind(t2)
        .bind(PROBE_NAME)
        .execute(&pool)
        .await
        .expect("insert probe client under tenant B");

    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(t1.to_string())
        .execute(&pool)
        .await
        .expect("set GUC t1");

    let cross: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM clients WHERE tenant_id = $1 AND name = $2",
    )
    .bind(t2)
    .bind(PROBE_NAME)
    .fetch_one(&pool)
    .await
    .expect("count cross-tenant");

    assert_eq!(
        cross, 0,
        "weissman_app with app.current_tenant_id=A must not see tenant B rows"
    );

    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(t2.to_string())
        .execute(&pool)
        .await
        .expect("set GUC t2 again");

    let same: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM clients WHERE tenant_id = $1 AND name = $2",
    )
    .bind(t2)
    .bind(PROBE_NAME)
    .fetch_one(&pool)
    .await
    .expect("count same-tenant");

    assert_eq!(
        same, 1,
        "sanity: same tenant must still see its own row"
    );

    let _ = sqlx::query("RESET ROLE").execute(&pool).await;
    let _ = sqlx::query("DELETE FROM clients WHERE name = $1")
        .bind(PROBE_NAME)
        .execute(&pool)
        .await;
}
