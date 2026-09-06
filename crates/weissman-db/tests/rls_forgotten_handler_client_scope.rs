//! Forgotten-handler contract: JWT cid / `begin_tenant_tx_scoped` is the only
//! customer filter a handler needs. A SELECT with no `WHERE client_id = $1`
//! still cannot see another customer's rows because FORCE RLS + dual GUC
//! (`app.current_tenant_id` + `app.current_client_id`) hide them.
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:...@localhost:5432/weissman' \
//!   cargo test -p weissman-db --test rls_forgotten_handler_client_scope -- --nocapture
//! ```

use sqlx::postgres::PgPoolOptions;

const T_SLUG: &str = "__rls_forgotten_handler_tenant__";
const CLIENT_A: &str = "__rls_forgotten_handler_a__";
const CLIENT_B: &str = "__rls_forgotten_handler_b__";

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
                "rls_forgotten_handler_client_scope requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!(
                "SKIP rls_forgotten_handler_client_scope: TEST_DATABASE_URL not set (no test Postgres)"
            );
            String::new()
        }
    }
}

#[tokio::test]
async fn forgotten_handler_cannot_select_other_customer_rows() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("connect TEST_DATABASE_URL");

    sqlx::query(
        r#"INSERT INTO tenants (slug, name) VALUES ($1, 'forgotten_handler')
           ON CONFLICT (slug) DO NOTHING"#,
    )
    .bind(T_SLUG)
    .execute(&pool)
    .await
    .expect("seed tenant");
    let tid: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1")
        .bind(T_SLUG)
        .fetch_one(&pool)
        .await
        .expect("tenant id");

    sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND name IN ($2, $3)")
        .bind(tid)
        .bind(CLIENT_A)
        .bind(CLIENT_B)
        .execute(&pool)
        .await
        .ok();
    let a_id: i64 =
        sqlx::query_scalar("INSERT INTO clients (tenant_id, name) VALUES ($1, $2) RETURNING id")
            .bind(tid)
            .bind(CLIENT_A)
            .fetch_one(&pool)
            .await
            .expect("client A");
    let b_id: i64 =
        sqlx::query_scalar("INSERT INTO clients (tenant_id, name) VALUES ($1, $2) RETURNING id")
            .bind(tid)
            .bind(CLIENT_B)
            .fetch_one(&pool)
            .await
            .expect("client B");

    sqlx::query(
        r#"INSERT INTO tenants (slug, name) VALUES ($1, 'forgotten_handler_other')
           ON CONFLICT (slug) DO NOTHING"#,
    )
    .bind("__rls_forgotten_handler_other__")
    .execute(&pool)
    .await
    .expect("seed other tenant");
    let other_tid: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1")
        .bind("__rls_forgotten_handler_other__")
        .fetch_one(&pool)
        .await
        .expect("other tenant id");
    sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND name = $2")
        .bind(other_tid)
        .bind("__rls_forgotten_handler_other_c__")
        .execute(&pool)
        .await
        .ok();
    let other_cid: i64 =
        sqlx::query_scalar("INSERT INTO clients (tenant_id, name) VALUES ($1, $2) RETURNING id")
            .bind(other_tid)
            .bind("__rls_forgotten_handler_other_c__")
            .fetch_one(&pool)
            .await
            .expect("other tenant client");

    // Forgotten handler: begin_tenant_tx_scoped with JWT cid = A, then
    // `SELECT * FROM clients` with no WHERE client_id filter.
    let mut tx = weissman_db::begin_tenant_tx_scoped(&pool, tid, Some(a_id))
        .await
        .expect("begin scoped tx");
    sqlx::query("SET LOCAL ROLE weissman_app")
        .execute(&mut *tx)
        .await
        .expect("SET LOCAL ROLE weissman_app");

    let tenant_guc: String =
        sqlx::query_scalar("SELECT current_setting('app.current_tenant_id', true)")
            .fetch_one(&mut *tx)
            .await
            .expect("tenant GUC");
    let client_guc: String =
        sqlx::query_scalar("SELECT current_setting('app.current_client_id', true)")
            .fetch_one(&mut *tx)
            .await
            .expect("client GUC");
    assert_eq!(
        tenant_guc,
        tid.to_string(),
        "SET LOCAL app.current_tenant_id"
    );
    assert_eq!(
        client_guc,
        a_id.to_string(),
        "SET LOCAL app.current_client_id"
    );

    let visible: Vec<i64> = sqlx::query_scalar("SELECT id FROM clients ORDER BY id")
        .fetch_all(&mut *tx)
        .await
        .expect("forgotten SELECT *");
    let _ = tx.rollback().await;

    assert!(
        visible.contains(&a_id),
        "scoped session must still see its own customer, got {visible:?}"
    );
    assert!(
        !visible.contains(&b_id),
        "forgotten handler leaked customer B ({b_id}) via SELECT without WHERE client_id; visible={visible:?}"
    );
    assert!(
        !visible.contains(&other_cid),
        "forgotten handler leaked other-tenant client ({other_cid}); visible={visible:?}"
    );

    // FORCE RLS: every public relation with RLS enabled must also be FORCEd.
    let unforced: Vec<String> = sqlx::query_scalar(
        r#"SELECT c.relname::text
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public'
             AND c.relkind = 'r'
             AND c.relrowsecurity
             AND NOT c.relforcerowsecurity
           ORDER BY 1"#,
    )
    .fetch_all(&pool)
    .await
    .expect("FORCE RLS inventory");
    assert!(
        unforced.is_empty(),
        "FORCE RLS missing on {unforced:?} — a forgotten handler on the table owner path can skip policies"
    );

    let _ = sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND name IN ($2, $3)")
        .bind(tid)
        .bind(CLIENT_A)
        .bind(CLIENT_B)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND name = $2")
        .bind(other_tid)
        .bind("__rls_forgotten_handler_other_c__")
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn begin_tenant_tx_sets_both_gucs() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("connect");
    let mut tx = weissman_db::begin_tenant_tx_scoped(&pool, 7, Some(11))
        .await
        .expect("tx");
    let tenant: String =
        sqlx::query_scalar("SELECT current_setting('app.current_tenant_id', true)")
            .fetch_one(&mut *tx)
            .await
            .expect("tid");
    let client: String =
        sqlx::query_scalar("SELECT current_setting('app.current_client_id', true)")
            .fetch_one(&mut *tx)
            .await
            .expect("cid");
    assert_eq!(tenant, "7");
    assert_eq!(client, "11");
    let _ = tx.rollback().await;
}
