//! Live contract: master-bootstrap `role=admin` staff is promoted to platform owner.
//!
//! CI smoke (`scripts/smoke_engine_groups.mjs`) logs in as
//! `WEISSMAN_MASTER_BOOTSTRAP_EMAIL`. That row is inserted as staff (`role=admin`,
//! `is_superadmin=false`). `POST /api/clients` is owner-only, so boot must flip
//! the flag under RLS.
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p fingerprint_engine --test auth_owner_bootstrap -- --nocapture
//! ```
//! Skips (not fails) when TEST_DATABASE_URL is unset, unless WEISSMAN_REQUIRE_DB_TESTS=1.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

fn test_db_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            assert!(
                !std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
                    .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(false),
                "auth_owner_bootstrap requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP auth_owner_bootstrap: TEST_DATABASE_URL not set");
            String::new()
        }
    }
}

async fn pool() -> Option<PgPool> {
    let url = test_db_url();
    if url.is_empty() {
        return None;
    }
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect TEST_DATABASE_URL"),
    )
}

#[tokio::test]
async fn master_bootstrap_staff_admin_is_promoted_to_owner() {
    let Some(pool) = pool().await else {
        return;
    };

    let tenant_id: i64 = sqlx::query_scalar(
        "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .expect("lookup default tenant")
    .expect("default tenant exists");

    let email = format!(
        "owner-promote-{}@ci.localhost",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );

    let mut tx = weissman_db::begin_tenant_tx(&pool, tenant_id)
        .await
        .expect("begin tenant tx");
    let user_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO users (tenant_id, email, password_hash, role, is_superadmin, is_active)
           VALUES ($1, $2, 'x', 'admin', false, true)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&email)
    .fetch_one(&mut *tx)
    .await
    .expect("insert staff admin");
    tx.commit().await.expect("commit insert");

    let before: bool = sqlx::query_scalar(
        "SELECT COALESCE(is_superadmin, false) FROM auth.v_user_lookup WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("read before promote");
    assert!(!before, "fixture must start as staff");

    fingerprint_engine::auth_bootstrap::sync_one_owner(&pool, &pool, &email, None).await;

    let after = sqlx::query(
        r#"SELECT COALESCE(is_superadmin, false) AS is_superadmin,
                  COALESCE(role, '') AS role
           FROM auth.v_user_lookup
           WHERE id = $1"#,
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("read after promote");
    let is_superadmin: bool = after.try_get("is_superadmin").expect("is_superadmin");
    let role: String = after.try_get("role").expect("role");
    assert!(
        is_superadmin,
        "master-bootstrap staff admin must become platform owner"
    );
    assert_eq!(role, "admin");

    let mut cleanup = weissman_db::begin_tenant_tx(&pool, tenant_id)
        .await
        .expect("begin cleanup tx");
    sqlx::query("DELETE FROM users WHERE id = $1 AND tenant_id = $2")
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *cleanup)
        .await
        .expect("delete fixture user");
    cleanup.commit().await.expect("commit cleanup");
}
