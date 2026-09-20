//! Live test for the `app.current_tenant_id` drift detector wired into
//! `weissman_db::role_guard::assert_pool_role` (roadmap step 3a).
//!
//! `tenant_guc_role_default_count` is what makes a production boot fail closed if a
//! DB-/role-level default for `app.current_tenant_id` is ever reintroduced — the exact
//! drift behind the historical production tenant leak (migration
//! `20260811000100_reset_role_tenant_guc_defaults` cleared it). This proves the
//! detector reads 0 on a correctly-migrated database and flips to non-zero the moment
//! such a default is set.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test role_guard_guc_drift -- --nocapture
//! ```
//!
//! `TEST_DATABASE_URL` must be a superuser (to `ALTER ROLE ... IN DATABASE`). Same
//! env/skip contract as the sibling live-DB tests: a hard failure in CI
//! (`WEISSMAN_REQUIRE_DB_TESTS=1`), a visible skip locally.

use sqlx::postgres::PgPoolOptions;

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
                "role_guard_guc_drift requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP role_guard_guc_drift: TEST_DATABASE_URL not set (no test Postgres)");
            String::new()
        }
    }
}

#[tokio::test]
async fn tenant_guc_role_default_drift_is_detected() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("connect TEST_DATABASE_URL");

    // Isolate the mutation to a throwaway role so this test can never disturb a
    // concurrently-running weissman_app-based test on the same database (cargo runs the
    // live-DB tests in parallel). A role-level default lands in pg_db_role_setting exactly
    // like a real drift, and the detector counts it regardless of which role owns it.
    const PROBE_ROLE: &str = "weissman_guc_drift_probe_role";
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {PROBE_ROLE}"))
        .execute(&pool)
        .await;

    // A correctly-migrated database has no app.current_tenant_id default.
    let clean = weissman_db::role_guard::tenant_guc_role_default_count(&pool)
        .await
        .expect("count on clean DB");
    assert_eq!(
        clean, 0,
        "a correctly-migrated DB must have zero app.current_tenant_id defaults; \
         got {clean} — migration 20260811000100 should have RESET them"
    );

    // Inject the exact drift the historical leak had (on the throwaway role).
    sqlx::query(&format!("CREATE ROLE {PROBE_ROLE} NOLOGIN"))
        .execute(&pool)
        .await
        .expect("create throwaway probe role");
    // Role-wide default (no `IN DATABASE`, so setdatabase = 0). The drift detector's
    // WHERE clause matches `setdatabase = 0 OR datname = current_database()`, so a
    // role-wide default is exactly the kind it must catch — and this avoids the
    // `IN DATABASE current_database()` form, which is a syntax error (IN DATABASE takes
    // a literal name, not a function).
    sqlx::query(&format!(
        "ALTER ROLE {PROBE_ROLE} SET app.current_tenant_id = '0'"
    ))
    .execute(&pool)
    .await
    .expect("inject role-level GUC default");

    let drifted = weissman_db::role_guard::tenant_guc_role_default_count(&pool).await;

    // Always clean up before asserting, so a failed assertion can't leave the probe role
    // (and its drift default) behind for other live tests sharing this database. DROP ROLE
    // also drops its pg_db_role_setting rows.
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {PROBE_ROLE}"))
        .execute(&pool)
        .await;

    let drifted = drifted.expect("count after injecting default");
    assert!(
        drifted >= 1,
        "the detector must see the injected app.current_tenant_id default; got {drifted}"
    );

    // And it must return to zero after cleanup.
    let restored = weissman_db::role_guard::tenant_guc_role_default_count(&pool)
        .await
        .expect("count after reset");
    assert_eq!(
        restored, 0,
        "detector must read 0 again after dropping the probe role"
    );
}
