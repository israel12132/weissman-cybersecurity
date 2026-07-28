//! Live DB integration for per-tenant resource quotas. Exercises the real Postgres
//! round-trip under RLS: atomic upsert-increment, monotonic per-period accounting, and the
//! allow→deny flip at the limit boundary.
//!
//! ```text
//! TEST_DATABASE_URL='postgres://weissman_app:weissman_app@127.0.0.1:5432/weissman' \
//!   cargo test -p fingerprint_engine --test tenant_quota_integration -- --nocapture
//! ```
//! Skips (not fails) when TEST_DATABASE_URL is unset, unless WEISSMAN_REQUIRE_DB_TESTS=1.

use fingerprint_engine::tenant_quota::{enforce, report, QuotaWindow};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

const TENANT: i64 = 1;
// Each test uses a DISTINCT resource so they stay independent under parallel `cargo test`
// (they share tenant + period, so a shared resource row would interleave their increments).
// Delta-based assertions also make each robust to rows left by a previous run this period.

fn test_db_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            assert!(
                !std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
                    .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(false),
                "tenant_quota_integration requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP tenant_quota_integration: TEST_DATABASE_URL not set");
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
            // Explicit, not sqlx's 30 s default: a starved pool here should fail while the test
            // output still points at this pool, not after a delay long enough to read as a hang.
            // See docs/TECH_DEBT_flaky_db_test_hang.md.
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect TEST_DATABASE_URL"),
    )
}

/// Serialises this file's tests against the process-environment mutation below.
///
/// `github_token_resolves_from_saved_integration_then_env` must set and clear `GITHUB_TOKEN` /
/// `WEISSMAN_GITHUB_TOKEN` — proving the env fallback *is* what it asserts, so the mutation cannot
/// be designed away. But `setenv`/`unsetenv` are not thread-safe in glibc: they can reallocate
/// `environ` while another thread walks it, leaving a concurrent reader dereferencing freed
/// memory. Rust 2024 marks `set_var` `unsafe` for exactly this reason.
///
/// The sibling quota tests reach a live database, and connecting reads the environment, so they
/// are readers. Serialising is what keeps the writer from overlapping them.
static ENV_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn increments_are_atomic_and_monotonic() {
    let _env_guard = ENV_GUARD.lock().await;
    let Some(pool) = pool().await else { return };
    const RES: &str = "itest_scans_mono";
    // Baseline (unlimited so allowed is always true).
    let base = report(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
        .await
        .expect("report");
    let start = base.used;

    // Three consumptions increment used by exactly one each.
    for i in 1..=3u64 {
        let d = enforce(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
            .await
            .expect("enforce");
        assert_eq!(d.used, start + i, "used must increment by 1 per call");
        assert!(d.allowed, "unlimited quota always allowed");
    }

    // report reflects the accumulated usage without adding to it.
    let after = report(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
        .await
        .expect("report");
    assert_eq!(after.used, start + 3);
}

#[tokio::test]
async fn deny_flips_at_limit_boundary() {
    let _env_guard = ENV_GUARD.lock().await;
    let Some(pool) = pool().await else { return };
    const RES: &str = "itest_scans_deny";
    // Current usage for this period.
    let now = report(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
        .await
        .expect("report")
        .used;

    // Consume once more with the limit set exactly to the resulting usage → still allowed
    // (usage == limit is the last allowed request).
    let at_limit = enforce(&pool, TENANT, RES, QuotaWindow::Monthly, now + 1)
        .await
        .expect("enforce");
    assert_eq!(at_limit.used, now + 1);
    assert!(at_limit.allowed, "usage == limit is allowed");
    assert_eq!(at_limit.remaining, 0);

    // Next consumption with the same (now-exceeded) limit → denied.
    let over = enforce(&pool, TENANT, RES, QuotaWindow::Monthly, now + 1)
        .await
        .expect("enforce");
    assert_eq!(over.used, now + 2);
    assert!(!over.allowed, "usage > limit must be denied");
    assert_eq!(over.remaining, 0);

    // Unlimited (limit 0) is always allowed regardless of usage.
    let unlimited = enforce(&pool, TENANT, RES, QuotaWindow::Monthly, 0)
        .await
        .expect("enforce");
    assert!(unlimited.allowed);
}

/// The auto-heal GitHub token resolver reads the tenant's saved "GitHub PR" integration
/// (stored encrypted in integrations_registry, exactly as the Integration Manager UI writes
/// it), decrypts it, and falls back to the deployment env — so a token entered once in the UI
/// drives PR automation without being passed per request.
#[tokio::test]
async fn github_token_resolves_from_saved_integration_then_env() {
    let _env_guard = ENV_GUARD.lock().await;
    std::env::set_var(
        "WEISSMAN_INTEGRATIONS_VAULT_KEY",
        "weissman-itest-vault-key-please-32b+",
    );
    std::env::remove_var("GITHUB_TOKEN");
    std::env::remove_var("WEISSMAN_GITHUB_TOKEN");
    let Some(pool) = pool().await else { return };

    // Encrypt the token exactly as the UI's integrations save path does.
    let token = "ghp_EXAMPLE_itest_not_a_secret_0000_klmn";
    let cfg = fingerprint_engine::soar::integrations_vault::encrypt_config(
        &serde_json::json!({ "token": token, "default_repo": "o/r" }),
    );
    let registry =
        serde_json::json!([{ "id": "github", "name": "GitHub PR", "category": "SOAR", "config": cfg }])
            .to_string();

    // Insert under the tenant GUC (system_configs enforces RLS).
    let mut conn = pool.acquire().await.expect("conn");
    sqlx::query("SELECT set_config('app.current_tenant_id', $1::text, false)")
        .bind(TENANT.to_string())
        .execute(&mut *conn)
        .await
        .expect("guc");
    sqlx::query(
        "INSERT INTO system_configs (tenant_id, key, value, description) \
         VALUES ($1, 'integrations_registry', $2, 'itest') \
         ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(TENANT)
    .bind(&registry)
    .execute(&mut *conn)
    .await
    .expect("insert registry");
    drop(conn);

    // Resolves the decrypted token from the saved integration.
    let resolved = fingerprint_engine::auto_heal::github_token_for_tenant(&pool, TENANT).await;
    assert_eq!(
        resolved.as_deref(),
        Some(token),
        "resolves the saved GitHub integration token"
    );

    // Remove the integration → falls back to the deployment env.
    let mut c2 = pool.acquire().await.expect("conn2");
    sqlx::query("SELECT set_config('app.current_tenant_id', $1::text, false)")
        .bind(TENANT.to_string())
        .execute(&mut *c2)
        .await
        .expect("guc2");
    sqlx::query(
        "DELETE FROM system_configs WHERE tenant_id = $1 AND key = 'integrations_registry'",
    )
    .bind(TENANT)
    .execute(&mut *c2)
    .await
    .expect("cleanup");
    drop(c2);

    std::env::set_var(
        "WEISSMAN_GITHUB_TOKEN",
        "ghp_ENV_fallback_not_a_secret_00_zzzz",
    );
    let env_resolved = fingerprint_engine::auto_heal::github_token_for_tenant(&pool, TENANT).await;
    assert_eq!(
        env_resolved.as_deref(),
        Some("ghp_ENV_fallback_not_a_secret_00_zzzz"),
        "falls back to the env token when no integration is saved"
    );
    std::env::remove_var("WEISSMAN_GITHUB_TOKEN");
}
