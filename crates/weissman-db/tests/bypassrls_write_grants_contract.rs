//! Live contract: a BYPASSRLS service role must not hold write privileges on a
//! tenant-scoped (FORCE ROW LEVEL SECURITY) table outside a documented
//! control/auth-plane allowlist.
//!
//! # Why this exists
//!
//! `weissman_app` (the request/engine role) is NOSUPERUSER/NOBYPASSRLS, so RLS is a
//! live backstop for every tenant write it makes. The two roles that ARE BYPASSRLS —
//! `weissman_auth` (login/billing plane; must act before a tenant is known) and
//! `weissman_worker` (job-bus claim across tenants) — bypass every RLS policy. If
//! such a role is ALSO granted write on an ordinary tenant table, any code path or
//! future SQL-injection sink running as that role can cross tenants with ZERO RLS
//! net. That is exactly how `weissman_worker` came to hold full CRUD on seven
//! tenant-scoped campaign/proof tables (revoked in
//! 20260920130000_least_privilege_bypassrls_and_drop_dead_fuzz.sql).
//!
//! This test introspects the live schema and fails CI if any BYPASSRLS service role
//! has INSERT/UPDATE/DELETE on a FORCE-RLS table that is not on the explicit
//! allowlist below. Adding such a grant then forces a reviewer to justify it here.
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test bypassrls_write_grants_contract -- --nocapture
//! ```
//!
//! Same env/skip contract as the sibling live-DB tests: a hard failure in CI
//! (`WEISSMAN_REQUIRE_DB_TESTS=1`), a visible skip locally.

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

/// (role, table) pairs where a BYPASSRLS service role legitimately writes a
/// FORCE-RLS table. Every entry is a control/auth-plane table that must be reachable
/// before or independent of a tenant RLS scope; NONE is ordinary customer data.
///
/// weissman_auth — the login/billing plane authenticates and provisions before a
/// tenant GUC exists, so it bypasses RLS by design.
/// weissman_worker — claims and drives the cross-tenant job bus.
const ALLOWED_BYPASSRLS_RLS_WRITES: &[(&str, &str)] = &[
    // weissman_auth: login / token / billing / provisioning plane.
    ("weissman_auth", "system_configs"),
    ("weissman_auth", "tenant_llm_usage"),
    ("weissman_auth", "tenant_paddle_customers"),
    ("weissman_auth", "tenant_subscriptions"),
    ("weissman_auth", "tenant_usage_counters"),
    ("weissman_auth", "tenants"),
    ("weissman_auth", "user_refresh_tokens"),
    ("weissman_auth", "weissman_async_jobs"),
    ("weissman_auth", "weissman_job_events"),
    ("weissman_auth", "weissman_job_forensic_dlq"),
    ("weissman_auth", "weissman_revoked_tokens"),
    // SAML anti-replay: the ACS runs on the auth plane (weissman_auth, BYPASSRLS) before a tenant
    // GUC is set, and records/GCs accepted assertion IDs by explicit tenant_id. The table is
    // FORCE-RLS fail-closed as defense-in-depth; weissman_app holds no grant. See
    // 20260922130000_saml_seen_assertions_replay_guard.sql.
    ("weissman_auth", "saml_seen_assertions"),
    // weissman_worker: job-bus control plane (mirrors role_guard::WORKER_JOB_BUS_TABLES).
    ("weissman_worker", "weissman_async_jobs"),
    ("weissman_worker", "weissman_job_events"),
    ("weissman_worker", "weissman_job_forensic_dlq"),
];

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
                "bypassrls_write_grants_contract requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!(
                "SKIP bypassrls_write_grants_contract: TEST_DATABASE_URL not set (no test Postgres)"
            );
            String::new()
        }
    }
}

#[tokio::test]
async fn bypassrls_roles_do_not_write_tenant_tables_outside_allowlist() {
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

    // Every (BYPASSRLS non-superuser weissman_* role, FORCE-RLS public table) pair
    // where the role holds any write privilege.
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT g.grantee AS role, g.table_name AS tbl
        FROM information_schema.role_table_grants g
        JOIN pg_class c ON c.relname = g.table_name
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = g.table_schema
        JOIN pg_roles r ON r.rolname = g.grantee
        WHERE g.privilege_type IN ('INSERT', 'UPDATE', 'DELETE')
          AND g.table_schema = 'public'
          AND c.relforcerowsecurity
          AND r.rolbypassrls
          AND NOT r.rolsuper
          AND g.grantee LIKE 'weissman\_%'
        ORDER BY 1, 2
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("introspect BYPASSRLS write grants");

    let allow: std::collections::BTreeSet<(&str, &str)> =
        ALLOWED_BYPASSRLS_RLS_WRITES.iter().copied().collect();

    let mut offenders: Vec<String> = Vec::new();
    for row in &rows {
        let role: String = row.get("role");
        let tbl: String = row.get("tbl");
        if !allow.contains(&(role.as_str(), tbl.as_str())) {
            offenders.push(format!("{role} -> {tbl}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "{} BYPASSRLS write grant(s) on FORCE-RLS tenant tables are not on the \
         control/auth-plane allowlist — a role that bypasses RLS can cross tenants \
         when writing these. REVOKE the grant, or (if genuinely control-plane) add it \
         to ALLOWED_BYPASSRLS_RLS_WRITES with justification:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );

    // Guard the other direction: every allowlist entry must still be a real grant, so
    // the list cannot rot into stale exceptions that quietly permit a future regression.
    let live: std::collections::BTreeSet<(String, String)> = rows
        .iter()
        .map(|r| (r.get::<String, _>("role"), r.get::<String, _>("tbl")))
        .collect();
    let stale: Vec<String> = ALLOWED_BYPASSRLS_RLS_WRITES
        .iter()
        .filter(|(role, tbl)| !live.contains(&((*role).to_string(), (*tbl).to_string())))
        .map(|(role, tbl)| format!("{role} -> {tbl}"))
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWED_BYPASSRLS_RLS_WRITES has {} entry(ies) that no longer match a live \
         grant — remove them so the allowlist stays honest:\n  {}",
        stale.len(),
        stale.join("\n  ")
    );
}
