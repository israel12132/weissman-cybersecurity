//! Contract tests: RLS migration and tenant GUC wiring must remain present (no DB required).

#[test]
fn row_level_security_migration_exists() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/weissman-db/migrations");
    let rls = dir.join("20250328120002_row_level_security.sql");
    assert!(rls.is_file(), "RLS migration missing: {}", rls.display());
    let text = std::fs::read_to_string(&rls).unwrap_or_default();
    assert!(!text.is_empty(), "read {}", rls.display());
    assert!(
        text.contains("FORCE ROW LEVEL SECURITY"),
        "migration should FORCE RLS"
    );
    assert!(
        text.contains("app.current_tenant_id"),
        "migration should use app.current_tenant_id"
    );
}

#[test]
fn intel_schema_migration_exists() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/weissman-db/migrations");
    let p = dir.join("20260407140000_intel_schema_async_jobs.sql");
    assert!(p.is_file(), "intel/jobs migration missing: {}", p.display());
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    assert!(
        text.contains("CREATE SCHEMA"),
        "intel migration should create schema"
    );
    assert!(
        text.contains("weissman_async_jobs"),
        "intel migration should define job queue"
    );
}

#[test]
fn db_begin_tenant_tx_sets_guc() {
    let lib = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/weissman-db/src/lib.rs"),
    )
    .unwrap_or_default();
    assert!(!lib.is_empty(), "weissman-db lib readable");
    assert!(lib.contains("set_config('app.current_tenant_id'"));
    assert!(
        lib.contains("set_config('app.current_client_id'"),
        "begin_tenant_tx must SET LOCAL both tenant and client GUCs"
    );
}

#[test]
fn architect_tenant_scope_guard_migration_forces_rls_and_grants() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/weissman-db/migrations");
    let p = dir.join("20260827193000_architect_tenant_scope_guard.sql");
    assert!(p.is_file(), "architect tenant-scope migration missing");
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    assert!(text.contains("FORCE ROW LEVEL SECURITY"));
    assert!(text.contains("user_client_scope_grants"));
    assert!(text.contains("user_scope_switch_audit"));
    assert!(text.contains("app.current_tenant_id"));
    assert!(text.contains("app.current_client_id"));
    assert!(text.contains("app_set_session_scope"));
}

#[test]
fn tenant_scope_guard_is_wired_on_authenticated_router() {
    let serve = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/http/serve.rs");
    let text = std::fs::read_to_string(&serve).unwrap_or_default();
    assert!(
        text.contains("tenant_scope_guard"),
        "authenticated API tree must install TenantScopeGuard"
    );
    assert!(
        !text.contains("client_scope_middleware"),
        "legacy client_scope_middleware must not remain the router layer"
    );
}

#[test]
fn rls_leak_check_job_queue_documented() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/weissman-db/migrations");
    let p = dir.join("20260407140000_intel_schema_async_jobs.sql");
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    assert!(
        text.contains("no RLS"),
        "job queue migration should document RLS posture (cross-tenant dequeue)"
    );
}

#[test]
fn correlation_incidents_migration_has_forced_rls() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations/20260614120000_correlation_incidents.sql");
    assert!(
        p.is_file(),
        "correlation incidents migration missing: {}",
        p.display()
    );
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    assert!(text.contains("CREATE TABLE IF NOT EXISTS weissman_correlation_incidents"));
    assert!(text.contains("FORCE ROW LEVEL SECURITY"), "must force RLS");
    assert!(
        text.contains("current_setting('app.current_tenant_id'"),
        "must scope by tenant GUC"
    );
    assert!(text.contains("TO weissman_app"), "must grant to app role");
}

#[test]
fn correlation_incidents_migration_in_sync_both_dirs() {
    let fe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations/20260614120000_correlation_incidents.sql");
    let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/weissman-db/migrations/20260614120000_correlation_incidents.sql");
    let a = std::fs::read_to_string(&fe).unwrap_or_default();
    let b = std::fs::read_to_string(&db).unwrap_or_default();
    assert!(!a.is_empty(), "migration present");
    assert_eq!(
        a, b,
        "migration must be identical in both dirs (sync check)"
    );
}

#[test]
fn ndr_itdr_ingest_migration_has_forced_rls() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations/20260614130000_ndr_itdr_ingest.sql");
    assert!(
        p.is_file(),
        "ndr/itdr ingest migration missing: {}",
        p.display()
    );
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    assert!(text.contains("CREATE TABLE IF NOT EXISTS ndr_flow_samples"));
    assert!(text.contains("CREATE TABLE IF NOT EXISTS itdr_auth_events"));
    assert_eq!(
        text.matches("FORCE ROW LEVEL SECURITY").count(),
        2,
        "both ingest tables must FORCE RLS"
    );
    assert_eq!(
        text.matches("current_setting('app.current_tenant_id'")
            .count(),
        4,
        "USING + WITH CHECK per table must scope by tenant GUC"
    );
    assert!(text.contains("ON ndr_flow_samples TO weissman_app"));
    assert!(text.contains("ON itdr_auth_events TO weissman_app"));
}

#[test]
fn ndr_itdr_ingest_migration_in_sync_both_dirs() {
    let fe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations/20260614130000_ndr_itdr_ingest.sql");
    let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/weissman-db/migrations/20260614130000_ndr_itdr_ingest.sql");
    let a = std::fs::read_to_string(&fe).unwrap_or_default();
    let b = std::fs::read_to_string(&db).unwrap_or_default();
    assert!(!a.is_empty(), "migration present");
    assert_eq!(
        a, b,
        "migration must be identical in both dirs (sync check)"
    );
}
