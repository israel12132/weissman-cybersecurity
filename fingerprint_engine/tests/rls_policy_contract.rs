//! Contract tests: RLS migration and tenant GUC wiring must remain present (no DB required).

#[test]
fn row_level_security_migration_exists() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/weissman-db/migrations");
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
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/weissman-db/migrations");
    let p = dir.join("20260407140000_intel_schema_async_jobs.sql");
    assert!(p.is_file(), "intel/jobs migration missing: {}", p.display());
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    assert!(text.contains("CREATE SCHEMA"), "intel migration should create schema");
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
}

#[test]
fn rls_leak_check_job_queue_documented() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/weissman-db/migrations");
    let p = dir.join("20260407140000_intel_schema_async_jobs.sql");
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    assert!(
        text.contains("no RLS"),
        "job queue migration should document RLS posture (cross-tenant dequeue)"
    );
}
