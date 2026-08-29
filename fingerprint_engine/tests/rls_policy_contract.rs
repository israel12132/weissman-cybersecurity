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
fn pgvector_hnsw_params_and_hermetic_roles_migrations_exist() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/weissman-db/migrations");
    let hnsw = std::fs::read_to_string(dir.join("20260827120000_pgvector_hnsw_m16_ef64.sql"))
        .unwrap_or_default();
    assert!(hnsw.contains("m = 16"));
    assert!(hnsw.contains("ef_construction = 64"));
    assert!(hnsw.starts_with("-- weissman:no-transaction"));
    let roles = std::fs::read_to_string(dir.join("20260827120100_hermetic_db_roles.sql"))
        .unwrap_or_default();
    assert!(roles.contains("NOBYPASSRLS"));
    assert!(roles.contains("statement_timeout = '15s'"));
    assert_eq!(weissman_db::role_guard::RO_SELECT_TABLES.len(), 13);
}

#[test]
fn force_rls_catch_all_migration_forces_without_enabling() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/weissman-db/migrations");
    let fe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations/20260828180000_force_rls_all_tenant_tables.sql");
    let db = dir.join("20260828180000_force_rls_all_tenant_tables.sql");
    let a = std::fs::read_to_string(&fe).unwrap_or_default();
    let b = std::fs::read_to_string(&db).unwrap_or_default();
    assert!(!a.is_empty(), "FORCE RLS catch-all migration present");
    assert_eq!(a, b, "migration must be identical in both dirs");
    assert!(a.contains("ALTER TABLE IF EXISTS public.tenants FORCE ROW LEVEL SECURITY"));
    assert!(a.contains("FORCE ROW LEVEL SECURITY"));
    assert!(a.contains("relrowsecurity"));
    assert!(a.contains("NOT c.relforcerowsecurity"));
    assert!(a.contains("SET row_security = on"));
    assert!(
        !a.to_ascii_uppercase().contains("ENABLE ROW LEVEL SECURITY"),
        "catch-all must not ENABLE RLS on tables that currently have none"
    );
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
