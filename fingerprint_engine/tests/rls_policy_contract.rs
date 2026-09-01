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
    let hnsw = std::fs::read_to_string(dir.join("20260827115700_pgvector_hnsw_m16_ef64.sql"))
        .unwrap_or_default();
    assert!(hnsw.contains("m = 16"));
    assert!(hnsw.contains("ef_construction = 64"));
    assert!(hnsw.starts_with("-- weissman:no-transaction"));
    let roles = std::fs::read_to_string(dir.join("20260827115800_hermetic_db_roles.sql"))
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

/// Global / catalog tables that are allowed to exist without tenant RLS.
/// Customer-data tables must NEVER be added here — the test fails if a new
/// `CREATE TABLE` ships without `FORCE ROW LEVEL SECURITY`.
const RLS_FORCE_ALLOWLIST: &[&str] = &[
    "billing_plans",
    "cognitive_poison_library",
    "compliance_control_mappings",
    "compliance_frameworks",
    "compliance_mappings",
    // Shared unbounded discovery corpus (`intel.discovery_knowledge`) — seed +
    // live LLM + probe hits. Same tenant-agnostic model as dynamic_payloads.
    "discovery_knowledge",
    "dynamic_payloads",
    "endpoint_agent_enroll_attempts",
    "ephemeral_payloads",
    "epss_intel",
    "kev_intel",
    "oast_interaction_hits",
    "pending_signups",
    "stripe_webhook_events",
    "weissman_self_heal_gate",
    "ueba_sovereign_binary_allowlist",
    // Corrupt MessagePack with no tenant identity cannot insert under FORCE RLS.
    "cem_dago_telemetry_quarantine_global",
];

#[test]
fn sql_idents_after_skips_schema_qualification() {
    assert_eq!(
        sql_idents_after(
            "create table if not exists intel.discovery_knowledge (",
            "create table"
        ),
        vec!["discovery_knowledge".to_string()]
    );
    assert_eq!(
        sql_idents_after(
            "create table if not exists public.weissman_billing_usage_snapshot (",
            "create table"
        ),
        vec!["weissman_billing_usage_snapshot".to_string()]
    );
    assert_eq!(
        sql_idents_after("alter table cicd_scan_events force", "alter table"),
        vec!["cicd_scan_events".to_string()]
    );
}

fn sql_idents_after(hay: &str, needle_lc: &str) -> Vec<String> {
    let lower = hay.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find(needle_lc) {
        let after = search_from + rel + needle_lc.len();
        let mut rest = lower[after..].trim_start();
        for prefix in ["if not exists", "if exists", "only"] {
            if rest.starts_with(prefix) {
                rest = rest[prefix.len()..].trim_start();
            }
        }
        // Skip catalog/schema qualification (`public.foo`, `intel.discovery_knowledge`).
        // Stopping at the first ident used to treat `intel.discovery_knowledge` as
        // a table named `intel` (schema, not relation) and fail the FORCE-RLS gate.
        loop {
            let ident: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if ident.is_empty() {
                break;
            }
            rest = rest[ident.len()..].trim_start();
            if rest.starts_with('.') {
                rest = rest[1..].trim_start();
                continue;
            }
            out.push(ident);
            break;
        }
        search_from = after;
    }
    out
}

#[test]
fn every_new_table_forces_rls_unless_allowlisted() {
    use std::collections::BTreeSet;

    let mut created: BTreeSet<String> = BTreeSet::new();
    let mut forced: BTreeSet<String> = BTreeSet::new();
    for dir in [
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/weissman-db/migrations"),
    ] {
        for entry in std::fs::read_dir(&dir).expect("migrations dir") {
            let path = entry.expect("entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("sql") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let collapsed = text
                .to_ascii_lowercase()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            created.extend(sql_idents_after(&collapsed, "create table"));
            for (i, _) in collapsed.match_indices("force row level security") {
                let before = &collapsed[..i];
                if let Some(rel) = before.rfind("alter table") {
                    forced.extend(sql_idents_after(&collapsed[rel..i], "alter table"));
                }
            }
        }
    }

    assert!(
        forced.contains("cicd_scan_events"),
        "cicd_scan_events must FORCE RLS — tenant CI findings are customer data"
    );
    assert!(
        !RLS_FORCE_ALLOWLIST.contains(&"cicd_scan_events"),
        "cicd_scan_events must not be on the RLS allowlist"
    );
    assert!(
        RLS_FORCE_ALLOWLIST.contains(&"discovery_knowledge"),
        "intel.discovery_knowledge is shared catalog intel (no tenant column) — must stay allowlisted"
    );
    assert!(
        !forced.contains("discovery_knowledge"),
        "discovery_knowledge must remain without FORCE RLS (global corpus, same as dynamic_payloads)"
    );

    let allow: BTreeSet<&str> = RLS_FORCE_ALLOWLIST.iter().copied().collect();
    let missing: Vec<String> = created
        .into_iter()
        .filter(|t| !forced.contains(t) && !allow.contains(t.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "these CREATE TABLE names have no FORCE ROW LEVEL SECURITY \
         (add FORCE RLS + tenant policy, or justify a catalog allowlist entry): {missing:?}"
    );
}

#[test]
fn hardening_migrations_20260827_identical_in_both_dirs() {
    let names = [
        "20260827120000_cicd_scan_events_rls.sql",
        "20260827120100_weissman_ro_dashboard_grants.sql",
        "20260827120200_nl_query_audit_encrypted.sql",
        "20260827120300_soar_hitl_and_stale_alerts.sql",
        "20260827120400_nl_query_audit_hash_chain.sql",
        "20260827120500_nl_query_audit_chain_update.sql",
        "20260827120600_cicd_scan_events_rls_cast_safe.sql",
        "20260827160000_ot_ics_hardening_safety.sql",
        "20260827160100_ot_ics_rls_cast_safe.sql",
        "20260830140000_nl_audit_chain_epoch_and_sovereign_allowlist.sql",
        "20260830160000_privilege_escalation_controls.sql",
        "20260830180000_cem_dago_telemetry_quarantine.sql",
        "20260830184500_nl_epoch_cap_and_sovereign_signature.sql",
        "20260830190000_cem_dago_telemetry_quarantine_global.sql",
        "20260830203000_discovery_knowledge.sql",
    ];
    for name in names {
        let fe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("migrations")
            .join(name);
        let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/weissman-db/migrations")
            .join(name);
        let a = std::fs::read_to_string(&fe).unwrap_or_default();
        let b = std::fs::read_to_string(&db).unwrap_or_default();
        assert!(
            !a.is_empty(),
            "missing {name} in fingerprint_engine/migrations"
        );
        assert_eq!(a, b, "{name} must be byte-identical in both migration dirs");
    }
}

/// Migrations after the 2026-08-11 GUC cast-safety rewrite must not reintroduce
/// `current_setting(...)::bigint` on CREATE/ALTER POLICY. 20260827120000 did
/// exactly that for cicd_scan_events and is superseded by 20260827120600.
#[test]
fn post_cast_safety_policies_use_app_current_tenant_id() {
    let dirs = [
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/weissman-db/migrations"),
    ];
    let unsafe_needles = [
        "current_setting('app.current_tenant_id', true)::bigint",
        "current_setting('app.current_tenant_id'::text, true)::bigint",
    ];
    let mut offenders = Vec::new();
    let mut saw_cast_safe_followon = false;
    for dir in dirs {
        let rd = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".sql") {
                continue;
            }
            if name.starts_with("20260827120600_") {
                saw_cast_safe_followon = true;
            }
            if name.starts_with("20260827160100_") {
                saw_cast_safe_followon = true;
            }
            let Some(ver) = name.split('_').next() else {
                continue;
            };
            if ver <= "20260811000000" {
                continue;
            }
            // Already-applied; follow-on restates the policy with app_current_tenant_id().
            if name.starts_with("20260827120000_") || name.starts_with("20260827160000_") {
                continue;
            }
            let text = std::fs::read_to_string(ent.path()).unwrap_or_default();
            let executable = strip_sql_comments(&text);
            for needle in unsafe_needles {
                if executable.contains(needle) {
                    offenders.push(format!("{name}: {needle}"));
                }
            }
        }
    }
    assert!(
        saw_cast_safe_followon,
        "20260827120600_cicd_scan_events_rls_cast_safe.sql must exist in both trees"
    );
    assert!(
        offenders.is_empty(),
        "these post-20260811 migrations reintroduce a raw tenant GUC cast (use \
         public.app_current_tenant_id(); empty GUC + ::bigint took production down \
         for four days): {offenders:?}"
    );
}

fn strip_sql_comments(sql: &str) -> String {
    let b = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    let mut in_block = false;
    while i < b.len() {
        if in_block {
            if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                in_block = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if b[i] == b'-' && i + 1 < b.len() && b[i + 1] == b'-' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            in_block = true;
            i += 2;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

#[test]
fn auth_bootstrap_promotes_master_bootstrap_to_owner() {
    // POST /api/clients is owner-only. CI smoke logs in as
    // WEISSMAN_MASTER_BOOTSTRAP_EMAIL; boot must promote that row, not only
    // WEISSMAN_ADMIN_EMAIL, or engine-group smoke dies with 403 owner_required.
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/auth_bootstrap.rs"),
    )
    .unwrap_or_default();
    assert!(
        src.contains("WEISSMAN_MASTER_BOOTSTRAP_EMAIL"),
        "master bootstrap must be in the owner promotion set"
    );
    assert!(
        src.contains("fn merge_owner_emails"),
        "owner email set must stay a named helper so both env operators are promoted"
    );
    assert!(
        src.contains("fn env_nonempty"),
        "env operators must be read through env_nonempty so empty strings are skipped"
    );
    assert!(
        src.contains("sync_admin_credentials_from"),
        "promotion must accept injected emails so tests do not hold an env mutex across await"
    );
}

#[test]
fn privilege_escalation_controls_migration_has_forced_rls() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations/20260830160000_privilege_escalation_controls.sql");
    assert!(
        p.is_file(),
        "privilege escalation controls migration missing: {}",
        p.display()
    );
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(text.contains("CREATE TABLE IF NOT EXISTS privilege_escalation_control_results"));
    assert!(text.contains("tenant_id     BIGINT NOT NULL REFERENCES tenants(id)"));
    assert!(text.contains("FORCE ROW LEVEL SECURITY"));
    assert!(text.contains("public.app_current_tenant_id()"));
    assert!(text.contains("CHECK (status IN ('pass', 'fail', 'na', 'not_observed'))"));
    assert!(text.contains("ux_pac_controls_tenant_host_id"));
    assert!(text.contains("ON privilege_escalation_control_results TO weissman_app"));
    assert_eq!(
        text.matches("app_current_tenant_id()").count(),
        2,
        "USING + WITH CHECK must both scope by tenant GUC"
    );
}

#[test]
fn privilege_escalation_controls_migration_in_sync_both_dirs() {
    let fe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations/20260830160000_privilege_escalation_controls.sql");
    let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/weissman-db/migrations/20260830160000_privilege_escalation_controls.sql");
    let a = std::fs::read_to_string(&fe).unwrap_or_default();
    let b = std::fs::read_to_string(&db).unwrap_or_default();
    assert!(!a.is_empty(), "migration present");
    assert_eq!(
        a, b,
        "privilege_escalation_controls migration must be identical in both dirs"
    );
}
