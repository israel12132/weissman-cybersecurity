//! Guard: no Rust source may enumerate tenants by reading `tenants` off an RLS-subject pool.
//!
//! `tenants` is `FORCE ROW LEVEL SECURITY` with `USING (id = <current tenant>)`. So the obvious
//! line for a cross-tenant background sweep —
//!
//! ```sql
//! SELECT id FROM tenants WHERE active = true
//! ```
//!
//! — does not enumerate tenants at all on the app pool. It returns the connection's *own* tenant,
//! and once the tenant GUC is unset (the correct default after migration `20260811000100`) it
//! returns **nothing**.
//!
//! The failure is silent in the worst way: the query succeeds, the worker iterates an empty list,
//! logs nothing, and reports healthy. Three sweeps shipped exactly that way — `self_improve`
//! (every tenant), `sovereign_self_scan` and `predictive_analyzer` (first active tenant, the
//! latter with an `.unwrap_or(1)` that silently pinned it to tenant 1 forever). Six other workers
//! got it right only by happening to hold the `weissman_auth` BYPASSRLS pool, which is not a
//! property any of them stated or checked.
//!
//! The rule: enumerate through [`weissman_db::active_tenant_ids`], backed by the
//! `public.active_tenant_ids()` SECURITY DEFINER function, which returns ids and nothing else.
//! Reading `tenants` for other columns, scoped to the current tenant, is unaffected — this guard
//! matches only the enumerating shape.

use std::path::{Path, PathBuf};

/// The enumerating shape: selecting ids out of `tenants` filtered on `active`.
///
/// Split so this file does not match its own rule. Matched case-insensitively on a
/// whitespace-collapsed line, because these queries are wrapped across lines inconsistently.
fn is_tenant_enumeration(collapsed: &str) -> bool {
    let needle_from = concat!("from ", "tenants");
    let needle_active = "active";
    // Two shapes, both of which return "whatever this connection is scoped to" rather than the
    // fleet: selecting ids out of `tenants` filtered on active, and — the one that slipped past
    // the first version of this guard — `SELECT DISTINCT tenant_id` out of ANY tenant-scoped
    // table. endpoint_agents.rs discovered tenants that way and would have gone silently idle the
    // moment the tenant GUC default was removed.
    let enumerates_tenants_table =
        collapsed.contains(needle_from) && collapsed.contains(needle_active)
            && collapsed.contains("select id");
    let distinct_tenant_id = collapsed.contains("select distinct tenant_id");
    enumerates_tenants_table || distinct_tenant_id
}

/// Files allowed to read `tenants` in the enumerating shape, each with the reason it is safe.
///
/// Adding a file here is a claim that its query runs on a pool that can actually see every tenant
/// — say which one.
const ALLOWED: &[&str] = &[
    // The helper itself is a thin wrapper over the SECURITY DEFINER function, not a raw read.
    "crates/weissman-db/src/lib.rs",
    // This guard.
    "crates/weissman-db/tests/tenant_enumeration_discipline.rs",
    // Runs on the weissman_auth (BYPASSRLS) pool — verified by reading each call site: the query
    // is issued against a pool parameter named `auth_pool`, which serve.rs builds from
    // WEISSMAN_AUTH_DATABASE_URL and which the role catalog confirms is BYPASSRLS.
    "fingerprint_engine/src/alert_evaluator_worker.rs",
    "fingerprint_engine/src/audit_log.rs",
    "fingerprint_engine/src/ceo/tenant_engines.rs",
    "fingerprint_engine/src/db_backup.rs",
    "fingerprint_engine/src/http/serve.rs",
    "fingerprint_engine/src/intel_findings_backfill.rs",
    "fingerprint_engine/src/orchestrator/dispatch.rs",
    "fingerprint_engine/src/orchestrator/mod.rs",
    "fingerprint_engine/src/payload_sync_worker.rs",
    "fingerprint_engine/src/redteam_background_worker.rs",
    "fingerprint_engine/src/scan_schedule_worker.rs",
    "fingerprint_engine/src/soar/worker.rs",
    "fingerprint_engine/src/threat_intel_ingestor.rs",
    // Test fixtures that seed and read their own tenants as superuser.
    "crates/weissman-db/tests/rls_cross_tenant.rs",
    // Contract test: issues the naive query *deliberately*, on an RLS-subject pool, to prove it
    // returns nothing where active_tenant_ids returns every tenant.
    "crates/weissman-db/tests/rls_worker_dequeue_regression.rs",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("weissman-db lives two levels below the workspace root")
        .to_path_buf()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), "target" | ".git" | "node_modules" | "vendor") {
                continue;
            }
            collect_rs(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

fn workspace_sources() -> Vec<(String, PathBuf)> {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rs(&root, &mut files);
    assert!(
        files.len() > 100,
        "source walk found only {} .rs files under {} — the walk is broken, not the tree",
        files.len(),
        root.display()
    );
    files
        .into_iter()
        .map(|f| {
            let rel = f
                .strip_prefix(&root)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            (rel, f)
        })
        .collect()
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*')
}

#[test]
fn tenants_are_enumerated_only_through_the_cross_tenant_helper() {
    let mut offenders = Vec::new();
    for (rel, path) in workspace_sources() {
        if ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if is_comment(line) {
                continue;
            }
            // These queries are wrapped inconsistently, so look at a small window rather than a
            // single line — otherwise `SELECT id\n FROM tenants WHERE active` slips through.
            let window = lines[i..(i + 3).min(lines.len())]
                .iter()
                .filter(|l| !is_comment(l))
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
            let collapsed = window.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
            if is_tenant_enumeration(&collapsed) {
                offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                break; // one report per file is enough to make the point
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "tenant enumeration read straight off `tenants`. That table is FORCE ROW LEVEL SECURITY, \
         so on an RLS-subject pool this returns only the connection's own tenant — and nothing at \
         all once the tenant GUC is unset. The sweep then silently does nothing and still reports \
         success. Use weissman_db::active_tenant_ids(pool) instead.\n\
         If the call site provably runs on the weissman_auth (BYPASSRLS) pool, add it to ALLOWED \
         in crates/weissman-db/tests/tenant_enumeration_discipline.rs with the reason.\n\
         Offenders:\n  {}",
        offenders.join("\n  ")
    );
}
