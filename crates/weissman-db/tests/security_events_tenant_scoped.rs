//! Guard: every read of `security_events` must be tenant-scoped, or declared global on purpose.
//!
//! `security_events` was the ONE table of the 91 carrying a `tenant_id` that had no row-level
//! security: `relrowsecurity = false`, `relforcerowsecurity = false`, zero policies, and
//! `weissman_app` holding full SELECT/INSERT/UPDATE/DELETE. It stores authentication and BYPASSRLS
//! audit events — client IPs, event types, free-form details.
//!
//! Three call sites read it on a bare pool with no tenant predicate, and the two that mattered
//! were not obscure:
//!
//!   * `predictive_analyzer` selected the latest 120 rows across EVERY tenant, stamped each line
//!     with `tenant:<id>` and the client IP, and posted them to the LLM endpoint configured by a
//!     single tenant — so one customer's third-party model provider received other customers'
//!     audit trails, attributed by tenant;
//!   * `strategy_engine` built a per-tenant self-defense audit out of all tenants' events and
//!     returned the conclusions to that one tenant.
//!
//! Nothing leaked only because the deployment had a single tenant. The exposure begins with
//! customer number two — which is to say, at the moment the product is sold.
//!
//! Migration `20260817000000_security_events_rls` turns RLS on and forces it, but **RLS alone does
//! not close this**, and that is the point of this guard. The policy admits the row when the tenant
//! GUC is unset, because the worker and the migration runner legitimately run without one; every
//! one of these three call sites ran in exactly that state. A reader on a bare pool therefore still
//! sees the whole table after the migration. The predicate has to be in the query.
//!
//! So: any Rust source containing a query over `security_events` must also bind a tenant, unless
//! the file is listed in `GLOBAL_ALLOWED` with a reason.

use std::path::{Path, PathBuf};

/// Split so this file does not match its own rule.
const TABLE_NEEDLE: &str = concat!("FROM security", "_events");

/// Evidence that a query is tenant-scoped. Any one of these appearing in the same file is enough;
/// this guard deliberately does not parse SQL, it only insists the author had to think about it.
const SCOPE_MARKERS: &[&str] = &[
    "tenant_id = $",
    "tenant_id=$",
    "WHERE tenant_id",
    "AND tenant_id",
    "begin_tenant_tx",
];

/// Files allowed to read `security_events` WITHOUT a tenant predicate.
///
/// Adding a file here is a claim that the read is global by design and that no per-tenant row or
/// field crosses a tenant boundary as a result. Say which, and why.
const GLOBAL_ALLOWED: &[&str] = &[
    // Feeds Cloudflare's zone-wide security level. The zone fronts the entire deployment, so there
    // is no per-tenant edge to put into "under attack" mode, and a distributed attack is precisely
    // what would clear a global threshold while slipping under every per-tenant one. Only a single
    // COUNT(DISTINCT client_ip) crosses the boundary — no rows, no IPs, no per-tenant detail.
    "fingerprint_engine/src/sovereign_c2.rs",
    // This guard names the table in its own documentation.
    "crates/weissman-db/tests/security_events_tenant_scoped.rs",
];

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <root>/crates/weissman-db
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
            // `.claude` holds git worktrees — full copies of this repo. Walking into them makes
            // every guarded file appear once per worktree under a path no allowlist entry can
            // match, so the suite would fail from the main checkout and pass inside a worktree.
            if matches!(
                name.as_ref(),
                "target" | ".git" | ".claude" | "node_modules" | "vendor"
            ) {
                continue;
            }
            collect_rs(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_security_events_read_is_tenant_scoped() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rs(&root, &mut files);
    assert!(
        !files.is_empty(),
        "walked the workspace and found no Rust sources — the guard would pass vacuously"
    );

    let mut offenders = Vec::new();
    for path in &files {
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        if !src.contains(TABLE_NEEDLE) {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if GLOBAL_ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        if SCOPE_MARKERS.iter().any(|m| src.contains(m)) {
            continue;
        }
        offenders.push(rel);
    }

    assert!(
        offenders.is_empty(),
        "these files query security_events with no tenant predicate:\n  {}\n\n\
         security_events holds per-tenant authentication and BYPASSRLS audit events, including \
         client IPs. Its RLS policy admits every row when the tenant GUC is unset — which is the \
         state a bare pool is in — so enabling RLS does NOT scope this for you; the predicate has \
         to be in the query. Add `WHERE tenant_id = $n` (or read inside begin_tenant_tx), or list \
         the file in GLOBAL_ALLOWED with the reason the read is global and what, if anything, \
         crosses a tenant boundary.",
        offenders.join("\n  ")
    );
}
