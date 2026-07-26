//! Guard: no Rust source in this workspace may take a Postgres advisory lock directly.
//!
//! `docs/TECH_DEBT_flaky_db_test_hang.md` and `docs/TECH_DEBT_live_e2e_runtime.md` both record the
//! same failure mode — a guard is added, and later silently lost. A rule stated only in prose is
//! exactly that kind of guard. This test makes Rule 1 of the DB-hang document self-enforcing:
//! it runs inside the existing blocking `cargo test --workspace` gate, needs no CI step of its
//! own, and lives next to the module it protects.
//!
//! Why it matters: `pg_advisory_lock` / `pg_advisory_xact_lock` block **forever**. Whether the
//! wait is bounded depends on the `lock_timeout` of whichever connection the caller happened to
//! be handed — a non-local property. `weissman_db::advisory_lock` makes the bound intrinsic to
//! the lock. A new raw call site silently reintroduces the multi-hour CI hang.

use std::path::{Path, PathBuf};

/// The literal is split so this file does not match its own rule.
///
/// Matches the **blocking** forms only — `pg_advisory_lock`, `pg_advisory_xact_lock` and their
/// `_shared` variants. The `pg_try_advisory_*` family does not match, and that is deliberate:
/// those return immediately with a boolean and can never hang, so they need no bound.
const NEEDLE: &str = concat!("pg_advisory", "_");

/// Paths (workspace-relative) allowed to contain the raw call.
const ALLOWED: &[&str] = &[
    // The helper itself — the one place the raw statement is supposed to live.
    "crates/weissman-db/src/advisory_lock.rs",
    // Contract test: deliberately takes a raw lock to *create* the contention it measures.
    "crates/weissman-db/tests/advisory_lock_bound.rs",
    // This guard.
    "crates/weissman-db/tests/no_raw_advisory_locks.rs",
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
            // Build output and vendored/third-party trees are not ours to police.
            if matches!(name.as_ref(), "target" | ".git" | "node_modules" | "vendor") {
                continue;
            }
            collect_rs(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

#[test]
fn advisory_locks_are_only_taken_through_the_bounded_helper() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rs(&root, &mut files);
    assert!(
        files.len() > 100,
        "source walk found only {} .rs files under {} — the walk is broken, not the tree",
        files.len(),
        root.display()
    );

    let mut offenders = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (i, line) in src.lines().enumerate() {
            // Prose in a doc comment describing the hazard is fine; a real call is not.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }
            if line.contains(NEEDLE) {
                offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "raw Postgres advisory locks found — use weissman_db::advisory_lock instead, which bounds \
         the wait with SET LOCAL lock_timeout so a contended lock fails fast rather than hanging \
         the process (see docs/TECH_DEBT_flaky_db_test_hang.md).\n\
         If a new site legitimately needs the raw statement, add it to ALLOWED in \
         crates/weissman-db/tests/no_raw_advisory_locks.rs with a comment saying why.\n\n{}",
        offenders.join("\n")
    );
}
