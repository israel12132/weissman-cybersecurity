//! Guard: no Rust source in this workspace may take an **unbounded** Postgres lock.
//!
//! `docs/TECH_DEBT_flaky_db_test_hang.md` and `docs/TECH_DEBT_live_e2e_runtime.md` both record the
//! same failure mode — a guard is added, and later silently lost. A rule stated only in prose is
//! exactly that kind of guard. This test makes the DB-hang document's rules self-enforcing:
//! it runs inside the existing blocking `cargo test --workspace` gate, needs no CI step of its
//! own, and lives next to the module it protects.
//!
//! Two rules, one underlying defect. A Postgres lock wait is unbounded unless something sets
//! `lock_timeout`, and whether anything does is a **non-local property** of whichever connection
//! the caller happened to be handed:
//!
//! * the product pools set `statement_timeout`, so a blocked wait dies (crudely) in production;
//! * every **test** pool is a bare `PgPoolOptions::new()` — `lock_timeout = 0`,
//!   `statement_timeout = 0`, i.e. *infinite*.
//!
//! So the identical code path is bounded in production and unbounded under `cargo test`, where it
//! wedges the whole test binary until a step timeout SIGKILLs it with no diagnostic.
//!
//! Rule 1 — advisory locks: go through `weissman_db::advisory_lock`.
//! Rule 2 — blocking row locks: live only in files reviewed as bounded (see `ROW_LOCK_ALLOWED`).

use std::path::{Path, PathBuf};

/// The literal is split so this file does not match its own rule.
///
/// Matches the **blocking** forms only — `pg_advisory_lock`, `pg_advisory_xact_lock` and their
/// `_shared` variants. The `pg_try_advisory_*` family does not match, and that is deliberate:
/// those return immediately with a boolean and can never hang, so they need no bound.
const ADVISORY_NEEDLE: &str = concat!("pg_advisory", "_");

/// Paths (workspace-relative) allowed to contain the raw advisory-lock call.
const ADVISORY_ALLOWED: &[&str] = &[
    // The helper itself — the one place the raw statement is supposed to live.
    "crates/weissman-db/src/advisory_lock.rs",
    // Contract test: deliberately takes a raw lock to *create* the contention it measures.
    "crates/weissman-db/tests/advisory_lock_bound.rs",
    // This guard.
    "crates/weissman-db/tests/no_unbounded_lock_waits.rs",
];

/// Row-level lock clauses that **wait** when the row is already locked.
///
/// All **four** of Postgres' row-lock modes are listed, deliberately. `FOR KEY SHARE` is the
/// weakest of them and is easy to leave out — it is usually taken implicitly for foreign-key
/// checks rather than written by hand — but an explicit one waits indefinitely exactly like
/// `FOR UPDATE` does. A guard whose whole value is exhaustiveness cannot cover three quarters of
/// the cases. None is currently written anywhere in the tree; this is here so the *first* one
/// has to be bounded.
///
/// Matched case-sensitively and uppercase, which is how SQL is written throughout this workspace.
/// That is not laziness: it is what keeps ordinary Rust like `for share in [...]` from being
/// flagged, without needing to parse Rust to tell code from a query string.
///
/// No needle is a substring of another — `NO KEY ` and `KEY ` sit between the words in the long
/// forms — so they cannot shadow one another and the order here does not matter.
const ROW_LOCK_NEEDLES: &[&str] = &[
    "FOR UPDATE",
    "FOR NO KEY UPDATE",
    "FOR SHARE",
    "FOR KEY SHARE",
];

/// Clauses that make a row lock non-blocking, so a match followed by one of these is fine.
///
/// `SKIP LOCKED` steps over locked rows; `NOWAIT` errors immediately. Neither can ever hang,
/// which is the only property this guard cares about.
const NON_BLOCKING_SUFFIXES: &[&str] = &["SKIP LOCKED", "NOWAIT"];

/// Files allowed to take a **blocking** row lock, each because its wait is provably bounded.
///
/// A blocking row lock is correct and often necessary — it is what makes a read-then-write pair
/// atomic. The rule is not "never block", it is "never block *without a bound*". Adding a file
/// here is a claim that its transaction carries `lock_timeout`; say which mechanism supplies it.
const ROW_LOCK_ALLOWED: &[&str] = &[
    // Bounded via `weissman_db::set_tenant_tx`, which sets `lock_timeout` alongside the RLS GUC
    // for every tenant transaction. Both of these begin with `begin_tenant_tx`.
    "fingerprint_engine/src/council_hitl.rs",
    "fingerprint_engine/src/self_improve.rs",
    // Runs on the AUTH pool with no tenant GUC, so it cannot inherit the bound from
    // `set_tenant_tx`; it calls `advisory_lock::bound_lock_wait` explicitly right after `begin()`.
    "fingerprint_engine/src/auth_refresh.rs",
    // Contract test: deliberately takes blocking row locks to *create* the contention it
    // measures, and asserts the bound fires.
    "crates/weissman-db/tests/tenant_tx_lock_bound.rs",
    // This guard.
    "crates/weissman-db/tests/no_unbounded_lock_waits.rs",
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
                        // `.claude` holds git worktrees — full copies of this repo. Walking into them makes
            // every guarded file appear once per worktree under a path that no ALLOWED entry can
            // match, so these tests failed for anyone running the suite from the main checkout
            // with a worktree present (they passed inside a worktree, which has no nested copy).
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

/// Every `.rs` file in the workspace, paired with its workspace-relative path.
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

/// True for a line that is purely a comment. Prose in a doc comment describing the hazard is
/// fine; a real call is not.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*')
}

#[test]
fn advisory_locks_are_only_taken_through_the_bounded_helper() {
    let mut offenders = Vec::new();
    for (rel, path) in workspace_sources() {
        if ADVISORY_ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (i, line) in src.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            if line.contains(ADVISORY_NEEDLE) {
                offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "raw Postgres advisory locks found — use weissman_db::advisory_lock instead, which bounds \
         the wait with SET LOCAL lock_timeout so a contended lock fails fast rather than hanging \
         the process (see docs/TECH_DEBT_flaky_db_test_hang.md).\n\
         If a new site legitimately needs the raw statement, add it to ADVISORY_ALLOWED in \
         crates/weissman-db/tests/no_unbounded_lock_waits.rs with a comment saying why.\n\n{}",
        offenders.join("\n")
    );
}

#[test]
fn blocking_row_locks_live_only_in_reviewed_files() {
    let mut offenders = Vec::new();
    for (rel, path) in workspace_sources() {
        if ROW_LOCK_ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };

        // A lock clause is routinely split across lines inside a raw string, e.g.
        //   r#"SELECT ...
        //      FOR UPDATE SKIP LOCKED"#
        // so `SKIP LOCKED` can land on a different line from `FOR UPDATE`. Match against the
        // whole file with whitespace collapsed rather than line by line, otherwise a perfectly
        // safe `SKIP LOCKED` query gets reported as an offender.
        let code: String = src
            .lines()
            .filter(|l| !is_comment(l))
            .collect::<Vec<_>>()
            .join(" ");
        let flat = code.split_whitespace().collect::<Vec<_>>().join(" ");

        for needle in ROW_LOCK_NEEDLES {
            let mut from = 0usize;
            while let Some(hit) = flat[from..].find(needle) {
                let at = from + hit;
                let rest = flat[at + needle.len()..].trim_start();
                if !NON_BLOCKING_SUFFIXES.iter().any(|s| rest.starts_with(s)) {
                    let end = (at + needle.len() + 40).min(flat.len());
                    offenders.push(format!("{rel}: …{}…", &flat[at..end]));
                }
                from = at + needle.len();
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "blocking row locks found in files not reviewed for a lock-wait bound.\n\
         `SELECT … FOR UPDATE` waits FOREVER by default — the same defect as a raw advisory lock, \
         in different syntax (see docs/TECH_DEBT_flaky_db_test_hang.md).\n\
         Fix by either: (a) beginning the transaction with weissman_db::begin_tenant_tx, which \
         bounds every lock wait in it via set_tenant_tx; (b) calling \
         weissman_db::advisory_lock::bound_lock_wait right after begin() when there is no tenant \
         GUC; or (c) using SKIP LOCKED / NOWAIT if the work is genuinely skippable.\n\
         Then add the file to ROW_LOCK_ALLOWED in \
         crates/weissman-db/tests/no_unbounded_lock_waits.rs, saying which mechanism bounds it.\
         \n\n{}",
        offenders.join("\n")
    );
}
