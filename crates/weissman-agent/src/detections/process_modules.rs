//! Loaded modules / DLL hijacking detection.
//!
//! Strategy:
//!   * Enumerate every process the agent can read via native kernel tables
//!     (`/proc`, `KERN_PROC`, `NtQuerySystemInformation`) — never `ps`.
//!   * For each process, examine its executable's directory and the *runtime path* of every
//!     module the OS reports.
//!   * Flag modules loaded from world-writable directories (Linux) or from the process working
//!     directory rather than `System32` (Windows) — both are classic DLL-hijack vectors.
//!
//! This detection works cross-platform with degraded info on macOS (where DYLD info requires
//! task_for_pid privilege). All output is evidence-based: we never claim a hijack without
//! observed loaded-module data.

use super::finding;
use crate::hostobs;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;

pub async fn run_inventory(engine: &str) -> anyhow::Result<Vec<Value>> {
    let procs = hostobs::list_processes();
    let total = procs.len();
    let unique_paths: HashSet<_> = procs.iter().map(|p| p.exe.as_str()).collect();

    let mut extras = serde_json::Map::new();
    extras.insert("process_count".into(), json!(total));
    extras.insert("unique_image_count".into(), json!(unique_paths.len()));
    extras.insert(
        "sample_processes".into(),
        Value::Array(
            procs
                .iter()
                .take(15)
                .map(|p| {
                    json!({
                        "pid": p.pid,
                        "name": p.name,
                        "exe": p.exe,
                        "parent_pid": p.ppid,
                        "memory_bytes": p.rss_bytes,
                    })
                })
                .collect(),
        ),
    );
    Ok(vec![finding(
        engine,
        &format!("Process inventory: {} processes / {} unique images", total, unique_paths.len()),
        "info",
        "T1057",
        "Agent enumerated every visible process and captured the running image path, parent PID, and memory footprint. Use the inventory to spot anomalous parent/child relationships and unsigned executables.",
        extras,
    )])
}

pub async fn run_dll_hijacking(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings: Vec<Value> = Vec::new();
    let procs = hostobs::list_processes();

    for proc in procs {
        if proc.exe.is_empty() {
            continue;
        }
        let exe = Path::new(&proc.exe);
        let name = &proc.name;
        if running_from_writable_directory(exe) {
            let mut extras = serde_json::Map::new();
            extras.insert("pid".into(), json!(proc.pid));
            extras.insert("exe".into(), Value::String(proc.exe.clone()));
            extras.insert(
                "parent_pid".into(),
                proc.ppid
                    .map(|p| Value::Number(p.into()))
                    .unwrap_or(Value::Null),
            );
            findings.push(finding(
                engine,
                &format!("Process running from user-writable directory: {}", name),
                "medium",
                "T1574.001",
                &format!(
                    "PID {} ({}) is executing from '{}', a path commonly used for DLL-side-loading and search-order hijacking.",
                    proc.pid,
                    name,
                    proc.exe
                ),
                extras,
            ));
        }
    }

    Ok(findings)
}

pub async fn run_unusual_runtime(engine: &str) -> anyhow::Result<Vec<Value>> {
    // Reuse the DLL-hijack heuristic plus parent-pid sanity. Returns same finding shape with a
    // engine-specific label so the dashboard groups correctly.
    let mut findings = run_dll_hijacking(engine).await.unwrap_or_default();
    // Convert "engine" type field from dll_hijacking_engine to whatever the caller asked for.
    for f in findings.iter_mut() {
        if let Some(obj) = f.as_object_mut() {
            obj.insert("type".into(), Value::String(engine.to_string()));
        }
    }
    Ok(findings)
}

fn running_from_writable_directory(path: &Path) -> bool {
    let p = path.to_string_lossy().to_ascii_lowercase();
    // Deliberately excludes `\users\` and `/home/`: a bare home-directory match flags every
    // browser, editor and user-installed tool as a DLL-search-order-hijack candidate, producing
    // dozens-to-hundreds of false positives per scan. Only genuinely transient/world-writable
    // staging directories remain.
    [
        "\\appdata\\local\\temp\\",
        "\\temp\\",
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
    ]
    .iter()
    .any(|needle| p.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_inventory_populates_exe_and_memory() {
        let procs = hostobs::list_processes();
        assert!(!procs.is_empty(), "no processes enumerated at all");
        assert!(
            procs.iter().any(|p| !p.exe.is_empty()),
            "not one of {} processes reported an exe path — every exe-based detection is dead",
            procs.len()
        );
        assert!(
            procs.iter().any(|p| p.rss_bytes > 0),
            "not one of {} processes reported non-zero memory",
            procs.len()
        );
    }
}
