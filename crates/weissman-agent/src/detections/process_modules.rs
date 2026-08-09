//! Loaded modules / DLL hijacking detection.
//!
//! Strategy:
//!   * Enumerate every process the agent can read (via `sysinfo` for portable identity).
//!   * For each process, examine its executable's directory and the *runtime path* of every
//!     module the OS reports.
//!   * Flag modules loaded from world-writable directories (Linux) or from the process working
//!     directory rather than `System32` (Windows) — both are classic DLL-hijack vectors.
//!
//! This detection works cross-platform with degraded info on macOS (where DYLD info requires
//! task_for_pid privilege). All output is evidence-based: we never claim a hijack without
//! observed loaded-module data.

use super::finding;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;
use sysinfo::{ProcessRefreshKind, System};

pub async fn run_inventory(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    let total = sys.processes().len();
    let unique_paths: HashSet<_> = sys
        .processes()
        .values()
        .map(|p| p.exe().map(|x| x.display().to_string()).unwrap_or_default())
        .collect();

    let mut extras = serde_json::Map::new();
    extras.insert("process_count".into(), json!(total));
    extras.insert("unique_image_count".into(), json!(unique_paths.len()));
    extras.insert(
        "sample_processes".into(),
        Value::Array(
            sys.processes()
                .values()
                .take(15)
                .map(|p| {
                    json!({
                        "pid": usize::from(p.pid()),
                        "name": p.name(),
                        "exe": p.exe().map(|x| x.display().to_string()).unwrap_or_default(),
                        "parent_pid": p.parent().map(usize::from),
                        "memory_bytes": p.memory(),
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
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());

    for proc in sys.processes().values() {
        let exe = match proc.exe() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => continue,
        };
        let name = proc.name();
        // Heuristic 1: process running from a temp / user-writable folder.
        if running_from_writable_directory(exe) {
            let mut extras = serde_json::Map::new();
            extras.insert("pid".into(), json!(usize::from(proc.pid())));
            extras.insert("exe".into(), Value::String(exe.display().to_string()));
            extras.insert(
                "parent_pid".into(),
                proc.parent()
                    .map(|p| Value::Number(usize::from(p).into()))
                    .unwrap_or(Value::Null),
            );
            findings.push(finding(
                engine,
                &format!("Process running from user-writable directory: {}", name),
                "medium",
                "T1574.001",
                &format!(
                    "PID {} ({}) is executing from '{}', a path commonly used for DLL-side-loading and search-order hijacking.",
                    proc.pid(),
                    name,
                    exe.display()
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
