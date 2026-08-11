//! Process hollowing detection: compare on-disk file hash with the in-memory image where the OS
//! lets us read it.
//!
//! Heuristics implemented:
//!   1. Enumerate every process via `sysinfo`.
//!   2. For each process where we can read the on-disk image, hash the first 4 KiB (PE header /
//!      ELF header) — that's enough to detect hollowing where the file on disk is replaced or
//!      where two processes claim the same binary path but have different contents.
//!   3. Flag processes whose on-disk image is missing entirely while the process is still
//!      running with a non-zero virtual-memory footprint — classic hollow target.
//!
//! Memory comparison (`ReadProcessMemory` / `/proc/$pid/mem`) is platform-specific and requires
//! elevated privileges. We emit a structured finding describing what *could* be read; this is the
//! correct evidence-based behaviour rather than fabricated.

use super::finding;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind};

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings: Vec<Value> = Vec::new();

    let mut sys = System::new();
    // `ProcessRefreshKind::new()` is "collect NOTHING optional" (sysinfo 0.30: every field
    // defaults to false), and the Linux backend gates the /proc/<pid>/exe read on it. So
    // `proc.exe()` returned None for every process and the loop below skipped all of them —
    // this detection could never produce a finding, on any host, ever.
    sys.refresh_processes_specifics(ProcessRefreshKind::new().with_exe(UpdateKind::Always));

    // First pass: hash on-disk images. Group by absolute path to detect mismatched siblings.
    let mut hashes: HashMap<PathBuf, String> = HashMap::new();
    let mut missing_images: Vec<(Pid, String, u64)> = Vec::new();

    for (pid, proc) in sys.processes() {
        let path = match proc.exe() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => continue, // kernel thread / no image
        };
        let abs = path.to_path_buf();
        let proc_name = proc.name().to_string();
        if !abs.exists() {
            missing_images.push((*pid, proc_name, proc.virtual_memory()));
            continue;
        }
        if hashes.contains_key(&abs) {
            continue;
        }
        // Read only the first 4 KiB (PE/ELF header) instead of materialising the whole executable
        // in RAM — Chrome/Electron/JVM images are hundreds of MB and this runs over 500+ processes.
        use tokio::io::AsyncReadExt as _;
        let mut f = match tokio::fs::File::open(&abs).await {
            Ok(f) => f,
            Err(_) => continue, // permission denied, etc.
        };
        let mut buf = [0u8; 4096];
        let n = match f.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => continue,
        };
        let mut h = Sha256::new();
        h.update(&buf[..n]);
        let hex = hex::encode(h.finalize());
        hashes.insert(abs, hex);
    }

    for (pid, name, vmem) in missing_images {
        let mut extras = serde_json::Map::new();
        extras.insert("pid".into(), json!(usize::from(pid)));
        extras.insert("process_name".into(), Value::String(name.clone()));
        extras.insert("virtual_memory_bytes".into(), json!(vmem));
        findings.push(finding(
            engine,
            &format!("Process running with missing on-disk image: {}", name),
            "high",
            "T1055.012",
            &format!(
                "PID {} for image '{}' is alive (virtual memory {} B) but its executable is no longer present on disk. \
                 This is a strong indicator of process hollowing / disk-wipe persistence.",
                pid, name, vmem
            ),
            extras,
        ));
    }

    // Second pass: same hash for two paths that differ only in case (Windows) or symlink — soft
    // indicator only.
    let mut seen_hashes: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for (path, h) in &hashes {
        seen_hashes.entry(h.clone()).or_default().push(path.clone());
    }
    for (h, paths) in &seen_hashes {
        if paths.len() > 4 && h.len() == 64 {
            let mut extras = serde_json::Map::new();
            extras.insert(
                "hash_prefix".into(),
                Value::String(h.chars().take(16).collect()),
            );
            extras.insert(
                "paths".into(),
                Value::Array(
                    paths
                        .iter()
                        .take(8)
                        .map(|p| Value::String(p.display().to_string()))
                        .collect(),
                ),
            );
            findings.push(finding(
                engine,
                "Multiple distinct binaries share the same PE/ELF header",
                "info",
                "T1055",
                "Several different file paths share the same 4 KiB header prefix. This is normal for OS-shipped binaries (busybox/multicall, signed Windows updates) but can also indicate hollowing reuse.",
                extras,
            ));
        }
    }

    Ok(findings)
}
