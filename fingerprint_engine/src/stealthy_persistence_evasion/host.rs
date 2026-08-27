//! Live host-integrity collectors (Linux `/proc` + Windows-safe equivalents).
//!
//! These are **read-only** assessments of process environment, loader, memory
//! maps, persistence paths, EDR presence, and telemetry daemons. They never
//! patch ntdll, never issue raw syscalls, never inject, never disable ETW/AMSI,
//! and never install persistence.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize)]
pub struct HostSnapshot {
    pub os: &'static str,
    pub arch: &'static str,
    pub pid: u32,
    pub tracer_pid: u32,
    pub seccomp_mode: u32,
    pub nstgid: Vec<u32>,
    pub rwx_maps: usize,
    pub deleted_exe: bool,
    pub ld_preload: Vec<String>,
    pub sensitive_environ: Vec<String>,
    pub cmdline_len: usize,
    pub thread_count: usize,
    pub stack_kb: u64,
    pub libc_disk_sha256: Option<String>,
    pub libc_mapped: bool,
    pub edr_vendors: Vec<String>,
    pub persistence_paths: Vec<String>,
    pub writable_persist_paths: Vec<String>,
    pub auditd_running: bool,
    pub journald_running: bool,
    pub high_entropy_tmp: usize,
    pub self_exe_exists: bool,
    pub weissman_canaries: Vec<String>,
    pub agent_binary_bytes: Option<u64>,
}

const SENSITIVE_ENV: &[&str] = &[
    "WEISSMAN_JWT_SECRET",
    "WEISSMAN_ADMIN_PASSWORD",
    "DATABASE_URL",
    "REDIS_URL",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_CLIENT_SECRET",
    "GITHUB_TOKEN",
];

const EDR_NEEDLES: &[(&str, &str)] = &[
    ("msmpeng", "Microsoft Defender"),
    ("mssense", "Microsoft Defender for Endpoint"),
    ("csfalconservice", "CrowdStrike Falcon"),
    ("falcond", "CrowdStrike Falcon"),
    ("sentinelagent", "SentinelOne"),
    ("xagt", "Trellix"),
    ("ds_agent", "Trend Micro"),
    ("carbonblack", "Carbon Black"),
    ("sophos", "Sophos"),
];

const PERSIST_PATHS: &[&str] = &[
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/systemd/system",
    "/etc/ld.so.preload",
    "/var/spool/cron",
    "/etc/xdg/autostart",
    "/usr/lib/systemd/system",
];

pub fn collect_live() -> HostSnapshot {
    let mut snap = HostSnapshot {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        pid: std::process::id(),
        ..HostSnapshot::default()
    };

    #[cfg(target_os = "linux")]
    collect_linux(&mut snap);
    #[cfg(not(target_os = "linux"))]
    collect_generic(&mut snap);

    snap.self_exe_exists = std::env::current_exe()
        .ok()
        .map(|p| p.exists())
        .unwrap_or(false);
    if let Ok(exe) = std::env::current_exe() {
        if let Ok(meta) = std::fs::metadata(&exe) {
            snap.agent_binary_bytes = Some(meta.len());
        }
    }
    snap.weissman_canaries = find_canaries();
    snap
}

#[cfg(target_os = "linux")]
fn collect_linux(snap: &mut HostSnapshot) {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("TracerPid:") {
                snap.tracer_pid = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Seccomp:") {
                snap.seccomp_mode = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("NStgid:") {
                snap.nstgid = v
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
            } else if let Some(v) = line.strip_prefix("Threads:") {
                snap.thread_count = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("VmStk:") {
                let kb = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                snap.stack_kb = kb;
            }
        }
    }

    if let Ok(exe) = std::fs::read_link("/proc/self/exe") {
        let s = exe.to_string_lossy();
        snap.deleted_exe = s.contains("(deleted)");
    }

    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            let perms = line.split_whitespace().nth(1).unwrap_or("");
            if perms.starts_with("rwx") || perms == "rwxp" {
                snap.rwx_maps += 1;
            }
            if line.contains("libc.so") {
                snap.libc_mapped = true;
            }
        }
    }

    if let Ok(environ) = std::fs::read("/proc/self/environ") {
        for entry in environ.split(|b| *b == 0) {
            if entry.is_empty() {
                continue;
            }
            let s = String::from_utf8_lossy(entry);
            if let Some((k, _)) = s.split_once('=') {
                if k == "LD_PRELOAD" && !s.ends_with('=') {
                    snap.ld_preload.push(s.to_string());
                }
                if SENSITIVE_ENV.iter().any(|n| k == *n) {
                    snap.sensitive_environ.push(k.to_string());
                }
            }
        }
    }

    if let Ok(cmd) = std::fs::read("/proc/self/cmdline") {
        snap.cmdline_len = cmd.len();
    }

    snap.libc_disk_sha256 = hash_libc();
    snap.edr_vendors = detect_edr();
    persist_inventory(snap);
    snap.auditd_running = process_running(&["auditd"]);
    snap.journald_running = process_running(&["systemd-journald", "journald"]);
    snap.high_entropy_tmp =
        high_entropy_in("/tmp") + high_entropy_in("/var/tmp") + high_entropy_in("/dev/shm");
}

#[cfg(not(target_os = "linux"))]
fn collect_generic(snap: &mut HostSnapshot) {
    snap.edr_vendors = detect_edr();
    persist_inventory(snap);
    if let Ok(v) = std::env::var("LD_PRELOAD") {
        if !v.is_empty() {
            snap.ld_preload.push(v);
        }
    }
    for k in SENSITIVE_ENV {
        if std::env::var(k).is_ok() {
            snap.sensitive_environ.push((*k).to_string());
        }
    }
}

fn hash_libc() -> Option<String> {
    let candidates = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
        "/lib/libc.so.6",
    ];
    for p in candidates {
        if Path::new(p).is_file() {
            let bytes = std::fs::read(p).ok()?;
            let mut h = Sha256::new();
            h.update(&bytes[..bytes.len().min(64 * 1024)]);
            return Some(format!("{:x}", h.finalize()));
        }
    }
    None
}

fn detect_edr() -> Vec<String> {
    let mut vendors = Vec::new();
    #[cfg(target_os = "linux")]
    {
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return vendors;
        };
        let mut names = Vec::new();
        for ent in rd.flatten() {
            let pid = ent.file_name();
            if pid.to_str().map(|s| s.chars().all(|c| c.is_ascii_digit())) != Some(true) {
                continue;
            }
            let comm = std::fs::read_to_string(ent.path().join("comm")).unwrap_or_default();
            names.push(comm.trim().to_ascii_lowercase());
        }
        for (needle, vendor) in EDR_NEEDLES {
            if names.iter().any(|n| n.contains(needle)) && !vendors.iter().any(|v| v == vendor) {
                vendors.push((*vendor).to_string());
            }
        }
    }
    vendors
}

fn persist_inventory(snap: &mut HostSnapshot) {
    for p in PERSIST_PATHS {
        if Path::new(p).exists() {
            snap.persistence_paths.push((*p).to_string());
            if path_writable_by_self(Path::new(p)) {
                snap.writable_persist_paths.push((*p).to_string());
            }
        }
    }
}

/// True when *this process* can write the path (euid vs mode), not merely when
/// any write bit is set on the inode. Avoids flagging root-owned 0755 dirs.
fn path_writable_by_self(p: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = meta.permissions().mode();
        let (euid, egid) = self_ids();
        if euid == 0 {
            return true;
        }
        if euid == meta.uid() {
            return mode & 0o200 != 0;
        }
        if egid == meta.gid() {
            return mode & 0o020 != 0;
        }
        mode & 0o002 != 0
    }
    #[cfg(not(unix))]
    {
        !meta.permissions().readonly()
    }
}

#[cfg(unix)]
fn self_ids() -> (u32, u32) {
    let mut euid = 0u32;
    let mut egid = 0u32;
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Uid:") {
                if let Some(eff) = v.split_whitespace().nth(1) {
                    euid = eff.parse().unwrap_or(0);
                }
            } else if let Some(v) = line.strip_prefix("Gid:") {
                if let Some(eff) = v.split_whitespace().nth(1) {
                    egid = eff.parse().unwrap_or(0);
                }
            }
        }
    }
    (euid, egid)
}

fn process_running(needles: &[&str]) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return false;
        };
        for ent in rd.flatten() {
            let comm = std::fs::read_to_string(ent.path().join("comm")).unwrap_or_default();
            let n = comm.trim().to_ascii_lowercase();
            if needles.iter().any(|x| n.contains(&x.to_ascii_lowercase())) {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = needles;
        false
    }
}

fn high_entropy_in(dir: &str) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0usize;
    for ent in rd.flatten().take(80) {
        let path = ent.path();
        if !path.is_file() {
            continue;
        }
        let Ok(meta) = ent.metadata() else { continue };
        if meta.len() < 4096 || meta.len() > 2_000_000 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if shannon(&bytes[..bytes.len().min(8192)]) > 7.5 {
            n += 1;
        }
    }
    n
}

fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Weissman assessment canaries only — never third-party persistence.
fn find_canaries() -> Vec<String> {
    let mut out = Vec::new();
    for dir in ["/tmp", "/var/tmp", "/dev/shm"] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let s = name.to_string_lossy();
            if s.starts_with(".weissman-stealth-canary") || s.starts_with("weissman-stealth-canary")
            {
                out.push(ent.path().display().to_string());
            }
        }
    }
    out
}

/// Remove only Weissman-tagged assessment canaries. Never touches OS persistence.
pub fn wipe_canaries() -> HashMap<String, String> {
    let mut report = HashMap::new();
    for path in find_canaries() {
        match std::fs::remove_file(&path) {
            Ok(()) => {
                report.insert(path, "removed".into());
            }
            Err(e) => {
                report.insert(path, format!("error:{e}"));
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_snapshot_has_pid_and_os() {
        let s = collect_live();
        assert!(s.pid > 0);
        assert!(!s.os.is_empty());
        assert!(s.self_exe_exists);
    }

    #[test]
    fn shannon_uniform_is_high() {
        let bytes: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!(shannon(&bytes) > 7.9);
    }

    #[test]
    fn fail_safe_wipes_only_weissman_canaries() {
        let canary = std::path::PathBuf::from("/tmp/weissman-stealth-canary-test-0eb7");
        std::fs::write(&canary, b"assessment-canary").expect("write canary");
        assert!(canary.exists());
        let report = wipe_canaries();
        assert!(
            !canary.exists(),
            "canary still on disk after wipe: {report:?}"
        );
    }
}
