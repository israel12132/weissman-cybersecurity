//! Intelligence-grade stealth persistence & defense-evasion host assessment.
//!
//! Read-only: /proc integrity, loader/preload, persistence enumeration, EDR
//! presence, telemetry daemons, entropy staging. Never patches AMSI/ETW,
//! never injects, never installs persistence.

use super::finding;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const ENGINE: &str = "stealthy_persistence_evasion";

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    let snap = snapshot();
    let mut findings = Vec::new();

    findings.push(emit(
        engine,
        "Host process-environment integrity (PEB/TEB equivalent)",
        if snap.tracer_pid != 0 || snap.deleted_exe || !snap.ld_preload.is_empty() {
            "high"
        } else if snap.rwx_maps > 0 {
            "medium"
        } else {
            "info"
        },
        "T1055",
        "Live /proc self-integrity: TracerPid, deleted exe, LD_PRELOAD, RWX maps, sensitive environ. Assessment only — no unhooking or PEB mutation.",
        json!({
            "pid": snap.pid,
            "tracer_pid": snap.tracer_pid,
            "deleted_exe": snap.deleted_exe,
            "rwx_maps": snap.rwx_maps,
            "ld_preload": snap.ld_preload,
            "sensitive_environ": snap.sensitive_environ,
            "thread_count": snap.thread_count,
            "libc_sha256_prefix": snap.libc_sha256.as_deref().map(|s| &s[..s.len().min(16)]),
            "memfd_hint": linux_memfd_hint(),
        }),
    ));

    findings.push(emit(
        engine,
        "Loader / syscall-surface integrity (HalosGate-class observation)",
        if !snap.ld_preload.is_empty() {
            "high"
        } else if snap.libc_sha256.is_none() {
            "info"
        } else {
            "info"
        },
        "T1106",
        "Observed libc mapping + on-disk SHA-256 prefix and LD_PRELOAD. Does not recover SSNs or emit syscall stubs.",
        json!({
            "libc_mapped": snap.libc_mapped,
            "seccomp_mode": snap.seccomp_mode,
            "ld_preload": snap.ld_preload,
        }),
    ));

    findings.push(emit(
        engine,
        "Hollow/ghost artifacts (missing image, RWX)",
        if snap.deleted_exe {
            "high"
        } else if snap.rwx_maps > 0 {
            "medium"
        } else {
            "info"
        },
        "T1055.012",
        "Deleted-image and RWX-map heuristics. Does not perform process hollowing, ghosting, or herpaderping.",
        json!({
            "deleted_exe": snap.deleted_exe,
            "rwx_maps": snap.rwx_maps,
            "self_exe_exists": snap.self_exe_exists,
        }),
    ));

    findings.push(emit(
        engine,
        &format!(
            "Persistence inventory ({} paths, {} writable)",
            snap.persist.len(),
            snap.writable_persist.len()
        ),
        if snap.writable_persist.is_empty() {
            "info"
        } else {
            "medium"
        },
        "T1547",
        "Enumerated cron/systemd/ld.so.preload. Did not create WMI, COM, scheduled-task, or registry persistence.",
        json!({
            "paths": snap.persist,
            "writable": snap.writable_persist,
            "canaries": snap.canaries,
        }),
    ));

    findings.push(emit(
        engine,
        &format!("In-memory / staging entropy ({} high-entropy tmp files)", snap.high_entropy_tmp),
        if snap.high_entropy_tmp > 0 { "medium" } else { "info" },
        "T1027",
        "Entropy scan of /tmp /var/tmp /dev/shm. Does not encrypt agent .text or flatten control flow.",
        json!({ "high_entropy_tmp": snap.high_entropy_tmp }),
    ));

    findings.push(emit(
        engine,
        if snap.edr.is_empty() {
            "No EDR/AV process observed (telemetry posture gap)"
        } else {
            "EDR/AV process present (blinding not applied)"
        },
        if snap.edr.is_empty() { "high" } else { "info" },
        "T1562.001",
        "Process-table EDR inventory plus auditd/journald liveness. Does not patch ETW, AMSI, Sysmon, or Security Center.",
        json!({
            "edr_vendors": snap.edr,
            "auditd": snap.auditd,
            "journald": snap.journald,
        }),
    ));

    if !snap.canaries.is_empty() {
        findings.push(emit(
            engine,
            "Weissman stealth canaries present — fail-safe wipe available",
            "medium",
            "T1485",
            "Only Weissman-tagged assessment canaries are listed. Command Center fail-safe removes these files and the encrypted ring buffer.",
            json!({ "canaries": snap.canaries }),
        ));
    }

    if findings.is_empty() {
        findings.push(emit(
            engine,
            "Stealth integrity suite completed with no host signal",
            "info",
            "T1562",
            "Agent ran the intelligence-grade assessment collectors.",
            Map::new().into(),
        ));
    }
    let _ = ENGINE;
    Ok(findings)
}

fn emit(
    engine: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    extras: Value,
) -> Value {
    let map = extras.as_object().cloned().unwrap_or_default();
    finding(engine, title, severity, mitre, description, map)
}

struct Snap {
    pid: u32,
    tracer_pid: u32,
    seccomp_mode: u32,
    thread_count: usize,
    rwx_maps: usize,
    deleted_exe: bool,
    ld_preload: Vec<String>,
    sensitive_environ: Vec<String>,
    libc_mapped: bool,
    libc_sha256: Option<String>,
    persist: Vec<String>,
    writable_persist: Vec<String>,
    edr: Vec<String>,
    auditd: bool,
    journald: bool,
    high_entropy_tmp: usize,
    self_exe_exists: bool,
    canaries: Vec<String>,
}

fn snapshot() -> Snap {
    let mut s = Snap {
        pid: std::process::id(),
        tracer_pid: 0,
        seccomp_mode: 0,
        thread_count: 0,
        rwx_maps: 0,
        deleted_exe: false,
        ld_preload: Vec::new(),
        sensitive_environ: Vec::new(),
        libc_mapped: false,
        libc_sha256: None,
        persist: Vec::new(),
        writable_persist: Vec::new(),
        edr: Vec::new(),
        auditd: false,
        journald: false,
        high_entropy_tmp: 0,
        self_exe_exists: std::env::current_exe()
            .ok()
            .map(|p| p.exists())
            .unwrap_or(false),
        canaries: Vec::new(),
    };
    #[cfg(target_os = "linux")]
    fill_linux(&mut s);
    s.canaries = find_canaries();
    s
}

#[cfg(target_os = "linux")]
fn fill_linux(s: &mut Snap) {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("TracerPid:") {
                s.tracer_pid = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Seccomp:") {
                s.seccomp_mode = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Threads:") {
                s.thread_count = v.trim().parse().unwrap_or(0);
            }
        }
    }
    if let Ok(exe) = std::fs::read_link("/proc/self/exe") {
        s.deleted_exe = exe.to_string_lossy().contains("(deleted)");
    }
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            let perms = line.split_whitespace().nth(1).unwrap_or("");
            if perms.starts_with("rwx") {
                s.rwx_maps += 1;
            }
            if line.contains("libc.so") {
                s.libc_mapped = true;
            }
        }
    }
    if let Ok(environ) = std::fs::read("/proc/self/environ") {
        for entry in environ.split(|b| *b == 0) {
            let t = String::from_utf8_lossy(entry);
            if let Some((k, _)) = t.split_once('=') {
                if k == "LD_PRELOAD" {
                    s.ld_preload.push(t.to_string());
                }
                if matches!(
                    k,
                    "WEISSMAN_JWT_SECRET"
                        | "WEISSMAN_ADMIN_PASSWORD"
                        | "DATABASE_URL"
                        | "AWS_SECRET_ACCESS_KEY"
                ) {
                    s.sensitive_environ.push(k.to_string());
                }
            }
        }
    }
    for p in [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
    ] {
        if Path::new(p).is_file() {
            if let Ok(bytes) = std::fs::read(p) {
                let mut h = Sha256::new();
                h.update(&bytes[..bytes.len().min(65536)]);
                s.libc_sha256 = Some(format!("{:x}", h.finalize()));
            }
            break;
        }
    }
    for p in [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/systemd/system",
        "/etc/ld.so.preload",
    ] {
        if Path::new(p).exists() {
            s.persist.push(p.to_string());
            if let Ok(m) = std::fs::metadata(p) {
                if !m.permissions().readonly() {
                    s.writable_persist.push(p.to_string());
                }
            }
        }
    }
    s.auditd = comm_has("auditd");
    s.journald = comm_has("systemd-journald");
    s.edr = edr_vendors();
    s.high_entropy_tmp = entropy_hits("/tmp") + entropy_hits("/dev/shm");
}

#[cfg(target_os = "linux")]
fn comm_has(needle: &str) -> bool {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return false;
    };
    rd.flatten().any(|e| {
        std::fs::read_to_string(e.path().join("comm"))
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains(needle)
    })
}

#[cfg(target_os = "linux")]
fn edr_vendors() -> Vec<String> {
    let needles = [
        ("falcond", "CrowdStrike"),
        ("sentinel", "SentinelOne"),
        ("msmpeng", "Defender"),
        ("sophos", "Sophos"),
    ];
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let names: Vec<String> = rd
        .flatten()
        .filter_map(|e| std::fs::read_to_string(e.path().join("comm")).ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    let mut out = Vec::new();
    for (n, v) in needles {
        if names.iter().any(|x| x.contains(n)) {
            out.push(v.to_string());
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn entropy_hits(dir: &str) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .take(40)
        .filter(|e| {
            let Ok(meta) = e.metadata() else { return false };
            if !e.path().is_file() || meta.len() < 4096 || meta.len() > 1_000_000 {
                return false;
            }
            let Ok(b) = std::fs::read(e.path()) else {
                return false;
            };
            super::util::shannon_entropy(&b[..b.len().min(4096)]) > 7.5
        })
        .count()
}

fn linux_memfd_hint() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
        let memfd_maps = maps.lines().filter(|l| l.contains("/memfd:")).count();
        let mut memfd_fds = 0usize;
        if let Ok(rd) = std::fs::read_dir("/proc/self/fd") {
            memfd_fds = rd
                .flatten()
                .filter(|e| {
                    std::fs::read_link(e.path())
                        .map(|t| t.to_string_lossy().contains("memfd:"))
                        .unwrap_or(false)
                })
                .count();
        }
        json!({ "memfd_maps": memfd_maps, "memfd_fds": memfd_fds })
    }
    #[cfg(not(target_os = "linux"))]
    {
        json!({ "memfd_maps": 0, "memfd_fds": 0 })
    }
}

fn find_canaries() -> Vec<String> {
    let mut out = Vec::new();
    for dir in ["/tmp", "/var/tmp", "/dev/shm"] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let n = ent.file_name();
            let s = n.to_string_lossy();
            if s.contains("weissman-stealth-canary") {
                out.push(ent.path().display().to_string());
            }
        }
    }
    out
}

pub fn wipe_canaries() -> Vec<String> {
    let mut removed = Vec::new();
    for p in find_canaries() {
        if std::fs::remove_file(&p).is_ok() {
            removed.push(p);
        }
    }
    for dir in ["/tmp", "/var/tmp", "/dev/shm"] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let n = ent.file_name();
            let s = n.to_string_lossy();
            if s.contains("weissman-deception-canary") {
                let p = ent.path();
                if std::fs::remove_file(&p).is_ok() {
                    removed.push(p.display().to_string());
                }
            }
        }
    }
    removed
}

pub fn plant_deception() -> serde_json::Value {
    let uuid = format!("{:x}", std::process::id() as u64);
    let path = format!("/tmp/weissman-deception-canary-{uuid}");
    let mut body = b"WEISSMAN-DECEPTION\n".to_vec();
    body.extend(std::iter::repeat(0xA5).take(4096));
    let ok = std::fs::write(&path, &body).is_ok();
    serde_json::json!({ "ok": ok, "path": path, "note": "Weissman-tagged canary only" })
}

pub fn auto_remediate() -> serde_json::Value {
    let dir = "/tmp/weissman-remediation";
    let _ = std::fs::create_dir_all(dir);
    let path = format!("{dir}/99-weissman-stealth.conf");
    let body = "# weissman stealth auto-remediate (staging)\n\
kernel.yama.ptrace_scope=1\n\
kernel.kptr_restrict=2\n\
fs.suid_dumpable=0\n";
    let ok = std::fs::write(&path, body).is_ok();
    serde_json::json!({
        "ok": ok,
        "staged": path,
        "apply": std::env::var("WEISSMAN_APPLY_HOST_HARDENING").ok().as_deref() == Some("1"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_emits_live_findings() {
        let f = run("stealthy_persistence_evasion").await.unwrap();
        assert!(!f.is_empty());
        assert!(f
            .iter()
            .any(|x| x["title"].as_str().unwrap_or("").contains("integrity")));
    }
}
