//! Privilege Escalation & Credential Access — host-resident auditor.
//!
//! Read-only. Enumerates W^X maps, identity-daemon exposure, sudo/UAC posture,
//! credential *store existence* (never decrypts). Windows LSA/UAC values are
//! read in-process via Win32 `RegOpenKeyExW` — never `reg.exe`.
//! Per-PID `/proc` reads verify starttime before and after to defeat PID reuse.

use super::finding;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(windows)]
mod win_registry {
    include!("win_registry.rs");
}

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    tokio::task::spawn_blocking({
        let engine = engine.to_string();
        move || collect(&engine)
    })
    .await
    .map_err(|e| anyhow::anyhow!("priv_esc_cred join: {e}"))?
}

fn collect(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    maps_wx(engine, &mut findings);
    identity_and_cred(engine, &mut findings);
    priv_surface(engine, &mut findings);
    #[cfg(windows)]
    windows_lsa_uac(engine, &mut findings);
    if findings.is_empty() {
        findings.push(finding(
            engine,
            "Privilege/credential host audit completed — no failed controls on this OS sample",
            "info",
            "T1068",
            "Agent enumerated maps, identity daemons, sudo/docker, and credential-store modes. Windows LSA/UAC is Win32 registry, never reg.exe.",
            Map::new(),
        ));
    }
    Ok(findings)
}

fn maps_wx(engine: &str, findings: &mut Vec<Value>) {
    let Ok(text) = fs::read_to_string("/proc/self/maps") else {
        return;
    };
    let rwx: Vec<&str> = text
        .lines()
        .filter(|l| {
            l.split_whitespace()
                .nth(1)
                .is_some_and(|p| p.starts_with("rwx"))
        })
        .collect();
    if rwx.is_empty() {
        findings.push(finding(
            engine,
            "PAC-012 No RWX mappings in the agent process",
            "info",
            "T1106",
            "Agent parsed /proc/self/maps; no rwx pages (W^X held).",
            json_map(json!({ "check_id": 12, "maps_ok": true })),
        ));
    } else {
        findings.push(finding(
            engine,
            "PAC-012 RWX memory pages in the agent process",
            "critical",
            "T1106",
            "RWX pages are the Hell's Gate / reflective-stub pattern. The auditor flags them; it does not allocate them.",
            json_map(json!({
                "check_id": 12,
                "sample": rwx.iter().take(8).copied().collect::<Vec<_>>(),
            })),
        ));
    }
}

fn identity_and_cred(engine: &str, findings: &mut Vec<Value>) {
    if let Ok(meta) = fs::metadata("/etc/shadow") {
        let readable = fs::File::open("/etc/shadow").is_ok();
        let mode = file_mode(&meta);
        if readable {
            findings.push(finding(
                engine,
                "PAC-301 /etc/shadow is readable by the agent",
                "critical",
                "T1003.002",
                "SAM/shadow analog is readable — drop privileges.",
                json_map(json!({ "check_id": 301, "mode": format!("{mode:04o}") })),
            ));
        }
    }
    if path_writable("/var/run/docker.sock") {
        findings.push(finding(
            engine,
            "PAC-108 docker.sock is writable — container-to-host privilege path",
            "critical",
            "T1610",
            "Writable docker.sock is a potato-class analog.",
            json_map(json!({ "check_id": 108 })),
        ));
    }
    if let Some(v) = sysctl_u8("/proc/sys/kernel/yama/ptrace_scope") {
        if v == 0 {
            findings.push(finding(
                engine,
                "PAC-052 yama.ptrace_scope=0 — LSASS-class memory is ptraceable",
                "high",
                "T1003.001",
                "Enable kernel.yama.ptrace_scope=1 or 2 (RunAsPPL analog).",
                json_map(json!({ "check_id": 52, "ptrace_scope": v })),
            ));
        }
    }
    scan_procs_toctou(engine, findings);
}

fn scan_procs_toctou(engine: &str, findings: &mut Vec<Value>) {
    let Ok(rd) = fs::read_dir("/proc") else {
        return;
    };
    let mut recycled = 0u32;
    for ent in rd.flatten().take(4096) {
        let pid: u32 = match ent.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        match read_comm_stable(pid) {
            CommRead::Ok(Some(comm)) => {
                let c = comm.trim().to_ascii_lowercase();
                if ["mimikatz", "lazagne", "procdump", "sharphound"]
                    .iter()
                    .any(|n| c.contains(n))
                {
                    findings.push(finding(
                        engine,
                        &format!("PAC-064 credential-theft process: {c}"),
                        "high",
                        "T1003.001",
                        "Process name matched a credential-theft tool. starttime was verified before and after the comm read.",
                        json_map(json!({ "check_id": 64, "pid": pid, "comm": c })),
                    ));
                }
            }
            CommRead::Ok(None) | CommRead::Missing => {}
            CommRead::Recycled => recycled += 1,
        }
    }
    if recycled > 0 {
        findings.push(finding(
            engine,
            &format!("PAC-030 {recycled} PID(s) recycled mid-read (TOCTOU)"),
            "medium",
            "T1106",
            "starttime changed between /proc/<pid>/stat samples; those rows were discarded.",
            json_map(json!({ "check_id": 30, "recycled": recycled })),
        ));
    }
}

/// Field 22 of `/proc/<pid>/stat` (ticks since boot). Parse after the last `)`
/// because `comm` may contain spaces.
fn parse_stat_starttime(stat: &str) -> Option<u64> {
    let rparen = stat.rfind(')')?;
    stat.get(rparen + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

enum CommRead {
    Ok(Option<String>),
    Recycled,
    Missing,
}

fn read_comm_stable(pid: u32) -> CommRead {
    let before = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s,
        Err(_) => return CommRead::Missing,
    };
    let t0 = match parse_stat_starttime(&before) {
        Some(t) => t,
        None => return CommRead::Missing,
    };
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok();
    let after = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s,
        Err(_) => return CommRead::Recycled,
    };
    let t1 = match parse_stat_starttime(&after) {
        Some(t) => t,
        None => return CommRead::Recycled,
    };
    if t0 != t1 {
        return CommRead::Recycled;
    }
    CommRead::Ok(comm)
}

fn priv_surface(engine: &str, findings: &mut Vec<Value>) {
    for path in ["/etc/sudoers", "/etc/sudoers.d"] {
        let p = Path::new(path);
        if p.is_file() {
            if let Ok(text) = fs::read_to_string(p) {
                if text
                    .lines()
                    .any(|l| l.contains("NOPASSWD") && !l.trim().starts_with('#'))
                {
                    findings.push(finding(
                        engine,
                        "PAC-200 NOPASSWD sudo — UAC analog is off",
                        "high",
                        "T1548.002",
                        "Require a credential prompt.",
                        json_map(json!({ "check_id": 200 })),
                    ));
                    break;
                }
            }
        }
    }
    let home = std::env::var("HOME").ok().map(PathBuf::from);
    if let Some(home) = home {
        for p in [
            home.join(".ssh/id_ed25519"),
            home.join(".aws/credentials"),
            home.join(".docker/config.json"),
        ] {
            if let Ok(meta) = fs::metadata(&p) {
                if !meta.is_file() {
                    continue;
                }
                let mode = file_mode(&meta);
                findings.push(finding(
                    engine,
                    &format!("PAC-302 credential store present: {}", p.display()),
                    if mode & 0o004 != 0 { "high" } else { "medium" },
                    "T1555",
                    "Store exists (contents not collected).",
                    json_map(json!({ "check_id": 302, "mode": format!("{mode:04o}") })),
                ));
            }
        }
    }
}

#[cfg(windows)]
fn windows_lsa_uac(engine: &str, findings: &mut Vec<Value>) {
    for (_key, name, title, result) in win_registry::uac_lsa_wdigest() {
        match result {
            Ok(v) => {
                let (sev, desc) = match name {
                    "EnableLUA" if v != 1 => ("high", "EnableLUA must be 1"),
                    "ConsentPromptBehaviorAdmin" if v < 2 => (
                        "high",
                        "Always Notify requires ConsentPromptBehaviorAdmin=2",
                    ),
                    "PromptOnSecureDesktop" if v != 1 => {
                        ("high", "PromptOnSecureDesktop must be 1")
                    }
                    "RunAsPPL" if v == 0 => ("high", "LSASS RunAsPPL is off"),
                    "UseLogonCredential" if v == 1 => ("critical", "WDigest cleartext is enabled"),
                    _ => ("info", "registry DWORD observed via Win32 API"),
                };
                findings.push(finding(
                    engine,
                    &format!("{title}={v}"),
                    sev,
                    "T1548.002",
                    desc,
                    json_map(json!({ "value": v, "via": "RegQueryValueExW" })),
                ));
            }
            Err(e) => findings.push(finding(
                engine,
                &format!("{title} unreadable"),
                "medium",
                "T1548.002",
                &e,
                json_map(json!({ "via": "RegQueryValueExW" })),
            )),
        }
    }
}

fn json_map(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

fn file_mode(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0o600
    }
}

fn path_writable(path: &str) -> bool {
    use std::fs::OpenOptions;
    OpenOptions::new().write(true).open(path).is_ok()
}

fn sysctl_u8(path: &str) -> Option<u8> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_starttime_with_spaces_in_comm() {
        let mut fields = vec!["S"; 19];
        fields.push("777");
        let line = format!("9 (a b c) {}", fields.join(" "));
        assert_eq!(parse_stat_starttime(&line), Some(777));
    }

    #[test]
    fn source_never_spawns_reg_exe() {
        let src = include_str!("priv_esc_cred.rs");
        let spawn = ["Command::new(", "\"reg\")"].concat();
        assert!(!src.contains(&spawn));
        let win = include_str!("win_registry.rs");
        assert!(win.contains("RegOpenKeyExW"));
        assert!(win.contains("RegQueryValueExW"));
        assert!(!win.contains("Command::new"));
    }

    #[tokio::test]
    async fn collect_runs() {
        let f = run("privilege_escalation_credential_access")
            .await
            .expect("agent auditor");
        assert!(!f.is_empty());
    }
}
