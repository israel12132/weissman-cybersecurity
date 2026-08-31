//! Live host snapshot for privilege-escalation and credential-access **auditing**.
//!
//! Read-only. Never dumps secrets, never attaches to LSASS, never allocates RWX
//! stubs, never executes a UAC bypass. Per-PID `/proc` reads go through
//! [`super::proc_guard::with_stable_pid`] so a recycled PID cannot be scored
//! with another process's maps.

use super::eval::{apply, CheckStatus, Coverage};
use super::proc_guard::{with_stable_pid, PidRead};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Default)]
pub struct HostSnapshot {
    pub os: String,
    pub kernel: String,
    pub hostname: String,
    pub uid: u32,
    pub euid: u32,
    pub rwx_maps: Vec<String>,
    pub anon_exec_maps: Vec<String>,
    pub nx_stack: Option<bool>,
    pub ptrace_scope: Option<u8>,
    pub kptr_restrict: Option<u8>,
    pub dmesg_restrict: Option<u8>,
    pub unprivileged_bpf: Option<u8>,
    pub unprivileged_userns: Option<u8>,
    pub lockdown: Option<String>,
    pub secure_boot: Option<bool>,
    pub tainted: Option<String>,
    pub shadow_readable: bool,
    pub shadow_mode: Option<u32>,
    pub docker_sock_writable: bool,
    pub sudo_nopasswd: Vec<String>,
    pub world_writable_units: Vec<String>,
    pub tmp_services: Vec<String>,
    pub cred_hits: Vec<CredHit>,
    pub leak_paths: Vec<String>,
    pub suspicious_procs: Vec<String>,
    pub identity_daemons: Vec<String>,
    pub recycled_pids: u32,
    pub kernel_modules: Vec<String>,
    pub exe_sha384: Option<String>,
    pub cpu_pct: f32,
    pub rss_bytes: u64,
    pub auditd_running: bool,
    pub cap_effective: String,
    pub se_debug_analog: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone)]
pub struct CredHit {
    pub category: &'static str,
    pub path: String,
    pub mode: u32,
    pub readable: bool,
    pub world_readable: bool,
}

const SUSPICIOUS_PROCS: &[&str] = &[
    "mimikatz",
    "pypykatz",
    "lazagne",
    "procdump",
    "lsassy",
    "nanodump",
    "pplkiller",
    "juicypotato",
    "godpotato",
    "roguepotato",
    "sharpup",
    "rubeus",
    "sharphound",
    "bloodhound",
    "secretsdump",
    "psexec",
];
const IDENTITY_DAEMONS: &[&str] = &["lsass", "sssd", "winbind", "lightdm", "gdm", "kwalletd"];

pub fn collect() -> HostSnapshot {
    let started = Instant::now();
    let mut s = HostSnapshot {
        os: std::env::consts::OS.to_string(),
        kernel: uname_kernel(),
        hostname: hostname(),
        uid: current_uid(),
        euid: current_euid(),
        ..HostSnapshot::default()
    };
    parse_maps(&mut s);
    scan_foreign_maps(&mut s);
    s.nx_stack = elf_nx_stack(Path::new("/proc/self/exe"));
    s.ptrace_scope = sysctl_u8("/proc/sys/kernel/yama/ptrace_scope");
    s.kptr_restrict = sysctl_u8("/proc/sys/kernel/kptr_restrict");
    s.dmesg_restrict = sysctl_u8("/proc/sys/kernel/dmesg_restrict");
    s.unprivileged_bpf = sysctl_u8("/proc/sys/kernel/unprivileged_bpf_disabled");
    s.unprivileged_userns = sysctl_u8("/proc/sys/kernel/unprivileged_userns_clone");
    s.lockdown = read_trimmed("/sys/kernel/security/lockdown");
    s.secure_boot = detect_secure_boot();
    s.tainted = read_trimmed("/proc/sys/kernel/tainted");
    inspect_shadow(&mut s);
    s.docker_sock_writable = path_writable("/var/run/docker.sock");
    s.sudo_nopasswd = scan_sudo_nopasswd();
    scan_systemd(&mut s);
    scan_cred_stores(&mut s);
    scan_leak_snippets(&mut s);
    scan_proc_comms(&mut s);
    s.kernel_modules = list_modules();
    s.exe_sha384 = hash_self_exe();
    s.cap_effective = read_status_field("CapEff").unwrap_or_default();
    s.se_debug_analog = s.euid == 0 || cap_bit_set(&s.cap_effective, 19);
    s.auditd_running = comm_running("auditd") || Path::new("/var/run/auditd.pid").exists();
    let (cpu, rss) = self_cpu_rss();
    s.cpu_pct = cpu;
    s.rss_bytes = rss;
    s.elapsed_ms = started.elapsed().as_millis() as u64;
    s
}

pub fn apply_snapshot(cov: &mut Coverage, snap: &HostSnapshot) {
    if snap.rwx_maps.is_empty() {
        apply(
            cov,
            &[12, 17, 19, 33],
            CheckStatus::Pass,
            "no rwx mappings in /proc/self/maps",
        );
    } else {
        apply(
            cov,
            &[12, 17, 19, 33],
            CheckStatus::Fail,
            &format!("RWX mappings: {}", snap.rwx_maps.join(", ")),
        );
    }
    if snap.anon_exec_maps.is_empty() {
        apply(
            cov,
            &[1, 11, 21, 41, 43, 50],
            CheckStatus::Pass,
            "no anonymous executable stub pages (Hell's Gate / Halo's Gate style allocs absent)",
        );
    } else {
        apply(
            cov,
            &[1, 11, 21, 41, 43],
            CheckStatus::Fail,
            &format!(
                "anonymous executable pages: {}",
                snap.anon_exec_maps.join(", ")
            ),
        );
    }
    match snap.nx_stack {
        Some(true) => apply(cov, &[12, 19], CheckStatus::Pass, "PT_GNU_STACK is NX"),
        Some(false) => apply(
            cov,
            &[12, 19],
            CheckStatus::Fail,
            "PT_GNU_STACK is executable",
        ),
        None => apply(
            cov,
            &[12],
            CheckStatus::NotObserved,
            "ELF GNU_STACK not parsed",
        ),
    }
    if let Some(k) = snap.kptr_restrict {
        if k == 0 {
            apply(cov, &[20, 23, 47], CheckStatus::Fail, "kptr_restrict=0");
        } else {
            apply(
                cov,
                &[20, 23, 47],
                CheckStatus::Pass,
                &format!("kptr_restrict={k}"),
            );
        }
    }
    apply(
        cov,
        &[48],
        CheckStatus::Pass,
        &format!("kernel={} os={}", snap.kernel, snap.os),
    );
    if let Some(ref h) = snap.exe_sha384 {
        apply(
            cov,
            &[9, 40],
            CheckStatus::Pass,
            &format!("self SHA-384={h}"),
        );
    }
    apply(
        cov,
        &[10, 22, 42],
        CheckStatus::Pass,
        "this engine never resolves SSNs via GetProcAddress and never prints syscall numbers",
    );
    if snap.auditd_running {
        apply(cov, &[27], CheckStatus::Pass, "auditd/ETW analog present");
    } else {
        apply(cov, &[27], CheckStatus::Fail, "auditd not observed");
    }
    if snap.recycled_pids > 0 {
        apply(
            cov,
            &[30, 45],
            CheckStatus::Fail,
            &format!(
                "{} PID(s) recycled mid-read (TOCTOU); rows discarded",
                snap.recycled_pids
            ),
        );
    } else {
        apply(
            cov,
            &[30],
            CheckStatus::Pass,
            "PID starttime stable across /proc reads",
        );
    }

    if snap.identity_daemons.is_empty() {
        apply(
            cov,
            &[51, 96],
            CheckStatus::NotObserved,
            "no LSASS/sssd/winbind process on this host",
        );
    } else {
        apply(
            cov,
            &[51],
            CheckStatus::Pass,
            &format!("identity daemons: {}", snap.identity_daemons.join(", ")),
        );
    }
    match snap.ptrace_scope {
        Some(0) => apply(
            cov,
            &[16, 51, 52, 61, 63],
            CheckStatus::Fail,
            "yama.ptrace_scope=0",
        ),
        Some(v) => apply(
            cov,
            &[16, 51, 52, 61],
            CheckStatus::Pass,
            &format!("yama.ptrace_scope={v}"),
        ),
        None => apply(cov, &[51, 52], CheckStatus::Na, "ptrace_scope not present"),
    }
    if snap.shadow_readable {
        apply(
            cov,
            &[60, 92, 301],
            CheckStatus::Fail,
            &format!(
                "/etc/shadow readable by uid={} mode={:?}",
                snap.uid, snap.shadow_mode
            ),
        );
    } else {
        apply(
            cov,
            &[60, 92, 98, 301],
            CheckStatus::Pass,
            "/etc/shadow is not readable by the scanner",
        );
    }
    if snap.suspicious_procs.is_empty() {
        apply(
            cov,
            &[64, 83, 93, 313, 318, 324, 348],
            CheckStatus::Pass,
            "no Mimikatz/LaZagne/SharpHound-class processes",
        );
    } else {
        apply(
            cov,
            &[64, 83, 93, 324, 348],
            CheckStatus::Fail,
            &format!(
                "credential-theft tooling: {}",
                snap.suspicious_procs.join(", ")
            ),
        );
    }
    match snap.lockdown.as_deref() {
        Some(v) if v.contains("[none]") || v.trim() == "none" => apply(
            cov,
            &[65, 94, 261, 267],
            CheckStatus::Fail,
            &format!("kernel lockdown={v}"),
        ),
        Some(v) => apply(
            cov,
            &[65, 94, 261, 267],
            CheckStatus::Pass,
            &format!("kernel lockdown={v}"),
        ),
        None => apply(
            cov,
            &[65, 261],
            CheckStatus::NotObserved,
            "lockdown sysfs node absent",
        ),
    }

    if snap.se_debug_analog {
        apply(
            cov,
            &[37, 104, 150],
            CheckStatus::Fail,
            &format!(
                "scanner uid={} euid={} CapEff={}",
                snap.uid, snap.euid, snap.cap_effective
            ),
        );
    } else {
        apply(
            cov,
            &[37, 104, 150],
            CheckStatus::Pass,
            "scanner is not root and lacks CAP_SYS_PTRACE",
        );
    }
    if snap.docker_sock_writable {
        apply(
            cov,
            &[108, 114, 149],
            CheckStatus::Fail,
            "/var/run/docker.sock is writable",
        );
    } else {
        apply(
            cov,
            &[108, 114],
            CheckStatus::Pass,
            "docker.sock is not writable by this process",
        );
    }
    if snap.sudo_nopasswd.is_empty() {
        apply(
            cov,
            &[183, 200],
            CheckStatus::Pass,
            "no NOPASSWD sudo (UAC analog on)",
        );
    } else {
        apply(
            cov,
            &[183, 200, 163],
            CheckStatus::Fail,
            &format!("NOPASSWD: {}", snap.sudo_nopasswd.join("; ")),
        );
    }

    if snap.tmp_services.is_empty() {
        apply(
            cov,
            &[206],
            CheckStatus::Pass,
            "no systemd units ExecStart from /tmp",
        );
    } else {
        apply(
            cov,
            &[206],
            CheckStatus::Fail,
            &format!("tmp services: {}", snap.tmp_services.join(", ")),
        );
    }
    if snap.world_writable_units.is_empty() {
        apply(
            cov,
            &[201, 217, 236],
            CheckStatus::Pass,
            "service units are not world-writable",
        );
    } else {
        apply(
            cov,
            &[201, 217, 236],
            CheckStatus::Fail,
            &format!(
                "world-writable units: {}",
                snap.world_writable_units.join(", ")
            ),
        );
    }

    match snap.secure_boot {
        Some(true) => apply(
            cov,
            &[251, 279, 267],
            CheckStatus::Pass,
            "Secure Boot analog present",
        ),
        Some(false) => apply(
            cov,
            &[251, 279],
            CheckStatus::Fail,
            "Secure Boot analog off",
        ),
        None => apply(
            cov,
            &[279],
            CheckStatus::NotObserved,
            "EFI SecureBoot var absent",
        ),
    }
    if let Some(b) = snap.unprivileged_bpf {
        if b == 0 {
            apply(
                cov,
                &[255, 266],
                CheckStatus::Fail,
                "unprivileged_bpf_disabled=0",
            );
        } else {
            apply(
                cov,
                &[255, 266],
                CheckStatus::Pass,
                &format!("unprivileged_bpf_disabled={b}"),
            );
        }
    }
    let bad_mod = snap.kernel_modules.iter().any(|m| is_loldriver(m));
    if bad_mod {
        apply(
            cov,
            &[253, 262, 300],
            CheckStatus::Fail,
            &format!("BYOVD-class module name: {}", snap.kernel_modules.join(",")),
        );
    } else if snap.kernel_modules.is_empty() {
        apply(
            cov,
            &[253, 300],
            CheckStatus::NotObserved,
            "module list empty",
        );
    } else {
        apply(
            cov,
            &[253, 300],
            CheckStatus::Pass,
            &format!(
                "{} modules, no known-vulnerable names",
                snap.kernel_modules.len()
            ),
        );
    }

    let world_creds: Vec<_> = snap.cred_hits.iter().filter(|c| c.world_readable).collect();
    if world_creds.is_empty() {
        apply(
            cov,
            &[302, 307, 326],
            CheckStatus::Pass,
            "no world-readable credential stores observed",
        );
    } else {
        apply(
            cov,
            &[302, 307, 326, 347],
            CheckStatus::Fail,
            &format!(
                "world-readable stores (contents not collected): {}",
                world_creds
                    .iter()
                    .map(|c| c.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    if snap.leak_paths.is_empty() {
        apply(
            cov,
            &[304],
            CheckStatus::Pass,
            "no password= keys in scanned config snippets",
        );
    } else {
        apply(
            cov,
            &[304, 347],
            CheckStatus::Fail,
            &format!("leak keys in: {}", snap.leak_paths.join(", ")),
        );
    }

    if snap.cpu_pct > 90.0 {
        apply(
            cov,
            &[357, 400],
            CheckStatus::Fail,
            &format!("scanner cpu_pct={:.1} (Performance Guard)", snap.cpu_pct),
        );
    } else {
        apply(
            cov,
            &[357, 400],
            CheckStatus::Pass,
            &format!("scanner cpu_pct={:.1} rss={}", snap.cpu_pct, snap.rss_bytes),
        );
    }
}

pub fn snapshot_json(s: &HostSnapshot) -> Value {
    json!({
        "os": s.os, "kernel": s.kernel, "hostname": s.hostname,
        "uid": s.uid, "euid": s.euid,
        "rwx_maps": s.rwx_maps.len(), "anon_exec_maps": s.anon_exec_maps.len(),
        "nx_stack": s.nx_stack, "ptrace_scope": s.ptrace_scope,
        "kptr_restrict": s.kptr_restrict, "lockdown": s.lockdown,
        "secure_boot": s.secure_boot, "shadow_readable": s.shadow_readable,
        "docker_sock_writable": s.docker_sock_writable,
        "sudo_nopasswd": s.sudo_nopasswd,
        "cred_stores": s.cred_hits.iter().map(|c| json!({"path": c.path, "category": c.category, "mode": format!("{:04o}", c.mode), "readable": c.readable, "world_readable": c.world_readable})).collect::<Vec<_>>(),
        "suspicious_procs": s.suspicious_procs,
        "identity_daemons": s.identity_daemons,
        "recycled_pids": s.recycled_pids,
        "exe_sha384": s.exe_sha384,
        "cpu_pct": s.cpu_pct, "rss_bytes": s.rss_bytes,
        "elapsed_ms": s.elapsed_ms,
    })
}

fn parse_maps(s: &mut HostSnapshot) {
    let Ok(text) = fs::read_to_string("/proc/self/maps") else {
        return;
    };
    ingest_maps_lines(s, None, &text);
}

/// Sample other PIDs' `/proc/<pid>/maps` under a starttime TOCTOU bracket.
/// Recycled PIDs are discarded — never scored against a previous process's maps.
fn scan_foreign_maps(s: &mut HostSnapshot) {
    let Ok(rd) = fs::read_dir("/proc") else {
        return;
    };
    let self_pid = std::process::id();
    let deadline = Instant::now() + Duration::from_millis(800);
    let mut sampled = 0u32;
    for ent in rd.flatten() {
        if sampled >= 128 || Instant::now() > deadline {
            break;
        }
        let pid: u32 = match ent.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid == self_pid {
            continue;
        }
        sampled += 1;
        match with_stable_pid(pid, || fs::read_to_string(ent.path().join("maps")).ok()) {
            PidRead::Ok(Some(text)) => ingest_maps_lines(s, Some(pid), &text),
            PidRead::Recycled => {
                s.recycled_pids = s.recycled_pids.saturating_add(1);
            }
            PidRead::Ok(None) | PidRead::Missing => {}
        }
    }
}

fn ingest_maps_lines(s: &mut HostSnapshot, pid: Option<u32>, text: &str) {
    let prefix = pid.map(|p| format!("pid={p} ")).unwrap_or_default();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let _range = parts.next();
        let perms = parts.next().unwrap_or("");
        let path = parts.last().unwrap_or("");
        if perms.starts_with("rwx") {
            s.rwx_maps.push(format!(
                "{prefix}{}",
                line.chars().take(120).collect::<String>()
            ));
        }
        if perms.contains('x')
            && (path.is_empty() || path.starts_with('[') || path == "0")
            && (perms.contains('w') || path == "[anon]" || path.is_empty())
        {
            s.anon_exec_maps.push(format!(
                "{prefix}{}",
                line.chars().take(120).collect::<String>()
            ));
        }
    }
}

fn elf_nx_stack(path: &Path) -> Option<bool> {
    let mut f = fs::File::open(path).ok()?;
    let mut hdr = [0u8; 64];
    f.read_exact(&mut hdr).ok()?;
    if hdr[0..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    let class = hdr[4];
    let (phoff, phentsize, phnum): (u64, usize, usize) = if class == 2 {
        (
            u64::from_le_bytes(hdr[32..40].try_into().ok()?),
            u16::from_le_bytes(hdr[54..56].try_into().ok()?) as usize,
            u16::from_le_bytes(hdr[56..58].try_into().ok()?) as usize,
        )
    } else if class == 1 {
        (
            u32::from_le_bytes(hdr[28..32].try_into().ok()?) as u64,
            u16::from_le_bytes(hdr[42..44].try_into().ok()?) as usize,
            u16::from_le_bytes(hdr[44..46].try_into().ok()?) as usize,
        )
    } else {
        return None;
    };
    if phentsize < 8 || phentsize > 128 || phnum == 0 || phnum > 128 {
        return None;
    }
    f.seek(SeekFrom::Start(phoff)).ok()?;
    let mut ph = vec![0u8; phentsize];
    const PT_GNU_STACK: u32 = 0x6474_e551;
    for _ in 0..phnum {
        f.read_exact(&mut ph).ok()?;
        let p_type = u32::from_le_bytes(ph.get(0..4)?.try_into().ok()?);
        if p_type == PT_GNU_STACK {
            let flags = if class == 2 {
                u32::from_le_bytes(ph.get(4..8)?.try_into().ok()?)
            } else {
                u32::from_le_bytes(ph.get(24..28)?.try_into().ok()?)
            };
            return Some((flags & 1) == 0);
        }
    }
    None
}

const SELF_HASH_CAP: u64 = 8 * 1024 * 1024;

fn hash_self_exe() -> Option<String> {
    let mut f = fs::File::open("/proc/self/exe").ok()?;
    let len = f.metadata().ok()?.len();
    let mut hasher = Sha384::new();
    let mut buf = [0u8; 65_536];
    let mut remaining = SELF_HASH_CAP.min(len);
    while remaining > 0 {
        let want = (buf.len() as u64).min(remaining) as usize;
        let n = f.read(&mut buf[..want]).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    let digest = format!("{:x}", hasher.finalize());
    if len > SELF_HASH_CAP {
        Some(format!("{digest}:len={len}:capped={SELF_HASH_CAP}"))
    } else {
        Some(digest)
    }
}

fn sysctl_u8(path: &str) -> Option<u8> {
    read_trimmed(path)?.parse().ok()
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn detect_secure_boot() -> Option<bool> {
    let p = Path::new("/sys/firmware/efi/efivars");
    if !p.is_dir() {
        return None;
    }
    let Ok(rd) = fs::read_dir(p) else {
        return Some(false);
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        if name.to_string_lossy().starts_with("SecureBoot-") {
            if let Ok(bytes) = fs::read(ent.path()) {
                if let Some(&v) = bytes.get(4) {
                    return Some(v == 1);
                }
            }
        }
    }
    Some(false)
}

fn inspect_shadow(s: &mut HostSnapshot) {
    let path = Path::new("/etc/shadow");
    if let Ok(meta) = fs::metadata(path) {
        s.shadow_mode = Some(file_mode(&meta));
        s.shadow_readable = fs::File::open(path).is_ok();
    }
}

fn path_writable(path: &str) -> bool {
    use std::fs::OpenOptions;
    OpenOptions::new().write(true).open(path).is_ok()
}

fn scan_sudo_nopasswd() -> Vec<String> {
    let mut out = Vec::new();
    for path in ["/etc/sudoers", "/etc/sudoers.d"] {
        let p = Path::new(path);
        if p.is_file() {
            if let Ok(text) = fs::read_to_string(p) {
                for line in text.lines() {
                    let t = line.trim();
                    if !t.is_empty() && !t.starts_with('#') && t.contains("NOPASSWD") {
                        out.push(format!(
                            "{path}: {}",
                            t.chars().take(80).collect::<String>()
                        ));
                    }
                }
            }
        } else if p.is_dir() {
            if let Ok(rd) = fs::read_dir(p) {
                for ent in rd.flatten().take(32) {
                    if let Ok(text) = fs::read_to_string(ent.path()) {
                        for line in text.lines() {
                            let t = line.trim();
                            if t.contains("NOPASSWD") && !t.starts_with('#') {
                                out.push(format!(
                                    "{}: {}",
                                    ent.path().display(),
                                    t.chars().take(80).collect::<String>()
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn scan_systemd(s: &mut HostSnapshot) {
    for dir in [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ] {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for ent in rd.flatten().take(80) {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("service") {
                continue;
            }
            if let Ok(meta) = ent.metadata() {
                if file_mode(&meta) & 0o002 != 0 {
                    s.world_writable_units.push(path.display().to_string());
                }
            }
            if let Ok(text) = fs::read_to_string(&path) {
                for line in text.lines() {
                    let l = line.trim();
                    if let Some(rest) = l.strip_prefix("ExecStart=") {
                        if rest.contains("/tmp/") || rest.contains("/var/tmp/") {
                            s.tmp_services.push(path.display().to_string());
                        }
                    }
                }
            }
        }
    }
}

fn scan_cred_stores(s: &mut HostSnapshot) {
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .map(PathBuf::from);
    let Some(home) = home else { return };
    let candidates: Vec<(&'static str, PathBuf)> = vec![
        ("ssh", home.join(".ssh/id_rsa")),
        ("ssh", home.join(".ssh/id_ed25519")),
        ("cloud", home.join(".aws/credentials")),
        ("cloud", home.join(".docker/config.json")),
        ("cloud", home.join(".kube/config")),
        ("netrc", home.join(".netrc")),
        (
            "browser",
            home.join(".config/google-chrome/Default/Login Data"),
        ),
        ("sam", PathBuf::from("/etc/shadow")),
    ];
    for (cat, p) in candidates {
        push_cred(s, cat, &p);
    }
}

fn push_cred(s: &mut HostSnapshot, category: &'static str, path: &Path) {
    let Ok(meta) = fs::metadata(path) else { return };
    if !meta.is_file() {
        return;
    }
    let mode = file_mode(&meta);
    s.cred_hits.push(CredHit {
        category,
        path: path.display().to_string(),
        mode,
        readable: fs::File::open(path).is_ok(),
        world_readable: mode & 0o004 != 0,
    });
}

fn scan_leak_snippets(s: &mut HostSnapshot) {
    let home = std::env::var("HOME").ok().map(PathBuf::from);
    let mut paths = vec![PathBuf::from("/etc/environment")];
    if let Some(h) = home {
        paths.push(h.join(".netrc"));
        paths.push(h.join(".docker/config.json"));
        paths.push(h.join(".aws/credentials"));
    }
    for p in paths {
        let Ok(bytes) = fs::read(&p) else { continue };
        if bytes.len() > 64 * 1024 {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        if text.contains("password=")
            || text.contains("\"password\"")
            || text.contains("aws_secret_access_key")
        {
            s.leak_paths.push(p.display().to_string());
        }
    }
}

fn scan_proc_comms(s: &mut HostSnapshot) {
    let Ok(rd) = fs::read_dir("/proc") else {
        return;
    };
    for ent in rd.flatten().take(8192) {
        let name = ent.file_name();
        let pid: u32 = match name.to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let comm = match with_stable_pid(pid, || fs::read_to_string(ent.path().join("comm")).ok()) {
            PidRead::Ok(Some(c)) => c,
            PidRead::Ok(None) | PidRead::Missing => continue,
            PidRead::Recycled => {
                s.recycled_pids = s.recycled_pids.saturating_add(1);
                continue;
            }
        };
        let comm = comm.trim().to_ascii_lowercase();
        if SUSPICIOUS_PROCS.iter().any(|n| comm.contains(n)) {
            s.suspicious_procs.push(format!("{comm}#{pid}"));
        }
        if IDENTITY_DAEMONS
            .iter()
            .any(|n| comm == *n || comm.starts_with(n))
        {
            s.identity_daemons.push(format!("{comm}#{pid}"));
        }
    }
}

fn comm_running(name: &str) -> bool {
    let Ok(rd) = fs::read_dir("/proc") else {
        return false;
    };
    for ent in rd.flatten().take(4096) {
        let pid: u32 = match ent.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let PidRead::Ok(Some(comm)) =
            with_stable_pid(pid, || fs::read_to_string(ent.path().join("comm")).ok())
        {
            if comm.trim() == name {
                return true;
            }
        }
    }
    false
}

fn list_modules() -> Vec<String> {
    fs::read_to_string("/proc/modules")
        .ok()
        .map(|t| {
            t.lines()
                .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
                .take(256)
                .collect()
        })
        .unwrap_or_default()
}

fn is_loldriver(name: &str) -> bool {
    const NAMES: &[&str] = &[
        "gdrv", "asio", "rtcore64", "iqvw64e", "winring0", "physmem", "capcom",
    ];
    let n = name.to_ascii_lowercase();
    NAMES.iter().any(|k| n.contains(k))
}

fn read_status_field(field: &str) -> Option<String> {
    let text = fs::read_to_string("/proc/self/status").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            return Some(rest.trim_start_matches(':').trim().to_string());
        }
    }
    None
}

fn cap_bit_set(hex_cap: &str, bit: u32) -> bool {
    let Ok(v) = u64::from_str_radix(hex_cap.trim(), 16) else {
        return false;
    };
    (v & (1u64 << bit)) != 0
}

fn self_cpu_rss() -> (f32, u64) {
    let text = match fs::read_to_string("/proc/self/stat") {
        Ok(t) => t,
        Err(_) => return (0.0, 0),
    };
    // Field 24 (rss) is index 21 of the post-comm remainder — never split the comm token.
    let rss_pages: u64 = text
        .rfind(')')
        .and_then(|i| text.get(i + 1..))
        .and_then(|rest| rest.split_whitespace().nth(21))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (0.0, rss_pages.saturating_mul(4096))
}

fn uname_kernel() -> String {
    read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| std::env::consts::ARCH.to_string())
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".into())
}

fn current_uid() -> u32 {
    read_status_field("Uid")
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(65534)
}

fn current_euid() -> u32 {
    read_status_field("Uid")
        .and_then(|s| s.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(65534)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_runs_on_this_os() {
        let s = collect();
        assert!(!s.os.is_empty());
        assert!(!s.kernel.is_empty());
        assert!(
            s.elapsed_ms < 15_000,
            "host snapshot took {}ms",
            s.elapsed_ms
        );
    }

    #[test]
    fn elf_and_self_hash_do_not_slurp_the_whole_image() {
        let started = Instant::now();
        let _ = elf_nx_stack(Path::new("/proc/self/exe"));
        let hash = hash_self_exe();
        assert!(started.elapsed().as_millis() < 5_000);
        assert!(hash.is_some());
    }
}
