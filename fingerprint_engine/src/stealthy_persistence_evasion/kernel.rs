//! Kernel-grade sensors beyond a single `/proc` snapshot.
//!
//! Live signals:
//! - `memfd:` mappings and fds (anonymous executable memory)
//! - anonymous `r-x` / `rwx` maps
//! - protection flapping (two-sample maps compare)
//! - tracepoint availability for `sys_enter_execve` / `sys_enter_memfd_create`
//! - CAP_BPF / CAP_PERFMON / bpf fs
//! - jittered, shuffled, size-capped process sampling (16 MiB max)
//!
//! HalosGate / Hell's Gate syscall stubs are **not** executed. Memory
//! interrogation is jittered `/proc` sampling so the agent does not look
//! like a sequential VirtualQuery recon sweep (T1592).

use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Hard cap on maps/fd bytes read per assessment (architect: 16 MiB).
pub const MAX_EVASION_SCAN_SIZE_LIMIT: usize = 16 * 1024 * 1024;
const MAX_PIDS: usize = 64;
const MARKER: &str = "WEISSMAN-DECEPTION";

#[derive(Debug, Clone, Default, Serialize)]
pub struct KernelSnapshot {
    pub memfd_maps: usize,
    pub memfd_fds: usize,
    pub anon_exec_maps: usize,
    pub prot_flap: bool,
    pub flap_ranges: usize,
    pub execve_tracepoint: bool,
    pub memfd_tracepoint: bool,
    pub bpf_fs_mounted: bool,
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    pub perf_event_paranoid: Option<i32>,
    pub trace_hits_memfd: usize,
    pub trace_hits_execve: usize,
    pub jitter_applied: bool,
    pub shuffled: bool,
    pub pids_sampled: usize,
    pub bytes_scanned: u64,
    pub scan_capped: bool,
    pub jitter_ms: u32,
    pub halosgate_executed: bool,
    pub sensor: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeceptionCanary {
    pub path: String,
    pub planted_unix: u64,
    pub size: u64,
    pub trips: Vec<String>,
}

pub fn collect() -> KernelSnapshot {
    collect_ex(!cfg!(test))
}

pub fn collect_ex(jitter: bool) -> KernelSnapshot {
    let mut snap = KernelSnapshot {
        sensor: "proc+memfd+tracepoint+jitter",
        halosgate_executed: false,
        jitter_applied: jitter,
        shuffled: true,
        ..KernelSnapshot::default()
    };
    #[cfg(target_os = "linux")]
    collect_linux(&mut snap, jitter);
    snap
}

#[cfg(target_os = "linux")]
fn collect_linux(snap: &mut KernelSnapshot, jitter: bool) {
    let t0 = Instant::now();
    let self_maps = read_capped("/proc/self/maps", MAX_EVASION_SCAN_SIZE_LIMIT);
    snap.bytes_scanned += self_maps.len() as u64;
    let first = parse_maps(&self_maps);
    snap.memfd_maps += first.memfd;
    snap.anon_exec_maps += first.anon_exec;

    if jitter {
        let us = gaussian_jitter_us(mix_seed(), 2_000, 3_000);
        std::thread::sleep(Duration::from_micros(us.min(8_000)));
        snap.jitter_ms = t0.elapsed().as_millis() as u32;
    }

    let second_maps = read_capped("/proc/self/maps", MAX_EVASION_SCAN_SIZE_LIMIT);
    snap.bytes_scanned += second_maps.len() as u64;
    let second = parse_maps(&second_maps);
    snap.flap_ranges = count_flaps(&first.perms, &second.perms);
    snap.prot_flap = snap.flap_ranges > 0;

    snap.memfd_fds += count_memfd_fds("/proc/self/fd");

    fill_tracepoints(snap);
    snap.bpf_fs_mounted = Path::new("/sys/fs/bpf").is_dir();
    let (bpf, perfmon) = cap_bpf_perfmon();
    snap.cap_bpf = bpf;
    snap.cap_perfmon = perfmon;
    snap.perf_event_paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .ok()
        .and_then(|s| s.trim().parse().ok());

    sample_other_pids(snap, jitter);
}

#[cfg(not(target_os = "linux"))]
fn collect_linux(_snap: &mut KernelSnapshot, _jitter: bool) {}

#[derive(Default)]
struct MapsParse {
    memfd: usize,
    anon_exec: usize,
    perms: HashMap<String, String>,
}

fn parse_maps(maps: &str) -> MapsParse {
    let mut out = MapsParse::default();
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let range = it.next().unwrap_or("");
        let perms = it.next().unwrap_or("");
        let path = it.nth(3).unwrap_or("");
        out.perms.insert(range.to_string(), perms.to_string());
        if path.contains("/memfd:") || line.contains("/memfd:") {
            out.memfd += 1;
        }
        let exec = perms.contains('x');
        let fileless = path.is_empty() || path == "0";
        let memfd = path.contains("/memfd:") || line.contains("/memfd:");
        let rwx = perms.starts_with("rwx");
        if exec && (fileless || memfd || rwx) {
            out.anon_exec += 1;
        }
    }
    out
}

fn count_flaps(a: &HashMap<String, String>, b: &HashMap<String, String>) -> usize {
    a.iter()
        .filter(|(range, p)| b.get(range.as_str()).is_some_and(|q| q != *p))
        .count()
}

fn count_memfd_fds(dir: &str) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .filter(|e| {
            std::fs::read_link(e.path())
                .map(|t| t.to_string_lossy().contains("memfd:"))
                .unwrap_or(false)
        })
        .count()
}

fn fill_tracepoints(snap: &mut KernelSnapshot) {
    let root = tracing_root();
    let Some(root) = root else {
        return;
    };
    let events = std::fs::read_to_string(root.join("available_events")).unwrap_or_default();
    snap.execve_tracepoint = events.contains("sys_enter_execve");
    snap.memfd_tracepoint = events.contains("sys_enter_memfd_create");
    if !snap.execve_tracepoint {
        snap.execve_tracepoint = root.join("events/syscalls/sys_enter_execve").is_dir();
    }
    if !snap.memfd_tracepoint {
        snap.memfd_tracepoint = root.join("events/syscalls/sys_enter_memfd_create").is_dir();
    }
    // Snapshot buffer (non-blocking). Never enable global tracing from here.
    if let Ok(trace) = std::fs::read_to_string(root.join("trace")) {
        let sample = if trace.len() > 256 * 1024 {
            &trace[..256 * 1024]
        } else {
            &trace
        };
        snap.trace_hits_memfd = sample.matches("memfd_create").count();
        snap.trace_hits_execve = sample.matches("execve").count();
    }
}

fn tracing_root() -> Option<PathBuf> {
    for p in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        if Path::new(p).join("available_events").is_file() || Path::new(p).join("events").is_dir() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

fn cap_bpf_perfmon() -> (bool, bool) {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return (false, false);
    };
    let mut cap = 0u64;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("CapEff:") {
            cap = u64::from_str_radix(v.trim(), 16).unwrap_or(0);
        }
    }
    const CAP_PERFMON: u32 = 38;
    const CAP_BPF: u32 = 39;
    const CAP_SYS_ADMIN: u32 = 21;
    let admin = cap & (1u64 << CAP_SYS_ADMIN) != 0;
    (
        (cap & (1u64 << CAP_BPF) != 0) || admin,
        (cap & (1u64 << CAP_PERFMON) != 0) || admin,
    )
}

fn sample_other_pids(snap: &mut KernelSnapshot, jitter: bool) {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return;
    };
    let self_pid = std::process::id();
    let mut pids: Vec<u32> = rd
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .filter(|p| *p != self_pid)
        .collect();
    shuffle(&mut pids, mix_seed());
    snap.shuffled = true;
    for pid in pids.into_iter().take(MAX_PIDS) {
        if snap.bytes_scanned as usize >= MAX_EVASION_SCAN_SIZE_LIMIT {
            snap.scan_capped = true;
            break;
        }
        if jitter {
            std::thread::sleep(Duration::from_micros(gaussian_jitter_us(
                mix_seed() ^ u64::from(pid),
                200,
                400,
            )));
        }
        let maps = read_capped(
            &format!("/proc/{pid}/maps"),
            MAX_EVASION_SCAN_SIZE_LIMIT.saturating_sub(snap.bytes_scanned as usize),
        );
        snap.bytes_scanned += maps.len() as u64;
        let parsed = parse_maps(&maps);
        snap.memfd_maps += parsed.memfd;
        snap.anon_exec_maps += parsed.anon_exec;
        snap.memfd_fds += count_memfd_fds(&format!("/proc/{pid}/fd"));
        snap.pids_sampled += 1;
    }
}

fn read_capped(path: &str, max: usize) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let take = bytes.len().min(max);
    String::from_utf8_lossy(&bytes[..take]).into_owned()
}

fn shuffle(pids: &mut [u32], seed: u64) {
    let mut s = seed | 1;
    for i in (1..pids.len()).rev() {
        s = s.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        let j = (s as usize) % (i + 1);
        pids.swap(i, j);
    }
}

fn mix_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    nanos ^ u64::from(std::process::id())
}

fn gaussian_jitter_us(seed: u64, mean: u64, std: u64) -> u64 {
    // Box-Muller from two LCG uniforms, clamped to a small window.
    let s1 = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    let s2 = s1.wrapping_mul(6364136223846793005).wrapping_add(1);
    let u1 = ((s1 >> 11) as f64 / (u64::MAX as f64)).clamp(1e-12, 1.0);
    let u2 = (s2 >> 11) as f64 / (u64::MAX as f64);
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    let v = (mean as f64) + z * (std as f64);
    v.clamp(0.0, (mean + 3 * std) as f64) as u64
}

/// Plant Weissman-tagged deception canaries (not APT malware). High-entropy
/// padding makes scanners notice them; the marker makes fail-safe unique.
pub fn plant_deception_canaries() -> Vec<DeceptionCanary> {
    let mut out = Vec::new();
    let uuid = format!("{:x}", mix_seed());
    for dir in ["/tmp", "/var/tmp", "/dev/shm"] {
        if !Path::new(dir).is_dir() {
            continue;
        }
        let path = format!("{dir}/weissman-deception-canary-{uuid}");
        let mut body = MARKER.as_bytes().to_vec();
        body.push(b'\n');
        let mut pad = vec![0u8; 4096];
        let mut s = mix_seed();
        for b in &mut pad {
            s = s.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            *b = (s >> 33) as u8;
        }
        body.extend_from_slice(&pad);
        if std::fs::write(&path, &body).is_err() {
            continue;
        }
        let planted = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let size = body.len() as u64;
        let trip = format!("{path}.trip.json");
        let meta = serde_json::json!({
            "marker": MARKER,
            "planted_unix": planted,
            "size": size,
            "path": path,
        });
        let _ = std::fs::write(&trip, meta.to_string());
        out.push(DeceptionCanary {
            path,
            planted_unix: planted,
            size,
            trips: vec![trip],
        });
        break;
    }
    out
}

pub fn deception_inventory() -> Vec<DeceptionCanary> {
    let mut out = Vec::new();
    for dir in ["/tmp", "/var/tmp", "/dev/shm"] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let s = name.to_string_lossy();
            if !s.starts_with("weissman-deception-canary-") || s.ends_with(".trip.json") {
                continue;
            }
            let path = ent.path();
            let trip = PathBuf::from(format!("{}.trip.json", path.display()));
            let mut trips = Vec::new();
            let meta = std::fs::read_to_string(&trip).ok();
            let planted = meta
                .as_ref()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                .and_then(|v| v.get("planted_unix").and_then(|x| x.as_u64()))
                .unwrap_or(0);
            if trip.exists() {
                trips.push(trip.display().to_string());
            }
            let Ok(meta_fs) = std::fs::metadata(&path) else {
                continue;
            };
            let mut flags = Vec::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if planted > 0 && meta_fs.mtime() as u64 > planted + 1 {
                    flags.push("mtime_changed".into());
                }
                if meta_fs.atime() as u64 > planted + 1 {
                    flags.push("atime_touched".into());
                }
            }
            if meta_fs.len()
                != meta
                    .as_ref()
                    .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                    .and_then(|v| v.get("size").and_then(|x| x.as_u64()))
                    .unwrap_or(meta_fs.len())
            {
                flags.push("size_changed".into());
            }
            out.push(DeceptionCanary {
                path: path.display().to_string(),
                planted_unix: planted,
                size: meta_fs.len(),
                trips: if flags.is_empty() { trips } else { flags },
            });
        }
    }
    out
}

pub fn wipe_deception_canaries() -> HashMap<String, String> {
    let mut report = HashMap::new();
    for dir in ["/tmp", "/var/tmp", "/dev/shm"] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let s = name.to_string_lossy();
            if s.contains("weissman-deception-canary") {
                let p = ent.path();
                match std::fs::remove_file(&p) {
                    Ok(()) => {
                        report.insert(p.display().to_string(), "removed".into());
                    }
                    Err(e) => {
                        report.insert(p.display().to_string(), format!("error:{e}"));
                    }
                }
            }
        }
    }
    report
}

/// Signed-looking hardening artifact. Staging only unless the agent is root
/// and `WEISSMAN_APPLY_HOST_HARDENING=1`.
pub fn generate_hardening_artifact(
    kernel: &KernelSnapshot,
    writable_persist: &[String],
) -> serde_json::Value {
    let sysctl = [
        "kernel.yama.ptrace_scope=1",
        "kernel.kptr_restrict=2",
        "fs.protected_regular=2",
        "fs.suid_dumpable=0",
    ];
    let systemd = concat!(
        "[Service]\n",
        "NoNewPrivileges=yes\n",
        "ProtectSystem=strict\n",
        "ProtectHome=yes\n",
        "PrivateTmp=yes\n",
        "RestrictSUIDSGID=yes\n",
        "MemoryDenyWriteExecute=yes\n",
        "SystemCallFilter=@system-service\n",
    );
    let needs_root =
        !writable_persist.is_empty() || kernel.memfd_maps > 0 || kernel.anon_exec_maps > 0;
    serde_json::json!({
        "kind": "weissman_stealth_hardening",
        "apply": std::env::var("WEISSMAN_APPLY_HOST_HARDENING").ok().as_deref() == Some("1"),
        "staging_dir": "/tmp/weissman-remediation",
        "sysctl": sysctl,
        "systemd_dropin": systemd,
        "writable_persist": writable_persist,
        "kernel": kernel,
        "needs_root": needs_root,
        "note": "Does not compile GPO/registry implants. Writes Weissman staging files only unless WEISSMAN_APPLY_HOST_HARDENING=1.",
    })
}

pub fn stage_hardening(artifact: &serde_json::Value) -> Result<String, String> {
    let dir = Path::new("/tmp/weissman-remediation");
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join("99-weissman-stealth.conf");
    let mut body = String::from("# weissman stealth auto-remediate (staging)\n");
    if let Some(arr) = artifact.get("sysctl").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                body.push_str(s);
                body.push('\n');
            }
        }
    }
    body.push_str("\n# systemd drop-in (reference)\n");
    if let Some(s) = artifact.get("systemd_dropin").and_then(|v| v.as_str()) {
        body.push_str(s);
    }
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_cap_is_16_mib() {
        assert_eq!(MAX_EVASION_SCAN_SIZE_LIMIT, 16 * 1024 * 1024);
    }

    #[test]
    fn parse_maps_sees_memfd_and_anon_exec() {
        let maps = "\
7f0000000000-7f0000001000 r-xp 00000000 00:00 0 \n\
7f0000001000-7f0000002000 rwxp 00000000 00:00 0 /memfd:weissman\n\
7f0000002000-7f0000003000 r-xp 00000000 00:00 0 /usr/lib/libc.so.6\n";
        let p = parse_maps(maps);
        assert_eq!(p.memfd, 1);
        assert!(p.anon_exec >= 2);
    }

    #[test]
    fn live_kernel_snapshot_never_executes_halosgate() {
        let s = collect_ex(false);
        assert!(!s.halosgate_executed);
        assert!(s.bytes_scanned as usize <= MAX_EVASION_SCAN_SIZE_LIMIT);
        assert_eq!(s.sensor.contains("memfd"), true);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memfd_create_is_visible_on_self_fd() {
        let pidfile = std::env::temp_dir().join("weissman-memfd-test.pid");
        let _ = std::fs::remove_file(&pidfile);
        let py = format!(
            r#"
import ctypes, os, time
libc = ctypes.CDLL(None)
fd = libc.memfd_create(b"weissman-kernel-test", 0)
if fd < 0:
    raise SystemExit(1)
open({pidfile:?}, "w").write(str(os.getpid()))
time.sleep(6)
"#
        );
        let mut child = std::process::Command::new("python3")
            .arg("-c")
            .arg(py)
            .spawn()
            .expect("spawn python memfd");
        let mut pid = String::new();
        for _ in 0..50 {
            if let Ok(s) = std::fs::read_to_string(&pidfile) {
                if !s.trim().is_empty() {
                    pid = s.trim().to_string();
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!pid.is_empty(), "python pid file");
        let n = count_memfd_fds(&format!("/proc/{pid}/fd"));
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&pidfile);
        assert!(n >= 1, "expected /proc/{pid}/fd to show memfd, got {n}");
    }

    #[test]
    fn deception_plant_and_wipe() {
        let planted = plant_deception_canaries();
        assert!(!planted.is_empty());
        let report = wipe_deception_canaries();
        assert!(report.values().any(|v| v == "removed"));
        for c in planted {
            assert!(!Path::new(&c.path).exists());
        }
    }
}
