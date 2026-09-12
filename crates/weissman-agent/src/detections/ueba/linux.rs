//! Linux /proc sampling — no netstat/ss, non-blocking auth.log, listen map, ghosts.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::{is_ephemeral, sanitize_comm, NetSummary, ProcessSnapshot, MAX_TOP_PROCESSES};

const AUTH_PATHS: &[&str] = &["/var/log/auth.log", "/var/log/secure"];

pub fn listening_tcp_ports() -> Vec<u16> {
    let mut out: std::collections::BTreeSet<u16> = Default::default();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(s) = fs::read_to_string(path) else {
            continue;
        };
        for line in s.lines().skip(1) {
            let mut it = line.split_whitespace();
            let _ = it.next();
            let Some(local) = it.next() else { continue };
            let Some(_) = it.next() else { continue };
            let Some(st) = it.next() else { continue };
            if st != "0A" {
                continue;
            }
            let Some((_, port_hex)) = local.rsplit_once(':') else {
                continue;
            };
            if let Ok(p) = u16::from_str_radix(port_hex, 16) {
                if p != 0 && !is_ephemeral(p) {
                    out.insert(p);
                }
            }
        }
    }
    out.into_iter().collect()
}

pub fn process_snapshot(lite: bool) -> ProcessSnapshot {
    let Ok(read) = fs::read_dir("/proc") else {
        return empty_snapshot();
    };
    let mut ranked: Vec<(u64, String, String, i32, i32)> = Vec::new();
    let mut users: HashSet<u32> = HashSet::new();
    let mut ghosts: Vec<u32> = Vec::new();
    let mut process_count = 0u64;
    let mut thread_count = 0u64;

    for entry in read.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        process_count += 1;
        let comm_raw = fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        let comm = sanitize_comm(&comm_raw);
        if comm.is_empty() {
            continue;
        }
        let (ppid, uid, threads, rss_kb) = parse_status_metrics(pid);
        thread_count = thread_count.saturating_add(threads as u64);
        users.insert(uid);
        if ppid == 0 && pid > 1 {
            ghosts.push(pid);
        }
        let exe = fs::read_link(entry.path().join("exe"))
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_default();
        ranked.push((rss_kb, comm, exe, pid as i32, ppid));
        if ranked.len() > 256 {
            ranked.sort_by(|a, b| b.0.cmp(&a.0));
            ranked.truncate(MAX_TOP_PROCESSES * 2);
        }
    }
    ranked.sort_by(|a, b| b.0.cmp(&a.0));
    ranked.truncate(MAX_TOP_PROCESSES);

    let hash_exes = !lite && !battery_discharging();
    let mut top = Vec::new();
    let mut paths = Vec::new();
    let mut sha256 = Vec::new();
    for (_, comm, exe, _, _) in &ranked {
        top.push(comm.clone());
        if !exe.is_empty() {
            paths.push(normalize_exe(exe));
            if hash_exes && sha256.len() < 8 {
                if let Some(h) = hash_exe_capped(exe) {
                    sha256.push(h);
                }
            }
        }
    }

    let listen_map = if lite { Vec::new() } else { build_listen_map() };

    ProcessSnapshot {
        process_count,
        unique_users: users.len() as u64,
        top,
        paths,
        sha256,
        listen_map,
        ghost_ppids: ghosts,
        thread_count,
    }
}

fn empty_snapshot() -> ProcessSnapshot {
    ProcessSnapshot {
        process_count: 0,
        unique_users: 0,
        top: Vec::new(),
        paths: Vec::new(),
        sha256: Vec::new(),
        listen_map: Vec::new(),
        ghost_ppids: Vec::new(),
        thread_count: 0,
    }
}

fn parse_status_metrics(pid: u32) -> (i32, u32, u32, u64) {
    let Ok(text) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return (0, 0, 1, 0);
    };
    let mut ppid = 0i32;
    let mut uid = 0u32;
    let mut threads = 1u32;
    let mut rss_kb = 0u64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Threads:") {
            threads = rest.trim().parse().unwrap_or(1);
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss_kb = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    (ppid, uid, threads, rss_kb)
}

fn normalize_exe(path: &str) -> String {
    let p = path.trim().replace('\\', "/");
    let base = p.rsplit('/').next().unwrap_or(&p);
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

fn hash_exe_capped(path: &str) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let digest = Sha256::digest(&bytes);
    Some(format!("{digest:x}"))
}

fn build_listen_map() -> Vec<String> {
    let inode_to_pid = inode_owners();
    let mut out = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            if cols[3] != "0A" {
                continue;
            }
            let port = cols[1]
                .rsplit_once(':')
                .and_then(|(_, p)| u16::from_str_radix(p, 16).ok())
                .unwrap_or(0);
            if port == 0 || is_ephemeral(port) {
                continue;
            }
            let inode: u64 = cols[9].parse().unwrap_or(0);
            let proc_name = inode_to_pid
                .get(&inode)
                .and_then(|pid| {
                    fs::read_to_string(format!("/proc/{pid}/comm"))
                        .ok()
                        .map(|s| sanitize_comm(&s))
                })
                .unwrap_or_else(|| "unknown".into());
            out.push(format!("{port}:{proc_name}"));
        }
    }
    out.sort();
    out.dedup();
    out.truncate(64);
    out
}

fn inode_owners() -> HashMap<u64, i32> {
    let mut map = HashMap::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return map;
    };
    for ent in dir.flatten() {
        let pid: i32 = match ent.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            let s = link.to_string_lossy();
            if let Some(rest) = s.strip_prefix("socket:[") {
                if let Some(num) = rest.strip_suffix(']') {
                    if let Ok(inode) = num.parse::<u64>() {
                        map.insert(inode, pid);
                    }
                }
            }
        }
    }
    map
}

pub fn uptime_seconds() -> Option<u64> {
    let s = fs::read_to_string("/proc/uptime").ok()?;
    s.split_whitespace()
        .next()
        .and_then(|x| x.parse::<f64>().ok())
        .map(|f| f as u64)
}

pub fn loadavg_1m() -> Option<f64> {
    let s = fs::read_to_string("/proc/loadavg").ok()?;
    s.split_whitespace()
        .next()
        .and_then(|x| x.parse::<f64>().ok())
}

pub fn memory_used_pct() -> Option<f64> {
    let s = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb = 0_u64;
    let mut avail_kb = 0_u64;
    for line in s.lines() {
        let mut it = line.split_whitespace();
        let key = it.next()?;
        let val: u64 = it.next()?.parse().ok()?;
        match key {
            "MemTotal:" => total_kb = val,
            "MemAvailable:" => avail_kb = val,
            _ => {}
        }
    }
    if total_kb == 0 {
        return None;
    }
    Some(((total_kb - avail_kb) as f64) / total_kb as f64 * 100.0)
}

pub fn self_rss_kb() -> Option<u64> {
    let pid = std::process::id();
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next().and_then(|s| s.parse().ok());
        }
    }
    None
}

/// Returns (auth_log_readable, failed_count). Never fabricates a count when the file is unreadable.
pub fn failed_logins_24h() -> (bool, u32) {
    for path in AUTH_PATHS {
        if !Path::new(path).exists() {
            continue;
        }
        match fs::metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return (false, 0);
            }
            Ok(_) => {
                return (true, count_failed_nonblocking(path));
            }
            Err(_) => continue,
        }
    }
    (false, 0)
}

fn count_failed_nonblocking(path: &str) -> u32 {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut f = file;
    let _ = f.seek(SeekFrom::End(-(256 * 1024)));
    let mut buf = Vec::with_capacity(256 * 1024);
    let _ = f.take(256 * 1024).read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    text.lines()
        .filter(|l| l.contains("Failed password") || l.contains("authentication failure"))
        .count() as u32
}

pub fn hardware_id() -> Option<String> {
    let id = fs::read_to_string("/etc/machine-id").ok()?;
    let t = id.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

pub fn tracer_pid() -> Option<u32> {
    let pid = std::process::id();
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

pub fn battery_discharging() -> bool {
    let sys = Path::new("/sys/class/power_supply");
    let Ok(dir) = fs::read_dir(sys) else {
        return false;
    };
    for ent in dir.flatten() {
        let p = ent.path();
        let typ = fs::read_to_string(p.join("type")).unwrap_or_default();
        if !typ.trim().eq_ignore_ascii_case("Battery") {
            continue;
        }
        let status = fs::read_to_string(p.join("status")).unwrap_or_default();
        let online = fs::read_to_string("/sys/class/power_supply/AC/online")
            .or_else(|_| fs::read_to_string("/sys/class/power_supply/ACAD/online"))
            .unwrap_or_default();
        if online.trim() == "0" || status.trim().eq_ignore_ascii_case("Discharging") {
            return true;
        }
    }
    false
}

pub fn network_summary() -> NetSummary {
    let mut conn = 0u64;
    let mut fail = 0u64;
    let mut remotes = HashSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            match cols[3] {
                "01" => {
                    conn += 1;
                    if let Some((iphex, _)) = cols[2].rsplit_once(':') {
                        remotes.insert(iphex.to_string());
                    }
                }
                "02" | "03" => fail += 1,
                _ => {}
            }
        }
    }
    NetSummary {
        conn_count: conn,
        conn_fail_count: fail,
        unique_remote_ips: remotes.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_exe() {
        assert_eq!(normalize_exe("C:\\Windows\\svchost.exe"), "svchost");
        assert_eq!(normalize_exe("/usr/sbin/sshd"), "sshd");
    }

    #[test]
    fn listening_ports_are_non_ephemeral() {
        for p in listening_tcp_ports() {
            assert!(
                !is_ephemeral(p),
                "ephemeral port {p} leaked into listen set"
            );
        }
    }
}
