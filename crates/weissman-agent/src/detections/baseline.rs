//! UEBA baseline sampler.
//!
//! Once per task dispatch the agent collects a snapshot of host metrics that
//! UEBA can baseline + anomaly-detect server-side. Cheap to sample (no shelling
//! out to heavy tools); no PII (top processes by name only, no command lines).
//!
//! Output shape — single finding of type `ueba_sample` whose `metrics` JSON
//! object is what `weissman-worker::ueba_detector` ingests:
//!
//! ```json
//! {
//!   "open_ports":      [22, 80, 443],
//!   "open_port_count": 3,
//!   "process_count":   142,
//!   "top_processes":   ["nginx", "postgres", "weissman-agent"],
//!   "top_process_hashes": {"nginx": "<sha256 of /proc/<pid>/exe>"},
//!   "unique_users":    1,
//!   "uptime_seconds":  872315,
//!   "load_1m":         0.42,
//!   "memory_used_pct": 38.5,
//!   "outbound_bytes":  0,
//!   "failed_logins":   0
//! }
//! ```
//!
//! On unsupported platforms or when `/proc` is unreadable the sample degrades
//! gracefully — counters stay zero, the server treats this as "no signal" and
//! does not throw a false anomaly.

use anyhow::Result;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

const TOP_PROCESSES_LIMIT: usize = 12;

pub async fn run(engine: &str) -> Result<Vec<Value>> {
    let metrics = collect_metrics();
    let mut extras: Map<String, Value> = Map::new();
    extras.insert("metrics".to_string(), metrics.clone());
    extras.insert("kind".to_string(), Value::String("ueba_sample".to_string()));
    // The server-side UEBA detector keys its baselines off this hour bucket.
    extras.insert(
        "hour_of_week".to_string(),
        Value::from(hour_of_week_utc() as i32),
    );

    let summary = format!(
        "Host UEBA sample: ports={} processes={} users={}",
        metrics
            .get("open_port_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        metrics
            .get("process_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        metrics
            .get("unique_users")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    );

    Ok(vec![super::finding(
        engine,
        "Host UEBA baseline sample",
        "info",  // raw samples are informational; anomalies become medium on the server
        "T1057", // ATT&CK Process Discovery (closest match for self-observation)
        &summary,
        extras,
    )])
}

fn hour_of_week_utc() -> u8 {
    // 0..167 — Mon 00:00 UTC = 0, Sun 23:00 UTC = 167.
    use chrono::Datelike;
    use chrono::Timelike;
    let n = chrono::Utc::now();
    let dow = (n.weekday().num_days_from_monday() as u8).min(6);
    let hour = (n.hour() as u8).min(23);
    dow * 24 + hour
}

fn collect_metrics() -> Value {
    let mut m = Map::new();

    // ── Open ports (Linux /proc/net/tcp parser) ─────────────────────────────
    let ports = read_listening_tcp_ports();
    m.insert("open_port_count".into(), Value::from(ports.len() as u64));
    m.insert(
        "open_ports".into(),
        Value::Array(
            ports
                .iter()
                .take(64)
                .map(|p| Value::from(*p as u64))
                .collect(),
        ),
    );

    // ── Processes (Linux /proc/*/comm + uid)  ───────────────────────────────
    let (procs_by_name, unique_users, pids) = read_process_table();
    m.insert(
        "process_count".into(),
        Value::from(procs_by_name.values().sum::<u64>()),
    );
    let mut top: Vec<(String, u64)> = procs_by_name.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    top.truncate(TOP_PROCESSES_LIMIT);
    m.insert(
        "top_processes".into(),
        Value::Array(
            top.iter()
                .map(|(name, _)| Value::String(name.clone()))
                .collect(),
        ),
    );
    let mut hashes = Map::new();
    for (name, _) in &top {
        if let Some(pid) = pids.get(name) {
            if let Some(h) = sha256_exe(pid) {
                hashes.insert(name.clone(), Value::String(h));
            }
        }
    }
    m.insert("top_process_hashes".into(), Value::Object(hashes));
    m.insert("unique_users".into(), Value::from(unique_users as u64));

    // ── Uptime + load + memory (Linux /proc/uptime, /proc/loadavg, /proc/meminfo)
    if let Some(uptime) = read_uptime_seconds() {
        m.insert("uptime_seconds".into(), Value::from(uptime));
    }
    if let Some(load) = read_loadavg_1m() {
        m.insert("load_1m".into(), json!(load));
    }
    if let Some(mem_pct) = read_memory_used_pct() {
        m.insert("memory_used_pct".into(), json!(mem_pct));
    }

    // ── Failed logins (Linux /var/log/btmp via lastb — best-effort, may fail
    //    silently in unprivileged contexts; that's fine — UEBA still works on
    //    the rest of the signal).
    let failed = read_failed_logins_24h();
    m.insert("failed_logins".into(), Value::from(failed as u64));

    Value::Object(m)
}

// ─── Linux-only platform readers (no-op on other targets) ─────────────────────

#[cfg(target_os = "linux")]
fn read_listening_tcp_ports() -> Vec<u16> {
    let mut out: std::collections::BTreeSet<u16> = Default::default();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            for line in s.lines().skip(1) {
                // local_address rem_address st …
                let mut it = line.split_whitespace();
                let _ = it.next();
                let Some(local) = it.next() else { continue };
                let Some(_) = it.next() else { continue };
                let Some(st) = it.next() else { continue };
                if st != "0A" {
                    continue; // not LISTEN
                }
                let Some((_, port_hex)) = local.rsplit_once(':') else {
                    continue;
                };
                if let Ok(p) = u16::from_str_radix(port_hex, 16) {
                    out.insert(p);
                }
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(not(target_os = "linux"))]
fn read_listening_tcp_ports() -> Vec<u16> {
    Vec::new()
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn sha256_exe(pid: &str) -> Option<String> {
    sha256_file(Path::new(&format!("/proc/{pid}/exe")))
}

#[cfg(not(target_os = "linux"))]
fn sha256_exe(_pid: &str) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn read_process_table() -> (HashMap<String, u64>, usize, HashMap<String, String>) {
    let Ok(read) = std::fs::read_dir("/proc") else {
        return (HashMap::new(), 0, HashMap::new());
    };
    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut pids: HashMap<String, String> = HashMap::new();
    let mut users: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for entry in read.flatten() {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
            let comm = comm.trim();
            if !comm.is_empty() {
                *counts.entry(comm.to_string()).or_insert(0) += 1;
                pids.entry(comm.to_string()).or_insert_with(|| name.clone());
            }
        }
        if let Ok(status) = std::fs::read_to_string(entry.path().join("status")) {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(uid_str) = rest.split_whitespace().next() {
                        if let Ok(uid) = uid_str.parse::<u32>() {
                            users.insert(uid);
                            break;
                        }
                    }
                }
            }
        }
    }
    (counts, users.len(), pids)
}

#[cfg(not(target_os = "linux"))]
fn read_process_table() -> (HashMap<String, u64>, usize, HashMap<String, String>) {
    (HashMap::new(), 0, HashMap::new())
}

#[cfg(target_os = "linux")]
fn read_uptime_seconds() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/uptime").ok()?;
    s.split_whitespace()
        .next()
        .and_then(|x| x.parse::<f64>().ok())
        .map(|f| f as u64)
}

#[cfg(not(target_os = "linux"))]
fn read_uptime_seconds() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn read_loadavg_1m() -> Option<f64> {
    let s = std::fs::read_to_string("/proc/loadavg").ok()?;
    s.split_whitespace()
        .next()
        .and_then(|x| x.parse::<f64>().ok())
}

#[cfg(not(target_os = "linux"))]
fn read_loadavg_1m() -> Option<f64> {
    None
}

#[cfg(target_os = "linux")]
fn read_memory_used_pct() -> Option<f64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
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

#[cfg(not(target_os = "linux"))]
fn read_memory_used_pct() -> Option<f64> {
    None
}

fn read_failed_logins_24h() -> u32 {
    // Best-effort: grep last 1000 lines of journald for "Failed password".
    // We deliberately avoid invoking external binaries — journalctl may not be
    // available and `lastb` requires root. Keep this honest and zero when
    // the file isn't readable.
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/var/log/auth.log") {
            return s
                .lines()
                .rev()
                .take(2000)
                .filter(|l| l.contains("Failed password") || l.contains("authentication failure"))
                .count() as u32;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hour_of_week_in_range() {
        let h = hour_of_week_utc();
        assert!(h < 168);
    }

    #[test]
    fn metrics_object_shape() {
        let v = collect_metrics();
        assert!(v.get("open_port_count").is_some());
        assert!(v.get("process_count").is_some());
        assert!(v.get("top_processes").is_some());
        assert!(v
            .get("top_process_hashes")
            .and_then(Value::as_object)
            .is_some());
    }

    #[test]
    fn sha256_file_is_live_digest() {
        let dir = std::env::temp_dir().join(format!(
            "ws-hash-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
