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
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

pub async fn run(engine: &str) -> Result<Vec<Value>> {
    let lite = super::ueba::is_lite() || super::ueba::rss_over_cap();
    let mut metrics = super::ueba::collect_metrics(lite);
    overlay_top_process_hashes(&mut metrics);
    let hour = hour_of_week_utc();
    match crate::ueba_edge::decide(&metrics, hour) {
        crate::ueba_edge::Gate::Suppress { z_max } => {
            tracing::debug!(target: "agent", z_max, "UEBA edge suppressed quiet sample");
            return Ok(vec![]);
        }
        crate::ueba_edge::Gate::Upload { reason, z_max } => {
            tracing::debug!(
                target: "agent",
                reason = %reason,
                z_max,
                "UEBA edge upload"
            );
        }
    }
    let mut extras: Map<String, Value> = Map::new();
    extras.insert("metrics".to_string(), metrics.clone());
    extras.insert("kind".to_string(), Value::String("ueba_sample".to_string()));
    // The server-side UEBA detector keys its baselines off this hour bucket.
    extras.insert("hour_of_week".to_string(), Value::from(hour as i32));

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

    let mut findings = vec![super::finding(
        engine,
        "Host UEBA baseline sample",
        "info",  // raw samples are informational; anomalies become medium on the server
        "T1057", // ATT&CK Process Discovery (closest match for self-observation)
        &summary,
        extras,
    )];
    findings.extend(super::ueba::drain_offline());
    Ok(findings)
}

fn hour_of_week_utc() -> u8 {
    super::ueba::hour_of_week_corrected().clamp(0, 167) as u8
}

fn collect_metrics() -> Value {
    let mut metrics = super::ueba::collect_metrics(false);
    overlay_top_process_hashes(&mut metrics);
    metrics
}

/// Keep the proven named `/proc/<pid>/exe` digest map so server uniqueness
/// still has a live hash keyed by process name (UEBA collectors expose a
/// parallel sha256 array).
fn overlay_top_process_hashes(metrics: &mut Value) {
    let Value::Object(m) = metrics else {
        return;
    };
    let pids = read_process_pids();
    let mut hashes = Map::new();
    if let Some(Value::Array(top)) = m.get("top_processes") {
        for name in top {
            let Some(raw) = name.as_str() else { continue };
            if let Some(pid) = pids.get(raw).or_else(|| {
                pids.iter().find_map(|(comm, pid)| {
                    (super::ueba::sanitize_comm(comm) == raw).then_some(pid)
                })
            }) {
                if let Some(h) = sha256_exe(pid) {
                    hashes.insert(raw.to_string(), Value::String(h));
                }
            }
        }
    }
    m.insert("top_process_hashes".into(), Value::Object(hashes));
}

// ─── Linux-only platform readers (no-op on other targets) ─────────────────────

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
fn read_process_pids() -> HashMap<String, String> {
    let Ok(read) = std::fs::read_dir("/proc") else {
        return HashMap::new();
    };
    let mut pids: HashMap<String, String> = HashMap::new();
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
                pids.entry(comm.to_string()).or_insert_with(|| name.clone());
            }
        }
    }
    pids
}

#[cfg(not(target_os = "linux"))]
fn read_process_pids() -> HashMap<String, String> {
    HashMap::new()
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
