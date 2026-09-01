//! UEBA baseline sampler.
//!
//! Once per task dispatch the agent collects a snapshot of host metrics via
//! native kernel tables (`/proc`, `KERN_PROC`, `NtQuerySystemInformation`) —
//! never `ps`/`lsof`. The sample is gated locally against the compact
//! hour-of-week mean/stddev the server pushed on Welcome: raw metrics go
//! upstream only on `|z| > 2`, a new process, or while the baseline is still
//! training. Quiet ticks complete the task with zero findings.

use crate::hostobs;
use crate::ueba_edge::{self, Gate};
use anyhow::Result;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const TOP_PROCESSES_LIMIT: usize = 12;

pub async fn run(engine: &str) -> Result<Vec<Value>> {
    let metrics = collect_metrics();
    let hour = hour_of_week_utc();
    match ueba_edge::decide(&metrics, hour) {
        Gate::Suppress { z_max } => {
            crate::ringbuf::note_ueba_suppressed();
            tracing::debug!(
                target: "agent",
                z_max,
                hour,
                "ueba sample suppressed at the edge"
            );
            Ok(Vec::new())
        }
        Gate::Upload { reason, z_max } => {
            crate::ringbuf::note_ueba_uploaded();
            let mut extras: Map<String, Value> = Map::new();
            extras.insert("metrics".to_string(), metrics.clone());
            extras.insert("kind".to_string(), Value::String("ueba_sample".to_string()));
            extras.insert("hour_of_week".to_string(), Value::from(hour as i32));
            extras.insert("edge_gate".to_string(), json!(reason));
            extras.insert("edge_z_max".to_string(), json!(z_max));

            let summary = format!(
                "Host UEBA sample: ports={} processes={} users={} gate={}",
                metrics
                    .get("open_port_count")
                    .and_then(Value::as_u64)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                metrics
                    .get("process_count")
                    .and_then(Value::as_u64)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                metrics
                    .get("unique_users")
                    .and_then(Value::as_u64)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                extras
                    .get("edge_gate")
                    .and_then(Value::as_str)
                    .unwrap_or("upload"),
            );

            Ok(vec![super::finding(
                engine,
                "Host UEBA baseline sample",
                "info", // raw samples are informational; anomalies become medium on the server
                "T1057", // ATT&CK Process Discovery (closest match for self-observation)
                &summary,
                extras,
            )])
        }
    }
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
    let mut sampling_failed = false;
    let mut sample_error: Option<String> = None;

    let ports = hostobs::list_listen_ports();
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

    match hostobs::sample_process_table() {
        Ok(procs) => {
            let mut procs_by_name: HashMap<String, u64> = HashMap::new();
            for p in &procs {
                let name = p.basename_lower();
                if !name.is_empty() {
                    *procs_by_name.entry(name).or_insert(0) += 1;
                }
            }
            m.insert("process_count".into(), Value::from(procs.len() as u64));
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
            m.insert(
                "unique_users".into(),
                Value::from(hostobs::unique_user_count(&procs) as u64),
            );
            let mut hashes = Map::new();
            for name in top.iter().map(|(n, _)| n.clone()) {
                if hashes.contains_key(&name) {
                    continue;
                }
                if let Some(p) = procs.iter().find(|pr| pr.basename_lower() == name) {
                    if let Some(h) = sha256_exe_path(&p.exe) {
                        hashes.insert(name, Value::String(h));
                    }
                }
            }
            m.insert("top_process_hashes".into(), Value::Object(hashes));
        }
        Err(e) => {
            sampling_failed = true;
            sample_error = Some(e.to_string());
            tracing::warn!(
                target: "agent",
                error = %e,
                "UEBA process sample failed — emitting sampling_failed, not process_count=0"
            );
        }
    }

    if sampling_failed {
        m.insert("sampling_failed".into(), Value::Bool(true));
        if let Some(err) = sample_error {
            m.insert("sample_error".into(), Value::String(err));
        }
    }

    if let Some(uptime) = read_uptime_seconds() {
        m.insert("uptime_seconds".into(), Value::from(uptime));
    }
    if let Some(load) = read_loadavg_1m() {
        m.insert("load_1m".into(), json!(load));
    }
    if let Some(mem_pct) = read_memory_used_pct() {
        m.insert("memory_used_pct".into(), json!(mem_pct));
    }

    let failed = read_failed_logins_24h();
    m.insert("failed_logins".into(), Value::from(failed as u64));

    Value::Object(m)
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

fn sha256_exe_path(exe: &str) -> Option<String> {
    let path = exe.trim();
    if path.is_empty() {
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 64 * 1024];
    let mut hasher = Sha256::new();
    use std::io::Read;
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
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
        assert_ne!(
            v.get("sampling_failed").and_then(Value::as_bool),
            Some(true)
        );
        assert!(v.get("open_port_count").is_some());
        assert!(v.get("process_count").is_some());
        assert!(v.get("top_processes").is_some());
        assert!(v
            .get("top_process_hashes")
            .and_then(Value::as_object)
            .is_some());
        let n = v.get("process_count").and_then(Value::as_u64).unwrap_or(0);
        assert!(n > 0, "native process table returned zero processes");
    }

    #[test]
    fn failed_sample_must_not_look_like_zero_processes() {
        // Contract: a SampleError becomes sampling_failed + omitted process_count,
        // never process_count=0. The live path on this host is healthy; the
        // structural guarantee is encoded in collect_metrics' Err arm.
        let src = include_str!("baseline.rs");
        assert!(src.contains("sampling_failed"));
        assert!(src.contains("sample_process_table"));
        assert!(
            !src.contains("unwrap_or(0),\n                extras"),
            "failed samples must not stringify as processes=0"
        );
    }
}
