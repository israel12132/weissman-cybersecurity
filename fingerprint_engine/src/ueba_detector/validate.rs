//! Schema, replay, and error-sanitisation for UEBA ingest payloads.

use serde_json::Value;
use std::collections::BTreeSet;

use super::stats::sanitize_f64;
use super::time::clamp_hour_of_week;

/// Maximum JSONB document we will accept (protects the ingest worker + Postgres).
pub const MAX_METRICS_BYTES: usize = 64 * 1024;
pub const MAX_TOP_PROCESSES: usize = 64;
pub const MAX_OPEN_PORTS: usize = 256;
pub const MAX_PROCESS_NAME_LEN: usize = 128;
pub const MAX_NONCE_LEN: usize = 64;

const ALLOWED_NUMERIC: &[&str] = &[
    "open_port_count",
    "process_count",
    "unique_users",
    "uptime_seconds",
    "load_1m",
    "memory_used_pct",
    "outbound_bytes",
    "failed_logins",
    "sudo_failures",
    "uac_failures",
    "memory_rss_kb",
    "conn_count",
    "conn_fail_count",
    "unique_remote_ips",
    "dns_query_entropy",
    "lsass_handle_count",
    "thread_count",
    "interrupt_delta",
    "sample_interval_ms",
    "ghost_ppid_count",
];

const ALLOWED_ARRAY: &[&str] = &[
    "open_ports",
    "top_processes",
    "process_paths",
    "process_sha256",
    "listen_map",
    "ghost_ppids",
];

const ALLOWED_META: &[&str] = &[
    "uptime_reset",
    "lite_sample",
    "auth_log_readable",
    "clock_skew_secs",
    "hardware_id",
    "battery",
    "tracer_pid",
    "debugger_present",
    "os",
    "seq",
    "nonce",
    "sampled_at",
    "session_user",
    "logon_type",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestReject {
    EmptyAgent,
    BadHour,
    MetricsNotObject,
    MetricsTooLarge,
    UnknownField(&'static str),
    BadType(&'static str),
    Replay,
    Scope,
    RateLimited,
    NoLiveSession,
    DiskGuard,
    Schema,
}

impl IngestReject {
    pub fn status_and_detail(&self) -> (u16, &'static str) {
        match self {
            Self::EmptyAgent
            | Self::BadHour
            | Self::MetricsNotObject
            | Self::BadType(_)
            | Self::UnknownField(_)
            | Self::Schema
            | Self::MetricsTooLarge => (400, "invalid ingest payload"),
            Self::Replay => (409, "replay rejected"),
            Self::Scope => (403, "agent out of client scope"),
            Self::RateLimited => (429, "agent sample rate exceeded"),
            Self::NoLiveSession => (403, "no live agent session"),
            Self::DiskGuard => (503, "ingest paused"),
        }
    }
}

/// Strip control characters / NULs that have historically crashed JSON parsers downstream.
pub fn sanitize_process_name(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len().min(MAX_PROCESS_NAME_LEN));
    for ch in raw.chars() {
        if s.len() >= MAX_PROCESS_NAME_LEN {
            break;
        }
        if ch == '\0' || ch.is_control() {
            continue;
        }
        if ch == '\\' || ch == '/' {
            s.clear(); // keep basename only
            continue;
        }
        s.push(ch);
    }
    let s = s.trim().to_ascii_lowercase();
    let s = s.strip_suffix(".exe").unwrap_or(s.as_str()).to_string();
    s
}

/// Keep POSIX/Windows path separators so masquerading checks still see the real image path.
pub fn sanitize_exe_path(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len().min(256));
    for ch in raw.chars() {
        if s.len() >= 256 {
            break;
        }
        if ch == '\0' || ch.is_control() {
            continue;
        }
        s.push(ch);
    }
    s.trim().to_string()
}

/// `port:process` listen map. Ephemeral ports are dropped.
fn sanitize_listen_map_entry(raw: &str) -> String {
    let t = raw.trim();
    let Some((port_s, proc)) = t.split_once(':') else {
        return String::new();
    };
    let Ok(port) = port_s.parse::<i32>() else {
        return String::new();
    };
    if is_ephemeral_port(port) || !(1..=65535).contains(&port) {
        return String::new();
    }
    let proc = sanitize_process_name(proc);
    if proc.is_empty() {
        return String::new();
    }
    format!("{port}:{proc}")
}

/// Linux/Windows ephemeral ranges are excluded from categorical port anomalies.
pub fn is_ephemeral_port(port: i32) -> bool {
    (32768..=61000).contains(&port) || (49152..=65535).contains(&port)
}

pub fn normalize_listen_port(port: i64) -> Option<i32> {
    if (1..=65535).contains(&port) {
        let p = port as i32;
        if is_ephemeral_port(p) {
            None
        } else {
            Some(p)
        }
    } else {
        None
    }
}

/// Validate + sanitise a metrics object in place. Unknown keys are dropped (not rejected) so
/// a newer agent can talk to an older server; disallowed *types* on known keys fail closed.
pub fn sanitize_metrics(metrics: &mut Value) -> Result<(), IngestReject> {
    let obj = metrics
        .as_object_mut()
        .ok_or(IngestReject::MetricsNotObject)?;
    let encoded = serde_json::to_vec(&*obj).unwrap_or_default();
    if encoded.len() > MAX_METRICS_BYTES {
        return Err(IngestReject::MetricsTooLarge);
    }

    let allowed: BTreeSet<&str> = ALLOWED_NUMERIC
        .iter()
        .chain(ALLOWED_ARRAY.iter())
        .chain(ALLOWED_META.iter())
        .copied()
        .collect();

    let keys: Vec<String> = obj.keys().cloned().collect();
    for k in keys {
        if !allowed.contains(k.as_str()) {
            obj.remove(&k);
            continue;
        }
        if ALLOWED_NUMERIC.contains(&k.as_str()) {
            match obj.get(&k) {
                Some(Value::Number(n)) => {
                    let v = sanitize_f64(n.as_f64().unwrap_or(0.0));
                    obj.insert(k, Value::from(v));
                }
                Some(Value::Null) => {
                    obj.remove(&k);
                }
                _ => return Err(IngestReject::BadType("numeric")),
            }
            continue;
        }
        if k == "open_ports" {
            let ports = obj
                .get(&k)
                .and_then(Value::as_array)
                .ok_or(IngestReject::BadType("open_ports"))?;
            let mut clean: Vec<Value> = Vec::new();
            for p in ports.iter().take(MAX_OPEN_PORTS) {
                if let Some(n) = p.as_i64().and_then(normalize_listen_port) {
                    clean.push(Value::from(n));
                }
            }
            clean.sort_by_key(|v| v.as_i64().unwrap_or(0));
            clean.dedup();
            obj.insert(k, Value::Array(clean));
            continue;
        }
        if k == "top_processes" {
            let procs = obj
                .get(&k)
                .and_then(Value::as_array)
                .ok_or(IngestReject::BadType("top_processes"))?;
            let mut clean: Vec<Value> = Vec::new();
            for p in procs.iter().take(MAX_TOP_PROCESSES) {
                let Some(s) = p.as_str() else { continue };
                let n = sanitize_process_name(s);
                if !n.is_empty() {
                    clean.push(Value::String(n));
                }
            }
            obj.insert(k, Value::Array(clean));
            continue;
        }
        if k == "listen_map" {
            let arr = obj
                .get(&k)
                .and_then(Value::as_array)
                .ok_or(IngestReject::BadType("array"))?;
            let mut clean: Vec<Value> = Vec::new();
            for p in arr.iter().take(MAX_OPEN_PORTS) {
                let Some(s) = p.as_str() else { continue };
                let n = sanitize_listen_map_entry(s);
                if !n.is_empty() {
                    clean.push(Value::String(n));
                }
            }
            obj.insert(k, Value::Array(clean));
            continue;
        }
        if k == "process_paths" {
            let arr = obj
                .get(&k)
                .and_then(Value::as_array)
                .ok_or(IngestReject::BadType("array"))?;
            let mut clean: Vec<Value> = Vec::new();
            for p in arr.iter().take(MAX_TOP_PROCESSES) {
                let Some(s) = p.as_str() else { continue };
                let n = sanitize_exe_path(s);
                if !n.is_empty() {
                    clean.push(Value::String(n));
                }
            }
            obj.insert(k, Value::Array(clean));
            continue;
        }
        if k == "ghost_ppids" {
            let arr = obj
                .get(&k)
                .and_then(Value::as_array)
                .ok_or(IngestReject::BadType("array"))?;
            let mut clean: Vec<Value> = Vec::new();
            for p in arr.iter().take(MAX_TOP_PROCESSES) {
                if let Some(n) = p.as_u64() {
                    clean.push(Value::from(n));
                }
            }
            obj.insert(k, Value::Array(clean));
            continue;
        }
        if k == "process_sha256" {
            let arr = obj
                .get(&k)
                .and_then(Value::as_array)
                .ok_or(IngestReject::BadType("array"))?;
            let mut clean: Vec<Value> = Vec::new();
            for p in arr.iter().take(16) {
                let Some(s) = p.as_str() else { continue };
                let h: String = s
                    .chars()
                    .filter(|c| c.is_ascii_hexdigit())
                    .take(64)
                    .collect();
                if h.len() == 64 {
                    clean.push(Value::String(h.to_ascii_lowercase()));
                }
            }
            obj.insert(k, Value::Array(clean));
        }
    }
    Ok(())
}

pub fn validate_hour(hour_of_week: i16) -> Result<i16, IngestReject> {
    if !(0..=167).contains(&hour_of_week) {
        return Err(IngestReject::BadHour);
    }
    Ok(clamp_hour_of_week(hour_of_week))
}

pub fn validate_agent_id(agent_id: &str) -> Result<(), IngestReject> {
    let t = agent_id.trim();
    if t.is_empty() || t.len() > 80 {
        return Err(IngestReject::EmptyAgent);
    }
    Ok(())
}

pub fn validate_nonce(nonce: &str) -> bool {
    let t = nonce.trim();
    (8..=MAX_NONCE_LEN).contains(&t.len())
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Public-facing ingest errors never include paths, SQL, or variable names.
pub fn public_error(_: &str) -> &'static str {
    "ingest failed"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn process_name_strips_controls_and_exe() {
        assert_eq!(
            sanitize_process_name("C:\\Windows\\System32\\svchost.exe\n"),
            "svchost"
        );
        assert_eq!(sanitize_process_name("nginx\0worker"), "nginxworker");
        assert_eq!(sanitize_process_name("/usr/sbin/sshd"), "sshd");
    }

    #[test]
    fn ephemeral_ports_dropped() {
        assert!(is_ephemeral_port(35000));
        assert!(!is_ephemeral_port(443));
        assert_eq!(normalize_listen_port(443), Some(443));
        assert_eq!(normalize_listen_port(50000), None);
    }

    #[test]
    fn sanitize_metrics_keeps_known_drops_unknown() {
        let mut v = json!({
            "load_1m": 1.5,
            "open_ports": [22, 80, 443, 50000],
            "top_processes": ["Nginx.EXE", "sshd"],
            "evil_key": "nope",
            "failed_logins": 3
        });
        sanitize_metrics(&mut v).unwrap();
        let o = v.as_object().unwrap();
        assert!(o.get("evil_key").is_none());
        let ports: Vec<i64> = o["open_ports"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.as_i64())
            .collect();
        assert_eq!(ports, vec![22, 80, 443]);
        assert_eq!(o["top_processes"][0], "nginx");
    }

    #[test]
    fn reject_non_object() {
        let mut v = json!([1, 2, 3]);
        assert_eq!(
            sanitize_metrics(&mut v).unwrap_err(),
            IngestReject::MetricsNotObject
        );
    }

    #[test]
    fn public_error_does_not_echo_internal() {
        assert_eq!(public_error("/var/lib/postgresql"), "ingest failed");
    }

    #[test]
    fn listen_map_drops_ephemeral_and_keeps_pair() {
        let mut v = json!({
            "listen_map": ["443:nginx", "50000:chrome", "22:sshd"],
            "process_paths": ["/usr/sbin/sshd"],
            "process_sha256": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
        });
        sanitize_metrics(&mut v).unwrap();
        let lm: Vec<&str> = v["listen_map"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        assert_eq!(lm, vec!["443:nginx", "22:sshd"]);
        assert_eq!(v["process_paths"][0], "/usr/sbin/sshd");
    }
}
