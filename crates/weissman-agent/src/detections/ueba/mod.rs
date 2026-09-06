//! Agent-side UEBA sampling helpers (OS readers, smoothing, offline buffer, clock).

mod clock;
#[cfg(target_os = "linux")]
mod linux;
mod macos;
mod offline;
mod smooth;
mod windows;

pub use clock::{hour_of_week_corrected, note_http_date, note_server_utc_ms, skew_secs};
pub use offline::{drain_offline, next_nonce, next_seq, push_offline};
pub use smooth::{ema_load, ema_mem, note_uptime};

use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicBool, Ordering};

pub const TOP_PROCESSES_LIMIT: usize = 24;
pub const MAX_TOP_PROCESSES: usize = TOP_PROCESSES_LIMIT;

static LITE: AtomicBool = AtomicBool::new(false);

pub fn set_lite(on: bool) {
    LITE.store(on, Ordering::Relaxed);
}

pub fn is_lite() -> bool {
    LITE.load(Ordering::Relaxed)
}
const OPEN_PORTS_LIMIT: usize = 64;

pub fn collect_metrics(lite: bool) -> Value {
    let lite = lite || rss_over_cap();
    if lite {
        set_lite(true);
    }
    let mut m = Map::new();

    let ports = read_listening_tcp_ports();
    m.insert("open_port_count".into(), Value::from(ports.len() as u64));
    m.insert(
        "open_ports".into(),
        Value::Array(
            ports
                .iter()
                .take(OPEN_PORTS_LIMIT)
                .map(|p| Value::from(*p as u64))
                .collect(),
        ),
    );

    let snapshot = read_process_snapshot(lite);
    m.insert("process_count".into(), Value::from(snapshot.process_count));
    m.insert(
        "top_processes".into(),
        Value::Array(
            snapshot
                .top
                .iter()
                .map(|n| Value::String(n.clone()))
                .collect(),
        ),
    );
    if !snapshot.paths.is_empty() {
        m.insert(
            "process_paths".into(),
            Value::Array(snapshot.paths.into_iter().map(Value::String).collect()),
        );
    }
    if !snapshot.sha256.is_empty() {
        m.insert(
            "process_sha256".into(),
            Value::Array(snapshot.sha256.into_iter().map(Value::String).collect()),
        );
    }
    if !snapshot.listen_map.is_empty() {
        m.insert(
            "listen_map".into(),
            Value::Array(snapshot.listen_map.into_iter().map(Value::String).collect()),
        );
    }
    if !snapshot.ghost_ppids.is_empty() {
        m.insert(
            "ghost_ppid_count".into(),
            Value::from(snapshot.ghost_ppids.len() as u64),
        );
    }
    m.insert("unique_users".into(), Value::from(snapshot.unique_users));
    if snapshot.process_count == 0 {
        if crate::hostobs::sample_process_table().is_err() {
            m.insert("sampling_failed".into(), Value::Bool(true));
        }
    }
    if snapshot.thread_count > 0 {
        m.insert("thread_count".into(), Value::from(snapshot.thread_count));
    }

    if let Some(uptime) = read_uptime_seconds() {
        let reset = note_uptime(uptime);
        m.insert("uptime_seconds".into(), Value::from(uptime));
        if reset {
            m.insert("uptime_reset".into(), Value::Bool(true));
        }
    }
    if let Some(load) = read_loadavg_1m() {
        m.insert("load_1m".into(), json!(ema_load(load)));
    }
    if let Some(mem_pct) = read_memory_used_pct() {
        m.insert("memory_used_pct".into(), json!(ema_mem(mem_pct)));
    }
    if let Some(rss) = read_self_rss_kb() {
        m.insert("memory_rss_kb".into(), json!(rss));
    }

    let (auth_readable, failed) = read_failed_logins_24h();
    m.insert("failed_logins".into(), Value::from(failed as u64));
    m.insert("auth_log_readable".into(), Value::Bool(auth_readable));

    m.insert("os".into(), Value::String(std::env::consts::OS.into()));
    if let Some(hw) = hardware_id() {
        m.insert("hardware_id".into(), Value::String(hw));
    }
    if let Some(uid) = session_user() {
        m.insert("session_user".into(), Value::String(uid));
    }
    if let Some(tracer) = tracer_pid() {
        m.insert("tracer_pid".into(), Value::from(tracer));
        if tracer > 0 {
            m.insert("debugger_present".into(), Value::Bool(true));
        }
    }
    if battery_discharging() {
        m.insert("battery".into(), Value::String("discharging".into()));
    }
    m.insert("seq".into(), Value::from(next_seq()));
    m.insert("nonce".into(), Value::String(next_nonce()));
    if lite {
        m.insert("lite_sample".into(), Value::Bool(true));
    }
    let skew = skew_secs();
    if skew.abs() > 0 {
        m.insert("clock_skew_secs".into(), Value::from(skew));
    }

    let net = read_network_summary();
    if net.conn_count > 0 {
        m.insert("conn_count".into(), Value::from(net.conn_count));
        m.insert("conn_fail_count".into(), Value::from(net.conn_fail_count));
        m.insert(
            "unique_remote_ips".into(),
            Value::from(net.unique_remote_ips),
        );
    }

    Value::Object(m)
}

pub struct ProcessSnapshot {
    pub process_count: u64,
    pub unique_users: u64,
    pub top: Vec<String>,
    pub paths: Vec<String>,
    pub sha256: Vec<String>,
    pub listen_map: Vec<String>,
    pub ghost_ppids: Vec<u32>,
    pub thread_count: u64,
}

pub struct NetSummary {
    pub conn_count: u64,
    pub conn_fail_count: u64,
    pub unique_remote_ips: u64,
}

fn read_listening_tcp_ports() -> Vec<u16> {
    #[cfg(target_os = "linux")]
    {
        linux::listening_tcp_ports()
    }
    #[cfg(target_os = "windows")]
    {
        windows::listening_tcp_ports()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

fn read_process_snapshot(lite: bool) -> ProcessSnapshot {
    #[cfg(target_os = "linux")]
    {
        linux::process_snapshot(lite)
    }
    #[cfg(target_os = "windows")]
    {
        windows::process_snapshot(lite)
    }
    #[cfg(target_os = "macos")]
    {
        macos::process_snapshot(lite)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = lite;
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
}

fn read_uptime_seconds() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        linux::uptime_seconds()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn read_loadavg_1m() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        linux::loadavg_1m()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn read_memory_used_pct() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        linux::memory_used_pct()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn read_self_rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        linux::self_rss_kb()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn read_failed_logins_24h() -> (bool, u32) {
    #[cfg(target_os = "linux")]
    {
        linux::failed_logins_24h()
    }
    #[cfg(target_os = "windows")]
    {
        windows::failed_logins_24h()
    }
    #[cfg(target_os = "macos")]
    {
        macos::failed_logins_24h()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        (false, 0)
    }
}

fn hardware_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux::hardware_id()
    }
    #[cfg(target_os = "windows")]
    {
        windows::hardware_id()
    }
    #[cfg(target_os = "macos")]
    {
        macos::hardware_id()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        None
    }
}

fn session_user() -> Option<String> {
    let u = whoami::username();
    if u.trim().is_empty() {
        None
    } else {
        Some(u)
    }
}

fn tracer_pid() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        linux::tracer_pid()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn battery_discharging() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::battery_discharging()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn read_network_summary() -> NetSummary {
    #[cfg(target_os = "linux")]
    {
        linux::network_summary()
    }
    #[cfg(not(target_os = "linux"))]
    {
        NetSummary {
            conn_count: 0,
            conn_fail_count: 0,
            unique_remote_ips: 0,
        }
    }
}

pub fn sanitize_comm(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len().min(64));
    for ch in raw.chars() {
        if s.len() >= 64 {
            break;
        }
        if ch == '\0' || ch.is_control() {
            continue;
        }
        s.push(ch);
    }
    let s = s.trim().to_ascii_lowercase();
    s.strip_suffix(".exe").unwrap_or(&s).to_string()
}

pub fn is_ephemeral(port: u16) -> bool {
    (32768..=61000).contains(&port) || (49152..=65535).contains(&port)
}

pub fn rss_over_cap() -> bool {
    read_self_rss_kb().map(|kb| kb > 50 * 1024).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_comm_strips_control_and_exe() {
        assert_eq!(sanitize_comm("svchost.exe\n"), "svchost");
        assert_eq!(sanitize_comm("NOTEPAD.EXE"), "notepad");
        assert_eq!(sanitize_comm("bash\0\r"), "bash");
        assert_eq!(sanitize_comm("  systemd  "), "systemd");
    }

    #[test]
    fn ephemeral_ranges_match_iana_and_linux() {
        assert!(is_ephemeral(32768));
        assert!(is_ephemeral(61000));
        assert!(is_ephemeral(49152));
        assert!(!is_ephemeral(443));
        assert!(!is_ephemeral(22));
    }
}
