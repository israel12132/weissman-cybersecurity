//! Process-local health + failsafe flags for `/api/health` and the ingest worker.

use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;

static INGEST_OK: AtomicBool = AtomicBool::new(true);
static RETENTION_OK: AtomicBool = AtomicBool::new(true);
static FAILSAFE: AtomicBool = AtomicBool::new(false);
static QUEUE_DEPTH: AtomicU64 = AtomicU64::new(0);
static LAST_RETENTION_UNIX: AtomicU64 = AtomicU64::new(0);
static LAST_RETENTION_MS: AtomicU64 = AtomicU64::new(0);
static LAST_INGEST_UNIX: AtomicU64 = AtomicU64::new(0);
static ROWS_PURGED: AtomicU64 = AtomicU64::new(0);

fn flag() -> &'static AtomicBool {
    static ONCE: OnceLock<AtomicBool> = OnceLock::new();
    ONCE.get_or_init(|| AtomicBool::new(true))
}

#[allow(dead_code)]
fn _keep_flag() {
    let _ = flag();
}

pub fn set_ingest_ok(ok: bool) {
    INGEST_OK.store(ok, Ordering::Relaxed);
}

pub fn set_retention_ok(ok: bool) {
    RETENTION_OK.store(ok, Ordering::Relaxed);
}

pub fn set_failsafe(on: bool) {
    FAILSAFE.store(on, Ordering::Relaxed);
}

pub fn failsafe() -> bool {
    FAILSAFE.load(Ordering::Relaxed)
}

pub fn set_queue_depth(n: usize) {
    QUEUE_DEPTH.store(n as u64, Ordering::Relaxed);
}

pub fn note_ingest() {
    LAST_INGEST_UNIX.store(Utc::now().timestamp().max(0) as u64, Ordering::Relaxed);
    set_ingest_ok(true);
}

pub fn note_retention(elapsed_ms: u64, rows: u64) {
    LAST_RETENTION_UNIX.store(Utc::now().timestamp().max(0) as u64, Ordering::Relaxed);
    LAST_RETENTION_MS.store(elapsed_ms, Ordering::Relaxed);
    ROWS_PURGED.store(rows, Ordering::Relaxed);
    set_retention_ok(true);
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UebaHealth {
    pub ingest_ok: bool,
    pub retention_ok: bool,
    pub failsafe: bool,
    pub ingest_queue_depth: u64,
    pub last_ingest_unix: Option<u64>,
    pub last_retention_unix: Option<u64>,
    pub last_retention_ms: u64,
    pub last_retention_rows: u64,
}

pub fn snapshot() -> UebaHealth {
    let li = LAST_INGEST_UNIX.load(Ordering::Relaxed);
    let lr = LAST_RETENTION_UNIX.load(Ordering::Relaxed);
    UebaHealth {
        ingest_ok: INGEST_OK.load(Ordering::Relaxed),
        retention_ok: RETENTION_OK.load(Ordering::Relaxed),
        failsafe: failsafe(),
        ingest_queue_depth: QUEUE_DEPTH.load(Ordering::Relaxed),
        last_ingest_unix: if li == 0 { None } else { Some(li) },
        last_retention_unix: if lr == 0 { None } else { Some(lr) },
        last_retention_ms: LAST_RETENTION_MS.load(Ordering::Relaxed),
        last_retention_rows: ROWS_PURGED.load(Ordering::Relaxed),
    }
}

pub fn as_json() -> serde_json::Value {
    let h = snapshot();
    serde_json::json!({
        "ingest_ok": h.ingest_ok,
        "retention_ok": h.retention_ok,
        "failsafe": h.failsafe,
        "ingest_queue_depth": h.ingest_queue_depth,
        "last_ingest_unix": h.last_ingest_unix,
        "last_retention_unix": h.last_retention_unix,
        "last_retention_ms": h.last_retention_ms,
        "last_retention_rows": h.last_retention_rows,
    })
}

/// Host CPU busy estimate from /proc/stat. Returns 0..=100. None when unreadable.
pub fn host_cpu_busy_pct() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/stat").ok()?;
        let line = s.lines().next()?;
        let mut it = line.split_whitespace();
        if it.next()? != "cpu" {
            return None;
        }
        let nums: Vec<f64> = it.filter_map(|x| x.parse().ok()).collect();
        if nums.len() < 4 {
            return None;
        }
        let idle = nums[3] + nums.get(4).copied().unwrap_or(0.0);
        let total: f64 = nums.iter().sum();
        if total <= 0.0 {
            return None;
        }
        Some(((total - idle) / total * 100.0).clamp(0.0, 100.0))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub fn disk_free_pct(path: &str) -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/mounts").ok()?;
        let _ = s; // mounts not required; use statvfs via libc if present, else df-less fallback
                   // Read from /proc/self/mountinfo is overkill; use std::fs::metadata on path.
        let _ = path;
        // Best-effort: parse `MemAvailable` is wrong. Use `statvfs` via a tiny Command-free
        // read of /proc/diskstats? We expose None when we cannot measure honestly.
        disk_free_pct_statvfs(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

#[cfg(target_os = "linux")]
fn disk_free_pct_statvfs(path: &str) -> Option<f64> {
    // Avoid a new libc dep: parse `df` is forbidden (CLI). Read nothing rather than guess.
    // The worker still honours WEISSMAN_UEBA_DISK_FREE_PCT when an operator injects it.
    if let Ok(v) = std::env::var("WEISSMAN_UEBA_DISK_FREE_PCT") {
        return v.parse().ok();
    }
    let _ = path;
    None
}

#[allow(dead_code)]
pub fn last_retention_age_secs() -> Option<i64> {
    let ts = LAST_RETENTION_UNIX.load(Ordering::Relaxed) as i64;
    if ts == 0 {
        return None;
    }
    Some((Utc::now().timestamp() - ts).max(0))
}

#[allow(dead_code)]
pub fn last_retention_at() -> Option<DateTime<Utc>> {
    let ts = LAST_RETENTION_UNIX.load(Ordering::Relaxed) as i64;
    if ts == 0 {
        return None;
    }
    DateTime::from_timestamp(ts, 0)
}
