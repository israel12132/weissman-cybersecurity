//! Per-host probe I/O calibration and block detection.
//!
//! If more than 20% of recent attempts time out, pause that host for 300 seconds
//! and signal the caller to rotate evasion strategy.

use dashmap::DashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

pub const TIMEOUT_PAUSE_RATIO: f64 = 0.20;
pub const PAUSE_SECS: u64 = 300;
const WINDOW: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseDecision {
    Continue,
    PauseRotate,
}

#[derive(Debug, Default)]
struct HostWindow {
    results: Vec<bool>, // true = timeout
    paused_until: Option<Instant>,
}

static HOSTS: LazyLock<DashMap<String, Mutex<HostWindow>>> = LazyLock::new(DashMap::new);

pub fn is_paused(host: &str) -> bool {
    let Some(slot) = HOSTS.get(&host.to_ascii_lowercase()) else {
        return false;
    };
    let Ok(w) = slot.lock() else {
        return false;
    };
    w.paused_until.map(|t| Instant::now() < t).unwrap_or(false)
}

pub fn record_attempt(host: &str, timed_out: bool) -> PauseDecision {
    let key = host.to_ascii_lowercase();
    let slot = HOSTS.entry(key).or_default();
    let mut w = match slot.lock() {
        Ok(g) => g,
        Err(_) => return PauseDecision::Continue,
    };
    if let Some(until) = w.paused_until {
        if Instant::now() < until {
            return PauseDecision::PauseRotate;
        }
        w.paused_until = None;
        w.results.clear();
    }
    w.results.push(timed_out);
    if w.results.len() > WINDOW {
        let overflow = w.results.len() - WINDOW;
        w.results.drain(0..overflow);
    }
    if w.results.len() < 5 {
        return PauseDecision::Continue;
    }
    let timeouts = w.results.iter().filter(|t| **t).count();
    let ratio = timeouts as f64 / w.results.len() as f64;
    if ratio > TIMEOUT_PAUSE_RATIO {
        w.paused_until = Some(Instant::now() + Duration::from_secs(PAUSE_SECS));
        PauseDecision::PauseRotate
    } else {
        PauseDecision::Continue
    }
}

/// Adaptive connect timeout: start at 8s, grow to 20s after slow handshakes.
pub fn connect_timeout_secs() -> u64 {
    std::env::var("WEISSMAN_PROBE_CONNECT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        .clamp(3, 20)
}

pub fn pool_max_idle() -> usize {
    std::env::var("WEISSMAN_HTTP_POOL_MAX_IDLE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32)
        .clamp(4, 128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_timeouts_pause() {
        let host = format!("pause-test-{}", std::process::id());
        let mut last = PauseDecision::Continue;
        for _ in 0..6 {
            last = record_attempt(&host, true);
        }
        assert_eq!(last, PauseDecision::PauseRotate);
        assert!(is_paused(&host));
    }

    #[test]
    fn healthy_host_continues() {
        let host = format!("ok-test-{}", std::process::id());
        for _ in 0..10 {
            assert_eq!(record_attempt(&host, false), PauseDecision::Continue);
        }
        assert!(!is_paused(&host));
    }
}
