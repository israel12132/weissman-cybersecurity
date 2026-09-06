//! Process-wide atomic counters — no mutex on the hot path.

use crate::llm_ultra_guard::{tuning, Verdict};
use serde_json::json;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static INFLIGHT: AtomicU32 = AtomicU32::new(0);
static SCANS: AtomicU64 = AtomicU64::new(0);
static BLOCKS: AtomicU64 = AtomicU64::new(0);
static QUARANTINES: AtomicU64 = AtomicU64::new(0);
static ALLOWS: AtomicU64 = AtomicU64::new(0);
static LATENCY_US_SUM: AtomicU64 = AtomicU64::new(0);
static LATENCY_US_MAX: AtomicU64 = AtomicU64::new(0);
static LOAD_SHEDS: AtomicU64 = AtomicU64::new(0);

pub struct InflightGuard;

impl InflightGuard {
    pub fn enter() -> Self {
        INFLIGHT.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        INFLIGHT.fetch_sub(1, Ordering::Relaxed);
    }
}

#[must_use]
pub fn should_load_shed() -> bool {
    let inflight = INFLIGHT.load(Ordering::Relaxed);
    let cap = tuning::SANITIZATION.max_inflight.max(1);
    let ratio = inflight as f32 / cap as f32;
    if ratio >= tuning::SANITIZATION.load_shed_ratio {
        LOAD_SHEDS.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

pub fn record_scan(latency_us: u64, verdict: Verdict) {
    SCANS.fetch_add(1, Ordering::Relaxed);
    LATENCY_US_SUM.fetch_add(latency_us, Ordering::Relaxed);
    LATENCY_US_MAX.fetch_max(latency_us, Ordering::Relaxed);
    match verdict {
        Verdict::Block => {
            BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        Verdict::Quarantine => {
            QUARANTINES.fetch_add(1, Ordering::Relaxed);
        }
        Verdict::Allow => {
            ALLOWS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[must_use]
pub fn snapshot() -> serde_json::Value {
    let scans = SCANS.load(Ordering::Relaxed);
    let sum = LATENCY_US_SUM.load(Ordering::Relaxed);
    json!({
        "inflight": INFLIGHT.load(Ordering::Relaxed),
        "max_inflight": tuning::SANITIZATION.max_inflight,
        "scans": scans,
        "blocks": BLOCKS.load(Ordering::Relaxed),
        "quarantines": QUARANTINES.load(Ordering::Relaxed),
        "allows": ALLOWS.load(Ordering::Relaxed),
        "load_sheds": LOAD_SHEDS.load(Ordering::Relaxed),
        "latency_us_avg": if scans == 0 { 0 } else { sum / scans },
        "latency_us_max": LATENCY_US_MAX.load(Ordering::Relaxed),
        "load_shed_ratio": tuning::SANITIZATION.load_shed_ratio,
    })
}
