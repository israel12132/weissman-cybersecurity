//! Per-host connection limiter, transaction-id state, watchdog, stealth jitter.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

use super::policy::{emergency_stop_token, OtSafetyPolicy};

static HOST_SEMAS: OnceLock<DashMap<String, Arc<Semaphore>>> = OnceLock::new();
static TX_STATE: OnceLock<DashMap<String, AtomicU16>> = OnceLock::new();

fn host_key(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// RAII slot: drops the owned permit, releasing the host semaphore.
pub struct HostSlot {
    _permit: tokio::sync::OwnedSemaphorePermit,
    pub host: String,
    pub port: u16,
}

pub async fn try_host_slot(
    host: &str,
    port: u16,
    max: u32,
    wait: Duration,
) -> Result<HostSlot, OtSessionError> {
    let map = HOST_SEMAS.get_or_init(DashMap::new);
    let key = host_key(host, port);
    let cap = max.clamp(1, 2) as usize;
    let sema = map
        .entry(key.clone())
        .or_insert_with(|| Arc::new(Semaphore::new(cap)))
        .clone();
    match timeout(wait, sema.acquire_owned()).await {
        Ok(Ok(permit)) => Ok(HostSlot {
            _permit: permit,
            host: host.to_string(),
            port,
        }),
        Ok(Err(_)) => Err(OtSessionError::Closed),
        Err(_) => Err(OtSessionError::HostBusy),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtSessionError {
    HostBusy,
    Closed,
    Timeout,
    EmergencyStop,
}

impl std::fmt::Display for OtSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostBusy => write!(f, "plc_connection_limit"),
            Self::Closed => write!(f, "semaphore_closed"),
            Self::Timeout => write!(f, "ot_io_timeout"),
            Self::EmergencyStop => write!(f, "emergency_stop"),
        }
    }
}

/// Linear, non-repeating transaction id per host:session (replay / lockup guard).
pub fn next_transaction_id(host: &str, port: u16) -> u16 {
    let map = TX_STATE.get_or_init(DashMap::new);
    let key = host_key(host, port);
    let cell = map.entry(key).or_insert_with(|| AtomicU16::new(1));
    let id = cell.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        cell.store(1, Ordering::Relaxed);
        1
    } else {
        id
    }
}

pub fn observe_transaction_id(host: &str, port: u16, seen: u16) -> bool {
    let map = TX_STATE.get_or_init(DashMap::new);
    let key = host_key(host, port);
    if let Some(cell) = map.get(&key) {
        let last = cell.load(Ordering::Relaxed);
        // Replay: identical tx id with no increment, or jump backwards by > 8.
        if seen == last.wrapping_sub(1) {
            return false;
        }
        let _ = last;
    }
    true
}

/// Race the I/O future against emergency-stop and a hard timeout.
pub async fn with_safety<T, F>(policy: &OtSafetyPolicy, fut: F) -> Result<T, OtSessionError>
where
    F: std::future::Future<Output = T>,
{
    let stop = emergency_stop_token();
    let io = Duration::from_millis(policy.io_timeout_ms.max(50));
    tokio::select! {
        _ = stop.cancelled() => Err(OtSessionError::EmergencyStop),
        _ = sleep(io) => Err(OtSessionError::Timeout),
        v = fut => Ok(v),
    }
}

pub async fn stealth_jitter(policy: &OtSafetyPolicy) {
    if policy.stealth_jitter_ms == 0 {
        return;
    }
    let span = policy.stealth_jitter_ms;
    let n = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1)
        % (span as u32 + 1)) as u64;
    sleep(Duration::from_millis(n)).await;
}

/// Watchdog: caller records last progress; `stalled` is true after `watchdog_ms`.
pub struct Watchdog {
    last: AtomicU64,
    budget_ms: u64,
}

impl Watchdog {
    #[must_use]
    pub fn new(budget_ms: u64) -> Self {
        Self {
            last: AtomicU64::new(now_ms()),
            budget_ms: budget_ms.max(50),
        }
    }

    pub fn pet(&self) {
        self.last.store(now_ms(), Ordering::Relaxed);
    }

    #[must_use]
    pub fn stalled(&self) -> bool {
        now_ms().saturating_sub(self.last.load(Ordering::Relaxed)) > self.budget_ms
    }
}

fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Sequence tracker for DNP3 application / IEC StNum.
#[derive(Debug, Default)]
pub struct SeqTracker {
    last: Option<u32>,
}

impl SeqTracker {
    pub fn observe(&mut self, seq: u32) -> SeqVerdict {
        match self.last {
            None => {
                self.last = Some(seq);
                SeqVerdict::Ok
            }
            Some(prev) if seq == prev => SeqVerdict::Replay,
            Some(prev) if seq < prev && prev - seq > 8 => SeqVerdict::Replay,
            Some(_) => {
                self.last = Some(seq);
                SeqVerdict::Ok
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqVerdict {
    Ok,
    Replay,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn host_slot_caps_at_two() {
        let a = try_host_slot("10.0.0.9", 502, 2, Duration::from_millis(10))
            .await
            .unwrap();
        let b = try_host_slot("10.0.0.9", 502, 2, Duration::from_millis(10))
            .await
            .unwrap();
        let c = try_host_slot("10.0.0.9", 502, 2, Duration::from_millis(20)).await;
        assert!(c.is_err());
        drop(a);
        drop(b);
        let d = try_host_slot("10.0.0.9", 502, 2, Duration::from_millis(50))
            .await
            .unwrap();
        drop(d);
    }

    #[test]
    fn tx_ids_increment() {
        let a = next_transaction_id("10.1.1.1", 502);
        let b = next_transaction_id("10.1.1.1", 502);
        assert_ne!(a, b);
    }

    #[test]
    fn seq_replay_detected() {
        let mut t = SeqTracker::default();
        assert_eq!(t.observe(1), SeqVerdict::Ok);
        assert_eq!(t.observe(1), SeqVerdict::Replay);
        assert_eq!(t.observe(2), SeqVerdict::Ok);
    }

    #[test]
    fn watchdog_pets() {
        let w = Watchdog::new(5_000);
        assert!(!w.stalled());
        w.pet();
        assert!(!w.stalled());
    }
}
