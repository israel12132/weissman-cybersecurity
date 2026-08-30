//! Per-host / per-station connection limiter, transaction-id state, watchdog,
//! stealth jitter, and PLC-safe socket release (no half-open TCP).

use dashmap::DashMap;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

use super::policy::{emergency_stop_token, OtSafetyPolicy};

static PLC_SEMAS: OnceLock<DashMap<String, Arc<Semaphore>>> = OnceLock::new();
static GW_SEMAS: OnceLock<DashMap<String, Arc<Semaphore>>> = OnceLock::new();
static UNIT_SEMAS: OnceLock<DashMap<String, Arc<Semaphore>>> = OnceLock::new();
static TX_STATE: OnceLock<DashMap<String, AtomicU16>> = OnceLock::new();

pub const PLC_PHYSICAL_CAP: u32 = 2;
/// Moxa NPort / serial gateways collapse above 1–2 TCP pipes. Unit IDs multiplex.
pub const GATEWAY_PHYSICAL_CAP: u32 = 2;
pub const STATION_LOGICAL_CAP: usize = 1;
/// Wait after FIN before a last-resort RST. Old S7-300 stacks panic on linger=0 sprays.
pub const GRACEFUL_CLOSE_WAIT: Duration = Duration::from_millis(10);

fn host_key(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// Protocol station behind a shared TCP endpoint (Modbus gateway / DNP3 outstation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StationId {
    Unspecified,
    ModbusUnit(u8),
    Dnp3Addr(u16),
}

impl StationId {
    fn logical_suffix(self) -> Option<String> {
        match self {
            Self::Unspecified => None,
            Self::ModbusUnit(u) => Some(format!("mu:{u}")),
            Self::Dnp3Addr(a) => Some(format!("dnp:{a}")),
        }
    }
}

/// RAII slot: physical permit (and optional per-station logical permit).
pub struct HostSlot {
    _physical: tokio::sync::OwnedSemaphorePermit,
    _logical: Option<tokio::sync::OwnedSemaphorePermit>,
    pub host: String,
    pub port: u16,
    pub station: StationId,
}

/// Dedicated PLC: max 2 TCP sockets on the raw IP (DoS guard).
pub async fn try_host_slot(
    host: &str,
    port: u16,
    max: u32,
    wait: Duration,
) -> Result<HostSlot, OtSessionError> {
    acquire_slot(
        host,
        port,
        StationId::Unspecified,
        max.clamp(1, PLC_PHYSICAL_CAP),
        wait,
    )
    .await
}

/// Gateway-aware: physical cap on the IP (max 2 — serial RTU behind the gateway is one
/// RS-485 pipe) plus one logical slot per Unit/Station ID. Extra units wait and reuse
/// a pipe (MBAP multiplexing) instead of opening a third socket.
pub async fn try_station_slot(
    host: &str,
    port: u16,
    station: StationId,
    gateway_max: u32,
    wait: Duration,
) -> Result<HostSlot, OtSessionError> {
    acquire_slot(
        host,
        port,
        station,
        gateway_max.clamp(1, GATEWAY_PHYSICAL_CAP),
        wait,
    )
    .await
}

async fn acquire_slot(
    host: &str,
    port: u16,
    station: StationId,
    physical_max: u32,
    wait: Duration,
) -> Result<HostSlot, OtSessionError> {
    let phys_map = if station == StationId::Unspecified {
        PLC_SEMAS.get_or_init(DashMap::new)
    } else {
        GW_SEMAS.get_or_init(DashMap::new)
    };
    let phys_key = host_key(host, port);
    let cap = physical_max.max(1) as usize;
    let phys = phys_map
        .entry(phys_key)
        .or_insert_with(|| Arc::new(Semaphore::new(cap)))
        .clone();

    let physical = match timeout(wait, phys.acquire_owned()).await {
        Ok(Ok(p)) => p,
        Ok(Err(_)) => return Err(OtSessionError::Closed),
        Err(_) => return Err(OtSessionError::HostBusy),
    };

    let logical = if let Some(suffix) = station.logical_suffix() {
        let unit_map = UNIT_SEMAS.get_or_init(DashMap::new);
        let ukey = format!("{}:{suffix}", host_key(host, port));
        let unit = unit_map
            .entry(ukey)
            .or_insert_with(|| Arc::new(Semaphore::new(STATION_LOGICAL_CAP)))
            .clone();
        match timeout(wait, unit.acquire_owned()).await {
            Ok(Ok(p)) => Some(p),
            Ok(Err(_)) => return Err(OtSessionError::Closed),
            Err(_) => return Err(OtSessionError::HostBusy),
        }
    } else {
        None
    };

    Ok(HostSlot {
        _physical: physical,
        _logical: logical,
        host: host.to_string(),
        port,
        station,
    })
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
        if seen == last.wrapping_sub(1) {
            return false;
        }
        let _ = last;
    }
    true
}

/// Last-resort RST only. Never call this on the happy path — S7-300 / MicroLogix
/// TCP stacks wedge or reboot under linger=0 sprays.
#[allow(deprecated)]
fn arm_rst_last_resort(stream: &TcpStream) {
    let _ = stream.set_linger(Some(Duration::ZERO));
}

/// Graceful deceleration: FIN first, 10 ms for the PLC to ACK, RST only if silent.
pub async fn graceful_plc_socket_close(stream: &mut TcpStream) {
    let _ = stream.shutdown().await;
    tokio::select! {
        _ = sleep(GRACEFUL_CLOSE_WAIT) => {
            arm_rst_last_resort(stream);
        }
        r = stream.readable() => {
            if r.is_ok() {
                let mut b = [0u8; 8];
                let _ = stream.try_read(&mut b);
            }
        }
    }
}

/// Same as [`graceful_plc_socket_close`] — kept for call sites that used the old name.
pub async fn release_plc_socket(stream: &mut TcpStream) {
    graceful_plc_socket_close(stream).await;
}

/// Fire-and-forget close when Drop cannot await (never linger=0 in Drop).
pub fn spawn_graceful_close(mut stream: TcpStream) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            graceful_plc_socket_close(&mut stream).await;
        });
    }
}

/// Race the I/O future against emergency-stop and a hard timeout.
/// Caller MUST `release_plc_socket` when this returns Timeout/EmergencyStop.
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

    #[tokio::test]
    async fn distinct_units_share_gateway_ip_within_two_pipes() {
        let wait = Duration::from_millis(40);
        let a = try_station_slot("10.8.8.1", 502, StationId::ModbusUnit(1), 2, wait)
            .await
            .unwrap();
        let b = try_station_slot("10.8.8.1", 502, StationId::ModbusUnit(2), 2, wait)
            .await
            .unwrap();
        assert_ne!(a.station, b.station);
        let c = try_station_slot("10.8.8.1", 502, StationId::ModbusUnit(3), 2, wait).await;
        assert!(
            c.is_err(),
            "third concurrent TCP on a serial gateway must wait"
        );
        drop(a);
        drop(b);
    }

    #[tokio::test]
    async fn same_unit_is_single_flight() {
        let wait = Duration::from_millis(20);
        let a = try_station_slot("10.8.8.2", 502, StationId::ModbusUnit(7), 2, wait)
            .await
            .unwrap();
        let b = try_station_slot("10.8.8.2", 502, StationId::ModbusUnit(7), 2, wait).await;
        assert!(b.is_err());
        drop(a);
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

    #[tokio::test]
    async fn graceful_close_sends_fin_on_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8];
            // Peer sees FIN (read returns 0) rather than a linger=0 RST abort.
            let n = tokio::io::AsyncReadExt::read(&mut s, &mut buf)
                .await
                .unwrap();
            n
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        graceful_plc_socket_close(&mut stream).await;
        let n = peer.await.unwrap();
        assert_eq!(n, 0, "graceful close must deliver FIN, not a reset abort");
    }
}
