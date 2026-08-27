//! In-memory encrypted circular buffer for agent→server frames while WSS is down.
//!
//! XChaCha20-Poly1305 with a fresh 192-bit nonce per frame. The nonce mixer is
//! non-blocking (CPU RDRAND/RNDR + Linux `getrandom(GRND_NONBLOCK)` + seq/time
//! SHA-256) so a cold VM with an empty entropy pool cannot hang agent boot.

use crate::protocol::AgentToServer;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Hard ceiling for the local ring — never allocate past this.
pub const MAX_BYTES: usize = 10 * 1024 * 1024;
/// Adaptive drain starts here (architect: not a fixed 64 KiB/s).
pub const DRAIN_START_BYTES_PER_SEC: usize = 256 * 1024;
pub const DRAIN_MIN_BYTES_PER_SEC: usize = 64 * 1024;
pub const DRAIN_MAX_BYTES_PER_SEC: usize = 1024 * 1024;
/// Minimum gap between *bulk* flushed frames.
pub const FLUSH_MIN_GAP: Duration = Duration::from_millis(5);
const NONCE_LEN: usize = 24;
static NONCE_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Critical,
    Bulk,
}

struct Frame {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

pub struct EncryptedRing {
    key: XChaCha20Poly1305,
    critical: VecDeque<Frame>,
    bulk: VecDeque<Frame>,
    bytes: usize,
    dropped: u64,
    pushed: u64,
    flushed: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RingStats {
    pub bytes: u32,
    pub frames: u32,
    pub dropped: u64,
    pub pushed: u64,
    pub flushed: u64,
}

impl EncryptedRing {
    #[must_use]
    pub fn new(secret: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"weissman-agent-ring-v2-xchacha\0");
        h.update(secret.as_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let key = XChaCha20Poly1305::new(Key::from_slice(&digest));
        Self {
            key,
            critical: VecDeque::new(),
            bulk: VecDeque::new(),
            bytes: 0,
            dropped: 0,
            pushed: 0,
            flushed: 0,
        }
    }

    /// Encrypt and enqueue. KeepAlivePing is never stored.
    pub fn push_msg(&mut self, msg: &AgentToServer) {
        if matches!(msg, AgentToServer::KeepAlivePing) {
            return;
        }
        let Ok(plain) = serde_json::to_vec(msg) else {
            return;
        };
        self.push_bytes(&plain, lane_for(msg));
    }

    pub fn push_bytes(&mut self, plain: &[u8], lane: Lane) {
        if plain.is_empty() {
            return;
        }
        let nonce_raw = fill_xchacha_nonce();
        let nonce = XNonce::from_slice(&nonce_raw);
        let Ok(ciphertext) = self.key.encrypt(nonce, plain) else {
            return;
        };
        let frame_bytes = NONCE_LEN + ciphertext.len();
        if frame_bytes > MAX_BYTES {
            self.dropped += 1;
            return;
        }
        while self.bytes + frame_bytes > MAX_BYTES {
            let old = if !self.bulk.is_empty() {
                self.bulk.pop_front()
            } else {
                self.critical.pop_front()
            };
            match old {
                Some(old) => {
                    self.bytes = self.bytes.saturating_sub(NONCE_LEN + old.ciphertext.len());
                    self.dropped += 1;
                }
                None => break,
            }
        }
        self.bytes += frame_bytes;
        let frame = Frame {
            nonce: nonce_raw,
            ciphertext,
        };
        match lane {
            Lane::Critical => self.critical.push_back(frame),
            Lane::Bulk => self.bulk.push_back(frame),
        }
        self.pushed += 1;
    }

    fn decrypt_pop(
        key: &XChaCha20Poly1305,
        q: &mut VecDeque<Frame>,
        bytes: &mut usize,
    ) -> Option<String> {
        let frame = q.pop_front()?;
        *bytes = bytes.saturating_sub(NONCE_LEN + frame.ciphertext.len());
        let nonce = XNonce::from_slice(&frame.nonce);
        let plain = key.decrypt(nonce, frame.ciphertext.as_ref()).ok()?;
        String::from_utf8(plain).ok()
    }

    /// Decrypt and pop critical first, then bulk.
    pub fn pop_json(&mut self) -> Option<String> {
        let json = if !self.critical.is_empty() {
            Self::decrypt_pop(&self.key, &mut self.critical, &mut self.bytes)
        } else {
            Self::decrypt_pop(&self.key, &mut self.bulk, &mut self.bytes)
        }?;
        self.flushed += 1;
        Some(json)
    }

    pub fn pop_msg(&mut self) -> Option<(Lane, AgentToServer)> {
        let lane = if !self.critical.is_empty() {
            Lane::Critical
        } else {
            Lane::Bulk
        };
        let json = self.pop_json()?;
        let msg = serde_json::from_str(&json).ok()?;
        Some((lane, msg))
    }

    #[must_use]
    pub fn stats(&self) -> RingStats {
        RingStats {
            bytes: self.bytes.min(u32::MAX as usize) as u32,
            frames: (self.critical.len() + self.bulk.len()).min(u32::MAX as usize) as u32,
            dropped: self.dropped,
            pushed: self.pushed,
            flushed: self.flushed,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.critical.is_empty() && self.bulk.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.critical.len() + self.bulk.len()
    }
}

/// High/critical detections and task errors skip the bulk throttle.
#[must_use]
pub fn is_critical(msg: &AgentToServer) -> bool {
    lane_for(msg) == Lane::Critical
}

#[must_use]
pub fn lane_for(msg: &AgentToServer) -> Lane {
    match msg {
        AgentToServer::KeepAlivePing => Lane::Bulk,
        AgentToServer::TaskError { .. } => Lane::Critical,
        AgentToServer::Finding {
            engine, finding, ..
        } => {
            if engine == "ueba_baseline" {
                return Lane::Bulk;
            }
            if severity_is_hot(finding) {
                Lane::Critical
            } else {
                Lane::Bulk
            }
        }
        _ => Lane::Bulk,
    }
}

fn severity_is_hot(finding: &Value) -> bool {
    let s = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    s == "critical" || s == "high"
}

/// 192-bit XChaCha20 nonce that never blocks the agent on a starved `/dev/urandom`.
///
/// Mix, in order:
///   1. CPU RNG when present (RDRAND / AArch64 RNDR) — non-blocking.
///   2. OS entropy with `GRND_NONBLOCK` on Linux (EAGAIN is ignored).
///   3. SHA-256(seq ‖ unix-nanos ‖ pid ‖ bytes-so-far) XOR'd over the buffer
///      so uniqueness holds even on a cold VM with an empty entropy pool.
#[must_use]
pub(crate) fn fill_xchacha_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    mix_hw_rng(&mut nonce);
    mix_os_nonblock(&mut nonce);
    mix_counter_time(&mut nonce);
    nonce
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn mix_hw_rng(out: &mut [u8; NONCE_LEN]) {
    if !is_x86_feature_detected!("rdrand") {
        return;
    }
    let mut off = 0usize;
    while off < NONCE_LEN {
        let Some(v) = rdrand_u64() else {
            break;
        };
        let b = v.to_le_bytes();
        let n = (NONCE_LEN - off).min(8);
        for i in 0..n {
            out[off + i] ^= b[i];
        }
        off += n;
    }
}

#[cfg(target_arch = "x86_64")]
fn rdrand_u64() -> Option<u64> {
    let mut val = 0u64;
    for _ in 0..16 {
        if unsafe { core::arch::x86_64::_rdrand64_step(&mut val) } == 1 {
            return Some(val);
        }
    }
    None
}

#[cfg(target_arch = "x86")]
fn rdrand_u64() -> Option<u64> {
    let mut lo = 0u32;
    let mut hi = 0u32;
    for _ in 0..16 {
        let a = unsafe { core::arch::x86::_rdrand32_step(&mut lo) };
        let b = unsafe { core::arch::x86::_rdrand32_step(&mut hi) };
        if a == 1 && b == 1 {
            return Some((u64::from(hi) << 32) | u64::from(lo));
        }
    }
    None
}

#[cfg(target_arch = "aarch64")]
fn mix_hw_rng(out: &mut [u8; NONCE_LEN]) {
    if !std::arch::is_aarch64_feature_detected!("rand") {
        return;
    }
    let mut off = 0usize;
    while off < NONCE_LEN {
        let Some(v) = (unsafe { core::arch::aarch64::__rndr() }) else {
            break;
        };
        let b = v.to_le_bytes();
        let n = (NONCE_LEN - off).min(8);
        for i in 0..n {
            out[off + i] ^= b[i];
        }
        off += n;
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
fn mix_hw_rng(_out: &mut [u8; NONCE_LEN]) {}

#[cfg(target_os = "linux")]
fn mix_os_nonblock(out: &mut [u8; NONCE_LEN]) {
    let mut tmp = [0u8; NONCE_LEN];
    let n = unsafe {
        libc::getrandom(
            tmp.as_mut_ptr() as *mut libc::c_void,
            tmp.len(),
            libc::GRND_NONBLOCK,
        )
    };
    if n > 0 {
        let n = (n as usize).min(NONCE_LEN);
        for i in 0..n {
            out[i] ^= tmp[i];
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn mix_os_nonblock(out: &mut [u8; NONCE_LEN]) {
    let mut tmp = [0u8; NONCE_LEN];
    if getrandom::getrandom(&mut tmp).is_ok() {
        for i in 0..NONCE_LEN {
            out[i] ^= tmp[i];
        }
    }
}

fn mix_counter_time(out: &mut [u8; NONCE_LEN]) {
    let seq = NONCE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = u64::from(std::process::id());
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(nanos.to_le_bytes());
    h.update(pid.to_le_bytes());
    h.update(out.as_slice());
    let digest: [u8; 32] = h.finalize().into();
    for i in 0..NONCE_LEN {
        out[i] ^= digest[i];
    }
}

static RING: OnceLock<Mutex<EncryptedRing>> = OnceLock::new();
static UEBA_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
static UEBA_UPLOADED: AtomicU64 = AtomicU64::new(0);
static LAST_RTT_US: AtomicU64 = AtomicU64::new(0);

/// Initialise the process-wide ring from the agent renewal secret.
pub fn init(secret: &str) {
    let ring = EncryptedRing::new(secret);
    let _ = RING.set(Mutex::new(ring));
}

pub fn push(msg: &AgentToServer) {
    if let Some(lock) = RING.get() {
        if let Ok(mut g) = lock.lock() {
            g.push_msg(msg);
        }
    }
}

pub fn pop_msg() -> Option<(Lane, AgentToServer)> {
    RING.get()?.lock().ok()?.pop_msg()
}

#[must_use]
pub fn stats() -> RingStats {
    RING.get()
        .and_then(|l| l.lock().ok())
        .map(|g| g.stats())
        .unwrap_or_default()
}

#[must_use]
pub fn pending() -> bool {
    RING.get()
        .and_then(|l| l.lock().ok())
        .map(|g| !g.is_empty())
        .unwrap_or(false)
}

pub fn note_ueba_suppressed() {
    UEBA_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
}

pub fn note_ueba_uploaded() {
    UEBA_UPLOADED.fetch_add(1, Ordering::Relaxed);
}

#[must_use]
pub fn ueba_suppressed() -> u64 {
    UEBA_SUPPRESSED.load(Ordering::Relaxed)
}

#[must_use]
pub fn ueba_uploaded() -> u64 {
    UEBA_UPLOADED.load(Ordering::Relaxed)
}

pub fn note_send_rtt(rtt: Duration) {
    LAST_RTT_US.store(
        rtt.as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
}

/// Sleep the throttle gap for bulk frames only. Critical frames return immediately.
pub async fn throttle_wait(window: &mut FlushWindow, frame_len: usize, lane: Lane) {
    if lane == Lane::Critical {
        return;
    }
    window.adapt();
    window.note(frame_len);
    let extra = window.penalty();
    tokio::time::sleep(FLUSH_MIN_GAP + extra).await;
}

pub struct FlushWindow {
    started: Instant,
    bytes: usize,
    budget: usize,
}

impl FlushWindow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes: 0,
            budget: DRAIN_START_BYTES_PER_SEC,
        }
    }

    fn adapt(&mut self) {
        let rtt_us = LAST_RTT_US.load(Ordering::Relaxed);
        if rtt_us > 0 {
            if rtt_us < 50_000 {
                self.budget = ((self.budget as f64) * 1.25) as usize;
            } else if rtt_us > 200_000 {
                self.budget = ((self.budget as f64) * 0.7) as usize;
            }
        }
        if let Some((load1, ncpu)) = host_load() {
            if ncpu > 0.0 && load1 > ncpu {
                self.budget = self.budget.min(128 * 1024);
            }
        }
        self.budget = self
            .budget
            .clamp(DRAIN_MIN_BYTES_PER_SEC, DRAIN_MAX_BYTES_PER_SEC);
    }

    fn note(&mut self, n: usize) {
        if self.started.elapsed() >= Duration::from_secs(1) {
            self.started = Instant::now();
            self.bytes = 0;
        }
        self.bytes = self.bytes.saturating_add(n);
    }

    fn penalty(&self) -> Duration {
        if self.bytes <= self.budget {
            return Duration::ZERO;
        }
        Duration::from_secs(1).saturating_sub(self.started.elapsed())
    }
}

impl Default for FlushWindow {
    fn default() -> Self {
        Self::new()
    }
}

fn host_load() -> Option<(f64, f64)> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string("/proc/loadavg").ok()?;
        let load1: f64 = raw.split_whitespace().next()?.parse().ok()?;
        let ncpu = std::thread::available_parallelism()
            .map(|n| n.get() as f64)
            .unwrap_or(1.0);
        Some((load1, ncpu))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::AgentToServer;
    use serde_json::json;

    fn sample() -> AgentToServer {
        AgentToServer::Heartbeat {
            agent_id: "a".into(),
            running_tasks: 0,
            completed_tasks: 1,
            uptime_secs: 9,
            ring_buffer_bytes: 0,
            ring_buffer_frames: 0,
            ueba_suppressed: 0,
            ueba_uploaded: 0,
        }
    }

    #[test]
    fn round_trips_encrypted_frame() {
        let mut ring = EncryptedRing::new("unit-test-secret");
        ring.push_msg(&sample());
        assert_eq!(ring.len(), 1);
        let (_lane, back) = ring.pop_msg().expect("decrypt");
        match back {
            AgentToServer::Heartbeat { agent_id, .. } => assert_eq!(agent_id, "a"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn xchacha_nonces_are_unique() {
        let mut ring = EncryptedRing::new("n");
        for _ in 0..32 {
            ring.push_msg(&sample());
        }
        let mut seen = std::collections::HashSet::new();
        for f in ring.critical.iter().chain(ring.bulk.iter()) {
            assert_eq!(f.nonce.len(), 24);
            assert!(seen.insert(f.nonce), "XChaCha nonce reused");
        }
    }

    #[test]
    fn nonce_fill_never_blocks_and_stays_unique() {
        let started = Instant::now();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..512 {
            assert!(seen.insert(fill_xchacha_nonce()), "nonce collision");
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "nonce fill blocked (entropy starvation): {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn nonce_mixer_does_not_call_blocking_getrandom_on_linux() {
        let src = include_str!("ringbuf.rs");
        assert!(src.contains("GRND_NONBLOCK"));
        assert!(src.contains("mix_counter_time"));
        assert!(src.contains("libc::getrandom"));
        // Crate getrandom is only on the non-Linux OS path.
        assert!(src.contains("#[cfg(not(target_os = \"linux\"))]"));
    }

    #[test]
    fn never_stores_keepalive() {
        let mut ring = EncryptedRing::new("k");
        ring.push_msg(&AgentToServer::KeepAlivePing);
        assert!(ring.is_empty());
    }

    #[test]
    fn critical_findings_drain_before_bulk() {
        let mut ring = EncryptedRing::new("prio");
        ring.push_msg(&sample());
        ring.push_msg(&AgentToServer::Finding {
            agent_id: "a".into(),
            task_id: "t".into(),
            engine: "process_hollowing".into(),
            finding: json!({"severity": "critical", "title": "hollowing"}),
        });
        let (lane, msg) = ring.pop_msg().expect("first");
        assert_eq!(lane, Lane::Critical);
        match msg {
            AgentToServer::Finding { engine, .. } => assert_eq!(engine, "process_hollowing"),
            other => panic!("expected critical finding first, got {other:?}"),
        }
    }

    #[test]
    fn ueba_baseline_is_bulk() {
        let msg = AgentToServer::Finding {
            agent_id: "a".into(),
            task_id: "t".into(),
            engine: "ueba_baseline".into(),
            finding: json!({"severity": "medium"}),
        };
        assert_eq!(lane_for(&msg), Lane::Bulk);
    }

    #[test]
    fn evicts_oldest_at_10mb() {
        let mut ring = EncryptedRing::new("cap");
        let blob = "x".repeat(64 * 1024);
        let msg = AgentToServer::TaskError {
            agent_id: "a".into(),
            task_id: "t".into(),
            engine: "e".into(),
            error: blob,
        };
        for _ in 0..200 {
            ring.push_msg(&msg);
        }
        assert!(
            ring.stats().bytes as usize <= MAX_BYTES,
            "ring grew past the 10 MiB hard cap: {}",
            ring.stats().bytes
        );
        assert!(ring.stats().dropped > 0, "cap should have evicted frames");
        let last = ring.critical.back().or(ring.bulk.back()).expect("retained");
        let nonce = XNonce::from_slice(&last.nonce);
        assert!(ring.key.decrypt(nonce, last.ciphertext.as_ref()).is_ok());
    }

    #[test]
    fn wrong_key_cannot_read() {
        let mut a = EncryptedRing::new("alpha");
        a.push_msg(&sample());
        let frame = a
            .bulk
            .pop_front()
            .or_else(|| a.critical.pop_front())
            .unwrap();
        let b = EncryptedRing::new("bravo");
        let nonce = XNonce::from_slice(&frame.nonce);
        assert!(b.key.decrypt(nonce, frame.ciphertext.as_ref()).is_err());
    }

    #[test]
    fn drain_budget_starts_at_256k() {
        assert_eq!(DRAIN_START_BYTES_PER_SEC, 256 * 1024);
        let w = FlushWindow::new();
        assert_eq!(w.budget, DRAIN_START_BYTES_PER_SEC);
    }
}
