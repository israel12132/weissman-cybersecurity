//! In-memory encrypted circular buffer for agent→server frames while WSS is down.
//!
//! Hard cap: 10 MiB of ciphertext. Oldest frames are dropped first. On reconnect
//! the writer drains with a 64 KiB/s / 20 ms pacing so a long outage cannot
//! stampede the control plane.

use crate::protocol::AgentToServer;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Hard ceiling for the local ring — never allocate past this.
pub const MAX_BYTES: usize = 10 * 1024 * 1024;
/// Reconnect drain: 64 KiB/s.
pub const FLUSH_BYTES_PER_SEC: usize = 64 * 1024;
/// Minimum gap between flushed frames.
pub const FLUSH_MIN_GAP: Duration = Duration::from_millis(20);

struct Frame {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

pub struct EncryptedRing {
    key: ChaCha20Poly1305,
    frames: VecDeque<Frame>,
    bytes: usize,
    dropped: u64,
    pushed: u64,
    flushed: u64,
    seq: u64,
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
        h.update(b"weissman-agent-ring-v1\0");
        h.update(secret.as_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let key = ChaCha20Poly1305::new(Key::from_slice(&digest));
        Self {
            key,
            frames: VecDeque::new(),
            bytes: 0,
            dropped: 0,
            pushed: 0,
            flushed: 0,
            seq: 1,
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
        self.push_bytes(&plain);
    }

    pub fn push_bytes(&mut self, plain: &[u8]) {
        if plain.is_empty() {
            return;
        }
        let mut nonce_raw = [0u8; 12];
        nonce_raw[4..].copy_from_slice(&self.seq.to_le_bytes());
        self.seq = self.seq.wrapping_add(1);
        let nonce = Nonce::from_slice(&nonce_raw);
        let Ok(ciphertext) = self.key.encrypt(nonce, plain) else {
            return;
        };
        let frame_bytes = 12 + ciphertext.len();
        if frame_bytes > MAX_BYTES {
            self.dropped += 1;
            return;
        }
        while self.bytes + frame_bytes > MAX_BYTES {
            if let Some(old) = self.frames.pop_front() {
                self.bytes = self.bytes.saturating_sub(12 + old.ciphertext.len());
                self.dropped += 1;
            } else {
                break;
            }
        }
        self.bytes += frame_bytes;
        self.frames.push_back(Frame {
            nonce: nonce_raw,
            ciphertext,
        });
        self.pushed += 1;
    }

    /// Decrypt and pop the oldest frame.
    pub fn pop_json(&mut self) -> Option<String> {
        let frame = self.frames.pop_front()?;
        self.bytes = self.bytes.saturating_sub(12 + frame.ciphertext.len());
        let nonce = Nonce::from_slice(&frame.nonce);
        let plain = self.key.decrypt(nonce, frame.ciphertext.as_ref()).ok()?;
        self.flushed += 1;
        String::from_utf8(plain).ok()
    }

    pub fn pop_msg(&mut self) -> Option<AgentToServer> {
        let json = self.pop_json()?;
        serde_json::from_str(&json).ok()
    }

    #[must_use]
    pub fn stats(&self) -> RingStats {
        RingStats {
            bytes: self.bytes.min(u32::MAX as usize) as u32,
            frames: self.frames.len().min(u32::MAX as usize) as u32,
            dropped: self.dropped,
            pushed: self.pushed,
            flushed: self.flushed,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }
}

static RING: OnceLock<Mutex<EncryptedRing>> = OnceLock::new();
static UEBA_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
static UEBA_UPLOADED: AtomicU64 = AtomicU64::new(0);

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

pub fn pop_msg() -> Option<AgentToServer> {
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

/// Sleep the throttle gap, scaled if the last window already spent its budget.
pub async fn throttle_wait(window: &mut FlushWindow, frame_len: usize) {
    window.note(frame_len);
    let extra = window.penalty();
    tokio::time::sleep(FLUSH_MIN_GAP + extra).await;
}

pub struct FlushWindow {
    started: Instant,
    bytes: usize,
}

impl FlushWindow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes: 0,
        }
    }

    fn note(&mut self, n: usize) {
        if self.started.elapsed() >= Duration::from_secs(1) {
            self.started = Instant::now();
            self.bytes = 0;
        }
        self.bytes = self.bytes.saturating_add(n);
    }

    fn penalty(&self) -> Duration {
        if self.bytes <= FLUSH_BYTES_PER_SEC {
            return Duration::ZERO;
        }
        // Over budget this second — wait out the remainder of the window.
        Duration::from_secs(1).saturating_sub(self.started.elapsed())
    }
}

impl Default for FlushWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::AgentToServer;

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
        let back = ring.pop_msg().expect("decrypt");
        match back {
            AgentToServer::Heartbeat { agent_id, .. } => assert_eq!(agent_id, "a"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn never_stores_keepalive() {
        let mut ring = EncryptedRing::new("k");
        ring.push_msg(&AgentToServer::KeepAlivePing);
        assert!(ring.is_empty());
    }

    #[test]
    fn evicts_oldest_at_10mb() {
        let mut ring = EncryptedRing::new("cap");
        // ~64 KiB plaintext each; ciphertext is slightly larger.
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
        // Newest still decrypts.
        let last = ring.frames.back().expect("retained");
        let nonce = Nonce::from_slice(&last.nonce);
        assert!(ring.key.decrypt(nonce, last.ciphertext.as_ref()).is_ok());
    }

    #[test]
    fn wrong_key_cannot_read() {
        let mut a = EncryptedRing::new("alpha");
        a.push_msg(&sample());
        let frame = a.frames.pop_front().unwrap();
        let b = EncryptedRing::new("bravo");
        let nonce = Nonce::from_slice(&frame.nonce);
        assert!(b.key.decrypt(nonce, frame.ciphertext.as_ref()).is_err());
    }
}
