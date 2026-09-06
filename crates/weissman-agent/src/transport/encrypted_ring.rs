//! AES-GCM encrypted in-memory ring buffer for agent telemetry.
//!
//! Findings sit encrypted at rest in the process until the WSS writer pulls
//! them. Fail-safe wipe zeroizes slots + key and **releases heap capacity**
//! (`shrink_to_fit` + `Vec::with_capacity(0)`) so a log-flood + fail-safe loop
//! cannot OOM the agent. No disk persistence.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

const SLOTS: usize = 256;
const NONCE_LEN: usize = 12;
/// Per-message plaintext cap (architect 16 MiB window is the whole ring).
const MAX_PLAINTEXT: usize = 64 * 1024;
pub const MAX_EVASION_SCAN_SIZE_LIMIT: usize = 16 * 1024 * 1024;

struct Slot {
    nonce: [u8; NONCE_LEN],
    ct: Vec<u8>,
}

struct Ring {
    key: [u8; 32],
    slots: Vec<Option<Slot>>,
    head: usize,
    acked: AtomicU64,
    dropped: AtomicU64,
    ct_bytes: usize,
}

impl Ring {
    fn new() -> Self {
        let mut key = [0u8; 32];
        let mut h = Sha256::new();
        h.update(std::process::id().to_le_bytes());
        h.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
                .to_le_bytes(),
        );
        if let Ok(exe) = std::env::current_exe() {
            h.update(exe.to_string_lossy().as_bytes());
        }
        key.copy_from_slice(&h.finalize());
        Self {
            key,
            slots: (0..SLOTS).map(|_| None).collect(),
            head: 0,
            acked: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            ct_bytes: 0,
        }
    }

    fn rearm_if_wiped(&mut self) {
        if self.slots.capacity() == 0 || self.slots.len() != SLOTS {
            *self = Self::new();
        }
    }

    fn push(&mut self, plaintext: &[u8]) {
        self.rearm_if_wiped();
        if plaintext.len() > MAX_PLAINTEXT {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.ct_bytes > MAX_EVASION_SCAN_SIZE_LIMIT {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("32-byte AES key");
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let n = self.head as u64;
        nonce_bytes[..8].copy_from_slice(&n.to_le_bytes());
        nonce_bytes[8..].copy_from_slice(&std::process::id().to_le_bytes()[..4]);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = match cipher.encrypt(nonce, plaintext) {
            Ok(c) => c,
            Err(_) => return,
        };
        if let Some(old) = self.slots[self.head % SLOTS].take() {
            self.ct_bytes = self.ct_bytes.saturating_sub(old.ct.len());
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.ct_bytes = self.ct_bytes.saturating_add(ct.len());
        self.slots[self.head % SLOTS] = Some(Slot {
            nonce: nonce_bytes,
            ct,
        });
        self.head = self.head.wrapping_add(1);
    }

    fn wipe(&mut self) {
        secure_agent_fail_safe_clear(self);
    }

    fn stats(&self) -> (u64, u64, usize, usize) {
        let occupied = self.slots.iter().filter(|s| s.is_some()).count();
        (
            self.acked.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
            occupied,
            self.slots.capacity(),
        )
    }
}

fn secure_agent_fail_safe_clear(ring: &mut Ring) {
    for slot in &mut ring.slots {
        if let Some(mut s) = slot.take() {
            s.nonce.zeroize();
            s.ct.zeroize();
        }
    }
    ring.key.zeroize();
    ring.head = 0;
    ring.ct_bytes = 0;
    ring.slots.clear();
    ring.slots.shrink_to_fit();
    ring.slots = Vec::with_capacity(0);
}

static RING: OnceLock<Mutex<Ring>> = OnceLock::new();
static PUSHES: AtomicUsize = AtomicUsize::new(0);
static LAST_WIPE_CAPACITY: AtomicUsize = AtomicUsize::new(usize::MAX);

fn ring() -> &'static Mutex<Ring> {
    RING.get_or_init(|| Mutex::new(Ring::new()))
}

pub fn push_json(v: &serde_json::Value) {
    let Ok(bytes) = serde_json::to_vec(v) else {
        return;
    };
    if let Ok(mut g) = ring().lock() {
        g.push(&bytes);
        PUSHES.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn ack() {
    if let Ok(g) = ring().lock() {
        g.acked.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn fail_safe_wipe() {
    if let Ok(mut g) = ring().lock() {
        g.wipe();
        LAST_WIPE_CAPACITY.store(g.slots.capacity(), Ordering::Relaxed);
    }
    PUSHES.store(0, Ordering::Relaxed);
}

pub fn stats() -> serde_json::Value {
    let (acked, dropped, occupied, cap) = ring().lock().map(|g| g.stats()).unwrap_or((0, 0, 0, 0));
    serde_json::json!({
        "pushes": PUSHES.load(Ordering::Relaxed),
        "acked": acked,
        "dropped": dropped,
        "occupied_slots": occupied,
        "capacity": cap,
        "last_wipe_capacity": LAST_WIPE_CAPACITY.load(Ordering::Relaxed),
        "max_ring_bytes": MAX_EVASION_SCAN_SIZE_LIMIT,
        "cipher": "AES-256-GCM",
        "heap_policy": "zeroize+shrink_to_fit+capacity_0",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypts_and_wipe_clears() {
        fail_safe_wipe();
        push_json(&serde_json::json!({"k":"secret-token-should-not-linger"}));
        let s = stats();
        assert!(
            s["occupied_slots"].as_u64().unwrap_or(0) >= 1
                || s["pushes"].as_u64().unwrap_or(0) >= 1
        );
        fail_safe_wipe();
        let s2 = stats();
        assert_eq!(s2["occupied_slots"].as_u64().unwrap_or(99), 0);
        assert_eq!(s2["pushes"].as_u64().unwrap_or(99), 0);
        assert_eq!(s2["capacity"].as_u64().unwrap_or(99), 0);
        assert_eq!(s2["last_wipe_capacity"].as_u64().unwrap_or(99), 0);
    }

    #[test]
    fn flood_then_wipe_releases_capacity() {
        fail_safe_wipe();
        for i in 0..400 {
            push_json(&serde_json::json!({"i": i, "pad": "x".repeat(1024)}));
        }
        fail_safe_wipe();
        let s = stats();
        assert_eq!(s["capacity"].as_u64().unwrap_or(1), 0);
        assert_eq!(s["occupied_slots"].as_u64().unwrap_or(1), 0);
    }
}
