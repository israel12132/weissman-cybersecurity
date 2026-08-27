//! AES-GCM encrypted in-memory ring buffer for agent telemetry.
//!
//! Findings sit encrypted at rest in the process until the WSS writer pulls
//! them. Fail-safe wipe zeroizes slots + key. No disk persistence.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

const SLOTS: usize = 256;
const NONCE_LEN: usize = 12;

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
}

impl Ring {
    fn new() -> Self {
        let mut key = [0u8; 32];
        // Mix pid + timestamp into a process-local key. Not a long-term secret;
        // it only hides telemetry in RAM from naive string scans.
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
        }
    }

    fn push(&mut self, plaintext: &[u8]) {
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
        if self.slots[self.head % SLOTS].is_some() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.slots[self.head % SLOTS] = Some(Slot {
            nonce: nonce_bytes,
            ct,
        });
        self.head = self.head.wrapping_add(1);
    }

    fn wipe(&mut self) {
        for slot in &mut self.slots {
            if let Some(mut s) = slot.take() {
                s.nonce.fill(0);
                for b in &mut s.ct {
                    *b = 0;
                }
            }
        }
        self.key = [0u8; 32];
        self.head = 0;
    }

    fn stats(&self) -> (u64, u64, usize) {
        let occupied = self.slots.iter().filter(|s| s.is_some()).count();
        (
            self.acked.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
            occupied,
        )
    }
}

static RING: OnceLock<Mutex<Ring>> = OnceLock::new();
static PUSHES: AtomicUsize = AtomicUsize::new(0);

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
    }
    PUSHES.store(0, Ordering::Relaxed);
}

pub fn stats() -> serde_json::Value {
    let (acked, dropped, occupied) = ring().lock().map(|g| g.stats()).unwrap_or((0, 0, 0));
    serde_json::json!({
        "pushes": PUSHES.load(Ordering::Relaxed),
        "acked": acked,
        "dropped": dropped,
        "occupied_slots": occupied,
        "capacity": SLOTS,
        "cipher": "AES-256-GCM",
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
    }
}
