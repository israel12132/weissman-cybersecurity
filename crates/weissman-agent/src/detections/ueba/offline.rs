//! Seq/nonce + in-memory ring buffer for WSS drop (categories 2, 10).
//! No SQLite — keeps the stripped musl binary small and avoids an on-disk secret store.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::sync::OnceLock;

use serde_json::Value;

const RING_CAP: usize = 32;
static SEQ: AtomicU64 = AtomicU64::new(1);

fn ring() -> &'static Mutex<VecDeque<Value>> {
    static R: OnceLock<Mutex<VecDeque<Value>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(VecDeque::with_capacity(RING_CAP)))
}

pub fn next_seq() -> u64 {
    SEQ.fetch_add(1, Ordering::Relaxed)
}

pub fn next_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn push_offline(finding: Value) {
    let Ok(mut g) = ring().lock() else {
        return;
    };
    if g.len() >= RING_CAP {
        g.pop_front();
    }
    g.push_back(finding);
}

pub fn drain_offline() -> Vec<Value> {
    let Ok(mut g) = ring().lock() else {
        return Vec::new();
    };
    g.drain(..).collect()
}

pub fn pending() -> usize {
    ring().lock().map(|g| g.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ring_drops_oldest() {
        // Isolate from other tests sharing the process-global ring.
        let _ = drain_offline();
        for i in 0..40 {
            push_offline(json!({"i": i}));
        }
        assert_eq!(pending(), RING_CAP);
        let drained = drain_offline();
        assert_eq!(drained.len(), RING_CAP);
        assert_eq!(drained[0]["i"], 8);
    }
}
