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

fn sampled_at_ord(v: &Value) -> (i64, i64) {
    let ts = parse_sampled_at_millis(v.get("sampled_at"))
        .or_else(|| parse_sampled_at_millis(v.get("metrics").and_then(|m| m.get("sampled_at"))))
        .unwrap_or(0);
    let seq = v
        .get("seq")
        .and_then(Value::as_i64)
        .or_else(|| v.get("seq").and_then(Value::as_u64).map(|n| n as i64))
        .unwrap_or(0);
    (ts, seq)
}

fn parse_sampled_at_millis(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    if let Some(s) = v.as_str() {
        return chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.timestamp_millis());
    }
    v.as_i64()
}

pub fn drain_offline() -> Vec<Value> {
    let Ok(mut g) = ring().lock() else {
        return Vec::new();
    };
    let mut out: Vec<Value> = g.drain(..).collect();
    // Server Welford/EWMV assumes chronological application. The ring may
    // hold a reconnect batch spanning hours; sort by original sampled_at.
    out.sort_by_key(sampled_at_ord);
    out
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

    #[test]
    fn drain_sorts_by_sampled_at() {
        let _ = drain_offline();
        push_offline(json!({
            "i": 2,
            "sampled_at": "2026-08-27T12:30:00+00:00",
            "seq": 3
        }));
        push_offline(json!({
            "i": 1,
            "sampled_at": "2026-08-27T12:00:00+00:00",
            "seq": 1
        }));
        push_offline(json!({
            "i": 3,
            "sampled_at": "2026-08-27T13:00:00+00:00",
            "seq": 4
        }));
        let drained = drain_offline();
        assert_eq!(
            drained
                .iter()
                .map(|v| v["i"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }
}
