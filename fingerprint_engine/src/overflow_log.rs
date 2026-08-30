//! Aggregated drop counters for full in-process channels.
//!
//! A bounded `mpsc` / flume queue that falls back to per-event JSON (tracing,
//! JSONL, or disk) will fill a host disk and drown the customer SIEM under a
//! DoS or a stuck consumer. Count the drops and emit **one** line per flush
//! window — never the payload.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counts dropped / blocked channel sends until [`DropAggregator::flush`].
pub struct DropAggregator {
    name: &'static str,
    pending: AtomicU64,
}

impl DropAggregator {
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            pending: AtomicU64::new(0),
        }
    }

    pub fn record(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.pending.fetch_add(n, Ordering::Relaxed);
    }

    /// Swap out the pending count and emit at most one tracing line.
    /// Returns the flushed count so tests can assert aggregation.
    pub fn flush(&self) -> Option<u64> {
        let n = self.pending.swap(0, Ordering::Relaxed);
        if n == 0 {
            return None;
        }
        tracing::warn!(
            target: "overflow_log",
            channel = self.name,
            dropped = n,
            "full channel; dropped payloads aggregated (not per-event JSON)"
        );
        Some(n)
    }

    #[cfg(test)]
    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_thousand_drops_flush_as_one_count() {
        let a = DropAggregator::new("test_ask_mpsc");
        for _ in 0..10_000 {
            a.record(1);
        }
        assert_eq!(a.pending(), 10_000);
        assert_eq!(a.flush(), Some(10_000));
        assert_eq!(a.flush(), None);
        assert_eq!(a.pending(), 0);
    }

    #[test]
    fn sse_bridge_uses_try_send_and_aggregator() {
        let src = include_str!("http/sse_bridge.rs");
        assert!(
            src.contains("try_send"),
            "slow SSE clients must not block the broadcast pump"
        );
        assert!(
            src.contains("overflow_log"),
            "full SSE mpsc must aggregate drops, not dump JSON"
        );
        assert!(
            !src.contains("tx.send(payload).await"),
            "blocking send on the client mpsc is the SIEM-flood path"
        );
    }

    #[test]
    fn poe_distributor_aggregates_full_channel() {
        let src = include_str!("http/serve.rs");
        assert!(
            src.contains("overflow_log"),
            "PoE SSE Full() must not stay silent or dump JSON"
        );
        assert!(src.contains("POE_DROPS"));
    }
}
