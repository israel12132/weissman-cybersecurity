//! Aggregated drop counters plus a bounded local audit spool.
//!
//! A bounded `mpsc` / flume queue must not dump per-event JSON to tracing (SIEM
//! flood) and must not silently discard security evidence. Count drops, emit one
//! tracing line per flush, and persist a hashed/previewed copy under
//! [`crate::audit_spool`].

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

    /// Count a drop **and** spool the payload (hash + preview) so an attacker
    /// cannot blind the audit trail by flooding the live channel.
    pub fn record_payload(&self, payload: &str) {
        self.record(1);
        crate::audit_spool::append(self.name, payload);
    }

    /// Swap out the pending count and emit at most one tracing line.
    /// Returns the flushed count so tests can assert aggregation.
    pub fn flush(&self) -> Option<u64> {
        let n = self.pending.swap(0, Ordering::Relaxed);
        if n == 0 {
            return None;
        }
        crate::audit_spool::append(
            self.name,
            &format!(r#"{{"aggregated_dropped":{n},"channel":"{}"}}"#, self.name),
        );
        tracing::warn!(
            target: "overflow_log",
            channel = self.name,
            dropped = n,
            "full channel; payloads spooled locally (not per-event SIEM JSON)"
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
            src.contains("record_payload"),
            "full SSE mpsc must spool the payload, not drop it silently"
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
        assert!(src.contains("record_payload"));
        let rest4 = include_str!("server_handlers_rest4.inc");
        assert!(
            rest4.contains("record_payload"),
            "PoE progress Full() must spool, not silently retain"
        );
    }
}
