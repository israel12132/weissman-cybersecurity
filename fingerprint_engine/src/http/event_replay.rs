//! Command Center telemetry **replay** — reconnect recovery via Last-Event-ID.
//!
//! The live feed (`/ws/command-center`) is a `tokio::sync::broadcast` fan-out: events
//! not delivered while a socket is disconnected are gone forever. A SOC console that
//! drops its connection for a few seconds must not silently lose the alerts that landed
//! in that window. This module keeps a **bounded, per-tenant history** of recent
//! telemetry so a reconnecting client can ask "give me everything after sequence N".
//!
//! ## Model
//! * A single [`spawn_recorder`] task subscribes to the raw telemetry broadcast, assigns
//!   every event a **monotonic global sequence** via [`EventReplayBuffer::record`], and
//!   re-emits the event enriched with `_seq` on a dedicated channel the WS consumes — so
//!   the seq a live client sees is the same seq [`EventReplayBuffer::replay_since`] resumes
//!   from. One sequencer = one source of truth; no per-connection duplication.
//! * **Per-tenant isolation** is inherited from [`crate::http::tenant_stream`]: every stored
//!   payload keeps its `_tid` stamp, and replay filters through [`tenant_stream::visible_to`]
//!   so tenant B can never replay tenant A's events (system-tenant `0` events reach everyone).
//!   Unstamped payloads are never recorded — fail-closed, exactly like the live path.
//! * The buffer is capacity-bounded (global ring). If a client's last-seen seq is older than
//!   the oldest retained event, continuity can't be proven, so [`ReplaySlice::gap`] is set and
//!   the caller tells the client to full-resync from source-of-truth instead of trusting a
//!   partial replay.
//!
//! This is an in-process buffer (per replica). Cross-replica durable replay (Redis Streams)
//! is a follow-up; the API here is deliberately storage-agnostic so it can be swapped.

use serde_json::Value;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Default number of telemetry events retained for replay. Override with
/// `WEISSMAN_CC_REPLAY_CAPACITY`. Sized so a multi-minute reconnect on a busy tenant
/// still resumes without a gap, while bounding memory (~1 KiB/event → ~1 MiB).
const DEFAULT_REPLAY_CAPACITY: usize = 1024;

/// One retained telemetry event.
struct Entry {
    seq: u64,
    /// The original **stamped** payload (keeps `_tid`) so replay can filter per-tenant.
    raw: String,
}

struct RingState {
    /// Sequence assigned to the next recorded event (starts at 1; `0` means "seen nothing").
    next_seq: u64,
    events: VecDeque<Entry>,
}

/// Result of a replay query: the deliverable events after the client's last seq, whether a
/// gap was detected (client should full-resync), and the newest seq the buffer holds.
pub struct ReplaySlice {
    /// `(seq, deliverable_payload)` pairs, ascending by seq. `deliverable_payload` is the
    /// tenant-unwrapped form (same shape the live path forwards before normalization).
    pub events: Vec<(u64, String)>,
    /// True when the buffer no longer covers the client's position — replay is incomplete.
    pub gap: bool,
    /// Newest sequence currently retained (0 if empty).
    pub latest_seq: u64,
}

/// Bounded per-tenant history of Command Center telemetry for reconnect replay.
pub struct EventReplayBuffer {
    capacity: usize,
    state: Mutex<RingState>,
}

impl EventReplayBuffer {
    /// Build a buffer retaining up to `capacity` events (minimum 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            state: Mutex::new(RingState {
                next_seq: 1,
                events: VecDeque::new(),
            }),
        }
    }

    /// Build a shared buffer from `WEISSMAN_CC_REPLAY_CAPACITY` (or [`DEFAULT_REPLAY_CAPACITY`]).
    #[must_use]
    pub fn shared_from_env() -> Arc<Self> {
        let cap = std::env::var("WEISSMAN_CC_REPLAY_CAPACITY")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_REPLAY_CAPACITY);
        Arc::new(Self::new(cap))
    }

    /// Record a raw (tenant-stamped) telemetry payload, returning its assigned sequence.
    /// Returns `None` — recording nothing — for payloads with no `_tid` stamp (fail-closed).
    pub fn record(&self, raw: &str) -> Option<u64> {
        // Require a tenant stamp, matching tenant_stream's fail-closed contract.
        let _tid = serde_json::from_str::<Value>(raw)
            .ok()?
            .get("_tid")
            .and_then(Value::as_i64)?;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let seq = st.next_seq;
        st.next_seq = st.next_seq.saturating_add(1);
        st.events.push_back(Entry {
            seq,
            raw: raw.to_string(),
        });
        while st.events.len() > self.capacity {
            st.events.pop_front();
        }
        Some(seq)
    }

    /// Return the events visible to `viewer_tid` with `seq > last_seq`, ascending.
    ///
    /// Sets `gap` when the oldest retained event is newer than `last_seq + 1`, i.e. events
    /// between the client's position and the buffer's window were already evicted.
    pub fn replay_since(&self, viewer_tid: i64, last_seq: u64) -> ReplaySlice {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let latest_seq = st.next_seq.saturating_sub(1);
        let gap = st
            .events
            .front()
            .is_some_and(|e| e.seq > last_seq.saturating_add(1));
        let events = st
            .events
            .iter()
            .filter(|e| e.seq > last_seq)
            .filter_map(|e| {
                crate::http::tenant_stream::visible_to(&e.raw, viewer_tid).map(|p| (e.seq, p))
            })
            .collect();
        ReplaySlice {
            events,
            gap,
            latest_seq,
        }
    }

    /// Newest sequence currently assigned (0 if nothing recorded). Handy for metrics/tests.
    #[must_use]
    pub fn latest_seq(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .next_seq
            .saturating_sub(1)
    }
}

/// Parse `last_event_id=N` out of a raw query string (`RawQuery`). Case-sensitive key,
/// returns the first parseable `u64`. Absent/invalid → `None` (client is treated as fresh).
#[must_use]
pub fn parse_last_event_id(query: Option<&str>) -> Option<u64> {
    let q = query?;
    q.split('&').find_map(|pair| {
        let mut it = pair.splitn(2, '=');
        if it.next() == Some("last_event_id") {
            it.next().and_then(|v| v.parse::<u64>().ok())
        } else {
            None
        }
    })
}

/// Build the resync marker emitted to live clients when the single sequencer itself falls
/// behind the raw telemetry broadcast.
///
/// This lag is distinct from a slow *client*: events dropped here are never assigned a seq,
/// so they leave **no gap** in the live seq stream and a reconnecting client cannot detect
/// the loss via `last_event_id`. The marker is stamped [`crate::http::tenant_stream::SYSTEM_TENANT`]
/// so every connected Command Center socket (any tenant — we don't know whose events were
/// dropped) receives it, and its shape matches the WS handler's per-client lag notice so the
/// client's existing resync handler fires and refetches authoritative state.
#[must_use]
fn recorder_lag_notice(dropped: u64) -> String {
    crate::http::tenant_stream::stamp(
        crate::http::tenant_stream::SYSTEM_TENANT,
        &serde_json::json!({
            "type": "resync",
            "kind": "stream_lagged",
            "dropped": dropped,
            "ts": chrono::Utc::now().timestamp_millis(),
        })
        .to_string(),
    )
}

/// Spawn the single sequencer/recorder: it drains the raw telemetry broadcast, records each
/// event (assigning a seq), and re-emits it enriched with `_seq` on `out` for live WS clients.
/// Recording is the one place seq is assigned, keeping live and replay in the same seq space.
pub fn spawn_recorder(
    mut rx: broadcast::Receiver<String>,
    out: Arc<broadcast::Sender<String>>,
    buffer: Arc<EventReplayBuffer>,
) {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(raw) => {
                    let Some(seq) = buffer.record(&raw) else {
                        // Unstamped — never recorded and (like the live path) not deliverable.
                        continue;
                    };
                    let enriched = match serde_json::from_str::<Value>(&raw) {
                        Ok(Value::Object(mut m)) => {
                            m.insert("_seq".to_string(), Value::from(seq));
                            Value::Object(m).to_string()
                        }
                        _ => raw,
                    };
                    // Best-effort: if no live subscribers, the event is still in the buffer
                    // for a future reconnect, so a send error here is not fatal.
                    let _ = out.send(enriched);
                }
                // A burst outran this single sequencer: `dropped` events were overwritten
                // before we could assign them a seq. Because they never entered the seq space,
                // the live stream stays contiguous and NO reconnect can detect the loss — so we
                // must not drop it silently. Count it and push a system-tenant resync marker so
                // every connected client refetches authoritative state instead of trusting a
                // now-incomplete feed. Then keep draining.
                Err(broadcast::error::RecvError::Lagged(dropped)) => {
                    metrics::counter!("weissman_cc_recorder_lagged_events_total")
                        .increment(dropped);
                    let _ = out.send(recorder_lag_notice(dropped));
                    continue;
                }
                // Producer side gone (shutdown) — stop.
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tenant_stream::{stamp, SYSTEM_TENANT};

    fn ev(tid: i64, body: &str) -> String {
        stamp(tid, body)
    }

    #[test]
    fn record_assigns_monotonic_sequences() {
        let buf = EventReplayBuffer::new(16);
        assert_eq!(buf.record(&ev(1, r#"{"event":"a"}"#)), Some(1));
        assert_eq!(buf.record(&ev(1, r#"{"event":"b"}"#)), Some(2));
        assert_eq!(buf.record(&ev(2, r#"{"event":"c"}"#)), Some(3));
        assert_eq!(buf.latest_seq(), 3);
    }

    #[test]
    fn unstamped_payload_is_not_recorded() {
        let buf = EventReplayBuffer::new(16);
        assert_eq!(buf.record(r#"{"event":"no_tid"}"#), None);
        assert_eq!(buf.record("not json"), None);
        assert_eq!(buf.latest_seq(), 0);
    }

    #[test]
    fn replay_returns_only_events_after_last_seq() {
        let buf = EventReplayBuffer::new(16);
        buf.record(&ev(7, r#"{"event":"a"}"#)); // seq 1
        buf.record(&ev(7, r#"{"event":"b"}"#)); // seq 2
        buf.record(&ev(7, r#"{"event":"c"}"#)); // seq 3
        let slice = buf.replay_since(7, 1);
        let seqs: Vec<u64> = slice.events.iter().map(|(s, _)| *s).collect();
        assert_eq!(seqs, vec![2, 3]);
        assert!(!slice.gap);
        assert_eq!(slice.latest_seq, 3);
    }

    #[test]
    fn replay_isolates_tenants() {
        let buf = EventReplayBuffer::new(16);
        buf.record(&ev(1, r#"{"event":"tenant-one"}"#)); // seq 1
        buf.record(&ev(2, r#"{"event":"tenant-two"}"#)); // seq 2
        buf.record(&ev(1, r#"{"event":"one-again"}"#)); // seq 3

        let one = buf.replay_since(1, 0);
        assert_eq!(
            one.events.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert!(one.events.iter().all(|(_, p)| !p.contains("tenant-two")));

        let two = buf.replay_since(2, 0);
        assert_eq!(
            two.events.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![2]
        );
        assert!(two.events.iter().all(|(_, p)| p.contains("tenant-two")));
    }

    #[test]
    fn system_tenant_events_replay_to_everyone() {
        let buf = EventReplayBuffer::new(16);
        buf.record(&ev(SYSTEM_TENANT, r#"{"event":"maintenance"}"#)); // seq 1
        buf.record(&ev(5, r#"{"event":"tenant-five"}"#)); // seq 2
        let five = buf.replay_since(5, 0);
        assert_eq!(
            five.events.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![1, 2]
        );
        let other = buf.replay_since(99, 0);
        assert_eq!(
            other.events.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn eviction_drops_oldest_and_flags_gap() {
        let buf = EventReplayBuffer::new(3);
        for i in 0..5 {
            buf.record(&ev(1, &format!(r#"{{"event":"e{i}"}}"#)));
        }
        // Only seq 3,4,5 remain (capacity 3). A client last at seq 1 lost 2..=? → gap.
        let slice = buf.replay_since(1, 1);
        assert!(
            slice.gap,
            "client behind the retained window must be told to resync"
        );
        assert_eq!(
            slice.events.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
    }

    #[test]
    fn no_gap_when_client_within_window() {
        let buf = EventReplayBuffer::new(3);
        for i in 0..5 {
            buf.record(&ev(1, &format!(r#"{{"event":"e{i}"}}"#)));
        }
        // Retained 3,4,5; client at seq 3 is inside the window → no gap, resume 4,5.
        let slice = buf.replay_since(1, 3);
        assert!(!slice.gap);
        assert_eq!(
            slice.events.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![4, 5]
        );
    }

    #[test]
    fn recorder_lag_notice_reaches_every_tenant_as_a_resync_signal() {
        let notice = recorder_lag_notice(7);
        // System-tenant stamped: the recorder can't know whose events were dropped, so
        // every connected client (any tenant) must receive it and resync.
        assert!(crate::http::tenant_stream::visible_to(&notice, 1).is_some());
        assert!(crate::http::tenant_stream::visible_to(&notice, 42).is_some());
        assert!(crate::http::tenant_stream::visible_to(&notice, 9999).is_some());
        // Shape matches the WS handler's per-client lag notice, so the client's existing
        // resync handler (type === 'resync' || kind === 'stream_lagged') fires.
        let v: Value = serde_json::from_str(&notice).unwrap();
        assert_eq!(v["type"], "resync");
        assert_eq!(v["kind"], "stream_lagged");
        assert_eq!(v["dropped"], 7);
        // Same contract as the WS handler's per-client lag notice, incl. the timestamp.
        assert!(v["ts"].as_i64().unwrap_or(0) > 0, "timestamp must be present");
    }

    #[test]
    fn recorder_lag_notice_is_never_recorded_into_the_seq_space() {
        // The marker is a live-only control frame: it must NOT be stamped with a seq, so it
        // is never stored in the replay buffer nor deduped away by a client's last_delivered.
        let notice = recorder_lag_notice(3);
        let v: Value = serde_json::from_str(&notice).unwrap();
        assert!(v.get("_seq").is_none(), "resync marker must carry no _seq");
    }

    #[test]
    fn parse_last_event_id_variants() {
        assert_eq!(parse_last_event_id(Some("last_event_id=42")), Some(42));
        assert_eq!(
            parse_last_event_id(Some("foo=1&last_event_id=7&bar=2")),
            Some(7)
        );
        assert_eq!(parse_last_event_id(Some("last_event_id=notanumber")), None);
        assert_eq!(parse_last_event_id(Some("other=1")), None);
        assert_eq!(parse_last_event_id(None), None);
    }
}
