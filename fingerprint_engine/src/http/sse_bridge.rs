//! Bounded broadcast → per-client SSE bridge. Drops relay task when client disconnects.
//!
//! When a slow client falls behind the broadcast ring, the skipped events are surfaced as an
//! explicit `resync` event (the same shape `/ws/command-center` uses) rather than dropped
//! silently, so the client can refetch authoritative state instead of trusting a gapped feed.
//!
//! The per-client `mpsc` is `try_send` only: a full buffer must not block the broadcast
//! pump (that stalls every other client) and must not dump the JSON payload to disk/SIEM.

use axum::response::sse::Event;
use futures::stream::Stream;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{broadcast, mpsc};

use crate::overflow_log::DropAggregator;

/// Per-client buffer — slow consumers lag/drop rather than pinning memory in broadcast fan-out.
const CLIENT_CHANNEL_CAPACITY: usize = 64;

static SSE_DROPS: DropAggregator = DropAggregator::new("sse_bridge");

/// Bridge a `broadcast` receiver into an SSE `Stream`, forwarding only payloads that pass `filter`.
pub fn bridge_broadcast<F>(
    mut rx: broadcast::Receiver<String>,
    filter: F,
) -> impl Stream<Item = Result<Event, Infallible>>
where
    F: Fn(&str) -> bool + Send + Sync + 'static,
{
    let (tx, mut client_rx) = mpsc::channel::<String>(CLIENT_CHANNEL_CAPACITY);

    tokio::spawn(async move {
        let mut flush = tokio::time::interval(Duration::from_secs(5));
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Ok(payload) => {
                            if !filter(&payload) {
                                continue;
                            }
                            match tx.try_send(payload) {
                                Ok(()) => {}
                                Err(TrySendError::Full(_)) => SSE_DROPS.record(1),
                                Err(TrySendError::Closed(_)) => break,
                            }
                        }
                        // Never drop silently: the ring overwrote `dropped` events this slow client
                        // never saw. Emit a resync marker (same shape the WS command-center path uses)
                        // so the client refetches authoritative state instead of trusting a gapped feed.
                        Err(broadcast::error::RecvError::Lagged(dropped)) => {
                            SSE_DROPS.record(dropped);
                            let notice = serde_json::json!({
                                "type": "resync",
                                "kind": "stream_lagged",
                                "dropped": dropped,
                                "ts": chrono::Utc::now().timestamp_millis(),
                            })
                            .to_string();
                            match tx.try_send(notice) {
                                Ok(()) => {}
                                Err(TrySendError::Full(_)) => SSE_DROPS.record(1),
                                Err(TrySendError::Closed(_)) => break,
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = flush.tick() => {
                    let _ = SSE_DROPS.flush();
                }
            }
        }
        let _ = SSE_DROPS.flush();
    });

    async_stream::stream! {
        while let Some(payload) = client_rx.recv().await {
            yield Ok(Event::default().data(payload));
        }
    }
}

/// Bridge a bounded channel, emitting an initial snapshot event first.
pub fn bridge_channel_with_initial(
    initial: String,
    rx: flume::Receiver<String>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        yield Ok(Event::default().data(initial));
        while let Ok(msg) = rx.recv_async().await {
            yield Ok(Event::default().data(msg));
        }
    }
}
