//! Bounded broadcast → per-client SSE bridge. Drops relay task when client disconnects.

use axum::response::sse::Event;
use futures::stream::Stream;
use std::convert::Infallible;
use tokio::sync::{broadcast, mpsc};

/// Per-client buffer — slow consumers lag/drop rather than pinning memory in broadcast fan-out.
const CLIENT_CHANNEL_CAPACITY: usize = 64;

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
        loop {
            match rx.recv().await {
                Ok(payload) => {
                    if !filter(&payload) {
                        continue;
                    }
                    if tx.send(payload).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
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
