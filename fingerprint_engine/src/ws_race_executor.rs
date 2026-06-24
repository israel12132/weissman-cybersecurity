//! Blind race-condition execution — synchronized multi-connection WebSocket frame dispatch.

use crate::ws_session::{connect_request, WsConnectOpts};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Debug)]
pub struct RaceConfig {
    pub connections: usize,
    pub sync_window_us: u64,
    pub payload: String,
    pub read_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RaceOutcome {
    pub connections: usize,
    pub success_responses: usize,
    pub spread_us: u64,
    pub responses: Vec<String>,
    pub duplicate_success: bool,
    pub timing_anomaly: bool,
}

fn looks_like_success(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    (l.contains("\"success\":true")
        || l.contains("created")
        || l.contains("accepted")
        || l.contains("ok")
        || l.contains("completed"))
        && !l.contains("error")
        && !l.contains("unauthorized")
}

async fn race_worker(
    http_url: String,
    opts: WsConnectOpts,
    payload: String,
    barrier: Arc<Barrier>,
    sync_window_us: u64,
    read_ms: u64,
) -> Option<(String, u128)> {
    let mut ws = connect_request(&http_url, &opts).await?;
    barrier.wait().await;
    if sync_window_us > 0 {
        tokio::time::sleep(Duration::from_micros(sync_window_us.min(50_000))).await;
    }
    let t0 = Instant::now();
    ws.send(Message::Text(payload)).await.ok()?;
    let deadline = Instant::now() + Duration::from_millis(read_ms.clamp(200, 5000));
    let mut first = String::new();
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                first = t.chars().take(512).collect();
                break;
            }
            Ok(Some(Ok(Message::Binary(b)))) if !b.is_empty() => {
                first = format!("[binary {}B]", b.len());
                break;
            }
            Ok(Some(Ok(Message::Close(_)))) => break,
            Ok(Some(Ok(_))) => {}
            _ => break,
        }
    }
    let _ = ws.close(None).await;
    let elapsed_us = t0.elapsed().as_micros();
    Some((first, elapsed_us))
}

/// Establish N simultaneous WebSocket connections and release transactional frames on a barrier.
pub async fn execute_race_burst(http_url: &str, opts: &WsConnectOpts, cfg: &RaceConfig) -> Option<RaceOutcome> {
    let n = cfg.connections.clamp(2, 16);
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for _ in 0..n {
        let b = barrier.clone();
        let url = http_url.to_string();
        let o = opts.clone();
        let payload = cfg.payload.clone();
        let sync = cfg.sync_window_us;
        let read = cfg.read_ms;
        handles.push(tokio::spawn(async move {
            race_worker(url, o, payload, b, sync, read).await
        }));
    }

    let mut responses = Vec::new();
    let mut timings = Vec::new();
    for h in handles {
        if let Ok(Some((body, us))) = h.await {
            if !body.is_empty() {
                responses.push(body);
                timings.push(us);
            }
        }
    }

    if responses.is_empty() {
        return None;
    }

    let success_count = responses.iter().filter(|r| looks_like_success(r)).count();
    let duplicate_success = success_count >= 2
        && responses
            .windows(2)
            .any(|w| looks_like_success(&w[0]) && looks_like_success(&w[1]) && w[0] == w[1]);

    let spread_us = if timings.len() >= 2 {
        let min_t = timings.iter().copied().min().unwrap_or(0);
        let max_t = timings.iter().copied().max().unwrap_or(0);
        max_t.saturating_sub(min_t) as u64
    } else {
        0
    };

    Some(RaceOutcome {
        connections: n,
        success_responses: success_count,
        spread_us,
        responses,
        duplicate_success,
        timing_anomaly: spread_us < 500 && success_count >= 2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_heuristic() {
        assert!(looks_like_success(r#"{"success":true,"id":"tx-1"}"#));
        assert!(!looks_like_success("unauthorized"));
    }
}
