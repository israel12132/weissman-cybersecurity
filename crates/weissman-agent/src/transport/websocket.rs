//! WebSocket session: send Hello, accept Tasks, stream Findings, send Heartbeats.

use crate::detections;
use crate::protocol::{AgentToServer, Enrollment, ServerToAgent};
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};
use url::Url;

const CHANNEL_BUFFER: usize = 256;
const READ_IDLE_TIMEOUT_SECS: u64 = 90;

/// Run a single WebSocket session. Returns when the connection closes.
pub async fn run_session(
    server_url: &str,
    enrollment: &Enrollment,
    heartbeat_secs: u64,
) -> anyhow::Result<()> {
    let ws_url = build_ws_url(server_url, &enrollment.ws_path, &enrollment.session_jwt)?;
    info!(target: "agent", "connecting to {}", scrub_token(&ws_url));

    let (ws_stream, _resp) = tokio_tungstenite::connect_async(ws_url).await?;
    let (mut sink, mut stream) = ws_stream.split();

    // Outbound channel: detections + heartbeat → WebSocket sink.
    let (out_tx, mut out_rx) = mpsc::channel::<AgentToServer>(CHANNEL_BUFFER);

    // Send Hello immediately.
    let hello = AgentToServer::Hello {
        agent_id: enrollment.agent_id.clone(),
        hostname: hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string()),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        tenant_id: enrollment.tenant_id,
        client_id: enrollment.client_id,
        capabilities: detections::all_capability_ids()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
    };
    out_tx.send(hello).await.ok();

    // Shared counters for heartbeat.
    let running_tasks = Arc::new(AtomicU32::new(0));
    let completed_tasks = Arc::new(AtomicU64::new(0));
    let started_at = Instant::now();

    // Heartbeat ticker.
    let hb_running = Arc::clone(&running_tasks);
    let hb_completed = Arc::clone(&completed_tasks);
    let hb_tx = out_tx.clone();
    let agent_id_hb = enrollment.agent_id.clone();
    let hb_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(heartbeat_secs.max(5)));
        // Skip the initial immediate tick — Hello already proved liveness.
        interval.tick().await;
        loop {
            interval.tick().await;
            let msg = AgentToServer::Heartbeat {
                agent_id: agent_id_hb.clone(),
                running_tasks: hb_running.load(Ordering::Relaxed),
                completed_tasks: hb_completed.load(Ordering::Relaxed),
                uptime_secs: started_at.elapsed().as_secs(),
            };
            if hb_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Writer: out_rx → sink.
    let writer_handle = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let line = match serde_json::to_string(&msg) {
                Ok(l) => l,
                Err(e) => {
                    error!(target: "agent", error = %e, "serialize outbound");
                    continue;
                }
            };
            if let Err(e) = sink.send(Message::Text(line)).await {
                error!(target: "agent", error = %e, "ws send failed");
                break;
            }
        }
        let _ = sink.send(Message::Close(None)).await;
    });

    // Reader: stream → handle ServerToAgent.
    let read_result = async {
        loop {
            let next =
                tokio::time::timeout(Duration::from_secs(READ_IDLE_TIMEOUT_SECS), stream.next())
                    .await;
            let frame = match next {
                Ok(Some(Ok(frame))) => frame,
                Ok(Some(Err(e))) => return Err(anyhow::anyhow!("read error: {e}")),
                Ok(None) => return Ok(()),
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "idle timeout (no frame for {}s)",
                        READ_IDLE_TIMEOUT_SECS
                    ))
                }
            };
            match frame {
                Message::Text(s) => {
                    handle_text(
                        &s,
                        &out_tx,
                        &running_tasks,
                        &completed_tasks,
                        enrollment.agent_id.clone(),
                    )
                    .await;
                }
                Message::Binary(b) => {
                    warn!(target: "agent", "ignoring binary frame ({} B)", b.len());
                }
                Message::Ping(p) => {
                    debug!(target: "agent", "ws ping {} B", p.len());
                }
                Message::Pong(_) => {}
                Message::Close(_) => {
                    info!(target: "agent", "ws close received");
                    return Ok(());
                }
                Message::Frame(_) => {}
            }
        }
    }
    .await;

    // Tear down workers cleanly.
    drop(out_tx);
    let _ = writer_handle.await;
    hb_handle.abort();
    read_result
}

async fn handle_text(
    text: &str,
    out_tx: &mpsc::Sender<AgentToServer>,
    running: &Arc<AtomicU32>,
    completed: &Arc<AtomicU64>,
    agent_id: String,
) {
    let parsed: Result<ServerToAgent, _> = serde_json::from_str(text);
    let msg = match parsed {
        Ok(m) => m,
        Err(e) => {
            warn!(target: "agent", error = %e, "drop malformed server frame");
            return;
        }
    };
    match msg {
        ServerToAgent::Welcome { .. } => {
            info!(target: "agent", "server welcomed agent");
        }
        ServerToAgent::Task {
            task_id,
            engine,
            target,
            params,
        } => {
            running.fetch_add(1, Ordering::SeqCst);
            let out_tx = out_tx.clone();
            let running_c = Arc::clone(running);
            let completed_c = Arc::clone(completed);
            let agent_id_c = agent_id.clone();
            tokio::spawn(async move {
                run_task(
                    task_id,
                    engine,
                    target,
                    params,
                    out_tx,
                    running_c,
                    completed_c,
                    agent_id_c,
                )
                .await;
            });
        }
        ServerToAgent::Ack { .. } => {}
        ServerToAgent::Shutdown { reason } => {
            warn!(target: "agent", reason = %reason, "server requested shutdown");
            std::process::exit(0);
        }
    }
}

async fn run_task(
    task_id: String,
    engine: String,
    target: Option<String>,
    params: serde_json::Value,
    out_tx: mpsc::Sender<AgentToServer>,
    running: Arc<AtomicU32>,
    completed: Arc<AtomicU64>,
    agent_id: String,
) {
    info!(target: "agent", task_id = %task_id, engine = %engine, "task start");

    // Hard cap per detection.
    let timeout = Duration::from_secs(90);
    let det = detections::run_detection(&engine, target.as_deref(), &params);
    let result = tokio::time::timeout(timeout, det).await;

    let (findings_count, status, message) = match result {
        Ok(Ok(findings)) => {
            let count = findings.len() as u32;
            for f in findings {
                let _ = out_tx
                    .send(AgentToServer::Finding {
                        agent_id: agent_id.clone(),
                        task_id: task_id.clone(),
                        engine: engine.clone(),
                        finding: f,
                    })
                    .await;
            }
            (count, "ok".to_string(), None)
        }
        Ok(Err(e)) => (0, "error".to_string(), Some(e.to_string())),
        Err(_) => (
            0,
            "error".to_string(),
            Some(format!("detection timed out after {}s", timeout.as_secs())),
        ),
    };

    let done = if status == "ok" {
        AgentToServer::TaskDone {
            agent_id: agent_id.clone(),
            task_id: task_id.clone(),
            engine: engine.clone(),
            findings_count,
            status,
            message,
        }
    } else {
        AgentToServer::TaskError {
            agent_id: agent_id.clone(),
            task_id: task_id.clone(),
            engine: engine.clone(),
            error: message.unwrap_or_else(|| "unknown".into()),
        }
    };
    let _ = out_tx.send(done).await;
    running.fetch_sub(1, Ordering::SeqCst);
    completed.fetch_add(1, Ordering::SeqCst);
}

fn build_ws_url(server_url: &str, path: &str, token: &str) -> anyhow::Result<Url> {
    let base = server_url.trim_end_matches('/');
    // Promote http→ws / https→wss.
    let ws_base = if let Some(r) = base.strip_prefix("https://") {
        format!("wss://{}", r)
    } else if let Some(r) = base.strip_prefix("http://") {
        format!("ws://{}", r)
    } else {
        format!("wss://{}", base)
    };
    let p = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    let full = format!("{}{}?access_token={}", ws_base, p, urlencoding(token));
    Ok(Url::parse(&full)?)
}

fn urlencoding(s: &str) -> String {
    // Minimal percent-encode for the token. Tokens are URL-safe base64 already, but `=` is
    // not safe inside a query string in some HTTP parsers, so escape it.
    s.chars()
        .map(|c| match c {
            '=' => "%3D".to_string(),
            '&' | '#' | '?' | ' ' => format!("%{:02X}", c as u32),
            _ => c.to_string(),
        })
        .collect()
}

fn scrub_token(url: &Url) -> String {
    let mut clean = url.clone();
    clean.set_query(Some("access_token=[redacted]"));
    clean.to_string()
}
