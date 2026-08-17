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
    let ws_url = build_ws_url(server_url, &enrollment.ws_path)?;
    info!(target: "agent", "connecting to {}", scrub_token(&ws_url));

    // tokio-tungstenite 0.24 dropped the `url` integration (url::Url no longer
    // implements IntoClientRequest); pass the URL as &str.
    // Bearer in a HEADER, not the query string. `?token=<jwt>` put a live credential into every
    // reverse-proxy access log, Referer chain and log bundle — deploy/nginx-gateway.conf proxies
    // /ws/ with default access logging, so the token was written to disk on every handshake.
    // Anyone who can read those logs could connect as this agent for the remainder of the token's
    // life and inject findings or close tasks for the tenant. The server already documents the
    // header as the preferred form ("prefer `Authorization: Bearer <session_jwt>`").
    let mut request =
        tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
            ws_url.as_str(),
        )?;
    request.headers_mut().insert(
        "Authorization",
        tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&format!(
            "Bearer {}",
            enrollment.session_jwt
        ))?,
    );
    let (ws_stream, _resp) = tokio_tungstenite::connect_async(request).await?;
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

    // Shared counters for heartbeat + concurrency gate.
    let running_tasks = Arc::new(AtomicU32::new(0));
    let completed_tasks = Arc::new(AtomicU64::new(0));
    // Per-session, so a reconnect deliberately re-accepts tasks the server still considers
    // pending — that is the replay path working as intended. Within one session it stops the
    // 5s re-push from running the same detection concurrently with itself.
    let seen_tasks = Arc::new(tokio::sync::Mutex::new(SeenTasks::default()));
    let max_parallel = Arc::new(AtomicU32::new(4));
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
            // Pair every heartbeat with a Ping. The heartbeat proves the agent is alive TO the
            // server; the Pong it induces proves the server is alive to the agent. Only the second
            // one resets the read-idle deadline.
            if hb_tx.send(AgentToServer::KeepAlivePing).await.is_err() {
                break;
            }
        }
    });

    // Writer: out_rx → sink.
    let writer_handle = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            // A `Ping` request from the heartbeat loop, not an application message. Sent so the
            // server's WebSocket layer answers with a Pong, which is inbound traffic and therefore
            // resets the read-idle deadline below. Without it the connection was torn down every
            // READ_IDLE_TIMEOUT_SECS on a perfectly healthy link: this protocol is
            // agent-talks-first, the server has nothing to say between tasks, and it sends no
            // keepalive of its own — so read-idle was measuring "the server had no work", not
            // "the connection is dead", and the agent reconnected every 90 seconds forever.
            if matches!(msg, AgentToServer::KeepAlivePing) {
                if let Err(e) = sink.send(Message::Ping(Vec::new().into())).await {
                    warn!(target: "agent", error = %e, "ping send failed");
                    break;
                }
                continue;
            }
            let line = match serde_json::to_string(&msg) {
                Ok(l) => l,
                Err(e) => {
                    error!(target: "agent", error = %e, "serialize outbound");
                    continue;
                }
            };
            if let Err(e) = sink.send(Message::text(line)).await {
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
                        &max_parallel,
                        &seen_tasks,
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

/// Task ids this session has already accepted, so a re-pushed task is not run twice.
///
/// The server re-sends every still-`pending` task to every online agent on a 5-second tick, and
/// only marks a task done when the agent reports back — so a 30s detection was delivered ~6 times
/// and ran ~6 times CONCURRENTLY on the same host, each run persisting duplicate findings and,
/// for `chronos`, independently issuing an autonomous SIGSTOP against a live process.
///
/// Bounded so a long-lived session cannot grow it without limit: oldest ids are evicted first.
/// Eviction can only ever allow a re-run of a task last seen thousands of tasks ago, which is
/// indistinguishable from a legitimate re-dispatch.
#[derive(Default)]
pub(crate) struct SeenTasks {
    order: std::collections::VecDeque<String>,
    set: std::collections::HashSet<String>,
}

impl SeenTasks {
    const CAPACITY: usize = 4096;

    /// Record `id`; returns true if it is new to this session.
    pub(crate) fn insert_new(&mut self, id: &str) -> bool {
        if !self.set.insert(id.to_string()) {
            return false;
        }
        self.order.push_back(id.to_string());
        if self.order.len() > Self::CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

async fn handle_text(
    text: &str,
    out_tx: &mpsc::Sender<AgentToServer>,
    running: &Arc<AtomicU32>,
    completed: &Arc<AtomicU64>,
    max_parallel: &Arc<AtomicU32>,
    seen: &Arc<tokio::sync::Mutex<SeenTasks>>,
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
        ServerToAgent::Welcome {
            scan_concurrency, ..
        } => {
            if let Some(n) = scan_concurrency {
                max_parallel.store(n.max(1), Ordering::Relaxed);
            }
            info!(target: "agent", "server welcomed agent");
        }
        ServerToAgent::Task {
            task_id,
            engine,
            target,
            params,
        } => {
            if !seen.lock().await.insert_new(&task_id) {
                debug!(
                    target: "agent", %task_id,
                    "duplicate task push ignored (already accepted this session)"
                );
                return;
            }
            let out_tx = out_tx.clone();
            let running_c = Arc::clone(running);
            let completed_c = Arc::clone(completed);
            let max_parallel_c = Arc::clone(max_parallel);
            let agent_id_c = agent_id.clone();
            tokio::spawn(async move {
                while running_c.load(Ordering::SeqCst)
                    >= max_parallel_c.load(Ordering::Relaxed).max(1)
                {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                running_c.fetch_add(1, Ordering::SeqCst);
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

fn build_ws_url(server_url: &str, path: &str) -> anyhow::Result<Url> {
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
    // No credential in the URL — it travels in the Authorization header (see run_session).
    let full = format!("{}{}", ws_base, p);
    Ok(Url::parse(&full)?)
}
fn scrub_token(url: &Url) -> String {
    let mut clean = url.clone();
    clean.set_query(Some("access_token=[redacted]"));
    clean.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `KeepAlivePing` is an internal writer signal and must never reach the wire as JSON.
    ///
    /// If it ever serialised, the server's frame parser would see an unknown variant and log a
    /// "drop malformed frame" warning on every heartbeat — turning a keepalive into noise.
    #[test]
    fn keepalive_ping_is_never_serialised() {
        let json = serde_json::to_string(&crate::protocol::AgentToServer::KeepAlivePing);
        let rendered = json.as_deref().unwrap_or("<error>");
        assert!(
            json.is_err() || rendered == "null",
            "KeepAlivePing must not serialise to a wire frame; got {rendered:?}"
        );
    }

    /// Every heartbeat must be paired with a ping, or the read-idle deadline still expires.
    #[test]
    fn seen_tasks_evicts_oldest_and_stays_bounded() {
        let mut seen = SeenTasks::default();
        for i in 0..(SeenTasks::CAPACITY + 10) {
            assert!(seen.insert_new(&format!("task-{i}")), "each id is new");
        }
        // The most recent ids are still remembered ...
        assert!(!seen.insert_new(&format!("task-{}", SeenTasks::CAPACITY + 5)));
        // ... and the set has not grown without bound.
        assert!(seen.set.len() <= SeenTasks::CAPACITY);
        assert_eq!(seen.set.len(), seen.order.len(), "index and queue stay in step");
    }
}
