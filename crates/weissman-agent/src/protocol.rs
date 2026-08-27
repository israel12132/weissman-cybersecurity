//! Wire protocol between the agent and the Weissman server.
//!
//! All messages are JSON, one envelope per line. The protocol is deliberately small so the same
//! schema can be replayed from raw `wscat` for debugging.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentToServer {
    /// Internal signal to the writer task: emit a WebSocket `Ping` control frame.
    ///
    /// Never serialised to the wire as JSON — the writer intercepts it and sends a protocol-level
    /// Ping instead, whose Pong is what resets the agent's read-idle deadline. This protocol is
    /// agent-talks-first and the server sends no keepalive, so without it a healthy connection
    /// was torn down every 90s and rebuilt, forever.
    #[serde(skip)]
    KeepAlivePing,
    /// First message after WS connect. Carries identity + version.
    Hello {
        agent_id: String,
        hostname: String,
        os: String,
        arch: String,
        version: String,
        tenant_id: i64,
        client_id: i64,
        capabilities: Vec<String>,
    },
    /// Periodic liveness ping. Reset on every detection.
    Heartbeat {
        agent_id: String,
        running_tasks: u32,
        completed_tasks: u64,
        uptime_secs: u64,
    },
    /// Engine-style finding produced by a local detection.
    Finding {
        agent_id: String,
        task_id: String,
        engine: String,
        finding: Value,
    },
    /// Detection completed. Carries summary counts.
    TaskDone {
        agent_id: String,
        task_id: String,
        engine: String,
        findings_count: u32,
        status: String, // "ok" | "error"
        message: Option<String>,
    },
    /// Detection failed.
    TaskError {
        agent_id: String,
        task_id: String,
        engine: String,
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerToAgent {
    /// Server accepted hello (echoes any per-agent settings).
    Welcome {
        scan_concurrency: Option<u32>,
        heartbeat_secs: Option<u64>,
    },
    /// Dispatch a detection task.
    Task {
        task_id: String,
        engine: String,
        target: Option<String>,
        params: Value,
    },
    /// Server-side acknowledgement of a finding (mostly for flow control).
    Ack { task_id: String },
    /// Asks the agent to shut down (revoked, deprovisioned, …). Unsigned — ignored
    /// unless `WEISSMAN_AGENT_ALLOW_LOCAL_STOP=1`.
    Shutdown { reason: String },
    /// Signed remote kill — agent verifies HMAC before latching and exiting.
    KillSwitch {
        reason: String,
        nonce: String,
        issued_at_unix: i64,
        signature: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrollment {
    pub agent_id: String,
    pub tenant_id: i64,
    pub client_id: i64,
    pub session_jwt: String,
    /// Long-lived renewal credential issued once at enrollment. Persisted to the agent state file
    /// and exchanged at `POST /api/agents/session` for a fresh `session_jwt`, so the agent
    /// survives a restart and a JWT expiry without a second (single-use) enrollment token.
    /// Defaulted so an older server that does not send it still deserializes.
    #[serde(default)]
    pub agent_secret: String,
    pub ws_path: String, // e.g. "/ws/agent"
    pub server_message: Option<String>,
    /// Derived HMAC key so this agent can verify a signed kill-switch. Empty on older servers.
    #[serde(default)]
    pub kill_hmac_key: String,
}
