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
        /// Encrypted ring occupancy while WSS was down (bytes of ciphertext).
        #[serde(default)]
        ring_buffer_bytes: u32,
        #[serde(default)]
        ring_buffer_frames: u32,
        /// Edge UEBA ticks that stayed local because |z| ≤ 2 and no new process.
        #[serde(default)]
        ueba_suppressed: u64,
        /// Edge UEBA ticks that were uploaded (training, |z| > 2, or new process).
        #[serde(default)]
        ueba_uploaded: u64,
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
        /// Compact hour-of-week mean/stddev so the agent can gate ueba_baseline locally.
        #[serde(default)]
        ueba_baseline: Option<UebaCompactSnapshot>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inner_key_hex: Option<String>,
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
    /// Mid-session refresh of the compact UEBA snapshot (after ingest recomputes baselines).
    UebaBaseline {
        #[serde(flatten)]
        snapshot: UebaCompactSnapshot,
    },
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

/// Compressed 7-day baseline for the current hour-of-week (or rolling-7d fallback).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UebaCompactSnapshot {
    pub hour_of_week: i16,
    #[serde(default = "default_z_upload")]
    pub z_upload_threshold: f64,
    #[serde(default = "default_min_n")]
    pub min_n: i32,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub metrics: Vec<UebaCompactMetric>,
    #[serde(default)]
    pub learned_processes: Vec<String>,
    /// HMAC-SHA256 (hex) over the canonical snapshot, keyed by the tenant-derived
    /// `ueba_mac_key` issued at enrollment. Empty / mismatch → agent refuses to install.
    #[serde(default)]
    pub mac: String,
}

fn default_z_upload() -> f64 {
    2.0
}
fn default_min_n() -> i32 {
    7
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UebaCompactMetric {
    pub name: String,
    pub mean: f64,
    pub stddev: f64,
    pub n: i32,
}

impl UebaCompactSnapshot {
    #[must_use]
    pub fn metric(&self, name: &str) -> Option<&UebaCompactMetric> {
        self.metrics.iter().find(|m| m.name == name)
    }
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
    /// Per-agent HMAC key (64 hex) for verifying Welcome / UebaBaseline snapshots.
    #[serde(default)]
    pub ueba_mac_key: String,
    /// Derived HMAC key so this agent can verify a signed kill-switch. Empty on older servers.
    #[serde(default)]
    pub kill_hmac_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welcome_round_trips_compact_baseline() {
        let msg = ServerToAgent::Welcome {
            scan_concurrency: Some(8),
            heartbeat_secs: Some(20),
            inner_key_hex: None,
            ueba_baseline: Some(UebaCompactSnapshot {
                hour_of_week: 42,
                z_upload_threshold: 2.0,
                min_n: 7,
                source: "hour_of_week".into(),
                metrics: vec![UebaCompactMetric {
                    name: "process_count".into(),
                    mean: 120.0,
                    stddev: 4.0,
                    n: 24,
                }],
                learned_processes: vec!["sshd".into()],
                mac: String::new(),
            }),
        };
        let v = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "welcome");
        assert_eq!(v["ueba_baseline"]["hour_of_week"], 42);
        let back: ServerToAgent = serde_json::from_value(v).unwrap();
        match back {
            ServerToAgent::Welcome {
                ueba_baseline: Some(s),
                ..
            } => {
                assert_eq!(s.hour_of_week, 42);
                assert_eq!(s.metric("process_count").unwrap().mean, 120.0);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn welcome_without_baseline_still_parses() {
        let v = serde_json::json!({
            "type": "welcome",
            "scan_concurrency": 4,
            "heartbeat_secs": null
        });
        let msg: ServerToAgent = serde_json::from_value(v).unwrap();
        match msg {
            ServerToAgent::Welcome { ueba_baseline, .. } => assert!(ueba_baseline.is_none()),
            other => panic!("unexpected {other:?}"),
        }
    }
}
