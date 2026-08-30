//! Durable agent identity.
//!
//! The agent used to call `enroll()` on every process start and keep nothing on disk. Enrollment
//! tokens are strictly single-use (`endpoint_agent_enrollment_tokens.consumed_at`), so the agent
//! could only ever run ONCE: any restart — systemd, reboot, crash, or the `Restart=always` in the
//! installer's own unit file — re-enrolled with a consumed token, got HTTP 401, and exited.
//! `scripts/agent/install.sh` then made it unreachable even on first boot by burning the token in
//! its pre-flight check before handing the same token to the service. The live table has never
//! held a single row.
//!
//! Persisting the enrollment turns the token into what it is meant to be — a one-time bootstrap —
//! and lets the agent renew its short-lived session JWT from its own long-lived secret.

use crate::protocol::Enrollment;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What survives a restart. The session JWT deliberately does NOT: it is short-lived
/// (`WEISSMAN_AGENT_JWT_TTL_MINS`, default 240) and is re-minted from `agent_secret` on start.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentState {
    pub agent_id: String,
    pub tenant_id: i64,
    pub client_id: i64,
    /// Long-lived renewal credential, issued once at enrollment. Only its hash is on the server.
    pub agent_secret: String,
    pub ws_path: String,
}

impl AgentState {
    #[must_use]
    pub fn from_enrollment(e: &Enrollment) -> Self {
        Self {
            agent_id: e.agent_id.clone(),
            tenant_id: e.tenant_id,
            client_id: e.client_id,
            agent_secret: e.agent_secret.clone(),
            ws_path: e.ws_path.clone(),
        }
    }

    /// Rebuild a full [`Enrollment`] from persisted identity plus a freshly minted session JWT.
    #[must_use]
    pub fn into_enrollment(self, session_jwt: String) -> Enrollment {
        Enrollment {
            agent_id: self.agent_id,
            tenant_id: self.tenant_id,
            client_id: self.client_id,
            session_jwt,
            agent_secret: self.agent_secret,
            ws_path: self.ws_path,
            server_message: None,
        }
    }
}

/// Where identity is persisted. Defaults next to the installed binary so the systemd unit's
/// `ProtectSystem=strict` / `PrivateTmp=true` cannot hide it from the next start.
#[must_use]
pub fn state_path() -> PathBuf {
    if let Some(p) = std::env::var_os("WEISSMAN_AGENT_STATE_FILE") {
        return PathBuf::from(p);
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("agent.state")))
        .unwrap_or_else(|| PathBuf::from("/opt/weissman/agent.state"))
}

/// Load persisted identity, or `None` when absent/unreadable/corrupt.
///
/// A corrupt file is treated as absent rather than fatal: the agent then bootstraps from its
/// enrollment token if it still has one, which is strictly better than refusing to start.
#[must_use]
pub fn load(path: &Path) -> Option<AgentState> {
    let raw = super::spool_crypto::load_maybe_encrypted(path)?;
    let text = String::from_utf8(raw).ok()?;
    match serde_json::from_str::<AgentState>(&text) {
        Ok(s) if !s.agent_id.trim().is_empty() && !s.agent_secret.trim().is_empty() => Some(s),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(
                target: "agent", path = %path.display(), error = %e,
                "agent state file is unreadable; falling back to enrollment"
            );
            None
        }
    }
}

/// Persist identity encrypted (Linux: kernel keyring IKM) with owner-only permissions.
pub fn save(path: &Path, state: &AgentState) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    super::spool_crypto::persist_encrypted(path, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AgentState {
        AgentState {
            agent_id: "11111111-2222-3333-4444-555555555555".into(),
            tenant_id: 1,
            client_id: 2,
            agent_secret: "s3cr3t-renewal-credential".into(),
            ws_path: "/ws/agent".into(),
        }
    }

    #[test]
    fn round_trips_and_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("weissman-agent-state-{}", std::process::id()));
        let path = dir.join("agent.state");
        save(&path, &sample()).expect("save");

        let loaded = load(&path).expect("load");
        assert_eq!(loaded.agent_id, sample().agent_id);
        assert_eq!(loaded.agent_secret, sample().agent_secret);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "state holds a bearer credential; must be owner-only"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persisted_file_must_not_contain_plaintext_agent_secret() {
        let dir = std::env::temp_dir().join(format!(
            "weissman-agent-spool-secret-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let path = dir.join("agent.state");
        save(&path, &sample()).expect("save");
        let raw = std::fs::read(&path).expect("read spool");
        assert!(
            super::super::spool_crypto::looks_encrypted(&raw),
            "spool must be WSPL AEAD, not JSON"
        );
        let secret = b"s3cr3t-renewal-credential";
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "agent_secret must not appear in raw spool bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_plaintext_json_loads_for_migration() {
        let dir = std::env::temp_dir().join(format!(
            "weissman-agent-legacy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(1)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.state");
        let body = serde_json::to_vec_pretty(&sample()).unwrap();
        assert_eq!(body.first().copied(), Some(b'{'));
        std::fs::write(&path, &body).unwrap();
        let loaded = load(&path).expect("legacy plaintext must load once");
        assert_eq!(loaded.agent_secret, sample().agent_secret);
        save(&path, &loaded).expect("rewrite encrypted");
        let raw = std::fs::read(&path).unwrap();
        assert!(super::super::spool_crypto::looks_encrypted(&raw));
        assert!(!raw
            .windows(b"s3cr3t-renewal-credential".len())
            .any(|w| w == b"s3cr3t-renewal-credential"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_or_missing_state_is_not_fatal() {
        let dir = std::env::temp_dir().join(format!("weissman-agent-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.state");
        assert!(load(&path).is_none(), "missing file yields None");

        std::fs::write(&path, b"{not json").unwrap();
        assert!(
            load(&path).is_none(),
            "corrupt file yields None, not a panic"
        );

        // Structurally valid but useless — no credential to renew with.
        std::fs::write(&path, br#"{"agent_id":"","tenant_id":1,"client_id":1,"agent_secret":"","ws_path":"/ws/agent"}"#).unwrap();
        assert!(load(&path).is_none(), "empty identity must not be accepted");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
