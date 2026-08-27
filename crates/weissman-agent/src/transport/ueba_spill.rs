//! Local spill for `ueba_baseline` findings when the server signals backpressure.
//!
//! The API's COPY ingest uses a bounded mPSC. When that channel is full the
//! server returns `ServerToAgent::Backpressure` instead of INSERT-falling-back
//! (INSERT would just move the flood onto Postgres). The agent keeps the last
//! UEBA finding next to `agent.state` and resends it after `retry_after_ms` or
//! on the next session.

use crate::protocol::AgentToServer;
use crate::transport::state;
use std::path::{Path, PathBuf};

#[must_use]
pub fn spill_path() -> PathBuf {
    state::state_path().with_file_name("ueba-spill.json")
}

fn path_beside(state_file: &Path) -> PathBuf {
    state_file.with_file_name("ueba-spill.json")
}

/// Persist the last UEBA finding (owner-only). Overwrites any previous spill.
pub fn write_finding(msg: &AgentToServer) -> std::io::Result<()> {
    write_finding_at(&spill_path(), msg)
}

pub fn write_finding_at(path: &Path, msg: &AgentToServer) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_vec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("spill.tmp");
    std::fs::write(&tmp, &body)?;
    set_owner_only(&tmp)?;
    std::fs::rename(&tmp, path)?;
    set_owner_only(path)
}

#[must_use]
pub fn load_finding() -> Option<AgentToServer> {
    load_finding_at(&spill_path())
}

#[must_use]
pub fn load_finding_at(path: &Path) -> Option<AgentToServer> {
    let raw = std::fs::read(path).ok()?;
    match serde_json::from_slice::<AgentToServer>(&raw) {
        Ok(msg @ AgentToServer::Finding { ref engine, .. }) if engine == "ueba_baseline" => {
            Some(msg)
        }
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(
                target: "agent", path = %path.display(), error = %e,
                "ueba spill file is unreadable; dropping"
            );
            None
        }
    }
}

pub fn clear() {
    let _ = std::fs::remove_file(spill_path());
}

#[allow(dead_code)]
pub fn clear_at(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[allow(dead_code)]
pub fn path_for_state(state_file: &Path) -> PathBuf {
    path_beside(state_file)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> AgentToServer {
        AgentToServer::Finding {
            agent_id: "agent-1".into(),
            task_id: "task-1".into(),
            engine: "ueba_baseline".into(),
            finding: json!({"hour_of_week": 16, "metrics": {"open_port_count": 3}}),
        }
    }

    #[test]
    fn spill_round_trips_ueba_finding() {
        let dir = std::env::temp_dir().join(format!("weissman-ueba-spill-{}", std::process::id()));
        let path = dir.join("ueba-spill.json");
        write_finding_at(&path, &sample()).expect("write");
        let loaded = load_finding_at(&path).expect("load");
        match loaded {
            AgentToServer::Finding { engine, finding, .. } => {
                assert_eq!(engine, "ueba_baseline");
                assert_eq!(finding["metrics"]["open_port_count"], 3);
            }
            other => panic!("unexpected {other:?}"),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        clear_at(&path);
        assert!(load_finding_at(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_ueba_finding_is_ignored() {
        let dir = std::env::temp_dir().join(format!("weissman-ueba-spill-other-{}", std::process::id()));
        let path = dir.join("ueba-spill.json");
        let msg = AgentToServer::Finding {
            agent_id: "a".into(),
            task_id: "t".into(),
            engine: "process_inventory".into(),
            finding: json!({}),
        };
        write_finding_at(&path, &msg).expect("write");
        assert!(load_finding_at(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
