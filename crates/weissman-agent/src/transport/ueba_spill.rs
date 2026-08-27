//! Local spill for `ueba_baseline` findings when the server signals backpressure
//! or the agent is offline.
//!
//! The API's COPY ingest uses a bounded mPSC. When that channel is full the
//! server returns `ServerToAgent::Backpressure` instead of INSERT-falling-back
//! (INSERT would just move the flood onto Postgres). The agent keeps a **FIFO
//! queue** next to `agent.state` as `ueba-spill.json` (owner-only `0600`) and
//! resends oldest-first after `retry_after_ms` or on the next session.
//!
//! Hard caps (`DEFAULT_MAX_SPILL_BYTES` / `DEFAULT_MAX_SPILL_SAMPLES`, overridable
//! via env) drop the oldest samples so a host that stays offline for weeks cannot
//! fill the disk and surface the agent via a Disk Full alert.

use crate::protocol::AgentToServer;
use crate::transport::state;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default on-disk cap (5 MiB). Override: `WEISSMAN_UEBA_SPILL_MAX_BYTES`.
pub const DEFAULT_MAX_SPILL_BYTES: usize = 5 * 1024 * 1024;
/// Default sample cap. Override: `WEISSMAN_UEBA_SPILL_MAX_SAMPLES`.
pub const DEFAULT_MAX_SPILL_SAMPLES: usize = 10_000;
/// Max findings resent on a fresh session so a 10k queue cannot flood the socket.
pub const DEFAULT_SESSION_RESEND_BURST: usize = 64;

const SPILL_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct SpillFile {
    v: u32,
    items: Vec<AgentToServer>,
}

#[must_use]
pub fn spill_path() -> PathBuf {
    state::state_path().with_file_name("ueba-spill.json")
}

fn path_beside(state_file: &Path) -> PathBuf {
    state_file.with_file_name("ueba-spill.json")
}

#[must_use]
pub fn spill_max_bytes() -> usize {
    env_usize("WEISSMAN_UEBA_SPILL_MAX_BYTES", DEFAULT_MAX_SPILL_BYTES).max(1)
}

#[must_use]
pub fn spill_max_samples() -> usize {
    env_usize("WEISSMAN_UEBA_SPILL_MAX_SAMPLES", DEFAULT_MAX_SPILL_SAMPLES).max(1)
}

fn env_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

fn is_ueba(msg: &AgentToServer) -> bool {
    matches!(msg, AgentToServer::Finding { engine, .. } if engine == "ueba_baseline")
}

fn findings_match(a: &AgentToServer, b: &AgentToServer) -> bool {
    serde_json::to_vec(a).ok() == serde_json::to_vec(b).ok()
}

/// Persist a UEBA finding (owner-only). Appends to the FIFO queue and trims
/// oldest samples when the byte or count cap is reached.
pub fn write_finding(msg: &AgentToServer) -> std::io::Result<()> {
    write_finding_at(&spill_path(), msg)
}

pub fn write_finding_at(path: &Path, msg: &AgentToServer) -> std::io::Result<()> {
    write_finding_at_capped(path, msg, spill_max_bytes(), spill_max_samples())
}

pub fn write_finding_at_capped(
    path: &Path,
    msg: &AgentToServer,
    max_bytes: usize,
    max_samples: usize,
) -> std::io::Result<()> {
    if !is_ueba(msg) {
        return Ok(());
    }
    let mut items = load_items(path);
    items.push(msg.clone());
    trim_fifo(&mut items, max_bytes, max_samples);
    persist_items(path, &items)
}

/// Peek the oldest spilled UEBA finding (does not remove it).
#[must_use]
pub fn load_finding() -> Option<AgentToServer> {
    load_finding_at(&spill_path())
}

#[must_use]
pub fn load_finding_at(path: &Path) -> Option<AgentToServer> {
    load_items(path).into_iter().next()
}

/// Remove the oldest finding after a successful resend.
pub fn pop_oldest() -> Option<AgentToServer> {
    pop_oldest_at(&spill_path())
}

pub fn pop_oldest_at(path: &Path) -> Option<AgentToServer> {
    let mut items = load_items(path);
    if items.is_empty() {
        return None;
    }
    let popped = items.remove(0);
    let _ = persist_items(path, &items);
    Some(popped)
}

/// Pop the oldest finding only when it still matches `expected` (avoids
/// dropping a different sample if another task already drained the head).
pub fn pop_oldest_if(expected: &AgentToServer) -> bool {
    pop_oldest_if_at(&spill_path(), expected)
}

pub fn pop_oldest_if_at(path: &Path, expected: &AgentToServer) -> bool {
    let mut items = load_items(path);
    let Some(head) = items.first() else {
        return false;
    };
    if !findings_match(head, expected) {
        return false;
    }
    items.remove(0);
    let _ = persist_items(path, &items);
    true
}

/// How many UEBA samples are currently spilled at `path`.
#[must_use]
pub fn spill_len_at(path: &Path) -> usize {
    load_items(path).len()
}

#[must_use]
pub fn spill_bytes_at(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn load_items(path: &Path) -> Vec<AgentToServer> {
    let Ok(raw) = std::fs::read(path) else {
        return Vec::new();
    };
    if raw.is_empty() {
        return Vec::new();
    }
    if let Ok(file) = serde_json::from_slice::<SpillFile>(&raw) {
        return file.items.into_iter().filter(is_ueba).collect();
    }
    match serde_json::from_slice::<AgentToServer>(&raw) {
        Ok(msg) if is_ueba(&msg) => vec![msg],
        Ok(_) => Vec::new(),
        Err(e) => {
            tracing::warn!(
                target: "agent", path = %path.display(), error = %e,
                "ueba spill file is unreadable; dropping"
            );
            Vec::new()
        }
    }
}

fn encoded_len(items: &[AgentToServer]) -> usize {
    serde_json::to_vec(&SpillFile {
        v: SPILL_FORMAT_VERSION,
        items: items.to_vec(),
    })
    .map(|b| b.len())
    .unwrap_or(usize::MAX)
}

fn trim_fifo(items: &mut Vec<AgentToServer>, max_bytes: usize, max_samples: usize) {
    if max_samples == 0 {
        items.clear();
        return;
    }
    while items.len() > max_samples {
        items.remove(0);
    }
    while items.len() > 1 && encoded_len(items) > max_bytes {
        items.remove(0);
    }
    if !items.is_empty() && encoded_len(items) > max_bytes {
        // A single sample larger than the cap must not blow the host disk.
        items.clear();
    }
}

fn persist_items(path: &Path, items: &[AgentToServer]) -> std::io::Result<()> {
    if items.is_empty() {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_vec(&SpillFile {
        v: SPILL_FORMAT_VERSION,
        items: items.to_vec(),
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("spill.tmp");
    std::fs::write(&tmp, &body)?;
    set_owner_only(&tmp)?;
    std::fs::rename(&tmp, path)?;
    set_owner_only(path)
}

#[allow(dead_code)]
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
    use std::sync::atomic::{AtomicU64, Ordering};

    fn sample() -> AgentToServer {
        sample_n(1)
    }

    fn sample_n(n: u32) -> AgentToServer {
        AgentToServer::Finding {
            agent_id: "agent-1".into(),
            task_id: format!("task-{n}"),
            engine: "ueba_baseline".into(),
            finding: json!({"hour_of_week": 16, "metrics": {"open_port_count": n}}),
        }
    }

    fn temp_path(label: &str) -> (PathBuf, PathBuf) {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "weissman-ueba-spill-{}-{}-{}",
            label,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ueba-spill.json");
        (dir, path)
    }

    #[test]
    fn spill_round_trips_ueba_finding() {
        let (dir, path) = temp_path("roundtrip");
        write_finding_at(&path, &sample()).expect("write");
        let loaded = load_finding_at(&path).expect("load");
        match loaded {
            AgentToServer::Finding { engine, finding, .. } => {
                assert_eq!(engine, "ueba_baseline");
                assert_eq!(finding["metrics"]["open_port_count"], 1);
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
        let (dir, path) = temp_path("other");
        let msg = AgentToServer::Finding {
            agent_id: "a".into(),
            task_id: "t".into(),
            engine: "process_inventory".into(),
            finding: json!({}),
        };
        write_finding_at(&path, &msg).expect("write");
        assert!(load_finding_at(&path).is_none());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fifo_drops_oldest_when_sample_cap_is_hit() {
        let (dir, path) = temp_path("fifo-count");
        for n in 1..=5 {
            write_finding_at_capped(&path, &sample_n(n), DEFAULT_MAX_SPILL_BYTES, 3).expect("write");
        }
        assert_eq!(spill_len_at(&path), 3);
        match load_finding_at(&path).expect("oldest") {
            AgentToServer::Finding { task_id, finding, .. } => {
                assert_eq!(task_id, "task-3");
                assert_eq!(finding["metrics"]["open_port_count"], 3);
            }
            other => panic!("unexpected {other:?}"),
        }
        let popped = pop_oldest_at(&path).expect("pop");
        match popped {
            AgentToServer::Finding { task_id, .. } => assert_eq!(task_id, "task-3"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(spill_len_at(&path), 2);
        match load_finding_at(&path).expect("next") {
            AgentToServer::Finding { task_id, .. } => assert_eq!(task_id, "task-4"),
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fifo_drops_oldest_when_byte_cap_is_hit() {
        let (dir, path) = temp_path("fifo-bytes");
        let bulky = AgentToServer::Finding {
            agent_id: "agent-1".into(),
            task_id: "task-big-1".into(),
            engine: "ueba_baseline".into(),
            finding: json!({"blob": "x".repeat(800)}),
        };
        let bulky2 = AgentToServer::Finding {
            agent_id: "agent-1".into(),
            task_id: "task-big-2".into(),
            engine: "ueba_baseline".into(),
            finding: json!({"blob": "y".repeat(800)}),
        };
        let bulky3 = AgentToServer::Finding {
            agent_id: "agent-1".into(),
            task_id: "task-big-3".into(),
            engine: "ueba_baseline".into(),
            finding: json!({"blob": "z".repeat(800)}),
        };
        // ~800-byte blob + envelope: two items fit under 2 KiB, three do not.
        write_finding_at_capped(&path, &bulky, 2_048, 10_000).expect("w1");
        write_finding_at_capped(&path, &bulky2, 2_048, 10_000).expect("w2");
        write_finding_at_capped(&path, &bulky3, 2_048, 10_000).expect("w3");
        assert!(spill_bytes_at(&path) <= 2_048, "file grew to {}", spill_bytes_at(&path));
        assert!(spill_len_at(&path) <= 2);
        match load_finding_at(&path).expect("oldest after byte trim") {
            AgentToServer::Finding { task_id, .. } => {
                assert_ne!(task_id, "task-big-1", "oldest must have been FIFO-dropped");
            }
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_single_object_file_still_loads() {
        let (dir, path) = temp_path("legacy");
        let raw = serde_json::to_vec(&sample()).expect("ser");
        std::fs::write(&path, raw).expect("write legacy");
        let loaded = load_finding_at(&path).expect("legacy load");
        match loaded {
            AgentToServer::Finding { engine, .. } => assert_eq!(engine, "ueba_baseline"),
            other => panic!("unexpected {other:?}"),
        }
        write_finding_at_capped(&path, &sample_n(2), DEFAULT_MAX_SPILL_BYTES, 10).expect("append");
        assert_eq!(spill_len_at(&path), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pop_oldest_if_only_removes_matching_head() {
        let (dir, path) = temp_path("pop-if");
        write_finding_at(&path, &sample_n(1)).unwrap();
        write_finding_at(&path, &sample_n(2)).unwrap();
        assert!(!pop_oldest_if_at(&path, &sample_n(2)));
        assert_eq!(spill_len_at(&path), 2);
        assert!(pop_oldest_if_at(&path, &sample_n(1)));
        assert_eq!(spill_len_at(&path), 1);
        match load_finding_at(&path).unwrap() {
            AgentToServer::Finding { task_id, .. } => assert_eq!(task_id, "task-2"),
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
