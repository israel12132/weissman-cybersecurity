//! Disk spool for findings / task completions when the WebSocket is down.

use crate::protocol::AgentToServer;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const MAX_SPOOL_BYTES: u64 = 32 * 1024 * 1024;

#[must_use]
pub fn spool_path() -> PathBuf {
    if let Some(p) = std::env::var_os("WEISSMAN_AGENT_SPOOL_FILE") {
        return PathBuf::from(p);
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("agent.spool.jsonl")))
        .unwrap_or_else(|| PathBuf::from("/opt/weissman/agent.spool.jsonl"))
}

pub fn append(path: &Path, msg: &AgentToServer) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if path.exists() {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > MAX_SPOOL_BYTES {
                tracing::error!(target: "agent", "offline spool full — dropping oldest half");
                truncate_oldest_half(path)?;
            }
        }
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    let mut line = serde_json::to_vec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');
    f.write_all(&line)?;
    Ok(())
}

pub fn drain(path: &Path) -> std::io::Result<Vec<AgentToServer>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let f = File::open(path)?;
    let mut out = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(msg) = serde_json::from_str::<AgentToServer>(&line) {
            out.push(msg);
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(out)
}

fn truncate_oldest_half(path: &Path) -> std::io::Result<()> {
    let raw = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = raw.lines().collect();
    let keep = &lines[lines.len() / 2..];
    std::fs::write(path, keep.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn append_and_drain_roundtrip() {
        let dir = std::env::temp_dir().join(format!("weissman-spool-{}", std::process::id()));
        let path = dir.join("agent.spool.jsonl");
        let msg = AgentToServer::Finding {
            agent_id: "a1".into(),
            task_id: "t1".into(),
            engine: "ueba_baseline".into(),
            finding: json!({"x": 1}),
        };
        append(&path, &msg).unwrap();
        let drained = drain(&path).unwrap();
        assert_eq!(drained.len(), 1);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
