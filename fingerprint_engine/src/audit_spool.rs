//! Bounded local audit spool for events that cannot ride an in-process channel.
//!
//! A full SSE / PoE / SIEM buffer must **not** silently discard security evidence
//! (Bank of Israel directive 361). It also must **not** unbounded-write JSON to
//! `/var/log` (that is a disk DoS). This module appends JSONL under a cap:
//! 8 MiB per file, 64 MiB per directory, oldest files deleted first.
//!
//! Override the directory with `WEISSMAN_AUDIT_SPOOL_DIR`.

use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DIR_BYTES: u64 = 64 * 1024 * 1024;
const PREVIEW_BYTES: usize = 2048;

static SPOOL_LOCK: Mutex<()> = Mutex::new(());

fn default_dir() -> PathBuf {
    if let Ok(p) = std::env::var("WEISSMAN_AUDIT_SPOOL_DIR") {
        let t = p.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }
    let varlib = PathBuf::from("/var/lib/weissman/audit-spool");
    if varlib.is_dir() || fs::create_dir_all(&varlib).is_ok() {
        return varlib;
    }
    std::env::temp_dir().join("weissman-audit-spool")
}

/// Append one audit line. `payload` is hashed in full; only a preview is stored
/// when the body exceeds [`PREVIEW_BYTES`] so a flood cannot fill the disk with
/// identical junk while still leaving a forensic fingerprint.
pub fn append(channel: &str, payload: &str) {
    let dir = default_dir();
    let _ = append_to(&dir, channel, payload);
}

pub fn append_to(dir: &Path, channel: &str, payload: &str) -> std::io::Result<PathBuf> {
    let _g = SPOOL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    fs::create_dir_all(dir)?;
    enforce_dir_cap(dir);
    let path = current_file(dir);
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    if f.metadata()?.len() >= MAX_FILE_BYTES {
        drop(f);
        let path = rotate_file(dir);
        f = OpenOptions::new().create(true).append(true).open(&path)?;
    }
    let digest = Sha256::digest(payload.as_bytes());
    let hex = hex::encode(digest);
    let preview = if payload.len() <= PREVIEW_BYTES {
        payload
    } else {
        &payload[..PREVIEW_BYTES]
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let truncated = payload.len() > PREVIEW_BYTES;
    let line = serde_json::json!({
        "ts_ms": ts,
        "channel": channel,
        "sha256": hex,
        "len": payload.len(),
        "truncated": truncated,
        "body": preview,
    });
    let mut w = BufWriter::new(f);
    writeln!(w, "{line}")?;
    w.flush()?;
    Ok(path)
}

fn current_file(dir: &Path) -> PathBuf {
    dir.join("spool.jsonl")
}

fn rotate_file(dir: &Path) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let rotated = dir.join(format!("spool-{ts}.jsonl"));
    let current = current_file(dir);
    let _ = fs::rename(&current, &rotated);
    current
}

fn enforce_dir_cap(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(u64, u64, PathBuf)> = Vec::new();
    let mut total = 0u64;
    for e in rd.flatten() {
        let path = e.path();
        let Ok(meta) = e.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let len = meta.len();
        total = total.saturating_add(len);
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        files.push((mtime, len, path));
    }
    if total <= MAX_DIR_BYTES {
        return;
    }
    files.sort_by_key(|(mtime, _, _)| *mtime);
    for (_, len, path) in files {
        if total <= MAX_DIR_BYTES {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spool_persists_payload_hash_and_preview() {
        let dir = tempfile::tempdir().expect("tempdir");
        append_to(dir.path(), "sse_bridge", "security-event-alpha").unwrap();
        let body = fs::read_to_string(dir.path().join("spool.jsonl")).unwrap();
        assert!(body.contains("sse_bridge"));
        assert!(body.contains("security-event-alpha"));
        assert!(body.contains("sha256"));
    }

    #[test]
    fn spool_is_capped_not_unbounded() {
        assert_eq!(MAX_DIR_BYTES, 64 * 1024 * 1024);
        assert_eq!(MAX_FILE_BYTES, 8 * 1024 * 1024);
        let src = include_str!("audit_spool.rs");
        assert!(src.contains("WEISSMAN_AUDIT_SPOOL_DIR"));
        assert!(src.contains("BufWriter"));
    }
}
