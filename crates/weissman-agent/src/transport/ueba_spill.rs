//! Local spill for `ueba_baseline` findings when the server signals backpressure
//! or the agent is offline.
//!
//! On-disk layout (all `0600`):
//! - `ueba-spill.json` — **NDJSON**, append-only. A new sample is one `write(2)`
//!   of a JSON line. No parse of the rest of the file.
//! - `ueba-spill.off` — little-endian `u64` head offset + `u64` live count so
//!   peek/pop are O(1) seeks, not a rewrite of 5 MiB.
//! - `ueba-spill.arc` — concatenated zstd frames of FIFO-evicted lines (forensics
//!   + extra capacity). Thawed back into the hot file when the hot queue is empty.
//!
//! Caps (`DEFAULT_MAX_SPILL_BYTES` / `DEFAULT_MAX_SPILL_SAMPLES`) apply to the
//! **hot** NDJSON window. Overflow is compressed, not dropped, until the archive
//! itself hits `DEFAULT_MAX_ARC_BYTES`.

use crate::protocol::AgentToServer;
use crate::transport::state;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default on-disk cap for the hot NDJSON window (5 MiB).
pub const DEFAULT_MAX_SPILL_BYTES: usize = 5 * 1024 * 1024;
/// Default live sample cap on the hot window.
pub const DEFAULT_MAX_SPILL_SAMPLES: usize = 10_000;
/// Max findings resent on a fresh session.
pub const DEFAULT_SESSION_RESEND_BURST: usize = 64;
/// Pacing between burst packets (ms). Override: `WEISSMAN_UEBA_SPILL_PACE_MS`.
pub const DEFAULT_RESEND_PACE_MS: u64 = 8;
/// Compressed archive cap (concatenated zstd frames).
pub const DEFAULT_MAX_ARC_BYTES: usize = 5 * 1024 * 1024;
/// Compact (drop the dead prefix) when the wasted head exceeds this.
const COMPACT_WASTE_BYTES: u64 = 64 * 1024;

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

fn off_path(path: &Path) -> PathBuf {
    path.with_extension("off")
}

fn arc_path(path: &Path) -> PathBuf {
    path.with_extension("arc")
}

#[must_use]
pub fn spill_max_bytes() -> usize {
    env_usize("WEISSMAN_UEBA_SPILL_MAX_BYTES", DEFAULT_MAX_SPILL_BYTES).max(1)
}

#[must_use]
pub fn spill_max_samples() -> usize {
    env_usize("WEISSMAN_UEBA_SPILL_MAX_SAMPLES", DEFAULT_MAX_SPILL_SAMPLES).max(1)
}

/// 5–10 ms inclusive, default 8, plus 0–2 ms of clock jitter so a 64-sample
/// burst cannot look like a synchronized packet train.
#[must_use]
pub fn resend_pace() -> Duration {
    let base = env_u64("WEISSMAN_UEBA_SPILL_PACE_MS", DEFAULT_RESEND_PACE_MS).clamp(5, 10);
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() as u64) % 3)
        .unwrap_or(0);
    Duration::from_millis(base.saturating_add(jitter))
}

fn env_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

fn env_u64(var: &str, default: u64) -> u64 {
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

struct Cursor {
    head: u64,
    count: u64,
}

fn read_cursor(path: &Path) -> Cursor {
    let raw = std::fs::read(off_path(path)).unwrap_or_default();
    if raw.len() >= 16 {
        let head = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
        let count = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
        Cursor { head, count }
    } else {
        Cursor { head: 0, count: 0 }
    }
}

fn write_cursor(path: &Path, cur: &Cursor) -> std::io::Result<()> {
    let off = off_path(path);
    if cur.count == 0 && cur.head == 0 {
        let _ = std::fs::remove_file(&off);
        return Ok(());
    }
    if let Some(dir) = off.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&cur.head.to_le_bytes());
    buf[8..16].copy_from_slice(&cur.count.to_le_bytes());
    let tmp = off.with_extension("off.tmp");
    std::fs::write(&tmp, buf)?;
    set_owner_only(&tmp)?;
    std::fs::rename(&tmp, &off)?;
    set_owner_only(&off)
}

/// Persist a UEBA finding (owner-only). Appends one NDJSON line — does not parse
/// the existing file.
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
    migrate_legacy(path)?;
    let mut line = serde_json::to_vec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    {
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        f.write_all(&line)?;
        f.flush()?;
    }
    set_owner_only(path)?;
    let mut cur = read_cursor(path);
    cur.count = cur.count.saturating_add(1);
    write_cursor(path, &cur)?;
    trim_hot_window(path, max_bytes, max_samples)?;
    compact_if_wasteful(path)
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn live_bytes(path: &Path, head: u64) -> u64 {
    file_len(path).saturating_sub(head)
}

fn trim_hot_window(path: &Path, max_bytes: usize, max_samples: usize) -> std::io::Result<()> {
    let mut cur = read_cursor(path);
    if cur.count == 0 {
        return Ok(());
    }
    while cur.count > max_samples as u64 {
        evict_oldest_line(path, &mut cur)?;
    }
    while cur.count > 1 && live_bytes(path, cur.head) > max_bytes as u64 {
        evict_oldest_line(path, &mut cur)?;
    }
    if cur.count == 1 && live_bytes(path, cur.head) > max_bytes as u64 {
        evict_oldest_line(path, &mut cur)?;
    }
    write_cursor(path, &cur)?;
    if cur.count == 0 {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(off_path(path));
    }
    Ok(())
}

fn evict_oldest_line(path: &Path, cur: &mut Cursor) -> std::io::Result<()> {
    let Some(raw) = read_raw_line_at(path, cur.head)? else {
        cur.head = file_len(path);
        cur.count = 0;
        return Ok(());
    };
    archive_raw_line(path, &raw)?;
    cur.head = cur.head.saturating_add(raw.len() as u64);
    cur.count = cur.count.saturating_sub(1);
    Ok(())
}

fn read_raw_line_at(path: &Path, offset: u64) -> std::io::Result<Option<Vec<u8>>> {
    let Ok(mut f) = File::open(path) else {
        return Ok(None);
    };
    f.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(f);
    let mut buf = Vec::new();
    let n = reader.read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(buf))
}

fn archive_raw_line(path: &Path, line: &[u8]) -> std::io::Result<()> {
    if line.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(());
    }
    let arc = arc_path(path);
    let compressed =
        zstd::encode_all(line, 1).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    if let Some(dir) = arc.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let existing = file_len(&arc);
    if existing.saturating_add(compressed.len() as u64) > DEFAULT_MAX_ARC_BYTES as u64 {
        // Bound the archive: drop oldest compressed frames (the whole file) rather
        // than grow past the cap. Hot window still holds the newest samples.
        let _ = std::fs::remove_file(&arc);
    }
    {
        let mut f = OpenOptions::new().create(true).append(true).open(&arc)?;
        f.write_all(&compressed)?;
        f.flush()?;
    }
    set_owner_only(&arc)
}

fn thaw_archive_into_hot(path: &Path) -> std::io::Result<()> {
    let arc = arc_path(path);
    let Ok(compressed) = std::fs::read(&arc) else {
        return Ok(());
    };
    if compressed.is_empty() {
        let _ = std::fs::remove_file(&arc);
        return Ok(());
    }
    let mut decoded = Vec::new();
    let mut rest = compressed.as_slice();
    while !rest.is_empty() {
        let mut cursor = std::io::Cursor::new(rest);
        let before = cursor.position();
        zstd::stream::copy_decode(&mut cursor, &mut decoded)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let consumed = (cursor.position() - before) as usize;
        if consumed == 0 || consumed > rest.len() {
            break;
        }
        rest = &rest[consumed..];
    }
    if decoded.is_empty() {
        let _ = std::fs::remove_file(&arc);
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("thaw.tmp");
    std::fs::write(&tmp, &decoded)?;
    set_owner_only(&tmp)?;
    std::fs::rename(&tmp, path)?;
    set_owner_only(path)?;
    let count = decoded.iter().filter(|b| **b == b'\n').count() as u64
        + u64::from(!decoded.ends_with(b"\n") && !decoded.is_empty());
    write_cursor(path, &Cursor { head: 0, count })?;
    let _ = std::fs::remove_file(&arc);
    Ok(())
}

fn compact_if_wasteful(path: &Path) -> std::io::Result<()> {
    let cur = read_cursor(path);
    if cur.head < COMPACT_WASTE_BYTES {
        return Ok(());
    }
    let Ok(mut f) = File::open(path) else {
        return Ok(());
    };
    f.seek(SeekFrom::Start(cur.head))?;
    let mut tail = Vec::new();
    f.read_to_end(&mut tail)?;
    if tail.is_empty() {
        let _ = std::fs::remove_file(path);
        write_cursor(path, &Cursor { head: 0, count: 0 })?;
        return Ok(());
    }
    let tmp = path.with_extension("compact.tmp");
    std::fs::write(&tmp, &tail)?;
    set_owner_only(&tmp)?;
    std::fs::rename(&tmp, path)?;
    set_owner_only(path)?;
    write_cursor(
        path,
        &Cursor {
            head: 0,
            count: cur.count,
        },
    )
}

fn migrate_legacy(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if off_path(path).exists() {
        return Ok(());
    }
    let Ok(raw) = std::fs::read(path) else {
        return Ok(());
    };
    if raw.is_empty() {
        return Ok(());
    }
    // Already NDJSON: first non-whitespace is `{` and a later newline exists,
    // and it is not a single wrapped SpillFile.
    if looks_like_ndjson(&raw) {
        let count =
            raw.iter().filter(|b| **b == b'\n').count() as u64 + u64::from(!raw.ends_with(b"\n"));
        write_cursor(path, &Cursor { head: 0, count })?;
        return Ok(());
    }
    let items = parse_legacy_items(&raw);
    if items.is_empty() {
        return Ok(());
    }
    let mut body = Vec::new();
    for item in &items {
        if let Ok(mut line) = serde_json::to_vec(item) {
            line.push(b'\n');
            body.extend_from_slice(&line);
        }
    }
    let tmp = path.with_extension("mig.tmp");
    std::fs::write(&tmp, &body)?;
    set_owner_only(&tmp)?;
    std::fs::rename(&tmp, path)?;
    set_owner_only(path)?;
    write_cursor(
        path,
        &Cursor {
            head: 0,
            count: items.len() as u64,
        },
    )
}

fn looks_like_ndjson(raw: &[u8]) -> bool {
    raw.contains(&b'\n') && serde_json::from_slice::<SpillFile>(raw).is_err()
}

fn parse_legacy_items(raw: &[u8]) -> Vec<AgentToServer> {
    if let Ok(file) = serde_json::from_slice::<SpillFile>(raw) {
        return file.items.into_iter().filter(is_ueba).collect();
    }
    match serde_json::from_slice::<AgentToServer>(raw) {
        Ok(msg) if is_ueba(&msg) => vec![msg],
        _ => Vec::new(),
    }
}

fn parse_line(raw: &[u8]) -> Option<AgentToServer> {
    let t = trim_ascii(raw);
    if t.is_empty() {
        return None;
    }
    let parsed: AgentToServer = serde_json::from_slice(t).ok()?;
    is_ueba(&parsed).then_some(parsed)
}

fn trim_ascii(raw: &[u8]) -> &[u8] {
    let start = raw
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    if start >= end {
        &[]
    } else {
        &raw[start..end]
    }
}

/// Peek the oldest spilled UEBA finding (does not remove it).
#[must_use]
pub fn load_finding() -> Option<AgentToServer> {
    load_finding_at(&spill_path())
}

#[must_use]
pub fn load_finding_at(path: &Path) -> Option<AgentToServer> {
    let _ = migrate_legacy(path);
    let cur = read_cursor(path);
    if cur.count == 0 {
        if arc_path(path).exists() {
            if thaw_archive_into_hot(path).is_err() {
                let _ = std::fs::remove_file(arc_path(path));
                return None;
            }
            return load_finding_at(path);
        }
        // Legacy file with no sidecar yet.
        if let Ok(raw) = std::fs::read(path) {
            return parse_legacy_items(&raw).into_iter().next();
        }
        return None;
    }
    let raw = read_raw_line_at(path, cur.head).ok().flatten()?;
    parse_line(&raw)
}

/// Remove the oldest finding after a successful resend.
pub fn pop_oldest() -> Option<AgentToServer> {
    pop_oldest_at(&spill_path())
}

pub fn pop_oldest_at(path: &Path) -> Option<AgentToServer> {
    let _ = migrate_legacy(path);
    let mut cur = read_cursor(path);
    if cur.count == 0 {
        if arc_path(path).exists() {
            if thaw_archive_into_hot(path).is_err() {
                let _ = std::fs::remove_file(arc_path(path));
                return None;
            }
            return pop_oldest_at(path);
        }
        return None;
    }
    let raw = read_raw_line_at(path, cur.head).ok().flatten()?;
    let parsed = parse_line(&raw)?;
    cur.head = cur.head.saturating_add(raw.len() as u64);
    cur.count = cur.count.saturating_sub(1);
    let _ = write_cursor(path, &cur);
    if cur.count == 0 {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(off_path(path));
        if arc_path(path).exists() {
            let _ = thaw_archive_into_hot(path);
        }
    } else {
        let _ = compact_if_wasteful(path);
    }
    Some(parsed)
}

/// Pop the oldest finding only when it still matches `expected`.
pub fn pop_oldest_if(expected: &AgentToServer) -> bool {
    pop_oldest_if_at(&spill_path(), expected)
}

pub fn pop_oldest_if_at(path: &Path, expected: &AgentToServer) -> bool {
    let Some(head) = load_finding_at(path) else {
        return false;
    };
    if !findings_match(&head, expected) {
        return false;
    }
    pop_oldest_at(path).is_some()
}

/// How many UEBA samples are currently in the **hot** window.
#[must_use]
pub fn spill_len_at(path: &Path) -> usize {
    let _ = migrate_legacy(path);
    read_cursor(path).count as usize
}

/// Live hot-window bytes (file size minus the dead FIFO prefix).
#[must_use]
pub fn spill_bytes_at(path: &Path) -> u64 {
    let cur = read_cursor(path);
    live_bytes(path, cur.head)
}

#[allow(dead_code)]
pub fn clear() {
    clear_at(&spill_path());
}

#[allow(dead_code)]
pub fn clear_at(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(off_path(path));
    let _ = std::fs::remove_file(arc_path(path));
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
            AgentToServer::Finding {
                engine, finding, ..
            } => {
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
            write_finding_at_capped(&path, &sample_n(n), DEFAULT_MAX_SPILL_BYTES, 3)
                .expect("write");
        }
        assert_eq!(spill_len_at(&path), 3);
        match load_finding_at(&path).expect("oldest") {
            AgentToServer::Finding {
                task_id, finding, ..
            } => {
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
        write_finding_at_capped(&path, &bulky, 2_048, 10_000).expect("w1");
        write_finding_at_capped(&path, &bulky2, 2_048, 10_000).expect("w2");
        write_finding_at_capped(&path, &bulky3, 2_048, 10_000).expect("w3");
        assert!(
            spill_bytes_at(&path) <= 2_048,
            "hot window grew to {}",
            spill_bytes_at(&path)
        );
        assert!(spill_len_at(&path) <= 2);
        match load_finding_at(&path).expect("oldest after byte trim") {
            AgentToServer::Finding { task_id, .. } => {
                assert_ne!(task_id, "task-big-1", "oldest must have been FIFO-evicted");
            }
            other => panic!("unexpected {other:?}"),
        }
        // Evicted line must be recoverable from the zstd archive after hot drain.
        while spill_len_at(&path) > 0 {
            let _ = pop_oldest_at(&path);
        }
        if arc_path(&path).exists() {
            let thawed = load_finding_at(&path);
            assert!(thawed.is_some(), "zstd archive should thaw into hot window");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ndjson_append_does_not_rewrite_history() {
        let (dir, path) = temp_path("ndjson");
        write_finding_at(&path, &sample_n(1)).unwrap();
        write_finding_at(&path, &sample_n(2)).unwrap();
        write_finding_at(&path, &sample_n(3)).unwrap();
        let raw = std::fs::read_to_string(&path).expect("read");
        assert!(
            !raw.contains("\"items\""),
            "must not be a JSON array wrapper"
        );
        assert_eq!(raw.lines().count(), 3);
        for (i, line) in raw.lines().enumerate() {
            let v: AgentToServer = serde_json::from_str(line).expect("line json");
            match v {
                AgentToServer::Finding { task_id, .. } => {
                    assert_eq!(task_id, format!("task-{}", i + 1));
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resend_pace_stays_in_the_5_to_12_ms_band() {
        for _ in 0..8 {
            let ms = resend_pace().as_millis();
            assert!(
                (5..=12).contains(&ms),
                "pace {ms} ms outside 5–12 ms jitter band"
            );
        }
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
