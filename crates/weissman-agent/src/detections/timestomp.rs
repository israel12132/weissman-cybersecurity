//! Timestomp heuristics from live filesystem metadata (mtime vs ctime, future timestamps).
//!
//! Compares modification time against metadata change time on high-value paths. A large gap
//! where ctime is newer than mtime often indicates backdated timestamps (T1070.006).

use super::finding;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MITRE: &str = "T1070.006";
const BACKDATE_THRESHOLD_SECS: u64 = 86_400; // 24h

fn scan_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if cfg!(target_os = "windows") {
        if let Ok(windir) = std::env::var("WINDIR") {
            paths.push(
                PathBuf::from(&windir)
                    .join("System32")
                    .join("drivers")
                    .join("etc")
                    .join("hosts"),
            );
            paths.push(
                PathBuf::from(&windir)
                    .join("System32")
                    .join("config")
                    .join("systemprofile"),
            );
        }
    } else {
        paths.push(PathBuf::from("/etc/passwd"));
        paths.push(PathBuf::from("/etc/shadow"));
        paths.push(PathBuf::from("/etc/hosts"));
        paths.push(PathBuf::from("/var/log/auth.log"));
        paths.push(PathBuf::from("/var/log/secure"));
        if let Ok(home) = std::env::var("HOME") {
            let home = PathBuf::from(home);
            paths.push(home.join(".bash_history"));
            paths.push(home.join(".ssh/authorized_keys"));
        }
    }
    paths
}

fn epoch_secs(t: SystemTime) -> Option<u64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn inspect_path(path: &Path) -> Option<(String, Map<String, Value>)> {
    let meta = std::fs::metadata(path).ok()?;
    let mut evidence = Map::new();
    evidence.insert("path".into(), json!(path.display().to_string()));

    let now = epoch_secs(SystemTime::now()).unwrap_or(0);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mtime = meta.mtime() as u64;
        let ctime = meta.ctime() as u64;
        evidence.insert("mtime_epoch".into(), json!(mtime));
        evidence.insert("ctime_epoch".into(), json!(ctime));

        if ctime > mtime && ctime.saturating_sub(mtime) >= BACKDATE_THRESHOLD_SECS {
            evidence.insert("indicator".into(), json!("mtime_older_than_ctime"));
            evidence.insert("delta_secs".into(), json!(ctime - mtime));
            return Some((
                format!("Timestomp indicator: mtime backdated on {}", path.display()),
                evidence,
            ));
        }
        if mtime > now.saturating_add(300) {
            evidence.insert("indicator".into(), json!("future_mtime"));
            return Some((
                format!("Future modification timestamp on {}", path.display()),
                evidence,
            ));
        }
    }

    #[cfg(windows)]
    {
        let modified = meta.modified().ok().and_then(epoch_secs);
        let created = meta.created().ok().and_then(epoch_secs);
        if let Some(m) = modified {
            evidence.insert("mtime_epoch".into(), json!(m));
        }
        if let Some(b) = created {
            evidence.insert("birthtime_epoch".into(), json!(b));
        }
        if let (Some(m), Some(b)) = (modified, created) {
            if m < b && b.saturating_sub(m) >= BACKDATE_THRESHOLD_SECS {
                evidence.insert("indicator".into(), json!("mtime_before_birth"));
                return Some((
                    format!(
                        "Timestomp indicator: mtime predates birth time on {}",
                        path.display()
                    ),
                    evidence,
                ));
            }
        }
        if let Some(m) = modified {
            if m > now.saturating_add(300) {
                evidence.insert("indicator".into(), json!("future_mtime"));
                return Some((
                    format!("Future modification timestamp on {}", path.display()),
                    evidence,
                ));
            }
        }
    }

    None
}

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    for path in scan_paths() {
        if let Some((title, evidence)) = inspect_path(&path) {
            findings.push(finding(
                engine,
                &title,
                "high",
                MITRE,
                "Filesystem metadata anomaly consistent with timestomping (T1070.006).",
                evidence,
            ));
        }
    }

    if findings.is_empty() {
        let mut ev = Map::new();
        ev.insert(
            "paths_scanned".into(),
            json!(scan_paths()
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()),
        );
        ev.insert(
            "note".into(),
            json!("No timestomp indicators in scanned paths; live stat() metadata compared."),
        );
        findings.push(finding(
            engine,
            "Timestomp scan complete — no indicators in scanned paths",
            "info",
            MITRE,
            "Scanned high-value paths using live filesystem metadata (mtime vs ctime). No backdating indicators detected.",
            ev,
        ));
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_paths_non_empty() {
        assert!(!scan_paths().is_empty());
    }
}
