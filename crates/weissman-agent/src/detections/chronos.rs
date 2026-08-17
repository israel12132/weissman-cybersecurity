//! CHRONOS endpoint monitor — 5ms process-delta ring buffer with autonomous SIGSTOP on shell spawn.

use super::finding;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use sysinfo::{ProcessRefreshKind, System};

#[derive(Debug, Clone, serde::Serialize)]
struct ProcessSnap {
    pid: u32,
    name: String,
    parent_pid: Option<u32>,
    exe: String,
}

const WEB_PARENTS: &[&str] = &[
    "nginx", "apache", "httpd", "node", "php-fpm", "gunicorn", "caddy", "envoy",
];
const SHELL_CHILDREN: &[&str] = &["sh", "bash", "dash", "zsh", "cmd", "powershell", "pwsh"];

/// Exact basename match, case-insensitive.
///
/// These were substring (`contains`) and suffix (`ends_with`) matches, which is far too loose for
/// a check whose response is to freeze the process:
///
///   "node_exporter".contains("node")  -> true   (this deployment runs node_exporter)
///   "ssh".ends_with("sh")             -> true
///
/// so a monitoring agent exec'ing `ssh` was classified as "shell spawned by a web server" and
/// SIGSTOPped. Nothing ever sends SIGCONT, so the backup or deploy job it belonged to hangs
/// forever. An exact basename comparison still catches the real pattern (nginx spawning bash)
/// without inventing it out of unrelated names.
fn name_matches(name: &str, list: &[&str]) -> bool {
    let n = name.trim().to_ascii_lowercase();
    // Compare the basename: sysinfo may report a path on some platforms.
    let base = n.rsplit(['/', '\\']).next().unwrap_or(&n);
    // Tolerate a Windows .exe suffix, which is part of the name rather than a different program.
    let base = base.strip_suffix(".exe").unwrap_or(base);
    list.iter().any(|p| base == *p)
}

fn is_web_parent(name: &str) -> bool {
    name_matches(name, WEB_PARENTS)
}

fn is_shell_child(name: &str) -> bool {
    name_matches(name, SHELL_CHILDREN)
}

fn capture_snapshot() -> HashMap<u32, ProcessSnap> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    let mut map = HashMap::new();
    for (pid, proc) in sys.processes() {
        let pid_u = usize::from(*pid) as u32;
        let parent = proc.parent().map(|p| usize::from(p) as u32);
        map.insert(
            pid_u,
            ProcessSnap {
                pid: pid_u,
                name: proc.name().to_string(),
                parent_pid: parent,
                exe: proc
                    .exe()
                    .map(|x| x.display().to_string())
                    .unwrap_or_default(),
            },
        );
    }
    map
}

fn detect_shell_spawn(
    prev: &HashMap<u32, ProcessSnap>,
    curr: &HashMap<u32, ProcessSnap>,
) -> Option<ProcessSnap> {
    for (pid, snap) in curr {
        if prev.contains_key(pid) {
            continue;
        }
        if !is_shell_child(&snap.name) {
            continue;
        }
        if let Some(ppid) = snap.parent_pid {
            if let Some(parent) = curr.get(&ppid) {
                if is_web_parent(&parent.name) {
                    return Some(snap.clone());
                }
            }
        }
    }
    None
}

/// Confirm the pid still refers to the process we decided to freeze.
///
/// The decision is made from a snapshot taken up to `sample_interval_ms` earlier. Linux recycles
/// pids, so without this the SIGSTOP could land on a completely unrelated process that happened
/// to inherit the number — freezing something nobody chose, with no record of what it was.
#[cfg(target_os = "linux")]
fn pid_still_named(pid: u32, expected_name: &str) -> bool {
    let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else {
        return false;
    };
    let actual = comm.trim().to_ascii_lowercase();
    let expected = expected_name.trim().to_ascii_lowercase();
    // /proc/<pid>/comm is truncated to 15 chars, so compare on that prefix.
    let n = actual.len().min(expected.len()).min(15);
    n > 0 && actual[..n] == expected[..n]
}

#[cfg(not(target_os = "linux"))]
fn pid_still_named(_pid: u32, _expected_name: &str) -> bool {
    // No cheap identity re-check available; the caller treats this as "do not signal".
    false
}

async fn attempt_sigstop(pid: u32, expected_name: &str) -> String {
    #[cfg(unix)]
    {
        if !pid_still_named(pid, expected_name) {
            return format!(
                "SIGSTOP skipped pid {pid}: no longer running as '{expected_name}' (pid reused or exited)"
            );
        }
        let out = tokio::process::Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .output()
            .await;
        match out {
            Ok(o) if o.status.success() => format!("SIGSTOP pid {pid}"),
            Ok(o) => format!(
                "SIGSTOP failed pid {pid}: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => format!("SIGSTOP error pid {pid}: {e}"),
        }
    }
    #[cfg(not(unix))]
    {
        format!("SIGSTOP unavailable on this platform (pid {pid})")
    }
}

pub async fn run(engine: &str, params: &Value) -> anyhow::Result<Vec<Value>> {
    let sample_ms = params
        .get("sample_interval_ms")
        .and_then(Value::as_u64)
        .unwrap_or(5)
        .max(1);
    let window_ms = params
        .get("observation_window_ms")
        .and_then(Value::as_u64)
        .unwrap_or(5000)
        .max(sample_ms);
    // Opt-IN, not opt-out. This autonomously freezes a process on a customer's endpoint with
    // no human in the loop and nothing that ever sends SIGCONT; defaulting that to on meant one
    // false positive hung a production job indefinitely. Detection still runs and still reports;
    // only the response is gated.
    let auto_freeze = params
        .get("auto_freeze")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let max_samples = ((window_ms / sample_ms) as usize).clamp(10, 2000);

    let mut ring: Vec<HashMap<u32, ProcessSnap>> = Vec::with_capacity(max_samples);
    let start = Instant::now();
    let mut prev = capture_snapshot();
    ring.push(prev.clone());

    while start.elapsed() < Duration::from_millis(window_ms) {
        tokio::time::sleep(Duration::from_millis(sample_ms)).await;
        let curr = capture_snapshot();
        if let Some(anomaly) = detect_shell_spawn(&prev, &curr) {
            let action = if auto_freeze {
                attempt_sigstop(anomaly.pid, &anomaly.name).await
            } else {
                "freeze_disabled".to_string()
            };
            let ring_tail: Vec<Value> = ring
                .iter()
                .rev()
                .take(20)
                .map(|snap| {
                    json!(snap
                        .values()
                        .take(8)
                        .map(|p| json!({"pid": p.pid, "name": p.name, "parent": p.parent_pid}))
                        .collect::<Vec<_>>())
                })
                .collect();

            let mut extras = serde_json::Map::new();
            extras.insert("pid".into(), json!(anomaly.pid));
            extras.insert("parent_pid".into(), json!(anomaly.parent_pid));
            extras.insert("process_name".into(), json!(anomaly.name));
            extras.insert("exe".into(), json!(anomaly.exe));
            extras.insert("action_taken".into(), json!(action));
            extras.insert("sample_interval_ms".into(), json!(sample_ms));
            extras.insert("observation_window_ms".into(), json!(window_ms));
            extras.insert("delta_ring_tail".into(), json!(ring_tail));
            extras.insert(
                "syscall_hint".into(),
                json!("execve — web parent spawned shell child"),
            );

            return Ok(vec![finding(
                engine,
                &format!(
                    "CHRONOS freeze — {} spawned from web parent (pid {})",
                    anomaly.name, anomaly.pid
                ),
                "critical",
                "T1059",
                "Process-delta ring buffer detected shell spawn from web server parent; autonomous SIGSTOP applied.",
                extras,
            )]);
        }
        ring.push(curr.clone());
        if ring.len() > max_samples {
            ring.remove(0);
        }
        prev = curr;
    }

    let mut extras = serde_json::Map::new();
    extras.insert("samples".into(), json!(ring.len()));
    extras.insert("sample_interval_ms".into(), json!(sample_ms));
    extras.insert("observation_window_ms".into(), json!(window_ms));
    extras.insert("process_count".into(), json!(prev.len()));
    Ok(vec![finding(
        engine,
        &format!(
            "CHRONOS delta monitor — {} samples @ {}ms, no shell spawn",
            ring.len(),
            sample_ms
        ),
        "info",
        "T1057",
        "Live process-delta ring buffer completed observation window without shell-spawn anomaly.",
        extras,
    )])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nginx_sh_spawn() {
        let mut prev = HashMap::new();
        prev.insert(
            100,
            ProcessSnap {
                pid: 100,
                name: "nginx".into(),
                parent_pid: Some(1),
                exe: "/usr/sbin/nginx".into(),
            },
        );
        let mut curr = prev.clone();
        curr.insert(
            200,
            ProcessSnap {
                pid: 200,
                name: "sh".into(),
                parent_pid: Some(100),
                exe: "/bin/sh".into(),
            },
        );
        let a = detect_shell_spawn(&prev, &curr);
        assert!(a.is_some());
        assert_eq!(a.unwrap().name, "sh");
    }

    /// The exact cases that made CHRONOS freeze innocent processes.
    #[test]
    fn matching_is_exact_basename_not_substring() {
        // The two real-world false positives from the audit. This deployment runs node_exporter.
        assert!(
            !is_web_parent("node_exporter"),
            "substring match on 'node' froze node_exporter's children"
        );
        assert!(
            !is_shell_child("ssh"),
            "'ssh'.ends_with(\"sh\") classified ssh as a shell"
        );
        assert!(!is_web_parent("nodemon"));
        assert!(!is_shell_child("flush"));
        assert!(!is_shell_child("ash-utils"));

        // The genuine pattern must still be caught, or the fix is just a mute button.
        assert!(is_web_parent("nginx"));
        assert!(is_web_parent("NGINX"));
        assert!(is_web_parent("node"));
        assert!(is_web_parent("php-fpm"));
        assert!(is_shell_child("bash"));
        assert!(is_shell_child("sh"));
        assert!(
            is_shell_child("powershell.exe"),
            "a .exe suffix is part of the name"
        );
        assert!(
            is_web_parent("/usr/sbin/nginx"),
            "a full path must match on its basename"
        );
    }

    /// A stale pid must not be signalled.
    #[cfg(target_os = "linux")]
    #[test]
    fn pid_identity_is_revalidated_before_signalling() {
        let me = std::process::id();
        let my_name = std::fs::read_to_string(format!("/proc/{me}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        assert!(pid_still_named(me, &my_name), "our own pid must validate");
        assert!(
            !pid_still_named(me, "definitely-not-this-process"),
            "a mismatched name must not validate — this is what stops a recycled pid being frozen"
        );
        // A pid that cannot exist.
        assert!(!pid_still_named(u32::MAX, "anything"));
    }
}
