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

fn is_web_parent(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    WEB_PARENTS.iter().any(|p| n.contains(p))
}

fn is_shell_child(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SHELL_CHILDREN.iter().any(|p| n == *p || n.ends_with(p))
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

async fn attempt_sigstop(pid: u32) -> String {
    #[cfg(unix)]
    {
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
    let auto_freeze = params
        .get("auto_freeze")
        .and_then(Value::as_bool)
        .unwrap_or(true);
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
                attempt_sigstop(anomaly.pid).await
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
}
