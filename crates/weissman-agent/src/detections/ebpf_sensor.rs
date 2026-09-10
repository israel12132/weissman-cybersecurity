//! Linux eBPF / tracing sensor — real attach when CAP_BPF+bpftrace exist.

use super::finding;
use serde_json::{json, Value};

pub async fn run(engine: &str, params: &Value) -> anyhow::Result<Vec<Value>> {
    let mut extras = serde_json::Map::new();
    extras.insert("os".into(), json!(std::env::consts::OS));

    #[cfg(target_os = "linux")]
    {
        let btf = tokio::fs::metadata("/sys/kernel/btf/vmlinux").await.is_ok();
        extras.insert("btf_vmlinux".into(), json!(btf));
        let bpf_fs = tokio::fs::metadata("/sys/fs/bpf").await.is_ok();
        extras.insert("bpffs".into(), json!(bpf_fs));

        let seconds = params
            .get("seconds")
            .and_then(Value::as_u64)
            .unwrap_or(2)
            .clamp(1, 8);
        let traced = tokio::time::timeout(
            std::time::Duration::from_secs(seconds + 1),
            async {
                tokio::process::Command::new("timeout")
                    .args([
                        &seconds.to_string(),
                        "bpftrace",
                        "-e",
                        "tracepoint:syscalls:sys_enter_execve { printf(\"%s\\n\", comm); }",
                    ])
                    .output()
                    .await
            },
        )
        .await;
        match traced {
            Ok(Ok(out)) if out.status.success() || !out.stdout.is_empty() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let lines = stdout.lines().filter(|l| !l.trim().is_empty()).count();
                extras.insert("execve_events".into(), json!(lines));
                    extras.insert("sensor".into(), json!("bpftrace"));
                    return Ok(vec![finding(
                    engine,
                    "eBPF execve trace completed",
                    if lines > 0 { "info" } else { "low" },
                    "T1059",
                    &format!(
                        "bpftrace sys_enter_execve ran for {seconds}s; {lines} comm samples. BTF={} bpffs={}.",
                        btf, bpf_fs
                    ),
                    extras,
                )]);
            }
            _ => {
                if btf {
                    return Ok(vec![finding(
                        engine,
                        "Kernel BTF present but bpftrace attach did not run",
                        "info",
                        "T1059",
                        "Install bpftrace and CAP_BPF/CAP_PERFMON to enable live syscall ingest. Chronos still uses process-delta polling until this sensor is privileged.",
                        extras,
                    )]);
                }
                return Ok(vec![finding(
                    engine,
                    "eBPF sensor unavailable on this host",
                    "info",
                    "T1059",
                    "No /sys/kernel/btf/vmlinux and bpftrace failed — not reporting fake syscall telemetry.",
                    extras,
                )]);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = params;
        Ok(vec![finding(
            engine,
            "eBPF sensor is Linux-only",
            "info",
            "T1059",
            "This host is not Linux; no syscall trace was invented.",
            extras,
        )])
    }
}
