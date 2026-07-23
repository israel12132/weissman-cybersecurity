//! eBPF probe deployment via SSH. Runs a lightweight tracer on the remote host and streams events to runtime_traces API.

use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const SSH_TIMEOUT_SECS: u64 = 60;

/// SSH authentication for eBPF deploy.
#[derive(Clone)]
pub enum SshAuth {
    Key { key_path: std::path::PathBuf },
    Password(String),
}

/// Deploy and run eBPF tracer on host via SSH (system ssh). Runs bpftrace and streams each line to ingest_url.
pub async fn deploy_and_stream_ebpf(
    host: &str,
    port: u16,
    username: &str,
    auth: &SshAuth,
    client_id: &str,
    ingest_url: &str,
) -> Result<(), String> {
    let cmd = match auth {
        SshAuth::Key { key_path } => {
            let path = key_path.to_string_lossy();
            format!(
                "ssh -o StrictHostKeyChecking=no -o ConnectTimeout={} -i {} -p {} {}@{} 'bpftrace -e \"tracepoint:syscalls:sys_enter_openat {{ printf(\\\"%d\\n\\\", pid); }}\" 2>/dev/null || echo NO_BPFTRACE'",
                SSH_TIMEOUT_SECS, path, port, username, host
            )
        }
        SshAuth::Password(_) => {
            return Err("Password auth for eBPF deploy not supported (use key)".to_string());
        }
    };
    let mut child = Command::new("sh")
        .args(["-c", &cmd])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("No stdout")?;
    let mut lines = BufReader::new(stdout).lines();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    while let Ok(Some(line)) = lines.next_line().await {
        if line.is_empty() || line == "NO_BPFTRACE" {
            continue;
        }
        let payload_hash = format!("{:x}", md5_hash(line.as_bytes()));
        let _ = client
            .post(ingest_url)
            .json(&serde_json::json!({
                "client_id": client_id,
                "source_file": "kernel",
                "line_number": 0,
                "function_name": "sys_enter_openat",
                "payload_hash": payload_hash,
                "metadata": { "raw": line }
            }))
            .send()
            .await;
    }
    Ok(())
}

fn md5_hash(b: &[u8]) -> u128 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    h.finish().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_hash_is_deterministic() {
        assert_eq!(md5_hash(b"abc"), md5_hash(b"abc"));
        assert_eq!(md5_hash(b""), md5_hash(b""));
        assert_eq!(md5_hash(b"kernel-line"), md5_hash(b"kernel-line"));
    }

    #[test]
    fn md5_hash_varies_with_input() {
        assert_ne!(md5_hash(b"abc"), md5_hash(b"xyz"));
        assert_ne!(md5_hash(b"line-1"), md5_hash(b"line-2"));
        assert_ne!(md5_hash(b""), md5_hash(b"x"));
    }

    // Password auth returns early with an error before any process spawn / network IO.
    #[tokio::test]
    async fn password_auth_is_rejected_without_io() {
        let auth = SshAuth::Password("secret".to_string());
        let err = deploy_and_stream_ebpf("host", 22, "user", &auth, "cid", "http://ingest")
            .await
            .unwrap_err();
        assert_eq!(err, "Password auth for eBPF deploy not supported (use key)");
    }
}
