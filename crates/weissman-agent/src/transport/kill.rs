//! Verify a signed kill-switch and latch it on disk.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

#[must_use]
pub fn latch_path() -> PathBuf {
    if let Some(p) = std::env::var_os("WEISSMAN_AGENT_KILL_FILE") {
        return PathBuf::from(p);
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("agent.killed")))
        .unwrap_or_else(|| PathBuf::from("/opt/weissman/agent.killed"))
}

#[must_use]
pub fn is_latched() -> bool {
    latch_path().exists()
}

pub fn latch(reason: &str) -> std::io::Result<()> {
    let path = latch_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, reason.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[must_use]
pub fn verify(
    stored_key_hex: &str,
    agent_id: &str,
    nonce: &str,
    issued_at_unix: i64,
    reason: &str,
    signature_hex: &str,
) -> bool {
    let Ok(key) = hex::decode(stored_key_hex.trim()) else {
        return false;
    };
    let Ok(expected) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(&key) else {
        return false;
    };
    let canonical = format!("weissman-kill-v1|{agent_id}|{nonce}|{issued_at_unix}|{reason}");
    mac.update(canonical.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

/// Debugger / ptrace self-check (Linux). True when something is attached.
#[must_use]
pub fn debugger_present() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("TracerPid:") {
                    let pid: i32 = rest.trim().parse().unwrap_or(0);
                    return pid != 0;
                }
            }
        }
    }
    false
}

pub fn protect_path(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_rejects_bad_sig() {
        assert!(!verify("aa", "agent", "n", 1, "r", "00"));
    }
}
