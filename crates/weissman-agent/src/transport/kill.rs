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

/// Minimum decoded key length (bytes) that counts as a *provisioned* kill key.
///
/// The server derives the key as `hex(HMAC-SHA256(platform_secret, agent_id))`, which is always
/// 32 bytes / 64 hex chars (see `fingerprint_engine/src/agent_kill.rs::derived_kill_key`). An
/// empty or short value therefore never denotes a legitimate key — it means the enrollment carried
/// no key (older/downgraded server, or a stripped `EnrollResponse`). Verifying a kill-switch
/// against an empty (i.e. publicly-known) HMAC key authenticates nothing, so we reject it before
/// computing any MAC and fail closed.
pub const MIN_KILL_KEY_BYTES: usize = 32;

/// True only when `stored_key_hex` decodes to a usable HMAC key of at least
/// [`MIN_KILL_KEY_BYTES`] bytes. An empty string decodes to zero bytes and is *not* provisioned.
#[must_use]
pub fn key_is_provisioned(stored_key_hex: &str) -> bool {
    match hex::decode(stored_key_hex.trim()) {
        Ok(key) => key.len() >= MIN_KILL_KEY_BYTES,
        Err(_) => false,
    }
}

/// Lab-only opt-in that honours an *unsigned* kill-switch when no verification key is provisioned.
///
/// Off by default. Setting it in production re-opens the remote-kill denial-of-service this guard
/// closes, so it exists solely for lab/test rigs that never receive a derived key.
#[must_use]
pub fn allow_unsigned() -> bool {
    matches!(
        std::env::var("WEISSMAN_AGENT_ALLOW_UNSIGNED").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

/// Verify a signed kill-switch. **Fail-closed.**
///
/// Returns `true` only when a real key is provisioned (>= [`MIN_KILL_KEY_BYTES`] bytes) *and* the
/// HMAC-SHA256 over the canonical string equals `signature_hex`. An empty or short key is rejected
/// before any MAC is computed, so a kill-switch can never be accepted against a publicly-known
/// (empty) key — closing the prior fail-open where an older/downgraded or compromised server could
/// forge a valid empty-key HMAC and force the agent to latch and exit.
///
/// The signature comparison uses `verify_slice`, which is constant-time.
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
    // Fail-closed: an absent/short key is treated as "no key provisioned", never as a valid key.
    if key.len() < MIN_KILL_KEY_BYTES {
        return false;
    }
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

    /// Sign a canonical kill message with `key` exactly as the server does
    /// (`fingerprint_engine/src/agent_kill.rs::sign`). Used to build both legitimately-signed
    /// messages and the attacker-forgeable empty-key message.
    fn sign_with(
        key: &[u8],
        agent_id: &str,
        nonce: &str,
        issued_at_unix: i64,
        reason: &str,
    ) -> String {
        let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
        let canonical = format!("weissman-kill-v1|{agent_id}|{nonce}|{issued_at_unix}|{reason}");
        mac.update(canonical.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn empty_key_rejects_even_a_matching_empty_key_hmac() {
        // Older/downgraded server sends no key. An attacker who knows the key is empty can compute
        // a "valid" empty-key HMAC — verify() must still refuse (fail-closed).
        let forged = sign_with(&[], "agent", "n", 1, "r");
        assert!(!key_is_provisioned(""));
        assert!(!verify("", "agent", "n", 1, "r", &forged));
    }

    #[test]
    fn short_key_rejects() {
        // A sub-32-byte value is not a real derived key.
        let forged = sign_with(&[0xaa], "agent", "n", 1, "r");
        assert!(!key_is_provisioned("aa"));
        assert!(!verify("aa", "agent", "n", 1, "r", &forged));
    }

    #[test]
    fn bad_signature_with_real_key_rejects() {
        let key = [7u8; MIN_KILL_KEY_BYTES];
        let key_hex = hex::encode(key);
        assert!(key_is_provisioned(&key_hex));
        // Signature over a DIFFERENT reason must not verify for "compromise".
        let wrong = sign_with(&key, "agent", "n", 1, "other-reason");
        assert!(!verify(&key_hex, "agent", "n", 1, "compromise", &wrong));
        // Absent and malformed signatures are also rejected.
        assert!(!verify(&key_hex, "agent", "n", 1, "compromise", ""));
        assert!(!verify(&key_hex, "agent", "n", 1, "compromise", "zz"));
    }

    #[test]
    fn good_signature_with_real_key_accepts() {
        let key = [7u8; MIN_KILL_KEY_BYTES];
        let key_hex = hex::encode(key);
        let sig = sign_with(&key, "agent-1", "nonce-xyz", 1_700_000_000, "compromise");
        assert!(verify(
            &key_hex,
            "agent-1",
            "nonce-xyz",
            1_700_000_000,
            "compromise",
            &sig
        ));
    }
}
