//! Signed remote kill-switch for endpoint agents.
//!
//! The HMAC key is derived per agent (`HMAC(platform_secret, agent_id)`) so the
//! agent can verify without holding the platform JWT. The derived key is sent
//! once at enrollment and persisted on the endpoint.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn platform_secret() -> Vec<u8> {
    std::env::var("WEISSMAN_AGENT_KILL_SECRET")
        .ok()
        .filter(|s| s.trim().len() >= 16)
        .or_else(|| std::env::var("WEISSMAN_JWT_SECRET").ok())
        .unwrap_or_default()
        .into_bytes()
}

/// Per-agent HMAC key (hex). Sent at enrollment; server can always re-derive it.
#[must_use]
pub fn derived_kill_key(agent_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(&platform_secret()).unwrap_or_else(|_| {
        HmacSha256::new_from_slice(b"weissman-agent-kill-unconfigured").expect("hmac")
    });
    mac.update(agent_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[must_use]
pub fn canonical(agent_id: &str, nonce: &str, issued_at_unix: i64, reason: &str) -> String {
    format!("weissman-kill-v1|{agent_id}|{nonce}|{issued_at_unix}|{reason}")
}

#[must_use]
pub fn sign(agent_id: &str, nonce: &str, issued_at_unix: i64, reason: &str) -> String {
    let key = hex::decode(derived_kill_key(agent_id)).unwrap_or_default();
    let mut mac = HmacSha256::new_from_slice(&key).unwrap_or_else(|_| {
        HmacSha256::new_from_slice(b"weissman-agent-kill-unconfigured").expect("hmac")
    });
    mac.update(canonical(agent_id, nonce, issued_at_unix, reason).as_bytes());
    hex::encode(mac.finalize().into_bytes())
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
    mac.update(canonical(agent_id, nonce, issued_at_unix, reason).as_bytes());
    mac.verify_slice(&expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let agent = "11111111-2222-3333-4444-555555555555";
        let key = derived_kill_key(agent);
        let sig = sign(agent, "n1", 1_700_000_000, "compromise");
        assert!(verify(&key, agent, "n1", 1_700_000_000, "compromise", &sig));
        assert!(!verify(&key, agent, "n1", 1_700_000_000, "other", &sig));
    }
}
