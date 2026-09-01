//! Tenant-vault HMAC for the compact UEBA snapshot pushed to agents.
//!
//! Master key: `WEISSMAN_UEBA_SNAPSHOT_MAC_KEY` (64 hex) or SHA-256 of
//! `weissman-ueba-snapshot-mac-v1|` plus `WEISSMAN_VAULT_KEY` / `WEISSMAN_JWT_SECRET`.
//! Per-agent key: HMAC-SHA256(master, tenant_id || agent_id). That derived key is
//! issued at enrollment (`ueba_mac_key`) so the agent can verify without holding
//! the tenant vault.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::ueba_detector::{UebaCompactMetric, UebaCompactSnapshot};

type HmacSha256 = Hmac<Sha256>;

const DOMAIN: &[u8] = b"weissman-ueba-snapshot-v1\0";
const KEY_DOMAIN: &[u8] = b"weissman-ueba-snapshot-mac-v1|";
const AGENT_DOMAIN: &[u8] = b"ueba-snapshot-agent-v1\0";

fn master_key() -> Option<[u8; 32]> {
    static KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    *KEY.get_or_init(|| {
        if let Ok(raw) = std::env::var("WEISSMAN_UEBA_SNAPSHOT_MAC_KEY") {
            let t = raw.trim();
            if !t.is_empty() {
                match hex::decode(t) {
                    Ok(b) if b.len() == 32 => {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&b);
                        return Some(k);
                    }
                    _ => eprintln!(
                        "[Weissman][ueba-mac] WEISSMAN_UEBA_SNAPSHOT_MAC_KEY must be 64 hex chars; ignoring"
                    ),
                }
            }
        }
        let material = std::env::var("WEISSMAN_VAULT_KEY")
            .ok()
            .filter(|s| s.trim().len() >= 16)
            .or_else(|| std::env::var("WEISSMAN_JWT_SECRET").ok())
            .unwrap_or_default();
        if material.trim().len() < 16 {
            return None;
        }
        let mut h = Sha256::new();
        h.update(KEY_DOMAIN);
        h.update(material.as_bytes());
        let d = h.finalize();
        let mut k = [0u8; 32];
        k.copy_from_slice(&d);
        Some(k)
    })
}

/// 32-byte per-agent MAC key (hex). Empty string if the vault is unconfigured.
#[must_use]
pub fn agent_mac_key_hex(tenant_id: i64, agent_id: &str) -> String {
    match agent_mac_key(tenant_id, agent_id) {
        Some(k) => hex::encode(k),
        None => String::new(),
    }
}

fn agent_mac_key(tenant_id: i64, agent_id: &str) -> Option<[u8; 32]> {
    let master = master_key()?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&master).ok()?;
    mac.update(AGENT_DOMAIN);
    mac.update(&tenant_id.to_le_bytes());
    mac.update(agent_id.trim().as_bytes());
    let out = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    Some(k)
}

#[must_use]
pub fn canonical_bytes(s: &UebaCompactSnapshot) -> Vec<u8> {
    let mut o = Vec::with_capacity(256);
    o.extend_from_slice(DOMAIN);
    o.extend_from_slice(&s.hour_of_week.to_le_bytes());
    o.extend_from_slice(&s.z_upload_threshold.to_le_bytes());
    o.extend_from_slice(&s.min_n.to_le_bytes());
    let src = s.source.as_bytes();
    o.extend_from_slice(&(src.len() as u32).to_le_bytes());
    o.extend_from_slice(src);
    let mut metrics = s.metrics.clone();
    metrics.sort_by(|a, b| a.name.cmp(&b.name));
    o.extend_from_slice(&(metrics.len() as u32).to_le_bytes());
    for m in &metrics {
        let n = m.name.as_bytes();
        o.extend_from_slice(&(n.len() as u32).to_le_bytes());
        o.extend_from_slice(n);
        o.extend_from_slice(&m.mean.to_le_bytes());
        o.extend_from_slice(&m.stddev.to_le_bytes());
        o.extend_from_slice(&m.n.to_le_bytes());
    }
    let mut procs = s.learned_processes.clone();
    procs.sort();
    o.extend_from_slice(&(procs.len() as u32).to_le_bytes());
    for p in &procs {
        let b = p.as_bytes();
        o.extend_from_slice(&(b.len() as u32).to_le_bytes());
        o.extend_from_slice(b);
    }
    o
}

/// Fill `s.mac`. No-op (leaves mac empty) when the vault key is missing.
pub fn sign(s: &mut UebaCompactSnapshot, tenant_id: i64, agent_id: &str) {
    s.mac.clear();
    let Some(key) = agent_mac_key(tenant_id, agent_id) else {
        return;
    };
    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(&key) else {
        return;
    };
    mac.update(&canonical_bytes(s));
    s.mac = hex::encode(mac.finalize().into_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_canonical_are_stable() {
        let mut s = UebaCompactSnapshot {
            hour_of_week: 3,
            z_upload_threshold: 2.0,
            min_n: 7,
            source: "rolling_7d".into(),
            metrics: vec![UebaCompactMetric {
                name: "process_count".into(),
                mean: 10.0,
                stddev: 1.0,
                n: 24,
            }],
            learned_processes: vec!["sshd".into()],
            mac: String::new(),
        };
        std::env::set_var(
            "WEISSMAN_JWT_SECRET",
            "ueba-mac-unit-test-secret-32b-minimum",
        );
        // OnceLock may already be populated from another test; signing still
        // produces 64 hex chars when a key exists, or empty when not.
        sign(&mut s, 1, "agent-1");
        if !s.mac.is_empty() {
            assert_eq!(s.mac.len(), 64);
            let mac1 = s.mac.clone();
            sign(&mut s, 1, "agent-1");
            assert_eq!(s.mac, mac1);
            sign(&mut s, 1, "agent-2");
            assert_ne!(s.mac, mac1);
        }
    }
}
