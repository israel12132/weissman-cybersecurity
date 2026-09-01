//! Tenant-derived HMAC-SHA256 over the compact UEBA snapshot.
//!
//! The server signs Welcome / UebaBaseline with a key derived from the vault
//! for `(tenant_id, agent_id)`. The agent is given that derived key at
//! enrollment (`ueba_mac_key`) and refuses to install an unsigned or
//! mismatched snapshot — otherwise an on-host attacker can inflate `stddev`
//! and blind the edge gate.

use crate::protocol::UebaCompactSnapshot;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const DOMAIN: &[u8] = b"weissman-ueba-snapshot-v1\0";

/// Canonical encoding of the snapshot **excluding** `mac`.
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

#[must_use]
pub fn sign_with_key(s: &UebaCompactSnapshot, key: &[u8]) -> Option<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).ok()?;
    mac.update(&canonical_bytes(s));
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Constant-time verify. Empty key or empty/missing mac is a hard fail.
#[must_use]
pub fn verify(s: &UebaCompactSnapshot, key_hex: &str) -> bool {
    let key_hex = key_hex.trim();
    if key_hex.is_empty() || s.mac.trim().is_empty() {
        return false;
    }
    let Ok(key) = hex::decode(key_hex) else {
        return false;
    };
    if key.len() != 32 {
        return false;
    }
    let Some(expected) = sign_with_key(s, &key) else {
        return false;
    };
    // Lengths are equal (both 64 hex chars); compare decoded MACs via HMAC verify.
    let Ok(presented) = hex::decode(s.mac.trim()) else {
        return false;
    };
    let Ok(want) = hex::decode(expected) else {
        return false;
    };
    if presented.len() != want.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    presented.ct_eq(&want).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::UebaCompactMetric;

    fn snap() -> UebaCompactSnapshot {
        UebaCompactSnapshot {
            hour_of_week: 12,
            z_upload_threshold: 2.0,
            min_n: 7,
            source: "hour_of_week".into(),
            metrics: vec![UebaCompactMetric {
                name: "process_count".into(),
                mean: 80.0,
                stddev: 2.0,
                n: 4,
            }],
            learned_processes: vec!["sshd".into()],
            mac: String::new(),
        }
    }

    #[test]
    fn round_trip_mac() {
        let key = [0x11u8; 32];
        let mut s = snap();
        s.mac = sign_with_key(&s, &key).unwrap();
        assert!(verify(&s, &hex::encode(key)));
    }

    #[test]
    fn poisoned_stddev_fails() {
        let key = [0x11u8; 32];
        let mut s = snap();
        s.mac = sign_with_key(&s, &key).unwrap();
        s.metrics[0].stddev = 1_000_000.0;
        assert!(!verify(&s, &hex::encode(key)));
    }

    #[test]
    fn missing_mac_or_key_fails() {
        let s = snap();
        assert!(!verify(&s, &hex::encode([0x11u8; 32])));
        let mut signed = snap();
        signed.mac = sign_with_key(&signed, &[0x11u8; 32]).unwrap();
        assert!(!verify(&signed, ""));
    }
}
