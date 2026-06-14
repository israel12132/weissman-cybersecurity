//! Tamper-evident finding attestation.
//!
//! Every persisted finding is bound to a cryptographic receipt: an HMAC-SHA256 over
//! a canonical digest of its immutable fields (`finding_id, title, severity, target,
//! discovered_at`). The receipt is computed **at persist time** and stored with the
//! row. On read, the server recomputes the digest from the stored fields and verifies
//! it against the stored receipt — so any out-of-band tampering with a finding in the
//! database is detectable (`attestation_valid = false`). This gives Board / regulator /
//! court-grade, non-repudiable evidence that a finding has not been altered since it was
//! recorded — a guarantee competitors do not provide out of the box.
//!
//! Key: `WEISSMAN_ATTESTATION_KEY` (64 hex / 32 bytes) or, failing that, derived from the
//! managed `WEISSMAN_JWT_SECRET`. With no key (dev) attestation is skipped (returns None).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

const ATTEST_DOMAIN: &[u8] = b"weissman-finding-attestation-v1|";
pub const ATTEST_ALG: &str = "HMAC-SHA256";

fn attestation_key() -> Option<[u8; 32]> {
    static KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    *KEY.get_or_init(|| {
        if let Ok(raw) = std::env::var("WEISSMAN_ATTESTATION_KEY") {
            let t = raw.trim();
            if !t.is_empty() {
                match hex::decode(t) {
                    Ok(b) if b.len() == 32 => {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&b);
                        return Some(k);
                    }
                    _ => eprintln!(
                        "[Weissman][attestation] WEISSMAN_ATTESTATION_KEY must be 64 hex chars; ignoring"
                    ),
                }
            }
        }
        let js = std::env::var("WEISSMAN_JWT_SECRET").unwrap_or_default();
        if js.trim().len() < 16 {
            return None;
        }
        let mut h = Sha256::new();
        h.update(b"weissman-attestation-key-v1|");
        h.update(js.as_bytes());
        let d = h.finalize();
        let mut k = [0u8; 32];
        k.copy_from_slice(&d);
        Some(k)
    })
}

/// Canonical SHA-256 digest (hex) over a finding's immutable identifying fields.
#[must_use]
pub fn content_digest(
    finding_id: &str,
    title: &str,
    severity: &str,
    target: &str,
    discovered_at: &str,
) -> String {
    let mut h = Sha256::new();
    for part in [finding_id, title, severity, target, discovered_at] {
        h.update(part.trim().as_bytes());
        h.update(b"\x1e"); // record separator
    }
    hex::encode(h.finalize())
}

/// Produce an HMAC-SHA256 receipt (hex) over a content digest. `None` if no key.
#[must_use]
pub fn attest(digest_hex: &str) -> Option<String> {
    let key = attestation_key()?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).ok()?;
    mac.update(ATTEST_DOMAIN);
    mac.update(digest_hex.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Convenience: digest a finding then attest it. Returns `(digest_hex, receipt_hex)`.
#[must_use]
pub fn attest_finding(
    finding_id: &str,
    title: &str,
    severity: &str,
    target: &str,
    discovered_at: &str,
) -> Option<(String, String)> {
    let digest = content_digest(finding_id, title, severity, target, discovered_at);
    let receipt = attest(&digest)?;
    Some((digest, receipt))
}

/// Verify a receipt against a content digest in constant time.
#[must_use]
pub fn verify(digest_hex: &str, receipt_hex: &str) -> bool {
    let Some(key) = attestation_key() else {
        return false;
    };
    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(&key) else {
        return false;
    };
    mac.update(ATTEST_DOMAIN);
    mac.update(digest_hex.as_bytes());
    let expected = mac.finalize().into_bytes();
    crate::security_hardening::constant_time_hmac_hex_eq(&expected, receipt_hex)
}

/// Verify a finding's stored receipt by recomputing the digest from its fields.
#[must_use]
pub fn verify_finding(
    finding_id: &str,
    title: &str,
    severity: &str,
    target: &str,
    discovered_at: &str,
    receipt_hex: &str,
) -> bool {
    let digest = content_digest(finding_id, title, severity, target, discovered_at);
    verify(&digest, receipt_hex)
}

/// Whether attestation is active (a key is configured/derivable).
#[must_use]
pub fn is_enabled() -> bool {
    attestation_key().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ensure a deterministic key for tests regardless of env ordering.
    fn with_key<T>(f: impl FnOnce() -> T) -> T {
        // attestation_key caches; in CI WEISSMAN_JWT_SECRET may be unset. Set one
        // before first use within this test binary.
        if std::env::var("WEISSMAN_ATTESTATION_KEY").is_err()
            && std::env::var("WEISSMAN_JWT_SECRET").is_err()
        {
            std::env::set_var(
                "WEISSMAN_JWT_SECRET",
                "test-attestation-secret-key-1234567890",
            );
        }
        f()
    }

    #[test]
    fn digest_is_deterministic_and_field_sensitive() {
        let d1 = content_digest("eng-abc", "SQLi", "high", "https://x", "2026-01-01");
        let d2 = content_digest("eng-abc", "SQLi", "high", "https://x", "2026-01-01");
        let d3 = content_digest("eng-abc", "SQLi", "critical", "https://x", "2026-01-01");
        assert_eq!(d1, d2);
        assert_ne!(d1, d3, "severity change must change the digest");
    }

    #[test]
    fn attest_then_verify_roundtrips_and_detects_tampering() {
        with_key(|| {
            let (digest, receipt) =
                attest_finding("eng-abc", "SQLi", "high", "https://x", "2026-01-01")
                    .expect("attest with key");
            assert!(verify(&digest, &receipt), "valid receipt must verify");
            assert!(verify_finding(
                "eng-abc",
                "SQLi",
                "high",
                "https://x",
                "2026-01-01",
                &receipt
            ));
            // Tamper: severity flipped in the DB → digest changes → receipt fails.
            assert!(
                !verify_finding(
                    "eng-abc",
                    "SQLi",
                    "low",
                    "https://x",
                    "2026-01-01",
                    &receipt
                ),
                "tampered finding must fail attestation"
            );
            // Garbage receipt fails.
            assert!(!verify(&digest, "deadbeef"));
        });
    }
}
