//! Signed heal receipts: tamper-evident proof that a fix was really verified in the sandbox.
//!
//! Reuses the platform attestation key/HMAC (`finding_attestation::attest`/`verify`) and hashing
//! (`crypto_engine::sha256_hex`). Domain separation from finding attestation is achieved by baking
//! a `weissman-heal-attestation-v1|` prefix into the digested content, so a heal receipt and a
//! finding receipt can never collide. In dev (no attestation key) signing returns `None` and the
//! receipt is simply omitted — nothing is faked.

use crate::crypto_engine::sha256_hex;
use crate::verification_sandbox::VerificationResult;

const HEAL_DOMAIN: &str = "weissman-heal-attestation-v1|";
const RS: char = '\u{1e}'; // ASCII record separator

/// A signed heal receipt: the content digest and its HMAC receipt (both hex).
#[derive(Debug, Clone)]
pub struct HealReceipt {
    pub digest: String,
    pub receipt: String,
}

/// Deterministic content digest over the heal proof fields. Pure — no key required.
#[must_use]
pub fn heal_digest(
    finding_id: &str,
    verdict: &str,
    baseline_status: u16,
    after_status: u16,
    poc_curl: &str,
    changed_files: &[(String, String)],
    ts: i64,
) -> String {
    let exploit_hash = sha256_hex(poc_curl.as_bytes());
    // Order-independent hash of the applied files (path + content).
    let mut items: Vec<String> = changed_files
        .iter()
        .map(|(p, c)| format!("{p}\n{c}"))
        .collect();
    items.sort();
    let files_hash = sha256_hex(items.join(&RS.to_string()).as_bytes());
    let canonical = format!(
        "{HEAL_DOMAIN}{finding_id}{RS}{verdict}{RS}{baseline_status}{RS}{after_status}{RS}{exploit_hash}{RS}{files_hash}{RS}{ts}"
    );
    sha256_hex(canonical.as_bytes())
}

/// Sign a heal proof. Returns `None` when attestation is disabled (dev / no key).
#[must_use]
pub fn sign_heal(
    finding_id: &str,
    verdict: &str,
    baseline_status: u16,
    after_status: u16,
    poc_curl: &str,
    changed_files: &[(String, String)],
    ts: i64,
) -> Option<HealReceipt> {
    let digest = heal_digest(
        finding_id,
        verdict,
        baseline_status,
        after_status,
        poc_curl,
        changed_files,
        ts,
    );
    let receipt = crate::finding_attestation::attest(&digest)?;
    Some(HealReceipt { digest, receipt })
}

/// Convenience: sign directly from a `VerificationResult`.
#[must_use]
pub fn sign_from_result(
    finding_id: &str,
    poc_curl: &str,
    vr: &VerificationResult,
    ts: i64,
) -> Option<HealReceipt> {
    sign_heal(
        finding_id,
        vr.verdict.as_str(),
        vr.baseline_status,
        vr.after_patch_status,
        poc_curl,
        &vr.changed_files,
        ts,
    )
}

/// Verify a heal receipt against recomputed fields (constant-time via `finding_attestation::verify`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_heal(
    finding_id: &str,
    verdict: &str,
    baseline_status: u16,
    after_status: u16,
    poc_curl: &str,
    changed_files: &[(String, String)],
    ts: i64,
    receipt_hex: &str,
) -> bool {
    let digest = heal_digest(
        finding_id,
        verdict,
        baseline_status,
        after_status,
        poc_curl,
        changed_files,
        ts,
    );
    crate::finding_attestation::verify(&digest, receipt_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<(String, String)> {
        vec![("app.js".into(), "safe\n".into())]
    }

    #[test]
    fn digest_is_deterministic_and_order_independent() {
        let a = heal_digest("F1", "fixed", 200, 403, "curl x", &files(), 100);
        let b = heal_digest("F1", "fixed", 200, 403, "curl x", &files(), 100);
        assert_eq!(a, b);
        // order of changed files must not matter
        let two_a = vec![("a".to_string(), "1".to_string()), ("b".to_string(), "2".to_string())];
        let two_b = vec![("b".to_string(), "2".to_string()), ("a".to_string(), "1".to_string())];
        assert_eq!(
            heal_digest("F", "fixed", 200, 403, "p", &two_a, 1),
            heal_digest("F", "fixed", 200, 403, "p", &two_b, 1)
        );
    }

    #[test]
    fn digest_changes_when_any_field_changes() {
        let base = heal_digest("F1", "fixed", 200, 403, "curl x", &files(), 100);
        assert_ne!(base, heal_digest("F2", "fixed", 200, 403, "curl x", &files(), 100));
        assert_ne!(base, heal_digest("F1", "broke_app", 200, 403, "curl x", &files(), 100));
        assert_ne!(base, heal_digest("F1", "fixed", 200, 200, "curl x", &files(), 100));
        assert_ne!(base, heal_digest("F1", "fixed", 200, 403, "curl y", &files(), 100));
        assert_ne!(base, heal_digest("F1", "fixed", 200, 403, "curl x", &files(), 101));
    }

    #[test]
    fn digest_is_64_hex_chars() {
        let d = heal_digest("F", "fixed", 200, 403, "p", &files(), 1);
        assert_eq!(d.len(), 64);
        assert!(d.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
