//! Structured, replayable, tamper-evident per-finding evidence (Step 16).
//!
//! The live-verify path (`finding_live_verify`) performs real request/response I/O but
//! collapses everything into a free-text `detail` string — so a CONFIRMED verdict cannot be
//! shown to an auditor as the transcript that justified it, and nothing binds that evidence
//! into a tamper-evident chain. This module supplies the missing object:
//!
//!   * [`EvidenceTranscript`] — a well-typed, serde-serializable capture of the request
//!     (method, URL, **header NAMES only** — never values, which can carry auth tokens),
//!     the response (status, a safe header subset, a bounded body snippet, body hash+len),
//!     and timing (`started_at`, `elapsed_ms`) plus the `verifier_version`.
//!   * [`EvidenceTranscript::canonical_bytes`] — a deterministic serialization (fixed field
//!     order, sorted headers, `\x1e` record separators) so the same evidence always hashes
//!     to the same commitment regardless of map iteration order.
//!   * [`EvidenceTranscript::commitment`] — `SHA256(canonical_bytes)`, hex.
//!   * [`sign`] — fuses the two existing provenance primitives (the `finding_attestation`
//!     HMAC receipt and the `nl_audit_*` prev-hash chain) into one signed, hash-chained
//!     [`LedgerEntry`]: `entry_hash = SHA256(version | prev_hash | commitment | finding_id)`
//!     and `receipt = finding_attestation::attest(entry_hash)`.
//!   * [`verify_entry`] — recomputes the commitment and the chained `entry_hash`, checks the
//!     link to the expected previous hash, and (when present) constant-time-verifies the
//!     HMAC receipt. Any mutation of the transcript, the chain link, or the finding id fails.
//!
//! Pure logic, no network: fully unit-testable here. The caller (finding_live_verify) fills
//! `started_at`/`elapsed_ms` from the live probe; this module never reads the clock, so the
//! commitment stays deterministic.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Bump when `canonical_bytes` layout changes — old commitments then verify against the old
/// version string, so a format change cannot silently validate against a new hash.
pub const LEDGER_VERSION: &str = "weissman-evidence-ledger-v1";

/// Genesis previous-hash for the first entry in a finding's chain.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const RS: u8 = 0x1e; // ASCII record separator
const MAX_SNIPPET: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRequest {
    pub method: String,
    pub url: String,
    /// Header NAMES only — request header values can contain Authorization/cookies.
    pub header_names: Vec<String>,
    pub body_sha256: String,
    pub body_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceResponse {
    pub status: u16,
    /// A safe subset of response headers (name -> value); BTreeMap keeps it ordered.
    pub headers: BTreeMap<String, String>,
    /// Bounded, printable prefix of the response body for human inspection.
    pub body_snippet: String,
    pub body_sha256: String,
    pub body_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTranscript {
    pub verifier_version: String,
    /// RFC3339, supplied by the caller from the live probe (never read from the clock here).
    pub started_at: String,
    pub elapsed_ms: u64,
    pub request: EvidenceRequest,
    pub response: EvidenceResponse,
}

/// A signed, hash-chained entry committing one finding's evidence transcript.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerEntry {
    pub finding_id: String,
    pub prev_hash: String,
    pub commitment: String,
    pub entry_hash: String,
    /// HMAC receipt over `entry_hash`; `None` when no signing key is configured.
    pub receipt: Option<String>,
}

/// Hash of arbitrary bytes, hex-encoded.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

impl EvidenceRequest {
    /// Build from raw parts, capturing header NAMES only (lower-cased, sorted, deduped) and
    /// the body hash+len — never the request header values or raw body.
    #[must_use]
    pub fn capture(method: &str, url: &str, header_names: &[String], body: &[u8]) -> Self {
        let mut names: Vec<String> = header_names.iter().map(|n| n.trim().to_ascii_lowercase()).collect();
        names.sort();
        names.dedup();
        Self {
            method: method.trim().to_ascii_uppercase(),
            url: url.trim().to_string(),
            header_names: names,
            body_sha256: sha256_hex(body),
            body_len: body.len(),
        }
    }
}

impl EvidenceResponse {
    /// Build from raw parts, storing a bounded printable snippet + body hash+len. Header keys
    /// are lower-cased into a BTreeMap for deterministic ordering.
    #[must_use]
    pub fn capture(status: u16, headers: &[(String, String)], body: &[u8]) -> Self {
        let mut hmap = BTreeMap::new();
        for (k, v) in headers {
            hmap.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
        let snippet: String = String::from_utf8_lossy(body)
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .take(MAX_SNIPPET)
            .collect();
        Self {
            status,
            headers: hmap,
            body_snippet: snippet,
            body_sha256: sha256_hex(body),
            body_len: body.len(),
        }
    }
}

impl EvidenceTranscript {
    /// Deterministic byte serialization: fixed field order, sorted headers, `\x1e` record
    /// separators. Independent of any map/hash iteration order.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut push = |s: &str| {
            out.extend_from_slice(s.as_bytes());
            out.push(RS);
        };
        push(LEDGER_VERSION);
        push(&self.verifier_version);
        push(&self.started_at);
        push(&self.elapsed_ms.to_string());
        push(&self.request.method);
        push(&self.request.url);
        push(&self.request.header_names.join(","));
        push(&self.request.body_sha256);
        push(&self.request.body_len.to_string());
        push(&self.response.status.to_string());
        for (k, v) in &self.response.headers {
            push(k);
            push(v);
        }
        push(&self.response.body_sha256);
        push(&self.response.body_len.to_string());
        push(&self.response.body_snippet);
        out
    }

    /// SHA-256 commitment (hex) over the canonical bytes.
    #[must_use]
    pub fn commitment(&self) -> String {
        sha256_hex(&self.canonical_bytes())
    }
}

/// Compute the chained entry hash: `SHA256(version | prev_hash | commitment | finding_id)`.
#[must_use]
fn chain_hash(prev_hash: &str, commitment: &str, finding_id: &str) -> String {
    let mut h = Sha256::new();
    for part in [LEDGER_VERSION, prev_hash, commitment, finding_id] {
        h.update(part.as_bytes());
        h.update([RS]);
    }
    hex::encode(h.finalize())
}

/// Sign a transcript into a hash-chained ledger entry linked to `prev_hash`. The HMAC
/// `receipt` is `None` when no signing key is configured (dev without `WEISSMAN_JWT_SECRET`);
/// the hash chain itself is always produced and independently verifiable.
#[must_use]
pub fn sign(transcript: &EvidenceTranscript, prev_hash: &str, finding_id: &str) -> LedgerEntry {
    let commitment = transcript.commitment();
    let entry_hash = chain_hash(prev_hash, &commitment, finding_id);
    let receipt = crate::finding_attestation::attest(&entry_hash);
    LedgerEntry {
        finding_id: finding_id.to_string(),
        prev_hash: prev_hash.to_string(),
        commitment,
        entry_hash,
        receipt,
    }
}

/// Verify an entry against its transcript and the expected previous hash. Checks, in order:
/// the transcript re-commits to `entry.commitment`; the chain link matches `expected_prev`;
/// `entry_hash` recomputes; and, when a receipt is present, it constant-time-verifies. A
/// missing receipt still validates the (unforgeable-without-collision) hash chain.
#[must_use]
pub fn verify_entry(entry: &LedgerEntry, transcript: &EvidenceTranscript, expected_prev: &str) -> bool {
    if entry.prev_hash != expected_prev {
        return false;
    }
    if transcript.commitment() != entry.commitment {
        return false;
    }
    if chain_hash(expected_prev, &entry.commitment, &entry.finding_id) != entry.entry_hash {
        return false;
    }
    match &entry.receipt {
        Some(r) => crate::finding_attestation::verify(&entry.entry_hash, r),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EvidenceTranscript {
        EvidenceTranscript {
            verifier_version: "live-verify/2".to_string(),
            started_at: "2026-09-20T12:00:00Z".to_string(),
            elapsed_ms: 143,
            request: EvidenceRequest::capture(
                "get",
                "https://t.example/login",
                &["Host".into(), "Authorization".into(), "Accept".into()],
                b"payload",
            ),
            response: EvidenceResponse::capture(
                200,
                &[("Server".into(), "nginx".into()), ("Content-Type".into(), "text/html".into())],
                b"<html>evidence body</html>",
            ),
        }
    }

    #[test]
    fn request_capture_keeps_names_only_sorted_and_never_values() {
        let r = EvidenceRequest::capture("get", "u", &["Host".into(), "authorization".into()], b"x");
        assert_eq!(r.method, "GET");
        assert_eq!(r.header_names, vec!["authorization".to_string(), "host".to_string()]);
        // body is hashed, not stored
        assert_eq!(r.body_sha256, sha256_hex(b"x"));
        assert_eq!(r.body_len, 1);
    }

    #[test]
    fn commitment_is_deterministic_and_order_independent() {
        // Two transcripts equal except response header INSERTION order must commit identically.
        let mut a = sample();
        let mut b = sample();
        a.response = EvidenceResponse::capture(
            200,
            &[("Server".into(), "nginx".into()), ("Content-Type".into(), "text/html".into())],
            b"<html>evidence body</html>",
        );
        b.response = EvidenceResponse::capture(
            200,
            &[("Content-Type".into(), "text/html".into()), ("Server".into(), "nginx".into())],
            b"<html>evidence body</html>",
        );
        assert_eq!(a.commitment(), b.commitment(), "header order must not change the commitment");
    }

    #[test]
    fn commitment_changes_when_any_evidence_field_changes() {
        let base = sample().commitment();
        let mut t = sample();
        t.response.status = 403;
        assert_ne!(base, t.commitment(), "status change must change commitment");
        let mut t2 = sample();
        t2.elapsed_ms = 999;
        assert_ne!(base, t2.commitment(), "timing change must change commitment");
        let mut t3 = sample();
        t3.request = EvidenceRequest::capture("get", "https://t.example/login", &["Host".into()], b"different");
        assert_ne!(base, t3.commitment(), "request body-hash change must change commitment");
    }

    #[test]
    fn valid_chain_verifies_and_links() {
        let t1 = sample();
        let e1 = sign(&t1, GENESIS_PREV, "VLN-1");
        assert!(verify_entry(&e1, &t1, GENESIS_PREV));

        let t2 = sample();
        let e2 = sign(&t2, &e1.entry_hash, "VLN-2");
        assert!(verify_entry(&e2, &t2, &e1.entry_hash), "second entry links to first");
        // Wrong expected-prev breaks the link.
        assert!(!verify_entry(&e2, &t2, GENESIS_PREV), "broken chain link must fail");
    }

    #[test]
    fn tampering_with_transcript_after_signing_fails_verification() {
        let t = sample();
        let e = sign(&t, GENESIS_PREV, "VLN-1");
        let mut tampered = t.clone();
        tampered.response.body_snippet = "<html>rewritten</html>".to_string();
        assert!(
            !verify_entry(&e, &tampered, GENESIS_PREV),
            "a mutated transcript must not verify against the original entry"
        );
    }

    #[test]
    fn forged_finding_id_or_commitment_fails() {
        let t = sample();
        let mut e = sign(&t, GENESIS_PREV, "VLN-1");
        e.finding_id = "VLN-999".to_string(); // entry_hash no longer recomputes
        assert!(!verify_entry(&e, &t, GENESIS_PREV));
        let mut e2 = sign(&t, GENESIS_PREV, "VLN-1");
        e2.commitment = sha256_hex(b"fake");
        assert!(!verify_entry(&e2, &t, GENESIS_PREV));
    }
}
