//! Rekor transparency-log verification: RFC 6962 Merkle inclusion proofs and the Signed Entry
//! Timestamp (SET).
//!
//! A signature proves *who* signed; the transparency log proves the signature was *publicly
//! recorded at a point in time*. This matters for two reasons that are load-bearing for keyless
//! Sigstore:
//!   * Fulcio certificates live for only ten minutes. A signature is trusted long after the cert
//!     expires *because* the log recorded that the signature existed while the cert was valid — the
//!     `integratedTime` is the trusted clock. No log entry, no trusted timestamp, no keyless trust.
//!   * The log is append-only and monitorable, so a compromised-key signature cannot be created and
//!     used in secret; it must be published to be trusted, where monitors can catch it.
//!
//! We verify both independent facts ourselves: the inclusion proof (this entry is really in a tree
//! whose root we can recompute) and the SET (the log operator's key signed this entry's coordinates
//! at `integratedTime`). Trusting one without the other leaves a gap; we compute both.

use super::keyring::TrustedKey;
use sha2::{Digest, Sha256};

const RFC6962_LEAF_PREFIX: u8 = 0x00;
const RFC6962_NODE_PREFIX: u8 = 0x01;

/// RFC 6962 leaf hash: `SHA-256(0x00 || entry)`.
#[must_use]
pub fn merkle_leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([RFC6962_LEAF_PREFIX]);
    h.update(entry);
    h.finalize().into()
}

/// RFC 6962 interior node hash: `SHA-256(0x01 || left || right)`.
#[must_use]
fn hash_children(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([RFC6962_NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Recompute the Merkle root implied by an inclusion proof, following the algorithm of
/// RFC 6962 / transparency-dev's `RootFromInclusionProof`. Returns `None` if the proof length is
/// inconsistent with `(index, size)` — a structurally invalid proof, which must never verify.
#[must_use]
pub fn root_from_inclusion_proof(
    index: u64,
    size: u64,
    leaf_hash: &[u8; 32],
    proof: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if size == 0 || index >= size {
        return None;
    }
    // Number of proof hashes that pair within the "inner" part of the path.
    let inner = inner_proof_size(index, size);
    // Number of hashes needed to fold the remaining left-border subtrees.
    let border = (index >> inner).count_ones() as usize;
    if proof.len() != inner + border {
        return None;
    }

    let mut res = *leaf_hash;
    for (i, sibling) in proof.iter().enumerate().take(inner) {
        if (index >> i) & 1 == 0 {
            // Current node is a left child: sibling is on the right.
            res = hash_children(&res, sibling);
        } else {
            res = hash_children(sibling, &res);
        }
    }
    for sibling in proof.iter().skip(inner) {
        res = hash_children(sibling, &res);
    }
    Some(res)
}

/// `bits.Len64(index ^ (size - 1))` — the height at which the leaf's path leaves the perfect
/// subtree it sits in.
fn inner_proof_size(index: u64, size: u64) -> usize {
    let x = index ^ (size - 1);
    (64 - x.leading_zeros()) as usize
}

/// A Rekor inclusion proof as returned by the log.
#[derive(Clone, Debug)]
pub struct InclusionProof {
    pub log_index: u64,
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub hashes: Vec<[u8; 32]>,
}

/// The coordinates of a Rekor log entry that the SET is computed over.
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// base64-encoded canonical entry body (the bytes hashed into the Merkle leaf).
    pub body_b64: String,
    pub integrated_time: i64,
    /// Hex log id (SHA-256 of the log's public key).
    pub log_id: String,
    pub log_index: i64,
}

impl LogEntry {
    /// The RFC 8785-canonical JSON the SET signs: the four coordinates with sorted keys and no
    /// insignificant whitespace. The keys are already in lexical order
    /// (`body < integratedTime < logID < logIndex`); values are minimally JSON-escaped.
    #[must_use]
    pub fn set_canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"body\":\"{}\",\"integratedTime\":{},\"logID\":\"{}\",\"logIndex\":{}}}",
            json_escape(&self.body_b64),
            self.integrated_time,
            json_escape(&self.log_id),
            self.log_index,
        )
        .into_bytes()
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The outcome of verifying a Rekor entry: both facts are computed independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RekorVerification {
    /// The recomputed Merkle root matches the proof's stated root.
    pub inclusion_verified: bool,
    /// The log operator's key signed the entry's coordinates (SET valid).
    pub set_verified: bool,
    /// The trusted timestamp (seconds since epoch) at which the entry was integrated.
    pub integrated_time: i64,
}

impl RekorVerification {
    /// Both proofs held: the entry is genuinely, verifiably logged.
    #[must_use]
    pub fn is_fully_verified(&self) -> bool {
        self.inclusion_verified && self.set_verified
    }
}

/// Verify a Rekor entry's inclusion proof and SET.
///
/// * `entry` — the log entry coordinates.
/// * `proof` — the inclusion proof; its `log_index` is the index within `tree_size`.
/// * `set_signature` — the raw (base64-decoded) SET signature bytes.
/// * `log_key` — the Rekor log's trusted public key (ECDSA P-256 / SHA-256 in production).
#[must_use]
pub fn verify_entry(
    entry: &LogEntry,
    proof: &InclusionProof,
    set_signature: &[u8],
    log_key: &TrustedKey,
) -> RekorVerification {
    let inclusion_verified = verify_inclusion(entry, proof);
    let set_verified = log_key.verify(&entry.set_canonical_bytes(), set_signature);
    RekorVerification {
        inclusion_verified,
        set_verified,
        integrated_time: entry.integrated_time,
    }
}

fn verify_inclusion(entry: &LogEntry, proof: &InclusionProof) -> bool {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    let Ok(body) = BASE64.decode(entry.body_b64.as_bytes()) else {
        return false;
    };
    let leaf = merkle_leaf_hash(&body);
    match root_from_inclusion_proof(proof.log_index, proof.tree_size, &leaf, &proof.hashes) {
        Some(root) => root == proof.root_hash,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Signer;

    // Reference tree builder for tests: a full RFC 6962 Merkle tree over `leaves`.
    fn tree_root(leaves: &[Vec<u8>]) -> [u8; 32] {
        let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| merkle_leaf_hash(l)).collect();
        root_of_hashes(&hashes)
    }

    fn root_of_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
        match hashes.len() {
            0 => Sha256::digest([]).into(),
            1 => hashes[0],
            n => {
                let k = largest_power_of_two_below(n);
                let left = root_of_hashes(&hashes[..k]);
                let right = root_of_hashes(&hashes[k..]);
                hash_children(&left, &right)
            }
        }
    }

    fn largest_power_of_two_below(n: usize) -> usize {
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        k
    }

    // Reference inclusion-proof generator (RFC 6962 SUBPROOF).
    fn inclusion_hashes(index: usize, hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
        subproof(index, hashes, true)
    }

    fn subproof(m: usize, hashes: &[[u8; 32]], _root: bool) -> Vec<[u8; 32]> {
        let n = hashes.len();
        if n == 1 {
            return vec![];
        }
        let k = largest_power_of_two_below(n);
        if m < k {
            let mut p = subproof(m, &hashes[..k], false);
            p.push(root_of_hashes(&hashes[k..]));
            p
        } else {
            let mut p = subproof(m - k, &hashes[k..], false);
            p.push(root_of_hashes(&hashes[..k]));
            p
        }
    }

    #[test]
    fn inclusion_proof_verifies_for_each_leaf_across_tree_sizes() {
        for size in 1usize..=17 {
            let leaves: Vec<Vec<u8>> = (0..size).map(|i| vec![i as u8, 0xEE]).collect();
            let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| merkle_leaf_hash(l)).collect();
            let root = tree_root(&leaves);
            for index in 0..size {
                let proof = inclusion_hashes(index, &hashes);
                let recomputed = root_from_inclusion_proof(
                    index as u64,
                    size as u64,
                    &merkle_leaf_hash(&leaves[index]),
                    &proof,
                )
                .expect("valid proof shape");
                assert_eq!(recomputed, root, "size={size} index={index}");
            }
        }
    }

    #[test]
    fn tampered_proof_does_not_verify() {
        let size = 8usize;
        let leaves: Vec<Vec<u8>> = (0..size).map(|i| vec![i as u8]).collect();
        let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| merkle_leaf_hash(l)).collect();
        let root = tree_root(&leaves);
        let mut proof = inclusion_hashes(3, &hashes);
        proof[0][0] ^= 0xFF;
        let recomputed =
            root_from_inclusion_proof(3, size as u64, &merkle_leaf_hash(&leaves[3]), &proof)
                .unwrap();
        assert_ne!(recomputed, root);
    }

    #[test]
    fn wrong_length_proof_is_rejected() {
        let leaf = merkle_leaf_hash(b"x");
        // size=4 index=0 needs a specific proof length; an empty proof is wrong.
        assert!(root_from_inclusion_proof(0, 4, &leaf, &[]).is_none());
        assert!(root_from_inclusion_proof(0, 0, &leaf, &[]).is_none());
        assert!(root_from_inclusion_proof(5, 4, &leaf, &[]).is_none());
    }

    fn rekor_key() -> (PKey<Private>, TrustedKey) {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let priv_key = PKey::from_ec_key(ec).unwrap();
        let pem = priv_key.public_key_to_pem().unwrap();
        (priv_key, TrustedKey::from_pem(&pem, "rekor-log").unwrap())
    }

    #[test]
    fn set_and_inclusion_verify_together() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;
        let (priv_key, log_key) = rekor_key();

        // Build a small tree; our entry is leaf 2 of 5.
        let leaves: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8, 0x42]).collect();
        let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| merkle_leaf_hash(l)).collect();
        let root = tree_root(&leaves);
        let index = 2usize;
        let proof = InclusionProof {
            log_index: index as u64,
            tree_size: 5,
            root_hash: root,
            hashes: inclusion_hashes(index, &hashes),
        };
        let entry = LogEntry {
            body_b64: BASE64.encode(&leaves[index]),
            integrated_time: 1_700_000_000,
            log_id: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d".into(),
            log_index: 42,
        };
        // Sign the SET canonical bytes with the log key.
        let mut s = Signer::new(MessageDigest::sha256(), &priv_key).unwrap();
        s.update(&entry.set_canonical_bytes()).unwrap();
        let set = s.sign_to_vec().unwrap();

        let v = verify_entry(&entry, &proof, &set, &log_key);
        assert!(v.is_fully_verified());
        assert_eq!(v.integrated_time, 1_700_000_000);

        // A forged SET (bit-flipped) fails the SET check but inclusion still holds.
        let mut bad_set = set.clone();
        bad_set[10] ^= 0x01;
        let v2 = verify_entry(&entry, &proof, &bad_set, &log_key);
        assert!(v2.inclusion_verified);
        assert!(!v2.set_verified);
        assert!(!v2.is_fully_verified());
    }
}
