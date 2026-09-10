//! Ed25519 signatures on `ueba_sovereign_binary_allowlist` rows.
//!
//! A local attacker with INSERT on the catalog table cannot bless a SHA-256 into
//! Learn: the engine verifies `sovereign_signature` against the public key compiled
//! into this crate. The matching private seed is only `WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY`
//! (64 hex). Env / USB / packaged hashes still grant Learn as operator-local input.

use openssl::pkey::{Id, PKey};
use openssl::sign::{Signer, Verifier};

/// Weissman sovereign UEBA allow-list verifying key. Rotate by replacing this
/// constant and provisioning a new `WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY`.
pub const EMBEDDED_SOVEREIGN_PUBKEY: [u8; 32] = [
    0x0b, 0x48, 0x93, 0x20, 0xe0, 0xac, 0x90, 0x87, 0x08, 0xb1, 0x71, 0x8c, 0x2e, 0x67, 0x58, 0x77,
    0x43, 0xf0, 0x64, 0x04, 0x55, 0x7a, 0xb6, 0x5d, 0x52, 0xea, 0xd7, 0xaf, 0x9a, 0xb7, 0xe2, 0xe8,
];

#[must_use]
pub fn parse_ed25519_seed_hex(raw: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(raw.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Some(k)
}

#[must_use]
pub fn signing_seed_from_env() -> Option<[u8; 32]> {
    parse_ed25519_seed_hex(&std::env::var("WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY").ok()?)
}

/// Sign the lowercase 64-hex digest. The signature verifies only if `seed`
/// is the secret half of [`EMBEDDED_SOVEREIGN_PUBKEY`].
pub fn sign_sha256_hex(seed: &[u8; 32], sha256_hex: &str) -> Option<String> {
    if sha256_hex.len() != 64 || !sha256_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let pkey = PKey::private_key_from_raw_bytes(seed, Id::ED25519).ok()?;
    let mut signer = Signer::new_without_digest(&pkey).ok()?;
    let sig = signer.sign_oneshot_to_vec(sha256_hex.as_bytes()).ok()?;
    if sig.len() != 64 {
        return None;
    }
    let hex_sig = hex::encode(sig);
    if !verify_sha256_hex_against(sha256_hex, &hex_sig, &EMBEDDED_SOVEREIGN_PUBKEY) {
        return None;
    }
    Some(hex_sig)
}

#[must_use]
pub fn verify_sha256_hex(sha256_hex: &str, signature_hex: &str) -> bool {
    verify_sha256_hex_against(sha256_hex, signature_hex, &EMBEDDED_SOVEREIGN_PUBKEY)
}

#[must_use]
pub fn verify_sha256_hex_against(sha256_hex: &str, signature_hex: &str, pubkey: &[u8; 32]) -> bool {
    if sha256_hex.len() != 64
        || !sha256_hex
            .chars()
            .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    {
        return false;
    }
    let Ok(sig) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    if sig.len() != 64 {
        return false;
    }
    let Ok(pkey) = PKey::public_key_from_raw_bytes(pubkey, Id::ED25519) else {
        return false;
    };
    let Ok(mut verifier) = Verifier::new_without_digest(&pkey) else {
        return false;
    };
    verifier
        .verify_oneshot(&sig, sha256_hex.as_bytes())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    #[test]
    fn unsigned_and_forged_signatures_never_verify() {
        let sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(!verify_sha256_hex(sha, ""));
        assert!(!verify_sha256_hex(sha, "00".repeat(64).as_str()));
        assert!(!verify_sha256_hex("deadbeef", &"ab".repeat(64)));
    }

    #[test]
    fn ephemeral_pair_round_trips_only_on_its_own_key() {
        let pkey = PKey::generate_ed25519().expect("ed25519");
        let seed = pkey.raw_private_key().expect("seed");
        let pub_bytes = pkey.raw_public_key().expect("pub");
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&pub_bytes);
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other = PKey::private_key_from_raw_bytes(&seed_arr, Id::ED25519).unwrap();
        let mut signer = Signer::new_without_digest(&other).unwrap();
        let sig = hex::encode(signer.sign_oneshot_to_vec(sha.as_bytes()).unwrap());
        assert!(verify_sha256_hex_against(sha, &sig, &pub_arr));
        assert!(
            !verify_sha256_hex(sha, &sig),
            "a signature from a non-platform key must not verify against the embedded pubkey"
        );
    }

    #[test]
    fn env_seed_that_does_not_match_embedded_pubkey_cannot_sign() {
        let pkey = PKey::generate_ed25519().expect("ed25519");
        let seed = pkey.raw_private_key().expect("seed");
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        let sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(
            sign_sha256_hex(&seed_arr, sha).is_none(),
            "sign must refuse a seed that is not the platform key"
        );
    }

    #[test]
    fn embedded_pubkey_is_32_bytes() {
        assert_eq!(EMBEDDED_SOVEREIGN_PUBKEY.len(), 32);
        let src = include_str!("ueba_sovereign_sign.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(prod.contains("EMBEDDED_SOVEREIGN_PUBKEY"));
        assert!(prod.contains("WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY"));
    }
}
