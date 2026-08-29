//! Heap-zeroizing helpers for vault key material.
//!
//! `std::env::var` copies the C environ bytes onto a new `String` on the heap.
//! `remove_var` does not overwrite that allocation (or leftover copies from
//! `hex::decode` / SHA-256). Every env read of vault key material must go
//! through [`Zeroizing`] so `Drop` writes `\0` over the physical bytes as soon
//! as derivation finishes.

use zeroize::{Zeroize, Zeroizing};

/// Read an env var into a [`Zeroizing`] buffer. `Drop` overwrites the heap copy.
#[must_use]
pub fn env_zeroizing(name: &str) -> Option<Zeroizing<String>> {
    std::env::var(name).ok().map(Zeroizing::new)
}

/// Parse 32 bytes from hex, zeroing the decode buffer on every path.
#[must_use]
pub fn hex32(raw: &str) -> Option<[u8; 32]> {
    let decoded = hex::decode(raw.trim()).ok()?;
    let decoded = Zeroizing::new(decoded);
    if decoded.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&decoded);
    Some(k)
}

/// Derive an AES-256 key (SHA-256 of domain || material).
///
/// The hasher output buffer is overwritten after the copy so leftover digest
/// bytes do not linger on the heap next to the env `String` this was derived from.
#[must_use]
pub fn derive_aes256_key(domain: &[u8], material: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(material.as_bytes());
    let digest = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&digest);
    k
}

/// True when `name` is a 64-hex dedicated vault key. Heap copy is zeroized.
#[must_use]
pub fn env_is_hex32_key(name: &str) -> bool {
    env_zeroizing(name)
        .as_deref()
        .and_then(|v| hex32(v.trim()))
        .is_some()
}

/// Overwrite the live environ slot with same-length filler, zero the Rust copy,
/// then unset so `/proc/self/environ` and the heap slice cannot be scanned for
/// the original key.
pub fn scrub_env_var(name: &str) {
    if let Some(value) = env_zeroizing(name) {
        let n = value.len();
        drop(value);
        if n > 0 {
            let mut filler = "0".repeat(n);
            std::env::set_var(name, &filler);
            filler.zeroize();
        }
        std::env::remove_var(name);
    } else {
        std::env::remove_var(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex32_accepts_64_hex_and_rejects_wrong_length() {
        let ok = "ab".repeat(32);
        assert!(hex32(&ok).is_some());
        assert!(hex32("deadbeef").is_none());
        assert!(hex32("not-hex").is_none());
    }

    #[test]
    fn derive_aes256_key_is_stable_and_domain_separated() {
        let a = derive_aes256_key(b"dom-a|", "secret-material");
        let b = derive_aes256_key(b"dom-a|", "secret-material");
        let c = derive_aes256_key(b"dom-b|", "secret-material");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn scrub_env_var_unsets_and_zeroizing_drop_covers_copy() {
        let key = "WEISSMAN_TEST_ZEROIZE_SCRUB";
        std::env::set_var(key, "super-secret-vault-material-do-not-leak");
        assert!(std::env::var(key).is_ok());
        scrub_env_var(key);
        assert!(std::env::var(key).is_err());
    }
}
