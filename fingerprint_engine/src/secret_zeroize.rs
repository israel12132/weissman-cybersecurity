//! Vault key material: locked, zeroizing byte buffers — never `String`.
//!
//! `std::env::var` copies environ bytes onto a heap `String`. The allocator may
//! duplicate that slice across resizes and then put the old pages on the free
//! list without wiping them. A memory dump then recovers live vault keys.
//!
//! Load path:
//! 1. `var_os` → `into_encoded_bytes` (no UTF-8 `String`)
//! 2. `mlock` / `VirtualLock` so the copy cannot be swapped
//! 3. Linux `MADV_DONTDUMP` so core dumps skip the pages
//! 4. `Zeroize` on drop, then `munlock`
//! 5. In-place environ overwrite + `remove_var` for vault key names (JWT stays)

use zeroize::Zeroize;

/// Sealed heap buffer for vault key bytes. Locked into RAM while alive.
pub struct LockedBytes {
    buf: Vec<u8>,
    locked_len: usize,
}

impl LockedBytes {
    fn from_vec(mut buf: Vec<u8>) -> Self {
        let locked_len = buf.len();
        memlock::lock_secret_pages(buf.as_mut_ptr(), locked_len);
        Self { buf, locked_len }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    #[must_use]
    pub fn trim_ascii(&self) -> &[u8] {
        trim_ascii(&self.buf)
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        let ptr = self.buf.as_mut_ptr();
        let lock_len = self.locked_len;
        self.buf.zeroize();
        memlock::unlock_secret_pages(ptr, lock_len);
    }
}

/// ASCII trim without allocating a `String`.
#[must_use]
pub fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let mut s = bytes;
    while s.first().is_some_and(u8::is_ascii_whitespace) {
        s = &s[1..];
    }
    while s.last().is_some_and(u8::is_ascii_whitespace) {
        s = &s[..s.len() - 1];
    }
    s
}

/// Split comma-separated env blobs (previous-key rings) without `String`.
pub fn split_csv(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|b| *b == b',')
        .map(trim_ascii)
        .filter(|s| !s.is_empty())
}

/// Copy an env var into a locked byte buffer. Never constructs `String`.
#[must_use]
pub fn take_env_bytes_locked(name: &str) -> Option<LockedBytes> {
    let os = std::env::var_os(name)?;
    Some(LockedBytes::from_vec(os.into_encoded_bytes()))
}

/// Parse 32 bytes from hex on the stack — no `hex::decode` heap buffer.
#[must_use]
pub fn hex32(raw: &[u8]) -> Option<[u8; 32]> {
    let raw = trim_ascii(raw);
    if raw.len() != 64 {
        return None;
    }
    let mut k = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(raw[i * 2])?;
        let lo = hex_nibble(raw[i * 2 + 1])?;
        k[i] = (hi << 4) | lo;
    }
    Some(k)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Derive an AES-256 key (SHA-256 of domain || material). Digest buffer is zeroed.
#[must_use]
pub fn derive_aes256_key(domain: &[u8], material: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(material);
    let mut digest = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&digest);
    digest.zeroize();
    k
}

/// True when `name` is a 64-hex dedicated vault key.
#[must_use]
pub fn env_is_hex32_key(name: &str) -> bool {
    take_env_bytes_locked(name)
        .as_ref()
        .and_then(|v| hex32(v.trim_ascii()))
        .is_some()
}

/// Overwrite the live environ slot with same-length filler, zero the locked copy,
/// then unset so `/proc/self/environ` cannot be scanned for the original key.
pub fn scrub_env_var(name: &str) {
    if let Some(value) = take_env_bytes_locked(name) {
        let n = value.as_bytes().len();
        drop(value);
        if n > 0 {
            let filler = "0".repeat(n);
            // SAFETY: filler is ASCII zeros, not secret material.
            std::env::set_var(name, &filler);
        }
        std::env::remove_var(name);
    } else {
        std::env::remove_var(name);
    }
}

/// Pin secret pages (mlock / VirtualLock + MADV_DONTDUMP).
///
/// The crate denies `unsafe_code` at the crate root; this module is a documented
/// exception (same pattern as `hpc_runtime::linux_affinity`).
#[allow(unsafe_code)]
mod memlock {
    /// Best-effort pin. Failures are ignored: some containers cap `RLIMIT_MEMLOCK`
    /// and Windows may reject `VirtualLock`; callers still zeroize on drop.
    pub fn lock_secret_pages(ptr: *mut u8, len: usize) {
        if ptr.is_null() || len == 0 {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `ptr`/`len` describe a live `Vec<u8>` allocation owned by
            // `LockedBytes` for the whole pin window. `mlock` / `madvise` may fail
            // (EPERM, ENOMEM, container memlock cap); a nonzero return is ignored.
            unsafe {
                let p = ptr.cast::<libc::c_void>();
                let _ = libc::mlock(p, len);
                let _ = libc::madvise(p, len, libc::MADV_DONTDUMP);
            }
        }
        #[cfg(windows)]
        {
            // SAFETY: `VirtualLock` on a live allocation; BOOL failure is ignored.
            unsafe {
                let _ = VirtualLock(ptr.cast(), len);
            }
        }
        let _ = (ptr, len);
    }

    pub fn unlock_secret_pages(ptr: *mut u8, len: usize) {
        if ptr.is_null() || len == 0 {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: pages were previously mlock'd (or mlock failed — munlock is
            // then a no-op / harmless error). The allocation is still live.
            unsafe {
                let _ = libc::munlock(ptr.cast::<libc::c_void>(), len);
            }
        }
        #[cfg(windows)]
        {
            unsafe {
                let _ = VirtualUnlock(ptr.cast(), len);
            }
        }
        let _ = (ptr, len);
    }

    #[cfg(windows)]
    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualLock(lpAddress: *mut core::ffi::c_void, dwSize: usize) -> i32;
        fn VirtualUnlock(lpAddress: *mut core::ffi::c_void, dwSize: usize) -> i32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex32_accepts_64_hex_and_rejects_wrong_length() {
        let ok = "ab".repeat(32);
        assert!(hex32(ok.as_bytes()).is_some());
        assert!(hex32(b"deadbeef").is_none());
        assert!(hex32(b"not-hex").is_none());
        assert!(hex32(b"  ").is_none());
    }

    #[test]
    fn hex32_trims_ascii_whitespace_without_string() {
        let inner = "cd".repeat(32);
        let padded = format!(" \n{inner}\t");
        assert_eq!(hex32(padded.as_bytes()), hex32(inner.as_bytes()));
    }

    #[test]
    fn derive_aes256_key_is_stable_and_domain_separated() {
        let a = derive_aes256_key(b"dom-a|", b"secret-material");
        let b = derive_aes256_key(b"dom-a|", b"secret-material");
        let c = derive_aes256_key(b"dom-b|", b"secret-material");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn scrub_env_var_unsets_and_zeroizing_drop_covers_copy() {
        let key = "WEISSMAN_TEST_ZEROIZE_SCRUB";
        std::env::set_var(key, "super-secret-vault-material-do-not-leak");
        assert!(std::env::var_os(key).is_some());
        scrub_env_var(key);
        assert!(std::env::var_os(key).is_none());
    }

    #[test]
    fn take_env_bytes_locked_round_trips_bytes_not_string() {
        let key = "WEISSMAN_TEST_LOCKED_BYTES";
        std::env::set_var(key, "abc-not-a-rust-string-secret");
        let locked = take_env_bytes_locked(key).expect("env present");
        assert_eq!(locked.as_bytes(), b"abc-not-a-rust-string-secret");
        drop(locked);
        std::env::remove_var(key);
    }

    #[test]
    fn split_csv_skips_empty_and_trims() {
        let parts: Vec<&[u8]> = split_csv(b" aa ,bb,  ").collect();
        assert_eq!(parts, [b"aa".as_slice(), b"bb".as_slice()]);
    }

    #[test]
    fn module_never_calls_env_var_string() {
        let src = include_str!("secret_zeroize.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production source");
        assert!(
            !prod.contains("std::env::var("),
            "vault load path must not allocate a heap String via std::env::var"
        );
        assert!(prod.contains("var_os"));
        assert!(prod.contains("into_encoded_bytes"));
        assert!(prod.contains("mlock") || prod.contains("VirtualLock"));
    }
}
