//! Encrypted agent identity spool.
//!
//! Linux: AEAD key lives in the kernel user keyring (`keyctl`) and in process
//! memory only. It is **never** derived from `/etc/machine-id`, MAC addresses,
//! or environment — those are recoverable by an unprivileged local attacker.
//! Non-Linux: same AEAD; IKM is getrandom() then HKDF. Windows can additionally
//! wrap via DPAPI later; we still never use host fingerprints as IKM.
//!
//! libc 0.2 does not export `add_key`/`keyctl` wrappers on this crate version —
//! only `SYS_add_key` / `SYS_keyctl` plus `linux/keyctl.h` constants. We issue
//! those syscalls directly.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::Path;
use std::sync::OnceLock;

const MAGIC: &[u8; 4] = b"WSPL";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const KEYRING_DESC: &str = "weissman-agent-spool";

type HmacSha256 = Hmac<Sha256>;

static AEAD_KEY: OnceLock<[u8; 32]> = OnceLock::new();

fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut extract =
        <HmacSha256 as Mac>::new_from_slice(&[0u8; 32]).expect("HMAC accepts any key length");
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();
    let mut expand =
        <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC accepts any key length");
    expand.update(info);
    expand.update(&[1u8]);
    let okm = expand.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

fn random_ikm() -> std::io::Result<[u8; 32]> {
    let mut ikm = [0u8; 32];
    getrandom::getrandom(&mut ikm).map_err(std::io::Error::other)?;
    Ok(ikm)
}

fn aead_key() -> std::io::Result<[u8; 32]> {
    if let Some(k) = AEAD_KEY.get() {
        return Ok(*k);
    }
    let ikm = load_or_create_ikm()?;
    let key = hkdf_sha256(&ikm, b"weissman-agent-spool-v1");
    let _ = AEAD_KEY.set(key);
    Ok(*AEAD_KEY.get().expect("key set"))
}

fn load_or_create_ikm() -> std::io::Result<[u8; 32]> {
    #[cfg(target_os = "linux")]
    {
        if let Some(ikm) = linux_keyring::read() {
            return Ok(ikm);
        }
        let ikm = random_ikm()?;
        if let Err(e) = linux_keyring::install(&ikm) {
            // Keyring unavailable (restricted container, seccomp, no user keyring).
            // Keep IKM in process memory. After reboot the spool cannot decrypt and
            // the agent re-enrolls — that is the intended fail-closed behaviour.
            tracing::warn!(
                target: "agent",
                error = %e,
                "kernel keyring unavailable; spool IKM is RAM-only (reboot requires re-enroll)"
            );
        }
        Ok(ikm)
    }
    #[cfg(not(target_os = "linux"))]
    {
        random_ikm()
    }
}

pub fn encrypt_spool(plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
    let key = aead_key()?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(std::io::Error::other)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| std::io::Error::other("spool aead encrypt failed"))?;
    let mut out = Vec::with_capacity(4 + 1 + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_spool(blob: &[u8]) -> std::io::Result<Vec<u8>> {
    if blob.len() < 4 + 1 + NONCE_LEN + 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "spool blob too short",
        ));
    }
    if &blob[0..4] != MAGIC || blob[4] != VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "spool magic/version mismatch",
        ));
    }
    let nonce = XNonce::from_slice(&blob[5..5 + NONCE_LEN]);
    let ct = &blob[5 + NONCE_LEN..];
    let key = aead_key()?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    cipher.decrypt(nonce, ct).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "spool aead decrypt failed")
    })
}

pub fn looks_encrypted(blob: &[u8]) -> bool {
    blob.len() >= 5 && &blob[0..4] == MAGIC && blob[4] == VERSION
}

pub fn persist_encrypted(path: &Path, plaintext: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let blob = encrypt_spool(plaintext)?;
    let tmp = path.with_extension("state.tmp");
    write_owner_only(&tmp, &blob)?;
    std::fs::rename(&tmp, path)?;
    set_owner_only(path)
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

fn set_owner_only(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

pub fn load_maybe_encrypted(path: &Path) -> Option<Vec<u8>> {
    let raw = std::fs::read(path).ok()?;
    if looks_encrypted(&raw) {
        return decrypt_spool(&raw).ok();
    }
    // One-release plaintext fallback (pre-encryption agents). Next save rewrites AEAD.
    if raw.first().copied() == Some(b'{') {
        return Some(raw);
    }
    None
}

#[cfg(target_os = "linux")]
mod linux_keyring {
    use std::ffi::CString;
    use std::io;

    const KEY_LEN: usize = 32;

    fn cstr(s: &str) -> io::Result<CString> {
        CString::new(s).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    pub fn read() -> Option<[u8; KEY_LEN]> {
        let typ = cstr("user").ok()?;
        let desc = cstr(super::KEYRING_DESC).ok()?;
        // SAFETY: C strings live for the syscall; dest keyring 0 = do not link a copy.
        let serial = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                libc::KEYCTL_SEARCH as libc::c_long,
                libc::KEY_SPEC_USER_KEYRING as libc::c_long,
                typ.as_ptr(),
                desc.as_ptr(),
                0_i64,
            )
        };
        if serial < 0 {
            return None;
        }
        let mut buf = [0u8; KEY_LEN];
        // SAFETY: buffer is KEY_LEN bytes; kernel writes at most buflen.
        let n = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                libc::KEYCTL_READ as libc::c_long,
                serial,
                buf.as_mut_ptr(),
                KEY_LEN as libc::c_long,
                0_i64,
            )
        };
        if n != KEY_LEN as libc::c_long {
            return None;
        }
        Some(buf)
    }

    pub fn install(ikm: &[u8; KEY_LEN]) -> io::Result<()> {
        let typ = cstr("user")?;
        let desc = cstr(super::KEYRING_DESC)?;
        // SAFETY: type/description are valid C strings; payload is KEY_LEN bytes.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                typ.as_ptr(),
                desc.as_ptr(),
                ikm.as_ptr(),
                KEY_LEN as libc::size_t,
                libc::KEY_SPEC_USER_KEYRING as libc::c_long,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_aead_blob() {
        let pt = br#"{"agent_id":"a","agent_secret":"s"}"#;
        let blob = encrypt_spool(pt).expect("encrypt");
        assert!(looks_encrypted(&blob));
        assert!(
            !blob.windows(pt.len()).any(|w| w == pt),
            "plaintext must not leak into spool"
        );
        let out = decrypt_spool(&blob).expect("decrypt");
        assert_eq!(out, pt);
    }

    #[test]
    fn key_is_not_host_fingerprint() {
        // Guard: IKM must be 32 random bytes, not a hash of machine-id shaped ASCII.
        let ikm = random_ikm().expect("rand");
        assert!(
            ikm.iter()
                .any(|&b| b > 127 || (b > 0 && !b.is_ascii_digit())),
            "IKM looks too structured"
        );
        let k1 = hkdf_sha256(&ikm, b"weissman-agent-spool-v1");
        let k2 = hkdf_sha256(&ikm, b"weissman-agent-spool-v1");
        assert_eq!(k1, k2);
        assert_ne!(k1, ikm);
    }

    #[test]
    fn ikm_is_not_copied_from_machine_id() {
        let ikm = random_ikm().expect("rand");
        let Ok(mid) = std::fs::read("/etc/machine-id") else {
            return;
        };
        let mid: Vec<u8> = mid
            .into_iter()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        if mid.len() < 8 {
            return;
        }
        assert!(
            !ikm.windows(8).any(|w| mid.windows(8).any(|m| m == w)),
            "IKM must not contain /etc/machine-id bytes"
        );
    }
}
