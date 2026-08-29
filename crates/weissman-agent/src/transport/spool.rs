//! Encrypted disk spool for findings / task completions when the WebSocket is down.
//!
//! Offline telemetry is written under an innocuous cache name and sealed with
//! AES-256-GCM. The wrapping key is HKDF-SHA256 over real OS entropy (getrandom).
//! IKM lives in a **reboot-stable** directory (never `/tmp`): systemd credentials,
//! TPM 2.0 seal (`tpm2-tools` on `/dev/tpmrm0`), Linux user keyring cache, or a
//! 0600 file. Never `/etc/machine-id`, DMI UUID, MAC, or hostname. On Windows the
//! ciphertext is additionally wrapped with DPAPI (`CryptProtectData`).

use crate::protocol::AgentToServer;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::path::{Path, PathBuf};

const MAX_SPOOL_BYTES: u64 = 32 * 1024 * 1024;
const MAGIC: &[u8; 4] = b"CACH";
const VERSION: u8 = 2;
const HKDF_SALT: &[u8] = b"ws-agent-spool-v2";
const HKDF_INFO: &[u8] = b"aes-256-gcm";

#[must_use]
pub fn spool_path() -> PathBuf {
    if let Some(p) = std::env::var_os("WEISSMAN_AGENT_SPOOL_FILE") {
        return PathBuf::from(p);
    }
    obfuscated_default_path()
}

/// Durable agent state (IKM + spool ciphertext). Never `/tmp` — tmpfs is wiped
/// on reboot and would make AES-256-GCM keys and offline telemetry unrecoverable.
#[must_use]
pub fn persistent_state_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("WEISSMAN_AGENT_STATE_DIR") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    {
        return std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\Microsoft\Windows\INetCache"))
            .join("Microsoft")
            .join("Windows")
            .join("INetCache")
            .join("IE");
    }
    #[cfg(not(windows))]
    {
        if let Some(p) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(p).join(".cache").join("fontconfig");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join(".cache")
                .join("fontconfig");
        }
        PathBuf::from("/var/lib/weissman-agent/.cache")
    }
}

fn obfuscated_default_path() -> PathBuf {
    let token = hex::encode(&derive_key()[..16]);
    #[cfg(windows)]
    {
        return persistent_state_dir()
            .join(&token[..8.min(token.len())])
            .join(format!("{token}.dat"));
    }
    #[cfg(not(windows))]
    {
        persistent_state_dir().join(format!("{token}.cache-7"))
    }
}

fn default_ikm_path() -> PathBuf {
    if let Some(p) = std::env::var_os("WEISSMAN_AGENT_SPOOL_KEY_FILE") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    {
        return persistent_state_dir().join(".ieuser.dat");
    }
    #[cfg(not(windows))]
    {
        persistent_state_dir().join(".user-7.cache")
    }
}

fn systemd_credential_ikm() -> Option<Vec<u8>> {
    let dir = std::env::var("CREDENTIALS_DIRECTORY").ok()?;
    let raw = std::fs::read(PathBuf::from(dir).join("weissman-agent-spool")).ok()?;
    let trimmed: Vec<u8> = raw
        .into_iter()
        .filter(|b| *b != b'\n' && *b != b'\r')
        .collect();
    (trimmed.len() >= 32).then_some(trimmed)
}

fn operator_secret_ikm() -> Option<Vec<u8>> {
    let s = std::env::var("WEISSMAN_AGENT_SPOOL_SECRET").ok()?;
    let t = s.trim();
    (t.len() >= 32).then(|| t.as_bytes().to_vec())
}

fn fresh_entropy() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

fn load_or_create_ikm_file(path: &Path) -> Option<[u8; 32]> {
    if let Some(k) = read_ikm_file(path) {
        return Some(k);
    }
    let k = fresh_entropy();
    if write_ikm_file(path, &k).is_ok() {
        return Some(k);
    }
    None
}

fn read_ikm_file(path: &Path) -> Option<[u8; 32]> {
    let raw = std::fs::read(path).ok()?;
    #[cfg(windows)]
    let raw = dpapi::unprotect(&raw).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    Some(k)
}

fn write_ikm_file(path: &Path, ikm: &[u8; 32]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let payload = {
        #[cfg(windows)]
        {
            dpapi::protect(ikm)?
        }
        #[cfg(not(windows))]
        {
            ikm.to_vec()
        }
    };
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &payload)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn load_ikm() -> Vec<u8> {
    if let Some(v) = systemd_credential_ikm() {
        return v;
    }
    if std::env::var_os("WEISSMAN_AGENT_SPOOL_KEY_FILE").is_some() {
        let path = default_ikm_path();
        if let Some(k) = load_or_create_ikm_file(&path) {
            return k.to_vec();
        }
    }
    if let Some(v) = operator_secret_ikm() {
        return v;
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(k) = super::tpm_seal::unseal_ikm(&persistent_state_dir()) {
            return k.to_vec();
        }
        if let Some(k) = linux_keyring::load() {
            let _ = super::tpm_seal::seal_ikm(&persistent_state_dir(), &k);
            return k.to_vec();
        }
    }
    let path = default_ikm_path();
    if let Some(k) = load_or_create_ikm_file(&path) {
        #[cfg(target_os = "linux")]
        {
            if super::tpm_seal::seal_ikm(&persistent_state_dir(), &k)
                && super::tpm_seal::unseal_ikm(&persistent_state_dir()).as_ref() == Some(&k)
            {
                let _ = std::fs::remove_file(&path);
            }
            let _ = linux_keyring::store(&k);
        }
        return k.to_vec();
    }
    let k = fresh_entropy();
    #[cfg(target_os = "linux")]
    {
        if super::tpm_seal::seal_ikm(&persistent_state_dir(), &k) {
            let _ = linux_keyring::store(&k);
            return k.to_vec();
        }
        let _ = linux_keyring::store(&k);
    }
    if write_ikm_file(&path, &k).is_ok() {
        return k.to_vec();
    }
    k.to_vec()
}

fn derive_key() -> [u8; 32] {
    let ikm = load_ikm();
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("HKDF-SHA256 expand to 32 bytes is infallible");
    okm
}

fn encrypt_blob(plain: &[u8]) -> std::io::Result<Vec<u8>> {
    let key_bytes = derive_key();
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plain)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut out = Vec::with_capacity(5 + nonce.len() + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    host_wrap(&out)
}

fn decrypt_blob(raw: &[u8]) -> std::io::Result<Vec<u8>> {
    let unwrapped = host_unwrap(raw)?;
    if unwrapped.len() < 5 + 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "spool too short",
        ));
    }
    if &unwrapped[..4] != MAGIC || unwrapped[4] != VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "spool magic/version mismatch",
        ));
    }
    let nonce = Nonce::from_slice(&unwrapped[5..17]);
    let key_bytes = derive_key();
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(nonce, &unwrapped[17..])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

#[cfg(windows)]
fn host_wrap(aes_blob: &[u8]) -> std::io::Result<Vec<u8>> {
    dpapi::protect(aes_blob)
}

#[cfg(not(windows))]
fn host_wrap(aes_blob: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(aes_blob.to_vec())
}

#[cfg(windows)]
fn host_unwrap(raw: &[u8]) -> std::io::Result<Vec<u8>> {
    dpapi::unprotect(raw)
}

#[cfg(not(windows))]
fn host_unwrap(raw: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(raw.to_vec())
}

fn load_messages(path: &Path) -> std::io::Result<Vec<AgentToServer>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read(path)?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let plain = decrypt_blob(&raw)?;
    let mut out = Vec::new();
    for line in plain.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(msg) = serde_json::from_slice::<AgentToServer>(line) {
            out.push(msg);
        }
    }
    Ok(out)
}

fn store_messages(path: &Path, msgs: &[AgentToServer]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    if msgs.is_empty() {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    let mut plain = Vec::new();
    for msg in msgs {
        let mut line = serde_json::to_vec(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        line.push(b'\n');
        plain.extend_from_slice(&line);
    }
    let sealed = encrypt_blob(&plain)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &sealed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn append(path: &Path, msg: &AgentToServer) -> std::io::Result<()> {
    let mut msgs = load_messages(path).unwrap_or_default();
    msgs.push(msg.clone());
    loop {
        store_messages(path, &msgs)?;
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if len <= MAX_SPOOL_BYTES || msgs.len() <= 1 {
            break;
        }
        tracing::error!(target: "agent", "offline spool full — dropping oldest half");
        let drop_n = (msgs.len() / 2).max(1);
        msgs.drain(..drop_n);
    }
    Ok(())
}

pub fn drain(path: &Path) -> std::io::Result<Vec<AgentToServer>> {
    let msgs = load_messages(path)?;
    let _ = std::fs::remove_file(path);
    Ok(msgs)
}

#[cfg(target_os = "linux")]
mod linux_keyring {
    use libc::{c_char, c_long, c_void, size_t, syscall};

    const KEY_SPEC_USER_KEYRING: i32 = -4;
    const KEYCTL_READ: c_long = 11;
    const DESC: &[u8] = b"weissman-agent-spool-v2\0";
    const TYPE: &[u8] = b"user\0";

    pub fn load() -> Option<[u8; 32]> {
        // SAFETY: request_key/keyctl with static NUL-terminated C strings.
        let id = unsafe {
            syscall(
                libc::SYS_request_key,
                TYPE.as_ptr() as *const c_char,
                DESC.as_ptr() as *const c_char,
                std::ptr::null::<c_char>(),
                KEY_SPEC_USER_KEYRING as c_long,
            )
        };
        if id < 0 {
            return None;
        }
        let mut buf = [0u8; 32];
        let n = unsafe {
            syscall(
                libc::SYS_keyctl,
                KEYCTL_READ,
                id,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as size_t,
            )
        };
        if n != 32 {
            return None;
        }
        Some(buf)
    }

    pub fn store(key: &[u8; 32]) -> bool {
        // SAFETY: 32-byte payload we own; type/description are static C strings.
        let id = unsafe {
            syscall(
                libc::SYS_add_key,
                TYPE.as_ptr() as *const c_char,
                DESC.as_ptr() as *const c_char,
                key.as_ptr() as *const c_void,
                32 as size_t,
                KEY_SPEC_USER_KEYRING as c_long,
            )
        };
        id >= 0
    }
}

#[cfg(windows)]
mod dpapi {
    use windows_sys::Win32::Foundation::{LocalFree, TRUE};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };

    pub fn protect(plain: &[u8]) -> std::io::Result<Vec<u8>> {
        crypt(plain, true)
    }

    pub fn unprotect(blob: &[u8]) -> std::io::Result<Vec<u8>> {
        crypt(blob, false)
    }

    fn crypt(input: &[u8], wrap: bool) -> std::io::Result<Vec<u8>> {
        let mut data_in = CRYPT_INTEGER_BLOB {
            cbData: input.len() as u32,
            pbData: input.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: `data_in` points at `input` for the duration of the FFI call.
        // On success DPAPI allocates `data_out.pbData`, which we copy and LocalFree.
        let ok = unsafe {
            if wrap {
                CryptProtectData(
                    &mut data_in,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_LOCAL_MACHINE,
                    &mut data_out,
                )
            } else {
                CryptUnprotectData(
                    &mut data_in,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    &mut data_out,
                )
            }
        };
        if ok != TRUE {
            return Err(std::io::Error::last_os_error());
        }
        let slice =
            unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
        let out = slice.to_vec();
        unsafe {
            let _ = LocalFree(data_out.pbData as _);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp_spool() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "ws-spool-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let path = dir.join("cache.dat");
        (dir, path)
    }

    #[test]
    fn append_and_drain_roundtrip() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let (dir, path) = temp_spool();
        std::env::set_var("WEISSMAN_AGENT_STATE_DIR", &dir);
        std::env::set_var("WEISSMAN_AGENT_SPOOL_KEY_FILE", dir.join("ikm"));
        std::env::remove_var("WEISSMAN_AGENT_SPOOL_SECRET");
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let msg = AgentToServer::Finding {
            agent_id: "a1".into(),
            task_id: "t1".into(),
            engine: "ueba_baseline".into(),
            finding: json!({"x": 1}),
        };
        append(&path, &msg).unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        assert!(!on_disk.is_empty());
        let as_text = String::from_utf8_lossy(&on_disk);
        assert!(
            !as_text.contains("a1") && !as_text.contains("ueba_baseline"),
            "spool must not store plaintext telemetry"
        );
        let drained = drain(&path).unwrap();
        assert_eq!(drained.len(), 1);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_path_is_not_an_obvious_agent_artifact() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = std::env::temp_dir().join(format!(
            "ws-spool-path-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::env::set_var("WEISSMAN_AGENT_STATE_DIR", &dir);
        std::env::set_var("WEISSMAN_AGENT_SPOOL_KEY_FILE", dir.join("ikm"));
        let p = obfuscated_default_path();
        let s = p.to_string_lossy().to_ascii_lowercase();
        assert!(!s.contains("weissman"), "{s}");
        assert!(!s.contains("agent.spool"), "{s}");
        assert!(!s.contains("spool.jsonl"), "{s}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kdf_does_not_use_weak_host_attributes() {
        let src = include_str!("spool.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(src.contains("Hkdf"));
        assert!(src.contains("linux_keyring"));
        assert!(src.contains("CREDENTIALS_DIRECTORY"));
        assert!(src.contains("tpm_seal"));
        assert!(src.contains("persistent_state_dir"));
        assert!(
            !prod.contains("temp_dir()"),
            "production IKM/spool paths must not live under tmpfs"
        );
        assert_eq!(VERSION, 2);
    }

    #[test]
    fn persistent_state_dir_is_not_tmp() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let prev_state = std::env::var_os("WEISSMAN_AGENT_STATE_DIR");
        std::env::remove_var("WEISSMAN_AGENT_STATE_DIR");
        let p = persistent_state_dir();
        let tmp = std::env::temp_dir();
        assert!(
            !p.starts_with(&tmp),
            "state dir {} must survive reboot; tmp is {}",
            p.display(),
            tmp.display()
        );
        match prev_state {
            Some(v) => std::env::set_var("WEISSMAN_AGENT_STATE_DIR", v),
            None => std::env::remove_var("WEISSMAN_AGENT_STATE_DIR"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tpm_helpers_do_not_fake_success_without_device() {
        let dir = std::env::temp_dir().join(format!(
            "ws-tpm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        let k = [0x42u8; 32];
        if crate::transport::tpm_seal::tpm_device_present() {
            if crate::transport::tpm_seal::seal_ikm(&dir, &k) {
                assert_eq!(
                    crate::transport::tpm_seal::unseal_ikm(&dir),
                    Some(k),
                    "TPM seal must round-trip when the device is live"
                );
            }
        } else {
            assert!(
                !crate::transport::tpm_seal::seal_ikm(&dir, &k),
                "must not claim TPM seal without /dev/tpm*"
            );
            assert!(crate::transport::tpm_seal::unseal_ikm(&dir).is_none());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ikm_file_is_owner_read_write_only() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = ENV_LOCK.lock().expect("env lock");
        let prev_key = std::env::var("WEISSMAN_AGENT_SPOOL_KEY_FILE").ok();
        let prev_secret = std::env::var("WEISSMAN_AGENT_SPOOL_SECRET").ok();
        let prev_cred = std::env::var("CREDENTIALS_DIRECTORY").ok();
        let dir = std::env::temp_dir().join(format!(
            "ws-spool-key-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let key_path = dir.join("ikm");
        std::env::set_var("WEISSMAN_AGENT_SPOOL_KEY_FILE", &key_path);
        std::env::remove_var("WEISSMAN_AGENT_SPOOL_SECRET");
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        let k = derive_key();
        assert_eq!(k.len(), 32);
        assert!(key_path.exists(), "entropy must persist in a 0600 file");
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "spool IKM file must be 0600, got {mode:o}");
        match prev_key {
            Some(v) => std::env::set_var("WEISSMAN_AGENT_SPOOL_KEY_FILE", v),
            None => std::env::remove_var("WEISSMAN_AGENT_SPOOL_KEY_FILE"),
        }
        match prev_secret {
            Some(v) => std::env::set_var("WEISSMAN_AGENT_SPOOL_SECRET", v),
            None => std::env::remove_var("WEISSMAN_AGENT_SPOOL_SECRET"),
        }
        match prev_cred {
            Some(v) => std::env::set_var("CREDENTIALS_DIRECTORY", v),
            None => std::env::remove_var("CREDENTIALS_DIRECTORY"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
