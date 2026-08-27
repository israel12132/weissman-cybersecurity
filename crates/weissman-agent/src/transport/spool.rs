//! Encrypted disk spool for findings / task completions when the WebSocket is down.
//!
//! The agent otherwise aims for a near-zero disk footprint. Offline telemetry is
//! written under an innocuous temp-cache name and sealed with AES-256-GCM using a
//! key derived from host identity. On Windows the ciphertext is additionally wrapped
//! with DPAPI (`CryptProtectData` / `CRYPTPROTECT_LOCAL_MACHINE`).

use crate::protocol::AgentToServer;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_SPOOL_BYTES: u64 = 32 * 1024 * 1024;
const MAGIC: &[u8; 4] = b"CACH";
const VERSION: u8 = 1;

#[must_use]
pub fn spool_path() -> PathBuf {
    if let Some(p) = std::env::var_os("WEISSMAN_AGENT_SPOOL_FILE") {
        return PathBuf::from(p);
    }
    obfuscated_default_path()
}

fn obfuscated_default_path() -> PathBuf {
    let token = hex::encode(&derive_key()[..16]);
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        return base
            .join("Microsoft")
            .join("Windows")
            .join("INetCache")
            .join("IE")
            .join(&token[..8.min(token.len())])
            .join(format!("{token}.dat"));
    }
    #[cfg(not(windows))]
    {
        std::env::temp_dir()
            .join(".cache")
            .join("fontconfig")
            .join(format!("{token}.cache-7"))
    }
}

fn host_key_material() -> Vec<u8> {
    let mut ikm = Vec::new();
    #[cfg(unix)]
    {
        if let Ok(id) = std::fs::read("/etc/machine-id") {
            ikm.extend_from_slice(&id);
        }
        if let Ok(uuid) = std::fs::read("/sys/class/dmi/id/product_uuid") {
            ikm.extend_from_slice(&uuid);
        }
    }
    if let Ok(h) = hostname::get() {
        if let Ok(s) = h.into_string() {
            ikm.extend_from_slice(s.as_bytes());
        }
    }
    if let Ok(extra) = std::env::var("WEISSMAN_AGENT_SPOOL_SECRET") {
        ikm.extend_from_slice(extra.as_bytes());
    }
    if ikm.is_empty() {
        ikm.extend_from_slice(b"spool-fallback");
    }
    ikm
}

fn derive_key() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ws-agent-spool-v1");
    h.update(&host_key_material());
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
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
    dpapi::protect(aes_blob).or_else(|_| Ok(aes_blob.to_vec()))
}

#[cfg(not(windows))]
fn host_wrap(aes_blob: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(aes_blob.to_vec())
}

#[cfg(windows)]
fn host_unwrap(raw: &[u8]) -> std::io::Result<Vec<u8>> {
    dpapi::unprotect(raw).or_else(|_| Ok(raw.to_vec()))
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

    fn temp_spool() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("ws-spool-{}", std::process::id()));
        let path = dir.join("cache.dat");
        (dir, path)
    }

    #[test]
    fn append_and_drain_roundtrip() {
        let (dir, path) = temp_spool();
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
        let p = obfuscated_default_path();
        let s = p.to_string_lossy().to_ascii_lowercase();
        assert!(!s.contains("weissman"), "{s}");
        assert!(!s.contains("agent.spool"), "{s}");
        assert!(!s.contains("spool.jsonl"), "{s}");
    }
}
