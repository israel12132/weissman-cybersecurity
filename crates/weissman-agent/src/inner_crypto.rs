//! Inner AES-256-GCM layer for WSS frames (mirrors server elite_hardening::wss_inner).
//! Hello stays plaintext; wrapping starts after Welcome carries `inner_key_hex`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

const VERSION: u8 = 1;
static NONCE_CTR: AtomicU64 = AtomicU64::new(1);

fn next_nonce() -> [u8; 12] {
    let n = NONCE_CTR.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&n.to_le_bytes());
    nonce_bytes[8..12].copy_from_slice(&nanos.to_le_bytes()[..4]);
    nonce_bytes
}

pub fn wrap(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce_bytes = next_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "_wss": VERSION,
        "n": hex::encode(nonce_bytes),
        "c": hex::encode(ct),
    })
    .to_string())
}

pub fn unwrap_or_plain(key: Option<&[u8; 32]>, frame: &str) -> Result<String, String> {
    let trimmed = frame.trim();
    if !trimmed.starts_with('{') {
        return Ok(frame.to_string());
    }
    let v: Value = serde_json::from_str(trimmed).unwrap_or(Value::Null);
    if v.get("_wss").is_none() {
        return Ok(frame.to_string());
    }
    let Some(k) = key else {
        return Err("inner-crypto frame without session key".into());
    };
    let n = v.get("n").and_then(Value::as_str).ok_or("missing nonce")?;
    let c = v
        .get("c")
        .and_then(Value::as_str)
        .ok_or("missing ciphertext")?;
    let nonce_bytes = hex::decode(n).map_err(|e| e.to_string())?;
    if nonce_bytes.len() != 12 {
        return Err("nonce must be 12 bytes".into());
    }
    let ct = hex::decode(c).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new_from_slice(k).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|e| e.to_string())?;
    String::from_utf8(pt).map_err(|e| e.to_string())
}

pub fn key_from_hex(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_roundtrip() {
        let key = [7u8; 32];
        let wrapped = wrap(&key, r#"{"type":"heartbeat"}"#).unwrap();
        let plain = unwrap_or_plain(Some(&key), &wrapped).unwrap();
        assert_eq!(plain, r#"{"type":"heartbeat"}"#);
        assert!(!wrapped.contains("heartbeat"));
    }

    #[test]
    fn hello_stays_plain() {
        let hello = r#"{"type":"hello","agent_id":"a"}"#;
        assert_eq!(unwrap_or_plain(None, hello).unwrap(), hello);
    }
}
