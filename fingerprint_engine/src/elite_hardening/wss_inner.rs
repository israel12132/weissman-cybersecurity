//! Inner AES-256-GCM layer for agent WSS frames.
//!
//! TLS already protects the socket. This second layer keeps telemetry opaque if a
//! middlebox terminates TLS (corporate MitM). Hello remains plaintext JSON so
//! older agents interoperate; wrapping starts after Welcome carries `inner_key_b64`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use serde_json::{json, Value};

pub const ALGO: &str = "AES-256-GCM";
pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
const VERSION: u8 = 1;

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for b in key.iter_mut() {
        *b = rand::random_range(0u8..=255);
    }
    key
}

pub fn wrap(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    for b in nonce_bytes.iter_mut() {
        *b = rand::random_range(0u8..=255);
    }
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

pub fn unwrap_frame(key: &[u8; 32], frame: &str) -> Result<String, String> {
    let v: Value = serde_json::from_str(frame).map_err(|e| e.to_string())?;
    if v.get("_wss").and_then(Value::as_u64) != Some(VERSION as u64) {
        return Err("not inner-crypto frame".into());
    }
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
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|e| e.to_string())?;
    String::from_utf8(pt).map_err(|e| e.to_string())
}

/// If the frame is inner-crypto, decrypt; otherwise return the original (compat).
pub fn unwrap_or_plain(key: Option<&[u8; 32]>, frame: &str) -> Result<String, String> {
    let trimmed = frame.trim();
    if !trimmed.starts_with('{') {
        return Ok(frame.to_string());
    }
    let v: Value = serde_json::from_str(trimmed).unwrap_or(Value::Null);
    if v.get("_wss").is_some() {
        let Some(k) = key else {
            return Err("inner-crypto frame without session key".into());
        };
        return unwrap_frame(k, trimmed);
    }
    Ok(frame.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = generate_key();
        let wrapped = wrap(&key, r#"{"type":"heartbeat"}"#).unwrap();
        let plain = unwrap_frame(&key, &wrapped).unwrap();
        assert_eq!(plain, r#"{"type":"heartbeat"}"#);
        assert!(wrapped.contains("_wss"));
        assert!(!wrapped.contains("heartbeat"));
    }

    #[test]
    fn plaintext_passthrough() {
        let s = r#"{"type":"hello","agent_id":"x"}"#;
        assert_eq!(unwrap_or_plain(None, s).unwrap(), s);
    }

    #[test]
    fn wrapped_without_key_fails_closed() {
        let key = generate_key();
        let wrapped = wrap(&key, "{}").unwrap();
        assert!(unwrap_or_plain(None, &wrapped).is_err());
    }
}
