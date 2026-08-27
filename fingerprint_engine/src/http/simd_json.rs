//! SIMD-accelerated JSON for the Axum **ingest / telemetry** path (sonic-rs).
//!
//! Engines and reports stay on `serde_json`: their serialize time is negligible
//! next to probe/DB work, and complex schemas stay compatible. `serde_json`
//! remains the crate-wide `Value` / `json!` type.

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// Parse `T` from JSON bytes with sonic-rs (SIMD). Falls back to serde_json so
/// unusual serde attributes still decode if the SIMD parser rejects them.
pub fn from_slice<'a, T>(buf: &'a [u8]) -> Result<T, String>
where
    T: Deserialize<'a>,
{
    match sonic_rs::from_slice::<T>(buf) {
        Ok(v) => Ok(v),
        Err(simd_err) => serde_json::from_slice::<T>(buf)
            .map_err(|e| format!("json: simd={simd_err}; serde_json={e}")),
    }
}

/// Parse an owned type (no borrows into `buf`).
pub fn from_slice_owned<T: DeserializeOwned>(buf: &[u8]) -> Result<T, String> {
    from_slice(buf)
}

/// SIMD serialize. Falls back to serde_json when sonic-rs cannot encode `T`.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    match sonic_rs::to_vec(value) {
        Ok(v) => Ok(v),
        Err(simd_err) => serde_json::to_vec(value)
            .map_err(|e| format!("json encode: simd={simd_err}; serde_json={e}")),
    }
}

/// SIMD serialize to UTF-8 string.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, String> {
    match sonic_rs::to_string(value) {
        Ok(s) => Ok(s),
        Err(simd_err) => serde_json::to_string(value)
            .map_err(|e| format!("json encode: simd={simd_err}; serde_json={e}")),
    }
}

/// Convenience: SIMD-parse a `serde_json::Value` from a UTF-8 slice.
pub fn parse_value(raw: &str) -> Result<Value, String> {
    from_slice_owned(raw.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::borrow::Cow;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Borrowed<'a> {
        #[serde(borrow)]
        agent_id: Cow<'a, str>,
        client_id: i64,
    }

    #[test]
    fn simd_roundtrip_object() {
        let v = serde_json::json!({"ok": true, "n": 7, "s": "ueba"});
        let bytes = to_vec(&v).expect("encode");
        let back: Value = from_slice_owned(&bytes).expect("decode");
        assert_eq!(back["n"], 7);
        assert_eq!(back["s"], "ueba");
    }

    #[test]
    fn borrow_agent_id_from_buffer() {
        let raw = br#"{"agent_id":"agent-zero-copy","client_id":42}"#;
        let parsed: Borrowed<'_> = from_slice(raw).expect("borrow parse");
        assert_eq!(parsed.agent_id.as_ref(), "agent-zero-copy");
        assert_eq!(parsed.client_id, 42);
        assert!(
            matches!(parsed.agent_id, Cow::Borrowed(_)),
            "unescaped JSON string must borrow from the input buffer"
        );
    }

    #[test]
    fn invalid_json_is_err() {
        assert!(from_slice_owned::<Value>(b"{").is_err());
    }
}
