//! S7CommPlus structural telemetry — no Siemens keys, no ciphertext decrypt.
//!
//! S7-Plus wraps ISO-on-TCP in vendor crypto. We never attempt to recover
//! session keys. Instead we score entropy, PDU size, and nonce-like 32-bit
//! cadence so firmware swaps and session hijacks still surface as anomalies.

use serde::Serialize;

/// S7CommPlus magic after COTP userdata.
pub const S7PLUS_MAGIC: u8 = 0x72;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct S7PlusTelemetry {
    pub entropy_bits: f64,
    pub len: usize,
    pub suspected_s7plus: bool,
    pub high_entropy: bool,
    pub nonce: Option<u32>,
    pub nonce_jump: Option<i64>,
    pub size_class: &'static str,
}

#[must_use]
pub fn shannon_entropy(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for &b in buf {
        hist[b as usize] += 1;
    }
    let n = buf.len() as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[must_use]
pub fn extract_nonce_candidate(buf: &[u8]) -> Option<u32> {
    if buf.len() < 8 {
        return None;
    }
    // S7-Plus places a rolling 32-bit field after the 0x72 + version byte.
    let off = if buf[0] == S7PLUS_MAGIC { 4 } else { 0 };
    if off + 4 > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

#[must_use]
pub fn size_class(len: usize) -> &'static str {
    match len {
        0..=16 => "tiny",
        17..=64 => "handshake",
        65..=256 => "session",
        257..=1024 => "bulk",
        _ => "jumbo",
    }
}

#[must_use]
pub fn inspect(userdata: &[u8], prev_nonce: Option<u32>) -> S7PlusTelemetry {
    let entropy_bits = shannon_entropy(userdata);
    let suspected =
        userdata.first() == Some(&S7PLUS_MAGIC) || (userdata.len() >= 32 && entropy_bits > 7.2);
    let nonce = extract_nonce_candidate(userdata);
    let nonce_jump = match (prev_nonce, nonce) {
        (Some(p), Some(n)) => Some(i64::from(n) - i64::from(p)),
        _ => None,
    };
    S7PlusTelemetry {
        high_entropy: entropy_bits > 7.2,
        entropy_bits,
        len: userdata.len(),
        suspected_s7plus: suspected,
        nonce,
        nonce_jump,
        size_class: size_class(userdata.len()),
    }
}

#[must_use]
pub fn nonce_cadence_anomaly(jump: i64) -> bool {
    // Monotonic +1/+2 is healthy. A jump > 8 or a rewind is a session splice.
    jump.abs() > 8 || jump < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_have_zero_entropy() {
        assert_eq!(shannon_entropy(&[0, 0, 0, 0]), 0.0);
    }

    #[test]
    fn mixed_bytes_have_positive_entropy() {
        let e = shannon_entropy(&[0x00, 0xFF, 0xAA, 0x55]);
        assert!(e > 1.0);
    }

    #[test]
    fn s7plus_magic_is_flagged() {
        let mut buf = vec![S7PLUS_MAGIC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        buf.extend_from_slice(&[7u8; 40]);
        let t = inspect(&buf, Some(4));
        assert!(t.suspected_s7plus);
        assert_eq!(t.nonce, Some(5));
        assert_eq!(t.nonce_jump, Some(1));
        assert!(!nonce_cadence_anomaly(t.nonce_jump.unwrap()));
    }

    #[test]
    fn nonce_rewind_is_anomaly() {
        assert!(nonce_cadence_anomaly(-3));
        assert!(nonce_cadence_anomaly(64));
        assert!(!nonce_cadence_anomaly(1));
    }
}
