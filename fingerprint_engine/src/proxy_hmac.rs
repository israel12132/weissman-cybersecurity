//! Short-lived HMAC over TLS fingerprint headers forwarded by nginx/OpenResty.
//!
//! Unsigned `X-SSL-Client-Hello` / JA3 headers are attacker-controlled if the
//! client can reach Axum directly. Axum parses those headers only when
//! `X-Weissman-Proxy-Hmac` verifies against the vault/sovereign secret.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub const HEADER_HMAC: &str = "x-weissman-proxy-hmac";
pub const HEADER_TS: &str = "x-weissman-proxy-ts";
/// Replay window for the proxy timestamp (seconds).
pub const MAX_SKEW_SECS: i64 = 30;

#[derive(Debug, Clone)]
pub struct ProxyTlsHeaders {
    pub client_hello_b64: String,
    pub protocol: String,
    pub cipher: String,
    pub ciphers: String,
    pub curves: String,
    pub ja3: String,
    pub ja4: String,
}

impl ProxyTlsHeaders {
    #[must_use]
    pub fn canonical_v1(&self, ts: i64) -> String {
        format!(
            "v1\n{ts}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.client_hello_b64.trim(),
            self.protocol.trim(),
            self.cipher.trim(),
            self.ciphers.trim(),
            self.curves.trim(),
            self.ja3.trim(),
            self.ja4.trim()
        )
    }
}

/// Dedicated proxy HMAC, then vault key, then JWT (last-resort, warned once).
#[must_use]
pub fn signing_secret() -> Option<Vec<u8>> {
    static WARNED: OnceLock<()> = OnceLock::new();
    if let Some(s) = env_nonempty("WEISSMAN_PROXY_HMAC_SECRET") {
        return Some(s.into_bytes());
    }
    if let Some(s) = env_nonempty("WEISSMAN_VAULT_KEY") {
        return Some(s.into_bytes());
    }
    let jwt = env_nonempty("WEISSMAN_JWT_SECRET")?;
    WARNED.get_or_init(|| {
        tracing::warn!(
            target: "proxy_hmac",
            "WEISSMAN_PROXY_HMAC_SECRET unset — falling back to WEISSMAN_JWT_SECRET for TLS header HMAC. \
             Set a dedicated proxy HMAC so nginx signatures are isolated from auth tokens."
        );
    });
    Some(jwt.into_bytes())
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[must_use]
pub fn sign_hex(secret: &[u8], canonical: &str) -> Option<String> {
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(canonical.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

#[must_use]
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Constant-time verify of hex (or base64) HMAC + timestamp skew.
#[must_use]
pub fn verify(secret: &[u8], headers: &ProxyTlsHeaders, ts_raw: &str, hmac_raw: &str) -> bool {
    let ts: i64 = ts_raw.trim().parse().ok().filter(|t| *t > 0).unwrap_or(0);
    if ts == 0 {
        return false;
    }
    let now = now_unix();
    if (now - ts).abs() > MAX_SKEW_SECS {
        return false;
    }
    let Some(expected) = sign_hex(secret, &headers.canonical_v1(ts)) else {
        return false;
    };
    let got = hmac_raw.trim();
    if let Ok(got_bytes) = hex::decode(got) {
        if let Ok(exp_bytes) = hex::decode(&expected) {
            return constant_eq(&got_bytes, &exp_bytes);
        }
    }
    // Accept URL-safe base64 HMAC from njs/lua variants.
    if let Ok(got_bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, got)
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, got))
    {
        if let Ok(exp_bytes) = hex::decode(&expected) {
            return constant_eq(&got_bytes, &exp_bytes);
        }
    }
    false
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers() -> ProxyTlsHeaders {
        ProxyTlsHeaders {
            client_hello_b64: "AAAA".into(),
            protocol: "TLSv1.3".into(),
            cipher: "TLS_AES_256_GCM_SHA384".into(),
            ciphers: "c1".into(),
            curves: "X25519".into(),
            ja3: String::new(),
            ja4: String::new(),
        }
    }

    #[test]
    fn round_trip_hmac() {
        let secret = b"sovereign-proxy-hmac-secret-32bytes!!";
        let ts = 1_700_000_000;
        let h = headers();
        let mac = sign_hex(secret, &h.canonical_v1(ts)).unwrap();
        // Pin time by using ts within skew of now — use now_unix for verify.
        let ts_now = now_unix();
        let mac_now = sign_hex(secret, &h.canonical_v1(ts_now)).unwrap();
        assert!(verify(secret, &h, &ts_now.to_string(), &mac_now));
        assert!(!verify(secret, &h, &ts.to_string(), &mac)); // 2023 timestamp is stale
        assert!(!verify(secret, &h, &ts_now.to_string(), "deadbeef"));
    }

    #[test]
    fn tampered_hello_fails() {
        let secret = b"sovereign-proxy-hmac-secret-32bytes!!";
        let ts = now_unix();
        let mut h = headers();
        let mac = sign_hex(secret, &h.canonical_v1(ts)).unwrap();
        h.client_hello_b64 = "BBBB".into();
        assert!(!verify(secret, &h, &ts.to_string(), &mac));
    }
}
