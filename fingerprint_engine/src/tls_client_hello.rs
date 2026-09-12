//! Parse a TLS ClientHello and compute live JA3 / JA4 fingerprints.
//!
//! Bytes come from the TLS terminator (nginx / OpenResty) via trusted-proxy
//! headers. We never invent a hash when the hello was not captured.

use axum::http::HeaderMap;
use dashmap::DashMap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::OnceLock;

use crate::http::client_ip::peer_is_trusted_proxy;
use crate::proxy_hmac::{self, ProxyTlsHeaders};

static PROXY_HELLO: OnceLock<DashMap<SocketAddr, Vec<u8>>> = OnceLock::new();

fn hello_stash() -> &'static DashMap<SocketAddr, Vec<u8>> {
    PROXY_HELLO.get_or_init(DashMap::new)
}

/// Stash raw ClientHello bytes taken from PROXY v2 TLV 0xE0 for this TCP peer.
pub fn stash_proxy_hello(peer: SocketAddr, hello: Vec<u8>) {
    if hello.is_empty() || hello.len() > 16_384 {
        return;
    }
    hello_stash().insert(peer, hello);
}

#[must_use]
pub fn peek_stashed_hello(peer: SocketAddr) -> Option<Vec<u8>> {
    hello_stash().get(&peer).map(|v| v.clone())
}

pub fn drop_stashed_hello(peer: SocketAddr) {
    hello_stash().remove(&peer);
}

const GREASE: fn(u16) -> bool = |v| {
    let hi = (v >> 8) as u8;
    let lo = v as u8;
    hi == lo && (hi & 0x0f) == 0x0a
};

#[derive(Debug, Clone, Default)]
pub struct TlsFingerprint {
    pub ja3: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja4: Option<String>,
    pub source: String,
    pub offered_ciphers: Option<String>,
    pub offered_curves: Option<String>,
    pub negotiated_protocol: Option<String>,
    pub negotiated_cipher: Option<String>,
}

impl TlsFingerprint {
    #[must_use]
    fn with_source(mut self, source: &str) -> Self {
        self.source = source.to_string();
        self
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "ja3": self.ja3,
            "ja3_string": self.ja3_raw,
            "ja4": self.ja4,
            "source": self.source,
            "offered_ciphers": self.offered_ciphers,
            "offered_curves": self.offered_curves,
            "negotiated_protocol": self.negotiated_protocol,
            "negotiated_cipher": self.negotiated_cipher,
        })
    }
}

/// Extract TLS fingerprints. HTTP `X-SSL-*` / `X-TLS-*` headers are parsed only
/// when the peer is a trusted proxy **and** `X-Weissman-Proxy-Hmac` verifies
/// against the vault/sovereign secret. PROXY v2 TLV ClientHello (TCP preface)
/// is trusted without HTTP HMAC because it is not attacker-controlled headers.
#[must_use]
pub fn from_request_headers(headers: &HeaderMap, peer: SocketAddr) -> TlsFingerprint {
    from_request_headers_inner(headers, peer, peer_is_trusted_proxy(peer), None)
}

#[must_use]
pub fn from_request_headers_inner(
    headers: &HeaderMap,
    peer: SocketAddr,
    trusted_proxy: bool,
    secret_override: Option<&[u8]>,
) -> TlsFingerprint {
    if let Some(raw) = peek_stashed_hello(peer) {
        if let Some(parsed) = parse_client_hello(&raw) {
            return parsed.with_source("proxy_protocol_tlv");
        }
    }

    let mut fp = TlsFingerprint {
        source: "not_terminated_in_app_layer".into(),
        ..TlsFingerprint::default()
    };

    if !trusted_proxy {
        return fp;
    }

    let tls_hdrs = ProxyTlsHeaders {
        client_hello_b64: hdr(headers, "x-ssl-client-hello").unwrap_or_default(),
        protocol: hdr(headers, "x-ssl-protocol").unwrap_or_default(),
        cipher: hdr(headers, "x-ssl-cipher").unwrap_or_default(),
        ciphers: hdr(headers, "x-ssl-ciphers").unwrap_or_default(),
        curves: hdr(headers, "x-ssl-curves").unwrap_or_default(),
        ja3: hdr(headers, "x-tls-ja3")
            .or_else(|| hdr(headers, "x-ssl-ja3"))
            .or_else(|| hdr(headers, "x-ja3-fingerprint"))
            .or_else(|| hdr(headers, "cf-ja3"))
            .unwrap_or_default(),
        ja4: hdr(headers, "x-tls-ja4")
            .or_else(|| hdr(headers, "x-ssl-ja4"))
            .or_else(|| hdr(headers, "x-ja4-fingerprint"))
            .unwrap_or_default(),
    };

    let hmac_raw = hdr(headers, proxy_hmac::HEADER_HMAC).unwrap_or_default();
    let ts_raw = hdr(headers, proxy_hmac::HEADER_TS).unwrap_or_default();
    let Some(secret) = secret_override
        .map(|s| s.to_vec())
        .or_else(proxy_hmac::signing_secret)
    else {
        fp.source = "proxy_hmac_secret_missing".into();
        return fp;
    };
    if hmac_raw.is_empty()
        || ts_raw.is_empty()
        || !proxy_hmac::verify(&secret, &tls_hdrs, &ts_raw, &hmac_raw)
    {
        fp.source = "proxy_hmac_rejected".into();
        return fp;
    }

    fp.negotiated_protocol = Some(tls_hdrs.protocol.clone()).filter(|s| !s.is_empty());
    fp.negotiated_cipher = Some(tls_hdrs.cipher.clone()).filter(|s| !s.is_empty());
    fp.offered_ciphers = Some(tls_hdrs.ciphers.clone()).filter(|s| !s.is_empty());
    fp.offered_curves = Some(tls_hdrs.curves.clone()).filter(|s| !s.is_empty());

    if !tls_hdrs.client_hello_b64.is_empty() {
        if let Some(parsed) = parse_client_hello_b64(&tls_hdrs.client_hello_b64) {
            let mut parsed = parsed;
            parsed.negotiated_protocol = fp.negotiated_protocol.clone();
            parsed.negotiated_cipher = fp.negotiated_cipher.clone();
            parsed.source = "raw_client_hello".into();
            return parsed;
        }
        fp.source = "client_hello_header_unparseable".into();
    }

    if !tls_hdrs.ja3.is_empty() {
        fp.ja3 = Some(tls_hdrs.ja3.to_ascii_lowercase());
        fp.source = "proxy_ja3_header".into();
    }
    if !tls_hdrs.ja4.is_empty() {
        fp.ja4 = Some(tls_hdrs.ja4.to_ascii_lowercase());
        if fp.source == "not_terminated_in_app_layer" {
            fp.source = "proxy_ja4_header".into();
        }
    }

    if fp.ja3.is_none() && fp.ja4.is_none() {
        if fp
            .offered_ciphers
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        {
            fp.source = "nginx_ssl_ciphers_incomplete".into();
        }
    }
    fp
}

fn hdr(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 16_384)
        .map(str::to_string)
}

#[must_use]
pub fn parse_client_hello_b64(b64: &str) -> Option<TlsFingerprint> {
    let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cleaned)
        .or_else(|_| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &cleaned)
        })
        .ok()?;
    parse_client_hello(&bytes)
}

#[must_use]
pub fn parse_client_hello(bytes: &[u8]) -> Option<TlsFingerprint> {
    let hello = locate_client_hello(bytes)?;
    let parsed = parse_hello_body(hello)?;
    let ja3_str = ja3_string(&parsed);
    let ja3 = md5_hex(&ja3_str);
    let ja4 = ja4_fingerprint(&parsed);
    Some(TlsFingerprint {
        ja3: Some(ja3),
        ja3_raw: Some(ja3_str),
        ja4: Some(ja4),
        source: "raw_client_hello".into(),
        offered_ciphers: Some(
            parsed
                .ciphers
                .iter()
                .map(|c| format!("{c:04x}"))
                .collect::<Vec<_>>()
                .join("-"),
        ),
        offered_curves: Some(
            parsed
                .curves
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("-"),
        ),
        negotiated_protocol: None,
        negotiated_cipher: None,
    })
}

struct Hello {
    legacy_version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    curves: Vec<u16>,
    point_formats: Vec<u8>,
    has_sni: bool,
    alpn: Vec<u8>,
    supported_versions: Vec<u16>,
    signature_algs: Vec<u16>,
}

fn locate_client_hello(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 6 {
        return None;
    }
    // TLS record: 0x16 handshake
    if bytes[0] == 0x16 && bytes.len() >= 5 {
        let rec_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        let rec = bytes.get(5..5 + rec_len.min(bytes.len().saturating_sub(5)))?;
        return handshake_body(rec);
    }
    handshake_body(bytes)
}

fn handshake_body(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 4 || bytes[0] != 0x01 {
        return None;
    }
    let len = u24(&bytes[1..4])?;
    bytes.get(4..4 + len.min(bytes.len().saturating_sub(4)))
}

fn u24(b: &[u8]) -> Option<usize> {
    (b.len() >= 3).then(|| ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
}

fn parse_hello_body(mut b: &[u8]) -> Option<Hello> {
    if b.len() < 34 {
        return None;
    }
    let legacy_version = u16::from_be_bytes([b[0], b[1]]);
    b = &b[34..]; // version + random
    let sid_len = *b.first()? as usize;
    b = b.get(1 + sid_len..)?;
    if b.len() < 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([b[0], b[1]]) as usize;
    b = b.get(2..)?;
    let cs_bytes = b.get(..cs_len)?;
    let mut ciphers = Vec::new();
    for chunk in cs_bytes.chunks_exact(2) {
        let v = u16::from_be_bytes([chunk[0], chunk[1]]);
        if !GREASE(v) {
            ciphers.push(v);
        }
    }
    b = b.get(cs_len..)?;
    let comp_len = *b.first()? as usize;
    b = b.get(1 + comp_len..)?;

    let mut extensions = Vec::new();
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();
    let mut has_sni = false;
    let mut alpn = Vec::new();
    let mut supported_versions = Vec::new();
    let mut signature_algs = Vec::new();

    if b.len() >= 2 {
        let ext_len = u16::from_be_bytes([b[0], b[1]]) as usize;
        b = b.get(2..)?;
        let mut ext = b.get(..ext_len.min(b.len()))?;
        while ext.len() >= 4 {
            let etype = u16::from_be_bytes([ext[0], ext[1]]);
            let elen = u16::from_be_bytes([ext[2], ext[3]]) as usize;
            ext = ext.get(4..)?;
            let edata = ext.get(..elen.min(ext.len()))?;
            ext = ext.get(elen.min(ext.len())..).unwrap_or(&[]);
            if GREASE(etype) {
                continue;
            }
            extensions.push(etype);
            match etype {
                0 => has_sni = true,
                10 => curves = parse_u16_list(edata),
                11 => {
                    if let Some((&n, rest)) = edata.split_first() {
                        point_formats = rest.get(..n as usize).unwrap_or(rest).to_vec();
                    }
                }
                13 => signature_algs = parse_u16_list(edata),
                16 => alpn = edata.to_vec(),
                43 => supported_versions = parse_supported_versions(edata),
                _ => {}
            }
        }
    }

    Some(Hello {
        legacy_version,
        ciphers,
        extensions,
        curves: curves.into_iter().filter(|v| !GREASE(*v)).collect(),
        point_formats,
        has_sni,
        alpn,
        supported_versions,
        signature_algs: signature_algs.into_iter().filter(|v| !GREASE(*v)).collect(),
    })
}

fn parse_u16_list(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    let bytes = data.get(2..2 + n).unwrap_or(&data[2..]);
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !GREASE(*v))
        .collect()
}

fn parse_supported_versions(data: &[u8]) -> Vec<u16> {
    if data.is_empty() {
        return Vec::new();
    }
    let n = data[0] as usize;
    let bytes = data.get(1..1 + n).unwrap_or(&data[1..]);
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !GREASE(*v))
        .collect()
}

fn ja3_string(h: &Hello) -> String {
    let ciphers = join_u16(&h.ciphers);
    let exts = join_u16(&h.extensions);
    let curves = join_u16(&h.curves);
    let pf = h
        .point_formats
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "{},{},{},{},{}",
        h.legacy_version, ciphers, exts, curves, pf
    )
}

fn join_u16(v: &[u16]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn ja4_fingerprint(h: &Hello) -> String {
    let ver = ja4_version(h);
    let sni = if h.has_sni { 'd' } else { 'i' };
    let ccount = (h.ciphers.len().min(99)) as u8;
    let ecount = (h.extensions.len().min(99)) as u8;
    let alpn = ja4_alpn(&h.alpn);
    let a = format!("t{ver}{sni}{ccount:02}{ecount:02}{alpn}");

    let mut cipher_hex: Vec<String> = h.ciphers.iter().map(|c| format!("{c:04x}")).collect();
    cipher_hex.sort();
    let b = sha256_12(&cipher_hex.join(","));

    let mut ext_hex: Vec<String> = h
        .extensions
        .iter()
        .filter(|e| **e != 0 && **e != 16) // SNI + ALPN omitted from ja4_c per spec
        .map(|e| format!("{e:04x}"))
        .collect();
    ext_hex.sort();
    let sig = h
        .signature_algs
        .iter()
        .map(|s| format!("{s:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let c_payload = if sig.is_empty() {
        ext_hex.join(",")
    } else {
        format!("{}_{sig}", ext_hex.join(","))
    };
    let c = sha256_12(&c_payload);
    format!("{a}_{b}_{c}")
}

fn ja4_version(h: &Hello) -> &'static str {
    let v = h
        .supported_versions
        .iter()
        .copied()
        .max()
        .unwrap_or(h.legacy_version);
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn ja4_alpn(raw: &[u8]) -> String {
    // ALPN ext: uint16 list_len, then (len, bytes)+
    let list = if raw.len() >= 2 {
        let n = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        raw.get(2..2 + n).unwrap_or(&raw[2..])
    } else {
        raw
    };
    if list.is_empty() {
        return "00".into();
    }
    let n = list[0] as usize;
    let proto = list.get(1..1 + n).unwrap_or(&[]);
    let chars: Vec<char> = proto
        .iter()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| *b as char)
        .collect();
    match chars.len() {
        0 => "00".into(),
        1 => format!("{}{}", chars[0], chars[0]),
        _ => format!("{}{}", chars[0], chars[chars.len() - 1]),
    }
}

fn md5_hex(s: &str) -> String {
    match openssl::hash::hash(openssl::hash::MessageDigest::md5(), s.as_bytes()) {
        Ok(d) => hex::encode(d),
        Err(_) => String::new(),
    }
}

fn sha256_12(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(&h.finalize()[..])[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_tls12_one_cipher() -> Vec<u8> {
        // Handshake ClientHello, TLS 1.2, one cipher 0x002f, no session, null compression, no ext.
        let mut h = Vec::new();
        h.extend_from_slice(&[0x03, 0x03]); // version
        h.extend_from_slice(&[0u8; 32]); // random
        h.push(0); // session id
        h.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // ciphers
        h.extend_from_slice(&[0x01, 0x00]); // compression
        h.extend_from_slice(&[0x00, 0x00]); // extensions empty
        let mut rec = vec![0x01, 0x00, 0x00, h.len() as u8];
        rec.extend(h);
        rec
    }

    #[test]
    fn ja3_from_minimal_hello() {
        let fp = parse_client_hello(&hello_tls12_one_cipher()).expect("parse");
        assert_eq!(fp.source, "raw_client_hello");
        assert_eq!(fp.ja3_raw.as_deref(), Some("771,47,,,"));
        assert_eq!(fp.ja3.as_deref(), Some(md5_hex("771,47,,,").as_str()));
        assert!(fp.ja4.as_ref().unwrap().starts_with("t12i"));
    }

    #[test]
    fn grease_cipher_is_stripped() {
        let mut h = Vec::new();
        h.extend_from_slice(&[0x03, 0x03]);
        h.extend_from_slice(&[0u8; 32]);
        h.push(0);
        h.extend_from_slice(&[0x00, 0x04, 0x0a, 0x0a, 0x00, 0x2f]); // GREASE + 0x002f
        h.extend_from_slice(&[0x01, 0x00]);
        h.extend_from_slice(&[0x00, 0x00]);
        let mut rec = vec![0x01, 0x00, 0x00, h.len() as u8];
        rec.extend(h);
        let fp = parse_client_hello(&rec).unwrap();
        assert_eq!(fp.ja3_raw.as_deref(), Some("771,47,,,"));
    }

    #[test]
    fn untrusted_peer_ignores_spoofed_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tls-ja3", "deadbeef".parse().unwrap());
        let peer: SocketAddr = "203.0.113.9:443".parse().unwrap();
        // Default: WEISSMAN_TRUST_PROXY_HEADERS unset → not trusted.
        let fp = from_request_headers(&headers, peer);
        assert!(fp.ja3.is_none());
        assert_eq!(fp.source, "not_terminated_in_app_layer");
    }

    #[test]
    fn garbage_hello_does_not_panic() {
        assert!(parse_client_hello(&[0, 1, 2, 3]).is_none());
        assert!(parse_client_hello_b64("@@@").is_none());
    }

    #[test]
    fn trusted_peer_unsigned_hello_is_rejected() {
        let hello = hello_tls12_one_cipher();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &hello);
        let mut headers = HeaderMap::new();
        headers.insert("x-ssl-client-hello", b64.parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let secret = b"sovereign-proxy-hmac-secret-32bytes!!";
        let fp = from_request_headers_inner(&headers, peer, true, Some(secret));
        assert!(fp.ja3.is_none());
        assert_eq!(fp.source, "proxy_hmac_rejected");
    }

    #[test]
    fn trusted_peer_signed_hello_parses_ja3() {
        let hello = hello_tls12_one_cipher();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &hello);
        let secret = b"sovereign-proxy-hmac-secret-32bytes!!";
        let ts = crate::proxy_hmac::now_unix();
        let tls = crate::proxy_hmac::ProxyTlsHeaders {
            client_hello_b64: b64.clone(),
            protocol: "TLSv1.2".into(),
            cipher: String::new(),
            ciphers: String::new(),
            curves: String::new(),
            ja3: String::new(),
            ja4: String::new(),
        };
        let mac = crate::proxy_hmac::sign_hex(secret, &tls.canonical_v1(ts)).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-ssl-client-hello", b64.parse().unwrap());
        headers.insert("x-ssl-protocol", "TLSv1.2".parse().unwrap());
        headers.insert("x-weissman-proxy-ts", ts.to_string().parse().unwrap());
        headers.insert("x-weissman-proxy-hmac", mac.parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let fp = from_request_headers_inner(&headers, peer, true, Some(secret));
        assert_eq!(fp.source, "raw_client_hello");
        assert_eq!(fp.ja3_raw.as_deref(), Some("771,47,,,"));
        assert!(fp.ja3.is_some());
    }

    #[test]
    fn proxy_tlv_stash_yields_ja3_for_untrusted_http_peer() {
        let peer: SocketAddr = "203.0.113.44:54321".parse().unwrap();
        stash_proxy_hello(peer, hello_tls12_one_cipher());
        let fp = from_request_headers(&HeaderMap::new(), peer);
        drop_stashed_hello(peer);
        assert_eq!(fp.source, "proxy_protocol_tlv");
        assert_eq!(fp.ja3_raw.as_deref(), Some("771,47,,,"));
        assert!(fp.ja3.is_some());
    }
}
