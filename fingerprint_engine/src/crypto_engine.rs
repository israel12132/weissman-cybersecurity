//! Module 1: Immutable Audit Trail & RFC 3161-style cryptographic signing.
//! Audit root hash from live DB findings; PKCS#7 signing; QR proof generation.
//!
//! Crypto posture engine: live TLS handshakes, HTTP secret leakage, cookie/JWT surface,
//! and predictable nonce detection — evidence-bearing findings only.

use crate::arsenal_config::{finding_rich, Evidence};
use crate::engine_probes::{detect_secrets, extract_host, header_value, http_get, normalize_url};
use crate::engine_result::EngineResult;
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine,
};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs7::Pkcs7Flags;
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use openssl::x509::{X509Ref, X509VerifyResult, X509};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

const ENGINE_ID: &str = "crypto_engine";
const MITRE_CRYPTO: &str = "T1600";
const MITRE_MITM: &str = "T1557";
const LEGACY_CIPHER_LIST: &str = "ALL:COMPLEMENTOFALL:@SECLEVEL=0";
const GRADE_LADDER: &[&str] = &["A", "B", "C", "D", "E", "F"];

/// One row from vulnerabilities for canonical serialization (live data only).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditFindingRow {
    pub id: i64,
    pub run_id: i64,
    pub client_id: String,
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub status: String,
    pub discovered_at: String,
}

/// Compute the Audit Root Hash (SHA-256) from live findings. Deterministic canonical JSON (sorted by id).
pub fn compute_audit_root_hash(findings: &[AuditFindingRow]) -> String {
    let mut sorted: Vec<_> = findings.to_vec();
    sorted.sort_by_key(|r| r.id);
    let canonical = serde_json::to_string(&sorted).unwrap_or_else(|e| {
        tracing::error!(target: "security_audit", error = %e, "audit findings JSON serialize failed; using empty array");
        "[]".to_string()
    });
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex_encode(&hasher.finalize())
}

/// Hex encode for audit hash (no external crate if we use a tiny hex).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// Re-export for callers that already have digest bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

/// Generate a self-signed X.509 certificate and private key, save to disk. Returns (cert_path, key_path).
pub fn ensure_self_signed_cert(
    cert_dir: &Path,
) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    let cert_path = cert_dir.join("weissman_audit.crt");
    let key_path = cert_dir.join("weissman_audit.key");
    if cert_path.exists() && key_path.exists() {
        return Ok((cert_path, key_path));
    }
    std::fs::create_dir_all(cert_dir).map_err(|e| e.to_string())?;
    let rsa = openssl::rsa::Rsa::generate(2048).map_err(|e| e.to_string())?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| e.to_string())?;
    let mut builder = openssl::x509::X509Builder::new().map_err(|e| e.to_string())?;
    builder.set_version(2).map_err(|e| e.to_string())?;
    let serial = openssl::bn::BigNum::from_u32(1).map_err(|e| e.to_string())?;
    let serial = openssl::asn1::Asn1Integer::from_bn(&serial).map_err(|e| e.to_string())?;
    builder
        .set_serial_number(&serial)
        .map_err(|e| e.to_string())?;
    builder.set_pubkey(&pkey).map_err(|e| e.to_string())?;
    let not_before = openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(365 * 10).map_err(|e| e.to_string())?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| e.to_string())?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| e.to_string())?;
    let name = {
        let mut n = openssl::x509::X509NameBuilder::new().map_err(|e| e.to_string())?;
        n.append_entry_by_text("CN", "Weissman Audit Signer")
            .map_err(|e| e.to_string())?;
        n.append_entry_by_text("O", "Weissman Cybersecurity")
            .map_err(|e| e.to_string())?;
        n.build()
    };
    builder.set_subject_name(&name).map_err(|e| e.to_string())?;
    builder.set_issuer_name(&name).map_err(|e| e.to_string())?;
    builder
        .sign(&pkey, MessageDigest::sha256())
        .map_err(|e| e.to_string())?;
    let cert = builder.build();
    let cert_pem = cert.to_pem().map_err(|e| e.to_string())?;
    let key_pem = pkey.private_key_to_pem_pkcs8().map_err(|e| e.to_string())?;
    std::fs::write(&cert_path, &cert_pem).map_err(|e| e.to_string())?;
    std::fs::write(&key_path, &key_pem).map_err(|e| e.to_string())?;
    Ok((cert_path, key_path))
}

/// Sign the audit root hash (or any payload) with PKCS#7 detached. Returns PEM or DER base64.
pub fn sign_audit_hash_pkcs7(
    payload: &[u8],
    cert_path: &Path,
    key_path: &Path,
) -> Result<String, String> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| e.to_string())?;
    let key_pem = std::fs::read(key_path).map_err(|e| e.to_string())?;
    let cert = X509::from_pem(&cert_pem).map_err(|e| e.to_string())?;
    let pkey = PKey::private_key_from_pem(&key_pem).map_err(|e| e.to_string())?;
    let mut certs = openssl::stack::Stack::new().map_err(|e| e.to_string())?;
    certs.push(cert.clone()).map_err(|e| e.to_string())?;
    let pkcs7 = openssl::pkcs7::Pkcs7::sign(&cert, &pkey, &certs, payload, Pkcs7Flags::DETACHED)
        .map_err(|e| e.to_string())?;
    let der = pkcs7.to_der().map_err(|e| e.to_string())?;
    Ok(BASE64.encode(&der))
}

/// Build verification URL for the audit root hash (e.g. /api/verify-audit/{hash}).
pub fn verification_url_for_hash(base_url: &str, hash: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{}/api/verify-audit/{}", base, hash)
}

/// Generate QR code containing payload; return SVG as Base64 data URL (works in all browsers).
pub fn qr_code_base64_svg(payload: &str) -> Result<String, String> {
    use qrcode::render::svg;
    let qr = qrcode::QrCode::new(payload.as_bytes()).map_err(|e| e.to_string())?;
    let svg_str = qr
        .render::<svg::Color>()
        .quiet_zone(true)
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        BASE64.encode(svg_str.as_bytes())
    ))
}

/// Combined: payload string for QR (hash + verification URL), then SVG base64.
pub fn qr_code_for_audit(base_url: &str, audit_root_hash: &str) -> Result<String, String> {
    let url = verification_url_for_hash(base_url, audit_root_hash);
    let payload = format!("HASH:{}\nVERIFY:{}", audit_root_hash, url);
    qr_code_base64_svg(&payload)
}

// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic posture engine (live probes)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct LeafCertInfo {
    subject: String,
    issuer: String,
    common_name: Option<String>,
    self_signed: bool,
    not_after: String,
    expired: bool,
    days_until_expiry: i64,
    key_type: String,
    key_bits: u32,
    sig_algo: String,
    sig_weak: bool,
    san: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CertWeakness {
    WeakSigSha1,
    RsaKeyTooSmall,
    EcKeyTooSmall,
    Expired,
    HostnameMismatch,
    SelfSigned,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct JwtSurfaceIssues {
    alg_none: bool,
    hs256_with_kid: bool,
    missing_exp: bool,
    alg: String,
}

#[derive(Clone, Debug, Default)]
struct PostureScores {
    tls: u8,
    secrets: u8,
    cookies: u8,
    jwt: u8,
}

#[derive(Clone, Debug, Default)]
struct TlsProbeResult {
    reachable: bool,
    negotiated_version: String,
    cipher: String,
    cipher_bits: u32,
    chain: Vec<LeafCertInfo>,
    verify_ok: bool,
    verify_msg: String,
    tls10_enabled: bool,
    tls11_enabled: bool,
}

#[derive(Clone, Debug, Default)]
struct HstsInfo {
    present: bool,
    max_age: Option<u64>,
    include_subdomains: bool,
    preload: bool,
    strong: bool,
}

fn score_to_grade(score: u8) -> &'static str {
    match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        50..=59 => "E",
        _ => "F",
    }
}

fn worse_grade(a: &str, b: &str) -> &'static str {
    let rank = |g: &str| {
        GRADE_LADDER
            .iter()
            .position(|x| *x == g)
            .unwrap_or(GRADE_LADDER.len() - 1)
    };
    let idx = rank(a).max(rank(b));
    GRADE_LADDER[idx.min(GRADE_LADDER.len() - 1)]
}

fn classify_cert_weaknesses(cert: &LeafCertInfo, host: &str) -> Vec<CertWeakness> {
    let mut out = Vec::new();
    if cert.sig_weak {
        out.push(CertWeakness::WeakSigSha1);
    }
    if cert.key_type == "RSA" && cert.key_bits < 2048 {
        out.push(CertWeakness::RsaKeyTooSmall);
    }
    if cert.key_type == "EC" && cert.key_bits > 0 && cert.key_bits < 256 {
        out.push(CertWeakness::EcKeyTooSmall);
    }
    if cert.expired {
        out.push(CertWeakness::Expired);
    }
    if cert.self_signed {
        out.push(CertWeakness::SelfSigned);
    }
    if !host_matches_cert(host, cert) {
        out.push(CertWeakness::HostnameMismatch);
    }
    out
}

fn parse_jwt_header_issues(token: &str) -> Option<JwtSurfaceIssues> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0].as_bytes()).ok()?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1].as_bytes()).ok()?;
    let header: Value = serde_json::from_slice(&header_bytes).ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let kid_present = header.get("kid").and_then(Value::as_str).is_some();
    Some(JwtSurfaceIssues {
        alg_none: alg.eq_ignore_ascii_case("none"),
        hs256_with_kid: alg.eq_ignore_ascii_case("HS256") && kid_present,
        missing_exp: payload.get("exp").is_none(),
        alg,
    })
}

fn host_matches_cert(host: &str, cert: &LeafCertInfo) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }
    let mut names: Vec<String> = cert.san.iter().map(|s| s.to_ascii_lowercase()).collect();
    if names.is_empty() {
        if let Some(cn) = &cert.common_name {
            names.push(cn.to_ascii_lowercase());
        }
    }
    names.iter().any(|n| name_matches(&host, n))
}

fn name_matches(host: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if let Some((_, rest)) = host.split_once('.') {
            return rest.eq_ignore_ascii_case(suffix);
        }
        return false;
    }
    host.eq_ignore_ascii_case(pattern)
}

fn resolve_addr(host: &str, port: u16) -> Option<SocketAddr> {
    (host, port).to_socket_addrs().ok()?.next()
}

fn build_tls_connector(ver: SslVersion) -> Result<SslConnector, String> {
    let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_min_proto_version(Some(ver))
        .map_err(|e| e.to_string())?;
    b.set_max_proto_version(Some(ver))
        .map_err(|e| e.to_string())?;
    if ver != SslVersion::TLS1_3 {
        let _ = b.set_cipher_list(LEGACY_CIPHER_LIST);
    }
    Ok(b.build())
}

fn parse_leaf_cert(cert: &X509Ref) -> LeafCertInfo {
    let fmt_name = |name: &openssl::x509::X509NameRef| -> String {
        name.entries()
            .map(|e| {
                let key = e.object().nid().short_name().unwrap_or("?");
                let val = e
                    .data()
                    .as_utf8()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                format!("{key}={val}")
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let subject = fmt_name(cert.subject_name());
    let issuer = fmt_name(cert.issuer_name());
    let common_name = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()));
    let now = openssl::asn1::Asn1Time::days_from_now(0).ok();
    let not_after = cert.not_after();
    let expired = now.as_ref().is_some_and(|n| not_after < n.as_ref());
    let days_until_expiry = now
        .as_ref()
        .and_then(|n| not_after.diff(n.as_ref()).ok())
        .map(|d| i64::from(d.days))
        .unwrap_or(0);
    let pkey = cert.public_key().ok();
    let key_bits = pkey.as_ref().map(|k| k.bits()).unwrap_or(0);
    let key_type = match pkey.as_ref() {
        Some(k) if k.rsa().is_ok() => "RSA",
        Some(k) if k.ec_key().is_ok() => "EC",
        Some(k) if k.dsa().is_ok() => "DSA",
        _ => "unknown",
    }
    .to_string();
    let sig_algo = cert
        .signature_algorithm()
        .object()
        .nid()
        .short_name()
        .unwrap_or("unknown")
        .to_string();
    let sig_low = sig_algo.to_ascii_lowercase();
    let sig_weak = sig_low.contains("md2")
        || sig_low.contains("md4")
        || sig_low.contains("md5")
        || sig_low.contains("sha1");
    let mut san = Vec::new();
    if let Some(names) = cert.subject_alt_names() {
        for n in names {
            if let Some(dns) = n.dnsname() {
                san.push(dns.to_string());
            }
        }
    }
    let self_signed = subject == issuer;
    LeafCertInfo {
        subject,
        issuer,
        common_name,
        self_signed,
        not_after: not_after.to_string(),
        expired,
        days_until_expiry,
        key_type,
        key_bits,
        sig_algo,
        sig_weak,
        san,
    }
}

fn tls_handshake(
    addr: SocketAddr,
    sni: &str,
    connector: &SslConnector,
    timeout: Duration,
) -> Result<(String, String, u32, Vec<LeafCertInfo>, bool, String), String> {
    let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let mut cfg = connector.configure().map_err(|e| e.to_string())?;
    cfg.set_use_server_name_indication(!sni.is_empty());
    cfg.set_verify_hostname(false);
    let ssl = cfg.into_ssl(sni).map_err(|e| e.to_string())?;
    let mut stream = SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
    stream.connect().map_err(|e| e.to_string())?;
    let ssl = stream.ssl();
    let version = ssl
        .current_cipher()
        .map(|c| c.version().to_string())
        .unwrap_or_else(|| ssl.version_str().to_string());
    let (cipher, bits) = ssl
        .current_cipher()
        .map(|c| (c.name().to_string(), c.bits().secret.max(0) as u32))
        .unwrap_or_else(|| ("unknown".to_string(), 0));
    let mut chain: Vec<LeafCertInfo> = ssl
        .peer_cert_chain()
        .map(|st| st.iter().map(parse_leaf_cert).collect())
        .unwrap_or_default();
    if chain.is_empty() {
        if let Some(leaf) = ssl.peer_certificate() {
            chain.push(parse_leaf_cert(&leaf));
        }
    }
    let verify = ssl.verify_result();
    Ok((
        version,
        cipher,
        bits,
        chain,
        verify == X509VerifyResult::OK,
        verify.error_string().to_string(),
    ))
}

fn probe_tls_version(addr: SocketAddr, sni: &str, ver: SslVersion, timeout: Duration) -> bool {
    let Ok(connector) = build_tls_connector(ver) else {
        return false;
    };
    tls_handshake(addr, sni, &connector, timeout).is_ok()
}

fn probe_tls_blocking(host: &str, port: u16) -> TlsProbeResult {
    let mut out = TlsProbeResult::default();
    let Some(addr) = resolve_addr(host, port) else {
        return out;
    };
    let timeout = Duration::from_secs(8);
    let sni = host.to_string();
    out.tls10_enabled = probe_tls_version(addr, &sni, SslVersion::TLS1, timeout);
    out.tls11_enabled = probe_tls_version(addr, &sni, SslVersion::TLS1_1, timeout);
    for ver in [SslVersion::TLS1_3, SslVersion::TLS1_2] {
        let Ok(connector) = build_tls_connector(ver) else {
            continue;
        };
        if let Ok((version, cipher, bits, chain, verify_ok, verify_msg)) =
            tls_handshake(addr, &sni, &connector, timeout)
        {
            out.reachable = true;
            out.negotiated_version = version;
            out.cipher = cipher;
            out.cipher_bits = bits;
            out.chain = chain;
            out.verify_ok = verify_ok;
            out.verify_msg = verify_msg;
            break;
        }
    }
    out
}

fn parse_hsts(raw: &str) -> HstsInfo {
    let mut info = HstsInfo {
        present: true,
        ..Default::default()
    };
    for part in raw.split(';') {
        let p = part.trim();
        let lower = p.to_ascii_lowercase();
        if lower.starts_with("max-age=") {
            info.max_age = lower.trim_start_matches("max-age=").trim().parse().ok();
        } else if lower == "includesubdomains" {
            info.include_subdomains = true;
        } else if lower == "preload" {
            info.preload = true;
        }
    }
    info.strong = info.max_age.unwrap_or(0) >= 31536000 && info.include_subdomains;
    info
}

fn extract_form_nonces(html: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r#"(?i)<input[^>]+(?:name=["'](?:csrf(?:token)?|_token|nonce|authenticity_token)["'][^>]+value=["']([^"']+)["']|value=["']([^"']+)["'][^>]+name=["'](?:csrf(?:token)?|_token|nonce|authenticity_token)["'])"#,
        )
        .unwrap_or_else(|_| Regex::new("^$").expect("fallback regex"))
    });
    re.captures_iter(html)
        .filter_map(|cap| {
            cap.get(1)
                .or_else(|| cap.get(2))
                .map(|m| m.as_str().to_string())
        })
        .collect()
}

fn jwt_like(value: &str) -> bool {
    value.starts_with("eyJ") && value.matches('.').count() >= 2
}

fn collect_jwt_tokens(headers: &[(String, String)]) -> Vec<String> {
    let mut tokens = Vec::new();
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if kl == "authorization" {
            let token = v
                .trim()
                .strip_prefix("Bearer ")
                .or_else(|| v.trim().strip_prefix("bearer "))
                .unwrap_or(v.trim());
            if jwt_like(token) {
                tokens.push(token.to_string());
            }
        } else if kl == "set-cookie" {
            let cookie_val = v.split(';').next().unwrap_or(v);
            if let Some((_name, val)) = cookie_val.split_once('=') {
                let val = val.trim();
                if jwt_like(val) {
                    tokens.push(val.to_string());
                }
            }
        }
    }
    tokens.sort();
    tokens.dedup();
    tokens
}

fn scan_http_secrets(headers: &[(String, String)], body: &str) -> Vec<&'static str> {
    let mut found = HashSet::new();
    for (_, v) in headers {
        for kind in detect_secrets(v) {
            found.insert(kind);
        }
    }
    for kind in detect_secrets(body) {
        found.insert(kind);
    }
    let mut out: Vec<&'static str> = found.into_iter().collect();
    out.sort_unstable();
    out
}

fn emit_tls_findings(
    target: &str,
    host: &str,
    tls: &TlsProbeResult,
    hsts: &HstsInfo,
    scores: &mut PostureScores,
    findings: &mut Vec<Value>,
) {
    if !tls.reachable {
        scores.tls = scores.tls.saturating_sub(40);
        findings.push(finding_rich(
            ENGINE_ID,
            "TLS endpoint unreachable",
            "high",
            MITRE_MITM,
            &format!(
                "Could not complete a TLS handshake to {host}:443. Transport encryption posture is unknown or the service is down."
            ),
            target,
            0.9,
            Evidence::new().with("host", host).with("port", 443),
        ));
        return;
    }

    findings.push(finding_rich(
        ENGINE_ID,
        "TLS negotiation observed",
        "info",
        MITRE_CRYPTO,
        &format!(
            "Negotiated {} with cipher {} ({}-bit). Chain depth {}.",
            tls.negotiated_version,
            tls.cipher,
            tls.cipher_bits,
            tls.chain.len()
        ),
        target,
        1.0,
        Evidence::new()
            .with("version", tls.negotiated_version.as_str())
            .with("cipher", tls.cipher.as_str())
            .with("cipher_bits", tls.cipher_bits)
            .with("chain_depth", tls.chain.len()),
    ));

    if tls.tls10_enabled {
        scores.tls = scores.tls.saturating_sub(25);
        findings.push(finding_rich(
            ENGINE_ID,
            "Deprecated TLS 1.0 enabled",
            "high",
            MITRE_CRYPTO,
            "Server negotiated TLS 1.0 — vulnerable to BEAST/POODLE-era downgrade attacks. Disable TLS 1.0/1.1.",
            target,
            0.95,
            Evidence::new().with("protocol", "TLSv1.0"),
        ));
    }
    if tls.tls11_enabled {
        scores.tls = scores.tls.saturating_sub(15);
        findings.push(finding_rich(
            ENGINE_ID,
            "Deprecated TLS 1.1 enabled",
            "medium",
            MITRE_CRYPTO,
            "Server negotiated TLS 1.1. Disable legacy protocols and require TLS 1.2+.",
            target,
            0.9,
            Evidence::new().with("protocol", "TLSv1.1"),
        ));
    }

    if let Some(leaf) = tls.chain.first() {
        for weakness in classify_cert_weaknesses(leaf, host) {
            match weakness {
                CertWeakness::WeakSigSha1 => {
                    scores.tls = scores.tls.saturating_sub(20);
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Certificate signed with SHA-1",
                        "high",
                        MITRE_CRYPTO,
                        &format!(
                            "Leaf certificate uses weak signature algorithm {} (SHA-1 family). Re-issue with SHA-256 or better.",
                            leaf.sig_algo
                        ),
                        target,
                        0.92,
                        Evidence::new().with("sig_algo", leaf.sig_algo.as_str()),
                    ));
                }
                CertWeakness::RsaKeyTooSmall => {
                    scores.tls = scores.tls.saturating_sub(30);
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "RSA certificate key too small",
                        "critical",
                        MITRE_CRYPTO,
                        &format!(
                            "Leaf certificate RSA key is {} bits (<2048). Upgrade to ≥2048-bit RSA or ECDSA P-256.",
                            leaf.key_bits
                        ),
                        target,
                        0.98,
                        Evidence::new().with("key_type", "RSA").with("key_bits", leaf.key_bits),
                    ));
                }
                CertWeakness::EcKeyTooSmall => {
                    scores.tls = scores.tls.saturating_sub(25);
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "EC certificate key too small",
                        "high",
                        MITRE_CRYPTO,
                        &format!(
                            "Leaf certificate EC key is {} bits (<256). Use P-256 or stronger curves.",
                            leaf.key_bits
                        ),
                        target,
                        0.95,
                        Evidence::new().with("key_type", "EC").with("key_bits", leaf.key_bits),
                    ));
                }
                CertWeakness::Expired => {
                    scores.tls = scores.tls.saturating_sub(35);
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Certificate expired",
                        "critical",
                        MITRE_MITM,
                        &format!("Leaf certificate expired (notAfter={}).", leaf.not_after),
                        target,
                        1.0,
                        Evidence::new().with("not_after", leaf.not_after.as_str()),
                    ));
                }
                CertWeakness::SelfSigned => {
                    scores.tls = scores.tls.saturating_sub(20);
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Self-signed certificate",
                        "high",
                        MITRE_MITM,
                        &format!("Certificate issuer matches subject ({}) — not anchored to a public CA.", leaf.subject),
                        target,
                        0.95,
                        Evidence::new().with("subject", leaf.subject.as_str()).with("issuer", leaf.issuer.as_str()),
                    ));
                }
                CertWeakness::HostnameMismatch => {
                    scores.tls = scores.tls.saturating_sub(25);
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Certificate hostname mismatch",
                        "high",
                        MITRE_MITM,
                        &format!(
                            "Certificate SAN/CN does not match requested host '{}'. Clients will reject or warn.",
                            host
                        ),
                        target,
                        0.95,
                        Evidence::new()
                            .with("host", host)
                            .with("common_name", leaf.common_name.clone().unwrap_or_default())
                            .with("san", json!(leaf.san)),
                    ));
                }
            }
        }
        if leaf.days_until_expiry >= 0 && leaf.days_until_expiry <= 30 && !leaf.expired {
            scores.tls = scores.tls.saturating_sub(10);
            findings.push(finding_rich(
                ENGINE_ID,
                "Certificate expiring soon",
                "medium",
                MITRE_CRYPTO,
                &format!(
                    "Leaf certificate expires in {} days (notAfter={}).",
                    leaf.days_until_expiry, leaf.not_after
                ),
                target,
                0.85,
                Evidence::new().with("days_until_expiry", leaf.days_until_expiry),
            ));
        }
    }

    if !tls.verify_ok {
        scores.tls = scores.tls.saturating_sub(15);
        findings.push(finding_rich(
            ENGINE_ID,
            "Certificate chain not trusted",
            "high",
            MITRE_MITM,
            &format!("OpenSSL chain verification failed: {}", tls.verify_msg),
            target,
            0.9,
            Evidence::new().with("verify_msg", tls.verify_msg.as_str()),
        ));
    }

    if !hsts.present {
        scores.tls = scores.tls.saturating_sub(10);
        findings.push(finding_rich(
            ENGINE_ID,
            "HSTS header missing",
            "medium",
            MITRE_MITM,
            "Strict-Transport-Security header absent — clients may fall back to cleartext on first visit.",
            target,
            0.85,
            Evidence::new().with("hsts_present", false),
        ));
    } else if !hsts.strong {
        scores.tls = scores.tls.saturating_sub(5);
        findings.push(finding_rich(
            ENGINE_ID,
            "HSTS policy not fully hardened",
            "low",
            MITRE_MITM,
            &format!(
                "HSTS present (max-age={:?}) but missing includeSubDomains and/or max-age≥31536000.",
                hsts.max_age
            ),
            target,
            0.75,
            Evidence::new()
                .with("max_age", hsts.max_age.unwrap_or(0))
                .with("include_subdomains", hsts.include_subdomains)
                .with("preload", hsts.preload),
        ));
    }
}

fn emit_secret_findings(
    target: &str,
    secret_kinds: &[&str],
    scores: &mut PostureScores,
    findings: &mut Vec<Value>,
) {
    if secret_kinds.is_empty() {
        return;
    }
    scores.secrets = scores
        .secrets
        .saturating_sub((secret_kinds.len() as u8).saturating_mul(25));
    let sev = if secret_kinds
        .iter()
        .any(|k| k.contains("Private Key") || k.contains("Stripe") || k.contains("AWS Secret"))
    {
        "critical"
    } else {
        "high"
    };
    findings.push(finding_rich(
        ENGINE_ID,
        "Hardcoded cryptographic material in HTTP response",
        sev,
        MITRE_CRYPTO,
        &format!(
            "Live HTTP response contained secret patterns: {}. Rotate exposed credentials immediately.",
            secret_kinds.join(", ")
        ),
        target,
        0.98,
        Evidence::new().with("secret_types", json!(secret_kinds)),
    ));
}

fn emit_cookie_findings(
    target: &str,
    headers: &[(String, String)],
    scores: &mut PostureScores,
    findings: &mut Vec<Value>,
) {
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let lc = v.to_ascii_lowercase();
        let name = v.split('=').next().unwrap_or("cookie").trim();
        let session_like = lc.contains("session")
            || lc.contains("sid")
            || lc.contains("token")
            || lc.contains("auth")
            || jwt_like(v.split('=').nth(1).unwrap_or(""));
        if !session_like {
            continue;
        }
        let mut issues = Vec::new();
        if !lc.contains("secure") {
            issues.push("missing Secure");
        }
        if !lc.contains("httponly") {
            issues.push("missing HttpOnly");
        }
        if !lc.contains("samesite") {
            issues.push("missing SameSite");
        }
        if issues.is_empty() {
            continue;
        }
        scores.cookies = scores.cookies.saturating_sub(20);
        let sev = if issues.contains(&"missing Secure") {
            "high"
        } else {
            "medium"
        };
        findings.push(finding_rich(
            ENGINE_ID,
            &format!("Session cookie missing crypto flags: {name}"),
            sev,
            MITRE_CRYPTO,
            &format!(
                "Cookie '{name}' lacks {} — vulnerable to XSS theft, CSRF, or cleartext leakage.",
                issues.join(", ")
            ),
            target,
            0.9,
            Evidence::new()
                .with("cookie", name)
                .with("issues", json!(issues)),
        ));
    }
}

fn emit_jwt_findings(
    target: &str,
    headers: &[(String, String)],
    scores: &mut PostureScores,
    findings: &mut Vec<Value>,
) {
    for token in collect_jwt_tokens(headers) {
        let Some(issues) = parse_jwt_header_issues(&token) else {
            continue;
        };
        if issues.alg_none {
            scores.jwt = scores.jwt.saturating_sub(40);
            findings.push(finding_rich(
                ENGINE_ID,
                "JWT advertises alg=none",
                "critical",
                MITRE_CRYPTO,
                "Token header declares alg=none — server may accept unsigned tokens (forgery). Reject none and pin algorithms.",
                target,
                0.98,
                Evidence::new().with("alg", "none").with("surface", "header_only"),
            ));
        }
        if issues.hs256_with_kid {
            scores.jwt = scores.jwt.saturating_sub(20);
            findings.push(finding_rich(
                ENGINE_ID,
                "JWT HS256 with kid header (injection surface)",
                "high",
                MITRE_CRYPTO,
                "Symmetric HS256 token exposes kid header — test for key-confusion / kid path injection against JWKS endpoints.",
                target,
                0.85,
                Evidence::new().with("alg", "HS256").with("kid_present", true),
            ));
        }
        if issues.missing_exp {
            scores.jwt = scores.jwt.saturating_sub(15);
            findings.push(finding_rich(
                ENGINE_ID,
                "JWT missing exp claim",
                "medium",
                MITRE_CRYPTO,
                &format!(
                    "Token (alg={}) has no exp claim — sessions may not expire. Enforce short-lived tokens.",
                    issues.alg
                ),
                target,
                0.8,
                Evidence::new().with("alg", issues.alg.as_str()).with("missing_exp", true),
            ));
        }
    }
}

fn emit_nonce_findings(
    target: &str,
    nonces_a: &[String],
    nonces_b: &[String],
    scores: &mut PostureScores,
    findings: &mut Vec<Value>,
) {
    if nonces_a.is_empty() || nonces_b.is_empty() {
        return;
    }
    let repeated: Vec<&String> = nonces_a.iter().filter(|n| nonces_b.contains(n)).collect();
    if repeated.is_empty() {
        return;
    }
    scores.tls = scores.tls.saturating_sub(10);
    findings.push(finding_rich(
        ENGINE_ID,
        "Predictable form nonce/token observed",
        "medium",
        MITRE_CRYPTO,
        &format!(
            "Identical CSRF/nonce values returned across consecutive GET requests ({}). RNG may be weak or static.",
            repeated.len()
        ),
        target,
        0.82,
        Evidence::new().with("repeated_nonces", repeated.len()),
    ));
}

/// Run crypto engine scan: TLS/PKI surface probe (cipher suite, cert chain, weak protocols).
pub async fn run_crypto_engine_result(target: &str) -> EngineResult {
    let url = normalize_url(target);
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    let mut scores = PostureScores {
        tls: 100,
        secrets: 100,
        cookies: 100,
        jwt: 100,
    };

    let host_for_tls = host.clone();
    let tls = tokio::task::spawn_blocking(move || probe_tls_blocking(&host_for_tls, 443))
        .await
        .ok()
        .unwrap_or_default();

    let client = crate::engine_probes::http_client().await;
    let probe = http_get(&client, &url).await;
    let (headers, body, hsts) = if let Some(p) = probe {
        let hsts = header_value(&p.headers, "strict-transport-security")
            .map(parse_hsts)
            .unwrap_or_default();
        (p.headers, p.body, hsts)
    } else {
        (vec![], String::new(), HstsInfo::default())
    };

    emit_tls_findings(target, &host, &tls, &hsts, &mut scores, &mut findings);

    if !headers.is_empty() || !body.is_empty() {
        let secret_kinds = scan_http_secrets(&headers, &body);
        emit_secret_findings(target, &secret_kinds, &mut scores, &mut findings);
        emit_cookie_findings(target, &headers, &mut scores, &mut findings);
        emit_jwt_findings(target, &headers, &mut scores, &mut findings);

        let nonces_a = extract_form_nonces(&body);
        if let Some(p2) = http_get(&client, &url).await {
            let nonces_b = extract_form_nonces(&p2.body);
            emit_nonce_findings(target, &nonces_a, &nonces_b, &mut scores, &mut findings);
        }
    }

    let subgrades = json!({
        "tls": score_to_grade(scores.tls),
        "secrets": score_to_grade(scores.secrets),
        "cookies": score_to_grade(scores.cookies),
        "jwt": score_to_grade(scores.jwt),
    });
    let subscores = json!({
        "tls": scores.tls,
        "secrets": scores.secrets,
        "cookies": scores.cookies,
        "jwt": scores.jwt,
    });
    let overall = worse_grade(
        score_to_grade(scores.tls),
        worse_grade(
            score_to_grade(scores.secrets),
            worse_grade(score_to_grade(scores.cookies), score_to_grade(scores.jwt)),
        ),
    );
    findings.push(finding_rich(
        ENGINE_ID,
        &format!("Cryptographic posture grade: {overall}"),
        if overall == "A" || overall == "B" {
            "info"
        } else if overall == "C" || overall == "D" {
            "medium"
        } else {
            "high"
        },
        MITRE_CRYPTO,
        &format!(
            "Composite grade {overall} from live probes (TLS, HTTP secrets, cookies, JWT). Subgrades: tls={}, secrets={}, cookies={}, jwt={}.",
            subgrades["tls"], subgrades["secrets"], subgrades["cookies"], subgrades["jwt"]
        ),
        target,
        1.0,
        Evidence::new()
            .with("grade", overall)
            .with("subgrades", subgrades.clone())
            .with("subscores", subscores),
    ));

    let msg = format!(
        "Crypto posture scan complete — grade {overall} (tls={}, secrets={}, cookies={}, jwt={})",
        subgrades["tls"], subgrades["secrets"], subgrades["cookies"], subgrades["jwt"]
    );
    EngineResult::ok(findings, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert(
        key_type: &str,
        key_bits: u32,
        sig_weak: bool,
        expired: bool,
        self_signed: bool,
        san: Vec<String>,
        common_name: Option<String>,
    ) -> LeafCertInfo {
        LeafCertInfo {
            subject: if self_signed {
                "CN=test.local".to_string()
            } else {
                "CN=leaf".to_string()
            },
            issuer: if self_signed {
                "CN=test.local".to_string()
            } else {
                "CN=CA".to_string()
            },
            common_name,
            self_signed,
            not_after: "Dec 31 2099".to_string(),
            expired,
            days_until_expiry: if expired { -1 } else { 120 },
            key_type: key_type.to_string(),
            key_bits,
            sig_algo: if sig_weak {
                "sha1WithRSAEncryption".to_string()
            } else {
                "sha256WithRSAEncryption".to_string()
            },
            sig_weak,
            san,
        }
    }

    #[test]
    fn cert_weakness_classifier_flags_sha1_rsa_and_host_mismatch() {
        let cert = sample_cert(
            "RSA",
            1024,
            true,
            false,
            false,
            vec![],
            Some("other.example".into()),
        );
        let weaknesses = classify_cert_weaknesses(&cert, "app.example.com");
        assert!(weaknesses.contains(&CertWeakness::WeakSigSha1));
        assert!(weaknesses.contains(&CertWeakness::RsaKeyTooSmall));
        assert!(weaknesses.contains(&CertWeakness::HostnameMismatch));
    }

    #[test]
    fn cert_weakness_classifier_flags_ec_and_self_signed() {
        let cert = sample_cert(
            "EC",
            224,
            false,
            true,
            true,
            vec!["*.test.local".into()],
            None,
        );
        let weaknesses = classify_cert_weaknesses(&cert, "api.test.local");
        assert!(weaknesses.contains(&CertWeakness::EcKeyTooSmall));
        assert!(weaknesses.contains(&CertWeakness::Expired));
        assert!(weaknesses.contains(&CertWeakness::SelfSigned));
        assert!(!weaknesses.contains(&CertWeakness::HostnameMismatch));
    }

    #[test]
    fn jwt_header_parser_detects_none_hs256_kid_and_missing_exp() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"123"}"#.as_bytes());
        let token = format!("{header}.{payload}.sig");
        let issues = parse_jwt_header_issues(&token).expect("parse");
        assert!(issues.alg_none);
        assert!(!issues.hs256_with_kid);
        assert!(issues.missing_exp);

        let header =
            URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","kid":"../../etc/passwd"}"#.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"123","exp":9999999999}"#.as_bytes());
        let token = format!("{header}.{payload}.sig");
        let issues = parse_jwt_header_issues(&token).expect("parse");
        assert!(!issues.alg_none);
        assert!(issues.hs256_with_kid);
        assert!(!issues.missing_exp);
    }

    #[test]
    fn host_matching_supports_wildcard_san() {
        let cert = sample_cert(
            "RSA",
            2048,
            false,
            false,
            false,
            vec!["*.example.com".into()],
            None,
        );
        assert!(host_matches_cert("app.example.com", &cert));
        assert!(!host_matches_cert("app.other.com", &cert));
    }
}
