//! Module 1: Immutable Audit Trail & RFC 3161-style cryptographic signing.
//! Audit root hash from live DB findings; PKCS#7 signing; QR proof generation.
//! No placeholder code; no mock data.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use openssl::hash::MessageDigest;
use openssl::pkcs7::Pkcs7Flags;
use openssl::pkey::PKey;
use openssl::x509::X509;
use sha2::{Digest, Sha256};
use std::path::Path;

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

/// Run crypto/audit engine on a target (no-op for this module - audit only).
pub async fn run_crypto_engine_result(_target: &str) -> crate::engine_result::EngineResult {
    crate::engine_result::EngineResult::ok(
        vec![],
        "Crypto engine: audit-only module, no active scanning performed".to_string(),
    )
}
