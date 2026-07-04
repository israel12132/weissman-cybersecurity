//! World-class PKI / TLS deep assessment engine.
//!
//! This is a real, evidence-bearing TLS analyzer — not a header sniff. For every operator-selected
//! port it performs **live OpenSSL handshakes** to map the server's exact security posture, the way
//! `testssl.sh` / `sslyze` / Qualys SSL Labs do, and then computes an SSL-Labs-style letter grade
//! from the observed matrix:
//!
//!   * **Protocol matrix** — one forced handshake per version (SSLv3, TLS 1.0/1.1/1.2/1.3) records
//!     exactly which the server negotiates. Deprecated versions are flagged with their CVE.
//!   * **Cipher-suite enumeration** — iterative handshakes peel off every accepted suite per protocol
//!     (the classic `!cipher` exclusion walk) and classify each (RC4, 3DES/SWEET32, EXPORT, NULL,
//!     anonymous, CBC, MD5, key bits, forward secrecy).
//!   * **Certificate + chain forensics** — leaf + chain parsing: key type/size, signature algorithm,
//!     validity window, expiry runway, self-signed, hostname/SAN match, wildcard, serial, SHA-256
//!     fingerprint, and the OpenSSL chain `verify_result`.
//!   * **Vulnerability heuristics** — POODLE, BEAST, SWEET32, FREAK/LOGJAM, RC4, weak-key, weak-sig,
//!     no-PFS, missing OCSP stapling — each only emitted from a real observation.
//!   * **Transport hardening** — HSTS (max-age/includeSubDomains/preload), HTTP→HTTPS redirect,
//!     Certificate Transparency (crt.sh), DNS CAA coverage, and DANE/TLSA pinning (RFC 6698).
//!   * **Posture scorecard** — 0–100 aggregate with PCI-DSS / NIST SP 800-52 compliance tags.
//!
//! Every knob is driven from the live scan request body (`POST /api/command-center/scan` →
//! `EngineRunContext::job_params`) through [`crate::arsenal_config::ArsenalConfig`], so an operator
//! can tune **every** aspect (ports, SNI, STARTTLS, per-protocol toggles, cipher-walk depth,
//! per-check switches, timeouts, intensity, expiry thresholds) with no code change. Findings carry a
//! structured `evidence` trail so the operator can audit exactly what each handshake observed.
//!
//! MITRE: T1557 (Adversary-in-the-Middle), T1600 (Weaken Encryption).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{dns_caa, dns_tlsa, header_value, http_client, http_get, normalize_url};
use crate::engine_result::{print_result, EngineResult};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion, StatusType};
use openssl::x509::{X509Ref, X509VerifyResult};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const ENGINE_ID: &str = "pki_tls";
const MITRE_MITM: &str = "T1557";
const MITRE_CRYPTO: &str = "T1600";

/// Permissive cipher string that asks OpenSSL to offer every suite it can, including legacy ones
/// (security level 0). On stacks that reject `@SECLEVEL=0` the directive is silently ignored.
const LEGACY_CIPHER_LIST: &str = "ALL:COMPLEMENTOFALL:@SECLEVEL=0";

/// The five standardised TLS 1.3 cipher suites, enumerated one at a time.
const TLS13_SUITES: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
];

// ─────────────────────────────────────────────────────────────────────────────
// STARTTLS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StartTls {
    None,
    Smtp,
    Imap,
    Pop3,
    Ftp,
}

impl StartTls {
    fn as_str(self) -> &'static str {
        match self {
            StartTls::None => "none",
            StartTls::Smtp => "smtp",
            StartTls::Imap => "imap",
            StartTls::Pop3 => "pop3",
            StartTls::Ftp => "ftp",
        }
    }

    fn parse(raw: &str, port: u16) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "smtp" => StartTls::Smtp,
            "imap" => StartTls::Imap,
            "pop3" => StartTls::Pop3,
            "ftp" => StartTls::Ftp,
            "auto" => match port {
                25 | 587 => StartTls::Smtp,
                143 => StartTls::Imap,
                110 => StartTls::Pop3,
                21 => StartTls::Ftp,
                _ => StartTls::None,
            },
            _ => StartTls::None,
        }
    }
}

fn st_read(mut s: &TcpStream) -> Result<String, String> {
    use std::io::Read;
    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

fn st_write(mut s: &TcpStream, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    s.write_all(data).map_err(|e| e.to_string())
}

/// Drive a plaintext STARTTLS upgrade on `tcp` before the TLS handshake is layered on top.
fn starttls_negotiate(tcp: &TcpStream, proto: StartTls) -> Result<(), String> {
    match proto {
        StartTls::None => Ok(()),
        StartTls::Smtp => {
            let _greeting = st_read(tcp)?;
            st_write(tcp, b"EHLO weissman.scan\r\n")?;
            let _ehlo = st_read(tcp)?;
            st_write(tcp, b"STARTTLS\r\n")?;
            let r = st_read(tcp)?;
            if r.contains("220") {
                Ok(())
            } else {
                Err(format!("SMTP STARTTLS refused: {}", r.trim()))
            }
        }
        StartTls::Imap => {
            let _greeting = st_read(tcp)?;
            st_write(tcp, b"a001 STARTTLS\r\n")?;
            let r = st_read(tcp)?;
            if r.to_ascii_uppercase().contains("OK") {
                Ok(())
            } else {
                Err(format!("IMAP STARTTLS refused: {}", r.trim()))
            }
        }
        StartTls::Pop3 => {
            let _greeting = st_read(tcp)?;
            st_write(tcp, b"STLS\r\n")?;
            let r = st_read(tcp)?;
            if r.starts_with("+OK") {
                Ok(())
            } else {
                Err(format!("POP3 STLS refused: {}", r.trim()))
            }
        }
        StartTls::Ftp => {
            let _greeting = st_read(tcp)?;
            st_write(tcp, b"AUTH TLS\r\n")?;
            let r = st_read(tcp)?;
            if r.starts_with("234") {
                Ok(())
            } else {
                Err(format!("FTP AUTH TLS refused: {}", r.trim()))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (every operator knob)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct TlsScanConfig {
    ports: Vec<u16>,
    sni_override: Option<String>,
    starttls_raw: String,
    timeout_ms: u64,
    port_budget_secs: u64,
    cipher_limit: usize,
    expiry_warning_days: i64,
    intensity: Intensity,
    test_ssl3: bool,
    test_tls10: bool,
    test_tls11: bool,
    test_tls12: bool,
    test_tls13: bool,
    check_protocols: bool,
    check_ciphers: bool,
    check_certificate: bool,
    check_chain_trust: bool,
    check_hostname: bool,
    check_forward_secrecy: bool,
    check_vulnerabilities: bool,
    check_ocsp: bool,
    check_http_headers: bool,
    check_security_headers: bool,
    check_ct_logs: bool,
    check_caa: bool,
    check_dane: bool,
    check_posture_score: bool,
    min_grade: Option<String>,
}

impl Default for TlsScanConfig {
    fn default() -> Self {
        Self {
            ports: vec![443],
            sni_override: None,
            starttls_raw: "none".to_string(),
            timeout_ms: 4000,
            port_budget_secs: 45,
            cipher_limit: 80,
            expiry_warning_days: 30,
            intensity: Intensity::Normal,
            test_ssl3: true,
            test_tls10: true,
            test_tls11: true,
            test_tls12: true,
            test_tls13: true,
            check_protocols: true,
            check_ciphers: true,
            check_certificate: true,
            check_chain_trust: true,
            check_hostname: true,
            check_forward_secrecy: true,
            check_vulnerabilities: true,
            check_ocsp: true,
            check_http_headers: true,
            check_security_headers: true,
            check_ct_logs: true,
            check_caa: true,
            check_dane: true,
            check_posture_score: true,
            min_grade: None,
        }
    }
}

impl TlsScanConfig {
    fn from_ctx(ctx: &EngineRunContext, default_port: u16) -> Self {
        let c = ArsenalConfig::from_ctx(ctx);
        let intensity = c.intensity();
        let mut cfg = Self::default();

        // Intensity shapes the cost/coverage trade-off before explicit overrides apply.
        match intensity {
            Intensity::Light => {
                cfg.test_ssl3 = false;
                cfg.test_tls10 = false;
                cfg.test_tls11 = false;
                cfg.cipher_limit = 32;
                cfg.port_budget_secs = 20;
            }
            Intensity::Normal => {}
            Intensity::Aggressive => {
                cfg.cipher_limit = 200;
                cfg.port_budget_secs = 120;
            }
        }
        cfg.intensity = intensity;

        let mut ports = c.ports_or("ports", &[default_port]);
        if ports.is_empty() {
            ports = c.ports_or("tls_ports", &[default_port]);
        }
        ports.truncate(16);
        cfg.ports = ports;

        cfg.sni_override = c.string("sni").or_else(|| c.string("server_name"));
        cfg.starttls_raw = c.string_or("starttls", "none");
        cfg.timeout_ms = c.timeout_ms(cfg.timeout_ms);
        cfg.port_budget_secs = c
            .u64_or("port_budget_secs", cfg.port_budget_secs)
            .clamp(5, 600);
        cfg.cipher_limit = c
            .usize_or("cipher_enumeration_limit", cfg.cipher_limit)
            .clamp(1, 512);
        cfg.expiry_warning_days = i64::try_from(c.u64_or("expiry_warning_days", 30)).unwrap_or(30);

        // Explicit protocol selection overrides the intensity defaults entirely.
        if let Some(list) = c.string("protocols") {
            cfg.test_ssl3 = false;
            cfg.test_tls10 = false;
            cfg.test_tls11 = false;
            cfg.test_tls12 = false;
            cfg.test_tls13 = false;
            for tok in list.split([',', ' ', ';']) {
                match tok
                    .trim()
                    .to_ascii_lowercase()
                    .replace(['.', '_'], "")
                    .as_str()
                {
                    "ssl3" | "sslv3" => cfg.test_ssl3 = true,
                    "tls1" | "tls10" => cfg.test_tls10 = true,
                    "tls11" => cfg.test_tls11 = true,
                    "tls12" => cfg.test_tls12 = true,
                    "tls13" => cfg.test_tls13 = true,
                    _ => {}
                }
            }
        }

        cfg.check_protocols = c.bool_or("check_protocols", cfg.check_protocols);
        cfg.check_ciphers = c.bool_or("check_ciphers", cfg.check_ciphers);
        cfg.check_certificate = c.bool_or("check_certificate", cfg.check_certificate);
        cfg.check_chain_trust = c.bool_or("check_chain_trust", cfg.check_chain_trust);
        cfg.check_hostname = c.bool_or("check_hostname", cfg.check_hostname);
        cfg.check_forward_secrecy = c.bool_or("check_forward_secrecy", cfg.check_forward_secrecy);
        cfg.check_vulnerabilities = c.bool_or("check_vulnerabilities", cfg.check_vulnerabilities);
        cfg.check_ocsp = c.bool_or("check_ocsp", cfg.check_ocsp);
        cfg.check_http_headers = c.bool_or("check_http_headers", cfg.check_http_headers);
        cfg.check_security_headers =
            c.bool_or("check_security_headers", cfg.check_security_headers);
        cfg.check_ct_logs = c.bool_or("check_ct_logs", cfg.check_ct_logs);
        cfg.check_caa = c.bool_or("check_caa", cfg.check_caa);
        cfg.check_dane = c.bool_or("check_dane", cfg.check_dane);
        cfg.check_posture_score = c.bool_or("check_posture_score", cfg.check_posture_score);
        cfg.min_grade = c.string("min_grade");
        cfg
    }

    fn versions_to_test(&self) -> Vec<(&'static str, SslVersion)> {
        let mut v = Vec::new();
        if self.test_ssl3 {
            v.push(("SSLv3", SslVersion::SSL3));
        }
        if self.test_tls10 {
            v.push(("TLSv1.0", SslVersion::TLS1));
        }
        if self.test_tls11 {
            v.push(("TLSv1.1", SslVersion::TLS1_1));
        }
        if self.test_tls12 {
            v.push(("TLSv1.2", SslVersion::TLS1_2));
        }
        if self.test_tls13 {
            v.push(("TLSv1.3", SslVersion::TLS1_3));
        }
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Observed data structures (all plain / owned so they cross spawn_blocking safely)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct CertInfo {
    subject: String,
    issuer: String,
    common_name: Option<String>,
    self_signed: bool,
    not_before: String,
    not_after: String,
    expired: bool,
    not_yet_valid: bool,
    days_until_expiry: i64,
    validity_days: i64,
    key_type: String,
    key_bits: u32,
    sig_algo: String,
    sig_weak: bool,
    san: Vec<String>,
    wildcard: bool,
    serial_hex: String,
    sha256_fp: String,
}

#[derive(Clone, Debug)]
struct CipherInfo {
    name: String,
    iana: Option<String>,
    bits: i32,
    protocol: String,
    pfs: bool,
    weaknesses: Vec<String>,
}

#[derive(Clone, Debug)]
struct ProtocolResult {
    version: &'static str,
    supported: bool,
}

#[derive(Clone, Debug, Default)]
struct PortReport {
    port: u16,
    reachable: bool,
    tls: bool,
    protocols: Vec<ProtocolResult>,
    ciphers: Vec<CipherInfo>,
    leaf: Option<CertInfo>,
    chain_len: usize,
    verify_ok: bool,
    verify_msg: String,
    ocsp_stapled: Option<bool>,
    alpn: Option<String>,
}

struct HandshakeResult {
    cipher: Option<CipherInfo>,
    chain: Vec<CertInfo>,
    verify_ok: bool,
    verify_msg: String,
    ocsp_stapled: bool,
    alpn: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level handshake primitives
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_addr(host: &str, port: u16) -> Option<SocketAddr> {
    (host, port).to_socket_addrs().ok()?.next()
}

fn build_connector(
    ver: SslVersion,
    cipher_list: Option<&str>,
    ciphersuites: Option<&str>,
    want_alpn: bool,
) -> Result<SslConnector, String> {
    let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_min_proto_version(Some(ver))
        .map_err(|e| e.to_string())?;
    b.set_max_proto_version(Some(ver))
        .map_err(|e| e.to_string())?;
    if let Some(cl) = cipher_list {
        let _ = b.set_cipher_list(cl);
    }
    if let Some(cs) = ciphersuites {
        let _ = b.set_ciphersuites(cs);
    }
    if want_alpn {
        let _ = b.set_alpn_protos(b"\x02h2\x08http/1.1");
    }
    Ok(b.build())
}

/// One full handshake against `addr`. Returns the negotiated cipher, peer chain, trust verdict,
/// OCSP staple presence and ALPN. `Err` means the handshake did not complete (version/cipher refused
/// or the port is not speaking TLS) — exactly the signal protocol/cipher enumeration relies on.
fn do_handshake(
    addr: SocketAddr,
    sni: &str,
    starttls: StartTls,
    connector: &SslConnector,
    request_ocsp: bool,
    timeout: Duration,
) -> Result<HandshakeResult, String> {
    let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    starttls_negotiate(&tcp, starttls)?;

    let mut cfg = connector.configure().map_err(|e| e.to_string())?;
    cfg.set_use_server_name_indication(!sni.is_empty());
    cfg.set_verify_hostname(false);
    let mut ssl = cfg.into_ssl(sni).map_err(|e| e.to_string())?;
    if request_ocsp {
        let _ = ssl.set_status_type(StatusType::OCSP);
    }
    let mut stream = SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
    stream.connect().map_err(|e| e.to_string())?;

    let ssl = stream.ssl();
    let cipher = ssl.current_cipher().map(|c| {
        let name = c.name().to_string();
        let bits = c.bits().secret;
        let (pfs, weaknesses) = classify_cipher(&name, bits);
        CipherInfo {
            iana: c.standard_name().map(str::to_string),
            protocol: c.version().to_string(),
            name,
            bits,
            pfs,
            weaknesses,
        }
    });

    let mut chain: Vec<CertInfo> = ssl
        .peer_cert_chain()
        .map(|st| st.iter().map(parse_cert).collect())
        .unwrap_or_default();
    if chain.is_empty() {
        if let Some(leaf) = ssl.peer_certificate() {
            chain.push(parse_cert(&leaf));
        }
    }

    let verify = ssl.verify_result();
    Ok(HandshakeResult {
        cipher,
        chain,
        verify_ok: verify == X509VerifyResult::OK,
        verify_msg: verify.error_string().to_string(),
        ocsp_stapled: ssl.ocsp_status().map(|b| !b.is_empty()).unwrap_or(false),
        alpn: ssl
            .selected_alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string()),
    })
}

fn parse_cert(cert: &X509Ref) -> CertInfo {
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
    let not_before = cert.not_before();
    let expired = now.as_ref().is_some_and(|n| not_after < n.as_ref());
    let not_yet_valid = now.as_ref().is_some_and(|n| not_before > n.as_ref());
    let days_until_expiry = now
        .as_ref()
        .and_then(|n| not_after.diff(n.as_ref()).ok())
        .map(|d| i64::from(d.days))
        .unwrap_or(0);
    let validity_days = not_before
        .diff(not_after)
        .ok()
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
    let wildcard = san.iter().any(|s| s.starts_with("*."))
        || common_name.as_deref().is_some_and(|c| c.starts_with("*."));

    let serial_hex = cert
        .serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let sha256_fp = cert
        .digest(MessageDigest::sha256())
        .ok()
        .map(|d| {
            d.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_default();

    CertInfo {
        self_signed: subject == issuer,
        subject,
        issuer,
        common_name,
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
        expired,
        not_yet_valid,
        days_until_expiry,
        validity_days,
        key_type,
        key_bits,
        sig_algo,
        sig_weak,
        san,
        wildcard,
        serial_hex,
        sha256_fp,
    }
}

/// Classify an OpenSSL cipher name into `(forward_secrecy, weaknesses)`.
fn classify_cipher(name: &str, bits: i32) -> (bool, Vec<String>) {
    let up = name.to_ascii_uppercase();
    // TLS 1.3 suites (TLS_*) always use ephemeral (EC)DHE, so they have forward secrecy even
    // though the name carries no DHE token.
    let pfs = up.starts_with("TLS_")
        || up.contains("ECDHE")
        || up.contains("DHE")
        || up.contains("EECDH")
        || up.contains("EDH");
    let mut weak = Vec::new();
    if up.contains("NULL") {
        weak.push("NULL cipher — no encryption".to_string());
    }
    if up.contains("ADH") || up.contains("AECDH") || up.contains("ANON") {
        weak.push("Anonymous key exchange — no server authentication".to_string());
    }
    if up.contains("EXP") {
        weak.push("EXPORT-grade — FREAK/LOGJAM (CVE-2015-0204/CVE-2015-4000)".to_string());
    }
    if up.contains("RC4") {
        weak.push("RC4 stream cipher — biased keystream (CVE-2013-2566/CVE-2015-2808)".to_string());
    }
    if up.contains("3DES") || up.contains("DES-CBC3") || up.contains("DES_CBC3") {
        weak.push("3DES — 64-bit block SWEET32 (CVE-2016-2183)".to_string());
    } else if up.contains("DES") {
        weak.push("Single DES — 56-bit key, trivially breakable".to_string());
    }
    if up.contains("RC2") {
        weak.push("RC2 — broken legacy cipher".to_string());
    }
    if up.contains("MD5") {
        weak.push("MD5 MAC — collision-prone integrity".to_string());
    }
    // AEAD suites (GCM/CCM/ChaCha20-Poly1305 and all TLS 1.3 suites) are not CBC; RC4/NULL are
    // stream/none. Everything else is a CBC-mode block cipher (BEAST/Lucky13 on old protocols).
    let aead = up.contains("GCM")
        || up.contains("CCM")
        || up.contains("CHACHA20")
        || up.contains("POLY1305")
        || up.starts_with("TLS_");
    if !aead && !up.contains("RC4") && !up.contains("NULL") {
        weak.push(
            "CBC mode — padding-oracle / BEAST / Lucky13 exposure on old protocols".to_string(),
        );
    }
    if bits > 0 && bits < 128 {
        weak.push(format!("Weak key strength — {bits}-bit (< 128-bit)"));
    }
    if !pfs {
        weak.push("No forward secrecy — static key exchange".to_string());
    }
    (pfs, weak)
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-port probe (blocking; one spawn_blocking per port)
// ─────────────────────────────────────────────────────────────────────────────

fn legacy_connector(ver: SslVersion, want_alpn: bool) -> Result<SslConnector, String> {
    build_connector(ver, Some(LEGACY_CIPHER_LIST), None, want_alpn)
}

fn probe_port_blocking(host: String, sni: String, port: u16, cfg: TlsScanConfig) -> PortReport {
    let mut report = PortReport {
        port,
        ..PortReport::default()
    };
    let Some(addr) = resolve_addr(&host, port) else {
        return report;
    };
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let deadline = Instant::now() + Duration::from_secs(cfg.port_budget_secs);
    let starttls = StartTls::parse(&cfg.starttls_raw, port);

    if TcpStream::connect_timeout(&addr, timeout).is_err() {
        return report;
    }
    report.reachable = true;

    // ── Protocol matrix ──────────────────────────────────────────────────────
    let versions = cfg.versions_to_test();
    for (label, ver) in &versions {
        if Instant::now() > deadline {
            break;
        }
        let connector = if *ver == SslVersion::TLS1_3 {
            build_connector(*ver, None, None, false)
        } else {
            legacy_connector(*ver, false)
        };
        let supported =
            connector.is_ok_and(|c| do_handshake(addr, &sni, starttls, &c, false, timeout).is_ok());
        if supported {
            report.tls = true;
        }
        report.protocols.push(ProtocolResult {
            version: label,
            supported,
        });
    }

    if !report.tls {
        return report;
    }

    // ── Cipher enumeration per supported protocol ────────────────────────────
    if cfg.check_ciphers {
        for (label, ver) in &versions {
            let ok = report
                .protocols
                .iter()
                .any(|p| p.version == *label && p.supported);
            if !ok || Instant::now() > deadline {
                continue;
            }
            if *ver == SslVersion::TLS1_3 {
                enumerate_tls13(addr, &sni, &cfg, starttls, deadline, &mut report.ciphers);
            } else {
                enumerate_legacy(
                    addr,
                    &sni,
                    &cfg,
                    starttls,
                    *ver,
                    label,
                    deadline,
                    &mut report.ciphers,
                );
            }
        }
    }

    // ── Certificate / chain / OCSP / ALPN via the best supported protocol ─────
    if let Some(ver) = pick_best(&report.protocols) {
        let connector = if ver == SslVersion::TLS1_3 {
            build_connector(ver, None, None, true)
        } else {
            legacy_connector(ver, true)
        };
        if let Ok(c) = connector {
            if let Ok(h) = do_handshake(addr, &sni, starttls, &c, cfg.check_ocsp, timeout) {
                report.chain_len = h.chain.len();
                report.leaf = h.chain.into_iter().next();
                report.verify_ok = h.verify_ok;
                report.verify_msg = h.verify_msg;
                report.alpn = h.alpn;
                if cfg.check_ocsp {
                    report.ocsp_stapled = Some(h.ocsp_stapled);
                }
            }
        }
    }

    report
}

fn pick_best(protocols: &[ProtocolResult]) -> Option<SslVersion> {
    for (label, ver) in [
        ("TLSv1.3", SslVersion::TLS1_3),
        ("TLSv1.2", SslVersion::TLS1_2),
        ("TLSv1.1", SslVersion::TLS1_1),
        ("TLSv1.0", SslVersion::TLS1),
        ("SSLv3", SslVersion::SSL3),
    ] {
        if protocols.iter().any(|p| p.version == label && p.supported) {
            return Some(ver);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn enumerate_legacy(
    addr: SocketAddr,
    sni: &str,
    cfg: &TlsScanConfig,
    starttls: StartTls,
    ver: SslVersion,
    label: &'static str,
    deadline: Instant,
    out: &mut Vec<CipherInfo>,
) {
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let mut excludes = String::new();
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..cfg.cipher_limit {
        if Instant::now() > deadline {
            break;
        }
        let list = format!("ALL:COMPLEMENTOFALL{excludes}:@SECLEVEL=0");
        let Ok(connector) = build_connector(ver, Some(&list), None, false) else {
            break;
        };
        let Ok(h) = do_handshake(addr, sni, starttls, &connector, false, timeout) else {
            break;
        };
        let Some(mut cipher) = h.cipher else {
            break;
        };
        if !seen.insert(cipher.name.clone()) {
            break;
        }
        excludes.push_str(":!");
        excludes.push_str(&cipher.name);
        cipher.protocol = label.to_string();
        if !out
            .iter()
            .any(|c| c.name == cipher.name && c.protocol == cipher.protocol)
        {
            out.push(cipher);
        }
    }
}

fn enumerate_tls13(
    addr: SocketAddr,
    sni: &str,
    cfg: &TlsScanConfig,
    starttls: StartTls,
    deadline: Instant,
    out: &mut Vec<CipherInfo>,
) {
    let timeout = Duration::from_millis(cfg.timeout_ms);
    for suite in TLS13_SUITES {
        if Instant::now() > deadline {
            break;
        }
        let Ok(connector) = build_connector(SslVersion::TLS1_3, None, Some(suite), false) else {
            continue;
        };
        if let Ok(h) = do_handshake(addr, sni, starttls, &connector, false, timeout) {
            if let Some(cipher) = h.cipher {
                if !out.iter().any(|c| c.name == cipher.name) {
                    out.push(cipher);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hostname matching
// ─────────────────────────────────────────────────────────────────────────────

fn host_matches_cert(host: &str, cert: &CertInfo) -> bool {
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
        // Wildcard matches exactly one left-most label.
        if let Some((_, rest)) = host.split_once('.') {
            return rest.eq_ignore_ascii_case(suffix);
        }
        return false;
    }
    host.eq_ignore_ascii_case(pattern)
}

// ─────────────────────────────────────────────────────────────────────────────
// Grading (SSL-Labs-style cap ladder)
// ─────────────────────────────────────────────────────────────────────────────

const GRADE_LADDER: &[&str] = &["A+", "A", "B", "C", "D", "E", "F"];

fn grade_rank(grade: &str) -> usize {
    GRADE_LADDER
        .iter()
        .position(|g| *g == grade)
        .unwrap_or(GRADE_LADDER.len() - 1)
}

/// Return the worse (lower) of two grades on the ladder.
fn worse<'a>(a: &'a str, b: &'a str) -> &'a str {
    if grade_rank(a) >= grade_rank(b) {
        a
    } else {
        b
    }
}

struct GradeOutcome {
    grade: String,
    trust_issue: bool,
    reasons: Vec<String>,
}

fn grade_port(report: &PortReport, host: &str, hsts_ok: bool, cfg: &TlsScanConfig) -> GradeOutcome {
    let mut cap = "A+";
    let mut reasons: Vec<String> = Vec::new();
    let supported = |v: &str| {
        report
            .protocols
            .iter()
            .any(|p| p.version == v && p.supported)
    };

    if supported("SSLv3") {
        cap = worse(cap, "F");
        reasons.push("SSLv3 negotiated (POODLE) → cap F".to_string());
    }
    if supported("TLSv1.0") {
        cap = worse(cap, "C");
        reasons.push("TLS 1.0 negotiated → cap C".to_string());
    }
    if supported("TLSv1.1") {
        cap = worse(cap, "B");
        reasons.push("TLS 1.1 negotiated → cap B".to_string());
    }
    if cfg.test_tls13 && !supported("TLSv1.3") {
        cap = worse(cap, "A");
        reasons.push("No TLS 1.3 support → cap A".to_string());
    }
    if cfg.test_tls12 && !supported("TLSv1.2") && !supported("TLSv1.3") {
        cap = worse(cap, "C");
        reasons.push("No modern protocol (TLS 1.2/1.3) → cap C".to_string());
    }

    // Cipher posture
    let has_fs = report.ciphers.iter().any(|c| c.pfs);
    for c in &report.ciphers {
        let up = c.name.to_ascii_uppercase();
        if up.contains("NULL") || up.contains("ADH") || up.contains("AECDH") || up.contains("EXP") {
            cap = worse(cap, "F");
            reasons.push(format!("Insecure cipher {} → cap F", c.name));
        } else if up.contains("RC4") {
            cap = worse(cap, "F");
            reasons.push("RC4 cipher offered → cap F".to_string());
        } else if up.contains("3DES") || up.contains("DES") {
            cap = worse(cap, "C");
            reasons.push("64-bit block cipher (SWEET32) → cap C".to_string());
        }
    }
    if !report.ciphers.is_empty() && !has_fs {
        cap = worse(cap, "B");
        reasons.push("No forward-secrecy cipher → cap B".to_string());
    }

    // Certificate key / signature strength
    let mut trust_issue = false;
    if let Some(leaf) = &report.leaf {
        if (leaf.key_type == "RSA" && leaf.key_bits < 2048)
            || (leaf.key_type == "DSA")
            || (leaf.key_type == "EC" && leaf.key_bits < 256)
        {
            cap = worse(cap, "F");
            reasons.push(format!(
                "Weak certificate key — {} {}-bit → cap F",
                leaf.key_type, leaf.key_bits
            ));
        }
        if leaf.sig_weak {
            cap = worse(cap, "C");
            reasons.push(format!(
                "Weak signature algorithm {} → cap C",
                leaf.sig_algo
            ));
        }
        if leaf.expired {
            trust_issue = true;
            reasons.push("Certificate expired".to_string());
        }
        if leaf.not_yet_valid {
            trust_issue = true;
            reasons.push("Certificate not yet valid".to_string());
        }
        if leaf.self_signed {
            trust_issue = true;
            reasons.push("Self-signed certificate".to_string());
        }
        if cfg.check_hostname && !host_matches_cert(host, leaf) {
            trust_issue = true;
            reasons.push("Certificate does not match hostname".to_string());
        }
    } else if report.tls {
        trust_issue = true;
        reasons.push("No certificate presented".to_string());
    }
    if cfg.check_chain_trust && report.leaf.is_some() && !report.verify_ok {
        trust_issue = true;
        reasons.push(format!("Chain not trusted: {}", report.verify_msg));
    }

    // HSTS gates A+
    if grade_rank(cap) == 0 && !hsts_ok {
        cap = "A";
        reasons.push("No strong HSTS → A+ withheld".to_string());
    }

    let grade = if trust_issue {
        format!("T (would be {cap})")
    } else {
        cap.to_string()
    };
    GradeOutcome {
        grade,
        trust_issue,
        reasons,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding builders
// ─────────────────────────────────────────────────────────────────────────────

fn cert_evidence(leaf: &CertInfo) -> Value {
    json!({
        "subject": leaf.subject,
        "issuer": leaf.issuer,
        "common_name": leaf.common_name,
        "self_signed": leaf.self_signed,
        "not_before": leaf.not_before,
        "not_after": leaf.not_after,
        "days_until_expiry": leaf.days_until_expiry,
        "validity_days": leaf.validity_days,
        "key_type": leaf.key_type,
        "key_bits": leaf.key_bits,
        "signature_algorithm": leaf.sig_algo,
        "san": leaf.san,
        "wildcard": leaf.wildcard,
        "serial": leaf.serial_hex,
        "sha256_fingerprint": leaf.sha256_fp,
    })
}

fn protocol_evidence(report: &PortReport) -> Value {
    Value::Array(
        report
            .protocols
            .iter()
            .map(|p| json!({ "version": p.version, "supported": p.supported }))
            .collect(),
    )
}

fn cipher_evidence(report: &PortReport) -> Value {
    Value::Array(
        report
            .ciphers
            .iter()
            .map(|c| {
                json!({
                    "name": c.name,
                    "iana": c.iana,
                    "bits": c.bits,
                    "protocol": c.protocol,
                    "forward_secrecy": c.pfs,
                    "weaknesses": c.weaknesses,
                })
            })
            .collect(),
    )
}

fn severity_for_grade(grade: &str, trust_issue: bool) -> &'static str {
    if trust_issue {
        return "critical";
    }
    let base = grade.split_whitespace().next().unwrap_or(grade);
    match base {
        "A+" | "A" => "info",
        "B" => "low",
        "C" => "medium",
        "D" | "E" => "high",
        _ => "critical",
    }
}

fn sev_rank(sev: &str) -> u8 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn bump_worst(current: &str, candidate: &str) -> String {
    if sev_rank(candidate) > sev_rank(current) {
        candidate.to_string()
    } else {
        current.to_string()
    }
}

fn with_category(mut finding: Value, category: &str) -> Value {
    if let Some(obj) = finding.as_object_mut() {
        obj.insert("category".to_string(), json!(category));
    }
    finding
}

/// Strip SSL-Labs-style trust suffix and return the base letter grade.
fn grade_base(grade: &str) -> &str {
    if let Some(rest) = grade.strip_prefix("T (would be ") {
        return rest.trim_end_matches(')');
    }
    grade.split_whitespace().next().unwrap_or(grade)
}

fn grade_to_score(grade: &str, trust_issue: bool) -> u32 {
    let mut score: u32 = match grade_base(grade) {
        "A+" => 100,
        "A" => 95,
        "B" => 85,
        "C" => 70,
        "D" => 55,
        "E" => 40,
        _ => 20,
    };
    if trust_issue {
        score = score.saturating_sub(25);
    }
    score.clamp(0, 100)
}

#[derive(Clone, Debug, Default)]
struct TlsPosture {
    ports_scanned: usize,
    ports_tls: usize,
    best_grade: String,
    worst_grade: String,
    grades_by_port: Vec<(u16, String)>,
    hsts_ok: bool,
    dane_checked: bool,
    dane_present: bool,
    worst_severity: String,
    trust_issue: bool,
}

impl TlsPosture {
    fn record_port_grade(&mut self, port: u16, grade: &GradeOutcome) {
        self.ports_tls += 1;
        self.grades_by_port.push((port, grade.grade.clone()));
        if self.best_grade.is_empty() {
            self.best_grade = grade.grade.clone();
            self.worst_grade = grade.grade.clone();
        } else {
            let best_base = grade_base(&self.best_grade);
            let worst_base = grade_base(&self.worst_grade);
            let new_base = grade_base(&grade.grade);
            if grade_rank(new_base) < grade_rank(best_base) {
                self.best_grade = grade.grade.clone();
            }
            if grade_rank(new_base) > grade_rank(worst_base) {
                self.worst_grade = grade.grade.clone();
            }
        }
        if grade.trust_issue {
            self.trust_issue = true;
        }
        let sev = severity_for_grade(&grade.grade, grade.trust_issue);
        self.worst_severity = bump_worst(&self.worst_severity, sev);
    }

    fn posture_score(&self) -> u32 {
        if self.grades_by_port.is_empty() {
            return 0;
        }
        let mut total = 0u32;
        for (_, g) in &self.grades_by_port {
            let trust = g.starts_with("T (");
            total += grade_to_score(g, trust);
        }
        let avg = total / u32::try_from(self.grades_by_port.len()).unwrap_or(1);
        let mut score = avg;
        if !self.hsts_ok {
            score = score.saturating_sub(5);
        }
        if self.dane_checked && self.dane_present {
            score = (score + 3).min(100);
        }
        score
    }

    fn display_grade(&self) -> String {
        if self.worst_grade.is_empty() {
            return "N/A".to_string();
        }
        self.worst_grade.clone()
    }
}

#[allow(clippy::too_many_lines)]
fn findings_for_port(
    report: &PortReport,
    target: &str,
    host: &str,
    hsts_ok: bool,
    cfg: &TlsScanConfig,
) -> Vec<Value> {
    let mut out = Vec::new();
    let tag = |t: &str| format!("[:{}] {t}", report.port);

    if !report.reachable {
        return out;
    }
    if !report.tls {
        out.push(finding_rich(
            ENGINE_ID,
            &tag("Port reachable but no TLS negotiated"),
            "info",
            MITRE_MITM,
            "TCP connect succeeded but no SSL/TLS version completed a handshake on this port.",
            target,
            0.6,
            Evidence::new()
                .with("host", host)
                .with("port", i64::from(report.port))
                .with(
                    "starttls",
                    StartTls::parse(&cfg.starttls_raw, report.port).as_str(),
                ),
        ));
        return out;
    }

    let grade = grade_port(report, host, hsts_ok, cfg);
    let summary_sev = severity_for_grade(&grade.grade, grade.trust_issue);
    let evidence = Evidence::new()
        .with("host", host)
        .with("port", i64::from(report.port))
        .with("grade", grade.grade.clone())
        .with("grade_reasons", json!(grade.reasons))
        .with("protocols", protocol_evidence(report))
        .with(
            "cipher_count",
            i64::try_from(report.ciphers.len()).unwrap_or(0),
        )
        .with("ciphers", cipher_evidence(report))
        .with("forward_secrecy", report.ciphers.iter().any(|c| c.pfs))
        .with("chain_length", i64::try_from(report.chain_len).unwrap_or(0))
        .with("chain_trusted", report.verify_ok)
        .with("chain_verify", report.verify_msg.clone())
        .with("ocsp_stapled", json!(report.ocsp_stapled))
        .with("alpn", json!(report.alpn))
        .with(
            "certificate",
            report.leaf.as_ref().map_or(Value::Null, cert_evidence),
        );
    out.push(with_category(
        finding_rich(
            ENGINE_ID,
            &tag(&format!("TLS posture grade: {}", grade.grade)),
            summary_sev,
            MITRE_MITM,
            &format!(
                "Live TLS assessment of {host}:{} — grade {}. {} protocol(s) probed, {} cipher(s) enumerated, chain {} ({}).",
                report.port,
                grade.grade,
                report.protocols.len(),
                report.ciphers.len(),
                if report.verify_ok { "trusted" } else { "untrusted" },
                report.verify_msg,
            ),
            target,
            0.97,
            evidence,
        ),
        "tls_grade",
    ));

    // Deprecated protocol findings
    if cfg.check_protocols {
        for p in &report.protocols {
            if !p.supported {
                continue;
            }
            let (sev, note, cve) = match p.version {
                "SSLv3" => ("high", "SSLv3 is broken (POODLE).", "CVE-2014-3566"),
                "TLSv1.0" => (
                    "medium",
                    "TLS 1.0 is deprecated (PCI-DSS prohibits it).",
                    "CVE-2011-3389",
                ),
                "TLSv1.1" => ("medium", "TLS 1.1 is deprecated.", ""),
                _ => continue,
            };
            out.push(finding_rich(
                ENGINE_ID,
                &tag(&format!("Deprecated protocol enabled: {}", p.version)),
                sev,
                MITRE_MITM,
                &format!(
                    "{note} Disable {} on the server and require TLS 1.2+.",
                    p.version
                ),
                target,
                0.95,
                Evidence::new()
                    .with("protocol", p.version)
                    .with("cve", cve)
                    .with("port", i64::from(report.port)),
            ));
        }
        if cfg.test_tls13
            && !report
                .protocols
                .iter()
                .any(|p| p.version == "TLSv1.3" && p.supported)
        {
            out.push(finding_rich(
                ENGINE_ID,
                &tag("TLS 1.3 not supported"),
                "low",
                MITRE_CRYPTO,
                "The server does not negotiate TLS 1.3. Enable it for the strongest handshakes (1-RTT, modern AEAD, no legacy downgrade).",
                target,
                0.9,
                Evidence::new().with("port", i64::from(report.port)),
            ));
        }
    }

    // Cipher weakness findings (deduped by weakness category)
    if cfg.check_ciphers {
        let mut seen_cat: HashSet<String> = HashSet::new();
        for c in &report.ciphers {
            for w in &c.weaknesses {
                if w.starts_with("CBC mode") || w.starts_with("No forward secrecy") {
                    continue; // handled at posture level to avoid noise
                }
                let cat = w.split(' ').next().unwrap_or(w).to_string();
                if !seen_cat.insert(cat) {
                    continue;
                }
                let sev = if w.contains("NULL")
                    || w.contains("Anonymous")
                    || w.contains("EXPORT")
                    || w.contains("RC4")
                {
                    "high"
                } else {
                    "medium"
                };
                out.push(finding_rich(
                    ENGINE_ID,
                    &tag(&format!("Weak cipher accepted: {}", c.name)),
                    sev,
                    MITRE_CRYPTO,
                    w,
                    target,
                    0.93,
                    Evidence::new()
                        .with("cipher", c.name.clone())
                        .with("iana", json!(c.iana))
                        .with("bits", i64::from(c.bits))
                        .with("protocol", c.protocol.clone())
                        .with("port", i64::from(report.port)),
                ));
            }
        }
    }

    // Forward secrecy
    if cfg.check_forward_secrecy
        && !report.ciphers.is_empty()
        && !report.ciphers.iter().any(|c| c.pfs)
    {
        out.push(finding_rich(
            ENGINE_ID,
            &tag("No forward secrecy"),
            "medium",
            MITRE_CRYPTO,
            "No ECDHE/DHE cipher was negotiated. Without forward secrecy a future key compromise decrypts all captured past sessions. Prefer ECDHE suites.",
            target,
            0.9,
            Evidence::new().with("port", i64::from(report.port)),
        ));
    }

    // Certificate findings
    if cfg.check_certificate {
        if let Some(leaf) = &report.leaf {
            out.extend(certificate_findings(leaf, report, target, host, cfg));
        }
    }

    // OCSP stapling
    if cfg.check_ocsp {
        if let Some(false) = report.ocsp_stapled {
            out.push(finding_rich(
                ENGINE_ID,
                &tag("OCSP stapling not enabled"),
                "low",
                MITRE_MITM,
                "The server did not staple an OCSP response. Stapling speeds revocation checks and avoids leaking client browsing to the CA. Enable OCSP stapling.",
                target,
                0.85,
                Evidence::new().with("port", i64::from(report.port)),
            ));
        }
    }

    out
}

fn certificate_findings(
    leaf: &CertInfo,
    report: &PortReport,
    target: &str,
    host: &str,
    cfg: &TlsScanConfig,
) -> Vec<Value> {
    let mut out = Vec::new();
    let tag = |t: &str| format!("[:{}] {t}", report.port);
    let ev = || {
        Evidence::new()
            .with("certificate", cert_evidence(leaf))
            .with("port", i64::from(report.port))
    };

    if leaf.expired {
        out.push(finding_rich(
            ENGINE_ID,
            &tag("Expired TLS certificate"),
            "high",
            MITRE_MITM,
            &format!(
                "Certificate for {host} expired (notAfter {}). Renew immediately — clients reject it.",
                leaf.not_after
            ),
            target,
            0.98,
            ev(),
        ));
    } else if leaf.days_until_expiry <= cfg.expiry_warning_days {
        out.push(finding_rich(
            ENGINE_ID,
            &tag(&format!(
                "Certificate expires in {} days",
                leaf.days_until_expiry
            )),
            "medium",
            MITRE_MITM,
            &format!(
                "Certificate for {host} expires in {} days. Automate renewal (ACME) to avoid an outage.",
                leaf.days_until_expiry
            ),
            target,
            0.95,
            ev(),
        ));
    }
    if leaf.not_yet_valid {
        out.push(finding_rich(
            ENGINE_ID,
            &tag("Certificate not yet valid"),
            "high",
            MITRE_MITM,
            &format!(
                "Certificate notBefore is in the future ({}). Check server clock / issuance.",
                leaf.not_before
            ),
            target,
            0.95,
            ev(),
        ));
    }
    if leaf.self_signed {
        out.push(finding_rich(
            ENGINE_ID,
            &tag("Self-signed certificate"),
            "high",
            MITRE_MITM,
            "The leaf certificate is self-signed — no public CA path, so clients cannot authenticate the server (MITM-enabling).",
            target,
            0.95,
            ev(),
        ));
    }
    if cfg.check_hostname && !host_matches_cert(host, leaf) {
        out.push(finding_rich(
            ENGINE_ID,
            &tag("Certificate hostname mismatch"),
            "high",
            MITRE_MITM,
            &format!(
                "None of the certificate names match {host}. SAN={:?}, CN={:?}.",
                leaf.san, leaf.common_name
            ),
            target,
            0.9,
            ev(),
        ));
    }
    if leaf.key_type == "RSA" && leaf.key_bits < 2048 {
        out.push(finding_rich(
            ENGINE_ID,
            &tag(&format!("Weak RSA key ({}-bit)", leaf.key_bits)),
            "high",
            MITRE_CRYPTO,
            "RSA key below 2048-bit is under NIST minimum. Reissue with ≥2048-bit RSA or ECDSA P-256.",
            target,
            0.95,
            ev(),
        ));
    }
    if leaf.sig_weak {
        out.push(finding_rich(
            ENGINE_ID,
            &tag(&format!("Weak certificate signature ({})", leaf.sig_algo)),
            "medium",
            MITRE_CRYPTO,
            "Certificate signed with a deprecated hash (MD5/SHA-1). Reissue with SHA-256 or stronger.",
            target,
            0.92,
            ev(),
        ));
    }
    if cfg.check_chain_trust && !report.verify_ok {
        out.push(finding_rich(
            ENGINE_ID,
            &tag("Untrusted certificate chain"),
            "high",
            MITRE_MITM,
            &format!(
                "OpenSSL chain verification failed: {} (chain length {}). Install the full intermediate chain.",
                report.verify_msg, report.chain_len
            ),
            target,
            0.9,
            ev(),
        ));
    }
    if leaf.validity_days > 398 {
        out.push(finding_rich(
            ENGINE_ID,
            &tag("Certificate validity exceeds 398 days"),
            "low",
            MITRE_MITM,
            &format!(
                "Validity window is {} days; CA/Browser Forum caps public certs at 398 days. Shorten via automated renewal.",
                leaf.validity_days
            ),
            target,
            0.8,
            ev(),
        ));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Async transport-hardening probes (HTTP/HSTS, CT logs, CAA)
// ─────────────────────────────────────────────────────────────────────────────

struct HttpHardening {
    hsts_ok: bool,
    findings: Vec<Value>,
}

async fn http_hardening(target: &str, host: &str, cfg: &TlsScanConfig) -> HttpHardening {
    let mut findings = Vec::new();
    let mut hsts_ok = false;
    if !cfg.check_http_headers {
        return HttpHardening { hsts_ok, findings };
    }
    let client = http_client().await;
    let base = normalize_url(target);
    if let Some(p) = http_get(&client, &base).await {
        match header_value(&p.headers, "strict-transport-security") {
            Some(hsts) => {
                let max_age = parse_hsts_max_age(hsts);
                hsts_ok = max_age >= 15_768_000;
                if !hsts_ok {
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "HSTS max-age too short",
                        "low",
                        MITRE_MITM,
                        &format!(
                            "HSTS present ('{hsts}') but max-age below 6 months. Set max-age=31536000; includeSubDomains; preload."
                        ),
                        target,
                        0.85,
                        Evidence::new()
                            .with("hsts", hsts)
                            .with("max_age", i64::try_from(max_age).unwrap_or(0)),
                    ));
                }
            }
            None => {
                findings.push(finding_rich(
                    ENGINE_ID,
                    "Missing HSTS header",
                    "medium",
                    MITRE_MITM,
                    "No Strict-Transport-Security header. Without HSTS the first request can be downgraded to HTTP (SSL-strip). Add HSTS with a long max-age.",
                    target,
                    0.9,
                    Evidence::new().with("final_url", p.final_url.clone()),
                ));
            }
        }
        if cfg.check_security_headers {
            for (hdr, title) in [
                ("x-content-type-options", "Missing X-Content-Type-Options"),
                ("x-frame-options", "Missing X-Frame-Options"),
                ("content-security-policy", "Missing Content-Security-Policy"),
            ] {
                if header_value(&p.headers, hdr).is_none() {
                    findings.push(finding_rich(
                        ENGINE_ID,
                        title,
                        "low",
                        MITRE_MITM,
                        &format!("Security header '{hdr}' is absent on the HTTPS response."),
                        target,
                        0.75,
                        Evidence::new().with("header", hdr),
                    ));
                }
            }
        }
    }

    // HTTP → HTTPS redirect
    let http_url = format!("http://{host}");
    if let Some(p) = http_get(&client, &http_url).await {
        let redirected = p.final_url.starts_with("https://");
        if p.status == 200 && !redirected {
            findings.push(finding_rich(
                ENGINE_ID,
                "HTTP not redirected to HTTPS",
                "medium",
                MITRE_MITM,
                "Plain HTTP returns 200 without redirecting to HTTPS, allowing cleartext access and SSL-strip. Force a 301 to https://.",
                target,
                0.88,
                Evidence::new()
                    .with("http_url", http_url)
                    .with("status", i64::from(p.status)),
            ));
        }
    }
    HttpHardening { hsts_ok, findings }
}

fn parse_hsts_max_age(hsts: &str) -> u64 {
    for part in hsts.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("max-age=") {
            return v.trim().trim_matches('"').parse().unwrap_or(0);
        }
    }
    0
}

async fn ct_log_findings(target: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let client = http_client().await;
    let crt_url = format!("https://crt.sh/?q={host}&output=json");
    if let Some(p) = http_get(&client, &crt_url).await {
        if p.status == 200 && p.body.trim_start().starts_with('[') {
            if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&p.body) {
                let mut names: HashSet<String> = HashSet::new();
                for c in &arr {
                    if let Some(nv) = c.get("name_value").and_then(Value::as_str) {
                        for n in nv.split('\n') {
                            names.insert(n.trim().to_ascii_lowercase());
                        }
                    }
                }
                let sample: Vec<&String> = names.iter().take(40).collect();
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("Certificate Transparency: {} log entries", arr.len()),
                    "info",
                    MITRE_MITM,
                    &format!(
                        "crt.sh holds {} CT entries covering {} distinct names for {host}. Review for unexpected or stale issuance.",
                        arr.len(),
                        names.len()
                    ),
                    target,
                    0.8,
                    Evidence::new()
                        .with("ct_entries", i64::try_from(arr.len()).unwrap_or(0))
                        .with("distinct_names", i64::try_from(names.len()).unwrap_or(0))
                        .with("sample_names", json!(sample)),
                ));
            }
        }
    }
    out
}

async fn caa_findings(target: &str, host: &str) -> Vec<Value> {
    let records = dns_caa(host).await;
    if records.is_empty() {
        vec![with_category(
            finding_rich(
                ENGINE_ID,
                "No DNS CAA records",
                "low",
                MITRE_MITM,
                &format!(
                    "{host} publishes no CAA records, so any public CA may issue for it. Add CAA to restrict issuance to your CA(s)."
                ),
                target,
                0.78,
                Evidence::new().with("host", host),
            ),
            "tls_caa",
        )]
    } else {
        vec![with_category(
            finding_rich(
                ENGINE_ID,
                &format!("CAA policy present ({} record/s)", records.len()),
                "info",
                MITRE_MITM,
                "DNS CAA records restrict which CAs may issue certificates for this domain.",
                target,
                0.85,
                Evidence::new().with("caa", json!(records)),
            ),
            "tls_caa",
        )]
    }
}

async fn dane_findings(target: &str, host: &str, ports: &[u16]) -> (Vec<Value>, bool, bool) {
    let mut out = Vec::new();
    let mut checked = false;
    let mut any_present = false;
    let mut seen: HashSet<String> = HashSet::new();

    for &port in ports {
        let tlsa_name = format!("_{port}._tcp.{host}");
        if !seen.insert(tlsa_name.clone()) {
            continue;
        }
        let records = dns_tlsa(&tlsa_name).await;
        checked = true;
        if records.is_empty() {
            out.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!("No DANE/TLSA for {tlsa_name}"),
                    "info",
                    MITRE_MITM,
                    &format!(
                        "{tlsa_name} has no TLSA records. DANE (RFC 6698) pins the expected certificate in DNS — when DNSSEC is enabled, DANE-aware clients reject mismatched certs."
                    ),
                    target,
                    0.72,
                    Evidence::new()
                        .with("tlsa_name", tlsa_name.clone())
                        .check("tlsa_present", false, "none"),
                ),
                "tls_dane",
            ));
        } else {
            any_present = true;
            out.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!("DANE/TLSA present for {tlsa_name}"),
                    "info",
                    MITRE_MITM,
                    &format!(
                        "{tlsa_name} publishes {} TLSA record(s). DANE-aware clients can reject certificates that do not match the pinned association.",
                        records.len()
                    ),
                    target,
                    0.88,
                    Evidence::new()
                        .with("tlsa_name", tlsa_name)
                        .with("tlsa", json!(records)),
                ),
                "tls_dane",
            ));
        }
    }
    (out, checked, any_present)
}

fn pci_nist_tags(posture: &TlsPosture, reports: &[PortReport]) -> Value {
    let mut pci_fail = Vec::new();
    let mut nist_fail = Vec::new();
    for report in reports {
        for p in &report.protocols {
            if !p.supported {
                continue;
            }
            if p.version == "SSLv3" || p.version == "TLSv1.0" || p.version == "TLSv1.1" {
                pci_fail.push(format!("{}:{}", report.port, p.version));
                nist_fail.push(format!("{}:{}", report.port, p.version));
            }
        }
        for c in &report.ciphers {
            let up = c.name.to_ascii_uppercase();
            if up.contains("RC4")
                || up.contains("3DES")
                || up.contains("NULL")
                || up.contains("EXPORT")
            {
                pci_fail.push(format!("{}:{}", report.port, c.name));
            }
            if !c.pfs && c.protocol != "TLSv1.3" {
                nist_fail.push(format!("{}:no_pfs", report.port));
            }
        }
        if let Some(leaf) = &report.leaf {
            if leaf.key_bits < 2048 && leaf.key_type == "RSA" {
                pci_fail.push(format!("{}:weak_key", report.port));
                nist_fail.push(format!("{}:weak_key", report.port));
            }
        }
    }
    if posture.trust_issue {
        pci_fail.push("trust".to_string());
        nist_fail.push("trust".to_string());
    }
    json!({
        "pci_dss_tls12_plus": pci_fail.is_empty(),
        "pci_dss_violations": pci_fail,
        "nist_sp800_52_rev2": nist_fail.is_empty(),
        "nist_violations": nist_fail,
    })
}

fn build_posture_summary(
    target: &str,
    host: &str,
    posture: &TlsPosture,
    reports: &[PortReport],
    finding_count: usize,
) -> Value {
    let score = posture.posture_score();
    let grade = posture.display_grade();
    let description = format!(
        "TLS/PKI posture for {host} from {} port(s) with {} TLS handshake(s) across {} finding(s). \
         Best grade {} · worst {} · HSTS {} · DANE {}.",
        posture.ports_scanned,
        posture.ports_tls,
        finding_count,
        posture.best_grade,
        posture.worst_grade,
        if posture.hsts_ok { "strong" } else { "weak/missing" },
        if !posture.dane_checked {
            "not checked"
        } else if posture.dane_present {
            "present"
        } else {
            "absent"
        },
    );
    let compliance = pci_nist_tags(posture, reports);
    let ev = Evidence::new()
        .with("posture_score", score)
        .with("grade", grade.clone())
        .with("best_grade", posture.best_grade.clone())
        .with("worst_grade", posture.worst_grade.clone())
        .with(
            "ports_scanned",
            i64::try_from(posture.ports_scanned).unwrap_or(0),
        )
        .with("ports_tls", i64::try_from(posture.ports_tls).unwrap_or(0))
        .with("hsts_ok", posture.hsts_ok)
        .with("dane_checked", posture.dane_checked)
        .with("dane_present", posture.dane_present)
        .with("trust_issue", posture.trust_issue)
        .with("worst_severity", posture.worst_severity.clone())
        .with(
            "grades_by_port",
            json!(posture
                .grades_by_port
                .iter()
                .map(|(p, g)| json!({ "port": p, "grade": g }))
                .collect::<Vec<_>>()),
        )
        .with("compliance", compliance);

    let mut summary = finding_rich(
        ENGINE_ID,
        &format!("TLS posture {}/100 (grade {})", score, grade),
        "info",
        MITRE_MITM,
        &description,
        target,
        0.99,
        ev,
    );
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("category".to_string(), json!("posture_summary"));
        obj.insert("summary".to_string(), json!(true));
        obj.insert("posture_score".to_string(), json!(score));
        obj.insert("grade".to_string(), json!(grade));
        obj.insert(
            "worst_severity".to_string(),
            json!(posture.worst_severity.clone()),
        );
    }
    summary
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration / public API
// ─────────────────────────────────────────────────────────────────────────────

fn extract_host_port(target: &str) -> (String, Option<u16>) {
    let t = target
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let authority = t.split('/').next().unwrap_or(t);
    if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), Some(port));
        }
    }
    (authority.to_string(), None)
}

async fn run_pki_tls_scan(target: &str, mut cfg: TlsScanConfig) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let (host, url_port) = extract_host_port(target);
    if host.is_empty() {
        return EngineResult::error("could not parse host from target");
    }
    // A port embedded in the URL takes precedence unless the operator set ports explicitly.
    if let Some(p) = url_port {
        if cfg.ports == vec![443] {
            cfg.ports = vec![p];
        }
    }
    let sni = cfg.sni_override.clone().unwrap_or_else(|| host.clone());

    let mut findings: Vec<Value> = Vec::new();
    let mut graded: Vec<String> = Vec::new();
    let mut posture = TlsPosture {
        ports_scanned: cfg.ports.len(),
        worst_severity: "info".to_string(),
        ..TlsPosture::default()
    };
    let mut port_reports: Vec<PortReport> = Vec::new();

    // HTTP hardening once (HSTS feeds the grade), then per-port TLS probing.
    let hardening = http_hardening(target, &host, &cfg).await;
    findings.extend(hardening.findings);
    posture.hsts_ok = hardening.hsts_ok;

    let mut reachable_any = false;
    for port in cfg.ports.clone() {
        let host_c = host.clone();
        let sni_c = sni.clone();
        let cfg_c = cfg.clone();
        let report =
            tokio::task::spawn_blocking(move || probe_port_blocking(host_c, sni_c, port, cfg_c))
                .await
                .unwrap_or(PortReport {
                    port,
                    ..PortReport::default()
                });
        if report.reachable {
            reachable_any = true;
        }
        if report.tls {
            let g = grade_port(&report, &host, hardening.hsts_ok, &cfg);
            graded.push(format!("{}:{}={}", host, report.port, g.grade));
            posture.record_port_grade(report.port, &g);
        }
        let port_findings = findings_for_port(&report, target, &host, hardening.hsts_ok, &cfg);
        for f in &port_findings {
            if let Some(sev) = f.get("severity").and_then(Value::as_str) {
                posture.worst_severity = bump_worst(&posture.worst_severity, sev);
            }
        }
        findings.extend(port_findings);
        port_reports.push(report);
    }

    if cfg.check_ct_logs {
        findings.extend(ct_log_findings(target, &host).await);
    }
    if cfg.check_caa {
        findings.extend(caa_findings(target, &host).await);
    }
    if cfg.check_dane {
        let (dane_f, checked, present) = dane_findings(target, &host, &cfg.ports).await;
        posture.dane_checked = checked;
        posture.dane_present = present;
        findings.extend(dane_f);
    }

    if cfg.check_posture_score && reachable_any && !posture.grades_by_port.is_empty() {
        findings.insert(
            0,
            build_posture_summary(target, &host, &posture, &port_reports, findings.len()),
        );
    }

    let summary = if !reachable_any {
        format!(
            "pki_tls: no reachable TLS port on {host} (tried {:?})",
            cfg.ports
        )
    } else if graded.is_empty() {
        format!(
            "pki_tls: {} finding(s); no TLS handshake completed on {host}",
            findings.len()
        )
    } else {
        format!(
            "pki_tls: {} finding(s) — TLS grade(s): {}",
            findings.len(),
            graded.join(", ")
        )
    };
    EngineResult::ok(findings, summary)
}

/// Back-compatible entry (default config). Used by crypto/mobile/network alias engines.
pub async fn run_pki_tls_result(target: &str) -> EngineResult {
    run_pki_tls_scan(target, TlsScanConfig::default()).await
}

/// Parameter-aware entry used by the dispatcher: reads every knob from `ctx.job_params`.
pub async fn run_pki_tls_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let (_, url_port) = extract_host_port(target);
    let cfg = TlsScanConfig::from_ctx(ctx, url_port.unwrap_or(443));
    run_pki_tls_scan(target, cfg).await
}

pub async fn run_pki_tls(target: &str) {
    print_result(run_pki_tls_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_with(params: Value) -> EngineRunContext {
        EngineRunContext {
            job_params: params,
            ..Default::default()
        }
    }

    #[test]
    fn config_parses_every_knob() {
        let ctx = ctx_with(json!({
            "ports": "443, 8443",
            "sni": "api.example.com",
            "starttls": "smtp",
            "timeout_ms": 2500,
            "cipher_enumeration_limit": 12,
            "expiry_warning_days": 14,
            "protocols": "tls1.2,tls1.3",
            "check_ocsp": false,
            "check_caa": "false",
        }));
        let cfg = TlsScanConfig::from_ctx(&ctx, 443);
        assert_eq!(cfg.ports, vec![443, 8443]);
        assert_eq!(cfg.sni_override.as_deref(), Some("api.example.com"));
        assert_eq!(StartTls::parse(&cfg.starttls_raw, 443), StartTls::Smtp);
        assert_eq!(cfg.timeout_ms, 2500);
        assert_eq!(cfg.cipher_limit, 12);
        assert_eq!(cfg.expiry_warning_days, 14);
        assert!(cfg.test_tls12 && cfg.test_tls13);
        assert!(!cfg.test_ssl3 && !cfg.test_tls10 && !cfg.test_tls11);
        assert!(!cfg.check_ocsp);
        assert!(!cfg.check_caa);
    }

    #[test]
    fn default_config_is_full_coverage() {
        let cfg = TlsScanConfig::default();
        assert_eq!(cfg.ports, vec![443]);
        assert_eq!(cfg.versions_to_test().len(), 5);
        assert!(cfg.check_protocols && cfg.check_ciphers && cfg.check_certificate);
    }

    #[test]
    fn starttls_auto_maps_well_known_ports() {
        assert_eq!(StartTls::parse("auto", 25), StartTls::Smtp);
        assert_eq!(StartTls::parse("auto", 587), StartTls::Smtp);
        assert_eq!(StartTls::parse("auto", 143), StartTls::Imap);
        assert_eq!(StartTls::parse("auto", 110), StartTls::Pop3);
        assert_eq!(StartTls::parse("auto", 21), StartTls::Ftp);
        assert_eq!(StartTls::parse("auto", 443), StartTls::None);
    }

    #[test]
    fn classify_cipher_flags_legacy_and_pfs() {
        let (pfs, weak) = classify_cipher("ECDHE-RSA-AES128-GCM-SHA256", 128);
        assert!(pfs);
        assert!(weak.is_empty());

        let (pfs, weak) = classify_cipher("AES256-SHA", 256); // static RSA, CBC
        assert!(!pfs);
        assert!(weak.iter().any(|w| w.contains("forward secrecy")));
        assert!(weak.iter().any(|w| w.starts_with("CBC")));

        let (_, weak) = classify_cipher("ECDHE-RSA-RC4-SHA", 128);
        assert!(weak.iter().any(|w| w.contains("RC4")));

        let (_, weak) = classify_cipher("EXP-DES-CBC-SHA", 40);
        assert!(weak.iter().any(|w| w.contains("EXPORT")));
        assert!(weak
            .iter()
            .any(|w| w.contains("128-bit") || w.contains("< 128")));

        let (_, weak) = classify_cipher("DES-CBC3-SHA", 112);
        assert!(weak.iter().any(|w| w.contains("3DES")));

        let (pfs, weak) = classify_cipher("TLS_AES_256_GCM_SHA384", 256);
        assert!(pfs); // TLS 1.3 suites are implicitly ephemeral
        assert!(!weak.iter().any(|w| w.contains("forward secrecy")));
    }

    #[test]
    fn hostname_matching_handles_wildcards() {
        let cert = CertInfo {
            subject: "CN=*.example.com".to_string(),
            issuer: "CN=CA".to_string(),
            common_name: Some("*.example.com".to_string()),
            self_signed: false,
            not_before: String::new(),
            not_after: String::new(),
            expired: false,
            not_yet_valid: false,
            days_until_expiry: 100,
            validity_days: 90,
            key_type: "RSA".to_string(),
            key_bits: 2048,
            sig_algo: "RSA-SHA256".to_string(),
            sig_weak: false,
            san: vec!["*.example.com".to_string(), "example.com".to_string()],
            wildcard: true,
            serial_hex: String::new(),
            sha256_fp: String::new(),
        };
        assert!(host_matches_cert("api.example.com", &cert));
        assert!(host_matches_cert("example.com", &cert));
        assert!(!host_matches_cert("a.b.example.com", &cert));
        assert!(!host_matches_cert("example.org", &cert));
    }

    #[test]
    fn grade_ladder_worse_picks_lower() {
        assert_eq!(worse("A+", "C"), "C");
        assert_eq!(worse("F", "B"), "F");
        assert_eq!(worse("A", "A"), "A");
    }

    #[test]
    fn grade_to_score_maps_ladder() {
        assert_eq!(grade_to_score("A+", false), 100);
        assert_eq!(grade_to_score("B", false), 85);
        assert_eq!(grade_to_score("F", false), 20);
        assert_eq!(grade_to_score("T (would be A+)", true), 75);
    }

    #[test]
    fn grade_caps_on_legacy_protocol() {
        let report = PortReport {
            port: 443,
            reachable: true,
            tls: true,
            protocols: vec![
                ProtocolResult {
                    version: "TLSv1.0",
                    supported: true,
                },
                ProtocolResult {
                    version: "TLSv1.2",
                    supported: true,
                },
                ProtocolResult {
                    version: "TLSv1.3",
                    supported: false,
                },
            ],
            ciphers: vec![CipherInfo {
                name: "ECDHE-RSA-AES128-GCM-SHA256".to_string(),
                iana: None,
                bits: 128,
                protocol: "TLSv1.2".to_string(),
                pfs: true,
                weaknesses: vec![],
            }],
            leaf: None,
            chain_len: 0,
            verify_ok: true,
            verify_msg: "ok".to_string(),
            ocsp_stapled: Some(true),
            alpn: None,
        };
        let cfg = TlsScanConfig::default();
        let g = grade_port(&report, "example.com", true, &cfg);
        // TLS 1.0 caps at C; no leaf means a trust issue is recorded too.
        assert!(g.grade.contains('C'));
        assert!(g.trust_issue);
    }

    #[test]
    fn parse_hsts_reads_max_age() {
        assert_eq!(
            parse_hsts_max_age("max-age=31536000; includeSubDomains"),
            31_536_000
        );
        assert_eq!(parse_hsts_max_age("includeSubDomains"), 0);
    }

    #[test]
    fn extract_host_port_splits_authority() {
        assert_eq!(
            extract_host_port("https://x.test:8443/a"),
            ("x.test".to_string(), Some(8443))
        );
        assert_eq!(extract_host_port("x.test"), ("x.test".to_string(), None));
    }
}
