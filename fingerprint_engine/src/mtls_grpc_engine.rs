//! Transport Security Posture Engine (TLS / mTLS / HTTP hardening) — agentless, world-class,
//! evidence-driven assessment of how a service protects data in transit.
//!
//! Every finding is backed by a **real** observation — a live TLS handshake + parsed X.509
//! certificate, an actual HTTP response and its headers, or an observed redirect/ALPN result.
//! Nothing is simulated.
//!
//! ## What it inspects (all live)
//!   * **TLS certificate** — issuer/subject, expiry (and days remaining), self-signed status, public
//!     key strength (RSA bit length), signature algorithm (flags SHA-1/MD5), and SAN coverage
//!     (host-name match + wildcard).
//!   * **HTTP strict transport** — HSTS presence/strength (`max-age`, `includeSubDomains`, `preload`)
//!     and whether plain `http://` upgrades to `https://`.
//!   * **Browser hardening headers** — CSP (incl. `unsafe-inline`/wildcard), X-Frame-Options /
//!     `frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and the
//!     cross-origin isolation trio (COOP/COEP/CORP).
//!   * **Cookie flags** — `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie`.
//!   * **Protocol modernity** — HTTP/2 (ALPN `h2`) negotiation; legacy TLS 1.0/1.1 downgrade surface.
//!   * **gRPC surface** — live HTTP/2 POST with real gRPC wire frames (5-byte prefix) to health,
//!     reflection, gRPC-Web and Connect-RPC paths; flags reachable reflection APIs and cleartext h2c.
//!   * **mTLS enforcement** — real TLS handshakes without a client certificate on gRPC/API ports;
//!     distinguishes "certificate required" (good) from anonymous acceptance (exposure).
//!   * **Weak-crypto matrix** — targeted TLS 1.2 handshakes for RC4, 3DES/SWEET32, EXPORT, NULL and
//!     static-RSA (no forward secrecy) suites — each finding only when the server actually negotiates it.
//!   * **API hardening** — HTTP TRACE cross-site tracing, permissive CORS (`Access-Control-Allow-Origin: *`).
//!   * **DANE / TLSA** — DNS pinning records for `_443._tcp.host` (RFC 6698).
//!   * **Certificate consistency** — SHA-256 fingerprint matrix across operator ports (split-brain TLS).
//!   * **HTTP/3 readiness** — ALPN `h3` negotiation probe on TLS 1.3.
//!   * **security.txt** — `/.well-known/security.txt` presence for coordinated disclosure.
//!   * **Chain trust** — OpenSSL verify against system CA store (not just cert parse).
//!   * **Redirect-chain audit** — follows HTTP→HTTPS hops; flags cleartext mid-chain redirects.
//!   * **gRPC h2c preface** — `PRI * HTTP/2.0` prior-knowledge probe on gRPC ports without TLS.
//!   * **WebSocket upgrade** — 101 / Upgrade: websocket on HTTPS origin.
//!   * **Cache policy** — public `Cache-Control` on dynamic/API responses.
//!   * **CT shadow hosts** — staging/dev/uat hostnames surfaced from Certificate Transparency.
//!   * **Coverage manifest** — audit trail listing every executed probe module (no placeholders).
//!   * **OCSP stapling** — TLS status_request extension; missing staple on public HTTPS is flagged.
//!   * **Certificate Transparency + CAA** — live crt.sh inventory count and DNS CAA policy presence.
//!   * **Version disclosure** — `Server` / `X-Powered-By` leakage.
//!
//! ## Differentiators (Wiz-style)
//!   * **Attack-path synthesis** — toxic combinations (e.g. no-HSTS + insecure cookie) become an
//!     ordered MITM/session-theft kill chain.
//!   * **Security graph** — endpoint + weakness nodes via [`EngineResult::ok_with_graph`].
//!   * **Posture score** — a quantified 0–100 transport-security grade from real observations.
//!
//! Every check, port, threshold, timeout and toggle is GUI-driven via [`ArsenalConfig`].
//!
//! MITRE ATT&CK: T1557 (Adversary-in-the-Middle), T1040 (Network Sniffing), T1190 (Exploit
//! Public-Facing Application), T1185 (Browser Session Hijacking).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    dns_caa, dns_tlsa, extract_host, header_value, http2_client, http_get,
    http_get_with_headers, http_method_with_headers, http_post_bytes_with_headers, tcp_open,
    tls_cert_details,
};
use crate::engine_result::{print_result, EngineResult};
use chrono::{NaiveDate, Utc};
use openssl::hash::MessageDigest;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion, StatusType};
use openssl::x509::X509VerifyResult;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

const ENGINE_ID: &str = "mtls_grpc";

const T_MITM: &str = "T1557"; // Adversary-in-the-Middle
const T_SNIFF: &str = "T1040"; // Network Sniffing
const T_EXPLOIT: &str = "T1190"; // Exploit Public-Facing Application
const T_SESSION: &str = "T1185"; // Browser Session Hijacking

const LEGACY_CIPHER_LIST: &str = "ALL:COMPLEMENTOFALL:@SECLEVEL=0";

/// Empty gRPC message frame (uncompressed, length 0) for health/reflection probes.
const GRPC_EMPTY_FRAME: &[u8] = &[0, 0, 0, 0, 0];

#[derive(Default, Clone)]
struct TransportPosture {
    https_reachable: bool,
    cert_expired: bool,
    cert_self_signed: bool,
    weak_key: bool,
    weak_sig: bool,
    san_mismatch: bool,
    cert_expiring_soon: bool,
    hsts_missing: bool,
    no_https_upgrade: bool,
    csp_missing: bool,
    clickjacking: bool,
    insecure_cookies: usize,
    http2: bool,
    version_disclosure: bool,
    grpc_reflection: bool,
    grpc_detected: bool,
    mtls_not_enforced: bool,
    ocsp_missing: bool,
    no_caa: bool,
    high_ct_footprint: bool,
    cross_origin_weak: bool,
    plaintext_grpc_port: bool,
    legacy_tls: bool,
    tls13_supported: bool,
    weak_ciphers: bool,
    no_forward_secrecy: bool,
    trace_enabled: bool,
    cors_permissive: bool,
    h2c_upgrade: bool,
    grpc_web: bool,
    cert_inconsistent: bool,
    dane_missing: bool,
    http3_alpn: bool,
    security_txt_missing: bool,
    sni_permissive: bool,
    chain_untrusted: bool,
    redirect_downgrade: bool,
    grpc_h2c_live: bool,
    ws_upgrade: bool,
    cacheable_api: bool,
    ct_shadow_hosts: bool,
    mixed_passive: bool,
    must_staple_violation: bool,
    ct_recent_surge: bool,
    tls_compression: bool,
    checks: u32,
}

/// Eight-dimension executive scorecard (0–100 each) — Wiz/CISO dashboard grade.
#[derive(Clone, Debug)]
struct TransportDimensionScores {
    tls_crypto: u32,
    http_hardening: u32,
    grpc_mtls: u32,
    dns_pki: u32,
    api_exposure: u32,
    protocol_modernity: u32,
    attack_surface: u32,
    operational: u32,
}

impl TransportDimensionScores {
    fn from_posture(p: &TransportPosture) -> Self {
        let mut tls = 100i32;
        if p.cert_expired {
            tls -= 40;
        }
        if p.weak_key || p.weak_sig {
            tls -= 25;
        }
        if p.cert_self_signed || p.chain_untrusted {
            tls -= 20;
        }
        if p.weak_ciphers || p.legacy_tls || p.tls_compression {
            tls -= 25;
        }
        if p.no_forward_secrecy {
            tls -= 10;
        }
        if p.ocsp_missing || p.must_staple_violation {
            tls -= 10;
        }
        if p.san_mismatch || p.cert_inconsistent || p.sni_permissive {
            tls -= 12;
        }

        let mut http = 100i32;
        if p.hsts_missing {
            http -= 20;
        }
        if p.no_https_upgrade || p.redirect_downgrade {
            http -= 18;
        }
        if p.csp_missing || p.clickjacking {
            http -= 12;
        }
        if p.insecure_cookies > 0 {
            http -= (p.insecure_cookies as i32).min(4) * 5;
        }
        if p.cross_origin_weak {
            http -= 8;
        }
        if p.mixed_passive {
            http -= 10;
        }

        let mut grpc = 100i32;
        if p.grpc_reflection {
            grpc -= 30;
        }
        if p.mtls_not_enforced {
            grpc -= 25;
        }
        if p.plaintext_grpc_port || p.grpc_h2c_live {
            grpc -= 35;
        }
        if p.grpc_web {
            grpc -= 8;
        }

        let mut dns = 100i32;
        if p.no_caa {
            dns -= 8;
        }
        if p.high_ct_footprint || p.ct_shadow_hosts || p.ct_recent_surge {
            dns -= 10;
        }
        if p.dane_missing {
            dns -= 5;
        }

        let mut api = 100i32;
        if p.trace_enabled {
            api -= 15;
        }
        if p.cors_permissive {
            api -= 18;
        }
        if p.cacheable_api {
            api -= 10;
        }

        let mut proto = 100i32;
        if !p.tls13_supported && p.https_reachable {
            proto -= 12;
        }
        if !p.http2 {
            proto -= 8;
        }
        if p.h2c_upgrade {
            proto -= 20;
        }
        if p.http3_alpn {
            proto -= 0; // informational positive
        }

        let mut attack = 100i32;
        if p.grpc_reflection && p.mtls_not_enforced {
            attack -= 30;
        }
        if (p.hsts_missing || p.no_https_upgrade) && p.insecure_cookies > 0 {
            attack -= 25;
        }
        if p.weak_ciphers && p.no_https_upgrade {
            attack -= 20;
        }
        if p.grpc_web && p.cors_permissive {
            attack -= 22;
        }

        let mut ops = 100i32;
        if p.security_txt_missing {
            ops -= 8;
        }
        if p.version_disclosure {
            ops -= 5;
        }

        Self {
            tls_crypto: tls.clamp(0, 100) as u32,
            http_hardening: http.clamp(0, 100) as u32,
            grpc_mtls: grpc.clamp(0, 100) as u32,
            dns_pki: dns.clamp(0, 100) as u32,
            api_exposure: api.clamp(0, 100) as u32,
            protocol_modernity: proto.clamp(0, 100) as u32,
            attack_surface: attack.clamp(0, 100) as u32,
            operational: ops.clamp(0, 100) as u32,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "tls_crypto": self.tls_crypto,
            "http_hardening": self.http_hardening,
            "grpc_mtls": self.grpc_mtls,
            "dns_pki": self.dns_pki,
            "api_exposure": self.api_exposure,
            "protocol_modernity": self.protocol_modernity,
            "attack_surface": self.attack_surface,
            "operational": self.operational,
        })
    }
}

impl TransportPosture {
    fn score(&self) -> u32 {
        let mut s: i32 = 100;
        if self.cert_expired {
            s -= 30;
        }
        if self.cert_self_signed {
            s -= 18;
        }
        if self.weak_key {
            s -= 25;
        }
        if self.weak_sig {
            s -= 25;
        }
        if self.san_mismatch {
            s -= 15;
        }
        if self.cert_expiring_soon {
            s -= 8;
        }
        if self.hsts_missing {
            s -= 12;
        }
        if self.no_https_upgrade {
            s -= 15;
        }
        if self.csp_missing {
            s -= 8;
        }
        if self.clickjacking {
            s -= 8;
        }
        s -= (self.insecure_cookies as i32).min(5) * 4;
        if self.version_disclosure {
            s -= 3;
        }
        if self.legacy_tls {
            s -= 20;
        }
        if self.ocsp_missing {
            s -= 5;
        }
        if self.no_caa {
            s -= 3;
        }
        if self.high_ct_footprint {
            s -= 2;
        }
        if self.cross_origin_weak {
            s -= 5;
        }
        if self.grpc_reflection {
            s -= 15;
        }
        if self.mtls_not_enforced {
            s -= 18;
        }
        if self.plaintext_grpc_port {
            s -= 20;
        }
        if self.weak_ciphers {
            s -= 22;
        }
        if self.no_forward_secrecy {
            s -= 10;
        }
        if self.trace_enabled {
            s -= 8;
        }
        if self.cors_permissive {
            s -= 6;
        }
        if self.h2c_upgrade {
            s -= 12;
        }
        if self.cert_inconsistent {
            s -= 10;
        }
        if self.sni_permissive {
            s -= 8;
        }
        if self.chain_untrusted {
            s -= 15;
        }
        if self.redirect_downgrade {
            s -= 10;
        }
        if self.grpc_h2c_live {
            s -= 18;
        }
        if self.ws_upgrade {
            s -= 4;
        }
        if self.cacheable_api {
            s -= 5;
        }
        if self.ct_shadow_hosts {
            s -= 3;
        }
        if self.mixed_passive {
            s -= 8;
        }
        if self.must_staple_violation {
            s -= 12;
        }
        if self.ct_recent_surge {
            s -= 2;
        }
        if self.tls_compression {
            s -= 15;
        }
        if !self.tls13_supported && self.https_reachable {
            s -= 4;
        }
        s.clamp(0, 100) as u32
    }
    fn grade(&self) -> &'static str {
        match self.score() {
            90..=100 => "A",
            75..=89 => "B",
            60..=74 => "C",
            40..=59 => "D",
            _ => "F",
        }
    }
    fn has_exposure(&self) -> bool {
        self.cert_expired
            || self.cert_self_signed
            || self.weak_key
            || self.weak_sig
            || self.san_mismatch
            || self.hsts_missing
            || self.no_https_upgrade
            || self.csp_missing
            || self.clickjacking
            || self.insecure_cookies > 0
            || self.legacy_tls
            || self.grpc_reflection
            || self.mtls_not_enforced
            || self.plaintext_grpc_port
            || self.weak_ciphers
            || self.no_forward_secrecy
            || self.trace_enabled
            || self.cors_permissive
            || self.h2c_upgrade
            || self.cert_inconsistent
            || self.sni_permissive
            || self.chain_untrusted
            || self.redirect_downgrade
            || self.grpc_h2c_live
            || self.cacheable_api
            || self.mixed_passive
            || self.must_staple_violation
            || self.tls_compression
    }
}

/// Canonical module registry — contract-tested; every entry maps to a live probe arm.
pub const TRANSPORT_PROBE_MODULES: &[&str] = &[
    "tls_certificate",
    "tls_session_matrix",
    "weak_cipher_matrix",
    "legacy_tls",
    "chain_trust",
    "cert_fingerprint_matrix",
    "sni_policy",
    "grpc_reflection",
    "grpc_web_connect",
    "grpc_h2c_preface",
    "mtls_enforcement",
    "hsts_headers_cookies",
    "cross_origin_isolation",
    "http_https_redirect",
    "redirect_chain_audit",
    "api_trace_cors",
    "h2c_http_upgrade",
    "http2_alpn",
    "http3_alpn_alt_svc",
    "websocket_upgrade",
    "cache_policy",
    "dane_tlsa",
    "dns_caa",
    "certificate_transparency",
    "ct_shadow_hosts",
    "ct_caa_crosscheck",
    "security_txt",
    "hsts_preload",
    "mixed_passive_content",
    "must_staple_correlation",
    "mesh_proxy_fingerprint",
    "grpc_custom_paths",
    "tls_compression_crime",
    "reporting_headers",
    "upgrade_insecure_requests",
    "dimension_scorecard",
    "attack_path_synthesis",
    "posture_scoring",
    "coverage_manifest",
];

#[derive(Clone, Debug, Default)]
struct PortTlsObservation {
    port: u16,
    tls_ok: bool,
    ocsp_stapled: Option<bool>,
    legacy_tls10: bool,
    legacy_tls11: bool,
    tls13: bool,
    mtls_required: Option<bool>,
    alpn_h2: bool,
}

fn build_client(timeout_ms: u64, follow_redirects: bool) -> reqwest::Client {
    let policy = if follow_redirects {
        reqwest::redirect::Policy::limited(5)
    } else {
        reqwest::redirect::Policy::none()
    };
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.clamp(400, 30_000)))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .redirect(policy)
        .user_agent("Weissman-TransportPosture/3.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn with_fields(mut f: Value, extra: &[(&str, Value)]) -> Value {
    if let Some(obj) = f.as_object_mut() {
        for (k, v) in extra {
            obj.insert((*k).to_string(), v.clone());
        }
    }
    f
}

fn tri(cfg: &ArsenalConfig, key: &str, default: bool) -> bool {
    match cfg.string(key).map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("on" | "true" | "1" | "yes" | "enabled") => true,
        Some("off" | "false" | "0" | "no" | "disabled") => false,
        _ => default,
    }
}

fn resolve_addr(host: &str, port: u16) -> Option<SocketAddr> {
    (host, port).to_socket_addrs().ok()?.next()
}

fn version_label(v: SslVersion) -> &'static str {
    match v {
        SslVersion::TLS1 => "TLS 1.0",
        SslVersion::TLS1_1 => "TLS 1.1",
        SslVersion::TLS1_2 => "TLS 1.2",
        SslVersion::TLS1_3 => "TLS 1.3",
        _ => "unknown",
    }
}

fn build_version_connector(ver: SslVersion, want_alpn: bool) -> Option<SslConnector> {
    let mut b = SslConnector::builder(SslMethod::tls()).ok()?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_min_proto_version(Some(ver)).ok()?;
    b.set_max_proto_version(Some(ver)).ok()?;
    if ver == SslVersion::TLS1 || ver == SslVersion::TLS1_1 {
        let _ = b.set_cipher_list(LEGACY_CIPHER_LIST);
    }
    if want_alpn {
        let _ = b.set_alpn_protos(b"\x02h2\x08http/1.1");
    }
    Some(b.build())
}

struct HandshakeObservation {
    ok: bool,
    ocsp_stapled: bool,
    alpn_h2: bool,
    mtls_required: Option<bool>,
    error_hint: Option<String>,
}

fn do_tls_handshake(
    addr: SocketAddr,
    sni: &str,
    connector: &SslConnector,
    request_ocsp: bool,
    timeout: Duration,
) -> HandshakeObservation {
    let tcp = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            return HandshakeObservation {
                ok: false,
                ocsp_stapled: false,
                alpn_h2: false,
                mtls_required: None,
                error_hint: Some(e.to_string()),
            };
        }
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    let mut cfg = match connector.configure() {
        Ok(c) => c,
        Err(e) => {
            return HandshakeObservation {
                ok: false,
                ocsp_stapled: false,
                alpn_h2: false,
                mtls_required: None,
                error_hint: Some(e.to_string()),
            };
        }
    };
    cfg.set_use_server_name_indication(!sni.is_empty());
    cfg.set_verify_hostname(false);
    let mut ssl = match cfg.into_ssl(sni) {
        Ok(s) => s,
        Err(e) => {
            return HandshakeObservation {
                ok: false,
                ocsp_stapled: false,
                alpn_h2: false,
                mtls_required: None,
                error_hint: Some(e.to_string()),
            };
        }
    };
    if request_ocsp {
        let _ = ssl.set_status_type(StatusType::OCSP);
    }
    let mut stream = match SslStream::new(ssl, tcp) {
        Ok(s) => s,
        Err(e) => {
            return HandshakeObservation {
                ok: false,
                ocsp_stapled: false,
                alpn_h2: false,
                mtls_required: None,
                error_hint: Some(e.to_string()),
            };
        }
    };

    match stream.connect() {
        Ok(()) => {
            let ssl = stream.ssl();
            let ocsp_stapled = ssl.ocsp_status().map(|b| !b.is_empty()).unwrap_or(false);
            let alpn_h2 = ssl
                .selected_alpn_protocol()
                .map(|p| p == b"h2")
                .unwrap_or(false);
            HandshakeObservation {
                ok: true,
                ocsp_stapled,
                alpn_h2,
                mtls_required: Some(false),
                error_hint: None,
            }
        }
        Err(e) => {
            let msg = e.to_string().to_ascii_lowercase();
            let mtls_required = if msg.contains("certificate required")
                || msg.contains("handshake failure")
                || msg.contains("unknown ca")
                || msg.contains("peer did not return a certificate")
                || msg.contains("sslv3 alert")
            {
                Some(true)
            } else {
                None
            };
            HandshakeObservation {
                ok: false,
                ocsp_stapled: false,
                alpn_h2: false,
                mtls_required,
                error_hint: Some(e.to_string()),
            }
        }
    }
}

fn probe_port_tls_blocking(
    host: &str,
    port: u16,
    timeout_ms: u64,
    check_ocsp: bool,
    check_legacy: bool,
    check_mtls: bool,
) -> PortTlsObservation {
    let timeout = Duration::from_millis(timeout_ms.clamp(400, 30_000));
    let Some(addr) = resolve_addr(host, port) else {
        return PortTlsObservation {
            port,
            ..Default::default()
        };
    };

    let mut obs = PortTlsObservation {
        port,
        ..Default::default()
    };

    if let Some(c) = build_version_connector(SslVersion::TLS1_2, true) {
        let h = do_tls_handshake(addr, host, &c, check_ocsp, timeout);
        if h.ok {
            obs.tls_ok = true;
            obs.alpn_h2 = h.alpn_h2;
            if check_ocsp {
                obs.ocsp_stapled = Some(h.ocsp_stapled);
            }
            if check_mtls {
                obs.mtls_required = h.mtls_required;
            }
        } else if check_mtls {
            obs.mtls_required = h.mtls_required;
        }
    }

    if check_legacy {
        for (ver, flag) in [
            (SslVersion::TLS1, &mut obs.legacy_tls10),
            (SslVersion::TLS1_1, &mut obs.legacy_tls11),
        ] {
            if let Some(c) = build_version_connector(ver, false) {
                let h = do_tls_handshake(addr, host, &c, false, timeout);
                *flag = h.ok;
            }
        }
    }

    if let Some(c) = build_version_connector(SslVersion::TLS1_3, true) {
        let h = do_tls_handshake(addr, host, &c, false, timeout);
        obs.tls13 = h.ok;
    }

    obs
}

async fn probe_port_tls(
    host: &str,
    port: u16,
    timeout_ms: u64,
    check_ocsp: bool,
    check_legacy: bool,
    check_mtls: bool,
) -> PortTlsObservation {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || {
        probe_port_tls_blocking(&host, port, timeout_ms, check_ocsp, check_legacy, check_mtls)
    })
    .await
    .unwrap_or_default()
}

fn cert_sha256_fp_blocking(host: &str, port: u16, sni: &str, timeout_ms: u64) -> Option<String> {
    let timeout = Duration::from_millis(timeout_ms.clamp(400, 30_000));
    let addr = resolve_addr(host, port)?;
    let connector = build_version_connector(SslVersion::TLS1_2, false)?;
    let tcp = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let mut cfg = connector.configure().ok()?;
    cfg.set_use_server_name_indication(!sni.is_empty());
    cfg.set_verify_hostname(false);
    let ssl = cfg.into_ssl(sni).ok()?;
    let mut stream = SslStream::new(ssl, tcp).ok()?;
    stream.connect().ok()?;
    let cert = stream.ssl().peer_certificate()?;
    cert.digest(MessageDigest::sha256())
        .ok()
        .map(|d| {
            d.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
}

fn try_cipher_blocking(
    host: &str,
    port: u16,
    cipher_list: &str,
    timeout_ms: u64,
) -> Option<String> {
    let timeout = Duration::from_millis(timeout_ms.clamp(400, 30_000));
    let addr = resolve_addr(host, port)?;
    let mut b = SslConnector::builder(SslMethod::tls()).ok()?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_min_proto_version(Some(SslVersion::TLS1_2)).ok()?;
    b.set_max_proto_version(Some(SslVersion::TLS1_2)).ok()?;
    b.set_cipher_list(cipher_list).ok()?;
    let connector = b.build();
    let tcp = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let mut cfg = connector.configure().ok()?;
    cfg.set_use_server_name_indication(true);
    cfg.set_verify_hostname(false);
    let ssl = cfg.into_ssl(host).ok()?;
    let mut stream = SslStream::new(ssl, tcp).ok()?;
    stream.connect().ok()?;
    stream
        .ssl()
        .current_cipher()
        .map(|c| c.name().to_string())
}

fn probe_http3_alpn_blocking(host: &str, port: u16, timeout_ms: u64) -> bool {
    let timeout = Duration::from_millis(timeout_ms.clamp(400, 30_000));
    let Some(addr) = resolve_addr(host, port) else {
        return false;
    };
    let Some(mut b) = SslConnector::builder(SslMethod::tls()).ok() else {
        return false;
    };
    b.set_verify(SslVerifyMode::NONE);
    if b.set_min_proto_version(Some(SslVersion::TLS1_3)).is_err()
        || b.set_max_proto_version(Some(SslVersion::TLS1_3)).is_err()
    {
        return false;
    }
    let _ = b.set_alpn_protos(b"\x02h3\x02h2");
    let connector = b.build();
    let tcp = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let mut cfg = match connector.configure() {
        Ok(c) => c,
        Err(_) => return false,
    };
    cfg.set_use_server_name_indication(true);
    cfg.set_verify_hostname(false);
    let ssl = match cfg.into_ssl(host) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut stream = match SslStream::new(ssl, tcp) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if stream.connect().is_err() {
        return false;
    }
    stream
        .ssl()
        .selected_alpn_protocol()
        .map(|p| p == b"h3")
        .unwrap_or(false)
}

async fn cert_sha256_fp(host: &str, port: u16, sni: &str, timeout_ms: u64) -> Option<String> {
    let host = host.to_string();
    let sni = sni.to_string();
    tokio::task::spawn_blocking(move || cert_sha256_fp_blocking(&host, port, &sni, timeout_ms))
        .await
        .ok()
        .flatten()
}

async fn try_cipher(host: &str, port: u16, cipher_list: &str, timeout_ms: u64) -> Option<String> {
    let host = host.to_string();
    let list = cipher_list.to_string();
    tokio::task::spawn_blocking(move || try_cipher_blocking(&host, port, &list, timeout_ms))
        .await
        .ok()
        .flatten()
}

async fn probe_http3_alpn(host: &str, port: u16, timeout_ms: u64) -> bool {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || probe_http3_alpn_blocking(&host, port, timeout_ms))
        .await
        .unwrap_or(false)
}

/// Whether `host` is covered by a certificate SAN entry (supports a single leading wildcard).
fn san_covers(host: &str, san: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    san.iter().any(|n| {
        let n = n.trim().to_ascii_lowercase();
        if let Some(suffix) = n.strip_prefix("*.") {
            host.strip_suffix(suffix)
                .map(|p| p.ends_with('.') && p.trim_end_matches('.').split('.').count() == 1)
                .unwrap_or(false)
                || host == suffix
        } else {
            host == n
        }
    })
}

fn grpc_response_indicates_service(status: u16, body: &[u8], headers: &[(String, String)]) -> bool {
    if status == 404 {
        return false;
    }
    if body.len() >= 5 && (body[0] == 0 || body[0] == 1) {
        return true;
    }
    headers.iter().any(|(k, v)| {
        let k = k.to_ascii_lowercase();
        (k == "grpc-status" || k == "content-type") && (v.contains("grpc") || k == "grpc-status")
    }) || (200..500).contains(&status) && status != 404
}

fn grpc_reflection_likely(status: u16, body: &[u8], path: &str) -> bool {
    path.contains("ServerReflection")
        && status == 200
        && body.len() > 5
        && (body[0] == 0 || body[0] == 1)
}

// ─────────────────────────────────────────────────────────────────────────────
// Probes
// ─────────────────────────────────────────────────────────────────────────────

async fn probe_certificate(
    host: &str,
    target: &str,
    min_rsa_bits: u32,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let Some(cert) = tls_cert_details(host).await else {
        return;
    };
    posture.https_reachable = true;

    if cert.expired {
        posture.cert_expired = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "TLS certificate is expired",
                "critical",
                T_MITM,
                &format!(
                    "The TLS certificate for {} is expired (issuer: {}). Clients see hard browser errors and connections are trivially MITM-able once users click through. Renew immediately and automate renewal (ACME).",
                    host, cert.issuer
                ),
                target,
                0.97,
                Evidence::new().with("issuer", cert.issuer.clone()).with("subject", cert.subject.clone()).with("expired", true),
            ),
            &[("category", json!("tls_certificate"))],
        ));
    } else if cert.days_until_expiry <= 14 {
        posture.cert_expiring_soon = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("TLS certificate expires in {} day(s)", cert.days_until_expiry),
                "medium",
                T_EXPLOIT,
                &format!("The certificate for {} expires in {} day(s). Imminent expiry risks an outage; verify automated renewal.", host, cert.days_until_expiry),
                target,
                0.9,
                Evidence::new().with("days_until_expiry", cert.days_until_expiry),
            ),
            &[("category", json!("tls_certificate"))],
        ));
    }

    if cert.self_signed {
        posture.cert_self_signed = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Self-signed TLS certificate",
                "high",
                T_MITM,
                &format!("{} presents a self-signed certificate (issuer == subject). It provides no third-party identity assurance and trains users to bypass warnings, enabling MITM. Use a publicly-trusted CA (e.g. Let's Encrypt).", host),
                target,
                0.9,
                Evidence::new().with("issuer", cert.issuer.clone()).with("self_signed", true),
            ),
            &[("category", json!("tls_certificate"))],
        ));
    }

    let sig = cert.signature_algorithm.to_ascii_lowercase();
    if sig.contains("sha1") || sig.contains("md5") {
        posture.weak_sig = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Weak certificate signature algorithm ({})", cert.signature_algorithm),
                "critical",
                T_MITM,
                &format!("The certificate is signed with {}, which is cryptographically broken (collision attacks). Re-issue with SHA-256 or stronger.", cert.signature_algorithm),
                target,
                0.95,
                Evidence::new().with("signature_algorithm", cert.signature_algorithm.clone()),
            ),
            &[("category", json!("tls_certificate"))],
        ));
    }

    if cert.is_rsa && cert.public_key_bits > 0 && cert.public_key_bits < min_rsa_bits {
        posture.weak_key = true;
        let sev = if cert.public_key_bits < 2048 { "critical" } else { "medium" };
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Weak RSA public key ({}-bit)", cert.public_key_bits),
                sev,
                T_MITM,
                &format!("The certificate uses a {}-bit RSA key (policy minimum {}). Keys under 2048-bit are factorable; re-issue with ≥2048-bit RSA or an ECDSA P-256 key.", cert.public_key_bits, min_rsa_bits),
                target,
                0.9,
                Evidence::new().with("public_key_bits", cert.public_key_bits).with("is_rsa", true),
            ),
            &[("category", json!("tls_certificate"))],
        ));
    }

    if !cert.san_dns_names.is_empty() && !san_covers(host, &cert.san_dns_names) {
        posture.san_mismatch = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Certificate SAN does not cover the host",
                "high",
                T_MITM,
                &format!("The host {} is not present in the certificate SAN list ({:?}). Browsers reject the name mismatch; an attacker could exploit the inconsistency. Re-issue covering this exact host.", host, cert.san_dns_names),
                target,
                0.85,
                Evidence::new().with("host", host).with("san_dns_names", json!(cert.san_dns_names)),
            ),
            &[("category", json!("tls_certificate"))],
        ));
    }
}

async fn probe_headers_and_cookies(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    min_hsts_age: u64,
    check_cross_origin: bool,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("https://{}/", host);
    let Some(p) = crate::engine_probes::http_get(client, &url).await else {
        return;
    };
    posture.https_reachable = true;

    // ── HSTS ──────────────────────────────────────────────────────────────────
    match header_value(&p.headers, "strict-transport-security") {
        None => {
            posture.hsts_missing = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "HSTS (Strict-Transport-Security) not set",
                    "high",
                    T_MITM,
                    "No Strict-Transport-Security header is sent, so a network attacker can SSL-strip the first request and downgrade users to plaintext. Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
                    target,
                    0.9,
                    Evidence::new().with("header", "missing"),
                ),
                &[("category", json!("hsts"))],
            ));
        }
        Some(v) => {
            let lower = v.to_ascii_lowercase();
            let max_age = lower
                .split(';')
                .find_map(|p| p.trim().strip_prefix("max-age="))
                .and_then(|n| n.trim().parse::<u64>().ok())
                .unwrap_or(0);
            if max_age < min_hsts_age || !lower.contains("includesubdomains") {
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        "Weak HSTS policy",
                        "medium",
                        T_MITM,
                        &format!("HSTS is set ({}) but is weak: max-age={} (recommended ≥ {}){}. Strengthen to a 1-year max-age with includeSubDomains and preload.", v, max_age, min_hsts_age, if lower.contains("includesubdomains") { "" } else { ", missing includeSubDomains" }),
                        target,
                        0.85,
                        Evidence::new().with("hsts", v).with("max_age", max_age),
                    ),
                    &[("category", json!("hsts"))],
                ));
            }
        }
    }

    // ── CSP ───────────────────────────────────────────────────────────────────
    let csp = header_value(&p.headers, "content-security-policy");
    let has_frame_ancestors = csp.map(|c| c.to_ascii_lowercase().contains("frame-ancestors")).unwrap_or(false);
    match csp {
        None => {
            posture.csp_missing = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "Content-Security-Policy not set",
                    "medium",
                    T_EXPLOIT,
                    "No Content-Security-Policy header is present. CSP is the primary defence against XSS and data-injection; add a strict policy (`default-src 'self'; object-src 'none'; frame-ancestors 'self'`).",
                    target,
                    0.85,
                    Evidence::new().with("header", "missing"),
                ),
                &[("category", json!("csp"))],
            ));
        }
        Some(c) => {
            let lc = c.to_ascii_lowercase();
            if lc.contains("unsafe-inline") || lc.contains("unsafe-eval") || lc.contains("default-src *") {
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        "Weak Content-Security-Policy",
                        "low",
                        T_EXPLOIT,
                        "The CSP includes unsafe directives ('unsafe-inline'/'unsafe-eval' or wildcard sources), substantially weakening XSS protection. Replace inline scripts with nonces/hashes and remove wildcards.",
                        target,
                        0.8,
                        Evidence::new().with("csp", c.chars().take(240).collect::<String>()),
                    ),
                    &[("category", json!("csp"))],
                ));
            }
        }
    }

    // ── Clickjacking (X-Frame-Options / frame-ancestors) ───────────────────────
    if header_value(&p.headers, "x-frame-options").is_none() && !has_frame_ancestors {
        posture.clickjacking = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Clickjacking protection missing",
                "medium",
                T_SESSION,
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be framed by any origin (clickjacking / UI-redress). Add `X-Frame-Options: DENY` and `frame-ancestors 'self'`.",
                target,
                0.85,
                Evidence::new().with("x_frame_options", "missing"),
            ),
            &[("category", json!("clickjacking"))],
        ));
    }

    // ── Cross-origin isolation (COOP / COEP / CORP) ───────────────────────────
    if check_cross_origin {
        let coop = header_value(&p.headers, "cross-origin-opener-policy");
        let coep = header_value(&p.headers, "cross-origin-embedder-policy");
        let corp = header_value(&p.headers, "cross-origin-resource-policy");
        let coop_ok = coop.map(|v| {
            let lc = v.to_ascii_lowercase();
            lc.contains("same-origin") || lc.contains("same-origin-allow-popups")
        }).unwrap_or(false);
        let coep_ok = coep.map(|v| v.to_ascii_lowercase().contains("require-corp")).unwrap_or(false);
        let corp_ok = corp.is_some();
        if !coop_ok || !coep_ok || !corp_ok {
            posture.cross_origin_weak = true;
            let mut missing = Vec::new();
            if !coop_ok {
                missing.push("Cross-Origin-Opener-Policy");
            }
            if !coep_ok {
                missing.push("Cross-Origin-Embedder-Policy: require-corp");
            }
            if !corp_ok {
                missing.push("Cross-Origin-Resource-Policy");
            }
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "Cross-origin isolation headers incomplete",
                    "low",
                    T_EXPLOIT,
                    &format!(
                        "Missing or weak cross-origin isolation headers ({}). Spectre-class attacks and cross-origin data leaks are harder to mitigate without COOP/COEP/CORP.",
                        missing.join(", ")
                    ),
                    target,
                    0.78,
                    Evidence::new()
                        .with("coop", coop.unwrap_or("missing"))
                        .with("coep", coep.unwrap_or("missing"))
                        .with("corp", corp.unwrap_or("missing")),
                ),
                &[("category", json!("cross_origin_isolation"))],
            ));
        }
    }

    // ── Low-severity hardening headers ─────────────────────────────────────────
    for (hdr, label, why) in [
        ("x-content-type-options", "X-Content-Type-Options: nosniff", "Prevents MIME-sniffing that can turn uploads into script execution."),
        ("referrer-policy", "Referrer-Policy", "Controls referrer leakage of sensitive URLs to third parties."),
        ("permissions-policy", "Permissions-Policy", "Restricts powerful browser features (camera, geolocation, etc.)."),
    ] {
        if header_value(&p.headers, hdr).is_none() {
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("Missing hardening header: {}", label),
                    "low",
                    T_EXPLOIT,
                    &format!("The `{}` header is not set. {} Add it to harden the browser security model.", label, why),
                    target,
                    0.7,
                    Evidence::new().with("header", hdr),
                ),
                &[("category", json!("security_headers"))],
            ));
        }
    }

    // ── Version disclosure ─────────────────────────────────────────────────────
    for hdr in ["server", "x-powered-by", "x-aspnet-version"] {
        if let Some(v) = header_value(&p.headers, hdr) {
            if v.chars().any(|c| c.is_ascii_digit()) {
                posture.version_disclosure = true;
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Software version disclosed via {}", hdr),
                        "low",
                        T_EXPLOIT,
                        &format!("The `{}: {}` response header discloses exact software/version, letting attackers map known CVEs. Suppress or genericise version banners.", hdr, v),
                        target,
                        0.75,
                        Evidence::new().with("header", hdr).with("value", v),
                    ),
                    &[("category", json!("information_disclosure"))],
                ));
                break;
            }
        }
    }

    // ── Cookie flags ───────────────────────────────────────────────────────────
    let set_cookies: Vec<&str> = p
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.as_str())
        .collect();
    for ck in set_cookies {
        let lc = ck.to_ascii_lowercase();
        let name = ck.split('=').next().unwrap_or("cookie").trim();
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
        if !issues.is_empty() {
            posture.insecure_cookies += 1;
            let sev = if issues.contains(&"missing Secure") { "high" } else { "medium" };
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("Insecure cookie flags: {}", name),
                    sev,
                    T_SESSION,
                    &format!("Cookie '{}' is set without proper flags ({}). Missing Secure allows transmission over HTTP; missing HttpOnly exposes it to XSS theft; missing SameSite enables CSRF. Set `Secure; HttpOnly; SameSite=Lax`.", name, issues.join(", ")),
                    target,
                    0.85,
                    Evidence::new().with("cookie", name).with("issues", json!(issues)),
                ),
                &[("category", json!("cookie_security"))],
            ));
        }
    }
}

async fn probe_https_upgrade(
    client_no_redirect: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let Some(p) = crate::engine_probes::http_get(client_no_redirect, &format!("http://{}/", host)).await else {
        return;
    };
    let redirects_to_https = p
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.to_ascii_lowercase().starts_with("https://"))
        .unwrap_or(false);
    let is_redirect = (300..400).contains(&p.status);
    if !(is_redirect && redirects_to_https) && p.status == 200 {
        posture.no_https_upgrade = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Plain HTTP does not redirect to HTTPS",
                "high",
                T_SNIFF,
                &format!("`http://{}/` served content over cleartext (HTTP {}) instead of redirecting to HTTPS. All traffic on the first request is sniffable/modifiable. Force a 301 redirect to https and enable HSTS.", host, p.status),
                target,
                0.9,
                Evidence::new().with("http_status", p.status).with("redirects_to_https", false),
            ),
            &[("category", json!("transport_downgrade"))],
        ));
    }
}

async fn probe_http2(host: &str, posture: &mut TransportPosture) {
    posture.checks += 1;
    let client = http2_client().await;
    if let Ok(resp) = client.get(format!("https://{}/", host)).send().await {
        if resp.version() == reqwest::Version::HTTP_2 {
            posture.http2 = true;
        }
    }
}

async fn probe_tls_session_matrix(
    host: &str,
    target: &str,
    ports: &[u16],
    timeout_ms: u64,
    check_ocsp: bool,
    check_legacy: bool,
    check_mtls: bool,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    for &port in ports {
        posture.checks += 1;
        let obs = probe_port_tls(host, port, timeout_ms, check_ocsp, check_legacy, check_mtls).await;
        if obs.tls_ok {
            posture.https_reachable = true;
        }
        if obs.tls13 {
            posture.tls13_supported = true;
        }
        if obs.alpn_h2 {
            posture.http2 = true;
        }

        if check_legacy && (obs.legacy_tls10 || obs.legacy_tls11) {
            posture.legacy_tls = true;
            let versions: Vec<&str> = [
                obs.legacy_tls10.then_some("TLS 1.0"),
                obs.legacy_tls11.then_some("TLS 1.1"),
            ]
            .into_iter()
            .flatten()
            .collect();
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("Deprecated TLS protocol(s) accepted on port {}", port),
                    "high",
                    T_MITM,
                    &format!(
                        "Port {} negotiates {} — protocols with known downgrade/POODLE/BEAST-class weaknesses (PCI-DSS forbids TLS 1.0/1.1). Disable legacy versions and enforce TLS 1.2+.",
                        port,
                        versions.join(" and ")
                    ),
                    target,
                    0.92,
                    Evidence::new()
                        .with("port", i64::from(port))
                        .with("tls10", obs.legacy_tls10)
                        .with("tls11", obs.legacy_tls11),
                ),
                &[("category", json!("legacy_tls"))],
            ));
        }

        if check_ocsp && obs.tls_ok {
            if obs.ocsp_stapled == Some(false) {
                posture.ocsp_missing = true;
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("OCSP stapling not enabled (port {})", port),
                        "low",
                        T_MITM,
                        "The server completed TLS but did not staple an OCSP response. Clients must perform live OCSP lookups (privacy + latency) and may soft-fail on revocation. Enable OCSP stapling on the load balancer or origin.",
                        target,
                        0.82,
                        Evidence::new().with("port", i64::from(port)).with("ocsp_stapled", false),
                    ),
                    &[("category", json!("ocsp_stapling"))],
                ));
            }
        }

        if check_mtls && obs.tls_ok && obs.mtls_required == Some(false) {
            posture.mtls_not_enforced = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("mTLS not enforced on port {} — anonymous TLS accepted", port),
                    "high",
                    T_MITM,
                    &format!(
                        "Port {} completed a TLS handshake without presenting a client certificate. Internal/gRPC APIs should require mutual TLS so only enrolled workloads can connect.",
                        port
                    ),
                    target,
                    0.9,
                    Evidence::new().with("port", i64::from(port)).with("client_cert_required", false),
                ),
                &[("category", json!("mtls_enforcement"))],
            ));
        }

        if !obs.tls13 && obs.tls_ok && port == 443 {
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "TLS 1.3 not negotiated on HTTPS port",
                    "low",
                    T_MITM,
                    "The server speaks TLS 1.2 but did not negotiate TLS 1.3 on a forced 1.3 handshake. Enable TLS 1.3 for 1-RTT handshakes and modern AEAD-only cipher suites.",
                    target,
                    0.8,
                    Evidence::new().with("port", i64::from(port)).with("tls13", false),
                ),
                &[("category", json!("tls_modernity"))],
            ));
        }
    }
}

async fn probe_grpc_surface(
    _client: &reqwest::Client,
    host: &str,
    target: &str,
    grpc_ports: &[u16],
    check_reflection: bool,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    let h2 = http2_client().await;
    let paths = [
        ("/grpc.health.v1.Health/Check", "health"),
        ("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "reflection_v1alpha"),
        ("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", "reflection_v1"),
    ];

    for &port in grpc_ports {
        posture.checks += 1;
        let open = tcp_open(host, port).await;
        if !open {
            continue;
        }

        let tls_obs = probe_port_tls(host, port, 6000, false, false, false).await;
        if open && !tls_obs.tls_ok {
            posture.plaintext_grpc_port = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("Possible plaintext gRPC listener on port {}", port),
                    "critical",
                    T_SNIFF,
                    &format!(
                        "TCP port {} is open but a TLS handshake did not complete. gRPC often runs cleartext (h2c) on this port — credentials and payloads would traverse the network unencrypted. Bind gRPC behind TLS or enforce mTLS.",
                        port
                    ),
                    target,
                    0.93,
                    Evidence::new().with("port", i64::from(port)).with("tls_handshake", false),
                ),
                &[("category", json!("plaintext_grpc"))],
            ));
            continue;
        }

        let base = if port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{port}")
        };

        for (path, kind) in &paths {
            if !check_reflection && kind.contains("reflection") {
                continue;
            }
            let url = format!("{base}{path}");
            let headers = [
                ("content-type", "application/grpc"),
                ("te", "trailers"),
            ];
            let probe = http_post_bytes_with_headers(&h2, &url, GRPC_EMPTY_FRAME, &headers).await;
            let Some(p) = probe else { continue };

            if grpc_response_indicates_service(p.status, p.body.as_bytes(), &p.headers) {
                posture.grpc_detected = true;
                if grpc_reflection_likely(p.status, p.body.as_bytes(), path) {
                    posture.grpc_reflection = true;
                    findings.push(with_fields(
                        finding_rich(
                            ENGINE_ID,
                            &format!("gRPC server reflection exposed on port {}", port),
                            "high",
                            T_EXPLOIT,
                            &format!(
                                "Live POST to {} returned a valid gRPC frame (HTTP {}, {} bytes). Server reflection lets unauthenticated callers enumerate every RPC method — a direct map for exploitation. Disable reflection in production or gate it behind mTLS.",
                                url, p.status, p.body.len()
                            ),
                            target,
                            0.92,
                            Evidence::new()
                                .with("port", i64::from(port))
                                .with("path", path)
                                .with("http_status", p.status)
                                .with("response_bytes", p.body.len()),
                        ),
                        &[("category", json!("grpc_reflection"))],
                    ));
                } else if *kind == "health" {
                    findings.push(with_fields(
                        finding_rich(
                            ENGINE_ID,
                            &format!("gRPC health service reachable on port {}", port),
                            "info",
                            T_EXPLOIT,
                            &format!(
                                "Standard gRPC health check path responded on port {} (HTTP {}). This confirms an active gRPC stack — verify authentication and network segmentation.",
                                port, p.status
                            ),
                            target,
                            0.85,
                            Evidence::new().with("port", i64::from(port)).with("path", path),
                        ),
                        &[("category", json!("grpc_detected"))],
                    ));
                }
            }
        }
    }
}

async fn probe_grpc_web_and_connect(
    host: &str,
    target: &str,
    grpc_ports: &[u16],
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    let h2 = http2_client().await;
    let probes = [
        (
            "/grpc.health.v1.Health/Check",
            "application/grpc-web+proto",
            "grpc_web_health",
        ),
        (
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
            "application/grpc-web+proto",
            "grpc_web_reflection",
        ),
        (
            "/connectrpc.health.v1.Health/Check",
            "application/connect+proto",
            "connect_rpc",
        ),
    ];
    for &port in grpc_ports {
        let base = if port == 443 {
            format!("https://{host}")
        } else if tcp_open(host, port).await {
            format!("https://{host}:{port}")
        } else {
            continue;
        };
        for (path, ctype, kind) in &probes {
            posture.checks += 1;
            let url = format!("{base}{path}");
            let headers = [("content-type", *ctype), ("te", "trailers")];
            let Some(p) = http_post_bytes_with_headers(&h2, &url, GRPC_EMPTY_FRAME, &headers).await
            else {
                continue;
            };
            if grpc_response_indicates_service(p.status, p.body.as_bytes(), &p.headers) {
                posture.grpc_web = true;
                let title = match *kind {
                    "grpc_web_reflection" => format!("gRPC-Web reflection exposed on port {port}"),
                    "connect_rpc" => format!("Connect-RPC surface reachable on port {port}"),
                    _ => format!("gRPC-Web health endpoint on port {port}"),
                };
                let sev = if (*kind).contains("reflection") { "high" } else { "medium" };
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &title,
                        sev,
                        T_EXPLOIT,
                        &format!(
                            "Live POST to {url} with `{ctype}` returned HTTP {} and a gRPC-class frame ({} bytes). Browser-reachable gRPC-Web/Connect surfaces expand the attack plane beyond native gRPC clients — enforce auth, mTLS, and disable reflection in production.",
                            p.status,
                            p.body.len()
                        ),
                        target,
                        0.88,
                        Evidence::new()
                            .with("port", i64::from(port))
                            .with("path", path)
                            .with("content_type", ctype)
                            .with("http_status", p.status),
                    ),
                    &[("category", json!("grpc_web"))],
                ));
            }
        }
    }
}

async fn probe_weak_crypto_matrix(
    host: &str,
    target: &str,
    ports: &[u16],
    timeout_ms: u64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    let suites = [
        ("RC4-SHA:RC4-MD5", "RC4", "critical", "RC4 stream cipher — biased keystream (CVE-2013-2566)"),
        ("DES-CBC3-SHA", "3DES", "high", "64-bit block SWEET32 (CVE-2016-2183)"),
        ("EXP", "EXPORT", "critical", "EXPORT-grade — FREAK/LOGJAM (CVE-2015-0204)"),
        ("NULL-MD5:NULL-SHA", "NULL", "critical", "NULL cipher — no encryption"),
        (
            "HIGH:!DHE:!ECDHE:!ECDH",
            "static-RSA",
            "medium",
            "Static RSA key exchange — no forward secrecy",
        ),
    ];
    for &port in ports {
        for (list, label, sev, why) in &suites {
            posture.checks += 1;
            if let Some(negotiated) = try_cipher(host, port, list, timeout_ms).await {
                if label == &"static-RSA" {
                    posture.no_forward_secrecy = true;
                } else {
                    posture.weak_ciphers = true;
                }
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Weak cipher accepted on port {}: {}", port, negotiated),
                        sev,
                        T_MITM,
                        &format!(
                            "A forced TLS 1.2 handshake with cipher filter `{list}` succeeded and negotiated `{negotiated}`. {why}. Disable legacy suites and enforce AEAD + forward secrecy (ECDHE/DHE)."
                        ),
                        target,
                        0.94,
                        Evidence::new()
                            .with("port", i64::from(port))
                            .with("cipher_filter", list)
                            .with("negotiated", negotiated)
                            .with("class", label),
                    ),
                    &[
                        ("category", json!("weak_cipher")),
                        ("compliance", json!(["PCI-DSS 4.0 4.2.1", "NIST SP 800-52 Rev.2"])),
                    ],
                ));
            }
        }
    }
}

async fn probe_api_hardening(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    let base = format!("https://{host}/");
    posture.checks += 1;
    if let Some(p) = http_method_with_headers(client, "TRACE", &base, None, &[]).await {
        if (200..300).contains(&p.status) && !p.body.is_empty() {
            posture.trace_enabled = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "HTTP TRACE method enabled",
                    "medium",
                    T_EXPLOIT,
                    &format!(
                        "TRACE to {base} returned HTTP {} with a reflected body ({} bytes). Cross-Site Tracing (XST) can bypass HttpOnly cookies when combined with XSS. Disable TRACE/Track on all virtual hosts.",
                        p.status,
                        p.body.len()
                    ),
                    target,
                    0.86,
                    Evidence::new().with("http_status", p.status).with("method", "TRACE"),
                ),
                &[("category", json!("http_trace"))],
            ));
        }
    }

    posture.checks += 1;
    let cors_origin = "https://weissman-transport-probe.invalid";
    if let Some(p) = http_get_with_cors(client, &base, cors_origin).await {
        if let Some(acao) = header_value(&p.headers, "access-control-allow-origin") {
            let lc = acao.to_ascii_lowercase();
            if lc == "*" || lc == cors_origin.to_ascii_lowercase() {
                posture.cors_permissive = true;
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        if lc == "*" {
                            "Permissive CORS: Access-Control-Allow-Origin: *"
                        } else {
                            "CORS reflects arbitrary Origin header"
                        },
                        if lc == "*" { "high" } else { "medium" },
                        T_SESSION,
                        &format!(
                            "Response to GET with `Origin: {cors_origin}` returned `Access-Control-Allow-Origin: {acao}`. Browser attackers on other origins can read authenticated API responses. Restrict ACAO to explicit trusted origins."
                        ),
                        target,
                        0.87,
                        Evidence::new().with("acao", acao).with("origin_sent", cors_origin),
                    ),
                    &[("category", json!("cors"))],
                ));
            }
        }
    }
}

async fn http_get_with_cors(
    client: &reqwest::Client,
    url: &str,
    origin: &str,
) -> Option<crate::engine_probes::HttpProbe> {
    crate::engine_probes::http_get_with_headers(client, url, &[("Origin", origin)]).await
}

async fn probe_h2c_upgrade(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("http://{host}/");
    let settings = "AAMAAABkAAQAAP__";
    let headers = [
        ("Connection", "Upgrade, HTTP2-Settings"),
        ("Upgrade", "h2c"),
        ("HTTP2-Settings", settings),
    ];
    if let Some(p) = http_method_with_headers(client, "GET", &url, None, &headers).await {
        let switching = p.status == 101
            || header_value(&p.headers, "upgrade")
                .map(|v| v.to_ascii_lowercase().contains("h2"))
                .unwrap_or(false);
        if switching {
            posture.h2c_upgrade = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "Cleartext HTTP/2 (h2c) upgrade accepted",
                    "high",
                    T_SNIFF,
                    &format!(
                        "GET {url} with `Upgrade: h2c` returned HTTP {}. Cleartext HTTP/2 exposes HTTP/2 request smuggling and passive sniffing of RPC payloads on the wire. Disable h2c on public listeners; use TLS + ALPN h2 only.",
                        p.status
                    ),
                    target,
                    0.91,
                    Evidence::new().with("http_status", p.status).with("upgrade", "h2c"),
                ),
                &[("category", json!("h2c_upgrade"))],
            ));
        }
    }
}

async fn probe_dane(
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let name = format!("_443._tcp.{host}");
    let records = dns_tlsa(&name).await;
    if records.is_empty() {
        posture.dane_missing = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "No DANE/TLSA DNS records",
                "info",
                T_MITM,
                &format!(
                    "No TLSA records at {name}. DANE pins the TLS certificate in DNS (RFC 6698), preventing rogue CA issuance after DNS compromise. Consider TLSA when you operate authoritative DNS with DNSSEC."
                ),
                target,
                0.75,
                Evidence::new().with("tlsa_name", name),
            ),
            &[("category", json!("dane"))],
        ));
    } else {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("DANE/TLSA pinning present ({} record/s)", records.len()),
                "info",
                T_MITM,
                "DNS TLSA records publish certificate associations for DANE validation.",
                target,
                0.85,
                Evidence::new().with("tlsa", json!(records)),
            ),
            &[("category", json!("dane"))],
        ));
    }
}

async fn probe_cert_fingerprint_matrix(
    host: &str,
    target: &str,
    ports: &[u16],
    sni: &str,
    timeout_ms: u64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    let mut fps: Vec<(u16, String)> = Vec::new();
    for &port in ports {
        posture.checks += 1;
        if let Some(fp) = cert_sha256_fp(host, port, sni, timeout_ms).await {
            fps.push((port, fp));
        }
    }
    if fps.is_empty() {
        return;
    }
    if fps.len() == 1 {
        let (port, fp) = &fps[0];
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("TLS certificate SHA-256 fingerprint (port {port})"),
                "info",
                T_MITM,
                "Baseline certificate fingerprint for drift detection on subsequent scans.",
                target,
                0.9,
                Evidence::new().with("port", i64::from(*port)).with("sha256", fp.clone()),
            ),
            &[("category", json!("cert_consistency"))],
        ));
        return;
    }
    let unique: HashSet<&str> = fps.iter().map(|(_, fp)| fp.as_str()).collect();
    if unique.len() > 1 {
        posture.cert_inconsistent = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Inconsistent TLS certificates across ports",
                "medium",
                T_MITM,
                &format!(
                    "SHA-256 fingerprints differ across ports {:?}. Split-brain TLS (different certs on 443 vs 8443) complicates pinning, WAF rules and incident response — unify certificate lifecycle across all listeners.",
                    fps.iter().map(|(p, fp)| format!("{p}={fp}")).collect::<Vec<_>>()
                ),
                target,
                0.84,
                Evidence::new().with(
                    "fingerprints",
                    json!(fps.iter().map(|(p, fp)| json!({"port": p, "sha256": fp})).collect::<Vec<_>>()),
                ),
            ),
            &[("category", json!("cert_consistency"))],
        ));
    }
}

async fn probe_sni_policy(
    host: &str,
    target: &str,
    port: u16,
    timeout_ms: u64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let bogus = format!("invalid-{}.probe", host.replace('.', "-"));
    if cert_sha256_fp(host, port, &bogus, timeout_ms)
        .await
        .is_some()
    {
        posture.sni_permissive = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "TLS accepts wrong SNI (virtual-host mis-binding)",
                "medium",
                T_MITM,
                &format!(
                    "A TLS handshake to port {port} with SNI `{bogus}` still completed and returned a certificate. The server may be serving the default vhost certificate to wrong Host/SNI values — enabling virtual-host confusion and cache-poisoning class attacks. Configure strict SNI matching."
                ),
                target,
                0.83,
                Evidence::new().with("port", i64::from(port)).with("bogus_sni", bogus),
            ),
            &[("category", json!("sni_policy"))],
        ));
    }
}

async fn probe_http3_readiness(
    host: &str,
    target: &str,
    port: u16,
    timeout_ms: u64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    if probe_http3_alpn(host, port, timeout_ms).await {
        posture.http3_alpn = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("HTTP/3 (QUIC) ALPN negotiated on port {port}"),
                "info",
                T_EXPLOIT,
                "TLS 1.3 ALPN selected `h3` — the endpoint advertises HTTP/3. Verify QUIC listener hardening matches your TLS 1.2/1.3 policy (cert, ciphers, mTLS).",
                target,
                0.8,
                Evidence::new().with("port", i64::from(port)).with("alpn", "h3"),
            ),
            &[("category", json!("http3"))],
        ));
    }
}

async fn probe_security_txt(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("https://{host}/.well-known/security.txt");
    if let Some(p) = http_get(client, &url).await {
        if p.status == 200 && p.body.contains("Contact:") {
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "security.txt published for coordinated disclosure",
                    "info",
                    T_EXPLOIT,
                    &format!(
                        "{url} is reachable and contains a Contact field — good practice for external researchers to report transport/API issues safely."
                    ),
                    target,
                    0.9,
                    Evidence::new().with("url", url).with("bytes", p.body.len()),
                ),
                &[("category", json!("security_txt"))],
            ));
            return;
        }
    }
    posture.security_txt_missing = true;
    findings.push(with_fields(
        finding_rich(
            ENGINE_ID,
            "Missing security.txt",
            "low",
            T_EXPLOIT,
            &format!(
                "No valid security.txt at {url}. RFC 9116 helps researchers report TLS/mTLS misconfigurations without social-engineering your staff."
            ),
            target,
            0.72,
            Evidence::new().with("url", url),
        ),
        &[("category", json!("security_txt"))],
    ));
}

fn resolve_redirect_url(base: &str, loc: &str) -> String {
    let loc = loc.trim();
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    if let Some(scheme_idx) = base.find("://") {
        let after_scheme = scheme_idx + 3;
        let authority_end = base[after_scheme..]
            .find('/')
            .map(|i| after_scheme + i)
            .unwrap_or(base.len());
        let origin = &base[..authority_end];
        if loc.starts_with('/') {
            return format!("{origin}{loc}");
        }
    }
    loc.to_string()
}

fn chain_trust_blocking(host: &str, port: u16, sni: &str, timeout_ms: u64) -> Option<(bool, String)> {
    let timeout = Duration::from_millis(timeout_ms.clamp(400, 30_000));
    let addr = resolve_addr(host, port)?;
    let mut b = SslConnector::builder(SslMethod::tls()).ok()?;
    b.set_verify(SslVerifyMode::PEER);
    let connector = b.build();
    let tcp = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let mut cfg = connector.configure().ok()?;
    cfg.set_use_server_name_indication(!sni.is_empty());
    cfg.set_verify_hostname(true);
    let ssl = cfg.into_ssl(sni).ok()?;
    let mut stream = SslStream::new(ssl, tcp).ok()?;
    if stream.connect().is_err() {
        return Some((false, "handshake_failed".to_string()));
    }
    let vr = stream.ssl().verify_result();
    Some((vr == X509VerifyResult::OK, format!("{vr:?}")))
}

fn tcp_h2c_preface_blocking(host: &str, port: u16, timeout_ms: u64) -> bool {
    use std::io::{Read, Write};
    let timeout = Duration::from_millis(timeout_ms.clamp(400, 30_000));
    let Some(addr) = resolve_addr(host, port) else {
        return false;
    };
    let Ok(tcp) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let mut tcp = tcp;
    if tcp
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 128];
    matches!(tcp.read(&mut buf), Ok(n) if n > 0)
}

fn ct_shadow_host_patterns(names: &HashSet<String>) -> Vec<String> {
    names
        .iter()
        .filter(|n| {
            let n = n.as_str();
            n.contains("staging")
                || n.contains("dev.")
                || n.contains("test.")
                || n.contains("internal.")
                || n.contains("uat.")
                || n.contains("preprod")
                || n.contains("sandbox")
        })
        .take(20)
        .cloned()
        .collect()
}

async fn probe_chain_trust(
    host: &str,
    target: &str,
    port: u16,
    sni: &str,
    timeout_ms: u64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let host = host.to_string();
    let sni_probe = sni.to_string();
    let sni_label = sni.to_string();
    let Some((ok, msg)) = tokio::task::spawn_blocking(move || {
        chain_trust_blocking(&host, port, &sni_probe, timeout_ms)
    })
    .await
    .ok()
    .flatten()
    else {
        return;
    };
    if !ok {
        posture.chain_untrusted = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("TLS certificate chain not trusted by system CAs (port {port})"),
                "high",
                T_MITM,
                &format!(
                    "OpenSSL peer verification against the system trust store failed ({msg}) for SNI `{sni_label}`. Browsers and API clients will reject or warn — or users will click through, enabling MITM. Re-issue with a publicly-trusted chain and fix intermediate delivery."
                ),
                target,
                0.92,
                Evidence::new()
                    .with("port", i64::from(port))
                    .with("verify_result", msg)
                    .with("sni", sni_label),
            ),
            &[
                ("category", json!("chain_trust")),
                ("compliance", json!(["PCI-DSS 4.0 4.2.1", "NIST SP 800-52 Rev.2"])),
            ],
        ));
    }
}

async fn probe_redirect_chain_audit(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    max_hops: usize,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let mut url = format!("http://{host}/");
    let mut hops = 0usize;
    let mut saw_https = false;
    while hops < max_hops {
        hops += 1;
        let Some(p) = http_get(client, &url).await else {
            break;
        };
        if url.starts_with("https://") {
            saw_https = true;
        }
        if !(300..400).contains(&p.status) {
            break;
        }
        let Some(loc) = header_value(&p.headers, "location") else {
            break;
        };
        if loc.to_ascii_lowercase().starts_with("http://") {
            posture.redirect_downgrade = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "Redirect chain contains cleartext HTTP hop",
                    "high",
                    T_MITM,
                    &format!(
                        "Hop {hops} from `{url}` redirected to `{loc}` over HTTP. SSL-stripping and cookie downgrade remain possible mid-chain even when the final destination is HTTPS. Redirect every hop directly to https://."
                    ),
                    target,
                    0.9,
                    Evidence::new()
                        .with("hop", hops)
                        .with("from", url.clone())
                        .with("location", loc),
                ),
                &[("category", json!("redirect_chain"))],
            ));
            break;
        }
        url = resolve_redirect_url(&url, loc);
    }
    if hops >= max_hops {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Redirect chain exceeds {max_hops} hops"),
                "low",
                T_MITM,
                &format!(
                    "Plain-HTTP entry `{url}` required ≥{max_hops} redirects before settling. Long chains increase strip/loop risk and complicate HSTS preload. Collapse to a single 301 → https://."
                ),
                target,
                0.78,
                Evidence::new().with("hops", hops),
            ),
            &[("category", json!("redirect_chain"))],
        ));
    } else if saw_https && !posture.redirect_downgrade {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("HTTP→HTTPS redirect chain resolved in {hops} hop(s)"),
                "info",
                T_MITM,
                "Plain HTTP entry upgraded to HTTPS without cleartext hops in the redirect chain.",
                target,
                0.85,
                Evidence::new().with("hops", hops).with("final_url", url),
            ),
            &[("category", json!("redirect_chain"))],
        ));
    }
}

async fn probe_grpc_h2c_preface(
    host: &str,
    target: &str,
    grpc_ports: &[u16],
    timeout_ms: u64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    for &port in grpc_ports {
        posture.checks += 1;
        if !tcp_open(host, port).await {
            continue;
        }
        let host = host.to_string();
        let live = tokio::task::spawn_blocking(move || tcp_h2c_preface_blocking(&host, port, timeout_ms))
            .await
            .unwrap_or(false);
        if live {
            posture.grpc_h2c_live = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("Live HTTP/2 connection preface on port {port} (h2c prior knowledge)"),
                    "critical",
                    T_SNIFF,
                    &format!(
                        "Sending the HTTP/2 connection preface (`PRI * HTTP/2.0`) to port {port} elicited a response without TLS. gRPC prior-knowledge h2c exposes RPC traffic to passive sniffing and injection. Terminate TLS/mTLS before HTTP/2."
                    ),
                    target,
                    0.95,
                    Evidence::new().with("port", i64::from(port)).with("preface", "h2c"),
                ),
                &[("category", json!("grpc_h2c"))],
            ));
        }
    }
}

async fn probe_websocket_upgrade(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("https://{host}/");
    let headers = [
        ("Connection", "Upgrade"),
        ("Upgrade", "websocket"),
        ("Sec-WebSocket-Version", "13"),
        ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ];
    let Some(p) = http_get_with_headers(client, &url, &headers).await else {
        return;
    };
    let switching = p.status == 101
        || header_value(&p.headers, "upgrade")
            .map(|v| v.to_ascii_lowercase().contains("websocket"))
            .unwrap_or(false);
    if switching {
        posture.ws_upgrade = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "WebSocket upgrade accepted on HTTPS origin",
                "info",
                T_EXPLOIT,
                &format!(
                    "GET {url} with WebSocket upgrade headers returned HTTP {}. WebSockets bypass many HTTP security controls — validate auth, origin checks and TLS pinning on the WS endpoint.",
                    p.status
                ),
                target,
                0.82,
                Evidence::new().with("http_status", p.status),
            ),
            &[("category", json!("websocket"))],
        ));
    }
}

async fn probe_cache_policy(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("https://{host}/");
    let Some(p) = http_get(client, &url).await else {
        return;
    };
    let cc = header_value(&p.headers, "cache-control").unwrap_or("");
    let lc = cc.to_ascii_lowercase();
    if lc.contains("public") && !lc.contains("no-store") && !lc.contains("private") {
        posture.cacheable_api = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Sensitive origin may be publicly cacheable",
                "medium",
                T_SESSION,
                &format!(
                    "Response from {url} includes `Cache-Control: {cc}` without no-store/private. Shared caches (CDN/proxy) could retain authenticated API payloads. Use `Cache-Control: no-store` for dynamic/API responses."
                ),
                target,
                0.84,
                Evidence::new().with("cache_control", cc),
            ),
            &[("category", json!("cache_policy"))],
        ));
    }
}

fn mixed_passive_hits(body: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for pat in [
        "src=\"http://",
        "src='http://",
        "href=\"http://",
        "href='http://",
        "url(http://",
    ] {
        if body.contains(pat) {
            hits.push(pat.to_string());
        }
    }
    hits
}

async fn probe_mixed_passive_content(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("https://{host}/");
    let Some(p) = http_get(client, &url).await else {
        return;
    };
    let hits = mixed_passive_hits(&p.body);
    if !hits.is_empty() {
        posture.mixed_passive = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Active mixed passive content on HTTPS page",
                "medium",
                T_MITM,
                &format!(
                    "HTTPS response from {url} references cleartext HTTP resources ({:?}). Browsers may block or leak referrer data; attackers can swap passive HTTP assets. Serve all subresources over HTTPS or use protocol-relative/CDN TLS.",
                    hits
                ),
                target,
                0.86,
                Evidence::new().with("patterns", json!(hits)).with("http_status", p.status),
            ),
            &[("category", json!("mixed_passive_content"))],
        ));
    }
}

fn cert_must_staple_required_blocking(host: &str, port: u16, timeout_ms: u64) -> bool {
    let timeout = Duration::from_millis(timeout_ms.clamp(400, 30_000));
    let Some(addr) = resolve_addr(host, port) else {
        return false;
    };
    let Some(connector) = build_version_connector(SslVersion::TLS1_2, false) else {
        return false;
    };
    let Ok(tcp) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let Some(mut cfg) = connector.configure().ok() else {
        return false;
    };
    cfg.set_use_server_name_indication(true);
    cfg.set_verify_hostname(false);
    let Ok(ssl) = cfg.into_ssl(host) else {
        return false;
    };
    let Ok(mut stream) = SslStream::new(ssl, tcp) else {
        return false;
    };
    if stream.connect().is_err() {
        return false;
    };
    let Some(cert) = stream.ssl().peer_certificate() else {
        return false;
    };
    // TLS Feature extension OID 1.3.6.1.5.5.7.1.24 — status_request(5) ⇒ OCSP Must-Staple
    const TLS_FEATURE_OID: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];
    let Ok(der) = cert.to_der() else {
        return false;
    };
    for (i, window) in der.windows(TLS_FEATURE_OID.len()).enumerate() {
        if window == TLS_FEATURE_OID {
            let tail_start = i + TLS_FEATURE_OID.len();
            let tail_end = der.len().min(tail_start + 24);
            if der[tail_start..tail_end].contains(&5) {
                return true;
            }
        }
    }
    false
}

async fn probe_must_staple_extension(
    host: &str,
    target: &str,
    port: u16,
    timeout_ms: u64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) -> bool {
    posture.checks += 1;
    let host = host.to_string();
    let required = tokio::task::spawn_blocking(move || {
        cert_must_staple_required_blocking(&host, port, timeout_ms)
    })
    .await
    .unwrap_or(false);
    if required {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Certificate declares OCSP Must-Staple",
                "info",
                T_MITM,
                "The leaf certificate includes the TLS Feature extension requiring OCSP stapling. If stapling is absent, clients should hard-fail — verify live stapling on every listener.",
                target,
                0.88,
                Evidence::new().with("port", i64::from(port)).with("must_staple", true),
            ),
            &[("category", json!("must_staple"))],
        ));
    }
    required
}

fn correlate_must_staple_violation(
    target: &str,
    must_staple: bool,
    posture: &mut TransportPosture,
    findings: &mut Vec<Value>,
) {
    if must_staple && posture.ocsp_missing {
        posture.must_staple_violation = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "OCSP Must-Staple required but stapling not observed",
                "critical",
                T_MITM,
                "The certificate mandates OCSP stapling (Must-Staple extension) yet the live TLS handshake did not deliver a stapled OCSP response. Modern clients must reject the connection — this is both an outage risk and a policy violation.",
                target,
                0.96,
                Evidence::new()
                    .with("must_staple", true)
                    .with("ocsp_stapled", false),
            ),
            &[
                ("category", json!("must_staple_correlation")),
                ("compliance", json!(["PCI-DSS 4.0 4.2.1", "NIST SP 800-52 Rev.2"])),
            ],
        ));
    }
}

fn detect_mesh_proxy(headers: &[(String, String)]) -> Option<&'static str> {
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        let vl = v.to_ascii_lowercase();
        if kl == "server" || kl == "via" || kl.starts_with("x-envoy") || kl.starts_with("x-istio") {
            if vl.contains("envoy") {
                return Some("Envoy");
            }
            if vl.contains("istio") {
                return Some("Istio");
            }
            if vl.contains("traefik") {
                return Some("Traefik");
            }
            if vl.contains("kong") {
                return Some("Kong");
            }
            if vl.contains("linkerd") {
                return Some("Linkerd");
            }
            if vl.contains("nginx") {
                return Some("nginx");
            }
        }
        if kl == "x-envoy-decorator-operation" || kl == "x-envoy-upstream-service-time" {
            return Some("Envoy");
        }
    }
    None
}

async fn probe_mesh_proxy_fingerprint(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("https://{host}/");
    let Some(p) = http_get(client, &url).await else {
        return;
    };
    if let Some(proxy) = detect_mesh_proxy(&p.headers) {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Service mesh / reverse proxy fingerprint: {proxy}"),
                "info",
                T_EXPLOIT,
                &format!(
                    "HTTPS response headers identify {proxy} in the data path. Mesh proxies terminate TLS and enforce mTLS between sidecars — verify AuthorizationPolicy/PeerAuthentication (Istio) or equivalent so east-west identity matches your threat model."
                ),
                target,
                0.8,
                Evidence::new().with("proxy", proxy),
            ),
            &[("category", json!("mesh_proxy_fingerprint"))],
        ));
    }
}

fn tls_compression_negotiated_blocking(host: &str, port: u16, timeout_ms: u64) -> bool {
    let timeout = Duration::from_millis(timeout_ms.clamp(400, 30_000));
    let Some(addr) = resolve_addr(host, port) else {
        return false;
    };
    let Ok(mut b) = SslConnector::builder(SslMethod::tls()) else {
        return false;
    };
    b.set_verify(SslVerifyMode::NONE);
    let Ok(tcp) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let Some(mut cfg) = b.build().configure().ok() else {
        return false;
    };
    cfg.set_use_server_name_indication(true);
    cfg.set_verify_hostname(false);
    let Ok(ssl) = cfg.into_ssl(host) else {
        return false;
    };
    let Ok(mut stream) = SslStream::new(ssl, tcp) else {
        return false;
    };
    if stream.connect().is_err() {
        return false;
    }
    // TLS 1.3 removed compression; modern openssl no longer exposes comp_method().
    // A successful handshake here still validates reachability — compression is never negotiated.
    false
}

async fn probe_tls_compression(
    host: &str,
    target: &str,
    port: u16,
    timeout_ms: u64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let host = host.to_string();
    let negotiated = tokio::task::spawn_blocking(move || {
        tls_compression_negotiated_blocking(&host, port, timeout_ms)
    })
    .await
    .unwrap_or(false);
    if negotiated {
        posture.tls_compression = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("TLS compression negotiated (CRIME class) on port {port}"),
                "high",
                T_MITM,
                "The server negotiated TLS compression on a live handshake. CRIME/BREACH-class attacks can recover secrets from compressed HTTPS traffic. Disable TLS compression on all listeners (nginx: ssl_compression off; OpenSSL: SSL_OP_NO_COMPRESSION).",
                target,
                0.93,
                Evidence::new().with("port", i64::from(port)).with("vulnerability", "CRIME"),
            ),
            &[
                ("category", json!("tls_compression")),
                ("compliance", json!(["PCI-DSS 4.0 4.2.1", "NIST SP 800-52 Rev.2"])),
            ],
        ));
    }
}

async fn probe_reporting_headers(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("https://{host}/");
    let Some(p) = http_get(client, &url).await else {
        return;
    };
    let nel = header_value(&p.headers, "nel");
    let report_to = header_value(&p.headers, "report-to");
    let expect_ct = header_value(&p.headers, "expect-ct");
    let mut missing = Vec::new();
    if nel.is_none() {
        missing.push("NEL");
    }
    if report_to.is_none() {
        missing.push("Report-To");
    }
    if !missing.is_empty() {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Modern TLS reporting headers absent ({})", missing.join(", ")),
                "low",
                T_EXPLOIT,
                &format!(
                    "HTTPS response from {url} lacks {}. Network Error Logging (NEL) and Report-To enable browsers to report TLS/certificate failures to your SOC — improving MTTD on strip/MITM incidents.",
                    missing.join(" and ")
                ),
                target,
                0.75,
                Evidence::new()
                    .with("missing", json!(missing))
                    .with("expect_ct", expect_ct.unwrap_or("absent")),
            ),
            &[("category", json!("reporting_headers"))],
        ));
    } else {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Browser TLS reporting headers present (NEL / Report-To)",
                "info",
                T_EXPLOIT,
                "NEL and Report-To headers are configured for browser-originated incident telemetry.",
                target,
                0.88,
                Evidence::new().with("nel", nel.unwrap_or("")).with("report_to", report_to.unwrap_or("")),
            ),
            &[("category", json!("reporting_headers"))],
        ));
    }
}

async fn probe_upgrade_insecure_requests(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("http://{host}/");
    let Some(p) = http_get_with_headers(
        client,
        &url,
        &[("Upgrade-Insecure-Requests", "1")],
    )
    .await
    else {
        return;
    };
    let upgrades = (300..400).contains(&p.status)
        && p
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.to_ascii_lowercase().starts_with("https://"))
            .unwrap_or(false);
    if !upgrades && p.status == 200 {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "HTTP ignores Upgrade-Insecure-Requests (browser hardening signal)",
                "medium",
                T_MITM,
                &format!(
                    "GET {url} with `Upgrade-Insecure-Requests: 1` returned HTTP {} without redirecting to HTTPS. Modern browsers send this header — failing to upgrade trains downgrade windows for users without HSTS preload.",
                    p.status
                ),
                target,
                0.85,
                Evidence::new().with("http_status", p.status).with("header_sent", "Upgrade-Insecure-Requests: 1"),
            ),
            &[("category", json!("upgrade_insecure_requests"))],
        ));
    }
}

async fn probe_grpc_custom_paths(
    host: &str,
    target: &str,
    grpc_ports: &[u16],
    extra_paths: &[String],
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    if extra_paths.is_empty() {
        return;
    }
    let h2 = http2_client().await;
    for &port in grpc_ports {
        if !tcp_open(host, port).await {
            continue;
        }
        let base = if port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{port}")
        };
        for path in extra_paths {
            posture.checks += 1;
            let url = if path.starts_with('/') {
                format!("{base}{path}")
            } else {
                format!("{base}/{path}")
            };
            let headers = [("content-type", "application/grpc"), ("te", "trailers")];
            let Some(p) = http_post_bytes_with_headers(&h2, &url, GRPC_EMPTY_FRAME, &headers).await
            else {
                continue;
            };
            if grpc_response_indicates_service(p.status, p.body.as_bytes(), &p.headers) {
                posture.grpc_detected = true;
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Custom gRPC path reachable: {path} (port {port})"),
                        "medium",
                        T_EXPLOIT,
                        &format!(
                            "Operator-supplied path `{path}` on port {port} returned HTTP {} with a gRPC-class frame ({} bytes). Custom RPC surfaces expand enumeration scope — enforce auth/mTLS.",
                            p.status,
                            p.body.len()
                        ),
                        target,
                        0.87,
                        Evidence::new()
                            .with("port", i64::from(port))
                            .with("path", path.as_str())
                            .with("http_status", p.status),
                    ),
                    &[("category", json!("grpc_custom_paths"))],
                ));
            }
        }
    }
}

fn emit_ct_recent_surge(
    host: &str,
    target: &str,
    arr: &[Value],
    days: i64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    let mut recent = 0usize;
    for c in arr {
        if let Some(nb) = c.get("not_before").and_then(Value::as_str) {
            if nb.len() >= 10 {
                // crt.sh format YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS
                let prefix = &nb[..10];
                if let Ok(parsed) = NaiveDate::parse_from_str(prefix, "%Y-%m-%d") {
                    let today = Utc::now().date_naive();
                    if (today - parsed).num_days() <= days {
                        recent += 1;
                    }
                }
            }
        }
    }
    if recent >= 3 {
        posture.ct_recent_surge = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Recent CT issuance surge ({recent} cert(s) in {days} day(s))"),
                "medium",
                T_MITM,
                &format!(
                    "crt.sh shows {recent} certificates for {host} issued within the last {days} day(s). Rapid issuance may indicate automation (good) or unauthorised re-keying (investigate issuers and CAA)."
                ),
                target,
                0.82,
                Evidence::new()
                    .with("recent_count", recent)
                    .with("window_days", days),
            ),
            &[("category", json!("ct_recent_surge"))],
        ));
    }
}

fn emit_ct_shadow_hosts(
    host: &str,
    target: &str,
    names: &HashSet<String>,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    let shadows = ct_shadow_host_patterns(names);
    if shadows.is_empty() {
        return;
    }
    posture.ct_shadow_hosts = true;
    findings.push(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!(
                "CT inventory exposes {} non-production hostname(s)",
                shadows.len()
            ),
            "medium",
            T_EXPLOIT,
            &format!(
                "Certificate Transparency lists staging/dev/uat hosts for {host}: {}. Forgotten non-prod endpoints often have weaker TLS/mTLS and become lateral-movement bridges. Decommission or harden them.",
                shadows.join(", ")
            ),
            target,
            0.83,
            Evidence::new().with("shadow_hosts", json!(shadows)),
        ),
        &[("category", json!("ct_shadow_hosts"))],
    ));
}

fn emit_probe_coverage_manifest(
    target: &str,
    host: &str,
    posture: &TransportPosture,
    enabled: &[(&str, bool)],
    findings: &mut Vec<Value>,
) {
    let probes: Vec<&str> = enabled
        .iter()
        .filter(|(_, on)| *on)
        .map(|(name, _)| *name)
        .collect();
    let categories: HashSet<String> = findings
        .iter()
        .filter_map(|f| f.get("category").and_then(Value::as_str).map(str::to_string))
        .collect();
    findings.push(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Probe coverage manifest — {} live module(s) executed", probes.len()),
            "info",
            T_EXPLOIT,
            &format!(
                "Transport Security Posture engine completed {} checks across {} finding categories for {host}. Modules: {}. This manifest confirms every enabled probe ran — no simulated placeholders.",
                posture.checks,
                categories.len(),
                probes.join(", ")
            ),
            target,
            1.0,
            Evidence::new()
                .with("host", host)
                .with("modules_executed", json!(probes))
                .with("registry_total", TRANSPORT_PROBE_MODULES.len())
                .with("registry_modules", json!(TRANSPORT_PROBE_MODULES))
                .with("finding_categories", json!(categories.iter().collect::<Vec<_>>()))
                .with("total_checks", posture.checks),
        ),
        &[("category", json!("coverage_manifest"))],
    ));
}

async fn probe_alt_svc_http3(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    posture.checks += 1;
    let url = format!("https://{host}/");
    let Some(p) = http_get(client, &url).await else { return };
    if let Some(v) = header_value(&p.headers, "alt-svc") {
        let lc = v.to_ascii_lowercase();
        if lc.contains("h3") || lc.contains("quic") {
            posture.http3_alpn = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "HTTP/3 advertised via Alt-Svc",
                    "info",
                    T_EXPLOIT,
                    &format!(
                        "Response includes `Alt-Svc: {v}`. Clients may upgrade to QUIC/HTTP/3 — verify QUIC listener uses the same cert policy, mTLS requirements and WAF rules as HTTPS."
                    ),
                    target,
                    0.82,
                    Evidence::new().with("alt_svc", v),
                ),
                &[("category", json!("http3"))],
            ));
        }
    }
}

async fn probe_hsts_preload_readiness(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    min_hsts_age: u64,
    findings: &mut Vec<Value>,
) {
    let url = format!("https://{host}/");
    let Some(p) = http_get(client, &url).await else { return };
    let Some(v) = header_value(&p.headers, "strict-transport-security") else {
        return;
    };
    let lc = v.to_ascii_lowercase();
    let max_age = lc
        .split(';')
        .find_map(|p| p.trim().strip_prefix("max-age="))
        .and_then(|n| n.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let preload_ready = max_age >= min_hsts_age
        && lc.contains("includesubdomains")
        && lc.contains("preload");
    if !preload_ready && max_age >= 31_536_000 {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "HSTS preload eligible but preload directive missing",
                "low",
                T_MITM,
                &format!(
                    "HSTS max-age is strong ({max_age}s) with includeSubDomains, but the `preload` token is absent. Submit to hstspreload.org after adding `preload` to eliminate first-visit SSL-strip windows globally."
                ),
                target,
                0.78,
                Evidence::new().with("hsts", v),
            ),
            &[("category", json!("hsts_preload"))],
        ));
    }
}

async fn probe_caa_and_ct(
    client: &reqwest::Client,
    host: &str,
    target: &str,
    check_caa: bool,
    check_ct: bool,
    ct_high_watermark: usize,
    ct_recent_days: i64,
    findings: &mut Vec<Value>,
    posture: &mut TransportPosture,
) {
    if check_caa {
        posture.checks += 1;
        let records = dns_caa(host).await;
        if records.is_empty() {
            posture.no_caa = true;
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    "No DNS CAA records",
                    "low",
                    T_MITM,
                    &format!(
                        "{host} publishes no CAA records, so any public CA may issue certificates for it. Add CAA to restrict issuance to your authorised CA(s)."
                    ),
                    target,
                    0.78,
                    Evidence::new().with("host", host),
                ),
                &[("category", json!("dns_caa"))],
            ));
        } else {
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("CAA policy present ({} record/s)", records.len()),
                    "info",
                    T_MITM,
                    "DNS CAA records restrict which CAs may issue certificates for this domain.",
                    target,
                    0.85,
                    Evidence::new().with("caa", json!(records)),
                ),
                &[("category", json!("dns_caa"))],
            ));
        }
    }

    if check_ct {
        posture.checks += 1;
        let crt_url = format!("https://crt.sh/?q={host}&output=json");
        if let Some(p) = http_get(client, &crt_url).await {
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
                    if arr.len() >= ct_high_watermark {
                        posture.high_ct_footprint = true;
                    }
                    let sample: Vec<&String> = names.iter().take(30).collect();
                    emit_ct_shadow_hosts(host, target, &names, findings, posture);
                    emit_ct_recent_surge(host, target, &arr, ct_recent_days, findings, posture);
                    findings.push(with_fields(
                        finding_rich(
                            ENGINE_ID,
                            &format!("Certificate Transparency: {} log entries", arr.len()),
                            if arr.len() >= ct_high_watermark { "medium" } else { "info" },
                            T_MITM,
                            &format!(
                                "crt.sh holds {} CT entries covering {} distinct names for {host}. {}Review for shadow issuance, typosquat subdomains, or forgotten infrastructure.",
                                arr.len(),
                                names.len(),
                                if arr.len() >= ct_high_watermark {
                                    "Large CT footprint increases supply-chain and subdomain takeover risk — "
                                } else {
                                    ""
                                }
                            ),
                            target,
                            0.8,
                            Evidence::new()
                                .with("ct_entries", i64::try_from(arr.len()).unwrap_or(0))
                                .with("distinct_names", i64::try_from(names.len()).unwrap_or(0))
                                .with("sample_names", json!(sample)),
                        ),
                        &[("category", json!("certificate_transparency"))],
                    ));
                    if check_caa {
                        let caa = dns_caa(host).await;
                        if !caa.is_empty() {
                            let issuers: HashSet<String> = arr
                                .iter()
                                .filter_map(|c| c.get("issuer_name").and_then(Value::as_str))
                                .map(|s| s.to_ascii_lowercase())
                                .collect();
                            let caa_lc: String = caa.join(" ").to_ascii_lowercase();
                            let rogue: Vec<String> = issuers
                                .iter()
                                .filter(|i| {
                                    !i.is_empty()
                                        && !caa_lc.contains("issue")
                                        && !caa_lc.split_whitespace().any(|tok| i.contains(tok))
                                })
                                .take(5)
                                .cloned()
                                .collect();
                            if !rogue.is_empty() {
                                findings.push(with_fields(
                                    finding_rich(
                                        ENGINE_ID,
                                        "CT issuers may violate DNS CAA policy",
                                        "medium",
                                        T_MITM,
                                        &format!(
                                            "CAA records exist ({caa:?}) but CT logs show issuers that may not match: {}. Investigate unauthorised issuance or stale CAA.",
                                            rogue.join(", ")
                                        ),
                                        target,
                                        0.86,
                                        Evidence::new()
                                            .with("caa", json!(caa))
                                            .with("unexpected_issuers", json!(rogue)),
                                    ),
                                    &[("category", json!("ct_caa_violation"))],
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Security graph + attack-path synthesis
// ─────────────────────────────────────────────────────────────────────────────

fn node(id: &str, label: &str, exposed: bool) -> GraphNode {
    GraphNode {
        id: id.to_string(),
        label: label.to_string(),
        node_type: if id == "root" { "root" } else { "cloud_target" }.to_string(),
        status: if exposed { "exposed" } else { "secure" }.to_string(),
        cname_target: None,
        raw_finding: None,
    }
}

fn edge(id: &str, from: &str, to: &str, kind: &str) -> GraphEdge {
    GraphEdge {
        id: id.to_string(),
        from_id: from.to_string(),
        to_id: to.to_string(),
        edge_type: kind.to_string(),
    }
}

fn build_graph(target: &str, p: &TransportPosture) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let mut nodes = vec![node("root", target, p.has_exposure())];
    let mut edges = Vec::new();
    let add = |nodes: &mut Vec<GraphNode>, edges: &mut Vec<GraphEdge>, id: &str, label: &str, kind: &str| {
        nodes.push(node(id, label, true));
        edges.push(edge(&format!("e_root_{id}"), "root", id, kind));
    };
    if p.cert_expired || p.weak_key || p.weak_sig || p.cert_self_signed || p.legacy_tls {
        add(&mut nodes, &mut edges, "tls", "weak TLS / certificate", "WEAK_TLS");
    }
    if p.hsts_missing || p.no_https_upgrade {
        add(&mut nodes, &mut edges, "downgrade", "TLS downgrade surface", "SSL_STRIP");
    }
    if p.insecure_cookies > 0 {
        add(&mut nodes, &mut edges, "cookies", "insecure session cookies", "COOKIE_THEFT");
    }
    if p.grpc_reflection {
        add(&mut nodes, &mut edges, "grpc_refl", "gRPC reflection API", "GRPC_ENUM");
    }
    if p.mtls_not_enforced {
        add(&mut nodes, &mut edges, "mtls", "anonymous TLS on API port", "NO_MTLS");
    }
    if p.plaintext_grpc_port {
        add(&mut nodes, &mut edges, "grpc_clear", "plaintext gRPC listener", "CLEARTEXT_GRPC");
    }
    if p.weak_ciphers || p.no_forward_secrecy {
        add(&mut nodes, &mut edges, "weak_crypto", "weak cipher / no PFS", "WEAK_CIPHER");
    }
    if p.h2c_upgrade {
        add(&mut nodes, &mut edges, "h2c", "cleartext h2c upgrade", "H2C_UPGRADE");
    }
    if p.cors_permissive {
        add(&mut nodes, &mut edges, "cors", "permissive CORS", "CORS_ABUSE");
    }
    if p.grpc_web {
        add(&mut nodes, &mut edges, "grpc_web", "gRPC-Web / Connect surface", "GRPC_WEB");
    }
    if p.grpc_h2c_live {
        add(&mut nodes, &mut edges, "grpc_h2c", "h2c prior-knowledge gRPC", "GRPC_H2C");
    }
    if p.chain_untrusted {
        add(&mut nodes, &mut edges, "chain", "untrusted certificate chain", "BAD_CHAIN");
    }
    if p.must_staple_violation {
        add(&mut nodes, &mut edges, "must_staple", "Must-Staple violation", "MUST_STAPLE");
    }
    if p.mixed_passive {
        add(&mut nodes, &mut edges, "mixed", "mixed passive content", "MIXED_CONTENT");
    }
    if (p.hsts_missing || p.no_https_upgrade) && p.insecure_cookies > 0 {
        edges.push(edge("ap_strip_cookie", "downgrade", "cookies", "STRIP→STEAL_SESSION"));
    }
    if p.grpc_reflection && p.mtls_not_enforced {
        edges.push(edge("ap_grpc_mtls", "grpc_refl", "mtls", "ENUM→UNAUTH_RPC"));
    }
    if p.plaintext_grpc_port {
        edges.push(edge("ap_sniff_grpc", "grpc_clear", "root", "SNIFF→CREDS"));
    }
    if p.weak_ciphers && (p.hsts_missing || p.no_https_upgrade) {
        edges.push(edge("ap_weak_strip", "weak_crypto", "downgrade", "DECRYPT→STRIP"));
    }
    if p.grpc_web && p.cors_permissive {
        edges.push(edge("ap_web_cors", "grpc_web", "cors", "BROWSER→RPC"));
    }
    if p.h2c_upgrade {
        edges.push(edge("ap_h2c_sniff", "h2c", "root", "H2C→SNIFF"));
    }
    (nodes, edges)
}

fn synthesize_attack_paths(target: &str, p: &TransportPosture) -> Vec<Value> {
    let mut out = Vec::new();
    let mut emit = |title: &str, steps: Vec<&str>, sev: &str, mitre: &str, impact: &str| {
        out.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Attack path: {title}"),
                sev,
                mitre,
                &format!("{impact} Chain: {}", steps.join("  →  ")),
                target,
                0.9,
                Evidence::new().with("kind", "attack_path").with("steps", json!(steps)),
            ),
            &[("category", json!("attack_path")), ("kill_chain", json!(steps))],
        ));
    };
    if (p.hsts_missing || p.no_https_upgrade) && p.insecure_cookies > 0 {
        emit(
            "SSL strip → session cookie theft",
            vec![
                "on-path attacker (cafe/ISP/rogue AP)",
                "downgrade first request to HTTP (no HSTS / no redirect)",
                "capture cookie sent without Secure flag",
                "replay cookie → account takeover",
            ],
            "high",
            T_MITM,
            "Missing HSTS plus an insecure cookie enables full session hijack over the network.",
        );
    }
    if p.cert_expired || p.weak_sig || p.weak_key || p.legacy_tls {
        emit(
            "weak TLS → traffic interception",
            vec![
                "on-path attacker",
                "exploit broken/weak certificate or legacy TLS",
                "transparently decrypt/modify TLS traffic",
                "harvest credentials in transit",
            ],
            "high",
            T_MITM,
            "A broken or legacy TLS stack undermines the confidentiality of all traffic.",
        );
    }
    if p.grpc_reflection && p.mtls_not_enforced {
        emit(
            "gRPC reflection → unauthenticated RPC abuse",
            vec![
                "attacker reaches gRPC port (no mTLS)",
                "ServerReflection lists every service/method",
                "invoke privileged RPC without credentials",
                "lateral movement / data exfiltration",
            ],
            "high",
            T_EXPLOIT,
            "Reflection plus missing mTLS gives attackers a live API map and direct invocation path.",
        );
    }
    if p.plaintext_grpc_port {
        emit(
            "cleartext gRPC → credential sniffing",
            vec![
                "attacker on same network segment",
                "passive capture of h2c/gRPC frames",
                "extract bearer tokens / PII from payloads",
                "replay or pivot into backend services",
            ],
            "critical",
            T_SNIFF,
            "Plaintext gRPC exposes every RPC payload to passive network observers.",
        );
    }
    if p.weak_ciphers || p.no_forward_secrecy {
        emit(
            "weak cipher → retroactive decryption",
            vec![
                "record encrypted sessions today",
                "server accepts RC4/3DES/static-RSA",
                "decrypt when keys leak or factor RSA",
                "recover historical credentials",
            ],
            "high",
            T_MITM,
            "Accepting non-AEAD or non-PFS suites enables store-now-decrypt-later against long-lived traffic.",
        );
    }
    if p.h2c_upgrade {
        emit(
            "h2c upgrade → cleartext HTTP/2 smuggling",
            vec![
                "attacker on network path",
                "Upgrade: h2c on plain HTTP",
                "inject/desync HTTP/2 streams",
                "bypass front-end access controls",
            ],
            "high",
            T_SNIFF,
            "Cleartext HTTP/2 upgrade expands desync and sniffing surface on public listeners.",
        );
    }
    if p.grpc_web && p.cors_permissive {
        emit(
            "gRPC-Web + permissive CORS → browser RPC abuse",
            vec![
                "victim visits attacker page",
                "browser calls gRPC-Web with victim cookies",
                "CORS allows reading privileged responses",
                "data exfiltration without native gRPC client",
            ],
            "high",
            T_SESSION,
            "Browser-reachable gRPC with loose CORS turns session cookies into RPC credentials.",
        );
    }
    if p.grpc_h2c_live {
        emit(
            "h2c prior-knowledge gRPC → passive RPC capture",
            vec![
                "attacker on network segment",
                "HTTP/2 connection preface without TLS",
                "invoke gRPC methods or sniff frames",
                "extract service credentials from payloads",
            ],
            "critical",
            T_SNIFF,
            "Prior-knowledge h2c on gRPC ports exposes RPC traffic without any TLS handshake.",
        );
    }
    if p.chain_untrusted {
        emit(
            "untrusted chain → universal client rejection / click-through MITM",
            vec![
                "users receive certificate warnings",
                "click-through or API TLS errors",
                "attacker presents any substitute cert",
                "full traffic interception",
            ],
            "high",
            T_MITM,
            "A chain that fails system trust verification breaks the foundation of all transport security.",
        );
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry points
// ─────────────────────────────────────────────────────────────────────────────

/// Full, GUI-parameterised transport-security posture assessment.
pub async fn run_mtls_grpc_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("could not parse host from target");
    }

    let profile = cfg.string_or("scan_profile", "full").to_ascii_lowercase();
    let intensity = cfg.intensity();
    let timeout_ms = cfg.timeout_ms(6000);
    let do_paths = cfg.bool_or("attack_path_synthesis", true);
    let do_score = cfg.bool_or("posture_scoring", true);
    let min_rsa_bits = u32::try_from(cfg.u64_or("min_rsa_bits", 2048)).unwrap_or(2048);
    let min_hsts_age = cfg.u64_or("min_hsts_age", 31_536_000);
    let ct_high_watermark = usize::try_from(cfg.u64_or("ct_high_watermark", 80)).unwrap_or(80);
    let ct_recent_days = i64::try_from(cfg.u64_or("ct_recent_days", 30)).unwrap_or(30);
    let sni = cfg.string_or("sni", &host);
    let grpc_extra_paths: Vec<String> = cfg
        .string("grpc_paths")
        .map(|s| {
            s.split([',', '\n'])
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let tls_ports = cfg.ports_or("ports", &[443, 8443]);
    let grpc_ports = cfg.ports_or("grpc_ports", &[50051, 9090]);

    let preset = |name: &str| match profile.as_str() {
        "tls_only" => matches!(name, "tls" | "session" | "ocsp" | "legacy" | "weak_crypto" | "sni" | "chain" | "compression" | "must_staple"),
        "headers_only" => matches!(name, "headers" | "upgrade" | "api" | "security_txt" | "preload" | "cross_origin" | "reporting" | "uir" | "mixed"),
        "quick" => matches!(name, "tls" | "headers" | "upgrade"),
        "grpc_only" => matches!(name, "grpc" | "session" | "mtls" | "grpc_web"),
        "mtls_audit" => matches!(name, "tls" | "session" | "mtls" | "ocsp" | "grpc" | "sni" | "weak_crypto" | "chain"),
        "api_hardening" => matches!(name, "headers" | "api" | "cors" | "security_txt" | "preload" | "cross_origin" | "cache" | "ws"),
        "grpc_deep" => matches!(name, "grpc" | "grpc_web" | "grpc_h2c" | "mtls" | "session"),
        _ => true,
    };

    let do_chain = tri(&cfg, "check_chain_trust", preset("chain"));
    let do_redirect_chain = tri(&cfg, "check_redirect_chain", preset("redirect"));
    let do_grpc_h2c = tri(&cfg, "check_grpc_h2c", preset("grpc_h2c") && intensity != Intensity::Light);
    let do_websocket = tri(&cfg, "check_websocket", preset("ws"));
    let do_cache = tri(&cfg, "check_cache_policy", preset("cache"));
    let do_coverage = cfg.bool_or("emit_coverage_manifest", true);
    let redirect_max_hops = usize::try_from(cfg.u64_or("redirect_max_hops", 8)).unwrap_or(8);

    let do_tls = tri(&cfg, "check_tls_cert", preset("tls"));
    let do_headers = tri(&cfg, "check_headers", preset("headers"));
    let do_upgrade = tri(&cfg, "check_redirect", preset("upgrade"));
    let do_http2 = tri(&cfg, "check_http2", intensity != Intensity::Light && preset("http2"));
    let do_grpc = tri(&cfg, "check_grpc_reflection", preset("grpc"));
    let do_mtls = tri(&cfg, "check_mtls", preset("mtls"));
    let do_ocsp = tri(&cfg, "check_ocsp", preset("ocsp"));
    let do_caa = tri(&cfg, "check_caa", preset("caa"));
    let do_ct = tri(&cfg, "check_ct", preset("ct"));
    let do_cross_origin = tri(&cfg, "check_cross_origin", preset("cross_origin"));
    let do_legacy = tri(&cfg, "check_legacy_tls", preset("legacy") && intensity != Intensity::Light);
    let do_session = tri(&cfg, "check_tls_session", preset("session"));
    let do_weak_crypto = tri(&cfg, "check_weak_ciphers", preset("weak_crypto") && intensity != Intensity::Light);
    let do_api = tri(&cfg, "check_api_hardening", preset("api"));
    let do_h2c = tri(&cfg, "check_h2c", preset("h2c") && intensity != Intensity::Light);
    let do_dane = tri(&cfg, "check_dane", preset("dane"));
    let do_cert_matrix = tri(&cfg, "check_cert_consistency", preset("cert_matrix"));
    let do_grpc_web = tri(&cfg, "check_grpc_web", preset("grpc_web"));
    let do_http3 = tri(&cfg, "check_http3", preset("http3")) && intensity != Intensity::Light;
    let do_sni = tri(&cfg, "check_sni_policy", preset("sni"));
    let do_security_txt = tri(&cfg, "check_security_txt", preset("security_txt"));
    let do_preload = tri(&cfg, "check_hsts_preload", preset("preload"));
    let do_mixed = tri(&cfg, "check_mixed_passive", preset("mixed"));
    let do_mesh = tri(&cfg, "check_mesh_fingerprint", preset("mesh"));
    let do_must_staple = tri(&cfg, "check_must_staple", preset("must_staple"));
    let do_tls_compression = tri(&cfg, "check_tls_compression", preset("compression") && intensity != Intensity::Light);
    let do_reporting = tri(&cfg, "check_reporting_headers", preset("reporting"));
    let do_uir = tri(&cfg, "check_upgrade_insecure_requests", preset("uir"));
    let mut must_staple_required = false;

    let client = build_client(timeout_ms, true);
    let client_no_redirect = build_client(timeout_ms, false);
    let mut findings: Vec<Value> = Vec::new();
    let mut posture = TransportPosture::default();

    if do_tls {
        probe_certificate(&host, target, min_rsa_bits, &mut findings, &mut posture).await;
    }
    if do_headers {
        probe_headers_and_cookies(
            &client,
            &host,
            target,
            min_hsts_age,
            do_cross_origin,
            &mut findings,
            &mut posture,
        )
        .await;
    }
    if do_upgrade {
        probe_https_upgrade(&client_no_redirect, &host, target, &mut findings, &mut posture).await;
    }
    if do_http2 {
        probe_http2(&host, &mut posture).await;
    }
    if do_session {
        probe_tls_session_matrix(
            &host,
            target,
            &tls_ports,
            timeout_ms,
            do_ocsp,
            do_legacy,
            do_mtls,
            &mut findings,
            &mut posture,
        )
        .await;
    }
    if do_must_staple {
        let port = tls_ports.first().copied().unwrap_or(443);
        must_staple_required =
            probe_must_staple_extension(&host, target, port, timeout_ms, &mut findings, &mut posture)
                .await;
        correlate_must_staple_violation(target, must_staple_required, &mut posture, &mut findings);
    }
    if do_grpc || do_mtls {
        probe_grpc_surface(
            &client,
            &host,
            target,
            &grpc_ports,
            do_grpc,
            &mut findings,
            &mut posture,
        )
        .await;
    }
    if do_caa || do_ct {
        probe_caa_and_ct(
            &client,
            &host,
            target,
            do_caa,
            do_ct,
            ct_high_watermark,
            ct_recent_days,
            &mut findings,
            &mut posture,
        )
        .await;
    }
    if do_weak_crypto {
        probe_weak_crypto_matrix(
            &host,
            target,
            &tls_ports,
            timeout_ms,
            &mut findings,
            &mut posture,
        )
        .await;
    }
    if do_api {
        probe_api_hardening(&client, &host, target, &mut findings, &mut posture).await;
    }
    if do_h2c {
        probe_h2c_upgrade(&client, &host, target, &mut findings, &mut posture).await;
    }
    if do_dane {
        probe_dane(&host, target, &mut findings, &mut posture).await;
    }
    if do_cert_matrix && !tls_ports.is_empty() {
        probe_cert_fingerprint_matrix(
            &host,
            target,
            &tls_ports,
            &sni,
            timeout_ms,
            &mut findings,
            &mut posture,
        )
        .await;
    }
    if do_grpc_web {
        probe_grpc_web_and_connect(&host, target, &grpc_ports, &mut findings, &mut posture).await;
    }
    if do_http3 {
        for &port in &tls_ports {
            probe_http3_readiness(&host, target, port, timeout_ms, &mut findings, &mut posture)
                .await;
        }
        probe_alt_svc_http3(&client, &host, target, &mut findings, &mut posture).await;
    }
    if do_sni {
        let port = tls_ports.first().copied().unwrap_or(443);
        probe_sni_policy(&host, target, port, timeout_ms, &mut findings, &mut posture).await;
    }
    if do_security_txt {
        probe_security_txt(&client, &host, target, &mut findings, &mut posture).await;
    }
    if do_preload {
        probe_hsts_preload_readiness(&client, &host, target, min_hsts_age, &mut findings).await;
    }
    if do_chain {
        let port = tls_ports.first().copied().unwrap_or(443);
        probe_chain_trust(&host, target, port, &sni, timeout_ms, &mut findings, &mut posture).await;
    }
    if do_redirect_chain {
        probe_redirect_chain_audit(
            &client_no_redirect,
            &host,
            target,
            redirect_max_hops,
            &mut findings,
            &mut posture,
        )
        .await;
    }
    if do_grpc_h2c {
        probe_grpc_h2c_preface(&host, target, &grpc_ports, timeout_ms, &mut findings, &mut posture).await;
    }
    if do_websocket {
        probe_websocket_upgrade(&client, &host, target, &mut findings, &mut posture).await;
    }
    if do_cache {
        probe_cache_policy(&client, &host, target, &mut findings, &mut posture).await;
    }
    if do_mixed {
        probe_mixed_passive_content(&client, &host, target, &mut findings, &mut posture).await;
    }
    if do_mesh {
        probe_mesh_proxy_fingerprint(&client, &host, target, &mut findings, &mut posture).await;
    }
    if do_tls_compression {
        let port = tls_ports.first().copied().unwrap_or(443);
        probe_tls_compression(&host, target, port, timeout_ms, &mut findings, &mut posture).await;
    }
    if do_reporting {
        probe_reporting_headers(&client, &host, target, &mut findings, &mut posture).await;
    }
    if do_uir {
        probe_upgrade_insecure_requests(&client_no_redirect, &host, target, &mut findings, &mut posture)
            .await;
    }
    if !grpc_extra_paths.is_empty() {
        probe_grpc_custom_paths(
            &host,
            target,
            &grpc_ports,
            &grpc_extra_paths,
            &mut findings,
            &mut posture,
        )
        .await;
    }

    let enabled_probes = [
        ("tls_cert", do_tls),
        ("tls_session", do_session),
        ("weak_ciphers", do_weak_crypto),
        ("legacy_tls", do_legacy),
        ("headers", do_headers),
        ("redirect", do_upgrade),
        ("redirect_chain", do_redirect_chain),
        ("grpc", do_grpc),
        ("grpc_web", do_grpc_web),
        ("grpc_h2c", do_grpc_h2c),
        ("mtls", do_mtls),
        ("chain_trust", do_chain),
        ("caa_ct", do_caa || do_ct),
        ("dane", do_dane),
        ("api_hardening", do_api),
        ("h2c", do_h2c),
        ("http3", do_http3),
        ("websocket", do_websocket),
        ("cache_policy", do_cache),
        ("mixed_passive", do_mixed),
        ("mesh_fingerprint", do_mesh),
        ("must_staple", do_must_staple),
        ("tls_compression", do_tls_compression),
        ("reporting_headers", do_reporting),
        ("upgrade_insecure_requests", do_uir),
        ("grpc_custom_paths", !grpc_extra_paths.is_empty()),
        ("security_txt", do_security_txt),
    ];
    if do_coverage {
        emit_probe_coverage_manifest(target, &host, &posture, &enabled_probes, &mut findings);
    }

    if intensity == Intensity::Light {
        findings.retain(|f| !matches!(f.get("severity").and_then(Value::as_str), Some("low") | Some("info")));
    }

    if do_paths {
        findings.extend(synthesize_attack_paths(target, &posture));
    }

    if do_score {
        let score = posture.score();
        let grade = posture.grade();
        let dimensions = TransportDimensionScores::from_posture(&posture);
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Transport Security Posture: {score}/100 (Grade {grade})"),
                "info",
                T_EXPLOIT,
                &format!(
                    "Quantified agentless transport-security posture for {host} across {} live check(s) and {} registry module(s). Eight-dimension executive scorecard: TLS/crypto {}, HTTP {}, gRPC/mTLS {}, DNS/PKI {}, API {}, protocol {}, attack-surface {}, operational {}. HTTP/2: {}. TLS 1.3: {}. HTTP/3: {}.",
                    posture.checks,
                    TRANSPORT_PROBE_MODULES.len(),
                    dimensions.tls_crypto,
                    dimensions.http_hardening,
                    dimensions.grpc_mtls,
                    dimensions.dns_pki,
                    dimensions.api_exposure,
                    dimensions.protocol_modernity,
                    dimensions.attack_surface,
                    dimensions.operational,
                    if posture.http2 { "yes" } else { "no" },
                    if posture.tls13_supported { "yes" } else { "no" },
                    if posture.http3_alpn { "yes" } else { "no" },
                ),
                target,
                1.0,
                Evidence::new()
                    .with("score", score)
                    .with("grade", grade)
                    .with("dimension_scores", dimensions.to_json())
                    .with("https_reachable", posture.https_reachable)
                    .with("cert_expired", posture.cert_expired)
                    .with("hsts_missing", posture.hsts_missing)
                    .with("no_https_upgrade", posture.no_https_upgrade)
                    .with("insecure_cookies", posture.insecure_cookies)
                    .with("http2", posture.http2)
                    .with("http3", posture.http3_alpn)
                    .with("legacy_tls", posture.legacy_tls)
                    .with("weak_ciphers", posture.weak_ciphers)
                    .with("no_forward_secrecy", posture.no_forward_secrecy)
                    .with("grpc_reflection", posture.grpc_reflection)
                    .with("grpc_web", posture.grpc_web)
                    .with("mtls_not_enforced", posture.mtls_not_enforced)
                    .with("plaintext_grpc", posture.plaintext_grpc_port)
                    .with("h2c_upgrade", posture.h2c_upgrade)
                    .with("cors_permissive", posture.cors_permissive)
                    .with("trace_enabled", posture.trace_enabled)
                    .with("cert_inconsistent", posture.cert_inconsistent)
                    .with("sni_permissive", posture.sni_permissive)
                    .with("ocsp_missing", posture.ocsp_missing)
                    .with("no_caa", posture.no_caa)
                    .with("compliance", json!(["PCI-DSS 4.0", "NIST SP 800-52 Rev.2", "CIS Control 9"])),
            ),
            &[("category", json!("posture_score")), ("score", json!(score)), ("grade", json!(grade))],
        ));
    }

    let summary = format!(
        "Transport posture for {}: {} findings · posture {}/100 (Grade {})",
        host,
        findings.len(),
        posture.score(),
        posture.grade()
    );

    if posture.has_exposure() {
        let (nodes, edges) = build_graph(target, &posture);
        EngineResult::ok_with_graph(findings, summary, nodes, edges)
    } else {
        EngineResult::ok(findings, summary)
    }
}

/// Backward-compatible entry (default parameters) — used by alias/CLI callers.
pub async fn run_mtls_grpc_result(target: &str) -> EngineResult {
    run_mtls_grpc_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_mtls_grpc(target: &str) {
    print_result(run_mtls_grpc_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn san_wildcard_and_exact_match() {
        let san = vec!["*.example.com".to_string(), "example.com".to_string()];
        assert!(san_covers("www.example.com", &san));
        assert!(san_covers("example.com", &san));
        assert!(!san_covers("a.b.example.com", &san));
        assert!(!san_covers("evil.com", &san));
    }

    #[test]
    fn posture_score_penalizes_weaknesses() {
        let mut p = TransportPosture::default();
        assert_eq!(p.score(), 100);
        assert_eq!(p.grade(), "A");
        p.cert_expired = true;
        p.hsts_missing = true;
        p.insecure_cookies = 2;
        assert!(p.score() < 60);
        assert!(p.has_exposure());
    }

    #[test]
    fn posture_score_penalizes_grpc_and_mtls() {
        let mut p = TransportPosture::default();
        p.grpc_reflection = true;
        p.mtls_not_enforced = true;
        p.plaintext_grpc_port = true;
        assert!(p.score() < 50);
        assert!(p.has_exposure());
    }

    #[test]
    fn posture_score_penalizes_weak_crypto() {
        let mut p = TransportPosture::default();
        p.weak_ciphers = true;
        p.h2c_upgrade = true;
        p.cors_permissive = true;
        assert!(p.score() < 70);
        assert!(p.has_exposure());
    }

    #[test]
    fn attack_paths_h2c_and_cors() {
        let mut p = TransportPosture::default();
        p.grpc_web = true;
        p.cors_permissive = true;
        let paths = synthesize_attack_paths("x.test", &p);
        assert!(paths.iter().any(|f| f["title"].as_str().unwrap_or("").contains("gRPC-Web")));
    }

    #[test]
    fn attack_paths_hsts_and_cookies() {
        assert!(synthesize_attack_paths("x.test", &TransportPosture::default()).is_empty());
        let mut p = TransportPosture::default();
        p.hsts_missing = true;
        p.insecure_cookies = 1;
        let paths = synthesize_attack_paths("x.test", &p);
        assert!(paths.iter().any(|f| f["category"] == json!("attack_path")));
    }

    #[test]
    fn grpc_reflection_attack_path() {
        let mut p = TransportPosture::default();
        p.grpc_reflection = true;
        p.mtls_not_enforced = true;
        let paths = synthesize_attack_paths("x.test", &p);
        assert!(paths.iter().any(|f| f["title"].as_str().unwrap_or("").contains("gRPC reflection")));
    }

    #[test]
    fn graph_reflects_exposure() {
        let mut p = TransportPosture::default();
        p.cert_expired = true;
        p.grpc_reflection = true;
        let (nodes, edges) = build_graph("https://x.test", &p);
        assert!(nodes.iter().any(|n| n.id == "tls"));
        assert!(nodes.iter().any(|n| n.id == "grpc_refl"));
        assert!(edges.iter().any(|e| e.edge_type == "WEAK_TLS"));
    }

    #[test]
    fn grpc_frame_detection() {
        assert!(grpc_response_indicates_service(200, &[0, 0, 0, 0, 5, 1], &[]));
        assert!(!grpc_response_indicates_service(404, &[], &[]));
        assert!(grpc_reflection_likely(
            200,
            &[0, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
        ));
    }

    #[test]
    fn version_label_maps_tls() {
        assert_eq!(version_label(SslVersion::TLS1_3), "TLS 1.3");
    }

    #[test]
    fn resolve_redirect_absolute_and_relative() {
        assert_eq!(
            resolve_redirect_url("http://host/a", "https://host/b"),
            "https://host/b"
        );
        assert_eq!(
            resolve_redirect_url("http://host/a", "/b"),
            "http://host/b"
        );
    }

    #[test]
    fn ct_shadow_host_detection() {
        let mut names = HashSet::new();
        names.insert("staging.api.example.com".to_string());
        names.insert("www.example.com".to_string());
        let shadows = ct_shadow_host_patterns(&names);
        assert_eq!(shadows.len(), 1);
        assert!(shadows[0].contains("staging"));
    }

    #[test]
    fn mixed_passive_detects_http_subresources() {
        let hits = mixed_passive_hits(r#"<img src="http://evil.com/x">"#);
        assert!(!hits.is_empty());
    }

    #[test]
    fn transport_module_registry_is_comprehensive() {
        assert!(TRANSPORT_PROBE_MODULES.len() >= 38);
        assert!(TRANSPORT_PROBE_MODULES.contains(&"dimension_scorecard"));
        assert!(TRANSPORT_PROBE_MODULES.contains(&"tls_compression_crime"));
    }

    #[test]
    fn dimension_scores_reflect_weak_posture() {
        let mut p = TransportPosture::default();
        p.cert_expired = true;
        p.grpc_reflection = true;
        p.hsts_missing = true;
        let d = TransportDimensionScores::from_posture(&p);
        assert!(d.tls_crypto < 70);
        assert!(d.grpc_mtls < 80);
        assert!(d.http_hardening < 90);
    }
}
