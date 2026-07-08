//! Shared real-probe primitives for the `advanced_*` engine families.
//!
//! Every helper performs **live** network/HTTP/DNS/TCP/TLS operations against the user-supplied
//! target. No simulated findings are emitted: if the probe doesn't observe an actual signal, no
//! finding is returned. All probes respect `weissman_core::tls_policy::danger_accept_invalid_certs()`
//! and bounded timeouts so an engine cannot hang the worker pool.

use crate::engine_result::EngineResult;
use futures::stream::{self, StreamExt};
use regex::Regex;
use reqwest::Client;
use serde_json::{json, Value};
use std::net::ToSocketAddrs;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;
const TCP_CONNECT_TIMEOUT_MS: u64 = 1500;
const TCP_BANNER_READ_MS: u64 = 1500;

#[must_use]
pub fn normalize_url(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

#[must_use]
pub fn extract_host(target: &str) -> String {
    target
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target)
        .split(':')
        .next()
        .unwrap_or(target)
        .to_string()
}

static HTTP_CLIENT: OnceLock<Client> = OnceLock::new();
static HTTP1_CLIENT: OnceLock<Client> = OnceLock::new();
static HTTP2_CLIENT: OnceLock<Client> = OnceLock::new();

fn shared_client_builder(user_agent: &str) -> reqwest::ClientBuilder {
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
        .pool_max_idle_per_host(16)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent(user_agent)
}

fn init_http_client() -> Client {
    shared_client_builder("Weissman-Probe/1.0")
        .build()
        .unwrap_or_else(|_| Client::new())
}

fn init_http1_client() -> Client {
    shared_client_builder("Weissman-LiminalProbe/1.0 h1")
        .http1_only()
        .build()
        .unwrap_or_else(|_| Client::new())
}

fn init_http2_client() -> Client {
    shared_client_builder("Weissman-LiminalProbe/1.0 h2")
        .http2_adaptive_window(true)
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// Shared pooled HTTP client — reused across all engine probes (connection pooling).
pub async fn http_client() -> Client {
    HTTP_CLIENT.get_or_init(init_http_client).clone()
}

/// HTTP/1.1-only client — used to compare against HTTP/2 ALPN on the same URL.
pub async fn http1_client() -> Client {
    HTTP1_CLIENT.get_or_init(init_http1_client).clone()
}

/// HTTP/2-capable client (ALPN negotiates h2 on TLS). Pair with [`http1_client`].
pub async fn http2_client() -> Client {
    HTTP2_CLIENT.get_or_init(init_http2_client).clone()
}

/// Attempt a TCP connect+banner read. Returns banner string if the port is open.
pub async fn tcp_banner(host: &str, port: u16) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let socket = match timeout(
        Duration::from_millis(TCP_CONNECT_TIMEOUT_MS),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let mut stream = socket;
    let mut buf = vec![0u8; 256];
    match timeout(
        Duration::from_millis(TCP_BANNER_READ_MS),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
        _ => Some(String::new()),
    }
}

/// Connect-only TCP test. Returns true if port is reachable within timeout.
pub async fn tcp_open(host: &str, port: u16) -> bool {
    let addr = format!("{}:{}", host, port);
    matches!(
        timeout(
            Duration::from_millis(TCP_CONNECT_TIMEOUT_MS),
            TcpStream::connect(&addr),
        )
        .await,
        Ok(Ok(_))
    )
}

/// Send a binary payload to a TCP port and read response (for protocol fingerprinting).
pub async fn tcp_probe_response(host: &str, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let addr = format!("{}:{}", host, port);
    let socket = match timeout(
        Duration::from_millis(TCP_CONNECT_TIMEOUT_MS),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let mut stream = socket;
    if stream.write_all(payload).await.is_err() {
        return None;
    }
    let _ = stream.flush().await;
    let mut buf = vec![0u8; 1024];
    match timeout(
        Duration::from_millis(TCP_BANNER_READ_MS),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Resolve host → list of IPs (IPv4+IPv6). Returns empty on failure.
pub fn resolve_ips(host: &str) -> Vec<String> {
    format!("{}:80", host)
        .to_socket_addrs()
        .map(|iter| iter.map(|s| s.ip().to_string()).collect())
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
pub struct HttpProbe {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub final_url: String,
}

/// GET with optional extra headers (for cache-oracle / rewrite probes).
pub async fn http_get_with_headers(
    client: &Client,
    url: &str,
    extra: &[(&str, &str)],
) -> Option<HttpProbe> {
    crate::fleet_shaping::acquire_for_url(url).await;
    let started = std::time::Instant::now();
    let mut req = client.get(url);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(_) => {
            crate::fleet_shaping::report_outcome(
                url,
                0,
                Some(started.elapsed().as_millis() as u64),
                false,
            );
            return None;
        }
    };
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 65_536 {
        body[..65_536].to_string()
    } else {
        body
    };
    crate::fleet_shaping::report_outcome(
        url,
        status,
        Some(started.elapsed().as_millis() as u64),
        false,
    );
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

/// Fetch URL and return status, headers, body (truncated to 64 KiB).
pub async fn http_get(client: &Client, url: &str) -> Option<HttpProbe> {
    http_get_with_headers(client, url, &[]).await
}

/// POST JSON with optional extra headers (e.g. Authorization probes).
pub async fn http_post_json_with_headers(
    client: &Client,
    url: &str,
    payload: &Value,
    extra: &[(&str, &str)],
) -> Option<HttpProbe> {
    crate::fleet_shaping::acquire_for_url(url).await;
    let started = std::time::Instant::now();
    let mut req = client.post(url).json(payload);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(_) => {
            crate::fleet_shaping::report_outcome(
                url,
                0,
                Some(started.elapsed().as_millis() as u64),
                false,
            );
            return None;
        }
    };
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 65_536 {
        body[..65_536].to_string()
    } else {
        body
    };
    crate::fleet_shaping::report_outcome(
        url,
        status,
        Some(started.elapsed().as_millis() as u64),
        false,
    );
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

/// POST JSON and return status + body (truncated).
pub async fn http_post_json(client: &Client, url: &str, payload: &Value) -> Option<HttpProbe> {
    http_post_json_with_headers(client, url, payload, &[]).await
}

/// POST raw bytes with optional extra headers (gRPC frames, protobuf payloads, etc.).
pub async fn http_post_bytes_with_headers(
    client: &Client,
    url: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> Option<HttpProbe> {
    let mut req = client.post(url).body(body.to_vec());
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let raw = resp.bytes().await.unwrap_or_default();
    let truncated = if raw.len() > 65_536 {
        &raw[..65_536]
    } else {
        &raw
    };
    let body = String::from_utf8_lossy(truncated).into_owned();
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

/// Arbitrary HTTP method with optional body and headers.
pub async fn http_method_with_headers(
    client: &Client,
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    extra: &[(&str, &str)],
) -> Option<HttpProbe> {
    let m = reqwest::Method::from_bytes(method.as_bytes()).ok()?;
    let mut req = client.request(m, url);
    if let Some(b) = body {
        req = req.body(b.to_vec());
    }
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let raw = resp.bytes().await.unwrap_or_default();
    let truncated = if raw.len() > 65_536 {
        &raw[..65_536]
    } else {
        &raw
    };
    let body = String::from_utf8_lossy(truncated).into_owned();
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

pub fn has_header(headers: &[(String, String)], name: &str) -> bool {
    let ln = name.to_ascii_lowercase();
    headers.iter().any(|(k, _)| k.to_ascii_lowercase() == ln)
}

pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let ln = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == ln)
        .map(|(_, v)| v.as_str())
}

/// DNS TXT record lookup using hickory-resolver.
pub async fn dns_txt(host: &str) -> Vec<String> {
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    if let Ok(txt) = resolver.txt_lookup(host).await {
        for record in txt.answers() {
            let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data else {
                continue;
            };
            let mut joined = String::new();
            for chunk in txt.txt_data.iter() {
                joined.push_str(&String::from_utf8_lossy(chunk));
            }
            out.push(joined);
        }
    }
    out
}

pub async fn dns_mx(host: &str) -> Vec<String> {
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    if let Ok(mx) = resolver.mx_lookup(host).await {
        for record in mx.answers() {
            let hickory_resolver::proto::rr::RData::MX(mx) = &record.data else {
                continue;
            };
            out.push(mx.exchange.to_string());
        }
    }
    out
}

pub async fn dns_a(host: &str) -> Vec<String> {
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    if let Ok(a) = resolver.ipv4_lookup(host).await {
        for record in a.answers() {
            let hickory_resolver::proto::rr::RData::A(a) = &record.data else {
                continue;
            };
            out.push(a.0.to_string());
        }
    }
    out
}

/// Minimum TTL (seconds) among A records for `host`, if any.
pub async fn dns_a_min_ttl(host: &str) -> Option<u32> {
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return None,
    };
    let lookup = resolver.ipv4_lookup(host).await.ok()?;
    lookup.answers().iter().map(|r| r.ttl).min()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCertSummary {
    pub issuer: String,
    pub subject: String,
    pub self_signed: bool,
    pub expired: bool,
}

/// Extended TLS certificate fields for crypto/PQC posture probes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCertDetails {
    pub issuer: String,
    pub subject: String,
    pub self_signed: bool,
    pub expired: bool,
    pub days_until_expiry: i64,
    pub public_key_bits: u32,
    pub signature_algorithm: String,
    pub is_rsa: bool,
    pub is_ec: bool,
    pub san_dns_names: Vec<String>,
}

/// Fetch the peer TLS certificate issuer/subject for HTTPS on port 443.
pub async fn tls_cert_summary(host: &str) -> Option<TlsCertSummary> {
    tls_cert_details(host).await.map(|d| TlsCertSummary {
        issuer: d.issuer,
        subject: d.subject,
        self_signed: d.self_signed,
        expired: d.expired,
    })
}

/// Fetch extended TLS certificate metadata for HTTPS on port 443.
pub async fn tls_cert_details(host: &str) -> Option<TlsCertDetails> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || tls_cert_details_blocking(&host))
        .await
        .ok()
        .flatten()
}

fn tls_cert_details_blocking(host: &str) -> Option<TlsCertDetails> {
    use openssl::ssl::{SslConnector, SslMethod};
    use std::net::TcpStream;
    let connector = SslConnector::builder(SslMethod::tls()).ok()?.build();
    let stream = TcpStream::connect(format!("{host}:443")).ok()?;
    let stream = connector.connect(host, stream).ok()?;
    let cert = stream.ssl().peer_certificate()?;
    Some(parse_cert_details(&cert))
}

fn parse_cert_details(cert: &openssl::x509::X509) -> TlsCertDetails {
    let fmt_dn_entry = |e: &openssl::x509::X509NameEntryRef| -> String {
        let key = e.object().nid().short_name().unwrap_or("?");
        let val = match e.data().as_utf8() {
            Ok(s) => s.to_string(),
            Err(_) => "?".to_string(),
        };
        format!("{key}={val}")
    };
    let issuer = cert
        .issuer_name()
        .entries()
        .map(fmt_dn_entry)
        .collect::<Vec<_>>()
        .join(", ");
    let subject = cert
        .subject_name()
        .entries()
        .map(fmt_dn_entry)
        .collect::<Vec<_>>()
        .join(", ");
    let self_signed = issuer == subject;
    let not_after = cert.not_after().to_owned();
    let now = openssl::asn1::Asn1Time::days_from_now(0).ok();
    let expired = now.as_ref().is_some_and(|n| not_after <= *n);
    let days_until_expiry = now
        .as_ref()
        .and_then(|n| not_after.diff(n.as_ref()).ok())
        .map(|diff| i64::from(diff.days))
        .unwrap_or(0);
    let pkey = cert.public_key().ok();
    let public_key_bits = pkey.as_ref().map(|k| k.bits()).unwrap_or(0);
    let signature_algorithm = cert
        .signature_algorithm()
        .object()
        .nid()
        .short_name()
        .unwrap_or("unknown")
        .to_string();
    let is_rsa = pkey.as_ref().is_some_and(|k| k.rsa().is_ok());
    let is_ec = pkey.as_ref().is_some_and(|k| k.ec_key().is_ok());
    let mut san_dns_names = Vec::new();
    if let Some(alt_names) = cert.subject_alt_names() {
        for name in alt_names {
            if let Some(dns) = name.dnsname() {
                san_dns_names.push(dns.to_string());
            }
        }
    }
    TlsCertDetails {
        issuer,
        subject,
        self_signed,
        expired,
        days_until_expiry,
        public_key_bits,
        signature_algorithm,
        is_rsa,
        is_ec,
        san_dns_names,
    }
}

/// UDP send/receive with bounded timeout (SNMP, NTP, etc.).
pub async fn udp_probe_response(host: &str, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    use tokio::net::UdpSocket;
    let local = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let remote = format!("{}:{}", host, port);
    local.connect(&remote).await.ok()?;
    local.send(payload).await.ok()?;
    let mut buf = vec![0u8; 1024];
    match timeout(
        Duration::from_millis(TCP_BANNER_READ_MS),
        local.recv(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => Some(buf[..n].to_vec()),
        _ => None,
    }
}

pub async fn dns_caa(host: &str) -> Vec<String> {
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    if let Ok(caa) = resolver.lookup(host, RecordType::CAA).await {
        for record in caa.answers() {
            let hickory_resolver::proto::rr::RData::CAA(caa) = &record.data else {
                continue;
            };
            out.push(format!(
                "{}={}",
                caa.tag,
                String::from_utf8_lossy(&caa.value)
            ));
        }
    }
    out
}

/// RFC 6698 TLSA records for DANE (e.g. `_443._tcp.example.com`).
pub async fn dns_tlsa(name: &str) -> Vec<String> {
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    if let Ok(tlsa) = resolver.lookup(name, RecordType::TLSA).await {
        for record in tlsa.answers() {
            let hickory_resolver::proto::rr::RData::TLSA(t) = &record.data else {
                continue;
            };
            out.push(t.to_string());
        }
    }
    out
}

/// True when a foreign Host header yields a successful response (rebinding surface).
#[must_use]
pub fn host_header_rebinding_signal(
    baseline_status: u16,
    foreign_status: u16,
    foreign_body_len: usize,
) -> bool {
    foreign_status >= 200
        && foreign_status < 400
        && foreign_body_len > 32
        && (baseline_status >= 400 || foreign_status != baseline_status)
}

/// Whether speculative *advisory* findings (suggested-test / risk-scenario rows that are not backed
/// by an observed vulnerability signal) should be emitted. Off by default so a scan surfaces only
/// evidence-backed findings; operators who want the speculative coaching set
/// `WEISSMAN_ADVISORY_FINDINGS=1`.
pub fn advisory_findings_enabled() -> bool {
    std::env::var("WEISSMAN_ADVISORY_FINDINGS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

/// Convenience: build a result with optional empty findings (no simulated content).
pub fn empty_ok(engine_id: &str, target: &str) -> EngineResult {
    EngineResult::ok(
        vec![],
        format!("{}: no live signal observed on {}", engine_id, target),
    )
}

/// Build a result for engines that cannot be detected from a remote network probe alone
/// (process injection, kernel rootkits, air-gap exfil channels, physical attacks, etc.).
///
/// We emit a single *info* finding explaining the limitation and pointing the operator to the
/// agent-based collector. This is honest: no fake high-severity findings, but the engine isn't
/// silently empty either.
pub fn agent_required_ok(
    engine_id: &str,
    target: &str,
    title: &str,
    rationale: &str,
) -> EngineResult {
    let finding = serde_json::json!({
        "type": engine_id,
        "category": "agent_required",
        "title": title,
        "severity": "info",
        "mitre_attack": "",
        "description": format!(
            "{} requires an endpoint agent to detect (no purely-remote signal exists). {} Install Weissman-Agent on the asset, then re-run the engine.",
            engine_id, rationale
        ),
        "target": target,
        "agent_required": true,
    });
    EngineResult::ok(
        vec![finding],
        format!("{}: agent-based collector required", engine_id),
    )
}

/// Convenience: severity selector based on observed condition.
#[must_use]
pub fn severity_for(strong: bool) -> &'static str {
    if strong {
        "high"
    } else {
        "medium"
    }
}

/// Build a structured finding. `remediation` is inferred from severity + engine class so every
/// finding has actionable guidance attached.
pub fn finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> Value {
    json!({
        "type": engine_id,
        "title": title,
        "severity": severity,
        "mitre_attack": mitre,
        "description": description,
        "target": target,
        "remediation": default_remediation(engine_id, severity),
        "compliance": default_compliance(engine_id),
    })
}

/// Structured finding with an extra `probe_depth` metadata field.
pub fn finding_with_probe_depth(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    probe_depth: &str,
) -> Value {
    let mut f = finding(engine_id, title, severity, mitre, description, target);
    if let Some(obj) = f.as_object_mut() {
        obj.insert("probe_depth".to_string(), json!(probe_depth));
    }
    f
}

/// Lookup-table for a default remediation hint. The orchestrator can override per-finding when
/// it has more context; this guarantees no finding is shipped *without* guidance.
#[must_use]
pub fn default_remediation(engine_id: &str, severity: &str) -> &'static str {
    let sev = severity.to_ascii_lowercase();
    if engine_id.contains("ssrf") {
        return "Block outbound requests to 169.254.169.254 / metadata.google.internal at the egress firewall and on the application server. Validate URL inputs with an allow-list of approved hosts.";
    }
    if engine_id.contains("graphql") {
        return "Disable introspection in production (`graphql.config.introspection = false`), enable depth + complexity limits, and require authentication on the /graphql endpoint.";
    }
    if engine_id.contains("jwt") {
        return "Pin the JWT signing algorithm (reject 'none' and weak HMAC keys), rotate the signing key, enforce short token lifetime, and validate aud/iss claims server-side.";
    }
    if engine_id.contains("cors") {
        return "Replace `Access-Control-Allow-Origin: *` with an allow-list of trusted origins. Never combine `*` or `null` with `Access-Control-Allow-Credentials: true`.";
    }
    if engine_id.contains("liminal_boundary") {
        return "Unify WAF/auth rules across HTTP/1.1 and HTTP/2 (ALPN) paths; add correct Vary headers for every cache-key dimension (Cookie, Accept-Language); strip or validate X-Original-URL / X-Rewrite-URL at the edge; disable trusted-header routing unless explicitly required.";
    }
    if engine_id.contains("xss")
        || engine_id.contains("css_injection")
        || engine_id.contains("template_injection")
    {
        return "Adopt a strict Content-Security-Policy: `default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none';`. HTML-escape all dynamic content.";
    }
    if engine_id.contains("clickjacking") {
        return "Send `X-Frame-Options: DENY` (or `SAMEORIGIN`) and the CSP directive `frame-ancestors 'self'`. Verify with `securityheaders.com`.";
    }
    if engine_id.contains("subdomain_takeover") {
        return "Remove the dangling DNS record (CNAME or A) pointing at the unclaimed third-party service, or re-register the resource on the upstream provider.";
    }
    if engine_id.contains("s3") || engine_id.contains("cloud_data_exfil") {
        return "Block public ACLs at the AWS account level (`BlockPublicAccess`), set bucket policy to private, and enable S3 Object Ownership = BucketOwnerEnforced.";
    }
    if engine_id.contains("scada")
        || engine_id.contains("modbus")
        || engine_id.contains("plc")
        || engine_id.contains("opcua")
    {
        return "OT protocols (Modbus, DNP3, OPC-UA, IEC 61850) must never be reachable from the internet. Isolate inside the OT VLAN, place a Purdue-Level 3.5 firewall, and require VPN + MFA for engineering access.";
    }
    if engine_id.contains("mfa") {
        return "Enforce MFA for all privileged accounts. Block fallback to SMS one-time codes; prefer phishing-resistant factors (WebAuthn / FIDO2).";
    }
    if engine_id.contains("password") {
        return "Disable password reuse, enforce zxcvbn ≥ 3 strength, require MFA, monitor for credential-stuffing patterns and rotate any leaked secrets.";
    }
    if engine_id.contains("supply_chain")
        || engine_id.contains("npm_package")
        || engine_id.contains("pypi")
        || engine_id.contains("docker_image_poison")
    {
        return "Lock dependencies (lockfiles + hash verification), enable Sigstore / cosign signature verification, and scan via OSV / pip-audit / npm audit on every build.";
    }
    if engine_id.contains("pki") || engine_id.contains("tls") {
        return "Issue certificates with at least 2048-bit RSA / 256-bit ECC, enable HSTS with `max-age=31536000; includeSubDomains; preload`, and disable TLS 1.0 / 1.1.";
    }
    match sev.as_str() {
        "critical" => "Treat as P0: take affected resource offline if exposure is confirmed, rotate credentials/keys, deploy patched configuration, and run a confirmation scan.",
        "high" => "Schedule a fix within 7 days. Apply vendor patch or harden configuration; add detection rule for further exploitation attempts.",
        "medium" => "Plan a fix within the current sprint (≤30 days). Document the risk in your asset register.",
        "low" => "Track as backlog. Re-evaluate when surrounding controls change.",
        _ => "Investigate the observation and validate whether it represents real risk in your environment.",
    }
}

/// Standard compliance-framework tags so the UI can group findings by GDPR / SOC2 / NIS2 etc.
#[must_use]
pub fn default_compliance(engine_id: &str) -> Vec<&'static str> {
    let mut tags: Vec<&'static str> = Vec::new();
    if engine_id.contains("password")
        || engine_id.contains("mfa")
        || engine_id.contains("session")
        || engine_id.contains("kerberos")
    {
        tags.extend_from_slice(&["ISO27001:A.9", "SOC2:CC6.1", "NIS2:Art.21(2)(i)"]);
    }
    if engine_id.contains("tls") || engine_id.contains("crypto") || engine_id.contains("pqc") {
        tags.extend_from_slice(&["ISO27001:A.10", "SOC2:CC6.7", "PCI:4.1"]);
    }
    if engine_id.contains("scada")
        || engine_id.contains("ot")
        || engine_id.contains("modbus")
        || engine_id.contains("plc")
    {
        tags.extend_from_slice(&["NIS2:Art.21(2)(h)", "IEC62443"]);
    }
    if engine_id.contains("cloud")
        || engine_id.contains("aws")
        || engine_id.contains("azure")
        || engine_id.contains("gcp")
    {
        tags.extend_from_slice(&["SOC2:CC6.6", "CSA-CCM:DCS-04"]);
    }
    if engine_id.contains("supply_chain") || engine_id.contains("sbom") {
        tags.extend_from_slice(&["NIS2:Art.21(2)(d)", "SOC2:CC7.1"]);
    }
    if engine_id.contains("gdpr") || engine_id.contains("personal") || engine_id.contains("pii") {
        tags.push("GDPR:Art.32");
    }
    if tags.is_empty() {
        tags.push("ISO27001:A.12");
    }
    tags
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared real-probe primitives (batch foundation): retry/backoff, bounded-
// concurrency path + port scanning, product/version fingerprinting, and token
// matching. Every helper is live network I/O — no simulated data. These exist so
// every `advanced_*` engine can do genuine, evidence-bearing probing instead of a
// single GET + substring check, and so a transient network failure is retried
// rather than silently collapsing into "0 findings".
// ─────────────────────────────────────────────────────────────────────────────

/// Default bounded concurrency for fan-out path/port probing.
pub const DEFAULT_PROBE_CONCURRENCY: usize = 12;

/// `http_get` with bounded retry + linear backoff. A `None` from `http_get`
/// means the request itself failed (DNS / connect / timeout / TLS), so we retry;
/// a real HTTP response (even 4xx/5xx) is returned immediately on the first try.
pub async fn http_get_retry(client: &Client, url: &str, attempts: u8) -> Option<HttpProbe> {
    let tries = attempts.max(1);
    for i in 0..tries {
        if let Some(p) = http_get(client, url).await {
            return Some(p);
        }
        if i + 1 < tries {
            tokio::time::sleep(Duration::from_millis(180 * u64::from(i + 1))).await;
        }
    }
    None
}

/// Join a base URL and a path into an absolute URL. If `path` is already
/// absolute (`http://` / `https://`) it is returned unchanged.
#[must_use]
pub fn join_url(base: &str, path: &str) -> String {
    let p = path.trim();
    if p.starts_with("http://") || p.starts_with("https://") {
        return p.to_string();
    }
    let b = base.trim_end_matches('/');
    if p.is_empty() || p == "/" {
        b.to_string()
    } else {
        format!("{}/{}", b, p.trim_start_matches('/'))
    }
}

/// Probe many paths under `base` concurrently (bounded). Returns the live
/// [`HttpProbe`] for every request that produced a response. Failed requests are
/// dropped (already retried at the call site if desired).
pub async fn probe_paths_concurrent(
    client: &Client,
    base: &str,
    paths: &[&str],
    concurrency: usize,
) -> Vec<HttpProbe> {
    let urls: Vec<String> = paths.iter().map(|p| join_url(base, p)).collect();
    stream::iter(urls)
        .map(|u| {
            let c = client.clone();
            async move { http_get(&c, &u).await }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await
}

/// TCP-connect scan of `ports` on `host`, bounded concurrency. Returns the
/// subset of ports that accepted a connection within the timeout.
pub async fn tcp_scan(host: &str, ports: &[u16], concurrency: usize) -> Vec<u16> {
    let host = host.to_string();
    let mut open: Vec<u16> = stream::iter(ports.iter().copied())
        .map(|port| {
            let h = host.clone();
            async move {
                if tcp_open(&h, port).await {
                    Some(port)
                } else {
                    None
                }
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;
    open.sort_unstable();
    open
}

/// Lower-cased, newline-joined view of a probe's headers (for token matching).
#[must_use]
pub fn headers_blob_lower(probe: &HttpProbe) -> String {
    probe
        .headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase()
}

/// Return the first `tokens` entry that appears (case-insensitive) in the
/// probe's body or headers. Used to *confirm a product/technology* from a real
/// response before emitting a finding (turns path-spray into evidence-based
/// detection).
#[must_use]
pub fn probe_matched_token(probe: &HttpProbe, tokens: &[&str]) -> Option<String> {
    let body = probe.body.to_ascii_lowercase();
    let headers = headers_blob_lower(probe);
    tokens
        .iter()
        .find(|t| {
            let n = t.to_ascii_lowercase();
            !n.is_empty() && (body.contains(&n) || headers.contains(&n))
        })
        .map(|t| (*t).to_string())
}

/// True when an HTTP status indicates the path *exists / is gated* (worth
/// reporting as exposed surface) rather than a hard 404/410.
#[must_use]
pub fn status_indicates_presence(status: u16) -> bool {
    matches!(
        status,
        200 | 201 | 204 | 301 | 302 | 307 | 308 | 401 | 403 | 405 | 500
    )
}

/// A product/version observation parsed from a real HTTP response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackFingerprint {
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub via: Option<String>,
    pub generator: Option<String>,
    /// `(product, version)` pairs parsed from `Server` / `X-Powered-By` tokens.
    pub products: Vec<(String, String)>,
}

/// Extract a server/framework fingerprint from a real response. Parses
/// `Server`, `X-Powered-By`, `Via`, and an HTML `<meta name="generator">` tag,
/// then splits `product/version` tokens (e.g. `nginx/1.18.0`, `PHP/7.4.3`).
#[must_use]
pub fn fingerprint_stack(probe: &HttpProbe) -> StackFingerprint {
    let mut fp = StackFingerprint {
        server: header_value(&probe.headers, "server").map(str::to_string),
        powered_by: header_value(&probe.headers, "x-powered-by").map(str::to_string),
        via: header_value(&probe.headers, "via").map(str::to_string),
        ..StackFingerprint::default()
    };
    if let Some(idx) = probe.body.to_ascii_lowercase().find("name=\"generator\"") {
        let tail = &probe.body[idx..];
        if let Some(cstart) = tail.to_ascii_lowercase().find("content=\"") {
            let rest = &tail[cstart + "content=\"".len()..];
            if let Some(end) = rest.find('"') {
                fp.generator = Some(rest[..end].trim().to_string());
            }
        }
    }
    for raw in [fp.server.clone(), fp.powered_by.clone(), fp.via.clone()]
        .into_iter()
        .flatten()
    {
        for token in raw.split([' ', ',', ';']) {
            if let Some((prod, ver)) = token.split_once('/') {
                let prod = prod.trim();
                let ver = ver.trim();
                if !prod.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    fp.products.push((prod.to_string(), ver.to_string()));
                }
            }
        }
    }
    fp
}

/// High-precision secret detector shared across cloud / leak / supply-chain engines.
/// Returns the list of secret *types* whose pattern matched the text (deduped).
/// Pattern-based (not `contains("=")`), so it does not fire on ordinary HTML.
pub fn detect_secrets(text: &str) -> Vec<&'static str> {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        let raw: &[(&str, &str)] = &[
            ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
            ("AWS Secret Access Key", r#"(?i)aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+]{40}"#),
            ("Google API Key", r"AIza[0-9A-Za-z_\-]{35}"),
            ("Google OAuth Token", r"ya29\.[0-9A-Za-z_\-]{20,}"),
            ("Slack Token", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
            ("GitHub Token", r"gh[pousr]_[0-9A-Za-z]{36,}"),
            ("GitLab Token", r"glpat-[0-9A-Za-z_\-]{20,}"),
            ("Stripe Live Key", r"sk_live_[0-9A-Za-z]{24,}"),
            ("Twilio Key", r"SK[0-9a-fA-F]{32}"),
            ("Private Key Block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
            ("JSON Web Token", r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
            ("DB Connection URI with credentials", r"(?i)(postgres|postgresql|mysql|mongodb)(\+srv)?://[^:\s/]+:[^@\s]+@"),
            (
                "Credential assignment",
                r#"(?i)(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|password|passwd)\s*[=:]\s*['"][^'"\s]{8,}['"]"#,
            ),
        ];
        raw.iter()
            .filter_map(|(name, pat)| Regex::new(pat).ok().map(|re| (*name, re)))
            .collect()
    });
    let mut out: Vec<&'static str> = patterns
        .iter()
        .filter(|(_, re)| re.is_match(text))
        .map(|(name, _)| *name)
        .collect();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_secrets_finds_real_keys_not_html() {
        assert!(detect_secrets("<html>a = b; total == 3</html>").is_empty());
        assert!(detect_secrets("AKIAIOSFODNN7EXAMPLE").contains(&"AWS Access Key ID"));
        assert!(detect_secrets("-----BEGIN RSA PRIVATE KEY-----").contains(&"Private Key Block"));
        assert!(detect_secrets("DATABASE_URL=postgres://u:p4ss@db:5432/x")
            .contains(&"DB Connection URI with credentials"));
    }

    #[test]
    fn host_header_rebinding_signal_detects_foreign_host_success() {
        assert!(host_header_rebinding_signal(404, 200, 64));
        assert!(!host_header_rebinding_signal(200, 200, 64));
    }

    #[test]
    fn join_url_handles_absolute_and_relative() {
        assert_eq!(join_url("https://x.test/", "/owa/"), "https://x.test/owa/");
        assert_eq!(
            join_url("https://x.test", "remote/login"),
            "https://x.test/remote/login"
        );
        assert_eq!(
            join_url("https://x.test/", "https://y.test/a"),
            "https://y.test/a"
        );
        assert_eq!(join_url("https://x.test/", "/"), "https://x.test");
    }

    #[test]
    fn status_presence_excludes_hard_404() {
        assert!(status_indicates_presence(401));
        assert!(status_indicates_presence(200));
        assert!(!status_indicates_presence(404));
        assert!(!status_indicates_presence(410));
    }

    #[test]
    fn probe_matched_token_matches_header_and_body() {
        let probe = HttpProbe {
            status: 200,
            headers: vec![("Server".to_string(), "Microsoft-IIS/10.0".to_string())],
            body: "<html>Outlook Web App</html>".to_string(),
            final_url: "https://x.test/owa/".to_string(),
        };
        assert_eq!(
            probe_matched_token(&probe, &["nginx", "iis"]).as_deref(),
            Some("iis")
        );
        assert_eq!(
            probe_matched_token(&probe, &["outlook"]).as_deref(),
            Some("outlook")
        );
        assert!(probe_matched_token(&probe, &["citrix"]).is_none());
    }

    #[test]
    fn fingerprint_stack_parses_products() {
        let probe = HttpProbe {
            status: 200,
            headers: vec![
                ("Server".to_string(), "nginx/1.18.0".to_string()),
                ("X-Powered-By".to_string(), "PHP/7.4.3".to_string()),
            ],
            body: String::new(),
            final_url: "https://x.test/".to_string(),
        };
        let fp = fingerprint_stack(&probe);
        assert!(fp
            .products
            .contains(&("nginx".to_string(), "1.18.0".to_string())));
        assert!(fp
            .products
            .contains(&("PHP".to_string(), "7.4.3".to_string())));
    }
}
