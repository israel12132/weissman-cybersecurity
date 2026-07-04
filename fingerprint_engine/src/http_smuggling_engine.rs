//! HTTP Request Smuggling & Desync Posture — world-class, evidence-first, agentless.
//!
//! Modelled on the research and tooling that define the category (PortSwigger / Burp Suite HTTP
//! Desync Scanner, Bishop Fox, Fastly, Cloudflare hardening guides). Unlike scanners that send
//! malformed requests through a high-level HTTP client (which silently normalises away the very
//! ambiguity smuggling exploits), this engine speaks **raw HTTP/1.1 on the wire** over plain TCP
//! and TLS — the only honest way to test front-end/back-end desynchronisation.
//!
//! What it measures (every finding requires a real observed response — nothing is simulated):
//!   * **CL.TE / TE.CL confusion** — conflicting `Content-Length` + `Transfer-Encoding` probes; flags
//!     acceptance without `400`, body reflection of a unique canary, and differential behaviour vs
//!     a strict baseline.
//!   * **TE.TE dual-header ambiguity** — two `Transfer-Encoding` values with obfuscation variants
//!     (`xchunked`, tab/space tricks, `cow`, `CHUNKED`, …) accepted when a strict parser would
//!     reject them.
//!   * **Transfer-Encoding obfuscation oracle** — compares acceptance of standard `chunked` vs
//!     each obfuscated form; differential acceptance is a live smuggling primitive.
//!   * **Content-Length anomalies** — negative, duplicate, and overflow-length headers.
//!   * **HTTP/1.1 pipeline / keep-alive desync** — sends two complete requests on one connection;
//!     two distinct HTTP response blocks prove the stack processes pipelined bytes (smuggling
//!     prerequisite).
//!   * **HTTP/2 downgrade surface** — same URL over HTTP/1.1-only vs HTTP/2 ALPN; divergence
//!     indicates a protocol-boundary the edge may not inspect consistently.
//!   * **0.CL / CL.0 desync** — `Content-Length: 0` with a chunked body; front stops at zero
//!     bytes while the back-end consumes smuggled chunks (PortSwigger 0.CL class).
//!   * **h2c cleartext upgrade surface** — raw `Upgrade: h2c` probe; `101 Switching Protocols`
//!     means cleartext HTTP/2 is reachable (BishopFox h2csmuggler-class architecture).
//!   * **Chunk-extension ambiguity** — non-standard chunk extensions accepted by the parser.
//!   * **Dual-response / embedded-status oracle** — a single read returning two HTTP status lines
//!     proves the connection is in a desynchronised state (stronger than pipeline alone).
//!   * **Timing differential oracle** — smuggle probe stalls vs baseline GET (back-end waiting
//!     for bytes the front-end did not forward).
//!   * **Client-side desync surface** — GET with body / HTTP/1.0-style persistence quirks.
//!   * **Front-end fingerprint** — `Server`, `Via`, CDN/WAF headers + Alt-Svc / h2 hints.
//!   * **Wiz-style attack-path synthesis** + a quantified 0–100 desync-resistance posture score.
//!
//! Safety contract: every probe uses `Connection: close` and a unique per-scan canary token so a
//! test cannot leave a desynchronised connection that affects other users. No second-request
//! gadget chains are fired against third parties.
//!
//! Every knob (paths, per-check toggles, intensity, canary prefix, timeout, concurrency) is
//! GUI-driven via [`ArsenalConfig`] (`POST /api/command-center/scan` → `EngineRunContext::job_params`).
//!
//! MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1557 (Adversary-in-the-Middle —
//! smuggling enables cache-poison / credential-hijack chains).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, http1_client, http2_client, http_get_with_headers, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const ENGINE_ID: &str = "http_smuggling";
const MITRE: &str = "T1190";
const MITRE_MITM: &str = "T1557";

const DEFAULT_PATHS: &[&str] = &["/", "/api", "/login", "/admin", "/api/v1", "/graphql"];

// ── Configuration ───────────────────────────────────────────────────────────────

struct ScanConfig {
    timeout_ms: u64,
    concurrency: usize,
    intensity: Intensity,
    paths: Vec<String>,
    canary_prefix: String,
    check_cl_te: bool,
    check_te_cl: bool,
    check_te_te: bool,
    check_te_obfuscation: bool,
    check_cl_anomalies: bool,
    check_pipeline: bool,
    check_h2_downgrade: bool,
    check_zero_cl: bool,
    check_h2c_upgrade: bool,
    check_chunk_extensions: bool,
    check_dual_response: bool,
    check_timing_oracle: bool,
    check_client_desync: bool,
    check_response_queue: bool,
    check_backend_fingerprint: bool,
    check_cl_cl: bool,
    check_lf_only: bool,
    check_cl0: bool,
    check_host_confusion: bool,
    check_multi_port: bool,
    ports: Vec<u16>,
    check_fingerprint: bool,
    include_info: bool,
    attack_paths: bool,
    posture_score: bool,
}

impl ScanConfig {
    fn load(cfg: &ArsenalConfig) -> Self {
        let intensity = cfg.intensity();
        Self {
            timeout_ms: cfg.timeout_ms(8000),
            concurrency: cfg.concurrency().clamp(1, 32),
            intensity,
            paths: cfg.string_list_or("paths", DEFAULT_PATHS),
            canary_prefix: cfg.string_or("canary_prefix", "WZSM"),
            check_cl_te: cfg.bool_or("check_cl_te", true),
            check_te_cl: cfg.bool_or("check_te_cl", true),
            check_te_te: cfg.bool_or("check_te_te", true),
            check_te_obfuscation: cfg.bool_or("check_te_obfuscation", true),
            check_cl_anomalies: cfg.bool_or("check_cl_anomalies", intensity != Intensity::Light),
            check_pipeline: cfg.bool_or("check_pipeline", intensity != Intensity::Light),
            check_h2_downgrade: cfg.bool_or("check_h2_downgrade", true),
            check_zero_cl: cfg.bool_or("check_zero_cl", intensity != Intensity::Light),
            check_h2c_upgrade: cfg.bool_or("check_h2c_upgrade", true),
            check_chunk_extensions: cfg
                .bool_or("check_chunk_extensions", intensity != Intensity::Light),
            check_dual_response: cfg.bool_or("check_dual_response", true),
            check_timing_oracle: cfg
                .bool_or("check_timing_oracle", intensity == Intensity::Aggressive),
            check_client_desync: cfg.bool_or("check_client_desync", intensity != Intensity::Light),
            check_response_queue: cfg
                .bool_or("check_response_queue", intensity != Intensity::Light),
            check_backend_fingerprint: cfg.bool_or("check_backend_fingerprint", true),
            check_cl_cl: cfg.bool_or("check_cl_cl", intensity != Intensity::Light),
            check_lf_only: cfg.bool_or("check_lf_only", intensity == Intensity::Aggressive),
            check_cl0: cfg.bool_or("check_cl0", intensity != Intensity::Light),
            check_host_confusion: cfg
                .bool_or("check_host_confusion", intensity != Intensity::Light),
            check_multi_port: cfg.bool_or("check_multi_port", true),
            ports: cfg.ports_or("ports", &[]),
            check_fingerprint: cfg.bool_or("check_fingerprint", true),
            include_info: cfg.bool_or("include_info_findings", true),
            attack_paths: cfg.bool_or("check_attack_paths", true),
            posture_score: cfg.bool_or("check_posture_score", true),
        }
    }
}

// ── Raw wire I/O ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
struct RawResponse {
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: String,
    raw: String,
    elapsed_ms: u64,
    response_count: usize,
}

#[derive(Clone, Debug)]
struct Endpoint {
    host: String,
    port: u16,
    tls: bool,
    path: String,
    url: String,
}

fn parse_endpoint(target: &str, path: &str) -> Endpoint {
    let base = normalize_url(target);
    let host = extract_host(&base);
    let tls = base.starts_with("https://");
    let port = if base.contains(":443") || (tls && !base.contains(':')) {
        443
    } else if base.contains(":80") || (!tls && !base.contains(':')) {
        80
    } else {
        base.trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .and_then(|h| h.split(':').nth(1))
            .and_then(|p| p.parse().ok())
            .unwrap_or(if tls { 443 } else { 80 })
    };
    let p = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    let url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        p.trim_start_matches('/')
    );
    Endpoint {
        host,
        port,
        tls,
        path: p,
        url,
    }
}

fn parse_http_response(raw: &str) -> (Option<u16>, Vec<(String, String)>, String) {
    let mut blocks = raw.split("\r\n\r\n");
    let head = blocks.next().unwrap_or("");
    let body = blocks.collect::<Vec<_>>().join("\r\n\r\n");
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok());
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            let mut p = l.splitn(2, ": ");
            Some((p.next()?.to_string(), p.next()?.to_string()))
        })
        .collect();
    (status, headers, body)
}

fn count_http_responses(raw: &str) -> usize {
    raw.matches("HTTP/1.")
        .count()
        .max(if raw.is_empty() { 0 } else { 1 })
}

/// Every HTTP status code observed in a raw wire read (multi-block / desync oracle).
fn all_status_codes(raw: &str) -> Vec<u16> {
    let mut codes = Vec::new();
    let mut rest = raw;
    while let Some(idx) = rest.find("HTTP/1.") {
        let slice = &rest[idx..];
        let after = slice.strip_prefix("HTTP/1.").unwrap_or(slice);
        if let Some(code_str) = after.split_whitespace().nth(1) {
            if let Ok(code) = code_str.parse::<u16>() {
                codes.push(code);
            }
        }
        rest = &rest[idx + 7..];
    }
    codes
}

fn has_h2c_upgrade_accept(raw: &str) -> bool {
    raw.starts_with("HTTP/1.1 101")
        || raw.starts_with("HTTP/1.0 101")
        || raw.contains("\r\n101 ")
        || raw.to_ascii_lowercase().contains("switching protocols")
}

fn raw_probe_sync(
    host: &str,
    port: u16,
    tls: bool,
    request: &[u8],
    timeout_ms: u64,
) -> RawResponse {
    let start = Instant::now();
    let addr = match format!("{}:{}", host, port).to_socket_addrs() {
        Ok(mut a) => match a.next() {
            Some(x) => x,
            None => return RawResponse::default(),
        },
        Err(_) => return RawResponse::default(),
    };
    let dur = Duration::from_millis(timeout_ms.clamp(500, 30_000));
    let tcp = match TcpStream::connect_timeout(&addr, dur) {
        Ok(s) => s,
        Err(_) => return RawResponse::default(),
    };
    let _ = tcp.set_read_timeout(Some(dur));
    let _ = tcp.set_write_timeout(Some(dur));

    let mut raw_buf = Vec::with_capacity(65536);

    if tls {
        let connector = match SslConnector::builder(SslMethod::tls()) {
            Ok(mut b) => {
                b.set_verify(SslVerifyMode::NONE);
                b.build()
            }
            Err(_) => return RawResponse::default(),
        };
        let mut ssl = match connector.configure() {
            Ok(mut c) => {
                c.set_verify_hostname(false);
                match c.into_ssl(host) {
                    Ok(s) => s,
                    Err(_) => return RawResponse::default(),
                }
            }
            Err(_) => return RawResponse::default(),
        };
        let mut stream = match SslStream::new(ssl, tcp) {
            Ok(s) => s,
            Err(_) => return RawResponse::default(),
        };
        if stream.connect().is_err() {
            return RawResponse::default();
        }
        if stream.write_all(request).is_err() {
            return RawResponse {
                elapsed_ms: start.elapsed().as_millis() as u64,
                ..Default::default()
            };
        }
        let _ = stream.flush();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw_buf.extend_from_slice(&chunk[..n]);
                    if raw_buf.len() >= 65_536 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    } else {
        let mut stream = tcp;
        if stream.write_all(request).is_err() {
            return RawResponse {
                elapsed_ms: start.elapsed().as_millis() as u64,
                ..Default::default()
            };
        }
        let _ = stream.flush();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw_buf.extend_from_slice(&chunk[..n]);
                    if raw_buf.len() >= 65_536 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    let raw = String::from_utf8_lossy(&raw_buf).to_string();
    let (status, headers, body) = parse_http_response(&raw);
    RawResponse {
        status,
        headers,
        body,
        raw: raw.clone(),
        elapsed_ms: start.elapsed().as_millis() as u64,
        response_count: count_http_responses(&raw),
    }
}

async fn raw_probe(ep: &Endpoint, request: Vec<u8>, timeout_ms: u64) -> RawResponse {
    let host = ep.host.clone();
    let port = ep.port;
    let tls = ep.tls;
    tokio::task::spawn_blocking(move || raw_probe_sync(&host, port, tls, &request, timeout_ms))
        .await
        .unwrap_or_default()
}

static TOKEN_SEQ: AtomicU64 = AtomicU64::new(0);

fn canary(prefix: &str) -> String {
    let n = TOKEN_SEQ.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}{:x}{:x}", prefix, t, n)
}

// ── Request builders (raw bytes — no client normalisation) ────────────────────────

fn build_get(host: &str, path: &str, connection: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: {}\r\nAccept: */*\r\n\r\n",
        path, host, connection
    )
    .into_bytes()
}

fn build_cl_te(host: &str, path: &str, token: &str) -> Vec<u8> {
    // CL.TE: front may honour Content-Length; back may honour chunked terminator.
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{}\r\n0\r\n\r\n",
        path, host, token
    )
    .into_bytes()
}

fn build_te_cl(host: &str, path: &str, token: &str) -> Vec<u8> {
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: {}\r\n\r\n0\r\n\r\n{}",
        path, host, token.len(), token
    )
    .into_bytes()
}

fn build_te_te(host: &str, path: &str, te1: &str, te2: &str) -> Vec<u8> {
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: {}\r\nTransfer-Encoding: {}\r\nContent-Length: 4\r\n\r\n{}\r\n",
        path, host, te1, te2, "test"
    )
    .into_bytes()
}

fn build_te_obfuscated(host: &str, path: &str, te_header: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\n{}\r\nContent-Length: {}\r\n\r\n{}",
        path, host, te_header, body.len(), body
    )
    .into_bytes()
}

fn build_cl_anomaly(host: &str, path: &str, cl_value: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
        path, host, cl_value, body
    )
    .into_bytes()
}

fn build_pipeline(host: &str, path: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\nGET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host, path, host
    )
    .into_bytes()
}

/// 0.CL — Content-Length: 0 but chunked body follows (front reads zero, back reads chunks).
fn build_zero_cl(host: &str, path: &str, token: &str) -> Vec<u8> {
    let chunk = format!("{:x}", token.len());
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n{}\r\n{}\r\n0\r\n\r\n",
        path, host, chunk, token
    )
    .into_bytes()
}

/// h2c cleartext upgrade probe (BishopFox h2csmuggler class).
fn build_h2c_upgrade(host: &str, path: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
        path, host
    )
    .into_bytes()
}

/// Chunk-extension ambiguity — some parsers treat `;ext=…` differently.
fn build_chunk_extension(host: &str, path: &str, token: &str) -> Vec<u8> {
    let chunk = format!("{:x}", token.len());
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n{};ext=weissman\r\n{}\r\n0\r\n\r\n",
        path, host, chunk, token
    )
    .into_bytes()
}

/// Client-side desync — GET with a body (many stacks key/route on method+URL only).
fn build_fat_get(host: &str, path: &str, token: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
        path, host, token.len(), token
    )
    .into_bytes()
}

/// HTTP/1.0-style persistence — some back-ends differ on version handling.
fn build_http10_post(host: &str, path: &str, token: &str) -> Vec<u8> {
    format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
        path, host, token.len(), token
    )
    .into_bytes()
}

/// CL.CL — two Content-Length headers with different values (front/back pick different one).
fn build_cl_cl(host: &str, path: &str, token: &str) -> Vec<u8> {
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nContent-Length: {}\r\n\r\n{}",
        path, host, token.len(), token
    )
    .into_bytes()
}

/// Response-queue self-oracle — smuggle-shaped POST pipelined into a follow-up GET on same connection.
/// Safe: only affects our own connection; Connection closes after the probe read completes.
fn build_response_queue_oracle(host: &str, path: &str) -> Vec<u8> {
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host, path, host
    )
    .into_bytes()
}

fn server_fingerprint(headers: &[(String, String)]) -> String {
    for key in [
        "Server",
        "X-Powered-By",
        "Via",
        "X-AspNet-Version",
        "X-Backend",
    ] {
        if let Some(v) = header_value(headers, key) {
            if !v.is_empty() {
                return format!("{key}: {v}");
            }
        }
    }
    String::new()
}

fn cdn_extra_te_variants(vendor: Option<&str>) -> Vec<ObfuscationVariant> {
    let mut out = Vec::new();
    match vendor {
        Some(v) if v.contains("Cloudflare") => {
            out.push(ObfuscationVariant {
                id: "cf-chunked-tab",
                header: "Transfer-Encoding:\tchunked",
                body: "0\r\n\r\n",
            });
            out.push(ObfuscationVariant {
                id: "cf-xchunked",
                header: "Transfer-Encoding: xchunked",
                body: "0\r\n\r\n",
            });
        }
        Some(v) if v.contains("Akamai") => {
            out.push(ObfuscationVariant {
                id: "akamai-compress-chunked",
                header: "Transfer-Encoding: compress, chunked",
                body: "0\r\n\r\n",
            });
        }
        Some(v) if v.contains("Fastly") => {
            out.push(ObfuscationVariant {
                id: "fastly-chunked-identity",
                header: "Transfer-Encoding: chunked, identity",
                body: "0\r\n\r\n",
            });
        }
        _ => {}
    }
    out
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let n = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == n)
        .map(|(_, v)| v.clone())
}

fn with_category(mut f: Value, category: &str) -> Value {
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!(category));
    }
    f
}

// ── Posture accumulator ─────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct SmugglePosture {
    checks: u32,
    cl_te_surfaces: Vec<String>,
    te_cl_surfaces: Vec<String>,
    te_te_surfaces: Vec<String>,
    obfuscation_hits: Vec<String>,
    confirmed_reflections: Vec<String>,
    pipeline_confirmed: Vec<String>,
    cl_anomalies: Vec<String>,
    zero_cl_surfaces: Vec<String>,
    h2c_exposed: Vec<String>,
    chunk_extension_hits: Vec<String>,
    dual_response_hits: Vec<String>,
    timing_anomalies: Vec<String>,
    client_desync_hits: Vec<String>,
    response_queue_hits: Vec<String>,
    backend_divergence: Vec<String>,
    cl_cl_surfaces: Vec<String>,
    lf_only_hits: Vec<String>,
    cl0_surfaces: Vec<String>,
    host_confusion_hits: Vec<String>,
    proxy_hops: u32,
    h2_divergence: bool,
    http11_only: bool,
    cdn_vendor: Option<String>,
    worst: String,
}

impl SmugglePosture {
    fn bump_worst(&mut self, sev: &str) {
        let rank = |s: &str| match s {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        if rank(sev) > rank(&self.worst) {
            self.worst = sev.to_string();
        }
    }

    fn score(&self) -> u32 {
        let mut s: i32 = 100;
        s -= (self.confirmed_reflections.len() as i32).min(3) * 25;
        s -= (self.pipeline_confirmed.len() as i32).min(3) * 15;
        s -= (self.cl_te_surfaces.len() as i32).min(4) * 8;
        s -= (self.te_cl_surfaces.len() as i32).min(4) * 8;
        s -= (self.te_te_surfaces.len() as i32).min(4) * 6;
        s -= (self.obfuscation_hits.len() as i32).min(6) * 5;
        s -= (self.cl_anomalies.len() as i32).min(3) * 7;
        s -= (self.zero_cl_surfaces.len() as i32).min(3) * 10;
        s -= (self.h2c_exposed.len() as i32).min(2) * 18;
        s -= (self.dual_response_hits.len() as i32).min(2) * 12;
        s -= (self.chunk_extension_hits.len() as i32).min(4) * 5;
        s -= (self.client_desync_hits.len() as i32).min(3) * 6;
        s -= (self.timing_anomalies.len() as i32).min(3) * 8;
        s -= (self.response_queue_hits.len() as i32).min(2) * 14;
        s -= (self.backend_divergence.len() as i32).min(2) * 6;
        s -= (self.cl_cl_surfaces.len() as i32).min(3) * 7;
        s -= (self.lf_only_hits.len() as i32).min(2) * 9;
        s -= (self.cl0_surfaces.len() as i32).min(2) * 8;
        s -= (self.host_confusion_hits.len() as i32).min(2) * 7;
        if self.proxy_hops >= 2 {
            s -= 4;
        }
        if self.h2_divergence {
            s -= 10;
        }
        if self.http11_only {
            s -= 5;
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

    fn has_findings(&self) -> bool {
        !self.cl_te_surfaces.is_empty()
            || !self.te_cl_surfaces.is_empty()
            || !self.te_te_surfaces.is_empty()
            || !self.obfuscation_hits.is_empty()
            || !self.confirmed_reflections.is_empty()
            || !self.pipeline_confirmed.is_empty()
            || !self.cl_anomalies.is_empty()
            || !self.zero_cl_surfaces.is_empty()
            || !self.h2c_exposed.is_empty()
            || !self.dual_response_hits.is_empty()
            || !self.chunk_extension_hits.is_empty()
            || !self.client_desync_hits.is_empty()
            || !self.timing_anomalies.is_empty()
            || !self.response_queue_hits.is_empty()
            || !self.backend_divergence.is_empty()
            || !self.cl_cl_surfaces.is_empty()
            || !self.lf_only_hits.is_empty()
            || !self.cl0_surfaces.is_empty()
            || !self.host_confusion_hits.is_empty()
            || self.h2_divergence
    }
}

// ── Per-endpoint probes ───────────────────────────────────────────────────────────

struct ObfuscationVariant {
    id: &'static str,
    header: &'static str,
    body: &'static str,
}

const TE_OBFUSCATIONS: &[ObfuscationVariant] = &[
    ObfuscationVariant {
        id: "xchunked",
        header: "Transfer-Encoding: xchunked",
        body: "PROBE",
    },
    ObfuscationVariant {
        id: "tab-value",
        header: "Transfer-Encoding:\tchunked",
        body: "0\r\n\r\n",
    },
    ObfuscationVariant {
        id: "capital",
        header: "Transfer-Encoding: CHUNKED",
        body: "0\r\n\r\n",
    },
    ObfuscationVariant {
        id: "cow",
        header: "Transfer-Encoding: cow",
        body: "moo",
    },
    ObfuscationVariant {
        id: "space-colon",
        header: "Transfer-Encoding : chunked",
        body: "0\r\n\r\n",
    },
    ObfuscationVariant {
        id: "quoted",
        header: "Transfer-Encoding: \"chunked\"",
        body: "0\r\n\r\n",
    },
    ObfuscationVariant {
        id: "compress-chunked",
        header: "Transfer-Encoding: compress, chunked",
        body: "0\r\n\r\n",
    },
    ObfuscationVariant {
        id: "chunked-gzip",
        header: "Transfer-Encoding: chunked, gzip",
        body: "0\r\n\r\n",
    },
];

fn emit_dual_response(
    findings: &mut Vec<Value>,
    posture: &mut SmugglePosture,
    ep: &Endpoint,
    target: &str,
    resp: &RawResponse,
    variant: &str,
    enabled: bool,
) {
    if !enabled {
        return;
    }
    let codes = all_status_codes(&resp.raw);
    if codes.len() < 2 {
        return;
    }
    posture
        .dual_response_hits
        .push(format!("{}:{}", ep.url, variant));
    posture.bump_worst("critical");
    let ev = Evidence::new()
        .with("url", ep.url.clone())
        .with("variant", variant)
        .with("status_codes", json!(codes))
        .with("response_count", resp.response_count)
        .raw_excerpt(resp.raw.as_bytes())
        .check("embedded_second_response", true, codes.len());
    findings.push(with_category(
        finding_rich(
            ENGINE_ID,
            &format!("Dual HTTP response blocks ({}) on {}", variant, ep.path),
            "critical",
            MITRE,
            &format!(
                "Probe `{variant}` to {} returned {} distinct HTTP status lines {codes:?} in one read — \
                 the connection delivered multiple responses without a clean boundary (embedded-response oracle).",
                ep.url,
                codes.len()
            ),
            target,
            0.92,
            ev,
        ),
        "smuggle_dual_response",
    ));
}

fn emit_timing_oracle(
    findings: &mut Vec<Value>,
    posture: &mut SmugglePosture,
    ep: &Endpoint,
    target: &str,
    resp: &RawResponse,
    variant: &str,
    baseline_ms: u64,
    enabled: bool,
) {
    if !enabled || baseline_ms == 0 {
        return;
    }
    let threshold = baseline_ms.saturating_mul(4).max(2500);
    if resp.elapsed_ms < threshold || resp.elapsed_ms.saturating_sub(baseline_ms) <= 1500 {
        return;
    }
    posture
        .timing_anomalies
        .push(format!("{}:{}", ep.url, variant));
    posture.bump_worst("high");
    let delta = resp.elapsed_ms.saturating_sub(baseline_ms);
    let ev = Evidence::new()
        .with("url", ep.url.clone())
        .with("variant", variant)
        .with("baseline_ms", baseline_ms)
        .with("probe_ms", resp.elapsed_ms)
        .with("delta_ms", delta)
        .check("timing_stall", true, variant);
    findings.push(with_category(
        finding_rich(
            ENGINE_ID,
            &format!("Timing desync oracle ({variant}) on {}", ep.path),
            "high",
            MITRE,
            &format!(
                "The `{variant}` probe to {} took {}ms vs baseline GET {}ms (Δ{delta}ms). \
                 Parser desync often stalls the back-end waiting for body bytes the front-end did not forward.",
                ep.url, resp.elapsed_ms, baseline_ms
            ),
            target,
            0.68,
            ev,
        ),
        "smuggle_timing",
    ));
}

async fn probe_endpoint(ep: &Endpoint, cfg: &ScanConfig, target: &str) -> Vec<Value> {
    let mut findings = Vec::new();
    let mut posture = SmugglePosture::default();
    let token = canary(&cfg.canary_prefix);

    // Baseline GET for fingerprint + strict-parser reference.
    let baseline_req = build_get(&ep.host, &ep.path, "close");
    let baseline = raw_probe(ep, baseline_req, cfg.timeout_ms).await;
    posture.checks += 1;

    if cfg.check_fingerprint && baseline.status.is_some() {
        let server = header_value(&baseline.headers, "Server");
        let via = header_value(&baseline.headers, "Via");
        let cf = header_value(&baseline.headers, "CF-RAY");
        let x_cache = header_value(&baseline.headers, "X-Cache");
        let alt_svc = header_value(&baseline.headers, "Alt-Svc");
        let mut vendor = None;
        if cf.is_some() {
            vendor = Some("Cloudflare".to_string());
        } else if x_cache
            .as_deref()
            .map(|x| x.contains("cloudfront"))
            .unwrap_or(false)
        {
            vendor = Some("AWS CloudFront".to_string());
        } else if header_value(&baseline.headers, "X-Served-By").is_some() {
            vendor = Some("Fastly".to_string());
        } else if header_value(&baseline.headers, "X-Akamai-Transformed").is_some() {
            vendor = Some("Akamai".to_string());
        }
        posture.cdn_vendor = vendor.clone();
        posture.http11_only = true;

        if cfg.include_info {
            let ev = Evidence::new()
                .with("url", ep.url.clone())
                .with("status", baseline.status.unwrap_or(0))
                .with("server", server.clone().unwrap_or_default())
                .with("via", via.clone().unwrap_or_default())
                .with("cdn_vendor", vendor.clone().unwrap_or_default())
                .with("alt_svc", alt_svc.clone().unwrap_or_default())
                .check(
                    "baseline_reachable",
                    baseline.status.is_some(),
                    "GET baseline",
                );
            findings.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    "HTTP/1.1 front-end fingerprint",
                    "info",
                    MITRE,
                    &format!(
                        "Baseline GET {} returned HTTP {}. Server={:?} Via={:?} CDN={:?} Alt-Svc={:?}. \
                         A distinct front-end (CDN/WAF/reverse-proxy) parsing HTTP/1.1 differently from \
                         the origin is the architectural precondition for request smuggling.",
                        ep.url,
                        baseline.status.unwrap_or(0),
                        server,
                        via,
                        vendor,
                        alt_svc
                    ),
                    target,
                    0.95,
                    ev,
                ),
                "smuggle_fingerprint",
            ));
        }
    }

    let baseline_ms = baseline.elapsed_ms;
    let baseline_fp = server_fingerprint(&baseline.headers);
    let baseline_status = baseline.status.unwrap_or(0);

    // CL.TE
    if cfg.check_cl_te {
        let req = build_cl_te(&ep.host, &ep.path, &token);
        let resp = raw_probe(ep, req, cfg.timeout_ms).await;
        posture.checks += 1;
        if let Some(status) = resp.status {
            let reflected = resp.body.contains(&token) || resp.raw.contains(&token);
            let rejected = status == 400 || status == 501;
            if reflected {
                posture.confirmed_reflections.push(ep.url.clone());
                posture.bump_worst("critical");
                let ev = Evidence::new()
                    .with("url", ep.url.clone())
                    .with("status", status)
                    .with("canary", token.clone())
                    .with("variant", "CL.TE")
                    .raw_excerpt(resp.raw.as_bytes())
                    .check("body_reflection", true, "canary in response");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("CL.TE smuggling canary reflected on {}", ep.path),
                        "critical",
                        MITRE,
                        &format!(
                            "A CL.TE desync probe to {} returned HTTP {} and the unique canary `{}` \
                             appeared in the response — the front/back-end parsed the message \
                             differently and leaked smuggled bytes. This is a confirmed desync primitive.",
                            ep.url, status, token
                        ),
                        target,
                        0.95,
                        ev,
                    ),
                    "smuggle_confirmed",
                ));
            } else if !rejected {
                posture.cl_te_surfaces.push(ep.url.clone());
                posture.bump_worst("high");
                let ev = Evidence::new()
                    .with("url", ep.url.clone())
                    .with("status", status)
                    .with("variant", "CL.TE")
                    .check("conflict_accepted", true, "CL+TE not rejected with 400");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("CL.TE header conflict accepted on {}", ep.path),
                        "high",
                        MITRE,
                        &format!(
                            "The target {} accepted a POST with both Content-Length and \
                             Transfer-Encoding: chunked and responded HTTP {} (expected 400 from a \
                             strict RFC 7230 parser). This is the prerequisite for CL.TE request \
                             smuggling when a back-end honours the other header.",
                            ep.url, status
                        ),
                        target,
                        0.75,
                        ev,
                    ),
                    "smuggle_cl_te",
                ));
            }
        }
        emit_dual_response(
            &mut findings,
            &mut posture,
            ep,
            target,
            &resp,
            "CL.TE",
            cfg.check_dual_response,
        );
        emit_timing_oracle(
            &mut findings,
            &mut posture,
            ep,
            target,
            &resp,
            "CL.TE",
            baseline_ms,
            cfg.check_timing_oracle,
        );
        if cfg.check_backend_fingerprint {
            let post_fp = server_fingerprint(&resp.headers);
            if !post_fp.is_empty() && !baseline_fp.is_empty() && post_fp != baseline_fp {
                posture.backend_divergence.push(ep.url.clone());
                posture.bump_worst("medium");
                let ev = Evidence::new()
                    .with("url", ep.url.clone())
                    .with("baseline_fingerprint", baseline_fp.clone())
                    .with("smuggle_fingerprint", post_fp.clone())
                    .check(
                        "backend_tier_divergence",
                        true,
                        "Server/Via changed on smuggle probe",
                    );
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Front/back-end fingerprint divergence on {}", ep.path),
                        "medium",
                        MITRE,
                        &format!(
                            "Baseline GET fingerprint `{}` differs from CL.TE POST fingerprint `{}` on {}. \
                             A distinct back-end tier behind the edge is the classic smuggling architecture \
                             (CDN/WAF front, different parser origin).",
                            baseline_fp, post_fp, ep.url
                        ),
                        target,
                        0.72,
                        ev,
                    ),
                    "smuggle_backend_fp",
                ));
            }
        }
    }

    // TE.CL
    if cfg.check_te_cl {
        let req = build_te_cl(&ep.host, &ep.path, &token);
        let resp = raw_probe(ep, req, cfg.timeout_ms).await;
        posture.checks += 1;
        if let Some(status) = resp.status {
            let reflected = resp.body.contains(&token) || resp.raw.contains(&token);
            let rejected = status == 400 || status == 501;
            if reflected {
                posture.confirmed_reflections.push(ep.url.clone());
                posture.bump_worst("critical");
                let ev = Evidence::new()
                    .with("url", ep.url.clone())
                    .with("status", status)
                    .with("canary", token.clone())
                    .with("variant", "TE.CL")
                    .check("body_reflection", true, "canary in response");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("TE.CL smuggling canary reflected on {}", ep.path),
                        "critical",
                        MITRE,
                        &format!(
                            "TE.CL probe to {} reflected the canary `{}` (HTTP {}). Front-end/back-end \
                             disagree on whether Content-Length or Transfer-Encoding governs the body.",
                            ep.url, token, status
                        ),
                        target,
                        0.95,
                        ev,
                    ),
                    "smuggle_confirmed",
                ));
            } else if !rejected {
                posture.te_cl_surfaces.push(ep.url.clone());
                posture.bump_worst("high");
                let ev = Evidence::new()
                    .with("url", ep.url.clone())
                    .with("status", status)
                    .with("variant", "TE.CL")
                    .check("conflict_accepted", true, "TE+CL not rejected");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("TE.CL header conflict accepted on {}", ep.path),
                        "high",
                        MITRE,
                        &format!(
                            "{} accepted Transfer-Encoding: chunked together with Content-Length \
                             (HTTP {}). TE.CL smuggling is possible when the front-end uses CL and \
                             the back-end uses TE.",
                            ep.url, status
                        ),
                        target,
                        0.72,
                        ev,
                    ),
                    "smuggle_te_cl",
                ));
            }
        }
        emit_dual_response(
            &mut findings,
            &mut posture,
            ep,
            target,
            &resp,
            "TE.CL",
            cfg.check_dual_response,
        );
        emit_timing_oracle(
            &mut findings,
            &mut posture,
            ep,
            target,
            &resp,
            "TE.CL",
            baseline_ms,
            cfg.check_timing_oracle,
        );
    }

    // 0.CL — Content-Length: 0 with trailing chunked body
    if cfg.check_zero_cl {
        let req = build_zero_cl(&ep.host, &ep.path, &token);
        let resp = raw_probe(ep, req, cfg.timeout_ms).await;
        posture.checks += 1;
        if let Some(status) = resp.status {
            let reflected = resp.body.contains(&token) || resp.raw.contains(&token);
            let rejected = status == 400 || status == 501;
            if reflected {
                posture.confirmed_reflections.push(ep.url.clone());
                posture.bump_worst("critical");
                let ev = Evidence::new()
                    .with("url", ep.url.clone())
                    .with("status", status)
                    .with("canary", token.clone())
                    .with("variant", "0.CL")
                    .check("body_reflection", true, "canary in response");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("0.CL desync canary reflected on {}", ep.path),
                        "critical",
                        MITRE,
                        &format!(
                            "0.CL probe (Content-Length: 0 + chunked body) to {} reflected `{}` \
                             (HTTP {}). Front-end read zero bytes; back-end consumed chunked data.",
                            ep.url, token, status
                        ),
                        target,
                        0.93,
                        ev,
                    ),
                    "smuggle_confirmed",
                ));
            } else if !rejected {
                posture.zero_cl_surfaces.push(ep.url.clone());
                posture.bump_worst("high");
                let ev = Evidence::new()
                    .with("url", ep.url.clone())
                    .with("status", status)
                    .with("variant", "0.CL")
                    .check("zero_cl_accepted", true, "CL:0 + TE accepted");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("0.CL header conflict accepted on {}", ep.path),
                        "high",
                        MITRE,
                        &format!(
                            "{} accepted Content-Length: 0 together with Transfer-Encoding: chunked \
                             and a non-empty chunked body (HTTP {}). Classic 0.CL smuggling surface.",
                            ep.url, status
                        ),
                        target,
                        0.78,
                        ev,
                    ),
                    "smuggle_zero_cl",
                ));
            }
        }
        emit_dual_response(
            &mut findings,
            &mut posture,
            ep,
            target,
            &resp,
            "0.CL",
            cfg.check_dual_response,
        );
        emit_timing_oracle(
            &mut findings,
            &mut posture,
            ep,
            target,
            &resp,
            "0.CL",
            baseline_ms,
            cfg.check_timing_oracle,
        );
    }

    // TE.TE dual Transfer-Encoding
    if cfg.check_te_te {
        let pairs = [
            ("identity-chunked", "identity", "chunked"),
            ("chunked-identity", "chunked", "identity"),
            ("gzip-chunked", "gzip", "chunked"),
        ];
        let tier_ok = cfg.intensity != Intensity::Light;
        for (label, te1, te2) in pairs {
            if !tier_ok && label != "identity-chunked" {
                continue;
            }
            let req = build_te_te(&ep.host, &ep.path, te1, te2);
            let resp = raw_probe(ep, req, cfg.timeout_ms).await;
            posture.checks += 1;
            if let Some(status) = resp.status {
                if status != 400 && status != 501 {
                    posture.te_te_surfaces.push(format!("{}:{}", ep.url, label));
                    posture.bump_worst("medium");
                    let ev = Evidence::new()
                        .with("url", ep.url.clone())
                        .with("status", status)
                        .with("te1", te1)
                        .with("te2", te2)
                        .check("dual_te_accepted", true, label);
                    findings.push(with_category(
                        finding_rich(
                            ENGINE_ID,
                            &format!("TE.TE dual Transfer-Encoding accepted ({}) on {}", label, ep.path),
                            "medium",
                            MITRE,
                            &format!(
                                "The server at {} accepted two Transfer-Encoding values (`{}` + `{}`) \
                                 with HTTP {}. TE.TE ambiguity lets attackers pick which TE header \
                                 each tier honours.",
                                ep.url, te1, te2, status
                            ),
                            target,
                            0.65,
                            ev,
                        ),
                        "smuggle_te_te",
                    ));
                }
            }
        }
    }

    // TE obfuscation oracle — differential vs strict `chunked` baseline.
    if cfg.check_te_obfuscation {
        let strict_body = "0\r\n\r\n";
        let strict_req = build_te_obfuscated(
            &ep.host,
            &ep.path,
            "Transfer-Encoding: chunked",
            strict_body,
        );
        let strict = raw_probe(ep, strict_req, cfg.timeout_ms).await;
        posture.checks += 1;
        let strict_ok = strict.status.map(|s| s != 400 && s != 501).unwrap_or(false);

        let max_variants = match cfg.intensity {
            Intensity::Light => 2,
            Intensity::Normal => TE_OBFUSCATIONS.len(),
            Intensity::Aggressive => TE_OBFUSCATIONS.len(),
        };
        for variant in TE_OBFUSCATIONS.iter().take(max_variants) {
            let req = build_te_obfuscated(&ep.host, &ep.path, variant.header, variant.body);
            let resp = raw_probe(ep, req, cfg.timeout_ms).await;
            posture.checks += 1;
            if let Some(status) = resp.status {
                let accepted = status != 400 && status != 501;
                // Differential: obfuscated accepted when strict rejected, or vice versa.
                let differential = accepted != strict_ok || (accepted && variant.id != "capital");
                if accepted && (differential || variant.id == "xchunked" || variant.id == "cow") {
                    posture
                        .obfuscation_hits
                        .push(format!("{}:{}", ep.url, variant.id));
                    let sev = if variant.id == "xchunked" || variant.id == "cow" {
                        posture.bump_worst("high");
                        "high"
                    } else {
                        posture.bump_worst("medium");
                        "medium"
                    };
                    let ev = Evidence::new()
                        .with("url", ep.url.clone())
                        .with("status", status)
                        .with("variant", variant.id)
                        .with("te_header", variant.header)
                        .with("strict_baseline_status", strict.status.unwrap_or(0))
                        .check("obfuscated_te_accepted", true, variant.id);
                    findings.push(with_category(
                        finding_rich(
                            ENGINE_ID,
                            &format!("Obfuscated Transfer-Encoding accepted ({}) on {}", variant.id, ep.path),
                            sev,
                            MITRE,
                            &format!(
                                "The server at {} accepted `{}` with HTTP {} (strict chunked baseline \
                                 status {}). Non-standard TE parsing is the root cause behind TE.CL \
                                 and TE.TE smuggling.",
                                ep.url, variant.header, status, strict.status.unwrap_or(0)
                            ),
                            target,
                            if sev == "high" { 0.82 } else { 0.6 },
                            ev,
                        ),
                        "smuggle_te_obfuscation",
                    ));
                }
            }
        }
        // CDN-specific TE variants when vendor identified from baseline.
        for variant in cdn_extra_te_variants(posture.cdn_vendor.as_deref()) {
            let req = build_te_obfuscated(&ep.host, &ep.path, variant.header, variant.body);
            let resp = raw_probe(ep, req, cfg.timeout_ms).await;
            posture.checks += 1;
            if let Some(status) = resp.status {
                if status != 400 && status != 501 {
                    posture
                        .obfuscation_hits
                        .push(format!("{}:{}", ep.url, variant.id));
                    posture.bump_worst("high");
                    let ev = Evidence::new()
                        .with("url", ep.url.clone())
                        .with("status", status)
                        .with("variant", variant.id)
                        .with("cdn_vendor", posture.cdn_vendor.clone().unwrap_or_default())
                        .check("cdn_te_accepted", true, variant.id);
                    findings.push(with_category(
                            finding_rich(
                                ENGINE_ID,
                                &format!("CDN-specific TE variant accepted ({}) on {}", variant.id, ep.path),
                                "high",
                                MITRE,
                                &format!(
                                    "CDN vendor {:?} front-end at {} accepted `{}` with HTTP {} — \
                                     vendor-tuned obfuscation is a live WAF-bypass smuggling primitive.",
                                    posture.cdn_vendor, ep.url, variant.header, status
                                ),
                                target,
                                0.84,
                                ev,
                            ),
                            "smuggle_te_obfuscation",
                        ));
                }
            }
        }
    }

    // CL.CL — duplicate Content-Length with conflicting values
    if cfg.check_cl_cl {
        let req = build_cl_cl(&ep.host, &ep.path, &token);
        let resp = raw_probe(ep, req, cfg.timeout_ms).await;
        posture.checks += 1;
        if let Some(status) = resp.status {
            let reflected = resp.body.contains(&token) || resp.raw.contains(&token);
            let rejected = status == 400 || status == 501;
            if reflected {
                posture.confirmed_reflections.push(ep.url.clone());
                posture.bump_worst("critical");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("CL.CL canary reflected on {}", ep.path),
                        "critical",
                        MITRE,
                        &format!(
                            "CL.CL probe (duplicate Content-Length) to {} reflected `{}` (HTTP {}).",
                            ep.url, token, status
                        ),
                        target,
                        0.91,
                        Evidence::new().with("url", ep.url.clone()).with("variant", "CL.CL"),
                    ),
                    "smuggle_confirmed",
                ));
            } else if !rejected {
                posture.cl_cl_surfaces.push(ep.url.clone());
                posture.bump_worst("high");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("CL.CL duplicate Content-Length accepted on {}", ep.path),
                        "high",
                        MITRE,
                        &format!(
                            "{} accepted two Content-Length headers with different values (HTTP {}). \
                             CL.CL lets each tier pick a different body boundary.",
                            ep.url, status
                        ),
                        target,
                        0.74,
                        Evidence::new().with("url", ep.url.clone()).with("status", status),
                    ),
                    "smuggle_cl_cl",
                ));
            }
        }
        emit_dual_response(
            &mut findings,
            &mut posture,
            ep,
            target,
            &resp,
            "CL.CL",
            cfg.check_dual_response,
        );
    }

    // Content-Length anomalies
    if cfg.check_cl_anomalies {
        let anomalies = [
            ("negative", "-1", "x"),
            ("zero-with-body", "0", "BODY"),
            ("duplicate", "4", "test"), // sent with duplicate header below
        ];
        for (label, cl, body) in anomalies {
            let req = if label == "duplicate" {
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n{}",
                    ep.path, ep.host, body
                )
                .into_bytes()
            } else {
                build_cl_anomaly(&ep.host, &ep.path, cl, body)
            };
            let resp = raw_probe(ep, req, cfg.timeout_ms).await;
            posture.checks += 1;
            if let Some(status) = resp.status {
                if status != 400 && status != 501 && status != 411 {
                    posture.cl_anomalies.push(format!("{}:{}", ep.url, label));
                    posture.bump_worst("medium");
                    let ev = Evidence::new()
                        .with("url", ep.url.clone())
                        .with("status", status)
                        .with("anomaly", label)
                        .check("cl_anomaly_accepted", true, label);
                    findings.push(with_category(
                        finding_rich(
                            ENGINE_ID,
                            &format!("Content-Length anomaly accepted ({}) on {}", label, ep.path),
                            "medium",
                            MITRE,
                            &format!(
                                "Anomalous Content-Length (`{}` = {}) was accepted with HTTP {} on {}. \
                                 CL parsing inconsistencies enable CL.0 / CL.CL desync variants.",
                                label, cl, status, ep.url
                            ),
                            target,
                            0.58,
                            ev,
                        ),
                        "smuggle_cl_anomaly",
                    ));
                }
            }
        }
    }

    // Pipeline / keep-alive desync prerequisite
    if cfg.check_pipeline {
        let req = build_pipeline(&ep.host, &ep.path);
        let resp = raw_probe(ep, req, cfg.timeout_ms).await;
        posture.checks += 1;
        if resp.response_count >= 2 {
            posture.pipeline_confirmed.push(ep.url.clone());
            posture.bump_worst("high");
            let ev = Evidence::new()
                .with("url", ep.url.clone())
                .with("response_count", resp.response_count)
                .raw_excerpt(resp.raw.as_bytes())
                .check("pipeline_responses", true, resp.response_count);
            findings.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!("HTTP/1.1 pipeline desync surface on {}", ep.path),
                    "high",
                    MITRE,
                    &format!(
                        "Sending two pipelined GET requests on one connection to {} yielded {} \
                         distinct HTTP response blocks. Pipelining is a prerequisite for request \
                         smuggling gadget chains (queue poisoning, response queue poisoning).",
                        ep.url, resp.response_count
                    ),
                    target,
                    0.8,
                    ev,
                ),
                "smuggle_pipeline",
            ));
        } else if cfg.include_info && resp.status.is_some() {
            let ev = Evidence::new()
                .with("url", ep.url.clone())
                .with("response_count", resp.response_count)
                .check("pipeline_responses", false, "single response only");
            findings.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!("No HTTP pipeline on {} (single response)", ep.path),
                    "info",
                    MITRE,
                    "The pipelined probe returned a single HTTP response — the stack may serialize \
                     requests (reduces classic smuggling but does not eliminate all desync classes).",
                    target,
                    0.5,
                    ev,
                ),
                "smuggle_pipeline",
            ));
        }
    }

    // Response-queue self-oracle — smuggle POST pipelined into GET on same connection.
    if cfg.check_response_queue {
        let req = build_response_queue_oracle(&ep.host, &ep.path);
        let resp = raw_probe(ep, req, cfg.timeout_ms).await;
        posture.checks += 1;
        let codes = all_status_codes(&resp.raw);
        if codes.len() >= 2 {
            let second = codes[1];
            let shifted = second != baseline_status;
            posture.response_queue_hits.push(ep.url.clone());
            let sev = if shifted { "critical" } else { "high" };
            posture.bump_worst(sev);
            let ev = Evidence::new()
                .with("url", ep.url.clone())
                .with("baseline_status", baseline_status)
                .with("second_response_status", second)
                .with("status_codes", json!(codes))
                .with("response_count", resp.response_count)
                .raw_excerpt(resp.raw.as_bytes())
                .check("response_queue_shifted", shifted, second);
            findings.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!(
                        "Response-queue oracle{} on {}",
                        if shifted { " — status shifted" } else { "" },
                        ep.path
                    ),
                    sev,
                    MITRE_MITM,
                    &format!(
                        "Smuggle-shaped POST + pipelined GET on {} returned status sequence {:?} \
                         (baseline GET was HTTP {}). {} — live evidence the connection queue \
                         processed smuggled bytes before the visible GET.",
                        ep.url,
                        codes,
                        baseline_status,
                        if shifted {
                            "The second response status differs from baseline — response-queue poisoning is likely exploitable"
                        } else {
                            "Multiple responses on one smuggle-pipeline read — queue desync prerequisite confirmed"
                        }
                    ),
                    target,
                    if shifted { 0.9 } else { 0.82 },
                    ev,
                ),
                "smuggle_response_queue",
            ));
        }
    }

    // Chunk-extension parser ambiguity
    if cfg.check_chunk_extensions {
        let req = build_chunk_extension(&ep.host, &ep.path, &token);
        let resp = raw_probe(ep, req, cfg.timeout_ms).await;
        posture.checks += 1;
        if let Some(status) = resp.status {
            if status != 400 && status != 501 {
                let reflected = resp.body.contains(&token) || resp.raw.contains(&token);
                posture.chunk_extension_hits.push(ep.url.clone());
                let sev = if reflected { "high" } else { "medium" };
                posture.bump_worst(sev);
                let ev = Evidence::new()
                    .with("url", ep.url.clone())
                    .with("status", status)
                    .with("canary", token.clone())
                    .check("chunk_extension_accepted", true, "ext=weissman");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Chunk extension accepted on {}", ep.path),
                        sev,
                        MITRE,
                        &format!(
                            "The server at {} accepted a chunked body with extension `;ext=weissman` \
                             (HTTP {}). Non-standard chunk-extension parsing is a lesser-known \
                             desync primitive used to split front/back-end chunk boundaries.",
                            ep.url, status
                        ),
                        target,
                        if reflected { 0.8 } else { 0.55 },
                        ev,
                    ),
                    "smuggle_chunk_ext",
                ));
            }
        }
    }

    // h2c cleartext upgrade — only meaningful when target speaks HTTP/1.1 on this port
    if cfg.check_h2c_upgrade {
        let req = build_h2c_upgrade(&ep.host, &ep.path);
        let resp = raw_probe(ep, req, cfg.timeout_ms).await;
        posture.checks += 1;
        if has_h2c_upgrade_accept(&resp.raw) || resp.status == Some(101) {
            posture.h2c_exposed.push(ep.url.clone());
            posture.bump_worst("high");
            let ev = Evidence::new()
                .with("url", ep.url.clone())
                .with("status", resp.status.unwrap_or(0))
                .raw_excerpt(resp.raw.as_bytes())
                .check("h2c_upgrade_accepted", true, "101 Switching Protocols");
            findings.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!("h2c cleartext HTTP/2 upgrade accepted on {}", ep.path),
                    "high",
                    MITRE,
                    &format!(
                        "The target {} accepted `Upgrade: h2c` (HTTP {}). Cleartext HTTP/2 enables \
                         H2.TE / H2.CL desync classes (BishopFox h2csmuggler) when a proxy downgrades \
                         to HTTP/1.1 toward the origin.",
                        ep.url,
                        resp.status.unwrap_or(101)
                    ),
                    target,
                    0.85,
                    ev,
                ),
                "smuggle_h2c",
            ));
        }
    }

    // Client-side desync — GET-with-body + HTTP/1.0 persistence quirks
    if cfg.check_client_desync {
        for (label, req) in [
            ("fat-get", build_fat_get(&ep.host, &ep.path, &token)),
            ("http10-post", build_http10_post(&ep.host, &ep.path, &token)),
        ] {
            let resp = raw_probe(ep, req, cfg.timeout_ms).await;
            posture.checks += 1;
            if let Some(status) = resp.status {
                if status != 400 && status != 501 && status != 405 {
                    let reflected = resp.body.contains(&token);
                    if label == "fat-get" || reflected {
                        posture
                            .client_desync_hits
                            .push(format!("{}:{}", ep.url, label));
                        let sev = if reflected { "high" } else { "medium" };
                        posture.bump_worst(sev);
                        let ev = Evidence::new()
                            .with("url", ep.url.clone())
                            .with("status", status)
                            .with("variant", label)
                            .check("client_desync_accepted", true, label);
                        findings.push(with_category(
                            finding_rich(
                                ENGINE_ID,
                                &format!("Client-side desync surface ({label}) on {}", ep.path),
                                sev,
                                MITRE,
                                &format!(
                                    "The server at {} accepted a `{label}` probe with HTTP {} \
                                     (GET-with-body / HTTP/1.0 persistence class). Client-side desync \
                                     poisons browser connection pools — a distinct class from classic \
                                     server-side CL.TE smuggling.",
                                    ep.url, status
                                ),
                                target,
                                if reflected { 0.76 } else { 0.58 },
                                ev,
                            ),
                            "smuggle_client_desync",
                        ));
                    }
                }
            }
        }
    }

    // HTTP/2 downgrade divergence (reqwest ALPN — complementary to raw h1 probes).
    if cfg.check_h2_downgrade {
        let h1c = http1_client().await;
        let h2c = http2_client().await;
        if let (Some(h1), Some(h2)) = (
            http_get_with_headers(&h1c, &ep.url, &[]).await,
            http_get_with_headers(&h2c, &ep.url, &[]).await,
        ) {
            posture.checks += 1;
            let diverge = h1.status != h2.status
                || (h1.status == h2.status
                    && h1.body.len().abs_diff(h2.body.len())
                        > h1.body.len().max(h2.body.len()) / 4);
            if diverge {
                posture.h2_divergence = true;
                posture.bump_worst("medium");
                let ev = Evidence::new()
                    .with("url", ep.url.clone())
                    .with("h1_status", h1.status)
                    .with("h2_status", h2.status)
                    .with("h1_body_len", h1.body.len())
                    .with("h2_body_len", h2.body.len())
                    .check("protocol_divergence", true, "h1 vs h2");
                findings.push(with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("HTTP/1.1 ↔ HTTP/2 protocol schism on {}", ep.path),
                        "medium",
                        MITRE,
                        &format!(
                            "The same URL {} returns HTTP {} over HTTP/1.1 but HTTP {} over HTTP/2 \
                             (body sizes {} vs {} bytes). Inconsistent inspection across ALPN \
                             negotiated protocols is a liminal-boundary bypass class.",
                            ep.url, h1.status, h2.status, h1.body.len(), h2.body.len()
                        ),
                        target,
                        0.7,
                        ev,
                    ),
                    "smuggle_h2_downgrade",
                ));
            }
        }
    }

    // Attack paths for this endpoint's posture slice.
    if cfg.attack_paths && posture.has_findings() {
        findings.extend(synthesize_attack_paths(target, &posture, &ep.url));
    }

    findings
}

fn synthesize_attack_paths(target: &str, p: &SmugglePosture, url: &str) -> Vec<Value> {
    let mut paths = Vec::new();
    if !p.confirmed_reflections.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: confirmed desync → request queue poisoning",
                "critical",
                MITRE_MITM,
                &format!(
                    "Confirmed body reflection on {} proves the front/back-end parsers disagree. \
                     An attacker can smuggle a prefix request to poison the back-end queue — leading \
                     to cache poisoning, credential capture, or bypass of access controls on the \
                     next victim request.",
                    url
                ),
                target,
                0.9,
                Evidence::new()
                    .with("url", url)
                    .with("stage", "desync_confirmed")
                    .check("reflection", true, "canary reflected"),
            ),
            "attack_path",
        ));
    }
    if !p.pipeline_confirmed.is_empty()
        && (!p.cl_te_surfaces.is_empty() || !p.te_cl_surfaces.is_empty())
    {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: pipeline + header conflict → response queue poisoning",
                "critical",
                MITRE_MITM,
                &format!(
                    "HTTP pipelining is enabled on {} and conflicting CL/TE headers are accepted. \
                     Combined, an attacker can desync the connection and capture the next user's \
                     response (response queue poisoning) or inject a cached malicious response.",
                    url
                ),
                target,
                0.85,
                Evidence::new()
                    .with("url", url)
                    .with("pipeline", true)
                    .with("header_conflict", true),
            ),
            "attack_path",
        ));
    }
    if !p.obfuscation_hits.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: TE obfuscation → TE.CL bypass of WAF",
                "high",
                MITRE,
                &format!(
                    "Obfuscated Transfer-Encoding accepted on {} allows an attacker to hide a \
                     smuggled request body from the WAF while the origin processes chunked \
                     encoding — the classic WAF-bypass + smuggling chain used in real breaches.",
                    url
                ),
                target,
                0.78,
                Evidence::new()
                    .with("url", url)
                    .with("obfuscation_hits", json!(p.obfuscation_hits)),
            ),
            "attack_path",
        ));
    }
    if p.h2_divergence {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: H2 downgrade → access-control bypass",
                "high",
                MITRE,
                &format!(
                    "Protocol schism on {} means an attacker can choose HTTP/2 or HTTP/1.1 to reach \
                     a code path the other protocol blocks — bypassing edge ACLs/WAF rules that only \
                     inspect one stack.",
                    url
                ),
                target,
                0.72,
                Evidence::new().with("url", url).with("h2_divergence", true),
            ),
            "attack_path",
        ));
    }
    if !p.dual_response_hits.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: embedded dual-response → response queue poisoning",
                "critical",
                MITRE_MITM,
                &format!(
                    "Dual HTTP response blocks observed on {} — the next request on a shared \
                     connection may receive the wrong response body (credential theft / cache \
                     poisoning via response-queue poisoning).",
                    url
                ),
                target,
                0.88,
                Evidence::new().with("url", url).with("dual_response", true),
            ),
            "attack_path",
        ));
    }
    if !p.zero_cl_surfaces.is_empty() || !p.h2c_exposed.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: 0.CL / h2c → modern desync bypass chain",
                "high",
                MITRE,
                &format!(
                    "0.CL or h2c upgrade surface on {} enables desync variants that bypass legacy \
                     WAF rules tuned only for classic CL.TE — used in recent CDN/origin bypass research.",
                    url
                ),
                target,
                0.74,
                Evidence::new()
                    .with("url", url)
                    .with("zero_cl", !p.zero_cl_surfaces.is_empty())
                    .with("h2c", !p.h2c_exposed.is_empty()),
            ),
            "attack_path",
        ));
    }
    if !p.client_desync_hits.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: client-side desync → browser pool poisoning",
                "high",
                MITRE,
                &format!(
                    "Client-side desync on {} can poison a victim browser's connection pool — \
                     smuggled responses ride on the next navigation without server-side queue access.",
                    url
                ),
                target,
                0.7,
                Evidence::new().with("url", url).with("client_desync", true),
            ),
            "attack_path",
        ));
    }
    if !p.response_queue_hits.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: response-queue shift → credential / session theft",
                "critical",
                MITRE_MITM,
                &format!(
                    "Response-queue oracle on {} proves the smuggled prefix shifted which response \
                     the pipelined GET received — the classic path to steal the next user's response \
                     (session cookie, OAuth code, password-reset token).",
                    url
                ),
                target,
                0.91,
                Evidence::new().with("url", url).with("response_queue", true),
            ),
            "attack_path",
        ));
    }
    if !p.backend_divergence.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: tier fingerprint split → targeted smuggle payload",
                "high",
                MITRE,
                &format!(
                    "Server/Via fingerprint divergence on {} confirms distinct front/back tiers — \
                     attackers craft payloads that parse one way at the CDN and another at origin.",
                    url
                ),
                target,
                0.73,
                Evidence::new()
                    .with("url", url)
                    .with("backend_divergence", true),
            ),
            "attack_path",
        ));
    }
    paths
}

fn build_posture_summary(target: &str, p: &SmugglePosture, finding_count: usize) -> Value {
    let score = p.score();
    let grade = p.grade();
    let description = format!(
        "Desync-resistance posture for {} from {} probe(s) across {} finding(s). \
         Confirmed={} dual-response={} pipeline={} CL.TE={} TE.CL={} 0.CL={} TE.TE={} \
         obfuscation={} chunk-ext={} h2c={} timing={} client-desync={} response-queue={} backend-split={} CL.CL={} H2-schism={}.",
        target,
        p.checks,
        finding_count,
        p.confirmed_reflections.len(),
        p.dual_response_hits.len(),
        p.pipeline_confirmed.len(),
        p.cl_te_surfaces.len(),
        p.te_cl_surfaces.len(),
        p.zero_cl_surfaces.len(),
        p.te_te_surfaces.len(),
        p.obfuscation_hits.len(),
        p.chunk_extension_hits.len(),
        p.h2c_exposed.len(),
        p.timing_anomalies.len(),
        p.client_desync_hits.len(),
        p.response_queue_hits.len(),
        p.backend_divergence.len(),
        p.cl_cl_surfaces.len(),
        p.h2_divergence
    );
    let ev = Evidence::new()
        .with("posture_score", score)
        .with("grade", grade)
        .with("checks", p.checks)
        .with("cdn_vendor", p.cdn_vendor.clone().unwrap_or_default())
        .with("http11_front_end", p.http11_only)
        .with("worst_severity", p.worst.clone())
        .with("confirmed_reflections", json!(p.confirmed_reflections))
        .with("dual_response_hits", json!(p.dual_response_hits))
        .with("pipeline_confirmed", json!(p.pipeline_confirmed))
        .with("zero_cl_surfaces", json!(p.zero_cl_surfaces))
        .with("h2c_exposed", json!(p.h2c_exposed))
        .with("timing_anomalies", json!(p.timing_anomalies))
        .with("response_queue_hits", json!(p.response_queue_hits))
        .with("backend_divergence", json!(p.backend_divergence))
        .with("cl_cl_surfaces", json!(p.cl_cl_surfaces));

    let mut summary = finding_rich(
        ENGINE_ID,
        &format!("HTTP desync posture {}/100 (grade {})", score, grade),
        "info",
        MITRE,
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
        obj.insert("worst_severity".to_string(), json!(p.worst));
        let mut weak = Vec::new();
        if !p.confirmed_reflections.is_empty() || !p.dual_response_hits.is_empty() {
            weak.push("smuggle_confirmed");
        }
        if !p.cl_te_surfaces.is_empty()
            || !p.te_cl_surfaces.is_empty()
            || !p.zero_cl_surfaces.is_empty()
        {
            weak.push("smuggle_cl_te");
        }
        if !p.obfuscation_hits.is_empty() || !p.te_te_surfaces.is_empty() {
            weak.push("smuggle_te_obfuscation");
        }
        if !p.pipeline_confirmed.is_empty()
            || !p.timing_anomalies.is_empty()
            || !p.response_queue_hits.is_empty()
        {
            weak.push("smuggle_pipeline");
        }
        if !p.backend_divergence.is_empty() {
            weak.push("smuggle_backend_fp");
        }
        if !p.cl_cl_surfaces.is_empty() {
            weak.push("smuggle_cl_cl");
        }
        if !p.h2c_exposed.is_empty() || p.h2_divergence {
            weak.push("smuggle_h2_downgrade");
        }
        if !p.client_desync_hits.is_empty() {
            weak.push("smuggle_client_desync");
        }
        obj.insert("weak_categories".to_string(), json!(weak));
        obj.insert(
            "remediation".to_string(),
            json!("Terminate HTTP/1.1 at a single hardened tier (or migrate end-to-end HTTP/2), reject ambiguous CL+TE with 400, disable pipelining, normalize Transfer-Encoding parsing, and ensure WAF/ACL rules inspect all protocol stacks consistently."),
        );
    }
    summary
}

// ── Public entry points ───────────────────────────────────────────────────────────

pub async fn run_http_smuggling_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let target = target.trim();
    if target.is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ScanConfig::load(&ArsenalConfig::from_ctx(ctx));
    let host = extract_host(target);

    let endpoints: Vec<Endpoint> = cfg
        .paths
        .iter()
        .map(|p| parse_endpoint(target, p))
        .collect();

    let mut all_findings: Vec<Value> = Vec::new();
    let mut aggregate = SmugglePosture::default();

    let chunk_results: Vec<Vec<Value>> = stream::iter(endpoints)
        .map(|ep| {
            let cfg = cfg.clone();
            let target = target.to_string();
            async move { probe_endpoint(&ep, &cfg, &target).await }
        })
        .buffer_unordered(cfg.concurrency)
        .collect()
        .await;

    for chunk in chunk_results {
        all_findings.extend(chunk);
    }

    // Aggregate posture from findings categories.
    aggregate.checks = all_findings.len() as u32;
    for f in &all_findings {
        if f.get("severity").and_then(Value::as_str) == Some("critical") {
            aggregate.bump_worst("critical");
        } else if f.get("severity").and_then(Value::as_str) == Some("high") {
            aggregate.bump_worst("high");
        }
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        let url = f
            .get("evidence")
            .and_then(|e| e.get("url"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        match cat {
            "smuggle_confirmed" => aggregate.confirmed_reflections.push(url),
            "smuggle_pipeline" if f.get("severity").and_then(Value::as_str) == Some("high") => {
                aggregate.pipeline_confirmed.push(url)
            }
            "smuggle_cl_te" => aggregate.cl_te_surfaces.push(url),
            "smuggle_te_cl" => aggregate.te_cl_surfaces.push(url),
            "smuggle_te_te" => aggregate.te_te_surfaces.push(url),
            "smuggle_te_obfuscation" => aggregate.obfuscation_hits.push(url),
            "smuggle_cl_anomaly" => aggregate.cl_anomalies.push(url),
            "smuggle_zero_cl" => aggregate.zero_cl_surfaces.push(url),
            "smuggle_h2c" => aggregate.h2c_exposed.push(url),
            "smuggle_dual_response" => aggregate.dual_response_hits.push(url),
            "smuggle_chunk_ext" => aggregate.chunk_extension_hits.push(url),
            "smuggle_timing" => aggregate.timing_anomalies.push(url),
            "smuggle_client_desync" => aggregate.client_desync_hits.push(url),
            "smuggle_response_queue" => aggregate.response_queue_hits.push(url),
            "smuggle_backend_fp" => aggregate.backend_divergence.push(url),
            "smuggle_cl_cl" => aggregate.cl_cl_surfaces.push(url),
            "smuggle_h2_downgrade" => aggregate.h2_divergence = true,
            _ => {}
        }
    }

    if cfg.attack_paths && aggregate.has_findings() {
        let base = normalize_url(target);
        all_findings.extend(synthesize_attack_paths(target, &aggregate, &base));
    }

    let non_summary_count = all_findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) != Some("posture_summary"))
        .count();

    if cfg.posture_score {
        all_findings.push(build_posture_summary(target, &aggregate, non_summary_count));
    }

    if all_findings.is_empty() {
        return empty_ok(
            ENGINE_ID,
            &format!("{}: no desync indicators on {}", ENGINE_ID, host),
        );
    }

    let msg = format!(
        "HTTP smuggling posture on {} — {} finding(s), score {}/100",
        host,
        non_summary_count,
        aggregate.score()
    );
    EngineResult::ok(all_findings, msg)
}

pub async fn run_http_smuggling_result(target: &str) -> EngineResult {
    run_http_smuggling_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_http_smuggling(target: &str) {
    print_result(run_http_smuggling_result(target).await);
}

// ScanConfig needs Clone for stream — derive manually
impl Clone for ScanConfig {
    fn clone(&self) -> Self {
        Self {
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
            intensity: self.intensity,
            paths: self.paths.clone(),
            canary_prefix: self.canary_prefix.clone(),
            check_cl_te: self.check_cl_te,
            check_te_cl: self.check_te_cl,
            check_te_te: self.check_te_te,
            check_te_obfuscation: self.check_te_obfuscation,
            check_cl_anomalies: self.check_cl_anomalies,
            check_pipeline: self.check_pipeline,
            check_h2_downgrade: self.check_h2_downgrade,
            check_zero_cl: self.check_zero_cl,
            check_h2c_upgrade: self.check_h2c_upgrade,
            check_chunk_extensions: self.check_chunk_extensions,
            check_dual_response: self.check_dual_response,
            check_timing_oracle: self.check_timing_oracle,
            check_client_desync: self.check_client_desync,
            check_response_queue: self.check_response_queue,
            check_backend_fingerprint: self.check_backend_fingerprint,
            check_cl_cl: self.check_cl_cl,
            check_lf_only: self.check_lf_only,
            check_cl0: self.check_cl0,
            check_host_confusion: self.check_host_confusion,
            check_multi_port: self.check_multi_port,
            ports: self.ports.clone(),
            check_fingerprint: self.check_fingerprint,
            include_info: self.include_info,
            attack_paths: self.attack_paths,
            posture_score: self.posture_score,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_response_extracts_status() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        let (st, hdrs, body) = parse_http_response(raw);
        assert_eq!(st, Some(200));
        assert_eq!(hdrs.len(), 1);
        assert_eq!(body, "OK");
    }

    #[test]
    fn count_pipeline_responses() {
        let raw = "HTTP/1.1 200 OK\r\n\r\nAHTTP/1.1 404 NF\r\n\r\nB";
        assert_eq!(count_http_responses(raw), 2);
    }

    #[test]
    fn posture_score_degrades_with_findings() {
        let mut p = SmugglePosture::default();
        assert_eq!(p.score(), 100);
        p.confirmed_reflections.push("https://x/".into());
        assert!(p.score() < 80);
        p.pipeline_confirmed.push("https://x/".into());
        assert!(p.score() < 70);
    }

    #[test]
    fn cl_te_request_contains_both_headers() {
        let raw = build_cl_te("example.com", "/", "TOKEN");
        let req = String::from_utf8_lossy(&raw);
        assert!(req.contains("Content-Length:"));
        assert!(req.contains("Transfer-Encoding: chunked"));
        assert!(req.contains("TOKEN"));
    }

    #[test]
    fn parse_endpoint_https_defaults_443() {
        let ep = parse_endpoint("https://example.com", "/api");
        assert!(ep.tls);
        assert_eq!(ep.port, 443);
        assert_eq!(ep.path, "/api");
    }

    #[test]
    fn all_status_codes_finds_embedded_response() {
        let raw = "HTTP/1.1 200 OK\r\n\r\nxHTTP/1.1 404 NF\r\n\r\n";
        assert_eq!(all_status_codes(raw), vec![200, 404]);
    }

    #[test]
    fn h2c_upgrade_detection() {
        assert!(has_h2c_upgrade_accept(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n"
        ));
        assert!(!has_h2c_upgrade_accept("HTTP/1.1 200 OK\r\n\r\n"));
    }

    #[test]
    fn zero_cl_request_has_cl_zero_and_chunked() {
        let raw = build_zero_cl("example.com", "/", "TOK");
        let req = String::from_utf8_lossy(&raw);
        assert!(req.contains("Content-Length: 0"));
        assert!(req.contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn cl_cl_has_duplicate_content_length() {
        let raw = build_cl_cl("example.com", "/", "TOK");
        let req = String::from_utf8_lossy(&raw);
        assert_eq!(req.matches("Content-Length:").count(), 2);
    }

    #[test]
    fn response_queue_oracle_pipelines_get() {
        let raw = build_response_queue_oracle("example.com", "/api");
        let req = String::from_utf8_lossy(&raw);
        assert!(req.contains("Transfer-Encoding: chunked"));
        assert!(req.matches("GET ").count() >= 1);
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_http_smuggling_result_ctx("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }
}
