//! **Liminal Boundary Engine** — world-class protocol-stack fracture detection, agentless.
//!
//! Conventional scanners test URLs in isolation; real breaches exploit *invisible trust boundaries*
//! where the edge applies different routing, auth, caching, and inspection depending on protocol
//! (HTTP/1.1 vs HTTP/2 ALPN), cache-key dimensions (`Vary`, `Cookie`, `Accept-Language`,
//! `Accept-Encoding`), and "trusted" rewrite headers the reverse proxy forwards. Attackers cross
//! these liminal gaps daily — this engine probes them with **live traffic only**; zero simulated
//! findings.
//!
//! What it measures (every finding requires a real observed response):
//!   * **Protocol schism** — same URL over HTTP/1.1-only vs HTTP/2 (ALPN); flags status/body
//!     divergence (403 on h1 → 200 on h2 = auth bypass at the protocol boundary).
//!   * **Method schism** — GET vs OPTIONS/HEAD across protocol stacks; inconsistent method handling
//!     exposes shadow endpoints and ACL gaps.
//!   * **Cache Vary oracle** — content that changes with `Accept-Language`, `Cookie`, or
//!     `Accept-Encoding` but lacks correct `Vary` while publicly cacheable → session/content leak.
//!   * **Trusted-header rewrite** — `X-Original-URL` / `X-Rewrite-URL` / `X-Forwarded-Prefix` and
//!     IP-trust headers causing the edge to serve a different resource than the path suggests.
//!   * **Entropy divergence** — identical HTTP status but radically different response entropy
//!     across protocol stacks → shadow API tier / canary path exposure.
//!   * **Encoding schism** — gzip vs identity variants served without `Vary: Accept-Encoding`.
//!   * **Front-end fingerprint** — CDN/WAF/reverse-proxy vendor from baseline headers for context.
//!   * **Wiz-style attack-path synthesis** + quantified 0–100 liminal-boundary posture grade.
//!
//! Every knob (paths, sensitive paths, per-check toggles, intensity, thresholds, timeout,
//! concurrency) is GUI-driven via [`ArsenalConfig`] (`POST /api/command-center/scan` →
//! `EngineRunContext::job_params`).
//!
//! MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1557 (Adversary-in-the-Middle —
//! cache/session bleed chains).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, finding, header_value, http1_client, http2_client,
    http_get_with_headers, normalize_url, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

const ENGINE_ID: &str = "liminal_boundary";
const MITRE: &str = "T1190";
const MITRE_MITM: &str = "T1557";

const DEFAULT_PATHS: &[&str] = &["/", "/admin", "/api", "/api/v1", "/internal", "/dashboard"];
const DEFAULT_SENSITIVE: &[&str] = &[
    "/admin",
    "/api/admin",
    "/internal",
    "/manager",
    "/console",
    "/actuator",
    "/debug",
];
const DEFAULT_REWRITE_HEADERS: &[&str] = &[
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Prefix",
    "X-Original-Host",
    "X-Forwarded-Path",
];

// ── Configuration ───────────────────────────────────────────────────────────────

struct ScanConfig {
    timeout_ms: u64,
    concurrency: usize,
    intensity: Intensity,
    paths: Vec<String>,
    sensitive_paths: Vec<String>,
    rewrite_headers: Vec<String>,
    body_delta_ratio: f64,
    entropy_delta: f64,
    cookie_probe: String,
    check_protocol_schism: bool,
    check_method_schism: bool,
    check_cache_vary: bool,
    check_trusted_headers: bool,
    check_ip_trust_headers: bool,
    check_entropy_divergence: bool,
    check_encoding_schism: bool,
    check_fingerprint: bool,
    check_attack_paths: bool,
    check_posture_score: bool,
    include_info: bool,
    auth_headers: Vec<(String, String)>,
}

impl ScanConfig {
    fn load(cfg: &ArsenalConfig) -> Self {
        let intensity = cfg.intensity();
        let mut auth_headers = Vec::new();
        if let Some(h) = cfg.string("auth_header") {
            if let Some((k, v)) = h.split_once(':') {
                auth_headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        if let Some(tok) = cfg.string("bearer_token") {
            auth_headers.push((
                "Authorization".to_string(),
                format!("Bearer {}", tok.trim()),
            ));
        }
        if let Some(c) = cfg.string("cookies") {
            auth_headers.push(("Cookie".to_string(), c));
        }
        Self {
            timeout_ms: cfg.timeout_ms(6000),
            concurrency: cfg.concurrency().clamp(1, 24),
            intensity,
            paths: cfg.string_list_or("paths", DEFAULT_PATHS),
            sensitive_paths: cfg.string_list_or("sensitive_paths", DEFAULT_SENSITIVE),
            rewrite_headers: cfg.string_list_or("rewrite_headers", DEFAULT_REWRITE_HEADERS),
            body_delta_ratio: cfg
                .string("body_delta_ratio")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.15),
            entropy_delta: cfg
                .string("entropy_delta")
                .and_then(|s| s.parse().ok())
                .unwrap_or(2.0),
            cookie_probe: cfg.string_or("cookie_probe", "session=weissman-liminal-probe"),
            check_protocol_schism: cfg.bool_or("check_protocol_schism", true),
            check_method_schism: cfg.bool_or("check_method_schism", intensity != Intensity::Light),
            check_cache_vary: cfg.bool_or("check_cache_vary", true),
            check_trusted_headers: cfg.bool_or("check_trusted_headers", true),
            check_ip_trust_headers: cfg
                .bool_or("check_ip_trust_headers", intensity == Intensity::Aggressive),
            check_entropy_divergence: cfg.bool_or("check_entropy_divergence", true),
            check_encoding_schism: cfg
                .bool_or("check_encoding_schism", intensity != Intensity::Light),
            check_fingerprint: cfg.bool_or("check_fingerprint", true),
            check_attack_paths: cfg.bool_or("check_attack_paths", true),
            check_posture_score: cfg.bool_or("check_posture_score", true),
            include_info: cfg.bool_or("include_info_findings", true),
            auth_headers,
        }
    }
}

impl Clone for ScanConfig {
    fn clone(&self) -> Self {
        Self {
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
            intensity: self.intensity,
            paths: self.paths.clone(),
            sensitive_paths: self.sensitive_paths.clone(),
            rewrite_headers: self.rewrite_headers.clone(),
            body_delta_ratio: self.body_delta_ratio,
            entropy_delta: self.entropy_delta,
            cookie_probe: self.cookie_probe.clone(),
            check_protocol_schism: self.check_protocol_schism,
            check_method_schism: self.check_method_schism,
            check_cache_vary: self.check_cache_vary,
            check_trusted_headers: self.check_trusted_headers,
            check_ip_trust_headers: self.check_ip_trust_headers,
            check_entropy_divergence: self.check_entropy_divergence,
            check_encoding_schism: self.check_encoding_schism,
            check_fingerprint: self.check_fingerprint,
            check_attack_paths: self.check_attack_paths,
            check_posture_score: self.check_posture_score,
            include_info: self.include_info,
            auth_headers: self.auth_headers.clone(),
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────────

fn with_category(mut f: Value, category: &str) -> Value {
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!(category));
    }
    f
}

fn body_sha256(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data.bytes() {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn body_size_delta_ratio(a: &str, b: &str) -> f64 {
    let la = a.len().max(1) as f64;
    let lb = b.len().max(1) as f64;
    (la - lb).abs() / la.max(lb)
}

fn is_auth_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn is_auth_block(status: u16) -> bool {
    matches!(status, 401 | 403 | 405 | 406)
}

fn merge_headers(base: &[(String, String)], extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = base.to_vec();
    out.extend_from_slice(extra);
    out
}

fn header_pairs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

async fn get_with_merged(
    client: &reqwest::Client,
    url: &str,
    base: &[(String, String)],
    extra: &[(String, String)],
) -> Option<HttpProbe> {
    let merged = merge_headers(base, extra);
    let refs = header_pairs(&merged);
    http_get_with_headers(client, url, &refs).await
}

async fn options_probe(
    client: &reqwest::Client,
    url: &str,
    auth_headers: &[(String, String)],
) -> Option<HttpProbe> {
    let mut h = reqwest::header::HeaderMap::new();
    for (k, v) in auth_headers {
        if let (Ok(n), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            h.insert(n, val);
        }
    }
    let resp = client
        .request(reqwest::Method::OPTIONS, url)
        .headers(h)
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

async fn fetch_get(
    h1: &reqwest::Client,
    h2: &reqwest::Client,
    url: &str,
    extra: &[(String, String)],
) -> (Option<HttpProbe>, Option<HttpProbe>) {
    let refs = header_pairs(extra);
    let p1 = http_get_with_headers(h1, url, &refs).await;
    let p2 = http_get_with_headers(h2, url, &refs).await;
    (p1, p2)
}

fn fingerprint_edge(headers: &[(String, String)], body: &str) -> Option<(&'static str, String)> {
    let hm: std::collections::HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    let get = |k: &str| hm.get(&k.to_ascii_lowercase()).map(|s| s.as_str());
    let body_lc = body.to_ascii_lowercase();

    if get("cf-ray").is_some() || get("cf-mitigated").is_some() || body_lc.contains("cloudflare") {
        return Some((
            "Cloudflare",
            get("cf-ray").unwrap_or("cloudflare").to_string(),
        ));
    }
    if get("x-akamai-transformed").is_some() || body_lc.contains("akamai") {
        return Some(("Akamai", "akamai".to_string()));
    }
    if get("x-amzn-requestid").is_some() || get("x-amz-cf-id").is_some() {
        return Some(("AWS CloudFront/WAF", "aws".to_string()));
    }
    if get("x-fastly-request-id").is_some() {
        return Some((
            "Fastly",
            get("x-fastly-request-id").unwrap_or("fastly").to_string(),
        ));
    }
    if get("x-sucuri-id").is_some() {
        return Some(("Sucuri WAF", "sucuri".to_string()));
    }
    if get("x-iinfo").is_some() || body_lc.contains("incapsula") {
        return Some(("Imperva/Incapsula", "imperva".to_string()));
    }
    if let Some(s) = get("server") {
        if s.contains("nginx") {
            return Some(("nginx", s.to_string()));
        }
        if s.contains("envoy") {
            return Some(("Envoy", s.to_string()));
        }
    }
    None
}

// ── Posture accumulator ─────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct LiminalPosture {
    checks: u32,
    protocol_bypasses: Vec<String>,
    method_schisms: Vec<String>,
    cache_vary_gaps: Vec<String>,
    header_rewrites: Vec<String>,
    ip_trust_bypasses: Vec<String>,
    entropy_divergences: Vec<String>,
    encoding_schisms: Vec<String>,
    edge_vendor: Option<String>,
    worst: String,
}

impl LiminalPosture {
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

    fn absorb_finding(&mut self, category: &str, sev: &str, path: &str) {
        self.bump_worst(sev);
        match category {
            "boundary_protocol_bypass" => self.protocol_bypasses.push(path.to_string()),
            "boundary_method_schism" => self.method_schisms.push(path.to_string()),
            "boundary_cache_vary" => self.cache_vary_gaps.push(path.to_string()),
            "boundary_header_rewrite" => self.header_rewrites.push(path.to_string()),
            "boundary_ip_trust" => self.ip_trust_bypasses.push(path.to_string()),
            "boundary_entropy" => self.entropy_divergences.push(path.to_string()),
            "boundary_encoding" => self.encoding_schisms.push(path.to_string()),
            _ => {}
        }
    }

    fn score(&self) -> u32 {
        let mut s: i32 = 100;
        s -= (self.protocol_bypasses.len() as i32).min(4) * 22;
        s -= (self.method_schisms.len() as i32).min(4) * 12;
        s -= (self.cache_vary_gaps.len() as i32).min(4) * 14;
        s -= (self.header_rewrites.len() as i32).min(4) * 18;
        s -= (self.ip_trust_bypasses.len() as i32).min(3) * 16;
        s -= (self.entropy_divergences.len() as i32).min(4) * 8;
        s -= (self.encoding_schisms.len() as i32).min(3) * 10;
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
        !self.protocol_bypasses.is_empty()
            || !self.method_schisms.is_empty()
            || !self.cache_vary_gaps.is_empty()
            || !self.header_rewrites.is_empty()
            || !self.ip_trust_bypasses.is_empty()
            || !self.entropy_divergences.is_empty()
            || !self.encoding_schisms.is_empty()
    }
}

// ── Probe implementations ───────────────────────────────────────────────────────

struct ProbePair {
    path: String,
    h1: HttpProbe,
    h2: HttpProbe,
}

fn probe_protocol_schism(
    target: &str,
    pair: &ProbePair,
    cfg: &ScanConfig,
    posture: &mut LiminalPosture,
    findings: &mut Vec<Value>,
) {
    let h1 = &pair.h1;
    let h2 = &pair.h2;
    let h1_hash = body_sha256(&h1.body);
    let h2_hash = body_sha256(&h2.body);

    if is_auth_block(h1.status) && is_auth_success(h2.status) {
        let ev = Evidence::new()
            .with("path", &pair.path)
            .with("h1_status", h1.status)
            .with("h2_status", h2.status)
            .with("h1_body_sha256", &h1_hash[..16])
            .with("h2_body_sha256", &h2_hash[..16])
            .check("protocol_schism", true, "h1 blocked, h2 allowed");
        let f = with_category(
            finding_rich(
                ENGINE_ID,
                &format!(
                    "Protocol schism auth bypass on {} (HTTP/1.1 {} → HTTP/2 {})",
                    pair.path, h1.status, h2.status
                ),
                "critical",
                MITRE,
                &format!(
                    "Path {} on {} returns HTTP {} over HTTP/1.1 but HTTP {} over HTTP/2 (ALPN). \
                     The edge applies inconsistent access control across protocol stacks — a bypass \
                     class no commercial scanner tests systematically.",
                    pair.path, target, h1.status, h2.status
                ),
                target,
                0.92,
                ev,
            ),
            "boundary_protocol_bypass",
        );
        posture.absorb_finding("boundary_protocol_bypass", "critical", &pair.path);
        findings.push(f);
        return;
    }
    if is_auth_block(h2.status) && is_auth_success(h1.status) {
        let ev = Evidence::new()
            .with("path", &pair.path)
            .with("h1_status", h1.status)
            .with("h2_status", h2.status)
            .check("protocol_schism", true, "h2 blocked, h1 allowed");
        let f = with_category(
            finding_rich(
                ENGINE_ID,
                &format!(
                    "Protocol schism auth bypass on {} (HTTP/2 {} → HTTP/1.1 {})",
                    pair.path, h2.status, h1.status
                ),
                "critical",
                MITRE,
                &format!(
                    "Path {} on {} is blocked over HTTP/2 (HTTP {}) but accessible over HTTP/1.1 \
                     (HTTP {}). Attackers can choose the permissive protocol stack to bypass edge controls.",
                    pair.path, target, h2.status, h1.status
                ),
                target,
                0.9,
                ev,
            ),
            "boundary_protocol_bypass",
        );
        posture.absorb_finding("boundary_protocol_bypass", "critical", &pair.path);
        findings.push(f);
        return;
    }

    if cfg.check_entropy_divergence
        && is_auth_success(h1.status)
        && h1.status == h2.status
        && h1_hash != h2_hash
        && body_size_delta_ratio(&h1.body, &h2.body) > cfg.body_delta_ratio
    {
        let e1 = shannon_entropy(&h1.body);
        let e2 = shannon_entropy(&h2.body);
        let sev = if (e1 - e2).abs() > cfg.entropy_delta {
            "high"
        } else {
            "medium"
        };
        let ev = Evidence::new()
            .with("path", &pair.path)
            .with("h1_entropy", e1)
            .with("h2_entropy", e2)
            .with("h1_len", h1.body.len())
            .with("h2_len", h2.body.len())
            .check(
                "entropy_divergence",
                true,
                "bodies differ across ALPN stacks",
            );
        let f = with_category(
            finding_rich(
                ENGINE_ID,
                &format!(
                    "Protocol entropy divergence on {} (HTTP {} both stacks, different content)",
                    pair.path, h1.status
                ),
                sev,
                MITRE,
                &format!(
                    "Path {} returns HTTP {} on both HTTP/1.1 and HTTP/2 but response bodies differ \
                     (h1_len={} h2_len={} h1_entropy={:.2} h2_entropy={:.2}). Separate backend pools \
                     or canary deployments may be reachable only via one protocol.",
                    pair.path, h1.status, h1.body.len(), h2.body.len(), e1, e2
                ),
                target,
                0.78,
                ev,
            ),
            "boundary_entropy",
        );
        posture.absorb_finding("boundary_entropy", sev, &pair.path);
        findings.push(f);
    }
}

async fn probe_method_schism(
    target: &str,
    base: &str,
    path: &str,
    cfg: &ScanConfig,
    posture: &mut LiminalPosture,
    findings: &mut Vec<Value>,
) {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let h1c = http1_client().await;
    let h2c = http2_client().await;
    let refs = header_pairs(&cfg.auth_headers);

    let h1_get = http_get_with_headers(&h1c, &url, &refs).await;
    let h2_get = http_get_with_headers(&h2c, &url, &refs).await;
    let h1_opt = options_probe(&h1c, &url, &cfg.auth_headers).await;
    let h2_opt = options_probe(&h2c, &url, &cfg.auth_headers).await;

    if let (Some(get), Some(opt)) = (&h1_get, &h1_opt) {
        if is_auth_block(get.status) && is_auth_success(opt.status) {
            let ev = Evidence::new()
                .with("path", path)
                .with("get_status", get.status)
                .with("options_status", opt.status)
                .check(
                    "method_schism_h1",
                    true,
                    "OPTIONS allowed where GET blocked",
                );
            let f = with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!(
                        "Method schism on {} — OPTIONS {} vs GET {}",
                        path, opt.status, get.status
                    ),
                    "high",
                    MITRE,
                    &format!(
                        "On HTTP/1.1, GET {} returns HTTP {} but OPTIONS returns HTTP {}. \
                         Method-based ACL gaps expose shadow endpoints invisible to crawlers.",
                        url, get.status, opt.status
                    ),
                    target,
                    0.82,
                    ev,
                ),
                "boundary_method_schism",
            );
            posture.absorb_finding("boundary_method_schism", "high", path);
            findings.push(f);
        }
    }
    if let (Some(get), Some(opt)) = (&h2_get, &h2_opt) {
        if is_auth_block(get.status) && is_auth_success(opt.status) {
            let ev = Evidence::new()
                .with("path", path)
                .with("get_status", get.status)
                .with("options_status", opt.status)
                .check(
                    "method_schism_h2",
                    true,
                    "OPTIONS allowed where GET blocked on HTTP/2",
                );
            let f = with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!(
                        "HTTP/2 method schism on {} — OPTIONS {} vs GET {}",
                        path, opt.status, get.status
                    ),
                    "high",
                    MITRE,
                    &format!(
                        "On HTTP/2, GET {} returns HTTP {} but OPTIONS returns HTTP {}. \
                         Protocol-specific method ACL inconsistency.",
                        url, get.status, opt.status
                    ),
                    target,
                    0.8,
                    ev,
                ),
                "boundary_method_schism",
            );
            posture.absorb_finding("boundary_method_schism", "high", path);
            findings.push(f);
        }
    }
}

async fn probe_cache_vary_oracle(
    target: &str,
    base: &str,
    cfg: &ScanConfig,
    posture: &mut LiminalPosture,
    findings: &mut Vec<Value>,
) {
    let client = http1_client().await;
    let url = format!("{}/", base.trim_end_matches('/'));
    let baseline =
        match http_get_with_headers(&client, &url, &header_pairs(&cfg.auth_headers)).await {
            Some(p) => p,
            None => return,
        };

    let lang_a = get_with_merged(
        &client,
        &url,
        &cfg.auth_headers,
        &[("Accept-Language".to_string(), "en-US,en;q=0.9".to_string())],
    )
    .await;
    let lang_b = get_with_merged(
        &client,
        &url,
        &cfg.auth_headers,
        &[("Accept-Language".to_string(), "zh-CN,zh;q=0.9".to_string())],
    )
    .await;
    if let (Some(a), Some(b)) = (lang_a, lang_b) {
        let hash_a = body_sha256(&a.body);
        let hash_b = body_sha256(&b.body);
        if hash_a != hash_b && a.status == b.status && is_auth_success(a.status) {
            let cache_ctrl = header_value(&a.headers, "cache-control").unwrap_or("");
            let vary = header_value(&a.headers, "vary").unwrap_or("");
            let publicly_cacheable = cache_ctrl.contains("public")
                || cache_ctrl.contains("s-maxage")
                || (!cache_ctrl.contains("private") && !cache_ctrl.contains("no-store"));
            let vary_ok = vary.to_ascii_lowercase().contains("accept-language");
            if publicly_cacheable && !vary_ok {
                let ev = Evidence::new()
                    .with("url", &url)
                    .with("cache_control", cache_ctrl)
                    .with("vary", vary)
                    .check("accept_language_vary", false, "content varies without Vary");
                let f = with_category(
                    finding_rich(
                        ENGINE_ID,
                        "Cache Vary oracle — language-variant content publicly cacheable without Vary",
                        "high",
                        MITRE_MITM,
                        &format!(
                            "Responses at {} differ by Accept-Language but Cache-Control='{}' and \
                             Vary='{}'. A shared CDN cache may serve one user's language-specific \
                             content to another.",
                            url, cache_ctrl, vary
                        ),
                        target,
                        0.86,
                        ev,
                    ),
                    "boundary_cache_vary",
                );
                posture.absorb_finding("boundary_cache_vary", "high", "/");
                findings.push(f);
            }
        }
    }

    if let Some(with_cookie) = get_with_merged(
        &client,
        &url,
        &cfg.auth_headers,
        &[("Cookie".to_string(), cfg.cookie_probe.clone())],
    )
    .await
    {
        let base_hash = body_sha256(&baseline.body);
        let cookie_hash = body_sha256(&with_cookie.body);
        if base_hash != cookie_hash
            && baseline.status == with_cookie.status
            && is_auth_success(baseline.status)
        {
            let cache_ctrl = header_value(&baseline.headers, "cache-control").unwrap_or("");
            let vary = header_value(&baseline.headers, "vary").unwrap_or("");
            let publicly_cacheable = cache_ctrl.contains("public")
                || (!cache_ctrl.contains("private") && !cache_ctrl.contains("no-store"));
            let vary_ok = vary.to_ascii_lowercase().contains("cookie");
            if publicly_cacheable && !vary_ok {
                let ev = Evidence::new()
                    .with("url", &url)
                    .with("cache_control", cache_ctrl)
                    .check("cookie_vary", false, "cookie-variant content cacheable");
                let f = with_category(
                    finding_rich(
                        ENGINE_ID,
                        "Cache Vary oracle — cookie-variant content cacheable without Vary: Cookie",
                        "critical",
                        MITRE_MITM,
                        &format!(
                            "Homepage at {} returns different content with Cookie but lacks Vary: Cookie \
                             while publicly cacheable (Cache-Control='{}'). Authenticated fragments can \
                             be served to anonymous users via CDN.",
                            url, cache_ctrl
                        ),
                        target,
                        0.9,
                        ev,
                    ),
                    "boundary_cache_vary",
                );
                posture.absorb_finding("boundary_cache_vary", "critical", "/");
                findings.push(f);
            }
        }
    }

    if cfg.check_encoding_schism {
        let enc_a = get_with_merged(
            &client,
            &url,
            &cfg.auth_headers,
            &[("Accept-Encoding".to_string(), "gzip, deflate".to_string())],
        )
        .await;
        let enc_b = get_with_merged(
            &client,
            &url,
            &cfg.auth_headers,
            &[("Accept-Encoding".to_string(), "identity".to_string())],
        )
        .await;
        if let (Some(a), Some(b)) = (enc_a, enc_b) {
            if a.status == b.status
                && is_auth_success(a.status)
                && body_sha256(&a.body) != body_sha256(&b.body)
            {
                let vary = header_value(&a.headers, "vary").unwrap_or("");
                let cache_ctrl = header_value(&a.headers, "cache-control").unwrap_or("");
                let publicly_cacheable = !cache_ctrl.contains("no-store");
                let vary_ok = vary.to_ascii_lowercase().contains("accept-encoding");
                if publicly_cacheable && !vary_ok {
                    let ev = Evidence::new().with("url", &url).with("vary", vary).check(
                        "encoding_vary",
                        false,
                        "gzip vs identity without Vary",
                    );
                    let f = with_category(
                        finding_rich(
                            ENGINE_ID,
                            "Encoding schism — gzip vs identity cacheable without Vary: Accept-Encoding",
                            "high",
                            MITRE_MITM,
                            &format!(
                                "Responses at {} differ by Accept-Encoding (gzip vs identity) without \
                                 Vary: Accept-Encoding (Vary='{}'). BREACH-class cache-key fracture.",
                                url, vary
                            ),
                            target,
                            0.84,
                            ev,
                        ),
                        "boundary_encoding",
                    );
                    posture.absorb_finding("boundary_encoding", "high", "/");
                    findings.push(f);
                }
            }
        }
    }
}

async fn probe_trusted_header_rewrite(
    target: &str,
    base: &str,
    cfg: &ScanConfig,
    posture: &mut LiminalPosture,
    findings: &mut Vec<Value>,
) {
    let client = http1_client().await;
    let root_url = format!("{}/", base.trim_end_matches('/'));

    for path in &cfg.sensitive_paths {
        let direct_url = format!("{}{}", base.trim_end_matches('/'), path);
        let direct =
            match http_get_with_headers(&client, &direct_url, &header_pairs(&cfg.auth_headers))
                .await
            {
                Some(p) => p,
                None => continue,
            };

        for header in &cfg.rewrite_headers {
            if let Some(rewritten) = get_with_merged(
                &client,
                &root_url,
                &cfg.auth_headers,
                &[(header.clone(), path.clone())],
            )
            .await
            {
                let direct_hash = body_sha256(&direct.body);
                let rewrite_hash = body_sha256(&rewritten.body);
                if rewrite_hash == direct_hash
                    && is_auth_success(rewritten.status)
                    && is_auth_block(direct.status)
                {
                    let ev = Evidence::new()
                        .with("header", header)
                        .with("path", path)
                        .with("direct_status", direct.status)
                        .with("rewrite_status", rewritten.status)
                        .check(
                            "header_rewrite_bypass",
                            true,
                            "trusted header reached blocked path",
                        );
                    let f = with_category(
                        finding_rich(
                            ENGINE_ID,
                            &format!("Trusted-header rewrite bypass via {} → {}", header, path),
                            "critical",
                            MITRE,
                            &format!(
                                "GET {} returns HTTP {} but GET / with {}: {} returns HTTP {} with \
                                 identical body. The edge trusts {} for internal routing while the \
                                 direct path is blocked.",
                                direct_url, direct.status, header, path, rewritten.status, header
                            ),
                            target,
                            0.93,
                            ev,
                        ),
                        "boundary_header_rewrite",
                    );
                    posture.absorb_finding("boundary_header_rewrite", "critical", path);
                    findings.push(f);
                } else if rewrite_hash == direct_hash
                    && rewritten.status == direct.status
                    && is_auth_success(rewritten.status)
                    && direct.body.len() > 64
                {
                    let ev = Evidence::new()
                        .with("header", header)
                        .with("path", path)
                        .check(
                            "header_rewrite_expose",
                            true,
                            "internal path via rewrite header",
                        );
                    let f = with_category(
                        finding_rich(
                            ENGINE_ID,
                            &format!("Trusted-header {} exposes {}", header, path),
                            "high",
                            MITRE,
                            &format!(
                                "Header {}: {} on GET / returns the same content as GET {} (HTTP {}, \
                                 body_len={}). Internal paths reachable through header-based rewrite.",
                                header, path, path, rewritten.status, rewritten.body.len()
                            ),
                            target,
                            0.8,
                            ev,
                        ),
                        "boundary_header_rewrite",
                    );
                    posture.absorb_finding("boundary_header_rewrite", "high", path);
                    findings.push(f);
                }
            }
        }
    }
}

async fn probe_ip_trust_headers(
    target: &str,
    base: &str,
    path: &str,
    cfg: &ScanConfig,
    posture: &mut LiminalPosture,
    findings: &mut Vec<Value>,
) {
    let client = http1_client().await;
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let baseline =
        match http_get_with_headers(&client, &url, &header_pairs(&cfg.auth_headers)).await {
            Some(p) => p,
            None => return,
        };
    if !is_auth_block(baseline.status) {
        return;
    }

    for (header, value) in [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("Client-IP", "127.0.0.1"),
    ] {
        if let Some(probe) = get_with_merged(
            &client,
            &url,
            &cfg.auth_headers,
            &[(header.to_string(), value.to_string())],
        )
        .await
        {
            if is_auth_success(probe.status) && probe.status != baseline.status {
                let ev = Evidence::new()
                    .with("path", path)
                    .with("header", header)
                    .with("baseline_status", baseline.status)
                    .with("probe_status", probe.status)
                    .check("ip_trust_bypass", true, format!("{}: {}", header, value));
                let f = with_category(
                    finding_rich(
                        ENGINE_ID,
                        &format!("IP-trust header bypass via {} on {}", header, path),
                        "critical",
                        MITRE,
                        &format!(
                            "GET {} returns HTTP {} but HTTP {} with {}: {}. The application trusts \
                             client IP from a spoofable header — internal/admin ACL bypass.",
                            url, baseline.status, probe.status, header, value
                        ),
                        target,
                        0.88,
                        ev,
                    ),
                    "boundary_ip_trust",
                );
                posture.absorb_finding("boundary_ip_trust", "critical", path);
                findings.push(f);
            }
        }
    }
}

fn synthesize_attack_paths(target: &str, p: &LiminalPosture, url: &str) -> Vec<Value> {
    let mut paths = Vec::new();
    if !p.protocol_bypasses.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: protocol schism → WAF/ACL bypass → protected API",
                "critical",
                MITRE,
                &format!(
                    "Protocol schism on {} lets an attacker reach endpoints blocked on the inspected \
                     stack by switching ALPN negotiation (HTTP/1.1 ↔ HTTP/2) — bypassing edge WAF rules \
                     that only cover one protocol path.",
                    url
                ),
                target,
                0.9,
                Evidence::new()
                    .with("url", url)
                    .with("paths", json!(p.protocol_bypasses)),
            ),
            "attack_path",
        ));
    }
    if !p.cache_vary_gaps.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: cache Vary gap → session/account data bleed",
                "critical",
                MITRE_MITM,
                &format!(
                    "Missing Vary dimensions on {} allow a CDN to serve one user's cookie/language-specific \
                     response to another victim — account takeover via shared cache without touching the origin.",
                    url
                ),
                target,
                0.87,
                Evidence::new().with("url", url).with("vary_gaps", json!(p.cache_vary_gaps.len())),
            ),
            "attack_path",
        ));
    }
    if !p.header_rewrites.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: trusted-header rewrite → admin console access",
                "critical",
                MITRE,
                &format!(
                    "Trusted rewrite headers on {} reach internal/admin paths blocked by URL-only ACLs — \
                     invisible to crawlers and many WAF rule sets.",
                    url
                ),
                target,
                0.91,
                Evidence::new().with("url", url).with("rewrite_paths", json!(p.header_rewrites)),
            ),
            "attack_path",
        ));
    }
    if !p.ip_trust_bypasses.is_empty() {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: IP-trust header → internal admin bypass",
                "critical",
                MITRE,
                &format!(
                    "Spoofable IP-trust headers on {} bypass localhost/internal ACL checks — classic \
                     admin-panel bypass used in real-world breaches.",
                    url
                ),
                target,
                0.89,
                Evidence::new().with("url", url),
            ),
            "attack_path",
        ));
    }
    paths
}

fn build_posture_summary(target: &str, p: &LiminalPosture, finding_count: usize) -> Value {
    let score = p.score();
    let grade = p.grade();
    let description = format!(
        "Liminal-boundary posture for {} from {} probe(s) across {} finding(s). \
         Protocol bypasses={} method schisms={} cache Vary gaps={} header rewrites={} \
         IP-trust bypasses={} entropy divergences={} encoding schisms={}.",
        target,
        p.checks,
        finding_count,
        p.protocol_bypasses.len(),
        p.method_schisms.len(),
        p.cache_vary_gaps.len(),
        p.header_rewrites.len(),
        p.ip_trust_bypasses.len(),
        p.entropy_divergences.len(),
        p.encoding_schisms.len()
    );
    let ev = Evidence::new()
        .with("posture_score", score)
        .with("grade", grade)
        .with("checks", p.checks)
        .with("edge_vendor", p.edge_vendor.clone().unwrap_or_default())
        .with("worst_severity", p.worst.clone())
        .with("protocol_bypasses", json!(p.protocol_bypasses))
        .with("header_rewrites", json!(p.header_rewrites));

    let mut summary = finding_rich(
        ENGINE_ID,
        &format!("Liminal boundary posture {}/100 (grade {})", score, grade),
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
        obj.insert(
            "remediation".to_string(),
            json!("Unify WAF/auth rules across HTTP/1.1 and HTTP/2 (ALPN) paths; add correct Vary headers for every cache-key dimension (Cookie, Accept-Language, Accept-Encoding); strip or validate X-Original-URL / X-Rewrite-URL at the edge; never trust X-Forwarded-For / X-Real-IP for access control unless set by a trusted hop."),
        );
    }
    summary
}

async fn probe_path(
    base: &str,
    path: &str,
    target: &str,
    cfg: &ScanConfig,
    is_https: bool,
) -> (Vec<Value>, LiminalPosture) {
    let mut findings = Vec::new();
    let mut posture = LiminalPosture::default();
    posture.checks += 1;

    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let h1c = http1_client().await;
    let h2c = http2_client().await;

    if cfg.check_fingerprint && path == cfg.paths.first().map(String::as_str).unwrap_or("/") {
        if let Some(probe) =
            http_get_with_headers(&h1c, &url, &header_pairs(&cfg.auth_headers)).await
        {
            if let Some((vendor, ev)) = fingerprint_edge(&probe.headers, &probe.body) {
                posture.edge_vendor = Some(vendor.to_string());
                if cfg.include_info {
                    let f = with_category(
                        finding_rich(
                            ENGINE_ID,
                            &format!("Front-end fingerprint: {}", vendor),
                            "info",
                            MITRE,
                            &format!(
                                "Baseline GET {} identifies edge component '{}' (evidence: {}). \
                                 Context for interpreting protocol/cache boundary fractures.",
                                url, vendor, ev
                            ),
                            target,
                            0.95,
                            Evidence::new()
                                .with("url", &url)
                                .with("vendor", vendor)
                                .with("evidence", ev),
                        ),
                        "boundary_fingerprint",
                    );
                    findings.push(f);
                }
            }
        }
    }

    if is_https && cfg.check_protocol_schism {
        let refs = header_pairs(&cfg.auth_headers);
        if let (Some(h1), Some(h2)) = fetch_get(&h1c, &h2c, &url, &cfg.auth_headers).await {
            let pair = ProbePair {
                path: path.to_string(),
                h1,
                h2,
            };
            probe_protocol_schism(target, &pair, cfg, &mut posture, &mut findings);
        }
        let _ = refs;
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    if cfg.check_method_schism && is_https {
        probe_method_schism(target, base, path, cfg, &mut posture, &mut findings).await;
    }

    if cfg.check_ip_trust_headers {
        probe_ip_trust_headers(target, base, path, cfg, &mut posture, &mut findings).await;
    }

    if cfg.check_attack_paths && posture.has_findings() {
        findings.extend(synthesize_attack_paths(target, &posture, &url));
    }

    (findings, posture)
}

// ── Public entry points ───────────────────────────────────────────────────────────

pub async fn run_liminal_boundary_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let target = target.trim();
    if target.is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ScanConfig::load(&ArsenalConfig::from_ctx(ctx));
    let base = normalize_url(target);
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("invalid target host");
    }
    let is_https = base.starts_with("https://");

    let mut all_findings: Vec<Value> = Vec::new();
    let mut aggregate = LiminalPosture::default();

    let path_results: Vec<(Vec<Value>, LiminalPosture)> = stream::iter(cfg.paths.clone())
        .map(|path| {
            let base = base.clone();
            let target = target.to_string();
            let cfg = cfg.clone();
            async move { probe_path(&base, &path, &target, &cfg, is_https).await }
        })
        .buffer_unordered(cfg.concurrency)
        .collect()
        .await;

    for (mut chunk, mut p) in path_results {
        all_findings.append(&mut chunk);
        aggregate.checks += p.checks;
        aggregate.protocol_bypasses.append(&mut p.protocol_bypasses);
        aggregate.method_schisms.append(&mut p.method_schisms);
        aggregate.cache_vary_gaps.append(&mut p.cache_vary_gaps);
        aggregate.header_rewrites.append(&mut p.header_rewrites);
        aggregate.ip_trust_bypasses.append(&mut p.ip_trust_bypasses);
        aggregate
            .entropy_divergences
            .append(&mut p.entropy_divergences);
        aggregate.encoding_schisms.append(&mut p.encoding_schisms);
        if aggregate.edge_vendor.is_none() {
            aggregate.edge_vendor = p.edge_vendor;
        }
        aggregate.bump_worst(&p.worst);
    }

    // Site-wide probes (once per scan).
    if cfg.check_cache_vary {
        let mut vary_findings = Vec::new();
        let mut vary_posture = LiminalPosture::default();
        probe_cache_vary_oracle(target, &base, &cfg, &mut vary_posture, &mut vary_findings).await;
        all_findings.append(&mut vary_findings);
        aggregate
            .cache_vary_gaps
            .append(&mut vary_posture.cache_vary_gaps);
        aggregate
            .encoding_schisms
            .append(&mut vary_posture.encoding_schisms);
        aggregate.bump_worst(&vary_posture.worst);
    }

    if cfg.check_trusted_headers {
        let mut rewrite_findings = Vec::new();
        let mut rewrite_posture = LiminalPosture::default();
        probe_trusted_header_rewrite(
            target,
            &base,
            &cfg,
            &mut rewrite_posture,
            &mut rewrite_findings,
        )
        .await;
        all_findings.append(&mut rewrite_findings);
        aggregate
            .header_rewrites
            .append(&mut rewrite_posture.header_rewrites);
        aggregate.bump_worst(&rewrite_posture.worst);
    }

    if cfg.check_attack_paths && aggregate.has_findings() {
        all_findings.extend(synthesize_attack_paths(
            target,
            &aggregate,
            &format!("{}/", base.trim_end_matches('/')),
        ));
    }

    for f in &mut all_findings {
        if let Some(obj) = f.as_object_mut() {
            if !obj.contains_key("cwe") {
                obj.insert("cwe".into(), json!("CWE-693"));
            }
            if !obj.contains_key("remediation") {
                obj.insert(
                    "remediation".into(),
                    json!(crate::engine_probes::default_remediation(
                        ENGINE_ID,
                        obj.get("severity")
                            .and_then(|v| v.as_str())
                            .unwrap_or("medium")
                    )),
                );
            }
        }
    }

    if cfg.check_posture_score {
        let n = all_findings
            .iter()
            .filter(|f| f.get("summary") != Some(&json!(true)))
            .count();
        all_findings.insert(0, build_posture_summary(target, &aggregate, n));
    }

    if all_findings.is_empty()
        || all_findings
            .iter()
            .all(|f| f.get("summary") == Some(&json!(true)))
    {
        if all_findings.is_empty() {
            empty_ok(ENGINE_ID, target)
        } else {
            EngineResult::ok(
                all_findings,
                format!(
                    "liminal_boundary: no boundary fractures on {} (posture {}/100)",
                    host,
                    aggregate.score()
                ),
            )
        }
    } else {
        let n = all_findings
            .iter()
            .filter(|f| f.get("summary") != Some(&json!(true)))
            .count();
        EngineResult::ok(
            all_findings,
            format!(
                "liminal_boundary: {} live boundary fracture(s) on {} (posture {}/100 grade {})",
                n,
                host,
                aggregate.score(),
                aggregate.grade()
            ),
        )
    }
}

pub async fn run_liminal_boundary_result(target: &str) -> EngineResult {
    run_liminal_boundary_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_liminal_boundary(target: &str) {
    print_result(run_liminal_boundary_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_json_higher_than_repeated_char() {
        let json_body = r#"{"users":[{"id":1,"email":"a@b.c","role":"admin"}]}"#;
        let flat = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(shannon_entropy(json_body) > shannon_entropy(flat));
    }

    #[test]
    fn body_size_delta_detects_material_change() {
        assert!(body_size_delta_ratio("a", "abcdefghij") > 0.15);
        assert!(body_size_delta_ratio("same", "same") < 0.01);
    }

    #[test]
    fn auth_classifiers() {
        assert!(is_auth_block(403));
        assert!(is_auth_success(200));
    }

    #[test]
    fn posture_score_degrades_with_bypasses() {
        let mut p = LiminalPosture::default();
        p.protocol_bypasses.push("/admin".into());
        assert!(p.score() < 100);
        assert!(p.grade().len() == 1);
    }

    #[test]
    fn scan_config_defaults_from_empty_ctx() {
        let cfg = ScanConfig::load(&ArsenalConfig::from_value(json!({})));
        assert!(cfg.check_protocol_schism);
        assert!(!cfg.paths.is_empty());
    }
}
