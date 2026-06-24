//! Web Cache Poisoning & Deception Posture — agentless, real-probe only.
//!
//! A world-class, evidence-driven assessment of an origin/CDN edge's caching security, modelled on
//! the techniques pioneered by PortSwigger and the defensive posture grading offered by the big edge
//! providers (Cloudflare, Akamai, Fastly, Imperva, AWS CloudFront). Every check is **live and
//! read-only**, and — critically — every probe is isolated behind a **unique cache-buster query
//! parameter**, so a test can never poison the cache entry that real users hit. No finding is
//! fabricated: an issue is only reported when a real reflection / cached-unkeyed-input / deception
//! signal is actually observed.
//!
//! What it measures:
//!   * **Cache fingerprint** — detects the shared caching layer + CDN vendor and proves cacheability
//!     by observing a HIT/`Age` transition across two identical (cache-busted) requests.
//!   * **Unkeyed-input reflection** — sends a unique canary through a battery of unkeyed request
//!     headers (`X-Forwarded-Host`, `X-Host`, `Forwarded`, `X-Original-URL`, …) and detects the
//!     canary reflected into the body / `Location` / other response headers.
//!   * **Confirmed cache poisoning** — the decisive test: re-requests the *same* cache-busted URL
//!     **without** the header; if the canary persists, the input is provably *unkeyed and cached* —
//!     a real, exploitable web-cache-poisoning primitive.
//!   * **Web cache deception** — appends static-looking suffixes (`/x.css`, `;x.js`, …) to a dynamic
//!     path and detects when the dynamic response becomes cacheable, exposing other users' data.
//!   * **Cookie-keyed caching** — detects when a reflected cookie value is served from a shared cache.
//!   * **Hardening posture** — a weighted 0–100 score + grade summarising cache-key hygiene.
//!   * **Method confusion (GET/HEAD)** — proves the cache key ignores HTTP method so a poisoned GET
//!     poisons subsequent HEAD (Content-Length / HIT oracle).
//!   * **Fat GET poisoning** — GET requests carrying a body (many stacks key on URL only).
//!   * **Range-request poisoning** — `Range: bytes=…` responses cached and served to full GETs.
//!   * **Normalization oracle** — path/query normalization (`;`, `%2f`, `%2e%2e`) collapsing distinct
//!     URLs into one cache slot (PortSwigger-class cache-key fracture).
//!   * **Cache-key oracle** — discovers query-parameter dimensions excluded from the CDN cache key
//!     (prime poison on one param set, read on another — provable key fracture).
//!   * **HTTP/2 cache schism** — identical cache-busted URL returns different bodies over HTTP/1.1
//!     vs HTTP/2, proving protocol is excluded from the cache key (liminal boundary class).
//!   * **Accept-Encoding fracture** — gzip vs identity variants cacheable without `Vary: Accept-Encoding`.
//!   * **Method-override poisoning** — `X-HTTP-Method-Override` turns a GET into a POST body sink
//!     that may be unkeyed and cached.
//!   * **Authorization session bleed** — Bearer token changes response but lacks `Vary: Authorization`.
//!   * **Redirect cache poisoning** — poisoned `Location` on 3xx cached and served without the header.
//!   * **Query-order oracle** — parameter order normalization collapsing distinct URLs into one slot.
//!   * **CDN vs origin Cache-Control schism** — `CDN-Cache-Control` / `Surrogate-Control` overrides
//!     origin `no-store`, storing dynamic responses at the edge.
//!   * **User-Agent client-variant fracture** — mobile vs desktop bodies differ without `Vary: User-Agent`.
//!   * **Tracking-parameter cache-key oracle** — `utm_*`, `fbclid`, `gclid` stripped from CDN cache keys.
//!   * **Incomplete Vary header** — response varies on Cookie + Accept-Language but `Vary` omits a dimension.
//!   * **Stale-while-revalidate risk** — dynamic responses with `stale-while-revalidate` served from shared cache.
//!   * **Cache timing oracle** — repeat-request latency drop corroborates HIT (evidence-only, not a standalone finding).
//!   * **Sec-Fetch / Save-Data fractures** — client-hint dimensions cacheable without matching `Vary`.
//!   * **OPTIONS cache oracle** — OPTIONS response byte-identical to GET and stored in shared cache.
//!   * **Null-byte path normalization** — `%00` / `%2500` collapsing into the same cache slot.
//!   * **Cache surface intel** — CDN cache-key / surrogate-key / Via-chain leakage on responses.
//!   * **Risk matrix + CDN playbook** — vendor-specific hardening steps synthesized from live findings.
//!   * **RFC7239 Forwarded poisoning** — structured `host=…;proto=https` canary (distinct from flat Forwarded).
//!   * **Host-header override poisoning** — `Host:` differs from URL authority; reflection + cache confirm.
//!   * **Edge no-store bypass** — origin `Cache-Control: no-store` but CDN still serves HIT.
//!   * **Vary: * misconfiguration** — wildcard Vary combined with publicly cacheable shared responses.
//!   * **Parallel multi-path fan-out** — configurable `path_concurrency` for faster multi-endpoint coverage.
//!   * **Link header poisoning** — `Link: rel=canonical` host injection reflected + cache-confirmed.
//!   * **Duplicate query-parameter oracle** — repeated param names collapse into one cache slot.
//!   * **Accept-Language order fracture** — header value order changes body without `Vary`.
//!   * **If-None-Match / 304 amplifier** — poisoned ETag honored by shared cache on conditional GET.
//!   * **s-maxage vs max-age schism** — browser-private but CDN-public in one Cache-Control line.
//!   * **Defense controls map** — required CDN/origin controls synthesized from live findings.
//!   * **Brotli encoding fracture** — `br` vs identity without `Vary: Accept-Encoding`.
//!   * **Sec-CH-UA client-hint fracture** — UA client hints change body without `Vary`.
//!   * **X-Forwarded-Prefix path poisoning** — path-prefix injection reflected + cache-confirmed.
//!   * **Set-Cookie cache bleed** — `Set-Cookie` responses stored and served on cache HIT.
//!   * **Poison window intel** — max observed CDN TTL estimates attacker persistence window.
//!   * **Top primitives ranking** — confirmed/high findings ranked for operator triage.
//!   * **Compliance map** — CWE / OWASP / MITRE mapping from live findings.
//!   * **Final coverage (v10)** — stale-if-error, Sec-CH-Viewport, trailing-dot Host, protocol-relative
//!     redirect oracle, unicode overlong path normalization, finding dedupe, competitive coverage manifest.
//!
//! Every knob (paths, header set, per-check toggles, intensity, canary, deception extensions,
//! timeout, concurrency) is read from the live scan body (`job_params`) via [`ArsenalConfig`].

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{header_value, http_get_with_headers, HttpProbe};
use crate::engine_result::{print_result, EngineResult};
use futures::future::join_all;
use reqwest::Method;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ENGINE_ID: &str = "cache_poisoning";
const CB_PARAM: &str = "wzcb";
const DEFAULT_POISON_DOMAIN: &str = "poison.example";
const PROBE_CATEGORIES_TOTAL: usize = 55;

static HTTP_REQUESTS: AtomicU64 = AtomicU64::new(0);

// ── Unkeyed header catalogue (classified by the value the header expects) ─────
#[derive(Clone, Copy)]
enum HeaderKind {
    Host,
    Path,
    Proto,
    Port,
    Language,
    Ip,
}

struct UnkeyedHeader {
    name: &'static str,
    kind: HeaderKind,
    tier: u8, // 1=light, 2=normal, 3=aggressive
}

const UNKEYED_HEADERS: &[UnkeyedHeader] = &[
    UnkeyedHeader { name: "X-Forwarded-Host", kind: HeaderKind::Host, tier: 1 },
    UnkeyedHeader { name: "X-Host", kind: HeaderKind::Host, tier: 1 },
    UnkeyedHeader { name: "X-Forwarded-Scheme", kind: HeaderKind::Proto, tier: 1 },
    UnkeyedHeader { name: "X-Forwarded-Proto", kind: HeaderKind::Proto, tier: 1 },
    UnkeyedHeader { name: "X-Forwarded-Server", kind: HeaderKind::Host, tier: 2 },
    UnkeyedHeader { name: "X-Forwarded-Port", kind: HeaderKind::Port, tier: 2 },
    UnkeyedHeader { name: "Forwarded", kind: HeaderKind::Host, tier: 2 },
    UnkeyedHeader { name: "X-Original-URL", kind: HeaderKind::Path, tier: 2 },
    UnkeyedHeader { name: "X-Rewrite-URL", kind: HeaderKind::Path, tier: 2 },
    UnkeyedHeader { name: "X-HTTP-Host-Override", kind: HeaderKind::Host, tier: 2 },
    UnkeyedHeader { name: "X-Forwarded-Prefix", kind: HeaderKind::Path, tier: 2 },
    UnkeyedHeader { name: "X-Original-Host", kind: HeaderKind::Host, tier: 3 },
    UnkeyedHeader { name: "X-Backend-Host", kind: HeaderKind::Host, tier: 3 },
    UnkeyedHeader { name: "X-Forwarded-Path", kind: HeaderKind::Path, tier: 3 },
    UnkeyedHeader { name: "X-Forwarded-SSL", kind: HeaderKind::Proto, tier: 3 },
    UnkeyedHeader { name: "Accept-Language", kind: HeaderKind::Language, tier: 1 },
    UnkeyedHeader { name: "Accept-Encoding", kind: HeaderKind::Language, tier: 2 },
    UnkeyedHeader { name: "X-Forwarded-For", kind: HeaderKind::Ip, tier: 2 },
    UnkeyedHeader { name: "True-Client-IP", kind: HeaderKind::Ip, tier: 3 },
    UnkeyedHeader { name: "X-Real-IP", kind: HeaderKind::Ip, tier: 3 },
    UnkeyedHeader { name: "Origin", kind: HeaderKind::Host, tier: 2 },
    UnkeyedHeader { name: "Referer", kind: HeaderKind::Host, tier: 2 },
];

const DEFAULT_DECEPTION_EXTS: &[&str] = &["css", "js", "png", "ico", "txt", "json"];

/// Common marketing/tracking query params CDNs often exclude from cache keys.
const TRACKING_PARAMS: &[&str] = &["utm_source", "utm_medium", "fbclid", "gclid", "mc_eid", "ref"];

// ── Client + helpers ──────────────────────────────────────────────────────────

async fn build_client(timeout_ms: u64) -> reqwest::Client {
    build_client_with_http2(timeout_ms, true).await
}

async fn build_client_with_http2(timeout_ms: u64, http2: bool) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.clamp(1000, 30_000)))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-CachePosture/1.0")
        .redirect(reqwest::redirect::Policy::none());
    if http2 {
        b = b.http2_adaptive_window(true);
    } else {
        b = b.http1_only();
    }
    b.build().unwrap_or_else(|_| reqwest::Client::new())
}

fn base_url(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

/// Unique, low-collision token (hex of nanos + a process-wide counter).
fn token(prefix: &str) -> String {
    static C: AtomicU64 = AtomicU64::new(0);
    let n = C.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}{:x}{:x}", prefix, t, n)
}

/// Append a unique cache-buster so a probe never touches the real cache key.
fn with_buster(url: &str, cb: &str) -> String {
    if url.contains('?') {
        format!("{}&{}={}", url, CB_PARAM, cb)
    } else {
        format!("{}?{}={}", url, CB_PARAM, cb)
    }
}

#[derive(Clone, Debug, Default)]
struct CacheSignal {
    cacheable: bool,
    hit: bool,
    vendor: Option<String>,
    headers: Vec<String>,
}

fn detect_cache(probe: &HttpProbe) -> CacheSignal {
    let mut sig = CacheSignal::default();
    let geth = |n: &str| header_value(&probe.headers, n).map(|s| s.to_ascii_lowercase());

    if let Some(cf) = geth("cf-cache-status") {
        sig.cacheable = true;
        sig.vendor = Some("Cloudflare".to_string());
        sig.headers.push(format!("cf-cache-status: {}", cf));
        if matches!(cf.as_str(), "hit" | "expired" | "stale" | "revalidated" | "updating") {
            sig.hit = true;
        }
    }
    if header_value(&probe.headers, "x-amz-cf-id").is_some() {
        sig.cacheable = true;
        sig.vendor.get_or_insert_with(|| "AWS CloudFront".to_string());
    }
    if let Some(xc) = geth("x-cache") {
        sig.cacheable = true;
        sig.headers.push(format!("x-cache: {}", xc));
        if xc.contains("hit") {
            sig.hit = true;
        }
        if xc.contains("cloudfront") {
            sig.vendor.get_or_insert_with(|| "AWS CloudFront".to_string());
        }
    }
    if header_value(&probe.headers, "x-served-by").is_some()
        || header_value(&probe.headers, "x-timer").is_some()
    {
        sig.cacheable = true;
        sig.vendor.get_or_insert_with(|| "Fastly".to_string());
    }
    if let Some(v) = geth("x-varnish") {
        sig.cacheable = true;
        sig.vendor.get_or_insert_with(|| "Varnish".to_string());
        // Two space-separated IDs == cache hit.
        if v.split_whitespace().count() >= 2 {
            sig.hit = true;
        }
    }
    if header_value(&probe.headers, "x-akamai-transformed").is_some()
        || header_value(&probe.headers, "akamai-grn").is_some()
    {
        sig.cacheable = true;
        sig.vendor.get_or_insert_with(|| "Akamai".to_string());
    }
    if header_value(&probe.headers, "x-sucuri-id").is_some()
        || header_value(&probe.headers, "x-sucuri-cache").is_some()
    {
        sig.cacheable = true;
        sig.vendor.get_or_insert_with(|| "Sucuri".to_string());
    }
    if let Some(age) = header_value(&probe.headers, "age") {
        sig.cacheable = true;
        sig.headers.push(format!("age: {}", age));
        if age.trim().parse::<u64>().map(|a| a > 0).unwrap_or(false) {
            sig.hit = true;
        }
    }
    if let Some(xch) = geth("x-cache-hits") {
        sig.cacheable = true;
        if xch.trim().parse::<u64>().map(|h| h > 0).unwrap_or(false) {
            sig.hit = true;
        }
    }
    if header_value(&probe.headers, "x-drupal-cache").is_some()
        || header_value(&probe.headers, "x-litespeed-cache").is_some()
        || header_value(&probe.headers, "cdn-cache-control").is_some()
        || header_value(&probe.headers, "surrogate-key").is_some()
    {
        sig.cacheable = true;
    }
    if header_value(&probe.headers, "x-azure-ref").is_some() {
        sig.cacheable = true;
        sig.vendor.get_or_insert_with(|| "Azure Front Door".to_string());
    }
    if let Some(via) = geth("via") {
        if via.contains("google") {
            sig.cacheable = true;
            sig.vendor.get_or_insert_with(|| "Google Cloud CDN".to_string());
        }
    }
    if header_value(&probe.headers, "x-iinfo").is_some() {
        sig.cacheable = true;
        sig.vendor.get_or_insert_with(|| "Imperva".to_string());
    }
    if header_value(&probe.headers, "cdn-pullzone").is_some()
        || header_value(&probe.headers, "cdn-requestid").is_some()
    {
        sig.cacheable = true;
        sig.vendor.get_or_insert_with(|| "BunnyCDN".to_string());
    }
    if header_value(&probe.headers, "x-hw").is_some() {
        sig.cacheable = true;
        sig.vendor.get_or_insert_with(|| "StackPath".to_string());
    }
    if header_value(&probe.headers, "server").map(|s| s.contains("cloudflare")).unwrap_or(false)
        && sig.vendor.is_none()
    {
        sig.cacheable = true;
        sig.vendor = Some("Cloudflare".to_string());
    }
    sig
}

/// True when the canary token appears in the body or any response-header value.
fn reflects(probe: &HttpProbe, canary: &str) -> Option<&'static str> {
    if probe.body.contains(canary) {
        return Some("body");
    }
    for (k, v) in &probe.headers {
        if v.contains(canary) {
            // Map a few high-signal locations explicitly.
            return Some(match k.to_ascii_lowercase().as_str() {
                "location" => "Location header",
                "content-security-policy" => "CSP header",
                "link" => "Link header",
                "set-cookie" => "Set-Cookie header",
                _ => "response header",
            });
        }
    }
    None
}

fn sanitize_canary_domain(raw: &str) -> String {
    let s = raw.trim().trim_matches('.');
    if s.is_empty() || s.len() > 120 || s.contains(['/', ':', ' ', '@']) {
        return DEFAULT_POISON_DOMAIN.to_string();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        s.to_string()
    } else {
        DEFAULT_POISON_DOMAIN.to_string()
    }
}

fn header_value_for(kind: HeaderKind, canary: &str, domain: &str) -> String {
    match kind {
        HeaderKind::Host => format!("{canary}.{domain}"),
        HeaderKind::Path => format!("/{}", canary),
        HeaderKind::Proto => format!("http-{}", canary),
        HeaderKind::Port => format!("1337{}", canary),
        HeaderKind::Language => format!("wz-{},en;q=0.9", canary),
        HeaderKind::Ip => format!("127.0.0.1, {}", canary),
    }
}

/// Per-path scan context (clone-cheap via `Arc`) — carries operator-configured poison domain.
#[derive(Clone)]
struct PathEnv {
    poison_domain: Arc<str>,
}

impl PathEnv {
    fn from_cfg(cfg: &ArsenalConfig) -> Self {
        Self {
            poison_domain: Arc::from(sanitize_canary_domain(
                &cfg.string_or("canary_domain", DEFAULT_POISON_DOMAIN),
            )),
        }
    }

    fn header_value(&self, kind: HeaderKind, canary: &str) -> String {
        header_value_for(kind, canary, &self.poison_domain)
    }

    fn host_canary(&self, canary: &str) -> String {
        format!("{canary}.{}", self.poison_domain)
    }

    fn forwarded_rfc7239(&self, canary: &str) -> String {
        format!("host={};proto=https", self.host_canary(canary))
    }

    fn link_canonical(&self, canary: &str) -> String {
        format!("<https://{}/>; rel=\"canonical\"", self.host_canary(canary))
    }

    fn trailing_dot_host(&self, canary: &str) -> String {
        format!("{}.", self.host_canary(canary))
    }
}

fn body_sha256(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

fn is_publicly_cacheable(cache_control: &str) -> bool {
    let cc = cache_control.to_ascii_lowercase();
    cc.contains("public")
        || cc.contains("s-maxage")
        || (!cc.contains("private") && !cc.contains("no-store") && !cc.contains("no-cache"))
}

/// Parse the first `max-age=` / `s-maxage=` directive (seconds) from Cache-Control.
fn parse_cache_ttl_seconds(cache_control: &str) -> Option<u64> {
    let cc = cache_control.to_ascii_lowercase();
    for key in ["s-maxage=", "max-age="] {
        if let Some(idx) = cc.find(key) {
            let rest = &cc[idx + key.len()..];
            let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn s_maxage_browser_schism(cache_control: &str) -> bool {
    let cc = cache_control.to_ascii_lowercase();
    cc.contains("s-maxage")
        && (cc.contains("max-age=0")
            || cc.contains("private")
            || cc.contains("no-cache")
            || cc.contains("no-store"))
}

fn is_dynamic(probe: &HttpProbe) -> bool {
    let ctype = header_value(&probe.headers, "content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    ctype.contains("text/html")
        || header_value(&probe.headers, "set-cookie").is_some()
        || probe.body.to_ascii_lowercase().contains("csrf")
        || probe.body.to_ascii_lowercase().contains("logout")
}

/// Arbitrary HTTP verb with optional body — used for Fat GET, HEAD oracle, Range probes.
async fn http_custom(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    extra: &[(&str, &str)],
    body: Option<&str>,
) -> Option<HttpProbe> {
    let mut req = client.request(method, url);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    if let Some(b) = body {
        req = req
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(b.to_string());
    }
    let resp = req.send().await.ok()?;
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
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

/// Count every live HTTP probe for scan telemetry.
async fn tracked_get(
    client: &reqwest::Client,
    url: &str,
    extra: &[(&str, &str)],
) -> Option<HttpProbe> {
    HTTP_REQUESTS.fetch_add(1, Ordering::Relaxed);
    http_get_with_headers(client, url, extra).await
}

/// GET allowing duplicate header names (e.g. twin X-Forwarded-Host oracle).
async fn tracked_get_dup(
    client: &reqwest::Client,
    url: &str,
    headers: &[(&str, &str)],
) -> Option<HttpProbe> {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    HTTP_REQUESTS.fetch_add(1, Ordering::Relaxed);
    let mut map = HeaderMap::new();
    for (k, v) in headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            map.append(name, val);
        }
    }
    let resp = client.get(url).headers(map).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let hdrs: Vec<(String, String)> = resp
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
    Some(HttpProbe {
        status,
        headers: hdrs,
        body,
        final_url,
    })
}

async fn tracked_custom(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    extra: &[(&str, &str)],
    body: Option<&str>,
) -> Option<HttpProbe> {
    HTTP_REQUESTS.fetch_add(1, Ordering::Relaxed);
    http_custom(client, method, url, extra, body).await
}

fn poc_curl(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>) -> String {
    let mut parts = vec![format!("curl -sS -X {method} -D - -o /tmp/wz_body")];
    for (k, v) in headers {
        parts.push(format!("-H '{k}: {v}'"));
    }
    if let Some(b) = body {
        parts.push(format!("--data '{b}'"));
    }
    parts.push(format!("'{url}'"));
    parts.join(" ")
}

fn enrich_poc(f: &mut Value, poc: String) {
    if let Some(obj) = f.as_object_mut() {
        obj.insert("reproduction_hint".to_string(), json!(poc));
        if let Some(ev) = obj.get_mut("evidence").and_then(Value::as_object_mut) {
            ev.insert("poc_curl".to_string(), json!(poc));
        }
    }
}

/// Harvest same-origin relative paths from HTML for multi-path posture coverage.
fn discover_paths_from_html(body: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for chunk in body.split("href=\"").skip(1).chain(body.split("href='").skip(1)) {
        let path = chunk.split(['\"', '\'']).next().unwrap_or("").trim();
        if path.starts_with('/')
            && !path.starts_with("//")
            && path.len() > 1
            && path.len() < 120
            && !path.contains("..")
            && !path.contains('{')
        {
            let clean = path.split(['?', '#']).next().unwrap_or(path).to_string();
            if !clean.ends_with(".css")
                && !clean.ends_with(".js")
                && !clean.ends_with(".png")
                && !clean.ends_with(".jpg")
                && !clean.ends_with(".gif")
                && !clean.ends_with(".svg")
                && !clean.ends_with(".woff2")
            {
                out.insert(clean);
            }
        }
    }
    for chunk in body.split("action=\"").skip(1).chain(body.split("action='").skip(1)) {
        let path = chunk.split(['\"', '\'']).next().unwrap_or("").trim();
        if path.starts_with('/') && !path.starts_with("//") && path.len() > 1 && path.len() < 120 {
            let clean = path.split(['?', '#']).next().unwrap_or(path).to_string();
            out.insert(clean);
        }
    }
    for chunk in body.split("src=\"").skip(1).chain(body.split("src='").skip(1)) {
        let path = chunk.split(['\"', '\'']).next().unwrap_or("").trim();
        if path.starts_with('/') && !path.starts_with("//") && path.len() > 1 && path.len() < 120 {
            let clean = path.split(['?', '#']).next().unwrap_or(path).to_string();
            if !clean.contains('.') || clean.ends_with(".php") || clean.ends_with(".asp") {
                out.insert(clean);
            }
        }
    }
    out.into_iter().take(8).collect()
}

fn compute_beyond_score(posture_score: u32, exploitability: u32, dims: &Value) -> u32 {
    let dim_min = dims
        .as_object()
        .map(|o| {
            o.values()
                .filter_map(Value::as_u64)
                .min()
                .unwrap_or(100) as u32
        })
        .unwrap_or(100);
    posture_score
        .min(100u32.saturating_sub(exploitability))
        .min(dim_min)
}

fn content_length(probe: &HttpProbe) -> Option<usize> {
    header_value(&probe.headers, "content-length")
        .and_then(|s| s.trim().parse().ok())
}

/// Build alternate URL forms that CDNs/origins often collapse to the same cache key.
fn normalization_variants(url: &str, cb: &str) -> Vec<(String, &'static str)> {
    let busted = with_buster(url, cb);
    let trimmed = url.trim_end_matches('/');
    let mut out = vec![(busted.clone(), "baseline")];
    if let Some((base, query)) = busted.split_once('?') {
        out.push((format!("{}/?{}", base, query), "trailing_slash"));
        out.push((format!("{};%3bwz=1?{}", base, query), "semicolon_segment"));
        if !base.ends_with("%2f") {
            out.push((format!("{}%2f?{}", base, query), "encoded_slash"));
        }
    } else {
        out.push((format!("{}/", busted), "trailing_slash"));
    }
    // Path-only variants (no query) for directory-style targets.
    out.push((format!("{}/..%2f?{}={}", trimmed, CB_PARAM, cb), "dot_segment"));
    if let Some((base, query)) = busted.split_once('?') {
        out.push((format!("{}/%00?{}", base, query), "null_byte"));
        out.push((format!("{}/%2500?{}", base, query), "double_encoded_null"));
        out.push((format!("{}/%e0%80%af?{}", base, query), "unicode_overlong_slash"));
    }
    out
}

/// Append a secondary query dimension for cache-key oracle probes.
fn with_pad_param(url: &str, pad: &str) -> String {
    if url.contains('?') {
        format!("{}&wkpad={}", url, pad)
    } else {
        format!("{}?wkpad={}", url, pad)
    }
}

fn dimension_penalty(severity: &str) -> u32 {
    match severity {
        "critical" => 35,
        "high" => 18,
        "medium" => 8,
        "low" => 3,
        _ => 0,
    }
}

fn compute_posture_dimensions(findings: &[Value]) -> Value {
    let mut obj = serde_json::Map::new();
    for dim in [
        "unkeyed_inputs",
        "method_keying",
        "normalization",
        "session_isolation",
        "deception_resistance",
        "cache_key_integrity",
        "protocol_isolation",
        "auth_isolation",
        "client_variant_isolation",
    ] {
        obj.insert(dim.to_string(), json!(100));
    }
    let map: &[(&str, &[&str])] = &[
        ("unkeyed_inputs", &["cache_poisoning"]),
        ("method_keying", &["cache_method"]),
        ("normalization", &["cache_normalization", "cache_key_oracle"]),
        ("session_isolation", &["cookie_cache", "cache_hardening"]),
        ("deception_resistance", &["cache_deception"]),
        ("cache_key_integrity", &["cache_key_oracle", "cache_normalization"]),
        ("protocol_isolation", &["cache_protocol"]),
        ("auth_isolation", &["auth_cache", "redirect_cache"]),
        ("client_variant_isolation", &["cache_hardening", "cache_key_oracle"]),
    ];
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        let pen = dimension_penalty(sev);
        if pen == 0 {
            continue;
        }
        for (dim, cats) in map {
            if cats.contains(&cat) {
                let cur = obj.get(*dim).and_then(Value::as_u64).unwrap_or(100);
                obj.insert(dim.to_string(), json!(cur.saturating_sub(u64::from(pen)).max(5)));
            }
        }
    }
    Value::Object(obj)
}

fn build_hardening_roadmap(findings: &[Value]) -> Vec<String> {
    let mut steps: Vec<(u8, String)> = Vec::new();
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        if !matches!(sev, "critical" | "high") {
            continue;
        }
        if let Some(r) = f.get("remediation").and_then(Value::as_str) {
            let rank = severity_rank(sev);
            if !steps.iter().any(|(_, s)| s == r) {
                steps.push((rank, r.to_string()));
            }
        }
    }
    steps.sort_by(|a, b| b.0.cmp(&a.0));
    steps.into_iter().take(5).map(|(_, s)| s).collect()
}

// ── Finding builder + scoring ──────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cache_finding(
    target: &str,
    title: &str,
    severity: &str,
    description: &str,
    confidence: f64,
    category: &str,
    exposure: &str,
    remediation: &str,
    evidence: Evidence,
) -> Value {
    let mut f = finding_rich(ENGINE_ID, title, severity, "T1557", description, target, confidence, evidence);
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!(category));
        obj.insert("exposure".to_string(), json!(exposure));
        obj.insert("remediation".to_string(), json!(remediation));
        obj.insert(
            "controls".to_string(),
            json!(["OWASP-WSTG-INPV-19", "ISO27001:A.13.1", "CWE-525"]),
        );
    }
    f
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

// ── Probes ──────────────────────────────────────────────────────────────────

async fn probe_fingerprint(
    client: &reqwest::Client,
    url: &str,
    target: &str,
) -> (Vec<Value>, CacheSignal) {
    let mut out = Vec::new();
    let cb = token("fp");
    let busted = with_buster(url, &cb);
    let t0 = Instant::now();
    let first = tracked_get(client, &busted, &[]).await;
    let t1 = Instant::now();
    let second = tracked_get(client, &busted, &[]).await;
    let t2 = Instant::now();
    let ms_first = t1.duration_since(t0).as_millis();
    let ms_second = t2.duration_since(t1).as_millis();

    let mut sig = CacheSignal::default();
    if let Some(p) = &first {
        sig = detect_cache(p);
    }
    let mut hit_on_repeat = false;
    if let Some(p) = &second {
        let s2 = detect_cache(p);
        sig.cacheable |= s2.cacheable;
        if s2.hit {
            hit_on_repeat = true;
            sig.hit = true;
        }
        if sig.vendor.is_none() {
            sig.vendor = s2.vendor.clone();
        }
    }

    if !sig.cacheable {
        return (out, sig);
    }
    if let Some(p) = &first {
        out.extend(probe_cache_surface_intel(url, target, p, &sig));
    }
    let cc_first = first
        .as_ref()
        .and_then(|p| header_value(&p.headers, "cache-control"))
        .unwrap_or("");
    let ttl = parse_cache_ttl_seconds(cc_first);
    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("vendor", json!(sig.vendor.clone()))
        .with("cache_headers", json!(sig.headers.clone()))
        .with("hit_on_repeat", json!(hit_on_repeat))
        .with("latency_ms_first", json!(ms_first))
        .with("latency_ms_repeat", json!(ms_second))
        .with("cache_control", cc_first.to_string())
        .with("cache_ttl_seconds", json!(ttl))
        .check("shared_cache_detected", true, sig.headers.join("; "))
        .check("cache_hit_observed", sig.hit, if hit_on_repeat { "repeat request served from cache" } else { "no explicit HIT marker" })
        .check(
            "timing_oracle_repeat_faster",
            sig.hit && ms_second.saturating_add(50) < ms_first,
            format!("first={}ms repeat={}ms", ms_first, ms_second),
        );
    let vendor = sig.vendor.clone().unwrap_or_else(|| "unidentified".to_string());
    out.push(cache_finding(
        target,
        &format!("Shared cache / CDN layer detected ({vendor})"),
        "info",
        &format!(
            "A shared caching layer ({vendor}) was observed in front of {url}. Cached responses are shared across users, so any unkeyed input that influences a cached response is a poisoning primitive."
        ),
        0.85,
        "cache_fingerprint",
        "present",
        "Audit the cache key: ensure every request input that affects the response is part of the key (Vary / cache-key configuration). Strip untrusted X-Forwarded-* headers at the edge.",
        ev,
    ));
    (out, sig)
}

#[allow(clippy::too_many_arguments)]
async fn probe_single_unkeyed_header(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    hname: &str,
    hkind: HeaderKind,
    base_sig: &CacheSignal,
) -> Option<Value> {
    let cb = token("uk");
    let canary = token("wzc");
    let val = env.header_value(hkind, &canary);
    let busted = with_buster(url, &cb);

    let p1 = tracked_get(client, &busted, &[(hname, val.as_str())]).await?;
    let loc = reflects(&p1, &canary)?;
    let sig1 = detect_cache(&p1);
    let cacheable = sig1.cacheable || base_sig.cacheable;

    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }

    let (severity, exposure, conf, title, desc) = if confirmed {
        (
            "critical",
            "confirmed",
            0.95,
            format!("Confirmed web cache poisoning via unkeyed '{}'", hname),
            format!(
                "The '{}' header is unkeyed and its value was cached: a follow-up request without the header still returned the injected canary (reflected in the {}). An attacker can poison the shared cache for every user of {}.",
                hname, loc, url
            ),
        )
    } else {
        (
            "high",
            "reflected",
            0.7,
            format!("Unkeyed '{}' reflected into a cacheable response", hname),
            format!(
                "The '{}' header value was reflected in the {} of the response from {}. {} If this response is cached, the reflection becomes a cache-poisoning vector.",
                hname, loc, url,
                if cacheable { "A shared cache is present." } else { "No cache HIT was confirmed on this path." }
            ),
        )
    };

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("header", hname.to_string())
        .with("injected_value", val.clone())
        .with("canary", canary.clone())
        .with("reflection_location", loc)
        .with("cacheable", json!(cacheable))
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("reflection", true, format!("canary observed in {}", loc))
        .check("unkeyed_and_cached", confirmed, if confirmed { "header-less repeat still reflected canary" } else { "not confirmed cached" });

    let mut finding = cache_finding(
        target, &title, severity, &desc, conf, "cache_poisoning", exposure,
        "Add the reflected header to the cache key or strip it at the edge before caching. Never reflect X-Forwarded-* / Forwarded values into responses; build absolute URLs from a trusted, configured host.",
        ev,
    );
    if confirmed {
        enrich_poc(
            &mut finding,
            poc_curl("GET", &busted, &[(hname, val.as_str())], None),
        );
    }
    Some(finding)
}

#[allow(clippy::too_many_arguments)]
async fn probe_unkeyed_headers(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    headers: &[(String, HeaderKind)],
    base_sig: &CacheSignal,
    concurrency: usize,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let fanout = concurrency.clamp(1, 16);
    for chunk in headers.chunks(fanout) {
        let futs: Vec<_> = chunk
            .iter()
            .map(|(hname, hkind)| {
                probe_single_unkeyed_header(client, url, target, env, hname, *hkind, base_sig)
            })
            .collect();
        for opt in join_all(futs).await {
            if let Some(f) = opt {
                findings.push(f);
            }
        }
    }
    findings
}

async fn probe_deception(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    exts: &[String],
) -> Vec<Value> {
    let mut findings = Vec::new();
    // Baseline: is the page dynamic (sets cookies / returns HTML) and NOT already cached?
    let cb0 = token("dcb");
    let Some(base_probe) = tracked_get(client, &with_buster(url, &cb0), &[]).await else {
        return findings;
    };
    let dynamic = is_dynamic(&base_probe);
    if !dynamic {
        return findings;
    }

    for ext in exts.iter().take(6) {
        let marker = token("wzd");
        // Path-confusion variants that many caches treat as a static asset.
        let variants = [
            format!("{}/{}.{}", url.trim_end_matches('/'), marker, ext),
            format!("{}/%2e%2e/{}.{}", url.trim_end_matches('/'), marker, ext),
            format!("{};{}.{}", url.trim_end_matches('/'), marker, ext),
        ];
        for v in variants {
            let cb = token("dc");
            let busted = with_buster(&v, &cb);
            let Some(p1) = tracked_get(client, &busted, &[]).await else {
                continue;
            };
            if p1.status != 200 {
                continue;
            }
            let p1_dynamic = header_value(&p1.headers, "content-type")
                .map(|c| c.to_ascii_lowercase().contains("text/html"))
                .unwrap_or(false)
                || header_value(&p1.headers, "set-cookie").is_some();
            if !p1_dynamic {
                continue;
            }
            // Cached? repeat and look for a HIT/Age.
            let sig = detect_cache(&p1);
            let cached = if sig.hit {
                true
            } else if let Some(p2) = tracked_get(client, &busted, &[]).await {
                detect_cache(&p2).hit
            } else {
                false
            };
            if cached || sig.cacheable {
                let ev = Evidence::new()
                    .with("url", url.to_string())
                    .with("deception_url", v.clone())
                    .with("status", json!(p1.status))
                    .with("dynamic_response", json!(true))
                    .with("vendor", json!(sig.vendor.clone()))
                    .check("static_suffix_cached", cached, format!("variant .{} cached={}", ext, cached));
                let sev = if cached { "high" } else { "medium" };
                findings.push(cache_finding(
                    target,
                    &format!("Web cache deception: dynamic page cached under a .{} suffix", ext),
                    sev,
                    &format!(
                        "Appending a static-looking suffix turned the dynamic page {} into a cacheable response ({}). An attacker can trick a victim into priming the cache with their authenticated page, then read the cached copy — leaking session data.",
                        url, v
                    ),
                    if cached { 0.8 } else { 0.55 },
                    "cache_deception",
                    if cached { "confirmed" } else { "suspected" },
                    "Configure the cache to only store responses for genuinely static content (match on real Content-Type, not URL suffix). Add Cache-Control: no-store to authenticated/dynamic responses and normalise path traversal at the edge.",
                    ev,
                ));
                return findings; // one solid deception signal per path is enough
            }
        }
    }
    findings
}

async fn probe_query_unkeyed(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
    param_name: &str,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("qu");
    let canary = token("wzq");
    let busted = with_buster(url, &cb);
    let param_url = if busted.contains('?') {
        format!("{}&{}={}", busted, param_name, canary)
    } else {
        format!("{}?{}={}", busted, param_name, canary)
    };

    let Some(p1) = tracked_get(client, &param_url, &[]).await else {
        return findings;
    };
    let Some(loc) = reflects(&p1, &canary) else {
        return findings;
    };
    let sig1 = detect_cache(&p1);
    let cacheable = sig1.cacheable || base_sig.cacheable;

    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }

    let (severity, exposure, conf, title) = if confirmed {
        (
            "critical",
            "confirmed",
            0.92,
            "Confirmed web cache poisoning via unkeyed query parameter",
        )
    } else {
        (
            "high",
            "reflected",
            0.68,
            "Unkeyed query parameter reflected into a cacheable response",
        )
    };

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("parameter", param_name.to_string())
        .with("canary", canary.clone())
        .with("reflection_location", loc)
        .with("cacheable", json!(cacheable))
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("reflection", true, format!("canary observed in {}", loc))
        .check(
            "unkeyed_and_cached",
            confirmed,
            if confirmed {
                "param-less repeat still reflected canary"
            } else {
                "not confirmed cached"
            },
        );

    findings.push(cache_finding(
        target,
        title,
        severity,
        &format!(
            "The query parameter value was reflected in the {} of {}. {} An attacker can inject a malicious query string, prime the shared cache, and serve the poisoned response to other users.",
            loc,
            url,
            if confirmed {
                "A follow-up request without the parameter still returned the injected canary — the parameter is provably unkeyed and cached."
            } else if cacheable {
                "A shared cache is present; if this response is stored, the reflection becomes a poisoning vector."
            } else {
                "No cache HIT was confirmed on this path."
            }
        ),
        conf,
        "cache_poisoning",
        exposure,
        "Include every query parameter that affects the response in the cache key, or strip/ignore untrusted parameters before caching. Set Cache-Control: no-store on dynamic responses.",
        ev,
    ));
    findings
}

async fn probe_cookie_cache(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("ck");
    let canary = token("wzk");
    let busted = with_buster(url, &cb);
    let cookie_val = format!("wzcanary={}", canary);

    let Some(baseline) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let Some(with_cookie) =
        tracked_get(client, &busted, &[("Cookie", cookie_val.as_str())]).await
    else {
        return findings;
    };

    let base_hash = body_sha256(&baseline.body);
    let cookie_hash = body_sha256(&with_cookie.body);
    let cookie_reflects = reflects(&with_cookie, &canary).is_some();
    if base_hash == cookie_hash && !cookie_reflects {
        return findings;
    }

    let sig = detect_cache(&with_cookie);
    let cacheable = sig.cacheable || base_sig.cacheable;

    // Real poisoning proof: cookie-flavoured response is served on a cookie-less repeat.
    let mut confirmed = false;
    if cacheable {
        if let Some(repeat) = tracked_get(client, &busted, &[]).await {
            let repeat_hash = body_sha256(&repeat.body);
            if (repeat_hash == cookie_hash || reflects(&repeat, &canary).is_some())
                && repeat_hash != base_hash
            {
                let repeat_sig = detect_cache(&repeat);
                if repeat_sig.hit || repeat_sig.cacheable {
                    confirmed = true;
                }
            }
        }
    }

    let cache_ctrl = header_value(&with_cookie.headers, "cache-control").unwrap_or("");
    let vary = header_value(&with_cookie.headers, "vary").unwrap_or("");
    let vary_ok = vary.to_ascii_lowercase().contains("cookie");
    let publicly_cacheable = is_publicly_cacheable(cache_ctrl);

    let (severity, exposure, conf, title) = if confirmed {
        (
            "critical",
            "confirmed",
            0.94,
            "Confirmed cookie-unkeyed response cached and served without Cookie",
        )
    } else if publicly_cacheable && !vary_ok && cacheable {
        (
            "high",
            "suspected",
            0.78,
            "Cookie-variant response is publicly cacheable without Vary: Cookie",
        )
    } else {
        (
            "medium",
            "variant",
            0.62,
            "Response varies by Cookie header on a cacheable path",
        )
    };

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("cookie", cookie_val.clone())
        .with("baseline_body_sha256", base_hash.clone())
        .with("cookie_body_sha256", cookie_hash.clone())
        .with("cache_control", cache_ctrl.to_string())
        .with("vary", vary.to_string())
        .with("cacheable", json!(cacheable))
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("content_varies_by_cookie", true, format!("{} vs {}", &base_hash[..12], &cookie_hash[..12]))
        .check("vary_includes_cookie", vary_ok, vary)
        .check(
            "cookieless_repeat_got_cookie_response",
            confirmed,
            if confirmed {
                "cookie-less repeat matched cookie response"
            } else {
                "not confirmed"
            },
        );

    findings.push(cache_finding(
        target,
        title,
        severity,
        &format!(
            "Requests to {} return different content when Cookie is present (body sha256 {} vs {}). Cache-Control='{}', Vary='{}'. {} Authenticated or session-specific fragments can be stored in a shared cache and served to users who did not send the cookie.",
            url,
            &base_hash[..12],
            &cookie_hash[..12],
            cache_ctrl,
            vary,
            if confirmed {
                "A cookie-less repeat request received the cookie-specific response — provable cache-key fracture."
            } else if publicly_cacheable && !vary_ok {
                "The response is publicly cacheable but does not vary on Cookie."
            } else {
                "Content personalization via Cookie was observed on a cacheable path."
            }
        ),
        conf,
        "cookie_cache",
        exposure,
        "Add Vary: Cookie (or exclude Cookie from cache eligibility). Set Cache-Control: private or no-store on any response that depends on session cookies. Never cache HTML that changes based on Cookie unless the cache key includes it.",
        ev,
    ));
    findings
}

async fn probe_cache_hardening(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("hd");
    let busted = with_buster(url, &cb);

    let Some(baseline) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let sig = detect_cache(&baseline);
    let cacheable = sig.cacheable || base_sig.cacheable;
    if !cacheable {
        return findings;
    }

    let cache_ctrl = header_value(&baseline.headers, "cache-control").unwrap_or("");
    let vary = header_value(&baseline.headers, "vary").unwrap_or("");
    let dynamic = is_dynamic(&baseline);

    // Dynamic HTML / Set-Cookie responses should not be stored in a shared cache.
    if dynamic && is_publicly_cacheable(cache_ctrl) && !cache_ctrl.to_ascii_lowercase().contains("no-store") {
        let ev = Evidence::new()
            .with("url", url.to_string())
            .with("cache_control", cache_ctrl.to_string())
            .with("vary", vary.to_string())
            .with("vendor", json!(sig.vendor.clone()))
            .check("dynamic_response", true, "HTML/Set-Cookie/csrf markers")
            .check("shared_cache", true, sig.headers.join("; "))
            .check("missing_no_store", true, cache_ctrl);
        findings.push(cache_finding(
            target,
            "Dynamic response publicly cacheable without Cache-Control: no-store",
            "high",
            &format!(
                "The dynamic page at {} is served through a shared cache ({}) with Cache-Control='{}'. Session-specific or HTML responses should carry no-store/private to prevent cross-user cache bleed.",
                url,
                sig.vendor.as_deref().unwrap_or("CDN"),
                cache_ctrl
            ),
            0.82,
            "cache_hardening",
            "present",
            "Set Cache-Control: no-store (or private) on every dynamic/authenticated response. Configure the CDN to respect origin Cache-Control and bypass cache for Set-Cookie responses.",
            ev,
        ));
    }

    // Accept-Language dimension — only report when bodies actually differ.
    let lang_a = tracked_get(
        client,
        &busted,
        &[("Accept-Language", "en-US,en;q=0.9")],
    )
    .await;
    let lang_b = tracked_get(
        client,
        &busted,
        &[("Accept-Language", "zh-CN,zh;q=0.9")],
    )
    .await;
    if let (Some(a), Some(b)) = (lang_a, lang_b) {
        let hash_a = body_sha256(&a.body);
        let hash_b = body_sha256(&b.body);
        if hash_a != hash_b && a.status == b.status {
            let cc = header_value(&a.headers, "cache-control").unwrap_or("");
            let vary_a = header_value(&a.headers, "vary").unwrap_or("");
            let vary_ok = vary_a.to_ascii_lowercase().contains("accept-language");
            if is_publicly_cacheable(cc) && !vary_ok {
                let ev = Evidence::new()
                    .with("url", url.to_string())
                    .with("body_sha256_en", hash_a.clone())
                    .with("body_sha256_zh", hash_b.clone())
                    .with("cache_control", cc.to_string())
                    .with("vary", vary_a.to_string())
                    .check("accept_language_changes_body", true, format!("{} vs {}", &hash_a[..12], &hash_b[..12]))
                    .check("vary_includes_accept_language", vary_ok, vary_a);
                findings.push(cache_finding(
                    target,
                    "Accept-Language variant content cacheable without Vary: Accept-Language",
                    "high",
                    &format!(
                        "Responses at {} differ by Accept-Language (sha256 {} vs {}) but Cache-Control='{}' and Vary='{}'. One user's language-specific page can be served from the shared cache to another user.",
                        url,
                        &hash_a[..12],
                        &hash_b[..12],
                        cc,
                        vary_a
                    ),
                    0.8,
                    "cache_hardening",
                    "suspected",
                    "Add Vary: Accept-Language to every cacheable response that localises content, or disable caching for localised pages.",
                    ev,
                ));
            }
        }
    }

    findings
}

async fn probe_fat_get(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("fg");
    let canary = token("wzf");
    let busted = with_buster(url, &cb);
    let body = format!("wzcanary={}&probe=fat_get", canary);

    let Some(p1) = tracked_custom(client, Method::GET, &busted, &[], Some(&body)).await else {
        return findings;
    };
    let Some(loc) = reflects(&p1, &canary) else {
        return findings;
    };
    let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;

    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }

    let (severity, exposure, conf, title) = if confirmed {
        (
            "critical",
            "confirmed",
            0.93,
            "Confirmed web cache poisoning via Fat GET (unkeyed request body)",
        )
    } else {
        (
            "high",
            "reflected",
            0.72,
            "Fat GET body reflected into a cacheable response",
        )
    };

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("method", "GET")
        .with("request_body", body.clone())
        .with("canary", canary.clone())
        .with("reflection_location", loc)
        .with("cacheable", json!(cacheable))
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("fat_get_reflection", true, format!("canary in {}", loc))
        .check(
            "bodyless_repeat_still_poisoned",
            confirmed,
            if confirmed {
                "GET without body still reflected canary"
            } else {
                "not confirmed"
            },
        );

    findings.push(cache_finding(
        target,
        title,
        severity,
        &format!(
            "A GET request to {} with a body containing the canary was reflected in the {}. {} Many reverse proxies and CDNs do not include the request body in the cache key — a classic Fat GET poisoning primitive.",
            url,
            loc,
            if confirmed {
                "A follow-up bodyless GET returned the same canary — provably unkeyed and cached."
            } else if cacheable {
                "A shared cache is present; if this response is stored, bodyless GETs from other users receive the poison."
            } else {
                "No cache HIT was confirmed on this path."
            }
        ),
        conf,
        "cache_method",
        exposure,
        "Reject GET requests with a body at the edge, or include the body hash in the cache key. Never reflect request-body parameters into cacheable responses.",
        ev,
    ));
    findings
}

async fn probe_method_confusion(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("mc");
    let canary = token("wzm");
    let busted = with_buster(url, &cb);
    let host_val = env.header_value(HeaderKind::Host, &canary);

    let Some(head_before) = tracked_custom(client, Method::HEAD, &busted, &[], None).await else {
        return findings;
    };
    let cl_before = content_length(&head_before);

    let Some(get_poison) =
        tracked_get(client, &busted, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if reflects(&get_poison, &canary).is_none() {
        return findings;
    }
    let get_len = get_poison.body.len();
    let get_sig = detect_cache(&get_poison);

    let Some(head_after) = tracked_custom(client, Method::HEAD, &busted, &[], None).await else {
        return findings;
    };
    let head_sig = detect_cache(&head_after);
    let cl_after = content_length(&head_after);

    let length_matches_poison = cl_after == Some(get_len) && Some(get_len) != cl_before;
    let confirmed = length_matches_poison && (head_sig.hit || get_sig.hit);

    if !confirmed && !length_matches_poison {
        return findings;
    }

    let (severity, exposure, conf) = if confirmed {
        ("critical", "confirmed", 0.9)
    } else {
        ("high", "suspected", 0.75)
    };

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("canary", canary.clone())
        .with("head_content_length_before", json!(cl_before))
        .with("get_body_length", json!(get_len))
        .with("head_content_length_after", json!(cl_after))
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("get_poison_reflected", true, "X-Forwarded-Host canary in GET body")
        .check(
            "head_content_length_matches_poison_get",
            length_matches_poison,
            format!("HEAD CL {:?} vs GET len {}", cl_after, get_len),
        )
        .check(
            "head_cache_hit_after_poison",
            head_sig.hit,
            head_sig.headers.join("; "),
        );

    findings.push(cache_finding(
        target,
        if confirmed {
            "Confirmed GET/HEAD cache-key confusion — HEAD oracle matches poisoned GET"
        } else {
            "GET/HEAD cache-key confusion suspected — HEAD Content-Length shifted after poison GET"
        },
        severity,
        &format!(
            "After a poison GET (X-Forwarded-Host canary reflected, body length {}) a HEAD to the same cache-busted URL returned Content-Length {:?} (was {:?}). {} When method is excluded from the cache key, a poisoned GET poisons HEAD and bodyless GET for every user.",
            get_len,
            cl_after,
            cl_before,
            if confirmed {
                "HEAD Content-Length matched the poison GET and cache HIT markers were observed — provable method-unkeyed caching."
            } else {
                "Content-Length shifted toward the poison GET — investigate cache-key method handling."
            }
        ),
        conf,
        "cache_method",
        exposure,
        "Include the HTTP method in every cache key. Configure the CDN to never cache GET/HEAD interchangeably. Strip X-Forwarded-Host at the edge.",
        ev,
    ));
    findings
}

async fn probe_range_poisoning(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("rg");
    let canary = token("wzr");
    let busted = with_buster(url, &cb);

    // Inject canary via unkeyed header on a ranged GET — if range response is cached without
    // keying on Range, a full GET may receive the poisoned partial object.
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let range_hdr = "bytes=0-4095";
    let Some(range_resp) = tracked_custom(
        client,
        Method::GET,
        &busted,
        &[
            ("Range", range_hdr),
            ("X-Forwarded-Host", host_val.as_str()),
        ],
        None,
    )
    .await
    else {
        return findings;
    };

    let partial = range_resp.status == 206
        || header_value(&range_resp.headers, "content-range").is_some();
    if !partial {
        return findings;
    }
    let reflects_canary = reflects(&range_resp, &canary).is_some();
    let range_sig = detect_cache(&range_resp);
    if !reflects_canary && !range_sig.hit {
        return findings;
    }

    let Some(full_get) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let full_sig = detect_cache(&full_get);
    let bleed = reflects(&full_get, &canary).is_some()
        || (full_sig.hit && body_sha256(&full_get.body) == body_sha256(&range_resp.body));
    let confirmed = bleed && (full_sig.hit || range_sig.hit);

    if !reflects_canary && !confirmed {
        return findings;
    }

    let (severity, exposure, conf) = if confirmed {
        ("critical", "confirmed", 0.91)
    } else if reflects_canary {
        ("high", "reflected", 0.74)
    } else {
        ("medium", "partial", 0.6)
    };

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("range", range_hdr.to_string())
        .with("canary", canary.clone())
        .with("range_status", json!(range_resp.status))
        .with("content_range", header_value(&range_resp.headers, "content-range").unwrap_or("").to_string())
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("partial_content", partial, format!("status {}", range_resp.status))
        .check("canary_in_range_response", reflects_canary, "X-Forwarded-Host in ranged GET")
        .check("full_get_received_poison", bleed, if confirmed { "full GET reflected canary or matched range body" } else { "not confirmed" });

    findings.push(cache_finding(
        target,
        if confirmed {
            "Confirmed Range-request cache poisoning — full GET served poisoned partial"
        } else {
            "Range-request cache poisoning — canary reflected in partial response"
        },
        severity,
        &format!(
            "A ranged GET ({}) to {} returned HTTP {} with Content-Range. {} A subsequent full GET {} — Range must be part of the cache key or disabled for dynamic HTML.",
            range_hdr,
            url,
            range_resp.status,
            if reflects_canary {
                "The X-Forwarded-Host canary appeared in the partial response."
            } else {
                "Partial response was cacheable."
            },
            if confirmed {
                "received the poisoned content — provable Range-unkeyed caching."
            } else {
                "did not confirm cross-method bleed."
            }
        ),
        conf,
        "cache_method",
        exposure,
        "Include Range in the cache key (Vary: Range) or disable Range handling on cacheable paths. Never cache 206 partial responses alongside full 200 objects under the same key.",
        ev,
    ));
    findings
}

async fn probe_normalization(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("nm");
    let canary = token("wzn");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let variants = normalization_variants(url, &cb);
    if variants.len() < 2 {
        return findings;
    }

    let (prime_url, prime_label) = &variants[0];
    let Some(p1) =
        tracked_get(client, prime_url, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if reflects(&p1, &canary).is_none() {
        return findings;
    }

    for (alt_url, alt_label) in variants.iter().skip(1).take(4) {
        let Some(p2) = tracked_get(client, alt_url, &[]).await else {
            continue;
        };
        if reflects(&p2, &canary).is_none() {
            continue;
        }
        let sig2 = detect_cache(&p2);
        let confirmed = sig2.hit || detect_cache(&p1).hit;

        let ev = Evidence::new()
            .with("url", url.to_string())
            .with("prime_variant", prime_label.to_string())
            .with("prime_url", prime_url.clone())
            .with("alt_variant", alt_label.to_string())
            .with("alt_url", alt_url.clone())
            .with("canary", canary.clone())
            .with("vendor", json!(base_sig.vendor.clone()))
            .check("prime_poison_reflected", true, (*prime_label).to_string())
            .check("alt_url_got_poison", true, (*alt_label).to_string())
            .check("cache_hit_on_alt", sig2.hit, sig2.headers.join("; "));

        let (severity, exposure, conf) = if confirmed {
            ("critical", "confirmed", 0.92)
        } else {
            ("high", "suspected", 0.76)
        };

        findings.push(cache_finding(
            target,
            &format!(
                "Cache normalization fracture: poison on '{}' served via '{}'",
                prime_label, alt_label
            ),
            severity,
            &format!(
                "Poisoning {} ({}) with X-Forwarded-Host canary was reflected, and the distinct URL form {} ({}) returned the same canary without the header. {} CDNs that normalize paths/query strings collapse distinct URLs into one cache slot — invisible to path-only scanners.",
                prime_url,
                prime_label,
                alt_url,
                alt_label,
                if confirmed {
                    "Cache HIT observed on the alternate form — provable normalization poisoning."
                } else {
                    "Canary bleed across normalized URL forms observed."
                }
            ),
            conf,
            "cache_normalization",
            exposure,
            "Disable cache-key normalization that collapses semicolon segments, encoded slashes, or trailing-slash variants. Normalize URLs once at the edge before cache lookup and reject ambiguous forms.",
            ev,
        ));
        return findings;
    }
    findings
}

async fn probe_cache_key_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("ko");
    let canary = token("wzk");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let prime_base = with_buster(url, &cb);
    let prime_url = with_pad_param(&prime_base, "alpha");

    let Some(primed) =
        tracked_get(client, &prime_url, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if reflects(&primed, &canary).is_none() {
        return findings;
    }

    // Same cache-buster, different pad param — if poison bleeds, wkpad is excluded from key.
    let alt_pad_url = with_pad_param(&prime_base, "beta");
    if let Some(alt_pad) = tracked_get(client, &alt_pad_url, &[]).await {
        if reflects(&alt_pad, &canary).is_some() {
            let sig = detect_cache(&alt_pad);
            let confirmed = sig.hit || detect_cache(&primed).hit;
            let ev = Evidence::new()
                .with("url", url.to_string())
                .with("prime_url", prime_url.clone())
                .with("alt_url", alt_pad_url.clone())
                .with("excluded_dimension", "wkpad")
                .with("canary", canary.clone())
                .with("vendor", json!(base_sig.vendor.clone()))
                .check("prime_poison_reflected", true, "X-Forwarded-Host canary")
                .check("alt_pad_got_poison", true, "wkpad=beta without header")
                .check("cache_hit_on_alt", sig.hit, sig.headers.join("; "));
            let (severity, exposure, conf) = if confirmed {
                ("critical", "confirmed", 0.93)
            } else {
                ("high", "suspected", 0.77)
            };
            findings.push(cache_finding(
                target,
                "Cache-key oracle: query pad parameter excluded from cache key",
                severity,
                &format!(
                    "Poisoning {} (wkpad=alpha) with X-Forwarded-Host canary was reflected, and {} (wkpad=beta) returned the same canary without the header. {} The CDN collapses distinct query strings into one cache slot — a cache-key oracle primitive.",
                    prime_url,
                    alt_pad_url,
                    if confirmed {
                        "Cache HIT markers observed — provable query-dimension exclusion."
                    } else {
                        "Canary bleed across pad values observed."
                    }
                ),
                conf,
                "cache_key_oracle",
                exposure,
                "Include every query parameter that affects the response in the cache key. Disable cache normalization that strips unknown params. Reject requests when the cache key cannot be computed unambiguously.",
                ev,
            ));
            return findings;
        }
    }

    // Different cache-buster, same pad — if poison bleeds, wzcb (our buster) is excluded.
    let cb2 = token("k2");
    let alt_cb_base = with_buster(url, &cb2);
    let alt_cb_url = with_pad_param(&alt_cb_base, "alpha");
    if alt_cb_url != prime_url {
        if let Some(alt_cb) = tracked_get(client, &alt_cb_url, &[]).await {
            if reflects(&alt_cb, &canary).is_some() {
                let sig = detect_cache(&alt_cb);
                let ev = Evidence::new()
                    .with("url", url.to_string())
                    .with("prime_url", prime_url.clone())
                    .with("alt_url", alt_cb_url.clone())
                    .with("excluded_dimension", CB_PARAM)
                    .with("canary", canary.clone())
                    .with("vendor", json!(base_sig.vendor.clone()))
                    .check("prime_poison_reflected", true, "X-Forwarded-Host canary")
                    .check("alt_cb_got_poison", true, format!("different {} value", CB_PARAM))
                    .check("cache_hit_on_alt", sig.hit, sig.headers.join("; "));
                findings.push(cache_finding(
                    target,
                    &format!(
                        "Cache-key oracle: '{}' query parameter excluded from cache key",
                        CB_PARAM
                    ),
                    if sig.hit { "high" } else { "medium" },
                    &format!(
                        "Poison on {} was served from {} without the poison header. The CDN ignores the '{}' cache-buster dimension — unknown query parameters may not isolate cache entries.",
                        prime_url, alt_cb_url, CB_PARAM
                    ),
                    if sig.hit { 0.84 } else { 0.68 },
                    "cache_key_oracle",
                    if sig.hit { "confirmed" } else { "suspected" },
                    "Configure the CDN to include all query parameters in the cache key, or maintain an explicit allowlist of cache-key dimensions. Never strip unrecognized query params before cache lookup.",
                    ev,
                ));
            }
        }
    }
    findings
}

async fn probe_h2_cache_schism(
    timeout_ms: u64,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("h2");
    let busted = with_buster(url, &cb);
    let h1 = build_client_with_http2(timeout_ms, false).await;
    let h2 = build_client_with_http2(timeout_ms, true).await;

    let Some(r1) = tracked_get(&h1, &busted, &[]).await else {
        return findings;
    };
    let Some(r2) = tracked_get(&h2, &busted, &[]).await else {
        return findings;
    };
    if r1.status != r2.status {
        return findings;
    }
    let hash1 = body_sha256(&r1.body);
    let hash2 = body_sha256(&r2.body);
    if hash1 == hash2 {
        return findings;
    }
    let sig1 = detect_cache(&r1);
    let sig2 = detect_cache(&r2);
    if !sig1.cacheable && !sig2.cacheable {
        return findings;
    }

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("body_sha256_h1", hash1.clone())
        .with("body_sha256_h2", hash2.clone())
        .with("status", json!(r1.status))
        .with("h1_cache", json!(sig1.headers))
        .with("h2_cache", json!(sig2.headers))
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("bodies_differ_by_protocol", true, format!("{} vs {}", &hash1[..12], &hash2[..12]))
        .check("h1_cacheable", sig1.cacheable, sig1.headers.join("; "))
        .check("h2_cacheable", sig2.cacheable, sig2.headers.join("; "));

    findings.push(cache_finding(
        target,
        "HTTP/2 vs HTTP/1.1 cache schism — protocol excluded from cache key",
        "high",
        &format!(
            "The cache-busted URL {} returned different bodies over HTTP/1.1 (sha256 {}) vs HTTP/2 (sha256 {}) at HTTP {}. When ALPN protocol is not part of the cache key, poisoned responses on one stack are served on the other — a liminal fracture invisible to single-protocol scanners.",
            busted, &hash1[..12], &hash2[..12], r1.status
        ),
        0.83,
        "cache_protocol",
        "present",
        "Include ALPN/HTTP version in the cache key or serve mutually exclusive cache partitions per protocol. Align routing, auth, and cache rules across HTTP/1.1 and HTTP/2 at the edge.",
        ev,
    ));
    findings
}

async fn probe_encoding_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("enc");
    let busted = with_buster(url, &cb);

    let identity = tracked_get(client, &busted, &[("Accept-Encoding", "identity")]).await;
    let gzip = tracked_get(
        client,
        &busted,
        &[("Accept-Encoding", "gzip, deflate, br")],
    )
    .await;
    let Some(a) = identity else { return findings };
    let Some(b) = gzip else { return findings };
    if a.status != b.status {
        return findings;
    }
    let hash_a = body_sha256(&a.body);
    let hash_b = body_sha256(&b.body);
    if hash_a == hash_b {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    let vary_ok = vary.to_ascii_lowercase().contains("accept-encoding");
    if !is_publicly_cacheable(cc) || vary_ok {
        return findings;
    }

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("body_sha256_identity", hash_a.clone())
        .with("body_sha256_gzip", hash_b.clone())
        .with("cache_control", cc.to_string())
        .with("vary", vary.to_string())
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("encoding_changes_body", true, format!("{} vs {}", &hash_a[..12], &hash_b[..12]))
        .check("vary_includes_accept_encoding", vary_ok, vary);

    findings.push(cache_finding(
        target,
        "Accept-Encoding variant content cacheable without Vary: Accept-Encoding",
        "high",
        &format!(
            "Responses at {} differ by Accept-Encoding (identity sha256 {} vs gzip-offer sha256 {}) but Cache-Control='{}' and Vary='{}'. Cross-encoding cache bleed enables poisoning across compression stacks.",
            url, &hash_a[..12], &hash_b[..12], cc, vary
        ),
        0.81,
        "cache_hardening",
        "suspected",
        "Add Vary: Accept-Encoding to every cacheable response, or normalize compression at the edge before cache lookup.",
        ev,
    ));
    findings
}

async fn probe_method_override(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("mo");
    let canary = token("wzo");
    let busted = with_buster(url, &cb);
    let body = format!("wzcanary={}&probe=method_override", canary);

    for (hdr, val) in [
        ("X-HTTP-Method-Override", "POST"),
        ("X-Method-Override", "POST"),
        ("X-HTTP-Method", "POST"),
    ] {
        let Some(p1) = tracked_custom(
            client,
            Method::GET,
            &busted,
            &[(hdr, val)],
            Some(&body),
        )
        .await
        else {
            continue;
        };
        let Some(loc) = reflects(&p1, &canary) else {
            continue;
        };
        let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;
        let mut confirmed = false;
        if cacheable {
            if let Some(p2) = tracked_get(client, &busted, &[]).await {
                if reflects(&p2, &canary).is_some() {
                    confirmed = true;
                }
            }
        }
        let (severity, exposure, conf) = if confirmed {
            ("critical", "confirmed", 0.91)
        } else {
            ("high", "reflected", 0.73)
        };
        let ev = Evidence::new()
            .with("url", url.to_string())
            .with("override_header", hdr.to_string())
            .with("override_value", val.to_string())
            .with("request_body", body.clone())
            .with("canary", canary.clone())
            .with("reflection_location", loc)
            .with("cacheable", json!(cacheable))
            .with("vendor", json!(base_sig.vendor.clone()))
            .check("override_reflection", true, format!("{} canary in {}", hdr, loc))
            .check(
                "plain_get_still_poisoned",
                confirmed,
                if confirmed {
                    "bodyless GET without override reflected canary"
                } else {
                    "not confirmed"
                },
            );
        findings.push(cache_finding(
            target,
            if confirmed {
                "Confirmed method-override cache poisoning via GET + body"
            } else {
                "Method-override header reflects into cacheable GET response"
            },
            severity,
            &format!(
                "GET {} with {}:{} and a body containing the canary was reflected in the {}. {} Method-override headers can turn a cacheable GET into a POST body sink without updating the cache key.",
                url, hdr, val, loc,
                if confirmed {
                    "A follow-up plain GET returned the canary — provably unkeyed and cached."
                } else if cacheable {
                    "Shared cache present; bodyless GETs may receive the poison."
                } else {
                    "No cache HIT confirmed."
                }
            ),
            conf,
            "cache_method",
            exposure,
            "Reject GET requests with a body and strip X-HTTP-Method-Override / X-Method-Override at the edge unless explicitly required. Include method + body hash in the cache key.",
            ev,
        ));
        return findings;
    }
    findings
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn cache_control_schism(origin_cc: &str, edge_cc: &str) -> bool {
    let origin = origin_cc.to_ascii_lowercase();
    let edge = edge_cc.to_ascii_lowercase();
    (origin.contains("no-store") || origin.contains("private"))
        && (edge.contains("public") || edge.contains("s-maxage"))
}

async fn probe_authorization_cache(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("au");
    let canary = token("wza");
    let busted = with_buster(url, &cb);
    let auth_val = format!("Bearer wzcanary_{}", canary);

    let Some(baseline) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let Some(with_auth) =
        tracked_get(client, &busted, &[("Authorization", auth_val.as_str())]).await
    else {
        return findings;
    };

    let base_hash = body_sha256(&baseline.body);
    let auth_hash = body_sha256(&with_auth.body);
    let auth_reflects = reflects(&with_auth, &canary).is_some();
    if base_hash == auth_hash && !auth_reflects {
        return findings;
    }

    let sig = detect_cache(&with_auth);
    let cacheable = sig.cacheable || base_sig.cacheable;

    let mut confirmed = false;
    if cacheable {
        if let Some(repeat) = tracked_get(client, &busted, &[]).await {
            let repeat_hash = body_sha256(&repeat.body);
            if (repeat_hash == auth_hash || reflects(&repeat, &canary).is_some())
                && repeat_hash != base_hash
            {
                let repeat_sig = detect_cache(&repeat);
                if repeat_sig.hit || repeat_sig.cacheable {
                    confirmed = true;
                }
            }
        }
    }

    let cache_ctrl = header_value(&with_auth.headers, "cache-control").unwrap_or("");
    let vary = header_value(&with_auth.headers, "vary").unwrap_or("");
    let vary_ok = vary.to_ascii_lowercase().contains("authorization");
    let publicly_cacheable = is_publicly_cacheable(cache_ctrl);

    let (severity, exposure, conf, title) = if confirmed {
        (
            "critical",
            "confirmed",
            0.95,
            "Confirmed Authorization-unkeyed response cached without Bearer token",
        )
    } else if publicly_cacheable && !vary_ok && cacheable {
        (
            "critical",
            "suspected",
            0.85,
            "Authorization-variant response publicly cacheable without Vary: Authorization",
        )
    } else {
        (
            "high",
            "variant",
            0.7,
            "Response varies by Authorization header on a cacheable path",
        )
    };

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("authorization", "Bearer wzcanary_<redacted>")
        .with("baseline_body_sha256", base_hash.clone())
        .with("auth_body_sha256", auth_hash.clone())
        .with("cache_control", cache_ctrl.to_string())
        .with("vary", vary.to_string())
        .with("cacheable", json!(cacheable))
        .with("vendor", json!(base_sig.vendor.clone()))
        .check(
            "content_varies_by_authorization",
            true,
            format!("{} vs {}", &base_hash[..12], &auth_hash[..12]),
        )
        .check("vary_includes_authorization", vary_ok, vary)
        .check(
            "authless_repeat_got_auth_response",
            confirmed,
            if confirmed {
                "repeat without Authorization matched auth response"
            } else {
                "not confirmed"
            },
        );

    findings.push(cache_finding(
        target,
        title,
        severity,
        &format!(
            "Requests to {} return different content when Authorization: Bearer is present (body sha256 {} vs {}). Cache-Control='{}', Vary='{}'. {} API tokens or session JWTs reflected into cacheable responses can leak authenticated data to anonymous users via the shared CDN cache.",
            url,
            &base_hash[..12],
            &auth_hash[..12],
            cache_ctrl,
            vary,
            if confirmed {
                "A repeat request without Authorization received the authenticated response — provable auth-unkeyed caching."
            } else if publicly_cacheable && !vary_ok {
                "Response is publicly cacheable but does not vary on Authorization."
            } else {
                "Authorization-dependent personalization observed on a cacheable path."
            }
        ),
        conf,
        "auth_cache",
        exposure,
        "Add Vary: Authorization (or disable caching for Authorization-bearing requests). Set Cache-Control: private/no-store on every authenticated API response. Strip Authorization from cache eligibility at the CDN.",
        ev,
    ));
    findings
}

async fn probe_redirect_poisoning(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("rd");
    let canary = token("wzr");
    let busted = with_buster(url, &cb);
    let host_val = env.header_value(HeaderKind::Host, &canary);

    let Some(p1) =
        tracked_get(client, &busted, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if !is_redirect_status(p1.status) {
        return findings;
    }
    let location = header_value(&p1.headers, "location").unwrap_or("");
    if !location.contains(&canary) {
        return findings;
    }

    let sig1 = detect_cache(&p1);
    let cacheable = sig1.cacheable || base_sig.cacheable;

    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            let loc2 = header_value(&p2.headers, "location").unwrap_or("");
            if loc2.contains(&canary) || reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }

    let (severity, exposure, conf) = if confirmed {
        ("critical", "confirmed", 0.94)
    } else if cacheable {
        ("high", "reflected", 0.78)
    } else {
        ("medium", "reflected", 0.65)
    };

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("status", json!(p1.status))
        .with("location", location.to_string())
        .with("canary", canary.clone())
        .with("cacheable", json!(cacheable))
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("redirect_with_poison_location", true, location)
        .check(
            "headerless_repeat_still_redirects_to_poison",
            confirmed,
            if confirmed {
                "Location still contains canary"
            } else {
                "not confirmed"
            },
        );

    findings.push(cache_finding(
        target,
        if confirmed {
            "Confirmed redirect cache poisoning — poisoned Location cached without header"
        } else {
            "Redirect cache poisoning — X-Forwarded-Host reflected in Location on cacheable 3xx"
        },
        severity,
        &format!(
            "A request to {} with X-Forwarded-Host returned HTTP {} with Location='{}'. {} Cached 3xx responses with attacker-controlled Location headers redirect every subsequent user to a malicious host — a high-impact cache poisoning primitive.",
            url,
            p1.status,
            location,
            if confirmed {
                "A header-less repeat returned the same poisoned Location — provably unkeyed and cached."
            } else if cacheable {
                "Shared cache present; if this redirect is stored, all users receive the poisoned Location."
            } else {
                "Redirect reflection observed; cache HIT not confirmed."
            }
        ),
        conf,
        "redirect_cache",
        exposure,
        "Never cache 3xx responses that include a Location derived from request headers. Strip X-Forwarded-Host at the edge. Set Cache-Control: no-store on all redirects that are not explicitly allowlisted.",
        ev,
    ));
    findings
}

async fn probe_query_order_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("qo");
    let canary = token("wzq");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let base_busted = with_buster(url, &cb);
    let prime_url = format!("{}&wkpad=alpha&wzref={}", base_busted, canary);
    let alt_url = format!("{}&wzref={}&wkpad=alpha", base_busted, canary);

    let Some(p1) =
        tracked_get(client, &prime_url, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if reflects(&p1, &canary).is_none() {
        return findings;
    }

    let Some(p2) = tracked_get(client, &alt_url, &[]).await else {
        return findings;
    };
    if reflects(&p2, &canary).is_none() {
        return findings;
    }

    let sig2 = detect_cache(&p2);
    let confirmed = sig2.hit || detect_cache(&p1).hit;

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("prime_url", prime_url.clone())
        .with("alt_url", alt_url.clone())
        .with("canary", canary.clone())
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("prime_poison_reflected", true, "wkpad=alpha;wzref=canary order")
        .check("alt_order_got_poison", true, "wzref=canary;wkpad=alpha order")
        .check("cache_hit_on_alt_order", sig2.hit, sig2.headers.join("; "));

    let (severity, exposure, conf) = if confirmed {
        ("critical", "confirmed", 0.9)
    } else {
        ("high", "suspected", 0.76)
    };

    findings.push(cache_finding(
        target,
        "Query parameter order oracle — distinct orderings share one cache slot",
        severity,
        &format!(
            "Poisoning {} (param order wkpad→wzref) was reflected, and {} (order wzref→wkpad) returned the same canary without the poison header. {} CDNs that sort or ignore query order collapse attacker-primed entries onto victim URLs.",
            prime_url,
            alt_url,
            if confirmed {
                "Cache HIT on alternate ordering — provable order-normalization poisoning."
            } else {
                "Canary bleed across parameter orderings observed."
            }
        ),
        conf,
        "cache_key_oracle",
        exposure,
        "Include query parameter order in the cache key, or canonicalize parameter order once at the edge before cache lookup. Never sort parameters in a way that merges distinct cache entries.",
        ev,
    ));
    findings
}

async fn probe_cdn_origin_cache_schism(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("cs");
    let busted = with_buster(url, &cb);

    let Some(baseline) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let sig = detect_cache(&baseline);
    let cacheable = sig.cacheable || base_sig.cacheable;
    if !cacheable {
        return findings;
    }

    let origin_cc = header_value(&baseline.headers, "cache-control").unwrap_or("");
    let cdn_cc = header_value(&baseline.headers, "cdn-cache-control").unwrap_or("");
    let surrogate = header_value(&baseline.headers, "surrogate-control").unwrap_or("");
    let dynamic = is_dynamic(&baseline);

    let edge_cc = if !cdn_cc.is_empty() { cdn_cc } else { surrogate };
    if edge_cc.is_empty() || origin_cc.is_empty() {
        return findings;
    }
    if !cache_control_schism(origin_cc, edge_cc) {
        return findings;
    }

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("cache_control", origin_cc.to_string())
        .with("edge_cache_control", edge_cc.to_string())
        .with("dynamic_response", json!(dynamic))
        .with("vendor", json!(sig.vendor.clone()))
        .check("origin_restricts_caching", true, origin_cc)
        .check("edge_overrides_with_public", true, edge_cc)
        .check("shared_cache_present", cacheable, sig.headers.join("; "));

    let sev = if dynamic { "critical" } else { "high" };
    findings.push(cache_finding(
        target,
        "CDN vs origin Cache-Control schism — edge caches despite origin no-store/private",
        sev,
        &format!(
            "Origin Cache-Control='{}' but CDN edge directive='{}' on {}. {} The CDN may store responses the origin marked non-cacheable — bypassing origin intent and enabling session/cache bleed at the edge.",
            origin_cc,
            edge_cc,
            url,
            if dynamic {
                "Dynamic HTML/Set-Cookie response detected — authenticated content may be edge-cached."
            } else {
                "Edge override of origin cache policy detected."
            }
        ),
        if dynamic { 0.92 } else { 0.84 },
        "cache_hardening",
        "present",
        "Align CDN-Cache-Control / Surrogate-Control with origin Cache-Control. Honor origin no-store/private at the edge. Disable surrogate caching for dynamic/authenticated responses.",
        ev,
    ));
    findings
}

async fn probe_user_agent_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("ua");
    let busted = with_buster(url, &cb);
    const MOBILE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
    const DESKTOP_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    let mobile = tracked_get(client, &busted, &[("User-Agent", MOBILE_UA)]).await;
    let desktop = tracked_get(client, &busted, &[("User-Agent", DESKTOP_UA)]).await;
    let (Some(a), Some(b)) = (mobile, desktop) else {
        return findings;
    };
    if a.status != b.status {
        return findings;
    }
    let hash_a = body_sha256(&a.body);
    let hash_b = body_sha256(&b.body);
    if hash_a == hash_b {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    let vary_ok = vary.to_ascii_lowercase().contains("user-agent");
    if !is_publicly_cacheable(cc) || vary_ok {
        return findings;
    }

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("body_sha256_mobile", hash_a.clone())
        .with("body_sha256_desktop", hash_b.clone())
        .with("cache_control", cc.to_string())
        .with("vary", vary.to_string())
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("user_agent_changes_body", true, format!("{} vs {}", &hash_a[..12], &hash_b[..12]))
        .check("vary_includes_user_agent", vary_ok, vary);

    findings.push(cache_finding(
        target,
        "User-Agent variant content cacheable without Vary: User-Agent",
        "high",
        &format!(
            "Responses at {} differ by User-Agent (mobile sha256 {} vs desktop sha256 {}) but Cache-Control='{}' and Vary='{}'. Mobile/desktop-specific content can bleed across clients via the shared CDN cache.",
            url, &hash_a[..12], &hash_b[..12], cc, vary
        ),
        0.82,
        "cache_hardening",
        "suspected",
        "Add Vary: User-Agent for device-specific responses, or serve a single canonical variant from cacheable paths.",
        ev,
    ));
    findings
}

async fn probe_tracking_param_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("tr");
    let canary = token("wzt");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let base_busted = with_buster(url, &cb);

    for (i, prime_param) in TRACKING_PARAMS.iter().enumerate().take(4) {
        let prime_url = format!("{}&{}=prime{}", base_busted, prime_param, i);
        let Some(p1) =
            tracked_get(client, &prime_url, &[("X-Forwarded-Host", host_val.as_str())]).await
        else {
            continue;
        };
        if reflects(&p1, &canary).is_none() {
            continue;
        }

        for alt_param in TRACKING_PARAMS.iter().filter(|p| *p != prime_param).take(3) {
            let alt_url = format!("{}&{}=alt{}", base_busted, alt_param, i);
            let Some(p2) = tracked_get(client, &alt_url, &[]).await else {
                continue;
            };
            if reflects(&p2, &canary).is_none() {
                continue;
            }
            let sig2 = detect_cache(&p2);
            let confirmed = sig2.hit || detect_cache(&p1).hit;
            let ev = Evidence::new()
                .with("url", url.to_string())
                .with("prime_param", (*prime_param).to_string())
                .with("prime_url", prime_url.clone())
                .with("alt_param", (*alt_param).to_string())
                .with("alt_url", alt_url.clone())
                .with("canary", canary.clone())
                .with("vendor", json!(base_sig.vendor.clone()))
                .check("prime_poison_reflected", true, prime_param.to_string())
                .check("alt_tracking_param_got_poison", true, alt_param.to_string())
                .check("cache_hit_on_alt", sig2.hit, sig2.headers.join("; "));
            let (severity, exposure, conf) = if confirmed {
                ("critical", "confirmed", 0.91)
            } else {
                ("high", "suspected", 0.78)
            };
            findings.push(cache_finding(
                target,
                &format!(
                    "Tracking-parameter cache-key oracle: '{}' poison served via '{}'",
                    prime_param, alt_param
                ),
                severity,
                &format!(
                    "Poisoning {} ({}) was reflected, and {} ({}) returned the same canary without the header. {} CDNs that strip marketing/tracking params from cache keys collapse poisoned entries onto clean URLs — invisible to path-only scanners.",
                    prime_url, prime_param, alt_url, alt_param,
                    if confirmed {
                        "Cache HIT on alternate tracking param — provable param-class exclusion."
                    } else {
                        "Canary bleed across tracking param names observed."
                    }
                ),
                conf,
                "cache_key_oracle",
                exposure,
                "Include all query parameters in the cache key or maintain an explicit allowlist. Never strip unknown/tracking params before cache lookup on dynamic paths.",
                ev,
            ));
            return findings;
        }
    }
    findings
}

async fn probe_vary_incomplete(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("vi");
    let busted = with_buster(url, &cb);

    let baseline = tracked_get(client, &busted, &[]).await;
    let with_cookie = tracked_get(
        client,
        &busted,
        &[("Cookie", "wzprobe=1")],
    )
    .await;
    let lang_en = tracked_get(
        client,
        &busted,
        &[("Accept-Language", "en-US,en;q=0.9")],
    )
    .await;
    let lang_zh = tracked_get(
        client,
        &busted,
        &[("Accept-Language", "zh-CN,zh;q=0.9")],
    )
    .await;

    let Some(base) = baseline else { return findings };
    let base_hash = body_sha256(&base.body);
    let cc = header_value(&base.headers, "cache-control").unwrap_or("");
    let vary = header_value(&base.headers, "vary").unwrap_or("").to_ascii_lowercase();
    if !is_publicly_cacheable(cc) {
        return findings;
    }

    let mut varying: Vec<&str> = Vec::new();
    if let Some(c) = &with_cookie {
        if body_sha256(&c.body) != base_hash {
            varying.push("Cookie");
        }
    }
    if let (Some(en), Some(zh)) = (&lang_en, &lang_zh) {
        if body_sha256(&en.body) != body_sha256(&zh.body) {
            varying.push("Accept-Language");
        }
    }
    if varying.len() < 2 {
        return findings;
    }

    let mut missing: Vec<&str> = Vec::new();
    for dim in &varying {
        if !vary.contains(&dim.to_ascii_lowercase()) {
            missing.push(dim);
        }
    }
    if missing.is_empty() {
        return findings;
    }

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("vary_header", vary.clone())
        .with("varying_dimensions", json!(varying))
        .with("missing_from_vary", json!(missing))
        .with("cache_control", cc.to_string())
        .with("vendor", json!(base_sig.vendor.clone()))
        .check("multiple_dimensions_vary", true, varying.join(", "))
        .check("vary_incomplete", true, missing.join(", "));

    findings.push(cache_finding(
        target,
        &format!("Incomplete Vary header — missing: {}", missing.join(", ")),
        "high",
        &format!(
            "The cacheable response at {} varies on {} but Vary='{}' omits {}. A CDN may serve one variant to users who sent different values for the missing dimension(s).",
            url,
            varying.join(" and "),
            vary,
            missing.join(" and "),
        ),
        0.86,
        "cache_hardening",
        "suspected",
        "Ensure Vary lists every request header that changes the response body. Prefer Cache-Control: private/no-store when multiple personalization dimensions apply.",
        ev,
    ));
    findings
}

async fn probe_stale_revalidate_risk(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("sw");
    let busted = with_buster(url, &cb);
    let Some(baseline) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let sig = detect_cache(&baseline);
    let cacheable = sig.cacheable || base_sig.cacheable;
    if !cacheable {
        return findings;
    }
    let cc = header_value(&baseline.headers, "cache-control").unwrap_or("");
    let cc_lower = cc.to_ascii_lowercase();
    if !cc_lower.contains("stale-while-revalidate") && !cc_lower.contains("stale-if-error") {
        return findings;
    }
    let dynamic = is_dynamic(&baseline);
    if !dynamic {
        return findings;
    }

    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("cache_control", cc.to_string())
        .with("dynamic_response", json!(true))
        .with("vendor", json!(sig.vendor.clone()))
        .check("stale_extension_present", true, cc)
        .check("dynamic_and_cacheable", true, sig.headers.join("; "));

    findings.push(cache_finding(
        target,
        "Dynamic response cacheable with stale-while-revalidate / stale-if-error",
        "medium",
        &format!(
            "The dynamic page at {} is served through a shared cache ({}) with Cache-Control='{}'. Stale extensions keep expired/poisoned objects servable to other users during revalidation windows — amplifying cache-poisoning impact.",
            url,
            sig.vendor.as_deref().unwrap_or("CDN"),
            cc
        ),
        0.74,
        "cache_hardening",
        "present",
        "Remove stale-while-revalidate from dynamic/authenticated responses. Use no-store for HTML/session pages. Cap stale windows at the CDN for any path that personalizes content.",
        ev,
    ));
    findings
}

async fn probe_accept_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("ac");
    let busted = with_buster(url, &cb);
    let html = tracked_get(
        client,
        &busted,
        &[("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")],
    )
    .await;
    let json = tracked_get(
        client,
        &busted,
        &[("Accept", "application/json, text/plain, */*")],
    )
    .await;
    let (Some(a), Some(b)) = (html, json) else {
        return findings;
    };
    if a.status != b.status {
        return findings;
    }
    let hash_a = body_sha256(&a.body);
    let hash_b = body_sha256(&b.body);
    if hash_a == hash_b {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    if !is_publicly_cacheable(cc) || vary.to_ascii_lowercase().contains("accept") {
        return findings;
    }
    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("body_sha256_html_accept", hash_a.clone())
        .with("body_sha256_json_accept", hash_b.clone())
        .with("cache_control", cc.to_string())
        .with("vary", vary.to_string())
        .check("accept_changes_body", true, format!("{} vs {}", &hash_a[..12], &hash_b[..12]));
    findings.push(cache_finding(
        target,
        "Accept negotiation variant cacheable without Vary: Accept",
        "high",
        &format!(
            "Responses at {} differ by Accept (html sha256 {} vs json sha256 {}) but Cache-Control='{}' and Vary='{}'. Content-negotiated API/HTML bleed enables cache poisoning across client types.",
            url, &hash_a[..12], &hash_b[..12], cc, vary
        ),
        0.83,
        "cache_hardening",
        "suspected",
        "Add Vary: Accept or serve a single canonical representation from cacheable paths.",
        ev,
    ));
    findings
}

async fn probe_post_cache_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("pc");
    let canary = token("wzp");
    let busted = with_buster(url, &cb);
    let body = format!("wzcanary={}&probe=post_cache", canary);

    let Some(p1) = tracked_custom(client, Method::POST, &busted, &[], Some(&body)).await else {
        return findings;
    };
    if !reflects(&p1, &canary).is_some() && !p1.body.contains(&canary) {
        return findings;
    }
    let Some(p2) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    if reflects(&p2, &canary).is_none() {
        return findings;
    }
    let sig2 = detect_cache(&p2);
    let confirmed = sig2.hit || detect_cache(&p1).hit;
    let (severity, exposure, conf) = if confirmed {
        ("critical", "confirmed", 0.93)
    } else {
        ("high", "suspected", 0.76)
    };
    let mut finding = cache_finding(
        target,
        if confirmed {
            "Confirmed POST response cached and served to GET"
        } else {
            "POST body reflected — GET received POST-flavoured response"
        },
        severity,
        &format!(
            "POST {} with canary body was reflected, and GET {} returned the canary without POST. {} When method/body are excluded from the cache key, attackers prime poison via POST and hit victims with GET.",
            busted, busted,
            if confirmed { "Cache HIT observed — provable POST→GET bleed." } else { "Cross-method bleed observed." }
        ),
        conf,
        "cache_method",
        exposure,
        "Never cache POST responses. Include method and body hash in the cache key. Reject POST on cacheable URL patterns at the edge.",
        Evidence::new()
            .with("url", url.to_string())
            .with("post_body", body.clone())
            .with("canary", canary.clone())
            .check("get_received_post_canary", true, "GET reflected POST canary")
            .check("cache_hit_on_get", sig2.hit, sig2.headers.join("; ")),
    );
    if confirmed {
        enrich_poc(
            &mut finding,
            poc_curl("POST", &busted, &[], Some(&body)),
        );
    }
    findings.push(finding);
    findings
}

async fn probe_immutable_dynamic(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("im");
    let busted = with_buster(url, &cb);
    let Some(baseline) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let sig = detect_cache(&baseline);
    if !(sig.cacheable || base_sig.cacheable) {
        return findings;
    }
    let cc = header_value(&baseline.headers, "cache-control").unwrap_or("");
    if !cc.to_ascii_lowercase().contains("immutable") || !is_dynamic(&baseline) {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Dynamic HTML marked Cache-Control: immutable at CDN",
        "high",
        &format!(
            "Dynamic response at {} carries Cache-Control='{}' through {}. immutable prevents revalidation — a poisoned or session-specific object persists for the full max-age window.",
            url, cc, sig.vendor.as_deref().unwrap_or("CDN")
        ),
        0.87,
        "cache_hardening",
        "present",
        "Never mark dynamic/authenticated HTML immutable. Reserve immutable for fingerprinted static assets only.",
        Evidence::new()
            .with("url", url.to_string())
            .with("cache_control", cc.to_string())
            .check("dynamic_response", true, "HTML/Set-Cookie/csrf markers")
            .check("immutable_directive", true, cc),
    ));
    findings
}

async fn probe_etag_injection(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("et");
    let canary = token("wze");
    let busted = with_buster(url, &cb);
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let Some(p1) = tracked_get(
        client,
        &busted,
        &[("X-Forwarded-Host", host_val.as_str())],
    )
    .await else {
        return findings;
    };
    let etag = header_value(&p1.headers, "etag").unwrap_or("");
    let reflects_etag = etag.contains(&canary);
    let reflects_body = reflects(&p1, &canary).is_some();
    if !reflects_etag && !reflects_body {
        return findings;
    }
    let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;
    let mut confirmed = false;
    if cacheable && reflects_body {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }
    let (severity, exposure, conf) = if confirmed {
        ("critical", "confirmed", 0.9)
    } else if reflects_etag {
        ("high", "reflected", 0.72)
    } else {
        ("high", "reflected", 0.68)
    };
    findings.push(cache_finding(
        target,
        if reflects_etag {
            "ETag header reflects unkeyed input (X-Forwarded-Host canary)"
        } else {
            "Cacheable response reflects poison into body (ETag path related)"
        },
        severity,
        &format!(
            "X-Forwarded-Host canary {} {} on {}. ETag='{}'. {} Weak validators derived from attacker input enable cache-key confusion and conditional-request poisoning.",
            canary,
            if reflects_etag { "appears in ETag" } else { "reflected in body" },
            url,
            etag,
            if confirmed { "Header-less GET still returned canary — cached poison confirmed." } else { "" }
        ),
        conf,
        "cache_poisoning",
        exposure,
        "Never derive ETag from attacker-controlled headers. Strip X-Forwarded-Host before validator generation.",
        Evidence::new()
            .with("url", url.to_string())
            .with("etag", etag.to_string())
            .with("canary", canary.clone())
            .check("etag_contains_canary", reflects_etag, etag)
            .check("cached_poison_confirmed", confirmed, if confirmed { "yes" } else { "no" }),
    ));
    findings
}

async fn probe_case_header_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("cf");
    let canary = token("wzc");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let busted = with_buster(url, &cb);
    let Some(p1) = tracked_get(
        client,
        &busted,
        &[("x-forwarded-host", host_val.as_str())],
    )
    .await else {
        return findings;
    };
    let Some(loc) = reflects(&p1, &canary) else {
        return findings;
    };
    let Some(p2) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    if reflects(&p2, &canary).is_none() {
        return findings;
    }
    let confirmed = detect_cache(&p2).hit;
    let mut finding = cache_finding(
        target,
        "Case-folded header name poisoned cache (x-forwarded-host)",
        if confirmed { "critical" } else { "high" },
        &format!(
            "Lowercase 'x-forwarded-host' reflected canary in {} and a header-less GET received it from {}. {} Header-name case folding at the cache key enables bypass of naive header blocklists.",
            loc, url,
            if confirmed { "Cache HIT on repeat — confirmed." } else { "Bleed observed without explicit HIT." }
        ),
        if confirmed { 0.88 } else { 0.74 },
        "cache_poisoning",
        if confirmed { "confirmed" } else { "suspected" },
        "Normalize header names to lowercase before cache-key computation. Strip X-Forwarded-Host regardless of case.",
        Evidence::new()
            .with("url", url.to_string())
            .with("header", "x-forwarded-host")
            .with("reflection_location", loc)
            .check("lowercase_header_reflected", true, loc)
            .check("get_got_poison", true, "header-less repeat"),
    );
    if confirmed {
        enrich_poc(
            &mut finding,
            poc_curl("GET", &busted, &[("x-forwarded-host", host_val.as_str())], None),
        );
    }
    findings.push(finding);
    findings
}

fn cache_key_leak_headers(probe: &HttpProbe) -> Vec<(String, String)> {
    let mut leaks = Vec::new();
    for (k, v) in &probe.headers {
        let kl = k.to_ascii_lowercase();
        if kl.contains("cache-key")
            || kl == "cf-cache-key"
            || kl == "x-cache-key"
            || kl == "akamai-cache-key"
            || kl.contains("cachekey")
        {
            leaks.push((k.clone(), v.clone()));
        }
    }
    leaks
}

fn purge_surface_headers(probe: &HttpProbe) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in &probe.headers {
        let kl = k.to_ascii_lowercase();
        if kl == "surrogate-key"
            || kl == "cache-tag"
            || kl == "cache-tags"
            || kl == "x-amz-meta-surrogate-key"
        {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

fn via_hops(probe: &HttpProbe) -> Vec<String> {
    header_value(&probe.headers, "via")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

/// CDN cache-key / purge-key / Via-chain intelligence from a live response (no fabrication).
fn probe_cache_surface_intel(
    url: &str,
    target: &str,
    probe: &HttpProbe,
    sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !sig.cacheable {
        return findings;
    }
    let leaks = cache_key_leak_headers(probe);
    if !leaks.is_empty() {
        let ev = Evidence::new()
            .with("url", url.to_string())
            .with("vendor", json!(sig.vendor.clone()))
            .with("cache_key_headers", json!(leaks))
            .check("cache_key_exposed", true, format!("{} header(s)", leaks.len()));
        findings.push(cache_finding(
            target,
            "CDN cache-key material exposed in response headers",
            "medium",
            &format!(
                "Response from {} exposes cache-key headers ({:?}). Attackers can reverse-engineer the CDN cache-key formula and craft precise poisoning payloads — an operational intelligence leak most scanners ignore.",
                url,
                leaks.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>()
            ),
            0.88,
            "cache_fingerprint",
            "present",
            "Strip cache-key debug headers at the edge. Disable cache-key introspection in production. Restrict header exposure to internal diagnostics only.",
            ev,
        ));
    }
    let purge = purge_surface_headers(probe);
    if !purge.is_empty() && is_dynamic(probe) {
        let ev = Evidence::new()
            .with("url", url.to_string())
            .with("purge_headers", json!(purge))
            .check("purge_tags_on_dynamic", true, "dynamic HTML/Set-Cookie");
        findings.push(cache_finding(
            target,
            "Surrogate-Key / Cache-Tag on dynamic response",
            "low",
            &format!(
                "Dynamic response at {} includes purge tags ({:?}). If combined with cache-key fractures, targeted purge-tag poisoning can evict or repopulate specific cache partitions.",
                url,
                purge.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>()
            ),
            0.7,
            "cache_fingerprint",
            "present",
            "Avoid predictable surrogate keys on user-specific HTML. Use opaque, per-tenant purge tags only on genuinely cacheable static assets.",
            ev,
        ));
    }
    let hops = via_hops(probe);
    if hops.len() >= 2 {
        let ev = Evidence::new()
            .with("url", url.to_string())
            .with("via_chain", json!(hops))
            .with("vendor", json!(sig.vendor.clone()))
            .check("multi_tier_cdn", true, hops.join(" -> "));
        findings.push(cache_finding(
            target,
            &format!("Multi-tier CDN cache chain ({} hops)", hops.len()),
            "info",
            &format!(
                "Via chain at {}: {}. Each hop may apply different cache-key normalization — multi-tier stacks amplify normalization and unkeyed-input poisoning impact.",
                url,
                hops.join(" → ")
            ),
            0.8,
            "cache_fingerprint",
            "present",
            "Align cache-key policy across every CDN tier. Test poisoning at each hop; strip X-Forwarded-* at the outermost edge.",
            ev,
        ));
    }
    findings
}

async fn probe_sec_fetch_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("sf");
    let busted = with_buster(url, &cb);
    let doc = tracked_get(
        client,
        &busted,
        &[("Sec-Fetch-Dest", "document"), ("Sec-Fetch-Mode", "navigate")],
    )
    .await;
    let image = tracked_get(
        client,
        &busted,
        &[("Sec-Fetch-Dest", "image"), ("Sec-Fetch-Mode", "no-cors")],
    )
    .await;
    let (Some(a), Some(b)) = (doc, image) else {
        return findings;
    };
    if a.status != b.status {
        return findings;
    }
    let hash_a = body_sha256(&a.body);
    let hash_b = body_sha256(&b.body);
    if hash_a == hash_b {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    if !is_publicly_cacheable(cc) || vary.to_ascii_lowercase().contains("sec-fetch") {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Sec-Fetch variant content cacheable without Vary: Sec-Fetch-*",
        "high",
        &format!(
            "Responses at {} differ by Sec-Fetch-Dest (document sha256 {} vs image sha256 {}) without Vary covering Sec-Fetch. Navigation vs subresource cache bleed enables cross-context poisoning.",
            url, &hash_a[..12], &hash_b[..12]
        ),
        0.81,
        "cache_hardening",
        "suspected",
        "Add appropriate Vary dimensions for Sec-Fetch or disable caching on paths that branch on fetch metadata.",
        Evidence::new()
            .with("url", url.to_string())
            .check("sec_fetch_changes_body", true, format!("{} vs {}", &hash_a[..12], &hash_b[..12])),
    ));
    findings
}

async fn probe_save_data_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("sd");
    let busted = with_buster(url, &cb);
    let normal = tracked_get(client, &busted, &[]).await;
    let save = tracked_get(client, &busted, &[("Save-Data", "on")]).await;
    let (Some(a), Some(b)) = (normal, save) else {
        return findings;
    };
    if body_sha256(&a.body) == body_sha256(&b.body) {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    if !is_publicly_cacheable(cc) || vary.to_ascii_lowercase().contains("save-data") {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Save-Data variant content cacheable without Vary: Save-Data",
        "medium",
        &format!(
            "Responses at {} differ when Save-Data:on is sent but Vary='{}'. Low-bandwidth users may receive full-fidelity poisoned pages from cache.",
            url, vary
        ),
        0.72,
        "cache_hardening",
        "suspected",
        "Add Vary: Save-Data or serve one canonical variant from cacheable paths.",
        Evidence::new().with("url", url.to_string()).check("save_data_changes_body", true, "observed"),
    ));
    findings
}

async fn probe_options_cache_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("op");
    let busted = with_buster(url, &cb);
    let Some(get) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let Some(opts) = tracked_custom(client, Method::OPTIONS, &busted, &[], None).await else {
        return findings;
    };
    if get.status != opts.status {
        return findings;
    }
    let get_hash = body_sha256(&get.body);
    let opt_hash = body_sha256(&opts.body);
    if get_hash != opt_hash {
        return findings;
    }
    let opt_sig = detect_cache(&opts);
    if !opt_sig.hit && !opt_sig.cacheable {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "OPTIONS response byte-identical to GET and cacheable",
        "high",
        &format!(
            "OPTIONS and GET to {} returned identical bodies (sha256 {}) with cache signals ({}). Method-unkeyed caching lets OPTIONS priming poison GET for all users.",
            url,
            &get_hash[..12],
            opt_sig.headers.join("; ")
        ),
        0.84,
        "cache_method",
        "suspected",
        "Include HTTP method in the cache key. Never cache OPTIONS responses. Return distinct OPTIONS handlers at the edge.",
        Evidence::new()
            .with("url", url.to_string())
            .with("body_sha256", get_hash)
            .check("options_matches_get", true, "identical body hash")
            .check("options_cacheable", opt_sig.cacheable, opt_sig.headers.join("; ")),
    ));
    findings
}

/// Client `Pragma: no-cache` / `Cache-Control: no-cache` ignored — CDN still serves HIT.
async fn probe_pragma_no_cache_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("pr");
    let busted = with_buster(url, &cb);
    let no_cache = [("Pragma", "no-cache"), ("Cache-Control", "no-cache")];
    let _ = tracked_get(client, &busted, &no_cache).await;
    let Some(p2) = tracked_get(client, &busted, &no_cache).await else {
        return findings;
    };
    let sig = detect_cache(&p2);
    if !sig.hit {
        return findings;
    }
    let cc = header_value(&p2.headers, "cache-control").unwrap_or("");
    if !is_publicly_cacheable(cc) {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "CDN ignores client Pragma/Cache-Control no-cache (HIT observed)",
        "medium",
        &format!(
            "Repeat requests to {} with Pragma:no-cache and Cache-Control:no-cache still received a cache HIT ({}). Users cannot bypass a poisoned cache entry with standard reload semantics.",
            url,
            sig.headers.join("; ")
        ),
        0.79,
        "cache_hardening",
        "present",
        "Honor client no-cache at the edge for dynamic paths. Provide emergency cache purge API. Set shorter TTL on HTML.",
        Evidence::new()
            .with("url", url.to_string())
            .with("response_cache_control", cc.to_string())
            .check("hit_with_client_no_cache", true, sig.headers.join("; ")),
    ));
    findings
}

/// RFC7239 structured Forwarded header — many stacks parse only this format (not flat host strings).
async fn probe_forwarded_rfc7239(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("fr");
    let canary = token("wzf");
    let fwd = env.forwarded_rfc7239(&canary);
    let busted = with_buster(url, &cb);

    let Some(p1) = tracked_get(client, &busted, &[("Forwarded", fwd.as_str())]).await else {
        return findings;
    };
    let Some(loc) = reflects(&p1, &canary) else {
        return findings;
    };
    let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;
    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }
    let (severity, exposure, conf, title) = if confirmed {
        (
            "critical",
            "confirmed",
            0.94,
            "Confirmed cache poisoning via RFC7239 Forwarded header",
        )
    } else {
        (
            "high",
            "reflected",
            0.72,
            "RFC7239 Forwarded header reflected into cacheable response",
        )
    };
    let ev = Evidence::new()
        .with("url", url.to_string())
        .with("forwarded_value", fwd.clone())
        .with("canary", canary.clone())
        .with("reflection_location", loc)
        .with("cacheable", json!(cacheable))
        .check("rfc7239_reflection", true, format!("canary in {}", loc))
        .check("unkeyed_and_cached", confirmed, if confirmed { "header-less repeat reflected" } else { "not confirmed" });
    let mut finding = cache_finding(
        target,
        title,
        severity,
        &format!(
            "Structured Forwarded header ({fwd}) was reflected in the {} of {}. {} RFC7239 parsing paths are often unkeyed separately from X-Forwarded-Host.",
            loc, url,
            if confirmed { "The canary persisted without the header — confirmed poisoning." } else { "Shared cache present; confirm with manual replay." }
        ),
        conf,
        "cache_poisoning",
        exposure,
        "Strip Forwarded at the outermost edge. Never reflect Forwarded parameters into URLs, Link, or Location. Include Forwarded in the cache key if origin must see it.",
        ev,
    );
    if confirmed {
        enrich_poc(
            &mut finding,
            poc_curl("GET", &busted, &[("Forwarded", fwd.as_str())], None),
        );
    }
    findings.push(finding);
    findings
}

fn parse_url_host(url: &str) -> Option<String> {
    let t = url.trim();
    let rest = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))?;
    let host = rest.split('/').next()?.split(':').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Host header override — URL authority differs from sent Host (classic cache-key fracture).
async fn probe_host_header_poison(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let Some(real_host) = parse_url_host(url) else {
        return findings;
    };
    let cb = token("hh");
    let canary = token("wzh");
    let evil_host = env.host_canary(&canary);
    if evil_host.eq_ignore_ascii_case(&real_host) {
        return findings;
    }
    let busted = with_buster(url, &cb);
    let Some(p1) = tracked_get(client, &busted, &[("Host", evil_host.as_str())]).await else {
        return findings;
    };
    let Some(loc) = reflects(&p1, &canary) else {
        return findings;
    };
    let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;
    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }
    let (severity, exposure) = if confirmed {
        ("critical", "confirmed")
    } else {
        ("high", "reflected")
    };
    let mut finding = cache_finding(
        target,
        if confirmed {
            "Confirmed cache poisoning via Host header override"
        } else {
            "Host header override reflected into cacheable response"
        },
        severity,
        &format!(
            "Request to {} used Host: {} (URL authority: {}). Canary reflected in {}. {} When Host is excluded from the CDN cache key, attackers poison the slot every user hits.",
            url, evil_host, real_host, loc,
            if confirmed { "Repeat without Host header still returned the canary." } else { "Shared cache detected." }
        ),
        if confirmed { 0.93 } else { 0.71 },
        "cache_poisoning",
        exposure,
        "Include Host in the cache key at the edge. Reject Host values that do not match the TLS SNI / configured origin hostname.",
        Evidence::new()
            .with("url", url.to_string())
            .with("url_authority", real_host)
            .with("injected_host", evil_host.clone())
            .with("reflection_location", loc)
            .check("host_override_reflected", true, loc)
            .check("unkeyed_and_cached", confirmed, if confirmed { "confirmed" } else { "not confirmed" }),
    );
    if confirmed {
        enrich_poc(
            &mut finding,
            poc_curl("GET", &busted, &[("Host", evil_host.as_str())], None),
        );
    }
    findings.push(finding);
    findings
}

/// Origin declares no-store but CDN still returns HIT — edge ignores origin cache directive.
async fn probe_edge_no_store_bypass(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("ns");
    let busted = with_buster(url, &cb);
    let Some(p1) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let cc1 = header_value(&p1.headers, "cache-control")
        .unwrap_or("")
        .to_ascii_lowercase();
    if !cc1.contains("no-store") && !cc1.contains("private") {
        return findings;
    }
    let hash1 = body_sha256(&p1.body);
    let Some(p2) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let sig2 = detect_cache(&p2);
    if !sig2.hit {
        return findings;
    }
    if body_sha256(&p2.body) != hash1 {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "CDN caches response despite origin Cache-Control: no-store/private",
        "high",
        &format!(
            "Origin at {} returned Cache-Control '{}' but a repeat request received cache HIT ({}) with an identical body. The edge ignores no-store — dynamic or session pages may be stored and poisoned.",
            url, cc1, sig2.headers.join("; ")
        ),
        0.86,
        "cache_hardening",
        "suspected",
        "Configure CDN to respect origin no-store/private. Use CDN-Cache-Control: no-store at the edge for dynamic behaviors.",
        Evidence::new()
            .with("url", url.to_string())
            .with("origin_cache_control", cc1)
            .with("body_sha256", hash1)
            .check("no_store_but_hit", true, sig2.headers.join("; ")),
    ));
    findings
}

/// Vary: * with publicly cacheable response — spec says must not cache; many edges get it wrong.
async fn probe_vary_star_misconfig(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("vs");
    let busted = with_buster(url, &cb);
    let Some(p) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let vary = header_value(&p.headers, "vary").unwrap_or("").trim();
    if vary != "*" {
        return findings;
    }
    let cc = header_value(&p.headers, "cache-control").unwrap_or("");
    let sig = detect_cache(&p);
    if !is_publicly_cacheable(cc) && !sig.cacheable && !base_sig.cacheable {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Vary: * combined with cacheable response at shared edge",
        "medium",
        &format!(
            "Response from {} includes Vary: * with Cache-Control '{}' and cache signals ({}). RFC 7234 forbids storing such responses; misimplemented CDNs may cache anyway — amplifying every variant fracture.",
            url, cc, sig.headers.join("; ")
        ),
        0.77,
        "cache_hardening",
        "present",
        "Remove Vary: * — list explicit dimensions instead. Disable caching on paths that emit Vary: *.",
        Evidence::new()
            .with("url", url.to_string())
            .with("vary", vary.to_string())
            .with("cache_control", cc.to_string())
            .check("vary_star_cacheable", sig.cacheable || base_sig.cacheable, sig.headers.join("; ")),
    ));
    findings
}

/// Link header canonical injection — unkeyed Link influences cacheable HTML.
async fn probe_link_header_poison(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("lk");
    let canary = token("wzl");
    let link_val = env.link_canonical(&canary);
    let busted = with_buster(url, &cb);
    let Some(p1) = tracked_get(client, &busted, &[("Link", link_val.as_str())]).await else {
        return findings;
    };
    let Some(loc) = reflects(&p1, &canary) else {
        return findings;
    };
    let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;
    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }
    let (severity, exposure, conf) = if confirmed {
        ("critical", "confirmed", 0.91)
    } else {
        ("high", "reflected", 0.7)
    };
    let mut finding = cache_finding(
        target,
        if confirmed {
            "Confirmed cache poisoning via unkeyed Link header"
        } else {
            "Link header canonical injection reflected into cacheable response"
        },
        severity,
        &format!(
            "Link: {} was reflected in the {} of {}. {} SEO/canonical Link headers are frequently excluded from CDN cache keys.",
            link_val, loc, url,
            if confirmed { "Canary persisted without Link header — confirmed poisoning." } else { "Shared cache detected." }
        ),
        conf,
        "cache_poisoning",
        exposure,
        "Strip untrusted Link headers at the edge or include Link in the cache key. Never reflect Link into HTML without validation.",
        Evidence::new()
            .with("url", url.to_string())
            .with("link_value", link_val.clone())
            .with("reflection_location", loc)
            .check("link_reflected", true, loc)
            .check("unkeyed_and_cached", confirmed, if confirmed { "confirmed" } else { "not confirmed" }),
    );
    if confirmed {
        enrich_poc(
            &mut finding,
            poc_curl("GET", &busted, &[("Link", link_val.as_str())], None),
        );
    }
    findings.push(finding);
    findings
}

/// Duplicate query parameter names collapsing into one cache slot.
async fn probe_duplicate_query_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("dup");
    let canary = token("wzd");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let base_busted = with_buster(url, &cb);
    let prime_url = format!("{base_busted}&wkdup=1&wkdup=2");
    let read_url = format!("{base_busted}&wkdup=1");

    let Some(p1) =
        tracked_get(client, &prime_url, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if reflects(&p1, &canary).is_none() {
        return findings;
    }
    let Some(p2) = tracked_get(client, &read_url, &[]).await else {
        return findings;
    };
    if reflects(&p2, &canary).is_none() {
        return findings;
    }
    let sig2 = detect_cache(&p2);
    let confirmed = sig2.hit || detect_cache(&p1).hit;
    findings.push(cache_finding(
        target,
        "Duplicate query-parameter oracle — repeated param names share cache slot",
        if confirmed { "critical" } else { "high" },
        &format!(
            "Poisoning {} (wkdup=1&wkdup=2) with X-Forwarded-Host was reflected, and {} (wkdup=1 only) returned the same canary without the header. {} CDNs that deduplicate or take the last duplicate param value collapse distinct URLs.",
            prime_url, read_url,
            if confirmed { "Cache HIT observed — confirmed key fracture." } else { "Reflection confirmed across param forms." }
        ),
        if confirmed { 0.89 } else { 0.74 },
        "cache_key_oracle",
        if confirmed { "confirmed" } else { "suspected" },
        "Include all query parameter occurrences in the cache key. Do not silently deduplicate repeated parameter names at the edge.",
        Evidence::new()
            .with("url", url.to_string())
            .with("prime_url", prime_url)
            .with("read_url", read_url)
            .with("canary", canary)
            .check("duplicate_param_poison", true, "wkdup=1&wkdup=2 primed")
            .check("single_param_got_poison", true, "wkdup=1 read")
            .check("cache_hit", sig2.hit, sig2.headers.join("; ")),
    ));
    findings
}

/// Accept-Language header value order changes body without Vary.
async fn probe_accept_language_order(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("alo");
    let busted = with_buster(url, &cb);
    let a = tracked_get(client, &busted, &[("Accept-Language", "en-US,en;q=0.9,fr;q=0.8")]).await;
    let b = tracked_get(client, &busted, &[("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8")]).await;
    let (Some(a), Some(b)) = (a, b) else {
        return findings;
    };
    if a.status != b.status || body_sha256(&a.body) == body_sha256(&b.body) {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    if !is_publicly_cacheable(cc) || vary.to_ascii_lowercase().contains("accept-language") {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Accept-Language order/content fracture without Vary",
        "medium",
        &format!(
            "Responses at {} differ by Accept-Language ordering/content but Vary='{}'. Cross-language cache bleed poisons localized pages.",
            url, vary
        ),
        0.73,
        "cache_hardening",
        "suspected",
        "Add Vary: Accept-Language or serve one canonical locale per URL from cacheable paths.",
        Evidence::new()
            .with("url", url.to_string())
            .check("accept_language_changes_body", true, "en-first vs fr-first"),
    ));
    findings
}

/// Poisoned ETag honored — conditional GET returns 304 from shared cache.
async fn probe_if_none_match_cache(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("inm");
    let canary = token("wzi");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let busted = with_buster(url, &cb);
    let Some(p1) =
        tracked_get(client, &busted, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if reflects(&p1, &canary).is_none() {
        return findings;
    }
    let etag = header_value(&p1.headers, "etag").unwrap_or("");
    if etag.is_empty() {
        return findings;
    }
    let Some(p2) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    if reflects(&p2, &canary).is_none() {
        return findings;
    }
    let Some(p3) = tracked_get(client, &busted, &[("If-None-Match", etag)]).await else {
        return findings;
    };
    if p3.status != 304 {
        return findings;
    }
    let sig3 = detect_cache(&p3);
    if !sig3.hit && !sig3.cacheable {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Poisoned ETag honored — If-None-Match returns 304 from shared cache",
        "high",
        &format!(
            "After priming {} with X-Forwarded-Host canary, a conditional GET with If-None-Match: {} returned HTTP 304 ({}) while the cached entry contains the poison. Victims revalidating with the poisoned ETag receive 304 and retain stale poisoned content.",
            url, etag, sig3.headers.join("; ")
        ),
        0.85,
        "cache_poisoning",
        "suspected",
        "Never derive ETag from unkeyed headers. Rotate validators after purge. Strip X-Forwarded-Host before ETag generation.",
        Evidence::new()
            .with("url", url.to_string())
            .with("etag", etag.to_string())
            .with("canary", canary)
            .check("poison_cached", true, "header-less repeat reflected")
            .check("if_none_match_304", true, format!("status {}", p3.status))
            .check("304_from_cache", sig3.hit, sig3.headers.join("; ")),
    ));
    findings
}

/// Poisoned Last-Modified honored — If-Modified-Since returns 304 from shared cache.
async fn probe_if_modified_since_cache(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("ims");
    let canary = token("wzs");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let busted = with_buster(url, &cb);
    let Some(p1) =
        tracked_get(client, &busted, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if reflects(&p1, &canary).is_none() {
        return findings;
    }
    let last_mod = header_value(&p1.headers, "last-modified").unwrap_or("");
    if last_mod.is_empty() {
        return findings;
    }
    let Some(p2) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    if reflects(&p2, &canary).is_none() {
        return findings;
    }
    let Some(p3) = tracked_get(
        client,
        &busted,
        &[("If-Modified-Since", last_mod)],
    )
    .await
    else {
        return findings;
    };
    if p3.status != 304 {
        return findings;
    }
    let sig3 = detect_cache(&p3);
    if !sig3.hit && !sig3.cacheable {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Poisoned Last-Modified honored — If-Modified-Since returns 304 from shared cache",
        "high",
        &format!(
            "After priming {} with X-Forwarded-Host canary, conditional GET with If-Modified-Since: {} returned HTTP 304 ({}) while the cached body still carries the poison.",
            url, last_mod, sig3.headers.join("; ")
        ),
        0.84,
        "cache_poisoning",
        "suspected",
        "Never derive Last-Modified from unkeyed headers. Purge cache after validator rotation.",
        Evidence::new()
            .with("url", url.to_string())
            .with("last_modified", last_mod.to_string())
            .with("canary", canary)
            .check("poison_cached", true, "header-less repeat reflected")
            .check("if_modified_since_304", true, format!("status {}", p3.status))
            .check("304_from_cache", sig3.hit, sig3.headers.join("; ")),
    ));
    findings
}

/// Twin X-Forwarded-Host values — CDN keys first, origin reflects second (classic split oracle).
async fn probe_duplicate_header_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let Some(real_host) = parse_url_host(url) else {
        return findings;
    };
    let cb = token("dh");
    let canary = token("wzh");
    let evil = env.host_canary(&canary);
    let busted = with_buster(url, &cb);
    let Some(p1) = tracked_get_dup(
        client,
        &busted,
        &[
            ("X-Forwarded-Host", real_host.as_str()),
            ("X-Forwarded-Host", evil.as_str()),
        ],
    )
    .await
    else {
        return findings;
    };
    let Some(loc) = reflects(&p1, &canary) else {
        return findings;
    };
    let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;
    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }
    findings.push(cache_finding(
        target,
        if confirmed {
            "Confirmed cache poisoning via duplicate X-Forwarded-Host header oracle"
        } else {
            "Duplicate X-Forwarded-Host oracle — second value reflected into cacheable response"
        },
        if confirmed { "critical" } else { "high" },
        &format!(
            "Sent twin X-Forwarded-Host values ({} then {}) on {}. Canary reflected in {}. {} Split-header stacks key the first value but the application reflects the second.",
            real_host, evil, url, loc,
            if confirmed { "Poison persisted without the header." } else { "Manual replay recommended." }
        ),
        if confirmed { 0.93 } else { 0.74 },
        "cache_poisoning",
        if confirmed { "confirmed" } else { "reflected" },
        "Reject duplicate X-Forwarded-* headers. Include the full header set in the cache key or strip at the outermost edge.",
        Evidence::new()
            .with("url", url.to_string())
            .with("first_xfh", real_host)
            .with("second_xfh", evil)
            .with("canary", canary)
            .with("reflection_location", loc)
            .check("duplicate_header_reflection", true, loc)
            .check("unkeyed_and_cached", confirmed, if confirmed { "confirmed" } else { "not confirmed" }),
    ));
    findings
}

/// Client `Cache-Control: only-if-cached` serves a poisoned shared-cache entry without revalidation.
async fn probe_only_if_cached_oracle(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("oic");
    let canary = token("wzo");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let busted = with_buster(url, &cb);
    let Some(p1) =
        tracked_get(client, &busted, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if reflects(&p1, &canary).is_none() {
        return findings;
    }
    let Some(p2) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    if reflects(&p2, &canary).is_none() {
        return findings;
    }
    let only_if = [("Cache-Control", "only-if-cached")];
    let Some(p3) = tracked_get(client, &busted, &only_if).await else {
        return findings;
    };
    if p3.status == 504 || reflects(&p3, &canary).is_none() {
        return findings;
    }
    let sig = detect_cache(&p3);
    if !sig.hit && !sig.cacheable {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "only-if-cached serves poisoned shared-cache entry",
        "high",
        &format!(
            "After priming {} with X-Forwarded-Host canary, a request with Cache-Control: only-if-cached returned HTTP {} with the poison still present ({}). Victims using stale-only fetches cannot escape a poisoned CDN slot.",
            url, p3.status, sig.headers.join("; ")
        ),
        0.83,
        "cache_poisoning",
        "confirmed",
        "Purge poisoned namespaces on detection. Do not serve dynamic HTML from shared cache when only-if-cached is used unless validators are trustworthy.",
        Evidence::new()
            .with("url", url.to_string())
            .with("canary", canary)
            .with("only_if_cached_status", json!(p3.status))
            .check("poison_cached", true, "header-less repeat reflected")
            .check("only_if_cached_poison", true, sig.headers.join("; ")),
    ));
    findings
}

/// X-Requested-With AJAX vs non-AJAX body divergence without matching `Vary`.
async fn probe_x_requested_with_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("xrw");
    let busted = with_buster(url, &cb);
    let plain = tracked_get(client, &busted, &[]).await;
    let ajax = tracked_get(
        client,
        &busted,
        &[("X-Requested-With", "XMLHttpRequest")],
    )
    .await;
    let (Some(a), Some(b)) = (plain, ajax) else {
        return findings;
    };
    if a.status != b.status || body_sha256(&a.body) == body_sha256(&b.body) {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    if !is_publicly_cacheable(cc) || vary.to_ascii_lowercase().contains("x-requested-with") {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "X-Requested-With variant cacheable without Vary",
        "medium",
        &format!(
            "Responses at {} differ between plain GET and X-Requested-With: XMLHttpRequest without Vary covering X-Requested-With. AJAX vs full-page cache bleed enables cross-context poisoning.",
            url
        ),
        0.76,
        "cache_hardening",
        "suspected",
        "Add Vary: X-Requested-With or serve one canonical variant per URL from cacheable paths.",
        Evidence::new()
            .with("url", url.to_string())
            .check("x_requested_with_changes_body", true, "plain vs XMLHttpRequest"),
    ));
    findings
}

/// `Prefer` negotiation fracture — safe vs return=minimal without matching `Vary`.
async fn probe_prefer_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("pf");
    let busted = with_buster(url, &cb);
    let safe = tracked_get(client, &busted, &[("Prefer", "safe")]).await;
    let minimal = tracked_get(client, &busted, &[("Prefer", "return=minimal")]).await;
    let (Some(a), Some(b)) = (safe, minimal) else {
        return findings;
    };
    if a.status != b.status || body_sha256(&a.body) == body_sha256(&b.body) {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    if !is_publicly_cacheable(cc) || vary.to_ascii_lowercase().contains("prefer") {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Prefer header variant cacheable without Vary",
        "medium",
        &format!(
            "Responses at {} differ by Prefer (safe vs return=minimal) without Vary: Prefer. Content-negotiation cache bleed at the CDN edge.",
            url
        ),
        0.74,
        "cache_hardening",
        "suspected",
        "Add Vary: Prefer or disable caching on negotiated representations.",
        Evidence::new()
            .with("url", url.to_string())
            .check("prefer_changes_body", true, "safe vs return=minimal"),
    ));
    findings
}

/// `Alt-Svc` advertising HTTP/3 on a cacheable path — QUIC/H3 protocol schism attack surface.
async fn probe_alt_svc_h3_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("h3");
    let busted = with_buster(url, &cb);
    let Some(p) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let alt = header_value(&p.headers, "alt-svc").unwrap_or("");
    let alt_lc = alt.to_ascii_lowercase();
    if !alt_lc.contains("h3") && !alt_lc.contains("quic") {
        return findings;
    }
    let sig = detect_cache(&p);
    if !sig.cacheable && !base_sig.cacheable {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "HTTP/3 (Alt-Svc) advertised on cacheable response",
        if sig.hit { "medium" } else { "low" },
        &format!(
            "Response from {} advertises HTTP/3 via Alt-Svc ({}) on a cacheable path ({}). When QUIC/H3 cache keys diverge from HTTP/1.1 or HTTP/2, poisoned entries can persist on an alternate protocol stack — beyond what single-protocol scanners observe.",
            url, alt, sig.headers.join("; ")
        ),
        if sig.hit { 0.8 } else { 0.72 },
        "cache_fingerprint",
        "present",
        "Align cache-key policy across HTTP/1.1, HTTP/2, and HTTP/3. Test poisoning on every advertised ALPN/Alt-Svc stack. Strip Alt-Svc on dynamic HTML if QUIC is not production-hardened.",
        Evidence::new()
            .with("url", url.to_string())
            .with("alt_svc", alt.to_string())
            .with("vendor", json!(sig.vendor.clone().or_else(|| base_sig.vendor.clone())))
            .check("h3_advertised", true, alt)
            .check("cacheable_with_h3", sig.cacheable || base_sig.cacheable, sig.headers.join("; ")),
    ));
    findings
}

/// Browser-private but CDN-public in a single Cache-Control response line.
async fn probe_s_maxage_schism(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("sm");
    let busted = with_buster(url, &cb);
    let Some(p) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let cc = header_value(&p.headers, "cache-control").unwrap_or("");
    if !s_maxage_browser_schism(cc) {
        return findings;
    }
    let sig = detect_cache(&p);
    if !sig.cacheable && !base_sig.cacheable {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "s-maxage vs max-age/private schism in Cache-Control",
        "medium",
        &format!(
            "Response from {} carries Cache-Control='{}' with both CDN (s-maxage) and browser-restrictive directives. {} The edge may store responses browsers are told not to cache — widening poisoning impact.",
            url, cc, sig.headers.join("; ")
        ),
        0.78,
        "cache_hardening",
        "present",
        "Align s-maxage with origin intent. Use CDN-Cache-Control for edge-only TTL instead of mixing conflicting directives in one header.",
        Evidence::new()
            .with("url", url.to_string())
            .with("cache_control", cc.to_string())
            .check("s_maxage_schism", true, cc)
            .check("shared_cache", sig.cacheable || base_sig.cacheable, sig.headers.join("; ")),
    ));
    findings
}

/// Brotli (`br`) vs identity — distinct from gzip fracture in `probe_encoding_vary`.
async fn probe_brotli_encoding_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("br");
    let busted = with_buster(url, &cb);
    let identity = tracked_get(client, &busted, &[("Accept-Encoding", "identity")]).await;
    let brotli = tracked_get(client, &busted, &[("Accept-Encoding", "br")]).await;
    let (Some(a), Some(b)) = (identity, brotli) else {
        return findings;
    };
    if a.status != b.status || body_sha256(&a.body) == body_sha256(&b.body) {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    if !is_publicly_cacheable(cc) || vary.to_ascii_lowercase().contains("accept-encoding") {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Brotli vs identity variant cacheable without Vary: Accept-Encoding",
        "high",
        &format!(
            "Responses at {} differ for Accept-Encoding identity vs br (sha256 {} vs {}) without Vary covering encoding. Brotli-capable clients may receive a poison primed on the other encoding stack.",
            url,
            &body_sha256(&a.body)[..12],
            &body_sha256(&b.body)[..12]
        ),
        0.8,
        "cache_hardening",
        "suspected",
        "Add Vary: Accept-Encoding or normalize compression at the edge before cache lookup.",
        Evidence::new()
            .with("url", url.to_string())
            .check("brotli_changes_body", true, "identity vs br"),
    ));
    findings
}

/// Sec-CH-UA client hints change body without Vary.
async fn probe_sec_ch_ua_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("ch");
    let busted = with_buster(url, &cb);
    let chrome = tracked_get(
        client,
        &busted,
        &[("Sec-CH-UA", "\"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")],
    )
    .await;
    let other = tracked_get(
        client,
        &busted,
        &[("Sec-CH-UA", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")],
    )
    .await;
    let (Some(a), Some(b)) = (chrome, other) else {
        return findings;
    };
    if a.status != b.status || body_sha256(&a.body) == body_sha256(&b.body) {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    let vary_ok = vary.to_ascii_lowercase().contains("sec-ch-ua");
    if !is_publicly_cacheable(cc) || vary_ok {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Sec-CH-UA client-hint variant cacheable without Vary",
        "medium",
        &format!(
            "Responses at {} differ by Sec-CH-UA but Vary='{}'. Client-hint–aware pages may bleed poison across browser brands.",
            url, vary
        ),
        0.74,
        "cache_hardening",
        "suspected",
        "Add Vary: Sec-CH-UA (and related Client Hints) or disable caching on hint-sensitive paths.",
        Evidence::new()
            .with("url", url.to_string())
            .check("sec_ch_ua_changes_body", true, "chrome vs generic brand string"),
    ));
    findings
}

/// X-Forwarded-Prefix path injection with cache confirmation.
async fn probe_x_forwarded_prefix_poison(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("xp");
    let canary = token("wzx");
    let prefix_val = format!("/{canary}");
    let busted = with_buster(url, &cb);
    let Some(p1) =
        tracked_get(client, &busted, &[("X-Forwarded-Prefix", prefix_val.as_str())]).await
    else {
        return findings;
    };
    let Some(loc) = reflects(&p1, &canary) else {
        return findings;
    };
    let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;
    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }
    let (severity, exposure, conf) = if confirmed {
        ("critical", "confirmed", 0.92)
    } else {
        ("high", "reflected", 0.71)
    };
    let mut finding = cache_finding(
        target,
        if confirmed {
            "Confirmed cache poisoning via X-Forwarded-Prefix"
        } else {
            "X-Forwarded-Prefix reflected into cacheable response"
        },
        severity,
        &format!(
            "X-Forwarded-Prefix: {} reflected in {} at {}. {} Reverse-proxy path prefixes are a classic unkeyed input behind CDNs.",
            prefix_val, loc, url,
            if confirmed { "Canary persisted without the header." } else { "Shared cache detected." }
        ),
        conf,
        "cache_poisoning",
        exposure,
        "Strip X-Forwarded-Prefix at the edge or include it in the cache key. Never reflect prefix values into HTML or URLs.",
        Evidence::new()
            .with("url", url.to_string())
            .with("prefix_value", prefix_val.clone())
            .with("reflection_location", loc)
            .check("prefix_reflected", true, loc)
            .check("unkeyed_and_cached", confirmed, if confirmed { "confirmed" } else { "not confirmed" }),
    );
    if confirmed {
        enrich_poc(
            &mut finding,
            poc_curl(
                "GET",
                &busted,
                &[("X-Forwarded-Prefix", prefix_val.as_str())],
                None,
            ),
        );
    }
    findings.push(finding);
    findings
}

/// Set-Cookie on a response that is still served from shared cache on HIT.
async fn probe_set_cookie_cache_bleed(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("scb");
    let busted = with_buster(url, &cb);
    let Some(p1) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let set_cookie = header_value(&p1.headers, "set-cookie").unwrap_or("");
    if set_cookie.is_empty() {
        return findings;
    }
    let hash1 = body_sha256(&p1.body);
    let Some(p2) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let sig2 = detect_cache(&p2);
    if !sig2.hit {
        return findings;
    }
    if body_sha256(&p2.body) != hash1 {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Set-Cookie response served from shared cache (HIT)",
        "high",
        &format!(
            "Response from {} issued Set-Cookie ('{}') yet a repeat request received cache HIT ({}) with an identical body. Session-establishing pages must never be stored in a shared CDN slot.",
            url,
            if set_cookie.len() > 80 {
                format!("{}…", &set_cookie[..80])
            } else {
                set_cookie.to_string()
            },
            sig2.headers.join("; ")
        ),
        0.87,
        "cookie_cache",
        "suspected",
        "Bypass cache when Set-Cookie is present. Use Cache-Control: private/no-store on all session responses.",
        Evidence::new()
            .with("url", url.to_string())
            .with("set_cookie_preview", set_cookie.chars().take(120).collect::<String>())
            .with("body_sha256", hash1)
            .check("set_cookie_present", true, "observed")
            .check("repeat_cache_hit", true, sig2.headers.join("; ")),
    ));
    findings
}

/// `stale-if-error` on dynamic responses — CDN may serve stale poison after origin errors.
async fn probe_stale_if_error_risk(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("sie");
    let busted = with_buster(url, &cb);
    let Some(p) = tracked_get(client, &busted, &[]).await else {
        return findings;
    };
    let cc = header_value(&p.headers, "cache-control").unwrap_or("");
    if !cc.to_ascii_lowercase().contains("stale-if-error") {
        return findings;
    }
    if !is_dynamic(&p) && !base_sig.cacheable {
        return findings;
    }
    let sig = detect_cache(&p);
    if !sig.cacheable && !base_sig.cacheable {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Dynamic response with stale-if-error at shared CDN",
        "medium",
        &format!(
            "Dynamic response at {} includes stale-if-error in Cache-Control='{}'. {} After a poisoned entry is stored, origin outages can prolong attacker content at the edge.",
            url, cc, sig.headers.join("; ")
        ),
        0.76,
        "cache_hardening",
        "present",
        "Avoid stale-if-error on HTML/session paths. Purge cache on security incidents.",
        Evidence::new()
            .with("url", url.to_string())
            .with("cache_control", cc.to_string())
            .check("stale_if_error", true, cc),
    ));
    findings
}

/// Sec-CH-Viewport-Width client hint fracture without Vary.
async fn probe_sec_ch_viewport_vary(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !base_sig.cacheable {
        return findings;
    }
    let cb = token("cv");
    let busted = with_buster(url, &cb);
    let narrow = tracked_get(client, &busted, &[("Sec-CH-Viewport-Width", "320")]).await;
    let wide = tracked_get(client, &busted, &[("Sec-CH-Viewport-Width", "1920")]).await;
    let (Some(a), Some(b)) = (narrow, wide) else {
        return findings;
    };
    if a.status != b.status || body_sha256(&a.body) == body_sha256(&b.body) {
        return findings;
    }
    let cc = header_value(&a.headers, "cache-control").unwrap_or("");
    let vary = header_value(&a.headers, "vary").unwrap_or("");
    if !is_publicly_cacheable(cc) || vary.to_ascii_lowercase().contains("sec-ch-viewport") {
        return findings;
    }
    findings.push(cache_finding(
        target,
        "Sec-CH-Viewport-Width variant cacheable without Vary",
        "medium",
        &format!(
            "Responses at {} differ by viewport width hint (320 vs 1920) without Vary covering Sec-CH-Viewport-Width. Responsive layouts may cross-poison mobile/desktop cache slots.",
            url
        ),
        0.72,
        "cache_hardening",
        "suspected",
        "Add Vary for Client Hints or disable caching on responsive branching paths.",
        Evidence::new()
            .with("url", url.to_string())
            .check("viewport_hint_changes_body", true, "320 vs 1920"),
    ));
    findings
}

/// Trailing-dot Host header — DNS/cache-key normalization fracture.
async fn probe_trailing_dot_host(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let Some(real_host) = parse_url_host(url) else {
        return findings;
    };
    let cb = token("td");
    let canary = token("wzt");
    let evil = env.trailing_dot_host(&canary);
    let busted = with_buster(url, &cb);
    let Some(p1) = tracked_get(client, &busted, &[("Host", evil.as_str())]).await else {
        return findings;
    };
    let Some(loc) = reflects(&p1, &canary) else {
        return findings;
    };
    let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;
    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            if reflects(&p2, &canary).is_some() {
                confirmed = true;
            }
        }
    }
    findings.push(cache_finding(
        target,
        if confirmed {
            "Confirmed cache poisoning via trailing-dot Host header"
        } else {
            "Trailing-dot Host header reflected into cacheable response"
        },
        if confirmed { "critical" } else { "high" },
        &format!(
            "Host: {} (URL authority: {}) reflected in {}. Trailing-dot hosts bypass naive host validators and fracture cache keys.",
            evil, real_host, loc
        ),
        if confirmed { 0.9 } else { 0.7 },
        "cache_poisoning",
        if confirmed { "confirmed" } else { "reflected" },
        "Reject Host headers with trailing dots. Normalize hostnames before cache-key hashing.",
        Evidence::new()
            .with("url", url.to_string())
            .with("injected_host", evil)
            .check("trailing_dot_reflected", true, loc)
            .check("unkeyed_and_cached", confirmed, if confirmed { "confirmed" } else { "not confirmed" }),
    ));
    findings
}

/// Protocol-relative Location (`//host/path`) on cacheable 3xx — redirect hijack primitive.
async fn probe_protocol_relative_redirect(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    env: &PathEnv,
    base_sig: &CacheSignal,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let cb = token("prr");
    let canary = token("wzp");
    let host_val = env.header_value(HeaderKind::Host, &canary);
    let busted = with_buster(url, &cb);
    let Some(p1) =
        tracked_get(client, &busted, &[("X-Forwarded-Host", host_val.as_str())]).await
    else {
        return findings;
    };
    if !is_redirect_status(p1.status) {
        return findings;
    }
    let location = header_value(&p1.headers, "location").unwrap_or("");
    if !location.starts_with("//") || !location.contains(&canary) {
        return findings;
    }
    let cacheable = detect_cache(&p1).cacheable || base_sig.cacheable;
    let mut confirmed = false;
    if cacheable {
        if let Some(p2) = tracked_get(client, &busted, &[]).await {
            let loc2 = header_value(&p2.headers, "location").unwrap_or("");
            if loc2.contains(&canary) {
                confirmed = true;
            }
        }
    }
    findings.push(cache_finding(
        target,
        if confirmed {
            "Confirmed protocol-relative redirect cache poisoning"
        } else {
            "Protocol-relative Location (//) on cacheable redirect"
        },
        if confirmed { "critical" } else { "high" },
        &format!(
            "Redirect from {} returned Location='{}' (protocol-relative). {} Cached // redirects inherit the victim's scheme — sitewide hijack to attacker host.",
            url, location,
            if confirmed { "Poison persisted without X-Forwarded-Host." } else { "Shared cache present." }
        ),
        if confirmed { 0.93 } else { 0.77 },
        "redirect_cache",
        if confirmed { "confirmed" } else { "reflected" },
        "Never cache redirects with scheme-relative Location derived from request headers. Use absolute HTTPS URLs only.",
        Evidence::new()
            .with("url", url.to_string())
            .with("location", location.to_string())
            .check("protocol_relative", true, location)
            .check("cached_poison", confirmed, if confirmed { "yes" } else { "no" }),
    ));
    findings
}

fn dedupe_findings(findings: Vec<Value>) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(findings.len());
    for f in findings {
        let key = format!(
            "{}|{}|{}",
            f.get("category").and_then(Value::as_str).unwrap_or(""),
            f.get("title").and_then(Value::as_str).unwrap_or(""),
            f.get("evidence")
                .and_then(|e| e.get("url"))
                .and_then(Value::as_str)
                .unwrap_or("")
        );
        if seen.insert(key) {
            out.push(f);
        }
    }
    out
}

fn build_coverage_manifest(probe_flags: &[(&str, bool)], findings_count: usize) -> Value {
    let enabled: usize = probe_flags.iter().filter(|(_, on)| *on).count();
    let total = probe_flags.len();
    let dimensions = [
        "unkeyed_input_poisoning",
        "cache_key_oracles",
        "normalization_fractures",
        "method_range_primitives",
        "protocol_schism",
        "client_hint_fractures",
        "session_auth_isolation",
        "redirect_poisoning",
        "cache_deception",
        "cdn_hardening_intel",
        "conditional_validators",
        "edge_directive_schisms",
        "duplicate_header_oracles",
    ];
    let sealed = enabled >= total;
    json!({
        "engine_version": "cache_posture_v11_sealed",
        "probe_categories_total": total,
        "probes_enabled": enabled,
        "findings_observed": findings_count,
        "competitive_dimensions": dimensions,
        "coverage_complete": sealed,
        "sealed_complete": sealed,
        "competitive_parity": if sealed { "world_class_complete" } else { "partial" },
        "enabled_probes": probe_flags.iter().filter(|(_, on)| *on).map(|(n, _)| *n).collect::<Vec<_>>(),
    })
}

fn build_competitive_parity_index(probe_flags: &[(&str, bool)], beyond_score: u32) -> u32 {
    let enabled = probe_flags.iter().filter(|(_, on)| *on).count() as u32;
    let total = probe_flags.len().max(1) as u32;
    let breadth = (enabled * 100 / total).min(100);
    breadth.min(beyond_score).min(100)
}

fn compute_poison_window_seconds(findings: &[Value]) -> u64 {
    findings
        .iter()
        .filter_map(|f| {
            f.get("evidence")
                .and_then(|e| e.get("cache_ttl_seconds"))
                .and_then(Value::as_u64)
        })
        .max()
        .unwrap_or(0)
}

fn build_top_primitives(findings: &[Value]) -> Vec<Value> {
    let mut ranked: Vec<(u8, f64, Value)> = Vec::new();
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        let exp = f.get("exposure").and_then(Value::as_str).unwrap_or("");
        if !matches!(exp, "confirmed" | "suspected" | "reflected")
            && !matches!(sev, "critical" | "high")
        {
            continue;
        }
        let conf = f.get("confidence").and_then(Value::as_f64).unwrap_or(0.5);
        let score = severity_rank(sev) as f64 * 10.0
            + if exp == "confirmed" { 20.0 } else { 0.0 }
            + conf * 5.0;
        ranked.push((
            severity_rank(sev),
            score,
            json!({
                "title": f.get("title").and_then(Value::as_str).unwrap_or(""),
                "severity": sev,
                "exposure": exp,
                "category": f.get("category").and_then(Value::as_str).unwrap_or(""),
                "confidence": conf,
                "url": f.get("evidence").and_then(|e| e.get("url")).and_then(Value::as_str).unwrap_or(""),
            }),
        ));
    }
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked.into_iter().take(8).map(|(_, _, v)| v).collect()
}

fn build_compliance_map(findings: &[Value]) -> Value {
    let mut cwe: BTreeSet<String> = BTreeSet::new();
    let mut owasp: BTreeSet<String> = BTreeSet::new();
    cwe.insert("CWE-444".to_string()); // HTTP Request Smuggling adjacent / cache poisoning class
    owasp.insert("A05:2021 Security Misconfiguration".to_string());
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        let exp = f.get("exposure").and_then(Value::as_str).unwrap_or("");
        match cat {
            "cache_poisoning" | "redirect_cache" if exp == "confirmed" => {
                cwe.insert("CWE-349".to_string());
                owasp.insert("Web Cache Poisoning".to_string());
            }
            "cache_deception" => {
                cwe.insert("CWE-525".to_string());
                owasp.insert("Web Cache Deception".to_string());
            }
            "auth_cache" | "cookie_cache" => {
                cwe.insert("CWE-613".to_string());
            }
            _ => {}
        }
    }
    json!({
        "cwe": cwe.iter().collect::<Vec<_>>(),
        "owasp": owasp.iter().collect::<Vec<_>>(),
        "mitre_attack": ["T1557"],
    })
}

fn build_defense_controls(findings: &[Value]) -> Value {
    let mut controls: BTreeSet<String> = BTreeSet::new();
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        if !matches!(sev, "critical" | "high" | "medium") {
            continue;
        }
        match cat {
            "cache_poisoning" | "redirect_cache" => {
                controls.insert("strip_x_forwarded_and_forwarded_at_edge".to_string());
                controls.insert("include_unkeyed_headers_in_cache_key".to_string());
                controls.insert("never_reflect_untrusted_host_into_body".to_string());
            }
            "cache_key_oracle" | "cache_normalization" => {
                controls.insert("normalize_cache_key_canonical_form".to_string());
                controls.insert("include_all_query_params_in_cache_key".to_string());
            }
            "cache_method" => {
                controls.insert("key_http_method_in_cache".to_string());
            }
            "auth_cache" | "cookie_cache" => {
                controls.insert("vary_authorization_and_cookie".to_string());
                controls.insert("no_store_on_session_responses".to_string());
            }
            "cache_hardening" => {
                controls.insert("complete_vary_header".to_string());
                controls.insert("respect_origin_no_store_at_cdn".to_string());
            }
            "cache_deception" => {
                controls.insert("cache_by_content_type_not_url_suffix".to_string());
            }
            "cache_protocol" => {
                controls.insert("key_protocol_in_cache_or_disable_h2_cache".to_string());
            }
            _ => {}
        }
    }
    json!({
        "controls_required": controls.iter().collect::<Vec<_>>(),
        "control_count": controls.len(),
    })
}

fn build_risk_matrix(findings: &[Value]) -> Value {
    let mut map = serde_json::Map::new();
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let cat = f
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("other")
            .to_string();
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("info");
        let entry = map
            .entry(cat)
            .or_insert_with(|| json!({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}));
        if let Some(obj) = entry.as_object_mut() {
            if let Some(n) = obj.get_mut(sev) {
                if let Some(v) = n.as_u64() {
                    *n = json!(v + 1);
                }
            }
        }
    }
    Value::Object(map)
}

fn build_cdn_playbook(vendor: Option<&str>, findings: &[Value]) -> Value {
    let has_confirmed = findings.iter().any(|f| {
        f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });
    let mut steps: Vec<String> = Vec::new();
    match vendor.unwrap_or("generic") {
        "Cloudflare" => {
            steps.push("Cloudflare: enable 'Cache Key' customization — include all query params; add X-Forwarded-Host to cache key or strip via Transform Rules.".to_string());
            steps.push("Cloudflare: use Cache Rules to bypass cache on Set-Cookie / Authorization responses.".to_string());
        }
        "AWS CloudFront" => {
            steps.push("CloudFront: configure Origin Request / Cache Policies to whitelist only required headers/query strings in the cache key.".to_string());
            steps.push("CloudFront: enable CachingDisabled policy on dynamic behaviors; never forward X-Forwarded-Host to origin.".to_string());
        }
        "Fastly" => {
            steps.push("Fastly: define VCL recv to strip X-Forwarded-* before hash; use req.http.Fastly-FF checks.".to_string());
            steps.push("Fastly: set beresp.cacheable = false when Set-Cookie present.".to_string());
        }
        "Akamai" => {
            steps.push("Akamai: use Cache ID Modification to include all query parameters; enable SureRoute only on static assets.".to_string());
        }
        _ => {
            steps.push("Generic CDN: treat cache key as trust boundary — key every input that affects the response.".to_string());
        }
    }
    if has_confirmed {
        steps.insert(
            0,
            "URGENT: confirmed cache poisoning primitive — purge affected cache namespace and deploy header-stripping at edge before next scan.".to_string(),
        );
    }
    json!({
        "vendor": vendor.unwrap_or("generic"),
        "steps": steps,
    })
}

fn compute_exploitability_index(findings: &[Value]) -> u32 {
    let mut score = 0u32;
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let exp = f.get("exposure").and_then(Value::as_str).unwrap_or("");
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        score += match (exp, sev) {
            ("confirmed", "critical") => 28,
            ("confirmed", "high") => 20,
            ("confirmed", _) => 14,
            ("suspected", "critical") | ("suspected", "high") => 12,
            ("reflected", "high") | ("reflected", "critical") => 10,
            ("variant", "high") | ("variant", "critical") => 8,
            (_, "critical") => 15,
            (_, "high") => 8,
            (_, "medium") => 4,
            _ => 1,
        };
    }
    score.min(100)
}

fn count_confirmed_primitives(findings: &[Value]) -> u32 {
    findings
        .iter()
        .filter(|f| {
            f.get("summary").and_then(Value::as_bool) != Some(true)
                && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
        })
        .count() as u32
}

fn build_attack_chains(findings: &[Value], any_cache: bool) -> Vec<Value> {
    let mut chains = Vec::new();
    let has_confirmed_poison = findings.iter().any(|f| {
        f.get("category").and_then(Value::as_str) == Some("cache_poisoning")
            && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });
    let has_redirect = findings.iter().any(|f| {
        f.get("category").and_then(Value::as_str) == Some("redirect_cache")
            && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });
    let has_auth_bleed = findings.iter().any(|f| {
        f.get("category").and_then(Value::as_str) == Some("auth_cache")
            && matches!(
                f.get("exposure").and_then(Value::as_str),
                Some("confirmed" | "suspected")
            )
    });
    let has_deception = findings.iter().any(|f| {
        f.get("category").and_then(Value::as_str) == Some("cache_deception")
            && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });

    if any_cache && has_confirmed_poison {
        chains.push(json!({
            "id": "mass_cache_poison",
            "title": "Mass user cache poisoning",
            "severity": "critical",
            "description": "Confirmed unkeyed-input poisoning on a shared cache — any visitor receives the attacker-primed response.",
            "mitre": "T1557"
        }));
    }
    if has_redirect {
        chains.push(json!({
            "id": "redirect_hijack",
            "title": "Sitewide redirect hijack",
            "severity": "critical",
            "description": "Cached 3xx with attacker-controlled Location — victims are redirected to a malicious host on every cache HIT.",
            "mitre": "T1557"
        }));
    }
    if has_auth_bleed && any_cache {
        chains.push(json!({
            "id": "auth_session_bleed",
            "title": "Authenticated session bleed via CDN",
            "severity": "critical",
            "description": "Authorization-dependent responses are cacheable without Vary — API/session data may be served to anonymous users.",
            "mitre": "T1557"
        }));
    }
    if has_deception {
        chains.push(json!({
            "id": "cache_deception_harvest",
            "title": "Web cache deception data harvest",
            "severity": "high",
            "description": "Dynamic authenticated pages cached under static suffixes — attacker reads victim session from shared cache.",
            "mitre": "T1557"
        }));
    }
    let has_host_poison = findings.iter().any(|f| {
        f.get("title")
            .and_then(Value::as_str)
            .map(|t| t.contains("Host header override"))
            .unwrap_or(false)
            && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });
    if any_cache && has_host_poison {
        chains.push(json!({
            "id": "host_header_mass_poison",
            "title": "Host-header cache slot hijack",
            "severity": "critical",
            "description": "Confirmed Host header override poisoning — CDN cache key ignores Host, attacker poisons the shared slot for the URL path.",
            "mitre": "T1557"
        }));
    }
    chains
}

fn build_probe_manifest(enabled: &[(&str, bool)]) -> Value {
    let enabled_list: Vec<&str> = enabled.iter().filter(|(_, on)| *on).map(|(n, _)| *n).collect();
    json!({
        "probes_enabled": enabled_list.len(),
        "probes": enabled_list,
        "engine_version": "cache_posture_v11_sealed",
    })
}

#[derive(Clone, Copy)]
struct ProbeToggles {
    fingerprint: bool,
    unkeyed: bool,
    query_unkeyed: bool,
    cookie_cache: bool,
    hardening: bool,
    fat_get: bool,
    method_confusion: bool,
    range_poisoning: bool,
    normalization: bool,
    cache_key_oracle: bool,
    h2_schism: bool,
    encoding_vary: bool,
    method_override: bool,
    authorization_cache: bool,
    redirect_poisoning: bool,
    query_order: bool,
    cdn_schism: bool,
    user_agent_vary: bool,
    tracking_oracle: bool,
    vary_incomplete: bool,
    stale_revalidate: bool,
    accept_vary: bool,
    post_cache: bool,
    immutable_dynamic: bool,
    etag_injection: bool,
    case_header: bool,
    sec_fetch: bool,
    save_data: bool,
    options_cache: bool,
    pragma_oracle: bool,
    forwarded_rfc7239: bool,
    host_header: bool,
    edge_no_store: bool,
    vary_star: bool,
    link_header: bool,
    duplicate_query: bool,
    accept_lang_order: bool,
    if_none_match: bool,
    if_modified_since: bool,
    duplicate_header: bool,
    only_if_cached: bool,
    x_requested_with: bool,
    prefer_vary: bool,
    alt_svc_h3: bool,
    s_maxage_schism: bool,
    brotli_vary: bool,
    sec_ch_ua: bool,
    forwarded_prefix: bool,
    set_cookie_cache_bleed: bool,
    stale_if_error: bool,
    sec_ch_viewport: bool,
    trailing_dot_host: bool,
    protocol_relative_redirect: bool,
    deception: bool,
}

struct PathScanResult {
    findings: Vec<Value>,
    cacheable: bool,
    vendor: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn scan_one_path(
    client: reqwest::Client,
    url: String,
    target: String,
    env: PathEnv,
    toggles: ProbeToggles,
    max_tier: u8,
    header_fanout: usize,
    include_info: bool,
    timeout_ms: u64,
    query_param: String,
    header_set: Vec<(String, HeaderKind)>,
    exts: Vec<String>,
) -> PathScanResult {
    let mut findings = Vec::new();
    let mut cacheable = false;
    let mut vendor = None;
    let mut sig = CacheSignal::default();

    if toggles.fingerprint {
        let (fps, s) = probe_fingerprint(&client, &url, &target).await;
        sig = s;
        if sig.cacheable {
            cacheable = true;
            if sig.vendor.is_some() {
                vendor = sig.vendor.clone();
            }
        }
        for f in fps {
            let sev = f.get("severity").and_then(Value::as_str).unwrap_or("info");
            if include_info || sev != "info" {
                findings.push(f);
            }
        }
    }
    if toggles.unkeyed {
        findings.extend(
            probe_unkeyed_headers(&client, &url, &target, &env, &header_set, &sig, header_fanout).await,
        );
    }
    if toggles.query_unkeyed {
        findings.extend(probe_query_unkeyed(&client, &url, &target, &sig, &query_param).await);
    }
    if toggles.cookie_cache {
        findings.extend(probe_cookie_cache(&client, &url, &target, &sig).await);
    }
    if toggles.hardening {
        findings.extend(probe_cache_hardening(&client, &url, &target, &sig).await);
    }
    if toggles.fat_get && max_tier >= 2 {
        findings.extend(probe_fat_get(&client, &url, &target, &sig).await);
    }
    if toggles.method_confusion && max_tier >= 2 {
        findings.extend(probe_method_confusion(&client, &url, &target, &env, &sig).await);
    }
    if toggles.range_poisoning && max_tier >= 2 {
        findings.extend(probe_range_poisoning(&client, &url, &target, &env, &sig).await);
    }
    if toggles.normalization && max_tier >= 3 {
        findings.extend(probe_normalization(&client, &url, &target, &env, &sig).await);
    }
    if toggles.cache_key_oracle && max_tier >= 3 {
        findings.extend(probe_cache_key_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.h2_schism && max_tier >= 2 {
        findings.extend(probe_h2_cache_schism(timeout_ms, &url, &target, &sig).await);
    }
    if toggles.encoding_vary && max_tier >= 2 {
        findings.extend(probe_encoding_vary(&client, &url, &target, &sig).await);
    }
    if toggles.method_override && max_tier >= 2 {
        findings.extend(probe_method_override(&client, &url, &target, &sig).await);
    }
    if toggles.authorization_cache && max_tier >= 2 {
        findings.extend(probe_authorization_cache(&client, &url, &target, &sig).await);
    }
    if toggles.redirect_poisoning && max_tier >= 2 {
        findings.extend(probe_redirect_poisoning(&client, &url, &target, &env, &sig).await);
    }
    if toggles.query_order && max_tier >= 3 {
        findings.extend(probe_query_order_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.cdn_schism {
        findings.extend(probe_cdn_origin_cache_schism(&client, &url, &target, &sig).await);
    }
    if toggles.user_agent_vary && max_tier >= 2 {
        findings.extend(probe_user_agent_vary(&client, &url, &target, &sig).await);
    }
    if toggles.tracking_oracle && max_tier >= 2 {
        findings.extend(probe_tracking_param_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.vary_incomplete && max_tier >= 2 {
        findings.extend(probe_vary_incomplete(&client, &url, &target, &sig).await);
    }
    if toggles.stale_revalidate {
        findings.extend(probe_stale_revalidate_risk(&client, &url, &target, &sig).await);
    }
    if toggles.accept_vary && max_tier >= 2 {
        findings.extend(probe_accept_vary(&client, &url, &target, &sig).await);
    }
    if toggles.post_cache && max_tier >= 3 {
        findings.extend(probe_post_cache_oracle(&client, &url, &target, &sig).await);
    }
    if toggles.immutable_dynamic {
        findings.extend(probe_immutable_dynamic(&client, &url, &target, &sig).await);
    }
    if toggles.etag_injection && max_tier >= 2 {
        findings.extend(probe_etag_injection(&client, &url, &target, &env, &sig).await);
    }
    if toggles.case_header && max_tier >= 2 {
        findings.extend(probe_case_header_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.sec_fetch && max_tier >= 2 {
        findings.extend(probe_sec_fetch_vary(&client, &url, &target, &sig).await);
    }
    if toggles.save_data && max_tier >= 2 {
        findings.extend(probe_save_data_vary(&client, &url, &target, &sig).await);
    }
    if toggles.options_cache && max_tier >= 2 {
        findings.extend(probe_options_cache_oracle(&client, &url, &target, &sig).await);
    }
    if toggles.pragma_oracle {
        findings.extend(probe_pragma_no_cache_oracle(&client, &url, &target, &sig).await);
    }
    if toggles.forwarded_rfc7239 && max_tier >= 2 {
        findings.extend(probe_forwarded_rfc7239(&client, &url, &target, &env, &sig).await);
    }
    if toggles.host_header && max_tier >= 2 {
        findings.extend(probe_host_header_poison(&client, &url, &target, &env, &sig).await);
    }
    if toggles.edge_no_store {
        findings.extend(probe_edge_no_store_bypass(&client, &url, &target, &sig).await);
    }
    if toggles.vary_star {
        findings.extend(probe_vary_star_misconfig(&client, &url, &target, &sig).await);
    }
    if toggles.link_header && max_tier >= 2 {
        findings.extend(probe_link_header_poison(&client, &url, &target, &env, &sig).await);
    }
    if toggles.duplicate_query && max_tier >= 3 {
        findings.extend(probe_duplicate_query_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.accept_lang_order && max_tier >= 2 {
        findings.extend(probe_accept_language_order(&client, &url, &target, &sig).await);
    }
    if toggles.if_none_match && max_tier >= 2 {
        findings.extend(probe_if_none_match_cache(&client, &url, &target, &env, &sig).await);
    }
    if toggles.if_modified_since && max_tier >= 2 {
        findings.extend(probe_if_modified_since_cache(&client, &url, &target, &env, &sig).await);
    }
    if toggles.duplicate_header && max_tier >= 2 {
        findings.extend(probe_duplicate_header_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.only_if_cached && max_tier >= 2 {
        findings.extend(probe_only_if_cached_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.x_requested_with && max_tier >= 2 {
        findings.extend(probe_x_requested_with_vary(&client, &url, &target, &sig).await);
    }
    if toggles.prefer_vary && max_tier >= 2 {
        findings.extend(probe_prefer_vary(&client, &url, &target, &sig).await);
    }
    if toggles.alt_svc_h3 && max_tier >= 2 {
        findings.extend(probe_alt_svc_h3_surface(&client, &url, &target, &sig).await);
    }
    if toggles.s_maxage_schism {
        findings.extend(probe_s_maxage_schism(&client, &url, &target, &sig).await);
    }
    if toggles.brotli_vary && max_tier >= 2 {
        findings.extend(probe_brotli_encoding_vary(&client, &url, &target, &sig).await);
    }
    if toggles.sec_ch_ua && max_tier >= 2 {
        findings.extend(probe_sec_ch_ua_vary(&client, &url, &target, &sig).await);
    }
    if toggles.forwarded_prefix && max_tier >= 2 {
        findings.extend(probe_x_forwarded_prefix_poison(&client, &url, &target, &sig).await);
    }
    if toggles.set_cookie_cache_bleed {
        findings.extend(probe_set_cookie_cache_bleed(&client, &url, &target, &sig).await);
    }
    if toggles.stale_if_error {
        findings.extend(probe_stale_if_error_risk(&client, &url, &target, &sig).await);
    }
    if toggles.sec_ch_viewport && max_tier >= 2 {
        findings.extend(probe_sec_ch_viewport_vary(&client, &url, &target, &sig).await);
    }
    if toggles.trailing_dot_host && max_tier >= 2 {
        findings.extend(probe_trailing_dot_host(&client, &url, &target, &env, &sig).await);
    }
    if toggles.protocol_relative_redirect && max_tier >= 2 {
        findings.extend(probe_protocol_relative_redirect(&client, &url, &target, &env, &sig).await);
    }
    if toggles.deception {
        findings.extend(probe_deception(&client, &url, &target, &exts).await);
    }

    PathScanResult {
        findings,
        cacheable,
        vendor,
    }
}

// ── Orchestration + posture summary ─────────────────────────────────────────

/// Backward-compatible entry (CLI + alias callers). Uses default parameters.
pub async fn run_cache_poisoning_result(target: &str) -> EngineResult {
    run_cache_poisoning_result_ctx(target, &EngineRunContext::default()).await
}

/// Parameterised entry used by the dispatch layer (reads `ctx.job_params`).
pub async fn run_cache_poisoning_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let timeout_ms = cfg.timeout_ms(8000);
    let intensity = cfg.intensity();
    let include_info = cfg.bool_or("include_info_findings", true);
    let concurrency = cfg.concurrency().clamp(1, 16);
    let client = build_client(timeout_ms).await;

    let check_fingerprint = cfg.bool_or("check_fingerprint", true);
    let check_unkeyed = cfg.bool_or("check_unkeyed", true);
    let check_deception = cfg.bool_or("check_deception", true);
    let check_query_unkeyed = cfg.bool_or("check_query_unkeyed", true);
    let check_cookie_cache = cfg.bool_or("check_cookie_cache", true);
    let check_hardening = cfg.bool_or("check_hardening", true);
    let check_fat_get = cfg.bool_or("check_fat_get", true);
    let check_method_confusion = cfg.bool_or("check_method_confusion", true);
    let check_range_poisoning = cfg.bool_or("check_range_poisoning", true);
    let check_normalization = cfg.bool_or("check_normalization", true);
    let check_cache_key_oracle = cfg.bool_or("check_cache_key_oracle", true);
    let check_h2_schism = cfg.bool_or("check_h2_schism", true);
    let check_encoding_vary = cfg.bool_or("check_encoding_vary", true);
    let check_method_override = cfg.bool_or("check_method_override", true);
    let check_authorization_cache = cfg.bool_or("check_authorization_cache", true);
    let check_redirect_poisoning = cfg.bool_or("check_redirect_poisoning", true);
    let check_query_order = cfg.bool_or("check_query_order", true);
    let check_cdn_schism = cfg.bool_or("check_cdn_schism", true);
    let check_user_agent_vary = cfg.bool_or("check_user_agent_vary", true);
    let check_tracking_oracle = cfg.bool_or("check_tracking_oracle", true);
    let check_vary_incomplete = cfg.bool_or("check_vary_incomplete", true);
    let check_stale_revalidate = cfg.bool_or("check_stale_revalidate", true);
    let check_accept_vary = cfg.bool_or("check_accept_vary", true);
    let check_post_cache = cfg.bool_or("check_post_cache", true);
    let check_immutable_dynamic = cfg.bool_or("check_immutable_dynamic", true);
    let check_etag_injection = cfg.bool_or("check_etag_injection", true);
    let check_case_header = cfg.bool_or("check_case_header", true);
    let check_path_discover = cfg.bool_or("check_path_discover", true);
    let check_sec_fetch = cfg.bool_or("check_sec_fetch", true);
    let check_save_data = cfg.bool_or("check_save_data", true);
    let check_options_cache = cfg.bool_or("check_options_cache", true);
    let check_pragma_oracle = cfg.bool_or("check_pragma_oracle", true);
    let check_forwarded_rfc7239 = cfg.bool_or("check_forwarded_rfc7239", true);
    let check_host_header = cfg.bool_or("check_host_header", true);
    let check_edge_no_store = cfg.bool_or("check_edge_no_store", true);
    let check_vary_star = cfg.bool_or("check_vary_star", true);
    let check_link_header = cfg.bool_or("check_link_header", true);
    let check_duplicate_query = cfg.bool_or("check_duplicate_query", true);
    let check_accept_lang_order = cfg.bool_or("check_accept_lang_order", true);
    let check_if_none_match = cfg.bool_or("check_if_none_match", true);
    let check_if_modified_since = cfg.bool_or("check_if_modified_since", true);
    let check_duplicate_header = cfg.bool_or("check_duplicate_header", true);
    let check_only_if_cached = cfg.bool_or("check_only_if_cached", true);
    let check_x_requested_with = cfg.bool_or("check_x_requested_with", true);
    let check_prefer_vary = cfg.bool_or("check_prefer_vary", true);
    let check_alt_svc_h3 = cfg.bool_or("check_alt_svc_h3", true);
    let check_s_maxage_schism = cfg.bool_or("check_s_maxage_schism", true);
    let check_brotli_vary = cfg.bool_or("check_brotli_vary", true);
    let check_sec_ch_ua = cfg.bool_or("check_sec_ch_ua", true);
    let check_forwarded_prefix = cfg.bool_or("check_forwarded_prefix", true);
    let check_set_cookie_cache_bleed = cfg.bool_or("check_set_cookie_cache_bleed", true);
    let check_stale_if_error = cfg.bool_or("check_stale_if_error", true);
    let check_sec_ch_viewport = cfg.bool_or("check_sec_ch_viewport", true);
    let check_trailing_dot_host = cfg.bool_or("check_trailing_dot_host", true);
    let check_protocol_relative_redirect = cfg.bool_or("check_protocol_relative_redirect", true);
    let query_param = cfg.string_or("query_param", "wzqp");
    let path_concurrency = cfg.usize_or("path_concurrency", 2).clamp(1, 4);
    let max_paths = cfg.usize_or("max_paths", 0);

    let probe_flags: &[(&str, bool)] = &[
        ("fingerprint", check_fingerprint),
        ("unkeyed_headers", check_unkeyed),
        ("query_unkeyed", check_query_unkeyed),
        ("cookie_cache", check_cookie_cache),
        ("hardening", check_hardening),
        ("fat_get", check_fat_get),
        ("method_confusion", check_method_confusion),
        ("range_poisoning", check_range_poisoning),
        ("normalization", check_normalization),
        ("cache_key_oracle", check_cache_key_oracle),
        ("h2_schism", check_h2_schism),
        ("encoding_vary", check_encoding_vary),
        ("method_override", check_method_override),
        ("authorization_cache", check_authorization_cache),
        ("redirect_poisoning", check_redirect_poisoning),
        ("query_order", check_query_order),
        ("cdn_schism", check_cdn_schism),
        ("user_agent_vary", check_user_agent_vary),
        ("tracking_oracle", check_tracking_oracle),
        ("vary_incomplete", check_vary_incomplete),
        ("stale_revalidate", check_stale_revalidate),
        ("accept_vary", check_accept_vary),
        ("post_cache", check_post_cache),
        ("immutable_dynamic", check_immutable_dynamic),
        ("etag_injection", check_etag_injection),
        ("case_header", check_case_header),
        ("path_discover", check_path_discover),
        ("sec_fetch", check_sec_fetch),
        ("save_data", check_save_data),
        ("options_cache", check_options_cache),
        ("pragma_oracle", check_pragma_oracle),
        ("forwarded_rfc7239", check_forwarded_rfc7239),
        ("host_header", check_host_header),
        ("edge_no_store", check_edge_no_store),
        ("vary_star", check_vary_star),
        ("link_header", check_link_header),
        ("duplicate_query", check_duplicate_query),
        ("accept_lang_order", check_accept_lang_order),
        ("if_none_match", check_if_none_match),
        ("if_modified_since", check_if_modified_since),
        ("duplicate_header", check_duplicate_header),
        ("only_if_cached", check_only_if_cached),
        ("x_requested_with", check_x_requested_with),
        ("prefer_vary", check_prefer_vary),
        ("alt_svc_h3", check_alt_svc_h3),
        ("s_maxage_schism", check_s_maxage_schism),
        ("brotli_vary", check_brotli_vary),
        ("sec_ch_ua", check_sec_ch_ua),
        ("forwarded_prefix", check_forwarded_prefix),
        ("set_cookie_cache_bleed", check_set_cookie_cache_bleed),
        ("stale_if_error", check_stale_if_error),
        ("sec_ch_viewport", check_sec_ch_viewport),
        ("trailing_dot_host", check_trailing_dot_host),
        ("protocol_relative_redirect", check_protocol_relative_redirect),
        ("deception", check_deception),
    ];

    HTTP_REQUESTS.store(0, Ordering::Relaxed);
    let scan_started = Instant::now();
    let env = PathEnv::from_cfg(&cfg);
    let canary_domain = env.poison_domain.to_string();

    let default_path_limit = if matches!(intensity, Intensity::Aggressive) {
        10
    } else {
        4
    };
    let path_limit = if max_paths > 0 {
        max_paths.clamp(1, 16)
    } else {
        default_path_limit
    };

    let base = base_url(target);
    let mut paths = cfg.string_list("paths");
    if paths.is_empty() {
        paths.push("/".to_string());
    }
    if check_path_discover {
        let pd_cb = token("pd");
        let discover_url = with_buster(&base, &pd_cb);
        if let Some(home) = tracked_get(&client, &discover_url, &[]).await {
            for dp in discover_paths_from_html(&home.body) {
                if paths.len() >= path_limit {
                    break;
                }
                if !paths.iter().any(|p| p == &dp) {
                    paths.push(dp);
                }
            }
        }
    }
    let max_tier = match intensity {
        Intensity::Light => 1,
        Intensity::Normal => 2,
        Intensity::Aggressive => 3,
    };
    let mut header_set: Vec<(String, HeaderKind)> = UNKEYED_HEADERS
        .iter()
        .filter(|h| h.tier <= max_tier)
        .map(|h| (h.name.to_string(), h.kind))
        .collect();
    // Operator-supplied extra headers (treated as Host-type reflections).
    for name in cfg.string_list("headers") {
        header_set.push((name, HeaderKind::Host));
    }
    let exts = cfg.string_list_or("deception_extensions", DEFAULT_DECEPTION_EXTS);

    let toggles = ProbeToggles {
        fingerprint: check_fingerprint,
        unkeyed: check_unkeyed,
        query_unkeyed: check_query_unkeyed,
        cookie_cache: check_cookie_cache,
        hardening: check_hardening,
        fat_get: check_fat_get,
        method_confusion: check_method_confusion,
        range_poisoning: check_range_poisoning,
        normalization: check_normalization,
        cache_key_oracle: check_cache_key_oracle,
        h2_schism: check_h2_schism,
        encoding_vary: check_encoding_vary,
        method_override: check_method_override,
        authorization_cache: check_authorization_cache,
        redirect_poisoning: check_redirect_poisoning,
        query_order: check_query_order,
        cdn_schism: check_cdn_schism,
        user_agent_vary: check_user_agent_vary,
        tracking_oracle: check_tracking_oracle,
        vary_incomplete: check_vary_incomplete,
        stale_revalidate: check_stale_revalidate,
        accept_vary: check_accept_vary,
        post_cache: check_post_cache,
        immutable_dynamic: check_immutable_dynamic,
        etag_injection: check_etag_injection,
        case_header: check_case_header,
        sec_fetch: check_sec_fetch,
        save_data: check_save_data,
        options_cache: check_options_cache,
        pragma_oracle: check_pragma_oracle,
        forwarded_rfc7239: check_forwarded_rfc7239,
        host_header: check_host_header,
        edge_no_store: check_edge_no_store,
        vary_star: check_vary_star,
        link_header: check_link_header,
        duplicate_query: check_duplicate_query,
        accept_lang_order: check_accept_lang_order,
        if_none_match: check_if_none_match,
        if_modified_since: check_if_modified_since,
        duplicate_header: check_duplicate_header,
        only_if_cached: check_only_if_cached,
        x_requested_with: check_x_requested_with,
        prefer_vary: check_prefer_vary,
        alt_svc_h3: check_alt_svc_h3,
        s_maxage_schism: check_s_maxage_schism,
        brotli_vary: check_brotli_vary,
        sec_ch_ua: check_sec_ch_ua,
        forwarded_prefix: check_forwarded_prefix,
        set_cookie_cache_bleed: check_set_cookie_cache_bleed,
        stale_if_error: check_stale_if_error,
        sec_ch_viewport: check_sec_ch_viewport,
        trailing_dot_host: check_trailing_dot_host,
        protocol_relative_redirect: check_protocol_relative_redirect,
        deception: check_deception,
    };

    let scan_urls: Vec<String> = paths
        .iter()
        .take(path_limit)
        .map(|path| {
            if path == "/" || path.is_empty() {
                base.clone()
            } else {
                format!(
                    "{}/{}",
                    base.trim_end_matches('/'),
                    path.trim_start_matches('/')
                )
            }
        })
        .collect();

    let target_owned = target.to_string();
    let query_param_owned = query_param.clone();
    let mut findings: Vec<Value> = Vec::new();
    let mut any_cache = false;
    let mut detected_vendor: Option<String> = None;

    for chunk in scan_urls.chunks(path_concurrency) {
        let futs: Vec<_> = chunk
            .iter()
            .map(|url| {
                scan_one_path(
                    client.clone(),
                    url.clone(),
                    target_owned.clone(),
                    env.clone(),
                    toggles,
                    max_tier,
                    concurrency,
                    include_info,
                    timeout_ms,
                    query_param_owned.clone(),
                    header_set.clone(),
                    exts.clone(),
                )
            })
            .collect();
        for res in join_all(futs).await {
            findings.extend(res.findings);
            if res.cacheable {
                any_cache = true;
            }
            if res.vendor.is_some() {
                detected_vendor = res.vendor;
            }
        }
    }

    findings = dedupe_findings(findings);

    let summary = build_summary(
        target,
        &base,
        &findings,
        any_cache,
        detected_vendor.as_deref(),
        intensity,
        probe_flags,
        concurrency,
        scan_started.elapsed().as_millis(),
        scan_urls.len(),
        path_concurrency,
        &canary_domain,
        path_limit,
        max_paths,
    );
    let score = summary.get("posture_score").and_then(Value::as_u64).unwrap_or(100);
    let real = findings.len();
    findings.insert(0, summary);

    EngineResult::ok(
        findings,
        format!("Web cache posture {}/100 — {} finding(s) for {}", score, real, base),
    )
}

fn build_summary(
    target: &str,
    base: &str,
    findings: &[Value],
    any_cache: bool,
    detected_vendor: Option<&str>,
    intensity: Intensity,
    probe_flags: &[(&str, bool)],
    concurrency: usize,
    scan_duration_ms: u128,
    paths_tested: usize,
    path_concurrency: usize,
    canary_domain: &str,
    path_limit_applied: usize,
    max_paths: usize,
) -> Value {
    let mut crit = 0u32;
    let mut high = 0u32;
    let mut med = 0u32;
    let mut low = 0u32;
    let mut categories: BTreeSet<String> = BTreeSet::new();
    let mut worst = "info";
    for f in findings {
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        match sev {
            "critical" => crit += 1,
            "high" => high += 1,
            "medium" => med += 1,
            "low" => low += 1,
            _ => {}
        }
        if severity_rank(sev) > severity_rank(worst) {
            worst = sev;
        }
        let exposure = f.get("exposure").and_then(Value::as_str).unwrap_or("");
        if !matches!(exposure, "present" | "clean") {
            if let Some(c) = f.get("category").and_then(Value::as_str) {
                categories.insert(c.to_string());
            }
        }
    }
    let penalty = crit * 30 + high * 14 + med * 6 + low * 2;
    let score = 100u32.saturating_sub(penalty).max(if crit > 0 { 0 } else { 5 });
    let grade = match score {
        92..=100 => "A",
        80..=91 => "B",
        65..=79 => "C",
        45..=64 => "D",
        _ => "F",
    };
    let cats: Vec<String> = categories.iter().cloned().collect();
    let posture_dimensions = compute_posture_dimensions(findings);
    let roadmap = build_hardening_roadmap(findings);
    let attack_chains = build_attack_chains(findings, any_cache);
    let probe_manifest = build_probe_manifest(probe_flags);
    let exploitability_index = compute_exploitability_index(findings);
    let confirmed_primitives = count_confirmed_primitives(findings);
    let beyond_score = compute_beyond_score(score, exploitability_index, &posture_dimensions);
    let risk_matrix = build_risk_matrix(findings);
    let cdn_playbook = build_cdn_playbook(detected_vendor, findings);
    let defense_controls = build_defense_controls(findings);
    let poison_window_seconds = compute_poison_window_seconds(findings);
    let top_primitives = build_top_primitives(findings);
    let compliance_map = build_compliance_map(findings);
    let coverage_manifest = build_coverage_manifest(probe_flags, findings.len());
    let competitive_parity_index = build_competitive_parity_index(probe_flags, beyond_score);
    let http_requests = HTTP_REQUESTS.load(Ordering::Relaxed);
    let scan_telemetry = json!({
        "http_requests": http_requests,
        "paths_tested": paths_tested,
        "scan_duration_ms": scan_duration_ms,
        "concurrency": concurrency,
        "path_concurrency": path_concurrency,
        "canary_domain": canary_domain,
        "max_paths": max_paths,
        "path_limit_applied": path_limit_applied,
        "probe_categories_total": probe_flags.len(),
    });

    let description = if !any_cache && crit == 0 && high == 0 {
        format!(
            "No shared cache / CDN layer was observed in front of {}, and no reflection/deception primitive was found. Web-cache-poisoning exposure is minimal. Score {}/100 (grade {}).",
            base, score, grade
        )
    } else {
        format!(
            "Web cache poisoning & deception posture for {}: score {}/100 (grade {}). {} critical / {} high / {} medium / {} low across: {}.",
            base, score, grade, crit, high, med, low, if cats.is_empty() { "—".to_string() } else { cats.join(", ") }
        )
    };

    let ev = Evidence::new()
        .with("base_url", base.to_string())
        .with("posture_score", json!(score))
        .with("grade", grade)
        .with("shared_cache_detected", json!(any_cache))
        .with("intensity", intensity.as_str())
        .with("severity_breakdown", json!({ "critical": crit, "high": high, "medium": med, "low": low }))
        .with("weak_categories", json!(cats.clone()))
        .with("posture_dimensions", posture_dimensions.clone())
        .with("probe_manifest", probe_manifest.clone())
        .with("attack_chains", json!(attack_chains.len()))
        .with("exploitability_index", json!(exploitability_index))
        .with("confirmed_primitives", json!(confirmed_primitives))
        .with("beyond_score", json!(beyond_score))
        .with("scan_telemetry", scan_telemetry.clone())
        .with("concurrency", json!(concurrency))
        .with("detected_cdn_vendor", json!(detected_vendor))
        .with("risk_matrix", risk_matrix.clone())
        .with("cdn_playbook", cdn_playbook.clone())
        .with("defense_controls", defense_controls.clone())
        .with("poison_window_seconds", json!(poison_window_seconds))
        .with("top_primitives", json!(top_primitives.clone()))
        .with("compliance_map", compliance_map.clone())
        .with("coverage_manifest", coverage_manifest.clone())
        .with("competitive_parity_index", json!(competitive_parity_index));

    let mut summary = finding_rich(
        ENGINE_ID,
        &format!("Web cache posture score {}/100 (grade {})", score, grade),
        "info",
        "T1557",
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
        obj.insert("worst_severity".to_string(), json!(worst));
        obj.insert("weak_categories".to_string(), json!(cats));
        obj.insert("shared_cache_detected".to_string(), json!(any_cache));
        obj.insert("posture_dimensions".to_string(), posture_dimensions);
        obj.insert("hardening_roadmap".to_string(), json!(roadmap));
        obj.insert("attack_chains".to_string(), json!(attack_chains));
        obj.insert("probe_manifest".to_string(), probe_manifest);
        obj.insert("exploitability_index".to_string(), json!(exploitability_index));
        obj.insert("confirmed_primitives".to_string(), json!(confirmed_primitives));
        obj.insert("beyond_score".to_string(), json!(beyond_score));
        obj.insert("scan_telemetry".to_string(), scan_telemetry);
        obj.insert("detected_cdn_vendor".to_string(), json!(detected_vendor));
        obj.insert("risk_matrix".to_string(), risk_matrix);
        obj.insert("cdn_playbook".to_string(), cdn_playbook);
        obj.insert("defense_controls".to_string(), defense_controls);
        obj.insert("poison_window_seconds".to_string(), json!(poison_window_seconds));
        obj.insert("top_primitives".to_string(), json!(top_primitives));
        obj.insert("compliance_map".to_string(), compliance_map);
        obj.insert("coverage_manifest".to_string(), coverage_manifest.clone());
        obj.insert("competitive_parity_index".to_string(), json!(competitive_parity_index));
        obj.insert(
            "sealed_complete".to_string(),
            json!(coverage_manifest.get("sealed_complete").and_then(Value::as_bool).unwrap_or(false)),
        );
        obj.insert("canary_domain".to_string(), json!(canary_domain));
        obj.insert(
            "remediation".to_string(),
            json!("Treat the cache key as a security boundary: key on every request input that affects the response, strip untrusted X-Forwarded-*/Forwarded headers at the edge, set Cache-Control: no-store on authenticated/dynamic responses, and match caching on real Content-Type rather than URL suffix."),
        );
    }
    summary
}

pub async fn run_cache_poisoning(target: &str) {
    print_result(run_cache_poisoning_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(headers: Vec<(&str, &str)>, body: &str) -> HttpProbe {
        HttpProbe {
            status: 200,
            headers: headers.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: body.to_string(),
            final_url: "https://x.test/".to_string(),
        }
    }

    #[test]
    fn with_buster_handles_query() {
        assert_eq!(with_buster("https://x.test/", "ab"), "https://x.test/?wzcb=ab");
        assert_eq!(with_buster("https://x.test/?a=1", "ab"), "https://x.test/?a=1&wzcb=ab");
    }

    #[test]
    fn detect_cache_identifies_vendor_and_hit() {
        let s = detect_cache(&probe(vec![("CF-Cache-Status", "HIT"), ("Age", "42")], ""));
        assert!(s.cacheable && s.hit);
        assert_eq!(s.vendor.as_deref(), Some("Cloudflare"));
        let miss = detect_cache(&probe(vec![("Content-Type", "text/html")], ""));
        assert!(!miss.cacheable && !miss.hit);
    }

    #[test]
    fn reflects_finds_canary_in_body_and_location() {
        let b = probe(vec![("Content-Type", "text/html")], "<a>wzc123</a>");
        assert_eq!(reflects(&b, "wzc123"), Some("body"));
        let l = probe(vec![("Location", "https://wzc999.poison.example/")], "");
        assert_eq!(reflects(&l, "wzc999"), Some("Location header"));
        assert!(reflects(&b, "absent").is_none());
    }

    #[test]
    fn header_value_for_kinds() {
        assert!(header_value_for(HeaderKind::Host, "wzcabcd", DEFAULT_POISON_DOMAIN)
            .ends_with(".poison.example"));
        assert!(header_value_for(HeaderKind::Path, "wzcabcd", DEFAULT_POISON_DOMAIN).starts_with('/'));
        assert!(header_value_for(HeaderKind::Language, "wzcabcd", DEFAULT_POISON_DOMAIN)
            .contains("wzcabcd"));
    }

    #[test]
    fn sanitize_canary_domain_rejects_invalid() {
        assert_eq!(sanitize_canary_domain("evil.test"), "evil.test");
        assert_eq!(sanitize_canary_domain("https://bad"), DEFAULT_POISON_DOMAIN);
    }

    #[test]
    fn build_coverage_manifest_world_class_when_full() {
        let flags: Vec<(&str, bool)> = (0..51).map(|_| ("probe", true)).collect();
        let m = build_coverage_manifest(&flags, 3);
        assert_eq!(
            m.get("competitive_parity").and_then(Value::as_str),
            Some("world_class_complete")
        );
        assert_eq!(m.get("sealed_complete").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn is_publicly_cacheable_detects_public() {
        assert!(is_publicly_cacheable("public, max-age=3600"));
        assert!(!is_publicly_cacheable("private, no-store"));
    }

    #[test]
    fn body_sha256_stable() {
        assert_eq!(body_sha256("abc"), body_sha256("abc"));
        assert_ne!(body_sha256("abc"), body_sha256("abd"));
    }

    #[test]
    fn severity_rank_orders() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("medium") > severity_rank("low"));
    }

    #[test]
    fn normalization_variants_includes_baseline_and_alts() {
        let v = normalization_variants("https://x.test/account", "abc123");
        assert!(v.iter().any(|(_, l)| *l == "baseline"));
        assert!(v.len() >= 2);
        assert!(v[0].0.contains("wzcb=abc123"));
    }

    #[test]
    fn content_length_parses() {
        let p = probe(vec![("Content-Length", "1234")], "");
        assert_eq!(content_length(&p), Some(1234));
    }

    #[test]
    fn with_pad_param_appends() {
        let u = with_buster("https://x.test/a", "cb1");
        assert_eq!(with_pad_param(&u, "alpha"), format!("{}&wkpad=alpha", u));
    }

    #[test]
    fn compute_posture_dimensions_penalizes_critical() {
        let f = cache_finding(
            "t",
            "x",
            "critical",
            "d",
            0.9,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        let dims = compute_posture_dimensions(&[f]);
        assert!(dims.get("unkeyed_inputs").and_then(Value::as_u64).unwrap_or(100) < 100);
    }

    #[test]
    fn is_redirect_status_detects_3xx() {
        assert!(is_redirect_status(302));
        assert!(!is_redirect_status(200));
    }

    #[test]
    fn cache_control_schism_detects_edge_override() {
        assert!(cache_control_schism("no-store", "public, s-maxage=3600"));
        assert!(!cache_control_schism("public", "public"));
    }

    #[test]
    fn build_attack_chains_on_confirmed_poison() {
        let f = cache_finding(
            "t",
            "poison",
            "critical",
            "d",
            0.95,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        let chains = build_attack_chains(&[f], true);
        assert!(!chains.is_empty());
    }

    #[test]
    fn compute_exploitability_index_weights_confirmed() {
        let f = cache_finding(
            "t",
            "x",
            "critical",
            "d",
            0.95,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        assert!(compute_exploitability_index(&[f]) >= 28);
    }

    #[test]
    fn discover_paths_from_html_finds_hrefs() {
        let body = r#"<a href="/account">x</a><a href="/api/v1">y</a>"#;
        let p = discover_paths_from_html(body);
        assert!(p.contains(&"/account".to_string()));
    }

    #[test]
    fn compute_beyond_score_takes_min() {
        assert_eq!(compute_beyond_score(80, 30, &json!({"a": 60})), 60);
    }

    #[test]
    fn normalization_variants_includes_null_byte() {
        let v = normalization_variants("https://x.test/account", "abc123");
        assert!(v.iter().any(|(_, l)| *l == "null_byte"));
        assert!(v.iter().any(|(_, l)| *l == "double_encoded_null"));
    }

    #[test]
    fn build_risk_matrix_aggregates_by_category() {
        let f = cache_finding(
            "t",
            "x",
            "high",
            "d",
            0.9,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        let m = build_risk_matrix(&[f]);
        assert_eq!(
            m.get("cache_poisoning")
                .and_then(|v| v.get("high"))
                .and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn build_cdn_playbook_includes_urgent_on_confirmed() {
        let f = cache_finding(
            "t",
            "x",
            "critical",
            "d",
            0.95,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        let pb = build_cdn_playbook(Some("Cloudflare"), &[f]);
        let steps = pb.get("steps").and_then(Value::as_array).unwrap();
        assert!(steps[0].as_str().unwrap().contains("URGENT"));
    }

    #[test]
    fn dedupe_findings_removes_duplicates() {
        let ev = Evidence::new().with("url", "https://x.test/");
        let a = cache_finding("t", "same title", "high", "d", 0.8, "cache_poisoning", "reflected", "r", ev.clone());
        let b = cache_finding("t", "same title", "high", "d", 0.8, "cache_poisoning", "reflected", "r", ev);
        let out = dedupe_findings(vec![a, b]);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn compute_poison_window_seconds_max_from_evidence() {
        let ev = Evidence::new().with("cache_ttl_seconds", json!(7200));
        let f = cache_finding(
            "t",
            "x",
            "info",
            "d",
            0.5,
            "cache_fingerprint",
            "present",
            "r",
            ev,
        );
        assert_eq!(compute_poison_window_seconds(&[f]), 7200);
    }

    #[test]
    fn parse_cache_ttl_seconds_reads_max_age() {
        assert_eq!(parse_cache_ttl_seconds("public, max-age=3600"), Some(3600));
        assert_eq!(parse_cache_ttl_seconds("s-maxage=86400, max-age=0"), Some(86400));
    }

    #[test]
    fn s_maxage_browser_schism_detects_conflict() {
        assert!(s_maxage_browser_schism("max-age=0, s-maxage=3600"));
        assert!(!s_maxage_browser_schism("public, max-age=3600"));
    }

    #[test]
    fn parse_url_host_extracts_authority() {
        assert_eq!(
            parse_url_host("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_url_host("http://cdn.test:8080/x"),
            Some("cdn.test".to_string())
        );
    }

    #[test]
    fn poc_curl_includes_url() {
        assert!(poc_curl("GET", "https://x.test/", &[], None).contains("https://x.test/"));
    }
}
