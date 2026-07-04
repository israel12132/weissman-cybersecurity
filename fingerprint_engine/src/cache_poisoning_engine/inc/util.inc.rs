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

