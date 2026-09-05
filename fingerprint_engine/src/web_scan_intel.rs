//! Web / ASM / identity scan intelligence — Burp / Wiz / Mandiant-class evidence.
//!
//! Shared classifiers used by HTTP, ASM, and identity probes, plus two live engines:
//!
//!   * [`run_web_http_intel_result`] — security-header *values*, cookie flags, cache/CDN,
//!     CORS preflight, TLS cert, DNS A/CAA, auth-surface map. Evidence on every finding.
//!   * [`run_web_identity_surface_result`] — OIDC/OAuth/SAML well-known surfaces,
//!     `WWW-Authenticate`, login forms, JWT-shaped cookies (name only), IdP fingerprints.
//!
//! **401/403 contract:** those statuses mean the path *exists* and is **auth-gated**.
//! They are never classified as public content / public data exposure. That matches
//! the API/cloud classification rule (401/403-as-existence, not 401/403-as-public).
//!
//! Defensive scanners only — no exploit payloads, no attack procedures.

use crate::arsenal_config::{finding_rich, Evidence};
use crate::engine_probes::{
    dns_a, dns_caa, dns_cname, dns_txt, empty_ok, extract_host, fingerprint_stack, header_value,
    http1_client, http2_client, http_client, http_get, http_method_with_headers, normalize_url,
    status_indicates_auth_gated, status_indicates_public_content, tls_cert_details, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::time::Duration;

const WEB_HTTP_INTEL: &str = "web_http_intel";
const WEB_IDENTITY_SURFACE: &str = "web_identity_surface";
const MITRE_WEB: &str = "T1190";
const MITRE_COOKIE: &str = "T1539";
const MITRE_RECON: &str = "T1592.002";
const MITRE_ID_TOKEN: &str = "T1550.001";
const MITRE_SAML: &str = "T1606.002";

const BODY_EXCERPT: usize = 240;

/// HTTP exposure class for operator-facing evidence. Distinct from "path present".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpExposureClass {
    PublicContent,
    Redirect,
    AuthGated,
    MethodNotAllowed,
    RateLimited,
    ServerError,
    NotFound,
    Other,
}

impl HttpExposureClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicContent => "public_content",
            Self::Redirect => "redirect",
            Self::AuthGated => "auth_gated",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::RateLimited => "rate_limited",
            Self::ServerError => "server_error",
            Self::NotFound => "not_found",
            Self::Other => "other",
        }
    }
}

/// Classify an HTTP status for exposure reporting.
///
/// 401/403 → [`HttpExposureClass::AuthGated`] (never public content).
#[must_use]
pub fn classify_http_exposure(status: u16) -> HttpExposureClass {
    match status {
        200..=299 => HttpExposureClass::PublicContent,
        301 | 302 | 303 | 307 | 308 => HttpExposureClass::Redirect,
        401 | 403 => HttpExposureClass::AuthGated,
        404 | 410 => HttpExposureClass::NotFound,
        405 => HttpExposureClass::MethodNotAllowed,
        429 => HttpExposureClass::RateLimited,
        500..=599 => HttpExposureClass::ServerError,
        _ => HttpExposureClass::Other,
    }
}

// ── Cookies ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CookieFlags {
    pub name: String,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: Option<String>,
    pub host_prefix: bool,
    pub secure_prefix: bool,
}

/// Parse a single `Set-Cookie` header into flag posture (name + attributes only).
#[must_use]
pub fn parse_set_cookie(raw: &str) -> CookieFlags {
    let mut parts = raw.split(';');
    let name_val = parts.next().unwrap_or("").trim();
    let name = name_val
        .split_once('=')
        .map(|(n, _)| n.trim().to_string())
        .unwrap_or_else(|| name_val.to_string());
    let mut flags = CookieFlags {
        host_prefix: name.starts_with("__Host-"),
        secure_prefix: name.starts_with("__Secure-"),
        name,
        secure: false,
        httponly: false,
        samesite: None,
    };
    for part in parts {
        let p = part.trim();
        let (k, v) = match p.split_once('=') {
            Some((a, b)) => (a.trim(), Some(b.trim())),
            None => (p, None),
        };
        match k.to_ascii_lowercase().as_str() {
            "secure" => flags.secure = true,
            "httponly" => flags.httponly = true,
            "samesite" => flags.samesite = v.map(|s| s.to_ascii_lowercase()),
            _ => {}
        }
    }
    flags
}

/// Session-like cookie names that should carry HttpOnly.
#[must_use]
pub fn cookie_looks_session(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let n = n
        .trim_start_matches("__host-")
        .trim_start_matches("__secure-");
    n.contains("session")
        || n.contains("sess")
        || n == "sid"
        || n == "jsessionid"
        || n.contains("token")
        || n.contains("auth")
        || n.contains("jwt")
}

/// Hardening gaps for a cookie observed over HTTPS. Never invents flags.
#[must_use]
pub fn cookie_hardening_gaps(flags: &CookieFlags, over_https: bool) -> Vec<&'static str> {
    let mut gaps = Vec::new();
    if over_https && !flags.secure {
        gaps.push("missing_secure");
    }
    if cookie_looks_session(&flags.name) && !flags.httponly {
        gaps.push("missing_httponly");
    }
    match flags.samesite.as_deref() {
        None => gaps.push("missing_samesite"),
        Some("none") if !flags.secure => gaps.push("samesite_none_without_secure"),
        _ => {}
    }
    if flags.host_prefix && !flags.secure {
        gaps.push("host_prefix_without_secure");
    }
    gaps
}

// ── CSP / HSTS / clickjacking ────────────────────────────────────────────────

/// CSP directive weaknesses from a live `Content-Security-Policy` value.
#[must_use]
pub fn csp_directive_weaknesses(csp: &str) -> Vec<&'static str> {
    if csp.trim().is_empty() {
        return vec!["missing"];
    }
    let lower = csp.to_ascii_lowercase();
    let mut out = Vec::new();
    if lower.contains("'unsafe-inline'") {
        out.push("unsafe_inline");
    }
    if lower.contains("'unsafe-eval'") {
        out.push("unsafe_eval");
    }
    if script_src_has_wildcard(&lower) {
        out.push("wildcard_script_src");
    }
    if frame_ancestors_allows_any(&lower) {
        out.push("frame_ancestors_wildcard");
    }
    out
}

fn directive_value<'a>(csp_lower: &'a str, name: &str) -> Option<&'a str> {
    for part in csp_lower.split(';') {
        let part = part.trim();
        let Some(rest) = part.strip_prefix(name) else {
            continue;
        };
        // Require a token boundary so `script-src` does not match `script-src-elem`.
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            return Some(rest.trim());
        }
    }
    None
}

fn csp_src_is_wildcard(src: &str) -> bool {
    src.split_whitespace()
        .any(|t| t == "*" || t == "https:" || t == "http:")
}

fn script_src_has_wildcard(csp_lower: &str) -> bool {
    let src = directive_value(csp_lower, "script-src")
        .or_else(|| directive_value(csp_lower, "default-src"))
        .unwrap_or("");
    let elem = directive_value(csp_lower, "script-src-elem").unwrap_or("");
    csp_src_is_wildcard(src) || csp_src_is_wildcard(elem)
}

fn frame_ancestors_allows_any(csp_lower: &str) -> bool {
    match directive_value(csp_lower, "frame-ancestors") {
        Some(v) => v
            .split_whitespace()
            .any(|t| t == "*" || t == "https:" || t == "http:"),
        None => false,
    }
}

/// Clickjacking surface: no XFO and no restrictive `frame-ancestors`, or an explicit allow-all.
#[must_use]
pub fn clickjacking_unprotected(xfo: &str, csp: &str) -> bool {
    let xfo_l = xfo.trim().to_ascii_lowercase();
    let csp_l = csp.to_ascii_lowercase();
    if xfo_l == "allowall" || xfo_l.contains("allow-from") {
        return true;
    }
    if frame_ancestors_allows_any(&csp_l) {
        return true;
    }
    let has_fa = directive_value(&csp_l, "frame-ancestors").is_some();
    xfo_l.is_empty() && !has_fa
}

/// HSTS issues from a live header value. Empty string means the header is missing.
#[must_use]
pub fn hsts_issues(value: &str) -> Vec<&'static str> {
    if value.trim().is_empty() {
        return vec!["missing"];
    }
    let lower = value.to_ascii_lowercase();
    let mut out = Vec::new();
    let max_age = parse_hsts_max_age(&lower).unwrap_or(0);
    if max_age < 31_536_000 {
        out.push("max_age_below_one_year");
    }
    if !lower.contains("includesubdomains") {
        out.push("missing_includesubdomains");
    }
    out
}

fn parse_hsts_max_age(hsts_lower: &str) -> Option<u64> {
    let idx = hsts_lower.find("max-age=")?;
    let rest = &hsts_lower[idx + "max-age=".len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

// ── WWW-Authenticate / identity ──────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WwwAuthenticate {
    pub scheme: String,
    pub realm: Option<String>,
}

/// Parse the first challenge in a `WWW-Authenticate` header.
#[must_use]
pub fn parse_www_authenticate(value: &str) -> Option<WwwAuthenticate> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    let mut it = v.splitn(2, char::is_whitespace);
    let scheme = it.next()?.trim().to_string();
    if scheme.is_empty() {
        return None;
    }
    let rest = it.next().unwrap_or("");
    let realm = rest.to_ascii_lowercase().find("realm=").and_then(|i| {
        let after = rest[i + 6..].trim();
        let after = after.trim_start_matches('"');
        let end = after.find('"').or_else(|| after.find(','))?;
        Some(after[..end].to_string())
    });
    Some(WwwAuthenticate { scheme, realm })
}

/// Map a WWW-Authenticate scheme to an identity protocol label.
#[must_use]
pub fn identity_scheme_label(scheme: &str) -> Option<&'static str> {
    match scheme.to_ascii_lowercase().as_str() {
        "negotiate" => Some("Kerberos/SPNEGO"),
        "ntlm" => Some("NTLM"),
        "basic" => Some("HTTP Basic"),
        "bearer" | "dpop" => Some("OAuth Bearer"),
        "digest" => Some("HTTP Digest"),
        _ => None,
    }
}

/// Severity for an internet-facing auth scheme observation.
#[must_use]
pub fn identity_scheme_severity(scheme: &str) -> &'static str {
    match scheme.to_ascii_lowercase().as_str() {
        "ntlm" => "high",
        "basic" => "medium",
        "negotiate" => "medium",
        "digest" => "low",
        _ => "info",
    }
}

// ── Spec / takeover / login ──────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecExposure {
    Public,
    AuthGated,
    Absent,
}

/// Classify an OpenAPI/Swagger/WSDL-style document response.
/// 200 + document tokens = public spec. 401 = gated (not a public leak).
/// Generic 403 HTML/WAF blocks are not treated as a spec surface.
#[must_use]
pub fn classify_spec_document(status: u16, body: &str, tokens: &[&str]) -> SpecExposure {
    let low = body.to_ascii_lowercase();
    let looks_like = tokens.iter().any(|t| low.contains(&t.to_ascii_lowercase()));
    if status_indicates_public_content(status) && looks_like {
        return SpecExposure::Public;
    }
    if status == 401 {
        return SpecExposure::AuthGated;
    }
    if status == 403 && looks_like {
        return SpecExposure::AuthGated;
    }
    SpecExposure::Absent
}

/// HTTP body signatures used by dangling third-party hosting (Can I Take Over XYZ).
#[must_use]
pub fn http_takeover_vendor(body: &str) -> Option<&'static str> {
    let low = body.to_ascii_lowercase();
    let signatures: &[(&str, &str)] = &[
        ("there isn't a github pages site here", "GitHub Pages"),
        ("nosuchbucket", "AWS S3"),
        ("the specified bucket does not exist", "AWS S3"),
        ("no such bucket", "AWS S3"),
        ("heroku | no such app", "Heroku"),
        ("no such app", "Heroku"),
        ("project not found", "Vercel"),
        ("repository not found", "GitHub Pages"),
        ("trying to access your account", "Tilda"),
        ("fastly error: unknown domain", "Fastly"),
        ("the request could not be satisfied", "CloudFront"),
        ("this shop is currently unavailable", "Shopify"),
        ("do you want to register", "WordPress.com"),
        ("no settings were found for this company", "HubSpot"),
        ("is not a registered instapage", "Instapage"),
        ("we could not find what you're looking for", "Help Scout"),
        ("unknown domain", "Generic CDN"),
    ];
    signatures
        .iter()
        .find(|(sig, _)| low.contains(sig))
        .map(|(_, vendor)| *vendor)
}

/// CNAME target suffixes that are reclaimable third-party hosting.
#[must_use]
pub fn cname_takeover_vendor(cname: &str) -> Option<&'static str> {
    let c = cname.to_ascii_lowercase();
    let table: &[(&str, &str)] = &[
        ("github.io", "GitHub Pages"),
        ("herokuapp.com", "Heroku"),
        ("herokudns.com", "Heroku"),
        ("azurewebsites.net", "Azure App Service"),
        ("cloudapp.azure.com", "Azure Cloud App"),
        ("cloudfront.net", "CloudFront"),
        ("s3.amazonaws.com", "AWS S3"),
        ("s3-website", "AWS S3 website"),
        ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
        ("shopify.com", "Shopify"),
        ("myshopify.com", "Shopify"),
        ("fastly.net", "Fastly"),
        ("netlify.app", "Netlify"),
        ("netlify.com", "Netlify"),
        ("vercel-dns.com", "Vercel"),
        ("vercel.app", "Vercel"),
        ("surge.sh", "Surge"),
        ("pantheonsite.io", "Pantheon"),
        ("wpengine.com", "WP Engine"),
        ("zendesk.com", "Zendesk"),
        ("helpjuice.com", "Helpjuice"),
        ("helpscoutdocs.com", "Help Scout"),
        ("ghost.io", "Ghost"),
        ("readthedocs.io", "Read the Docs"),
        ("unbouncepages.com", "Unbounce"),
        ("bitbucket.io", "Bitbucket"),
        ("azure-api.net", "Azure API Management"),
        ("blob.core.windows.net", "Azure Blob"),
        ("trafficmanager.net", "Azure Traffic Manager"),
        ("cloudapp.net", "Azure Cloud Service"),
    ];
    table
        .iter()
        .find(|(suf, _)| c.contains(suf))
        .map(|(_, v)| *v)
}

/// Confidence for a takeover observation: HTTP signature + matching CNAME is confirmed.
#[must_use]
pub fn takeover_confidence(http_vendor: Option<&str>, cname_vendor: Option<&str>) -> &'static str {
    match (http_vendor, cname_vendor) {
        (Some(h), Some(c)) if h == c => "confirmed_http_and_dns",
        (Some(_), Some(_)) => "http_and_cname_vendor_mismatch",
        (Some(_), None) => "http_signature_only",
        (None, Some(_)) => "cname_candidate",
        _ => "none",
    }
}

#[must_use]
pub fn login_form_present(body: &str) -> bool {
    let low = body.to_ascii_lowercase();
    low.contains("type=\"password\"")
        || low.contains("type='password'")
        || low.contains("name=\"password\"")
        || low.contains("name='password'")
        || low.contains("id=\"password\"")
}

#[must_use]
pub fn oidc_discovery_document(status: u16, body: &str) -> bool {
    status_indicates_public_content(status)
        && body.contains("\"issuer\"")
        && (body.contains("jwks_uri") || body.contains("authorization_endpoint"))
}

#[must_use]
pub fn saml_metadata_document(status: u16, body: &str) -> bool {
    let low = body.to_ascii_lowercase();
    status_indicates_public_content(status)
        && (low.contains("entitydescriptor")
            || low.contains("entityid=")
            || low.contains("urn:oasis:names:tc:saml"))
}

/// CDN / reverse-proxy fingerprints from live response headers (observation only).
#[must_use]
pub fn cdn_providers_from_headers(headers: &[(String, String)]) -> Vec<&'static str> {
    let get = |n: &str| header_value(headers, n).unwrap_or("").to_ascii_lowercase();
    let server = get("server");
    let via = get("via");
    let blob = format!(
        "{server} {via} {} {} {} {}",
        get("x-cache"),
        get("cf-ray"),
        get("x-amz-cf-id"),
        get("x-akamai-request-id"),
    );
    let mut out = Vec::new();
    if !get("cf-ray").is_empty() || blob.contains("cloudflare") {
        out.push("Cloudflare");
    }
    if !get("x-amz-cf-id").is_empty() || blob.contains("cloudfront") {
        out.push("CloudFront");
    }
    if blob.contains("fastly") {
        out.push("Fastly");
    }
    if !get("x-akamai-request-id").is_empty() || blob.contains("akamai") {
        out.push("Akamai");
    }
    if blob.contains("varnish") {
        out.push("Varnish");
    }
    out
}

/// Cookie names whose values look like JWTs (header.payload.sig). Returns names only —
/// the token itself is never copied into findings.
#[must_use]
pub fn jwt_cookie_names(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| {
            let (name, rest) = v.split_once('=')?;
            let value = rest.split(';').next()?.trim();
            let mut parts = value.split('.');
            let h = parts.next()?;
            let p = parts.next()?;
            let s = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            if h.starts_with("eyJ") && p.starts_with("eyJ") && s.len() >= 8 {
                Some(name.trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

// ── Evidence ─────────────────────────────────────────────────────────────────

#[must_use]
pub fn body_excerpt(body: &str, max: usize) -> String {
    let t = body.trim();
    if t.len() <= max {
        return t.to_string();
    }
    let mut end = max;
    while end > 0 && !t.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &t[..end])
}

/// Structured HTTP evidence for a finding (Burp-class request/response proof).
#[must_use]
pub fn http_evidence_json(probe: &HttpProbe, method: &str) -> Value {
    let class = classify_http_exposure(probe.status);
    let www = header_value(&probe.headers, "www-authenticate");
    let location = header_value(&probe.headers, "location");
    let ct = header_value(&probe.headers, "content-type");
    json!({
        "method": method,
        "url": probe.final_url,
        "status": probe.status,
        "exposure_class": class.as_str(),
        "public_content": status_indicates_public_content(probe.status),
        "auth_gated": status_indicates_auth_gated(probe.status),
        "www_authenticate": www,
        "location": location,
        "content_type": ct,
        "server": header_value(&probe.headers, "server"),
        "body_excerpt": body_excerpt(&probe.body, BODY_EXCERPT),
        "body_len": probe.body.len(),
    })
}

pub fn attach_http_evidence(finding: &mut Value, probe: &HttpProbe, method: &str) {
    if let Some(obj) = finding.as_object_mut() {
        obj.insert("evidence".into(), http_evidence_json(probe, method));
        obj.insert(
            "exposure_class".into(),
            json!(classify_http_exposure(probe.status).as_str()),
        );
    }
}

fn intel_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    confidence: f64,
    evidence: Evidence,
) -> Value {
    let mut f = finding_rich(
        engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        evidence,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("probe_depth".into(), json!("http_dns_tls"));
    }
    f
}

fn selected_headers(probe: &HttpProbe, names: &[&str]) -> Value {
    let mut map = serde_json::Map::new();
    for n in names {
        if let Some(v) = header_value(&probe.headers, n) {
            map.insert((*n).to_string(), json!(v));
        }
    }
    Value::Object(map)
}

const SECURITY_HEADER_NAMES: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "cache-control",
    "www-authenticate",
    "server",
    "x-powered-by",
    "via",
    "cf-ray",
    "x-cache",
    "age",
    "alt-svc",
    "access-control-allow-origin",
    "access-control-allow-credentials",
];

// ── web_http_intel ───────────────────────────────────────────────────────────

pub async fn run_web_http_intel_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let url = normalize_url(target);
    let host = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();

    let Some(probe) = http_get(&client, &url).await else {
        return EngineResult::error(format!("HTTP GET failed for {url}"));
    };
    let https = probe.final_url.starts_with("https://");
    let class = classify_http_exposure(probe.status);
    let fp = fingerprint_stack(&probe);

    let mut ev = Evidence::new()
        .with("method", "GET")
        .with("url", &probe.final_url)
        .with("status", probe.status)
        .with("exposure_class", class.as_str())
        .with(
            "public_content",
            status_indicates_public_content(probe.status),
        )
        .with("auth_gated", status_indicates_auth_gated(probe.status))
        .with("headers", selected_headers(&probe, SECURITY_HEADER_NAMES))
        .with("body_excerpt", body_excerpt(&probe.body, BODY_EXCERPT))
        .check(
            "public_content",
            status_indicates_public_content(probe.status),
            class.as_str(),
        );

    if class == HttpExposureClass::AuthGated {
        let www = header_value(&probe.headers, "www-authenticate").unwrap_or("");
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            "HTTP surface is auth-gated (not public content)",
            "info",
            MITRE_WEB,
            &format!(
                "GET {} returned HTTP {} — path is present but unauthenticated callers do not receive content. WWW-Authenticate={:?}.",
                probe.final_url, probe.status, www
            ),
            target,
            0.95,
            ev.clone()
                .with("www_authenticate", www)
                .check("auth_gated", true, probe.status),
        ));
    }

    if https {
        let hsts = header_value(&probe.headers, "strict-transport-security").unwrap_or("");
        for issue in hsts_issues(hsts) {
            let sev = if issue == "missing" { "medium" } else { "low" };
            findings.push(intel_finding(
                WEB_HTTP_INTEL,
                &format!("HSTS issue: {issue}"),
                sev,
                "T1557",
                &format!(
                    "Live Strict-Transport-Security on {} is '{hsts}' ({issue}).",
                    probe.final_url
                ),
                target,
                0.9,
                ev.clone().with("hsts", hsts).check(issue, true, hsts),
            ));
        }
    }

    let csp = header_value(&probe.headers, "content-security-policy").unwrap_or("");
    for weak in csp_directive_weaknesses(csp) {
        let sev = match weak {
            "missing" if class == HttpExposureClass::PublicContent => "medium",
            "wildcard_script_src" | "unsafe_eval" => "medium",
            "missing" => "low",
            _ => "low",
        };
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            &format!("CSP weakness: {weak}"),
            sev,
            MITRE_WEB,
            &format!(
                "Content-Security-Policy on {} is '{csp}' ({weak}).",
                probe.final_url
            ),
            target,
            0.88,
            ev.clone().with("csp", csp).check(weak, true, csp),
        ));
    }

    let xfo = header_value(&probe.headers, "x-frame-options").unwrap_or("");
    if clickjacking_unprotected(xfo, csp) {
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            "Clickjacking protections absent or allow-all",
            "medium",
            "T1185",
            &format!(
                "{} has X-Frame-Options='{xfo}' and CSP frame-ancestors is missing or wildcard.",
                probe.final_url
            ),
            target,
            0.9,
            ev.clone()
                .with("x_frame_options", xfo)
                .with("csp", csp)
                .check("clickjacking_unprotected", true, xfo),
        ));
    }

    if header_value(&probe.headers, "x-content-type-options")
        .map(|v| !v.to_ascii_lowercase().contains("nosniff"))
        .unwrap_or(true)
    {
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            "X-Content-Type-Options nosniff missing",
            "low",
            MITRE_WEB,
            &format!(
                "{} does not send X-Content-Type-Options: nosniff.",
                probe.final_url
            ),
            target,
            0.85,
            ev.clone().check("xcto_nosniff", false, "missing"),
        ));
    }

    for (k, v) in &probe.headers {
        if !k.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let flags = parse_set_cookie(v);
        let gaps = cookie_hardening_gaps(&flags, https);
        if gaps.is_empty() {
            continue;
        }
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            &format!("Cookie '{}' missing hardening flags", flags.name),
            if gaps.contains(&"missing_secure") || gaps.contains(&"samesite_none_without_secure") {
                "medium"
            } else {
                "low"
            },
            MITRE_COOKIE,
            &format!(
                "Set-Cookie name '{}' on {} lacks {} (Secure={}, HttpOnly={}, SameSite={:?}). Token value is not stored.",
                flags.name,
                probe.final_url,
                gaps.join(", "),
                flags.secure,
                flags.httponly,
                flags.samesite
            ),
            target,
            0.92,
            ev.clone()
                .with("cookie_name", &flags.name)
                .with("gaps", &gaps)
                .check("cookie_hardening", false, &gaps),
        ));
    }

    if let Some(server) = fp.server.as_deref() {
        if server.chars().any(|c| c.is_ascii_digit()) {
            findings.push(intel_finding(
                WEB_HTTP_INTEL,
                "Server version disclosed",
                "low",
                MITRE_RECON,
                &format!("Server header on {} discloses '{server}'.", probe.final_url),
                target,
                0.9,
                ev.clone()
                    .with("server", server)
                    .check("version_banner", true, server),
            ));
        }
    }
    if let Some(pb) = fp.powered_by.as_deref() {
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            "X-Powered-By disclosed",
            "low",
            MITRE_RECON,
            &format!("X-Powered-By on {} discloses '{pb}'.", probe.final_url),
            target,
            0.9,
            ev.clone().with("x_powered_by", pb),
        ));
    }

    let cdn = cdn_providers_from_headers(&probe.headers);
    if !cdn.is_empty() {
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            &format!("CDN/cache fingerprint: {}", cdn.join(", ")),
            "info",
            MITRE_RECON,
            &format!(
                "Live headers on {} attribute the edge to {}.",
                probe.final_url,
                cdn.join(", ")
            ),
            target,
            0.85,
            ev.clone()
                .with("cdn", &cdn)
                .check("cdn_fingerprint", true, &cdn),
        ));
    }

    let cache_control = header_value(&probe.headers, "cache-control").unwrap_or("");
    let sets_cookie = probe
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("set-cookie"));
    let cc_l = cache_control.to_ascii_lowercase();
    if sets_cookie
        && !cc_l.contains("no-store")
        && !cc_l.contains("private")
        && class == HttpExposureClass::PublicContent
    {
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            "Set-Cookie on a cacheable public response",
            "medium",
            MITRE_COOKIE,
            &format!(
                "{} issued Set-Cookie with Cache-Control='{cache_control}' — shared caches may store the cookie.",
                probe.final_url
            ),
            target,
            0.8,
            ev.clone()
                .with("cache_control", cache_control)
                .check("cookie_on_cacheable_response", true, cache_control),
        ));
    }

    // CORS preflight (OPTIONS) — observation only.
    let evil_origin = format!("https://weissman-cors-probe.{}", host);
    if let Some(opt) = http_method_with_headers(
        &client,
        "OPTIONS",
        &probe.final_url,
        None,
        &[
            ("Origin", evil_origin.as_str()),
            ("Access-Control-Request-Method", "PUT"),
            (
                "Access-Control-Request-Headers",
                "authorization,content-type",
            ),
        ],
    )
    .await
    {
        let acao = header_value(&opt.headers, "access-control-allow-origin").unwrap_or("");
        let creds = header_value(&opt.headers, "access-control-allow-credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let acam = header_value(&opt.headers, "access-control-allow-methods").unwrap_or("");
        ev = ev
            .clone()
            .with("preflight_status", opt.status)
            .with("preflight_acao", acao)
            .with("preflight_methods", acam);
        if acao == evil_origin || acao == "*" {
            let sev = if creds { "high" } else { "medium" };
            findings.push(intel_finding(
                WEB_HTTP_INTEL,
                "CORS preflight reflects attacker Origin or wildcard",
                sev,
                "T1185",
                &format!(
                    "OPTIONS {} ACAO='{acao}' credentials={creds} Allow-Methods='{acam}' (Origin sent={evil_origin}).",
                    opt.final_url
                ),
                target,
                0.93,
                ev.clone()
                    .check("cors_preflight_reflective", acao == evil_origin, acao)
                    .check("cors_credentials", creds, creds),
            ));
        }
    }

    // HTTP/1.1 vs HTTP/2 differential (protocol schism evidence, not an exploit).
    let h1 = http_get(&http1_client().await, &url).await;
    let h2 = http_get(&http2_client().await, &url).await;
    if let (Some(a), Some(b)) = (h1, h2) {
        if a.status != b.status || (a.body.len() as i64 - b.body.len() as i64).abs() > 64 {
            findings.push(intel_finding(
                WEB_HTTP_INTEL,
                "HTTP/1.1 vs HTTP/2 response differential",
                "low",
                MITRE_WEB,
                &format!(
                    "Forced HTTP/1.1 GET returned {} ({} bytes); HTTP/2-capable GET returned {} ({} bytes) on {}.",
                    a.status, a.body.len(), b.status, b.body.len(), url
                ),
                target,
                0.7,
                ev.clone()
                    .with("h1_status", a.status)
                    .with("h2_status", b.status)
                    .with("h1_body_len", a.body.len())
                    .with("h2_body_len", b.body.len())
                    .check("protocol_differential", true, "h1_vs_h2"),
            ));
        }
    }

    // DNS + TLS live evidence.
    let a_recs = dns_a(&host).await;
    let caa = dns_caa(&host).await;
    let cnames = dns_cname(&host).await;
    if a_recs.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            "No A records resolved",
            "info",
            "T1590.002",
            &format!("DNS A lookup for {host} returned no records."),
            target,
            0.6,
            Evidence::new()
                .with("host", &host)
                .check("dns_a", false, "empty"),
        ));
    }
    if caa.is_empty() && host.contains('.') && host.parse::<std::net::IpAddr>().is_err() {
        findings.push(intel_finding(
            WEB_HTTP_INTEL,
            "No CAA records for issuance control",
            "low",
            "T1587.003",
            &format!("{host} publishes no CAA records — any public CA may issue certificates."),
            target,
            0.8,
            Evidence::new()
                .with("host", &host)
                .with("a_records", &a_recs)
                .check("caa", false, "empty"),
        ));
    }
    let mut tls_summary: Option<Value> = None;
    if let Ok(Some(tls)) =
        tokio::time::timeout(Duration::from_secs(5), tls_cert_details(&host)).await
    {
        tls_summary = Some(json!({
            "subject": tls.subject,
            "issuer": tls.issuer,
            "days_until_expiry": tls.days_until_expiry,
            "public_key_bits": tls.public_key_bits,
            "signature_algorithm": tls.signature_algorithm,
            "san_dns_names": tls.san_dns_names,
            "self_signed": tls.self_signed,
            "expired": tls.expired,
            "is_rsa": tls.is_rsa,
        }));
        let tls_ev = Evidence::new()
            .with("subject", &tls.subject)
            .with("issuer", &tls.issuer)
            .with("days_until_expiry", tls.days_until_expiry)
            .with("public_key_bits", tls.public_key_bits)
            .with("signature_algorithm", &tls.signature_algorithm)
            .with("san_dns_names", &tls.san_dns_names);
        if tls.expired {
            findings.push(intel_finding(
                WEB_HTTP_INTEL,
                "TLS certificate expired",
                "high",
                "T1557",
                &format!(
                    "Certificate for {host} (CN={}, issuer={}) is expired.",
                    tls.subject, tls.issuer
                ),
                target,
                0.98,
                tls_ev.clone().check("expired", true, tls.days_until_expiry),
            ));
        } else if tls.days_until_expiry <= 21 {
            findings.push(intel_finding(
                WEB_HTTP_INTEL,
                "TLS certificate expiring soon",
                "medium",
                "T1557",
                &format!(
                    "Certificate for {host} expires in {} day(s).",
                    tls.days_until_expiry
                ),
                target,
                0.9,
                tls_ev
                    .clone()
                    .check("expiry_window", true, tls.days_until_expiry),
            ));
        }
        if tls.self_signed {
            findings.push(intel_finding(
                WEB_HTTP_INTEL,
                "Self-signed TLS certificate",
                "medium",
                "T1587.003",
                &format!(
                    "Certificate for {host} appears self-signed (CN={}).",
                    tls.subject
                ),
                target,
                0.9,
                tls_ev.clone().check("self_signed", true, &tls.subject),
            ));
        }
        if tls.is_rsa && tls.public_key_bits > 0 && tls.public_key_bits < 2048 {
            findings.push(intel_finding(
                WEB_HTTP_INTEL,
                "TLS RSA key smaller than 2048 bits",
                "high",
                "T1600",
                &format!(
                    "Leaf certificate for {host} uses RSA {}-bit key ({}).",
                    tls.public_key_bits, tls.signature_algorithm
                ),
                target,
                0.95,
                tls_ev.clone().check("weak_rsa", true, tls.public_key_bits),
            ));
        }
        let _ = tls_ev;
    }

    for cname in &cnames {
        if let Some(vendor) = cname_takeover_vendor(cname) {
            let http_v = http_takeover_vendor(&probe.body);
            let conf = takeover_confidence(http_v, Some(vendor));
            if conf != "cname_candidate" || http_v.is_some() {
                let sev = if conf == "confirmed_http_and_dns" {
                    "critical"
                } else {
                    "medium"
                };
                findings.push(intel_finding(
                    WEB_HTTP_INTEL,
                    &format!("Dangling {vendor} CNAME ({conf})"),
                    sev,
                    "T1584.001",
                    &format!(
                        "{host} CNAME {cname} maps to reclaimable {vendor}. HTTP vendor={:?}, confidence={conf}.",
                        http_v
                    ),
                    target,
                    if sev == "critical" { 0.95 } else { 0.7 },
                    Evidence::new()
                        .with("cname", cname)
                        .with("vendor", vendor)
                        .with("http_vendor", http_v)
                        .with("confidence", conf)
                        .check("takeover", true, conf),
                ));
            }
        }
    }

    findings.push(intel_finding(
        WEB_HTTP_INTEL,
        &format!(
            "HTTP intelligence summary — {} (HTTP {})",
            class.as_str(),
            probe.status
        ),
        "info",
        MITRE_RECON,
        &format!(
            "Live GET {} → HTTP {}, exposure={}, products={:?}, A={:?}, CAA={}.",
            probe.final_url,
            probe.status,
            class.as_str(),
            fp.products,
            a_recs,
            caa.len()
        ),
        target,
        0.99,
        {
            let mut summary_ev = ev
                .with("a_records", a_recs)
                .with("caa_count", caa.len())
                .with("cnames", cnames)
                .with("products", fp.products);
            if let Some(tls) = tls_summary {
                summary_ev = summary_ev.with("tls", tls);
            }
            summary_ev
        },
    ));

    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("web_http_intel: {n} evidence-backed finding(s)"),
    )
}

pub async fn run_web_http_intel(target: &str) {
    print_result(run_web_http_intel_result(target).await);
}

// ── web_identity_surface ─────────────────────────────────────────────────────

const IDENTITY_PATHS: &[(&str, &str)] = &[
    ("/.well-known/openid-configuration", "oidc_discovery"),
    (
        "/.well-known/oauth-authorization-server",
        "oauth_as_metadata",
    ),
    ("/.well-known/webfinger", "webfinger"),
    ("/.well-known/jwks.json", "jwks"),
    ("/oauth2/v1/keys", "jwks"),
    ("/protocol/openid-connect/certs", "jwks"),
    (
        "/realms/master/.well-known/openid-configuration",
        "keycloak_oidc",
    ),
    (
        "/FederationMetadata/2007-06/FederationMetadata.xml",
        "saml_federation_metadata",
    ),
    ("/saml/metadata", "saml_metadata"),
    ("/saml2/metadata", "saml_metadata"),
    ("/auth/saml/metadata", "saml_metadata"),
    ("/adfs/ls", "adfs"),
    ("/adfs/oauth2/authorize", "adfs_oauth"),
    ("/oauth/authorize", "oauth_authorize"),
    ("/oauth2/authorize", "oauth_authorize"),
    ("/oauth2/v2.0/authorize", "oauth_authorize"),
    ("/connect/authorize", "oauth_authorize"),
    ("/login", "login"),
    ("/signin", "login"),
    ("/sso", "sso"),
];

fn idp_from_hay(hay: &str) -> Option<&'static str> {
    let h = hay.to_ascii_lowercase();
    let table: &[(&str, &str)] = &[
        ("okta.com", "Okta"),
        ("auth0.com", "Auth0"),
        ("login.microsoftonline.com", "Microsoft Entra ID"),
        ("sts.windows.net", "Microsoft Entra ID"),
        ("b2clogin.com", "Azure AD B2C"),
        ("accounts.google.com", "Google Identity"),
        ("cognito-idp", "AWS Cognito"),
        ("onelogin.com", "OneLogin"),
        ("pingone.com", "Ping Identity"),
        ("pingidentity.com", "Ping Identity"),
        ("keycloak", "Keycloak"),
        ("forgerock", "ForgeRock"),
        ("duosecurity.com", "Cisco Duo"),
        ("jumpcloud.com", "JumpCloud"),
    ];
    table.iter().find(|(n, _)| h.contains(n)).map(|(_, l)| *l)
}

pub async fn run_web_identity_surface_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let host = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();

    if let Some(root) = http_get(&client, &base).await {
        let www = header_value(&root.headers, "www-authenticate").unwrap_or("");
        if let Some(chal) = parse_www_authenticate(www) {
            if let Some(label) = identity_scheme_label(&chal.scheme) {
                findings.push(intel_finding(
                    WEB_IDENTITY_SURFACE,
                    &format!("Identity challenge: {label}"),
                    identity_scheme_severity(&chal.scheme),
                    MITRE_ID_TOKEN,
                    &format!(
                        "GET {} returned HTTP {} with WWW-Authenticate scheme '{}' (realm={:?}) — {label} is internet-reachable. 401/403 is auth-gated, not public data.",
                        root.final_url, root.status, chal.scheme, chal.realm
                    ),
                    target,
                    0.92,
                    Evidence::new()
                        .with("status", root.status)
                        .with("exposure_class", classify_http_exposure(root.status).as_str())
                        .with("scheme", &chal.scheme)
                        .with("realm", &chal.realm)
                        .with("label", label)
                        .check("www_authenticate", true, &chal.scheme),
                ));
            }
        }
        if login_form_present(&root.body) {
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                "Login form observed on apex",
                "info",
                MITRE_ID_TOKEN,
                &format!(
                    "{} HTML contains a password field (HTTP {}). Review MFA, CSRF, and credential stuffing controls.",
                    root.final_url, root.status
                ),
                target,
                0.85,
                Evidence::new()
                    .with("status", root.status)
                    .with("url", &root.final_url)
                    .check("login_form", true, "password_input"),
            ));
        }
        for name in jwt_cookie_names(&root.headers) {
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                &format!("JWT-shaped cookie '{name}' issued"),
                "low",
                MITRE_COOKIE,
                &format!(
                    "{} Set-Cookie '{name}' looks like a JWT (eyJ…eyJ…). Cookie value is not stored in evidence.",
                    root.final_url
                ),
                target,
                0.88,
                Evidence::new()
                    .with("cookie_name", &name)
                    .check("jwt_cookie", true, &name),
            ));
        }
        let hay = format!(
            "{} {} {}",
            root.final_url,
            header_value(&root.headers, "location").unwrap_or(""),
            body_excerpt(&root.body, 400)
        );
        if let Some(idp) = idp_from_hay(&hay) {
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                &format!("Identity provider fingerprint: {idp}"),
                "info",
                MITRE_ID_TOKEN,
                &format!("Live response/redirect for {host} fingerprints {idp}."),
                target,
                0.8,
                Evidence::new()
                    .with("idp", idp)
                    .with("url", &root.final_url)
                    .check("idp_fingerprint", true, idp),
            ));
        }
    }

    for (path, kind) in IDENTITY_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let Some(p) = http_get(&client, &url).await else {
            continue;
        };
        let class = classify_http_exposure(p.status);
        if class == HttpExposureClass::NotFound || class == HttpExposureClass::Other {
            continue;
        }
        let oidc =
            *kind == "oidc_discovery" || *kind == "oauth_as_metadata" || *kind == "keycloak_oidc";
        let saml = kind.starts_with("saml");
        if oidc && oidc_discovery_document(p.status, &p.body) {
            let issuer = p
                .body
                .split("\"issuer\"")
                .nth(1)
                .and_then(|s| s.split('"').nth(1))
                .unwrap_or("");
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                "Public OIDC/OAuth discovery document",
                "medium",
                MITRE_ID_TOKEN,
                &format!(
                    "Unauthenticated GET {} returned HTTP {} with issuer/jwks metadata (issuer='{issuer}').",
                    p.final_url, p.status
                ),
                target,
                0.95,
                Evidence::new()
                    .with("url", &p.final_url)
                    .with("status", p.status)
                    .with("exposure_class", "public_content")
                    .with("kind", *kind)
                    .with("issuer", issuer)
                    .with("body_excerpt", body_excerpt(&p.body, BODY_EXCERPT))
                    .check("oidc_discovery", true, issuer),
            ));
            continue;
        }
        if saml && saml_metadata_document(p.status, &p.body) {
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                "Public SAML metadata document",
                "medium",
                MITRE_SAML,
                &format!(
                    "Unauthenticated GET {} returned HTTP {} EntityDescriptor/SAML metadata.",
                    p.final_url, p.status
                ),
                target,
                0.93,
                Evidence::new()
                    .with("url", &p.final_url)
                    .with("status", p.status)
                    .with("exposure_class", "public_content")
                    .with("kind", *kind)
                    .with("body_excerpt", body_excerpt(&p.body, BODY_EXCERPT))
                    .check("saml_metadata", true, p.status),
            ));
            continue;
        }
        if class == HttpExposureClass::AuthGated {
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                &format!("Auth-gated identity path ({kind})"),
                "info",
                MITRE_ID_TOKEN,
                &format!(
                    "GET {} returned HTTP {} — identity surface exists but is not public content.",
                    p.final_url, p.status
                ),
                target,
                0.9,
                Evidence::new()
                    .with("url", &p.final_url)
                    .with("status", p.status)
                    .with("exposure_class", "auth_gated")
                    .with("kind", *kind)
                    .with(
                        "www_authenticate",
                        header_value(&p.headers, "www-authenticate"),
                    )
                    .check("auth_gated", true, p.status),
            ));
            continue;
        }
        if class == HttpExposureClass::PublicContent
            && (*kind == "oauth_authorize"
                || *kind == "adfs"
                || *kind == "adfs_oauth"
                || *kind == "login"
                || *kind == "sso")
        {
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                &format!("Identity endpoint reachable ({kind})"),
                "info",
                MITRE_ID_TOKEN,
                &format!(
                    "GET {} returned HTTP {} without authentication challenge.",
                    p.final_url, p.status
                ),
                target,
                0.75,
                Evidence::new()
                    .with("url", &p.final_url)
                    .with("status", p.status)
                    .with("exposure_class", class.as_str())
                    .with("kind", *kind)
                    .check("identity_endpoint", true, *kind),
            ));
        }
        if *kind == "jwks"
            && status_indicates_public_content(p.status)
            && p.body.contains("\"keys\"")
        {
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                "Public JWKS published",
                "low",
                MITRE_ID_TOKEN,
                &format!(
                    "GET {} returned HTTP {} with a JWK set — expected for OIDC, review key rotation and kty/alg.",
                    p.final_url, p.status
                ),
                target,
                0.9,
                Evidence::new()
                    .with("url", &p.final_url)
                    .with("status", p.status)
                    .with("exposure_class", "public_content")
                    .check("jwks", true, "keys"),
            ));
        }
    }

    // Email-identity DNS (SPF/DMARC) — live TXT, not a fabricated posture score.
    if host.contains('.') && host.parse::<std::net::IpAddr>().is_err() {
        let txt = dns_txt(&host).await;
        let spf = txt
            .iter()
            .find(|t| t.to_ascii_lowercase().starts_with("v=spf1"));
        if spf.is_none() {
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                "No SPF TXT on apex (identity email perimeter)",
                "medium",
                "T1566.002",
                &format!("{host} publishes no v=SPF1 TXT — spoofable sender identity."),
                target,
                0.85,
                Evidence::new()
                    .with("host", &host)
                    .with("txt_count", txt.len())
                    .check("spf", false, "missing"),
            ));
        }
        let dmarc = dns_txt(&format!("_dmarc.{host}")).await;
        let has_dmarc = dmarc
            .iter()
            .any(|t| t.to_ascii_lowercase().contains("v=dmarc1"));
        if !has_dmarc {
            findings.push(intel_finding(
                WEB_IDENTITY_SURFACE,
                "No DMARC policy (identity email perimeter)",
                "medium",
                "T1566.002",
                &format!(
                    "_dmarc.{host} has no v=DMARC1 TXT — spoofed identity mail is not rejected."
                ),
                target,
                0.85,
                Evidence::new()
                    .with("host", format!("_dmarc.{host}"))
                    .check("dmarc", false, "missing"),
            ));
        }
    }

    if findings.is_empty() {
        return empty_ok(WEB_IDENTITY_SURFACE, target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("web_identity_surface: {n} evidence-backed finding(s)"),
    )
}

pub async fn run_web_identity_surface(target: &str) {
    print_result(run_web_identity_surface_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_class_never_treats_401_403_as_public() {
        assert_eq!(classify_http_exposure(401), HttpExposureClass::AuthGated);
        assert_eq!(classify_http_exposure(403), HttpExposureClass::AuthGated);
        assert_eq!(
            classify_http_exposure(200),
            HttpExposureClass::PublicContent
        );
        assert_eq!(classify_http_exposure(404), HttpExposureClass::NotFound);
        assert_eq!(classify_http_exposure(302), HttpExposureClass::Redirect);
        assert_ne!(
            classify_http_exposure(401).as_str(),
            HttpExposureClass::PublicContent.as_str()
        );
    }

    #[test]
    fn spec_document_public_vs_gated() {
        let tokens = ["swagger", "openapi", "\"paths\""];
        assert_eq!(
            classify_spec_document(200, r#"{"openapi":"3.0.0","paths":{}}"#, &tokens),
            SpecExposure::Public
        );
        assert_eq!(
            classify_spec_document(401, "unauthorized", &tokens),
            SpecExposure::AuthGated
        );
        assert_eq!(
            classify_spec_document(403, r#"{"openapi":"3.0"}"#, &tokens),
            SpecExposure::AuthGated
        );
        assert_eq!(
            classify_spec_document(403, "<html>forbidden</html>", &tokens),
            SpecExposure::Absent
        );
        assert_eq!(
            classify_spec_document(404, "nope", &tokens),
            SpecExposure::Absent
        );
        assert_eq!(
            classify_spec_document(200, "<html>not a spec</html>", &tokens),
            SpecExposure::Absent
        );
    }

    #[test]
    fn cookie_flags_and_gaps() {
        let c = parse_set_cookie("sessionid=abc; Path=/; HttpOnly");
        assert_eq!(c.name, "sessionid");
        assert!(c.httponly);
        assert!(!c.secure);
        let gaps = cookie_hardening_gaps(&c, true);
        assert!(gaps.contains(&"missing_secure"));
        assert!(gaps.contains(&"missing_samesite"));
        let ok = parse_set_cookie("__Host-session=x; Secure; HttpOnly; SameSite=Lax; Path=/");
        assert!(cookie_hardening_gaps(&ok, true).is_empty());
        let none = parse_set_cookie("id=1; SameSite=None");
        assert!(cookie_hardening_gaps(&none, true).contains(&"samesite_none_without_secure"));
    }

    #[test]
    fn csp_and_clickjacking() {
        assert!(csp_directive_weaknesses("").contains(&"missing"));
        assert!(
            csp_directive_weaknesses("default-src 'self'; script-src 'unsafe-inline'")
                .contains(&"unsafe_inline")
        );
        assert!(csp_directive_weaknesses("script-src *").contains(&"wildcard_script_src"));
        assert!(clickjacking_unprotected("", ""));
        assert!(!clickjacking_unprotected("DENY", ""));
        assert!(clickjacking_unprotected(
            "",
            "default-src 'self'; frame-ancestors *"
        ));
        assert!(!clickjacking_unprotected(
            "",
            "default-src 'self'; frame-ancestors 'self'"
        ));
        assert!(clickjacking_unprotected(
            "ALLOWALL",
            "frame-ancestors 'self'"
        ));
    }

    #[test]
    fn hsts_max_age_and_missing() {
        assert_eq!(hsts_issues(""), vec!["missing"]);
        let weak = hsts_issues("max-age=3600");
        assert!(weak.contains(&"max_age_below_one_year"));
        assert!(weak.contains(&"missing_includesubdomains"));
        assert!(hsts_issues("max-age=31536000; includeSubDomains; preload").is_empty());
    }

    #[test]
    fn www_authenticate_identity_schemes() {
        let ntlm = parse_www_authenticate("NTLM").unwrap();
        assert_eq!(ntlm.scheme, "NTLM");
        assert_eq!(identity_scheme_label("NTLM"), Some("NTLM"));
        assert_eq!(identity_scheme_severity("NTLM"), "high");
        let bearer = parse_www_authenticate(r#"Bearer realm="api""#).unwrap();
        assert_eq!(identity_scheme_label(&bearer.scheme), Some("OAuth Bearer"));
        assert_eq!(identity_scheme_severity("negotiate"), "medium");
        assert_eq!(identity_scheme_severity("basic"), "medium");
        assert!(parse_www_authenticate("").is_none());
    }

    #[test]
    fn takeover_http_and_cname_correlation() {
        assert_eq!(
            http_takeover_vendor("There isn't a GitHub Pages site here."),
            Some("GitHub Pages")
        );
        assert_eq!(
            cname_takeover_vendor("acme.github.io"),
            Some("GitHub Pages")
        );
        assert_eq!(
            takeover_confidence(Some("GitHub Pages"), Some("GitHub Pages")),
            "confirmed_http_and_dns"
        );
        assert_eq!(takeover_confidence(None, Some("Heroku")), "cname_candidate");
        assert_eq!(cname_takeover_vendor("cdn.example.com"), None);
    }

    #[test]
    fn oidc_saml_and_login_signals() {
        assert!(oidc_discovery_document(
            200,
            r#"{"issuer":"https://idp.example","jwks_uri":"https://idp.example/keys"}"#
        ));
        assert!(!oidc_discovery_document(
            401,
            r#"{"issuer":"x","jwks_uri":"y"}"#
        ));
        assert!(saml_metadata_document(
            200,
            r#"<EntityDescriptor entityID="https://idp.example" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">"#
        ));
        assert!(!saml_metadata_document(403, "<EntityDescriptor>"));
        assert!(login_form_present(
            r#"<form><input type="password" name="p"></form>"#
        ));
        assert!(!login_form_present("<html>hello</html>"));
    }

    #[test]
    fn jwt_cookie_names_do_not_store_values() {
        let headers = vec![
            (
                "Set-Cookie".into(),
                "access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signatureX; HttpOnly".into(),
            ),
            ("Set-Cookie".into(), "theme=dark; Path=/".into()),
        ];
        let names = jwt_cookie_names(&headers);
        assert_eq!(names, vec!["access_token".to_string()]);
    }

    #[test]
    fn body_excerpt_respects_char_boundary() {
        let s = "שלום עולם";
        let e = body_excerpt(s, 3);
        assert!(e.ends_with('…') || e == s);
        assert!(body_excerpt("short", 100) == "short");
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_web_http_intel_result("").await;
        assert!(!r.success);
        let r2 = run_web_identity_surface_result("  ").await;
        assert!(!r2.success);
    }

    #[test]
    fn csp_script_src_elem_is_not_script_src() {
        assert!(
            !csp_directive_weaknesses("script-src-elem *; script-src 'self'")
                .contains(&"wildcard_script_src")
                || csp_directive_weaknesses("script-src-elem *").contains(&"wildcard_script_src")
        );
        assert!(csp_directive_weaknesses("script-src-elem *").contains(&"wildcard_script_src"));
        assert!(
            !csp_directive_weaknesses("script-src 'self'; script-src-elem 'self'")
                .contains(&"wildcard_script_src")
        );
    }

    #[test]
    fn cdn_fingerprint_from_live_headers() {
        let cf = vec![("cf-ray".into(), "abc".into())];
        assert_eq!(cdn_providers_from_headers(&cf), vec!["Cloudflare"]);
        let none = vec![("server".into(), "nginx".into())];
        assert!(cdn_providers_from_headers(&none).is_empty());
        let fastly = vec![("via".into(), "1.1 varnish, 1.1 fastly".into())];
        assert!(cdn_providers_from_headers(&fastly).contains(&"Fastly"));
    }

    #[tokio::test]
    async fn live_localhost_401_is_auth_gated_and_oidc_is_public() {
        use axum::http::{header, HeaderValue, StatusCode};
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::Router;

        async fn gated() -> impl IntoResponse {
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, HeaderValue::from_static("NTLM"))],
                "auth required",
            )
        }
        async fn oidc() -> impl IntoResponse {
            (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                r#"{"issuer":"https://idp.test","jwks_uri":"https://idp.test/keys","authorization_endpoint":"https://idp.test/auth"}"#,
            )
        }

        let app = Router::new()
            .route("/", get(gated))
            .route("/.well-known/openid-configuration", get(oidc));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        tokio::task::yield_now().await;

        let url = format!("http://127.0.0.1:{}", addr.port());
        let http = run_web_http_intel_result(&url).await;
        assert!(http.success, "{}", http.message);
        assert!(
            http.findings
                .iter()
                .any(|f| { f["title"].as_str().unwrap_or("").contains("auth-gated") }),
            "expected auth-gated finding, got {:?}",
            http.findings
                .iter()
                .map(|f| f["title"].clone())
                .collect::<Vec<_>>()
        );
        for f in &http.findings {
            if let Some(ev) = f.get("evidence") {
                assert_ne!(
                    ev.get("exposure_class").and_then(|v| v.as_str()),
                    Some("public_content"),
                    "401 must not be public content: {f}"
                );
                assert_ne!(
                    ev.get("public_content"),
                    Some(&json!(true)),
                    "401 must not set public_content=true: {f}"
                );
            }
        }

        let id = run_web_identity_surface_result(&url).await;
        assert!(id.success, "{}", id.message);
        let titles: Vec<_> = id
            .findings
            .iter()
            .filter_map(|f| f["title"].as_str())
            .collect();
        assert!(
            titles
                .iter()
                .any(|t| t.contains("NTLM") || t.contains("Identity challenge")),
            "expected NTLM/identity challenge, got {titles:?}"
        );
        assert!(
            titles
                .iter()
                .any(|t| t.contains("OIDC") || t.contains("discovery")),
            "expected public OIDC discovery, got {titles:?}"
        );
        for f in &id.findings {
            let title = f["title"].as_str().unwrap_or("");
            if title.contains("OIDC") {
                assert_eq!(f["severity"], json!("medium"));
                assert_eq!(
                    f["evidence"]["exposure_class"].as_str(),
                    Some("public_content")
                );
            }
            if title.contains("auth-gated") {
                assert_ne!(f["severity"], json!("critical"));
                assert_eq!(f["evidence"]["exposure_class"].as_str(), Some("auth_gated"));
            }
        }
    }
}
