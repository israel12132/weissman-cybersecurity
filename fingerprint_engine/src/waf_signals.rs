//! Shared WAF / CDN block detection.
//!
//! HTTP 403 from Cloudflare (and peers) is a **block**, not proof that SSRF, GraphQL, or
//! fuzz payloads reached an application. Verify + persist used to treat any `status > 0`
//! (including 403) as `LIKELY_VALID` because the stored evidence also said `403`.

use serde_json::Value;

/// Vendor → lowercase tokens scanned across headers + body.
const WAF_SIGNATURES: &[(&str, &[&str])] = &[
    (
        "Cloudflare",
        &[
            "cloudflare",
            "cf-ray",
            "cf-mitigated",
            "__cfduid",
            "cf_clearance",
            "__cf_bm",
            "attention required",
            "just a moment",
            "cf-error",
        ],
    ),
    ("Akamai", &["akamaighost", "akamai", "x-akamai"]),
    (
        "AWS CloudFront / WAF",
        &["cloudfront", "x-amz-cf-id", "x-amzn-waf", "awselb"],
    ),
    (
        "Imperva Incapsula",
        &["incap_ses", "visid_incap", "x-iinfo", "incapsula"],
    ),
    ("Sucuri", &["sucuri", "x-sucuri"]),
    ("F5 BIG-IP", &["bigipserver", "big-ip", "x-waf-"]),
    ("Fastly", &["fastly", "x-served-by"]),
    ("Barracuda", &["barracuda"]),
    ("ModSecurity", &["mod_security", "modsecurity"]),
    ("Azure Front Door", &["x-azure-ref", "azurefd"]),
    ("Fortinet FortiWeb", &["fortiwafsid", "fortiweb"]),
    ("Wordfence", &["wordfence"]),
];

/// Engines whose 403 responses are almost always a WAF/CDN challenge, not an authorization
/// oracle. Access-control engines keep 403 as a potentially valid finding.
const WAF_NOISE_ENGINE_NEEDLES: &[&str] = &[
    "ssrf",
    "graphql",
    "fuzz",
    "oast",
    "prototype_pollution",
    "http_smuggling",
    "file_upload",
    "path_fuzz",
    "llm_path",
    "timing",
    "ssti",
    "password_spray",
    "side_channel",
];

const AUTHZ_ENGINE_NEEDLES: &[&str] = &[
    "bola",
    "idor",
    "authz",
    "broken_access",
    "broken_object",
    "jwt_attack",
    "oauth",
    "saml",
    "rbac",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafClassification {
    pub blocked: bool,
    pub vendor: Option<&'static str>,
    pub reason: String,
}

impl WafClassification {
    pub fn none() -> Self {
        Self {
            blocked: false,
            vendor: None,
            reason: String::new(),
        }
    }
}

/// Classify an HTTP observation as a WAF/CDN block.
#[must_use]
pub fn classify_http(status: u16, headers_blob: &str, body: &str) -> WafClassification {
    let blob = format!("{headers_blob}\n{body}").to_ascii_lowercase();
    let vendor = WAF_SIGNATURES
        .iter()
        .find(|(_, tokens)| tokens.iter().any(|t| blob.contains(t)))
        .map(|(name, _)| *name);

    let challenge_status = matches!(status, 401 | 403 | 405 | 406 | 429 | 503);
    if let Some(vendor) = vendor {
        if challenge_status
            || blob.contains("attention required")
            || blob.contains("just a moment")
            || blob.contains("cf-mitigated")
        {
            return WafClassification {
                blocked: true,
                vendor: Some(vendor),
                reason: format!("WAF block HTTP {status} ({vendor})"),
            };
        }
        // Vendor present with 2xx is a CDN in front, not a block.
    }

    if challenge_status
        && (blob.contains("waf")
            || blob.contains("request rejected")
            || blob.contains("access denied")
            || blob.contains("not acceptable")
            || blob.contains("blocked by"))
    {
        return WafClassification {
            blocked: true,
            vendor: Some("generic"),
            reason: format!("WAF/ACL block HTTP {status}"),
        };
    }

    WafClassification::none()
}

#[must_use]
pub fn is_waf_block(status: u16, headers_blob: &str, body: &str) -> bool {
    classify_http(status, headers_blob, body).blocked
}

#[must_use]
pub fn engine_treats_403_as_noise(engine: &str) -> bool {
    let e = engine.trim().to_ascii_lowercase();
    if AUTHZ_ENGINE_NEEDLES.iter().any(|n| e.contains(n)) {
        return false;
    }
    WAF_NOISE_ENGINE_NEEDLES.iter().any(|n| e.contains(n))
}

fn title_suggests_noise_class(title: &str) -> bool {
    let t = title.to_ascii_lowercase();
    t.contains("ssrf") || t.contains("graphql") || t.contains("metadata")
}

fn json_status_inner(raw: &Value) -> u16 {
    for key in ["http_status", "status", "response_status", "response_code"] {
        if let Some(n) = raw.get(key).and_then(Value::as_u64) {
            return n as u16;
        }
        if let Some(n) = raw.get(key).and_then(Value::as_i64) {
            return n.max(0) as u16;
        }
    }
    if let Some(ev) = raw.get("evidence") {
        let s = json_status_inner(ev);
        if s > 0 {
            return s;
        }
    }
    if let Some(inner) = raw.get("raw") {
        let s = json_status_inner(inner);
        if s > 0 {
            return s;
        }
    }
    0
}

fn json_body(raw: &Value) -> String {
    for key in ["response_body", "body", "proof"] {
        if let Some(s) = raw.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    if let Some(ev) = raw.get("evidence") {
        if let Some(s) = ev.get("proof").and_then(Value::as_str) {
            return s.to_string();
        }
        if let Some(s) = ev.get("body").and_then(Value::as_str) {
            return s.to_string();
        }
        if let Some(s) = ev.get("raw_excerpt").and_then(Value::as_str) {
            return s.to_string();
        }
    }
    if let Some(inner) = raw.get("raw") {
        return json_body(inner);
    }
    String::new()
}

fn json_headers_blob(raw: &Value) -> String {
    let mut parts = Vec::new();
    for key in ["server", "server_header", "cf-ray", "cf_ray"] {
        if let Some(s) = raw.get(key).and_then(Value::as_str) {
            parts.push(format!("{key}: {s}"));
        }
    }
    if let Some(headers) = raw.get("headers") {
        match headers {
            Value::Object(map) => {
                for (k, v) in map {
                    parts.push(format!("{k}: {v}"));
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        parts.push(s.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(ev) = raw.get("evidence") {
        parts.push(json_headers_blob(ev));
    }
    if let Some(inner) = raw.get("raw") {
        parts.push(json_headers_blob(inner));
    }
    parts.join("\n")
}

/// Persist/verify: this finding is WAF noise and must not stay OPEN / LIKELY_VALID.
#[must_use]
pub fn finding_is_waf_noise(engine: &str, title: &str, raw: &Value) -> bool {
    if AUTHZ_ENGINE_NEEDLES
        .iter()
        .any(|n| engine.to_ascii_lowercase().contains(n))
    {
        return false;
    }
    if !engine_treats_403_as_noise(engine) && !title_suggests_noise_class(title) {
        return false;
    }
    let status = json_status_inner(raw);
    let body = json_body(raw);
    let headers = json_headers_blob(raw);
    let class = classify_http(status, &headers, &body);
    if class.blocked {
        return true;
    }
    // SSRF/GraphQL 403 with no vendor tokens is still not a confirmed vuln — origin
    // (or a silent WAF) refused the probe. Do not treat it as LIKELY_VALID.
    if status == 403 && (engine_treats_403_as_noise(engine) || title_suggests_noise_class(title)) {
        return true;
    }
    false
}

/// Verify-time: a live 403 on a noise-class engine is not reachability proof.
#[must_use]
pub fn live_403_is_noise(engine: &str, status: u16, headers_blob: &str, body: &str) -> bool {
    if !engine_treats_403_as_noise(engine) {
        return classify_http(status, headers_blob, body).blocked;
    }
    if classify_http(status, headers_blob, body).blocked {
        return true;
    }
    status == 403
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cloudflare_403_html_is_waf() {
        let c = classify_http(
            403,
            "server: cloudflare\ncf-ray: 9abc",
            "<html>Attention Required! | Cloudflare</html>",
        );
        assert!(c.blocked);
        assert_eq!(c.vendor, Some("Cloudflare"));
    }

    #[test]
    fn graphql_403_without_vendor_is_still_noise() {
        assert!(finding_is_waf_noise(
            "graphql_attack",
            "GraphQL endpoint discovered",
            &json!({ "http_status": 403, "response_body": "Forbidden" })
        ));
    }

    #[test]
    fn ssrf_cloudflare_is_noise() {
        assert!(finding_is_waf_noise(
            "ssrf_advanced",
            "SSRF: GCP metadata",
            &json!({
                "http_status": 403,
                "server": "cloudflare",
                "evidence": { "proof": "HTTP/2 403 cloudflare" }
            })
        ));
    }

    #[test]
    fn bola_403_is_not_auto_fp() {
        assert!(!finding_is_waf_noise(
            "bola_idor",
            "IDOR on /api/users/2",
            &json!({ "http_status": 403, "response_body": "Forbidden" })
        ));
    }

    #[test]
    fn http_200_cloudflare_cdn_is_not_a_block() {
        let c = classify_http(200, "server: cloudflare", "<html>ok</html>");
        assert!(!c.blocked);
    }

    #[test]
    fn timing_engine_403_is_noise() {
        assert!(engine_treats_403_as_noise("timing_sidechannel"));
        assert!(engine_treats_403_as_noise("microsecond_timing"));
        assert!(engine_treats_403_as_noise("ssti"));
        assert!(finding_is_waf_noise(
            "timing_sidechannel",
            "Auth timing oracle",
            &json!({ "http_status": 403, "response_body": "Forbidden" })
        ));
    }
}
