//! SaaS / IdP Discovery — best-effort hints from DNS + HTTP to identify enterprise IdPs and SaaS dependencies.
//!
//! This is **non-invasive**: it only performs lightweight DNS-over-HTTPS queries and a small set of HTTPS GETs
//! (OIDC discovery + landing page) against likely SSO endpoints derived from authorized client domains.

use futures::stream::{self, StreamExt};
use regex::Regex;
use reqwest::Url;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Duration;

const HTTP_TIMEOUT_SECS: u64 = 10;
const MAX_DOMAINS: usize = 12;
const MAX_HOST_CANDIDATES_PER_DOMAIN: usize = 10;
const HTTP_CONCURRENCY: usize = 12;

fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("Mozilla/5.0 (compatible; WeissmanSaasIdpDiscovery/1.0)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn spf_include_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\binclude:([a-z0-9._-]+)\b").unwrap_or_else(|_| Regex::new("$^").unwrap())
    })
}

fn normalize_domain(d: &str) -> Option<String> {
    let d = d.trim().to_lowercase();
    if d.is_empty() || d.len() > 255 {
        return None;
    }
    let d = d
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim();
    if d.is_empty() {
        return None;
    }
    Some(d.to_string())
}

fn host_candidates_for_domain(domain: &str) -> Vec<String> {
    let mut out = Vec::new();
    let prefixes = [
        "login", "sso", "idp", "auth", "signin", "accounts", "adfs", "sts", "oauth",
    ];
    for p in prefixes {
        out.push(format!("{}.{}", p, domain));
    }
    // Many orgs expose the IdP as the apex or via a dedicated "sso.".
    out.push(domain.to_string());
    out.into_iter()
        .take(MAX_HOST_CANDIDATES_PER_DOMAIN)
        .collect()
}

fn classify_idp_from_issuer_or_host(host: &str) -> Option<&'static str> {
    let h = host.to_lowercase();
    if h.contains("okta.com") || h.contains("oktapreview.com") || h.contains("okta-emea.com") {
        return Some("okta");
    }
    if h.contains("microsoftonline.com")
        || h.contains("sts.windows.net")
        || h.contains("b2clogin.com")
    {
        return Some("azure_ad");
    }
    if h.contains("google.com")
        || h.contains("googleusercontent.com")
        || h.contains("accounts.google")
    {
        return Some("google");
    }
    if h.contains("pingone.com") || h.contains("pingidentity.com") {
        return Some("ping");
    }
    if h.contains("onelogin.com") {
        return Some("onelogin");
    }
    if h.contains("jumpcloud.com") {
        return Some("jumpcloud");
    }
    if h.contains("duosecurity.com") || h.contains("duo.com") {
        return Some("duo");
    }
    None
}

fn classify_saas_from_spf_include(include_domain: &str) -> Option<&'static str> {
    let d = include_domain.to_lowercase();
    if d == "_spf.google.com" {
        return Some("google_workspace");
    }
    if d == "spf.protection.outlook.com" {
        return Some("microsoft_365");
    }
    if d.contains("sendgrid.net") {
        return Some("sendgrid");
    }
    if d.contains("mailgun.org") {
        return Some("mailgun");
    }
    if d.contains("spf.mandrillapp.com") || d.contains("mandrillapp.com") {
        return Some("mandrill");
    }
    None
}

async fn doh_txt_records(domain: &str) -> Vec<String> {
    let client = build_client();
    let url = format!(
        "https://dns.google/resolve?name={}&type=TXT",
        urlencoding::encode(domain)
    );
    let Ok(resp) = client.get(url).send().await else {
        return Vec::new();
    };
    let Ok(v) = resp.json::<Value>().await else {
        return Vec::new();
    };
    let Some(ans) = v.get("Answer").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    ans.iter()
        .filter_map(|a| {
            a.get("data")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string())
        })
        .collect()
}

async fn probe_oidc_discovery(client: &reqwest::Client, host: &str) -> Option<(String, String)> {
    let url = format!("https://{}/.well-known/openid-configuration", host);
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let final_url = resp.url().clone();
    let v = resp.json::<Value>().await.ok()?;
    let issuer = v.get("issuer")?.as_str()?.trim();
    if issuer.is_empty() {
        return None;
    }
    let final_host = final_url.host_str().unwrap_or(host).to_string();
    Some((issuer.to_string(), final_host))
}

async fn probe_https_landing(
    client: &reqwest::Client,
    host: &str,
) -> Option<(String, u16, String, HashMap<String, String>)> {
    let url = format!("https://{}/", host);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().clone();
    let final_host = final_url.host_str().unwrap_or(host).to_string();

    let mut hdrs = HashMap::new();
    for k in ["server", "set-cookie", "x-okta-request-id", "x-azure-ref"] {
        if let Some(v) = resp.headers().get(k).and_then(|h| h.to_str().ok()) {
            hdrs.insert(k.to_string(), v.chars().take(240).collect());
        }
    }
    let body = resp.text().await.ok().unwrap_or_default();
    let snippet: String = body.chars().take(16_384).collect();
    Some((final_host, status, snippet, hdrs))
}

fn detect_vendor_from_landing(
    snippet: &str,
    headers: &HashMap<String, String>,
    final_host: &str,
) -> Option<&'static str> {
    if let Some(v) = headers.get("x-okta-request-id") {
        if !v.is_empty() {
            return Some("okta");
        }
    }
    if let Some(v) = headers.get("x-azure-ref") {
        if !v.is_empty() {
            return Some("azure_ad");
        }
    }
    let lower = snippet.to_lowercase();
    if lower.contains("okta") {
        return Some("okta");
    }
    if lower.contains("azure active directory")
        || lower.contains("microsoft entra")
        || lower.contains("microsoftonline")
    {
        return Some("azure_ad");
    }
    if lower.contains("google workspace") || lower.contains("sign in with google") {
        return Some("google");
    }
    if lower.contains("ping identity") || lower.contains("pingone") {
        return Some("ping");
    }
    if lower.contains("adfs") || lower.contains("active directory federation services") {
        return Some("adfs");
    }
    classify_idp_from_issuer_or_host(final_host)
}

pub async fn discover(domains: &[String]) -> Value {
    let mut uniq = Vec::new();
    let mut seen = HashSet::<String>::new();
    for d in domains.iter().take(80) {
        if let Some(n) = normalize_domain(d) {
            if seen.insert(n.clone()) {
                uniq.push(n);
            }
        }
        if uniq.len() >= MAX_DOMAINS {
            break;
        }
    }

    let mut saas_signals: HashMap<String, Vec<String>> = HashMap::new();
    for d in &uniq {
        let txt = doh_txt_records(d).await;
        for rec in txt {
            if !rec.to_lowercase().contains("v=spf1") {
                continue;
            }
            for cap in spf_include_re().captures_iter(&rec) {
                let inc = cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                if let Some(saas) = classify_saas_from_spf_include(&inc) {
                    saas_signals
                        .entry(saas.to_string())
                        .or_default()
                        .push(format!("domain={} include={}", d, inc));
                }
            }
        }
    }

    let client = build_client();
    let mut host_candidates = Vec::new();
    for d in &uniq {
        for h in host_candidates_for_domain(d) {
            host_candidates.push(h);
        }
    }
    host_candidates.sort();
    host_candidates.dedup();

    let probe_results: Vec<Value> = stream::iter(host_candidates.into_iter().map(|host| {
        let c = client.clone();
        async move {
            let mut signals = Vec::new();
            if let Some((issuer, final_host)) = probe_oidc_discovery(&c, &host).await {
                let vendor = Url::parse(&issuer)
                    .ok()
                    .and_then(|u| u.host_str().map(|h| h.to_string()))
                    .and_then(|h| classify_idp_from_issuer_or_host(&h).map(|v| (v, h)));
                let (vendor, vendor_host) = vendor
                    .map(|(v, h)| (Some(v.to_string()), Some(h)))
                    .unwrap_or((None, None));
                signals.push(json!({
                    "kind": "oidc_discovery",
                    "host": host,
                    "issuer": issuer,
                    "final_host": final_host,
                    "vendor": vendor,
                    "vendor_host": vendor_host,
                    "confidence": 0.95,
                }));
            } else if let Some((final_host, status, snippet, headers)) =
                probe_https_landing(&c, &host).await
            {
                let vendor = detect_vendor_from_landing(&snippet, &headers, &final_host)
                    .map(|s| s.to_string());
                if vendor.is_some() {
                    signals.push(json!({
                        "kind": "landing_probe",
                        "host": host,
                        "final_host": final_host,
                        "status": status,
                        "vendor": vendor,
                        "confidence": if status >= 200 && status < 400 { 0.70 } else { 0.55 },
                        "headers": headers,
                    }));
                }
            }
            if signals.is_empty() {
                Value::Null
            } else {
                json!({ "host": host, "signals": signals })
            }
        }
    }))
    .buffer_unordered(HTTP_CONCURRENCY)
    .collect()
    .await;

    let mut idp_candidates: HashMap<String, Vec<Value>> = HashMap::new();
    for v in probe_results.into_iter().filter(|v| !v.is_null()) {
        if let Some(arr) = v.get("signals").and_then(|s| s.as_array()) {
            for sig in arr {
                if let Some(vendor) = sig.get("vendor").and_then(|x| x.as_str()) {
                    idp_candidates
                        .entry(vendor.to_string())
                        .or_default()
                        .push(sig.clone());
                }
            }
        }
    }

    let idps: Vec<Value> = idp_candidates
        .into_iter()
        .map(|(vendor, mut signals)| {
            signals.sort_by(|a, b| {
                let ca = a.get("confidence").and_then(|x| x.as_f64()).unwrap_or(0.0);
                let cb = b.get("confidence").and_then(|x| x.as_f64()).unwrap_or(0.0);
                cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
            });
            let top = signals.get(0).cloned().unwrap_or(Value::Null);
            json!({
                "vendor": vendor,
                "confidence": top.get("confidence").and_then(|x| x.as_f64()).unwrap_or(0.0),
                "top_signal": top,
                "signals": signals.into_iter().take(8).collect::<Vec<_>>(),
            })
        })
        .collect();

    let saas: Vec<Value> = saas_signals
        .into_iter()
        .map(|(k, v)| json!({"name": k, "evidence": v}))
        .collect();

    json!({
        "domains_considered": uniq,
        "idp_candidates": idps,
        "saas_signals": saas,
        "limits": {
            "max_domains": MAX_DOMAINS,
            "max_host_candidates_per_domain": MAX_HOST_CANDIDATES_PER_DOMAIN,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_lowercases_and_strips() {
        assert_eq!(normalize_domain("Example.COM"), Some("example.com".to_string()));
        assert_eq!(normalize_domain("https://foo.com/path"), Some("foo.com".to_string()));
        assert_eq!(normalize_domain("http://bar.com:8080/x"), Some("bar.com".to_string()));
        assert_eq!(normalize_domain("  spaced.com  "), Some("spaced.com".to_string()));
    }

    #[test]
    fn normalize_domain_rejects_empty_and_oversized() {
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("   "), None);
        assert_eq!(normalize_domain("https://"), None);
        let big = "a".repeat(256);
        assert_eq!(normalize_domain(&big), None);
    }

    #[test]
    fn host_candidates_covers_prefixes_and_apex() {
        let c = host_candidates_for_domain("example.com");
        // 9 prefixes + apex, capped at MAX_HOST_CANDIDATES_PER_DOMAIN (10).
        assert_eq!(c.len(), 10);
        assert_eq!(c[0], "login.example.com");
        assert!(c.contains(&"sso.example.com".to_string()));
        assert!(c.contains(&"idp.example.com".to_string()));
        assert!(c.contains(&"example.com".to_string()));
    }

    #[test]
    fn classify_idp_from_host() {
        assert_eq!(classify_idp_from_issuer_or_host("acme.okta.com"), Some("okta"));
        assert_eq!(classify_idp_from_issuer_or_host("OKTA.COM"), Some("okta"));
        assert_eq!(
            classify_idp_from_issuer_or_host("login.microsoftonline.com"),
            Some("azure_ad")
        );
        assert_eq!(classify_idp_from_issuer_or_host("sts.windows.net"), Some("azure_ad"));
        assert_eq!(classify_idp_from_issuer_or_host("accounts.google.com"), Some("google"));
        assert_eq!(classify_idp_from_issuer_or_host("auth.pingone.com"), Some("ping"));
        assert_eq!(classify_idp_from_issuer_or_host("x.onelogin.com"), Some("onelogin"));
        assert_eq!(classify_idp_from_issuer_or_host("x.jumpcloud.com"), Some("jumpcloud"));
        assert_eq!(classify_idp_from_issuer_or_host("api.duo.com"), Some("duo"));
        assert_eq!(classify_idp_from_issuer_or_host("random.example.net"), None);
    }

    #[test]
    fn classify_saas_from_spf() {
        assert_eq!(classify_saas_from_spf_include("_spf.google.com"), Some("google_workspace"));
        assert_eq!(
            classify_saas_from_spf_include("spf.protection.outlook.com"),
            Some("microsoft_365")
        );
        // Exact-match keys are case-insensitive via lowercasing.
        assert_eq!(
            classify_saas_from_spf_include("SPF.PROTECTION.OUTLOOK.COM"),
            Some("microsoft_365")
        );
        assert_eq!(classify_saas_from_spf_include("u123.wl.sendgrid.net"), Some("sendgrid"));
        assert_eq!(classify_saas_from_spf_include("mg.mailgun.org"), Some("mailgun"));
        assert_eq!(classify_saas_from_spf_include("spf.mandrillapp.com"), Some("mandrill"));
        assert_eq!(classify_saas_from_spf_include("unknown.example.com"), None);
    }

    #[test]
    fn spf_include_regex_captures() {
        let caps: Vec<String> = spf_include_re()
            .captures_iter("v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all")
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();
        assert_eq!(
            caps,
            vec![
                "_spf.google.com".to_string(),
                "spf.protection.outlook.com".to_string()
            ]
        );
    }

    #[test]
    fn detect_vendor_prefers_header_signals() {
        let mut h = HashMap::new();
        h.insert("x-okta-request-id".to_string(), "abc123".to_string());
        assert_eq!(detect_vendor_from_landing("", &h, "host"), Some("okta"));

        let mut h2 = HashMap::new();
        h2.insert("x-azure-ref".to_string(), "ref".to_string());
        assert_eq!(detect_vendor_from_landing("", &h2, "host"), Some("azure_ad"));
    }

    #[test]
    fn detect_vendor_from_body_keywords() {
        let empty = HashMap::new();
        assert_eq!(detect_vendor_from_landing("Welcome to Okta", &empty, "h"), Some("okta"));
        assert_eq!(
            detect_vendor_from_landing("Powered by Microsoft Entra", &empty, "h"),
            Some("azure_ad")
        );
        assert_eq!(
            detect_vendor_from_landing("Sign in with Google", &empty, "h"),
            Some("google")
        );
        assert_eq!(detect_vendor_from_landing("PingOne login", &empty, "h"), Some("ping"));
        assert_eq!(detect_vendor_from_landing("ADFS sign on", &empty, "h"), Some("adfs"));
    }

    #[test]
    fn detect_vendor_falls_back_to_host_then_none() {
        let empty = HashMap::new();
        // No header/body signal -> classify by final host.
        assert_eq!(detect_vendor_from_landing("nothing", &empty, "x.okta.com"), Some("okta"));
        // No signal anywhere.
        assert_eq!(detect_vendor_from_landing("nothing", &empty, "plain.example.net"), None);
    }
}
