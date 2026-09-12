//! Credential → ransomware fusion (legal clearnet OSINT only).
//!
//! Fuses live CISA KEV (ransomware-use flag + product match against the target's
//! HTTP `Server` header), Have I Been Pwned public breach catalog (and optional
//! authenticated domain search — counts only, never stored emails), and Abuse.ch
//! URLhaus hostinfo. No Tor, no .onion, no leak-site victim lists.

use crate::engine_probes::{
    empty_ok, extract_host, finding, header_value, http_client, http_get, http_get_with_headers,
    http_post_bytes_with_headers, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

pub const ENGINE_ID: &str = "credential_ransomware_fusion";
const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const HIBP_BREACHES_URL: &str = "https://haveibeenpwned.com/api/v3/breaches";
const UA: &str = "Weissman-CredentialFusion/1.0 (security-assessment; +https://weissman.io)";

pub async fn run_credential_ransomware_fusion(target: &str) {
    print_result(run_credential_ransomware_fusion_result(target).await);
}

pub async fn run_credential_ransomware_fusion_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let client = intel_client();
    let probe_client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let mut feeds_ok = 0u32;

    let server_hdr = probe_target_server(&probe_client, target).await;

    match fetch_json(&client, KEV_URL).await {
        Some((status, body)) if status == 200 => {
            feeds_ok += 1;
            findings.extend(kev_findings_for_host(&host, target, &server_hdr, &body));
        }
        _ => {}
    }

    match fetch_json(&client, HIBP_BREACHES_URL).await {
        Some((status, body)) if status == 200 => {
            feeds_ok += 1;
            findings.extend(hibp_public_findings(&host, target, &body));
        }
        _ => {}
    }

    if let Some(key) = hibp_api_key() {
        let url = format!(
            "https://haveibeenpwned.com/api/v3/breacheddomain/{}",
            urlencoding::encode(&apex_domain(&host))
        );
        if let Some(p) = http_get_with_headers(
            &probe_client,
            &url,
            &[("hibp-api-key", key.as_str()), ("user-agent", UA)],
        )
        .await
        {
            if p.status == 200 {
                feeds_ok += 1;
                findings.extend(hibp_domain_count_finding(&host, target, &p.body));
            } else if p.status == 404 {
                feeds_ok += 1; // verified empty
            }
        }
    }

    let urlhaus_post = "https://urlhaus-api.abuse.ch/v1/host/";
    let form = format!("host={}", urlencoding::encode(&host));
    let mut urlhaus_body: Option<String> = None;
    if let Some(p) = http_post_bytes_with_headers(
        &probe_client,
        urlhaus_post,
        form.as_bytes(),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("user-agent", UA),
        ],
    )
    .await
    {
        if p.status == 200 {
            urlhaus_body = Some(p.body);
        }
    }
    if urlhaus_body.is_none() {
        let urlhaus = format!(
            "https://urlhaus.abuse.ch/api/v1/hostinfo/{}/",
            urlencoding::encode(&host)
        );
        if let Some(p) = http_get(&probe_client, &urlhaus).await {
            if p.status == 200 {
                urlhaus_body = Some(p.body);
            }
        }
    }
    if let Some(body) = urlhaus_body {
        feeds_ok += 1;
        findings.extend(urlhaus_finding(&host, target, &body));
    }

    if findings.is_empty() {
        if feeds_ok == 0 {
            let f = live_finding(
                "Clearnet fusion feeds unreachable",
                "info",
                "T1597",
                &format!(
                    "credential_ransomware_fusion probed CISA KEV, HIBP, and URLhaus for '{}' but no feed returned HTTP 200. Fail-closed: no fabricated leak or actor names.",
                    host
                ),
                target,
                "feeds: cisa.gov KEV + haveibeenpwned.com/api/v3/breaches + urlhaus.abuse.ch — 0 HTTP 200",
            );
            return EngineResult::ok(vec![f], format!("{ENGINE_ID}: feeds unreachable"));
        }
        return empty_ok(ENGINE_ID, target);
    }
    EngineResult::ok(
        findings.clone(),
        format!("{ENGINE_ID}: {} finding(s)", findings.len()),
    )
}

fn intel_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .user_agent(UA)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn fetch_json(client: &reqwest::Client, url: &str) -> Option<(u16, String)> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.ok()?;
    Some((status, body))
}

async fn probe_target_server(client: &reqwest::Client, target: &str) -> String {
    let url = normalize_url(target);
    if let Some(p) = http_get(client, &url).await {
        return header_value(&p.headers, "server")
            .or_else(|| header_value(&p.headers, "x-powered-by"))
            .unwrap_or("")
            .to_string();
    }
    String::new()
}

fn hibp_api_key() -> Option<String> {
    let k = std::env::var("HIBP_API_KEY")
        .or_else(|_| std::env::var("WEISSMAN_HIBP_API_KEY"))
        .unwrap_or_default();
    let t = k.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

fn live_finding(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    proof: &str,
) -> Value {
    let mut f = finding(ENGINE_ID, title, severity, mitre, description, target);
    if let Some(obj) = f.as_object_mut() {
        obj.insert(
            "evidence".into(),
            json!({
                "engine_id": ENGINE_ID,
                "proof": proof,
            }),
        );
        obj.insert("proof".into(), json!(proof));
        obj.insert("remediation".into(), json!(fusion_remediation(severity)));
    }
    f
}

fn fusion_remediation(severity: &str) -> &'static str {
    if severity.eq_ignore_ascii_case("critical") || severity.eq_ignore_ascii_case("high") {
        "Rotate credentials and IdP sessions for the affected domain, patch KEV CVEs on the observed product, break internet-exposed identity paths, and open a gated auto-heal / SOAR ticket. Do not store stealer passwords — HIBP counts only."
    } else {
        "Confirm the live feed hit, reduce session lifetime, enforce phishing-resistant MFA, and re-run credential_ransomware_fusion after containment."
    }
}

#[derive(Debug, Deserialize)]
struct KevFeed {
    #[serde(default)]
    vulnerabilities: Vec<KevRow>,
}

#[derive(Debug, Deserialize, Default)]
struct KevRow {
    #[serde(rename = "cveID", default)]
    cve_id: String,
    #[serde(rename = "vendorProject", default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(rename = "vulnerabilityName", default)]
    vulnerability_name: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    known_ransomware_use: String,
    #[serde(rename = "dateAdded", default)]
    date_added: String,
}

pub fn kev_findings_for_host(host: &str, target: &str, server_hdr: &str, body: &str) -> Vec<Value> {
    let Ok(feed) = serde_json::from_str::<KevFeed>(body) else {
        return Vec::new();
    };
    let catalog_n = feed.vulnerabilities.len();
    let ransomware_n = feed
        .vulnerabilities
        .iter()
        .filter(|v| v.known_ransomware_use.eq_ignore_ascii_case("known"))
        .count();
    let mut out = Vec::new();
    if !server_hdr.trim().is_empty() {
        for row in &feed.vulnerabilities {
            if !product_matches_server(server_hdr, &row.vendor_project, &row.product) {
                continue;
            }
            let ransom = row.known_ransomware_use.eq_ignore_ascii_case("known");
            let sev = if ransom { "critical" } else { "high" };
            let proof = format!(
                "GET {} HTTP 200; target Server='{}' matched KEV product '{}' / vendor '{}' ({}); knownRansomwareCampaignUse={}",
                KEV_URL,
                server_hdr,
                row.product,
                row.vendor_project,
                row.cve_id,
                row.known_ransomware_use
            );
            out.push(live_finding(
                &format!(
                    "CISA KEV product match on live Server header: {} ({})",
                    row.product, row.cve_id
                ),
                sev,
                "T1190",
                &format!(
                    "Host '{}' advertised HTTP Server '{}'. CISA KEV lists {} ({}) added {}. Ransomware campaign use: {}. Catalog size {} ({} ransomware-flagged). Required: patch and isolate the internet-facing service.",
                    host,
                    server_hdr,
                    row.vulnerability_name,
                    row.cve_id,
                    row.date_added,
                    row.known_ransomware_use,
                    catalog_n,
                    ransomware_n
                ),
                target,
                &proof,
            ));
            if out.len() >= 8 {
                break;
            }
        }
    }
    out
}

const GENERIC_PRODUCTS: &[&str] = &[
    "linux",
    "windows",
    "unix",
    "http",
    "https",
    "server",
    "web",
    "unknown",
    "none",
    "n/a",
];

pub fn product_matches_server(server: &str, vendor: &str, product: &str) -> bool {
    let s = server.to_ascii_lowercase();
    let p = product.trim().to_ascii_lowercase();
    let v = vendor.trim().to_ascii_lowercase();
    if p.len() < 4 || GENERIC_PRODUCTS.contains(&p.as_str()) {
        return false;
    }
    if s.contains(&p) {
        return true;
    }
    if p.len() >= 6 && v.len() >= 3 && s.contains(&v) && s.contains(&p[..p.len().min(6)]) {
        return true;
    }
    false
}

#[derive(Debug, Deserialize)]
struct HibpBreach {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Domain", default)]
    domain: String,
    #[serde(rename = "BreachDate", default)]
    breach_date: String,
    #[serde(rename = "PwnCount", default)]
    pwn_count: i64,
    #[serde(rename = "IsVerified", default)]
    is_verified: bool,
    #[serde(rename = "DataClasses", default)]
    data_classes: Vec<String>,
}

pub fn hibp_public_findings(host: &str, target: &str, body: &str) -> Vec<Value> {
    let Ok(breaches) = serde_json::from_str::<Vec<HibpBreach>>(body) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for b in &breaches {
        if !host_matches_breach_domain(host, &b.domain) {
            continue;
        }
        let classes = b.data_classes.join(", ");
        let proof = format!(
            "GET {} HTTP 200; breach '{}' Domain='{}' BreachDate={} PwnCount={} verified={}",
            HIBP_BREACHES_URL, b.name, b.domain, b.breach_date, b.pwn_count, b.is_verified
        );
        out.push(live_finding(
            &format!(
                "HIBP public catalog lists '{}' as a breached site for {}",
                b.name, b.domain
            ),
            "high",
            "T1589",
            &format!(
                "Have I Been Pwned public breach catalog matches authorized host '{}'. Breach {} on {} (pwn_count={}, verified={}). Data classes: {}. Attribution: Have I Been Pwned (CC-BY). No passwords or email addresses are stored.",
                host, b.name, b.breach_date, b.pwn_count, b.is_verified, classes
            ),
            target,
            &proof,
        ));
        if out.len() >= 12 {
            break;
        }
    }
    out
}

pub fn host_matches_breach_domain(host: &str, breach_domain: &str) -> bool {
    let h = apex_domain(host);
    let d = apex_domain(breach_domain);
    if d.is_empty() {
        return false;
    }
    h == d || h.ends_with(&format!(".{d}"))
}

pub fn apex_domain(host: &str) -> String {
    let h = host
        .trim()
        .trim_start_matches("www.")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    h.split(':').next().unwrap_or(&h).to_string()
}

fn hibp_domain_count_finding(host: &str, target: &str, body: &str) -> Vec<Value> {
    // Authenticated HIBP domain search returns a JSON object of account → breach names.
    // Count keys only — never persist account identifiers.
    let count = match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(map)) => map.len(),
        Ok(Value::Array(arr)) => arr.len(),
        _ => body.matches("\":[").count().max(body.matches("\": [").count()),
    };
    if count == 0 {
        return Vec::new();
    }
    let proof = format!(
        "GET https://haveibeenpwned.com/api/v3/breacheddomain/{} HTTP 200; account_keys={} (identifiers stripped)",
        apex_domain(host),
        count
    );
    vec![live_finding(
        &format!(
            "HIBP verified-domain search: {count} account identifier(s) in breaches for {}",
            apex_domain(host)
        ),
        "high",
        "T1555",
        &format!(
            "Have I Been Pwned Pro domain search for '{}' returned {count} account identifier(s) present in catalogued breaches. Identifiers are not stored in Weissman findings. Rotate sessions, force password reset, and hunt infostealer store-existence on unmanaged endpoints. Attribution: Have I Been Pwned.",
            apex_domain(host)
        ),
        target,
        &proof,
    )]
}

fn urlhaus_finding(host: &str, target: &str, body: &str) -> Vec<Value> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let listed = v
        .get("query_status")
        .and_then(Value::as_str)
        .map(|s| s.eq_ignore_ascii_case("ok"))
        .unwrap_or(false);
    let url_count = v
        .get("urls")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    if !listed || url_count == 0 {
        return Vec::new();
    }
    let proof = format!(
        "POST https://urlhaus-api.abuse.ch/v1/host/ HTTP 200 query_status=ok urls={url_count} (clearnet IOC feed, not Tor)"
    );
    vec![live_finding(
        &format!("URLhaus lists {url_count} malicious URL(s) for {host}"),
        "high",
        "T1583.006",
        &format!(
            "Abuse.ch URLhaus hostinfo returned {url_count} URL(s) for '{host}'. Cross-check for malware delivery / C2. This is a clearnet IOC feed, not a dark-web crawl."
        ),
        target,
        &proof,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_match_is_apex_aware() {
        assert!(host_matches_breach_domain("www.adobe.com", "adobe.com"));
        assert!(host_matches_breach_domain("mail.adobe.com", "adobe.com"));
        assert!(!host_matches_breach_domain("example.com", "adobe.com"));
        assert!(!host_matches_breach_domain("notadobe.com", "adobe.com"));
    }

    #[test]
    fn kev_matches_distinct_server_product() {
        assert!(product_matches_server("FortiOS-7.0", "Fortinet", "FortiOS"));
        assert!(product_matches_server("nginx/1.24.0", "F5", "nginx"));
        assert!(!product_matches_server("Apache", "Microsoft", "Windows"));
        assert!(!product_matches_server("cloudflare", "n/a", "http"));
    }

    #[test]
    fn hibp_fixture_emits_count_not_emails() {
        let body = r#"[{"Name":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":152445165,"IsVerified":true,"DataClasses":["Email addresses","Passwords"]}]"#;
        let hits = hibp_public_findings("www.adobe.com", "https://adobe.com", body);
        assert_eq!(hits.len(), 1);
        let blob = hits[0].to_string();
        assert!(blob.contains("HIBP"));
        assert!(!blob.contains("@"), "must not persist emails");
        assert!(blob.contains("haveibeenpwned.com"));
    }

    #[test]
    fn kev_fixture_matches_fortios() {
        let body = r#"{"vulnerabilities":[{"cveID":"CVE-2024-21762","vendorProject":"Fortinet","product":"FortiOS","vulnerabilityName":"FortiOS SSL VPN","knownRansomwareCampaignUse":"Known","dateAdded":"2024-02-09"}]}"#;
        let hits = kev_findings_for_host("vpn.example.com", "https://vpn.example.com", "FortiOS", body);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["severity"], "critical");
        let blob = hits[0].to_string();
        assert!(blob.contains("CVE-2024-21762"));
        assert!(!blob.contains("APT28"));
        assert!(!blob.contains("Lazarus"));
    }

    #[test]
    fn kev_no_server_header_emits_nothing() {
        let body = r#"{"vulnerabilities":[{"cveID":"CVE-2024-21762","vendorProject":"Fortinet","product":"FortiOS","vulnerabilityName":"x","knownRansomwareCampaignUse":"Known","dateAdded":"2024-02-09"}]}"#;
        let hits = kev_findings_for_host("vpn.example.com", "https://vpn.example.com", "", body);
        assert!(hits.is_empty());
    }

    #[test]
    fn urlhaus_ok_emits_count_not_payload() {
        let body = r#"{"query_status":"ok","urls":[{"url":"https://evil.example/a"},{"url":"https://evil.example/b"}]}"#;
        let hits = urlhaus_finding("evil.example", "https://evil.example", body);
        assert_eq!(hits.len(), 1);
        let blob = hits[0].to_string();
        assert!(blob.contains("URLhaus"));
        assert!(blob.contains("2"));
        assert!(!blob.contains("APT28"));
    }

    #[test]
    fn hibp_domain_search_counts_keys_only() {
        let body = r#"{"alice":["Adobe"],"bob":["LinkedIn"]}"#;
        let hits = hibp_domain_count_finding("acme.com", "https://acme.com", body);
        assert_eq!(hits.len(), 1);
        let blob = hits[0].to_string();
        assert!(blob.contains("2"));
        assert!(!blob.contains("alice"));
        assert!(!blob.contains("bob"));
        assert!(!blob.contains("@"));
    }
}
