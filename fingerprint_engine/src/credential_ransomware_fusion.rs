//! Credential → ransomware fusion (legal clearnet OSINT only).
//!
//! Fuses live CISA KEV (ransomware-use flag + product match against the target's
//! HTTP `Server` header, or HTML vendor+product when Server is empty), Have I Been
//! Pwned public breach catalog (and optional authenticated domain search — counts
//! only, never stored emails), Abuse.ch URLhaus hostinfo, and optional IntelX
//! record counts. Two or more feed hits emit a grounded toxic-combo kill-chain.
//! No Tor, no .onion, no leak-site victim lists.

use crate::engine_probes::{
    empty_ok, extract_host, finding, header_value, http_client, http_get,
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

    let (server_hdr, html_hint) = probe_target_hints(&probe_client, target).await;

    match fetch_json(&client, KEV_URL).await {
        Some((status, body)) if status == 200 => {
            feeds_ok += 1;
            findings.extend(kev_findings_for_host(
                &host,
                target,
                &server_hdr,
                &html_hint,
                &body,
            ));
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
        if let Some((status, body)) = fetch_json_with_headers(
            &client,
            &url,
            &[("hibp-api-key", key.as_str()), ("user-agent", UA)],
        )
        .await
        {
            if status == 200 {
                feeds_ok += 1;
                findings.extend(hibp_domain_count_finding(&host, target, &body));
            } else if status == 404 {
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

    if let Some(f) = intelx_count_finding(&client, &host, target).await {
        feeds_ok += 1;
        findings.push(f);
    }

    if let Some(combo) = toxic_combo_from_findings(&host, target, &findings) {
        findings.insert(0, combo);
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
    fetch_json_with_headers(client, url, &[]).await
}

async fn fetch_json_with_headers(
    client: &reqwest::Client,
    url: &str,
    extra: &[(&str, &str)],
) -> Option<(u16, String)> {
    let mut req = client.get(url);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.ok()?;
    Some((status, body))
}

async fn probe_target_hints(client: &reqwest::Client, target: &str) -> (String, String) {
    let url = normalize_url(target);
    if let Some(p) = http_get(client, &url).await {
        let server = header_value(&p.headers, "server")
            .or_else(|| header_value(&p.headers, "x-powered-by"))
            .unwrap_or_default()
            .to_string();
        let html: String = p.body.chars().take(8000).collect();
        return (server, html);
    }
    (String::new(), String::new())
}

pub fn hibp_pro_configured() -> bool {
    hibp_api_key().is_some()
}

pub fn intelx_configured() -> bool {
    intelx_api_key().is_some()
}

fn intelx_api_key() -> Option<String> {
    let k = std::env::var("INTELX_API_KEY")
        .or_else(|_| std::env::var("WEISSMAN_INTELX_KEY"))
        .unwrap_or_default();
    let t = k.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

fn intelx_api_base() -> String {
    std::env::var("INTELX_API_URL")
        .or_else(|_| std::env::var("WEISSMAN_INTELX_URL"))
        .unwrap_or_else(|_| "https://2.intelx.io".to_string())
        .trim()
        .trim_end_matches('/')
        .to_string()
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
        obj.insert("poc".into(), json!(proof));
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

pub fn kev_findings_for_host(
    host: &str,
    target: &str,
    server_hdr: &str,
    html_hint: &str,
    body: &str,
) -> Vec<Value> {
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
    let server_empty = server_hdr.trim().is_empty();
    for row in &feed.vulnerabilities {
        let ransom = row.known_ransomware_use.eq_ignore_ascii_case("known");
        let from_html = if server_empty {
            if !ransom {
                continue;
            }
            if !product_matches_html(html_hint, &row.vendor_project, &row.product) {
                continue;
            }
            true
        } else if product_matches_server(server_hdr, &row.vendor_project, &row.product) {
            false
        } else {
            continue;
        };
        let sev = if ransom { "critical" } else { "high" };
        let surface = if from_html {
            "HTML body product+vendor (Server header empty)"
        } else {
            "HTTP Server header"
        };
        let proof = format!(
            "GET {} HTTP 200; surface={} Server='{}' matched KEV product '{}' / vendor '{}' ({}); knownRansomwareCampaignUse={}",
            KEV_URL,
            surface,
            server_hdr,
            row.product,
            row.vendor_project,
            row.cve_id,
            row.known_ransomware_use
        );
        let mut f = live_finding(
            &format!(
                "CISA KEV product match on live {surface}: {} ({})",
                row.product, row.cve_id
            ),
            sev,
            "T1190",
            &format!(
                "Host '{}' {surface}. CISA KEV lists {} ({}) added {}. Ransomware campaign use: {}. Catalog size {} ({} ransomware-flagged). Required: patch and isolate the internet-facing service.",
                host,
                row.vulnerability_name,
                row.cve_id,
                row.date_added,
                row.known_ransomware_use,
                catalog_n,
                ransomware_n
            ),
            target,
            &proof,
        );
        if let Some(obj) = f.as_object_mut() {
            obj.insert("cve".into(), json!(row.cve_id));
            obj.insert("kev".into(), json!(true));
        }
        out.push(f);
        if out.len() >= 8 {
            break;
        }
    }
    out
}

const GENERIC_PRODUCTS: &[&str] = &[
    "linux", "windows", "unix", "http", "https", "server", "web", "unknown", "none", "n/a",
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

/// HTML-only match: both vendor and product (≥6 chars) must appear. Reduces blog-post false positives.
pub fn product_matches_html(html: &str, vendor: &str, product: &str) -> bool {
    let h = html.to_ascii_lowercase();
    let p = product.trim().to_ascii_lowercase();
    let v = vendor.trim().to_ascii_lowercase();
    if p.len() < 6 || v.len() < 3 || GENERIC_PRODUCTS.contains(&p.as_str()) {
        return false;
    }
    h.contains(&p) && h.contains(&v)
}

pub fn toxic_combo_from_findings(host: &str, target: &str, findings: &[Value]) -> Option<Value> {
    let mut kev = 0usize;
    let mut hibp = 0usize;
    let mut urlhaus = 0usize;
    let mut intelx = 0usize;
    for f in findings {
        let hay = format!(
            "{} {} {}",
            f.get("title").and_then(Value::as_str).unwrap_or(""),
            f.get("description").and_then(Value::as_str).unwrap_or(""),
            f.get("proof").and_then(Value::as_str).unwrap_or("")
        )
        .to_ascii_lowercase();
        if hay.contains("cisa kev") || f.get("kev").and_then(Value::as_bool).unwrap_or(false) {
            kev += 1;
        }
        if hay.contains("hibp") || hay.contains("haveibeenpwned") {
            hibp += 1;
        }
        if hay.contains("urlhaus") {
            urlhaus += 1;
        }
        if hay.contains("intelx") || hay.contains("intelligence x") {
            intelx += 1;
        }
    }
    toxic_combo_finding(host, target, kev, hibp, urlhaus, intelx)
}

pub fn toxic_combo_finding(
    host: &str,
    target: &str,
    kev: usize,
    hibp: usize,
    urlhaus: usize,
    intelx: usize,
) -> Option<Value> {
    let mut hops: Vec<&str> = Vec::new();
    if kev > 0 {
        hops.push("CISA KEV ransomware/product");
    }
    if hibp > 0 {
        hops.push("HIBP credential exposure");
    }
    if urlhaus > 0 {
        hops.push("URLhaus malware URLs");
    }
    if intelx > 0 {
        hops.push("IntelX indexed records");
    }
    if hops.len() < 2 {
        return None;
    }
    let chain = hops.join(" -> ");
    let sev = if kev > 0 && hibp > 0 {
        "critical"
    } else {
        "high"
    };
    let mut f = live_finding(
        &format!("Toxic combo kill-chain: {chain}"),
        sev,
        "T1190",
        &format!(
            "Live fusion on '{host}' produced a grounded kill-chain from independent clearnet feeds (not an invented APT). Hops: {chain}. Counts: kev={kev} hibp={hibp} urlhaus={urlhaus} intelx={intelx}. Rotate credentials, patch the KEV product, and isolate the exposed service."
        ),
        target,
        &format!("kill-chain: {chain}; kev={kev} hibp={hibp} urlhaus={urlhaus} intelx={intelx}"),
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("parent_fqdn".into(), json!(host));
        obj.insert("kill_chain".into(), json!(chain));
    }
    Some(f)
}

fn intelx_record_count(body: &str) -> usize {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some(arr) = v.get("records").and_then(Value::as_array) {
            return arr.len();
        }
        if let Some(n) = v.get("records").and_then(Value::as_u64) {
            return n as usize;
        }
    }
    body.matches("\"storageid\"").count()
}

async fn intelx_count_finding(client: &reqwest::Client, host: &str, target: &str) -> Option<Value> {
    let key = intelx_api_key()?;
    let base = intelx_api_base();
    let search_url = format!("{base}/intelligent/search");
    let payload = json!({
        "term": host,
        "buckets": [],
        "lookuplevel": 0,
        "maxresults": 20,
        "timeout": 0,
        "datefrom": "",
        "dateto": "",
        "sort": 4,
        "media": 0,
        "terminate": []
    });
    let resp = client
        .post(&search_url)
        .header("x-key", key.as_str())
        .json(&payload)
        .send()
        .await
        .ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    let search_id = v.get("id").and_then(Value::as_str)?.to_string();
    let result_url = format!("{base}/intelligent/search/result?id={search_id}");
    let (status, body) =
        fetch_json_with_headers(client, &result_url, &[("x-key", key.as_str())]).await?;
    if status != 200 {
        return None;
    }
    let n = intelx_record_count(&body);
    if n == 0 {
        return None;
    }
    Some(live_finding(
        &format!("IntelX indexed {n} record(s) for {host} (count only)"),
        "medium",
        "T1597",
        &format!(
            "Intelligence X search for '{host}' returned {n} indexed record(s). Weissman stores the count only — no leak bodies, emails, or passwords. Review in the Dark Web Monitor with an authorized IntelX key. This is a commercial clearnet index, not a Tor crawl."
        ),
        target,
        &format!(
            "POST {search_url} + GET search/result HTTP 200 records={n} (identifiers stripped)"
        ),
    ))
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

const LEFT_HOST_LABELS: &[&str] = &[
    "www",
    "mail",
    "vpn",
    "app",
    "api",
    "staging",
    "dev",
    "portal",
    "remote",
    "autodiscover",
];

pub fn apex_domain(host: &str) -> String {
    let stripped = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let no_port = stripped.split(':').next().unwrap_or("").to_string();
    let mut labels: Vec<&str> = no_port.split('.').filter(|s| !s.is_empty()).collect();
    while labels.len() >= 3 && LEFT_HOST_LABELS.contains(&labels[0]) {
        labels.remove(0);
    }
    labels.join(".")
}

fn hibp_domain_count_finding(host: &str, target: &str, body: &str) -> Vec<Value> {
    // Authenticated HIBP domain search returns a JSON object of account → breach names.
    // Count keys only — never persist account identifiers.
    let count = match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(map)) => map.len(),
        Ok(Value::Array(arr)) => arr.len(),
        _ => body
            .matches("\":[")
            .count()
            .max(body.matches("\": [").count()),
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
        assert_eq!(apex_domain("vpn.example.com"), "example.com");
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
        let hits = kev_findings_for_host(
            "vpn.example.com",
            "https://vpn.example.com",
            "FortiOS",
            "",
            body,
        );
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
        let hits =
            kev_findings_for_host("vpn.example.com", "https://vpn.example.com", "", "", body);
        assert!(hits.is_empty());
    }

    #[test]
    fn kev_html_hint_matches_ransomware_product_when_server_empty() {
        let body = r#"{"vulnerabilities":[{"cveID":"CVE-2024-21762","vendorProject":"Fortinet","product":"FortiOS","vulnerabilityName":"FortiOS SSL VPN","knownRansomwareCampaignUse":"Known","dateAdded":"2024-02-09"}]}"#;
        let html = "<html><title>Fortinet FortiOS login</title></html>";
        let hits =
            kev_findings_for_host("vpn.example.com", "https://vpn.example.com", "", html, body);
        assert_eq!(hits.len(), 1);
        assert!(hits[0]["title"].as_str().unwrap().contains("HTML"));
    }

    #[test]
    fn toxic_combo_requires_two_legs() {
        assert!(toxic_combo_finding("h", "https://h", 1, 0, 0, 0).is_none());
        let f = toxic_combo_finding("h.example", "https://h.example", 1, 2, 0, 0).expect("combo");
        let blob = f.to_string();
        assert!(blob.contains("->"));
        assert!(blob.contains("CISA KEV"));
        assert!(blob.contains("HIBP"));
        assert!(!blob.contains("APT28"));
        assert_eq!(f["severity"], "critical");
    }

    #[test]
    fn intelx_counts_records_array_not_names() {
        let body =
            r#"{"records":[{"storageid":"a","name":"alice@evil.example"},{"storageid":"b"}]}"#;
        assert_eq!(intelx_record_count(body), 2);
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
