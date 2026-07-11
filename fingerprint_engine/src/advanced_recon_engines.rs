//! Advanced Recon Engines — real OSINT/DNS/HTTP probes. No simulated content.

use crate::engine_probes::{
    dns_a, dns_mx, dns_txt, empty_ok, extract_host, finding, header_value, http_client, http_get,
    http_get_with_headers, http_post_json_with_headers, normalize_url, tcp_scan,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

// ── satellite_recon ───────────────────────────────────────────────────────────
// Query a public geolocation API only when DNS resolves; report coordinates when the API returns them.
pub async fn run_satellite_recon_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let ips = dns_a(&host).await;
    if ips.is_empty() {
        return empty_ok("satellite_recon", target);
    }
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    for ip in ips.iter().take(2) {
        let url = format!(
            "http://ip-api.com/json/{}?fields=status,lat,lon,country,city",
            ip
        );
        if let Some(p) = http_get(&client, &url).await {
            if p.status != 200 {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(&p.body) {
                if v.get("status").and_then(Value::as_str) != Some("success") {
                    continue;
                }
                let lat = v.get("lat").and_then(Value::as_f64);
                let lon = v.get("lon").and_then(Value::as_f64);
                if lat.is_none() || lon.is_none() {
                    continue;
                }
                findings.push(finding(
                    "satellite_recon",
                    "Host IP geolocation enumerable",
                    "info",
                    "T1591.001",
                    &format!(
                        "{} resolves to {} → lat={}, lon={} ({}, {}). Physical OPSEC / facility exposure review recommended.",
                        host,
                        ip,
                        lat.unwrap_or(0.0),
                        lon.unwrap_or(0.0),
                        v.get("city").and_then(Value::as_str).unwrap_or(""),
                        v.get("country").and_then(Value::as_str).unwrap_or("")
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("satellite_recon", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("satellite_recon: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_satellite_recon, run_satellite_recon_result);

// ── darkweb_intel / deepweb_intel ─────────────────────────────────────────────
fn intelx_api_key() -> String {
    std::env::var("INTELX_API_KEY")
        .or_else(|_| std::env::var("WEISSMAN_INTELX_KEY"))
        .unwrap_or_default()
}

fn intelx_api_base() -> String {
    std::env::var("INTELX_API_URL")
        .or_else(|_| std::env::var("WEISSMAN_INTELX_URL"))
        .unwrap_or_else(|_| "https://2.intelx.io".to_string())
        .trim_end_matches('/')
        .to_string()
}

pub async fn run_darkweb_intel_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let host = extract_host(target);
    let key = intelx_api_key();

    if key.is_empty() {
        let finding = finding(
            "darkweb_intel",
            "IntelX deep-web lookup requires API key",
            "info",
            "T1597",
            &format!(
                "Intelligence X indexes leaks, paste sites, and dark-web mentions. Set INTELX_API_KEY (or WEISSMAN_INTELX_KEY) to query records for '{}'. Without a key, only manual lookup at https://intelx.io/?s={} is available.",
                host, urlencoding::encode(&host)
            ),
            target,
        );
        return EngineResult::ok(
            vec![finding],
            format!(
                "darkweb_intel: API key required for live lookup on {}",
                host
            ),
        );
    }

    let base = intelx_api_base();
    let search_url = format!("{}/intelligent/search", base);
    let payload = serde_json::json!({
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
    let mut findings: Vec<Value> = Vec::new();

    if let Some(p) =
        http_post_json_with_headers(&client, &search_url, &payload, &[("x-key", key.as_str())])
            .await
    {
        if p.status == 401 || p.status == 403 {
            findings.push(finding(
                "darkweb_intel",
                "IntelX API rejected credentials",
                "info",
                "T1597",
                &format!(
                    "IntelX returned HTTP {} — verify INTELX_API_KEY and INTELX_API_URL (default 2.intelx.io for paid keys).",
                    p.status
                ),
                target,
            ));
        } else if p.status == 200 {
            if let Ok(v) = serde_json::from_str::<Value>(&p.body) {
                if let Some(search_id) = v.get("id").and_then(|id| id.as_str()) {
                    let result_url = format!("{}/intelligent/search/result?id={}", base, search_id);
                    if let Some(rp) =
                        http_get_with_headers(&client, &result_url, &[("x-key", key.as_str())])
                            .await
                    {
                        let record_count = rp
                            .body
                            .matches("\"record\"")
                            .count()
                            .max(rp.body.matches("\"name\"").count());
                        let status =
                            rp.body.contains("\"status\":0") || rp.body.contains("\"status\": 0");
                        if status && record_count > 0 {
                            findings.push(finding(
                                "darkweb_intel",
                                &format!("IntelX returned {} candidate record(s) for {}", record_count, host),
                                "medium",
                                "T1597",
                                &format!(
                                    "Intelligence X search id {} returned {} hits referencing '{}'. Review for leaked credentials and breach exposure.",
                                    search_id, record_count, host
                                ),
                                target,
                            ));
                        } else if status {
                            findings.push(finding(
                                "darkweb_intel",
                                "IntelX search completed — no indexed records",
                                "info",
                                "T1597",
                                &format!(
                                    "Intelligence X query for '{}' completed with zero indexed records in configured buckets.",
                                    host
                                ),
                                target,
                            ));
                        }
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        empty_ok("darkweb_intel", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("darkweb_intel: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_darkweb_intel, run_darkweb_intel_result);

// ── financial_osint ───────────────────────────────────────────────────────────
/// Extract a SEC Central Index Key (CIK) from an EDGAR response — a confirmed
/// registrant identifier (`CIK=0001318605`).
fn extract_edgar_cik(body: &str) -> Option<String> {
    for marker in ["CIK=", "cik=", "CIK "] {
        if let Some(idx) = body.find(marker) {
            let digits: String = body[idx + marker.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if digits.len() >= 4 {
                return Some(digits);
            }
        }
    }
    None
}

pub async fn run_financial_osint_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    // Query by the organisation label (registrable name), not the full host.
    let org = host
        .split('.')
        .next()
        .filter(|s| s.len() > 2)
        .unwrap_or(&host);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let url = format!(
        "https://www.sec.gov/cgi-bin/browse-edgar?company={}&action=getcompany",
        urlencoding::encode(org)
    );
    if let Some(p) = http_get(&client, &url).await {
        if p.status == 200 && p.body.contains("EDGAR") {
            let body_low = p.body.to_lowercase();
            let cik = extract_edgar_cik(&p.body);
            let has_filings = cik.is_some()
                || body_low.contains("annual report")
                || body_low.contains("10-k")
                || body_low.contains("10-q");
            if has_filings {
                let (title, detail) = if let Some(cik) = &cik {
                    (
                        format!("SEC registrant confirmed (CIK {cik})"),
                        format!("EDGAR resolved '{org}' to CIK {cik} — a public SEC filer. Pull 10-K/10-Q for subsidiaries, acquisitions, named executives, and material cyber-incident disclosures (Item 1.05)."),
                    )
                } else {
                    (
                        "SEC EDGAR filings indexed for organisation".to_string(),
                        format!("EDGAR returned filings referencing '{org}' — review 10-K/10-Q for subsidiary and acquisition intel."),
                    )
                };
                findings.push(finding(
                    "financial_osint",
                    &title,
                    "info",
                    "T1591.002",
                    &detail,
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("financial_osint", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("financial_osint: {n}"))
    }
}
cli_wrapper!(run_financial_osint, run_financial_osint_result);

// ── blockchain_trace ──────────────────────────────────────────────────────────
/// Extract the wei balance string from an Etherscan `{status,result}` JSON body.
fn etherscan_balance_wei(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    if v.get("status").and_then(Value::as_str) != Some("1") {
        return None;
    }
    v.get("result")
        .and_then(Value::as_str)
        .filter(|s| s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty())
        .map(str::to_string)
}

/// Format a wei amount (as a decimal string) into an ETH string with 6 decimals.
/// Uses u128 so large balances (> 18 ETH ≈ u64 overflow) are handled.
fn wei_to_eth_string(wei: &str) -> Option<String> {
    let wei: u128 = wei.trim().parse().ok()?;
    let whole = wei / 1_000_000_000_000_000_000u128;
    let frac6 = (wei % 1_000_000_000_000_000_000u128) / 1_000_000_000_000u128;
    Some(format!("{whole}.{frac6:06}"))
}

pub async fn run_blockchain_trace_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    // Looks like an ETH address?
    let t = target.trim();
    let mut findings: Vec<Value> = Vec::new();
    if t.starts_with("0x") && t.len() == 42 && t[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        let client = http_client().await;
        let url = format!(
            "https://api.etherscan.io/api?module=account&action=balance&address={}&tag=latest",
            t
        );
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 {
                if let Some(wei) = etherscan_balance_wei(&p.body) {
                    let eth = wei_to_eth_string(&wei).unwrap_or_else(|| "?".to_string());
                    findings.push(finding(
                        "blockchain_trace",
                        &format!("On-chain ETH balance: {eth} ETH"),
                        "info",
                        "T1583.006",
                        &format!("Etherscan reports {eth} ETH ({wei} wei) for {t}. Pivot on transaction history for wallet clustering / ransom-payment attribution (supply WEISSMAN_ETHERSCAN_KEY for full traces)."),
                        target,
                    ));
                }
            }
        }
    }
    if findings.is_empty() {
        empty_ok("blockchain_trace", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("blockchain_trace: {n}"))
    }
}
cli_wrapper!(run_blockchain_trace, run_blockchain_trace_result);

// ── metadata_harvest ──────────────────────────────────────────────────────────
/// Extract `Disallow:` paths from a robots.txt body (a hidden-surface roadmap).
fn robots_disallow_paths(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| {
            let l = l.trim();
            let low = l.to_ascii_lowercase();
            if low.starts_with("disallow:") {
                let path = l[l.find(':').map_or(l.len(), |i| i + 1)..].trim();
                (!path.is_empty() && path != "/").then(|| path.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// True if a path looks like sensitive / hidden infrastructure.
fn is_sensitive_path(p: &str) -> bool {
    let p = p.to_ascii_lowercase();
    [
        "admin",
        "internal",
        "private",
        "backup",
        "config",
        "/api",
        "secret",
        "staging",
        "/dev",
        "test",
        "upload",
        "/db",
        "sql",
        "git",
        "env",
        "phpmyadmin",
        "login",
        "dashboard",
        "console",
        "debug",
    ]
    .iter()
    .any(|k| p.contains(k))
}

/// Extract `Contact:` lines from a security.txt body.
fn security_txt_contacts(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.to_ascii_lowercase().starts_with("contact:") {
                let v = l[l.find(':').map_or(l.len(), |i| i + 1)..].trim();
                (!v.is_empty()).then(|| v.to_string())
            } else {
                None
            }
        })
        .collect()
}

pub async fn run_metadata_harvest_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let root = base.trim_end_matches('/').to_string();
    let mut findings: Vec<Value> = Vec::new();

    // robots.txt — extract the actual Disallow paths (these routinely disclose
    // hidden admin/internal endpoints; a Disallow entry is a roadmap, not a control).
    if let Some(p) = http_get(&client, &format!("{root}/robots.txt")).await {
        if p.status == 200 && !p.body.trim().is_empty() {
            let paths = robots_disallow_paths(&p.body);
            let sensitive: Vec<String> = paths
                .iter()
                .filter(|p| is_sensitive_path(p))
                .cloned()
                .collect();
            if !sensitive.is_empty() {
                let shown = sensitive
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(finding(
                    "metadata_harvest",
                    &format!("robots.txt discloses {} sensitive disallowed path(s)", sensitive.len()),
                    "medium",
                    "T1592.002",
                    &format!("{root}/robots.txt reveals hidden surface via Disallow: {shown}. Audit and protect these endpoints — Disallow is a hint to crawlers, not access control."),
                    target,
                ));
            } else if !paths.is_empty() {
                findings.push(finding(
                    "metadata_harvest",
                    &format!("robots.txt lists {} disallowed path(s)", paths.len()),
                    "info",
                    "T1592.002",
                    &format!("{root}/robots.txt enumerates {} disallowed path(s) — map for hidden content.", paths.len()),
                    target,
                ));
            }
        }
    }
    // security.txt — extract disclosure contacts.
    if let Some(p) = http_get(&client, &format!("{root}/.well-known/security.txt")).await {
        if p.status == 200 {
            let contacts = security_txt_contacts(&p.body);
            if !contacts.is_empty() {
                findings.push(finding(
                    "metadata_harvest",
                    "security.txt published with disclosure contact(s)",
                    "info",
                    "T1592.002",
                    &format!("security.txt exposes contact(s): {}. Useful for coordinated disclosure and social-engineering target mapping.", contacts.join(", ")),
                    target,
                ));
            }
        }
    }
    // sitemap.xml — count exposed URLs (a full content map).
    if let Some(p) = http_get(&client, &format!("{root}/sitemap.xml")).await {
        if p.status == 200 && p.body.contains("<loc>") {
            let n = p.body.matches("<loc>").count();
            findings.push(finding(
                "metadata_harvest",
                &format!("sitemap.xml exposes {n} URL(s)"),
                "info",
                "T1592.002",
                &format!("{root}/sitemap.xml enumerates {n} URL(s) — a complete content map of the target."),
                target,
            ));
        }
    }

    if findings.is_empty() {
        empty_ok("metadata_harvest", target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!("metadata_harvest: {n} metadata signal(s)"),
        )
    }
}
cli_wrapper!(run_metadata_harvest, run_metadata_harvest_result);

// ── patent_recon ──────────────────────────────────────────────────────────────

/// Extract the real total result count from a Google Patents XHR JSON body.
/// The endpoint prefixes its JSON with an anti-hijacking token (`)]}'`) and may
/// encode the count as a number or a comma-formatted string — handle both.
fn extract_patent_result_count(body: &str) -> Option<u64> {
    let cleaned = body.trim_start().trim_start_matches(")]}'").trim_start();
    let v: Value = serde_json::from_str(cleaned).ok()?;
    let n = v.get("results").and_then(|r| r.get("total_num_results"))?;
    n.as_u64().or_else(|| {
        n.as_str()
            .and_then(|s| s.replace(',', "").trim().parse().ok())
    })
}

pub async fn run_patent_recon_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    // Organisation keyword = the registrable label (drop the TLD path).
    let org = host
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(&host);
    let client = http_client().await;
    // Google Patents' HTML is a client-rendered SPA, so a substring match on the
    // page body is meaningless (it always contains the word "patent"). Query the
    // structured XHR endpoint instead and report the ACTUAL number of patents
    // attributed to the organisation keyword — real IP-portfolio intelligence.
    let url = format!(
        "https://patents.google.com/xhr/query?url={}",
        urlencoding::encode(&format!("q=\"{org}\""))
    );
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if p.status == 200 {
            if let Some(count) = extract_patent_result_count(&p.body) {
                if count > 0 {
                    findings.push(finding(
                        "patent_recon",
                        &format!("{count} patent record(s) attributed to '{org}'"),
                        "info",
                        "T1591",
                        &format!(
                            "Google Patents returns {count} result(s) for organisation keyword '{org}'. Enumerate the portfolio to map R&D focus, inventor names (social-engineering targets), and disclosed tech stack."
                        ),
                        target,
                    ));
                }
            }
        }
    }
    if findings.is_empty() {
        empty_ok("patent_recon", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("patent_recon: {n} portfolio signal(s)"))
    }
}
cli_wrapper!(run_patent_recon, run_patent_recon_result);

#[cfg(test)]
mod patent_recon_tests {
    use super::extract_patent_result_count;

    #[test]
    fn parses_numeric_count() {
        let body = r#"{"results":{"total_num_results":1234}}"#;
        assert_eq!(extract_patent_result_count(body), Some(1234));
    }

    #[test]
    fn strips_xhr_prefix_and_parses_string_count() {
        let body = ")]}'\n{\"results\":{\"total_num_results\":\"12,345\"}}";
        assert_eq!(extract_patent_result_count(body), Some(12_345));
    }

    #[test]
    fn returns_none_on_garbage_or_missing() {
        assert_eq!(extract_patent_result_count("not json"), None);
        assert_eq!(extract_patent_result_count(r#"{"results":{}}"#), None);
    }
}

// ── telecom_osint ─────────────────────────────────────────────────────────────
/// Identify the managed mail provider from a domain's MX hostnames.
fn mail_provider_from_mx(mx: &[String]) -> Option<&'static str> {
    let joined = mx.join(" ").to_ascii_lowercase();
    const PROVIDERS: &[(&str, &str)] = &[
        ("aspmx.l.google.com", "Google Workspace"),
        ("googlemail.com", "Google Workspace"),
        ("google.com", "Google Workspace"),
        ("protection.outlook.com", "Microsoft 365"),
        ("outlook.com", "Microsoft 365"),
        ("pphosted.com", "Proofpoint"),
        ("ppe-hosted.com", "Proofpoint"),
        ("mimecast.com", "Mimecast"),
        ("messagelabs.com", "Broadcom/Symantec Email Security"),
        ("barracudanetworks.com", "Barracuda"),
        ("mailgun.org", "Mailgun"),
        ("sendgrid.net", "SendGrid"),
        ("amazonaws.com", "Amazon SES"),
        ("zoho.com", "Zoho Mail"),
        ("mx.cloudflare.net", "Cloudflare Email Routing"),
        ("secureserver.net", "GoDaddy Email"),
        ("yandex.net", "Yandex Mail"),
        ("qq.com", "Tencent QQ Mail"),
    ];
    PROVIDERS
        .iter()
        .find(|(needle, _)| joined.contains(needle))
        .map(|(_, name)| *name)
}

pub async fn run_telecom_osint_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mx = dns_mx(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    if !mx.is_empty() {
        if let Some(provider) = mail_provider_from_mx(&mx) {
            findings.push(finding(
                "telecom_osint",
                &format!("Mail provider identified: {provider}"),
                "info",
                "T1590.002",
                &format!("MX records for {host} route to {provider} ({}). Tailor the phishing-resistance review (SPF/DKIM/DMARC alignment) and known {provider} filtering-bypass techniques.", mx.join(", ")),
                target,
            ));
        } else {
            findings.push(finding(
                "telecom_osint",
                "MX records publicly resolvable (self-hosted / unrecognized provider)",
                "info",
                "T1590.002",
                &format!("MX records for {host}: {}. No managed provider matched — likely self-hosted mail; assess the mail server directly.", mx.join(", ")),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("telecom_osint", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("telecom_osint: {n}"))
    }
}
cli_wrapper!(run_telecom_osint, run_telecom_osint_result);

// ── iot_shodan_scan ───────────────────────────────────────────────────────────
pub async fn run_iot_shodan_scan_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let client = http_client().await;
    let key = std::env::var("WEISSMAN_SHODAN_API_KEY").unwrap_or_default();
    let mut findings: Vec<Value> = Vec::new();
    if !key.is_empty() {
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", host, key);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && p.body.contains("\"ports\"") {
                findings.push(finding(
                    "iot_shodan_scan",
                    "Shodan host metadata available",
                    "medium",
                    "T1595.001",
                    &format!(
                        "Shodan returned host metadata for {} (review exposed ports/services).",
                        host
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        let open = tcp_scan(&host, &[554, 1883, 8883, 502, 102, 8080, 8443, 161], 8).await;
        if !open.is_empty() {
            findings.push(finding(
                "iot_shodan_scan",
                &format!("Passive IoT port surface: {:?}", open),
                "medium",
                "T1595.001",
                &format!(
                    "No Shodan API key configured — live TCP connect found open ports {:?} on {host}. Set WEISSMAN_SHODAN_API_KEY for full host metadata.",
                    open
                ),
                target,
            ));
        } else {
            findings.push(finding(
                "iot_shodan_scan",
                "Shodan API key not configured — no IoT ports observed",
                "info",
                "T1595.001",
                &format!(
                    "Set WEISSMAN_SHODAN_API_KEY for Shodan host metadata on {host}. Passive TCP scan of common IoT ports found no listeners from this vantage."
                ),
                target,
            ));
        }
    }
    EngineResult::ok(
        findings.clone(),
        format!("iot_shodan_scan: {}", findings.len()),
    )
}
cli_wrapper!(run_iot_shodan_scan, run_iot_shodan_scan_result);

// ── job_posting_osint ─────────────────────────────────────────────────────────
/// Technologies commonly disclosed in job postings — maps a target's stack,
/// cloud provider, and defensive tooling.
fn extract_tech_stack(body_low: &str) -> Vec<&'static str> {
    const TECH: &[&str] = &[
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "docker",
        "terraform",
        "ansible",
        "react",
        "angular",
        "node.js",
        "python",
        "django",
        "spring",
        "golang",
        "rust",
        ".net",
        "kafka",
        "postgresql",
        "mongodb",
        "redis",
        "elasticsearch",
        "snowflake",
        "jenkins",
        "gitlab",
        "splunk",
        "crowdstrike",
        "sentinelone",
        "okta",
        "sailpoint",
        "cyberark",
        "palo alto",
        "fortinet",
        "servicenow",
        "salesforce",
        "sap",
    ];
    TECH.iter()
        .filter(|t| body_low.contains(**t))
        .copied()
        .collect()
}

pub async fn run_job_posting_osint_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let urls = [
        format!(
            "https://www.linkedin.com/jobs/search?keywords={}",
            urlencoding::encode(&host)
        ),
        format!(
            "https://www.indeed.com/jobs?q={}",
            urlencoding::encode(&host)
        ),
    ];
    for u in urls.iter() {
        if let Some(p) = http_get(&client, u).await {
            if p.status == 200 {
                let body_low = p.body.to_ascii_lowercase();
                // Real intel: the tech stack disclosed in job postings maps the
                // target's infrastructure and defensive tooling.
                let stack = extract_tech_stack(&body_low);
                if !stack.is_empty() {
                    findings.push(finding(
                        "job_posting_osint",
                        &format!("Tech stack disclosed in job postings ({} technologies)", stack.len()),
                        "info",
                        "T1591.004",
                        &format!("Postings on {u} for '{host}' disclose: {}. This maps the target's infrastructure, cloud provider, and defensive tooling for tailored exploitation and phishing pretexts.", stack.join(", ")),
                        target,
                    ));
                    break;
                }
                let mentions_target = host
                    .split('.')
                    .filter(|s| s.len() > 2)
                    .any(|tok| body_low.contains(&tok.to_ascii_lowercase()));
                if mentions_target
                    || body_low.contains("job")
                        && (body_low.contains("engineer") || body_low.contains("security"))
                {
                    findings.push(finding(
                        "job_posting_osint",
                        "Public job listings mention target org or role",
                        "info",
                        "T1591.004",
                        &format!(
                            "Job board {} returned listings referencing '{}' — review stack/infra hints in postings.",
                            u, host
                        ),
                        target,
                    ));
                    break;
                }
            }
        }
    }
    if findings.is_empty() {
        empty_ok("job_posting_osint", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("job_posting_osint: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_job_posting_osint, run_job_posting_osint_result);

// ── github_secret_scan ────────────────────────────────────────────────────────
pub async fn run_github_secret_scan_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let token = std::env::var("WEISSMAN_GITHUB_TOKEN").unwrap_or_default();
    if token.is_empty() {
        let finding = finding(
            "github_secret_scan",
            "GitHub secret scan requires API token",
            "info",
            "T1552.001",
            &format!(
                "Set WEISSMAN_GITHUB_TOKEN (or tenant github_token in system_configs) to run live GitHub code search for leaked secrets referencing '{}'. Without a token, only public web UI search is available.",
                host
            ),
            target,
        );
        return EngineResult::ok(
            vec![finding],
            format!("github_secret_scan: token required for live search on {host}"),
        );
    }
    crate::leak_hunter_engine::github_leak_search(&host, Some(&token))
        .await
        .into_iter()
        .collect::<Vec<_>>()
        .into_iter()
        .fold(
            EngineResult::ok(vec![], format!("github_secret_scan: 0 hits for {}", host)),
            |mut acc, f| {
                acc.findings.push(f);
                acc
            },
        )
}
cli_wrapper!(run_github_secret_scan, run_github_secret_scan_result);

// ── threat_intel_fusion ───────────────────────────────────────────────────────
pub async fn run_threat_intel_fusion_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let url = format!(
        "https://urlhaus.abuse.ch/api/v1/hostinfo/{}/",
        urlencoding::encode(&host)
    );
    if let Some(p) = http_get(&client, &url).await {
        if p.status == 200 {
            if let Ok(v) = serde_json::from_str::<Value>(&p.body) {
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
                if listed && url_count > 0 {
                    findings.push(finding(
                        "threat_intel_fusion",
                        &format!("URLhaus lists {} malicious URL(s) for host", url_count),
                        "high",
                        "T1597",
                        &format!(
                            "Abuse.ch URLhaus hostinfo returned {} URL(s) for {} — cross-check for malware delivery or C2.",
                            url_count, host
                        ),
                        target,
                    ));
                }
            }
        }
    }
    if findings.is_empty() {
        empty_ok("threat_intel_fusion", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("threat_intel_fusion: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_threat_intel_fusion, run_threat_intel_fusion_result);

// ── attack_surface_quantify ───────────────────────────────────────────────────
pub async fn run_attack_surface_quantify_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let asm = crate::asm_engine::run_asm_result(target).await;
    let cnt = asm.findings.len();
    if cnt == 0 {
        return empty_ok("attack_surface_quantify", target);
    }
    let mut findings = asm.findings.clone();
    findings.push(finding(
        "attack_surface_quantify",
        &format!("Attack-surface quantification = {} indicators", cnt),
        "info",
        "T1595",
        &format!(
            "ASM engine reported {} discoverable assets/ports for {}.",
            cnt, target
        ),
        target,
    ));
    EngineResult::ok(
        findings,
        format!("attack_surface_quantify: {} indicators", cnt),
    )
}
cli_wrapper!(
    run_attack_surface_quantify,
    run_attack_surface_quantify_result
);

// ── adversarial_threat_emulation ─────────────────────────────────────────────
pub async fn run_adversarial_threat_emulation_result(target: &str) -> EngineResult {
    // Reuse the real threat emulation engine to drive an end-to-end live probe.
    crate::threat_emulation_engine::run_threat_emulation_result(target).await
}
cli_wrapper!(
    run_adversarial_threat_emulation,
    run_adversarial_threat_emulation_result
);

/// Legacy name — live threat emulation only.
pub async fn run_adversarial_simulation_result(target: &str) -> EngineResult {
    run_adversarial_threat_emulation_result(target).await
}
cli_wrapper!(
    run_adversarial_simulation,
    run_adversarial_simulation_result
);

// ── dark_web_monitor ──────────────────────────────────────────────────────────
pub async fn run_dark_web_monitor_result(target: &str) -> EngineResult {
    // Same surface as darkweb_intel but tagged for brand monitoring use-case.
    let mut r = run_darkweb_intel_result(target).await;
    for f in r.findings.iter_mut() {
        if let Some(obj) = f.as_object_mut() {
            obj.insert(
                "type".into(),
                serde_json::Value::String("dark_web_monitor".into()),
            );
        }
    }
    r
}
cli_wrapper!(run_dark_web_monitor, run_dark_web_monitor_result);

// ── passive_dns_forensics ─────────────────────────────────────────────────────
/// True when at least one DNS record set is non-empty.
#[must_use]
fn passive_dns_has_records(a: &[String], mx: &[String], txt: &[String]) -> bool {
    !a.is_empty() || !mx.is_empty() || !txt.is_empty()
}

pub async fn run_passive_dns_forensics_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    let a = dns_a(&host).await;
    let txt = dns_txt(&host).await;
    let mx = dns_mx(&host).await;
    if !passive_dns_has_records(&a, &mx, &txt) {
        return empty_ok("passive_dns_forensics", target);
    }
    findings.push(finding(
        "passive_dns_forensics",
        &format!("Passive DNS snapshot for {}", host),
        "info",
        "T1590.002",
        &format!(
            "A={} MX={} TXT={}",
            a.join(","),
            mx.join(","),
            txt.join(" | ")
        ),
        target,
    ));
    EngineResult::ok(
        findings.clone(),
        format!("passive_dns_forensics: {} record set(s)", findings.len()),
    )
}
cli_wrapper!(run_passive_dns_forensics, run_passive_dns_forensics_result);

// Suppress unused warnings.
#[inline]
fn _unused(h: &[(String, String)]) -> bool {
    header_value(h, "x").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_dns_requires_at_least_one_record_set() {
        assert!(!passive_dns_has_records(&[], &[], &[]));
        assert!(passive_dns_has_records(&["1.2.3.4".into()], &[], &[]));
        assert!(passive_dns_has_records(
            &[],
            &["mx.example.com".into()],
            &[]
        ));
    }
}

#[cfg(test)]
mod osint_extract_tests {
    use super::{
        is_sensitive_path, mail_provider_from_mx, robots_disallow_paths, security_txt_contacts,
    };

    #[test]
    fn robots_paths_extracted_and_root_skipped() {
        let body = "User-agent: *\nDisallow: /admin\nDisallow: /\nDisallow:   /internal/db\nAllow: /public\n";
        let paths = robots_disallow_paths(body);
        assert_eq!(
            paths,
            vec!["/admin".to_string(), "/internal/db".to_string()]
        );
        assert!(is_sensitive_path("/admin"));
        assert!(is_sensitive_path("/internal/db"));
        assert!(!is_sensitive_path("/public/images"));
    }

    #[test]
    fn security_txt_contacts_extracted() {
        let body = "Contact: mailto:security@example.com\nExpires: 2030-01-01\ncontact: https://example.com/report\n";
        let c = security_txt_contacts(body);
        assert_eq!(c.len(), 2);
        assert!(c[0].contains("security@example.com"));
    }

    #[test]
    fn mail_provider_identified() {
        assert_eq!(
            mail_provider_from_mx(&["aspmx.l.google.com".to_string()]),
            Some("Google Workspace")
        );
        assert_eq!(
            mail_provider_from_mx(&["example-com.mail.protection.outlook.com".to_string()]),
            Some("Microsoft 365")
        );
        assert_eq!(
            mail_provider_from_mx(&["mx1.pphosted.com".to_string()]),
            Some("Proofpoint")
        );
        assert_eq!(
            mail_provider_from_mx(&["mail.self-hosted.example".to_string()]),
            None
        );
    }
}

#[cfg(test)]
mod osint_deep_tests {
    use super::{etherscan_balance_wei, extract_edgar_cik, extract_tech_stack, wei_to_eth_string};

    #[test]
    fn etherscan_balance_parsed_and_converted() {
        let ok = r#"{"status":"1","message":"OK","result":"1500000000000000000"}"#;
        assert_eq!(
            etherscan_balance_wei(ok).as_deref(),
            Some("1500000000000000000")
        );
        assert_eq!(
            wei_to_eth_string("1500000000000000000").as_deref(),
            Some("1.500000")
        );
        assert_eq!(wei_to_eth_string("0").as_deref(), Some("0.000000"));
        // Large balance > u64 range.
        assert_eq!(
            wei_to_eth_string("100000000000000000000").as_deref(),
            Some("100.000000")
        );
        // NOTOK responses yield nothing.
        let err = r#"{"status":"0","message":"NOTOK","result":"rate limit"}"#;
        assert_eq!(etherscan_balance_wei(err), None);
    }

    #[test]
    fn edgar_cik_extracted() {
        assert_eq!(
            extract_edgar_cik("...&CIK=0001318605&type=10-K...").as_deref(),
            Some("0001318605")
        );
        assert_eq!(extract_edgar_cik("no cik here at all"), None);
    }

    #[test]
    fn tech_stack_extracted() {
        let body =
            "we run kubernetes on aws with terraform, python microservices and crowdstrike edr";
        let stack = extract_tech_stack(body);
        assert!(stack.contains(&"kubernetes") && stack.contains(&"aws"));
        assert!(stack.contains(&"crowdstrike") && stack.contains(&"terraform"));
        assert!(extract_tech_stack("nothing technical here").is_empty());
    }
}
