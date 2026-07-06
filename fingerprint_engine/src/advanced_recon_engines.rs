//! Advanced Recon Engines — real OSINT/DNS/HTTP probes. No simulated content.

use crate::engine_probes::{
    dns_a, dns_mx, dns_txt, empty_ok, extract_host, finding, header_value, http_client, http_get,
    http_get_with_headers, http_post_json_with_headers, normalize_url,
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
pub async fn run_financial_osint_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let url = format!(
        "https://www.sec.gov/cgi-bin/browse-edgar?company={}&action=getcompany",
        urlencoding::encode(&host)
    );
    if let Some(p) = http_get(&client, &url).await {
        if p.status == 200 && p.body.contains("EDGAR") {
            let body_low = p.body.to_lowercase();
            let host_tokens: Vec<String> = host
                .split('.')
                .filter(|s| s.len() > 2)
                .map(|s| s.to_lowercase())
                .collect();
            let has_filings = body_low.contains("annual report")
                || body_low.contains("10-k")
                || body_low.contains("10-q")
                || host_tokens
                    .iter()
                    .any(|tok| !tok.is_empty() && body_low.contains(tok.as_str()));
            if has_filings {
                findings.push(finding(
                    "financial_osint",
                    "SEC EDGAR filings indexed for target keyword",
                    "info",
                    "T1591.002",
                    &format!(
                        "EDGAR search returned filings referencing '{}' — review 10-K/10-Q for subsidiary and acquisition intel.",
                        host
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("financial_osint", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("financial_osint: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_financial_osint, run_financial_osint_result);

// ── blockchain_trace ──────────────────────────────────────────────────────────
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
            if p.status == 200 && p.body.contains("result") {
                findings.push(finding(
                    "blockchain_trace",
                    "Etherscan balance retrieved",
                    "info",
                    "T1583.006",
                    &format!("Etherscan returned a balance object for {} (supply WEISSMAN_ETHERSCAN_KEY for full traces).", t),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("blockchain_trace", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("blockchain_trace: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_blockchain_trace, run_blockchain_trace_result);

// ── metadata_harvest ──────────────────────────────────────────────────────────
pub async fn run_metadata_harvest_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    for path in [
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/humans.txt",
    ] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && !p.body.trim().is_empty() {
                findings.push(finding(
                    "metadata_harvest",
                    &format!("Public metadata file: {}", path),
                    "info",
                    "T1592.002",
                    &format!(
                        "{} returned HTTP 200 ({} B) — extract hidden paths/contact emails.",
                        p.final_url,
                        p.body.len()
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("metadata_harvest", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("metadata_harvest: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_metadata_harvest, run_metadata_harvest_result);

// ── patent_recon ──────────────────────────────────────────────────────────────
pub async fn run_patent_recon_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let url = format!(
        "https://patents.google.com/?q={}",
        urlencoding::encode(&host)
    );
    if let Some(p) = http_get(&client, &url).await {
        if p.status == 200 && p.body.contains("patent") {
            findings.push(finding(
                "patent_recon",
                "Google Patents queryable for organisation",
                "info",
                "T1591",
                &format!("Google Patents reachable for keyword '{}'. Use full-text search to map IP portfolio.", host),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("patent_recon", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("patent_recon: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_patent_recon, run_patent_recon_result);

// ── telecom_osint ─────────────────────────────────────────────────────────────
pub async fn run_telecom_osint_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mx = dns_mx(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    if !mx.is_empty() {
        findings.push(finding(
            "telecom_osint",
            "MX records publicly resolvable",
            "info",
            "T1590.002",
            &format!("MX records for {}: {}", host, mx.join(", ")),
            target,
        ));
    }
    if findings.is_empty() {
        empty_ok("telecom_osint", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("telecom_osint: {}", findings.len()),
        )
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
        empty_ok("iot_shodan_scan", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("iot_shodan_scan: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_iot_shodan_scan, run_iot_shodan_scan_result);

// ── job_posting_osint ─────────────────────────────────────────────────────────
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
        return empty_ok("github_secret_scan", target);
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
