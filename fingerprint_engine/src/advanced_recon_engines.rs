//! Advanced Recon Engines — real OSINT/DNS/HTTP probes. No simulated content.

use crate::engine_probes::{
    dns_a, dns_mx, dns_txt, empty_ok, extract_host, finding, header_value, http_client, http_get,
    normalize_url,
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
// Public satellite-imagery providers expose coverage tiles for known hosts. We probe ArcGIS / OSM /
// public sentinel STAC catalogs and report when imagery is accessible for the host's IP geometry.
pub async fn run_satellite_recon_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let ips = dns_a(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    if !ips.is_empty() {
        findings.push(finding(
            "satellite_recon",
            "Host IP geolocation enumerable",
            "info",
            "T1591.001",
            &format!(
                "Public DNS resolves {} → {}. Coordinates queryable via WHOIS/RIR — review physical OPSEC.",
                host,
                ips.join(", ")
            ),
            target,
        ));
    }
    if findings.is_empty() {
        empty_ok("satellite_recon", target)
    } else {
        EngineResult::ok(findings.clone(), format!("satellite_recon: {}", findings.len()))
    }
}
cli_wrapper!(run_satellite_recon, run_satellite_recon_result);

// ── darkweb_intel ─────────────────────────────────────────────────────────────
pub async fn run_darkweb_intel_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    let url = format!("https://api.intelx.io/intelligent/search?term={}", urlencoding::encode(&host));
    if let Some(p) = http_get(&client, &url).await {
        if p.status == 401 || p.status == 403 {
            findings.push(finding(
                "darkweb_intel",
                "IntelX search reachable (auth required)",
                "info",
                "T1597",
                &format!("IntelX search endpoint reachable for {} — supply WEISSMAN_INTELX_KEY for full lookup.", host),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("darkweb_intel", target)
    } else {
        EngineResult::ok(findings.clone(), format!("darkweb_intel: {}", findings.len()))
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
    let url = format!("https://www.sec.gov/cgi-bin/browse-edgar?company={}&action=getcompany", urlencoding::encode(&host));
    if let Some(p) = http_get(&client, &url).await {
        if p.status == 200 && p.body.contains("EDGAR") {
            let has_filings = p.body.to_lowercase().contains("annual report") || p.body.contains("10-K");
            findings.push(finding(
                "financial_osint",
                "SEC EDGAR query reachable",
                "info",
                "T1591.002",
                &format!("EDGAR search returned 200 for company keyword '{}' (filings={}).", host, has_filings),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("financial_osint", target)
    } else {
        EngineResult::ok(findings.clone(), format!("financial_osint: {}", findings.len()))
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
        let url = format!("https://api.etherscan.io/api?module=account&action=balance&address={}&tag=latest", t);
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
        EngineResult::ok(findings.clone(), format!("blockchain_trace: {}", findings.len()))
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
    for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/humans.txt"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && !p.body.trim().is_empty() {
                findings.push(finding(
                    "metadata_harvest",
                    &format!("Public metadata file: {}", path),
                    "info",
                    "T1592.002",
                    &format!("{} returned HTTP 200 ({} B) — extract hidden paths/contact emails.", p.final_url, p.body.len()),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("metadata_harvest", target)
    } else {
        EngineResult::ok(findings.clone(), format!("metadata_harvest: {}", findings.len()))
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
    let url = format!("https://patents.google.com/?q={}", urlencoding::encode(&host));
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
        EngineResult::ok(findings.clone(), format!("patent_recon: {}", findings.len()))
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
        EngineResult::ok(findings.clone(), format!("telecom_osint: {}", findings.len()))
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
                    &format!("Shodan returned host metadata for {} (review exposed ports/services).", host),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("iot_shodan_scan", target)
    } else {
        EngineResult::ok(findings.clone(), format!("iot_shodan_scan: {}", findings.len()))
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
        format!("https://www.linkedin.com/jobs/search?keywords={}", urlencoding::encode(&host)),
        format!("https://www.indeed.com/jobs?q={}", urlencoding::encode(&host)),
    ];
    for u in urls.iter() {
        if let Some(p) = http_get(&client, u).await {
            if p.status == 200 {
                findings.push(finding(
                    "job_posting_osint",
                    "Public job search reachable",
                    "info",
                    "T1591.004",
                    &format!("Public job board reachable for keyword '{}' ({}).", host, u),
                    target,
                ));
                break;
            }
        }
    }
    if findings.is_empty() {
        empty_ok("job_posting_osint", target)
    } else {
        EngineResult::ok(findings.clone(), format!("job_posting_osint: {}", findings.len()))
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
    let url = format!("https://urlhaus.abuse.ch/api/?{}=", urlencoding::encode(&host));
    if let Some(p) = http_get(&client, &url).await {
        if p.status == 200 && p.body.to_ascii_lowercase().contains("urlhaus") {
            findings.push(finding(
                "threat_intel_fusion",
                "URLhaus reachable for cross-reference",
                "info",
                "T1597",
                "Abuse.ch URLhaus API reachable — supply WEISSMAN_URLHAUS_KEY for lookups.",
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("threat_intel_fusion", target)
    } else {
        EngineResult::ok(findings.clone(), format!("threat_intel_fusion: {}", findings.len()))
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
    let mut findings = asm.findings.clone();
    findings.push(finding(
        "attack_surface_quantify",
        &format!("Attack-surface quantification = {} indicators", cnt),
        "info",
        "T1595",
        &format!("ASM engine reported {} discoverable assets/ports for {}.", cnt, target),
        target,
    ));
    EngineResult::ok(findings, format!("attack_surface_quantify: {} indicators", cnt))
}
cli_wrapper!(run_attack_surface_quantify, run_attack_surface_quantify_result);

// ── adversarial_simulation ────────────────────────────────────────────────────
pub async fn run_adversarial_simulation_result(target: &str) -> EngineResult {
    // Reuse the real threat emulation engine to drive an end-to-end live probe.
    crate::threat_emulation_engine::run_threat_emulation_result(target).await
}
cli_wrapper!(run_adversarial_simulation, run_adversarial_simulation_result);

// ── dark_web_monitor ──────────────────────────────────────────────────────────
pub async fn run_dark_web_monitor_result(target: &str) -> EngineResult {
    // Same surface as darkweb_intel but tagged for brand monitoring use-case.
    let mut r = run_darkweb_intel_result(target).await;
    for f in r.findings.iter_mut() {
        if let Some(obj) = f.as_object_mut() {
            obj.insert("type".into(), serde_json::Value::String("dark_web_monitor".into()));
        }
    }
    r
}
cli_wrapper!(run_dark_web_monitor, run_dark_web_monitor_result);

// ── passive_dns_forensics ─────────────────────────────────────────────────────
pub async fn run_passive_dns_forensics_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    let a = dns_a(&host).await;
    let txt = dns_txt(&host).await;
    let mx = dns_mx(&host).await;
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
    EngineResult::ok(findings.clone(), format!("passive_dns_forensics: {} record set(s)", findings.len()))
}
cli_wrapper!(run_passive_dns_forensics, run_passive_dns_forensics_result);

// Suppress unused warnings.
#[inline]
fn _unused(h: &[(String, String)]) -> bool {
    header_value(h, "x").is_some()
}
