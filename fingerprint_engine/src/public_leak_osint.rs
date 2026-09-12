//! Legal public leak / malware-URL / CT OSINT. No Tor, no marketplace scraping.
//!
//! Live sources (fail visible, never fake hits):
//! - crt.sh certificate transparency (no key)
//! - urlscan.io search (no key)
//! - URLhaus host lookup when `WEISSMAN_ABUSECH_AUTH_KEY` / `ABUSECH_AUTH_KEY` is set
//! - ThreatFox IOC search when the same abuse.ch auth key is set
//! - IntelX intelligent search when `INTELX_API_KEY` / `WEISSMAN_INTELX_KEY` is set
//! - AlienVault OTX domain pulse when `OTX_API_KEY` is set

use crate::engine_probes::{
    extract_host, finding, http_client, http_get, http_get_with_headers, http_post_bytes_with_headers,
    http_post_json_with_headers,
};
use crate::engine_result::EngineResult;
use serde_json::{json, Value};

#[derive(Debug, Clone, Default)]
pub struct LeakOsintReport {
    pub findings: Vec<Value>,
    pub sources_attempted: Vec<&'static str>,
    pub sources_live: Vec<String>,
}

fn abusech_auth_key() -> String {
    std::env::var("WEISSMAN_ABUSECH_AUTH_KEY")
        .or_else(|_| std::env::var("ABUSECH_AUTH_KEY"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn intelx_api_key() -> String {
    std::env::var("INTELX_API_KEY")
        .or_else(|_| std::env::var("WEISSMAN_INTELX_KEY"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn intelx_api_base() -> String {
    std::env::var("INTELX_API_URL")
        .unwrap_or_else(|_| "https://2.intelx.io".into())
        .trim()
        .trim_end_matches('/')
        .to_string()
}

fn otx_api_key() -> String {
    std::env::var("OTX_API_KEY").unwrap_or_default().trim().to_string()
}

pub async fn collect_public_leak_osint(target: &str) -> LeakOsintReport {
    let mut report = LeakOsintReport::default();
    if target.trim().is_empty() {
        return report;
    }
    let host = extract_host(target);
    if host.is_empty() {
        return report;
    }
    let client = http_client().await;

    report.sources_attempted.push("crt.sh");
    if let Some(p) = http_get(
        &client,
        &format!("https://crt.sh/?q={}&output=json", urlencoding::encode(&host)),
    )
    .await
    {
        if p.status == 200 {
            if let Some((count, sample)) = parse_crtsh(&p.body) {
                report.sources_live.push(format!("crt.sh:{count}"));
                report.findings.push(finding(
                    "darkweb_intel",
                    &format!("Certificate Transparency: {count} issued cert(s) for {host}"),
                    if count > 20 { "medium" } else { "info" },
                    "T1596.003",
                    &format!(
                        "crt.sh returned {count} certificate record(s) for '{host}'. Sample names: {sample}. Review for forgotten hosts, staging names, and typosquat lookalikes in SANs."
                    ),
                    target,
                ));
            } else {
                report.sources_live.push("crt.sh:0".into());
            }
        }
    }

    report.sources_attempted.push("urlscan.io");
    if let Some(p) = http_get(
        &client,
        &format!(
            "https://urlscan.io/api/v1/search/?q=domain:{}&size=8",
            urlencoding::encode(&host)
        ),
    )
    .await
    {
        if p.status == 200 {
            if let Some((total, sample)) = parse_urlscan(&p.body) {
                report.sources_live.push(format!("urlscan.io:{total}"));
                if total > 0 {
                    report.findings.push(finding(
                        "darkweb_intel",
                        &format!("urlscan.io indexed {total} public scan(s) of {host}"),
                        "info",
                        "T1595.002",
                        &format!(
                            "urlscan.io search for domain:{host} returned {total} result(s). Sample URLs: {sample}. These are public scanner observations, not simulated hits."
                        ),
                        target,
                    ));
                }
            } else {
                report.sources_live.push("urlscan.io:parse_empty".into());
            }
        }
    }

    let abuse_key = abusech_auth_key();
    if abuse_key.is_empty() {
        report.findings.push(finding(
            "darkweb_intel",
            "abuse.ch URLHaus/ThreatFox require Auth-Key",
            "info",
            "T1597",
            "Set WEISSMAN_ABUSECH_AUTH_KEY (from https://auth.abuse.ch/) to query URLHaus malware-URL host intel and ThreatFox IOCs. Without a key those sources are skipped — crt.sh/urlscan still ran.",
            target,
        ));
    } else {
        report.sources_attempted.push("urlhaus");
        let body = format!("host={}", urlencoding::encode(&host));
        if let Some(p) = http_post_bytes_with_headers(
            &client,
            "https://urlhaus-api.abuse.ch/v1/host/",
            body.as_bytes(),
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("Auth-Key", abuse_key.as_str()),
            ],
        )
        .await
        {
            if p.status == 200 {
                match parse_urlhaus(&p.body) {
                    Some((n, sample, status)) if n > 0 => {
                        report.sources_live.push(format!("urlhaus:{n}"));
                        report.findings.push(finding(
                            "darkweb_intel",
                            &format!("URLHaus lists {n} malware URL(s) on {host}"),
                            "high",
                            "T1583.006",
                            &format!(
                                "URLHaus query_status={status} url_count={n} for '{host}'. Sample: {sample}. Treat as confirmed public malware-distribution intel, not a simulated listing."
                            ),
                            target,
                        ));
                    }
                    Some((_, _, status)) => {
                        report.sources_live.push(format!("urlhaus:{status}"));
                    }
                    None => {
                        report.sources_live.push("urlhaus:unparsed".into());
                    }
                }
            }
        }

        report.sources_attempted.push("threatfox");
        let tf = json!({"query": "search_ioc", "search_term": host, "exact_match": true});
        if let Some(p) = http_post_json_with_headers(
            &client,
            "https://threatfox-api.abuse.ch/api/v1/",
            &tf,
            &[("Auth-Key", abuse_key.as_str())],
        )
        .await
        {
            if p.status == 200 {
                match parse_threatfox(&p.body) {
                    Some((n, sample)) if n > 0 => {
                        report.sources_live.push(format!("threatfox:{n}"));
                        report.findings.push(finding(
                            "darkweb_intel",
                            &format!("ThreatFox has {n} IOC(s) matching {host}"),
                            "high",
                            "T1583.001",
                            &format!(
                                "ThreatFox search_ioc for '{host}' returned {n} indicator(s). Sample: {sample}."
                            ),
                            target,
                        ));
                    }
                    Some(_) => {
                        report.sources_live.push("threatfox:0".into());
                    }
                    None => {
                        report.sources_live.push("threatfox:unparsed".into());
                    }
                }
            }
        }
    }

    let otx = otx_api_key();
    if !otx.is_empty() {
        report.sources_attempted.push("otx");
        if let Some(p) = http_get_with_headers(
            &client,
            &format!("https://otx.alienvault.com/api/v1/indicators/domain/{host}/general"),
            &[("X-OTX-API-KEY", otx.as_str())],
        )
        .await
        {
            if p.status == 200 {
                if let Some((pulses, tags)) = parse_otx(&p.body) {
                    report.sources_live.push(format!("otx:{pulses}"));
                    if pulses > 0 {
                        report.findings.push(finding(
                            "darkweb_intel",
                            &format!("OTX pulses mention {host} ({pulses})"),
                            if pulses > 3 { "medium" } else { "info" },
                            "T1597",
                            &format!(
                                "AlienVault OTX domain general for '{host}' pulse_count={pulses}. Tags: {tags}."
                            ),
                            target,
                        ));
                    }
                }
            }
        }
    }

    let ix = intelx_api_key();
    if ix.is_empty() {
        report.findings.push(finding(
            "darkweb_intel",
            "IntelX leak index requires API key",
            "info",
            "T1597",
            &format!(
                "Intelligence X indexes leaks, paste sites, and dark-web mentions. Set INTELX_API_KEY (or WEISSMAN_INTELX_KEY) to query records for '{host}'. Public CT/urlscan/abuse.ch probes still ran independently."
            ),
            target,
        ));
    } else {
        report.sources_attempted.push("intelx");
        let base = intelx_api_base();
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
        if let Some(p) = http_post_json_with_headers(
            &client,
            &format!("{base}/intelligent/search"),
            &payload,
            &[("x-key", ix.as_str())],
        )
        .await
        {
            if p.status == 401 || p.status == 403 {
                report.sources_live.push(format!("intelx:http{}", p.status));
                report.findings.push(finding(
                    "darkweb_intel",
                    "IntelX API rejected credentials",
                    "info",
                    "T1597",
                    &format!(
                        "IntelX returned HTTP {} — verify INTELX_API_KEY and INTELX_API_URL.",
                        p.status
                    ),
                    target,
                ));
            } else if p.status == 200 {
                if let Some(search_id) = serde_json::from_str::<Value>(&p.body)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(|s| s.to_string()))
                {
                    if let Some(rp) = http_get_with_headers(
                        &client,
                        &format!("{base}/intelligent/search/result?id={search_id}"),
                        &[("x-key", ix.as_str())],
                    )
                    .await
                    {
                        let record_count = rp.body.matches("\"record\"").count().max(rp.body.matches("\"name\"").count());
                        report.sources_live.push(format!("intelx:{record_count}"));
                        if record_count > 0 {
                            report.findings.push(finding(
                                "darkweb_intel",
                                &format!("IntelX returned {record_count} candidate record(s) for {host}"),
                                "medium",
                                "T1597",
                                &format!(
                                    "Intelligence X search id {search_id} returned {record_count} hits referencing '{host}'. Review for leaked credentials and breach exposure."
                                ),
                                target,
                            ));
                        }
                    }
                }
            }
        }
    }

    report
}

pub async fn run_public_leak_osint_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let report = collect_public_leak_osint(target).await;
    if report.findings.is_empty() {
        EngineResult::ok(
            vec![],
            format!(
                "public_leak_osint: no indexed hits (attempted {})",
                report.sources_attempted.join(",")
            ),
        )
    } else {
        EngineResult::ok(
            report.findings.clone(),
            format!(
                "public_leak_osint: {} finding(s); live={}",
                report.findings.len(),
                report.sources_live.join(",")
            ),
        )
    }
}

/// Parse crt.sh JSON array. Returns (record_count, sample SAN/name list).
pub fn parse_crtsh(body: &str) -> Option<(usize, String)> {
    let v: Value = serde_json::from_str(body).ok()?;
    let arr = v.as_array()?;
    if arr.is_empty() {
        return Some((0, String::new()));
    }
    let mut names: Vec<String> = Vec::new();
    for row in arr.iter().take(40) {
        if let Some(nv) = row.get("name_value").and_then(|x| x.as_str()) {
            for part in nv.split(['\n', ' ']) {
                let p = part.trim();
                if !p.is_empty() && !names.iter().any(|x| x == p) {
                    names.push(p.to_string());
                }
                if names.len() >= 8 {
                    break;
                }
            }
        }
    }
    Some((arr.len(), names.join(", ")))
}

pub fn parse_urlscan(body: &str) -> Option<(u64, String)> {
    let v: Value = serde_json::from_str(body).ok()?;
    let total = v
        .get("total")
        .and_then(|x| x.as_u64())
        .or_else(|| v.get("results").and_then(|r| r.as_array()).map(|a| a.len() as u64))?;
    let mut urls = Vec::new();
    if let Some(results) = v.get("results").and_then(|x| x.as_array()) {
        for r in results.iter().take(5) {
            if let Some(u) = r
                .get("task")
                .and_then(|t| t.get("url"))
                .and_then(|x| x.as_str())
            {
                urls.push(u.to_string());
            }
        }
    }
    Some((total, urls.join(" | ")))
}

/// Returns (url_count, sample, query_status).
pub fn parse_urlhaus(body: &str) -> Option<(u64, String, String)> {
    let v: Value = serde_json::from_str(body).ok()?;
    let status = v
        .get("query_status")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if status == "no_results" {
        return Some((0, String::new(), status));
    }
    if status != "ok" && status != "ok_warning" {
        return Some((0, String::new(), status));
    }
    let count = v
        .get("url_count")
        .and_then(|x| {
            x.as_u64()
                .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
        })
        .or_else(|| v.get("urls").and_then(|u| u.as_array()).map(|a| a.len() as u64))
        .unwrap_or(0);
    let mut sample = Vec::new();
    if let Some(urls) = v.get("urls").and_then(|x| x.as_array()) {
        for u in urls.iter().take(3) {
            if let Some(s) = u.get("url").and_then(|x| x.as_str()) {
                sample.push(s.to_string());
            }
        }
    }
    Some((count, sample.join(" | "), status))
}

pub fn parse_threatfox(body: &str) -> Option<(usize, String)> {
    let v: Value = serde_json::from_str(body).ok()?;
    let status = v.get("query_status").and_then(|x| x.as_str()).unwrap_or("");
    if status == "no_result" || status == "no_results" {
        return Some((0, String::new()));
    }
    let data = v.get("data")?.as_array()?;
    let mut sample = Vec::new();
    for row in data.iter().take(4) {
        let ioc = row.get("ioc").and_then(|x| x.as_str()).unwrap_or("");
        let mal = row
            .get("malware_printable")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if !ioc.is_empty() {
            sample.push(format!("{ioc} ({mal})"));
        }
    }
    Some((data.len(), sample.join(" | ")))
}

pub fn parse_otx(body: &str) -> Option<(u64, String)> {
    let v: Value = serde_json::from_str(body).ok()?;
    let pulses = v
        .get("pulse_info")
        .and_then(|p| p.get("count"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let mut tags = Vec::new();
    if let Some(arr) = v
        .get("pulse_info")
        .and_then(|p| p.get("pulses"))
        .and_then(|x| x.as_array())
    {
        for p in arr.iter().take(4) {
            if let Some(n) = p.get("name").and_then(|x| x.as_str()) {
                tags.push(n.to_string());
            }
        }
    }
    Some((pulses, tags.join(" | ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crtsh_counts_unique_names() {
        let body = r#"[{"id":1,"name_value":"example.com\nwww.example.com"},{"id":2,"name_value":"api.example.com"}]"#;
        let (n, sample) = parse_crtsh(body).unwrap();
        assert_eq!(n, 2);
        assert!(sample.contains("example.com"));
        assert!(sample.contains("api.example.com"));
    }

    #[test]
    fn urlhaus_ok_and_no_results() {
        let ok = r#"{"query_status":"ok","url_count":"2","urls":[{"url":"http://example.com/a"},{"url":"http://example.com/b"}]}"#;
        let (n, sample, st) = parse_urlhaus(ok).unwrap();
        assert_eq!(n, 2);
        assert_eq!(st, "ok");
        assert!(sample.contains("example.com/a"));
        let none = r#"{"query_status":"no_results"}"#;
        let (n, _, st) = parse_urlhaus(none).unwrap();
        assert_eq!(n, 0);
        assert_eq!(st, "no_results");
    }

    #[test]
    fn threatfox_and_urlscan_parse() {
        let tf = r#"{"query_status":"ok","data":[{"ioc":"example.com","malware_printable":"Demo"}]}"#;
        let (n, s) = parse_threatfox(tf).unwrap();
        assert_eq!(n, 1);
        assert!(s.contains("example.com"));
        let us = r#"{"total":3,"results":[{"task":{"url":"https://example.com/"}}]}"#;
        let (t, sample) = parse_urlscan(us).unwrap();
        assert_eq!(t, 3);
        assert!(sample.contains("https://example.com/"));
    }

    #[test]
    fn otx_pulse_count() {
        let body = r#"{"pulse_info":{"count":2,"pulses":[{"name":"campaign-a"}]}}"#;
        let (n, tags) = parse_otx(body).unwrap();
        assert_eq!(n, 2);
        assert!(tags.contains("campaign-a"));
    }
}
