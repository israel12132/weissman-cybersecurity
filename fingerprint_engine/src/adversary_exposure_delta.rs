//! Adversary Exposure Delta — legal clearnet OSINT fusion.
//!
//! Queries public defender indexes that attackers also use to find victims:
//! urlscan.io (unauthenticated search), abuse.ch URLhaus/ThreatFox (Auth-Key),
//! IntelX (optional), HIBP published-breach catalog, AlienVault OTX.
//!
//! Does **not** crawl Tor hidden services or criminal marketplaces.

use crate::engine_probes::{
    extract_host, finding, http_client, http_get, http_get_with_headers,
    http_post_bytes_with_headers, http_post_json_with_headers,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

fn abusech_auth_key() -> String {
    std::env::var("ABUSECH_AUTH_KEY")
        .or_else(|_| std::env::var("WEISSMAN_ABUSECH_KEY"))
        .or_else(|_| std::env::var("URLHAUS_AUTH_KEY"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn urlscan_api_key() -> String {
    std::env::var("URLSCAN_API_KEY")
        .or_else(|_| std::env::var("WEISSMAN_URLSCAN_KEY"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn otx_api_key() -> String {
    std::env::var("OTX_API_KEY")
        .or_else(|_| std::env::var("WEISSMAN_OTX_KEY"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Parse URLhaus host lookup JSON. Empty / no_results is not a finding.
pub fn findings_from_urlhaus(engine_id: &str, host: &str, target: &str, body: &str) -> Vec<Value> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let qs = v
        .get("query_status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if qs != "ok" {
        return Vec::new();
    }
    let urls = v.get("urls").and_then(Value::as_array);
    let url_count = urls.map(|a| a.len()).unwrap_or(0);
    if url_count == 0 {
        return Vec::new();
    }
    let sample: Vec<&str> = urls
        .unwrap()
        .iter()
        .filter_map(|u| u.get("url").and_then(Value::as_str))
        .take(5)
        .collect();
    let reference = v
        .get("urlhaus_reference")
        .and_then(Value::as_str)
        .unwrap_or("");
    vec![finding(
        engine_id,
        &format!("URLhaus indexes {url_count} malicious URL(s) for {host}"),
        "high",
        "T1597",
        &format!(
            "abuse.ch URLhaus live host lookup for '{}' returned {} URL(s). Reference: {}. Samples: {}. This is a public malware-infra index, not a Tor crawl.",
            host,
            url_count,
            reference,
            sample.join(" | ")
        ),
        target,
    )]
}

/// Parse ThreatFox search_ioc JSON. `no_result` (singular) is empty.
pub fn findings_from_threatfox(
    engine_id: &str,
    host: &str,
    target: &str,
    body: &str,
) -> Vec<Value> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let qs = v
        .get("query_status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if qs == "no_result" {
        return Vec::new();
    }
    let data = v.get("data").and_then(Value::as_array);
    if qs != "ok" || data.map(|a| a.is_empty()).unwrap_or(true) {
        return Vec::new();
    }
    let data = data.unwrap();
    let sample: Vec<String> = data
        .iter()
        .take(5)
        .filter_map(|row| {
            let ioc = row.get("ioc").and_then(Value::as_str)?;
            let malware = row
                .get("malware_printable")
                .or_else(|| row.get("malware"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            Some(format!("{ioc} ({malware})"))
        })
        .collect();
    vec![finding(
        engine_id,
        &format!("ThreatFox lists {} IOC(s) matching {host}", data.len()),
        "high",
        "T1597",
        &format!(
            "abuse.ch ThreatFox search_ioc for '{}' returned {} live IOC(s) (API retains ~6 months). Samples: {}.",
            host,
            data.len(),
            sample.join(" | ")
        ),
        target,
    )]
}

/// Parse urlscan.io search JSON. `total==0` is empty (not malice by itself).
pub fn findings_from_urlscan(engine_id: &str, host: &str, target: &str, body: &str) -> Vec<Value> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let total = v.get("total").and_then(Value::as_u64).unwrap_or(0);
    let results = v.get("results").and_then(Value::as_array);
    if total == 0 || results.map(|a| a.is_empty()).unwrap_or(true) {
        return Vec::new();
    }
    let results = results.unwrap();
    let sample: Vec<&str> = results
        .iter()
        .filter_map(|r| {
            r.get("page")
                .and_then(|p| p.get("url"))
                .and_then(Value::as_str)
        })
        .take(5)
        .collect();
    let sev = if total >= 20 { "medium" } else { "info" };
    vec![finding(
        engine_id,
        &format!("urlscan.io has {total} public scan(s) for {host}"),
        sev,
        "T1597.001",
        &format!(
            "urlscan.io search for page.domain='{}' returned total={}. Public scan existence is not malware by itself — operators still review verdicts. Samples: {}.",
            host,
            total,
            sample.join(" | ")
        ),
        target,
    )]
}

/// HIBP public breach-source catalog (`/breaches?domain=`). Not employee mailbox proof.
pub fn findings_from_hibp_breach_source(
    engine_id: &str,
    host: &str,
    target: &str,
    status: u16,
    body: &str,
) -> Vec<Value> {
    if status != 200 {
        return Vec::new();
    }
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    if arr.is_empty() {
        return Vec::new();
    }
    let names: Vec<&str> = arr
        .iter()
        .filter_map(|b| b.get("Name").and_then(Value::as_str))
        .take(8)
        .collect();
    vec![finding(
        engine_id,
        &format!("{host} appears as a published HIBP breach source"),
        "medium",
        "T1530",
        &format!(
            "Have I Been Pwned public /breaches?domain={} returned {} catalog entries (e.g. {}). This means the domain was a *breach publisher*, not that employee mailboxes leaked. Employee-domain search requires a verified HIBP_API_KEY.",
            host,
            arr.len(),
            names.join(", ")
        ),
        target,
    )]
}

/// OTX indicator/general — skip whitelisted pulses.
pub fn findings_from_otx(engine_id: &str, host: &str, target: &str, body: &str) -> Vec<Value> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let validation = v.get("validation").and_then(Value::as_array);
    if validation.map(|a| !a.is_empty()).unwrap_or(false) {
        return Vec::new();
    }
    let count = v
        .get("pulse_info")
        .and_then(|p| p.get("count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let pulses = v
        .get("pulse_info")
        .and_then(|p| p.get("pulses"))
        .and_then(Value::as_array);
    if count == 0 || pulses.map(|a| a.is_empty()).unwrap_or(true) {
        return Vec::new();
    }
    let pulses = pulses.unwrap();
    let names: Vec<&str> = pulses
        .iter()
        .filter_map(|p| p.get("name").and_then(Value::as_str))
        .take(5)
        .collect();
    vec![finding(
        engine_id,
        &format!("OTX pulses reference {host} ({count})"),
        "medium",
        "T1597",
        &format!(
            "AlienVault/LevelBlue OTX indicator/general for '{}' has pulse_info.count={} and is not marked validation-whitelisted. Pulses: {}.",
            host,
            count,
            names.join(" | ")
        ),
        target,
    )]
}

async fn query_urlhaus(engine_id: &str, host: &str, target: &str) -> Vec<Value> {
    let key = abusech_auth_key();
    if key.is_empty() {
        return Vec::new();
    }
    let client = http_client().await;
    let body = format!("host={}", urlencoding::encode(host));
    let Some(p) = http_post_bytes_with_headers(
        &client,
        "https://urlhaus-api.abuse.ch/v1/host/",
        body.as_bytes(),
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Auth-Key", key.as_str()),
        ],
    )
    .await
    else {
        return Vec::new();
    };
    if p.status == 401 || p.status == 403 {
        return Vec::new();
    }
    findings_from_urlhaus(engine_id, host, target, &p.body)
}

async fn query_threatfox(engine_id: &str, host: &str, target: &str) -> Vec<Value> {
    let key = abusech_auth_key();
    if key.is_empty() {
        return Vec::new();
    }
    let client = http_client().await;
    let payload = json!({
        "query": "search_ioc",
        "search_term": host,
        "exact_match": true
    });
    let Some(p) = http_post_json_with_headers(
        &client,
        "https://threatfox-api.abuse.ch/api/v1/",
        &payload,
        &[("Auth-Key", key.as_str())],
    )
    .await
    else {
        return Vec::new();
    };
    if p.status == 401 || p.status == 403 {
        return Vec::new();
    }
    findings_from_threatfox(engine_id, host, target, &p.body)
}

async fn query_urlscan(engine_id: &str, host: &str, target: &str) -> Vec<Value> {
    let client = http_client().await;
    let q = format!("page.domain:\"{host}\"");
    let url = format!(
        "https://urlscan.io/api/v1/search/?q={}&size=10",
        urlencoding::encode(&q)
    );
    let key = urlscan_api_key();
    let probe = if key.is_empty() {
        http_get(&client, &url).await
    } else {
        http_get_with_headers(&client, &url, &[("API-Key", key.as_str())]).await
    };
    let Some(p) = probe else {
        return Vec::new();
    };
    if p.status != 200 {
        return Vec::new();
    }
    findings_from_urlscan(engine_id, host, target, &p.body)
}

async fn query_hibp_breach_source(engine_id: &str, host: &str, target: &str) -> Vec<Value> {
    let client = http_client().await;
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breaches?domain={}",
        urlencoding::encode(host)
    );
    let Some(p) = http_get_with_headers(
        &client,
        &url,
        &[(
            "User-Agent",
            "Weissman-Cybersecurity/1.0 (authorized-assessment)",
        )],
    )
    .await
    else {
        return Vec::new();
    };
    findings_from_hibp_breach_source(engine_id, host, target, p.status, &p.body)
}

async fn query_otx(engine_id: &str, host: &str, target: &str) -> Vec<Value> {
    let client = http_client().await;
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/general",
        urlencoding::encode(host)
    );
    let key = otx_api_key();
    let probe = if key.is_empty() {
        http_get(&client, &url).await
    } else {
        http_get_with_headers(&client, &url, &[("X-OTX-API-KEY", key.as_str())]).await
    };
    let Some(p) = probe else {
        return Vec::new();
    };
    if p.status != 200 {
        return Vec::new();
    }
    findings_from_otx(engine_id, host, target, &p.body)
}

/// Live clearnet adversary-index probes. Honest empty when every source is clean or skipped.
pub async fn collect_public_adversary_intel(engine_id: &str, target: &str) -> Vec<Value> {
    if target.trim().is_empty() {
        return Vec::new();
    }
    let host = extract_host(target);
    if host.is_empty() {
        return Vec::new();
    }
    let (urlhaus, threatfox, urlscan, hibp, otx) = tokio::join!(
        query_urlhaus(engine_id, &host, target),
        query_threatfox(engine_id, &host, target),
        query_urlscan(engine_id, &host, target),
        query_hibp_breach_source(engine_id, &host, target),
        query_otx(engine_id, &host, target),
    );
    let mut out = Vec::new();
    out.extend(urlhaus);
    out.extend(threatfox);
    out.extend(urlscan);
    out.extend(hibp);
    out.extend(otx);
    out
}

pub fn max_findings_from_params(params: &Value) -> usize {
    let n = params
        .get("max_findings")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .unwrap_or(50);
    (n as usize).clamp(1, 50)
}

pub async fn run_adversary_exposure_delta_result(
    target: &str,
    ctx: &crate::engine_dispatch::EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cap = max_findings_from_params(&ctx.job_params);
    let mut findings = collect_public_adversary_intel("adversary_exposure_delta", target).await;
    if findings.len() > cap {
        findings.truncate(cap);
    }
    if findings.is_empty() {
        let abusech = if abusech_auth_key().is_empty() {
            "urlhaus+threatfox skipped (no ABUSECH_AUTH_KEY)"
        } else {
            "urlhaus+threatfox queried"
        };
        EngineResult::ok(
            vec![],
            format!(
                "adversary_exposure_delta: no live signal on {}; feeds: urlscan+hibp+otx; {abusech}",
                extract_host(target)
            ),
        )
    } else {
        EngineResult::ok(
            findings.clone(),
            format!(
                "adversary_exposure_delta: {} (max_findings={cap})",
                findings.len()
            ),
        )
    }
}

pub async fn run_adversary_exposure_delta(target: &str) {
    print_result(
        run_adversary_exposure_delta_result(
            target,
            &crate::engine_dispatch::EngineRunContext::default(),
        )
        .await,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlhaus_no_results_is_empty() {
        let out = findings_from_urlhaus(
            "adversary_exposure_delta",
            "example.com",
            "example.com",
            r#"{"query_status":"no_results"}"#,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn urlhaus_ok_with_urls_is_a_hit() {
        let body = r#"{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/host/evil.example/","urls":[{"url":"http://evil.example/payload"}]}"#;
        let out = findings_from_urlhaus(
            "adversary_exposure_delta",
            "evil.example",
            "evil.example",
            body,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["severity"], "high");
        assert!(out[0]["description"].as_str().unwrap().contains("payload"));
    }

    #[test]
    fn threatfox_no_result_singular_is_empty() {
        let out = findings_from_threatfox(
            "adversary_exposure_delta",
            "example.com",
            "example.com",
            r#"{"query_status":"no_result"}"#,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn threatfox_ok_array_is_a_hit() {
        let body =
            r#"{"query_status":"ok","data":[{"ioc":"1.2.3.4","malware_printable":"Emotet"}]}"#;
        let out = findings_from_threatfox("x", "1.2.3.4", "1.2.3.4", body);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn urlscan_zero_total_is_empty() {
        let out = findings_from_urlscan(
            "x",
            "example.com",
            "example.com",
            r#"{"results":[],"total":0,"has_more":false}"#,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn urlscan_hit_is_not_claimed_as_malware() {
        let body = r#"{"total":2,"results":[{"page":{"url":"https://example.com/"}}]}"#;
        let out = findings_from_urlscan("x", "example.com", "example.com", body);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["severity"], "info");
        assert!(out[0]["description"]
            .as_str()
            .unwrap()
            .contains("not malware"));
    }

    #[test]
    fn hibp_empty_array_is_empty() {
        let out = findings_from_hibp_breach_source("x", "example.com", "example.com", 200, "[]");
        assert!(out.is_empty());
    }

    #[test]
    fn hibp_catalog_hit_is_not_mailbox_proof() {
        let body = r#"[{"Name":"Adobe","PwnCount":1}]"#;
        let out = findings_from_hibp_breach_source("x", "adobe.com", "adobe.com", 200, body);
        assert_eq!(out.len(), 1);
        assert!(out[0]["description"]
            .as_str()
            .unwrap()
            .contains("not that employee"));
    }

    #[test]
    fn otx_whitelist_is_empty() {
        let body = r#"{"validation":[{"name":"whitelist"}],"pulse_info":{"count":50,"pulses":[{"name":"noise"}]}}"#;
        let out = findings_from_otx("x", "example.com", "example.com", body);
        assert!(out.is_empty());
    }

    #[test]
    fn otx_real_pulses_are_hits() {
        let body =
            r#"{"pulse_info":{"count":1,"pulses":[{"id":"abc","name":"malicious campaign"}]}}"#;
        let out = findings_from_otx("x", "evil.test", "evil.test", body);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn max_findings_clamps_to_engine_range() {
        assert_eq!(max_findings_from_params(&json!({})), 50);
        assert_eq!(max_findings_from_params(&json!({"max_findings": 3})), 3);
        assert_eq!(max_findings_from_params(&json!({"max_findings": "8"})), 8);
        assert_eq!(max_findings_from_params(&json!({"max_findings": 0})), 1);
        assert_eq!(max_findings_from_params(&json!({"max_findings": 999})), 50);
    }
}
