//! Cache Poisoning Engine — unkeyed header injection, X-Forwarded-Host reflection, CDN cache detection.
//! MITRE: T1557 (Adversary-in-the-Middle).

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn base_url(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

const POISON_HOST: &str = "weissman-cache-poison-test.attacker.example.com";

pub async fn run_cache_poisoning_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    // First: baseline request to check cache headers
    let baseline_resp = client.get(&base).send().await;
    let mut is_cached = false;
    let mut cache_header_names: Vec<String> = Vec::new();

    if let Ok(ref resp) = baseline_resp {
        for (name, _value) in resp.headers().iter() {
            let hname = name.as_str().to_lowercase();
            if hname == "x-cache" || hname == "age" || hname == "cf-cache-status"
                || hname == "x-varnish" || hname == "x-cache-hits" || hname == "surrogate-key"
                || hname == "cdn-cache-control"
            {
                is_cached = true;
                cache_header_names.push(hname.clone());
            }
        }
        if is_cached {
            findings.push(json!({
                "type": "cache_poisoning",
                "title": "CDN/Cache Layer Detected",
                "severity": "info",
                "mitre_attack": "T1557",
                "description": format!(
                    "Caching layer detected at {} via headers: {}. Web cache poisoning attacks may be applicable.",
                    base, cache_header_names.join(", ")
                ),
                "value": cache_header_names.join(", ")
            }));
        }
    }

    // Unkeyed header injection tests
    let poison_headers: &[(&str, &str)] = &[
        ("X-Forwarded-Host", POISON_HOST),
        ("X-Original-URL", "/evil-path"),
        ("X-Rewrite-URL", "/evil-path"),
        ("X-Forwarded-Port", "1337"),
        ("X-Forwarded-Proto", "http"),
        ("X-Host", POISON_HOST),
        ("Forwarded", &format!("host={}", POISON_HOST)),
    ];

    for (header_name, header_value) in poison_headers {
        if let Ok(resp) = client
            .get(&base)
            .header(*header_name, *header_value)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let body = resp.text().await.unwrap_or_default();

            // Check if the injected value appears in the response body (reflection = poisoning possible)
            let poison_host_short = "weissman-cache-poison-test";
            if body.contains(poison_host_short) || body.contains(POISON_HOST) {
                findings.push(json!({
                    "type": "cache_poisoning",
                    "title": format!("Cache Poisoning: {} Reflected in Response", header_name),
                    "severity": "critical",
                    "mitre_attack": "T1557",
                    "description": format!(
                        "The unkeyed header '{}' was reflected in the response body from {}. If this response is cached, the injected host value poisons the cache for all users.",
                        header_name, base
                    ),
                    "value": format!("{}: {}", header_name, header_value)
                }));
            } else if (*header_name == "X-Forwarded-Host" || *header_name == "X-Host")
                && (status == 301 || status == 302)
            {
                // Redirect using our injected host
                if let Some(loc) = headers.get("location") {
                    let loc_str = loc.to_str().unwrap_or("");
                    if loc_str.contains(POISON_HOST) || loc_str.contains(poison_host_short) {
                        findings.push(json!({
                            "type": "cache_poisoning",
                            "title": format!("Cache Poisoning: {} Used in Redirect", header_name),
                            "severity": "high",
                            "mitre_attack": "T1557",
                            "description": format!(
                                "Redirect from {} incorporates the injected '{}' header value in the Location header. Cache poisoning can redirect all users to attacker-controlled domain.",
                                base, header_name
                            ),
                            "value": loc_str.to_string()
                        }));
                    }
                }
            }

            // Check X-Original-URL / X-Rewrite-URL path override
            if (*header_name == "X-Original-URL" || *header_name == "X-Rewrite-URL")
                && status != 404
            {
                findings.push(json!({
                    "type": "cache_poisoning",
                    "title": format!("Cache Poisoning: {} Path Override Accepted", header_name),
                    "severity": "medium",
                    "mitre_attack": "T1557",
                    "description": format!(
                        "Server at {} accepted the '{}' header (HTTP {}). This header can override the request path and may be used to access restricted resources or poison cache entries.",
                        base, header_name, status
                    ),
                    "value": format!("{}: {}", header_name, header_value)
                }));
            }
        }
    }

    let message = if findings.is_empty() {
        "No cache poisoning indicators detected".to_string()
    } else {
        format!("{} cache poisoning issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_cache_poisoning(target: &str) {
    print_result(run_cache_poisoning_result(target).await);
}
