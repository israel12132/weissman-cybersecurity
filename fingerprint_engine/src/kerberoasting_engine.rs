//! Kerberoasting Simulator — probes for Kerberos/AD-related HTTP endpoints and SPNEGO auth.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn normalize_target(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

const KERBEROS_PATHS: &[&str] = &[
    "/adfs/ls/",
    "/adfs/oauth2/authorize",
    "/adfs/oauth2/token",
    "/EWS/Exchange.asmx",
    "/autodiscover/autodiscover.xml",
    "/mapi/",
    "/rpc/",
    "/oab/",
    "/owa/",
    "/api/auth/negotiate",
    "/auth/kerberos",
    "/SPNEGO",
    "/negotiate",
    "/krb5/",
    "/kerberos/",
];

pub async fn run_kerberoasting_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    for path in KERBEROS_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let resp = client
            .get(&url)
            .header("Authorization", "Negotiate")
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let headers = r.headers().clone();

                // Check for WWW-Authenticate: Negotiate header
                let www_auth = headers
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();

                if status == 401 && www_auth.contains("negotiate") {
                    findings.push(json!({
                        "type": "kerberoasting",
                        "title": format!("Kerberos/SPNEGO authentication detected: {}", url),
                        "severity": "high",
                        "mitre_attack": "T1558.003",
                        "description": format!(
                            "Endpoint {} requires Kerberos/SPNEGO authentication (WWW-Authenticate: Negotiate). \
                            In Active Directory environments, this may expose the service to Kerberoasting attacks \
                            where TGS tickets for SPNs can be extracted and cracked offline.",
                            url
                        ),
                        "value": url,
                        "www_authenticate": www_auth,
                        "http_status": status
                    }));
                } else if status == 200 && (path.contains("adfs") || path.contains("ADFS")) {
                    findings.push(json!({
                        "type": "kerberoasting",
                        "title": format!("ADFS endpoint exposed: {}", url),
                        "severity": "medium",
                        "mitre_attack": "T1558.003",
                        "description": format!(
                            "Active Directory Federation Services endpoint is publicly accessible at {}. \
                            ADFS exposure may enable SPN enumeration and Kerberoasting in connected AD environments.",
                            url
                        ),
                        "value": url,
                        "http_status": status
                    }));
                } else if status == 200 && path.contains("Exchange") {
                    findings.push(json!({
                        "type": "kerberoasting",
                        "title": format!("Exchange Web Services exposed: {}", url),
                        "severity": "medium",
                        "mitre_attack": "T1558.003",
                        "description": format!(
                            "Microsoft Exchange Web Services endpoint accessible at {}. \
                            Exchange servers are common Kerberoasting targets due to SPNs registered for the service account.",
                            url
                        ),
                        "value": url,
                        "http_status": status
                    }));
                }
            }
            Err(_) => continue,
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("Kerberoasting: {} findings", findings.len()),
    )
}

pub async fn run_kerberoasting(target: &str) {
    print_result(run_kerberoasting_result(target).await);
}
