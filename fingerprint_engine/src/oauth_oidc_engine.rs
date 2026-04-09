//! OAuth/OIDC Attack Engine — discovery doc probing, dangerous response types, implicit flow, PKCE check.
//! MITRE: T1550 (Use Alternate Authentication Material).

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

pub async fn run_oauth_oidc_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    let discovery_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/default",
    ];

    for path in &discovery_paths {
        let url = format!("{}{}", base, path);
        let resp = client.get(&url).send().await;
        match resp {
            Ok(r) if r.status().as_u16() == 200 => {
                let body = r.text().await.unwrap_or_default();
                if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&body) {
                    findings.push(json!({
                        "type": "oauth_oidc",
                        "title": "OAuth/OIDC Discovery Document Found",
                        "severity": "info",
                        "mitre_attack": "T1550",
                        "description": format!("OAuth/OIDC discovery document is publicly accessible at {}", url),
                        "value": url
                    }));

                    // Check for dangerous response_types_supported (implicit / token in URL)
                    if let Some(response_types) = doc.get("response_types_supported").and_then(|v| v.as_array()) {
                        let types: Vec<String> = response_types.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                        let has_implicit = types.iter().any(|t| t == "token" || t.contains("token") && t != "code token");
                        if has_implicit {
                            findings.push(json!({
                                "type": "oauth_oidc",
                                "title": "Implicit Flow (Token in URL) Supported",
                                "severity": "high",
                                "mitre_attack": "T1550",
                                "description": format!("The server at {} supports implicit flow (response_type=token). Tokens exposed in URL fragment are vulnerable to leakage via Referer, browser history, and logs.", url),
                                "value": types.join(", ")
                            }));
                        }
                    }

                    // Check grant_types_supported for implicit
                    if let Some(grant_types) = doc.get("grant_types_supported").and_then(|v| v.as_array()) {
                        let types: Vec<String> = grant_types.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                        if types.iter().any(|t| t == "implicit") {
                            findings.push(json!({
                                "type": "oauth_oidc",
                                "title": "Implicit Grant Type Supported",
                                "severity": "high",
                                "mitre_attack": "T1550",
                                "description": format!("Implicit grant type is supported at {}. This is deprecated in OAuth 2.1 and exposes tokens in URL fragments.", url),
                                "value": types.join(", ")
                            }));
                        }
                    }

                    // Check if PKCE is required
                    let pkce_required = doc.get("require_pkce")
                        .or_else(|| doc.get("code_challenge_methods_supported"))
                        .is_some();
                    if !pkce_required {
                        findings.push(json!({
                            "type": "oauth_oidc",
                            "title": "PKCE Not Required",
                            "severity": "medium",
                            "mitre_attack": "T1550",
                            "description": format!("The OAuth server at {} does not advertise PKCE enforcement. Authorization code flows without PKCE are vulnerable to interception attacks.", url),
                            "value": url
                        }));
                    }
                }
            }
            _ => continue,
        }
    }

    // Probe common OAuth endpoints even without a discovery doc
    for path in &["/oauth/authorize", "/oauth/token", "/oauth2/authorize", "/oauth2/token", "/connect/authorize"] {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status != 404 {
                findings.push(json!({
                    "type": "oauth_oidc",
                    "title": "OAuth Endpoint Detected",
                    "severity": "info",
                    "mitre_attack": "T1550",
                    "description": format!("OAuth endpoint found at {} (HTTP {}). Verify proper PKCE enforcement and token binding.", url, status),
                    "value": url
                }));
            }
        }
    }

    let message = if findings.is_empty() {
        "No OAuth/OIDC vulnerabilities detected".to_string()
    } else {
        format!("{} OAuth/OIDC issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_oauth_oidc(target: &str) {
    print_result(run_oauth_oidc_result(target).await);
}
