//! Password Spray — detects login endpoints and tests rate-limiting / lockout policy.

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

const LOGIN_PATHS: &[&str] = &[
    "/login",
    "/api/login",
    "/auth/login",
    "/signin",
    "/api/auth",
    "/wp-login.php",
    "/admin/login",
    "/user/login",
    "/account/login",
    "/api/v1/auth/login",
];

pub async fn run_password_spray_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    for path in LOGIN_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let resp = client.get(&url).send().await;
        let status = match resp {
            Ok(r) => r.status().as_u16(),
            Err(_) => continue,
        };
        if status == 200 || status == 302 || status == 401 || status == 403 {
            findings.push(json!({
                "type": "password_spray",
                "title": format!("Login endpoint discovered: {}", url),
                "severity": "medium",
                "mitre_attack": "T1110.003",
                "description": format!(
                    "Login endpoint at {} responded with HTTP {}. Verify rate-limiting and lockout policy are enforced.",
                    url, status
                ),
                "value": url
            }));

            // Try JSON credentials to probe lockout
            let payloads = [
                json!({"username": "admin", "password": "admin"}),
                json!({"username": "admin", "password": "password"}),
            ];
            let mut blocked = false;
            for creds in &payloads {
                let r = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(creds)
                    .send()
                    .await;
                if let Ok(resp) = r {
                    let s = resp.status().as_u16();
                    if s == 429 || s == 423 {
                        blocked = true;
                        break;
                    }
                }
            }
            if !blocked {
                findings.push(json!({
                    "type": "password_spray",
                    "title": format!("No rate-limiting detected on login: {}", url),
                    "severity": "high",
                    "mitre_attack": "T1110.003",
                    "description": "Multiple failed login attempts did not trigger HTTP 429 (rate-limit) or 423 (locked). The endpoint may be vulnerable to credential spraying attacks.",
                    "value": url
                }));
            }
            break; // Stop after first discovered login endpoint
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("PasswordSpray: {} findings", findings.len()),
    )
}

pub async fn run_password_spray(target: &str) {
    print_result(run_password_spray_result(target).await);
}
