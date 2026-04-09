//! CI/CD Pipeline Attack Engine — extends cicd_ast_scan with GitHub Actions injection, ArgoCD, Tekton.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
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

const CICD_PATHS: &[&str] = &[
    // ArgoCD
    "/api/v1/applications",
    "/api/v1/repositories",
    "/api/v1/clusters",
    "/api/v1/projects",
    // Tekton
    "/apis/tekton.dev/v1beta1/pipelineruns",
    "/apis/tekton.dev/v1beta1/taskruns",
    // Jenkins
    "/api/json",
    "/job/",
    "/computer/",
    "/credentials/",
    // GitLab CI
    "/api/v4/runners",
    "/api/v4/pipelines",
    // GitHub Actions (self-hosted)
    "/_apis/distributedtask/pools",
    "/_apis/build/builds",
    // Drone
    "/api/user",
    "/api/repos",
    // CircleCI
    "/api/v1.1/me",
    // Spinnaker
    "/api/v1/applications",
    "/gate/applications",
];

const SECRET_PATTERNS: &[&str] = &[
    "password", "secret", "token", "api_key", "apikey", "private_key",
    "access_key", "aws_secret", "github_token", "gh_token", "slack_token",
];

pub async fn run_cicd_pipeline_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    for path in CICD_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = resp.status().as_u16();
        if status != 200 && status != 201 {
            continue;
        }
        let body = resp.text().await.unwrap_or_default();

        // Determine CI/CD tool from path
        let tool = if path.contains("argocd") || path.contains("v1/applications") || path.contains("v1/repositories") {
            "ArgoCD"
        } else if path.contains("tekton") {
            "Tekton"
        } else if path.contains("api/json") || path.contains("credentials") {
            "Jenkins"
        } else if path.contains("v4/runners") || path.contains("v4/pipelines") {
            "GitLab CI"
        } else if path.contains("_apis") {
            "Azure DevOps"
        } else if path.contains("drone") || path.contains("api/repos") {
            "Drone CI"
        } else {
            "CI/CD"
        };

        findings.push(json!({
            "type": "cicd_pipeline",
            "title": format!("{} endpoint exposed without authentication: {}", tool, url),
            "severity": "critical",
            "mitre_attack": "T1195.002",
            "description": format!(
                "{} API endpoint {} is accessible without authentication (HTTP {}). \
                Unauthenticated CI/CD access allows attackers to inject malicious pipeline steps, \
                steal secrets, and compromise the software supply chain.",
                tool, url, status
            ),
            "value": url
        }));

        // Scan body for leaked secrets
        let body_lower = body.to_lowercase();
        for pattern in SECRET_PATTERNS {
            if body_lower.contains(pattern) {
                findings.push(json!({
                    "type": "cicd_pipeline",
                    "title": format!("Potential secret keyword '{}' in {} response: {}", pattern, tool, url),
                    "severity": "critical",
                    "mitre_attack": "T1552.004",
                    "description": format!(
                        "The {} API response from {} contains the keyword '{}' which may indicate \
                        exposed CI/CD pipeline secrets, credentials, or API tokens.",
                        tool, url, pattern
                    ),
                    "value": url
                }));
                break; // One secret finding per endpoint
            }
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("CICDPipeline: {} findings", findings.len()),
    )
}

pub async fn run_cicd_pipeline(target: &str) {
    print_result(run_cicd_pipeline_result(target).await);
}
