//! Container Registry Engine — scans for public ECR/GCR/DockerHub registries and exposed image metadata.

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

fn extract_domain(target: &str) -> String {
    let t = target.trim();
    let stripped = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    // Return root domain (e.g. example.com from api.example.com)
    let parts: Vec<&str> = stripped.split('/').next().unwrap_or(stripped).split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        stripped.split('/').next().unwrap_or(stripped).to_string()
    }
}

fn extract_host(target: &str) -> String {
    let t = target.trim();
    let stripped = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    stripped.split('/').next().unwrap_or(stripped).to_string()
}

pub async fn run_container_registry_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let domain = extract_domain(target);
    let host = extract_host(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Check DockerHub for public images matching the org
    let org_name = domain.split('.').next().unwrap_or(&domain);
    let dockerhub_url = format!("https://hub.docker.com/v2/repositories/{}/", org_name);
    if let Ok(resp) = client.get(&dockerhub_url).send().await {
        if resp.status().as_u16() == 200 {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let count = data.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                if count > 0 {
                    findings.push(json!({
                        "type": "container_registry",
                        "title": format!("Public DockerHub repositories found for org '{}'", org_name),
                        "severity": "medium",
                        "mitre_attack": "T1525",
                        "description": format!(
                            "DockerHub organization '{}' has {} public repositories at {}. \
                            Public container images may contain hardcoded secrets, expose internal architecture, \
                            or use vulnerable base images. Review all public images for sensitive data.",
                            org_name, count, dockerhub_url
                        ),
                        "value": dockerhub_url,
                        "image_count": count
                    }));
                }
            }
        }
    }

    // Check for self-hosted registry at common paths on the target
    let registry_paths = [
        "/v2/_catalog",
        "/v2/",
        "/api/v2.0/repositories",  // Harbor
        "/api/repositories",
        "/service/token",           // Docker auth token endpoint
    ];

    let base = if host.starts_with("http") {
        host.clone()
    } else {
        format!("https://{}", host)
    };

    for path in &registry_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = resp.status().as_u16();

        if status == 200 {
            let body = resp.text().await.unwrap_or_default();
            let is_registry = body.contains("repositories") || body.contains("Docker-Distribution") || path.contains("v2");
            if is_registry || path.contains("v2") {
                findings.push(json!({
                    "type": "container_registry",
                    "title": format!("Container registry API exposed without authentication: {}", url),
                    "severity": "critical",
                    "mitre_attack": "T1525",
                    "description": format!(
                        "Container registry API endpoint {} returned HTTP 200 without authentication. \
                        Unauthenticated access to the registry catalog allows attackers to enumerate all \
                        images, pull sensitive layers containing secrets, and potentially push malicious images \
                        to compromise the supply chain.",
                        url
                    ),
                    "value": url
                }));
            }
        } else if status == 401 {
            let www_auth = resp
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            if www_auth.contains("bearer") || www_auth.contains("basic") {
                findings.push(json!({
                    "type": "container_registry",
                    "title": format!("Container registry detected (authentication required): {}", url),
                    "severity": "info",
                    "mitre_attack": "T1525",
                    "description": format!(
                        "Container registry at {} requires authentication ({}). \
                        Verify that only authorized users can push images and that image signing (Notary/Cosign) is enforced.",
                        url, www_auth
                    ),
                    "value": url
                }));
            }
        }
    }

    // Check for ECR public gallery
    let ecr_url = format!("https://public.ecr.aws/v2/{}/repositories/list", org_name);
    if let Ok(resp) = client.get(&ecr_url).send().await {
        if resp.status().as_u16() == 200 {
            findings.push(json!({
                "type": "container_registry",
                "title": format!("Public ECR repositories found for '{}'", org_name),
                "severity": "medium",
                "mitre_attack": "T1525",
                "description": format!(
                    "Public Amazon ECR galleries found for organization '{}'. \
                    Review all public ECR images for exposed secrets and ensure base images are scanned for CVEs.",
                    org_name
                ),
                "value": ecr_url
            }));
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("ContainerRegistry: {} findings", findings.len()),
    )
}

pub async fn run_container_registry(target: &str) {
    print_result(run_container_registry_result(target).await);
}
