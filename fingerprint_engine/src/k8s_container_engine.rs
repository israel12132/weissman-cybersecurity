//! K8s/Container Attack Engine — probes for exposed Kubernetes API, kubelet, Docker daemon, and dashboard.
//! MITRE: T1613 (Container and Resource Discovery).

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
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

fn extract_host(target: &str) -> String {
    let t = target.trim();
    let without_scheme = if let Some(s) = t.strip_prefix("https://") {
        s
    } else if let Some(s) = t.strip_prefix("http://") {
        s
    } else {
        t
    };
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}

const K8S_API_PATHS: &[&str] = &[
    "/api/v1",
    "/api/v1/namespaces",
    "/api/v1/pods",
    "/api/v1/secrets",
    "/api/v1/nodes",
    "/api/v1/services",
    "/apis",
    "/version",
    "/healthz",
    "/metrics",
];

const K8S_DASHBOARD_PATHS: &[&str] = &[
    "/kubernetes-dashboard",
    "/dashboard",
    "/k8s-dashboard",
    "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
    "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/",
];

const DOCKER_PATHS: &[&str] = &[
    "/v1.24/containers/json",
    "/v1.41/containers/json",
    "/containers/json",
    "/v1.24/info",
    "/v1.24/version",
    "/v1.24/images/json",
];

pub async fn run_k8s_container_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = build_client().await;
    let base = normalize_target(target);
    let host = extract_host(&base);
    let mut findings = Vec::new();

    // Check Kubernetes API (port 6443 via HTTPS)
    let k8s_api_base = format!("https://{}:6443", host);
    for path in K8S_API_PATHS {
        let url = format!("{}{}", k8s_api_base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 || status == 401 || status == 403 {
                let severity = if status == 200 { "critical" } else { "high" };
                let detail = if status == 200 {
                    "The Kubernetes API is unauthenticated and accessible."
                } else {
                    "The Kubernetes API is accessible (authentication required but port is exposed)."
                };
                findings.push(json!({
                    "type": "k8s_container",
                    "title": format!("Kubernetes API Exposed: {}", path),
                    "severity": severity,
                    "mitre_attack": "T1613",
                    "description": format!(
                        "Kubernetes API endpoint {} returned HTTP {}. {}",
                        url, status, detail
                    )
                }));
                break; // One finding per K8s API cluster is sufficient
            }
        }
    }

    // Check Kubernetes API via standard HTTP on the target (some misconfigs expose on port 80/443)
    for path in &["/api/v1", "/apis", "/version"] {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("APIVersions")
                    || body.contains("serverVersion")
                    || body.contains("\"kind\"")
                {
                    findings.push(json!({
                        "type": "k8s_container",
                        "title": format!("Kubernetes API Exposed on Standard Port: {}", path),
                        "severity": "critical",
                        "mitre_attack": "T1613",
                        "description": format!(
                            "Kubernetes API detected at {} on standard HTTP/HTTPS port. Cluster is exposed without port restriction.",
                            url
                        )
                    }));
                }
            }
        }
    }

    // Check kubelet API on port 10250
    let kubelet_base = format!("https://{}:10250", host);
    for path in &["/pods", "/exec", "/run", "/healthz"] {
        let url = format!("{}{}", kubelet_base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 || status == 401 || status == 403 {
                findings.push(json!({
                    "type": "k8s_container",
                    "title": format!("Kubelet API Exposed on Port 10250: {}", path),
                    "severity": "critical",
                    "mitre_attack": "T1613",
                    "description": format!(
                        "Kubelet API at {} returned HTTP {}. Exposed kubelet can allow container exec, log access, and pod enumeration.",
                        url, status
                    )
                }));
                break;
            }
        }
    }

    // Check Docker daemon API
    let docker_base_http = format!("http://{}:2375", host);
    for path in DOCKER_PATHS {
        let url = format!("{}{}", docker_base_http, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                findings.push(json!({
                    "type": "k8s_container",
                    "title": "Docker Daemon API Exposed (Port 2375)",
                    "severity": "critical",
                    "mitre_attack": "T1613",
                    "description": format!(
                        "Docker daemon REST API at {} is accessible without authentication. An attacker can list, create, and execute commands in containers.",
                        url
                    )
                }));
                break;
            }
        }
    }

    // Check for Kubernetes Dashboard
    for path in K8S_DASHBOARD_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 || status == 301 || status == 302 {
                findings.push(json!({
                    "type": "k8s_container",
                    "title": format!("Kubernetes Dashboard Exposed: {}", path),
                    "severity": "high",
                    "mitre_attack": "T1613",
                    "description": format!(
                        "Kubernetes Dashboard found at {} (HTTP {}). The dashboard may allow cluster management without proper authentication.",
                        url, status
                    )
                }));
            }
        }
    }

    EngineResult::ok(findings.clone(), format!("K8s/Container: {} findings", findings.len()))
}

pub async fn run_k8s_container(target: &str) {
    print_result(run_k8s_container_result(target).await);
}
