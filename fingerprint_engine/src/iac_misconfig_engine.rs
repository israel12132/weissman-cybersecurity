//! IaC Misconfig Engine — checks for exposed Terraform state, Ansible inventory, CloudFormation, and sensitive config files.
//! MITRE: T1552 (Unsecured Credentials).

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

struct SensitivePath {
    path: &'static str,
    label: &'static str,
    severity: &'static str,
    indicators: &'static [&'static str],
}

const SENSITIVE_PATHS: &[SensitivePath] = &[
    SensitivePath {
        path: "/.terraform/terraform.tfstate",
        label: "Terraform State File",
        severity: "critical",
        indicators: &["terraform_version", "resources", "outputs", "backend"],
    },
    SensitivePath {
        path: "/terraform.tfstate",
        label: "Terraform State File (Root)",
        severity: "critical",
        indicators: &["terraform_version", "resources", "outputs"],
    },
    SensitivePath {
        path: "/terraform.tfstate.backup",
        label: "Terraform State Backup",
        severity: "critical",
        indicators: &["terraform_version", "resources"],
    },
    SensitivePath {
        path: "/.terraform.tfstate.lock.info",
        label: "Terraform Lock File",
        severity: "medium",
        indicators: &["Operation", "Info", "Who"],
    },
    SensitivePath {
        path: "/inventory",
        label: "Ansible Inventory",
        severity: "high",
        indicators: &["[all]", "[webservers]", "[defaults]", "ansible_host", "ansible_user"],
    },
    SensitivePath {
        path: "/hosts",
        label: "Ansible Hosts File",
        severity: "high",
        indicators: &["[all]", "ansible_host", "ansible_ssh", "[defaults]"],
    },
    SensitivePath {
        path: "/ansible/hosts",
        label: "Ansible Hosts File",
        severity: "high",
        indicators: &["[all]", "ansible_host", "ansible_ssh"],
    },
    SensitivePath {
        path: "/.git/config",
        label: "Git Repository Config",
        severity: "high",
        indicators: &["[core]", "[remote", "url =", "repositoryformatversion"],
    },
    SensitivePath {
        path: "/.env",
        label: "Environment Variables File",
        severity: "critical",
        indicators: &["DB_PASSWORD", "SECRET_KEY", "API_KEY", "PASSWORD", "TOKEN", "="],
    },
    SensitivePath {
        path: "/docker-compose.yml",
        label: "Docker Compose Config",
        severity: "high",
        indicators: &["services:", "image:", "environment:", "volumes:", "ports:"],
    },
    SensitivePath {
        path: "/docker-compose.yaml",
        label: "Docker Compose Config",
        severity: "high",
        indicators: &["services:", "image:", "environment:"],
    },
    SensitivePath {
        path: "/Dockerfile",
        label: "Dockerfile",
        severity: "medium",
        indicators: &["FROM ", "RUN ", "ENV ", "COPY ", "ENTRYPOINT"],
    },
    SensitivePath {
        path: "/k8s.yaml",
        label: "Kubernetes Manifest",
        severity: "high",
        indicators: &["apiVersion:", "kind:", "metadata:", "spec:"],
    },
    SensitivePath {
        path: "/kubernetes.yaml",
        label: "Kubernetes Manifest",
        severity: "high",
        indicators: &["apiVersion:", "kind:", "metadata:"],
    },
    SensitivePath {
        path: "/k8s.yml",
        label: "Kubernetes Manifest",
        severity: "high",
        indicators: &["apiVersion:", "kind:", "metadata:"],
    },
];

pub async fn run_iac_misconfig_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = build_client().await;
    let base = normalize_target(target);
    let mut findings = Vec::new();

    for sp in SENSITIVE_PATHS {
        let url = format!("{}{}", base, sp.path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                let confirmed = sp.indicators.iter().any(|ind| body.contains(ind));

                if confirmed {
                    findings.push(json!({
                        "type": "iac_misconfig",
                        "title": format!("{} Exposed", sp.label),
                        "severity": sp.severity,
                        "mitre_attack": "T1552",
                        "description": format!(
                            "{} found at {} (HTTP {}). This file may contain infrastructure details, credentials, or sensitive configuration that should not be publicly accessible.",
                            sp.label, url, status
                        )
                    }));
                } else {
                    // Still report if path is accessible even without confirmed content
                    findings.push(json!({
                        "type": "iac_misconfig",
                        "title": format!("Sensitive Path Accessible: {}", sp.path),
                        "severity": "medium",
                        "mitre_attack": "T1552",
                        "description": format!(
                            "The path {} returned HTTP {} with {} bytes. Content could not be confirmed but the path should not be publicly accessible.",
                            url, status, body.len()
                        )
                    }));
                }
            }
        }
    }

    // Check for CloudFormation templates (JSON with AWSTemplateFormatVersion key)
    let cfn_paths = vec![
        "/template.json",
        "/cloudformation.json",
        "/stack.json",
        "/infra.json",
        "/infrastructure.json",
        "/cfn.json",
        "/cf-template.json",
    ];
    for path in cfn_paths {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("AWSTemplateFormatVersion") {
                    findings.push(json!({
                        "type": "iac_misconfig",
                        "title": format!("CloudFormation Template Exposed: {}", path),
                        "severity": "high",
                        "mitre_attack": "T1552",
                        "description": format!(
                            "A CloudFormation template was found at {} (HTTP {}). Templates may contain resource ARNs, IAM policies, parameter defaults, and infrastructure topology.",
                            url, status
                        )
                    }));
                }
            }
        }
    }

    EngineResult::ok(findings.clone(), format!("IaC Misconfig: {} findings", findings.len()))
}

pub async fn run_iac_misconfig(target: &str) {
    print_result(run_iac_misconfig_result(target).await);
}
