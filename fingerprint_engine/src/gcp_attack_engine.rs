//! GCP Attack Engine — probes for GCP metadata, GCS buckets, and service account credentials.
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

fn extract_domain(target: &str) -> String {
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

const GCP_WEB_PATHS: &[&str] = &[
    "/.gcp/",
    "/gcp.json",
    "/service-account.json",
    "/service_account.json",
    "/google-credentials.json",
    "/.config/gcloud/credentials.db",
    "/credentials.json",
    "/gcloud.json",
    "/sa-key.json",
    "/firebase.json",
    "/google-services.json",
];

const SA_KEY_INDICATORS: &[&str] = &[
    "service_account",
    "private_key_id",
    "private_key",
    "client_email",
    "client_id",
    "auth_uri",
    "token_uri",
    "\"type\": \"service_account\"",
    "googleapis.com",
    "project_id",
];

pub async fn run_gcp_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = build_client().await;
    let base = normalize_target(target);
    let domain = extract_domain(&base);
    let mut findings = Vec::new();

    // Check GCP metadata server
    let metadata_url = "http://metadata.google.internal/computeMetadata/v1/";
    if let Ok(resp) = client
        .get(metadata_url)
        .header("Metadata-Flavor", "Google")
        .timeout(Duration::from_secs(3))
        .send()
        .await
    {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            findings.push(json!({
                "type": "gcp_attack",
                "title": "GCP Compute Metadata Server Accessible",
                "severity": "critical",
                "mitre_attack": "T1552",
                "description": format!(
                    "GCP metadata server at {} is accessible. This exposes project info, service account tokens, SSH keys, and startup scripts. Preview: {}",
                    metadata_url,
                    &body[..body.len().min(300)]
                )
            }));
        }
    }

    // Check for exposed GCS buckets
    let domain_base = domain.split('.').next().unwrap_or(&domain);
    let gcs_urls = vec![
        format!("https://storage.googleapis.com/{}", domain_base),
        format!("https://storage.googleapis.com/{}", domain),
        format!("https://storage.googleapis.com/{}-public", domain_base),
        format!("https://storage.googleapis.com/{}-assets", domain_base),
        format!("https://storage.googleapis.com/{}-backup", domain_base),
    ];

    for gcs_url in &gcs_urls {
        if let Ok(resp) = client.get(gcs_url).send().await {
            let status = resp.status().as_u16();
            if status == 200 || status == 403 {
                let severity = if status == 200 { "critical" } else { "high" };
                let detail = if status == 200 {
                    "The GCS bucket is publicly readable."
                } else {
                    "The GCS bucket exists (403 Forbidden). Bucket name confirmed."
                };
                findings.push(json!({
                    "type": "gcp_attack",
                    "title": format!("GCS Bucket Exposed: {}", gcs_url),
                    "severity": severity,
                    "mitre_attack": "T1552",
                    "description": format!("GCS URL {} returned HTTP {}. {}", gcs_url, status, detail)
                }));
            }
        }
    }

    // Check for service account keys and GCP credentials files
    for path in GCP_WEB_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                let has_sa_key = SA_KEY_INDICATORS.iter().any(|ind| body.contains(ind));

                if has_sa_key {
                    findings.push(json!({
                        "type": "gcp_attack",
                        "title": format!("GCP Service Account Key Exposed at {}", path),
                        "severity": "critical",
                        "mitre_attack": "T1552",
                        "description": format!(
                            "File at {} (HTTP {}) contains GCP service account key indicators (private_key, client_email, etc.). Immediate rotation required.",
                            url, status
                        )
                    }));
                } else {
                    findings.push(json!({
                        "type": "gcp_attack",
                        "title": format!("GCP Configuration File Accessible: {}", path),
                        "severity": "high",
                        "mitre_attack": "T1552",
                        "description": format!(
                            "GCP-related file {} is publicly accessible (HTTP {}). Review for sensitive credential data.",
                            url, status
                        )
                    }));
                }
            }
        }
    }

    EngineResult::ok(findings.clone(), format!("GCP Attack: {} findings", findings.len()))
}

pub async fn run_gcp_attack(target: &str) {
    print_result(run_gcp_attack_result(target).await);
}
