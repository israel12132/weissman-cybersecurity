//! AWS Attack Engine — probes for exposed AWS metadata, S3 buckets, credentials, and API keys.
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

const AWS_WEB_PATHS: &[&str] = &[
    "/.aws/credentials",
    "/.aws/config",
    "/aws/credentials",
    "/_aws/",
    "/aws/",
    "/s3/",
    "/static/aws-config.js",
    "/js/config.js",
    "/assets/config.js",
    "/static/config.js",
    "/app.js",
    "/bundle.js",
    "/main.js",
];

const AWS_KEY_INDICATORS: &[&str] = &[
    "AKIA",
    "aws_access_key_id",
    "aws_secret_access_key",
    "AWSSecretKey",
    "AWSAccessKeyId",
    "s3.amazonaws.com",
    "aws_session_token",
    "[default]",
    "region = ",
];

pub async fn run_aws_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = build_client().await;
    let base = normalize_target(target);
    let domain = extract_domain(&base);
    let mut findings = Vec::new();

    // Check for AWS IMDS metadata endpoint (only relevant if on an internal/EC2 network)
    let imds_url = "http://169.254.169.254/latest/meta-data/";
    if let Ok(resp) = client
        .get(imds_url)
        .timeout(Duration::from_secs(3))
        .send()
        .await
    {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            findings.push(json!({
                "type": "aws_attack",
                "title": "AWS IMDS Metadata Endpoint Accessible",
                "severity": "critical",
                "mitre_attack": "T1552",
                "description": format!(
                    "AWS EC2 Instance Metadata Service (IMDS) at {} is accessible. This can expose IAM credentials and sensitive instance data. Response body preview: {}",
                    imds_url,
                    &body[..body.len().min(200)]
                )
            }));
        }
    }

    // Check for public S3 bucket derived from domain
    let domain_base = domain.split('.').next().unwrap_or(&domain);
    let s3_urls = vec![
        format!("https://s3.amazonaws.com/{}", domain_base),
        format!("https://s3.amazonaws.com/{}", domain),
        format!("https://{}.s3.amazonaws.com/", domain_base),
        format!("https://{}.s3.amazonaws.com/", domain),
    ];

    for s3_url in &s3_urls {
        if let Ok(resp) = client.get(s3_url).send().await {
            let status = resp.status().as_u16();
            if status == 200 || status == 403 {
                let severity = if status == 200 { "critical" } else { "high" };
                let detail = if status == 200 {
                    "The S3 bucket is publicly readable — data is exposed."
                } else {
                    "The S3 bucket exists but access is forbidden. Bucket enumeration confirmed."
                };
                findings.push(json!({
                    "type": "aws_attack",
                    "title": format!("AWS S3 Bucket Exposed: {}", s3_url),
                    "severity": severity,
                    "mitre_attack": "T1552",
                    "description": format!("S3 URL {} returned HTTP {}. {}", s3_url, status, detail)
                }));
            }
        }
    }

    // Check web root for exposed AWS credentials / API keys in files
    for path in AWS_WEB_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                let found_key = AWS_KEY_INDICATORS.iter().any(|ind| body.contains(ind));
                if found_key {
                    findings.push(json!({
                        "type": "aws_attack",
                        "title": format!("AWS Credentials Exposed at {}", path),
                        "severity": "critical",
                        "mitre_attack": "T1552",
                        "description": format!(
                            "File at {} (HTTP {}) contains AWS credential indicators (access keys, secret keys, or config). Immediate remediation required.",
                            url, status
                        )
                    }));
                } else if path.contains("credentials") || path.contains(".aws") {
                    findings.push(json!({
                        "type": "aws_attack",
                        "title": format!("AWS Credentials File Accessible: {}", path),
                        "severity": "high",
                        "mitre_attack": "T1552",
                        "description": format!(
                            "AWS credentials file path {} is accessible (HTTP {}). Even if empty, this path should not be publicly reachable.",
                            url, status
                        )
                    }));
                }
            }
        }
    }

    EngineResult::ok(findings.clone(), format!("AWS Attack: {} findings", findings.len()))
}

pub async fn run_aws_attack(target: &str) {
    print_result(run_aws_attack_result(target).await);
}
