//! AWS Attack Engine — honest remote probes for S3 exposure and leaked credentials on the target.
//! Does not probe the scanner host's link-local IMDS (169.254.169.254). MITRE: T1552.

use crate::engine_probes::{
    empty_ok, extract_host, finding_with_probe_depth, header_value, http_client, http_get,
    normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

const AWS_PROBE_DEPTH: &str = "aws_remote_surface";

fn aws_finding(title: &str, severity: &str, description: &str, target: &str) -> Value {
    finding_with_probe_depth(
        "aws_attack",
        title,
        severity,
        "T1552",
        description,
        target,
        AWS_PROBE_DEPTH,
    )
}

const AWS_WEB_PATHS: &[&str] = &[
    "/.aws/credentials",
    "/.aws/config",
    "/aws/credentials",
    "/static/aws-config.js",
    "/js/config.js",
    "/assets/config.js",
    "/static/config.js",
];

const AWS_KEY_INDICATORS: &[&str] = &[
    "AKIA",
    "aws_access_key_id",
    "aws_secret_access_key",
    "AWSSecretKey",
    "AWSAccessKeyId",
    "aws_session_token",
];

fn body_has_aws_keys(body: &str) -> bool {
    AWS_KEY_INDICATORS.iter().any(|ind| body.contains(ind))
}

fn s3_listing_exposed(body: &str) -> bool {
    body.contains("<ListBucketResult") || body.contains("<Contents>")
}

pub async fn run_aws_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = http_client().await;
    let base = normalize_url(target);
    let host = extract_host(target);
    let domain_base = host.split('.').next().unwrap_or(&host);
    let mut findings = Vec::new();

    let s3_urls = [
        format!("https://{}.s3.amazonaws.com/", domain_base),
        format!("https://{}.s3.amazonaws.com/", host),
        format!("https://s3.amazonaws.com/{}/", domain_base),
        format!("https://s3.amazonaws.com/{}/", host),
    ];

    for url in s3_urls.iter() {
        if let Some(p) = http_get(&client, url).await {
            if p.status == 200 && s3_listing_exposed(&p.body) {
                findings.push(aws_finding(
                    "Public S3 bucket listing",
                    "critical",
                    &format!("Bucket listing readable at {} (HTTP 200).", url),
                    target,
                ));
            } else if p.status == 403 && p.body.contains("AccessDenied") {
                findings.push(aws_finding(
                    "S3 bucket exists (AccessDenied)",
                    "info",
                    &format!(
                        "{} returned HTTP 403 AccessDenied — bucket name resolves; review ACL/policy.",
                        url
                    ),
                    target,
                ));
            }
        }
    }

    for path in AWS_WEB_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && body_has_aws_keys(&p.body) {
                findings.push(aws_finding(
                    &format!("AWS credential material at {}", path),
                    "critical",
                    &format!(
                        "{} (HTTP 200) contains AWS access-key indicators — rotate keys immediately.",
                        p.final_url
                    ),
                    target,
                ));
            }
        }
    }

    if let Some(p) = http_get(&client, &base).await {
        if header_value(&p.headers, "x-amzn-requestid").is_some()
            || header_value(&p.headers, "x-amz-apigw-id").is_some()
        {
            findings.push(aws_finding(
                "AWS API Gateway / Lambda front-end detected",
                "info",
                &format!(
                    "{} carries x-amzn-* headers — review IAM auth and stage logging.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    if findings.is_empty() {
        empty_ok("aws_attack", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("aws_attack: {} signal(s)", findings.len()),
        )
    }
}

pub async fn run_aws_attack(target: &str) {
    print_result(run_aws_attack_result(target).await);
}
