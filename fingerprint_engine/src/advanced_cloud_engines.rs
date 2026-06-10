//! Advanced Cloud Engines — real HTTP probes against cloud-metadata endpoints, S3-style buckets,
//! and SaaS APIs reachable from the target. No simulated findings.

use crate::engine_probes::{
    empty_ok, extract_host, finding, header_value, http_client, http_get, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

// Probe SSRF-forwarded cloud metadata via target.
async fn try_ssrf_metadata(target: &str) -> Vec<Value> {
    let client = http_client().await;
    let base = normalize_url(target);
    let metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ];
    let mut findings = Vec::new();
    for meta in metadata_urls.iter() {
        for q in ["url", "image", "callback", "redirect_uri"] {
            let url = format!(
                "{}/?{}={}",
                base.trim_end_matches('/'),
                q,
                urlencoding::encode(meta)
            );
            if let Some(p) = http_get(&client, &url).await {
                if p.body.contains("ami-id")
                    || p.body.contains("computeMetadata")
                    || p.body.contains("instanceId")
                {
                    findings.push(finding(
                        "cloud_metadata_ssrf",
                        "Cloud metadata reflected via SSRF param",
                        "critical",
                        "T1552.005",
                        &format!("?{}={} on {} returned cloud-metadata content.", q, meta, p.final_url),
                        target,
                    ));
                }
            }
        }
    }
    findings
}

// ── cloud_metadata_ssrf ───────────────────────────────────────────────────────
pub async fn run_cloud_metadata_ssrf_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let findings = try_ssrf_metadata(target).await;
    if findings.is_empty() {
        empty_ok("cloud_metadata_ssrf", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("cloud_metadata_ssrf: {} hit(s)", n))
    }
}
cli_wrapper!(run_cloud_metadata_ssrf, run_cloud_metadata_ssrf_result);

// ── s3_bucket_attack ──────────────────────────────────────────────────────────
pub async fn run_s3_bucket_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let bucket_guesses = [
        format!("https://{}.s3.amazonaws.com/", host.replace('.', "-")),
        format!("https://{}.s3.amazonaws.com/", host),
        format!("https://s3.amazonaws.com/{}/", host),
    ];
    for url in bucket_guesses.iter() {
        if let Some(p) = http_get(&client, url).await {
            if p.status == 200 && p.body.contains("<ListBucketResult") {
                findings.push(finding(
                    "s3_bucket_attack",
                    "Public S3 bucket listing",
                    "high",
                    "T1530",
                    &format!("Bucket listing readable at {} (HTTP 200).", url),
                    target,
                ));
            } else if p.status == 200 && p.body.contains("AccessDenied") {
                findings.push(finding(
                    "s3_bucket_attack",
                    "S3 bucket exists (AccessDenied)",
                    "info",
                    "T1530",
                    &format!("{} confirms bucket existence — review ACL.", url),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("s3_bucket_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("s3_bucket_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_s3_bucket_attack, run_s3_bucket_attack_result);

// ── lambda_escape ─────────────────────────────────────────────────────────────
pub async fn run_lambda_escape_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &base).await {
        if header_value(&p.headers, "x-amzn-requestid").is_some()
            || header_value(&p.headers, "x-amz-apigw-id").is_some()
        {
            findings.push(finding(
                "lambda_escape",
                "AWS Lambda / API Gateway detected",
                "info",
                "T1610",
                &format!("Response from {} carries AWS x-amzn-* headers — exposed Lambda runtime.", p.final_url),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("lambda_escape", target)
    } else {
        EngineResult::ok(findings.clone(), format!("lambda_escape: {}", findings.len()))
    }
}
cli_wrapper!(run_lambda_escape, run_lambda_escape_result);

// ── cloud_iam_escalation ──────────────────────────────────────────────────────
pub async fn run_cloud_iam_escalation_result(target: &str) -> EngineResult {
    crate::aws_attack_engine::run_aws_attack_result(target).await
}
cli_wrapper!(run_cloud_iam_escalation, run_cloud_iam_escalation_result);

// ── kubernetes_rbac_escape ────────────────────────────────────────────────────
pub async fn run_kubernetes_rbac_escape_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    for path in ["/api/v1/namespaces", "/healthz", "/api", "/apis", "/openapi/v2"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200
                && (p.body.contains("Kubernetes") || p.body.contains("kind\":\"Status\""))
            {
                findings.push(finding(
                    "kubernetes_rbac_escape",
                    "Public Kubernetes API surface",
                    "high",
                    "T1610",
                    &format!("Kubernetes API accessible at {} — verify anonymous access ClusterRole bindings.", p.final_url),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("kubernetes_rbac_escape", target)
    } else {
        EngineResult::ok(findings.clone(), format!("kubernetes_rbac_escape: {}", findings.len()))
    }
}
cli_wrapper!(run_kubernetes_rbac_escape, run_kubernetes_rbac_escape_result);

// ── azure_devops_attack ───────────────────────────────────────────────────────
pub async fn run_azure_devops_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let candidates = [
        format!("https://dev.azure.com/{}/_apis/projects", host),
        format!("https://{}.visualstudio.com/_apis/projects", host),
    ];
    for url in candidates.iter() {
        if let Some(p) = http_get(&client, url).await {
            if p.status == 200 && p.body.contains("value") && p.body.contains("name") {
                findings.push(finding(
                    "azure_devops_attack",
                    "Public Azure DevOps projects",
                    "high",
                    "T1195.002",
                    &format!("Azure DevOps project list public at {}.", url),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("azure_devops_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("azure_devops_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_azure_devops_attack, run_azure_devops_attack_result);

// ── gcp_privilege_attack ──────────────────────────────────────────────────────
pub async fn run_gcp_privilege_attack_result(target: &str) -> EngineResult {
    crate::gcp_attack_engine::run_gcp_attack_result(target).await
}
cli_wrapper!(run_gcp_privilege_attack, run_gcp_privilege_attack_result);

// ── terraform_state_attack ────────────────────────────────────────────────────
pub async fn run_terraform_state_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    for path in ["/terraform.tfstate", "/.terraform/terraform.tfstate", "/state/terraform.tfstate"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && p.body.contains("\"terraform_version\"") {
                findings.push(finding(
                    "terraform_state_attack",
                    "Public terraform.tfstate file",
                    "critical",
                    "T1552",
                    &format!("State file accessible at {} (HTTP 200) — secrets and resource IDs leaked.", p.final_url),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("terraform_state_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("terraform_state_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_terraform_state_attack, run_terraform_state_attack_result);

// ── cloudformation_injection ──────────────────────────────────────────────────
pub async fn run_cloudformation_injection_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    for path in ["/cloudformation.json", "/cfn-template.yaml", "/templates/main.yml"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && (p.body.contains("AWSTemplateFormatVersion") || p.body.contains("Resources:")) {
                findings.push(finding(
                    "cloudformation_injection",
                    "Public CloudFormation template",
                    "high",
                    "T1195",
                    &format!("CF template accessible at {} — review parameters and policies.", p.final_url),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("cloudformation_injection", target)
    } else {
        EngineResult::ok(findings.clone(), format!("cloudformation_injection: {}", findings.len()))
    }
}
cli_wrapper!(run_cloudformation_injection, run_cloudformation_injection_result);

// ── service_mesh_attack ───────────────────────────────────────────────────────
pub async fn run_service_mesh_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if header_value(&p.headers, "x-envoy-upstream-service-time").is_some()
            || header_value(&p.headers, "x-istio-attempt-count").is_some()
        {
            findings.push(finding(
                "service_mesh_attack",
                "Istio/Envoy header observed",
                "info",
                "T1190",
                &format!("Mesh proxy in path on {} — check mTLS enforcement and AuthorizationPolicies.", p.final_url),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("service_mesh_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("service_mesh_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_service_mesh_attack, run_service_mesh_attack_result);

// ── cloud_audit_evasion ───────────────────────────────────────────────────────
pub async fn run_cloud_audit_evasion_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if header_value(&p.headers, "x-aws-cloudtrail").is_some()
            || header_value(&p.headers, "x-trace-id").is_none()
        {
            // No trace-id is itself a weak signal.
            findings.push(finding(
                "cloud_audit_evasion",
                "Tracing headers absent",
                "low",
                "T1562.008",
                &format!("Response from {} has no X-Trace-Id / X-Request-Id — audit chain may be incomplete.", p.final_url),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("cloud_audit_evasion", target)
    } else {
        EngineResult::ok(findings.clone(), format!("cloud_audit_evasion: {}", findings.len()))
    }
}
cli_wrapper!(run_cloud_audit_evasion, run_cloud_audit_evasion_result);

// ── ecr_registry_attack ───────────────────────────────────────────────────────
pub async fn run_ecr_registry_attack_result(target: &str) -> EngineResult {
    crate::container_registry_engine::run_container_registry_result(target).await
}
cli_wrapper!(run_ecr_registry_attack, run_ecr_registry_attack_result);

// ── multi_cloud_pivot ─────────────────────────────────────────────────────────
pub async fn run_multi_cloud_pivot_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let ips = crate::engine_probes::dns_a(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    let mut providers: Vec<&str> = Vec::new();
    for ip in ips.iter() {
        if ip.starts_with("52.") || ip.starts_with("54.") || ip.starts_with("18.") {
            providers.push("AWS");
        } else if ip.starts_with("20.") || ip.starts_with("40.") {
            providers.push("Azure");
        } else if ip.starts_with("34.") || ip.starts_with("35.") {
            providers.push("GCP");
        }
    }
    if providers.len() > 1 {
        findings.push(finding(
            "multi_cloud_pivot",
            "Resolves to multiple cloud providers",
            "info",
            "T1583.003",
            &format!("{} resolves to IPs in {:?} — possible multi-cloud surface.", host, providers),
            target,
        ));
    }
    if findings.is_empty() {
        empty_ok("multi_cloud_pivot", target)
    } else {
        EngineResult::ok(findings.clone(), format!("multi_cloud_pivot: {}", findings.len()))
    }
}
cli_wrapper!(run_multi_cloud_pivot, run_multi_cloud_pivot_result);

// ── cloud_worm_propagation ────────────────────────────────────────────────────
pub async fn run_cloud_worm_propagation_result(target: &str) -> EngineResult {
    crate::serverless_attack_engine::run_serverless_attack_result(target).await
}
cli_wrapper!(run_cloud_worm_propagation, run_cloud_worm_propagation_result);

// ── serverless_injection ──────────────────────────────────────────────────────
pub async fn run_serverless_injection_result(target: &str) -> EngineResult {
    crate::serverless_attack_engine::run_serverless_attack_result(target).await
}
cli_wrapper!(run_serverless_injection, run_serverless_injection_result);

// ── cloud_data_exfil ──────────────────────────────────────────────────────────
pub async fn run_cloud_data_exfil_result(target: &str) -> EngineResult {
    run_s3_bucket_attack_result(target).await
}
cli_wrapper!(run_cloud_data_exfil, run_cloud_data_exfil_result);

// ── eks_attack ────────────────────────────────────────────────────────────────
pub async fn run_eks_attack_result(target: &str) -> EngineResult {
    run_kubernetes_rbac_escape_result(target).await
}
cli_wrapper!(run_eks_attack, run_eks_attack_result);

// ── cloud_network_attack ──────────────────────────────────────────────────────
pub async fn run_cloud_network_attack_result(target: &str) -> EngineResult {
    crate::asm_engine::run_asm_result(target).await
}
cli_wrapper!(run_cloud_network_attack, run_cloud_network_attack_result);

// ── secrets_manager_attack ────────────────────────────────────────────────────
pub async fn run_secrets_manager_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    for path in [
        "/.env",
        "/config.env",
        "/secrets.json",
        "/credentials.json",
        "/.aws/credentials",
        "/.aws/config",
        "/.git/config",
    ] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200
                && (p.body.contains("=")
                    || p.body.contains("AWS_ACCESS_KEY")
                    || p.body.contains("aws_access_key"))
            {
                findings.push(finding(
                    "secrets_manager_attack",
                    &format!("Possible secret file: {}", path),
                    "critical",
                    "T1552.001",
                    &format!("{} returned HTTP 200 — contents look like secrets/config.", p.final_url),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("secrets_manager_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("secrets_manager_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_secrets_manager_attack, run_secrets_manager_attack_result);

// ── cloud_privilege_persistence ───────────────────────────────────────────────
pub async fn run_cloud_privilege_persistence_result(target: &str) -> EngineResult {
    run_cloud_iam_escalation_result(target).await
}
cli_wrapper!(run_cloud_privilege_persistence, run_cloud_privilege_persistence_result);
