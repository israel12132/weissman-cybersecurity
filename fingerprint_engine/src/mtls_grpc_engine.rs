//! mTLS/gRPC Attack Engine — detects gRPC reflection, protobuf endpoints, and certificate pinning bypass risk.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
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

const GRPC_PATHS: &[&str] = &[
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/grpc.health.v1.Health/Check",
    "/grpc/",
    "/proto/",
    "/pb/",
    "/api.proto",
    "/service.proto",
];

pub async fn run_mtls_grpc_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Check if TLS is in use
    if base.starts_with("http://") {
        findings.push(json!({
            "type": "mtls_grpc",
            "title": "Target uses plain HTTP — mTLS not enforced",
            "severity": "high",
            "mitre_attack": "T1557.002",
            "description": format!(
                "Target {} operates over plain HTTP without TLS. mTLS (mutual TLS) requires TLS as a prerequisite. \
                Any gRPC services on this host are exposed without transport encryption.",
                base
            ),
            "value": base
        }));
    }

    // Check for grpc-status header (indicates gRPC traffic)
    let grpc_check = client
        .post(&base)
        .header("Content-Type", "application/grpc")
        .header("TE", "trailers")
        .body(vec![0u8; 5]) // Minimal gRPC frame
        .send()
        .await;

    if let Ok(resp) = grpc_check {
        let headers = resp.headers().clone();
        let has_grpc = headers.contains_key("grpc-status")
            || headers.contains_key("grpc-message")
            || headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.starts_with("application/grpc"))
                .unwrap_or(false);

        if has_grpc {
            findings.push(json!({
                "type": "mtls_grpc",
                "title": format!("gRPC endpoint detected at {}", base),
                "severity": "medium",
                "mitre_attack": "T1557.002",
                "description": format!(
                    "gRPC service detected at {}. Verify that gRPC reflection is disabled in production \
                    (reflection allows service enumeration) and that mTLS client certificate authentication \
                    is enforced for all service-to-service communication.",
                    base
                ),
                "value": base
            }));

            // Check if require_client_certificate is missing (mTLS bypass)
            let tls_required = headers
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if tls_required != "16" {
                // 16 = UNAUTHENTICATED
                findings.push(json!({
                    "type": "mtls_grpc",
                    "title": format!("gRPC responds without client certificate authentication: {}", base),
                    "severity": "high",
                    "mitre_attack": "T1557.002",
                    "description": format!(
                        "gRPC endpoint at {} accepted a request without a client TLS certificate (grpc-status: {}). \
                        mTLS is likely not enforced, allowing unauthorized service-to-service communication. \
                        Enable RequireClientCert in the TLS configuration.",
                        base, tls_required
                    ),
                    "value": base
                }));
            }
        }
    }

    // Probe gRPC reflection and proto endpoints
    for path in GRPC_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let resp = client
            .post(&url)
            .header("Content-Type", "application/grpc+proto")
            .header("TE", "trailers")
            .send()
            .await;

        if let Ok(r) = resp {
            let status = r.status().as_u16();
            let ct = r
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();

            if ct.contains("grpc") || status == 200 {
                let is_reflection = path.contains("reflection");
                findings.push(json!({
                    "type": "mtls_grpc",
                    "title": format!("{}: {}", if is_reflection { "gRPC reflection endpoint exposed" } else { "gRPC endpoint found" }, url),
                    "severity": if is_reflection { "high" } else { "medium" },
                    "mitre_attack": "T1557.002",
                    "description": if is_reflection {
                        format!("gRPC Server Reflection is enabled at {}. This allows attackers to enumerate all available \
                            gRPC services, methods, and protobuf schemas without authentication.", url)
                    } else {
                        format!("gRPC endpoint accessible at {} (HTTP {}). Test with grpcurl for unauthorized method invocation.", url, status)
                    },
                    "value": url
                }));
            }
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("mTLSgRPC: {} findings", findings.len()),
    )
}

pub async fn run_mtls_grpc(target: &str) {
    print_result(run_mtls_grpc_result(target).await);
}
