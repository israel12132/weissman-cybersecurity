//! Dual-control headers are accepted only with a cryptographic proxy signature.
//!
//! IP/CIDR allow-lists are **not** a dual-control trust signal. Kubernetes recycles
//! pod IPs: a crashed gateway pod's address can land on a neighbor workload that then
//! speaks to Axum `:8000` and injects `X-Weissman-Destructive-Confirm`. Nginx stripping
//! is also insufficient (direct bind / SSRF).
//!
//! Required header: `X-Weissman-Proxy-Signature: t=<unix>,v1=<hmac-sha256-hex>`
//! HMAC key: `WEISSMAN_PROXY_SIGNING_SECRET` (Vault / k8s secret, ≥32 chars in production).
//! Canonical: `v1:{t}\n{METHOD}\n{path}\n{confirm}\n{approve}`.

use axum::{
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use weissman_core::tls_policy::is_production_environment;

const DUAL_CONTROL_HEADERS: &[&str] =
    &["x-weissman-destructive-confirm", "x-weissman-dual-approve"];
const PROXY_SIG_HEADER: &str = "x-weissman-proxy-signature";
pub const MAX_PROXY_SIG_SKEW_SECS: i64 = 90;

type HmacSha256 = Hmac<Sha256>;

pub fn request_has_dual_control_headers(headers: &HeaderMap) -> bool {
    DUAL_CONTROL_HEADERS.iter().any(|name| {
        headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| !s.trim().is_empty())
    })
}

pub fn proxy_signing_secret() -> String {
    std::env::var("WEISSMAN_PROXY_SIGNING_SECRET").unwrap_or_default()
}

fn header_or_empty(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Canonical bytes the gateway HMAC-SHA256s. Stable — nginx njs / Vault signer must match.
pub fn canonical_proxy_payload(
    ts: i64,
    method: &str,
    path: &str,
    confirm: &str,
    approve: &str,
) -> String {
    format!("v1:{ts}\n{method}\n{path}\n{confirm}\n{approve}")
}

pub fn hmac_sha256_hex(secret: &str, payload: &str) -> Option<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProxySignature {
    pub ts: i64,
    pub v1_hex: String,
}

pub fn parse_proxy_signature(raw: &str) -> Option<ParsedProxySignature> {
    let mut ts = None;
    let mut v1 = None;
    for part in raw.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("t=") {
            ts = rest.trim().parse().ok();
        } else if let Some(rest) = part.strip_prefix("v1=") {
            v1 = Some(rest.trim().to_string());
        }
    }
    Some(ParsedProxySignature {
        ts: ts?,
        v1_hex: v1.filter(|s| !s.is_empty())?,
    })
}

pub fn format_proxy_signature(ts: i64, v1_hex: &str) -> String {
    format!("t={ts},v1={v1_hex}")
}

/// True when the dual-control headers are bound by a fresh HMAC from the gateway secret.
/// Peer IP is deliberately unused — pod IP reuse must not authorize destructive headers.
pub fn proxy_signature_authorizes(
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    now_unix: i64,
) -> bool {
    let secret = proxy_signing_secret();
    if secret.trim().len() < 32 {
        return false;
    }
    let raw = header_or_empty(headers, PROXY_SIG_HEADER);
    let Some(parsed) = parse_proxy_signature(&raw) else {
        return false;
    };
    if (now_unix - parsed.ts).abs() > MAX_PROXY_SIG_SKEW_SECS {
        return false;
    }
    let confirm = header_or_empty(headers, "x-weissman-destructive-confirm");
    let approve = header_or_empty(headers, "x-weissman-dual-approve");
    let canonical = canonical_proxy_payload(
        parsed.ts,
        method.as_str(),
        path,
        confirm.trim(),
        approve.trim(),
    );
    let Some(expected_hex) = hmac_sha256_hex(&secret, &canonical) else {
        return false;
    };
    crate::security_hardening::constant_time_hmac_hex_eq(
        &hex::decode(&expected_hex).unwrap_or_default(),
        &parsed.v1_hex,
    )
}

fn dual_control_forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "ok": false,
            "code": "dual_control_untrusted_peer",
            "detail": "X-Weissman-Destructive-Confirm / X-Weissman-Dual-Approve require a valid X-Weissman-Proxy-Signature (HMAC of t+method+path+headers with WEISSMAN_PROXY_SIGNING_SECRET). IP/CIDR is not a dual-control trust signal.",
        })),
    )
        .into_response()
}

/// Drop dual-control headers that are not bound by the gateway HMAC.
pub async fn dual_control_proxy_guard(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let headers = request.headers();
    if !request_has_dual_control_headers(headers) {
        return next.run(request).await;
    }
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let now = chrono::Utc::now().timestamp();
    if !proxy_signature_authorizes(headers, &method, &path, now) {
        tracing::warn!(
            target: "security_hardening",
            method = %method,
            path = %path,
            production = is_production_environment(),
            "rejected dual-control headers without a valid X-Weissman-Proxy-Signature"
        );
        return dual_control_forbidden();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(set: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let prev: Vec<(String, Option<String>)> = set
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in set {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        f();
        for (k, v) in prev {
            match v {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }

    const SECRET: &str = "proxy-signing-secret-must-be-32b!!";

    fn signed_headers(ts: i64, method: &str, path: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-weissman-destructive-confirm",
            HeaderValue::from_static("confirm-secret"),
        );
        headers.insert(
            "x-weissman-dual-approve",
            HeaderValue::from_static("approve-secret"),
        );
        let canonical =
            canonical_proxy_payload(ts, method, path, "confirm-secret", "approve-secret");
        let hex = hmac_sha256_hex(SECRET, &canonical).expect("hmac");
        headers.insert(
            PROXY_SIG_HEADER,
            format_proxy_signature(ts, &hex).parse().unwrap(),
        );
        headers
    }

    #[test]
    fn empty_headers_are_not_dual_control() {
        let headers = HeaderMap::new();
        assert!(!request_has_dual_control_headers(&headers));
    }

    #[test]
    fn whitespace_header_is_not_dual_control() {
        let mut headers = HeaderMap::new();
        headers.insert("x-weissman-destructive-confirm", "   ".parse().unwrap());
        assert!(!request_has_dual_control_headers(&headers));
    }

    #[test]
    fn confirm_header_counts() {
        let mut headers = HeaderMap::new();
        headers.insert("x-weissman-destructive-confirm", "secret".parse().unwrap());
        assert!(request_has_dual_control_headers(&headers));
    }

    #[test]
    fn cidr_or_pod_ip_never_authorizes_dual_control() {
        with_env(
            &[
                ("WEISSMAN_ENV", Some("production")),
                ("WEISSMAN_TRUST_PROXY_CIDRS", Some("10.0.0.0/8")),
                ("WEISSMAN_PROXY_SIGNING_SECRET", None),
            ],
            || {
                let mut headers = HeaderMap::new();
                headers.insert("x-weissman-destructive-confirm", "x".parse().unwrap());
                assert!(
                    !proxy_signature_authorizes(
                        &headers,
                        &Method::POST,
                        "/api/containment/execute",
                        1_700_000_000
                    ),
                    "recycled gateway pod IP / CIDR match must not authorize dual-control"
                );
            },
        );
    }

    #[test]
    fn valid_hmac_authorizes_regardless_of_peer_ip() {
        with_env(&[("WEISSMAN_PROXY_SIGNING_SECRET", Some(SECRET))], || {
            let ts = 1_700_000_000;
            let headers = signed_headers(ts, "POST", "/api/containment/execute");
            assert!(proxy_signature_authorizes(
                &headers,
                &Method::POST,
                "/api/containment/execute",
                ts
            ));
        });
    }

    #[test]
    fn expired_signature_is_rejected() {
        with_env(&[("WEISSMAN_PROXY_SIGNING_SECRET", Some(SECRET))], || {
            let ts = 1_700_000_000;
            let headers = signed_headers(ts, "POST", "/api/containment/execute");
            assert!(!proxy_signature_authorizes(
                &headers,
                &Method::POST,
                "/api/containment/execute",
                ts + MAX_PROXY_SIG_SKEW_SECS + 1
            ));
        });
    }

    #[test]
    fn tampered_path_is_rejected() {
        with_env(&[("WEISSMAN_PROXY_SIGNING_SECRET", Some(SECRET))], || {
            let ts = 1_700_000_000;
            let headers = signed_headers(ts, "POST", "/api/containment/execute");
            assert!(!proxy_signature_authorizes(
                &headers,
                &Method::POST,
                "/api/containment/execute-other",
                ts
            ));
        });
    }

    #[test]
    fn short_secret_never_authorizes() {
        with_env(
            &[("WEISSMAN_PROXY_SIGNING_SECRET", Some("too-short"))],
            || {
                let ts = 1_700_000_000;
                let mut headers = HeaderMap::new();
                headers.insert("x-weissman-destructive-confirm", "x".parse().unwrap());
                headers.insert(
                    PROXY_SIG_HEADER,
                    "t=1700000000,v1=deadbeef".parse().unwrap(),
                );
                assert!(!proxy_signature_authorizes(
                    &headers,
                    &Method::POST,
                    "/api/x",
                    ts
                ));
            },
        );
    }
}
