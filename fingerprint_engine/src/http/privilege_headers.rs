//! Reject dual-control / handshake headers unless the TCP peer is a trusted reverse proxy.
//!
//! nginx blanks these on public locations. Command Center sends the same secrets in the JSON
//! body. A sibling pod that hits Axum on :8000 must not be able to inject the headers even
//! if it learned the secret values from a leaked env — the TCP peer has to be the proxy.
//! Client identity still uses `WEISSMAN_TRUST_PROXY_HEADERS` / CIDRs; this gate uses
//! `ConnectInfo` only (never `X-Forwarded-For`).

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};

pub const DESTRUCTIVE_CONFIRM_HEADER: &str = "x-weissman-destructive-confirm";
pub const DUAL_APPROVE_HEADER: &str = "x-weissman-dual-approve";
pub const LLM_HANDSHAKE_HEADER: &str = "x-weissman-llm-handshake";

const PRIVILEGE_HEADERS: &[&str] = &[
    DESTRUCTIVE_CONFIRM_HEADER,
    DUAL_APPROVE_HEADER,
    LLM_HANDSHAKE_HEADER,
];

#[must_use]
pub fn privilege_admin_headers_present(headers: &HeaderMap) -> bool {
    PRIVILEGE_HEADERS.iter().any(|name| {
        headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some()
    })
}

fn parse_cidrs(raw: &str) -> Vec<IpNetwork> {
    raw.split(',')
        .filter_map(|part| part.trim().parse::<IpNetwork>().ok())
        .collect()
}

fn privilege_header_trusted_cidrs() -> Vec<IpNetwork> {
    if let Ok(raw) = std::env::var("WEISSMAN_PRIVILEGE_HEADER_TRUSTED_CIDRS") {
        let parsed = parse_cidrs(&raw);
        if !parsed.is_empty() {
            return parsed;
        }
    }
    if let Ok(raw) = std::env::var("WEISSMAN_TRUST_PROXY_CIDRS") {
        return parse_cidrs(&raw);
    }
    Vec::new()
}

/// TCP peer may present privilege headers.
///
/// Production: fail closed unless the peer is in the proxy CIDR allow-list
/// (`WEISSMAN_PRIVILEGE_HEADER_TRUSTED_CIDRS`, else `WEISSMAN_TRUST_PROXY_CIDRS`).
/// An empty list means headers are never accepted (JSON body tokens still work).
///
/// Non-production: loopback only. RFC1918 is **not** trusted — that is the
/// Kubernetes sibling-pod path the architect called out.
#[must_use]
pub fn privilege_header_peer_allowed(peer: IpAddr) -> bool {
    let cidrs = privilege_header_trusted_cidrs();
    if !cidrs.is_empty() {
        return cidrs.iter().any(|c| c.contains(peer));
    }
    if weissman_core::tls_policy::is_production_environment() {
        return false;
    }
    peer.is_loopback()
}

pub async fn privilege_header_proxy_middleware(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if privilege_admin_headers_present(request.headers())
        && !privilege_header_peer_allowed(peer.ip())
    {
        tracing::warn!(
            target: "privilege_headers",
            peer = %peer.ip(),
            path = %request.uri().path(),
            "rejected privilege headers from untrusted TCP peer"
        );
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "ok": false,
                "code": "privilege_header_proxy_required",
                "detail": "Dual-control headers are accepted only from trusted reverse proxies. Send JSON destructive_confirm / dual_approve instead.",
            })),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<F: FnOnce()>(set: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let prev: Vec<(String, Option<String>)> = set
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in set {
            if let Some(v) = v {
                std::env::set_var(k, v);
            } else {
                std::env::remove_var(k);
            }
        }
        f();
        for (k, v) in prev {
            if let Some(v) = v {
                std::env::set_var(&k, v);
            } else {
                std::env::remove_var(&k);
            }
        }
    }

    #[test]
    fn empty_headers_are_not_privilege() {
        assert!(!privilege_admin_headers_present(&HeaderMap::new()));
        let mut h = HeaderMap::new();
        h.insert(DESTRUCTIVE_CONFIRM_HEADER, "".parse().unwrap());
        assert!(!privilege_admin_headers_present(&h));
    }

    #[test]
    fn nonempty_header_is_privilege() {
        let mut h = HeaderMap::new();
        h.insert(DESTRUCTIVE_CONFIRM_HEADER, "tok".parse().unwrap());
        assert!(privilege_admin_headers_present(&h));
    }

    #[test]
    fn lab_trusts_loopback_not_rfc1918() {
        with_env(
            &[
                ("WEISSMAN_PRIVILEGE_HEADER_TRUSTED_CIDRS", None),
                ("WEISSMAN_TRUST_PROXY_CIDRS", None),
                ("WEISSMAN_ENV", Some("development")),
                ("RUST_ENV", Some("development")),
                ("NODE_ENV", Some("development")),
                ("APP_ENV", Some("development")),
                ("RAILS_ENV", Some("development")),
            ],
            || {
                assert!(privilege_header_peer_allowed(IpAddr::V4(
                    Ipv4Addr::LOCALHOST
                )));
                assert!(
                    !privilege_header_peer_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
                    "sibling pod / RFC1918 must not inject dual-control headers"
                );
            },
        );
    }

    #[test]
    fn allow_list_wins() {
        with_env(
            &[
                (
                    "WEISSMAN_PRIVILEGE_HEADER_TRUSTED_CIDRS",
                    Some("10.0.0.0/8"),
                ),
                ("WEISSMAN_ENV", Some("production")),
            ],
            || {
                assert!(privilege_header_peer_allowed(IpAddr::V4(Ipv4Addr::new(
                    10, 1, 2, 3
                ))));
                assert!(!privilege_header_peer_allowed(
                    IpAddr::from_str("203.0.113.9").unwrap()
                ));
            },
        );
    }
}
