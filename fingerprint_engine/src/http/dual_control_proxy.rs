//! Dual-control headers are accepted only from trusted reverse-proxy peers.
//!
//! Nginx stripping `X-Weissman-Destructive-Confirm` / `X-Weissman-Dual-Approve` is not
//! enough: an attacker on the overlay network (pod, SSRF to :8000) can speak to Axum
//! directly and inject those headers. Decode/accept them only when `ConnectInfo` peer IP
//! is in `WEISSMAN_TRUST_PROXY_CIDRS`. Any other peer presenting the headers is 403.

use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use weissman_core::tls_policy::is_production_environment;

const DUAL_CONTROL_HEADERS: &[&str] =
    &["x-weissman-destructive-confirm", "x-weissman-dual-approve"];

pub fn request_has_dual_control_headers(headers: &HeaderMap) -> bool {
    DUAL_CONTROL_HEADERS.iter().any(|name| {
        headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| !s.trim().is_empty())
    })
}

pub fn trusted_proxy_cidrs() -> Vec<IpNetwork> {
    std::env::var("WEISSMAN_TRUST_PROXY_CIDRS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .filter_map(|part| part.trim().parse::<IpNetwork>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// Peer may present dual-control headers.
///
/// Production: CIDR allow-list is mandatory and the TCP peer must match it.
/// Non-production: loopback is allowed when the list is empty (local labs).
pub fn peer_may_present_dual_control(peer: IpAddr) -> bool {
    let cidrs = trusted_proxy_cidrs();
    if !cidrs.is_empty() {
        return cidrs.iter().any(|c| c.contains(peer));
    }
    if is_production_environment() {
        return false;
    }
    match peer {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn dual_control_forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "ok": false,
            "code": "dual_control_untrusted_peer",
            "detail": "X-Weissman-Destructive-Confirm / X-Weissman-Dual-Approve are accepted only from WEISSMAN_TRUST_PROXY_CIDRS peers",
        })),
    )
        .into_response()
}

/// Drop dual-control headers that did not arrive from a trusted proxy peer.
pub async fn dual_control_proxy_guard(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let headers = request.headers();
    if !request_has_dual_control_headers(headers) {
        return next.run(request).await;
    }
    let Some(ConnectInfo(peer)) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
    else {
        return dual_control_forbidden();
    };
    if !peer_may_present_dual_control(peer.ip()) {
        tracing::warn!(
            target: "security_hardening",
            peer = %peer.ip(),
            "rejected dual-control headers from untrusted peer (direct :8000 / SSRF bypass)"
        );
        return dual_control_forbidden();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn production_without_cidr_denies_everyone() {
        with_env(
            &[
                ("WEISSMAN_ENV", Some("production")),
                ("WEISSMAN_TRUST_PROXY_CIDRS", None),
            ],
            || {
                assert!(!peer_may_present_dual_control("127.0.0.1".parse().unwrap()));
                assert!(!peer_may_present_dual_control("10.0.0.8".parse().unwrap()));
            },
        );
    }

    #[test]
    fn cidr_allowlist_accepts_nginx_rejects_pod() {
        with_env(
            &[
                ("WEISSMAN_ENV", Some("production")),
                ("WEISSMAN_TRUST_PROXY_CIDRS", Some("10.0.0.0/8")),
            ],
            || {
                assert!(peer_may_present_dual_control("10.0.0.8".parse().unwrap()));
                assert!(!peer_may_present_dual_control(
                    "198.51.100.22".parse().unwrap()
                ));
                assert!(!peer_may_present_dual_control("127.0.0.1".parse().unwrap()));
            },
        );
    }

    #[test]
    fn non_prod_loopback_ok_when_cidr_unset() {
        with_env(
            &[
                ("WEISSMAN_ENV", Some("development")),
                ("WEISSMAN_TRUST_PROXY_CIDRS", None),
            ],
            || {
                assert!(peer_may_present_dual_control("127.0.0.1".parse().unwrap()));
                assert!(peer_may_present_dual_control("::1".parse().unwrap()));
                assert!(!peer_may_present_dual_control("10.1.2.3".parse().unwrap()));
            },
        );
    }

    #[test]
    fn garbage_cidr_is_empty_allowlist() {
        with_env(
            &[
                ("WEISSMAN_ENV", Some("production")),
                ("WEISSMAN_TRUST_PROXY_CIDRS", Some("not-a-cidr,  ")),
            ],
            || {
                assert!(!peer_may_present_dual_control("10.0.0.8".parse().unwrap()));
                assert!(!peer_may_present_dual_control("127.0.0.1".parse().unwrap()));
            },
        );
    }
}
