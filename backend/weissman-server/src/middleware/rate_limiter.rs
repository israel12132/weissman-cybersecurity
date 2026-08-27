//! Multi-tier edge rate limits: dedicated buckets for signup / Paddle webhook, default for API.
//!
//! Login (`POST /api/login`, `POST /api/auth/mfa/verify`) is **not** pre-charged here.
//! Outcome-aware token buckets live in `fingerprint_engine::http::login_rate_limit` so
//! password failures stay strict while successful auth from a shared NAT is lighter.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
struct IpKey(IpAddr);

fn nz_u32(name: &str, def: u32, min: u32, max: u32) -> NonZeroU32 {
    let n: u32 = std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(def)
        .clamp(min, max);
    NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN)
}

fn limiter_signup() -> Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>> {
    static L: OnceLock<Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>>> =
        OnceLock::new();
    L.get_or_init(|| {
        let per_min = nz_u32("WEISSMAN_SIGNUP_PER_MINUTE", 4, 1, 30);
        let burst = nz_u32("WEISSMAN_SIGNUP_BURST", 6, 1, 60);
        let q = Quota::per_minute(per_min).allow_burst(burst);
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

fn limiter_paddle() -> Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>> {
    static L: OnceLock<Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>>> =
        OnceLock::new();
    L.get_or_init(|| {
        let per_min = nz_u32("WEISSMAN_PADDLE_WEBHOOK_PER_MINUTE", 120, 30, 6000);
        let burst = nz_u32("WEISSMAN_PADDLE_WEBHOOK_BURST", 240, 60, 12000);
        let q = Quota::per_minute(per_min).allow_burst(burst);
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

fn limiter_default() -> Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>> {
    static L: OnceLock<Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>>> =
        OnceLock::new();
    L.get_or_init(|| {
        let per_sec = nz_u32("WEISSMAN_RATE_LIMIT_PER_SEC", 30, 5, 500);
        let burst = nz_u32("WEISSMAN_RATE_LIMIT_BURST", 60, 10, 2000);
        let q = Quota::per_second(per_sec).allow_burst(burst);
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

#[must_use]
fn is_default_limited_api(path: &str) -> bool {
    path.starts_with("/api/") && path != "/api/health"
}

#[must_use]
fn is_login_delegated(method: &str, path: &str) -> bool {
    method == "POST"
        && matches!(
            path,
            "/api/login" | "/api/auth/mfa/verify" | "/api/agents/enroll" | "/api/agents/session"
        )
}

fn client_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)?;
    match fingerprint_engine::http::extract_client_ip(req.headers(), peer).parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) => Some(peer.ip()),
    }
}

fn check_limiter(
    limiter: &RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>,
    key: &IpKey,
) -> Option<u64> {
    match limiter.check_key(key) {
        Ok(()) => None,
        Err(neg) => {
            let clock = DefaultClock::default();
            Some(neg.wait_time_from(clock.now()).as_secs().max(1))
        }
    }
}

fn edge_429(retry_after_secs: u64) -> Response {
    let retry_after_secs = retry_after_secs.max(1);
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "ok": false,
            "code": "rate_limited",
            "detail": "rate limit exceeded",
            "retry_after_seconds": retry_after_secs,
        })),
    )
        .into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

pub async fn edge_multi_rate_limit_middleware(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let Some(ip) = client_ip(&request) else {
        tracing::warn!(target: "rate_limit", "missing ConnectInfo; skipping edge rate limit");
        return next.run(request).await;
    };
    let key = IpKey(ip);
    let ip_str = ip.to_string();
    if is_login_delegated(method.as_str(), path.as_str()) {
        return next.run(request).await;
    }
    let retry_after = match (method.as_str(), path.as_str()) {
        ("POST", "/api/onboarding/register") | ("POST", "/api/auth/signup") => {
            check_limiter(&limiter_signup(), &key)
        }
        ("POST", "/api/webhooks/paddle") => check_limiter(&limiter_paddle(), &key),
        _ if is_default_limited_api(&path) => {
            if let Some(secs) = check_limiter(&limiter_default(), &key) {
                fingerprint_engine::http::rate_limit_metrics::record_api_denied(&ip_str);
                Some(secs)
            } else {
                fingerprint_engine::http::rate_limit_metrics::record_api_allowed(&ip_str);
                None
            }
        }
        _ => None,
    };
    if let Some(retry_after_secs) = retry_after {
        tracing::warn!(
            target: "rate_limit",
            %path,
            client_ip = %ip,
            retry_after_secs,
            "edge rate limit exceeded"
        );
        return edge_429(retry_after_secs);
    }
    next.run(request).await
}

pub fn apply_global_rate_limit(router: axum::Router) -> axum::Router {
    router.layer(axum::middleware::from_fn(edge_multi_rate_limit_middleware))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_spa_assets_are_exempt_from_default_limiter() {
        for p in [
            "/command-center/assets/CloudPostureCommandCenter-Bv4HCP5O.js",
            "/command-center/",
            "/command-center/login",
            "/api/health",
            "/ws",
        ] {
            assert!(!is_default_limited_api(p), "{p} must be exempt");
        }
    }

    #[test]
    fn api_surface_is_default_limited() {
        for p in ["/api/clients", "/api/findings", "/api/rate-limits/status"] {
            assert!(is_default_limited_api(p), "{p} must be rate limited");
        }
    }

    #[test]
    fn login_class_posts_are_delegated_not_edge_precharged() {
        assert!(is_login_delegated("POST", "/api/login"));
        assert!(is_login_delegated("POST", "/api/auth/mfa/verify"));
        assert!(is_login_delegated("POST", "/api/agents/enroll"));
        assert!(!is_login_delegated("GET", "/api/login"));
        assert!(!is_login_delegated("POST", "/api/clients"));
    }

    #[test]
    fn edge_429_sets_retry_after() {
        let resp = edge_429(7);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok()),
            Some("7")
        );
    }

    #[test]
    fn nz_u32_clamps_within_bounds() {
        let k = "WEISSMAN_TEST_NZ_A";
        std::env::remove_var(k);
        assert_eq!(nz_u32(k, 10, 2, 60).get(), 10);
        std::env::set_var(k, "1");
        assert_eq!(nz_u32(k, 10, 5, 60).get(), 5);
        std::env::set_var(k, "9999");
        assert_eq!(nz_u32(k, 10, 5, 60).get(), 60);
        std::env::set_var(k, "25");
        assert_eq!(nz_u32(k, 10, 5, 60).get(), 25);
        std::env::remove_var(k);
    }

    #[test]
    fn nz_u32_never_zero_even_if_min_zero() {
        let k = "WEISSMAN_TEST_NZ_ZERO";
        std::env::set_var(k, "0");
        assert_eq!(nz_u32(k, 0, 0, 10).get(), 1);
        std::env::remove_var(k);
    }

    #[test]
    fn client_ip_uses_socket_peer_without_forwarding_headers() {
        let peer = SocketAddr::from(([203, 0, 113, 9], 51000));
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(client_ip(&req), Some(IpAddr::from([203, 0, 113, 9])));
    }

    #[test]
    fn client_ip_none_without_connect_info() {
        let req = Request::builder().body(()).unwrap();
        assert_eq!(client_ip(&req), None);
    }
}
