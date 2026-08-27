//! Per-IP rate limits for authenticated API traffic (after JWT auth).
//!
//! Login / MFA / agent enroll POSTs are excluded — they have a dedicated limiter in
//! `login_rate_limit`. Mixing them into this bucket made a NAT's `/api/login` traffic
//! 429 the Command Center's JWT poll burst.

use super::client_ip::extract_client_ip;
use super::login_rate_limit::uses_dedicated_unauth_limiter;
use super::rate_limit_metrics;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};

fn per_sec() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::api_limit_per_sec()).unwrap_or(NonZeroU32::MIN)
}

fn burst() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::api_burst()).unwrap_or(NonZeroU32::MIN)
}

fn limiter() -> Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>> {
    static LIM: OnceLock<Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>> =
        OnceLock::new();
    LIM.get_or_init(|| {
        let q = Quota::per_second(per_sec()).allow_burst(burst());
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

#[must_use]
pub fn is_authenticated_api_limited(method: &axum::http::Method, path: &str) -> bool {
    path.starts_with("/api/")
        && path != "/api/health"
        && !uses_dedicated_unauth_limiter(method, path)
}

fn api_429(retry_after_secs: u64, source: &str) -> Response {
    let retry_after_secs = retry_after_secs.max(1);
    let limit = per_sec().get() as u64;
    let burst_n = burst().get() as u64;
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "ok": false,
            "code": "rate_limited",
            "detail": format!(
                "API rate limit hit ({burst_n} burst / {limit} per second per IP). Retry in {retry_after_secs}s."
            ),
            "retry_after_seconds": retry_after_secs,
            "limit_per_second": limit,
            "burst": burst_n,
            "source": source,
        })),
    )
        .into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

pub async fn api_rate_limit_middleware(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if !is_authenticated_api_limited(&method, &path) {
        return next.run(request).await;
    }

    let ip = extract_client_ip(request.headers(), peer);
    let limit = per_sec().get() as u64;

    if super::rate_limit_redis::is_enabled() {
        match super::rate_limit_redis::api_token_consume(&ip).await {
            super::rate_limit_redis::StrictOp::Ok(admit) => {
                if !admit.allowed {
                    rate_limit_metrics::record_api_denied(&ip);
                    return api_429(admit.retry_after_secs, "redis");
                }
                rate_limit_metrics::record_api_allowed(&ip);
                return next.run(request).await;
            }
            super::rate_limit_redis::StrictOp::Unavailable
                if super::rate_limit_redis::distributed_state_required() =>
            {
                return super::rate_limit_redis::distributed_store_unavailable_response();
            }
            super::rate_limit_redis::StrictOp::Unavailable => {}
        }
    } else if super::rate_limit_redis::distributed_state_required() {
        return super::rate_limit_redis::distributed_store_unavailable_response();
    }

    if let Err(neg) = limiter().check_key(&ip) {
        rate_limit_metrics::record_api_denied(&ip);
        let clock = DefaultClock::default();
        let retry_after_secs = neg.wait_time_from(clock.now()).as_secs().max(1);
        let _ = limit;
        return api_429(retry_after_secs, "local");
    }

    rate_limit_metrics::record_api_allowed(&ip);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::middleware;
    use axum::routing::{get, post};
    use axum::Router;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU16, Ordering};
    use tower::ServiceExt;

    fn next_test_ip() -> SocketAddr {
        static PORT_OCTET: AtomicU16 = AtomicU16::new(1);
        let n = PORT_OCTET.fetch_add(1, Ordering::Relaxed);
        let b = n.to_be_bytes();
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, b[1].max(1))), 42000)
    }

    async fn ok() -> (StatusCode, axum::Json<serde_json::Value>) {
        (StatusCode::OK, axum::Json(serde_json::json!({"ok": true})))
    }

    fn api_app() -> Router {
        Router::new()
            .route("/api/clients", get(ok))
            .route("/api/login", post(ok))
            .route("/api/health", get(ok))
            .layer(middleware::from_fn(api_rate_limit_middleware))
    }

    fn req(method: Method, path: &str, peer: SocketAddr) -> Request<Body> {
        let mut r = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(peer));
        r
    }

    #[test]
    fn login_paths_are_not_authenticated_api_limited() {
        assert!(!is_authenticated_api_limited(&Method::POST, "/api/login"));
        assert!(!is_authenticated_api_limited(
            &Method::POST,
            "/api/auth/mfa/verify"
        ));
        assert!(!is_authenticated_api_limited(
            &Method::POST,
            "/api/agents/enroll"
        ));
        assert!(!is_authenticated_api_limited(&Method::GET, "/api/health"));
        assert!(is_authenticated_api_limited(&Method::GET, "/api/clients"));
    }

    #[tokio::test]
    async fn jwt_burst_polls_pass_at_documented_budget() {
        let app = api_app();
        let peer = next_test_ip();
        let budget = rate_limit_metrics::api_burst() as usize;
        for i in 0..budget {
            let resp = app
                .clone()
                .oneshot(req(Method::GET, "/api/clients", peer))
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "JWT poll {i}/{budget} must be within documented burst"
            );
        }
    }

    #[tokio::test]
    async fn login_posts_do_not_consume_api_budget() {
        let app = api_app();
        let peer = next_test_ip();
        let budget = rate_limit_metrics::api_burst() as usize;
        for _ in 0..budget {
            let resp = app
                .clone()
                .oneshot(req(Method::POST, "/api/login", peer))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        for i in 0..budget {
            let resp = app
                .clone()
                .oneshot(req(Method::GET, "/api/clients", peer))
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "poll {i} after login burst must still be within API budget"
            );
        }
    }
}
