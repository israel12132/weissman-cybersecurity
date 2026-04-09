//! Multi-tier edge rate limits: strict buckets for login / signup / Paddle webhook, default for API.
//!
//! Env: `WEISSMAN_RATE_LIMIT_PER_SEC`, `WEISSMAN_RATE_LIMIT_BURST` (default API).
//! Login: `WEISSMAN_LOGIN_PER_MINUTE` (default 8), `WEISSMAN_LOGIN_BURST` (default 12).
//! Signup: `WEISSMAN_SIGNUP_PER_MINUTE` (default 4), `WEISSMAN_SIGNUP_BURST` (default 6).
//! Paddle webhook: `WEISSMAN_PADDLE_WEBHOOK_PER_MINUTE` (default 120), burst 240.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::DefaultClock;
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

fn limiter_login() -> Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>> {
    static L: OnceLock<Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>>> =
        OnceLock::new();
    L.get_or_init(|| {
        let per_min = nz_u32("WEISSMAN_LOGIN_PER_MINUTE", 8, 2, 60);
        let burst = nz_u32("WEISSMAN_LOGIN_BURST", 12, 2, 120);
        let q = Quota::per_minute(per_min).allow_burst(burst);
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
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

fn client_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

pub async fn edge_multi_rate_limit_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let Some(ip) = client_ip(&request) else {
        tracing::warn!(target: "rate_limit", "missing ConnectInfo; skipping edge rate limit");
        return next.run(request).await;
    };
    let key = IpKey(ip);
    let limited = match (method.as_str(), path.as_str()) {
        ("POST", "/api/login") => limiter_login().check_key(&key).is_err(),
        ("POST", "/api/onboarding/register") => limiter_signup().check_key(&key).is_err(),
        ("POST", "/api/webhooks/paddle") => limiter_paddle().check_key(&key).is_err(),
        _ => limiter_default().check_key(&key).is_err(),
    };
    if limited {
        tracing::warn!(
            target: "rate_limit",
            %path,
            client_ip = %ip,
            "edge rate limit exceeded"
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "ok": false,
                "detail": "rate limit exceeded",
            })),
        )
            .into_response();
    }
    next.run(request).await
}

pub fn apply_global_rate_limit(router: axum::Router) -> axum::Router {
    router.layer(axum::middleware::from_fn(edge_multi_rate_limit_middleware))
}
