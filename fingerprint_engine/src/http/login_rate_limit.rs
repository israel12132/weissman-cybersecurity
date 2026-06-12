//! Per-IP rate limits for unauthenticated login, MFA verification, and agent enrollment POSTs.

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

use super::client_ip::extract_client_ip;
use super::login_lockout::is_account_lockout_post;
use super::rate_limit_metrics;

fn login_per_minute() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::login_limit_per_minute()).unwrap_or(NonZeroU32::MIN)
}

fn login_burst() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::login_burst()).unwrap_or(NonZeroU32::MIN)
}

fn login_limiter() -> Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>> {
    static LIM: OnceLock<Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>> =
        OnceLock::new();
    LIM.get_or_init(|| {
        let q = Quota::per_minute(login_per_minute()).allow_burst(login_burst());
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

fn enroll_per_minute() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::enroll_limit_per_minute()).unwrap_or(NonZeroU32::MIN)
}

fn enroll_burst() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::enroll_burst()).unwrap_or(NonZeroU32::MIN)
}

fn enroll_limiter() -> Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>> {
    static LIM: OnceLock<Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>> =
        OnceLock::new();
    LIM.get_or_init(|| {
        let q = Quota::per_minute(enroll_per_minute()).allow_burst(enroll_burst());
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnauthPostKind {
    Login,
    Enroll,
}

#[must_use]
pub fn is_login_post(method: &axum::http::Method, path: &str) -> bool {
    unauth_post_kind(method, path) == Some(UnauthPostKind::Login)
}

#[must_use]
fn unauth_post_kind(method: &axum::http::Method, path: &str) -> Option<UnauthPostKind> {
    if method != axum::http::Method::POST {
        return None;
    }
    if is_account_lockout_post(method, path) {
        return Some(UnauthPostKind::Login);
    }
    if path == "/api/agents/enroll" {
        return Some(UnauthPostKind::Enroll);
    }
    None
}

pub async fn login_rate_limit_middleware(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let Some(kind) = unauth_post_kind(&method, &path) else {
        return next.run(request).await;
    };

    let ip = extract_client_ip(request.headers(), peer);
    let (limiter, limit, burst, label) = match kind {
        UnauthPostKind::Login => (login_limiter(), login_per_minute(), login_burst(), "Login"),
        UnauthPostKind::Enroll => (
            enroll_limiter(),
            enroll_per_minute(),
            enroll_burst(),
            "Agent enroll",
        ),
    };

    if super::rate_limit_redis::is_enabled() {
        let redis_count = match kind {
            UnauthPostKind::Login => super::rate_limit_redis::incr_login_ip(&ip).await,
            UnauthPostKind::Enroll => super::rate_limit_redis::incr_enroll_ip(&ip).await,
        };
        if let Some(count) = redis_count {
            let max = limit.get() as u64;
            if count > max {
                rate_limit_metrics::record_login_denied(&ip, &path);
                let retry_after_secs = 60u64;
                tracing::warn!(
                    target: "rate_limit",
                    client_ip = %ip,
                    path = %path,
                    count,
                    limit = max,
                    kind = label,
                    "unauthenticated POST rate limit exceeded (redis)"
                );
                let mut resp = (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(serde_json::json!({
                        "ok": false,
                        "code": "rate_limited",
                        "detail": format!(
                            "{label} rate limit hit ({burst} burst / {limit} per minute per IP). Retry in {retry_after_secs}s."
                        ),
                        "retry_after_seconds": retry_after_secs,
                        "limit_per_minute": limit.get(),
                        "burst": burst.get(),
                        "source": "redis",
                    })),
                )
                    .into_response();
                if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                    resp.headers_mut().insert("Retry-After", v);
                }
                return resp;
            }
            rate_limit_metrics::record_login_allowed(&ip);
            return next.run(request).await;
        }
    }

    if let Err(neg) = limiter.check_key(&ip) {
        rate_limit_metrics::record_login_denied(&ip, &path);
        let clock = DefaultClock::default();
        let retry_after_secs = neg.wait_time_from(clock.now()).as_secs().max(1);
        let limit = limit.get();
        let burst = burst.get();
        tracing::warn!(
            target: "rate_limit",
            client_ip = %ip,
            path = %path,
            retry_after_secs,
            limit,
            burst,
            kind = label,
            "unauthenticated POST rate limit exceeded"
        );
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "ok": false,
                "code": "rate_limited",
                "detail": format!(
                    "{label} rate limit hit ({burst} burst / {limit} per minute per IP). Retry in {retry_after_secs}s."
                ),
                "retry_after_seconds": retry_after_secs,
                "limit_per_minute": limit,
                "burst": burst,
            })),
        )
            .into_response();
        if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
            resp.headers_mut().insert("Retry-After", v);
        }
        return resp;
    }

    rate_limit_metrics::record_login_allowed(&ip);
    next.run(request).await
}
