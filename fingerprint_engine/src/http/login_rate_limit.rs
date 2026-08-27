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

fn install_per_minute() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::install_limit_per_minute()).unwrap_or(NonZeroU32::MIN)
}

fn install_burst() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::install_burst()).unwrap_or(NonZeroU32::MIN)
}

fn install_limiter() -> Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>> {
    static LIM: OnceLock<Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>> =
        OnceLock::new();
    LIM.get_or_init(|| {
        let q = Quota::per_minute(install_per_minute()).allow_burst(install_burst());
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

fn is_install_download(method: &axum::http::Method, path: &str) -> bool {
    *method == axum::http::Method::GET
        && (path == "/install/agent.sh"
            || path == "/install/agent.ps1"
            || path.starts_with("/install/binaries/"))
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
    // Both agent credential endpoints share the Enroll bucket: /session takes a bearer secret
    // and is unauthenticated, so it is brute-forceable exactly like /enroll.
    if path == "/api/agents/enroll" || path == "/api/agents/session" {
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
    if is_install_download(&method, &path) {
        let ip = extract_client_ip(request.headers(), peer);
        let limiter = install_limiter();
        if limiter.check_key(&ip).is_err() {
            rate_limit_metrics::record_login_denied(&ip, &path);
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({
                    "ok": false,
                    "code": "rate_limited",
                    "detail": "agent installer download rate limit exceeded",
                })),
            )
                .into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str("60") {
                resp.headers_mut().insert("Retry-After", v);
            }
            return resp;
        }
        return next.run(request).await;
    }
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
            UnauthPostKind::Login => super::rate_limit_redis::incr_login_ip_strict(&ip).await,
            UnauthPostKind::Enroll => super::rate_limit_redis::incr_enroll_ip_strict(&ip).await,
        };
        match redis_count {
            super::rate_limit_redis::StrictOp::Ok(count) => {
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
                    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string())
                    {
                        resp.headers_mut().insert("Retry-After", v);
                    }
                    return resp;
                }
                rate_limit_metrics::record_login_allowed(&ip);
                return next.run(request).await;
            }
            super::rate_limit_redis::StrictOp::Unavailable
                if super::rate_limit_redis::distributed_state_required() =>
            {
                tracing::error!(
                    target: "rate_limit",
                    client_ip = %ip,
                    path = %path,
                    kind = label,
                    "Redis unavailable for required distributed rate limit (fail-closed)"
                );
                return super::rate_limit_redis::distributed_store_unavailable_response();
            }
            super::rate_limit_redis::StrictOp::Unavailable => {}
        }
    } else if super::rate_limit_redis::distributed_state_required() {
        tracing::error!(
            target: "rate_limit",
            client_ip = %ip,
            path = %path,
            kind = label,
            "REDIS_URL required but Redis rate limiter not initialized (fail-closed)"
        );
        return super::rate_limit_redis::distributed_store_unavailable_response();
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
