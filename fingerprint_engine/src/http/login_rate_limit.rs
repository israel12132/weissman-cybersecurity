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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    // Refresh hits the dedicated weissman_auth pool (bcrypt / token lookup) the
    // same way login does. Rate-limit it in the Login bucket before any Postgres
    // checkout so a spray cannot exhaust the auth pool.
    if path == "/api/auth/refresh" {
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

    // In-process governor first — no Redis, no auth-pool checkout. Under a
    // password-spray the weissman_auth pool must not be the first choke point.
    if let Err(neg) = limiter.check_key(&ip) {
        let clock = DefaultClock::default();
        let retry_after_secs = neg.wait_time_from(clock.now()).as_secs().max(1);
        return deny_unauth_post(&ip, &path, label, limit, burst, "local", retry_after_secs);
    }

    let redis = super::rate_limit_redis::is_enabled();
    if !redis && super::rate_limit_redis::distributed_state_required() {
        tracing::error!(
            target: "rate_limit",
            client_ip = %ip,
            path = %path,
            kind = label,
            "REDIS_URL required but Redis rate limiter not initialized (fail-closed)"
        );
        return super::rate_limit_redis::distributed_store_unavailable_response();
    }
    if redis
        && super::rate_limit_redis::distributed_state_required()
        && super::rate_limit_redis::redis_sync_unhealthy()
    {
        tracing::error!(
            target: "rate_limit",
            client_ip = %ip,
            path = %path,
            kind = label,
            "Redis sync unhealthy for required distributed rate limit (fail-closed)"
        );
        return super::rate_limit_redis::distributed_store_unavailable_response();
    }
    let bucket = match kind {
        UnauthPostKind::Login => "login",
        UnauthPostKind::Enroll => "enroll",
    };
    if redis && super::rate_limit_redis::distributed_ip_denied(bucket, &ip) {
        return deny_unauth_post(&ip, &path, label, limit, burst, "redis", 60);
    }
    // Async Redis token-bucket — never await on the request path. Global IP
    // state converges in milliseconds across replicas; local governor already ran.
    if redis {
        let max = limit.get() as u64;
        match kind {
            UnauthPostKind::Login => super::rate_limit_redis::spawn_incr_login_ip(ip.clone(), max),
            UnauthPostKind::Enroll => {
                super::rate_limit_redis::spawn_incr_enroll_ip(ip.clone(), max)
            }
        }
    }

    rate_limit_metrics::record_login_allowed(&ip);
    next.run(request).await
}

fn deny_unauth_post(
    ip: &str,
    path: &str,
    label: &str,
    limit: NonZeroU32,
    burst: NonZeroU32,
    source: &str,
    retry_after_secs: u64,
) -> Response {
    rate_limit_metrics::record_login_denied(ip, path);
    let limit_n = limit.get();
    let burst_n = burst.get();
    tracing::warn!(
        target: "rate_limit",
        client_ip = %ip,
        path = %path,
        retry_after_secs,
        limit = limit_n,
        burst = burst_n,
        kind = label,
        source,
        "unauthenticated POST rate limit exceeded"
    );
    let mut body = serde_json::json!({
        "ok": false,
        "code": "rate_limited",
        "detail": format!(
            "{label} rate limit hit ({burst_n} burst / {limit_n} per minute per IP). Retry in {retry_after_secs}s."
        ),
        "retry_after_seconds": retry_after_secs,
        "limit_per_minute": limit_n,
        "burst": burst_n,
    });
    if source == "redis" {
        body["source"] = serde_json::json!("redis");
    }
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn login_bucket_covers_auth_pool_posts() {
        assert!(is_login_post(&Method::POST, "/api/login"));
        assert!(is_login_post(&Method::POST, "/api/auth/mfa/verify"));
        assert!(is_login_post(&Method::POST, "/api/auth/refresh"));
        assert!(!is_login_post(&Method::GET, "/api/login"));
        assert!(!is_login_post(&Method::POST, "/api/agents/enroll"));
    }

    #[test]
    fn enroll_bucket_covers_agent_credential_posts() {
        assert_eq!(
            unauth_post_kind(&Method::POST, "/api/agents/enroll"),
            Some(UnauthPostKind::Enroll)
        );
        assert_eq!(
            unauth_post_kind(&Method::POST, "/api/agents/session"),
            Some(UnauthPostKind::Enroll)
        );
        assert_eq!(unauth_post_kind(&Method::POST, "/api/findings"), None);
    }

    #[test]
    fn local_governor_is_checked_before_redis_in_source() {
        let src = include_str!("login_rate_limit.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production source");
        let local = prod
            .find("limiter.check_key")
            .expect("in-process governor check");
        let redis = prod
            .find("rate_limit_redis::is_enabled")
            .expect("redis branch");
        assert!(
            local < redis,
            "in-process governor must run before any Redis I/O"
        );
        assert!(
            !prod.contains("incr_login_ip_strict"),
            "request path must not await Redis INCR; spawn async token-bucket instead"
        );
        assert!(
            prod.contains("spawn_incr_login_ip"),
            "local allow must fire-and-forget a Redis token-bucket update"
        );
    }
}
