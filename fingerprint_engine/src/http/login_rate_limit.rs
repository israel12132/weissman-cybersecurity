//! Login/MFA: per-IP **failure** stuffing lockout + a high volumetric bcrypt ceiling.
//! Agent enroll/session: request-counted brute-force bucket (unchanged).
//!
//! Legitimate parallel CI / cockpit / cloud-agent logins from one NAT are successes
//! (or valid credentials) and must not 429. Credential stuffing is many *failures*.

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
use super::login_lockout::{
    check_ip_failure_status, ip_locked_response, is_account_lockout_post, LockoutStatus,
};
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
    // Both agent credential endpoints share the Enroll bucket: /session takes a bearer secret
    // and is unauthenticated, so it is brute-forceable exactly like /enroll.
    if path == "/api/agents/enroll" || path == "/api/agents/session" {
        return Some(UnauthPostKind::Enroll);
    }
    None
}

fn volume_limited_response(
    ip: &str,
    path: &str,
    label: &str,
    retry_after_secs: u64,
    limit: u32,
    burst: u32,
    source: Option<&'static str>,
) -> Response {
    rate_limit_metrics::record_login_denied(ip, path);
    tracing::warn!(
        target: "rate_limit",
        client_ip = %ip,
        path = %path,
        retry_after_secs,
        limit,
        burst,
        kind = label,
        source = source.unwrap_or("governor"),
        "unauthenticated POST volume ceiling exceeded"
    );
    let mut body = serde_json::json!({
        "ok": false,
        "code": "rate_limited",
        "detail": format!(
            "{label} volume ceiling hit ({burst} burst / {limit} per minute per IP). Retry in {retry_after_secs}s."
        ),
        "retry_after_seconds": retry_after_secs,
        "limit_per_minute": limit,
        "burst": burst,
    });
    if let Some(src) = source {
        body["source"] = serde_json::json!(src);
    }
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

async fn deny_if_ip_stuffing_locked(ip: &str) -> Option<Response> {
    match check_ip_failure_status(ip).await {
        LockoutStatus::Locked(secs) => {
            rate_limit_metrics::record_login_denied(ip, "/api/login");
            tracing::warn!(
                target: "rate_limit",
                client_ip = %ip,
                retry_after_secs = secs,
                "login stuffing lockout (failed attempts from this IP)"
            );
            Some(ip_locked_response(secs))
        }
        LockoutStatus::DistributedStoreUnavailable => {
            tracing::error!(
                target: "rate_limit",
                client_ip = %ip,
                "Redis unavailable for required distributed login stuffing lockout (fail-closed)"
            );
            Some(super::rate_limit_redis::distributed_store_unavailable_response())
        }
        LockoutStatus::Allowed => None,
    }
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

    if kind == UnauthPostKind::Login {
        if let Some(denied) = deny_if_ip_stuffing_locked(&ip).await {
            return denied;
        }
    }

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
                    return volume_limited_response(
                        &ip,
                        &path,
                        label,
                        60,
                        limit.get(),
                        burst.get(),
                        Some("redis"),
                    );
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
        let clock = DefaultClock::default();
        let retry_after_secs = neg.wait_time_from(clock.now()).as_secs().max(1);
        return volume_limited_response(
            &ip,
            &path,
            label,
            retry_after_secs,
            limit.get(),
            burst.get(),
            None,
        );
    }

    rate_limit_metrics::record_login_allowed(&ip);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::login_lockout::{clear_ip_failures, record_ip_failure};
    use axum::extract::connect_info::MockConnectInfo;
    use axum::routing::post;
    use axum::Router;
    use tower::ServiceExt;

    fn test_ip(octet: u8) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, octet], 41000))
    }

    fn login_app(ip: SocketAddr) -> Router {
        Router::new()
            .route(
                "/api/login",
                post(|| async { (StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))) }),
            )
            .layer(axum::middleware::from_fn(login_rate_limit_middleware))
            .layer(MockConnectInfo(ip))
    }

    fn enroll_app(ip: SocketAddr) -> Router {
        Router::new()
            .route(
                "/api/agents/enroll",
                post(|| async { (StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))) }),
            )
            .layer(axum::middleware::from_fn(login_rate_limit_middleware))
            .layer(MockConnectInfo(ip))
    }

    async fn post_path(app: &Router, path: &str) -> StatusCode {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        resp.status()
    }

    #[test]
    fn login_and_mfa_are_login_posts_enroll_is_not() {
        assert!(is_login_post(&axum::http::Method::POST, "/api/login"));
        assert!(is_login_post(
            &axum::http::Method::POST,
            "/api/auth/mfa/verify"
        ));
        assert!(!is_login_post(&axum::http::Method::GET, "/api/login"));
        assert!(!is_login_post(
            &axum::http::Method::POST,
            "/api/agents/enroll"
        ));
        assert_eq!(
            unauth_post_kind(&axum::http::Method::POST, "/api/agents/enroll"),
            Some(UnauthPostKind::Enroll)
        );
    }

    #[tokio::test]
    async fn parallel_valid_logins_from_one_ip_are_not_429d() {
        let ip = test_ip(70);
        clear_ip_failures(&ip.ip().to_string()).await;
        let app = login_app(ip);
        const N: usize = 32;
        let mut futs = Vec::with_capacity(N);
        for _ in 0..N {
            let app = app.clone();
            futs.push(async move { post_path(&app, "/api/login").await });
        }
        let codes = futures::future::join_all(futs).await;
        let bad: Vec<StatusCode> = codes
            .iter()
            .copied()
            .filter(|c| *c == StatusCode::TOO_MANY_REQUESTS)
            .collect();
        assert!(
            bad.is_empty(),
            "legitimate parallel logins must not 429; got {codes:?}"
        );
        assert!(codes.iter().all(|c| *c == StatusCode::OK));
    }

    #[tokio::test]
    async fn stuffing_failures_lock_the_ip() {
        let ip = test_ip(71);
        let ip_s = ip.ip().to_string();
        clear_ip_failures(&ip_s).await;
        let budget = crate::http::login_lockout::ip_fail_max();
        for _ in 0..budget {
            record_ip_failure(&ip_s).await;
        }
        let app = login_app(ip);
        let code = post_path(&app, "/api/login").await;
        assert_eq!(
            code,
            StatusCode::TOO_MANY_REQUESTS,
            "failed-login stuffing must 429 after the per-IP budget"
        );
        clear_ip_failures(&ip_s).await;
        let code = post_path(&app, "/api/login").await;
        assert_eq!(
            code,
            StatusCode::OK,
            "clearing IP failures must allow login again"
        );
    }

    #[tokio::test]
    async fn enroll_still_counts_every_request() {
        let ip = test_ip(72);
        let app = enroll_app(ip);
        let burst = enroll_burst().get() as usize;
        let extra = burst + 8;
        let mut saw_429 = false;
        for _ in 0..extra {
            if post_path(&app, "/api/agents/enroll").await == StatusCode::TOO_MANY_REQUESTS {
                saw_429 = true;
                break;
            }
        }
        assert!(
            saw_429,
            "agent enroll must remain request-counted brute-force defense"
        );
    }
}
