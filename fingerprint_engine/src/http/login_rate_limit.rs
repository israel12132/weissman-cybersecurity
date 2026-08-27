//! Per-IP rate limits for unauthenticated login, MFA verification, and agent enrollment POSTs.
//!
//! Login is **outcome-aware** (token bucket / sliding refill):
//! - Every login POST **reserves** a failure token on admit (`WEISSMAN_LOGIN_PER_MINUTE` /
//!   `WEISSMAN_LOGIN_BURST`, default 8/min burst 12). Concurrent stuffing cannot overshoot.
//! - Password failures (`401`) keep the reservation. Successful auth (`200` / MFA `403`)
//!   **refunds** it and spends the lighter success bucket (`WEISSMAN_LOGIN_SUCCESS_*`,
//!   default 40/min burst 48) so sequential shared-NAT tools are not 429'd by the
//!   failure budget. Parallel unknowns above the failure burst get `Retry-After` and retry.
//!   The success path is still bounded (never unlimited).
//! - Per-email lockout (`login_lockout`, 10 failures / 15 min) is unchanged.
//!
//! 429 bodies are generic (`rate_limited`) — they do not reveal whether an account exists.
//! Authenticated API traffic is **not** counted here; see `api_rate_limit`.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use super::client_ip::extract_client_ip;
use super::login_lockout::is_account_lockout_post;
use super::rate_limit_metrics;
use super::token_bucket::{
    classify_auth_status, AdmitDecision, AuthOutcome, OutcomeAwareGate, TokenBucketConfig,
};

fn login_per_minute() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::login_limit_per_minute()).unwrap_or(NonZeroU32::MIN)
}

fn login_burst() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::login_burst()).unwrap_or(NonZeroU32::MIN)
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

fn local_login_gates() -> &'static DashMap<String, Mutex<OutcomeAwareGate>> {
    static S: OnceLock<DashMap<String, Mutex<OutcomeAwareGate>>> = OnceLock::new();
    S.get_or_init(DashMap::new)
}

fn new_login_gate() -> OutcomeAwareGate {
    OutcomeAwareGate::new(
        TokenBucketConfig::per_minute(
            rate_limit_metrics::login_limit_per_minute(),
            rate_limit_metrics::login_burst(),
        ),
        TokenBucketConfig::per_minute(
            rate_limit_metrics::login_success_per_minute(),
            rate_limit_metrics::login_success_burst(),
        ),
    )
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

/// Paths that have a dedicated unauthenticated limiter and must **not** consume the
/// authenticated API budget (`api_rate_limit` / edge default bucket).
#[must_use]
pub fn uses_dedicated_unauth_limiter(method: &axum::http::Method, path: &str) -> bool {
    unauth_post_kind(method, path).is_some()
}

#[must_use]
fn unauth_post_kind(method: &axum::http::Method, path: &str) -> Option<UnauthPostKind> {
    if method != axum::http::Method::POST {
        return None;
    }
    if is_account_lockout_post(method, path) {
        return Some(UnauthPostKind::Login);
    }
    if path == "/api/agents/enroll" || path == "/api/agents/session" {
        return Some(UnauthPostKind::Enroll);
    }
    None
}

fn generic_login_429(retry_after_secs: u64, source: &str) -> Response {
    let retry_after_secs = retry_after_secs.max(1);
    let fail_limit = login_per_minute().get();
    let fail_burst = login_burst().get();
    let ok_limit = rate_limit_metrics::login_success_per_minute();
    let ok_burst = rate_limit_metrics::login_success_burst();
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "ok": false,
            "code": "rate_limited",
            "detail": format!("Login rate limit hit. Retry in {retry_after_secs}s."),
            "retry_after_seconds": retry_after_secs,
            "limit_per_minute": fail_limit,
            "burst": fail_burst,
            "success_limit_per_minute": ok_limit,
            "success_burst": ok_burst,
            "source": source,
        })),
    )
        .into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

fn enroll_429(retry_after_secs: u64, source: &str) -> Response {
    let retry_after_secs = retry_after_secs.max(1);
    let limit = enroll_per_minute().get();
    let burst = enroll_burst().get();
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "ok": false,
            "code": "rate_limited",
            "detail": format!(
                "Agent enroll rate limit hit ({burst} burst / {limit} per minute per IP). Retry in {retry_after_secs}s."
            ),
            "retry_after_seconds": retry_after_secs,
            "limit_per_minute": limit,
            "burst": burst,
            "source": source,
        })),
    )
        .into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

enum RedisAdmit {
    Allow,
    Deny { retry_after_secs: u64 },
    FallbackLocal,
    StoreDown,
}

async fn redis_login_admit(ip: &str) -> RedisAdmit {
    if !super::rate_limit_redis::is_enabled() {
        if super::rate_limit_redis::distributed_state_required() {
            return RedisAdmit::StoreDown;
        }
        return RedisAdmit::FallbackLocal;
    }
    // Reserve a failure token atomically (Lua). Refunded on success/neutral.
    match super::rate_limit_redis::login_attempt_admit(ip).await {
        super::rate_limit_redis::StrictOp::Ok(admit) if admit.allowed => RedisAdmit::Allow,
        super::rate_limit_redis::StrictOp::Ok(admit) => RedisAdmit::Deny {
            retry_after_secs: admit.retry_after_secs.max(1),
        },
        super::rate_limit_redis::StrictOp::Unavailable
            if super::rate_limit_redis::distributed_state_required() =>
        {
            RedisAdmit::StoreDown
        }
        super::rate_limit_redis::StrictOp::Unavailable => RedisAdmit::FallbackLocal,
    }
}

fn local_login_admit(ip: &str) -> AdmitDecision {
    let cell = local_login_gates()
        .entry(ip.to_string())
        .or_insert_with(|| Mutex::new(new_login_gate()));
    let mut g = cell.lock().unwrap_or_else(|p| p.into_inner());
    g.admit(Instant::now())
}

fn local_login_record(ip: &str, outcome: AuthOutcome) {
    let cell = local_login_gates()
        .entry(ip.to_string())
        .or_insert_with(|| Mutex::new(new_login_gate()));
    let mut g = cell.lock().unwrap_or_else(|p| p.into_inner());
    g.record(Instant::now(), outcome);
}

async fn redis_login_record(ip: &str, outcome: AuthOutcome) {
    match outcome {
        AuthOutcome::Failure => {
            // Failure token already reserved on admit.
        }
        AuthOutcome::Success => {
            let _ = super::rate_limit_redis::login_failure_refund(ip).await;
            let _ = super::rate_limit_redis::login_success_consume(ip).await;
        }
        AuthOutcome::Neutral => {
            let _ = super::rate_limit_redis::login_failure_refund(ip).await;
        }
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

    if kind == UnauthPostKind::Enroll {
        return enroll_rate_limit(ip, path, request, next).await;
    }

    let mut used_redis = false;
    match redis_login_admit(&ip).await {
        RedisAdmit::StoreDown => {
            tracing::error!(
                target: "rate_limit",
                client_ip = %ip,
                path = %path,
                "Redis unavailable for required distributed login rate limit (fail-closed)"
            );
            return super::rate_limit_redis::distributed_store_unavailable_response();
        }
        RedisAdmit::Deny { retry_after_secs } => {
            rate_limit_metrics::record_login_denied(&ip, &path);
            tracing::warn!(
                target: "rate_limit",
                client_ip = %ip,
                path = %path,
                retry_after_secs,
                "login rate limit exceeded (redis token bucket)"
            );
            return generic_login_429(retry_after_secs, "redis");
        }
        RedisAdmit::Allow => {
            used_redis = true;
            rate_limit_metrics::record_login_allowed(&ip);
        }
        RedisAdmit::FallbackLocal => match local_login_admit(&ip) {
            AdmitDecision::Allow => {
                rate_limit_metrics::record_login_allowed(&ip);
            }
            denied => {
                rate_limit_metrics::record_login_denied(&ip, &path);
                let retry_after_secs = denied.retry_after_secs();
                tracing::warn!(
                    target: "rate_limit",
                    client_ip = %ip,
                    path = %path,
                    retry_after_secs,
                    "login rate limit exceeded (local token bucket)"
                );
                return generic_login_429(retry_after_secs, "local");
            }
        },
    }

    let resp = next.run(request).await;
    let outcome = classify_auth_status(resp.status());
    if used_redis {
        redis_login_record(&ip, outcome).await;
    } else {
        local_login_record(&ip, outcome);
    }
    resp
}

async fn enroll_rate_limit(
    ip: String,
    path: String,
    request: Request<Body>,
    next: Next,
) -> Response {
    let limiter = enroll_limiter();
    let limit = enroll_per_minute();

    if super::rate_limit_redis::is_enabled() {
        match super::rate_limit_redis::incr_enroll_ip_strict(&ip).await {
            super::rate_limit_redis::StrictOp::Ok(count) => {
                let max = limit.get() as u64;
                if count > max {
                    rate_limit_metrics::record_login_denied(&ip, &path);
                    return enroll_429(60, "redis");
                }
                rate_limit_metrics::record_login_allowed(&ip);
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

    if let Err(neg) = limiter.check_key(&ip) {
        rate_limit_metrics::record_login_denied(&ip, &path);
        let clock = DefaultClock::default();
        let retry_after_secs = neg.wait_time_from(clock.now()).as_secs().max(1);
        return enroll_429(retry_after_secs, "local");
    }

    rate_limit_metrics::record_login_allowed(&ip);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::middleware;
    use axum::routing::post;
    use axum::Router;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU8, Ordering};
    use tower::ServiceExt;

    fn next_test_ip() -> SocketAddr {
        static OCTET: AtomicU8 = AtomicU8::new(1);
        let o = OCTET.fetch_add(1, Ordering::Relaxed).max(1);
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, o)), 41000)
    }

    async fn login_ok() -> (StatusCode, axum::Json<serde_json::Value>) {
        (StatusCode::OK, axum::Json(serde_json::json!({"ok": true})))
    }

    async fn login_fail() -> (StatusCode, axum::Json<serde_json::Value>) {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "ok": false,
                "detail": "Invalid email or password"
            })),
        )
    }

    fn app_ok() -> Router {
        Router::new()
            .route("/api/login", post(login_ok))
            .layer(middleware::from_fn(login_rate_limit_middleware))
    }

    fn app_fail() -> Router {
        Router::new()
            .route("/api/login", post(login_fail))
            .layer(middleware::from_fn(login_rate_limit_middleware))
    }

    fn login_req(peer: SocketAddr) -> Request<Body> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/api/login")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        req
    }

    #[test]
    fn login_and_mfa_use_login_limiter_enroll_is_separate() {
        assert!(is_login_post(&Method::POST, "/api/login"));
        assert!(is_login_post(&Method::POST, "/api/auth/mfa/verify"));
        assert!(!is_login_post(&Method::GET, "/api/login"));
        assert!(!is_login_post(&Method::POST, "/api/clients"));
        assert!(uses_dedicated_unauth_limiter(
            &Method::POST,
            "/api/agents/enroll"
        ));
        assert!(!uses_dedicated_unauth_limiter(
            &Method::POST,
            "/api/clients"
        ));
    }

    #[tokio::test]
    async fn failed_logins_lock_with_retry_after() {
        let app = app_fail();
        let peer = next_test_ip();
        let burst = rate_limit_metrics::login_burst() as usize;
        for i in 0..burst {
            let resp = app.clone().oneshot(login_req(peer)).await.unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "failure {i} within burst must not 429"
            );
        }
        let blocked = app.clone().oneshot(login_req(peer)).await.unwrap();
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(blocked.headers().get("Retry-After").is_some());
        let body = axum::body::to_bytes(blocked.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "rate_limited");
        let detail = json["detail"].as_str().unwrap_or("").to_ascii_lowercase();
        assert!(!detail.contains("user"));
        assert!(!detail.contains("email"));
    }

    #[tokio::test]
    async fn successful_logins_from_same_ip_allowed_past_failure_burst() {
        let app = app_ok();
        let peer = next_test_ip();
        let past_failure = (rate_limit_metrics::login_burst() as usize) + 8;
        for i in 0..past_failure {
            let resp = app.clone().oneshot(login_req(peer)).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "success {i} from shared IP must not 429"
            );
        }
    }

    #[tokio::test]
    async fn success_path_still_bounded() {
        let app = app_ok();
        let peer = next_test_ip();
        let burst = rate_limit_metrics::login_success_burst() as usize;
        for _ in 0..burst {
            let resp = app.clone().oneshot(login_req(peer)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let blocked = app.clone().oneshot(login_req(peer)).await.unwrap();
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(blocked.headers().get("Retry-After").is_some());
    }

    #[tokio::test]
    async fn concurrent_failed_logins_cannot_overshoot_failure_burst() {
        let app = app_fail();
        let peer = next_test_ip();
        let burst = rate_limit_metrics::login_burst() as usize;
        let extra = 8usize;
        let futs: Vec<_> = (0..burst + extra)
            .map(|_| app.clone().oneshot(login_req(peer)))
            .collect();
        let results = futures::future::join_all(futs).await;
        let mut unauthorized = 0usize;
        let mut limited = 0usize;
        for r in results {
            let resp = r.unwrap();
            match resp.status() {
                StatusCode::UNAUTHORIZED => unauthorized += 1,
                StatusCode::TOO_MANY_REQUESTS => {
                    limited += 1;
                    assert!(resp.headers().get("Retry-After").is_some());
                }
                other => panic!("unexpected status {other}"),
            }
        }
        assert_eq!(
            unauthorized, burst,
            "concurrent stuffing must not exceed failure burst"
        );
        assert_eq!(limited, extra);
    }
}
