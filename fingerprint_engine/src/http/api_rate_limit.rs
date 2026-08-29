//! Per-IP rate limits for authenticated API traffic (after JWT auth).

use super::client_ip::extract_client_ip;
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
fn is_api_path(path: &str) -> bool {
    path.starts_with("/api/") && path != "/api/health"
}

/// Login / refresh already sit in the dedicated unauth login bucket (8/min).
/// Counting them in the 30/s API Redis bucket makes a parallel UI crawl's
/// session recovery compete with authenticated traffic.
#[must_use]
fn counts_toward_api_bucket(method: &axum::http::Method, path: &str) -> bool {
    is_api_path(path) && !super::login_rate_limit::is_login_post(method, path)
}

pub async fn api_rate_limit_middleware(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if !counts_toward_api_bucket(request.method(), path) {
        return next.run(request).await;
    }

    let ip = extract_client_ip(request.headers(), peer);
    let limit = per_sec().get() as u64;
    let path = path.to_string();

    if let Err(neg) = limiter().check_key(&ip) {
        let clock = DefaultClock::default();
        let retry_after_secs = neg.wait_time_from(clock.now()).as_secs().max(1);
        return deny_api(&ip, &path, limit, retry_after_secs, "local");
    }

    let redis = super::rate_limit_redis::is_enabled();
    if !redis && super::rate_limit_redis::distributed_state_required() {
        tracing::error!(
            target: "rate_limit",
            client_ip = %ip,
            path = %path,
            "REDIS_URL required but Redis API rate limiter not initialized (fail-closed)"
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
            "Redis sync unhealthy for required API rate limit (fail-closed)"
        );
        return super::rate_limit_redis::distributed_store_unavailable_response();
    }
    if redis && super::rate_limit_redis::distributed_ip_denied("api", &ip) {
        return deny_api(&ip, &path, limit, 1, "redis");
    }
    if redis {
        super::rate_limit_redis::spawn_incr_api_ip(ip.clone(), limit);
    }

    rate_limit_metrics::record_api_allowed(&ip);
    next.run(request).await
}

fn deny_api(ip: &str, path: &str, limit: u64, retry_after_secs: u64, source: &str) -> Response {
    rate_limit_metrics::record_api_denied(ip);
    tracing::warn!(
        target: "rate_limit",
        client_ip = %ip,
        path = %path,
        retry_after_secs,
        limit,
        source,
        "API rate limit exceeded"
    );
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "ok": false,
            "code": "rate_limited",
            "detail": format!(
                "API rate limit hit ({limit} per second per IP). Retry in {retry_after_secs}s."
            ),
            "retry_after_seconds": retry_after_secs,
            "limit_per_second": limit,
            "source": source,
        })),
    )
        .into_response();
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
    fn login_and_refresh_skip_the_api_bucket() {
        assert!(!counts_toward_api_bucket(&Method::POST, "/api/login"));
        assert!(!counts_toward_api_bucket(
            &Method::POST,
            "/api/auth/refresh"
        ));
        assert!(counts_toward_api_bucket(&Method::GET, "/api/clients"));
        assert!(counts_toward_api_bucket(&Method::GET, "/api/billing/usage"));
        assert!(!counts_toward_api_bucket(&Method::GET, "/api/health"));
    }

    #[test]
    fn local_governor_precedes_async_redis_on_request_path() {
        let src = include_str!("api_rate_limit.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production source");
        let local = prod
            .find("limiter().check_key")
            .expect("in-process governor check");
        let redis = prod
            .find("rate_limit_redis::is_enabled")
            .expect("redis branch");
        assert!(
            local < redis,
            "in-process governor must run before any Redis I/O"
        );
        assert!(
            !prod.contains("incr_api_ip_strict"),
            "request path must not await Redis INCR; spawn async token-bucket instead"
        );
        assert!(
            prod.contains("spawn_incr_api_ip"),
            "local allow must fire-and-forget a Redis token-bucket update"
        );
    }
}
