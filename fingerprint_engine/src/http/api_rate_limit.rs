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

/// Redis fixed-window cap. Must match governor `allow_burst`, not just refill,
/// or a live E2E from 127.0.0.1 429s at 30 req/s while in-process still has 60 burst.
fn window_cap() -> u64 {
    per_sec().get().max(burst().get()) as u64
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

pub async fn api_rate_limit_middleware(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if !is_api_path(path) {
        return next.run(request).await;
    }

    let ip = extract_client_ip(request.headers(), peer);
    let refill = per_sec().get() as u64;
    let limit = window_cap();

    if super::rate_limit_redis::is_enabled() {
        match super::rate_limit_redis::incr_api_ip_strict(&ip).await {
            super::rate_limit_redis::StrictOp::Ok(count) => {
                if count > limit {
                    rate_limit_metrics::record_api_denied(&ip);
                    let retry_after_secs = 1u64;
                    tracing::warn!(
                        target: "rate_limit",
                        client_ip = %ip,
                        path = %path,
                        count,
                        limit,
                        "API rate limit exceeded (redis)"
                    );
                    let mut resp = (
                        StatusCode::TOO_MANY_REQUESTS,
                        axum::Json(serde_json::json!({
                            "ok": false,
                            "code": "rate_limited",
                            "detail": format!(
                                "API rate limit hit ({limit} burst / {refill} per second per IP). Retry in {retry_after_secs}s."
                            ),
                            "retry_after_seconds": retry_after_secs,
                            "limit_per_second": refill,
                            "burst": limit,
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
                rate_limit_metrics::record_api_allowed(&ip);
                return next.run(request).await;
            }
            super::rate_limit_redis::StrictOp::Unavailable
                if super::rate_limit_redis::distributed_state_required() =>
            {
                tracing::error!(
                    target: "rate_limit",
                    client_ip = %ip,
                    path = %path,
                    "Redis unavailable for required API rate limit (fail-closed)"
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
            "REDIS_URL required but Redis API rate limiter not initialized (fail-closed)"
        );
        return super::rate_limit_redis::distributed_store_unavailable_response();
    }

    if let Err(neg) = limiter().check_key(&ip) {
        rate_limit_metrics::record_api_denied(&ip);
        let clock = DefaultClock::default();
        let retry_after_secs = neg.wait_time_from(clock.now()).as_secs().max(1);
        tracing::warn!(
            target: "rate_limit",
            client_ip = %ip,
            path = %path,
            retry_after_secs,
            limit,
            refill,
            "API rate limit exceeded"
        );
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "ok": false,
                "code": "rate_limited",
                "detail": format!(
                    "API rate limit hit ({limit} burst / {refill} per second per IP). Retry in {retry_after_secs}s."
                ),
                "retry_after_seconds": retry_after_secs,
                "limit_per_second": refill,
                "burst": limit,
            })),
        )
            .into_response();
        if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
            resp.headers_mut().insert("Retry-After", v);
        }
        return resp;
    }

    rate_limit_metrics::record_api_allowed(&ip);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_window_cap_is_max_of_refill_and_burst() {
        let cap = window_cap();
        let refill = per_sec().get() as u64;
        let burst = burst().get() as u64;
        assert_eq!(cap, refill.max(burst));
        assert!(
            cap >= burst,
            "Redis must not 429 inside the governor burst window (cap={cap} burst={burst})"
        );
    }
}
