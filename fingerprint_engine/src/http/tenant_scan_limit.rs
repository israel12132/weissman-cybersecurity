//! Per-tenant rate limits for scan / engine enqueue POSTs (after JWT auth).

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};

use crate::auth_jwt::AuthContext;

fn per_tenant_scan_per_minute() -> NonZeroU32 {
    let n: u32 = std::env::var("WEISSMAN_TENANT_SCAN_POSTS_PER_MINUTE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(24)
        .max(4)
        .min(240);
    NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN)
}

fn tenant_scan_burst() -> NonZeroU32 {
    let n: u32 = std::env::var("WEISSMAN_TENANT_SCAN_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12)
        .max(2)
        .min(120);
    NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN)
}

fn scan_limiter() -> Arc<RateLimiter<i64, DefaultKeyedStateStore<i64>, DefaultClock>> {
    static LIM: OnceLock<Arc<RateLimiter<i64, DefaultKeyedStateStore<i64>, DefaultClock>>> =
        OnceLock::new();
    LIM.get_or_init(|| {
        let q = Quota::per_minute(per_tenant_scan_per_minute()).allow_burst(tenant_scan_burst());
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

#[must_use]
pub fn is_scan_trigger_post(method: &axum::http::Method, path: &str) -> bool {
    if method != axum::http::Method::POST {
        return false;
    }
    matches!(
        path,
        "/api/command-center/scan"
            | "/api/onboarding/launch-scan"
            | "/api/scan/run-all"
            | "/api/command-center/deep-fuzz"
            | "/api/timing-scan/run"
            | "/api/ai-redteam/run"
            | "/api/threat-intel/run"
            | "/api/pipeline-scan/run"
            | "/api/poe-scan/run"
            | "/api/threat-ingest/run"
            | "/api/payload-sync/run"
    ) || path.ends_with("/cloud-scan/run")
        || path.ends_with("/swarm/run")
        || path.ends_with("/llm-fuzz/run")
        || path.ends_with("/deception/generate")
}

pub async fn tenant_scan_rate_limit_middleware(
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if !is_scan_trigger_post(&method, &path) {
        return next.run(request).await;
    }
    let Some(ctx) = request.extensions().get::<AuthContext>().cloned() else {
        return next.run(request).await;
    };
    if scan_limiter().check_key(&ctx.tenant_id).is_err() {
        tracing::warn!(
            target: "rate_limit",
            tenant_id = ctx.tenant_id,
            path = %path,
            "tenant scan POST rate limit exceeded"
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "ok": false,
                "detail": "scan rate limit exceeded for this tenant; retry shortly",
            })),
        )
            .into_response();
    }
    next.run(request).await
}
