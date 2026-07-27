//! Per-tenant rate limits for scan / engine enqueue POSTs (after JWT auth).

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};

use crate::auth_jwt::AuthContext;
use crate::http::serve::AppState;
use crate::tenant_quota::{self, QuotaWindow};

use super::rate_limit_metrics;

/// Plan-based monthly scan quota is opt-in (default off) so behaviour is unchanged unless an
/// operator enables it. When on, per-tenant overrides come from `system_configs`
/// (`scans_monthly_quota`); this env is the fallback ceiling (`0` = unlimited).
fn scan_quota_enabled() -> bool {
    std::env::var("WEISSMAN_SCAN_QUOTA_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn default_monthly_scan_quota() -> u64 {
    std::env::var("WEISSMAN_DEFAULT_MONTHLY_SCAN_QUOTA")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn per_tenant_scan_per_minute() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::scan_limit_per_minute()).unwrap_or(NonZeroU32::MIN)
}

fn tenant_scan_burst() -> NonZeroU32 {
    NonZeroU32::new(rate_limit_metrics::scan_burst()).unwrap_or(NonZeroU32::MIN)
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
    State(state): State<Arc<AppState>>,
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

    // Plan-based monthly scan quota (opt-in). A tenant over its monthly budget is rejected
    // outright, independent of the short-horizon per-minute limiter below. Fail-open on a
    // quota-store error so a transient DB blip never blocks legitimate scans.
    if scan_quota_enabled() {
        match tenant_quota::enforce(
            state.app_pool.as_ref(),
            ctx.tenant_id,
            "scans",
            QuotaWindow::Monthly,
            default_monthly_scan_quota(),
        )
        .await
        {
            Ok(d) if !d.allowed => {
                let retry = d
                    .reset_at_unix
                    .saturating_sub(tenant_quota::now_unix())
                    .max(1);
                rate_limit_metrics::record_scan_denied(ctx.tenant_id, &path);
                tracing::warn!(
                    target: "rate_limit",
                    tenant_id = ctx.tenant_id,
                    used = d.used,
                    limit = d.limit,
                    "monthly scan quota exceeded"
                );
                let mut resp = (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(serde_json::json!({
                        "ok": false,
                        "code": "quota_exceeded",
                        "detail": format!(
                            "Monthly scan quota reached ({} of {}). Resets in {}s.",
                            d.used, d.limit, retry
                        ),
                        "resource": "scans",
                        "window": "monthly",
                        "used": d.used,
                        "limit": d.limit,
                        "remaining": 0,
                        "reset_at_unix": d.reset_at_unix,
                        "retry_after_seconds": retry,
                    })),
                )
                    .into_response();
                if let Ok(v) = axum::http::HeaderValue::from_str(&retry.to_string()) {
                    resp.headers_mut().insert("Retry-After", v);
                }
                return resp;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(target: "rate_limit", error = %e, "scan quota check failed; allowing");
            }
        }
    }

    let limit = per_tenant_scan_per_minute().get() as u64;
    if super::rate_limit_redis::is_enabled() {
        if let Some(count) = super::rate_limit_redis::incr_tenant_scan(ctx.tenant_id).await {
            if count > limit {
                rate_limit_metrics::record_scan_denied(ctx.tenant_id, &path);
                let retry_after_secs = 60u64;
                let burst = tenant_scan_burst().get();
                tracing::warn!(
                    target: "rate_limit",
                    tenant_id = ctx.tenant_id,
                    path = %path,
                    count,
                    limit,
                    "tenant scan POST rate limit exceeded (redis)"
                );
                let mut resp = (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(serde_json::json!({
                        "ok": false,
                        "code": "rate_limited",
                        "detail": format!(
                            "Scan rate limit hit ({burst} burst / {limit} per minute per tenant). \
                             Retry in {retry_after_secs}s."
                        ),
                        "retry_after_seconds": retry_after_secs,
                        "limit_per_minute": limit,
                        "burst": burst,
                        "source": "redis",
                    })),
                )
                    .into_response();
                if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                    resp.headers_mut().insert("Retry-After", v);
                }
                return resp;
            }
            rate_limit_metrics::record_scan_allowed(ctx.tenant_id, &path);
            return next.run(request).await;
        }
    }

    if let Err(neg) = scan_limiter().check_key(&ctx.tenant_id) {
        rate_limit_metrics::record_scan_denied(ctx.tenant_id, &path);
        let clock = DefaultClock::default();
        let retry_after_secs = neg.wait_time_from(clock.now()).as_secs().max(1);
        let limit = per_tenant_scan_per_minute().get();
        let burst = tenant_scan_burst().get();
        tracing::warn!(
            target: "rate_limit",
            tenant_id = ctx.tenant_id,
            path = %path,
            retry_after_secs,
            limit,
            burst,
            "tenant scan POST rate limit exceeded"
        );
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "ok": false,
                "code": "rate_limited",
                "detail": format!(
                    "Scan rate limit hit ({burst} burst / {limit} per minute per tenant). \
                     Retry in {retry_after_secs}s, or batch your engine launches."
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
    rate_limit_metrics::record_scan_allowed(ctx.tenant_id, &path);
    next.run(request).await
}
