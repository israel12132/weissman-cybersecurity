//! Per-tenant rate limits for scan / engine enqueue POSTs (after JWT auth).

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

use crate::auth_jwt::AuthContext;

use super::rate_limit_metrics;

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

/// Retry-After hint (seconds) advertised when the platform sheds scan intake. A conservative
/// value: clients back off briefly and re-try; if the platform is still shedding they get 503
/// again. Sized in the ballpark of the recovery shed TTL so a single retry usually lands healthy.
const LOAD_SHED_RETRY_AFTER_SECS: u64 = 15;

/// Pure admission decision: shed a request only when it is a scan-trigger POST **and** the platform
/// is actively shedding load. Extracted for unit-testing without an axum request.
#[must_use]
pub fn should_shed_scan(is_scan_post: bool, load_shed_active: bool) -> bool {
    is_scan_post && load_shed_active
}

/// 503 Service Unavailable + `Retry-After` for platform load-shed. Distinct from the per-tenant
/// 429 (`rate_limited`): 503/`load_shed` means the *server* is temporarily protecting itself, not
/// that this tenant exceeded a quota — so clients (and dashboards) can tell the two apart.
fn load_shed_response() -> Response {
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({
            "ok": false,
            "code": "load_shed",
            "detail": format!(
                "The platform is temporarily shedding load to recover. Retry in \
                 {LOAD_SHED_RETRY_AFTER_SECS}s."
            ),
            "retry_after_seconds": LOAD_SHED_RETRY_AFTER_SECS,
            "source": "self_healing",
        })),
    )
        .into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&LOAD_SHED_RETRY_AFTER_SECS.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
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

    // Platform self-healing load-shed — applies BEFORE per-tenant limits and even before
    // AuthContext extraction, because it is a platform-wide protection. When the recovery engine
    // has engaged `shed_load` (genuine critical saturation: DB pool exhausted or async backlog past
    // its critical threshold), reject NEW heavy scan intake with 503 + Retry-After so the platform
    // can drain and recover instead of piling on more work. No-op unless self-heal recovery is
    // enabled AND actively shedding, and it auto-clears when the fault passes (TTL).
    if should_shed_scan(true, crate::self_heal_recovery::load_shed_active()) {
        metrics::counter!("weissman_self_heal_scan_shed_total").increment(1);
        tracing::warn!(
            target: "self_heal",
            path = %path,
            "shedding scan intake: platform load-shed engaged by self-healing recovery"
        );
        return load_shed_response();
    }

    let Some(ctx) = request.extensions().get::<AuthContext>().cloned() else {
        return next.run(request).await;
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn is_scan_trigger_post_matches_known_scan_routes() {
        assert!(is_scan_trigger_post(
            &Method::POST,
            "/api/command-center/scan"
        ));
        assert!(is_scan_trigger_post(&Method::POST, "/api/ai-redteam/run"));
        // Suffix-matched, tenant-prefixed routes still count.
        assert!(is_scan_trigger_post(
            &Method::POST,
            "/api/tenant/42/cloud-scan/run"
        ));
        // Wrong method or non-scan path must not gate.
        assert!(!is_scan_trigger_post(
            &Method::GET,
            "/api/command-center/scan"
        ));
        assert!(!is_scan_trigger_post(&Method::POST, "/api/health"));
    }

    #[test]
    fn shed_only_when_scan_post_and_platform_shedding() {
        assert!(should_shed_scan(true, true)); // scan POST while shedding ⇒ shed
        assert!(!should_shed_scan(true, false)); // healthy platform ⇒ allow
        assert!(!should_shed_scan(false, true)); // non-scan request ⇒ never shed here
        assert!(!should_shed_scan(false, false));
    }

    #[test]
    fn load_shed_response_is_503_with_retry_after() {
        let resp = load_shed_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let ra = resp
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        assert_eq!(ra, Some(LOAD_SHED_RETRY_AFTER_SECS));
    }
}
