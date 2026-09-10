//! Multi-tier edge rate limits: strict buckets for login / signup / Paddle webhook, default for API.
//!
//! Env: `WEISSMAN_RATE_LIMIT_PER_SEC`, `WEISSMAN_RATE_LIMIT_BURST` (default API).
//! Login: `WEISSMAN_LOGIN_PER_MINUTE` (default 8), `WEISSMAN_LOGIN_BURST` (default 12).
//! Signup: `WEISSMAN_SIGNUP_PER_MINUTE` (default 4), `WEISSMAN_SIGNUP_BURST` (default 6).
//! Paddle webhook: `WEISSMAN_PADDLE_WEBHOOK_PER_MINUTE` (default 120), burst 240.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
struct IpKey(IpAddr);

fn nz_u32(name: &str, def: u32, min: u32, max: u32) -> NonZeroU32 {
    let n: u32 = std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(def)
        .clamp(min, max);
    NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN)
}

fn limiter_login() -> Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>> {
    static L: OnceLock<Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>>> =
        OnceLock::new();
    L.get_or_init(|| {
        let per_min = nz_u32("WEISSMAN_LOGIN_PER_MINUTE", 8, 2, 60);
        let burst = nz_u32("WEISSMAN_LOGIN_BURST", 12, 2, 120);
        let q = Quota::per_minute(per_min).allow_burst(burst);
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

fn limiter_signup() -> Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>> {
    static L: OnceLock<Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>>> =
        OnceLock::new();
    L.get_or_init(|| {
        let per_min = nz_u32("WEISSMAN_SIGNUP_PER_MINUTE", 4, 1, 30);
        let burst = nz_u32("WEISSMAN_SIGNUP_BURST", 6, 1, 60);
        let q = Quota::per_minute(per_min).allow_burst(burst);
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

fn limiter_paddle() -> Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>> {
    static L: OnceLock<Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>>> =
        OnceLock::new();
    L.get_or_init(|| {
        let per_min = nz_u32("WEISSMAN_PADDLE_WEBHOOK_PER_MINUTE", 120, 30, 6000);
        let burst = nz_u32("WEISSMAN_PADDLE_WEBHOOK_BURST", 240, 60, 12000);
        let q = Quota::per_minute(per_min).allow_burst(burst);
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

fn limiter_default() -> Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>> {
    static L: OnceLock<Arc<RateLimiter<IpKey, DefaultKeyedStateStore<IpKey>, DefaultClock>>> =
        OnceLock::new();
    L.get_or_init(|| {
        let per_sec = nz_u32("WEISSMAN_RATE_LIMIT_PER_SEC", 30, 5, 500);
        let burst = nz_u32("WEISSMAN_RATE_LIMIT_BURST", 60, 10, 2000);
        let q = Quota::per_second(per_sec).allow_burst(burst);
        Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

/// The default per-IP edge limiter guards the general **API** surface only. It must exclude:
/// - `/api/health` — liveness/readiness probes (load balancer, CI health-wait) must never be
///   throttled, or a probe burst self-inflicts a 429 and marks the stack unhealthy; and
/// - every non-`/api/` path — the static SPA bundle (`/command-center/assets/*` hashed chunks),
///   the SPA shell, legal static pages, favicon/manifest, the service worker, and WS upgrades.
///   These are cheap, cacheable and non-sensitive, and a code-split front end legitimately
///   fetches dozens of chunks in a single navigation burst. Throttling them 429s the app's own
///   JavaScript, so `import()` fails and the route renders its "This view crashed" boundary — a
///   real, user-facing outage on first load, not just a test artifact. Edge throttling of static
///   files belongs at the CDN / reverse proxy, not the API rate limiter.
#[must_use]
fn is_default_limited_api(path: &str) -> bool {
    path.starts_with("/api/") && path != "/api/health"
}

fn client_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)?;
    // Proxy-aware keying: behind nginx/Caddy the socket peer is the reverse proxy, so
    // keying on it alone collapses every client into ONE bucket — defeating per-IP
    // login/signup throttles and turning them into a shared-bucket DoS. Reuse the same
    // trusted-proxy XFF/X-Real-IP resolution the inner API/login limiters use.
    // (Distributed, cross-replica enforcement is handled by the inner
    // `fingerprint_engine::http::api_rate_limit`/`rate_limit_redis` layer.)
    match fingerprint_engine::http::extract_client_ip(req.headers(), peer).parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) => Some(peer.ip()),
    }
}

pub async fn edge_multi_rate_limit_middleware(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let Some(ip) = client_ip(&request) else {
        tracing::warn!(target: "rate_limit", "missing ConnectInfo; skipping edge rate limit");
        return next.run(request).await;
    };
    let key = IpKey(ip);
    let ip_str = ip.to_string();
    let limited = match (method.as_str(), path.as_str()) {
        ("POST", "/api/login") => {
            if limiter_login().check_key(&key).is_err() {
                fingerprint_engine::http::rate_limit_metrics::record_login_denied(
                    &ip_str,
                    "/api/login",
                );
                true
            } else {
                fingerprint_engine::http::rate_limit_metrics::record_login_allowed(&ip_str);
                false
            }
        }
        ("POST", "/api/onboarding/register")
        | ("POST", "/api/auth/signup")
        | ("POST", "/api/public/demo-request") => limiter_signup().check_key(&key).is_err(),
        ("POST", "/api/webhooks/paddle") => limiter_paddle().check_key(&key).is_err(),
        // Default per-IP limiter — API surface only. Static SPA assets, the SPA shell, legal
        // pages, health probes and WS upgrades fall through to the exempt arm below so the
        // app's own code-split bundle is never 429'd (see `is_default_limited_api`).
        _ if is_default_limited_api(&path) => {
            if limiter_default().check_key(&key).is_err() {
                fingerprint_engine::http::rate_limit_metrics::record_api_denied(&ip_str);
                true
            } else {
                fingerprint_engine::http::rate_limit_metrics::record_api_allowed(&ip_str);
                false
            }
        }
        // Non-API, non-sensitive traffic (static assets, SPA shell, legal, health, WS): exempt.
        _ => false,
    };
    if limited {
        tracing::warn!(
            target: "rate_limit",
            %path,
            client_ip = %ip,
            "edge rate limit exceeded"
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "ok": false,
                "detail": "rate limit exceeded",
            })),
        )
            .into_response();
    }
    next.run(request).await
}

pub fn apply_global_rate_limit(router: axum::Router) -> axum::Router {
    router.layer(axum::middleware::from_fn(edge_multi_rate_limit_middleware))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_spa_assets_are_exempt_from_default_limiter() {
        // A code-split SPA fetches these in bursts on navigation; throttling them 429s the app's
        // own JavaScript and crashes the route. They must never hit the default API limiter.
        for p in [
            "/command-center/assets/CloudPostureCommandCenter-Bv4HCP5O.js",
            "/command-center/assets/index-DjceKEF_.js",
            "/command-center/assets/style-CKZedZbh.css",
            "/command-center/",
            "/command-center/operations",
            "/command-center/login",
            "/tactical-chunk-sw.js",
            "/favicon.ico",
            "/signup.html",
            "/",
            "/dashboard",
            "/api/health",
            "/ws",
        ] {
            assert!(!is_default_limited_api(p), "{p} must be exempt");
        }
    }

    #[test]
    fn api_surface_is_default_limited() {
        for p in [
            "/api/clients",
            "/api/findings",
            "/api/jobs/123",
            "/api/command-center/scan",
            "/api/rate-limits/status",
        ] {
            assert!(is_default_limited_api(p), "{p} must be rate limited");
        }
    }

    #[test]
    fn nz_u32_clamps_within_bounds() {
        // Unique env var per assertion avoids cross-test races on shared names.
        let k = "WEISSMAN_TEST_NZ_A";
        std::env::remove_var(k);
        // Unset -> default (already within bounds).
        assert_eq!(nz_u32(k, 10, 2, 60).get(), 10);
        // Below min -> min.
        std::env::set_var(k, "1");
        assert_eq!(nz_u32(k, 10, 5, 60).get(), 5);
        // Above max -> max.
        std::env::set_var(k, "9999");
        assert_eq!(nz_u32(k, 10, 5, 60).get(), 60);
        // In range -> honored.
        std::env::set_var(k, "25");
        assert_eq!(nz_u32(k, 10, 5, 60).get(), 25);
        std::env::remove_var(k);
    }

    #[test]
    fn nz_u32_never_zero_even_if_min_zero() {
        let k = "WEISSMAN_TEST_NZ_ZERO";
        std::env::set_var(k, "0");
        // clamp allows 0, but NonZeroU32 fallback keeps it >= 1.
        assert_eq!(nz_u32(k, 0, 0, 10).get(), 1);
        std::env::remove_var(k);
    }

    #[test]
    fn client_ip_uses_socket_peer_without_forwarding_headers() {
        let peer = SocketAddr::from(([203, 0, 113, 9], 51000));
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(client_ip(&req), Some(IpAddr::from([203, 0, 113, 9])));
    }

    #[test]
    fn client_ip_none_without_connect_info() {
        let req = Request::builder().body(()).unwrap();
        assert_eq!(client_ip(&req), None);
    }
}
