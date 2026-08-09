//! Browser CORS for the Command Center origin. Applied only by `weissman-server` (single HTTP entrypoint).
//!
//! Set `WEISSMAN_CORS_ORIGINS` to a comma-separated list (e.g. `https://app.example.com,https://weissmancyber.com`).
//! When unset, falls back to the origin of `WEISSMAN_PUBLIC_BASE_URL`, then `https://weissmancyber.com`.

use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};

fn configured_origins() -> Vec<HeaderValue> {
    let raw = std::env::var("WEISSMAN_CORS_ORIGINS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("WEISSMAN_PUBLIC_BASE_URL")
                .ok()
                .and_then(|base| url::Url::parse(base.trim()).ok())
                .map(|u| u.origin().ascii_serialization())
        });
    let Some(raw) = raw else {
        return vec![HeaderValue::from_static("https://weissmancyber.com")];
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect()
}

pub fn apply(router: Router) -> Router {
    let origins = configured_origins();
    let allow_origin = if origins.len() == 1 {
        AllowOrigin::exact(origins[0].clone())
    } else {
        AllowOrigin::list(origins)
    };
    // tower-http forbids allow_credentials(true) with allow_headers(Any); list concrete headers.
    let cors = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCEPT,
            HeaderName::from_static("x-weissman-destructive-confirm"),
            // Sent by auto-heal and heal-revert (RemediationDetail.jsx). Without it the CORS
            // preflight for those POSTs is rejected cross-origin and the request never lands.
            HeaderName::from_static("x-weissman-dual-approve"),
        ])
        // Expose non-safelisted response headers so cross-origin JS can read them: Retry-After
        // (rate-limit backoff), Content-Disposition (CSV/PDF download filenames), and the audit
        // NDJSON chain marker. Without this the SPA falls back to a 60s retry default and generic
        // download names in split-origin deployments.
        .expose_headers([
            HeaderName::from_static("retry-after"),
            CONTENT_DISPOSITION,
            HeaderName::from_static("x-audit-chain-intact"),
        ]);
    router.layer(cors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origins_as_strings() -> Vec<String> {
        configured_origins()
            .iter()
            .map(|h| h.to_str().unwrap().to_string())
            .collect()
    }

    // One test owns both env vars to avoid parallel races.
    #[test]
    fn configured_origins_precedence_and_fallback() {
        let cors = "WEISSMAN_CORS_ORIGINS";
        let base = "WEISSMAN_PUBLIC_BASE_URL";
        std::env::remove_var(cors);
        std::env::remove_var(base);

        // Neither set -> hardcoded production default.
        assert_eq!(origins_as_strings(), vec!["https://weissmancyber.com"]);

        // Falls back to the origin of the public base URL when CORS list is unset.
        std::env::set_var(base, "https://app.example.com/dashboard?x=1");
        assert_eq!(origins_as_strings(), vec!["https://app.example.com"]);

        // Explicit CORS list wins and is split/trimmed.
        std::env::set_var(cors, " https://a.example.com , https://b.example.com ");
        assert_eq!(
            origins_as_strings(),
            vec!["https://a.example.com", "https://b.example.com"]
        );

        std::env::remove_var(cors);
        std::env::remove_var(base);
    }
}
