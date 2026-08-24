//! Pre-authentication workspace directory for the login screen's tenant picker.
//!
//! `GET /api/auth/tenant-directory` — unauthenticated, because it feeds the field a user fills in
//! *before* logging in. Until this existed the login form asked for the tenant slug as free text,
//! and `api_login` resolves that slug before it ever looks at the password: an unknown slug returns
//! the same "Invalid email or password" as a wrong credential, so a typo in a field nobody can
//! validate looked exactly like a lockout. The field is a select now, and this is where its options
//! come from.
//!
//! ## What it will and will not say
//!
//! On a single-tenant instance the slug list is one entry describing the instance itself — the same
//! string that is in the deployment's own `.env` and in the docs. On a multi-tenant instance it is a
//! customer list, and handing that to an anonymous caller is the tenant enumeration an auditor will
//! (correctly) write up. So the listing decision is explicit:
//!
//! | `WEISSMAN_PUBLIC_TENANT_DIRECTORY` | Behaviour                                                |
//! |------------------------------------|----------------------------------------------------------|
//! | `1` / `true` / `yes` / `on`        | always list (operators who want a picker in every env)     |
//! | `0` / `false` / `no` / `off`       | never list — the UI falls back to manual slug entry       |
//! | unset (default)                    | list outside production; in production list only when the |
//! |                                    | instance has exactly one active tenant                    |
//!
//! The restricted answer is still `200 OK` with an empty list and `listing: "restricted"`, never an
//! error: the login page has to render either way, and a 403 here would tell a prober more than the
//! empty list does. Nothing in the response is tenant-scoped data — slug and display name only, no
//! ids, no counts, no user or finding data.
//!
//! Rate limiting comes from `http::api_rate_limit_middleware`, which runs before `auth_guard` and
//! therefore covers this route like any other `/api/*` path.

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::sync::Arc;

/// Slug used by `api_login` when the request omits one. Documented in `.env.example` and seeded by
/// `auth_bootstrap`, so echoing it is not a disclosure — it is the fallback the API already applies.
pub const DEFAULT_TENANT_SLUG: &str = "default";

/// Hard cap on listed workspaces. A picker is unusable past a few dozen entries and an unbounded
/// list would turn one anonymous GET into an arbitrarily large response.
pub const MAX_LISTED_TENANTS: usize = 200;

/// Longest display name echoed back. Names are operator-supplied; truncating keeps a pathological
/// row from dominating the response.
const MAX_NAME_LEN: usize = 120;

/// Outcome of the listing decision, mirrored to the client as `listing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    /// Slugs are included in the response.
    Enumerated,
    /// Slugs are withheld; the client must let the user type one.
    Restricted,
}

impl Listing {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Listing::Enumerated => "enumerated",
            Listing::Restricted => "restricted",
        }
    }
}

/// Explicit operator opt-in / opt-out, or `None` when the variable is unset or unrecognised.
fn configured_override() -> Option<bool> {
    let raw = std::env::var("WEISSMAN_PUBLIC_TENANT_DIRECTORY").ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "all" => Some(true),
        "0" | "false" | "no" | "off" | "none" => Some(false),
        _ => None,
    }
}

/// The listing decision. `active_tenants` is how many active tenants the instance actually has, and
/// `production` is [`weissman_core::tls_policy::is_production_environment`] — both are passed in so
/// this is a pure function the tests can pin.
#[must_use]
pub fn decide(active_tenants: usize, production: bool) -> Listing {
    if let Some(explicit) = configured_override() {
        return if explicit {
            Listing::Enumerated
        } else {
            Listing::Restricted
        };
    }
    // A single-tenant instance's only slug describes the instance, not a customer base. More than
    // one in production is a customer list, and the operator has to say so out loud to publish it.
    if production && active_tenants > 1 {
        Listing::Restricted
    } else {
        Listing::Enumerated
    }
}

/// Trim a display name to something a `<select>` can render, falling back to the slug.
#[must_use]
pub fn display_name(name: &str, slug: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return slug.to_string();
    }
    if trimmed.chars().count() <= MAX_NAME_LEN {
        return trimmed.to_string();
    }
    let mut out: String = trimmed.chars().take(MAX_NAME_LEN - 1).collect();
    out.push('…');
    out
}

/// Read the directory. Tries the auth pool first (BYPASSRLS in every shipped topology, and the pool
/// `api_login` itself resolves slugs on), then the app pool — `login_tenant_directory()` is SECURITY
/// DEFINER, so it returns the same rows either way, but a deployment that only configures one of the
/// two must not lose the picker over it.
async fn read_directory(state: &crate::http::AppState) -> Result<Vec<(String, String)>, sqlx::Error> {
    match weissman_db::login_tenant_directory(state.auth_pool.as_ref()).await {
        Ok(rows) => Ok(rows),
        Err(auth_err) => {
            tracing::debug!(
                target: "tenant_directory",
                error = %auth_err,
                "auth pool could not read the login tenant directory; retrying on the app pool"
            );
            weissman_db::login_tenant_directory(state.app_pool.as_ref()).await
        }
    }
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn api_auth_tenant_directory(State(state): State<Arc<crate::http::AppState>>) -> Response {
    let rows = match read_directory(&state).await {
        Ok(rows) => rows,
        Err(e) => {
            // Fail visibly rather than pretending the instance has no workspaces: an empty list and
            // a database outage must not look the same to the login screen.
            tracing::warn!(
                target: "tenant_directory",
                error = %e,
                "login tenant directory unavailable"
            );
            return no_store(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "ok": false,
                        "code": "tenant_directory_unavailable",
                        "detail": "Workspace directory is temporarily unavailable. Enter the workspace slug manually.",
                        "listing": Listing::Restricted.as_str(),
                        "tenants": [],
                        "default_slug": DEFAULT_TENANT_SLUG,
                        "allow_custom": true,
                    })),
                )
                    .into_response(),
            );
        }
    };

    let listing = decide(
        rows.len(),
        weissman_core::tls_policy::is_production_environment(),
    );
    let tenants: Vec<serde_json::Value> = match listing {
        Listing::Restricted => Vec::new(),
        Listing::Enumerated => rows
            .iter()
            .filter(|(slug, _)| !slug.trim().is_empty())
            .take(MAX_LISTED_TENANTS)
            .map(|(slug, name)| {
                json!({
                    "slug": slug.trim(),
                    "name": display_name(name, slug.trim()),
                })
            })
            .collect(),
    };
    let truncated = matches!(listing, Listing::Enumerated) && rows.len() > MAX_LISTED_TENANTS;

    no_store(
        (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "listing": listing.as_str(),
                "tenants": tenants,
                "default_slug": DEFAULT_TENANT_SLUG,
                // A restricted or truncated list means the slug a user needs may not be in it, so
                // the picker must keep a way to type one.
                "allow_custom": matches!(listing, Listing::Restricted) || truncated,
                "truncated": truncated,
            })),
        )
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `decide` reads process env, so the override cases must not run concurrently with each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard;

    impl EnvGuard {
        fn set(value: &str) -> Self {
            std::env::set_var("WEISSMAN_PUBLIC_TENANT_DIRECTORY", value);
            EnvGuard
        }
        fn cleared() -> Self {
            std::env::remove_var("WEISSMAN_PUBLIC_TENANT_DIRECTORY");
            EnvGuard
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("WEISSMAN_PUBLIC_TENANT_DIRECTORY");
        }
    }

    #[test]
    fn single_tenant_production_instance_lists_its_own_slug() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::cleared();
        assert_eq!(decide(1, true), Listing::Enumerated);
        assert_eq!(decide(0, true), Listing::Enumerated);
    }

    #[test]
    fn multi_tenant_production_instance_withholds_the_customer_list() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::cleared();
        assert_eq!(decide(2, true), Listing::Restricted);
        assert_eq!(decide(40, true), Listing::Restricted);
    }

    #[test]
    fn non_production_lists_every_workspace() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::cleared();
        assert_eq!(decide(9, false), Listing::Enumerated);
    }

    #[test]
    fn explicit_opt_in_lists_even_a_multi_tenant_production_instance() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::set("true");
        assert_eq!(decide(25, true), Listing::Enumerated);
    }

    #[test]
    fn explicit_opt_out_withholds_even_a_single_tenant_dev_instance() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::set("off");
        assert_eq!(decide(1, false), Listing::Restricted);
    }

    #[test]
    fn unrecognised_value_falls_back_to_the_default_policy() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::set("maybe");
        assert_eq!(decide(3, true), Listing::Restricted);
        assert_eq!(decide(1, true), Listing::Enumerated);
    }

    #[test]
    fn display_name_falls_back_to_slug_and_truncates() {
        assert_eq!(display_name("   ", "default"), "default");
        assert_eq!(display_name(" Weissman HQ ", "default"), "Weissman HQ");
        let long = "x".repeat(MAX_NAME_LEN + 40);
        let shown = display_name(&long, "default");
        assert_eq!(shown.chars().count(), MAX_NAME_LEN);
        assert!(shown.ends_with('…'));
    }
}
