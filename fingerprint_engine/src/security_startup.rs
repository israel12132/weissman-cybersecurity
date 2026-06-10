//! Production startup guards: weak secrets, dev-only bypass flags, insecure cookies.

use weissman_core::tls_policy::is_production_environment;

const WEAK_JWT_SECRETS: &[&str] = &[
    "change-me-in-production-docker",
    "changeme",
    "ci-engine-smoke-secret",
    "CHANGE_ME_MIN_32_BYTES_RANDOM_HEX_OR_BASE64",
];

const WEAK_DB_PASSWORD_FRAGMENTS: &[&str] = &[
    "weissman_dev_secret",
    "weissman_auth_dev",
    "weissman_ro_dev",
];

/// Refuse production boot when known-weak credentials or dev bypass flags are set.
pub fn enforce_production_security_policy() -> Result<(), String> {
    if !is_production_environment() {
        return Ok(());
    }

    if let Ok(secret) = std::env::var("WEISSMAN_JWT_SECRET") {
        let t = secret.trim();
        if t.len() < 32 {
            return Err(
                "WEISSMAN_JWT_SECRET must be at least 32 characters in production".into(),
            );
        }
        let lower = t.to_ascii_lowercase();
        if WEAK_JWT_SECRETS
            .iter()
            .any(|w| lower == w.to_ascii_lowercase())
        {
            return Err(
                "WEISSMAN_JWT_SECRET matches a known weak/default value; rotate before production deploy"
                    .into(),
            );
        }
    }

    if matches!(
        std::env::var("WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) {
        return Err(
            "WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD is set in production; unset it and configure WEISSMAN_ADMIN_PASSWORD"
                .into(),
        );
    }

    if matches!(
        std::env::var("WEISSMAN_SAML_INSECURE_SKIP_VERIFY").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) {
        return Err(
            "WEISSMAN_SAML_INSECURE_SKIP_VERIFY is set in production; configure WEISSMAN_XMLSEC1_BINARY instead"
                .into(),
        );
    }

    if !crate::auth_jwt::cookie_use_secure() {
        return Err(
            "WEISSMAN_COOKIE_SECURE must be 1 in production (HTTPS-only session cookies)".into(),
        );
    }

    for var in [
        "DATABASE_URL",
        "WEISSMAN_AUTH_DATABASE_URL",
        "WEISSMAN_READ_ONLY_DATABASE_URL",
    ] {
        if let Ok(url) = std::env::var(var) {
            let u = url.to_ascii_lowercase();
            if WEAK_DB_PASSWORD_FRAGMENTS.iter().any(|p| u.contains(p)) {
                return Err(format!(
                    "{var} contains a default dev database password; rotate all DB roles before production"
                ));
            }
        }
    }

    Ok(())
}
