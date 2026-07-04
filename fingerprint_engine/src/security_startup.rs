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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupScope {
    Server,
    Worker,
}

/// Refuse production server boot when known-weak credentials or dev bypass flags are set.
pub fn enforce_production_security_policy() -> Result<(), String> {
    enforce_production_security_policy_with_scope(StartupScope::Server)
}

/// Refuse production worker boot when known-weak credentials or dev bypass flags are set.
pub fn enforce_worker_production_security_policy() -> Result<(), String> {
    enforce_production_security_policy_with_scope(StartupScope::Worker)
}

fn enforce_production_security_policy_with_scope(scope: StartupScope) -> Result<(), String> {
    if !is_production_environment() {
        return Ok(());
    }

    if let Ok(secret) = std::env::var("WEISSMAN_JWT_SECRET") {
        let t = secret.trim();
        if t.len() < 48 {
            return Err("WEISSMAN_JWT_SECRET must be at least 48 characters in production".into());
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
    } else {
        return Err("WEISSMAN_JWT_SECRET must be set in production".into());
    }

    if env_truthy("WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD") {
        return Err(
            "WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD is set in production; unset it and configure WEISSMAN_ADMIN_PASSWORD"
                .into(),
        );
    }

    if env_truthy("WEISSMAN_SAML_INSECURE_SKIP_VERIFY") {
        return Err(
            "WEISSMAN_SAML_INSECURE_SKIP_VERIFY is set in production; configure WEISSMAN_XMLSEC1_BINARY instead"
                .into(),
        );
    }

    if matches!(scope, StartupScope::Server) && !crate::auth_jwt::cookie_use_secure() {
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

    if matches!(scope, StartupScope::Server) {
        if std::env::var("WEISSMAN_MIGRATE_URL")
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(
                "WEISSMAN_MIGRATE_URL must be set in production so schema migrations run at boot"
                    .into(),
            );
        }

        let metrics_token = std::env::var("WEISSMAN_METRICS_TOKEN").unwrap_or_default();
        if metrics_token.trim().len() < 32 {
            return Err(
                "WEISSMAN_METRICS_TOKEN must be set to a strong (>=32 chars) value in production"
                    .into(),
            );
        }

        let destructive = std::env::var("WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET").unwrap_or_default();
        if destructive.trim().len() < 32 {
            return Err(
                "WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET must be set to a strong (>=32 chars) value in production for destructive-action HMAC"
                    .into(),
            );
        }

        // Without Redis, login lockout + per-tenant/IP rate limits fall back to
        // per-replica in-memory state. In a multi-replica deployment that lets a
        // brute-force attacker spread attempts across replicas to dodge the limits,
        // and the telemetry bus can't fan out cross-replica. Require Redis in
        // production unless the operator explicitly acknowledges single-replica.
        let redis_unset = std::env::var("REDIS_URL")
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        if redis_unset && !env_truthy("WEISSMAN_ALLOW_SINGLE_NODE") {
            return Err(
                "REDIS_URL is not set in production: distributed login lockout, rate limiting, and the telemetry bus would degrade to per-replica in-memory state. Configure REDIS_URL, or set WEISSMAN_ALLOW_SINGLE_NODE=1 to acknowledge a single-replica deployment."
                    .into(),
            );
        }

        if env_truthy("WEISSMAN_SELF_SERVE_SIGNUP")
            && !env_truthy("WEISSMAN_ALLOW_SELF_SERVE_IN_PRODUCTION")
        {
            return Err(
                "WEISSMAN_SELF_SERVE_SIGNUP is enabled in production; set WEISSMAN_ALLOW_SELF_SERVE_IN_PRODUCTION=1 to acknowledge public signup exposure"
                    .into(),
            );
        }
    }

    // Server + worker: zero-trust job bus HMAC signing secret (no JWT fallback in production).
    if is_production_environment() {
        let orchestrator = std::env::var("WEISSMAN_JOB_ORCHESTRATOR_SECRET").unwrap_or_default();
        if orchestrator.trim().len() < 32 {
            return Err(
                "WEISSMAN_JOB_ORCHESTRATOR_SECRET must be set to a strong (>=32 chars) dedicated value in production for zero-trust job bus signing"
                    .into(),
            );
        }
    }

    Ok(())
}

/// True when production expects Redis-backed distributed lockout, rate limits, and agent registry.
#[must_use]
pub fn production_distributed_state_required() -> bool {
    if !is_production_environment() {
        return false;
    }
    if env_truthy_pub("WEISSMAN_ALLOW_SINGLE_NODE") {
        return false;
    }
    std::env::var("REDIS_URL")
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

fn env_truthy(name: &str) -> bool {
    env_truthy_pub(name)
}

/// Public wrapper for posture checks (same semantics as startup guards).
pub fn env_truthy_pub(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_truthy_recognizes_affirmatives_and_rejects_others() {
        // Uniquely-named var so parallel tests can't race on it.
        let key = "WEISSMAN_TEST_ENV_TRUTHY_SS";
        for v in ["1", "true", "TRUE", " yes ", "On"] {
            std::env::set_var(key, v);
            assert!(env_truthy(key), "expected truthy for {v:?}");
        }
        for v in ["0", "false", "no", "off", ""] {
            std::env::set_var(key, v);
            assert!(!env_truthy(key), "expected falsy for {v:?}");
        }
        std::env::remove_var(key);
        assert!(!env_truthy(key), "unset must be falsy");
    }

    #[test]
    fn non_production_env_skips_all_guards() {
        // The guard is a no-op outside production regardless of weak secrets, so
        // dev/CI default boot is never blocked by these checks.
        if !is_production_environment() {
            assert!(enforce_production_security_policy().is_ok());
            assert!(enforce_worker_production_security_policy().is_ok());
        }
    }
}
