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
    "weissman_worker_dev",
    "weissman_analytics_dev",
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

    // Every machine secret above has an enforced floor here — JWT >= 48, metrics >= 32,
    // destructive-confirm >= 32, job-orchestrator >= 32 — but the one credential a HUMAN types,
    // and the one that grants super-admin, had none. The only floor was
    // `require_len WEISSMAN_ADMIN_PASSWORD 12` in start_weissman_live.sh, which anyone bringing
    // the stack up with plain `docker compose up` bypasses entirely.
    //
    // 12 matches the launcher's existing documented contract rather than inventing a stricter one,
    // so this closes the bypass without moving the goalposts on an existing deployment.
    const MIN_ADMIN_PASSWORD_LEN: usize = 12;
    match std::env::var("WEISSMAN_ADMIN_PASSWORD") {
        Ok(p) if p.trim().chars().count() >= MIN_ADMIN_PASSWORD_LEN => {}
        Ok(p) if p.trim().is_empty() => {
            return Err("WEISSMAN_ADMIN_PASSWORD must be set in production".into());
        }
        Ok(p) => {
            return Err(format!(
                "WEISSMAN_ADMIN_PASSWORD is {} characters; production requires at least {} \
                 (start_weissman_live.sh generates a 24-character one)",
                p.trim().chars().count(),
                MIN_ADMIN_PASSWORD_LEN
            ));
        }
        Err(_) => {
            return Err("WEISSMAN_ADMIN_PASSWORD must be set in production".into());
        }
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
        "WEISSMAN_WORKER_DATABASE_URL",
        "WEISSMAN_ANALYTICS_DATABASE_URL",
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

    weissman_db::role_guard::enforce_production_dsn_roles()?;
    if matches!(scope, StartupScope::Worker) {
        weissman_db::role_guard::enforce_production_analytics_dsn()?;
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
    let orchestrator = std::env::var("WEISSMAN_JOB_ORCHESTRATOR_SECRET").unwrap_or_default();
    if orchestrator.trim().len() < 32 {
        return Err(
            "WEISSMAN_JOB_ORCHESTRATOR_SECRET must be set to a strong (>=32 chars) dedicated value in production for zero-trust job bus signing"
                .into(),
        );
    }

    // Secrets-at-rest vaults: fail closed rather than silently storing MFA seeds, SOAR provider
    // credentials and CEO-vault secrets under the token-signing key.
    //
    // These guards used to call `key_present()`, which is true whenever ANY key material exists —
    // including the fallback derived from WEISSMAN_JWT_SECRET. Since this function already
    // rejects a JWT secret shorter than 48 chars, that fallback always succeeds in production, so
    // both guards were unconditionally true. They read as a hard requirement and were dead code:
    // every stored secret in this deployment is encrypted with the JWT secret.
    //
    // That is not a storage key. It is the token-signing key, and it is deliberately distributed
    // to every replica including the worker container — so anyone who reads it from any one
    // process can both mint arbitrary auth tokens and decrypt every stored secret. Checking
    // `dedicated_key_configured()` makes these guards mean what their messages claim.
    //
    // Safe to enable: both decrypt keyrings now also carry the JWT-derived legacy key, so rows
    // written before the dedicated key existed keep opening while new writes use the new key.
    if !crate::soar::integrations_vault::dedicated_key_configured() {
        return Err(
            "no dedicated secrets-at-rest key in production: set WEISSMAN_INTEGRATIONS_VAULT_KEY (>=32 chars) or WEISSMAN_VAULT_KEY (64 hex). Deriving from WEISSMAN_JWT_SECRET means the token-signing key also decrypts every stored MFA/SOAR secret"
                .into(),
        );
    }
    if !crate::ceo::vault::dedicated_key_configured() {
        return Err(
            "CEO genesis vault has no dedicated key in production: set WEISSMAN_VAULT_KEY (64 hex); deriving from WEISSMAN_JWT_SECRET means the token-signing key also decrypts every vault secret"
                .into(),
        );
    }
    if !crate::soar::integrations_vault::dedicated_key_configured() {
        eprintln!(
            "[Weissman][vault] WARNING: no dedicated vault key; deriving from WEISSMAN_JWT_SECRET. \
             Set WEISSMAN_INTEGRATIONS_VAULT_KEY, and on JWT rotation set WEISSMAN_JWT_SECRET_PREVIOUS \
             so already-encrypted secrets stay readable."
        );
    }

    Ok(())
}

/// Load AES-256-GCM vault keys into process memory, then wipe the env copies so a
/// later memory dump / `/proc/self/environ` leak cannot recover
/// `WEISSMAN_VAULT_KEY` / `WEISSMAN_INTEGRATIONS_VAULT_KEY`.
pub fn lock_and_scrub_vault_keys_after_boot() {
    crate::ceo::vault::prime_keys_from_env();
    crate::soar::integrations_vault::prime_keys_from_env();
    if let Some(k) = crate::ceo::vault::vault_key() {
        crate::job_envelope::install_kek(k);
    }
    crate::ceo::vault::scrub_key_env_vars();
    crate::soar::integrations_vault::scrub_key_env_vars();
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
    fn vault_boot_installs_job_bus_kek_before_env_scrub() {
        let src = include_str!("security_startup.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production source");
        let kek = prod
            .find("job_envelope::install_kek")
            .expect("install job-bus KEK after vault prime");
        let scrub = prod
            .find("crate::ceo::vault::scrub_key_env_vars")
            .expect("scrub after prime");
        assert!(
            kek < scrub,
            "KEK must be copied into the job envelope before env wipe"
        );
    }
}
