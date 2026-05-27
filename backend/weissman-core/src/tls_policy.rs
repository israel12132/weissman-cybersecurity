//! Outbound TLS verification when probing customer or third-party HTTPS targets.
//!
//! **Default:** verify certificates (`danger_accept_invalid_certs` = false).
//! **Lab / explicit assessment mode:** set `WEISSMAN_ALLOW_INSECURE_TLS=1` (or `true` / `yes`) to
//! disable verification globally. Per-target overrides belong in scan/client config (e.g. cloud
//! containment `insecure_tls`) and should be OR'd with [`danger_accept_invalid_certs`] only where
//! the product intentionally models customer misconfiguration.

/// Whether to disable TLS certificate verification for outbound probe clients.
///
/// Returns `false` in production environments even when the flag is set, because the
/// `enforce_production_tls_policy` startup guard panics in that case before any
/// requests are issued. We keep the env check here as a defence-in-depth so the
/// guard's behaviour is consistent.
#[inline]
pub fn danger_accept_invalid_certs() -> bool {
    if is_production_environment() {
        return false;
    }
    env_truthy("WEISSMAN_ALLOW_INSECURE_TLS")
}

#[inline]
pub fn allow_insecure_tls_env() -> bool {
    danger_accept_invalid_certs()
}

/// Detect a production deployment from environment hints. Any of:
///   - `RUST_ENV=production`
///   - `NODE_ENV=production`
///   - `WEISSMAN_ENV=production`
///   - `APP_ENV=production`
#[inline]
pub fn is_production_environment() -> bool {
    for var in [
        "WEISSMAN_ENV",
        "RUST_ENV",
        "NODE_ENV",
        "APP_ENV",
        "RAILS_ENV", // legacy ops compat
    ] {
        if std::env::var(var)
            .ok()
            .map(|v| v.trim().eq_ignore_ascii_case("production") || v.trim().eq_ignore_ascii_case("prod"))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// Call at startup. Returns `Err` with a human-readable message when insecure TLS would be
/// disabled in production. Callers should abort the process on `Err`.
///
/// ```no_run
/// if let Err(e) = weissman_core::tls_policy::enforce_production_tls_policy() {
///     eprintln!("[startup] TLS policy refusal: {e}");
///     std::process::exit(2);
/// }
/// ```
pub fn enforce_production_tls_policy() -> Result<(), String> {
    if !is_production_environment() {
        return Ok(());
    }
    if env_truthy("WEISSMAN_ALLOW_INSECURE_TLS") {
        return Err(
            "WEISSMAN_ALLOW_INSECURE_TLS=1 is set together with a production environment marker. \
             Refusing to start: insecure TLS verification must never be enabled in production. \
             Unset WEISSMAN_ALLOW_INSECURE_TLS or switch the deployment environment."
                .to_string(),
        );
    }
    Ok(())
}

fn env_truthy(name: &str) -> bool {
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

    fn with_env<F: FnOnce()>(set: &[(&str, Option<&str>)], f: F) {
        let prev: Vec<(String, Option<String>)> = set
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in set {
            if let Some(v) = v {
                std::env::set_var(k, v);
            } else {
                std::env::remove_var(k);
            }
        }
        f();
        for (k, v) in prev {
            match v {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }

    #[test]
    fn refuses_insecure_in_production() {
        with_env(
            &[
                ("WEISSMAN_ENV", Some("production")),
                ("WEISSMAN_ALLOW_INSECURE_TLS", Some("1")),
            ],
            || {
                assert!(enforce_production_tls_policy().is_err());
                assert!(!danger_accept_invalid_certs());
            },
        );
    }

    #[test]
    fn allows_in_dev() {
        with_env(
            &[
                ("WEISSMAN_ENV", Some("development")),
                ("RUST_ENV", None),
                ("NODE_ENV", None),
                ("APP_ENV", None),
                ("RAILS_ENV", None),
                ("WEISSMAN_ALLOW_INSECURE_TLS", Some("1")),
            ],
            || {
                assert!(enforce_production_tls_policy().is_ok());
                assert!(danger_accept_invalid_certs());
            },
        );
    }
}
