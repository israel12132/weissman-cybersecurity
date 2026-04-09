//! Outbound TLS verification when probing customer or third-party HTTPS targets.
//!
//! **Default:** verify certificates (`danger_accept_invalid_certs` = false).  
//! **Lab / explicit assessment mode:** set `WEISSMAN_ALLOW_INSECURE_TLS=1` (or `true` / `yes`) to
//! disable verification globally. Per-target overrides belong in scan/client config (e.g. cloud
//! containment `insecure_tls`) and should be OR’d with [`danger_accept_invalid_certs`] only where
//! the product intentionally models customer misconfiguration.

/// Whether to disable TLS certificate verification for outbound probe clients.
#[inline]
pub fn danger_accept_invalid_certs() -> bool {
    env_truthy("WEISSMAN_ALLOW_INSECURE_TLS")
}

#[inline]
pub fn allow_insecure_tls_env() -> bool {
    danger_accept_invalid_certs()
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
