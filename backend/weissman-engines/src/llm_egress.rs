//! Fail-closed LLM egress / data-residency guard.
//!
//! The production Rust LLM path (`crate::openai_chat`, driven by `crate::llm_router` and
//! every `fingerprint_engine` caller) can be pointed at any OpenAI-compatible `base_url`.
//! Before this guard there was no residency control: a misconfigured `WEISSMAN_LLM_BASE_URL`
//! / `WEISSMAN_LLM_ENDPOINTS` could ship customer prompts, client IPs, and auth/BYPASSRLS
//! audit lines to a third-party model host.
//!
//! [`llm_egress_allowed`] is the single source of truth. It is enforced:
//!   * **per call**, at the top of every request-issuing entrypoint in [`crate::openai_chat`]
//!     (fail closed BEFORE the `/v1/models` health probe or the POST fires), and
//!   * **at startup**, from `fingerprint_engine::security_startup::enforce_llm_egress_policy`
//!     (every configured endpoint is validated at boot).
//!
//! ## Posture (`WEISSMAN_LLM_EGRESS`)
//! * **`sovereign`** (default; also the value used when the var is unset/empty/unrecognized):
//!   only loopback, RFC1918/RFC4193 private, link-local, RFC6598 shared, and in-cluster hosts
//!   (single-label service names, plus `.local` / `.internal` / `.svc` / `.cluster.local` /
//!   `.localhost` suffixes) may be reached. A public host (e.g. `api.openai.com`) is refused.
//! * **`hosted`**: the sovereign set PLUS any host named in `WEISSMAN_LLM_ALLOWED_HOSTS`
//!   (comma/space/semicolon/newline separated; a leading-dot entry like `.openai.com` also
//!   matches subdomains). `hosted` with an empty allowlist refuses every external host — so an
//!   external endpoint requires BOTH `WEISSMAN_LLM_EGRESS=hosted` and a non-empty allowlist.

use std::net::IpAddr;

/// Egress posture parsed from `WEISSMAN_LLM_EGRESS`. Defaults to the safe [`EgressPosture::Sovereign`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EgressPosture {
    Sovereign,
    Hosted,
}

/// Fail-closed egress check for a configured LLM `base_url`.
///
/// Returns `Ok(())` iff the URL's host is permitted by the active posture. A blank `base_url`
/// resolves to the built-in loopback default (`DEFAULT_LLM_BASE_URL`) and is allowed; a
/// non-blank URL whose host cannot be parsed is refused (fail closed).
pub fn llm_egress_allowed(base_url: &str) -> Result<(), String> {
    let host = match parse_host(base_url) {
        Some(h) => h,
        None => {
            if base_url.trim().is_empty() {
                // Empty => client falls back to DEFAULT_LLM_BASE_URL (loopback vLLM).
                return Ok(());
            }
            return Err(format!(
                "LLM egress blocked: could not parse a host from base_url '{base_url}'"
            ));
        }
    };
    egress_decision(&host, posture_from_env(), &allowed_hosts_from_env())
}

/// Pure policy decision (no env, no I/O) — unit-tested directly.
fn egress_decision(
    host: &str,
    posture: EgressPosture,
    allowed_hosts: &[String],
) -> Result<(), String> {
    // Loopback / private / in-cluster hosts are always allowed under both postures.
    if is_sovereign_host(host) {
        return Ok(());
    }
    match posture {
        EgressPosture::Sovereign => Err(format!(
            "LLM egress blocked: host '{host}' is not loopback/private/in-cluster and \
             WEISSMAN_LLM_EGRESS=sovereign. Point the LLM at an in-region private endpoint, or \
             set WEISSMAN_LLM_EGRESS=hosted with WEISSMAN_LLM_ALLOWED_HOSTS to permit it."
        )),
        EgressPosture::Hosted => {
            if allowed_hosts.is_empty() {
                return Err(
                    "LLM egress blocked: WEISSMAN_LLM_EGRESS=hosted requires a non-empty \
                     WEISSMAN_LLM_ALLOWED_HOSTS allowlist"
                        .to_string(),
                );
            }
            if allowed_hosts.iter().any(|p| host_matches(host, p)) {
                Ok(())
            } else {
                Err(format!(
                    "LLM egress blocked: host '{host}' is not in WEISSMAN_LLM_ALLOWED_HOSTS"
                ))
            }
        }
    }
}

fn posture_from_env() -> EgressPosture {
    match std::env::var("WEISSMAN_LLM_EGRESS")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("hosted") => EgressPosture::Hosted,
        // Unset / empty / "sovereign" / anything unrecognized => fail closed to sovereign.
        _ => EgressPosture::Sovereign,
    }
}

fn allowed_hosts_from_env() -> Vec<String> {
    std::env::var("WEISSMAN_LLM_ALLOWED_HOSTS")
        .ok()
        .map(|raw| {
            raw.split(|c: char| matches!(c, ',' | ' ' | '\t' | '\n' | ';'))
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Case-insensitive host match against one allowlist entry. A leading dot (`.example.com`)
/// matches the domain itself and any subdomain; otherwise an exact match is required.
fn host_matches(host: &str, pattern: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty() {
        return false;
    }
    if let Some(suffix) = p.strip_prefix('.') {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == p
    }
}

/// True when `host` is a loopback / private / in-cluster destination that never egresses to
/// the public internet — always permitted regardless of posture.
fn is_sovereign_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    // Kubernetes / docker-compose / internal DNS suffixes (all reserved, non-public).
    const INTERNAL_SUFFIXES: &[&str] = &[
        ".local",
        ".internal",
        ".svc",
        ".svc.cluster.local",
        ".cluster.local",
    ];
    if INTERNAL_SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return true;
    }
    // An IP literal => classify strictly by range (public IPs fall through to `false`).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_private_ip(&ip);
    }
    // A single-label hostname (no dot, not an IP) is a cluster/compose service name
    // (e.g. "vllm", "llm-gateway") and cannot resolve to a routable public host.
    !host.contains('.')
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()            // 127.0.0.0/8
                || v4.is_private()      // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()   // 169.254.0.0/16
                || v4.is_unspecified()  // 0.0.0.0
                // RFC 6598 shared address space (100.64.0.0/10) — EKS/k8s pod networks.
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                                 // ::1
                || v6.is_unspecified()                       // ::
                || (v6.segments()[0] & 0xfe00) == 0xfc00     // fc00::/7 unique-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Extract the lowercase host from an OpenAI-compatible base URL WITHOUT pulling in a URL
/// crate (weissman-engines has no `url` dependency). Handles an optional scheme, userinfo,
/// port, and a bracketed IPv6 literal.
fn parse_host(base_url: &str) -> Option<String> {
    let s = base_url.trim();
    if s.is_empty() {
        return None;
    }
    // Strip scheme if present ("http://", "https://", ...); tolerate a scheme-less authority.
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => s,
    };
    // Authority ends at the first '/', '?' or '#'.
    let authority_end = after_scheme
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    if authority.is_empty() {
        return None;
    }
    // Drop any userinfo ("user:pass@").
    let host_port = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    // Bracketed IPv6 literal "[::1]:8000" => take what is inside the brackets.
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        match rest.find(']') {
            Some(j) => &rest[..j],
            None => return None,
        }
    } else {
        // Strip a trailing ":port"; a bare (unbracketed) IPv6 is not valid URL authority
        // and is not expected here.
        match host_port.rfind(':') {
            Some(i) => &host_port[..i],
            None => host_port,
        }
    };
    let host = host.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_from_various_base_urls() {
        assert_eq!(
            parse_host("http://127.0.0.1:8000/v1").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            parse_host("https://api.openai.com/v1").as_deref(),
            Some("api.openai.com")
        );
        assert_eq!(parse_host("http://[::1]:8000/v1").as_deref(), Some("::1"));
        assert_eq!(
            parse_host("http://user:pass@vllm:8000/v1").as_deref(),
            Some("vllm")
        );
        // scheme + host lowercased.
        assert_eq!(
            parse_host("HTTPS://API.OpenAI.com/v1").as_deref(),
            Some("api.openai.com")
        );
        // scheme-less authority is tolerated.
        assert_eq!(
            parse_host("vllm-gateway:8000/v1").as_deref(),
            Some("vllm-gateway")
        );
        assert_eq!(parse_host(""), None);
        assert_eq!(parse_host("http://"), None);
    }

    #[test]
    fn loopback_and_private_hosts_allowed_under_sovereign() {
        let none: &[String] = &[];
        for base in [
            "http://127.0.0.1:8000/v1",
            "http://localhost:8000/v1",
            "http://[::1]:8000/v1",
            "http://10.4.2.9:8000/v1",
            "http://172.16.0.3:8000/v1",
            "http://192.168.1.50:8000/v1",
            "http://100.64.3.7:8000/v1", // RFC6598 (k8s pod net)
            "http://vllm:8000/v1",       // single-label service
            "http://llm.default.svc.cluster.local/v1", // k8s service DNS
            "http://gateway.internal/v1",
        ] {
            let host = parse_host(base).expect("host");
            assert!(
                egress_decision(&host, EgressPosture::Sovereign, none).is_ok(),
                "{base} should be allowed under sovereign"
            );
        }
    }

    #[test]
    fn public_host_blocked_under_sovereign() {
        let none: &[String] = &[];
        let host = parse_host("https://api.openai.com/v1").expect("host");
        let err = egress_decision(&host, EgressPosture::Sovereign, none)
            .expect_err("api.openai.com must be blocked under sovereign");
        assert!(err.contains("api.openai.com"), "{err}");
        // A public IP is blocked too.
        let host = parse_host("https://8.8.8.8/v1").expect("host");
        assert!(egress_decision(&host, EgressPosture::Sovereign, none).is_err());
    }

    #[test]
    fn public_host_allowed_only_under_hosted_plus_allowlist() {
        let host = parse_host("https://api.openai.com/v1").expect("host");
        // hosted + matching allowlist => allowed.
        let allow = vec!["api.openai.com".to_string()];
        assert!(egress_decision(&host, EgressPosture::Hosted, &allow).is_ok());
        // hosted + empty allowlist => still blocked (operator must set BOTH toggles).
        let none: &[String] = &[];
        assert!(egress_decision(&host, EgressPosture::Hosted, none).is_err());
        // hosted + non-matching allowlist => blocked.
        let other = vec!["api.anthropic.com".to_string()];
        assert!(egress_decision(&host, EgressPosture::Hosted, &other).is_err());
        // Leading-dot suffix entry matches subdomains.
        let suffix = vec![".openai.com".to_string()];
        assert!(egress_decision(&host, EgressPosture::Hosted, &suffix).is_ok());
        // Loopback stays allowed under hosted regardless of allowlist.
        let lo = parse_host("http://127.0.0.1:8000/v1").expect("host");
        assert!(egress_decision(&lo, EgressPosture::Hosted, none).is_ok());
    }

    #[test]
    fn blank_base_url_is_allowed_default_loopback() {
        // Returns before any env read (no parallel-test env race).
        assert!(llm_egress_allowed("").is_ok());
        assert!(llm_egress_allowed("   ").is_ok());
    }

    #[test]
    fn unparseable_nonblank_base_url_fails_closed() {
        assert!(llm_egress_allowed("http://").is_err());
    }
}
