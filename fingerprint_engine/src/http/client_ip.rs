//! Client IP for audit logs and rate limiting (X-Forwarded-For aware).

use axum::http::HeaderMap;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::net::SocketAddr;

fn trust_proxy_headers() -> bool {
    std::env::var("WEISSMAN_TRUST_PROXY_HEADERS")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn trusted_proxy_cidrs() -> Vec<IpNetwork> {
    std::env::var("WEISSMAN_TRUST_PROXY_CIDRS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .filter_map(|part| part.trim().parse::<IpNetwork>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn trusted_proxy_peer(peer: IpAddr) -> bool {
    if !trust_proxy_headers() {
        return false;
    }
    let cidrs = trusted_proxy_cidrs();
    if !cidrs.is_empty() {
        return cidrs.iter().any(|cidr| cidr.contains(peer));
    }

    // Safe local default for single-node deployments: trust only loopback/private peers
    // when explicit CIDR allow-list is not configured.
    match peer {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

pub fn extract_client_ip(headers: &HeaderMap, peer: SocketAddr) -> String {
    if trusted_proxy_peer(peer.ip()) {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // A conforming proxy APPENDS the address it saw, so the right-most entries
            // were added by our infrastructure and the left-most are fully attacker-
            // controllable. Taking the left-most token lets a client forge its source
            // IP (defeating per-IP rate limits and poisoning audit logs), so we read
            // from the right.
            let cidrs = trusted_proxy_cidrs();
            if cidrs.is_empty() {
                // No proxy allow-list configured: trust only the single hop our local
                // proxy appended — the right-most entry.
                if let Some(last) = xff.split(',').map(str::trim).rev().find(|s| !s.is_empty()) {
                    return last.to_string();
                }
            } else {
                // Allow-list configured: walk from the right, skipping addresses that
                // are themselves trusted proxies, and return the first real client addr.
                for hop in xff.split(',').rev() {
                    let hop = hop.trim();
                    if hop.is_empty() {
                        continue;
                    }
                    match hop.parse::<IpAddr>() {
                        Ok(ip) if cidrs.iter().any(|c| c.contains(ip)) => continue,
                        _ => return hop.to_string(),
                    }
                }
            }
        }
        if let Some(xr) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let ip = xr.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    peer.ip().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<F: FnOnce()>(set: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
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
            if let Some(v) = v {
                std::env::set_var(&k, v);
            } else {
                std::env::remove_var(&k);
            }
        }
    }

    #[test]
    fn no_proxy_trust_uses_peer_ip() {
        with_env(
            &[
                ("WEISSMAN_TRUST_PROXY_HEADERS", Some("false")),
                ("WEISSMAN_TRUST_PROXY_CIDRS", None),
            ],
            || {
                let mut headers = HeaderMap::new();
                headers.insert("x-forwarded-for", "203.0.113.8".parse().unwrap());
                let peer = SocketAddr::from_str("10.0.0.5:443").unwrap();
                assert_eq!(extract_client_ip(&headers, peer), "10.0.0.5");
            },
        );
    }

    #[test]
    fn trusted_local_proxy_uses_forwarded_for() {
        with_env(
            &[
                ("WEISSMAN_TRUST_PROXY_HEADERS", Some("true")),
                ("WEISSMAN_TRUST_PROXY_CIDRS", None),
            ],
            || {
                let mut headers = HeaderMap::new();
                headers.insert("x-forwarded-for", "198.51.100.22".parse().unwrap());
                let peer = SocketAddr::from_str("127.0.0.1:443").unwrap();
                assert_eq!(extract_client_ip(&headers, peer), "198.51.100.22");
            },
        );
    }

    #[test]
    fn forged_leftmost_forwarded_for_is_ignored() {
        // Attacker sends `X-Forwarded-For: 1.2.3.4`; the trusted local proxy appends
        // the real peer, so the right-most entry is authoritative and the forged
        // left-most value must NOT be returned.
        with_env(
            &[
                ("WEISSMAN_TRUST_PROXY_HEADERS", Some("true")),
                ("WEISSMAN_TRUST_PROXY_CIDRS", None),
            ],
            || {
                let mut headers = HeaderMap::new();
                headers.insert("x-forwarded-for", "1.2.3.4, 203.0.113.9".parse().unwrap());
                let peer = SocketAddr::from_str("127.0.0.1:443").unwrap();
                assert_eq!(extract_client_ip(&headers, peer), "203.0.113.9");
            },
        );
    }

    #[test]
    fn cidr_allowlist_skips_trusted_proxy_hops() {
        // Two-proxy chain: client, then two infra proxies in 10.0.0.0/8. Walking from
        // the right skips the trusted proxies and returns the real client address.
        with_env(
            &[
                ("WEISSMAN_TRUST_PROXY_HEADERS", Some("true")),
                ("WEISSMAN_TRUST_PROXY_CIDRS", Some("10.0.0.0/8")),
            ],
            || {
                let mut headers = HeaderMap::new();
                headers.insert(
                    "x-forwarded-for",
                    "203.0.113.9, 10.0.0.7, 10.0.0.8".parse().unwrap(),
                );
                let peer = SocketAddr::from_str("10.0.0.8:443").unwrap();
                assert_eq!(extract_client_ip(&headers, peer), "203.0.113.9");
            },
        );
    }
}
