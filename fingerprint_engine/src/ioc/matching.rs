//! Matching host observables against a loaded indicator set.
//!
//! Built for the retrohunt + endpoint paths: load the active indicators once,
//! then test many observables cheaply. Exact indicators (hashes, ips, urls,
//! emails) go into a hash map; CIDR and domain indicators need structured
//! matching (an IP inside a network, a hostname under a flagged domain).

use super::{normalize_value, IocType};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A lightweight, query-only view of an indicator for match results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchHit {
    pub ioc_type: IocType,
    pub value_norm: String,
    pub source: String,
    pub severity: String,
    pub confidence: u8,
}

/// One indicator as loaded into a [`MatchSet`].
#[derive(Debug, Clone)]
pub struct LoadedIndicator {
    pub ioc_type: IocType,
    pub value_norm: String,
    pub source: String,
    pub severity: String,
    pub confidence: u8,
}

impl LoadedIndicator {
    fn hit(&self) -> MatchHit {
        MatchHit {
            ioc_type: self.ioc_type,
            value_norm: self.value_norm.clone(),
            source: self.source.clone(),
            severity: self.severity.clone(),
            confidence: self.confidence,
        }
    }
}

/// Pre-indexed indicator set for fast repeated matching.
#[derive(Default)]
pub struct MatchSet {
    exact: HashMap<String, LoadedIndicator>,
    domains: Vec<LoadedIndicator>,
    cidrs_v4: Vec<(u32, u32, LoadedIndicator)>, // (network, mask, indicator)
    cidrs_v6: Vec<(u128, u128, LoadedIndicator)>,
    len: usize,
}

impl MatchSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Fold another set into this one (used to merge a tenant watchlist into
    /// the global indicator set). Exact keys already present are not overwritten.
    pub fn merge(&mut self, other: MatchSet) {
        for (k, v) in other.exact {
            if self.exact.insert(k, v).is_none() {
                self.len += 1;
            }
        }
        for d in other.domains {
            self.domains.push(d);
            self.len += 1;
        }
        for c in other.cidrs_v4 {
            self.cidrs_v4.push(c);
            self.len += 1;
        }
        for c in other.cidrs_v6 {
            self.cidrs_v6.push(c);
            self.len += 1;
        }
    }

    /// Insert one indicator into the appropriate index. `len` counts only
    /// indicators actually stored, so a malformed CIDR (parseable as neither v4
    /// nor v6) is dropped without inflating the count.
    pub fn insert(&mut self, ind: LoadedIndicator) {
        let stored = match ind.ioc_type {
            IocType::Domain => {
                self.domains.push(ind);
                true
            }
            IocType::Cidr => {
                if let Some((net, mask)) = parse_cidr_v4(&ind.value_norm) {
                    self.cidrs_v4.push((net, mask, ind));
                    true
                } else if let Some((net, mask)) = parse_cidr_v6(&ind.value_norm) {
                    self.cidrs_v6.push((net, mask, ind));
                    true
                } else {
                    false
                }
            }
            _ => {
                self.exact.insert(ind.value_norm.clone(), ind);
                true
            }
        };
        if stored {
            self.len += 1;
        }
    }

    /// Match a single observable. `obs_type` narrows the search; domain
    /// observables also test the CIDR-free domain suffix list, and IP
    /// observables test the CIDR ranges.
    #[must_use]
    pub fn match_observable(&self, obs_type: IocType, raw: &str) -> Option<MatchHit> {
        let norm = normalize_value(obs_type, raw);
        if norm.is_empty() {
            return None;
        }
        // Exact hit first (cheapest, covers hashes/ips/urls/emails).
        if let Some(ind) = self.exact.get(&norm) {
            return Some(ind.hit());
        }
        match obs_type {
            IocType::Domain => self.match_domain(&norm),
            // An IP observable is matched only by exact key or CIDR membership —
            // never against the domain-suffix list.
            IocType::Ipv4 => self.match_ipv4(&norm),
            IocType::Ipv6 => self.match_ipv6(&norm),
            IocType::Url => {
                // Fall back to host match for a URL observable.
                let host = norm.split('/').next().unwrap_or(&norm);
                self.match_domain(host)
            }
            _ => None,
        }
    }

    /// Match a batch; returns one hit per matched observable (first match wins).
    #[must_use]
    pub fn match_batch(&self, observables: &[(IocType, String)]) -> Vec<(String, MatchHit)> {
        let mut out = Vec::new();
        for (ty, v) in observables {
            if let Some(hit) = self.match_observable(*ty, v) {
                out.push((v.clone(), hit));
            }
        }
        out
    }

    fn match_domain(&self, host: &str) -> Option<MatchHit> {
        for ind in &self.domains {
            if domain_matches(host, &ind.value_norm) {
                return Some(ind.hit());
            }
        }
        None
    }

    fn match_ipv4(&self, ip_str: &str) -> Option<MatchHit> {
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        let ipn = u32::from(ip);
        for (net, mask, ind) in &self.cidrs_v4 {
            if ipn & mask == *net & mask {
                return Some(ind.hit());
            }
        }
        None
    }

    fn match_ipv6(&self, ip_str: &str) -> Option<MatchHit> {
        let ip: Ipv6Addr = ip_str.parse().ok()?;
        let ipn = u128::from(ip);
        for (net, mask, ind) in &self.cidrs_v6 {
            if ipn & mask == *net & mask {
                return Some(ind.hit());
            }
        }
        None
    }
}

/// A hostname matches a flagged domain when it equals it or is a subdomain.
/// `mail.evil.com` matches `evil.com`; `notevil.com` does NOT match `evil.com`.
#[must_use]
pub fn domain_matches(host: &str, flagged: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let flagged = flagged.trim_end_matches('.').to_ascii_lowercase();
    if flagged.is_empty() {
        return false;
    }
    if host == flagged {
        return true;
    }
    host.ends_with(&format!(".{flagged}"))
}

/// Parse `a.b.c.d/pre` into (network, mask) as u32. Returns None if not v4 CIDR.
#[must_use]
pub fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)> {
    let (addr, pre) = cidr.split_once('/')?;
    let ip: Ipv4Addr = addr.trim().parse().ok()?;
    let prefix: u32 = pre.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((u32::from(ip) & mask, mask))
}

/// Parse an IPv6 CIDR into (network, mask) as u128.
#[must_use]
pub fn parse_cidr_v6(cidr: &str) -> Option<(u128, u128)> {
    let (addr, pre) = cidr.split_once('/')?;
    let ip: Ipv6Addr = addr.trim().parse().ok()?;
    let prefix: u32 = pre.trim().parse().ok()?;
    if prefix > 128 {
        return None;
    }
    let mask = if prefix == 0 {
        0u128
    } else {
        u128::MAX << (128 - prefix)
    };
    Some((u128::from(ip) & mask, mask))
}

/// Test whether an IPv4 string falls within a v4 CIDR string.
#[must_use]
pub fn ipv4_in_cidr(ip: &str, cidr: &str) -> bool {
    let Some((net, mask)) = parse_cidr_v4(cidr) else {
        return false;
    };
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    u32::from(addr) & mask == net
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ind(ty: IocType, v: &str) -> LoadedIndicator {
        LoadedIndicator {
            ioc_type: ty,
            value_norm: normalize_value(ty, v),
            source: "test".into(),
            severity: "high".into(),
            confidence: 90,
        }
    }

    #[test]
    fn domain_matches_exact_and_subdomain_only() {
        assert!(domain_matches("evil.com", "evil.com"));
        assert!(domain_matches("mail.evil.com", "evil.com"));
        assert!(domain_matches("a.b.evil.com", "evil.com"));
        assert!(!domain_matches("notevil.com", "evil.com"));
        assert!(!domain_matches("evil.com.good.org", "evil.com"));
    }

    #[test]
    fn cidr_v4_membership() {
        assert!(ipv4_in_cidr("10.1.2.3", "10.0.0.0/8"));
        assert!(!ipv4_in_cidr("11.1.2.3", "10.0.0.0/8"));
        assert!(ipv4_in_cidr("192.168.1.50", "192.168.1.0/24"));
        assert!(!ipv4_in_cidr("192.168.2.50", "192.168.1.0/24"));
        assert!(ipv4_in_cidr("8.8.8.8", "0.0.0.0/0"));
    }

    #[test]
    fn matchset_exact_ip_and_hash() {
        let mut ms = MatchSet::new();
        ms.insert(ind(IocType::Ipv4, "1.2.3.4"));
        ms.insert(ind(
            IocType::Sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ));
        assert!(ms.match_observable(IocType::Ipv4, "1.2.3.4").is_some());
        assert!(ms.match_observable(IocType::Ipv4, "1.2.3.5").is_none());
        assert!(ms
            .match_observable(
                IocType::Sha256,
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
            )
            .is_some());
        assert_eq!(ms.len(), 2);
    }

    #[test]
    fn matchset_domain_suffix_and_cidr() {
        let mut ms = MatchSet::new();
        ms.insert(ind(IocType::Domain, "evil.com"));
        ms.insert(ind(IocType::Cidr, "45.0.0.0/8"));
        assert!(ms
            .match_observable(IocType::Domain, "c2.evil.com")
            .is_some());
        assert!(ms.match_observable(IocType::Domain, "good.org").is_none());
        assert!(ms.match_observable(IocType::Ipv4, "45.33.22.11").is_some());
        assert!(ms.match_observable(IocType::Ipv4, "46.33.22.11").is_none());
    }

    #[test]
    fn batch_matching_returns_only_hits() {
        let mut ms = MatchSet::new();
        ms.insert(ind(IocType::Ipv4, "1.2.3.4"));
        let obs = vec![
            (IocType::Ipv4, "1.2.3.4".to_string()),
            (IocType::Ipv4, "9.9.9.9".to_string()),
        ];
        let hits = ms.match_batch(&obs);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "1.2.3.4");
    }
}
