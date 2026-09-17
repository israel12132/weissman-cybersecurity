//! IOC (Indicator of Compromise) subsystem.
//!
//! A real, multi-source indicator pipeline:
//!   * [`feeds`]    — connectors + pure parsers for abuse.ch (ThreatFox,
//!                    URLhaus, Feodo), AlienVault OTX, STIX 2.1 bundles,
//!                    line-based blocklists, and MISP.
//!   * [`decay`]    — confidence aging + expiry math (per-type half-lives).
//!   * [`matching`] — exact / CIDR / domain-suffix matching of host
//!                    observables against a loaded indicator set.
//!   * [`store`]    — Postgres upsert/query for the global indicator store and
//!                    the tenant-scoped sightings / watchlist tables.
//!   * [`ingest`]   — feed orchestration + per-tenant retrohunt.
//!
//! Design notes
//! ------------
//! Public threat-intel indicators are identical for every tenant, so the
//! indicator store (`ioc_indicators`) is GLOBAL. What a tenant *saw*
//! (`ioc_sightings`) and a tenant's own curated indicators (`ioc_watchlist`)
//! are tenant-secret and RLS-scoped. See the `20260913120000` migration.
//!
//! Live-only doctrine: every fetcher hits a real upstream over the audited
//! `outbound_http` client and fails visibly (logged, empty result) when an
//! API key is absent — it never fabricates indicators.

pub mod creds;
pub mod decay;
pub mod feeds;
pub mod ingest;
pub mod matching;
pub mod store;

use serde::{Deserialize, Serialize};

/// Canonical indicator categories we normalize every feed into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ipv4,
    Ipv6,
    Cidr,
    Domain,
    Url,
    Sha256,
    Sha1,
    Md5,
    Email,
    Ja3,
    Ja3s,
    FilePath,
    Mutex,
    RegistryKey,
}

impl IocType {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            IocType::Ipv4 => "ipv4",
            IocType::Ipv6 => "ipv6",
            IocType::Cidr => "cidr",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::Sha256 => "sha256",
            IocType::Sha1 => "sha1",
            IocType::Md5 => "md5",
            IocType::Email => "email",
            IocType::Ja3 => "ja3",
            IocType::Ja3s => "ja3s",
            IocType::FilePath => "file_path",
            IocType::Mutex => "mutex",
            IocType::RegistryKey => "registry_key",
        }
    }

    #[must_use]
    pub fn from_str_lenient(s: &str) -> Option<IocType> {
        let s = s.trim().to_ascii_lowercase();
        Some(match s.as_str() {
            "ipv4" | "ip" | "ip-dst" | "ip-src" | "ip:port" | "ip-dst|port" => IocType::Ipv4,
            "ipv6" => IocType::Ipv6,
            "cidr" | "network" => IocType::Cidr,
            "domain" | "hostname" | "domain-name" => IocType::Domain,
            "url" | "uri" | "link" => IocType::Url,
            "sha256" | "sha-256" | "sha256_hash" => IocType::Sha256,
            "sha1" | "sha-1" => IocType::Sha1,
            "md5" | "md5_hash" => IocType::Md5,
            "email" | "email-src" | "email-dst" | "email-addr" => IocType::Email,
            "ja3" | "ja3-fingerprint-md5" | "ja3_fingerprint" => IocType::Ja3,
            "ja3s" => IocType::Ja3s,
            "filename" | "file_path" | "filepath" => IocType::FilePath,
            "mutex" | "windows-service-name" => IocType::Mutex,
            "regkey" | "registry_key" | "windows-registry-key" => IocType::RegistryKey,
            _ => return None,
        })
    }

    /// True for indicator classes the endpoint agent can evaluate locally.
    #[must_use]
    pub fn endpoint_evaluable(&self) -> bool {
        matches!(
            self,
            IocType::Ipv4
                | IocType::Ipv6
                | IocType::Cidr
                | IocType::Domain
                | IocType::Sha256
                | IocType::Sha1
                | IocType::Md5
        )
    }
}

/// A normalized indicator ready for persistence / matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub ioc_type: IocType,
    /// Value as published (after re-fanging), for display.
    pub value: String,
    /// Canonical match key (see [`normalize_value`]).
    pub value_norm: String,
    pub source: String,
    pub confidence: u8,
    pub severity: String,
    pub tlp: String,
    pub malware_family: String,
    pub mitre: String,
    pub tags: Vec<String>,
    pub reference_url: String,
}

impl Indicator {
    /// Build an indicator from a raw value, inferring normalization.
    pub fn new(ioc_type: IocType, raw_value: impl Into<String>, source: impl Into<String>) -> Self {
        let raw = raw_value.into();
        let refanged = refang(&raw);
        let value_norm = normalize_value(ioc_type, &refanged);
        Indicator {
            ioc_type,
            value: refanged,
            value_norm,
            source: source.into(),
            confidence: 50,
            severity: "medium".to_string(),
            tlp: "amber".to_string(),
            malware_family: String::new(),
            mitre: String::new(),
            tags: Vec::new(),
            reference_url: String::new(),
        }
    }

    #[must_use]
    pub fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c.min(100);
        self
    }

    #[must_use]
    pub fn with_severity(mut self, s: impl Into<String>) -> Self {
        self.severity = s.into();
        self
    }

    #[must_use]
    pub fn with_family(mut self, f: impl Into<String>) -> Self {
        self.malware_family = f.into();
        self
    }

    #[must_use]
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    #[must_use]
    pub fn with_reference(mut self, r: impl Into<String>) -> Self {
        self.reference_url = r.into();
        self
    }

    /// Valid once normalization produced a non-empty key of a plausible shape.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.value_norm.is_empty() || self.value_norm.len() > 2048 {
            return false;
        }
        match self.ioc_type {
            IocType::Ipv4 => self.value_norm.parse::<std::net::Ipv4Addr>().is_ok(),
            IocType::Ipv6 => self.value_norm.parse::<std::net::Ipv6Addr>().is_ok(),
            IocType::Sha256 => is_hex_len(&self.value_norm, 64),
            IocType::Sha1 => is_hex_len(&self.value_norm, 40),
            IocType::Md5 => is_hex_len(&self.value_norm, 32),
            IocType::Domain => looks_like_domain(&self.value_norm),
            IocType::Email => self.value_norm.contains('@') && self.value_norm.contains('.'),
            _ => true,
        }
    }
}

fn is_hex_len(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Canonicalize a dotted-quad IPv4 (tolerating zero-padded octets and an
/// optional `/prefix` or `:port` suffix that is stripped). `std::net::Ipv4Addr`
/// rejects zero-padded octets ("001.002.003.004") to avoid octal ambiguity, so
/// we parse octets ourselves. Returns the canonical `a.b.c.d` form or None.
#[must_use]
pub fn canonical_ipv4(s: &str) -> Option<String> {
    let host = s
        .split('/')
        .next()
        .unwrap_or(s)
        .split(':')
        .next()
        .unwrap_or(s)
        .trim();
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u32 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        octets[i] = n as u8;
    }
    Some(format!(
        "{}.{}.{}.{}",
        octets[0], octets[1], octets[2], octets[3]
    ))
}

/// A domain label string: at least one dot, only DNS-safe characters, no spaces.
#[must_use]
pub fn looks_like_domain(s: &str) -> bool {
    if !s.contains('.') || s.len() > 253 || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

/// Re-fang a defanged indicator: `hxxp://`, `[.]`, `(.)`, `[:]`, ` dot ` → real.
#[must_use]
pub fn refang(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    // Scheme defanging.
    s = s
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://");
    s = s
        .replace("hXXps://", "https://")
        .replace("hXXp://", "http://");
    s = s
        .replace("hxxps[:]//", "https://")
        .replace("hxxp[:]//", "http://");
    // Dot / colon bracketing.
    s = s
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[dot]", ".")
        .replace("(dot)", ".")
        .replace("[:]", ":")
        .replace("[://]", "://");
    // " dot " spelled out (only when it clearly separates labels).
    s = s.replace(" [.] ", ".").replace(" dot ", ".");
    s.trim().to_string()
}

/// Canonical matching key for a given indicator class.
///
/// * domains / emails / hashes → lowercased, trailing dot stripped.
/// * urls → scheme dropped, host lowercased, fragment/query trimmed, kept as
///   `host/path` so both full-URL and host lookups can hit.
/// * ips → parsed + re-serialized to canonical form where possible.
#[must_use]
pub fn normalize_value(ioc_type: IocType, refanged: &str) -> String {
    let v = refanged.trim();
    match ioc_type {
        IocType::Domain => v.trim_end_matches('.').to_ascii_lowercase(),
        IocType::Email
        | IocType::Ja3
        | IocType::Ja3s
        | IocType::Sha256
        | IocType::Sha1
        | IocType::Md5 => v.to_ascii_lowercase(),
        IocType::Ipv4 => canonical_ipv4(v).unwrap_or_else(|| v.to_string()),
        IocType::Ipv6 => v
            .parse::<std::net::Ipv6Addr>()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| v.to_ascii_lowercase()),
        IocType::Cidr => v.to_ascii_lowercase(),
        IocType::Url => normalize_url(v),
        IocType::FilePath | IocType::Mutex | IocType::RegistryKey => v.to_string(),
    }
}

fn normalize_url(raw: &str) -> String {
    let no_scheme = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .unwrap_or(raw);
    // Drop fragment then query for a stable key.
    let no_frag = no_scheme.split('#').next().unwrap_or(no_scheme);
    let core = no_frag.split('?').next().unwrap_or(no_frag);
    let core = core.trim_end_matches('/');
    // Lowercase only the host portion (path is case-sensitive on many servers).
    match core.split_once('/') {
        Some((host, path)) => format!("{}/{}", host.to_ascii_lowercase(), path),
        None => core.to_ascii_lowercase(),
    }
}

/// Heuristically classify a raw observable value. Returns `None` when no
/// confident classification is possible (caller should skip it).
#[must_use]
pub fn guess_type(raw: &str) -> Option<IocType> {
    let v = refang(raw);
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    if v.starts_with("http://") || v.starts_with("https://") {
        return Some(IocType::Url);
    }
    if v.contains('@') && !v.contains('/') && looks_like_domain(v.split('@').nth(1).unwrap_or("")) {
        return Some(IocType::Email);
    }
    if v.contains('/')
        && v.split('/')
            .next()
            .unwrap_or("")
            .parse::<std::net::Ipv4Addr>()
            .is_ok()
    {
        return Some(IocType::Cidr);
    }
    if v.parse::<std::net::Ipv4Addr>().is_ok()
        || (!v.contains('/') && !v.contains(':') && canonical_ipv4(v).is_some())
    {
        return Some(IocType::Ipv4);
    }
    if v.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some(IocType::Ipv6);
    }
    let lower = v.to_ascii_lowercase();
    if is_hex_len(&lower, 64) {
        return Some(IocType::Sha256);
    }
    if is_hex_len(&lower, 40) {
        return Some(IocType::Sha1);
    }
    if is_hex_len(&lower, 32) {
        return Some(IocType::Md5);
    }
    if looks_like_domain(v) {
        return Some(IocType::Domain);
    }
    None
}

/// Map a severity string to a 0..=4 rank for comparison.
#[must_use]
pub fn severity_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refang_handles_common_defang_styles() {
        assert_eq!(refang("hxxps://evil[.]com/a"), "https://evil.com/a");
        assert_eq!(refang("1[.]2[.]3[.]4"), "1.2.3.4");
        assert_eq!(refang("evil(dot)com"), "evil.com");
        assert_eq!(refang("  bad[.]domain[.]net  "), "bad.domain.net");
    }

    #[test]
    fn normalize_domain_lowercases_and_strips_dot() {
        assert_eq!(normalize_value(IocType::Domain, "EVIL.COM."), "evil.com");
    }

    #[test]
    fn normalize_url_drops_scheme_query_and_trailing_slash() {
        assert_eq!(
            normalize_value(IocType::Url, "https://Bad.COM/Path/?x=1#frag"),
            "bad.com/Path"
        );
        assert_eq!(normalize_value(IocType::Url, "http://Bad.COM/"), "bad.com");
    }

    #[test]
    fn normalize_ipv4_canonicalizes_and_strips_port() {
        assert_eq!(normalize_value(IocType::Ipv4, "1.2.3.4:443"), "1.2.3.4");
        assert_eq!(normalize_value(IocType::Ipv4, "001.002.003.004"), "1.2.3.4");
    }

    #[test]
    fn guess_type_classifies_each_class() {
        assert_eq!(guess_type("https://x.com/a"), Some(IocType::Url));
        assert_eq!(guess_type("8.8.8.8"), Some(IocType::Ipv4));
        assert_eq!(guess_type("10.0.0.0/8"), Some(IocType::Cidr));
        assert_eq!(guess_type("evil.com"), Some(IocType::Domain));
        assert_eq!(guess_type("a@evil.com"), Some(IocType::Email));
        assert_eq!(
            guess_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            Some(IocType::Sha256)
        );
        assert_eq!(guess_type(""), None);
        assert_eq!(guess_type("not a thing"), None);
    }

    #[test]
    fn indicator_validity_checks_shape() {
        assert!(Indicator::new(IocType::Ipv4, "1.2.3.4", "t").is_valid());
        assert!(!Indicator::new(IocType::Ipv4, "999.1.1.1", "t").is_valid());
        assert!(Indicator::new(
            IocType::Sha256,
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "t"
        )
        .is_valid());
        assert!(!Indicator::new(IocType::Sha256, "deadbeef", "t").is_valid());
        assert!(Indicator::new(IocType::Domain, "bad.example.com", "t").is_valid());
        assert!(!Indicator::new(IocType::Domain, "localhost", "t").is_valid());
    }

    #[test]
    fn endpoint_evaluable_covers_host_classes() {
        assert!(IocType::Sha256.endpoint_evaluable());
        assert!(IocType::Ipv4.endpoint_evaluable());
        assert!(IocType::Domain.endpoint_evaluable());
        assert!(!IocType::Url.endpoint_evaluable());
        assert!(!IocType::Email.endpoint_evaluable());
    }
}
