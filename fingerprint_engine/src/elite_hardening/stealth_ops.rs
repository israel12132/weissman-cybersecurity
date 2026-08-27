//! Stealth operators: jitter, DoH, header strip, beaconing.

use weissman_core::stealth_identity::{STRIP_HEADER_NAMES, USER_AGENTS};

pub const JITTER_PCT_MIN: u32 = 15;
pub const JITTER_PCT_MAX: u32 = 30;

/// Add 15–30% random jitter to a base interval (HTTPS beacon / heartbeat).
pub fn jitter_percent(base_ms: u64) -> u64 {
    if base_ms == 0 {
        return 0;
    }
    let pct = rand::random_range(JITTER_PCT_MIN..=JITTER_PCT_MAX);
    base_ms.saturating_add(base_ms.saturating_mul(pct as u64) / 100)
}

pub fn random_user_agent() -> &'static str {
    let i = rand::random_range(0..USER_AGENTS.len());
    USER_AGENTS[i]
}

pub fn is_scanner_header(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    STRIP_HEADER_NAMES.iter().any(|h| *h == n)
}

/// Cloudflare + Google DoH endpoints (high reputation).
pub const DOH_ENDPOINTS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
];

pub fn doh_endpoint() -> &'static str {
    let i = rand::random_range(0..DOH_ENDPOINTS.len());
    DOH_ENDPOINTS[i]
}

/// RFC 8484 JSON DoH query URL for an A record.
pub fn doh_json_url(name: &str) -> String {
    let host = name.trim().trim_end_matches('.');
    format!(
        "{}?name={}&type=A",
        doh_endpoint(),
        urlencoding::encode(host)
    )
}

/// Asset-class scan governor: production/ICS is slower than lab/dev.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetClass {
    Lab,
    Dev,
    Prod,
    Ics,
}

impl AssetClass {
    pub fn from_tags(tags: &[String]) -> Self {
        let joined = tags.join(" ").to_ascii_lowercase();
        if joined.contains("ics") || joined.contains("ot") || joined.contains("scada") {
            AssetClass::Ics
        } else if joined.contains("prod") || joined.contains("production") {
            AssetClass::Prod
        } else if joined.contains("dev") || joined.contains("staging") {
            AssetClass::Dev
        } else {
            AssetClass::Lab
        }
    }

    /// Multiplier applied to the per-tenant scan-per-minute quota (lower = stricter).
    pub fn scan_quota_factor(&self) -> f64 {
        match self {
            AssetClass::Ics => 0.15,
            AssetClass::Prod => 0.40,
            AssetClass::Dev => 0.75,
            AssetClass::Lab => 1.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_in_band() {
        let base = 1000u64;
        for _ in 0..50 {
            let j = jitter_percent(base);
            assert!(j >= 1150 && j <= 1300, "got {j}");
        }
    }

    #[test]
    fn ics_is_strictest() {
        assert!(AssetClass::Ics.scan_quota_factor() < AssetClass::Prod.scan_quota_factor());
        assert_eq!(AssetClass::from_tags(&["ot-ics".into()]), AssetClass::Ics);
    }

    #[test]
    fn strips_scanner_headers() {
        assert!(is_scanner_header("X-Scanner"));
        assert!(!is_scanner_header("User-Agent"));
    }

    #[test]
    fn doh_url_is_https() {
        let u = doh_json_url("example.com");
        assert!(u.starts_with("https://"));
        assert!(u.contains("example.com"));
    }
}
