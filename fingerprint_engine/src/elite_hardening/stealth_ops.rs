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
    doh_json_url_typed(name, "A")
}

/// RFC 8484 JSON DoH query URL for an arbitrary RR type (TXT, MX, AAAA, …).
pub fn doh_json_url_typed(name: &str, record_type: &str) -> String {
    let host = name.trim().trim_end_matches('.');
    let rr = record_type.trim().to_ascii_uppercase();
    format!(
        "{}?name={}&type={}",
        doh_endpoint(),
        urlencoding::encode(host),
        urlencoding::encode(&rr)
    )
}

/// Lab override: allow Hickory UDP/TCP when DoH is empty. Production default is DoH-only.
pub fn allow_udp_dns_fallback() -> bool {
    matches!(
        std::env::var("WEISSMAN_DNS_ALLOW_UDP")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Strip DoH JSON TXT quoting (`"v=spf1 …"` or split `"ab" "cd"`).
pub fn strip_doh_txt(raw: &str) -> String {
    let mut out = String::new();
    for part in raw.split('"') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        out.push_str(p);
    }
    if out.is_empty() {
        raw.trim().to_string()
    } else {
        out
    }
}

/// Parse Cloudflare/Google `application/dns-json` Answer[].data values.
pub fn parse_doh_answer_data(body: &serde_json::Value) -> Vec<String> {
    body.get("Answer")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|rr| rr.get("data").and_then(|d| d.as_str()))
                .map(|s| s.trim().trim_end_matches('.').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Result of a single DoH query. `definitive` is true when the resolver returned
/// NOERROR (0) or NXDOMAIN (3) — empty answers in that case are authoritative.
#[derive(Debug, Clone)]
pub struct DohLookup {
    pub answers: Vec<String>,
    pub definitive: bool,
}

/// Live DoH lookup (TLS 1.2+). Empty vec on transport/JSON failure — callers must not
/// silently fall back to UDP unless `allow_udp_dns_fallback()` is set.
pub async fn doh_lookup(name: &str, record_type: &str) -> Result<Vec<String>, String> {
    Ok(doh_lookup_detailed(name, record_type).await?.answers)
}

pub async fn doh_lookup_detailed(name: &str, record_type: &str) -> Result<DohLookup, String> {
    let host = name.trim();
    if host.is_empty() {
        return Err("empty DNS name".into());
    }
    let url = doh_json_url_typed(host, record_type);
    let client = crate::scan_http_client::internal_json_client(std::time::Duration::from_secs(8));
    let resp = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("DoH HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let mut answers = parse_doh_answer_data(&body);
    if record_type.eq_ignore_ascii_case("TXT") {
        answers = answers.into_iter().map(|s| strip_doh_txt(&s)).collect();
    }
    let dns_status = body.get("Status").and_then(|s| s.as_u64());
    let definitive = matches!(dns_status, Some(0) | Some(3));
    Ok(DohLookup {
        answers,
        definitive,
    })
}

/// Production DNS: DoH → DoT → organisation-internal UDP. Public UDP stays off.
pub async fn dns_lookup_cascade(name: &str, record_type: &str) -> Vec<String> {
    crate::elite_hardening::dns_cascade::lookup(name, record_type).await
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
        let txt = doh_json_url_typed("example.com", "TXT");
        assert!(txt.contains("type=TXT"));
    }

    #[test]
    fn doh_json_parses_answers() {
        let body = serde_json::json!({
            "Status": 0,
            "Answer": [
                {"name": "example.com.", "type": 1, "data": "93.184.216.34"}
            ]
        });
        let a = parse_doh_answer_data(&body);
        assert_eq!(a, vec!["93.184.216.34"]);
        assert_eq!(strip_doh_txt("\"v=spf1 -all\""), "v=spf1 -all");
        assert!(!allow_udp_dns_fallback());
    }
}
