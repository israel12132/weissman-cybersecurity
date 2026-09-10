//! Live-only truth for HTTP transport and mail DNS claims.
//!
//! Engines used to emit "Missing HSTS" from a Cloudflare 403 interstitial and
//! "No DMARC" / "No SPF" against `www.` instead of the organisational domain.
//! Those findings are not customer-true. This module is the single gate.
//!
//! Timing / sampling engines must also **fail fast** on an edge block: a 403/429
//! WAF challenge is not an origin oracle. Sampling it for minutes deadlocks the
//! catalog scan. [`skip_if_edge_block`] is the shared preflight.

use crate::engine_probes::HttpProbe;
use crate::engine_result::EngineResult;
use std::time::Duration;

/// One GET for edge-block preflight. Shorter than engine sample budgets so a hung
/// challenge page cannot stall the caller.
const EDGE_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(8);

/// Two-level public suffixes so `mail.corp.co.uk` → `corp.co.uk`.
const MULTI_PART_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "co.il",
    "org.il", "ac.il", "gov.il", "net.il", "muni.il", "k12.il", "idf.il", "co.jp", "or.jp",
    "ne.jp", "go.jp", "ac.jp", "co.kr", "or.kr", "go.kr", "com.au", "net.au", "org.au", "edu.au",
    "gov.au", "com.br", "net.br", "org.br", "gov.br", "com.cn", "net.cn", "org.cn", "gov.cn",
    "edu.cn", "com.tr", "gov.tr", "edu.tr", "co.za", "org.za", "gov.za", "co.nz", "net.nz",
    "org.nz", "govt.nz", "com.mx", "com.ar", "com.sg", "com.hk", "com.tw", "com.ua", "com.pl",
    "com.ph", "co.in", "net.in", "org.in", "gov.in",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HstsObservation {
    /// Successful HTTPS response with no Strict-Transport-Security.
    Missing,
    /// Present; `max_age` is the parsed directive (0 if unparsable).
    Present { max_age: u64, include_subdomains: bool },
    /// WAF/CDN challenge — header set on the origin is unknown.
    UnknownWaf,
    /// Non-success HTTP — do not claim HSTS is missing.
    UnknownStatus,
    /// Cleartext or empty probe.
    UnknownUnreachable,
}

impl HstsObservation {
    #[must_use]
    pub fn emit_missing(self) -> bool {
        matches!(self, HstsObservation::Missing)
    }
}

#[must_use]
pub fn organizational_domain(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.parse::<std::net::IpAddr>().is_ok() {
        return h;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() <= 2 {
        return h;
    }
    let last2 = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if MULTI_PART_SUFFIXES.iter().any(|s| *s == last2) && labels.len() >= 3 {
        return format!("{}.{}", labels[labels.len() - 3], last2);
    }
    last2
}

#[must_use]
pub fn host_from_target(target: &str) -> String {
    let t = target.trim();
    if t.is_empty() {
        return String::new();
    }
    let stripped = t
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = stripped
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase();
    host
}

fn parse_hsts_max_age(hsts: &str) -> u64 {
    let lower = hsts.to_ascii_lowercase();
    lower
        .split(';')
        .filter_map(|part| {
            let p = part.trim();
            p.strip_prefix("max-age=").and_then(|v| v.trim().parse().ok())
        })
        .next()
        .unwrap_or(0)
}

fn header_ci(headers_blob: &str, name: &str) -> Option<String> {
    let want = name.to_ascii_lowercase();
    for line in headers_blob.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(&want) {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Judge HSTS only on a live HTTPS 2xx/3xx that is not a WAF challenge.
#[must_use]
pub fn observe_hsts(
    status: u16,
    headers_blob: &str,
    body: &str,
    final_url: &str,
) -> HstsObservation {
    if crate::waf_signals::is_waf_block(status, headers_blob, body) {
        return HstsObservation::UnknownWaf;
    }
    if !(200..400).contains(&status) {
        return HstsObservation::UnknownStatus;
    }
    if !final_url.to_ascii_lowercase().starts_with("https://") {
        return HstsObservation::UnknownUnreachable;
    }
    match header_ci(headers_blob, "strict-transport-security") {
        Some(hsts) if !hsts.is_empty() => HstsObservation::Present {
            max_age: parse_hsts_max_age(&hsts),
            include_subdomains: hsts.to_ascii_lowercase().contains("includesubdomains"),
        },
        _ => HstsObservation::Missing,
    }
}

#[must_use]
pub fn observe_hsts_probe(p: &HttpProbe) -> HstsObservation {
    observe_hsts(p.status, &p.headers_blob(), &p.body, &p.final_url)
}

#[must_use]
pub fn title_claims_missing_hsts(title: &str) -> bool {
    let t = title.to_ascii_lowercase();
    (t.contains("missing hsts") || t.contains("hsts header missing") || t.contains("no hsts"))
        && !t.contains("max-age too short")
}

#[must_use]
pub fn title_claims_missing_dmarc(title: &str) -> bool {
    let t = title.to_ascii_lowercase();
    t.contains("no dmarc") || t.contains("missing dmarc")
}

#[must_use]
pub fn title_claims_missing_spf(title: &str) -> bool {
    let t = title.to_ascii_lowercase();
    t.contains("no spf") || t.contains("missing spf") || t.contains("lacks local spf")
}

/// `www` is a web hostname. Mail policy lives on the organisational domain.
/// Claiming "no DMARC/SPF" on www is stale unless www *is* the org domain.
#[must_use]
pub fn stale_www_mail_claim(title: &str, target: &str) -> bool {
    let mail_claim = title_claims_missing_dmarc(title) || title_claims_missing_spf(title);
    if !mail_claim {
        return false;
    }
    let host = host_from_target(target);
    if host.is_empty() {
        let t = title.to_ascii_lowercase();
        return t.contains("www.");
    }
    let org = organizational_domain(&host);
    host != org && (host.starts_with("www.") || host == format!("www.{org}"))
}

/// WAF/CDN challenge or explicit 403/429 — not an application signal for
/// timing, SSTI, spray, or fuzz sampling.
#[must_use]
pub fn probe_is_edge_block(p: &HttpProbe) -> bool {
    p.is_waf_block() || matches!(p.status, 403 | 429)
}

/// Empty success so the catalog scan records a skip, not a hard engine failure.
#[must_use]
pub fn edge_block_skip_result(engine_id: &str, target: &str, detail: &str) -> EngineResult {
    EngineResult::ok(
        vec![],
        format!("{engine_id}: edge block on {target} — skipped ({detail})"),
    )
}

/// One short GET. If the edge blocks, return skip so callers do not sample.
/// Unreachable / timed-out preflight returns `None` (let the engine or resilience decide).
pub async fn skip_if_edge_block(engine_id: &str, target: &str) -> Option<EngineResult> {
    let url = crate::engine_probes::normalize_url(target);
    if url.is_empty() {
        return None;
    }
    let client = crate::engine_probes::http_client().await;
    let probe = tokio::time::timeout(
        EDGE_PREFLIGHT_TIMEOUT,
        crate::engine_probes::http_get(&client, &url),
    )
    .await
    .ok()
    .flatten();
    let p = probe?;
    if probe_is_edge_block(&p) {
        Some(edge_block_skip_result(
            engine_id,
            target,
            &format!("HTTP {}", p.status),
        ))
    } else {
        None
    }
}

/// Persist/verify: this row is not customer-true given live HTTP or www-vs-apex mail.
#[must_use]
pub fn finding_is_stale_transport_or_mail(
    title: &str,
    target: &str,
    status: u16,
    headers_blob: &str,
    body: &str,
    final_url: &str,
) -> bool {
    if stale_www_mail_claim(title, target) {
        return true;
    }
    if title_claims_missing_hsts(title) {
        return !observe_hsts(status, headers_blob, body, final_url).emit_missing();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_domain_strips_www() {
        assert_eq!(organizational_domain("www.augury.com"), "augury.com");
        assert_eq!(organizational_domain("augury.com"), "augury.com");
        assert_eq!(organizational_domain("mail.corp.co.uk"), "corp.co.uk");
    }

    #[test]
    fn www_dmarc_claim_is_stale() {
        assert!(stale_www_mail_claim(
            "No DMARC record published",
            "https://www.augury.com"
        ));
        assert!(!stale_www_mail_claim(
            "No DMARC record published",
            "https://augury.com"
        ));
        assert!(stale_www_mail_claim(
            "No SPF record published",
            "www.augury.com"
        ));
    }

    #[test]
    fn hsts_present_on_200_not_missing() {
        let obs = observe_hsts(
            200,
            "server: cloudflare\nstrict-transport-security: max-age=31536000; includeSubDomains\n",
            "<html/>",
            "https://www.augury.com/",
        );
        assert_eq!(
            obs,
            HstsObservation::Present {
                max_age: 31_536_000,
                include_subdomains: true
            }
        );
        assert!(!obs.emit_missing());
    }

    #[test]
    fn hsts_403_cloudflare_is_unknown() {
        let obs = observe_hsts(
            403,
            "server: cloudflare\ncf-ray: abc\n",
            "Attention Required! Cloudflare",
            "https://www.augury.com/",
        );
        assert_eq!(obs, HstsObservation::UnknownWaf);
        assert!(!obs.emit_missing());
    }

    #[test]
    fn missing_hsts_only_on_https_success() {
        let obs = observe_hsts(200, "server: nginx\n", "ok", "https://example.com/");
        assert_eq!(obs, HstsObservation::Missing);
        assert!(obs.emit_missing());
    }

    #[test]
    fn title_hsts_detect() {
        assert!(title_claims_missing_hsts("Missing HSTS header"));
        assert!(title_claims_missing_hsts("HSTS header missing"));
        assert!(!title_claims_missing_hsts("HSTS max-age too short"));
    }

    fn probe(status: u16, headers: Vec<(&str, &str)>, body: &str) -> HttpProbe {
        HttpProbe {
            status,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
            final_url: "https://www.example.com/".to_string(),
        }
    }

    #[test]
    fn cloudflare_403_is_edge_block() {
        let p = probe(
            403,
            vec![("server", "cloudflare"), ("cf-ray", "abc")],
            "Attention Required! Cloudflare",
        );
        assert!(probe_is_edge_block(&p));
        assert!(!probe_is_edge_block(&probe(200, vec![("server", "nginx")], "ok")));
        assert!(!probe_is_edge_block(&probe(
            401,
            vec![("www-authenticate", "Basic")],
            "auth required"
        )));
        assert!(probe_is_edge_block(&probe(429, vec![], "slow down")));
        assert!(probe_is_edge_block(&probe(403, vec![], "forbidden")));
    }

    #[test]
    fn edge_skip_result_is_empty_ok() {
        let r = edge_block_skip_result("timing_sidechannel", "https://x", "HTTP 403");
        assert_eq!(r.status, "ok");
        assert!(r.findings.is_empty());
        assert!(r.message.contains("skipped"));
    }
}
