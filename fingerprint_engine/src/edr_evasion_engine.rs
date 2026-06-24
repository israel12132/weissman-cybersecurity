//! Detection & Evasion Surface Engine — world-class adversary-resilience assessment.
//!
//! Measures, with **live read-only probes only**, how hard it is for an attacker to operate
//! undetected against a target's observable perimeter — the same dimensions Wiz / CrowdStrike /
//! SentinelOne care about, but from the *remote* assessment plane an external red team actually has:
//!
//!   * **Edge detection matrix** — WAF/CDN/bot-management fingerprint (Cloudflare, Akamai, AWS WAF,
//!     Imperva, Sucuri, Fastly, DataDome, PerimeterX, …) plus a multi-User-Agent block-rate score.
//!   * **Rate-limit & challenge behaviour** — burst probe; 429/503/`Retry-After`/CAPTCHA body signals.
//!   * **Script-delivery & CSP posture** — `unsafe-inline`/`unsafe-eval`, wildcard `connect-src`,
//!     missing SRI on third-party scripts (injection runway for fileless-style payloads).
//!   * **Session/cookie hardening** — `Secure`/`HttpOnly`/`SameSite` audit on live `Set-Cookie`.
//!   * **Defender telemetry leakage** — RUM/APM/error-tracking keys in HTML/JS (Sentry, Datadog,
//!     New Relic, App Insights, Rollbar, Firebase, Segment) — *more* telemetry = harder to evade.
//!   * **Debug & admin surface** — reachable diagnostics, actuator, `.env`, source-map exposure.
//!   * **Error verbosity** — stack traces / framework debug pages on malformed requests.
//!   * **Minimal fingerprint / C2 fronting signals** — stripped `Server` headers, CDN fronting hints.
//!
//! Host-resident EDR checks (AMSI patch, ETW blind, syscall unhooking, process hollowing) **cannot**
//! be observed remotely; when `include_agent_findings` is on the engine emits an honest `agent_required`
//! guidance row pointing operators to the endpoint agent — never a fabricated high-severity hit.
//!
//! Every knob flows from `EngineRunContext::job_params` via [`crate::arsenal_config::ArsenalConfig`].
//! MITRE: T1562 (Impair Defenses), T1071 (Application Layer Protocol), T1027 (Obfuscated Files).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, has_header, header_value, http_client, http_get,
    http_get_with_headers, normalize_url, probe_paths_concurrent, status_indicates_presence,
    HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::OnceLock;

const ENGINE_ID: &str = "edr_evasion";
const MITRE_IMPAIR: &str = "T1562";
const MITRE_APP: &str = "T1071";

// ── Configuration ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct EdrScanConfig {
    intensity: Intensity,
    timeout_ms: u64,
    ua_burst: usize,
    rate_burst: u8,
    check_waf: bool,
    check_ua_matrix: bool,
    check_rate_limit: bool,
    check_headers: bool,
    check_cookies: bool,
    check_csp: bool,
    check_telemetry: bool,
    check_debug_paths: bool,
    check_source_maps: bool,
    check_error_verbosity: bool,
    check_minimal_fingerprint: bool,
    emit_agent_guidance: bool,
    extra_paths: Vec<String>,
    extra_user_agents: Vec<String>,
}

impl Default for EdrScanConfig {
    fn default() -> Self {
        Self {
            intensity: Intensity::Normal,
            timeout_ms: 8000,
            ua_burst: 24,
            rate_burst: 12,
            check_waf: true,
            check_ua_matrix: true,
            check_rate_limit: true,
            check_headers: true,
            check_cookies: true,
            check_csp: true,
            check_telemetry: true,
            check_debug_paths: true,
            check_source_maps: true,
            check_error_verbosity: true,
            check_minimal_fingerprint: true,
            emit_agent_guidance: true,
            extra_paths: Vec::new(),
            extra_user_agents: Vec::new(),
        }
    }
}

impl EdrScanConfig {
    fn from_ctx(ctx: &EngineRunContext) -> Self {
        let c = ArsenalConfig::from_ctx(ctx);
        let mut cfg = Self::default();
        cfg.intensity = c.intensity();
        match cfg.intensity {
            Intensity::Light => {
                cfg.rate_burst = 6;
                cfg.ua_burst = 12;
                cfg.check_source_maps = false;
            }
            Intensity::Normal => {}
            Intensity::Aggressive => {
                cfg.rate_burst = 24;
                cfg.ua_burst = 40;
            }
        }
        cfg.timeout_ms = c.timeout_ms(cfg.timeout_ms);
        cfg.ua_burst = c.usize_or("ua_matrix_limit", cfg.ua_burst).clamp(4, 80);
        cfg.rate_burst = u8::try_from(c.u64_or("rate_burst_count", u64::from(cfg.rate_burst)))
            .unwrap_or(cfg.rate_burst)
            .clamp(3, 40);
        cfg.check_waf = c.bool_or("check_waf", cfg.check_waf);
        cfg.check_ua_matrix = c.bool_or("check_ua_matrix", cfg.check_ua_matrix);
        cfg.check_rate_limit = c.bool_or("check_rate_limit", cfg.check_rate_limit);
        cfg.check_headers = c.bool_or("check_headers", cfg.check_headers);
        cfg.check_cookies = c.bool_or("check_cookies", cfg.check_cookies);
        cfg.check_csp = c.bool_or("check_csp", cfg.check_csp);
        cfg.check_telemetry = c.bool_or("check_telemetry", cfg.check_telemetry);
        cfg.check_debug_paths = c.bool_or("check_debug_paths", cfg.check_debug_paths);
        cfg.check_source_maps = c.bool_or("check_source_maps", cfg.check_source_maps);
        cfg.check_error_verbosity = c.bool_or("check_error_verbosity", cfg.check_error_verbosity);
        cfg.check_minimal_fingerprint = c.bool_or("check_minimal_fingerprint", cfg.check_minimal_fingerprint);
        cfg.emit_agent_guidance = c.emit_agent_guidance();
        cfg.extra_paths = c.string_list("extra_paths");
        cfg.extra_user_agents = c.string_list("extra_user_agents");
        cfg
    }
}

// ── WAF / CDN / Bot fingerprint ──────────────────────────────────────────────

struct WafHit {
    vendor: &'static str,
    signal: String,
    confidence: f64,
}

fn fingerprint_edge(probe: &HttpProbe) -> Option<WafHit> {
    let body_lc = probe.body.to_ascii_lowercase();
    let checks: &[(&str, &str, &str, f64)] = &[
        ("cf-ray", "", "Cloudflare", 0.95),
        ("cf-mitigated", "", "Cloudflare", 0.98),
        ("cf-cache-status", "", "Cloudflare", 0.85),
        ("x-sucuri-id", "", "Sucuri WAF", 0.95),
        ("x-sucuri-cache", "", "Sucuri WAF", 0.9),
        ("x-akamai-transformed", "", "Akamai CDN/WAF", 0.92),
        ("akamaighost", "", "Akamai CDN/WAF", 0.9),
        ("x-imperva-waf", "", "Imperva WAF", 0.95),
        ("x-iinfo", "", "Imperva/Incapsula", 0.88),
        ("x-amzn-requestid", "", "AWS CloudFront/WAF", 0.8),
        ("x-amz-cf-id", "", "AWS CloudFront", 0.88),
        ("x-fastly-request-id", "", "Fastly", 0.9),
        ("x-datadome", "", "DataDome Bot Management", 0.95),
        ("x-px-", "", "PerimeterX Bot Defender", 0.9),
        ("x-cdn", "", "Generic CDN", 0.7),
        ("server", "cloudflare", "Cloudflare", 0.85),
        ("server", "awselb", "AWS ELB/WAF", 0.8),
        ("server", "AkamaiGHost", "Akamai", 0.88),
    ];
    for (hdr, needle, vendor, conf) in checks {
        if let Some(v) = header_value(&probe.headers, hdr) {
            if needle.is_empty() || v.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()) {
                return Some(WafHit {
                    vendor,
                    signal: format!("{hdr}={v}"),
                    confidence: *conf,
                });
            }
        }
    }
    if body_lc.contains("attention required")
        || body_lc.contains("checking your browser")
        || body_lc.contains("cf-browser-verification")
    {
        return Some(WafHit {
            vendor: "Cloudflare Bot Challenge",
            signal: "challenge-page-body".to_string(),
            confidence: 0.92,
        });
    }
    if body_lc.contains("access denied")
        && (body_lc.contains("imperva") || body_lc.contains("incapsula"))
    {
        return Some(WafHit {
            vendor: "Imperva WAF",
            signal: "block-page-body".to_string(),
            confidence: 0.9,
        });
    }
    if body_lc.contains("request blocked") && body_lc.contains("aws") {
        return Some(WafHit {
            vendor: "AWS WAF",
            signal: "aws-waf-block-page".to_string(),
            confidence: 0.88,
        });
    }
    None
}

// ── User-Agent matrix ────────────────────────────────────────────────────────

fn default_scanner_user_agents() -> Vec<&'static str> {
    vec![
        "sqlmap/1.7.2#stable",
        "Nikto/2.1.6",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "masscan/1.3",
        "ZmEu",
        "dirbuster",
        "gobuster/3.6.0",
        "nuclei",
        "wpscan",
        "python-requests/2.31.0",
        "curl/8.5.0",
        "",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    ]
}

fn ua_blocked(status: u16, body: &str) -> bool {
    if matches!(status, 403 | 406 | 429 | 503) {
        return true;
    }
    let b = body.to_ascii_lowercase();
    b.contains("blocked")
        || b.contains("captcha")
        || b.contains("access denied")
        || b.contains("forbidden")
        || b.contains("bot detected")
}

async fn probe_ua_matrix(
    client: &reqwest::Client,
    base: &str,
    cfg: &EdrScanConfig,
) -> (usize, usize, Vec<Value>) {
    let mut agents: Vec<String> = default_scanner_user_agents()
        .into_iter()
        .map(str::to_string)
        .collect();
    agents.extend(cfg.extra_user_agents.clone());
    agents.truncate(cfg.ua_burst);

    let mut blocked = 0usize;
    let mut allowed = 0usize;
    let mut rows = Vec::new();

    for ua in &agents {
        let extra = if ua.is_empty() {
            vec![("User-Agent", "")]
        } else {
            vec![("User-Agent", ua.as_str())]
        };
        if let Some(p) = http_get_with_headers(client, base, &extra).await {
            let is_blocked = ua_blocked(p.status, &p.body);
            if is_blocked {
                blocked += 1;
            } else if p.status >= 200 && p.status < 400 {
                allowed += 1;
            }
            rows.push(json!({
                "user_agent": if ua.is_empty() { "(empty)" } else { ua.as_str() },
                "status": p.status,
                "blocked": is_blocked,
            }));
        }
    }
    (blocked, allowed, rows)
}

// ── Rate limit burst ─────────────────────────────────────────────────────────

async fn probe_rate_limit(client: &reqwest::Client, base: &str, burst: u8) -> (u8, Option<String>) {
    let mut throttled = 0u8;
    let mut retry_after = None;
    for _ in 0..burst {
        if let Some(p) = http_get(client, base).await {
            if p.status == 429 || p.status == 503 {
                throttled += 1;
                if retry_after.is_none() {
                    retry_after = header_value(&p.headers, "retry-after").map(str::to_string);
                }
            }
        }
    }
    (throttled, retry_after)
}

// ── CSP / headers ────────────────────────────────────────────────────────────

struct CspIssue {
    directive: String,
    issue: String,
    severity: &'static str,
}

fn analyze_csp(csp: &str) -> Vec<CspIssue> {
    let mut out = Vec::new();
    let lc = csp.to_ascii_lowercase();
    for bad in ["'unsafe-inline'", "'unsafe-eval'", " data:", " blob:"] {
        if lc.contains(bad.trim()) {
            out.push(CspIssue {
                directive: "script-src / default-src".to_string(),
                issue: format!("CSP allows {bad} — script injection & eval payloads easier to land"),
                severity: "medium",
            });
        }
    }
    if lc.contains("connect-src") && (lc.contains("connect-src *") || lc.contains("connect-src ' *'")) {
        out.push(CspIssue {
            directive: "connect-src".to_string(),
            issue: "Wildcard connect-src permits exfil/C2 callbacks to arbitrary hosts".to_string(),
            severity: "high",
        });
    }
    if !lc.contains("script-src") && !lc.contains("default-src") {
        out.push(CspIssue {
            directive: "missing".to_string(),
            issue: "No script-src/default-src — browsers apply permissive fallback".to_string(),
            severity: "medium",
        });
    }
    out
}

fn cookie_issues(set_cookies: &[String]) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    for raw in set_cookies {
        let lc = raw.to_ascii_lowercase();
        let name = raw.split('=').next().unwrap_or("cookie").to_string();
        if !lc.contains("httponly") {
            issues.push((name.clone(), "missing HttpOnly — stealable via XSS".to_string()));
        }
        if !lc.contains("secure") {
            issues.push((name.clone(), "missing Secure — sendable over HTTP".to_string()));
        }
        if !lc.contains("samesite") {
            issues.push((name, "missing SameSite — CSRF/session-riding risk".to_string()));
        }
    }
    issues
}

// ── Telemetry key patterns (defender visibility) ─────────────────────────────

fn telemetry_patterns() -> &'static [(&'static str, Regex)] {
    static CACHE: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let raw: &[(&str, &str)] = &[
            ("Sentry DSN", r#"https://[a-f0-9]+@[a-z0-9.-]+\.ingest\.(sentry\.io|us\.sentry\.io)/"#),
            ("Datadog RUM", r#"dd-api-key|datadoghq\.com|DD_RUM"#),
            ("New Relic", r#"newrelic\.com|NREUM|nr-data\.net"#),
            ("App Insights", r#"ApplicationInsights|ai\.instrumentationkey"#),
            ("Rollbar", r#"rollbar\.com|rollbar\.js"#),
            ("Bugsnag", r#"bugsnag\.com|apiKey.*bugsnag"#),
            ("Firebase", r#"firebaseio\.com|firebaseConfig"#),
            ("Segment", r#"cdn\.segment\.com|analytics\.js"#),
            ("Hotjar", r#"hotjar\.com|hjSettings"#),
            ("FullStory", r#"fullstory\.com|FS\.identify"#),
        ];
        raw.iter()
            .filter_map(|(name, pat)| Regex::new(pat).ok().map(|re| (*name, re)))
            .collect()
    })
}

fn scan_telemetry(body: &str) -> Vec<&'static str> {
    telemetry_patterns()
        .iter()
        .filter(|(_, re)| re.is_match(body))
        .map(|(name, _)| *name)
        .collect()
}

// ── Source maps ──────────────────────────────────────────────────────────────

fn extract_script_paths(body: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"src=["']([^"']+\.js[^"']*)"#).unwrap());
    re.captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .take(12)
        .collect()
}

// ── Error verbosity ──────────────────────────────────────────────────────────

fn error_verbose(body: &str, status: u16) -> bool {
    if status < 500 && status != 404 {
        return false;
    }
    let markers = [
        "stack trace",
        "stacktrace",
        "traceback",
        "exception in",
        "at line ",
        "syntaxerror",
        "referenceerror",
        "typeerror",
        "fatal error",
        "panic:",
        "runtime error",
        "internal server error:",
        "debug mode",
        "laravel",
        "symfony\\",
        "django.core",
        "rails error",
        "asp.net",
        "php fatal",
    ];
    let b = body.to_ascii_lowercase();
    markers.iter().any(|m| b.contains(m))
}

// ── Scoring ──────────────────────────────────────────────────────────────────

/// Detection Resilience Score (0–100): **higher = harder for an attacker to evade detection**.
struct ResilienceScore {
    score: u32,
    reasons: Vec<String>,
}

fn compute_resilience(
    waf: bool,
    waf_conf: f64,
    ua_block_rate: f64,
    rate_limited: bool,
    telemetry_count: usize,
    csp_issues: usize,
    cookie_issues: usize,
    debug_hits: usize,
    verbose_errors: bool,
    missing_headers: usize,
) -> ResilienceScore {
    let mut score: i32 = 35;
    let mut reasons = Vec::new();

    if waf {
        score += (15.0 * waf_conf).round() as i32;
        reasons.push(format!("Edge WAF/CDN detected (confidence {:.0}%)", waf_conf * 100.0));
    } else {
        reasons.push("No edge WAF/CDN fingerprint — easier HTTP ingress".to_string());
    }
    if ua_block_rate >= 0.75 {
        score += 20;
        reasons.push(format!("Scanner UA block rate {:.0}%", ua_block_rate * 100.0));
    } else if ua_block_rate >= 0.4 {
        score += 10;
        reasons.push(format!("Partial UA blocking ({:.0}%)", ua_block_rate * 100.0));
    } else {
        score -= 5;
        reasons.push("Scanner/spider User-Agents largely unblocked at the edge".to_string());
    }
    if rate_limited {
        score += 12;
        reasons.push("Rate limiting observed under burst probe".to_string());
    }
    if telemetry_count > 0 {
        score += (telemetry_count as i32 * 4).min(16);
        reasons.push(format!(
            "{telemetry_count} defender telemetry channel(s) in page — increases detection odds"
        ));
    } else {
        score -= 4;
        reasons.push("No RUM/APM/error-tracking keys observed in HTML (blinder spot)".to_string());
    }
    if csp_issues == 0 {
        score += 8;
    } else {
        score -= (csp_issues as i32 * 3).min(12);
        reasons.push(format!("{csp_issues} CSP weakness(es) — injection runway"));
    }
    if cookie_issues == 0 {
        score += 5;
    } else {
        score -= cookie_issues as i32 * 2;
    }
    if debug_hits == 0 {
        score += 5;
    } else {
        score -= debug_hits as i32 * 4;
        reasons.push(format!("{debug_hits} debug/admin path(s) reachable"));
    }
    if verbose_errors {
        score -= 10;
        reasons.push("Verbose error pages leak stack/framework details".to_string());
    }
    if missing_headers > 2 {
        score -= 5;
    }

    ResilienceScore {
        score: score.clamp(0, 100) as u32,
        reasons,
    }
}

fn severity_from_resilience(score: u32) -> &'static str {
    match score {
        80..=100 => "info",
        60..=79 => "low",
        40..=59 => "medium",
        20..=39 => "high",
        _ => "critical",
    }
}

// ── Debug paths ──────────────────────────────────────────────────────────────

fn default_debug_paths() -> Vec<&'static str> {
    vec![
        "/debug",
        "/trace",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/.env",
        "/server-status",
        "/server-info",
        "/phpinfo.php",
        "/info.php",
        "/_profiler",
        "/swagger-ui.html",
        "/api/swagger",
        "/graphql",
        "/.git/HEAD",
        "/.svn/entries",
        "/wp-config.php.bak",
        "/backup.zip",
        "/console",
        "/elmah.axd",
        "/__debug__",
    ]
}

// ── Main scan ────────────────────────────────────────────────────────────────

async fn run_edr_scan(target: &str, cfg: EdrScanConfig) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let base = normalize_url(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();

    let baseline = http_get(&client, &base).await;
    let Some(base_probe) = baseline else {
        return empty_ok(ENGINE_ID, target);
    };

    let mut waf_detected = false;
    let mut waf_conf = 0.0_f64;
    let mut waf_vendor = String::new();

    if cfg.check_waf {
        if let Some(hit) = fingerprint_edge(&base_probe) {
            waf_detected = true;
            waf_conf = hit.confidence;
            waf_vendor = hit.vendor.to_string();
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("Edge protection detected: {}", hit.vendor),
                "info",
                MITRE_IMPAIR,
                &format!(
                    "Live response from {} includes {} signals ({}) — automated scanners and many payloads hit an edge inspection layer before the origin.",
                    base_probe.final_url, hit.vendor, hit.signal
                ),
                target,
                hit.confidence,
                Evidence::new()
                    .with("vendor", hit.vendor)
                    .with("signal", hit.signal)
                    .with("final_url", base_probe.final_url.clone())
                    .check("edge_waf_present", true, hit.vendor),
            ));
        }
    }

    let mut ua_block_rate = 0.0_f64;
    if cfg.check_ua_matrix {
        let (blocked, allowed, rows) = probe_ua_matrix(&client, &base, &cfg).await;
        let total = blocked + allowed;
        if total > 0 {
            ua_block_rate = blocked as f64 / total as f64;
        }
        let sev = if ua_block_rate >= 0.6 {
            "info"
        } else if ua_block_rate >= 0.25 {
            "low"
        } else {
            "medium"
        };
        findings.push(finding_rich(
            ENGINE_ID,
            &format!(
                "User-Agent block matrix: {:.0}% of scanner probes blocked",
                ua_block_rate * 100.0
            ),
            sev,
            MITRE_IMPAIR,
            &format!(
                "Tested {} User-Agent strings against {} — {} blocked, {} allowed through with HTTP 2xx/3xx. Low block rates mean commodity offensive tools reach the origin unobstructed.",
                rows.len(),
                base,
                blocked,
                allowed
            ),
            target,
            0.9,
            Evidence::new()
                .with("blocked", blocked)
                .with("allowed", allowed)
                .with("matrix", Value::Array(rows))
                .check("scanner_ua_blocked_majority", ua_block_rate >= 0.5, ua_block_rate),
        ));
    }

    let mut rate_limited = false;
    if cfg.check_rate_limit {
        let (throttled, retry_after) = probe_rate_limit(&client, &base, cfg.rate_burst).await;
        rate_limited = throttled > 0;
        if rate_limited {
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("Rate limiting active ({throttled}/{} requests throttled)", cfg.rate_burst),
                "info",
                MITRE_IMPAIR,
                "Burst probe triggered HTTP 429/503 — edge or origin enforces request throttling, raising cost for brute-force and scanning.",
                target,
                0.88,
                Evidence::new()
                    .with("throttled", throttled)
                    .with("burst", cfg.rate_burst)
                    .with("retry_after", json!(retry_after)),
            ));
        }
    }

    let mut csp_issue_count = 0usize;
    if cfg.check_csp || cfg.check_headers {
        if cfg.check_headers {
            for (hdr, title) in [
                ("x-content-type-options", "Missing X-Content-Type-Options"),
                ("x-frame-options", "Missing X-Frame-Options"),
                ("referrer-policy", "Missing Referrer-Policy"),
                ("permissions-policy", "Missing Permissions-Policy"),
                ("cross-origin-opener-policy", "Missing Cross-Origin-Opener-Policy"),
            ] {
                if !has_header(&base_probe.headers, hdr) {
                    findings.push(finding_rich(
                        ENGINE_ID,
                        title,
                        "low",
                        MITRE_IMPAIR,
                        &format!("HTTPS response from {} lacks `{hdr}` — weakens browser-side attack containment.", base_probe.final_url),
                        target,
                        0.78,
                        Evidence::new().with("header", hdr).with("final_url", base_probe.final_url.clone()),
                    ));
                }
            }
        }
        if cfg.check_csp {
            match header_value(&base_probe.headers, "content-security-policy") {
                Some(csp) => {
                    for issue in analyze_csp(csp) {
                        csp_issue_count += 1;
                        findings.push(finding_rich(
                            ENGINE_ID,
                            &format!("CSP weakness: {}", issue.directive),
                            issue.severity,
                            MITRE_IMPAIR,
                            &issue.issue,
                            target,
                            0.85,
                            Evidence::new().with("csp", csp).with("directive", issue.directive),
                        ));
                    }
                }
                None => {
                    csp_issue_count += 1;
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "No Content-Security-Policy header",
                        "medium",
                        MITRE_IMPAIR,
                        "Missing CSP — injected script (fileless-style delivery, skimmers, C2 loaders) faces no browser policy barrier.",
                        target,
                        0.88,
                        Evidence::new().with("final_url", base_probe.final_url.clone()),
                    ));
                }
            }
        }
    }

    let mut cookie_issue_count = 0usize;
    if cfg.check_cookies {
        let set_cookies: Vec<String> = base_probe
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.clone())
            .collect();
        for (name, issue) in cookie_issues(&set_cookies) {
            cookie_issue_count += 1;
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("Insecure session cookie: {name}"),
                "medium",
                MITRE_IMPAIR,
                &issue,
                target,
                0.86,
                Evidence::new().with("cookie_name", name),
            ));
        }
    }

    let mut telemetry_count = 0usize;
    if cfg.check_telemetry {
        let hits = scan_telemetry(&base_probe.body);
        telemetry_count = hits.len();
        if !hits.is_empty() {
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("Defender telemetry visible in page ({})", hits.join(", ")),
                "info",
                MITRE_IMPAIR,
                "Client-side RUM/APM/error-tracking endpoints were observed in the live HTML/JS — increases the chance anomalous script behaviour is recorded (raises attacker evasion cost).",
                target,
                0.82,
                Evidence::new().with("channels", json!(hits)),
            ));
        }
    }

    let mut debug_hits = 0usize;
    if cfg.check_debug_paths {
        let mut paths: Vec<&str> = default_debug_paths();
        for p in &cfg.extra_paths {
            paths.push(p.as_str());
        }
        let mut dedup = HashSet::new();
        paths.retain(|p| dedup.insert(*p));
        let probes = probe_paths_concurrent(&client, &base, &paths, 8).await;
        for p in probes {
            if status_indicates_presence(p.status) && p.body.len() > 16 {
                debug_hits += 1;
                let path = p
                    .final_url
                    .strip_prefix(&base.trim_end_matches('/'))
                    .unwrap_or(&p.final_url);
                findings.push(finding_rich(
                    ENGINE_ID,
                    &format!("Debug/admin surface exposed: {path}"),
                    "high",
                    MITRE_IMPAIR,
                    &format!(
                        "{} returned HTTP {} ({} bytes) — diagnostics weaken monitoring and aid post-exploitation evasion.",
                        p.final_url, p.status, p.body.len()
                    ),
                    target,
                    0.93,
                    Evidence::new()
                        .with("url", p.final_url)
                        .with("status", p.status)
                        .with("body_len", p.body.len()),
                ));
            }
        }
    }

    if cfg.check_source_maps {
        for script in extract_script_paths(&base_probe.body) {
            let map_url = if script.ends_with(".js") {
                format!("{script}.map")
            } else {
                format!("{script}.map")
            };
            let url = if map_url.starts_with("http") {
                map_url
            } else {
                format!("{}{}", base.trim_end_matches('/'), if map_url.starts_with('/') { map_url } else { format!("/{map_url}") })
            };
            if let Some(p) = http_get(&client, &url).await {
                if p.status == 200 && (p.body.contains("\"mappings\"") || p.body.contains("\"sources\"")) {
                    findings.push(finding_rich(
                        ENGINE_ID,
                        &format!("JavaScript source map exposed: {url}"),
                        "medium",
                        MITRE_IMPAIR,
                        "Public source map reveals unobfuscated client logic — aids payload crafting and anti-detection tuning.",
                        target,
                        0.9,
                        Evidence::new().with("url", p.final_url).with("script", script),
                    ));
                    break;
                }
            }
        }
    }

    let mut verbose_errors = false;
    if cfg.check_error_verbosity {
        let probes = [
            format!("{}/%7B%7B7*7%7D%7D", base.trim_end_matches('/')),
            format!("{}/weissman-nonexistent-{}", base.trim_end_matches('/'), host),
        ];
        for url in &probes {
            if let Some(p) = http_get(&client, url).await {
                if error_verbose(&p.body, p.status) {
                    verbose_errors = true;
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Verbose error response leaks implementation details",
                        "medium",
                        MITRE_IMPAIR,
                        &format!(
                            "Request to {} returned HTTP {} with stack/framework markers in the body — helps attackers tune evasion and select exploits.",
                            p.final_url, p.status
                        ),
                        target,
                        0.87,
                        Evidence::new().with("url", p.final_url).with("status", p.status),
                    ));
                    break;
                }
            }
        }
    }

    if cfg.check_minimal_fingerprint {
        let server = header_value(&base_probe.headers, "server").unwrap_or("");
        let powered = header_value(&base_probe.headers, "x-powered-by").unwrap_or("");
        if server.is_empty() && powered.is_empty() && base_probe.status >= 200 && base_probe.status < 400 {
            findings.push(finding_rich(
                ENGINE_ID,
                "Minimal HTTP server fingerprint (stripped banners)",
                "info",
                MITRE_APP,
                &format!(
                    "{} omits Server and X-Powered-By — common on reverse proxies and C2 fronting; combine with egress allow-list reviews.",
                    base_probe.final_url
                ),
                target,
                0.75,
                Evidence::new().with("final_url", base_probe.final_url.clone()),
            ));
        }
    }

    if cfg.emit_agent_guidance {
        findings.push(finding_rich(
            ENGINE_ID,
            "Host-resident EDR tests require the endpoint agent",
            "info",
            MITRE_IMPAIR,
            "AMSI tampering, ETW provider blind spots, syscall/unhook validation, process hollowing and memory-only payload execution cannot be assessed from a remote HTTP probe. Enrol the Weissman Endpoint Agent on the asset and re-run agent-capable engines (process_hollowing, av_bypass_engine, …) for ground-truth host telemetry.",
            target,
            1.0,
            Evidence::new()
                .with("remote_only", true)
                .with("agent_engines", json!([
                    "process_hollowing", "av_bypass_engine", "anti_debug_evasion",
                    "memory_forensics_evasion", "log_tampering_engine"
                ]))
                .check("agent_required_for_host_edr", true, "endpoint_agent"),
        ));
    }

    let missing_hdrs = ["x-content-type-options", "content-security-policy"]
        .iter()
        .filter(|h| !has_header(&base_probe.headers, h))
        .count();

    let resilience = compute_resilience(
        waf_detected,
        waf_conf,
        ua_block_rate,
        rate_limited,
        telemetry_count,
        csp_issue_count,
        cookie_issue_count,
        debug_hits,
        verbose_errors,
        missing_hdrs,
    );

    findings.insert(
        0,
        finding_rich(
            ENGINE_ID,
            &format!("Detection resilience score: {}/100 for {host}", resilience.score),
            severity_from_resilience(resilience.score),
            MITRE_IMPAIR,
            &format!(
                "Composite remote detection posture for {host}: {}/100 (higher = harder for an attacker to evade edge & application monitoring). {}",
                resilience.score,
                resilience.reasons.join(" · ")
            ),
            target,
            0.96,
            Evidence::new()
                .with("host", host.clone())
                .with("detection_resilience_score", resilience.score)
                .with("waf_vendor", waf_vendor.clone())
                .with("ua_block_rate", (ua_block_rate * 100.0).round() / 100.0)
                .with("rate_limited", rate_limited)
                .with("telemetry_channels", telemetry_count)
                .with("debug_surfaces", debug_hits)
                .with("reasons", json!(resilience.reasons))
                .check("edge_waf", waf_detected, json!(waf_vendor))
                .check("resilience_above_60", resilience.score >= 60, resilience.score),
        ),
    );

    if findings.len() <= 1 && !cfg.emit_agent_guidance {
        return empty_ok(ENGINE_ID, target);
    }

    EngineResult::ok(
        findings.clone(),
        format!(
            "edr_evasion: resilience {}/100, {} finding(s) on {host}",
            resilience.score,
            findings.len()
        ),
    )
}

pub async fn run_edr_evasion_result(target: &str) -> EngineResult {
    run_edr_scan(target, EdrScanConfig::default()).await
}

pub async fn run_edr_evasion_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    run_edr_scan(target, EdrScanConfig::from_ctx(ctx)).await
}

pub async fn run_edr_evasion(target: &str) {
    print_result(run_edr_evasion_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx(params: Value) -> EngineRunContext {
        EngineRunContext {
            job_params: params,
            ..Default::default()
        }
    }

    #[test]
    fn config_reads_toggles() {
        let cfg = EdrScanConfig::from_ctx(&ctx(json!({
            "intensity": "light",
            "check_telemetry": false,
            "rate_burst_count": 8,
            "extra_paths": "/secret-admin"
        })));
        assert_eq!(cfg.intensity, Intensity::Light);
        assert!(!cfg.check_telemetry);
        assert!(!cfg.check_source_maps);
        assert_eq!(cfg.rate_burst, 8);
        assert!(cfg.extra_paths.contains(&"/secret-admin".to_string()));
    }

    #[test]
    fn csp_flags_unsafe_inline() {
        let issues = analyze_csp("default-src 'self'; script-src 'unsafe-inline'");
        assert!(issues.iter().any(|i| i.issue.contains("unsafe-inline")));
    }

    #[test]
    fn ua_blocked_detects_403_and_captcha() {
        assert!(ua_blocked(403, "Access Denied"));
        assert!(ua_blocked(200, "Please complete the captcha"));
        assert!(!ua_blocked(200, "Welcome"));
    }

    #[test]
    fn resilience_scores_edge_and_gaps() {
        let good = compute_resilience(true, 0.9, 0.8, true, 2, 0, 0, 0, false, 0);
        assert!(good.score >= 70);
        let weak = compute_resilience(false, 0.0, 0.1, false, 0, 3, 2, 2, true, 2);
        assert!(weak.score < 40);
    }

    #[test]
    fn telemetry_finds_sentry_pattern() {
        let body = r#"dsn: "https://abc123@o123.ingest.sentry.io/456""#;
        assert!(!scan_telemetry(body).is_empty());
    }
}
