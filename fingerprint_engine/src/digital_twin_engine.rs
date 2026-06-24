//! Digital Twin Attack Simulator — world-class environment modeling + live attack-path simulation.
//!
//! Builds a **live, evidence-only** digital twin of a web application surface from real HTTP/TLS/DNS
//! signals, then executes operator-selected attack scenarios (XSS, SQLi, MITM/TLS downgrade, CORS)
//! with differential probing — the same Wiz/CNAPP "toxic combination" model used by
//! `email_dns_posture` and `cloud_posture`:
//!
//!   * **Twin profile** — server stack, security-header posture, cookie flags, TLS certificate facts,
//!     cleartext HTTP availability, discovered paths, WAF hints.
//!   * **Scenario probes** — each scenario performs real network I/O; a "clear" verdict means probes
//!     did not observe an exploitable signal (not "we didn't look").
//!   * **Attack-path graph** — chains observed weaknesses into MITRE-aligned kill-chain steps with
//!     severity and evidence trails.
//!   * **Posture grade** (A+ … F), category sub-scores, toxic-combination headline, remediation roadmap.
//!
//! Every knob maps 1:1 to `POST /api/command-center/scan` → `EngineRunContext::job_params`.

#![allow(
    clippy::too_many_lines,
    clippy::module_name_repetitions,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    extract_host, has_header, header_value, http_client, http_get, http_get_with_headers,
    normalize_url, tls_cert_details, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use fuzz_core::{looks_like_sqli_response, reflected_xss_indicated};
use serde_json::{json, Map, Value};
use std::time::Duration;

const ENGINE_ID: &str = "digital_twin";

const DEFAULT_PROBE_PARAMS: &[&str] = &[
    "q", "search", "query", "id", "name", "page", "input", "msg", "message", "text", "value", "term",
    "keyword", "email", "user", "username", "filter", "sort", "order", "cat", "category",
];

const DEFAULT_PROBE_PATHS: &[&str] = &[
    "/",
    "/search",
    "/api",
    "/api/search",
    "/login",
    "/register",
    "/products",
    "/items",
    "/users",
    "/health",
];

const SQLI_ERROR_SIGS: &[(&str, &str)] = &[
    ("you have an error in your sql syntax", "mysql"),
    ("warning: mysql", "mysql"),
    ("unclosed quotation mark", "mssql"),
    ("microsoft ole db provider", "mssql"),
    ("odbc sql server driver", "mssql"),
    ("pg_query()", "postgresql"),
    ("postgresql query failed", "postgresql"),
    ("sqlite3::", "sqlite"),
    ("sqlite error", "sqlite"),
    ("ora-01756", "oracle"),
    ("oracle error", "oracle"),
    ("syntax error at or near", "postgresql"),
    ("sqlstate[", "pdo"),
];

// ─── Configuration ───────────────────────────────────────────────────────────────

struct TwinConfig {
    scenario: ScenarioMode,
    probe_depth: ProbeDepth,
    check_xss: bool,
    check_sqli: bool,
    check_mitm: bool,
    check_cors: bool,
    strict_mode: bool,
    include_http_cleartext: bool,
    canary_only: bool,
    extra_params: Vec<String>,
    extra_paths: Vec<String>,
    max_probe_urls: usize,
    timeout_ms: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ScenarioMode {
    Profile,
    Xss,
    Sqli,
    Mitm,
    Cors,
    All,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeDepth {
    Quick,
    Standard,
    Deep,
}

impl TwinConfig {
    fn from_ctx(ctx: &EngineRunContext) -> Self {
        let p = &ctx.job_params;
        Self {
            scenario: ScenarioMode::parse(pstr(p, "scenario")),
            probe_depth: ProbeDepth::parse(pstr(p, "probe_depth")),
            check_xss: pbool(p, "check_xss", true),
            check_sqli: pbool(p, "check_sqli", true),
            check_mitm: pbool(p, "check_mitm", true),
            check_cors: pbool(p, "check_cors", true),
            strict_mode: pbool(p, "strict_mode", false),
            include_http_cleartext: pbool(p, "include_http_cleartext", true),
            canary_only: pbool(p, "canary_only", true),
            extra_params: split_list(&pstr(p, "probe_params")),
            extra_paths: split_list(&pstr(p, "probe_paths")),
            max_probe_urls: pu64(p, "max_probe_urls", 32) as usize,
            timeout_ms: pu64(p, "timeout_ms", 8000).clamp(2000, 30000),
        }
    }

    fn runs_scenario(&self, s: ScenarioMode) -> bool {
        match self.scenario {
            ScenarioMode::All => true,
            ScenarioMode::Profile => false,
            other => other == s,
        }
    }
}

impl ScenarioMode {
    fn parse(raw: String) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "xss" | "xss_injection" => Self::Xss,
            "sqli" | "sql_injection" => Self::Sqli,
            "mitm" | "sslstrip" | "tls" => Self::Mitm,
            "cors" | "cors_misconfiguration" => Self::Cors,
            "all" | "full" | "run_all" => Self::All,
            _ => Self::Profile,
        }
    }
}

impl ProbeDepth {
    fn parse(raw: String) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "quick" | "fast" => Self::Quick,
            "deep" | "thorough" => Self::Deep,
            _ => Self::Standard,
        }
    }

    fn param_cap(self) -> usize {
        match self {
            Self::Quick => 4,
            Self::Standard => 8,
            Self::Deep => 14,
        }
    }

    fn path_cap(self) -> usize {
        match self {
            Self::Quick => 3,
            Self::Standard => 6,
            Self::Deep => 12,
        }
    }
}

fn pstr(p: &Value, key: &str) -> String {
    match p.get(key) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn pbool(p: &Value, key: &str, default: bool) -> bool {
    match p.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => {
            let s = s.trim().to_ascii_lowercase();
            if s.is_empty() {
                default
            } else {
                matches!(s.as_str(), "true" | "1" | "yes" | "on" | "enabled")
            }
        }
        Some(Value::Number(n)) => n.as_i64().map(|v| v != 0).unwrap_or(default),
        _ => default,
    }
}

fn pu64(p: &Value, key: &str, default: u64) -> u64 {
    match p.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_f64().map(|f| f as u64))
            .unwrap_or(default),
        Some(Value::String(s)) => s.trim().parse::<u64>().unwrap_or(default),
        _ => default,
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ', ';', '\n', '\t'])
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

// ─── Twin profile (live signals) ───────────────────────────────────────────────

#[derive(Default, Clone)]
struct TwinProfile {
    base_url: String,
    host: String,
    http_status: u16,
    server: String,
    powered_by: String,
    content_type: String,
    has_hsts: bool,
    hsts_max_age: Option<u64>,
    hsts_include_subdomains: bool,
    hsts_preload: bool,
    has_csp: bool,
    csp_value: String,
    csp_unsafe_inline: bool,
    csp_unsafe_eval: bool,
    csp_wildcard: bool,
    has_xfo: bool,
    xfo_value: String,
    has_referrer_policy: bool,
    has_permissions_policy: bool,
    cors_header_present: bool,
    cors_acao: String,
    cors_credentials: bool,
    cookies: Vec<CookieFact>,
    http_cleartext_available: bool,
    http_redirects_to_https: bool,
    tls_days_until_expiry: Option<i64>,
    tls_self_signed: bool,
    tls_expired: bool,
    tls_key_bits: Option<u32>,
    waf_hint: Option<String>,
    discovered_paths: Vec<String>,
}

#[derive(Clone)]
struct CookieFact {
    name: String,
    secure: bool,
    httponly: bool,
    samesite: Option<String>,
}

async fn build_client(timeout_ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-DigitalTwin/2.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn parse_hsts(raw: &str) -> (Option<u64>, bool, bool) {
    let lc = raw.to_ascii_lowercase();
    let max_age = lc
        .split(';')
        .find_map(|part| {
            let p = part.trim();
            p.strip_prefix("max-age=")
                .and_then(|v| v.trim().parse::<u64>().ok())
        });
    let include_sub = lc.contains("includesubdomains");
    let preload = lc.contains("preload");
    (max_age, include_sub, preload)
}

fn parse_csp_flags(csp: &str) -> (bool, bool, bool) {
    let lc = csp.to_ascii_lowercase();
    (
        lc.contains("'unsafe-inline'") || lc.contains("unsafe-inline"),
        lc.contains("'unsafe-eval'") || lc.contains("unsafe-eval"),
        lc.contains("script-src *") || lc.contains("default-src *"),
    )
}

fn parse_set_cookies(headers: &[(String, String)]) -> Vec<CookieFact> {
    let mut out = Vec::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            let name = v.split('=').next().unwrap_or("").trim().to_string();
            let lc = v.to_ascii_lowercase();
            out.push(CookieFact {
                name,
                secure: lc.contains("secure"),
                httponly: lc.contains("httponly"),
                samesite: if lc.contains("samesite=strict") {
                    Some("Strict".into())
                } else if lc.contains("samesite=lax") {
                    Some("Lax".into())
                } else if lc.contains("samesite=none") {
                    Some("None".into())
                } else {
                    None
                },
            });
        }
    }
    out
}

fn waf_from_headers_and_body(headers: &[(String, String)], body: &str) -> Option<String> {
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        let vl = v.to_ascii_lowercase();
        if kl == "server" && (vl.contains("cloudflare") || vl.contains("awselb")) {
            return Some(v.clone());
        }
        if kl == "cf-ray" || kl == "x-sucuri-id" || kl == "x-akamai-transformed" {
            return Some(k.clone());
        }
    }
    let bl = body.to_ascii_lowercase();
    if bl.contains("cloudflare") && bl.contains("ray id") {
        return Some("cloudflare-body".into());
    }
    if bl.contains("access denied") && bl.contains("incapsula") {
        return Some("incapsula".into());
    }
    None
}

async fn build_twin_profile(
    client: &reqwest::Client,
    base: &str,
    cfg: &TwinConfig,
    ctx: &EngineRunContext,
) -> TwinProfile {
    let host = extract_host(base);
    let mut profile = TwinProfile {
        base_url: base.to_string(),
        host: host.clone(),
        ..Default::default()
    };

    let mut paths: Vec<String> = ctx
        .discovered_paths
        .iter()
        .filter(|p| !p.is_empty())
        .take(24)
        .cloned()
        .collect();
    for ep in &cfg.extra_paths {
        if !paths.contains(ep) {
            paths.push(ep.clone());
        }
    }
    profile.discovered_paths = paths;

    if let Some(p) = http_get(client, base).await {
        profile.http_status = p.status;
        profile.server = header_value(&p.headers, "server")
            .unwrap_or("unknown")
            .to_string();
        profile.powered_by = header_value(&p.headers, "x-powered-by")
            .unwrap_or("")
            .to_string();
        profile.content_type = header_value(&p.headers, "content-type")
            .unwrap_or("")
            .to_string();
        if let Some(hsts) = header_value(&p.headers, "strict-transport-security") {
            profile.has_hsts = true;
            let (age, sub, preload) = parse_hsts(hsts);
            profile.hsts_max_age = age;
            profile.hsts_include_subdomains = sub;
            profile.hsts_preload = preload;
        }
        if let Some(csp) = header_value(&p.headers, "content-security-policy") {
            profile.has_csp = true;
            profile.csp_value = csp.to_string();
            let (ui, ue, wc) = parse_csp_flags(csp);
            profile.csp_unsafe_inline = ui;
            profile.csp_unsafe_eval = ue;
            profile.csp_wildcard = wc;
        }
        profile.has_xfo = has_header(&p.headers, "x-frame-options");
        profile.xfo_value = header_value(&p.headers, "x-frame-options")
            .unwrap_or("")
            .to_string();
        profile.has_referrer_policy = has_header(&p.headers, "referrer-policy");
        profile.has_permissions_policy =
            has_header(&p.headers, "permissions-policy")
                || has_header(&p.headers, "feature-policy");
        if let Some(acao) = header_value(&p.headers, "access-control-allow-origin") {
            profile.cors_header_present = true;
            profile.cors_acao = acao.to_string();
            profile.cors_credentials =
                has_header(&p.headers, "access-control-allow-credentials");
        }
        profile.cookies = parse_set_cookies(&p.headers);
        profile.waf_hint = waf_from_headers_and_body(&p.headers, &p.body);
    }

    if cfg.include_http_cleartext && !host.is_empty() {
        let http_url = format!("http://{host}/");
        if let Some(p) = http_get(client, &http_url).await {
            profile.http_cleartext_available = true;
            profile.http_redirects_to_https = p.final_url.starts_with("https://")
                || p.status == 301
                || p.status == 302
                || p.status == 307
                || p.status == 308;
        }
    }

    if let Some(tls) = tls_cert_details(&host).await {
        profile.tls_days_until_expiry = Some(tls.days_until_expiry);
        profile.tls_self_signed = tls.self_signed;
        profile.tls_expired = tls.expired;
        profile.tls_key_bits = Some(tls.public_key_bits);
    }

    profile
}

// ─── Finding helpers ─────────────────────────────────────────────────────────────

fn twin_finding(
    category: &str,
    scenario: &str,
    title: impl Into<String>,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    extra: Value,
) -> Value {
    let title = title.into();
    let mut obj = Map::new();
    obj.insert("type".into(), json!(ENGINE_ID));
    obj.insert("category".into(), json!(category));
    obj.insert("scenario".into(), json!(scenario));
    obj.insert("title".into(), json!(title));
    obj.insert("severity".into(), json!(severity));
    obj.insert("mitre_attack".into(), json!(mitre));
    obj.insert("description".into(), json!(description));
    obj.insert("value".into(), json!(target));
    if let Some(map) = extra.as_object() {
        for (k, v) in map {
            obj.insert(k.clone(), v.clone());
        }
    }
    Value::Object(obj)
}

fn attack_path_finding(
    scenario: &str,
    chain: &[&str],
    severity: &str,
    headline: &str,
    target: &str,
    evidence: Value,
) -> Value {
    twin_finding(
        "attack_path",
        scenario,
        headline,
        severity,
        match scenario {
            "xss" => "T1059.007",
            "sqli" => "T1190",
            "mitm" => "T1557",
            _ => "T1185",
        },
        &format!(
            "Attack path ({} steps): {}",
            chain.len(),
            chain.join(" → ")
        ),
        target,
        json!({
            "attack_chain": chain,
            "evidence": evidence,
        }),
    )
}

fn escalate_severity(sev: &str, strict: bool) -> &str {
    if !strict {
        return sev;
    }
    match sev {
        "medium" => "high",
        "low" => "medium",
        "info" => "low",
        _ => sev,
    }
}

// ─── Probe URL builder ───────────────────────────────────────────────────────────

fn build_probe_urls(base: &str, cfg: &TwinConfig, profile: &TwinProfile) -> Vec<String> {
    let base = base.trim_end_matches('/');
    let mut paths: Vec<&str> = DEFAULT_PROBE_PATHS.to_vec();
    for p in &profile.discovered_paths {
        if !p.is_empty() {
            paths.push(p.as_str());
        }
    }
    for p in &cfg.extra_paths {
        paths.push(p.as_str());
    }
    paths.sort_unstable();
    paths.dedup();

    let path_cap = cfg.probe_depth.path_cap();
    let param_cap = cfg.probe_depth.param_cap();

    let mut params: Vec<&str> = DEFAULT_PROBE_PARAMS.to_vec();
    for p in &cfg.extra_params {
        params.push(p.as_str());
    }
    params.truncate(param_cap);

    let mut urls = Vec::new();
    'outer: for path in paths.into_iter().take(path_cap) {
        let path = if path.starts_with('/') {
            path
        } else {
            "/"
        };
        let url_base = if path == "/" {
            base.to_string()
        } else {
            format!("{base}{path}")
        };
        for param in &params {
            urls.push(format!("{url_base}?{param}="));
            if urls.len() >= cfg.max_probe_urls {
                break 'outer;
            }
        }
    }
    urls
}

// ─── Scenario: XSS ───────────────────────────────────────────────────────────────

const XSS_CANARY_PREFIX: &str = "weissman_xss_canary_7331";

async fn probe_xss(
    client: &reqwest::Client,
    base: &str,
    cfg: &TwinConfig,
    profile: &TwinProfile,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let canary = format!("{XSS_CANARY_PREFIX}_probe");

    // CSP weakness — evidence from live header
    if !profile.has_csp {
        findings.push(twin_finding(
            "scenario_probe",
            "xss",
            "Content-Security-Policy absent — XSS blast radius unconstrained",
            escalate_severity("high", cfg.strict_mode),
            "T1059.007",
            &format!(
                "No CSP header on {}. Without a nonce/hash policy, any reflected or stored injection \
                 that reaches HTML execution context can run arbitrary script.",
                profile.base_url
            ),
            base,
            json!({ "control": "csp", "observed": "absent" }),
        ));
    } else if profile.csp_unsafe_inline || profile.csp_wildcard {
        findings.push(twin_finding(
            "scenario_probe",
            "xss",
            "Weak CSP allows inline script execution",
            escalate_severity("medium", cfg.strict_mode),
            "T1059.007",
            &format!(
                "CSP on {} contains {} — inline handlers and many DOM XSS gadgets remain viable.",
                profile.base_url,
                if profile.csp_unsafe_inline {
                    "'unsafe-inline'"
                } else {
                    "wildcard script-src"
                }
            ),
            base,
            json!({ "control": "csp", "csp": profile.csp_value }),
        ));
    }

    let payloads: Vec<(&str, &str)> = if cfg.canary_only {
        vec![
            (&canary, "canary-reflection"),
            ("<svg/onload=weissman7331>", "svg-onload"),
        ]
    } else {
        vec![
            (&canary, "canary-reflection"),
            ("<svg/onload=weissman7331>", "svg-onload"),
            ("\"><img src=x onerror=weissman7331>", "img-onerror"),
        ]
    };

    let urls = build_probe_urls(base, cfg, profile);
    for url in urls {
        for (payload, tag) in &payloads {
            let probe_url = format!("{url}{payload}");
            let Some(p) = http_get(client, &probe_url).await else {
                continue;
            };
            if reflected_xss_indicated(&p.body) || p.body.contains(&canary) {
                findings.push(twin_finding(
                    "scenario_probe",
                    "xss",
                    "Reflected XSS indicator — user input echoed without encoding",
                    escalate_severity("critical", cfg.strict_mode),
                    "T1059.007",
                    &format!(
                        "GET {} returned HTTP {} with the probe payload reflected in the body (probe: {}). \
                         An attacker can deliver a crafted link to steal session tokens or perform actions as the victim.",
                        p.final_url,
                        p.status,
                        tag
                    ),
                    base,
                    json!({
                        "probe_url": probe_url,
                        "probe_tag": tag,
                        "http_status": p.status,
                        "reflection": true,
                    }),
                ));
                return findings;
            }
        }
    }

    findings
}

// ─── Scenario: SQLi ──────────────────────────────────────────────────────────────

async fn probe_sqli(
    client: &reqwest::Client,
    base: &str,
    cfg: &TwinConfig,
    profile: &TwinProfile,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let sqli_payloads: &[(&str, &str)] = &[
        ("'", "quote"),
        ("\"", "dquote"),
        ("' OR '1'='1", "boolean"),
        ("1 AND 1=CONVERT(int,@@version)--", "mssql-version"),
        ("' AND SLEEP(0)--", "sleep-safe"),
    ];

    let urls = build_probe_urls(base, cfg, profile);
    for url in urls {
        for (payload, tag) in sqli_payloads {
            let probe_url = format!("{url}{payload}");
            let Some(p) = http_get(client, &probe_url).await else {
                continue;
            };
            let sqli_lib = looks_like_sqli_response(&p.body);
            let sig = sql_error_engine(&p.body);
            if sqli_lib || sig.is_some() {
                let engine = sig.unwrap_or("unknown-db");
                findings.push(twin_finding(
                    "scenario_probe",
                    "sqli",
                    "SQL injection error-based indicator observed",
                    escalate_severity("critical", cfg.strict_mode),
                    "T1190",
                    &format!(
                        "GET {} returned HTTP {} with a database error signature ({}) after injection probe `{}`. \
                         Error-based SQLi can escalate to authentication bypass and data exfiltration.",
                        p.final_url,
                        p.status,
                        engine,
                        tag
                    ),
                    base,
                    json!({
                        "probe_url": probe_url,
                        "probe_tag": tag,
                        "db_engine": engine,
                        "http_status": p.status,
                    }),
                ));
                return findings;
            }
        }
    }

    // Stack hint from twin profile (informational, not a vuln claim)
    if profile.powered_by.to_ascii_lowercase().contains("php")
        || profile.server.to_ascii_lowercase().contains("apache")
    {
        // no finding — absence of error is the honest signal
    }

    findings
}

fn sql_error_engine(body: &str) -> Option<&'static str> {
    let lc = body.to_ascii_lowercase();
    SQLI_ERROR_SIGS
        .iter()
        .find_map(|(sig, eng)| if lc.contains(sig) { Some(*eng) } else { None })
}

// ─── Scenario: MITM / TLS ────────────────────────────────────────────────────────

async fn probe_mitm(
    client: &reqwest::Client,
    base: &str,
    cfg: &TwinConfig,
    profile: &TwinProfile,
) -> Vec<Value> {
    let mut findings = Vec::new();

    if !profile.has_hsts {
        findings.push(twin_finding(
            "scenario_probe",
            "mitm",
            "HSTS not enforced — SSL stripping viable",
            escalate_severity("high", cfg.strict_mode),
            "T1557",
            &format!(
                "Strict-Transport-Security is absent on {}. A network adversary can downgrade the victim \
                 to cleartext HTTP and capture cookies or inject content.",
                profile.base_url
            ),
            base,
            json!({ "control": "hsts", "observed": "absent" }),
        ));
    } else if profile.hsts_max_age.unwrap_or(0) < 86400 {
        findings.push(twin_finding(
            "scenario_probe",
            "mitm",
            "HSTS max-age too short for durable protection",
            escalate_severity("medium", cfg.strict_mode),
            "T1557",
            &format!(
                "HSTS max-age={} on {} — browsers forget the policy quickly, reopening ssl-strip windows.",
                profile.hsts_max_age.unwrap_or(0),
                profile.base_url
            ),
            base,
            json!({ "hsts_max_age": profile.hsts_max_age }),
        ));
    }

    if profile.http_cleartext_available && !profile.http_redirects_to_https {
        findings.push(twin_finding(
            "scenario_probe",
            "mitm",
            "Cleartext HTTP serves content without redirecting to HTTPS",
            escalate_severity("high", cfg.strict_mode),
            "T1557",
            &format!(
                "http://{} responds without forcing HTTPS upgrade. Combined with missing/weak HSTS this \
                 enables trivial ssl-strip and credential capture.",
                profile.host
            ),
            base,
            json!({
                "http_cleartext": true,
                "redirects_to_https": profile.http_redirects_to_https,
            }),
        ));
    }

    for cookie in &profile.cookies {
        if !cookie.secure && !cookie.name.is_empty() {
            findings.push(twin_finding(
                "scenario_probe",
                "mitm",
                format!("Session cookie `{}` missing Secure flag", cookie.name),
                escalate_severity("high", cfg.strict_mode),
                "T1557",
                &format!(
                    "Set-Cookie `{}` on {} lacks the Secure attribute — the cookie will be sent over \
                     cleartext HTTP during an ssl-strip attack.",
                    cookie.name,
                    profile.base_url
                ),
                base,
                json!({
                    "cookie": cookie.name,
                    "secure": false,
                    "httponly": cookie.httponly,
                    "samesite": cookie.samesite,
                }),
            ));
        }
    }

    if profile.tls_expired {
        findings.push(twin_finding(
            "scenario_probe",
            "mitm",
            "TLS certificate expired",
            escalate_severity("critical", cfg.strict_mode),
            "T1557",
            &format!(
                "Certificate for {} is expired — clients may ignore validation or accept attacker-supplied certs.",
                profile.host
            ),
            base,
            json!({ "tls_expired": true }),
        ));
    } else if profile.tls_self_signed {
        findings.push(twin_finding(
            "scenario_probe",
            "mitm",
            "Self-signed TLS certificate",
            escalate_severity("high", cfg.strict_mode),
            "T1557",
            &format!(
                "Self-signed certificate on {} — users trained to click through warnings are trivial MITM targets.",
                profile.host
            ),
            base,
            json!({ "tls_self_signed": true }),
        ));
    }

    if let Some(days) = profile.tls_days_until_expiry {
        if days >= 0 && days <= 14 {
            findings.push(twin_finding(
                "scenario_probe",
                "mitm",
                format!("TLS certificate expires in {days} days"),
                escalate_severity("medium", cfg.strict_mode),
                "T1557",
                &format!(
                    "Certificate for {} expires soon ({days} days) — outage or mis-issued replacement \
                     increases MITM risk.",
                    profile.host
                ),
                base,
                json!({ "days_until_expiry": days }),
            ));
        }
    }

    findings
}

// ─── Scenario: CORS ──────────────────────────────────────────────────────────────

fn cors_misconfiguration_signal(
    sent_origin: Option<&str>,
    acao: &str,
    allow_credentials: bool,
) -> Option<(&'static str, &'static str, &'static str)> {
    let acao = acao.trim();
    if acao.is_empty() {
        return None;
    }
    if acao == "*" {
        return Some((
            "CORS Allow-Origin: * — cross-origin read of API responses",
            if allow_credentials {
                "high"
            } else {
                "medium"
            },
            "Wildcard ACAO",
        ));
    }
    if acao.contains("null") && allow_credentials {
        return Some((
            "CORS Allow-Origin: null with credentials",
            "high",
            "Origin=null with credentials=true",
        ));
    }
    if let Some(sent) = sent_origin {
        if acao == sent {
            return Some((
                "CORS reflects arbitrary Origin — credentialed cross-origin data theft",
                if allow_credentials {
                    "critical"
                } else {
                    "high"
                },
                "ACAO echoes attacker Origin",
            ));
        }
    }
    None
}

async fn probe_cors(client: &reqwest::Client, base: &str, cfg: &TwinConfig) -> Vec<Value> {
    let mut findings = Vec::new();
    let host = extract_host(base);
    let evil_origin = format!("https://weissman-twin-probe.{host}");

    let api_paths = ["/", "/api", "/api/v1", "/graphql"];
    for path in api_paths {
        let url = if path == "/" {
            normalize_url(base)
        } else {
            format!("{}{}", base.trim_end_matches('/'), path)
        };

        for (sent_origin, probe) in [
            (None, http_get(client, &url).await),
            (
                Some(evil_origin.as_str()),
                http_get_with_headers(client, &url, &[("Origin", evil_origin.as_str())]).await,
            ),
        ] {
            let Some(p) = probe else { continue };
            let Some(acao) = header_value(&p.headers, "access-control-allow-origin") else {
                continue;
            };
            let creds = has_header(&p.headers, "access-control-allow-credentials");
            if let Some((title, severity, detail)) =
                cors_misconfiguration_signal(sent_origin, acao, creds)
            {
                findings.push(twin_finding(
                    "scenario_probe",
                    "cors",
                    title,
                    escalate_severity(severity, cfg.strict_mode),
                    "T1185",
                    &format!(
                        "{detail} on {} (ACAO='{}', credentials={}, Origin sent={:?}). \
                         A malicious site can fetch authenticated API responses from the victim's browser.",
                        p.final_url,
                        acao,
                        creds,
                        sent_origin
                    ),
                    base,
                    json!({
                        "acao": acao,
                        "credentials": creds,
                        "origin_sent": sent_origin,
                        "probe_url": p.final_url,
                    }),
                ));
                return findings;
            }
        }
    }

    findings
}

// ─── Attack-path synthesis (Wiz-style toxic combinations) ──────────────────────

fn synthesize_attack_paths(profile: &TwinProfile, scenario_findings: &[Value], base: &str) -> Vec<Value> {
    let mut paths = Vec::new();

    let has_xss = scenario_findings.iter().any(|f| {
        f.get("scenario").and_then(|v| v.as_str()) == Some("xss")
            && f.get("severity").and_then(|v| v.as_str()) != Some("info")
    });
    let has_sqli = scenario_findings.iter().any(|f| {
        f.get("scenario").and_then(|v| v.as_str()) == Some("sqli")
            && matches!(
                f.get("severity").and_then(|v| v.as_str()),
                Some("critical" | "high")
            )
    });
    let has_mitm = scenario_findings.iter().any(|f| {
        f.get("scenario").and_then(|v| v.as_str()) == Some("mitm")
            && matches!(
                f.get("severity").and_then(|v| v.as_str()),
                Some("critical" | "high")
            )
    });
    let has_cors = scenario_findings.iter().any(|f| {
        f.get("scenario").and_then(|v| v.as_str()) == Some("cors")
            && matches!(
                f.get("severity").and_then(|v| v.as_str()),
                Some("critical" | "high")
            )
    });

    if has_mitm
        && profile.http_cleartext_available
        && profile.cookies.iter().any(|c| !c.secure)
    {
        paths.push(attack_path_finding(
            "mitm",
            &[
                "Network position: adversary on shared Wi‑Fi/VLAN",
                "Downgrade: cleartext HTTP available, HSTS absent/weak",
                "Capture: session cookie without Secure sent over HTTP",
                "Impact: account session hijack",
            ],
            "critical",
            "Toxic combination: SSL-strip → session hijack",
            base,
            json!({
                "http_cleartext": profile.http_cleartext_available,
                "hsts": profile.has_hsts,
                "insecure_cookies": profile.cookies.iter().filter(|c| !c.secure).map(|c| &c.name).collect::<Vec<_>>(),
            }),
        ));
    }

    if has_xss && !profile.has_csp {
        paths.push(attack_path_finding(
            "xss",
            &[
                "Delivery: reflected XSS via crafted URL",
                "Execution: no CSP blocks inline script",
                "Impact: steal HttpOnly-adjacent tokens / perform actions as victim",
            ],
            "critical",
            "Toxic combination: reflected XSS + no CSP",
            base,
            json!({ "csp": "absent" }),
        ));
    }

    if has_cors && profile.cors_credentials {
        paths.push(attack_path_finding(
            "cors",
            &[
                "Lure victim to attacker-controlled origin",
                "Cross-origin fetch with reflected ACAO + credentials",
                "Impact: read authenticated API JSON (PII, tokens, admin data)",
            ],
            "critical",
            "Toxic combination: CORS origin reflection + credentials",
            base,
            json!({ "acao": profile.cors_acao, "credentials": true }),
        ));
    }

    if has_sqli {
        paths.push(attack_path_finding(
            "sqli",
            &[
                "Initial access: error-based SQL injection on query parameter",
                "Discovery: enumerate schema via error messages",
                "Impact: authentication bypass / credential dump",
            ],
            "critical",
            "Toxic combination: SQLi → database compromise",
            base,
            json!({ "stack": profile.powered_by }),
        ));
    }

    paths
}

// ─── Scoring ─────────────────────────────────────────────────────────────────────

struct CategoryScore {
    earned: f64,
    possible: f64,
}

impl CategoryScore {
    fn new() -> Self {
        Self {
            earned: 0.0,
            possible: 0.0,
        }
    }

    fn deduct(&mut self, points: f64, weight: f64) {
        self.possible += weight;
        self.earned += (weight - points).max(0.0);
    }

    fn pct(&self) -> u32 {
        if self.possible <= 0.0 {
            return 100;
        }
        ((self.earned / self.possible) * 100.0).round() as u32
    }
}

fn grade_from_score(score: u32) -> &'static str {
    match score {
        97..=100 => "A+",
        93..=96 => "A",
        90..=92 => "A-",
        87..=89 => "B+",
        83..=86 => "B",
        80..=82 => "B-",
        77..=79 => "C+",
        73..=76 => "C",
        70..=72 => "C-",
        67..=69 => "D+",
        63..=66 => "D",
        60..=62 => "D-",
        _ => "F",
    }
}

struct ExploitabilityVerdict {
    verdict: &'static str,
    reason: String,
    severity: &'static str,
}

fn assess_exploitability(
    profile: &TwinProfile,
    paths: &[Value],
    scenario_findings: &[Value],
) -> ExploitabilityVerdict {
    let critical_paths = paths
        .iter()
        .filter(|p| p.get("severity").and_then(|v| v.as_str()) == Some("critical"))
        .count();
    let high_findings = scenario_findings
        .iter()
        .filter(|f| {
            matches!(
                f.get("severity").and_then(|v| v.as_str()),
                Some("critical" | "high")
            )
        })
        .count();

    if critical_paths > 0 || high_findings >= 2 {
        return ExploitabilityVerdict {
            verdict: "exploitable",
            reason: format!(
                "{critical_paths} critical attack path(s) and {high_findings} high-severity scenario signal(s) observed"
            ),
            severity: "critical",
        };
    }

    if high_findings == 1
        || paths.iter().any(|p| {
            p.get("severity").and_then(|v| v.as_str()) == Some("high")
        })
    {
        return ExploitabilityVerdict {
            verdict: "partial",
            reason: "One or more high-impact weaknesses observed — chained exploitation likely with additional access".into(),
            severity: "high",
        };
    }

    if !profile.has_hsts
        || !profile.has_csp
        || profile.http_cleartext_available
        || profile.cors_header_present
    {
        return ExploitabilityVerdict {
            verdict: "hardening_gaps",
            reason: "No confirmed injection/MITM chain yet, but material hardening gaps remain (HSTS/CSP/transport)".into(),
            severity: "medium",
        };
    }

    ExploitabilityVerdict {
        verdict: "hardened",
        reason: "Live probes did not observe exploitable XSS/SQLi/CORS/MITM chains on the tested surface".into(),
        severity: "info",
    }
}

fn toxic_headline(profile: &TwinProfile, exploit: &ExploitabilityVerdict, paths: &[Value]) -> String {
    if let Some(p) = paths.first() {
        if let Some(t) = p.get("title").and_then(|v| v.as_str()) {
            return t.to_string();
        }
    }
    if !profile.has_hsts && profile.http_cleartext_available {
        return "No HSTS + cleartext HTTP ⇒ trivial SSL-strip window".into();
    }
    if !profile.has_csp {
        return "No Content-Security-Policy ⇒ XSS impact unconstrained".into();
    }
    exploit.reason.clone()
}

fn compute_subscores(profile: &TwinProfile, scenario_findings: &[Value]) -> (CategoryScore, CategoryScore, CategoryScore, CategoryScore) {
    let mut transport = CategoryScore::new();
    let mut headers = CategoryScore::new();
    let mut cors = CategoryScore::new();
    let mut injection = CategoryScore::new();

    transport.deduct(if profile.has_hsts { 0.0 } else { 25.0 }, 25.0);
    transport.deduct(
        if profile.http_cleartext_available && !profile.http_redirects_to_https {
            20.0
        } else {
            0.0
        },
        20.0,
    );
    transport.deduct(
        if profile.tls_expired || profile.tls_self_signed {
            30.0
        } else {
            0.0
        },
        30.0,
    );
    transport.deduct(
        if profile.cookies.iter().any(|c| !c.secure) {
            15.0
        } else {
            0.0
        },
        15.0,
    );

    headers.deduct(if profile.has_csp { 0.0 } else { 30.0 }, 30.0);
    headers.deduct(
        if profile.csp_unsafe_inline || profile.csp_wildcard {
            15.0
        } else {
            0.0
        },
        15.0,
    );
    headers.deduct(if profile.has_xfo { 0.0 } else { 10.0 }, 10.0);

    cors.deduct(
        if profile.cors_header_present && (profile.cors_acao == "*" || profile.cors_credentials) {
            25.0
        } else {
            0.0
        },
        25.0,
    );

    let inj_hits = scenario_findings
        .iter()
        .filter(|f| {
            matches!(
                f.get("scenario").and_then(|v| v.as_str()),
                Some("xss" | "sqli")
            ) && matches!(
                f.get("severity").and_then(|v| v.as_str()),
                Some("critical" | "high")
            )
        })
        .count();
    injection.deduct((inj_hits as f64) * 35.0, 35.0);

    (transport, headers, cors, injection)
}

fn build_roadmap(profile: &TwinProfile, scenario_findings: &[Value]) -> Vec<String> {
    let mut steps: Vec<(u8, String)> = Vec::new();

    if !profile.has_hsts {
        steps.push((
            1,
            format!(
                "Enable HSTS on {}: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`",
                profile.host
            ),
        ));
    }
    if profile.http_cleartext_available && !profile.http_redirects_to_https {
        steps.push((
            1,
            format!(
                "Force HTTPS: redirect all HTTP requests on {} to HTTPS (301) and disable cleartext listeners where possible",
                profile.host
            ),
        ));
    }
    for c in &profile.cookies {
        if !c.secure {
            steps.push((
                2,
                format!("Add `Secure` (and `HttpOnly`) to session cookie `{}`", c.name),
            ));
        }
    }
    if !profile.has_csp {
        steps.push((
            2,
            "Deploy a strict Content-Security-Policy with nonce/hash script-src — remove 'unsafe-inline'".into(),
        ));
    } else if profile.csp_unsafe_inline {
        steps.push((
            3,
            "Remove 'unsafe-inline' from CSP; migrate to nonce-based script loading".into(),
        ));
    }
    if scenario_findings.iter().any(|f| f.get("scenario") == Some(&json!("xss"))) {
        steps.push((
            1,
            "Encode all user-controlled output in HTML contexts; add regression tests for reflected XSS".into(),
        ));
    }
    if scenario_findings.iter().any(|f| f.get("scenario") == Some(&json!("sqli"))) {
        steps.push((
            1,
            "Parameterize all SQL queries (prepared statements); disable verbose DB errors in production".into(),
        ));
    }
    if profile.cors_credentials || profile.cors_acao == "*" {
        steps.push((
            2,
            "Replace wildcard/reflected CORS with an allow-list of trusted origins; never reflect Origin with credentials=true".into(),
        ));
    }
    if profile.tls_expired || profile.tls_days_until_expiry.is_some_and(|d| d <= 14) {
        steps.push((2, "Renew TLS certificate and automate ACME/Let's Encrypt renewal".into()));
    }

    steps.sort_by_key(|(p, _)| *p);
    steps.into_iter().map(|(_, t)| t).collect()
}

fn profile_to_json(profile: &TwinProfile) -> Value {
    json!({
        "base_url": profile.base_url,
        "host": profile.host,
        "http_status": profile.http_status,
        "server": profile.server,
        "powered_by": profile.powered_by,
        "content_type": profile.content_type,
        "security_headers": {
            "hsts": profile.has_hsts,
            "hsts_max_age": profile.hsts_max_age,
            "hsts_include_subdomains": profile.hsts_include_subdomains,
            "hsts_preload": profile.hsts_preload,
            "csp": profile.has_csp,
            "csp_unsafe_inline": profile.csp_unsafe_inline,
            "csp_unsafe_eval": profile.csp_unsafe_eval,
            "x_frame_options": profile.has_xfo,
            "referrer_policy": profile.has_referrer_policy,
            "permissions_policy": profile.has_permissions_policy,
        },
        "cors": {
            "present": profile.cors_header_present,
            "acao": profile.cors_acao,
            "credentials": profile.cors_credentials,
        },
        "transport": {
            "http_cleartext": profile.http_cleartext_available,
            "http_redirects_to_https": profile.http_redirects_to_https,
            "tls_days_until_expiry": profile.tls_days_until_expiry,
            "tls_self_signed": profile.tls_self_signed,
            "tls_expired": profile.tls_expired,
            "tls_key_bits": profile.tls_key_bits,
        },
        "cookies": profile.cookies.iter().map(|c| json!({
            "name": c.name,
            "secure": c.secure,
            "httponly": c.httponly,
            "samesite": c.samesite,
        })).collect::<Vec<_>>(),
        "waf_hint": profile.waf_hint,
        "discovered_paths": profile.discovered_paths,
    })
}

// ─── Entry point ─────────────────────────────────────────────────────────────────

pub async fn run_digital_twin_result(target: &str) -> EngineResult {
    run_digital_twin_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_digital_twin_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let cfg = TwinConfig::from_ctx(ctx);
    let base = normalize_url(target);
    let client = build_client(cfg.timeout_ms).await;
    let mut findings: Vec<Value> = Vec::new();

    let profile = build_twin_profile(&client, &base, &cfg, ctx).await;

    // Twin profile finding (always emitted — drives the GUI environment panel)
    findings.push(twin_finding(
        "twin_profile",
        "profile",
        format!("Digital Twin environment profile: {}", profile.host),
        "info",
        "T1595.002",
        &format!(
            "Live twin built from {} — Server={}, PoweredBy={}, HSTS={}, CSP={}, cleartext_HTTP={}, paths={}.",
            profile.base_url,
            profile.server,
            if profile.powered_by.is_empty() { "—" } else { &profile.powered_by },
            profile.has_hsts,
            profile.has_csp,
            profile.http_cleartext_available,
            profile.discovered_paths.len(),
        ),
        &base,
        json!({ "twin_profile": profile_to_json(&profile) }),
    ));

    let mut scenario_findings: Vec<Value> = Vec::new();

    if cfg.scenario != ScenarioMode::Profile {
        if cfg.runs_scenario(ScenarioMode::Xss) && cfg.check_xss {
            scenario_findings.extend(probe_xss(&client, &base, &cfg, &profile).await);
        }
        if cfg.runs_scenario(ScenarioMode::Sqli) && cfg.check_sqli {
            scenario_findings.extend(probe_sqli(&client, &base, &cfg, &profile).await);
        }
        if cfg.runs_scenario(ScenarioMode::Mitm) && cfg.check_mitm {
            scenario_findings.extend(probe_mitm(&client, &base, &cfg, &profile).await);
        }
        if cfg.runs_scenario(ScenarioMode::Cors) && cfg.check_cors {
            scenario_findings.extend(probe_cors(&client, &base, &cfg).await);
        }
    }

    findings.extend(scenario_findings.clone());

    let attack_paths = synthesize_attack_paths(&profile, &scenario_findings, &base);
    findings.extend(attack_paths.clone());

    let (cat_transport, cat_headers, cat_cors, cat_injection) =
        compute_subscores(&profile, &scenario_findings);
    let score = ((cat_transport.pct() as f64 * 0.30)
        + (cat_headers.pct() as f64 * 0.25)
        + (cat_cors.pct() as f64 * 0.15)
        + (cat_injection.pct() as f64 * 0.30))
        .round() as u32;
    let letter = grade_from_score(score);
    let exploit = assess_exploitability(&profile, &attack_paths, &scenario_findings);
    let headline = toxic_headline(&profile, &exploit, &attack_paths);
    let roadmap = build_roadmap(&profile, &scenario_findings);

    let checks_failed = findings
        .iter()
        .filter(|f| {
            let cat = f.get("category").and_then(|v| v.as_str()).unwrap_or("");
            cat != "twin_profile"
                && cat != "summary"
                && matches!(
                    f.get("severity").and_then(|v| v.as_str()),
                    Some("critical" | "high" | "medium")
                )
        })
        .count();

    let summary = json!({
        "type": ENGINE_ID,
        "category": "summary",
        "scenario": pstr(&ctx.job_params, "scenario"),
        "title": format!("Digital Twin Posture: Grade {letter} ({score}/100) — {}", exploit.verdict),
        "severity": exploit.severity,
        "mitre_attack": "T1595",
        "description": format!(
            "Target `{}` scored {score}/100 (grade {letter}). Exploitability: {} — {}. {} material finding(s).",
            profile.host, exploit.verdict, headline, checks_failed
        ),
        "target": profile.host,
        "toxic_combination": headline,
        "remediation": "Prioritise transport hardening (HSTS + kill cleartext), CSP deployment, and fix any confirmed injection/CORS signals below.",
        "grade": letter,
        "score": score,
        "max_score": 100,
        "exploitability": exploit.verdict,
        "exploitability_reason": exploit.reason,
        "subscores": {
            "transport": cat_transport.pct(),
            "headers": cat_headers.pct(),
            "cors": cat_cors.pct(),
            "injection": cat_injection.pct(),
        },
        "attack_paths_count": attack_paths.len(),
        "scenario_signals": scenario_findings.len(),
        "checks_failed": checks_failed,
        "roadmap": roadmap,
        "twin_profile": profile_to_json(&profile),
        "details": {
            "scenario_requested": pstr(&ctx.job_params, "scenario"),
            "probe_depth": pstr(&ctx.job_params, "probe_depth"),
            "strict_mode": cfg.strict_mode,
        },
    });

    findings.insert(0, summary);

    let scenario_label = pstr(&ctx.job_params, "scenario");
    let msg = if scenario_label.is_empty() {
        format!(
            "{ENGINE_ID}: {} grade {letter} ({score}/100), {} — {} findings",
            profile.host,
            exploit.verdict,
            findings.len()
        )
    } else {
        format!(
            "{ENGINE_ID}: scenario={scenario_label} on {} — {} scenario signal(s), {} attack path(s)",
            profile.host,
            scenario_findings.len(),
            attack_paths.len()
        )
    };

    EngineResult::ok(findings, msg)
}

pub async fn run_digital_twin(target: &str) {
    print_result(run_digital_twin_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_boundaries() {
        assert_eq!(grade_from_score(100), "A+");
        assert_eq!(grade_from_score(93), "A");
        assert_eq!(grade_from_score(80), "B-");
        assert_eq!(grade_from_score(59), "F");
    }

    #[test]
    fn cors_reflect_is_critical_with_credentials() {
        let sig = cors_misconfiguration_signal(
            Some("https://evil.example"),
            "https://evil.example",
            true,
        );
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().1, "critical");
    }

    #[test]
    fn scenario_mode_parses_ui_values() {
        assert_eq!(
            ScenarioMode::parse("xss".into()),
            ScenarioMode::Xss
        );
        assert_eq!(
            ScenarioMode::parse("mitm".into()),
            ScenarioMode::Mitm
        );
        assert_eq!(
            ScenarioMode::parse("".into()),
            ScenarioMode::Profile
        );
    }

    #[test]
    fn sql_error_detects_mysql() {
        assert_eq!(
            sql_error_engine("You have an error in your SQL syntax near"),
            Some("mysql")
        );
    }
}
