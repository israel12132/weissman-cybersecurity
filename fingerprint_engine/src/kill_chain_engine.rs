//! Kill Chain Planner Engine — LIVE evidence-backed MITRE ATT&CK kill-chain mapper.
//! MITRE: T1595 (Active Scanning), T1190 (Exploit Public-Facing Application), etc.
//!
//! Builds attack paths only from observed HTTP headers, HTML/JS surfaces, and probed entry points.
//! No simulated chains or fabricated CVE matches.

use crate::engine_probes::{
    extract_host, header_value, http_client, http_get, join_url, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::collections::HashSet;

const ENGINE_ID: &str = "kill_chain";

// ── Kill-chain stage taxonomy ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum KillChainStage {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
}

impl KillChainStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::Weaponization => "Weaponization",
            Self::Delivery => "Delivery",
            Self::Exploitation => "Exploitation",
            Self::Installation => "Installation",
            Self::CommandAndControl => "Command and Control",
            Self::ActionsOnObjectives => "Actions on Objectives",
        }
    }

    fn all() -> &'static [KillChainStage; 7] {
        &[
            Self::Reconnaissance,
            Self::Weaponization,
            Self::Delivery,
            Self::Exploitation,
            Self::Installation,
            Self::CommandAndControl,
            Self::ActionsOnObjectives,
        ]
    }
}

/// Classify free-text evidence into a kill-chain stage (deterministic heuristics).
fn classify_stage(signal: &str) -> KillChainStage {
    let s = signal.to_ascii_lowercase();
    if s.contains("webhook")
        || s.contains("callback")
        || s.contains("dns-over-https")
        || s.contains("doh")
        || s.contains("alt-svc")
        || s.contains("exfil")
        || s.contains("c2")
        || s.contains("beacon")
    {
        KillChainStage::CommandAndControl
    } else if s.contains("upload")
        && (s.contains("no csp") || s.contains("httponly") || s.contains("prerequisite"))
    {
        KillChainStage::Exploitation
    } else if s.contains("login")
        || s.contains("auth")
        || s.contains("graphql")
        || s.contains("soap")
        || s.contains("upload")
        || s.contains("entry point")
        || s.contains("delivery")
    {
        KillChainStage::Delivery
    } else if s.contains("php")
        || s.contains("asp.net")
        || s.contains("tomcat")
        || s.contains("wordpress")
        || s.contains("drupal")
        || s.contains("joomla")
        || s.contains("exploit class")
        || s.contains("weaponization")
        || s.contains("stack")
    {
        KillChainStage::Weaponization
    } else if s.contains("robots")
        || s.contains("sitemap")
        || s.contains("server:")
        || s.contains("x-powered-by")
        || s.contains("cdn")
        || s.contains("waf")
        || s.contains("recon")
        || s.contains("fingerprint")
    {
        KillChainStage::Reconnaissance
    } else if s.contains("install") || s.contains("persistence") {
        KillChainStage::Installation
    } else if s.contains("impact") || s.contains("objective") || s.contains("data theft") {
        KillChainStage::ActionsOnObjectives
    } else {
        KillChainStage::Reconnaissance
    }
}

// ── Observation model ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct EntryPoint {
    kind: String,
    url: String,
    evidence: String,
    status: u16,
}

#[derive(Debug, Clone, Default)]
struct TargetObservations {
    base: String,
    reachable: bool,
    status: u16,
    server: Option<String>,
    powered_by: Option<String>,
    csp: Option<String>,
    set_cookies: Vec<String>,
    cookie_flags: Vec<String>,
    content_type: Option<String>,
    cdn_waf: Vec<String>,
    auth_endpoints: Vec<String>,
    api_versions: Vec<String>,
    entry_points: Vec<EntryPoint>,
    weaponization_hints: Vec<(String, String, String)>, // (stack, hint, evidence)
    exploitation_prereqs: Vec<(String, String)>,        // (combo, evidence)
    c2_exfil_hints: Vec<(String, String)>,              // (indicator, evidence)
    recon_evidence: Vec<String>,
    body_snippet: String,
}

impl TargetObservations {
    fn stages_with_evidence(&self) -> HashSet<KillChainStage> {
        let mut stages = HashSet::new();
        if !self.recon_evidence.is_empty()
            || self.server.is_some()
            || self.powered_by.is_some()
            || !self.cdn_waf.is_empty()
        {
            stages.insert(KillChainStage::Reconnaissance);
        }
        if !self.weaponization_hints.is_empty() {
            stages.insert(KillChainStage::Weaponization);
        }
        if !self.entry_points.is_empty() || !self.auth_endpoints.is_empty() {
            stages.insert(KillChainStage::Delivery);
        }
        if !self.exploitation_prereqs.is_empty() {
            stages.insert(KillChainStage::Exploitation);
        }
        if !self.c2_exfil_hints.is_empty() {
            stages.insert(KillChainStage::CommandAndControl);
        }
        stages
    }

    fn completion_score(&self) -> (usize, usize, f64) {
        let covered = self.stages_with_evidence().len();
        let total = KillChainStage::all().len();
        let pct = if total == 0 {
            0.0
        } else {
            (covered as f64 / total as f64) * 100.0
        };
        (covered, total, pct)
    }
}

// ── Header / stack analysis ─────────────────────────────────────────────────────

fn detect_cdn_waf(headers: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let checks: &[(&str, &str)] = &[
        ("cf-ray", "Cloudflare CDN/WAF"),
        ("cf-cache-status", "Cloudflare CDN"),
        ("x-sucuri-id", "Sucuri WAF"),
        ("x-akamai-", "Akamai CDN/WAF"),
        ("x-fastly-request-id", "Fastly CDN"),
        ("x-cache", "CDN cache layer"),
        ("x-amz-cf-id", "AWS CloudFront"),
        ("x-azure-ref", "Azure Front Door/CDN"),
        ("server", "nginx"), // partial — checked below
    ];
    for (hdr, label) in checks {
        if let Some(v) = header_value(headers, hdr.trim_end_matches('-')) {
            let vl = v.to_ascii_lowercase();
            if *hdr == "server" {
                if vl.contains("cloudflare") || vl.contains("akamaighost") {
                    out.push(format!("Server header indicates CDN: {}", v));
                }
            } else if hdr.ends_with('-') {
                if header_value(headers, hdr.trim_end_matches('-')).is_some()
                    || headers
                        .iter()
                        .any(|(k, _)| k.to_ascii_lowercase().starts_with(hdr))
                {
                    out.push(label.to_string());
                }
            } else {
                out.push(format!("{} ({})", label, v));
            }
        }
    }
    if let Some(v) = header_value(headers, "x-cdn") {
        out.push(format!("X-CDN: {}", v));
    }
    if let Some(v) = header_value(headers, "x-waf") {
        out.push(format!("X-WAF: {}", v));
    }
    out.sort();
    out.dedup();
    out
}

fn analyze_cookie_flags(set_cookie: &str) -> String {
    let lower = set_cookie.to_ascii_lowercase();
    let mut flags = Vec::new();
    if lower.contains("httponly") {
        flags.push("HttpOnly");
    } else {
        flags.push("missing-HttpOnly");
    }
    if lower.contains("secure") {
        flags.push("Secure");
    } else {
        flags.push("missing-Secure");
    }
    if lower.contains("samesite") {
        if lower.contains("samesite=none") {
            flags.push("SameSite=None");
        } else if lower.contains("samesite=strict") {
            flags.push("SameSite=Strict");
        } else {
            flags.push("SameSite=Lax");
        }
    } else {
        flags.push("missing-SameSite");
    }
    flags.join(", ")
}

fn weaponization_from_stack(
    server: Option<&str>,
    powered_by: Option<&str>,
) -> Vec<(String, String, String)> {
    let mut hints = Vec::new();
    let combined =
        format!("{} {}", server.unwrap_or(""), powered_by.unwrap_or("")).to_ascii_lowercase();

    if combined.contains("php") {
        let ver = powered_by.or(server).unwrap_or("").to_string();
        hints.push((
            "PHP".into(),
            "Observed PHP runtime — historical attack classes include file inclusion, unsafe deserialization, and session fixation against legacy modules.".into(),
            format!("X-Powered-By/Server: {}", ver),
        ));
    }
    if combined.contains("asp.net") || combined.contains("aspnet") {
        hints.push((
            "ASP.NET".into(),
            "Observed ASP.NET stack — review ViewState integrity, debug endpoints, and JWT/cookie auth bypass patterns for this framework.".into(),
            format!("Stack header: {}", combined.trim()),
        ));
    }
    if combined.contains("tomcat") || combined.contains("apache-coyote") {
        hints.push((
            "Apache Tomcat".into(),
            "Observed Java servlet container — common exploit classes include manager/console exposure, deserialization gadgets, and path normalization bugs.".into(),
            format!("Server: {}", server.unwrap_or("unknown")),
        ));
    }
    if combined.contains("express") || combined.contains("node") {
        hints.push((
            "Node.js/Express".into(),
            "Observed Node runtime — prototype pollution, SSRF in middleware, and template injection are recurring classes for this stack.".into(),
            format!("Stack: {}", combined.trim()),
        ));
    }
    if combined.contains("wordpress") {
        hints.push((
            "WordPress".into(),
            "Observed WordPress — plugin/theme surface and xmlrpc.php are typical initial-access vectors when outdated components are present.".into(),
            "WordPress fingerprint in Server/X-Powered-By or body".into(),
        ));
    }
    hints
}

fn extract_api_versions(body: &str, headers: &[(String, String)]) -> Vec<String> {
    let mut versions = HashSet::new();
    let body_l = body.to_ascii_lowercase();
    for prefix in ["/api/v", "/v1", "/v2", "/v3", "api-version:", "version="] {
        if body_l.contains(prefix) {
            versions.insert(prefix.trim_end_matches('=').to_string());
        }
    }
    if let Some(link) = header_value(headers, "link") {
        if link.contains("api") {
            versions.insert(format!("Link header: {}", link));
        }
    }
    if let Some(v) = header_value(headers, "api-version") {
        versions.insert(format!("Api-Version: {}", v));
    }
    versions.into_iter().collect()
}

fn parse_html_entry_points(base: &str, body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let body_l = body.to_ascii_lowercase();

    for pattern in [
        ("login", "/login"),
        ("sign in", "/login"),
        ("register", "/register"),
        ("upload", "/upload"),
        ("graphql", "/graphql"),
        ("webhook", "/webhook"),
        ("soap", "/soap"),
    ] {
        if body_l.contains(pattern.0) {
            out.push((
                pattern.1.to_string(),
                format!("HTML/JS references '{}'", pattern.0),
            ));
        }
    }

    // Form actions
    for chunk in body.split("<form").skip(1) {
        let fragment = &chunk[..chunk.find('>').unwrap_or(chunk.len().min(512))];
        let frag_l = fragment.to_ascii_lowercase();
        let action = fragment
            .split("action=")
            .nth(1)
            .map(|s| {
                s.trim_matches(['"', '\'', ' '])
                    .split(['"', '\'', ' '])
                    .next()
                    .unwrap_or("")
            })
            .unwrap_or("");
        let kind = if frag_l.contains("multipart") || frag_l.contains("type=\"file\"") {
            "upload"
        } else if frag_l.contains("password") || frag_l.contains("login") {
            "login"
        } else {
            "form"
        };
        if !action.is_empty() {
            let url = if action.starts_with("http") {
                action.to_string()
            } else {
                join_url(base, action)
            };
            out.push((url, format!("HTML form action ({})", kind)));
        }
    }

    // JS fetch/axios/graphql endpoints
    for token in [
        "fetch(\"",
        "fetch('",
        "/graphql",
        "/api/",
        "webhook",
        "callback=",
    ] {
        if body_l.contains(&token.to_ascii_lowercase()) {
            out.push((
                join_url(base, "/api/"),
                format!("JS/HTML references '{}'", token),
            ));
        }
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

const COMMON_PATHS: &[(&str, &str)] = &[
    ("/login", "login"),
    ("/signin", "login"),
    ("/auth/login", "login"),
    ("/admin/login", "login"),
    ("/upload", "upload"),
    ("/api/upload", "upload"),
    ("/webhook", "webhook"),
    ("/hooks", "webhook"),
    ("/graphql", "graphql"),
    ("/api/graphql", "graphql"),
    ("/soap", "soap"),
    ("/wsdl", "soap"),
    ("/api/v1", "api"),
    ("/api/v2", "api"),
    ("/api/v3", "api"),
    ("/.well-known/security.txt", "security_txt"),
];

fn c2_exfil_from_headers_and_body(
    headers: &[(String, String)],
    body: &str,
) -> Vec<(String, String)> {
    let mut hints = Vec::new();
    let body_l = body.to_ascii_lowercase();

    for param in [
        "webhook",
        "callback",
        "hook_url",
        "notify_url",
        "redirect_uri",
    ] {
        if body_l.contains(param) {
            hints.push((
                format!("Outbound {} parameter surface", param),
                format!("HTML/JS contains '{}' — may accept attacker-controlled callback URLs (SSRF/OAST/exfil pivot).", param),
            ));
        }
    }

    if let Some(alt) = header_value(headers, "alt-svc") {
        if alt.contains("h3") || alt.contains("443") {
            hints.push((
                "Alt-Svc HTTP/3 advertisement".into(),
                format!("Alt-Svc: {} — review DNS/QUIC routing; misconfigured edge DNS can widen exfil paths.", alt),
            ));
        }
    }

    // DoH misconfig hints purely from response headers (no DNS queries)
    if let Some(v) = header_value(headers, "use-dns-over-https") {
        hints.push((
            "Use-DNS-Over-HTTPS response header".into(),
            format!("Use-DNS-Over-HTTPS: {} — browser DoH policy exposed; verify enterprise split-horizon isn't bypassed.", v),
        ));
    }
    if headers.iter().any(|(k, v)| {
        k.to_ascii_lowercase().contains("dns") && v.to_ascii_lowercase().contains("https")
    }) {
        hints.push((
            "DNS-over-HTTPS policy header".into(),
            "Response advertises DNS-over-HTTPS behavior — audit resolver trust boundary.".into(),
        ));
    }

    hints
}

fn exploitation_prerequisites(obs: &TargetObservations) -> Vec<(String, String)> {
    let mut combos = Vec::new();
    let has_upload = obs.entry_points.iter().any(|e| e.kind == "upload");
    let weak_csp = obs
        .csp
        .as_ref()
        .map(|c| c.is_empty() || !c.contains("default-src"))
        .unwrap_or(true);
    let session_no_httponly = obs
        .cookie_flags
        .iter()
        .any(|f| f.contains("missing-HttpOnly"));

    if has_upload && weak_csp {
        combos.push((
            "upload + weak/absent CSP".into(),
            "File upload entry point observed while Content-Security-Policy is missing or permissive — enables XSS-assisted upload abuse.".into(),
        ));
    }
    if has_upload && session_no_httponly {
        combos.push((
            "upload + session cookie without HttpOnly".into(),
            format!(
                "Upload surface with session cookies missing HttpOnly: {}",
                obs.cookie_flags.join("; ")
            ),
        ));
    }
    let has_login = obs.entry_points.iter().any(|e| e.kind == "login");
    if has_login && session_no_httponly {
        combos.push((
            "login + session cookie without HttpOnly".into(),
            "Authenticated session may be readable via XSS — cookie flags lack HttpOnly.".into(),
        ));
    }
    if obs
        .entry_points
        .iter()
        .any(|e| e.kind == "graphql" || e.kind == "webhook")
        && weak_csp
    {
        combos.push((
            "API/webhook surface + weak CSP".into(),
            "GraphQL/webhook entry with weak CSP increases client-side token theft risk.".into(),
        ));
    }
    combos
}

// ── Attack-path synthesis ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AttackPath {
    title: String,
    severity: String,
    steps: Vec<Value>,
    evidence: Vec<String>,
    blast_radius: f64,
    mitre_path: Vec<String>,
}

/// Build 1–5 evidence-backed attack paths from accumulated observations.
fn synthesize_attack_paths(obs: &TargetObservations) -> Vec<AttackPath> {
    let mut paths = Vec::new();

    let has_login = obs.entry_points.iter().any(|e| e.kind == "login");
    let has_upload = obs.entry_points.iter().any(|e| e.kind == "upload");
    let has_graphql = obs.entry_points.iter().any(|e| e.kind == "graphql");
    let has_webhook = obs.entry_points.iter().any(|e| e.kind == "webhook");
    let php_stack = obs
        .weaponization_hints
        .iter()
        .any(|(s, _, _)| s.contains("PHP"));
    let weak_session = obs
        .cookie_flags
        .iter()
        .any(|f| f.contains("missing-HttpOnly"));
    let weak_csp = obs.csp.as_ref().map(|c| c.is_empty()).unwrap_or(true);

    if has_login && weak_session {
        let login_url = obs
            .entry_points
            .iter()
            .find(|e| e.kind == "login")
            .map(|e| e.url.clone())
            .unwrap_or_else(|| join_url(&obs.base, "/login"));
        paths.push(AttackPath {
            title: "Session theft via login surface + non-HttpOnly cookie".into(),
            severity: "high".into(),
            steps: vec![
                json!({"phase": "Reconnaissance", "action": "Fingerprint auth endpoint", "mitre": "T1595.002"}),
                json!({"phase": "Delivery", "action": "Deliver XSS/reflected payload via login or adjacent page", "mitre": "T1189"}),
                json!({"phase": "Exploitation", "action": "Steal session cookie readable by JavaScript", "mitre": "T1539"}),
                json!({"phase": "Actions on Objectives", "action": "Replay stolen session against authenticated API", "mitre": "T1078"}),
            ],
            evidence: vec![
                format!("Login entry: {}", login_url),
                format!("Cookie flags: {}", obs.cookie_flags.join("; ")),
            ],
            blast_radius: 0.72,
            mitre_path: vec!["T1595.002".into(), "T1189".into(), "T1539".into(), "T1078".into()],
        });
    }

    if has_upload && (weak_csp || php_stack) {
        let upload_url = obs
            .entry_points
            .iter()
            .find(|e| e.kind == "upload")
            .map(|e| e.url.clone())
            .unwrap_or_else(|| join_url(&obs.base, "/upload"));
        let stack_note = obs
            .weaponization_hints
            .first()
            .map(|(_, h, _)| h.clone())
            .unwrap_or_else(|| "Upload surface observed".into());
        paths.push(AttackPath {
            title: "Web shell / malicious upload pivot".into(),
            severity: if php_stack { "critical" } else { "high" }.into(),
            steps: vec![
                json!({"phase": "Reconnaissance", "action": "Identify upload handler and stack", "mitre": "T1595.002"}),
                json!({"phase": "Weaponization", "action": "Craft payload aligned to observed stack", "mitre": "T1587.001"}),
                json!({"phase": "Delivery", "action": "POST malicious file to upload endpoint", "mitre": "T1190"}),
                json!({"phase": "Exploitation", "action": "Trigger or browse uploaded content", "mitre": "T1203"}),
            ],
            evidence: vec![
                format!("Upload entry: {}", upload_url),
                stack_note,
                obs.csp
                    .clone()
                    .map(|c| format!("CSP: {}", c))
                    .unwrap_or_else(|| "CSP: absent".into()),
            ],
            blast_radius: if php_stack { 0.88 } else { 0.75 },
            mitre_path: vec!["T1595.002".into(), "T1587.001".into(), "T1190".into(), "T1203".into()],
        });
    }

    if has_graphql {
        let gql_url = obs
            .entry_points
            .iter()
            .find(|e| e.kind == "graphql")
            .map(|e| e.url.clone())
            .unwrap_or_else(|| join_url(&obs.base, "/graphql"));
        paths.push(AttackPath {
            title: "GraphQL introspection / BOLA initial access".into(),
            severity: "high".into(),
            steps: vec![
                json!({"phase": "Reconnaissance", "action": "Discover GraphQL endpoint", "mitre": "T1595.002"}),
                json!({"phase": "Delivery", "action": "Send introspection or batched queries", "mitre": "T1190"}),
                json!({"phase": "Exploitation", "action": "Abuse weak authorization on sensitive fields", "mitre": "T1213"}),
            ],
            evidence: vec![format!("GraphQL entry: {}", gql_url)],
            blast_radius: 0.7,
            mitre_path: vec!["T1595.002".into(), "T1190".into(), "T1213".into()],
        });
    }

    if has_webhook || !obs.c2_exfil_hints.is_empty() {
        let hint = obs
            .c2_exfil_hints
            .first()
            .map(|(i, e)| format!("{} — {}", i, e))
            .unwrap_or_else(|| "Webhook/callback surface in HTML".into());
        paths.push(AttackPath {
            title: "SSRF / callback exfil via webhook parameters".into(),
            severity: "high".into(),
            steps: vec![
                json!({"phase": "Reconnaissance", "action": "Map callback/webhook parameters", "mitre": "T1595.002"}),
                json!({"phase": "Delivery", "action": "Supply attacker-controlled callback URL", "mitre": "T1190"}),
                json!({"phase": "Command and Control", "action": "Receive outbound SSRF or DNS/exfil probe", "mitre": "T1071.001"}),
            ],
            evidence: vec![hint],
            blast_radius: 0.68,
            mitre_path: vec!["T1595.002".into(), "T1190".into(), "T1071.001".into()],
        });
    }

    if !obs.auth_endpoints.is_empty() && !obs.api_versions.is_empty() {
        paths.push(AttackPath {
            title: "Versioned API credential stuffing / auth bypass".into(),
            severity: "medium".into(),
            steps: vec![
                json!({"phase": "Reconnaissance", "action": "Enumerate API version and auth routes", "mitre": "T1595.002"}),
                json!({"phase": "Delivery", "action": "Target versioned auth endpoints", "mitre": "T1078.004"}),
                json!({"phase": "Exploitation", "action": "Exploit weak auth or default credentials", "mitre": "T1110.003"}),
            ],
            evidence: vec![
                format!("Auth endpoints: {}", obs.auth_endpoints.join(", ")),
                format!("API versions: {}", obs.api_versions.join(", ")),
            ],
            blast_radius: 0.55,
            mitre_path: vec!["T1595.002".into(), "T1078.004".into(), "T1110.003".into()],
        });
    }

    // Cap at 5 paths, prefer higher blast_radius
    paths.sort_by(|a, b| {
        b.blast_radius
            .partial_cmp(&a.blast_radius)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    paths.truncate(5);
    paths
}

fn attack_path_to_finding(path: &AttackPath, target: &str) -> Value {
    json!({
        "type": "kill_chain",
        "engine": ENGINE_ID,
        "category": "attack_path",
        "title": format!("Attack path: {}", path.title),
        "severity": path.severity,
        "mitre_attack": path.mitre_path.first().cloned().unwrap_or_else(|| "T1190".into()),
        "mitre_path": path.mitre_path,
        "target": target,
        "blast_radius": path.blast_radius,
        "steps": path.steps,
        "evidence": path.evidence,
        "description": path.steps.iter().filter_map(|s| {
            s.get("action").and_then(|a| a.as_str()).map(|a| a.to_string())
        }).collect::<Vec<_>>().join(" → "),
    })
}

// ── Live recon pipeline ─────────────────────────────────────────────────────────

async fn gather_observations(client: &reqwest::Client, target: &str) -> TargetObservations {
    let base = normalize_url(target);
    let mut obs = TargetObservations {
        base: base.clone(),
        ..Default::default()
    };

    if let Some(probe) = http_get(client, &base).await {
        obs.reachable = true;
        obs.status = probe.status;
        obs.server = header_value(&probe.headers, "server").map(str::to_string);
        obs.powered_by = header_value(&probe.headers, "x-powered-by").map(str::to_string);
        obs.csp = header_value(&probe.headers, "content-security-policy").map(str::to_string);
        obs.content_type = header_value(&probe.headers, "content-type").map(str::to_string);
        obs.cdn_waf = detect_cdn_waf(&probe.headers);

        for (k, v) in &probe.headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                obs.set_cookies.push(v.clone());
                obs.cookie_flags.push(analyze_cookie_flags(v));
            }
        }

        obs.recon_evidence.push(format!(
            "GET {} → HTTP {} Server={} X-Powered-By={}",
            base,
            probe.status,
            obs.server.as_deref().unwrap_or("—"),
            obs.powered_by.as_deref().unwrap_or("—")
        ));
        if let Some(csp) = &obs.csp {
            obs.recon_evidence
                .push(format!("Content-Security-Policy: {}", csp));
        }
        for c in &obs.cdn_waf {
            obs.recon_evidence.push(format!("CDN/WAF: {}", c));
        }

        obs.api_versions = extract_api_versions(&probe.body, &probe.headers);
        obs.weaponization_hints =
            weaponization_from_stack(obs.server.as_deref(), obs.powered_by.as_deref());
        obs.body_snippet = if probe.body.len() > 4096 {
            probe.body[..4096].to_string()
        } else {
            probe.body.clone()
        };

        for (url, ev) in parse_html_entry_points(&base, &probe.body) {
            obs.entry_points.push(EntryPoint {
                kind: if ev.contains("upload") {
                    "upload".into()
                } else if ev.contains("login") {
                    "login".into()
                } else if ev.contains("graphql") {
                    "graphql".into()
                } else if ev.contains("webhook") {
                    "webhook".into()
                } else {
                    "form".into()
                },
                url,
                evidence: ev,
                status: probe.status,
            });
        }

        obs.c2_exfil_hints = c2_exfil_from_headers_and_body(&probe.headers, &probe.body);
    }

    // Probe common paths (live HTTP only)
    for (path, kind) in COMMON_PATHS {
        let url = join_url(&base, path);
        if let Some(p) = http_get(client, &url).await {
            if p.status == 200 || p.status == 401 || p.status == 403 || p.status == 405 {
                if kind == &"login" {
                    obs.auth_endpoints.push(url.clone());
                }
                if kind == &"api" && p.body.contains("version") {
                    obs.api_versions
                        .push(format!("{} → HTTP {}", url, p.status));
                }
                let already = obs.entry_points.iter().any(|e| e.url == url);
                if !already {
                    obs.entry_points.push(EntryPoint {
                        kind: (*kind).to_string(),
                        url: url.clone(),
                        evidence: format!("Probe {} → HTTP {}", path, p.status),
                        status: p.status,
                    });
                }
            }
        }
    }

    // robots.txt disallowed paths (recon + delivery)
    let robots_url = join_url(&base, "/robots.txt");
    if let Some(p) = http_get(client, &robots_url).await {
        if p.status == 200 {
            obs.recon_evidence
                .push(format!("robots.txt reachable at {}", robots_url));
            for line in p.body.lines() {
                let line = line.trim();
                if line.to_lowercase().starts_with("disallow:") {
                    let dis = line[9..].trim();
                    if dis.len() > 1 && !dis.contains('*') {
                        let url = join_url(&base, dis);
                        if let Some(rp) = http_get(client, &url).await {
                            if rp.status == 200 || rp.status == 403 {
                                obs.entry_points.push(EntryPoint {
                                    kind: "hidden_path".into(),
                                    url: url.clone(),
                                    evidence: format!(
                                        "robots.txt Disallow {} → HTTP {}",
                                        dis, rp.status
                                    ),
                                    status: rp.status,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    obs.exploitation_prereqs = exploitation_prerequisites(&obs);
    obs
}

pub async fn run_kill_chain_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = http_client().await;
    let base = normalize_url(target);
    let host = extract_host(target);
    let obs = gather_observations(&client, target).await;
    let mut findings = Vec::new();

    if !obs.reachable {
        return EngineResult::ok(
            vec![json!({
                "type": "kill_chain",
                "title": "Target unreachable",
                "severity": "info",
                "mitre_attack": "T1595",
                "phase": "Reconnaissance",
                "description": format!("Could not reach {} — no live observations to map kill chain.", base),
            })],
            format!("Kill Chain: target {} unreachable", host),
        );
    }

    // Stage 1 — Reconnaissance findings
    findings.push(json!({
        "type": "kill_chain",
        "engine": ENGINE_ID,
        "title": "Reconnaissance: live target fingerprint",
        "severity": "info",
        "mitre_attack": "T1595.002",
        "phase": KillChainStage::Reconnaissance.as_str(),
        "evidence": obs.recon_evidence,
        "description": format!(
            "{} returned HTTP {}. Stack: Server={} X-Powered-By={}. CDN/WAF signals: {}. API/version hints: {}.",
            base,
            obs.status,
            obs.server.as_deref().unwrap_or("—"),
            obs.powered_by.as_deref().unwrap_or("—"),
            if obs.cdn_waf.is_empty() { "none".into() } else { obs.cdn_waf.join(", ") },
            if obs.api_versions.is_empty() { "none".into() } else { obs.api_versions.join(", ") },
        ),
    }));

    // Stage 2 — Weaponization hints (observed stack only)
    for (stack, hint, evidence) in &obs.weaponization_hints {
        findings.push(json!({
            "type": "kill_chain",
            "engine": ENGINE_ID,
            "title": format!("Weaponization hint: {} stack", stack),
            "severity": "info",
            "mitre_attack": "T1587.001",
            "phase": KillChainStage::Weaponization.as_str(),
            "evidence": [evidence],
            "description": hint,
        }));
    }

    // Stage 3 — Delivery vectors
    for ep in obs.entry_points.iter().take(12) {
        findings.push(json!({
            "type": "kill_chain",
            "engine": ENGINE_ID,
            "title": format!("Delivery vector: {} ({})", ep.kind, ep.url),
            "severity": if ep.status == 200 { "medium" } else { "info" },
            "mitre_attack": "T1190",
            "phase": KillChainStage::Delivery.as_str(),
            "evidence": [ep.evidence.clone()],
            "url": ep.url,
            "description": format!("Live entry point {} responded HTTP {} — {}", ep.url, ep.status, ep.evidence),
        }));
    }

    // Stage 4 — Exploitation prerequisites
    for (combo, evidence) in &obs.exploitation_prereqs {
        findings.push(json!({
            "type": "kill_chain",
            "engine": ENGINE_ID,
            "title": format!("Exploitation prerequisite: {}", combo),
            "severity": "high",
            "mitre_attack": "T1190",
            "phase": KillChainStage::Exploitation.as_str(),
            "evidence": [evidence],
            "description": evidence,
        }));
    }

    // Stage 5 — C2 / exfil indicators
    for (indicator, evidence) in &obs.c2_exfil_hints {
        findings.push(json!({
            "type": "kill_chain",
            "engine": ENGINE_ID,
            "title": format!("C2/Exfil indicator: {}", indicator),
            "severity": "medium",
            "mitre_attack": "T1071.001",
            "phase": KillChainStage::CommandAndControl.as_str(),
            "evidence": [evidence],
            "description": evidence,
        }));
    }

    // Stage 6 — Synthesized attack paths (1–5)
    let paths = synthesize_attack_paths(&obs);
    for path in &paths {
        findings.push(attack_path_to_finding(path, target));
    }

    // Kill-chain completion score
    let (covered, total, pct) = obs.completion_score();
    let stages_json: Vec<Value> = KillChainStage::all()
        .iter()
        .map(|s| {
            let has = obs.stages_with_evidence().contains(s);
            json!({
                "stage": s.as_str(),
                "evidence_present": has,
            })
        })
        .collect();

    findings.push(json!({
        "type": "kill_chain",
        "engine": ENGINE_ID,
        "category": "completion_score",
        "title": "Kill-chain completion score",
        "severity": if pct >= 60.0 { "medium" } else { "info" },
        "mitre_attack": "T1595",
        "stages_covered": covered,
        "stages_total": total,
        "completion_percent": (pct * 10.0).round() / 10.0,
        "stages": stages_json,
        "attack_paths_synthesized": paths.len(),
        "description": format!(
            "Evidence-backed coverage: {}/{} kill-chain stages ({:.1}%). {} attack path(s) synthesized from live observations.",
            covered, total, pct, paths.len()
        ),
    }));

    let finding_count = findings.len();
    EngineResult::ok(
        findings,
        format!(
            "Kill Chain: {} findings, {:.0}% stage coverage, {} attack path(s)",
            finding_count,
            pct,
            paths.len()
        ),
    )
}

pub async fn run_kill_chain(target: &str) {
    print_result(run_kill_chain_result(target).await);
}

// ── Inline tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_classifier_maps_signals() {
        assert_eq!(
            classify_stage("Server: nginx recon fingerprint"),
            KillChainStage::Reconnaissance
        );
        assert_eq!(
            classify_stage("PHP exploit class from X-Powered-By"),
            KillChainStage::Weaponization
        );
        assert_eq!(
            classify_stage("login entry point delivery"),
            KillChainStage::Delivery
        );
        assert_eq!(
            classify_stage("upload + no csp prerequisite"),
            KillChainStage::Exploitation
        );
        assert_eq!(
            classify_stage("webhook callback exfil param"),
            KillChainStage::CommandAndControl
        );
    }

    #[test]
    fn path_synthesizer_emits_bounded_evidence_backed_paths() {
        let obs = TargetObservations {
            base: "https://app.example.com".into(),
            reachable: true,
            status: 200,
            server: Some("nginx".into()),
            powered_by: Some("PHP/8.1.2".into()),
            csp: None,
            cookie_flags: vec!["missing-HttpOnly, missing-Secure".into()],
            weaponization_hints: vec![(
                "PHP".into(),
                "PHP runtime observed".into(),
                "X-Powered-By: PHP/8.1.2".into(),
            )],
            entry_points: vec![
                EntryPoint {
                    kind: "login".into(),
                    url: "https://app.example.com/login".into(),
                    evidence: "Probe /login → HTTP 200".into(),
                    status: 200,
                },
                EntryPoint {
                    kind: "upload".into(),
                    url: "https://app.example.com/upload".into(),
                    evidence: "HTML form upload".into(),
                    status: 200,
                },
            ],
            c2_exfil_hints: vec![("webhook param".into(), "callback= in HTML".into())],
            auth_endpoints: vec!["https://app.example.com/login".into()],
            api_versions: vec!["/api/v1".into()],
            exploitation_prereqs: vec![("upload + weak/absent CSP".into(), "observed".into())],
            ..Default::default()
        };

        let paths = synthesize_attack_paths(&obs);
        assert!(!paths.is_empty(), "expected at least one path");
        assert!(paths.len() <= 5, "must cap at 5 paths");
        for p in &paths {
            assert!(!p.steps.is_empty());
            assert!(!p.evidence.is_empty());
            assert!(p.blast_radius > 0.0 && p.blast_radius <= 1.0);
            assert!(!p.mitre_path.is_empty());
        }
    }

    #[test]
    fn completion_score_counts_observed_stages() {
        let obs = TargetObservations {
            recon_evidence: vec!["fingerprint".into()],
            weaponization_hints: vec![("PHP".into(), "hint".into(), "ev".into())],
            entry_points: vec![EntryPoint {
                kind: "login".into(),
                url: "https://x/login".into(),
                evidence: "probe".into(),
                status: 200,
            }],
            exploitation_prereqs: vec![("combo".into(), "ev".into())],
            c2_exfil_hints: vec![("webhook".into(), "ev".into())],
            ..Default::default()
        };
        let (covered, total, pct) = obs.completion_score();
        assert_eq!(total, 7);
        assert!(covered >= 4);
        assert!(pct > 0.0);
    }

    #[test]
    fn weaponization_requires_observed_stack_not_generic_cve() {
        let hints = weaponization_from_stack(Some("nginx/1.24"), Some("PHP/7.4.3"));
        assert_eq!(hints.len(), 1);
        assert!(hints[0].2.contains("PHP"));
        assert!(!hints[0].1.to_ascii_lowercase().contains("cve-"));
    }
}
