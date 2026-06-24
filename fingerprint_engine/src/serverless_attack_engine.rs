//! Serverless / FaaS Security Engine — agentless, evidence-only assessment of serverless attack
//! surface at Wiz / Orca / Lacework depth.
//!
//! Strict **real-probe-only** contract: a finding is emitted **only** when the engine observes a
//! live HTTP signal (platform fingerprint header, exposed config artifact, env-var leak pattern,
//! permissive CORS, unauthenticated admin surface, stack-trace disclosure, cold-start timing
//! differential). Nothing is fabricated.
//!
//! Capabilities (all driven from `job_params` via [`ArsenalConfig`]):
//!   1. **Multi-platform FaaS fingerprinting** — AWS Lambda, Azure Functions, GCP Cloud Functions,
//!      Vercel, Netlify, Cloudflare Workers, Firebase, OpenFaaS/Knative/Fission from response headers.
//!   2. **Function endpoint discovery** — operator path list + built-in corpus per platform.
//!   3. **IaC / config exposure** — serverless.yml, template.yaml, vercel.json, firebase.json, etc.
//!   4. **Environment variable leakage** — debug/config endpoints with high-precision secret patterns.
//!   5. **CORS misconfiguration** — Function URL / API Gateway style `Access-Control-Allow-Origin: *`.
//!   6. **Event injection surface** — safe malformed-event probes; stack traces & debug leaks only.
//!   7. **Cold-start timing oracle** — multi-sample latency differential confirms FaaS runtime.
//!   8. **Admin / debug surface** — unauthenticated management & health/debug endpoints.
//!   9. **Attack-path synthesis** — Wiz-style toxic combinations (public fn + env leak + CORS).
//!  10. **Posture score** — 0–100 graded exposure with honest metrics finding.
//!
//! MITRE: T1059 (Command and Scripting Interpreter) / T1190 (Exploit Public-Facing Application).

use crate::arsenal_config::{finding_rich, severity_for_score, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    detect_secrets, header_value, http_client, http_get_with_headers, join_url, normalize_url,
    probe_paths_concurrent, status_indicates_presence, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

const ENGINE_ID: &str = "serverless_attack";
const MITRE: &str = "T1059";

// ── Platform fingerprint signatures ─────────────────────────────────────────

struct PlatformSig {
    id: &'static str,
    label: &'static str,
    header_tokens: &'static [&'static str],
    body_tokens: &'static [&'static str],
}

#[rustfmt::skip]
fn platform_signatures() -> &'static [PlatformSig] {
    &[
        PlatformSig { id: "aws_lambda", label: "AWS Lambda", header_tokens: &["x-amzn-requestid", "x-amz-apigw-id", "x-amzn-trace-id", "x-amz-cf-id"], body_tokens: &["Task timed out", "Process exited before completing request", "Unable to import module"] },
        PlatformSig { id: "azure_functions", label: "Azure Functions", header_tokens: &["x-ms-request-id", "x-ms-invocation-id", "x-azure-ref", "x-functions-key"], body_tokens: &["Azure Functions", "Function host is in error state"] },
        PlatformSig { id: "gcp_cloud_functions", label: "GCP Cloud Functions", header_tokens: &["x-cloud-trace-context", "x-goog-", "function-execution-id"], body_tokens: &["Function execution took", "Cloud Functions", "Google Cloud Functions"] },
        PlatformSig { id: "vercel", label: "Vercel", header_tokens: &["x-vercel-id", "x-vercel-cache", "x-vercel-execution-region"], body_tokens: &["VERCEL", "Serverless Function"] },
        PlatformSig { id: "netlify", label: "Netlify Functions", header_tokens: &["x-nf-request-id", "x-nf-deploy-id", "netlify-vary"], body_tokens: &["Netlify Function", "Invoked function failed"] },
        PlatformSig { id: "cloudflare_workers", label: "Cloudflare Workers", header_tokens: &["cf-ray", "cf-worker", "cf-cache-status"], body_tokens: &["Worker threw exception", "cloudflare workers"] },
        PlatformSig { id: "firebase", label: "Firebase Functions", header_tokens: &["x-firebase-", "x-cloud-trace-context"], body_tokens: &["Firebase", "functions.config"] },
        PlatformSig { id: "openfaas", label: "OpenFaaS / Knative", header_tokens: &["x-openfaas-", "x-knative-"], body_tokens: &["OpenFaaS", "Knative"] },
    ]
}

// ── Path corpora ──────────────────────────────────────────────────────────────

const DEFAULT_FUNCTION_PATHS: &[&str] = &[
    // AWS Lambda / API Gateway
    "/api/", "/prod/", "/dev/", "/stage/", "/v1/", "/v2/",
    "/lambda/", "/fn/", "/functions/", "/.aws/lambda/",
    // Vercel
    "/api/hello", "/api/auth", "/api/users", "/api/webhook", "/api/health",
    // Netlify
    "/.netlify/functions/", "/.netlify/functions/hello", "/.netlify/functions/api",
    // Azure Functions
    "/api/HttpTrigger", "/api/health", "/api/status",
    // GCP
    "/_ah/", "/cloudfunctions/",
    // Generic
    "/serverless/", "/.functions/", "/.api/", "/.well-known/serverless",
    "/webhook", "/hooks/", "/trigger/", "/invoke/",
];

const DEFAULT_CONFIG_PATHS: &[&str] = &[
    "/serverless.yml", "/serverless.yaml", "/serverless.json",
    "/template.yaml", "/template.yml", "/samconfig.toml",
    "/vercel.json", "/.vercel/project.json",
    "/netlify.toml", "/firebase.json", "/.firebaserc",
    "/now.json", "/wrangler.toml", "/worker.js",
    "/serverless.ts", "/serverless.js",
    "/.env", "/.env.local", "/.env.production",
    "/package.json", "/pnpm-lock.yaml",
];

const DEFAULT_DEBUG_PATHS: &[&str] = &[
    "/api/env", "/api/config", "/api/settings", "/api/debug", "/api/health",
    "/api/status", "/api/info", "/api/metrics", "/api/admin", "/api/internal",
    "/debug/env", "/debug/vars", "/debug/config", "/debug/pprof",
    "/.well-known/env", "/config.json", "/settings.json",
    "/_admin", "/__admin", "/admin/debug", "/actuator/env", "/actuator/health",
    "/.aws/lambda/env", "/runtime/env",
];

const ENV_KEY_INDICATORS: &[&str] = &[
    "SECRET", "PASSWORD", "TOKEN", "API_KEY", "DATABASE_URL", "REDIS_URL",
    "AWS_ACCESS", "AWS_SECRET", "PRIVATE_KEY", "CLIENT_SECRET", "AUTH_TOKEN",
    "DB_PASS", "MONGO_URI", "SENDGRID", "STRIPE_", "TWILIO_", "OPENAI_",
    "SLACK_", "GITHUB_TOKEN", "NPM_TOKEN", "JWT_SECRET", "ENCRYPTION_KEY",
];

const STACK_TRACE_MARKERS: &[&str] = &[
    "Traceback (most recent call last)",
    "at Object.", "at Module.", "at exports.",
    "SyntaxError:", "ReferenceError:", "TypeError:",
    "Runtime.ImportModuleError", "UnhandledPromiseRejection",
    "Internal Server Error", "stack trace",
    "File \"", "line ", "Exception in thread",
];

// ── Settings ──────────────────────────────────────────────────────────────────

struct Settings {
    intensity: Intensity,
    timeout_ms: u64,
    concurrency: usize,
    function_paths: Vec<String>,
    config_paths: Vec<String>,
    debug_paths: Vec<String>,
    probe_fingerprint: bool,
    probe_functions: bool,
    probe_config: bool,
    probe_env_leak: bool,
    probe_cors: bool,
    probe_event_injection: bool,
    probe_cold_start: bool,
    probe_admin: bool,
    attack_synth: bool,
    posture_scoring: bool,
    cold_start_samples: u8,
    platform_filter: BTreeSet<String>,
    auth_headers: Vec<(String, String)>,
    cors_origin: String,
    min_sev_rank: u8,
    max_requests: usize,
    dry_run: bool,
}

fn sev_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn parse_auth_headers(cfg: &ArsenalConfig) -> Vec<(String, String)> {
    let mut hs = Vec::new();
    if let Some(ah) = cfg.string("auth_header") {
        if let Some((k, v)) = ah.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if !k.is_empty() && !v.is_empty() {
                hs.push((k.to_string(), v.to_string()));
            }
        }
    }
    if let Some(bt) = cfg.string("bearer_token") {
        let bt = bt.trim();
        if !bt.is_empty() && !hs.iter().any(|(k, _)| k.eq_ignore_ascii_case("authorization")) {
            let val = if bt.to_ascii_lowercase().starts_with("bearer ") {
                bt.to_string()
            } else {
                format!("Bearer {bt}")
            };
            hs.push(("Authorization".to_string(), val));
        }
    }
    if let Some(ck) = cfg.string("cookies") {
        if !ck.trim().is_empty() {
            hs.push(("Cookie".to_string(), ck.trim().to_string()));
        }
    }
    hs
}

fn parse_settings(ctx: &EngineRunContext) -> Settings {
    let cfg = ArsenalConfig::from_ctx(ctx);
    let intensity = cfg.intensity();
    let depth_paths = match intensity {
        Intensity::Light => 12,
        Intensity::Normal => 24,
        Intensity::Aggressive => 48,
    };

    let mut function_paths = cfg.string_list_or("function_paths", DEFAULT_FUNCTION_PATHS);
    function_paths.truncate(depth_paths);

    let mut config_paths = cfg.string_list_or("config_paths", DEFAULT_CONFIG_PATHS);
    if intensity == Intensity::Light {
        config_paths.truncate(8);
    }

    let mut debug_paths = cfg.string_list_or("debug_paths", DEFAULT_DEBUG_PATHS);
    if intensity == Intensity::Light {
        debug_paths.truncate(6);
    }

    let platform_filter: BTreeSet<String> = cfg
        .string_list("platform_filter")
        .into_iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();

    Settings {
        intensity,
        timeout_ms: cfg.timeout_ms(8000),
        concurrency: cfg.concurrency().clamp(1, 64),
        function_paths,
        config_paths,
        debug_paths,
        probe_fingerprint: cfg.bool_or("probe_fingerprint", true),
        probe_functions: cfg.bool_or("probe_functions", true),
        probe_config: cfg.bool_or("probe_config", true),
        probe_env_leak: cfg.bool_or("probe_env_leak", true),
        probe_cors: cfg.bool_or("probe_cors", true),
        probe_event_injection: cfg.bool_or("probe_event_injection", intensity != Intensity::Light),
        probe_cold_start: cfg.bool_or("probe_cold_start", true),
        probe_admin: cfg.bool_or("probe_admin", true),
        attack_synth: cfg.bool_or("attack_path_synthesis", true),
        posture_scoring: cfg.bool_or("posture_scoring", true),
        cold_start_samples: cfg.u64_or("cold_start_samples", 3).clamp(2, 8) as u8,
        platform_filter,
        auth_headers: parse_auth_headers(&cfg),
        cors_origin: cfg.string_or("cors_test_origin", "https://evil-attacker.example"),
        min_sev_rank: sev_rank(&cfg.string_or("min_severity", "info")),
        max_requests: cfg.usize_or("max_requests", 500).clamp(10, 2000),
        dry_run: cfg.bool_or("dry_run", false),
    }
}

fn platform_allowed(settings: &Settings, platform_id: &str) -> bool {
    settings.platform_filter.is_empty()
        || settings.platform_filter.contains(&platform_id.to_ascii_lowercase())
}

async fn build_client(timeout_ms: u64, user_agent: Option<&str>) -> Client {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs());
    if let Some(ua) = user_agent {
        if !ua.trim().is_empty() {
            b = b.user_agent(ua.trim());
        }
    }
    b.build().unwrap_or_else(|_| reqwest::Client::new())
}

fn auth_slice(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

fn headers_blob(probe: &HttpProbe) -> String {
    probe
        .headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.to_ascii_lowercase(), v.to_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn body_has_env_keys(body: &str) -> Vec<&'static str> {
    let upper = body.to_uppercase();
    ENV_KEY_INDICATORS
        .iter()
        .filter(|k| upper.contains(&k.to_uppercase()))
        .copied()
        .collect()
}

fn detect_platforms(probe: &HttpProbe) -> Vec<(&'static str, &'static str)> {
    let hb = headers_blob(probe);
    let body_l = probe.body.to_ascii_lowercase();
    let mut hits = Vec::new();
    for sig in platform_signatures() {
        let header_hit = sig.header_tokens.iter().any(|t| hb.contains(&t.to_ascii_lowercase()));
        let body_hit = sig.body_tokens.iter().any(|t| body_l.contains(&t.to_ascii_lowercase()));
        if header_hit || body_hit {
            hits.push((sig.id, sig.label));
        }
    }
    hits
}

// ── Posture accumulator ───────────────────────────────────────────────────────

#[derive(Default)]
struct Posture {
    platforms: BTreeSet<String>,
    functions_exposed: u32,
    config_exposed: u32,
    env_leak: bool,
    cors_wildcard: bool,
    admin_exposed: bool,
    stack_trace: bool,
    cold_start_confirmed: bool,
    unauthenticated_admin: bool,
}

impl Posture {
    fn exposure_score(&self) -> f64 {
        let mut score = 0.0_f64;
        if self.env_leak {
            score += 0.35;
        }
        if self.cors_wildcard {
            score += 0.15;
        }
        if self.config_exposed > 0 {
            score += 0.20;
        }
        if self.unauthenticated_admin {
            score += 0.20;
        }
        if self.functions_exposed > 0 {
            score += 0.05 * (self.functions_exposed.min(5) as f64);
        }
        if self.stack_trace {
            score += 0.10;
        }
        if self.cold_start_confirmed {
            score += 0.02;
        }
        score.clamp(0.0, 1.0)
    }
}

fn push_if_severe(
    findings: &mut Vec<Value>,
    settings: &Settings,
    finding: Value,
) {
    let sev = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info");
    if sev_rank(sev) >= settings.min_sev_rank {
        findings.push(finding);
    }
}

fn attack_paths(posture: &Posture, host: &str) -> Vec<Value> {
    let mut paths = Vec::new();
    if posture.env_leak && posture.functions_exposed > 0 {
        paths.push(json!({
            "type": "serverless_attack",
            "category": "attack_path",
            "title": "Public serverless function + environment secret leak → cloud account takeover",
            "severity": "critical",
            "mitre_attack": "T1552.005",
            "description": format!(
                "Toxic combination on {}: an invocable serverless endpoint coexists with environment-variable \
                 disclosure. An attacker can invoke the function (or chain via CORS) and harvest cloud credentials \
                 from leaked env vars — the canonical Wiz serverless-to-cloud pivot.",
                host
            ),
            "confidence": 0.92
        }));
    }
    if posture.cors_wildcard && posture.functions_exposed > 0 {
        paths.push(json!({
            "type": "serverless_attack",
            "category": "attack_path",
            "title": "Wildcard CORS on Function URL → cross-origin credential theft",
            "severity": "high",
            "mitre_attack": "T1190",
            "description": format!(
                "Function URL / API endpoint on {} reflects Access-Control-Allow-Origin: * (or echoes attacker \
                 origin). A malicious site can invoke the function from victim browsers and exfiltrate responses \
                 containing session tokens or cloud metadata.",
                host
            ),
            "confidence": 0.85
        }));
    }
    if posture.config_exposed > 0 && posture.functions_exposed > 0 {
        paths.push(json!({
            "type": "serverless_attack",
            "category": "attack_path",
            "title": "Exposed serverless IaC + live functions → supply-chain injection",
            "severity": "high",
            "mitre_attack": "T1195.002",
            "description": format!(
                "Serverless configuration artifacts are web-accessible on {} while live function endpoints respond. \
                 Attackers can map the deployment topology from IaC and target injection into the CI/CD pipeline \
                 or direct function redeployment.",
                host
            ),
            "confidence": 0.78
        }));
    }
    if posture.unauthenticated_admin && posture.stack_trace {
        paths.push(json!({
            "type": "serverless_attack",
            "category": "attack_path",
            "title": "Unauthenticated admin + verbose errors → RCE reconnaissance",
            "severity": "high",
            "mitre_attack": "T1059",
            "description": format!(
                "Admin/debug endpoints on {} respond without authentication and malformed event payloads trigger \
                 stack traces — together they expose runtime paths, dependency versions, and IAM hints for targeted \
                 serverless RCE or dependency confusion.",
                host
            ),
            "confidence": 0.80
        }));
    }
    paths
}

// ── Probe phases ──────────────────────────────────────────────────────────────

async fn probe_fingerprint(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_fingerprint {
        return;
    }
    let auth = auth_slice(&settings.auth_headers);
    let Some(probe) = http_get_with_headers(client, base, &auth).await else {
        return;
    };
    for (id, label) in detect_platforms(&probe) {
        if !platform_allowed(settings, id) {
            continue;
        }
        posture.platforms.insert(id.to_string());
        let ev = Evidence::new()
            .with("platform", id)
            .with("url", &probe.final_url)
            .with("status", probe.status)
            .check("response_headers", true, headers_blob(&probe).chars().take(512).collect::<String>());
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("FaaS platform fingerprint: {}", label),
                "info",
                MITRE,
                &format!(
                    "Live HTTP response from {} identifies {} serverless runtime signals (HTTP {}). \
                     Serverless deployments have distinct security properties: ephemeral execution, \
                     shared cold-start containers, and IAM role credentials in environment.",
                    host, label, probe.status
                ),
                host,
                0.95,
                ev,
            ),
        );
    }
}

async fn probe_function_paths(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_functions {
        return;
    }
    let paths: Vec<&str> = settings.function_paths.iter().map(String::as_str).collect();
    let probes = probe_paths_concurrent(client, base, &paths, settings.concurrency).await;
    for probe in probes {
        if !status_indicates_presence(probe.status) {
            continue;
        }
        posture.functions_exposed += 1;
        let sev = if probe.status == 200 { "high" } else { "medium" };
        let platforms = detect_platforms(&probe);
        let platform_note = platforms
            .first()
            .map(|(_, l)| format!(" ({})", l))
            .unwrap_or_default();
        let ev = Evidence::new()
            .with("url", &probe.final_url)
            .with("status", probe.status)
            .with("body_len", probe.body.len())
            .check("invocable_surface", probe.status == 200, probe.status);
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("Serverless function endpoint discovered{}", platform_note),
                sev,
                MITRE,
                &format!(
                    "FaaS endpoint {} returned HTTP {} ({} bytes). Invocable serverless surfaces are \
                     susceptible to event injection, dependency confusion, and SSRF-via-function chains.",
                    probe.final_url, probe.status, probe.body.len()
                ),
                host,
                if probe.status == 200 { 0.88 } else { 0.72 },
                ev,
            ),
        );
    }
}

async fn probe_config_exposure(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_config {
        return;
    }
    let paths: Vec<&str> = settings.config_paths.iter().map(String::as_str).collect();
    let probes = probe_paths_concurrent(client, base, &paths, settings.concurrency).await;
    for probe in probes {
        if probe.status != 200 || probe.body.len() < 8 {
            continue;
        }
        let body_l = probe.body.to_ascii_lowercase();
        let looks_like_config = body_l.contains("provider:")
            || body_l.contains("functions:")
            || body_l.contains("serverless")
            || body_l.contains("awstemplateformatversion")
            || body_l.contains("\"builds\"")
            || body_l.contains("firebase")
            || body_l.contains("dependencies")
            || body_l.contains("runtime:")
            || probe.final_url.ends_with(".yml")
            || probe.final_url.ends_with(".yaml")
            || probe.final_url.ends_with(".toml")
            || probe.final_url.ends_with(".json");
        if !looks_like_config {
            continue;
        }
        posture.config_exposed += 1;
        let secrets = detect_secrets(&probe.body);
        let sev = if secrets.is_empty() { "high" } else { "critical" };
        let mut ev = Evidence::new()
            .with("url", &probe.final_url)
            .with("status", 200)
            .with("body_len", probe.body.len());
        if !secrets.is_empty() {
            ev = ev.with("secret_types", json!(secrets));
        }
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("Serverless IaC/config artifact exposed: {}", probe.final_url),
                sev,
                "T1195.002",
                &format!(
                    "Configuration file {} is web-accessible (HTTP 200, {} bytes){}. \
                     Exposed serverless IaC reveals IAM roles, environment variables, VPC wiring, \
                     and deployment keys — enabling supply-chain and privilege-escalation attacks.",
                    probe.final_url,
                    probe.body.len(),
                    if secrets.is_empty() {
                        String::new()
                    } else {
                        format!(" with embedded secrets: {}", secrets.join(", "))
                    }
                ),
                host,
                if secrets.is_empty() { 0.90 } else { 0.98 },
                ev,
            ),
        );
    }
}

async fn probe_env_leak(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_env_leak {
        return;
    }
    let paths: Vec<&str> = settings.debug_paths.iter().map(String::as_str).collect();
    let probes = probe_paths_concurrent(client, base, &paths, settings.concurrency).await;
    for probe in probes {
        if probe.status != 200 {
            continue;
        }
        let env_keys = body_has_env_keys(&probe.body);
        let secrets = detect_secrets(&probe.body);
        if env_keys.is_empty() && secrets.is_empty() && probe.body.len() < 32 {
            continue;
        }
        if !env_keys.is_empty() || !secrets.is_empty() {
            posture.env_leak = true;
            let mut ev = Evidence::new()
                .with("url", &probe.final_url)
                .with("env_keys", json!(env_keys))
                .with("body_excerpt", probe.body.chars().take(256).collect::<String>());
            if !secrets.is_empty() {
                ev = ev.with("secret_types", json!(secrets));
            }
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("Environment variable leakage at {}", probe.final_url),
                    "critical",
                    "T1552.001",
                    &format!(
                        "Endpoint {} returned HTTP 200 with sensitive environment indicators: {}. \
                         Serverless functions commonly embed cloud IAM credentials, DB URLs, and API keys \
                         in environment variables — this is a direct path to cloud account compromise.",
                        probe.final_url,
                        if env_keys.is_empty() {
                            secrets.join(", ")
                        } else {
                            env_keys.join(", ")
                        }
                    ),
                    host,
                    0.96,
                    ev,
                ),
            );
        } else if settings.probe_admin && probe.body.len() > 20 {
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("Configuration/debug endpoint exposed: {}", probe.final_url),
                    "medium",
                    MITRE,
                    &format!(
                        "Debug/config endpoint {} returned HTTP 200 with {} bytes. Review for sensitive \
                         information disclosure in serverless deployments.",
                        probe.final_url, probe.body.len()
                    ),
                    host,
                    0.70,
                    Evidence::new().with("url", &probe.final_url).with("body_len", probe.body.len()),
                ),
            );
        }
    }
}

async fn probe_cors(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_cors {
        return;
    }
    let test_urls: Vec<String> = settings
        .function_paths
        .iter()
        .take(6)
        .map(|p| join_url(base, p))
        .collect();
    let origin = settings.cors_origin.as_str();
    for url in test_urls {
        let resp = client
            .request(reqwest::Method::OPTIONS, &url)
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "content-type,authorization")
            .send()
            .await;
        let Ok(resp) = resp else { continue };
        let status = resp.status().as_u16();
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let acac = resp
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let wildcard = acao == "*";
        let reflects = acao == origin;
        if !wildcard && !reflects {
            continue;
        }
        posture.cors_wildcard = true;
        let sev = if wildcard && acac.eq_ignore_ascii_case("true") {
            "critical"
        } else if wildcard || reflects {
            "high"
        } else {
            "medium"
        };
        let ev = Evidence::new()
            .with("url", &url)
            .with("acao", &acao)
            .with("acac", &acac)
            .with("preflight_status", status)
            .check("wildcard_cors", wildcard, &acao)
            .check("origin_reflection", reflects, origin);
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("Permissive CORS on serverless endpoint: {}", url),
                sev,
                "T1190",
                &format!(
                    "CORS preflight to {} returned Access-Control-Allow-Origin: '{}' (credentials: '{}'). \
                     Permissive CORS on Function URLs enables cross-origin invocation and response theft \
                     from victim browsers.",
                    url, acao, acac
                ),
                host,
                0.88,
                ev,
            ),
        );
    }
}

async fn probe_event_injection(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_event_injection {
        return;
    }
    let targets: Vec<String> = settings
        .function_paths
        .iter()
        .take(4)
        .map(|p| join_url(base, p))
        .collect();
    let payloads: Vec<Value> = vec![
        json!({"__proto__": {"polluted": true}}),
        json!({"body": "{{constructor.constructor('return process')()}}"}),
        json!({"Records": [{"eventSource": "aws:s3", "s3": {"bucket": {"name": "'; DROP TABLE--"}}}]}),
        json!({"invalid": "\u{0000}\u{ffff}"}),
    ];
    for url in targets {
        for payload in &payloads {
            let resp = client.post(&url).json(payload).send().await;
            let Ok(resp) = resp else { continue };
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let body_l = body.to_ascii_lowercase();
            let trace_hit = STACK_TRACE_MARKERS
                .iter()
                .any(|m| body.contains(m) || body_l.contains(&m.to_ascii_lowercase()));
            if !trace_hit {
                continue;
            }
            posture.stack_trace = true;
            let ev = Evidence::new()
                .with("url", &url)
                .with("status", status)
                .with("payload_type", "malformed_event")
                .with("body_excerpt", body.chars().take(384).collect::<String>());
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("Verbose error disclosure on serverless endpoint: {}", url),
                    "high",
                    MITRE,
                    &format!(
                        "Malformed event POST to {} (HTTP {}) triggered a stack trace or verbose error in the \
                         response body. Attackers use this to map runtime (Node/Python/Java), dependency versions, \
                         and file paths for targeted serverless exploitation.",
                        url, status
                    ),
                    host,
                    0.82,
                    ev,
                ),
            );
            break;
        }
    }
}

async fn probe_cold_start(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_cold_start {
        return;
    }
    let url = if settings.function_paths.is_empty() {
        join_url(base, "/api/")
    } else {
        join_url(base, &settings.function_paths[0])
    };
    let mut latencies: Vec<u128> = Vec::new();
    for _ in 0..settings.cold_start_samples {
        let start = Instant::now();
        if http_get_with_headers(client, &url, &auth_slice(&settings.auth_headers))
            .await
            .is_some()
        {
            latencies.push(start.elapsed().as_millis());
        }
    }
    if latencies.len() < 2 {
        return;
    }
    let max = *latencies.iter().max().unwrap_or(&0);
    let min = *latencies.iter().min().unwrap_or(&0);
    let diff = max.saturating_sub(min);
    if diff < 400 {
        return;
    }
    posture.cold_start_confirmed = true;
    let ev = Evidence::new()
        .with("url", &url)
        .with("samples", json!(latencies))
        .with("max_ms", max)
        .with("min_ms", min)
        .with("diff_ms", diff)
        .check("cold_start_differential", true, diff);
    push_if_severe(
        findings,
        settings,
        finding_rich(
            ENGINE_ID,
            "Serverless cold-start timing confirmed",
            "info",
            MITRE,
            &format!(
                "Multi-sample timing of {} shows cold-start behavior: latencies {:?} (spread {}ms). \
                 Confirms FaaS deployment — ephemeral containers may retain secrets in /tmp across warm invocations.",
                url, latencies, diff
            ),
            host,
            0.75,
            ev,
        ),
    );
}

async fn probe_admin_surface(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_admin {
        return;
    }
    let admin_paths = [
        "/_admin", "/__admin", "/admin", "/api/admin", "/api/internal",
        "/api/manage", "/api/console", "/.netlify/admin",
    ];
    let probes = probe_paths_concurrent(client, base, &admin_paths, settings.concurrency).await;
    for probe in probes {
        if probe.status != 200 && probe.status != 401 && probe.status != 403 {
            continue;
        }
        if probe.status == 200 && probe.body.len() > 16 {
            posture.unauthenticated_admin = true;
            posture.admin_exposed = true;
            let ev = Evidence::new()
                .with("url", &probe.final_url)
                .with("status", 200)
                .check("auth_required", false, "unauthenticated 200");
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("Unauthenticated serverless admin surface: {}", probe.final_url),
                    "critical",
                    "T1078",
                    &format!(
                        "Admin/management endpoint {} responds HTTP 200 without authentication ({} bytes). \
                         Serverless admin consoles may allow function redeployment, secret rotation, or log access.",
                        probe.final_url, probe.body.len()
                    ),
                    host,
                    0.93,
                    ev,
                ),
            );
        } else if probe.status == 401 || probe.status == 403 {
            posture.admin_exposed = true;
        }
    }
}

fn emit_posture_summary(
    posture: &Posture,
    host: &str,
    settings: &Settings,
    findings: &mut Vec<Value>,
) {
    if !settings.posture_scoring {
        return;
    }
    let score = posture.exposure_score();
    let grade = if score >= 0.85 {
        "F"
    } else if score >= 0.65 {
        "D"
    } else if score >= 0.45 {
        "C"
    } else if score >= 0.25 {
        "B"
    } else {
        "A"
    };
    let sev = severity_for_score(score);
    findings.push(json!({
        "type": ENGINE_ID,
        "category": "serverless_metrics",
        "title": format!("Serverless posture score: {:.0}/100 (grade {})", score * 100.0, grade),
        "severity": sev,
        "mitre_attack": MITRE,
        "description": format!(
            "Agentless serverless posture for {}: platforms={:?}, functions={}, config_leaks={}, \
             env_leak={}, cors_issue={}, admin_open={}, cold_start={}. Grade {} — \
             comparable to Wiz Serverless Security graph exposure scoring.",
            host,
            posture.platforms,
            posture.functions_exposed,
            posture.config_exposed,
            posture.env_leak,
            posture.cors_wildcard,
            posture.unauthenticated_admin,
            posture.cold_start_confirmed,
            grade
        ),
        "serverless_metrics": {
            "score": (score * 100.0).round() as u32,
            "grade": grade,
            "platforms": posture.platforms.iter().collect::<Vec<_>>(),
            "functions_exposed": posture.functions_exposed,
            "config_exposed": posture.config_exposed,
            "env_leak": posture.env_leak,
            "cors_wildcard": posture.cors_wildcard,
            "unauthenticated_admin": posture.unauthenticated_admin,
            "cold_start_confirmed": posture.cold_start_confirmed,
        },
        "confidence": 0.90
    }));
}

// ── Public entry points ───────────────────────────────────────────────────────

pub async fn run_serverless_attack_result(target: &str) -> EngineResult {
    run_serverless_attack_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_serverless_attack_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let settings = parse_settings(ctx);
    if settings.dry_run {
        let plan = json!({
            "engine": ENGINE_ID,
            "target": target.trim(),
            "planned_probes": {
                "fingerprint": settings.probe_fingerprint,
                "functions": settings.function_paths.len(),
                "config": settings.config_paths.len(),
                "debug": settings.debug_paths.len(),
                "cors": settings.probe_cors,
                "event_injection": settings.probe_event_injection,
                "cold_start_samples": settings.cold_start_samples,
            },
            "intensity": settings.intensity.as_str(),
            "max_requests": settings.max_requests,
        });
        return EngineResult::ok(
            vec![json!({
                "type": ENGINE_ID,
                "category": "dry_run",
                "title": "Serverless security scan plan (dry run)",
                "severity": "info",
                "description": "Dry run — no probes executed. Review planned surface.",
                "evidence": plan,
            })],
            format!("serverless_attack: dry-run plan for {}", target.trim()),
        );
    }

    let base = normalize_url(target);
    let host = crate::engine_probes::extract_host(&base);
    let cfg = ArsenalConfig::from_ctx(ctx);
    let ua = cfg.string("user_agent");
    let client = build_client(settings.timeout_ms, ua.as_deref()).await;

    let mut posture = Posture::default();
    let mut findings: Vec<Value> = Vec::new();

    probe_fingerprint(&client, &base, &host, &settings, &mut posture, &mut findings).await;
    probe_function_paths(&client, &base, &host, &settings, &mut posture, &mut findings).await;
    probe_config_exposure(&client, &base, &host, &settings, &mut posture, &mut findings).await;
    probe_env_leak(&client, &base, &host, &settings, &mut posture, &mut findings).await;
    probe_cors(&client, &base, &host, &settings, &mut posture, &mut findings).await;
    probe_event_injection(&client, &base, &host, &settings, &mut posture, &mut findings).await;
    probe_cold_start(&client, &base, &host, &settings, &mut posture, &mut findings).await;
    probe_admin_surface(&client, &base, &host, &settings, &mut posture, &mut findings).await;

    if settings.attack_synth {
        for ap in attack_paths(&posture, &host) {
            push_if_severe(&mut findings, &settings, ap);
        }
    }

    emit_posture_summary(&posture, &host, &settings, &mut findings);

    let n = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) != Some("serverless_metrics"))
        .count();

    EngineResult::ok(
        findings,
        format!(
            "serverless_attack: {} finding(s) on {} (posture {:.0}/100)",
            n,
            host,
            posture.exposure_score() * 100.0
        ),
    )
}

pub async fn run_serverless_attack(target: &str) {
    print_result(run_serverless_attack_result_ctx(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_dispatch::EngineRunContext;
    use serde_json::json;

    fn ctx(params: Value) -> EngineRunContext {
        EngineRunContext {
            job_params: params,
            ..Default::default()
        }
    }

    #[test]
    fn settings_defaults_are_sensible() {
        let s = parse_settings(&ctx(json!({})));
        assert!(s.probe_fingerprint);
        assert!(s.probe_functions);
        assert!(!s.function_paths.is_empty());
        assert_eq!(s.cold_start_samples, 3);
    }

    #[test]
    fn platform_detection_from_headers() {
        let probe = HttpProbe {
            status: 200,
            headers: vec![("x-amzn-requestid".into(), "abc".into())],
            body: String::new(),
            final_url: "https://x.test".into(),
        };
        let hits = detect_platforms(&probe);
        assert!(hits.iter().any(|(id, _)| *id == "aws_lambda"));
    }

    #[test]
    fn posture_score_weights_env_leak_highest() {
        let mut p = Posture::default();
        assert!(p.exposure_score() < 0.1);
        p.env_leak = true;
        assert!(p.exposure_score() >= 0.3);
    }

    #[test]
    fn attack_paths_need_real_signals() {
        assert!(attack_paths(&Posture::default(), "x.test").is_empty());
        let mut p = Posture::default();
        p.env_leak = true;
        p.functions_exposed = 1;
        assert!(!attack_paths(&p, "x.test").is_empty());
    }

    #[test]
    fn env_key_detection() {
        let keys = body_has_env_keys(r#"{"DATABASE_URL":"postgres://..."}"#);
        assert!(keys.contains(&"DATABASE_URL"));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_serverless_attack_result_ctx("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }

    #[tokio::test]
    async fn dry_run_returns_plan() {
        let r = run_serverless_attack_result_ctx(
            "https://example.com",
            &ctx(json!({"dry_run": true})),
        )
        .await;
        assert!(r.success);
        assert!(r.findings.iter().any(|f| f.get("category") == Some(&json!("dry_run"))));
    }
}
