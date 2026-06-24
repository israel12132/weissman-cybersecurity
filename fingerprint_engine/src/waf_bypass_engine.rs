//! WAF detection & bypass-surface characterization — vendor fingerprint + transform oracle.
//!
//! Live, read-only HTTP probes characterize how a target's edge WAF/CDN responds to harmless
//! attack-shaped payloads and whether encoding / header / path / verb transforms slip past
//! inspection. Every knob flows from `EngineRunContext::job_params` via [`ArsenalConfig`].
//!
//! MITRE: T1190 (Exploit Public-Facing Application), T1027 (Obfuscated Files or Information).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, http_client, http_get_with_headers, normalize_url, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::collections::HashMap;

const ENGINE_ID: &str = "waf_bypass";
const MITRE: &str = "T1027";
const PROBE_PARAM: &str = "wzx";

#[derive(Clone, Debug)]
struct WafScanConfig {
    intensity: Intensity,
    timeout_ms: u64,
    technique: String,
    check_fingerprint: bool,
    check_query_probes: bool,
    check_encoding: bool,
    check_header_injection: bool,
    check_path_normalization: bool,
    check_verb_tampering: bool,
    check_json_smuggling: bool,
    emit_score: bool,
    extra_payloads: Vec<String>,
}

impl Default for WafScanConfig {
    fn default() -> Self {
        Self {
            intensity: Intensity::Normal,
            timeout_ms: 8000,
            technique: "all".to_string(),
            check_fingerprint: true,
            check_query_probes: true,
            check_encoding: true,
            check_header_injection: true,
            check_path_normalization: true,
            check_verb_tampering: true,
            check_json_smuggling: true,
            emit_score: true,
            extra_payloads: Vec::new(),
        }
    }
}

impl WafScanConfig {
    fn from_ctx(ctx: &EngineRunContext) -> Self {
        let cfg = ArsenalConfig::from_ctx(ctx);
        let mut d = Self::default();
        d.intensity = cfg.intensity();
        d.timeout_ms = cfg.u64_or("timeout_ms", 8000).clamp(500, 30_000);
        d.technique = cfg.string_or("technique", "all");
        d.check_fingerprint = cfg.bool_or("check_fingerprint", true);
        d.check_query_probes = cfg.bool_or("check_query_probes", true);
        d.check_encoding = cfg.bool_or("check_encoding", true) && technique_allows(&d.technique, "encoding");
        d.check_header_injection = cfg.bool_or("check_header_injection", true)
            && technique_allows(&d.technique, "header_injection");
        d.check_path_normalization = cfg.bool_or("check_path_normalization", true)
            && technique_allows(&d.technique, "path_normalization");
        d.check_verb_tampering = cfg.bool_or("check_verb_tampering", true)
            && technique_allows(&d.technique, "verb_tampering");
        d.check_json_smuggling = cfg.bool_or("check_json_smuggling", true)
            && technique_allows(&d.technique, "json_smuggling");
        d.emit_score = cfg.bool_or("emit_score", true);
        d.extra_payloads = cfg
            .string_list("extra_payloads")
            .into_iter()
            .filter(|s| !s.trim().is_empty())
            .collect();
        if d.technique == "fragmentation" {
            d.check_encoding = false;
            d.check_header_injection = false;
        }
        if d.technique == "case_variation" || d.technique == "comments" {
            d.check_encoding = technique_allows(&d.technique, "encoding");
        }
        d
    }

    fn probe_budget(&self) -> usize {
        match self.intensity {
            Intensity::Light => 6,
            Intensity::Normal => 12,
            Intensity::Aggressive => 24,
        }
    }
}

fn technique_allows(selected: &str, kind: &str) -> bool {
    if selected == "all" {
        return true;
    }
    matches!(
        (selected, kind),
        ("encoding", "encoding")
            | ("fragmentation", "path_normalization")
            | ("case_variation", "encoding")
            | ("comments", "encoding")
            | ("header_injection", "header_injection")
            | ("path_normalization", "path_normalization")
            | ("verb_tampering", "verb_tampering")
            | ("json_smuggling", "json_smuggling")
    )
}

fn header_map(headers: &[(String, String)]) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect()
}

fn geth<'a>(hm: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    hm.get(&key.to_ascii_lowercase()).map(|s| s.as_str())
}

/// Fingerprint WAF/CDN vendor from response headers + body signatures.
fn fingerprint_waf(headers: &[(String, String)], body: &str) -> Option<(&'static str, String)> {
    let hm = header_map(headers);
    let body_lc = body.to_ascii_lowercase();

    if geth(&hm, "cf-ray").is_some()
        || geth(&hm, "cf-mitigated").is_some()
        || geth(&hm, "cf-cache-status").is_some()
        || body_lc.contains("cloudflare")
        || body_lc.contains("attention required")
    {
        let ev = geth(&hm, "cf-ray")
            .or(geth(&hm, "cf-mitigated"))
            .unwrap_or("cloudflare-body");
        return Some(("Cloudflare", ev.to_string()));
    }
    if geth(&hm, "x-akamai-transformed").is_some()
        || geth(&hm, "akamaighost").is_some()
        || body_lc.contains("akamai")
        || body_lc.contains("reference #")
    {
        return Some(("Akamai", "akamai-headers".to_string()));
    }
    if geth(&hm, "x-amzn-requestid").is_some()
        || geth(&hm, "x-amz-cf-id").is_some()
        || body_lc.contains("request blocked")
        || body_lc.contains("aws waf")
    {
        return Some(("AWS WAF / CloudFront", "aws-headers".to_string()));
    }
    if geth(&hm, "x-iinfo").is_some()
        || geth(&hm, "x-cdn").map(|v| v.contains("incapsula")).unwrap_or(false)
        || hm.keys().any(|k| k.starts_with("x-cdn"))
        || body_lc.contains("incapsula")
        || body_lc.contains("_incapsula_")
    {
        return Some(("Imperva / Incapsula", "incapsula-headers".to_string()));
    }
    for (k, v) in &hm {
        if k.contains("incap_ses") || k.contains("visid_incap") {
            return Some(("Imperva / Incapsula", format!("{}={}", k, v)));
        }
        if k.starts_with("ts") && v.len() > 8 {
            return Some(("F5 BIG-IP ASM", format!("{} cookie", k)));
        }
    }
    if body_lc.contains("the requested url was rejected")
        || body_lc.contains("bigip")
        || body_lc.contains("f5")
    {
        return Some(("F5 BIG-IP ASM", "f5-body".to_string()));
    }
    if geth(&hm, "x-sucuri-id").is_some() || geth(&hm, "x-sucuri-cache").is_some() {
        return Some(("Sucuri", "sucuri-headers".to_string()));
    }
    if body_lc.contains("mod_security") || body_lc.contains("modsecurity") || body_lc.contains("noyb")
    {
        return Some(("ModSecurity", "modsecurity-body".to_string()));
    }
    if geth(&hm, "x-fastly-request-id").is_some() || geth(&hm, "x-served-by").is_some() {
        return Some(("Fastly", "fastly-headers".to_string()));
    }
    if geth(&hm, "x-fw-server").is_some() || geth(&hm, "x-fw-protect").is_some() {
        return Some(("FortiWeb / Fortinet", "fortiweb-headers".to_string()));
    }
    if geth(&hm, "x-rdwr").is_some() || body_lc.contains("radware") {
        return Some(("Radware", "radware-headers".to_string()));
    }
    if geth(&hm, "x-datadome").is_some() || body_lc.contains("datadome") {
        return Some(("DataDome", "datadome-headers".to_string()));
    }
    if geth(&hm, "x-px-blocked").is_some() || body_lc.contains("perimeterx") {
        return Some(("PerimeterX", "perimeterx-headers".to_string()));
    }
    if geth(&hm, "x-citrix-gateway").is_some() || body_lc.contains("citrix") {
        return Some(("Citrix NetScaler", "citrix-headers".to_string()));
    }
    if geth(&hm, "x-reblaze-transaction").is_some() {
        return Some(("Reblaze", "reblaze-headers".to_string()));
    }
    if geth(&hm, "x-wallarm").is_some() {
        return Some(("Wallarm", "wallarm-headers".to_string()));
    }
    if geth(&hm, "server").map(|s| s.contains("barracuda")).unwrap_or(false) {
        return Some(("Barracuda WAF", "barracuda-server".to_string()));
    }
    None
}

fn is_waf_block(status: u16, body: &str, baseline_len: usize) -> bool {
    if matches!(status, 403 | 406 | 429 | 501 | 503) {
        return true;
    }
    let body_lc = body.to_ascii_lowercase();
    if body_lc.contains("blocked")
        || body_lc.contains("forbidden")
        || body_lc.contains("access denied")
        || body_lc.contains("request rejected")
        || body_lc.contains("not acceptable")
        || body_lc.contains("security violation")
        || body_lc.contains("captcha")
        || body_lc.contains("challenge-platform")
        || body_lc.contains("attention required")
    {
        return true;
    }
    baseline_len > 0 && body.len() > baseline_len.saturating_mul(3) && body.len() > 4096
}

fn is_waf_pass(status: u16, blocked: bool) -> bool {
    !blocked && matches!(status, 200 | 201 | 204 | 301 | 302 | 304 | 307 | 308)
}

fn build_probe_url(base: &str, payload: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    format!(
        "{}{}{}={}",
        base.trim_end_matches('/'),
        sep,
        PROBE_PARAM,
        urlencoding::encode(payload)
    )
}

/// Harmless XSS/SQLi/RCE probes for WAF characterization only.
const RAW_PROBES: &[(&str, &str)] = &[
    ("<script>alert(1)</script>", "raw-xss"),
    ("' OR '1'='1", "sqli-quote"),
    ("UNION SELECT NULL--", "sqli-union"),
    ("../../../etc/passwd", "path-traversal"),
    (";cat /etc/passwd", "cmd-injection"),
    ("${7*7}", "ssti-el"),
    ("{{7*7}}", "ssti-jinja"),
];

fn transform_variants(raw: &str, technique: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if technique == "all" || technique == "encoding" || technique == "case_variation" || technique == "comments" {
        if technique != "comments" {
            out.push(("case-mixed", mixed_case(raw)));
        }
        let enc: String = urlencoding::encode(raw).into();
        out.push(("url-encoded", enc));
        let double: String = urlencoding::encode(&urlencoding::encode(raw).to_string()).into();
        out.push(("double-url-encoded", double));
        if technique == "all" || technique == "comments" {
            out.push(("tab-split", raw.replace(' ', "\t")));
            out.push(("comment-split", raw.replace(' ', "/**/")));
        }
        if raw.contains('<') {
            out.push(("unicode-lt", raw.replace('<', "%u003c")));
            out.push(("html-entity-lt", raw.replace('<', "%3C")));
        }
        if raw.contains('\'') {
            out.push(("unicode-quote", raw.replace('\'', "%u0027")));
        }
    }
    if technique == "all" || technique == "fragmentation" {
        if raw.len() > 4 {
            let mid = raw.len() / 2;
            out.push(("fragment-split", format!("{}\r\n{}", &raw[..mid], &raw[mid..])));
        }
    }
    out
}

fn mixed_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

struct WafMetrics {
    probes_sent: u32,
    blocks: u32,
    bypasses: u32,
    vendor: Option<String>,
}

impl WafMetrics {
    fn hardening_score(&self) -> u8 {
        if self.probes_sent == 0 {
            return 50;
        }
        let block_rate = self.blocks as f64 / self.probes_sent as f64;
        let bypass_penalty = (self.bypasses as f64 * 18.0).min(60.0);
        let vendor_bonus = if self.vendor.is_some() { 12.0 } else { 0.0 };
        ((block_rate * 70.0 + vendor_bonus - bypass_penalty).clamp(0.0, 100.0)) as u8
    }
}

async fn http_get_probe(client: &reqwest::Client, url: &str) -> Option<HttpProbe> {
    http_get_with_headers(client, url, &[]).await
}

async fn run_waf_scan(target: &str, cfg: WafScanConfig) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    let mut metrics = WafMetrics {
        probes_sent: 0,
        blocks: 0,
        bypasses: 0,
        vendor: None,
    };

    let baseline = match http_get_probe(&client, &base).await {
        Some(p) => p,
        None => return EngineResult::error("target unreachable"),
    };
    let baseline_len = baseline.body.len();

    if cfg.check_fingerprint {
        if let Some((vendor, evidence)) = fingerprint_waf(&baseline.headers, &baseline.body) {
            metrics.vendor = Some(vendor.to_string());
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("WAF/CDN detected: {vendor}"),
                "info",
                MITRE,
                &format!(
                    "Baseline response from {} identifies {vendor} (evidence: {evidence}). Active edge inspection changes exploitability of downstream vulnerabilities.",
                    base
                ),
                target,
                0.92,
                Evidence::new()
                    .with("vendor", vendor)
                    .with("evidence", evidence)
                    .with("baseline_status", baseline.status)
                    .check("waf_present", true, vendor),
            ));
        } else {
            findings.push(finding_rich(
                ENGINE_ID,
                "No WAF/CDN vendor fingerprint on baseline",
                "info",
                MITRE,
                &format!(
                    "Baseline GET to {base} did not match known WAF/CDN header/body signatures — edge may be transparent or use a custom ruleset."
                ),
                target,
                0.65,
                Evidence::new().check("waf_present", false, "none"),
            ));
        }
    }

    let mut probe_list: Vec<(String, String)> = RAW_PROBES
        .iter()
        .map(|(p, k)| (p.to_string(), k.to_string()))
        .collect();
    for (i, extra) in cfg.extra_payloads.iter().enumerate().take(8) {
        probe_list.push((extra.clone(), format!("custom-{i}")));
    }
    let budget = cfg.probe_budget().min(probe_list.len());

    if cfg.check_query_probes {
        for (raw_payload, probe_kind) in probe_list.iter().take(budget) {
            let probe_url = build_probe_url(&base, raw_payload);
            let Some(probe) = http_get_probe(&client, &probe_url).await else {
                continue;
            };
            metrics.probes_sent += 1;
            let blocked = is_waf_block(probe.status, &probe.body, baseline_len);
            if blocked {
                metrics.blocks += 1;
            }

            if blocked {
                if let Some((vendor, _)) = fingerprint_waf(&probe.headers, &probe.body) {
                    findings.push(finding_rich(
                        ENGINE_ID,
                        &format!("WAF blocked {probe_kind} probe ({vendor})"),
                        "low",
                        MITRE,
                        &format!(
                            "Harmless {probe_kind} payload blocked (HTTP {}) by {vendor} — confirms active inspection.",
                            probe.status
                        ),
                        target,
                        0.88,
                        Evidence::new()
                            .with("probe", probe_kind.as_str())
                            .with("vendor", vendor)
                            .with("status", probe.status),
                    ));
                }

                if cfg.check_encoding {
                    for (transform, variant) in transform_variants(raw_payload, &cfg.technique) {
                        let variant_url = build_probe_url(&base, &variant);
                        if let Some(v) = http_get_probe(&client, &variant_url).await {
                            metrics.probes_sent += 1;
                            let v_blocked = is_waf_block(v.status, &v.body, baseline_len);
                            if v_blocked {
                                metrics.blocks += 1;
                            } else if is_waf_pass(v.status, v_blocked) {
                                metrics.bypasses += 1;
                                findings.push(finding_rich(
                                    ENGINE_ID,
                                    &format!("WAF bypass surface: {transform} passes {probe_kind}"),
                                    "high",
                                    MITRE,
                                    &format!(
                                        "Blocked {probe_kind} payload accepted after {transform} transform (HTTP {}). Live evasion surface — not an exploit chain.",
                                        v.status
                                    ),
                                    target,
                                    0.91,
                                    Evidence::new()
                                        .with("probe", probe_kind.as_str())
                                        .with("transform", transform)
                                        .with("blocked_status", probe.status)
                                        .with("passed_status", v.status)
                                        .with(
                                            "variant_excerpt",
                                            variant.chars().take(120).collect::<String>(),
                                        ),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    if cfg.check_header_injection {
        let xss = "<script>alert(1)</script>";
        let query_url = build_probe_url(&base, xss);
        if let Some(q) = http_get_probe(&client, &query_url).await {
            metrics.probes_sent += 1;
            if is_waf_block(q.status, &q.body, baseline_len) {
                metrics.blocks += 1;
                for (hdr, label) in [
                    ("X-Forwarded-For", "X-Forwarded-For"),
                    ("X-Original-URL", "X-Original-URL"),
                    ("X-Rewrite-URL", "X-Rewrite-URL"),
                    ("X-Custom-IP-Authorization", "X-Custom-IP-Authorization"),
                    ("Referer", "Referer"),
                ] {
                    if let Some(h) =
                        http_get_with_headers(&client, &base, &[(hdr, xss)]).await
                    {
                        metrics.probes_sent += 1;
                        let h_blocked = is_waf_block(h.status, &h.body, baseline_len);
                        if h_blocked {
                            metrics.blocks += 1;
                        } else if is_waf_pass(h.status, h_blocked) {
                            metrics.bypasses += 1;
                            findings.push(finding_rich(
                                ENGINE_ID,
                                &format!("WAF bypass: {label} header passes where query blocked"),
                                "high",
                                MITRE,
                                &format!(
                                    "XSS probe blocked in query (HTTP {}) but accepted via {label} header (HTTP {}). Location-based WAF bypass surface.",
                                    q.status, h.status
                                ),
                                target,
                                0.9,
                                Evidence::new()
                                    .with("vector", label)
                                    .with("query_status", q.status)
                                    .with("header_status", h.status),
                            ));
                        }
                    }
                }
            }
        }
    }

    if cfg.check_path_normalization {
        let paths = [
            ("/%2e%2e/%2e%2e/etc/passwd", "double-dot-encoded"),
            ("/..%252f..%252fetc/passwd", "double-url-dot"),
            ("/.%2e/./.%2e/etc/passwd", "dot-segment-mix"),
            ("/static/..%2f..%2fetc/passwd", "static-prefix-escape"),
        ];
        for (path, label) in paths {
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            if let Some(p) = http_get_probe(&client, &url).await {
                metrics.probes_sent += 1;
                let blocked = is_waf_block(p.status, &p.body, baseline_len);
                if blocked {
                    metrics.blocks += 1;
                } else if is_waf_pass(p.status, blocked)
                    && p.body.len().saturating_sub(baseline_len) > 32
                {
                    metrics.bypasses += 1;
                    findings.push(finding_rich(
                        ENGINE_ID,
                        &format!("Path normalization bypass surface: {label}"),
                        "medium",
                        MITRE,
                        &format!(
                            "Traversal-shaped path {path} returned HTTP {} with body delta vs baseline — WAF may not normalize path before inspection.",
                            p.status
                        ),
                        target,
                        0.82,
                        Evidence::new()
                            .with("path", path)
                            .with("label", label)
                            .with("status", p.status),
                    ));
                }
            }
        }
    }

    if cfg.check_verb_tampering {
        let sqli = "' OR '1'='1";
        let get_url = build_probe_url(&base, sqli);
        if let Some(g) = http_get_probe(&client, &get_url).await {
            metrics.probes_sent += 1;
            if is_waf_block(g.status, &g.body, baseline_len) {
                metrics.blocks += 1;
                let post_url = base.clone();
                let body = format!("{PROBE_PARAM}={}", urlencoding::encode(sqli));
                if let Ok(resp) = client
                    .post(&post_url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .await
                {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    metrics.probes_sent += 1;
                    let blocked = is_waf_block(status, &text, baseline_len);
                    if blocked {
                        metrics.blocks += 1;
                    } else if is_waf_pass(status, blocked) {
                        metrics.bypasses += 1;
                        findings.push(finding_rich(
                            ENGINE_ID,
                            "WAF bypass: POST body passes where GET query blocked",
                            "high",
                            MITRE,
                            &format!(
                                "SQLi-shaped probe blocked on GET (HTTP {}) but accepted on POST form body (HTTP {}) — verb-specific rule gap.",
                                g.status, status
                            ),
                            target,
                            0.89,
                            Evidence::new()
                                .with("get_status", g.status)
                                .with("post_status", status),
                        ));
                    }
                }
            }
        }
    }

    if cfg.check_json_smuggling {
        let payload = r#"{"q":"<script>alert(1)</script>"}"#;
        if let Ok(resp) = client
            .post(&base)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            metrics.probes_sent += 1;
            let blocked = is_waf_block(status, &text, baseline_len);
            if blocked {
                metrics.blocks += 1;
                findings.push(finding_rich(
                    ENGINE_ID,
                    "WAF blocks JSON XSS probe",
                    "info",
                    MITRE,
                    "POST application/json with script tag blocked — JSON body inspection active.",
                    target,
                    0.8,
                    Evidence::new().with("status", status),
                ));
            } else if is_waf_pass(status, blocked) {
                metrics.bypasses += 1;
                findings.push(finding_rich(
                    ENGINE_ID,
                    "WAF JSON inspection gap: script tag in JSON body accepted",
                    "high",
                    MITRE,
                    &format!(
                        "POST application/json with XSS-shaped field returned HTTP {} — WAF may not inspect JSON bodies.",
                        status
                    ),
                    target,
                    0.87,
                    Evidence::new().with("status", status).with("content_type", "application/json"),
                ));
            }
        }
    }

    if cfg.emit_score {
        let score = metrics.hardening_score();
        let sev = if score >= 75 {
            "info"
        } else if score >= 50 {
            "medium"
        } else {
            "high"
        };
        findings.insert(
            0,
            finding_rich(
                ENGINE_ID,
                &format!("WAF hardening score: {score}/100"),
                sev,
                MITRE,
                &format!(
                    "Composite edge WAF posture: {score}/100 (higher = stronger blocking). \
                     {}/{} probes blocked, {} bypass surface(s) observed{}.",
                    metrics.blocks,
                    metrics.probes_sent,
                    metrics.bypasses,
                    metrics
                        .vendor
                        .as_ref()
                        .map(|v| format!(", vendor: {v}"))
                        .unwrap_or_default()
                ),
                target,
                0.95,
                Evidence::new()
                    .with("waf_hardening_score", score)
                    .with("probes_sent", metrics.probes_sent)
                    .with("blocks", metrics.blocks)
                    .with("bypass_surfaces", metrics.bypasses)
                    .with("vendor", metrics.vendor.clone().unwrap_or_else(|| "unknown".into()))
                    .check("bypass_free", metrics.bypasses == 0, metrics.bypasses),
            ),
        );
    }

    if findings.is_empty() {
        empty_ok(ENGINE_ID, target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!(
                "waf_bypass: {} live finding(s), hardening {}/100",
                findings.len(),
                metrics.hardening_score()
            ),
        )
    }
}

pub async fn run_waf_bypass_result(target: &str) -> EngineResult {
    run_waf_scan(target, WafScanConfig::default()).await
}

pub async fn run_waf_bypass_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    run_waf_scan(target, WafScanConfig::from_ctx(ctx)).await
}

pub async fn run_waf_bypass(target: &str) {
    print_result(run_waf_bypass_result(target).await);
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
    fn fingerprint_cloudflare() {
        let h = vec![("cf-ray".to_string(), "abc-TLV".to_string())];
        let (vendor, _) = fingerprint_waf(&h, "").unwrap();
        assert_eq!(vendor, "Cloudflare");
    }

    #[test]
    fn block_detects_403() {
        assert!(is_waf_block(403, "Forbidden", 100));
    }

    #[test]
    fn pass_detects_200() {
        assert!(is_waf_pass(200, false));
        assert!(!is_waf_pass(403, true));
    }

    #[test]
    fn transforms_generate_variants() {
        let v = transform_variants("<script>", "all");
        assert!(v.iter().any(|(n, _)| *n == "url-encoded"));
        assert!(v.iter().any(|(n, _)| *n == "case-mixed"));
    }

    #[test]
    fn config_reads_technique() {
        let cfg = WafScanConfig::from_ctx(&ctx(json!({ "technique": "encoding", "check_header_injection": true })));
        assert!(cfg.check_encoding);
        assert!(!cfg.check_header_injection);
    }

    #[test]
    fn hardening_score_penalizes_bypasses() {
        let m = WafMetrics {
            probes_sent: 10,
            blocks: 8,
            bypasses: 2,
            vendor: Some("Cloudflare".into()),
        };
        assert!(m.hardening_score() < 80);
    }
}
