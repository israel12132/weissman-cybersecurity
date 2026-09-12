//! **Adversary Path Prover** — fused live recon + control-gap + STRIPS chain.
//!
//! Combines three evidence domains that other engines keep separate:
//! 1. Live HTTP/TCP perimeter observations (login, admin, GraphQL, SCM, lateral ports)
//! 2. Control-gap differentials (benign UA vs scanner/APT UA on the same path; WAF present
//!    but a sensitive path still returns 200)
//! 3. The existing STRIPS planner seeded **only** from those observations
//!
//! Privilege / impact facts are never invented. If the planner cannot reach
//! `impact:objective` from observed facts, no chain finding is emitted.

use crate::attack_chain_planner;
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    DEFAULT_PROBE_CONCURRENCY, empty_ok, extract_host, finding_with_probe_depth, fingerprint_stack,
    http_client, http_get, http_get_with_headers, join_url, normalize_url, probe_paths_concurrent,
    status_indicates_presence, tcp_scan,
};
use crate::engine_result::{EngineResult, print_result};
use serde_json::{Value, json};

pub const ENGINE_ID: &str = "adversary_path_prover";
const DEPTH: &str = "adversary_path_prover_live";
const MITRE_RECON: &str = "T1595";
const MITRE_EXPLOIT: &str = "T1190";
const MITRE_EVASION: &str = "T1562";
const BENIGN_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";
const SCANNER_UA: &str = "python-requests/2.31.0";

const SURFACE_PATHS_LIGHT: &[&str] = &["/login", "/admin", "/graphql", "/.git/HEAD", "/.env"];

const SURFACE_PATHS: &[&str] = &[
    "/login",
    "/admin",
    "/wp-login.php",
    "/graphql",
    "/.git/HEAD",
    "/actuator/health",
    "/api",
    "/upload",
    "/debug",
    "/.env",
];

const SURFACE_PATHS_AGGRESSIVE: &[&str] = &[
    "/login",
    "/admin",
    "/wp-login.php",
    "/graphql",
    "/.git/HEAD",
    "/actuator/health",
    "/api",
    "/upload",
    "/debug",
    "/.env",
    "/phpmyadmin",
    "/remote/login",
    "/console",
    "/manager/html",
];

/// Admin/lateral ports only — 80/443 are already covered by HTTP probes (T1190/T1595).
const LATERAL_PORTS: &[u16] = &[22, 445, 3389, 5985];

struct ProverSettings {
    intensity: String,
    stealth: String,
    max_findings: usize,
    evidence_mode: String,
    campaign: String,
}

fn jp_str(p: &Value, key: &str) -> Option<String> {
    p.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_settings(ctx: &EngineRunContext) -> ProverSettings {
    let p = &ctx.job_params;
    let nested = p.get("options");
    let src = nested.filter(|v| v.is_object()).unwrap_or(p);
    let intensity = jp_str(src, "intensity").unwrap_or_else(|| "normal".into());
    let stealth = jp_str(src, "stealth_mode").unwrap_or_else(|| "low".into());
    let max_findings = src
        .get("max_findings")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(200)
        .clamp(1, 5000) as usize;
    let evidence_mode = jp_str(src, "evidence_mode").unwrap_or_else(|| "standard".into());
    let campaign = jp_str(src, "campaign_name").unwrap_or_default();
    ProverSettings {
        intensity,
        stealth,
        max_findings,
        evidence_mode,
        campaign,
    }
}

fn surface_paths(intensity: &str) -> &'static [&'static str] {
    match intensity {
        "light" => SURFACE_PATHS_LIGHT,
        "aggressive" => SURFACE_PATHS_AGGRESSIVE,
        _ => SURFACE_PATHS,
    }
}

fn emit(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    campaign: &str,
) -> Value {
    let mut f = finding_with_probe_depth(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        DEPTH,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("engine".to_string(), json!(ENGINE_ID));
        obj.insert("probe_fidelity".to_string(), json!("live_http_tcp"));
        if !campaign.is_empty() {
            obj.insert("campaign_name".to_string(), json!(campaign));
        }
    }
    f
}

fn waf_tokens(blob: &str) -> Vec<&'static str> {
    let lower = blob.to_ascii_lowercase();
    [
        "cloudflare",
        "akamai",
        "imperva",
        "sucuri",
        "mod_security",
        "modsecurity",
        "aws-waf",
        "x-cdn",
        "cf-ray",
        "x-sucuri",
        "x-iinfo",
        "x-akamai",
    ]
    .into_iter()
    .filter(|t| lower.contains(t))
    .collect()
}

pub async fn run_adversary_path_prover_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let settings = parse_settings(ctx);
    let host = extract_host(target);
    let base = normalize_url(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let paths = surface_paths(&settings.intensity);
    let strict = settings.evidence_mode == "strict";
    let skip_scanner_ua = settings.stealth == "high";

    // ── 1. Live perimeter HTTP ──────────────────────────────────────────────
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    let mut open_sensitive: Vec<(String, u16)> = Vec::new();
    for p in &probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let sensitive = p.final_url.contains("/admin")
            || p.final_url.contains(".git")
            || p.final_url.contains("wp-login")
            || p.final_url.contains("graphql")
            || p.final_url.contains("actuator")
            || p.final_url.contains("/.env")
            || p.final_url.contains("/debug")
            || p.final_url.contains("/upload");
        let sev = if p.status == 200 && sensitive && !strict {
            "high"
        } else if p.status == 200 && sensitive {
            "medium"
        } else if p.status == 200 && !strict {
            "medium"
        } else {
            "info"
        };
        open_sensitive.push((p.final_url.clone(), p.status));
        findings.push(emit(
            &format!("Observed entry point {} ({})", p.final_url, p.status),
            sev,
            MITRE_EXPLOIT,
            &format!(
                "Live GET {} returned HTTP {} — evidence-only delivery surface, not an exploit.",
                p.final_url, p.status
            ),
            target,
            &settings.campaign,
        ));
    }

    if let Some(root) = http_get(&client, &base).await {
        let fp = fingerprint_stack(&root);
        let blob = format!(
            "{:?} {} {}",
            fp.server,
            fp.powered_by.as_deref().unwrap_or(""),
            root.headers
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let waf = waf_tokens(&blob);
        if !waf.is_empty() {
            findings.push(emit(
                &format!("Perimeter WAF/CDN observed: {}", waf.join(", ")),
                "info",
                MITRE_EVASION,
                &format!(
                    "{} advertised {} — control-gap hunter compares this control to origin-path status.",
                    root.final_url,
                    waf.join(", ")
                ),
                target,
                &settings.campaign,
            ));
        }
        if let Some(server) = fp.server.as_deref() {
            findings.push(emit(
                &format!("HTTP stack fingerprint: {server}"),
                "info",
                MITRE_RECON,
                &format!(
                    "Server header on {} is {} (X-Powered-By={}).",
                    root.final_url,
                    server,
                    fp.powered_by.as_deref().unwrap_or("—")
                ),
                target,
                &settings.campaign,
            ));
        }
        // Control gap: WAF present AND a sensitive path still 200.
        if !waf.is_empty() {
            for (url, status) in &open_sensitive {
                if *status == 200
                    && (url.contains("/admin")
                        || url.contains(".git")
                        || url.contains("wp-login")
                        || url.contains("/.env"))
                {
                    findings.push(emit(
                        &format!("Control gap: WAF present but {url} still HTTP 200"),
                        "high",
                        MITRE_EVASION,
                        &format!(
                            "Perimeter tokens {:?} on {} but live GET {} returned 200 — WAF did not block a sensitive path.",
                            waf, base, url
                        ),
                        target,
                        &settings.campaign,
                    ));
                    break;
                }
            }
        }
    }

    // ── 2. UA differential (benign vs scanner) ───────────────────────────────
    if !skip_scanner_ua {
        for path in ["/login", "/admin", "/wp-login.php", "/remote/login"] {
            let url = join_url(&base, path);
            let benign = http_get_with_headers(&client, &url, &[("User-Agent", BENIGN_UA)]).await;
            let scanner = http_get_with_headers(&client, &url, &[("User-Agent", SCANNER_UA)]).await;
            match (benign, scanner) {
                (Some(b), Some(s)) if b.status != s.status => {
                    let (sev, title) = if matches!(s.status, 403 | 406 | 429) && b.status == 200 {
                        (
                            "medium",
                            format!(
                                "Detection gap: scanner UA blocked ({}) but browser UA reached HTTP {}",
                                s.status, b.status
                            ),
                        )
                    } else if matches!(b.status, 403 | 406 | 429) && s.status == 200 {
                        (
                            "high",
                            format!(
                                "Inverted control: browser UA blocked ({}) but scanner UA reached HTTP {}",
                                b.status, s.status
                            ),
                        )
                    } else {
                        (
                            "info",
                            format!(
                                "UA differential on {path}: browser {} vs scanner {}",
                                b.status, s.status
                            ),
                        )
                    };
                    findings.push(emit(
                    &title,
                    sev,
                    MITRE_EVASION,
                    &format!(
                        "Same path {} returned HTTP {} for a browser UA and HTTP {} for {} — live control-gap, not a bypass exploit.",
                        url, b.status, s.status, SCANNER_UA
                    ),
                    target,
                    &settings.campaign,
                ));
                }
                _ => {}
            }
        }
    }

    // ── 3. Lateral TCP surface ─────────────────────────────────────────────
    let open = tcp_scan(&host, LATERAL_PORTS, 8).await;
    if !open.is_empty() {
        let sev = if open.iter().any(|p| matches!(p, 445 | 3389 | 5985)) {
            "high"
        } else {
            "medium"
        };
        findings.push(emit(
            &format!("Lateral/admin ports open: {open:?}"),
            sev,
            "T1021",
            &format!(
                "Host {host} accepts TCP {open:?} — observed adjacency for STRIPS (SMB/RDP/WinRM), not a lateral exploit."
            ),
            target,
            &settings.campaign,
        ));
    }

    // ── 4. STRIPS from observed facts only ───────────────────────────────────
    if let Some(chain_finding) =
        attack_chain_planner::strips_chain_finding(ENGINE_ID, target, &findings, "impact:objective")
    {
        findings.push(chain_finding);
    }

    if findings.len() > settings.max_findings {
        findings.truncate(settings.max_findings);
    }

    if findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    let count = findings.len();
    EngineResult::ok(
        findings,
        format!("{ENGINE_ID}: {count} live finding(s) on {host} (HTTP/TCP + control-gap + STRIPS)"),
    )
}

pub async fn run_adversary_path_prover(target: &str) {
    print_result(run_adversary_path_prover_result(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_id_is_stable() {
        assert_eq!(ENGINE_ID, "adversary_path_prover");
    }

    #[test]
    fn waf_tokens_detect_cloudflare_and_ignore_noise() {
        assert!(waf_tokens("cf-ray: abc\nserver: cloudflare").contains(&"cloudflare"));
        assert!(waf_tokens("hello world nginx").is_empty());
    }

    #[test]
    fn emit_carries_live_fidelity() {
        let f = emit("t", "high", "T1190", "d", "https://x.example", "q2");
        assert_eq!(f["type"], ENGINE_ID);
        assert_eq!(f["probe_depth"], DEPTH);
        assert_eq!(f["probe_fidelity"], "live_http_tcp");
        assert_eq!(f["engine"], ENGINE_ID);
        assert_eq!(f["campaign_name"], "q2");
    }

    #[test]
    fn empty_target_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let r = rt.block_on(run_adversary_path_prover_result(
            "",
            &EngineRunContext::default(),
        ));
        assert_eq!(r.status, "error");
    }

    #[test]
    fn lateral_ports_exclude_http_web_ports() {
        assert!(!LATERAL_PORTS.contains(&80));
        assert!(!LATERAL_PORTS.contains(&443));
        assert!(!LATERAL_PORTS.contains(&8080));
        assert!(LATERAL_PORTS.contains(&445));
        assert!(LATERAL_PORTS.contains(&3389));
    }

    #[test]
    fn parse_settings_reads_job_params_and_caps_findings() {
        let ctx = EngineRunContext {
            job_params: json!({
                "intensity": "light",
                "stealth_mode": "high",
                "max_findings": 3,
                "evidence_mode": "strict",
                "campaign_name": "RT-1"
            }),
            ..EngineRunContext::default()
        };
        let s = parse_settings(&ctx);
        assert_eq!(s.intensity, "light");
        assert_eq!(s.stealth, "high");
        assert_eq!(s.max_findings, 3);
        assert_eq!(s.evidence_mode, "strict");
        assert_eq!(s.campaign, "RT-1");
        assert_eq!(surface_paths("light").len() < SURFACE_PATHS.len(), true);
        let nested = EngineRunContext {
            job_params: json!({
                "options": {
                    "intensity": "aggressive",
                    "max_findings": 99999
                }
            }),
            ..EngineRunContext::default()
        };
        let s2 = parse_settings(&nested);
        assert_eq!(s2.intensity, "aggressive");
        assert_eq!(s2.max_findings, 5000);
    }
}
