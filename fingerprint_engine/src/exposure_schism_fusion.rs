//! **Exposure Schism Fusion** — why Weissman wins a PANW bake-off on one surface.
//!
//! Xpanse inventories; Prisma postures accounts; Cortex watches endpoints. None of
//! those SKUs diffs *first-seen* internet hosts and then proves HTTP/1.1↔HTTP/2 /
//! Vary / rewrite-header fractures on **only those FQDNs**, with kill-chain stages
//! mapped from **the same live HTTP evidence**.
//!
//! Live-only contract:
//! - First `first_mover_surface_delta` run stores a baseline — no invented schisms.
//! - Empty added/changed set (and no in-scope `extra_hosts`) → informational finding,
//!   never a filler score.
//! - `liminal_boundary` runs only against added, changed, or operator `extra_hosts`.
//! - Kill-chain stages are derived from observed `boundary_*` fractures. A second
//!   crawl (`kill_chain`) runs only when `deep_kill_chain=true`.
//! - Timeouts and follow-on errors emit `probe_timeout` / `probe_error` findings.
//!   They are never scored as “0 fractures”.
//! - Liminal path + rewrite budget is forced to `/` and `/api` (parent `paths` cannot
//!   leak the 6-path default). Origin is TCP/443 then TCP/80; closed ports are
//!   `probe_error`, not an empty fracture set.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding, http_client, http_get};
use crate::engine_result::EngineResult;
use crate::first_mover_surface_delta::{self, in_authorized_scope};
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;

pub const ENGINE_ID: &str = "exposure_schism_fusion";
const MITRE: &str = "T1190";
const MAX_HOSTS: usize = 4;
const LIMINAL_TIMEOUT: Duration = Duration::from_secs(50);
/// `kill_chain` does a base GET plus ~16 COMMON_PATHS plus robots.txt. 25s cannot
/// cover that on the process 10s client; 90s is the honest budget for the opt-in crawl.
const KILL_CHAIN_TIMEOUT: Duration = Duration::from_secs(90);
const HTTP_ALIVE_TIMEOUT: Duration = Duration::from_millis(6_000);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const HOST_CONCURRENCY: usize = 2;
const LIMINAL_PATH_CONCURRENCY: usize = 2;
const LIMINAL_PATHS: [&str; 2] = ["/", "/api"];
const LIMINAL_SENSITIVE_PATHS: [&str; 1] = ["/api"];

/// Categories actually emitted by `liminal_boundary_engine` (not the marketing names).
const SCHISM_CATEGORIES: &[&str] = &[
    "boundary_protocol_bypass",
    "boundary_method_schism",
    "boundary_cache_vary",
    "boundary_header_rewrite",
    "boundary_ip_trust",
    "boundary_entropy",
    "boundary_encoding",
];

const BLOCKED_SUFFIXES: &[&str] = &["metadata.google.internal", "localhost", "invalid", "onion"];

#[derive(Clone)]
struct ProbeTarget {
    fqdn: String,
    rank: u8,
}

struct HostOutcome {
    findings: Vec<Value>,
    timed_out: bool,
    errored: bool,
}

fn pbool(params: &Value, key: &str, default: bool) -> bool {
    params
        .get(key)
        .and_then(|v| {
            v.as_bool()
                .or_else(|| v.as_str().map(|s| s == "true" || s == "1"))
        })
        .unwrap_or(default)
}

fn is_reserved_probe_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return true;
    }
    for suf in BLOCKED_SUFFIXES {
        if h == *suf || h.ends_with(&format!(".{suf}")) {
            return true;
        }
    }
    let ip_s = h.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_s.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.is_private()
                    || v4.is_multicast()
                    || (o[0] == 169 && o[1] == 254)
                    || (o[0] == 100 && (64..=127).contains(&o[1]))
                    || o[0] >= 224
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || v6.is_unicast_link_local()
                    || v6.segments()[0] & 0xfe00 == 0xfc00
            }
        };
    }
    false
}

fn normalize_probe_host(raw: &str) -> Option<String> {
    let h = extract_host(raw)
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.is_empty() || h.contains('@') {
        return None;
    }
    if !h.contains('.') {
        return None;
    }
    if is_reserved_probe_host(&h) {
        return None;
    }
    Some(h)
}

fn rank_for_delta(category: &str, severity: &str) -> u8 {
    match (category, severity) {
        ("added", "critical") => 0,
        ("added", "high") => 1,
        ("changed", _) => 2,
        ("added", "medium") => 3,
        _ => 4,
    }
}

fn delta_candidates(findings: &[Value], apex: &str) -> Vec<ProbeTarget> {
    let mut out = Vec::new();
    for f in findings {
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        if cat != "added" && cat != "changed" {
            continue;
        }
        let raw = f
            .get("target")
            .or_else(|| f.get("value"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let Some(fqdn) = normalize_probe_host(raw) else {
            continue;
        };
        if !in_authorized_scope(apex, &fqdn) {
            continue;
        }
        if out.iter().any(|x: &ProbeTarget| x.fqdn == fqdn) {
            continue;
        }
        let sev = f
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_ascii_lowercase();
        out.push(ProbeTarget {
            rank: rank_for_delta(cat, &sev),
            fqdn,
        });
    }
    out
}

fn select_probe_hosts(findings: &[Value], params: &Value, apex: &str) -> Vec<ProbeTarget> {
    let mut hosts = delta_candidates(findings, apex);
    for raw in first_mover_surface_delta::extra_hosts_from_params(params) {
        let Some(fqdn) = normalize_probe_host(&raw) else {
            continue;
        };
        if !in_authorized_scope(apex, &fqdn) {
            continue;
        }
        if let Some(existing) = hosts.iter_mut().find(|h| h.fqdn == fqdn) {
            if existing.rank > 1 {
                existing.rank = 1;
            }
            continue;
        }
        hosts.push(ProbeTarget { fqdn, rank: 1 });
    }
    hosts.sort_by_key(|h| h.rank);
    hosts.truncate(MAX_HOSTS);
    hosts
}

pub(crate) fn is_schism_finding(f: &Value) -> bool {
    if f.get("summary") == Some(&json!(true)) {
        return false;
    }
    let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
    if cat == "posture_summary" || cat == "probe_timeout" || cat == "probe_error" {
        return false;
    }
    SCHISM_CATEGORIES
        .iter()
        .any(|c| cat.eq_ignore_ascii_case(c))
}

fn is_kill_chain_signal(f: &Value) -> bool {
    let phase = f
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if phase.is_empty() || phase == "reconnaissance" {
        return false;
    }
    let title = f.get("title").and_then(Value::as_str).unwrap_or("");
    if title.eq_ignore_ascii_case("target unreachable") {
        return false;
    }
    true
}

fn tag_parent(mut f: Value, host: &str, engine: &str) -> Value {
    if let Some(obj) = f.as_object_mut() {
        obj.insert("parent_fqdn".into(), json!(host));
        obj.insert("fusion".into(), json!(ENGINE_ID));
        obj.insert("fusion_engine".into(), json!(engine));
        obj.entry("asset")
            .or_insert_with(|| json!("exposure_schism"));
    }
    f
}

fn tagged_status(
    host: &str,
    category: &str,
    title: &str,
    description: &str,
    engine: &str,
) -> Value {
    let mut f = finding(ENGINE_ID, title, "info", MITRE, description, host);
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".into(), json!(category));
        if category == "probe_timeout" {
            obj.insert("timed_out".into(), json!(true));
        }
    }
    tag_parent(f, host, engine)
}

fn schism_summary_title(
    host_n: usize,
    schism_n: usize,
    chain_n: usize,
    timeout_n: usize,
    error_n: usize,
) -> String {
    if schism_n == 0 && (timeout_n > 0 || error_n > 0) {
        format!(
            "Exposure schism incomplete on {host_n} host(s) — {timeout_n} timed out, {error_n} probe error(s); not a clean bill"
        )
    } else if timeout_n > 0 || error_n > 0 {
        format!(
            "Exposure schism on {host_n} host(s) — {schism_n} boundary fracture(s), {chain_n} kill-chain stage(s); {timeout_n} timed out, {error_n} probe error(s)"
        )
    } else {
        format!(
            "Exposure schism on {host_n} host(s) — {schism_n} boundary fracture(s), {chain_n} kill-chain stage(s)"
        )
    }
}

fn outcome_flags(findings: &[Value]) -> (bool, bool) {
    let mut timed_out = false;
    let mut errored = false;
    for f in findings {
        match f.get("category").and_then(Value::as_str) {
            Some("probe_timeout") => timed_out = true,
            Some("probe_error") => errored = true,
            _ => {}
        }
    }
    (timed_out, errored)
}

/// `tcp_open` formats `{host}:{port}` which breaks IPv6 literals.
fn tcp_socket_addr(host: &str, port: u16) -> String {
    let h = host.trim().trim_matches(|c| c == '[' || c == ']');
    if h.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

async fn origin_port_open(host: &str, port: u16) -> bool {
    let addr = tcp_socket_addr(host, port);
    matches!(
        tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

async fn http_alive(url: &str) -> bool {
    let client = http_client().await;
    matches!(
        tokio::time::timeout(HTTP_ALIVE_TIMEOUT, http_get(&client, url)).await,
        Ok(Some(_))
    )
}

fn worst_severity(findings: &[Value]) -> &'static str {
    let mut rank = 0u8;
    for f in findings {
        let s = f
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_ascii_lowercase();
        let r = match s.as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        if r > rank {
            rank = r;
        }
    }
    match rank {
        4 => "critical",
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "info",
    }
}

fn kill_chain_from_schism(host: &str, schism: &Value) -> Option<Value> {
    let cat = schism.get("category").and_then(Value::as_str).unwrap_or("");
    let (phase, mitre, title) = match cat {
        "boundary_protocol_bypass" => (
            "Initial Access",
            "T1190",
            "HTTP/1.1↔HTTP/2 schism is a live initial-access fracture",
        ),
        "boundary_method_schism" => (
            "Initial Access",
            "T1190",
            "Method schism on a first-seen host is a live ACL gap",
        ),
        "boundary_cache_vary" => (
            "Collection",
            "T1530",
            "Cache Vary oracle on a first-seen host",
        ),
        "boundary_header_rewrite" => (
            "Defense Evasion",
            "T1078",
            "Rewrite-header trust bypass on a first-seen host",
        ),
        "boundary_ip_trust" => (
            "Initial Access",
            "T1190",
            "IP-trust header bypass on a first-seen host",
        ),
        "boundary_entropy" => (
            "Discovery",
            "T1046",
            "Protocol-stack entropy divergence on a first-seen host",
        ),
        "boundary_encoding" => (
            "Collection",
            "T1530",
            "Encoding schism without Vary on a first-seen host",
        ),
        _ => return None,
    };
    let proof = schism
        .get("description")
        .or_else(|| schism.get("title"))
        .and_then(Value::as_str)
        .unwrap_or(cat);
    let sev = schism
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("medium");
    let mut f = finding(
        ENGINE_ID,
        title,
        sev,
        mitre,
        &format!("Mapped from live liminal finding ({cat}) on {host}: {proof}"),
        host,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("phase".into(), json!(phase));
        obj.insert("category".into(), json!("kill_chain_mapped"));
        obj.insert("source_category".into(), json!(cat));
    }
    Some(tag_parent(f, host, "kill_chain"))
}

fn map_kill_chain_stages(host: &str, schisms: &[Value]) -> Vec<Value> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for f in schisms {
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        if seen.iter().any(|c| *c == cat) {
            continue;
        }
        if let Some(mapped) = kill_chain_from_schism(host, f) {
            seen.push(cat.to_string());
            out.push(mapped);
        }
    }
    out
}

/// HTTPS first (ALPN schism needs TLS). HTTP only when 443 is closed and 80 is open.
fn pick_origin_url(fqdn: &str, https_open: bool, http_open: bool) -> Option<String> {
    if https_open {
        Some(format!("https://{fqdn}"))
    } else if http_open {
        Some(format!("http://{fqdn}"))
    } else {
        None
    }
}

fn http_fallback_url(fqdn: &str, primary: &str, http_open: bool) -> Option<String> {
    if primary.starts_with("https://") && http_open {
        Some(format!("http://{fqdn}"))
    } else {
        None
    }
}

fn liminal_inner_ctx(host: &str, ctx: &EngineRunContext) -> EngineRunContext {
    let mut inner = ctx.clone();
    let mut jp = inner.job_params.clone();
    if !jp.is_object() {
        jp = json!({});
    }
    if let Some(o) = jp.as_object_mut() {
        o.insert("chain_web_engines".into(), json!(false));
        o.insert("trigger".into(), json!(ENGINE_ID));
        o.insert("parent_fqdn".into(), json!(host));
        o.insert("concurrency".into(), json!(LIMINAL_PATH_CONCURRENCY));
        o.insert("timeout_ms".into(), json!(6_000));
        o.insert("intensity".into(), json!("normal"));
        o.insert("check_attack_paths".into(), json!(false));
        o.insert("check_posture_score".into(), json!(false));
        o.insert("check_fingerprint".into(), json!(false));
        o.insert("check_ip_trust_headers".into(), json!(false));
        o.insert("include_info_findings".into(), json!(false));
        o.insert("paths".into(), json!(LIMINAL_PATHS));
        o.insert("sensitive_paths".into(), json!(LIMINAL_SENSITIVE_PATHS));
        if let Some(cid) = inner.client_id {
            o.insert("client_id".into(), json!(cid));
        }
    }
    inner.job_params = jp;
    inner
}

async fn run_liminal(url: &str, inner: &EngineRunContext) -> Result<EngineResult, bool> {
    match tokio::time::timeout(
        LIMINAL_TIMEOUT,
        crate::liminal_boundary_engine::run_liminal_boundary_result_ctx(url, inner),
    )
    .await
    {
        Ok(r) if r.success => Ok(r),
        Ok(r) => {
            tracing::warn!(
                target: "exposure_schism_fusion",
                url = %url,
                msg = %r.message,
                "liminal_boundary returned error — not faked"
            );
            Err(false)
        }
        Err(_) => {
            tracing::warn!(
                target: "exposure_schism_fusion",
                url = %url,
                "liminal_boundary timed out"
            );
            Err(true)
        }
    }
}

fn origin_unreachable(host: &str) -> HostOutcome {
    HostOutcome {
        findings: vec![tagged_status(
            host,
            "probe_error",
            &format!("Neither TCP/443 nor TCP/80 open on {host}"),
            "Origin did not accept TCP on 443 or 80. This is not a verified empty fracture set.",
            "liminal_boundary",
        )],
        timed_out: false,
        errored: true,
    }
}

fn origin_probe_failed(host: &str, timed_out: bool) -> HostOutcome {
    let cat = if timed_out {
        "probe_timeout"
    } else {
        "probe_error"
    };
    HostOutcome {
        findings: vec![tagged_status(
            host,
            cat,
            &format!("Liminal boundary failed on {host}"),
            "HTTPS then HTTP probes failed or timed out. Not scored as zero fractures.",
            "liminal_boundary",
        )],
        timed_out,
        errored: !timed_out,
    }
}

async fn probe_host(
    host: ProbeTarget,
    ctx: EngineRunContext,
    deep_kill_chain: bool,
) -> HostOutcome {
    let inner = liminal_inner_ctx(&host.fqdn, &ctx);
    let (https_open, http_open) = tokio::join!(
        origin_port_open(&host.fqdn, 443),
        origin_port_open(&host.fqdn, 80)
    );
    let Some(primary) = pick_origin_url(&host.fqdn, https_open, http_open) else {
        return origin_unreachable(&host.fqdn);
    };

    // TCP-open is not HTTP-alive. A filtered TLS stack must not be scored as 0 fractures.
    let primary = if http_alive(&primary).await {
        primary
    } else if let Some(http_url) = http_fallback_url(&host.fqdn, &primary, http_open) {
        if http_alive(&http_url).await {
            http_url
        } else {
            return origin_probe_failed(&host.fqdn, false);
        }
    } else {
        return origin_probe_failed(&host.fqdn, false);
    };

    let (used_url, liminal) = match run_liminal(&primary, &inner).await {
        Ok(r) => (primary, r),
        Err(timed_out) => {
            let Some(http_url) = http_fallback_url(&host.fqdn, &primary, http_open) else {
                return origin_probe_failed(&host.fqdn, timed_out);
            };
            match run_liminal(&http_url, &inner).await {
                Ok(r) => (http_url, r),
                Err(fb_timeout) => {
                    return origin_probe_failed(&host.fqdn, timed_out || fb_timeout);
                }
            }
        }
    };

    let schisms: Vec<Value> = liminal
        .findings
        .into_iter()
        .filter(is_schism_finding)
        .map(|f| tag_parent(f, &host.fqdn, "liminal_boundary"))
        .collect();

    if schisms.is_empty() {
        return HostOutcome {
            findings: vec![],
            timed_out: false,
            errored: false,
        };
    }

    let mut out = schisms.clone();
    out.extend(map_kill_chain_stages(&host.fqdn, &schisms));

    if deep_kill_chain {
        match tokio::time::timeout(
            KILL_CHAIN_TIMEOUT,
            crate::kill_chain_engine::run_kill_chain_result(&used_url),
        )
        .await
        {
            Ok(r) if r.success => {
                for f in r.findings {
                    if is_kill_chain_signal(&f) {
                        out.push(tag_parent(f, &host.fqdn, "kill_chain"));
                    }
                }
            }
            Ok(r) => {
                tracing::warn!(
                    target: "exposure_schism_fusion",
                    host = %host.fqdn,
                    msg = %r.message,
                    "kill_chain returned error — not faked"
                );
                out.push(tagged_status(
                    &host.fqdn,
                    "probe_error",
                    &format!("Deep kill-chain error on {}", host.fqdn),
                    "Optional deep crawl failed. Mapped stages from liminal evidence are still live.",
                    "kill_chain",
                ));
            }
            Err(_) => {
                tracing::warn!(
                    target: "exposure_schism_fusion",
                    host = %host.fqdn,
                    "kill_chain timed out"
                );
                out.push(tagged_status(
                    &host.fqdn,
                    "probe_timeout",
                    &format!("Deep kill-chain timed out on {}", host.fqdn),
                    "Optional deep crawl timed out. Mapped stages from liminal evidence are still live.",
                    "kill_chain",
                ));
            }
        }
    }

    let (timed_out, errored) = outcome_flags(&out);
    HostOutcome {
        findings: out,
        timed_out,
        errored,
    }
}

pub async fn run_exposure_schism_fusion_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let mut inner = ctx.clone();
    let mut params = ctx.job_params.clone();
    if !params.is_object() {
        params = json!({});
    }
    if let Some(o) = params.as_object_mut() {
        o.insert("chain_web_engines".into(), json!(false));
        o.insert("fusion_inline".into(), json!(true));
    }
    inner.job_params = params;

    let mut delta =
        first_mover_surface_delta::run_first_mover_surface_delta_result(target, &inner).await;
    if !delta.success {
        return delta;
    }

    let apex = extract_host(target)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let selected = select_probe_hosts(&delta.findings, &ctx.job_params, &apex);
    let deep_kill_chain = pbool(&ctx.job_params, "deep_kill_chain", false);

    if selected.is_empty() {
        let mut idle = finding(
            ENGINE_ID,
            "Exposure schism: no new hosts to fracture-test",
            "info",
            MITRE,
            "Live first-mover ran. Liminal boundary fires only on added/changed FQDNs (or extra_hosts). Baseline or a stable surface yields no schism score — never a filler grade.",
            target,
        );
        if let Some(obj) = idle.as_object_mut() {
            obj.insert("category".into(), json!("schism_idle"));
            obj.insert("fusion".into(), json!(ENGINE_ID));
        }
        delta.findings.push(idle);
        delta.message = format!("{} + schism idle (no added/changed hosts)", delta.message);
        return delta;
    }

    let batches: Vec<HostOutcome> = stream::iter(selected.clone())
        .map(|host| {
            let ctx = ctx.clone();
            async move { probe_host(host, ctx, deep_kill_chain).await }
        })
        .buffer_unordered(HOST_CONCURRENCY)
        .collect()
        .await;

    let mut fused = Vec::new();
    let mut timeout_n = 0usize;
    let mut error_n = 0usize;
    for batch in batches {
        if batch.timed_out {
            timeout_n += 1;
        }
        if batch.errored {
            error_n += 1;
        }
        fused.extend(batch.findings);
    }
    let schism_n = fused.iter().filter(|f| is_schism_finding(f)).count();
    let chain_n = fused
        .iter()
        .filter(|f| f.get("fusion_engine").and_then(Value::as_str) == Some("kill_chain"))
        .filter(|f| {
            f.get("category").and_then(Value::as_str) != Some("probe_timeout")
                && f.get("category").and_then(Value::as_str) != Some("probe_error")
        })
        .count();
    let schism_only: Vec<Value> = fused
        .iter()
        .filter(|f| is_schism_finding(f))
        .cloned()
        .collect();
    let headline_sev = if schism_n > 0 {
        worst_severity(&schism_only)
    } else {
        "info"
    };
    let added_list = selected
        .iter()
        .map(|h| h.fqdn.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let title = schism_summary_title(selected.len(), schism_n, chain_n, timeout_n, error_n);
    let mut headline = finding(
        ENGINE_ID,
        &title,
        headline_sev,
        MITRE,
        &format!(
            "Live first-mover hosts [{}]. Immediate liminal_boundary (HTTP/1.1↔HTTP/2, Vary, rewrite-header) ran against those FQDNs in this job. Kill-chain stages mapped from observed fractures{}. {} schism finding(s), {} kill-chain stage(s), {} timeout(s), {} error(s). Empty fracture set is empty_ok — a timeout or probe error is never a synthetic Prisma-style posture grade.",
            added_list,
            if deep_kill_chain {
                "; deep_kill_chain also crawled the origin"
            } else {
                " (same HTTP evidence; no second GET storm unless deep_kill_chain=true)"
            },
            schism_n,
            chain_n,
            timeout_n,
            error_n
        ),
        target,
    );
    if let Some(obj) = headline.as_object_mut() {
        obj.insert("category".into(), json!("schism_summary"));
        obj.insert("fusion".into(), json!(ENGINE_ID));
        obj.insert("timed_out".into(), json!(timeout_n > 0));
        obj.insert("probe_failed".into(), json!(timeout_n > 0 || error_n > 0));
    }
    delta.findings.insert(0, headline);
    delta.findings.extend(fused);

    if delta.findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    delta.message = format!(
        "{ENGINE_ID}: hosts={} schism_findings={schism_n} kill_chain={chain_n} timeouts={timeout_n} errors={error_n}",
        selected.len()
    );
    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_added_and_changed_fqdns() {
        let findings = vec![
            json!({"category":"added","target":"shop.acme.test","severity":"medium"}),
            json!({"category":"removed","target":"gone.acme.test"}),
            json!({"category":"added","value":"https://api.acme.test/v1","severity":"high"}),
            json!({"category":"changed","target":"www.acme.test","severity":"high"}),
            json!({"category":"summary","target":"acme.test"}),
        ];
        let hosts = select_probe_hosts(&findings, &json!({}), "acme.test");
        let names: Vec<&str> = hosts.iter().map(|h| h.fqdn.as_str()).collect();
        assert!(names.contains(&"shop.acme.test"));
        assert!(names.contains(&"api.acme.test"));
        assert!(names.contains(&"www.acme.test"));
        assert!(!names.contains(&"gone.acme.test"));
    }

    #[test]
    fn schism_requires_live_boundary_category_not_severity() {
        assert!(!is_schism_finding(&json!({
            "summary": true,
            "category": "posture_summary",
            "severity": "high"
        })));
        assert!(is_schism_finding(&json!({
            "category": "boundary_protocol_bypass",
            "severity": "critical",
            "title": "Protocol schism auth bypass"
        })));
        assert!(is_schism_finding(&json!({
            "category": "boundary_cache_vary",
            "severity": "high"
        })));
        assert!(!is_schism_finding(&json!({
            "severity": "high",
            "title": "Method schism"
        })));
        assert!(!is_schism_finding(&json!({
            "severity": "info",
            "title": "reachable"
        })));
        assert!(!is_schism_finding(&json!({
            "category": "probe_timeout",
            "severity": "info"
        })));
    }

    #[test]
    fn kill_chain_ignores_recon_fingerprint() {
        assert!(!is_kill_chain_signal(&json!({
            "phase": "Reconnaissance",
            "title": "Reconnaissance: live target fingerprint"
        })));
        assert!(is_kill_chain_signal(&json!({
            "phase": "Exploitation",
            "title": "Observed upload without CSP"
        })));
        assert!(!is_kill_chain_signal(&json!({
            "title": "Target unreachable"
        })));
    }

    #[test]
    fn maps_kill_chain_from_same_http_evidence() {
        let schism = json!({
            "category": "boundary_protocol_bypass",
            "severity": "critical",
            "title": "h1 403 vs h2 200",
            "description": "auth diverges across ALPN"
        });
        let mapped = kill_chain_from_schism("shop.acme.test", &schism).unwrap();
        assert_eq!(mapped["phase"], "Initial Access");
        assert_eq!(mapped["fusion_engine"], "kill_chain");
        assert_eq!(mapped["fusion"], ENGINE_ID);
        assert!(!is_schism_finding(&mapped));
    }

    #[test]
    fn extra_hosts_fill_when_baseline() {
        let findings = vec![json!({"category": "baseline", "target": "acme.test"})];
        let hosts = select_probe_hosts(
            &findings,
            &json!({"extra_hosts": ["shop.acme.test"]}),
            "acme.test",
        );
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].fqdn, "shop.acme.test");
    }

    #[test]
    fn extra_hosts_cannot_escape_authorized_apex() {
        let hosts = select_probe_hosts(
            &[],
            &json!({
                "extra_hosts": ["evil.example", "169.254.169.254", "shop.acme.test", "acme.test@169.254.169.254"]
            }),
            "acme.test",
        );
        let names: Vec<&str> = hosts.iter().map(|h| h.fqdn.as_str()).collect();
        assert_eq!(names, vec!["shop.acme.test"]);
    }

    #[test]
    fn userinfo_cannot_impersonate_in_scope_host() {
        assert_eq!(
            normalize_probe_host("https://shop.acme.test@169.254.169.254/"),
            None
        );
        assert_eq!(
            normalize_probe_host("https://shop.acme.test/path"),
            Some("shop.acme.test".into())
        );
    }

    #[test]
    fn cap_applies_after_merge_not_during_delta_walk() {
        let mut findings = Vec::new();
        for i in 0..6 {
            findings.push(json!({
                "category": "added",
                "target": format!("dns{i}.acme.test"),
                "severity": "low"
            }));
        }
        findings.push(json!({
            "category": "added",
            "target": "shop.acme.test",
            "severity": "critical"
        }));
        let hosts = select_probe_hosts(
            &findings,
            &json!({"extra_hosts": ["api.acme.test"]}),
            "acme.test",
        );
        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[0].fqdn, "shop.acme.test");
        assert!(hosts.iter().any(|h| h.fqdn == "api.acme.test"));
    }

    #[test]
    fn probe_errors_are_not_a_clean_zero_fracture_bill() {
        let incomplete = schism_summary_title(2, 0, 0, 0, 2);
        assert!(incomplete.contains("not a clean bill"));
        assert!(incomplete.contains("2 probe error(s)"));
        assert!(!incomplete.contains("0 boundary fracture(s)"));
        let timeout_only = schism_summary_title(1, 0, 0, 1, 0);
        assert!(timeout_only.contains("not a clean bill"));
        let live_schism = schism_summary_title(1, 3, 1, 0, 0);
        assert!(live_schism.contains("3 boundary fracture(s)"));
        assert!(!live_schism.contains("not a clean bill"));
        let mixed = schism_summary_title(1, 3, 1, 1, 0);
        assert!(mixed.contains("3 boundary fracture(s)"));
        assert!(mixed.contains("1 timed out"));
        assert!(!mixed.contains("not a clean bill"));
    }

    #[test]
    fn deep_kill_chain_timeout_is_counted_on_the_host_outcome() {
        let findings = vec![
            json!({"category": "boundary_protocol_bypass", "severity": "critical"}),
            json!({"category": "probe_timeout"}),
        ];
        let (timed_out, errored) = outcome_flags(&findings);
        assert!(timed_out);
        assert!(!errored);
        let err_only = vec![json!({"category": "probe_error"})];
        let (timed_out, errored) = outcome_flags(&err_only);
        assert!(!timed_out);
        assert!(errored);
        assert!(KILL_CHAIN_TIMEOUT >= Duration::from_secs(90));
    }

    #[test]
    fn ipv6_literals_use_bracketed_tcp_addrs() {
        assert_eq!(tcp_socket_addr("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(tcp_socket_addr("[2001:db8::1]", 80), "[2001:db8::1]:80");
        assert_eq!(tcp_socket_addr("shop.acme.test", 443), "shop.acme.test:443");
    }

    #[test]
    fn host_and_liminal_concurrency_are_two() {
        assert_eq!(HOST_CONCURRENCY, 2);
        assert_eq!(LIMINAL_PATH_CONCURRENCY, 2);
        assert_eq!(MAX_HOSTS, 4);
        assert_eq!(LIMINAL_PATHS, ["/", "/api"]);
        assert_eq!(LIMINAL_SENSITIVE_PATHS, ["/api"]);
    }

    #[test]
    fn liminal_budget_is_forced_not_inherited_from_parent_job() {
        let ctx = EngineRunContext {
            job_params: json!({
                "paths": ["/", "/admin", "/api", "/api/v1", "/internal", "/dashboard"],
                "sensitive_paths": ["/admin", "/console", "/actuator"],
                "concurrency": 16,
                "intensity": "aggressive",
                "check_ip_trust_headers": true,
                "check_fingerprint": true,
                "check_posture_score": true,
                "check_attack_paths": true,
            }),
            ..EngineRunContext::default()
        };
        let inner = liminal_inner_ctx("shop.acme.test", &ctx);
        assert_eq!(
            inner.job_params["concurrency"],
            json!(LIMINAL_PATH_CONCURRENCY)
        );
        assert_eq!(inner.job_params["paths"], json!(["/", "/api"]));
        assert_eq!(inner.job_params["sensitive_paths"], json!(["/api"]));
        assert_eq!(inner.job_params["intensity"], "normal");
        assert_eq!(inner.job_params["check_ip_trust_headers"], false);
        assert_eq!(inner.job_params["check_attack_paths"], false);
        assert_eq!(inner.job_params["check_posture_score"], false);
        assert_eq!(inner.job_params["check_fingerprint"], false);
        assert_eq!(inner.job_params["timeout_ms"], json!(6_000));
    }

    #[test]
    fn origin_is_https_then_http_never_http_first() {
        assert_eq!(
            pick_origin_url("shop.acme.test", true, true).as_deref(),
            Some("https://shop.acme.test")
        );
        assert_eq!(
            pick_origin_url("shop.acme.test", true, false).as_deref(),
            Some("https://shop.acme.test")
        );
        assert_eq!(
            pick_origin_url("shop.acme.test", false, true).as_deref(),
            Some("http://shop.acme.test")
        );
        assert_eq!(pick_origin_url("shop.acme.test", false, false), None);
        assert_eq!(
            http_fallback_url("shop.acme.test", "https://shop.acme.test", true).as_deref(),
            Some("http://shop.acme.test")
        );
        assert_eq!(
            http_fallback_url("shop.acme.test", "https://shop.acme.test", false),
            None
        );
        assert_eq!(
            http_fallback_url("shop.acme.test", "http://shop.acme.test", true),
            None
        );
    }

    #[test]
    fn headline_severity_from_schism_findings_only() {
        let schism = json!({
            "category": "boundary_protocol_bypass",
            "severity": "high"
        });
        let mapped = json!({
            "category": "kill_chain_mapped",
            "severity": "critical",
            "fusion_engine": "kill_chain"
        });
        let timeout = json!({
            "category": "probe_timeout",
            "severity": "info"
        });
        let added = json!({
            "category": "added",
            "severity": "critical"
        });
        assert!(is_schism_finding(&schism));
        assert!(!is_schism_finding(&mapped));
        assert!(!is_schism_finding(&timeout));
        assert!(!is_schism_finding(&added));
        let schism_only: Vec<Value> = [schism, mapped, timeout, added]
            .into_iter()
            .filter(is_schism_finding)
            .collect();
        assert_eq!(worst_severity(&schism_only), "high");
        assert_eq!(worst_severity(&[]), "info");
    }

    #[test]
    fn deep_kill_chain_defaults_off() {
        assert!(!pbool(&json!({}), "deep_kill_chain", false));
        assert!(!pbool(
            &json!({"deep_kill_chain": false}),
            "deep_kill_chain",
            false
        ));
        assert!(pbool(
            &json!({"deep_kill_chain": true}),
            "deep_kill_chain",
            false
        ));
        assert!(pbool(
            &json!({"deep_kill_chain": "true"}),
            "deep_kill_chain",
            false
        ));
    }
}
