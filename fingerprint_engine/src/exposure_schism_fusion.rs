//! **Exposure Schism Fusion** — why Weissman wins a PANW bake-off on one surface.
//!
//! Xpanse inventories; Prisma postures accounts; Cortex watches endpoints. None of
//! those SKUs diffs *first-seen* internet hosts and then proves HTTP/1.1↔HTTP/2 /
//! Vary / rewrite-header fractures on **only those FQDNs**, with a live kill-chain
//! mapped from the same HTTP evidence.
//!
//! Live-only contract:
//! - First `first_mover_surface_delta` run stores a baseline — no invented schisms.
//! - Empty added-host set → informational finding, never filler scores.
//! - `liminal_boundary` runs only against added (or operator `extra_hosts`) FQDNs.
//! - `kill_chain` runs only after a non-summary schism finding on that host.
//! - Timeouts and follow-on errors are logged, not faked as success.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, finding};
use crate::engine_result::EngineResult;
use crate::first_mover_surface_delta;
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;

pub const ENGINE_ID: &str = "exposure_schism_fusion";
const MITRE: &str = "T1190";
const MAX_HOSTS: usize = 4;
const LIMINAL_TIMEOUT: Duration = Duration::from_secs(50);
const KILL_CHAIN_TIMEOUT: Duration = Duration::from_secs(25);
const HOST_CONCURRENCY: usize = 2;

const SCHISM_CATEGORIES: &[&str] = &[
    "protocol_schism",
    "method_schism",
    "cache_vary",
    "cache_vary_oracle",
    "header_rewrite",
    "trusted_header",
    "ip_trust",
    "encoding_schism",
    "entropy_divergence",
    "attack_path",
];

fn normalize_fqdn(raw: &str) -> Option<String> {
    let h = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.contains('.') {
        Some(h)
    } else {
        None
    }
}

fn added_fqdns(findings: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for f in findings {
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        if cat != "added" {
            continue;
        }
        let raw = f
            .get("target")
            .or_else(|| f.get("value"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Some(h) = normalize_fqdn(raw) {
            if !out.iter().any(|x| x == &h) {
                out.push(h);
            }
        }
        if out.len() >= MAX_HOSTS {
            break;
        }
    }
    out
}

pub(crate) fn is_schism_finding(f: &Value) -> bool {
    if f.get("summary") == Some(&json!(true)) {
        return false;
    }
    let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
    if cat == "posture_summary" {
        return false;
    }
    if SCHISM_CATEGORIES
        .iter()
        .any(|c| cat.eq_ignore_ascii_case(c))
    {
        return true;
    }
    let sev = f
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info")
        .to_ascii_lowercase();
    matches!(sev.as_str(), "low" | "medium" | "high" | "critical")
}

fn is_kill_chain_signal(f: &Value) -> bool {
    let phase = f
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if phase.is_empty() {
        return false;
    }
    if phase == "reconnaissance" {
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

async fn probe_host(host: String, ctx: EngineRunContext) -> Vec<Value> {
    let url = format!("https://{host}");
    let mut inner = ctx.clone();
    let mut jp = inner.job_params.clone();
    if !jp.is_object() {
        jp = json!({});
    }
    if let Some(o) = jp.as_object_mut() {
        o.insert("chain_web_engines".into(), json!(false));
        o.insert("trigger".into(), json!(ENGINE_ID));
        o.insert("parent_fqdn".into(), json!(host.clone()));
        if let Some(cid) = inner.client_id {
            o.insert("client_id".into(), json!(cid));
        }
    }
    inner.job_params = jp;

    let liminal = match tokio::time::timeout(
        LIMINAL_TIMEOUT,
        crate::liminal_boundary_engine::run_liminal_boundary_result_ctx(&url, &inner),
    )
    .await
    {
        Ok(r) if r.success => r,
        Ok(r) => {
            tracing::warn!(
                target: "exposure_schism_fusion",
                host = %host,
                msg = %r.message,
                "liminal_boundary returned error — not faked"
            );
            return vec![];
        }
        Err(_) => {
            tracing::warn!(
                target: "exposure_schism_fusion",
                host = %host,
                "liminal_boundary timed out"
            );
            return vec![];
        }
    };

    let mut out: Vec<Value> = liminal
        .findings
        .into_iter()
        .filter(is_schism_finding)
        .map(|f| tag_parent(f, &host, "liminal_boundary"))
        .collect();

    if out.is_empty() {
        return out;
    }

    match tokio::time::timeout(
        KILL_CHAIN_TIMEOUT,
        crate::kill_chain_engine::run_kill_chain_result(&url),
    )
    .await
    {
        Ok(r) if r.success => {
            for f in r.findings {
                if is_kill_chain_signal(&f) {
                    out.push(tag_parent(f, &host, "kill_chain"));
                }
            }
        }
        Ok(r) => {
            tracing::warn!(
                target: "exposure_schism_fusion",
                host = %host,
                msg = %r.message,
                "kill_chain returned error — not faked"
            );
        }
        Err(_) => {
            tracing::warn!(
                target: "exposure_schism_fusion",
                host = %host,
                "kill_chain timed out"
            );
        }
    }
    out
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

    let mut added = added_fqdns(&delta.findings);
    for h in first_mover_surface_delta::extra_hosts_from_params(&ctx.job_params) {
        if let Some(h) = normalize_fqdn(&h) {
            if !added.iter().any(|x| x == &h) {
                added.push(h);
            }
        }
        if added.len() >= MAX_HOSTS {
            break;
        }
    }

    if added.is_empty() {
        delta.findings.push(finding(
            ENGINE_ID,
            "Exposure schism: no new hosts to fracture-test",
            "info",
            MITRE,
            "Live first-mover ran. Liminal boundary + kill-chain fire only on *added* FQDNs (or extra_hosts). Baseline or a stable surface yields no schism score — never a filler grade.",
            target,
        ));
        delta.message = format!("{} + schism idle (no added hosts)", delta.message);
        return delta;
    }

    let batches: Vec<Vec<Value>> = stream::iter(added.clone())
        .map(|host| {
            let ctx = ctx.clone();
            async move { probe_host(host, ctx).await }
        })
        .buffer_unordered(HOST_CONCURRENCY)
        .collect()
        .await;

    let mut fused = Vec::new();
    for batch in batches {
        fused.extend(batch);
    }
    let schism_n = fused
        .iter()
        .filter(|f| f.get("fusion_engine").and_then(Value::as_str) == Some("liminal_boundary"))
        .count();
    let chain_n = fused
        .iter()
        .filter(|f| f.get("fusion_engine").and_then(Value::as_str) == Some("kill_chain"))
        .count();
    let headline_sev = if schism_n > 0 {
        worst_severity(&fused)
    } else {
        "info"
    };

    delta.findings.insert(
        0,
        finding(
            ENGINE_ID,
            &format!(
                "Exposure schism on {} new host(s) — {} boundary fracture(s), {} kill-chain stage(s)",
                added.len(),
                schism_n,
                chain_n
            ),
            headline_sev,
            MITRE,
            &format!(
                "Live first-mover added [{}]. Immediate liminal_boundary (HTTP/1.1↔HTTP/2, Vary, rewrite-header) ran against those FQDNs in this job. Kill-chain mapped only after observed fractures. {} schism finding(s), {} post-recon kill-chain finding(s). Empty fracture set is empty_ok — not a synthetic Prisma-style posture grade.",
                added.join(", "),
                schism_n,
                chain_n
            ),
            target,
        ),
    );
    delta.findings.extend(fused);

    if delta.findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    delta.message = format!(
        "{ENGINE_ID}: added={} schism_findings={schism_n} kill_chain={chain_n}",
        added.len()
    );
    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_added_fqdns_only() {
        let findings = vec![
            json!({"category":"added","target":"shop.acme.test"}),
            json!({"category":"removed","target":"gone.acme.test"}),
            json!({"category":"added","value":"https://api.acme.test/v1"}),
            json!({"category":"summary","target":"acme.test"}),
        ];
        assert_eq!(
            added_fqdns(&findings),
            vec!["shop.acme.test", "api.acme.test"]
        );
    }

    #[test]
    fn schism_requires_live_fracture_not_posture_summary() {
        assert!(!is_schism_finding(&json!({
            "summary": true,
            "category": "posture_summary",
            "severity": "high"
        })));
        assert!(is_schism_finding(&json!({
            "category": "protocol_schism",
            "severity": "critical",
            "title": "Protocol schism auth bypass"
        })));
        assert!(is_schism_finding(&json!({
            "severity": "high",
            "title": "Method schism"
        })));
        assert!(!is_schism_finding(&json!({
            "severity": "info",
            "title": "reachable"
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
    fn extra_hosts_fill_when_baseline() {
        let findings = vec![json!({"category": "baseline", "target": "acme.test"})];
        let mut added = added_fqdns(&findings);
        assert!(added.is_empty());
        for h in first_mover_surface_delta::extra_hosts_from_params(&json!({
            "extra_hosts": ["shop.acme.test"]
        })) {
            if let Some(h) = normalize_fqdn(&h) {
                if !added.iter().any(|x| x == &h) {
                    added.push(h);
                }
            }
        }
        assert_eq!(added, vec!["shop.acme.test"]);
    }
}
