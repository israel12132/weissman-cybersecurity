//! **Exposure schism fusion** — first-seen hosts are immediately protocol-fracture probed.
//!
//! PANW splits this across SKUs: Xpanse inventories, Prisma postures, Cortex detects.
//! This engine diffs the live internet surface then runs `liminal_boundary` only on *added*
//! FQDNs in the same job. Findings require observed HTTP/1↔HTTP/2 / Vary / rewrite schisms.
//! Baseline or stable surface → honest info, never filler scores.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, finding};
use crate::engine_result::EngineResult;
use crate::first_mover_surface_delta;
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;

pub const ENGINE_ID: &str = "exposure_schism_fusion";
const MITRE: &str = "T1595";
const SCHISM_ENGINE: &str = "liminal_boundary";
const MAX_HOSTS: usize = 4;
const FOLLOW_TIMEOUT: Duration = Duration::from_secs(40);
const FOLLOW_CONCURRENCY: usize = 4;

fn normalize_host(raw: &str) -> Option<String> {
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
        if let Some(t) = f
            .get("target")
            .or_else(|| f.get("value"))
            .and_then(Value::as_str)
        {
            if let Some(h) = normalize_host(t) {
                if !out.iter().any(|x| x == &h) {
                    out.push(h);
                }
            }
        }
        if out.len() >= MAX_HOSTS {
            break;
        }
    }
    out
}

fn tag_parent(mut f: Value, host: &str) -> Value {
    if let Some(obj) = f.as_object_mut() {
        obj.insert("parent_fqdn".into(), json!(host));
        obj.insert("fusion".into(), json!(ENGINE_ID));
        obj.insert("fusion_engine".into(), json!(SCHISM_ENGINE));
        obj.entry("asset")
            .or_insert_with(|| json!("exposure_schism"));
    }
    f
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
        if let Some(h) = normalize_host(&h) {
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
            "Exposure schism: no new hosts to fracture-probe",
            "info",
            MITRE,
            "First-mover ran live. Liminal boundary fires only on *added* FQDNs in this job. \
Baseline or stable surface yields no protocol-schism findings.",
            target,
        ));
        delta.message = format!("{} + schism idle (no added hosts)", delta.message);
        return delta;
    }

    let extras: Vec<Vec<Value>> = stream::iter(added.clone())
        .map(|host| {
            let ctx = ctx.clone();
            async move {
                let url = format!("https://{host}");
                let mut c = ctx;
                let mut jp = c.job_params.clone();
                if !jp.is_object() {
                    jp = json!({});
                }
                if let Some(o) = jp.as_object_mut() {
                    o.insert("chain_web_engines".into(), json!(false));
                    o.insert("trigger".into(), json!(ENGINE_ID));
                    o.insert("parent_fqdn".into(), json!(host.clone()));
                    if let Some(cid) = c.client_id {
                        o.insert("client_id".into(), json!(cid));
                    }
                }
                c.job_params = jp;
                match tokio::time::timeout(
                    FOLLOW_TIMEOUT,
                    crate::engine_dispatch::run_engine(SCHISM_ENGINE, &url, &c),
                )
                .await
                {
                    Ok(r) if r.success => r
                        .findings
                        .into_iter()
                        .map(|f| tag_parent(f, &host))
                        .collect(),
                    Ok(r) => {
                        tracing::warn!(
                            target: "exposure_schism",
                            host = %host,
                            msg = %r.message,
                            "liminal_boundary returned error — not faked"
                        );
                        vec![]
                    }
                    Err(_) => {
                        tracing::warn!(
                            target: "exposure_schism",
                            host = %host,
                            "liminal_boundary timed out"
                        );
                        vec![]
                    }
                }
            }
        })
        .buffer_unordered(FOLLOW_CONCURRENCY)
        .collect()
        .await;

    let mut fused = 0usize;
    for batch in extras {
        fused += batch.len();
        delta.findings.extend(batch);
    }

    delta.findings.insert(
        0,
        finding(
            ENGINE_ID,
            &format!(
                "Exposure schism on {} new host(s) — liminal_boundary same FQDN",
                added.len()
            ),
            if fused > 0 { "high" } else { "info" },
            MITRE,
            &format!(
                "Live first-mover added [{}]. Immediate {} ran against those FQDNs in this job \
(not a later weekly hunt). {} schism finding(s).",
                added.join(", "),
                SCHISM_ENGINE,
                fused
            ),
            target,
        ),
    );
    if delta.findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    delta.message = format!("{ENGINE_ID}: added={} schism_findings={fused}", added.len());
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
    fn extra_hosts_fill_when_baseline() {
        let findings = vec![json!({"category": "baseline", "target": "acme.test"})];
        let mut added = added_fqdns(&findings);
        assert!(added.is_empty());
        for h in first_mover_surface_delta::extra_hosts_from_params(&json!({
            "extra_hosts": ["shop.acme.test"]
        })) {
            if let Some(h) = normalize_host(&h) {
                if !added.iter().any(|x| x == &h) {
                    added.push(h);
                }
            }
        }
        assert_eq!(added, vec!["shop.acme.test"]);
    }

    #[test]
    fn engine_id_is_stable() {
        assert_eq!(ENGINE_ID, "exposure_schism_fusion");
        assert_eq!(SCHISM_ENGINE, "liminal_boundary");
    }
}
