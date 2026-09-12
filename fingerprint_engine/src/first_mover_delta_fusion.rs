//! **Fusion on the delta** — a new host is not a separate hunt later.
//!
//! Runs live `first_mover_surface_delta` (without async chain enqueue), then immediately
//! executes takeover / leak / BOLA / JWT against each *added* FQDN in this same job.
//! Findings keep `parent_fqdn` so the Command Center kill-chain is one evidence graph.
//!
//! Not in the default orchestrator pack (that pack already chains via enqueue). This engine
//! is the inline kill-chain for ASM / Command Center.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, finding};
use crate::engine_result::EngineResult;
use crate::first_mover_surface_delta::{
    self, live_delta_follow_on_engines, DELTA_OAST_FOLLOW_ON_ENGINES,
};
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;

pub const ENGINE_ID: &str = "first_mover_delta_fusion";
const MITRE: &str = "T1595";
const MAX_HOSTS: usize = 4;
const FOLLOW_TIMEOUT: Duration = Duration::from_secs(40);
const FOLLOW_CONCURRENCY: usize = 4;

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
            let h = t
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("")
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if h.contains('.') && !out.iter().any(|x| x == &h) {
                out.push(h);
            }
        }
        if out.len() >= MAX_HOSTS {
            break;
        }
    }
    out
}

fn tag_parent(mut f: Value, host: &str, engine: &str, trigger: &str) -> Value {
    if let Some(obj) = f.as_object_mut() {
        obj.insert("parent_fqdn".into(), json!(host));
        obj.insert("fusion".into(), json!(ENGINE_ID));
        obj.insert("fusion_engine".into(), json!(engine));
        obj.entry("asset").or_insert_with(|| json!("delta_fusion"));
        if trigger == "certstream" {
            obj.insert("ct_squirt".into(), json!(true));
        }
        let verified = obj
            .get("oast_confirmed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || (obj
                .get("verified")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                && obj
                    .get("verification_method")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    == "oob_oast_callback");
        if verified {
            obj.insert("oast_confirmed".into(), json!(true));
        }
    }
    f
}

fn fusion_follow_on_jobs(added: &[String]) -> Vec<(String, String)> {
    let follow = live_delta_follow_on_engines();
    added
        .iter()
        .enumerate()
        .flat_map(|(i, h)| {
            follow.iter().filter_map(move |e| {
                // OAST poll is expensive — first two new hosts only.
                if DELTA_OAST_FOLLOW_ON_ENGINES.contains(e) && i >= 2 {
                    return None;
                }
                Some(((*e).to_string(), h.clone()))
            })
        })
        .collect()
}

pub async fn run_first_mover_delta_fusion_result(
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
        let h = h
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if h.contains('.') && !added.iter().any(|x| x == &h) {
            added.push(h);
        }
        if added.len() >= MAX_HOSTS {
            break;
        }
    }
    if added.is_empty() {
        delta.findings.push(finding(
            ENGINE_ID,
            "Delta fusion: no new hosts to attack in this snapshot",
            "info",
            MITRE,
            "First-mover ran live. Follow-on takeover/leak/BOLA/JWT (and OAST/SSRF when the collector is live) fire only on *added* FQDNs — not as a separate later hunt. Baseline or stable surface yields no kill-chain.",
            target,
        ));
        delta.message = format!("{} + fusion idle (no added hosts)", delta.message);
        return delta;
    }

    let trigger = ctx
        .job_params
        .get("trigger")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let jobs = fusion_follow_on_jobs(&added);
    let follow_engines = live_delta_follow_on_engines();

    let extras: Vec<Vec<Value>> = stream::iter(jobs)
        .map(|(eng, host)| {
            let ctx = ctx.clone();
            let trigger = trigger.clone();
            async move {
                if eng == ENGINE_ID || eng == first_mover_surface_delta::ENGINE_ID {
                    return vec![];
                }
                let url = format!("https://{host}");
                let mut c = ctx;
                let mut jp = c.job_params.clone();
                if !jp.is_object() {
                    jp = json!({});
                }
                if let Some(o) = jp.as_object_mut() {
                    o.insert("chain_web_engines".into(), json!(false));
                    o.insert(
                        "trigger".into(),
                        json!(if trigger == "certstream" {
                            "certstream"
                        } else {
                            "first_mover_delta_fusion"
                        }),
                    );
                    o.insert("parent_fqdn".into(), json!(host.clone()));
                    if let Some(cid) = c.client_id {
                        o.insert("client_id".into(), json!(cid));
                    }
                }
                c.job_params = jp;
                match tokio::time::timeout(
                    FOLLOW_TIMEOUT,
                    crate::engine_dispatch::run_engine(&eng, &url, &c),
                )
                .await
                {
                    Ok(r) if r.success => r
                        .findings
                        .into_iter()
                        .map(|f| tag_parent(f, &host, &eng, &trigger))
                        .collect(),
                    Ok(r) => {
                        tracing::warn!(
                            target: "delta_fusion",
                            engine = %eng,
                            host = %host,
                            msg = %r.message,
                            "follow-on returned error — not faked"
                        );
                        vec![]
                    }
                    Err(_) => {
                        tracing::warn!(
                            target: "delta_fusion",
                            engine = %eng,
                            host = %host,
                            "follow-on timed out"
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
                "Delta fusion kill-chain on {} new host(s) — takeover/leak/BOLA/JWT{} same FQDN",
                added.len(),
                if follow_engines.iter().any(|e| DELTA_OAST_FOLLOW_ON_ENGINES.contains(e)) {
                    "/OAST"
                } else {
                    ""
                }
            ),
            if fused > 0 { "high" } else { "info" },
            MITRE,
            &format!(
                "Live first-mover added [{}]. Immediate follow-on engines [{}] ran against those FQDNs in this job (not a later weekly hunt). {} follow-on finding(s). trigger={}.",
                added.join(", "),
                follow_engines.join(", "),
                fused,
                if trigger.is_empty() { "fusion" } else { trigger.as_str() }
            ),
            target,
        ),
    );
    if delta.findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    delta.message = format!(
        "{ENGINE_ID}: added={} follow_on_findings={fused}",
        added.len()
    );
    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_hosts_fill_kill_chain_when_baseline_findings() {
        let findings = vec![json!({"category": "baseline", "target": "acme.test"})];
        let mut added = added_fqdns(&findings);
        assert!(added.is_empty());
        for h in first_mover_surface_delta::extra_hosts_from_params(&json!({
            "extra_hosts": ["shop.acme.test"]
        })) {
            if h.contains('.') && !added.iter().any(|x| x == &h) {
                added.push(h);
            }
        }
        assert_eq!(added, vec!["shop.acme.test"]);
    }

    #[test]
    fn extracts_added_fqdns_only() {
        let findings = vec![
            json!({"category":"added","target":"shop.acme.test"}),
            json!({"category":"removed","target":"gone.acme.test"}),
            json!({"category":"added","value":"https://api.acme.test/v1"}),
            json!({"category":"summary","target":"acme.test"}),
        ];
        let a = added_fqdns(&findings);
        assert_eq!(a, vec!["shop.acme.test", "api.acme.test"]);
    }

    #[test]
    fn follow_on_list_is_the_kill_chain() {
        assert!(first_mover_surface_delta::DELTA_FOLLOW_ON_ENGINES.contains(&"subdomain_takeover"));
        assert!(first_mover_surface_delta::DELTA_FOLLOW_ON_ENGINES.contains(&"leak_hunter"));
        assert!(first_mover_surface_delta::DELTA_FOLLOW_ON_ENGINES.contains(&"bola_idor"));
        assert!(first_mover_surface_delta::DELTA_FOLLOW_ON_ENGINES.contains(&"jwt_attack"));
        assert!(!first_mover_surface_delta::DELTA_FOLLOW_ON_ENGINES.contains(&ENGINE_ID));
        assert!(DELTA_OAST_FOLLOW_ON_ENGINES.contains(&"oast_oob"));
        assert!(DELTA_OAST_FOLLOW_ON_ENGINES.contains(&"ssrf_advanced"));
    }

    #[test]
    fn fusion_jobs_always_cover_core_engines() {
        let jobs = fusion_follow_on_jobs(&["shop.acme.test".into()]);
        for e in first_mover_surface_delta::DELTA_FOLLOW_ON_ENGINES {
            assert!(
                jobs.iter().any(|(eng, _)| eng == e),
                "missing core follow-on {e}"
            );
        }
    }

    #[test]
    fn tag_parent_marks_ct_squirt_and_oast_confirm() {
        let f = tag_parent(
            json!({
                "title": "CONFIRMED",
                "verified": true,
                "verification_method": "oob_oast_callback",
            }),
            "shop.acme.test",
            "oast_oob",
            "certstream",
        );
        assert_eq!(f["parent_fqdn"], "shop.acme.test");
        assert_eq!(f["ct_squirt"], true);
        assert_eq!(f["oast_confirmed"], true);
        assert_eq!(f["fusion_engine"], "oast_oob");
    }
}
