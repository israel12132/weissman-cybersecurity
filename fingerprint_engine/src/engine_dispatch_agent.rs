//! Endpoint-agent dispatch — engines that require host-resident collection.
//!
//! Split from `engine_dispatch.rs` for maintainability. Hybrid engines (e.g. CHRONOS)
//! call `run_agent_required_engine` internally without being listed in the canonical agent list.

use super::EngineRunContext;
use crate::engine_probes::is_invented_agent_placeholder;
use crate::engine_result::EngineResult;

pub use weissman_core::models::engine_agent::{is_agent_required_engine, AGENT_REQUIRED_ENGINES};

/// Dispatch an agent-required engine to the endpoint fleet (or return a queue status).
///
/// Never invents host findings. When a client/pool is present the work is inserted into
/// `endpoint_agent_tasks` and the scan job is parked as `waiting_for_agent` until the agent
/// reports. Missing client/pool fails visibly — it is not empty success.
pub async fn run_agent_required_engine(
    engine_id: &str,
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if let (Some(pool), Some(registry), Some(client_id), Some(tenant_id)) = (
        ctx.app_pool.as_ref(),
        ctx.agents.as_ref(),
        ctx.client_id,
        ctx.tenant_id,
    ) {
        return dispatch_to_agent(
            pool.as_ref(),
            registry,
            tenant_id,
            client_id,
            engine_id,
            target,
            ctx,
        )
        .await;
    }
    EngineResult::waiting_for_agent(format!(
        "{}: cannot enqueue host task without client_id + database (select a client and re-run)",
        engine_id
    ))
}

/// Merge remote-surface findings with agent dispatch / queue state for hybrid engines.
pub(crate) fn merge_agent_hybrid(
    remote: EngineResult,
    agent: EngineResult,
    engine_id: &str,
) -> EngineResult {
    let mut findings: Vec<serde_json::Value> = Vec::new();
    for f in remote
        .findings
        .into_iter()
        .chain(agent.findings.iter().cloned())
    {
        if is_invented_agent_placeholder(&f) {
            continue;
        }
        let dup = findings.iter().any(|existing| {
            existing.get("title").and_then(|v| v.as_str())
                == f.get("title").and_then(|v| v.as_str())
                && f.get("title").is_some()
        });
        if !dup {
            findings.push(f);
        }
    }

    if agent.status.eq_ignore_ascii_case("error") && agent.agent_task_id.is_none() {
        let mut out = EngineResult::error(agent.message.clone());
        out.findings = findings;
        return out;
    }

    let queued = agent.is_waiting_for_agent() || agent.agent_task_id.is_some();
    let msg = if queued {
        let live = agent.live_dispatched.unwrap_or(false);
        if findings.is_empty() {
            agent.message.clone()
        } else {
            format!(
                "{}: {} remote-surface finding(s); host detection queued for endpoint agent (live={})",
                engine_id,
                findings.len(),
                live
            )
        }
    } else if findings.is_empty() {
        agent.message.clone()
    } else {
        format!(
            "{}: {} finding(s) (remote surface + agent)",
            engine_id,
            findings.len()
        )
    };

    let mut out = if queued {
        EngineResult::waiting_for_agent(msg)
    } else {
        EngineResult::ok(findings.clone(), msg)
    };
    if queued {
        out.findings = findings;
    }
    out.agent_task_id = agent.agent_task_id.clone();
    out.live_dispatched = agent.live_dispatched;
    out
}

async fn dispatch_to_agent(
    pool: &sqlx::PgPool,
    registry: &std::sync::Arc<crate::endpoint_agents::AgentRegistry>,
    tenant_id: i64,
    client_id: i64,
    engine: &str,
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    let mut params = if ctx.job_params.is_null() {
        serde_json::json!({})
    } else {
        ctx.job_params.clone()
    };
    if let Some(obj) = params.as_object_mut() {
        obj.entry("priority")
            .or_insert_with(|| serde_json::json!("high"));
        if let Some(job_id) = &ctx.job_id {
            obj.entry("scan_job_id")
                .or_insert_with(|| serde_json::json!(job_id));
        }
    }
    let (task, live_dispatched) = match crate::endpoint_agents::enqueue_and_dispatch_fleet(
        pool,
        registry,
        tenant_id,
        client_id,
        engine,
        Some(target),
        &params,
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            return EngineResult::error(format!("agent task enqueue failed for {}: {}", engine, e));
        }
    };
    let msg = if live_dispatched {
        format!(
            "{}: dispatched to online agent (task {}) — waiting for host evidence",
            engine, task
        )
    } else {
        format!(
            "{}: queued for next online agent (task {}) — no host finding until the collector connects",
            engine, task
        )
    };
    EngineResult::waiting_for_agent(msg).with_agent_task(task.to_string(), live_dispatched)
}

#[cfg(test)]
mod tests {
    use super::EngineRunContext;
    use super::*;
    use crate::engine_result::WAITING_FOR_AGENT;
    use serde_json::json;

    #[test]
    fn merge_empty_both_preserves_waiting_status() {
        let remote = EngineResult::ok(vec![], "remote-msg");
        let agent = EngineResult::waiting_for_agent("queued-msg").with_agent_task("t1", false);
        let merged = merge_agent_hybrid(remote, agent, "ENG");
        assert!(merged.findings.is_empty());
        assert_eq!(merged.status, WAITING_FOR_AGENT);
        assert!(!merged.success);
        assert_eq!(merged.agent_task_id.as_deref(), Some("t1"));
        assert_eq!(merged.live_dispatched, Some(false));
        assert!(merged.message.contains("queued-msg"));
    }

    #[test]
    fn merge_keeps_live_remote_findings_and_parks_host() {
        let remote = EngineResult::ok(vec![json!({"title": "A", "remote_surface": true})], "r");
        let agent = EngineResult::waiting_for_agent("queued").with_agent_task("t2", true);
        let merged = merge_agent_hybrid(remote, agent, "ENG");
        assert_eq!(merged.findings.len(), 1);
        assert_eq!(merged.status, WAITING_FOR_AGENT);
        assert_eq!(merged.agent_task_id.as_deref(), Some("t2"));
        assert!(merged.message.contains("1 remote-surface finding"));
        assert!(merged.message.contains("live=true"));
    }

    #[test]
    fn merge_strips_invented_agent_placeholders() {
        let remote = EngineResult::ok(vec![json!({"title": "A"})], "r");
        let agent = EngineResult::ok(
            vec![
                json!({"title": "fake", "agent_required": true, "category": "agent_required"}),
                json!({"title": "B"}),
            ],
            "a",
        );
        let merged = merge_agent_hybrid(remote, agent, "ENG");
        let titles: Vec<&str> = merged
            .findings
            .iter()
            .filter_map(|f| f.get("title").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(titles, vec!["A", "B"]);
        assert_eq!(merged.status, "ok");
    }

    #[test]
    fn merge_dedupes_by_title() {
        let remote = EngineResult::ok(vec![json!({"title": "A"})], "r");
        let agent = EngineResult::ok(vec![json!({"title": "A"}), json!({"title": "B"})], "a");
        let merged = merge_agent_hybrid(remote, agent, "ENG");
        assert_eq!(merged.findings.len(), 2);
    }

    #[test]
    fn merge_agent_error_keeps_remote_findings_and_does_not_succeed() {
        let remote = EngineResult::ok(
            vec![json!({"title": "perimeter", "remote_surface": true})],
            "r",
        );
        let agent = EngineResult::error("agent task enqueue failed for ENG: db down");
        let merged = merge_agent_hybrid(remote, agent, "ENG");
        assert_eq!(merged.status, "error");
        assert!(!merged.success);
        assert_eq!(merged.findings.len(), 1);
        assert_eq!(merged.findings[0]["title"], "perimeter");
    }

    #[tokio::test]
    async fn missing_client_does_not_invent_host_findings() {
        let ctx = EngineRunContext::default();
        let r = run_agent_required_engine("process_hollowing", "host.local", &ctx).await;
        assert!(r.is_waiting_for_agent());
        assert!(r.findings.is_empty());
        assert!(r.agent_task_id.is_none());
        assert!(!r.success);
        assert!(r.message.contains("client_id"));
    }
}
