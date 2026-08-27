//! Endpoint-agent dispatch — engines that require host-resident collection.
//!
//! Split from `engine_dispatch.rs` for maintainability. Hybrid engines (e.g. CHRONOS)
//! call `run_agent_required_engine` internally without being listed in the canonical agent list.

use super::EngineRunContext;
use crate::engine_result::EngineResult;

pub use weissman_core::models::engine_agent::{is_agent_required_engine, AGENT_REQUIRED_ENGINES};

/// Dispatch an agent-required engine to the endpoint fleet (or return a status finding).
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
    let f = serde_json::json!({
        "type": engine_id,
        "category": "agent_required",
        "title": format!("{} requires an enrolled endpoint agent", engine_id),
        "severity": "info",
        "mitre_attack": "",
        "description": "This detection runs on the host. Enrol the Weissman Endpoint Agent on this client and re-run the engine.",
        "target": target,
        "remediation": "Go to Dashboard → Agents → Generate token → run the install command on the affected host.",
        "agent_required": true,
    });
    EngineResult::ok(vec![f], format!("{}: requires endpoint agent", engine_id))
}

/// Merge remote-surface findings with agent dispatch / guidance for hybrid engines.
pub(crate) fn merge_agent_hybrid(
    remote: EngineResult,
    agent: EngineResult,
    engine_id: &str,
) -> EngineResult {
    let mut findings = remote.findings;
    for f in agent.findings {
        let dup = findings.iter().any(|existing| {
            existing.get("title").and_then(|v| v.as_str())
                == f.get("title").and_then(|v| v.as_str())
        });
        if !dup {
            findings.push(f);
        }
    }
    if findings.is_empty() {
        return EngineResult {
            status: agent.status,
            findings: Vec::new(),
            message: agent.message,
            success: agent.success,
            summary: agent.summary,
            graph_nodes: agent.graph_nodes,
            graph_edges: agent.graph_edges,
            roe_blocked: agent.roe_blocked,
            roe: agent.roe,
        };
    }
    let has_agent_guidance = findings.iter().any(|f| {
        f.get("agent_required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });
    let msg = if has_agent_guidance {
        format!(
            "{}: {} finding(s) — remote surface probed; endpoint agent recommended for host-resident validation",
            engine_id,
            findings.len()
        )
    } else {
        format!(
            "{}: {} finding(s) (remote surface + agent)",
            engine_id,
            findings.len()
        )
    };
    EngineResult::ok(findings, msg)
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
            return EngineResult::ok(
                vec![],
                format!("agent task enqueue failed for {}: {}", engine, e),
            );
        }
    };
    let f = serde_json::json!({
        "type": engine,
        "category": "agent_dispatched",
        "title": if live_dispatched {
            format!("{}: task dispatched to online agent", engine)
        } else {
            format!("{}: task queued for next online agent", engine)
        },
        "severity": "info",
        "mitre_attack": "",
        "description": format!(
            "Detection task {} routed to {} agent for client {}. Findings will stream to the dashboard as the agent reports them.",
            task,
            if live_dispatched { "live" } else { "next" },
            client_id
        ),
        "target": target,
        "task_id": task.to_string(),
        "live_dispatched": live_dispatched,
        "remediation": "View streaming findings under Dashboard → Findings, filtered by source = agent.",
    });
    EngineResult::ok(vec![f], format!("{}: task {} dispatched", engine, task))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_empty_both_returns_agent_shell() {
        let remote = EngineResult::ok(vec![], "remote-msg");
        let agent = EngineResult::ok(vec![], "agent-msg");
        let merged = merge_agent_hybrid(remote, agent, "ENG");
        assert!(merged.findings.is_empty());
        assert_eq!(merged.message, "agent-msg");
        assert_eq!(merged.status, "ok");
        assert!(merged.success);
    }

    #[test]
    fn merge_dedupes_by_title_and_builds_plain_message() {
        let remote = EngineResult::ok(vec![json!({"title": "A"})], "r");
        let agent = EngineResult::ok(vec![json!({"title": "A"}), json!({"title": "B"})], "a");
        let merged = merge_agent_hybrid(remote, agent, "ENG");
        assert_eq!(merged.findings.len(), 2);
        let titles: Vec<&str> = merged
            .findings
            .iter()
            .filter_map(|f| f.get("title").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(titles, vec!["A", "B"]);
        assert_eq!(merged.message, "ENG: 2 finding(s) (remote surface + agent)");
    }

    #[test]
    fn merge_flags_agent_guidance_in_message() {
        let remote = EngineResult::ok(vec![], "r");
        let agent = EngineResult::ok(vec![json!({"title": "X", "agent_required": true})], "a");
        let merged = merge_agent_hybrid(remote, agent, "ENG");
        assert_eq!(merged.findings.len(), 1);
        assert!(merged
            .message
            .contains("endpoint agent recommended for host-resident validation"));
        assert!(merged.message.starts_with("ENG: 1 finding(s)"));
    }
}
