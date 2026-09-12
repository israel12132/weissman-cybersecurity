//! Attach complementary attack / scan / findings detections to every live
//! endpoint agent.
//!
//! Fleet round-robin (`enqueue_and_dispatch_fleet`) delivers one engine to
//! **one** host. Operators asked to attach a helper to **every** agent that is
//! already online and improve what it already does: attack, scan, and
//! finding discovery. This module fans a curated leftover pack to each
//! WebSocket-live agent without duplicating a recent enroll-baseline or swarm
//! task, never arms `host_isolation`, and never fabricates findings.

use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::endpoint_agents::{
    all_agent_uuids_for_tenant, enqueue_task, mark_task_dispatched, AgentRegistry, ServerToAgent,
    AGENT_STATUS_LIMIT, FLEET_MAX_AGENTS,
};

/// `(engine_id, category)` — attack / scan / findings. Every id is agent-required.
/// Isolation and ransomware emulation stay out: those are dual-control / RoE paths.
pub const SWARM_ATTACH_PACK: &[(&str, &str)] = &[
    // Attack — host-resident offensive surface the remote engines cannot see.
    ("process_hollowing", "attack"),
    ("arp_spoofing_engine", "attack"),
    ("dns_tunneling_c2", "attack"),
    ("icmp_covert", "attack"),
    ("parent_pid_spoof", "attack"),
    // Scan — inventory and integrity.
    ("process_inventory", "scan"),
    ("persistence_mechanism", "scan"),
    ("ioc_yara_hunt", "scan"),
    ("usb_enumeration", "scan"),
    ("av_bypass_engine", "scan"),
    ("log_tampering_engine", "scan"),
    ("ebpf_sensor", "scan"),
    // Findings / discovery.
    ("host_privilege_escalation", "findings"),
    ("infostealer_emulation", "findings"),
    ("clipboard_hijack", "findings"),
    ("com_hijacking", "findings"),
    ("sandbox_evasion", "findings"),
    ("timestomping", "findings"),
];

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SwarmAttachReport {
    pub agents_seen: u32,
    pub agents_attached: u32,
    pub tasks_enqueued: u32,
    pub tasks_live: u32,
    pub skipped_recent: u32,
}

impl SwarmAttachReport {
    pub fn to_json(&self) -> Value {
        json!({
            "ok": true,
            "swarm_attach": true,
            "agents_seen": self.agents_seen,
            "agents_attached": self.agents_attached,
            "tasks_enqueued": self.tasks_enqueued,
            "tasks_live": self.tasks_live,
            "skipped_recent": self.skipped_recent,
            "pack_size": SWARM_ATTACH_PACK.len(),
            "pack": SWARM_ATTACH_PACK.iter().map(|(e, c)| json!({
                "engine": e,
                "category": c,
            })).collect::<Vec<_>>(),
        })
    }
}

/// High/critical host findings must invalidate Dijkstra so Attack Paths recompute
/// from live evidence instead of a stale graph.
pub fn finding_dirties_attack_graph(finding: &Value) -> bool {
    let sev = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(sev.as_str(), "high" | "critical")
}

/// Fan the leftover pack to every WebSocket-live agent in the tenant (optionally
/// one client). Queues when the socket is down so the pending pusher still delivers.
pub async fn attach_helpers_to_online_agents(
    pool: &PgPool,
    registry: &Arc<AgentRegistry>,
    tenant_id: i64,
    client_id: Option<i64>,
) -> SwarmAttachReport {
    let mut report = SwarmAttachReport::default();
    let Ok(agents) = all_agent_uuids_for_tenant(pool, tenant_id, AGENT_STATUS_LIMIT).await else {
        return report;
    };
    let mut attached_this_tick = 0u32;
    for (uuid, cid) in agents {
        if let Some(want) = client_id {
            if cid != want {
                continue;
            }
        }
        if !registry.is_agent_online(&uuid).await {
            continue;
        }
        report.agents_seen = report.agents_seen.saturating_add(1);
        if attached_this_tick >= FLEET_MAX_AGENTS as u32 {
            break;
        }
        let slice = attach_helpers_to_agent(pool, registry, tenant_id, cid, &uuid).await;
        report.tasks_enqueued = report.tasks_enqueued.saturating_add(slice.tasks_enqueued);
        report.tasks_live = report.tasks_live.saturating_add(slice.tasks_live);
        report.skipped_recent = report.skipped_recent.saturating_add(slice.skipped_recent);
        if slice.tasks_enqueued > 0 {
            report.agents_attached = report.agents_attached.saturating_add(1);
            attached_this_tick = attached_this_tick.saturating_add(1);
        }
    }
    tracing::info!(
        target: "agents",
        tenant_id,
        client_id = ?client_id,
        agents_seen = report.agents_seen,
        agents_attached = report.agents_attached,
        tasks_enqueued = report.tasks_enqueued,
        tasks_live = report.tasks_live,
        skipped_recent = report.skipped_recent,
        "swarm-attach helpers dispatched to live endpoint agents"
    );
    report
}

/// Attach the leftover pack to one already-online agent.
pub async fn attach_helpers_to_agent(
    pool: &PgPool,
    registry: &Arc<AgentRegistry>,
    tenant_id: i64,
    client_id: i64,
    agent_uuid: &str,
) -> SwarmAttachReport {
    let mut report = SwarmAttachReport {
        agents_seen: 1,
        ..SwarmAttachReport::default()
    };
    for (engine, category) in SWARM_ATTACH_PACK {
        match engine_recently_tasked(pool, tenant_id, client_id, engine, agent_uuid).await {
            Ok(true) => {
                report.skipped_recent = report.skipped_recent.saturating_add(1);
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    target: "agents",
                    tenant_id,
                    client_id,
                    engine,
                    error = %e,
                    "swarm-attach recent-task lookup failed"
                );
                continue;
            }
        }
        let params = json!({
            "trigger": "swarm_attach",
            "category": category,
            "priority": "high",
            "peer_agent": agent_uuid,
        });
        match enqueue_and_dispatch_to_agent(
            pool, registry, tenant_id, client_id, agent_uuid, engine, None, &params,
        )
        .await
        {
            Ok((_, live)) => {
                report.tasks_enqueued = report.tasks_enqueued.saturating_add(1);
                if live {
                    report.tasks_live = report.tasks_live.saturating_add(1);
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "agents",
                    tenant_id,
                    client_id,
                    engine,
                    agent = %agent_uuid,
                    error = %e,
                    "swarm-attach enqueue failed"
                );
            }
        }
    }
    if report.tasks_enqueued > 0 {
        report.agents_attached = 1;
    }
    report
}

/// Queue a task and live-push it to a **specific** agent (not fleet round-robin).
pub async fn enqueue_and_dispatch_to_agent(
    pool: &PgPool,
    registry: &Arc<AgentRegistry>,
    tenant_id: i64,
    client_id: i64,
    agent_uuid: &str,
    engine: &str,
    target: Option<&str>,
    params: &Value,
) -> Result<(Uuid, bool), sqlx::Error> {
    let task_uuid = enqueue_task(pool, tenant_id, client_id, engine, target, params).await?;
    let live = if registry.is_agent_online(agent_uuid).await {
        let sent = registry
            .send(
                agent_uuid,
                ServerToAgent::Task {
                    task_id: task_uuid.to_string(),
                    engine: engine.to_string(),
                    target: target.map(str::to_string),
                    params: params.clone(),
                },
            )
            .await
            .is_ok();
        if sent {
            if let Err(e) = mark_task_dispatched(pool, tenant_id, &task_uuid).await {
                tracing::warn!(
                    target: "agents",
                    task_uuid = %task_uuid,
                    error = %e,
                    "swarm-attach could not mark task dispatched"
                );
            }
        }
        sent
    } else {
        false
    };
    Ok((task_uuid, live))
}

async fn engine_recently_tasked(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    engine: &str,
    agent_uuid: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let exists = sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS(
            SELECT 1 FROM endpoint_agent_tasks
             WHERE tenant_id = $1 AND client_id = $2 AND engine = $3
               AND created_at > now() - interval '25 minutes'
               AND status IN ('pending','running','done')
               AND (
                 params->>'peer_agent' = $4
                 OR params->>'trigger' = 'enroll_baseline'
               )
        )"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(engine)
    .bind(agent_uuid)
    .fetch_one(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(exists)
}

/// Leader-only: periodically attach leftover helpers to every still-online agent.
pub fn spawn_swarm_attach_scheduler(pool: Arc<PgPool>, registry: Arc<AgentRegistry>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(10 * 60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Ok(tenants) = weissman_db::active_tenant_ids(pool.as_ref()).await else {
                continue;
            };
            for tenant_id in tenants {
                let _ = attach_helpers_to_online_agents(pool.as_ref(), &registry, tenant_id, None)
                    .await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pack_is_agent_required_categorized_and_non_destructive() {
        let mut seen = std::collections::HashSet::new();
        let mut cats = std::collections::HashSet::new();
        for (engine, cat) in SWARM_ATTACH_PACK {
            assert!(
                seen.insert(*engine),
                "duplicate swarm-attach engine {engine}"
            );
            assert!(
                weissman_core::models::engine_agent::is_agent_required_engine(engine),
                "{engine} must be agent-required"
            );
            assert!(
                matches!(*cat, "attack" | "scan" | "findings"),
                "unexpected category {cat} for {engine}"
            );
            cats.insert(*cat);
            assert_ne!(*engine, "host_isolation");
            assert_ne!(*engine, "ransomware_emulation");
        }
        assert!(cats.contains("attack"));
        assert!(cats.contains("scan"));
        assert!(cats.contains("findings"));
        assert!(SWARM_ATTACH_PACK.len() >= 12);
    }

    #[test]
    fn high_severity_dirties_attack_graph() {
        assert!(finding_dirties_attack_graph(
            &json!({"severity": "critical"})
        ));
        assert!(finding_dirties_attack_graph(&json!({"severity": "HIGH"})));
        assert!(!finding_dirties_attack_graph(&json!({"severity": "info"})));
        assert!(!finding_dirties_attack_graph(
            &json!({"severity": "medium"})
        ));
        assert!(!finding_dirties_attack_graph(&json!({})));
    }

    #[test]
    fn report_json_is_honest_live_shape() {
        let r = SwarmAttachReport {
            agents_seen: 2,
            agents_attached: 1,
            tasks_enqueued: 5,
            tasks_live: 4,
            skipped_recent: 3,
        };
        let v = r.to_json();
        assert_eq!(v["ok"], true);
        assert_eq!(v["swarm_attach"], true);
        assert_eq!(v["agents_seen"], 2);
        assert_eq!(v["tasks_live"], 4);
        assert_eq!(v["pack_size"], SWARM_ATTACH_PACK.len());
        assert!(v["pack"].as_array().unwrap().len() == SWARM_ATTACH_PACK.len());
    }
}
