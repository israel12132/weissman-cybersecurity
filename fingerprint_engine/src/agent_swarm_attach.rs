//! Attach leftover attack / scan / findings detections to every live
//! endpoint agent.
//!
//! Fleet round-robin (`enqueue_and_dispatch_fleet`) delivers one engine to
//! **one** host. Operators asked to attach a helper to **every** agent that is
//! already online and improve what it already does: attack, scan, and
//! finding discovery. This module fans the **zero-gap** leftover pack — every
//! `AGENT_REQUIRED_ENGINES` id except dual-control skips, plus hybrid extras —
//! to each WebSocket-live agent without duplicating a recent enroll-baseline
//! or swarm task, never arms `host_isolation` / `ransomware_emulation`, and
//! never fabricates vulnerabilities. Attach itself writes an operational
//! `swarm_attach` info finding so Command Center / Findings have live coverage
//! evidence.

use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;
use weissman_core::models::engine_agent::{
    swarm_attach_pack, AGENT_REQUIRED_ENGINES, SWARM_ATTACH_EXTRAS, SWARM_ATTACH_SKIP,
};

use crate::endpoint_agents::{
    all_agent_uuids_for_tenant, enqueue_task, mark_task_dispatched, AgentRegistry, ServerToAgent,
    AGENT_STATUS_LIMIT, FLEET_MAX_AGENTS,
};

/// Zero-gap helper pack: agent-required leftover + hybrid extras.
pub fn swarm_attach_helper_pack() -> Vec<(&'static str, &'static str)> {
    swarm_attach_pack()
}

fn pack_json() -> Vec<Value> {
    swarm_attach_pack()
        .iter()
        .map(|(e, c)| json!({ "engine": e, "category": c }))
        .collect()
}

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
        let pack = swarm_attach_pack();
        json!({
            "ok": true,
            "swarm_attach": true,
            "agents_seen": self.agents_seen,
            "agents_attached": self.agents_attached,
            "tasks_enqueued": self.tasks_enqueued,
            "tasks_live": self.tasks_live,
            "skipped_recent": self.skipped_recent,
            "pack_size": pack.len(),
            "agent_required_count": AGENT_REQUIRED_ENGINES.len(),
            "skipped_destructive": SWARM_ATTACH_SKIP,
            "pack": pack_json(),
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
        pack_size = swarm_attach_pack().len(),
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
    let mut queued_engines: Vec<String> = Vec::new();
    for (engine, category) in swarm_attach_pack() {
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
                queued_engines.push(engine.to_string());
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
        persist_attach_ledger(
            pool,
            tenant_id,
            client_id,
            agent_uuid,
            report.tasks_enqueued,
            &queued_engines,
        )
        .await;
    }
    report
}

/// Operational finding: honest live coverage, never a fake vulnerability.
async fn persist_attach_ledger(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    agent_uuid: &str,
    queued: u32,
    engines: &[String],
) {
    let pack_len = swarm_attach_pack().len();
    let finding = json!({
        "id": format!("swarm-attach-{agent_uuid}"),
        "type": "swarm_attach",
        "severity": "info",
        "title": "Live agent helper attach (zero-gap pack)",
        "description": format!(
            "Attached {queued} leftover helper task(s) onto live agent {agent_uuid}. Pack size {pack_len}. Dual-control engines skipped: {}.",
            SWARM_ATTACH_SKIP.join(", ")
        ),
        "evidence": {
            "agent_id": agent_uuid,
            "queued_tasks": queued,
            "engines": engines,
            "pack_size": pack_len,
            "skipped_destructive": SWARM_ATTACH_SKIP,
            "trigger": "swarm_attach",
            "live": true
        }
    });
    if let Err(e) =
        crate::endpoint_agents::store_finding(pool, tenant_id, client_id, "swarm_attach", &finding)
            .await
    {
        tracing::warn!(
            target: "agents",
            tenant_id,
            client_id,
            agent = %agent_uuid,
            error = %e,
            "swarm-attach ledger persist failed"
        );
    }
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

/// Live GET payload: pack, leftover engines, recent attach tasks, coverage %.
pub async fn swarm_attach_live_status(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    online: &HashSet<String>,
) -> Value {
    let pack = swarm_attach_pack();
    let pack_engines: Vec<&str> = pack.iter().map(|(e, _)| *e).collect();
    let mut attack = 0u32;
    let mut scan = 0u32;
    let mut findings = 0u32;
    for (_, cat) in &pack {
        match *cat {
            "attack" => attack += 1,
            "scan" => scan += 1,
            _ => findings += 1,
        }
    }

    let rows = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(mut tx) => {
            let r = if let Some(cid) = client_id {
                sqlx::query(
                    r#"SELECT engine, status, created_at, params->>'peer_agent' AS agent_uuid
                         FROM endpoint_agent_tasks
                        WHERE tenant_id = $1
                          AND client_id = $2
                          AND params->>'trigger' = 'swarm_attach'
                          AND created_at > now() - interval '24 hours'
                        ORDER BY created_at DESC
                        LIMIT 4000"#,
                )
                .bind(tenant_id)
                .bind(cid)
                .fetch_all(&mut *tx)
                .await
                .unwrap_or_default()
            } else {
                sqlx::query(
                    r#"SELECT engine, status, created_at, params->>'peer_agent' AS agent_uuid
                         FROM endpoint_agent_tasks
                        WHERE tenant_id = $1
                          AND params->>'trigger' = 'swarm_attach'
                          AND created_at > now() - interval '24 hours'
                        ORDER BY created_at DESC
                        LIMIT 4000"#,
                )
                .bind(tenant_id)
                .fetch_all(&mut *tx)
                .await
                .unwrap_or_default()
            };
            let _ = tx.commit().await;
            r
        }
        Err(_) => Vec::new(),
    };

    let mut tasked: HashSet<String> = HashSet::new();
    let mut per_agent: HashMap<String, HashSet<String>> = HashMap::new();
    let mut recent: Vec<Value> = Vec::new();
    for r in &rows {
        use sqlx::Row;
        let engine: String = r.try_get("engine").unwrap_or_default();
        let status: String = r.try_get("status").unwrap_or_default();
        let agent_uuid: String = r.try_get("agent_uuid").unwrap_or_default();
        let created_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("created_at").ok();
        if !engine.is_empty() {
            tasked.insert(engine.clone());
            if !agent_uuid.is_empty() {
                per_agent
                    .entry(agent_uuid.clone())
                    .or_default()
                    .insert(engine.clone());
            }
        }
        if recent.len() < 40 {
            recent.push(json!({
                "agent_id": agent_uuid,
                "engine": engine,
                "status": status,
                "created_at": created_at.map(|d| d.to_rfc3339()),
            }));
        }
    }

    let leftover: Vec<&str> = pack_engines
        .iter()
        .copied()
        .filter(|e| !tasked.contains(*e))
        .collect();
    let covered = pack_engines.len().saturating_sub(leftover.len());
    let coverage_pct = if pack_engines.is_empty() {
        100.0
    } else {
        ((covered as f64 / pack_engines.len() as f64) * 1000.0).round() / 10.0
    };

    let per_agent_json: Vec<Value> = online
        .iter()
        .map(|aid| {
            let done = per_agent.get(aid).cloned().unwrap_or_default();
            let leftover_for: Vec<&str> = pack_engines
                .iter()
                .copied()
                .filter(|e| !done.contains(*e))
                .collect();
            json!({
                "agent_id": aid,
                "tasked_24h": done.len(),
                "leftover": leftover_for,
                "coverage_pct": if pack_engines.is_empty() {
                    100.0
                } else {
                    ((done.len() as f64 / pack_engines.len() as f64) * 1000.0).round() / 10.0
                },
            })
        })
        .collect();

    json!({
        "ok": true,
        "swarm_attach": true,
        "live_agents": online.len(),
        "pack_size": pack.len(),
        "agent_required_count": AGENT_REQUIRED_ENGINES.len(),
        "skipped_destructive": SWARM_ATTACH_SKIP,
        "extras": SWARM_ATTACH_EXTRAS.iter().map(|(e, c)| json!({"engine": e, "category": c})).collect::<Vec<_>>(),
        "categories": { "attack": attack, "scan": scan, "findings": findings },
        "engines_tasked_24h": tasked.len(),
        "leftover_engines": leftover,
        "coverage_pct": coverage_pct,
        "zero_gap": leftover.is_empty(),
        "recent_tasks": recent,
        "per_agent": per_agent_json,
        "pack": pack_json(),
    })
}

/// Compact slice for GET /api/agents/status (no full pack dump).
pub fn swarm_attach_status_summary(full: &Value) -> Value {
    json!({
        "pack_size": full.get("pack_size").cloned().unwrap_or(json!(0)),
        "coverage_pct": full.get("coverage_pct").cloned().unwrap_or(json!(0.0)),
        "leftover_count": full.get("leftover_engines").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        "engines_tasked_24h": full.get("engines_tasked_24h").cloned().unwrap_or(json!(0)),
        "zero_gap": full.get("zero_gap").cloned().unwrap_or(json!(false)),
        "skipped_destructive": SWARM_ATTACH_SKIP,
    })
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
    use weissman_core::models::engine_agent::is_agent_required_engine;

    #[test]
    fn pack_is_zero_gap_against_agent_required() {
        let pack = swarm_attach_helper_pack();
        let expected =
            AGENT_REQUIRED_ENGINES.len() - SWARM_ATTACH_SKIP.len() + SWARM_ATTACH_EXTRAS.len();
        assert_eq!(
            pack.len(),
            expected,
            "pack must cover every leftover host engine"
        );
        let mut seen = HashSet::new();
        let mut cats = HashSet::new();
        for (engine, cat) in &pack {
            assert!(
                seen.insert(*engine),
                "duplicate swarm-attach engine {engine}"
            );
            assert!(
                matches!(*cat, "attack" | "scan" | "findings"),
                "unexpected category {cat} for {engine}"
            );
            cats.insert(*cat);
            assert!(!SWARM_ATTACH_SKIP.contains(engine));
            if !SWARM_ATTACH_EXTRAS.iter().any(|(e, _)| e == engine) {
                assert!(
                    is_agent_required_engine(engine),
                    "{engine} must be agent-required or an explicit extra"
                );
            }
        }
        for id in AGENT_REQUIRED_ENGINES {
            if SWARM_ATTACH_SKIP.contains(id) {
                assert!(!seen.contains(id), "skip {id} leaked into pack");
            } else {
                assert!(seen.contains(id), "gap: {id} missing from swarm pack");
            }
        }
        for (extra, _) in SWARM_ATTACH_EXTRAS {
            assert!(seen.contains(extra), "extra {extra} missing from pack");
        }
        assert!(cats.contains("attack"));
        assert!(cats.contains("scan"));
        assert!(cats.contains("findings"));
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
        let pack_len = swarm_attach_pack().len();
        assert_eq!(v["ok"], true);
        assert_eq!(v["swarm_attach"], true);
        assert_eq!(v["agents_seen"], 2);
        assert_eq!(v["tasks_live"], 4);
        assert_eq!(v["pack_size"], pack_len);
        assert_eq!(v["pack"].as_array().unwrap().len(), pack_len);
        assert!(v["skipped_destructive"].as_array().unwrap().len() >= 2);
        assert!(pack_len >= AGENT_REQUIRED_ENGINES.len() - 2);
    }
}
