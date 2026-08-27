//! Off-transaction SOAR / FAIR / risk-graph side effects for UEBA anomalies.

use crate::soar_playbook::{dispatch_event, PlaybookEvent};
use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;

use super::stats::{metric_weight, CRITICAL_Z};
use super::AnomalyRecord;

const SOAR_TIMEOUT: Duration = Duration::from_secs(3);
const UEBA_COOLDOWN_SECS: i64 = 3600;

pub fn should_isolate(anomalies: &[AnomalyRecord]) -> bool {
    let failed = anomalies
        .iter()
        .any(|a| a.metric == "failed_logins" && a.z_score.abs() >= 4.0 && a.severity != "medium");
    let new_ports = anomalies.iter().any(|a| a.metric == "open_ports");
    let critical = anomalies
        .iter()
        .any(|a| a.z_score.abs() >= CRITICAL_Z || a.severity == "critical");
    critical || (failed && new_ports)
}

pub fn should_page_oncall(anomalies: &[AnomalyRecord], offhours: bool) -> bool {
    offhours
        && anomalies.iter().any(|a| {
            a.severity == "critical" || a.severity == "high" && a.z_score.abs() >= HIGH_PAGE
        })
}

const HIGH_PAGE: f64 = 6.0;

/// Fire-and-forget after the ingest transaction commits. Timeouts are hard-capped so a slow
/// Slack/webhook cannot stall the worker.
pub fn spawn_post_commit(
    pool: PgPool,
    tenant_id: i64,
    client_id: i64,
    agent_id: String,
    anomalies: Vec<AnomalyRecord>,
    offhours: bool,
) {
    if anomalies.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let isolate = should_isolate(&anomalies);
        let page = should_page_oncall(&anomalies, offhours);
        for a in &anomalies {
            if a.severity != "high" && a.severity != "critical" {
                continue;
            }
            let ev = PlaybookEvent {
                kind: "ueba_anomaly".into(),
                tenant_id,
                client_id: Some(client_id),
                finding_id: None,
                cluster_id: None,
                title: format!("UEBA {} on {}", a.metric, agent_id),
                severity: a.severity.clone(),
                source: "ueba_detector".into(),
                target: agent_id.clone(),
                status: "OPEN".into(),
                cvss: None,
                epss: None,
                kev: false,
                kev_known_ransomware: false,
                cve: None,
                signature_hash: Some(format!("ueba:{}:{}", agent_id, a.metric)),
                internet_exposed: false,
            };
            let pool_c = pool.clone();
            let _ = tokio::time::timeout(SOAR_TIMEOUT, dispatch_event(&pool_c, ev, false)).await;
        }
        if isolate {
            let ev = PlaybookEvent {
                kind: "ueba_isolate".into(),
                tenant_id,
                client_id: Some(client_id),
                finding_id: None,
                cluster_id: None,
                title: format!("UEBA isolate_host {agent_id}"),
                severity: "critical".into(),
                source: "ueba_detector".into(),
                target: agent_id.clone(),
                status: "OPEN".into(),
                cvss: Some(9.0),
                epss: None,
                kev: false,
                kev_known_ransomware: false,
                cve: None,
                signature_hash: Some(format!("ueba-isolate:{agent_id}")),
                internet_exposed: false,
            };
            let evidence = crate::soar::types::ThreatEvidence::from_playbook_event(&ev);
            let cmd = crate::soar::engine::build_command(
                "isolate_host",
                tenant_id,
                Some(client_id),
                None,
                agent_id.clone(),
                serde_json::json!({"target": agent_id, "duration_seconds": 900}),
                evidence,
                false,
            );
            let _ = tokio::time::timeout(
                SOAR_TIMEOUT,
                crate::soar::engine::execute_armored_action(&pool, cmd),
            )
            .await;
            let _ = tokio::time::timeout(SOAR_TIMEOUT, dispatch_event(&pool, ev, false)).await;
            if let Ok(mut tx) = crate::db::begin_tenant_tx(&pool, tenant_id).await {
                let _ = crate::audit_log::insert_audit(
                    &mut tx,
                    tenant_id,
                    None,
                    "ueba_detector",
                    "containment_requested",
                    &format!(
                        "isolate_host agent={} cooldown={}s",
                        agent_id, UEBA_COOLDOWN_SECS
                    ),
                    "",
                )
                .await;
                let _ = tx.commit().await;
            }
        }
        if page {
            let ev = PlaybookEvent {
                kind: "ueba_page".into(),
                tenant_id,
                client_id: Some(client_id),
                finding_id: None,
                cluster_id: None,
                title: format!("UEBA page_oncall {agent_id}"),
                severity: "critical".into(),
                source: "ueba_detector".into(),
                target: agent_id.clone(),
                status: "OPEN".into(),
                cvss: None,
                epss: None,
                kev: false,
                kev_known_ransomware: false,
                cve: None,
                signature_hash: Some(format!("ueba-page:{agent_id}")),
                internet_exposed: false,
            };
            let evidence = crate::soar::types::ThreatEvidence::from_playbook_event(&ev);
            let cmd = crate::soar::engine::build_command(
                "page_oncall",
                tenant_id,
                Some(client_id),
                None,
                agent_id.clone(),
                serde_json::json!({"target": agent_id, "team": "sec-oncall", "severity": "critical"}),
                evidence,
                false,
            );
            let _ = tokio::time::timeout(
                SOAR_TIMEOUT,
                crate::soar::engine::execute_armored_action(&pool, cmd),
            )
            .await;
            let _ = tokio::time::timeout(SOAR_TIMEOUT, dispatch_event(&pool, ev, false)).await;
        }
        let _ = bump_fair_aro(&pool, tenant_id, client_id, &anomalies).await;
        let _ = touch_risk_graph(&pool, tenant_id, client_id, &agent_id, &anomalies).await;
        let _ = metric_weight("failed_logins"); // keep import live if unused in some cfgs
    });
}

async fn bump_fair_aro(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    anomalies: &[AnomalyRecord],
) -> Result<(), sqlx::Error> {
    if !anomalies
        .iter()
        .any(|a| a.severity == "critical" || a.z_score.abs() >= CRITICAL_Z)
    {
        return Ok(());
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    sqlx::query(
        r#"INSERT INTO ueba_fair_events (tenant_id, client_id, aro_floor, detail, created_at)
           VALUES ($1, $2, 2.0, $3, now())"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(format!("critical UEBA anomaly count={}", anomalies.len()))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn touch_risk_graph(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    agent_id: &str,
    anomalies: &[AnomalyRecord],
) -> Result<(), sqlx::Error> {
    if anomalies.is_empty() {
        return Ok(());
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let host_key = format!("ueba:agent:{agent_id}");
    let host_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO risk_graph_nodes (
                tenant_id, client_id, node_type, label, external_id, metadata, graph_key, risk_score, is_choke_point
            ) VALUES ($1, $2, 'asset', $3, $4, '{}', $5, 70, false)
            ON CONFLICT (tenant_id, client_id, graph_key) DO UPDATE SET
                label = EXCLUDED.label,
                risk_score = GREATEST(risk_graph_nodes.risk_score, EXCLUDED.risk_score)
            RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(format!("UEBA host {agent_id}"))
    .bind(agent_id)
    .bind(&host_key)
    .fetch_one(&mut *tx)
    .await?;
    for a in anomalies
        .iter()
        .filter(|a| a.severity == "high" || a.severity == "critical")
    {
        let anom_key = format!(
            "ueba:anom:{}:{}:{}",
            agent_id,
            a.metric,
            Utc::now().timestamp() / 3600
        );
        let anom_id: i64 = sqlx::query_scalar(
            r#"INSERT INTO risk_graph_nodes (
                    tenant_id, client_id, node_type, label, external_id, metadata, graph_key, risk_score, is_choke_point
                ) VALUES ($1, $2, 'finding', $3, $4, '{}', $5, $6, false)
                ON CONFLICT (tenant_id, client_id, graph_key) DO UPDATE SET
                    label = EXCLUDED.label
                RETURNING id"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(format!("UEBA {}", a.metric))
        .bind(agent_id)
        .bind(&anom_key)
        .bind(if a.severity == "critical" { 95 } else { 80 })
        .fetch_one(&mut *tx)
        .await?;
        let _ = sqlx::query(
            r#"INSERT INTO risk_graph_edges (tenant_id, client_id, from_node_id, to_node_id, edge_type, metadata)
               VALUES ($1, $2, $3, $4, 'leads_to', '{"source":"ueba"}')
               ON CONFLICT (tenant_id, client_id, from_node_id, to_node_id, edge_type) DO NOTHING"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(anom_id)
        .bind(host_id)
        .execute(&mut *tx)
        .await;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(metric: &str, z: f64, sev: &str) -> AnomalyRecord {
        AnomalyRecord {
            metric: metric.into(),
            observed: 0.0,
            baseline_mean: 0.0,
            baseline_stddev: 0.0,
            z_score: z,
            severity: sev.into(),
            detail: String::new(),
        }
    }

    #[test]
    fn isolate_on_failed_logins_plus_ports() {
        let a = vec![
            rec("failed_logins", 5.0, "high"),
            rec("open_ports", 1.0, "medium"),
        ];
        assert!(should_isolate(&a));
        assert!(!should_isolate(&[rec("load_1m", 3.2, "medium")]));
    }

    #[test]
    fn page_only_offhours() {
        let a = vec![rec("failed_logins", 7.0, "high")];
        assert!(should_page_oncall(&a, true));
        assert!(!should_page_oncall(&a, false));
    }
}
