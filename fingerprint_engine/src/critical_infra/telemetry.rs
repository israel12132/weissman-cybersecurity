//! Immediate, unbatched telemetry for critical-infrastructure engine activity.

use crate::engine_dispatch::EngineRunContext;
use serde_json::{json, Value};

/// Broadcast engine execution to Command Center — bypasses standard batching delays.
pub async fn emit_critical_risk_execution(
    ctx: &EngineRunContext,
    engine_id: &str,
    target: &str,
    findings_count: usize,
    message: &str,
) {
    let payload = json!({
        "event": "critical_risk_alert",
        "risk_class": "CRITICAL_RISK",
        "telemetry_priority": "immediate",
        "bypass_batch": true,
        "phase": "critical_infra_execution",
        "engine_id": engine_id,
        "target": target,
        "findings_count": findings_count,
        "message": message,
        "tenant_id": ctx.tenant_id,
        "client_id": ctx.client_id,
        "job_id": ctx.job_id,
        "severity": if findings_count > 0 { "critical" } else { "info" },
    });
    fanout(ctx, &payload).await;
    tracing::warn!(
        target: "critical_infra_telemetry",
        engine_id = %engine_id,
        target_host = %target,
        findings_count,
        "CRITICAL_RISK engine execution — immediate alert emitted"
    );
}

/// Per-finding immediate alert after persistence path (or inline from engine run).
pub async fn emit_critical_risk_finding(
    ctx: &EngineRunContext,
    engine_id: &str,
    target: &str,
    finding: &Value,
) {
    let title = finding
        .get("title")
        .or_else(|| finding.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("critical infrastructure finding");
    let severity = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("critical");
    let payload = json!({
        "event": "critical_risk_finding",
        "risk_class": "CRITICAL_RISK",
        "telemetry_priority": "immediate",
        "bypass_batch": true,
        "phase": "critical_infra_finding",
        "engine_id": engine_id,
        "target": target,
        "finding_title": title,
        "severity": severity,
        "tenant_id": ctx.tenant_id,
        "client_id": ctx.client_id,
        "job_id": ctx.job_id,
        "finding": finding,
    });
    fanout(ctx, &payload).await;
}

/// Persist-time alert when `risk_class` is present on a stored finding (no EngineRunContext).
pub async fn emit_critical_risk_finding_persisted(
    tenant_id: i64,
    client_id: i64,
    engine: &str,
    target: &str,
    finding_id: &str,
    title: &str,
    severity: &str,
) {
    let payload = json!({
        "event": "critical_risk_finding",
        "risk_class": "CRITICAL_RISK",
        "telemetry_priority": "immediate",
        "bypass_batch": true,
        "phase": "critical_infra_persisted",
        "engine_id": engine,
        "target": target,
        "finding_id": finding_id,
        "finding_title": title,
        "severity": severity,
        "tenant_id": tenant_id,
        "client_id": client_id,
    });
    let wire = payload.to_string();
    crate::telemetry_bus::publish_bus("telemetry", &wire).await;
    crate::telemetry_bus::publish_bus("war_room", &wire).await;
    tracing::warn!(
        target: "critical_infra_telemetry",
        engine_id = %engine,
        finding_id = %finding_id,
        "CRITICAL_RISK finding persisted — immediate alert emitted"
    );
}

async fn fanout(ctx: &EngineRunContext, payload: &Value) {
    let wire = payload.to_string();
    if let Some(tx) = &ctx.swarm_broadcast {
        let _ = tx.send(wire.clone());
    }
    crate::telemetry_bus::publish_bus("telemetry", &wire).await;
    crate::telemetry_bus::publish_bus("war_room", &wire).await;
}
