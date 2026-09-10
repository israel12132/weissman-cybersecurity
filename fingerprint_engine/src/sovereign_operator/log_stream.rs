//! Live engine log tape for the Sovereign Operator (owner-only).
//!
//! Events are persisted under RLS and published on the telemetry Redis bus so the
//! theater UI and the LLM consumer see the same live truth. No fabricated lines.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_resilience::EngineExecTelemetry;
use crate::engine_result::EngineResult;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;

pub const BUS_CHANNEL: &str = "sovereign_logs";

pub const PHASES: &[&str] = &["entered", "probe", "retry", "finding", "failed", "exited"];

#[derive(Debug, Clone)]
pub struct EngineLogEvent {
    pub tenant_id: i64,
    pub client_id: Option<i64>,
    pub job_id: Option<String>,
    pub engine_id: String,
    pub phase: String,
    pub target: String,
    pub detail: String,
    pub failure_class: Option<String>,
    pub finding_count: Option<i32>,
    pub payload: Value,
}

impl EngineLogEvent {
    pub fn is_valid_phase(phase: &str) -> bool {
        PHASES.iter().any(|p| *p == phase)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "sovereign_engine_log",
            "engine_id": self.engine_id,
            "phase": self.phase,
            "target": self.target,
            "detail": self.detail,
            "job_id": self.job_id,
            "client_id": self.client_id,
            "failure_class": self.failure_class,
            "finding_count": self.finding_count,
            "payload": self.payload,
        })
    }
}

fn spawn_io<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(fut);
    }
}

pub fn emit_phase(
    ctx: &EngineRunContext,
    phase: &str,
    engine_id: &str,
    target: &str,
    payload: Value,
) {
    let Some(tenant_id) = ctx.tenant_id else {
        return;
    };
    let event = EngineLogEvent {
        tenant_id,
        client_id: ctx.client_id,
        job_id: ctx.job_id.clone(),
        engine_id: engine_id.trim().to_string(),
        phase: phase.to_string(),
        target: target.to_string(),
        detail: String::new(),
        failure_class: None,
        finding_count: None,
        payload,
    };
    dispatch_event(ctx.app_pool.clone(), event);
}

pub fn finish_run(ctx: &EngineRunContext, engine_id: &str, target: &str, result: &EngineResult) {
    let Some(tenant_id) = ctx.tenant_id else {
        return;
    };
    let finding_count = i32::try_from(result.findings.len()).unwrap_or(i32::MAX);
    let mut events = Vec::new();
    if finding_count > 0 {
        events.push(EngineLogEvent {
            tenant_id,
            client_id: ctx.client_id,
            job_id: ctx.job_id.clone(),
            engine_id: engine_id.trim().to_string(),
            phase: "finding".into(),
            target: target.to_string(),
            detail: format!("{finding_count} live finding(s)"),
            failure_class: None,
            finding_count: Some(finding_count),
            payload: json!({ "message": result.message }),
        });
    }
    let failed = result.status.eq_ignore_ascii_case("error")
        || result.status.eq_ignore_ascii_case("failed")
        || result.status.eq_ignore_ascii_case("panic")
        || result.status.eq_ignore_ascii_case("timeout");
    events.push(EngineLogEvent {
        tenant_id,
        client_id: ctx.client_id,
        job_id: ctx.job_id.clone(),
        engine_id: engine_id.trim().to_string(),
        phase: if failed {
            "failed".into()
        } else {
            "exited".into()
        },
        target: target.to_string(),
        detail: result.message.clone(),
        failure_class: None,
        finding_count: Some(finding_count),
        payload: json!({ "status": result.status }),
    });
    dispatch_events(ctx.app_pool.clone(), events);
}

pub fn emit_resilience(
    tenant_id: i64,
    client_id: Option<i64>,
    job_id: Option<String>,
    engine_id: &str,
    target: &str,
    pool: Option<Arc<PgPool>>,
    telem: &EngineExecTelemetry,
) {
    if telem.attempts <= 1 {
        return;
    }
    dispatch_event(
        pool,
        EngineLogEvent {
            tenant_id,
            client_id,
            job_id,
            engine_id: engine_id.trim().to_string(),
            phase: "retry".into(),
            target: target.to_string(),
            detail: format!(
                "attempts={} status={} strategy={}",
                telem.attempts, telem.status, telem.strategy
            ),
            failure_class: telem.failure_class.clone(),
            finding_count: None,
            payload: telem.to_json(),
        },
    );
}

fn dispatch_event(pool: Option<Arc<PgPool>>, event: EngineLogEvent) {
    dispatch_events(pool, vec![event]);
}

fn dispatch_events(pool: Option<Arc<PgPool>>, events: Vec<EngineLogEvent>) {
    spawn_io(async move {
        for event in events {
            if let Some(pool) = pool.as_ref() {
                if let Err(e) = persist(pool.as_ref(), &event).await {
                    tracing::warn!(target: "sovereign_operator", error = %e, "engine log persist failed");
                }
            }
            let wire = crate::http::tenant_stream::stamp_value(event.tenant_id, event.to_json());
            crate::telemetry_bus::publish_bus("telemetry", &wire).await;
            crate::telemetry_bus::publish_bus(BUS_CHANNEL, &wire).await;
        }
    });
}

pub async fn persist(pool: &PgPool, event: &EngineLogEvent) -> Result<i64, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, event.tenant_id).await?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO weissman_sovereign_engine_logs
               (tenant_id, client_id, job_id, engine_id, phase, target, detail,
                failure_class, finding_count, payload)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
           RETURNING id"#,
    )
    .bind(event.tenant_id)
    .bind(event.client_id)
    .bind(event.job_id.as_deref())
    .bind(&event.engine_id)
    .bind(&event.phase)
    .bind(&event.target)
    .bind(&event.detail)
    .bind(event.failure_class.as_deref())
    .bind(event.finding_count)
    .bind(&event.payload)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn list_since(
    pool: &PgPool,
    tenant_id: i64,
    since_id: i64,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, client_id, job_id, engine_id, phase, target, detail,
                  failure_class, finding_count, payload,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts
           FROM weissman_sovereign_engine_logs
           WHERE id > $1
           ORDER BY id ASC
           LIMIT $2"#,
    )
    .bind(since_id)
    .bind(limit.clamp(1, 200))
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows.into_iter().map(row_to_event).collect())
}

/// Newest `limit` rows, returned oldest-first so the theater tape reads top→bottom.
pub async fn list_recent(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, client_id, job_id, engine_id, phase, target, detail,
                  failure_class, finding_count, payload,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts
           FROM weissman_sovereign_engine_logs
           ORDER BY id DESC
           LIMIT $1"#,
    )
    .bind(limit.clamp(1, 200))
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let mut out: Vec<Value> = rows.into_iter().map(row_to_event).collect();
    out.reverse();
    Ok(out)
}

fn row_to_event(r: sqlx::postgres::PgRow) -> Value {
    json!({
        "id": r.try_get::<i64,_>("id").ok(),
        "client_id": r.try_get::<Option<i64>,_>("client_id").ok().flatten(),
        "job_id": r.try_get::<Option<String>,_>("job_id").ok().flatten(),
        "engine_id": r.try_get::<String,_>("engine_id").ok(),
        "phase": r.try_get::<String,_>("phase").ok(),
        "target": r.try_get::<String,_>("target").ok(),
        "detail": r.try_get::<String,_>("detail").ok(),
        "failure_class": r.try_get::<Option<String>,_>("failure_class").ok().flatten(),
        "finding_count": r.try_get::<Option<i32>,_>("finding_count").ok().flatten(),
        "payload": r.try_get::<Value,_>("payload").ok().unwrap_or(json!({})),
        "ts": r.try_get::<String,_>("ts").ok(),
    })
}

/// Open engine windows: latest event per (engine, job) in the last two hours.
pub async fn live_windows(pool: &PgPool, tenant_id: i64) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT DISTINCT ON (engine_id, COALESCE(job_id, ''))
                  id, client_id, job_id, engine_id, phase, target, detail,
                  failure_class, finding_count,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts
           FROM weissman_sovereign_engine_logs
           WHERE created_at > now() - interval '2 hours'
           ORDER BY engine_id, COALESCE(job_id, ''), id DESC
           LIMIT 64"#,
    )
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            let phase: String = r.try_get("phase").unwrap_or_default();
            let open = matches!(phase.as_str(), "entered" | "probe" | "retry" | "finding");
            json!({
                "id": r.try_get::<i64,_>("id").ok(),
                "client_id": r.try_get::<Option<i64>,_>("client_id").ok().flatten(),
                "job_id": r.try_get::<Option<String>,_>("job_id").ok().flatten(),
                "engine_id": r.try_get::<String,_>("engine_id").ok(),
                "phase": phase,
                "target": r.try_get::<String,_>("target").ok(),
                "detail": r.try_get::<String,_>("detail").ok(),
                "failure_class": r.try_get::<Option<String>,_>("failure_class").ok().flatten(),
                "finding_count": r.try_get::<Option<i32>,_>("finding_count").ok().flatten(),
                "ts": r.try_get::<String,_>("ts").ok(),
                "open": open,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_are_canonical() {
        for p in PHASES {
            assert!(EngineLogEvent::is_valid_phase(p));
        }
        assert!(!EngineLogEvent::is_valid_phase("started"));
        assert!(!EngineLogEvent::is_valid_phase(""));
    }

    #[test]
    fn to_json_marks_live_type() {
        let ev = EngineLogEvent {
            tenant_id: 1,
            client_id: Some(9),
            job_id: Some("j1".into()),
            engine_id: "osint".into(),
            phase: "entered".into(),
            target: "https://example.com".into(),
            detail: String::new(),
            failure_class: None,
            finding_count: None,
            payload: json!({}),
        };
        let v = ev.to_json();
        assert_eq!(v["type"], "sovereign_engine_log");
        assert_eq!(v["engine_id"], "osint");
        assert_eq!(v["phase"], "entered");
    }
}
