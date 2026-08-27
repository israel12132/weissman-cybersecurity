//! Supreme Nerve Center — live operational truth for CEO / superadmin only.
//! Aggregates in-flight engine runs, async jobs, process telemetry, and subsystem health.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::OnceLock;
use std::time::Instant;
use weissman_core::models::engine::PRODUCTION_ENGINE_IDS;

const STUCK_HEARTBEAT_SECS: i64 = 120;
const STUCK_RUN_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize)]
pub struct LiveEngineRun {
    pub job_id: String,
    pub engine_id: String,
    pub target: String,
    pub tenant_id: i64,
    pub client_id: Option<i64>,
    pub phase: String,
    pub phase_detail: String,
    pub started_at: DateTime<Utc>,
    #[serde(skip)]
    pub started_instant: Instant,
    pub last_phase_at: DateTime<Utc>,
}

fn live_runs() -> &'static DashMap<String, LiveEngineRun> {
    static S: OnceLock<DashMap<String, LiveEngineRun>> = OnceLock::new();
    S.get_or_init(DashMap::new)
}

/// Worker invoked an engine run — register for nerve-center live view.
pub fn run_start(
    job_id: &str,
    engine_id: &str,
    target: &str,
    tenant_id: i64,
    client_id: Option<i64>,
    phase: &str,
    detail: &str,
) {
    let now = Utc::now();
    live_runs().insert(
        job_id.to_string(),
        LiveEngineRun {
            job_id: job_id.to_string(),
            engine_id: engine_id.to_string(),
            target: target.to_string(),
            tenant_id,
            client_id,
            phase: phase.to_string(),
            phase_detail: detail.to_string(),
            started_at: now,
            started_instant: Instant::now(),
            last_phase_at: now,
        },
    );
}

pub fn run_phase(job_id: &str, phase: &str, detail: Option<&str>) {
    if let Some(mut entry) = live_runs().get_mut(job_id) {
        entry.phase = phase.to_string();
        if let Some(d) = detail {
            entry.phase_detail = d.to_string();
        }
        entry.last_phase_at = Utc::now();
    }
}

pub fn run_end(job_id: &str) {
    live_runs().remove(job_id);
}

/// Idle seconds since last phase tick for an in-process engine run, if any.
#[must_use]
pub fn live_run_phase(job_id: &str) -> Option<(String, i64)> {
    let r = live_runs().get(job_id)?;
    let idle = Utc::now()
        .signed_duration_since(r.last_phase_at)
        .num_seconds()
        .max(0);
    Some((r.phase.clone(), idle))
}

/// RAII guard — removes the in-flight run when the job arm returns (Ok or Err).
pub struct RunGuard {
    job_id: String,
}

impl RunGuard {
    #[must_use]
    pub fn start(
        job_id: &str,
        engine_id: &str,
        target: &str,
        tenant_id: i64,
        client_id: Option<i64>,
        phase: &str,
        detail: &str,
    ) -> Self {
        run_start(
            job_id, engine_id, target, tenant_id, client_id, phase, detail,
        );
        Self {
            job_id: job_id.to_string(),
        }
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        run_end(&self.job_id);
    }
}

fn lifecycle_from_job_and_live(
    engine_id: &str,
    live: Option<&LiveEngineRun>,
    job: Option<&Value>,
) -> (String, Option<String>) {
    if let Some(r) = live {
        let idle_secs = Utc::now()
            .signed_duration_since(r.last_phase_at)
            .num_seconds();
        if idle_secs > STUCK_RUN_SECS {
            return (
                "stuck".into(),
                Some(format!(
                    "no phase update for {idle_secs}s (phase={})",
                    r.phase
                )),
            );
        }
        return ("running".into(), None);
    }
    if let Some(j) = job {
        let status = j
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        if status == "running" || status == "pending" {
            let hb_stale = j
                .get("heartbeat_stale_secs")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if hb_stale > STUCK_HEARTBEAT_SECS {
                return (
                    "stuck".into(),
                    Some(format!("worker heartbeat stale {hb_stale}s")),
                );
            }
            return ("running".into(), None);
        }
    }
    let telem = crate::engine_telemetry::snapshot();
    if let Some((_, h)) = telem.iter().find(|(id, _)| id == engine_id) {
        if h.last_status != "ok" && h.total_runs > 0 {
            return ("failed".into(), h.last_error.clone());
        }
        if h.total_runs > 0 {
            return ("idle".into(), None);
        }
    }
    ("idle".into(), None)
}

/// Full nerve-center snapshot (live DB + in-process registries).
pub async fn build_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    uptime_secs: u64,
) -> Result<Value, sqlx::Error> {
    let now = Utc::now();

    let job_rows = sqlx::query(
        r#"SELECT id::text AS id, kind, status, worker_id, heartbeat_at, created_at, updated_at,
                  attempt_count, last_error, payload
           FROM weissman_async_jobs
           WHERE tenant_id = $1 AND status IN ('pending', 'running')
           ORDER BY updated_at DESC
           LIMIT 500"#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let mut live_jobs: Vec<Value> = Vec::new();
    let mut engine_job_map: std::collections::HashMap<String, Value> =
        std::collections::HashMap::new();

    for r in &job_rows {
        let payload: Value = r.try_get::<Value, _>("payload").unwrap_or(json!({}));
        let engine_from_payload = payload
            .get("engine")
            .and_then(Value::as_str)
            .map(str::to_string);
        let hb = r
            .try_get::<Option<DateTime<Utc>>, _>("heartbeat_at")
            .ok()
            .flatten();
        let hb_stale = hb
            .map(|t| now.signed_duration_since(t).num_seconds())
            .unwrap_or(9999);
        let job_v = json!({
            "id": r.try_get::<String, _>("id").unwrap_or_default(),
            "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
            "status": r.try_get::<String, _>("status").unwrap_or_default(),
            "worker_id": r.try_get::<Option<String>, _>("worker_id").ok().flatten(),
            "heartbeat_at": hb.map(|t| t.to_rfc3339()),
            "heartbeat_stale_secs": hb_stale,
            "created_at": r.try_get::<DateTime<Utc>, _>("created_at").ok().map(|t| t.to_rfc3339()),
            "updated_at": r.try_get::<DateTime<Utc>, _>("updated_at").ok().map(|t| t.to_rfc3339()),
            "attempt_count": r.try_get::<i32, _>("attempt_count").unwrap_or(0),
            "last_error": r.try_get::<Option<String>, _>("last_error").ok().flatten(),
            "engine_id": engine_from_payload,
            "client_id": payload.get("client_id"),
            "target": payload.get("target"),
        });
        if let Some(ref eid) = engine_from_payload {
            engine_job_map.insert(eid.clone(), job_v.clone());
        }
        live_jobs.push(job_v);
    }

    let telem_map: std::collections::HashMap<String, crate::engine_telemetry::EngineHealth> =
        crate::engine_telemetry::snapshot().into_iter().collect();

    let mut engines: Vec<Value> = Vec::with_capacity(PRODUCTION_ENGINE_IDS.len());
    let mut running = 0u32;
    let mut stuck = 0u32;

    for &eid in PRODUCTION_ENGINE_IDS {
        let live_by_engine = live_runs()
            .iter()
            .find(|e| e.engine_id == eid)
            .map(|e| e.value().clone());

        let live_ref = live_by_engine.as_ref();
        let job_ref = engine_job_map.get(eid);
        let (lifecycle, stuck_reason) = lifecycle_from_job_and_live(eid, live_ref, job_ref);

        match lifecycle.as_str() {
            "running" => running += 1,
            "stuck" => stuck += 1,
            _ => {}
        }

        let telem = telem_map.get(eid);
        engines.push(json!({
            "engine_id": eid,
            "lifecycle": lifecycle,
            "stuck_reason": stuck_reason,
            "phase": live_ref.map(|r| r.phase.clone()).unwrap_or_default(),
            "phase_detail": live_ref.map(|r| r.phase_detail.clone()).unwrap_or_default(),
            "elapsed_ms": live_ref.map(|r| r.started_instant.elapsed().as_millis() as u64),
            "job_id": live_ref.map(|r| r.job_id.clone())
                .or_else(|| job_ref.and_then(|j| j.get("id")).and_then(Value::as_str).map(str::to_string)),
            "client_id": live_ref.and_then(|r| r.client_id)
                .or_else(|| job_ref.and_then(|j| j.get("client_id")).and_then(Value::as_i64)),
            "target": live_ref.map(|r| r.target.clone())
                .or_else(|| job_ref.and_then(|j| j.get("target")).and_then(Value::as_str).map(str::to_string)),
            "worker_id": job_ref.and_then(|j| j.get("worker_id")).cloned(),
            "last_status": telem.map(|t| t.last_status.clone()).unwrap_or_else(|| "never_run".into()),
            "last_elapsed_ms": telem.map(|t| t.last_elapsed_ms).unwrap_or(0),
            "last_error": telem.and_then(|t| t.last_error.clone()),
            "total_runs": telem.map(|t| t.total_runs).unwrap_or(0),
            "failed_runs": telem.map(|t| t.failed_runs).unwrap_or(0),
        }));
    }

    let modules = build_system_modules(pool, tenant_id, uptime_secs).await;

    let ceo_telem =
        crate::ceo::ops_status::build_ceo_telemetry_json(pool, tenant_id, uptime_secs).await;

    Ok(json!({
        "packet_type": "weissman-supreme-nerve-center-v1",
        "generated_at": now.to_rfc3339(),
        "summary": {
            "engines_total": PRODUCTION_ENGINE_IDS.len(),
            "engines_running": running,
            "engines_stuck": stuck,
            "engines_idle": PRODUCTION_ENGINE_IDS.len() as u32 - running - stuck,
            "live_jobs": live_jobs.len(),
            "in_flight_runs": live_runs().len(),
        },
        "control_parameters": build_control_parameters(),
        "system_modules": modules,
        "engines": engines,
        "live_jobs": live_jobs,
        "ceo_telemetry": ceo_telem,
        "engine_telemetry_aggregate": crate::engine_telemetry::to_json(),
    }))
}

fn build_control_parameters() -> Value {
    json!({
        "weissman_env": std::env::var("WEISSMAN_ENV").unwrap_or_else(|_| "development".into()),
        "redis_configured": crate::http::rate_limit_redis::is_enabled(),
        "redis_required_production": crate::security_startup::production_distributed_state_required(),
        "scanning_active": crate::orchestrator::is_scanning_active(),
        "scanning_env": std::env::var("WEISSMAN_SCANNING_ENABLED").unwrap_or_default(),
        "job_orchestrator_secret_set": std::env::var("WEISSMAN_JOB_ORCHESTRATOR_SECRET")
            .map(|s| s.trim().len() >= 32)
            .unwrap_or(false),
        "fleet_shaping_installed": crate::fleet_shaping::global().is_some(),
        "engine_stack_bytes": std::env::var("WEISSMAN_ENGINE_STACK_BYTES").unwrap_or_else(|_| "8388608".into()),
        "e2e_stack": std::env::var("WEISSMAN_E2E_STACK").ok().as_deref() == Some("1"),
    })
}

async fn build_system_modules(pool: &PgPool, tenant_id: i64, uptime_secs: u64) -> Vec<Value> {
    let pg_ok = sqlx::query_scalar::<_, i64>("SELECT 1::bigint")
        .fetch_one(pool)
        .await
        .is_ok();

    let redis_enabled = crate::http::rate_limit_redis::is_enabled();

    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM weissman_async_jobs WHERE tenant_id = $1 AND status = 'pending'",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let running: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM weissman_async_jobs WHERE tenant_id = $1 AND status = 'running'",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let agents_online: i64 = sqlx::query_scalar(
        r#"SELECT count(*)::bigint FROM endpoint_agents
           WHERE tenant_id = $1 AND last_seen_at > now() - interval '5 minutes'"#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or(0);

    vec![
        module_row(
            "weissman_server",
            "Weissman HTTP Server",
            "core",
            "Axum API, WebSocket, SSE, Command Center static, legal pages.",
            if pg_ok { "healthy" } else { "down" },
            true,
            "serving",
            json!({ "uptime_secs": uptime_secs }),
        ),
        module_row(
            "postgres",
            "PostgreSQL",
            "data",
            "Tenant RLS, async jobs, findings, audit hash chain.",
            if pg_ok { "healthy" } else { "down" },
            pg_ok,
            if pg_ok { "connected" } else { "unreachable" },
            json!({}),
        ),
        module_row(
            "redis",
            "Redis",
            "security",
            "Distributed login lockout, rate limits, job bus, agent registry.",
            if redis_enabled {
                "healthy"
            } else if crate::security_startup::production_distributed_state_required() {
                "down"
            } else {
                "degraded"
            },
            redis_enabled,
            if redis_enabled {
                "connected"
            } else {
                "in_memory_fallback"
            },
            json!({}),
        ),
        module_row(
            "async_job_worker",
            "Async Job Worker",
            "compute",
            "Consumes weissman_async_jobs; runs engine dispatch on large stack.",
            if running > 0 || pending == 0 {
                "healthy"
            } else if pending > 0 {
                "degraded"
            } else {
                "idle"
            },
            true,
            if pending > 0 && running == 0 {
                "backlog_no_worker"
            } else {
                "processing"
            },
            json!({ "pending": pending, "running": running }),
        ),
        module_row(
            "orchestrator",
            "Scan Orchestrator",
            "compute",
            "Tenant scan cycles; active_engines policy from system_configs.",
            if crate::orchestrator::is_scanning_active() {
                "healthy"
            } else {
                "idle"
            },
            true,
            if crate::orchestrator::is_scanning_active() {
                "scanning"
            } else {
                "paused"
            },
            json!({}),
        ),
        module_row(
            "job_bus",
            "Zero-Trust Job Bus",
            "security",
            "HMAC-signed job orchestration across replicas.",
            if std::env::var("WEISSMAN_JOB_ORCHESTRATOR_SECRET")
                .map(|s| s.len() >= 32)
                .unwrap_or(false)
            {
                "healthy"
            } else {
                "degraded"
            },
            true,
            "armed",
            json!({}),
        ),
        module_row(
            "fleet_shaping",
            "Fleet Traffic Shaper",
            "compute",
            "Adaptive rate limits for engine fleet load.",
            if crate::fleet_shaping::global().is_some() {
                "healthy"
            } else {
                "idle"
            },
            crate::fleet_shaping::global().is_some(),
            "coordinator",
            json!({}),
        ),
        module_row(
            "endpoint_agents",
            "Endpoint Agent Fleet",
            "edge",
            "Host-resident detections; timestomp, log integrity, USB, etc.",
            if agents_online > 0 { "healthy" } else { "idle" },
            true,
            "registry",
            json!({ "online_5m": agents_online }),
        ),
        module_row(
            "engine_telemetry",
            "Engine Reliability Telemetry",
            "observability",
            "In-process per-engine run outcomes (Datadog-style).",
            "healthy",
            true,
            "recording",
            crate::engine_telemetry::to_json(),
        ),
        module_row(
            "audit_hash_chain",
            "Audit Log Hash Chain",
            "security",
            "Tamper-evident SHA-256 chain on audit_logs.",
            "healthy",
            true,
            "append_only",
            json!({}),
        ),
        module_row(
            "soar_engine",
            "SOAR Action Engine",
            "response",
            "Durable action executions with idempotency and revert.",
            "healthy",
            true,
            "ready",
            json!({}),
        ),
        module_row(
            "compliance_snapshots",
            "Compliance Evidence Snapshots",
            "governance",
            "DB-backed evidence packs with SHA-256 for auditors.",
            "healthy",
            true,
            "ready",
            json!({}),
        ),
    ]
}

fn module_row(
    id: &str,
    label: &str,
    category: &str,
    description: &str,
    status: &str,
    loaded: bool,
    phase: &str,
    metrics: Value,
) -> Value {
    json!({
        "id": id,
        "label": label,
        "category": category,
        "description": description,
        "status": status,
        "loaded": loaded,
        "phase": phase,
        "metrics": metrics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stuck_when_phase_stale() {
        let mut run = LiveEngineRun {
            job_id: "j1".into(),
            engine_id: "osint".into(),
            target: "https://x".into(),
            tenant_id: 1,
            client_id: None,
            phase: "executing".into(),
            phase_detail: "dispatch".into(),
            started_at: Utc::now() - chrono::Duration::seconds(400),
            started_instant: Instant::now(),
            last_phase_at: Utc::now() - chrono::Duration::seconds(400),
        };
        let (lc, reason) = lifecycle_from_job_and_live("osint", Some(&run), None);
        assert_eq!(lc, "stuck");
        assert!(reason.is_some());

        run.last_phase_at = Utc::now();
        let (lc2, _) = lifecycle_from_job_and_live("osint", Some(&run), None);
        assert_eq!(lc2, "running");
    }
}
