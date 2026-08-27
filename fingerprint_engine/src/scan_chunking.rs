//! Micro-batch (task-chunk) fan-out for `tenant_full_scan`.
//!
//! A monolithic full-estate scan holding the worker's only claim loop is a Self-DoS:
//! one hung fuzz engine (`lease extend failed`) starves SOAR for every tenant.
//!
//! **Design:** the parent `tenant_full_scan` / `onboarding_tenant_scan` job **plans**
//! and **enqueues** claimable `tenant_scan_chunk` jobs (each with its own Redis lease),
//! then completes. Each chunk runs a small engine batch for one client, heartbeats,
//! and checkpoints completed engines so a Force-Abort can resume the remainder.
//!
//! Live-only: chunks call `engine_dispatch::run_engine`. They never fake findings or
//! mark fuzz complete without running it. RoE/stealth is whatever `run_engine` already
//! enforces — this module does not loosen it.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;
use weissman_core::models::engine::{
    is_production_engine_id, resolve_engine_id, DEFAULT_ORCHESTRATOR_ENGINES,
};

use crate::async_job_executor::AsyncJobChannels;
use crate::job_progress;

/// Claimable micro-batch kind. Each row has its own lease + 10s keep-alive.
pub const CHUNK_KIND: &str = "tenant_scan_chunk";

/// Default engines per claimable chunk. Override: `WEISSMAN_SCAN_CHUNK_ENGINES`.
pub const DEFAULT_ENGINES_PER_CHUNK: usize = 6;

#[must_use]
pub fn engines_per_chunk() -> usize {
    std::env::var("WEISSMAN_SCAN_CHUNK_ENGINES")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_ENGINES_PER_CHUNK)
        .clamp(1, 32)
}

/// One planned micro-batch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanChunkSpec {
    pub scan_run_id: String,
    pub chunk_index: usize,
    pub chunk_total: usize,
    pub client_id: i64,
    pub target: String,
    pub engine_ids: Vec<String>,
    /// Engines already finished on a previous attempt of this chunk (resume).
    #[serde(default)]
    pub completed_engines: Vec<String>,
}

/// Split `engines` into batches of `batch` (last batch may be shorter).
#[must_use]
pub fn chunk_engines(engines: &[String], batch: usize) -> Vec<Vec<String>> {
    let n = batch.max(1);
    if engines.is_empty() {
        return Vec::new();
    }
    engines.chunks(n).map(|c| c.to_vec()).collect()
}

/// Engines still to run after a Force-Abort, preserving order.
#[must_use]
pub fn remaining_engines(spec: &ScanChunkSpec) -> Vec<String> {
    spec.engine_ids
        .iter()
        .filter(|e| {
            !spec
                .completed_engines
                .iter()
                .any(|c| c.as_str() == e.as_str())
        })
        .cloned()
        .collect()
}

fn filter_production(ids: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out = Vec::new();
    for s in ids {
        let c = resolve_engine_id(s.trim());
        if is_production_engine_id(c) && !out.iter().any(|x: &String| x == c) {
            out.push(c.to_string());
        }
    }
    out
}

fn client_enabled_engines(client_configs_json: &str) -> Vec<String> {
    let json = client_configs_json.trim();
    if json.is_empty() {
        return filter_production(
            DEFAULT_ORCHESTRATOR_ENGINES
                .iter()
                .map(|s| (*s).to_string()),
        );
    }
    let v: Value = match serde_json::from_str(json) {
        Ok(x) => x,
        _ => {
            return filter_production(
                DEFAULT_ORCHESTRATOR_ENGINES
                    .iter()
                    .map(|s| (*s).to_string()),
            )
        }
    };
    match v.get("enabled_engines").and_then(|a| a.as_array()) {
        Some(arr) => filter_production(
            arr.iter()
                .filter_map(|s| s.as_str().map(|x| x.trim().to_string())),
        ),
        _ => filter_production(
            DEFAULT_ORCHESTRATOR_ENGINES
                .iter()
                .map(|s| (*s).to_string()),
        ),
    }
}

fn primary_target(domains_json: &str, ip_ranges_json: &str, name: &str) -> Option<String> {
    if let Ok(domains) = serde_json::from_str::<Vec<String>>(domains_json.trim()) {
        for d in domains {
            let d = d.trim();
            if d.is_empty() {
                continue;
            }
            if d.starts_with("http://") || d.starts_with("https://") {
                return Some(d.to_string());
            }
            return Some(format!("https://{}", d.trim_start_matches('/')));
        }
    }
    let hosts = crate::ot_ics_engine::resolve_scan_hosts("[]", ip_ranges_json, 1);
    if let Some(h) = hosts.into_iter().next() {
        return Some(format!("http://{h}"));
    }
    let n = name.trim();
    if n.is_empty() {
        None
    } else {
        Some(format!("https://{n}"))
    }
}

#[derive(Debug, Clone)]
struct PlannedClient {
    client_id: i64,
    target: String,
    engines: Vec<String>,
}

async fn load_client_plans(
    app_pool: &PgPool,
    tenant_id: i64,
) -> Result<Vec<PlannedClient>, String> {
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let rows = sqlx::query(
        r#"SELECT id, name,
                  COALESCE(domains, '[]') AS domains,
                  COALESCE(NULLIF(trim(ip_ranges), ''), '[]') AS ip_ranges,
                  COALESCE(client_configs, '') AS client_configs
             FROM clients"#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("list clients: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("clients commit: {e}"))?;

    let mut plans = Vec::new();
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let name: String = r.try_get("name").unwrap_or_default();
        let domains: String = r.try_get("domains").unwrap_or_else(|_| "[]".into());
        let ip_ranges: String = r.try_get("ip_ranges").unwrap_or_else(|_| "[]".into());
        let configs: String = r.try_get("client_configs").unwrap_or_default();
        let Some(target) = primary_target(&domains, &ip_ranges, &name) else {
            continue;
        };
        let engines = client_enabled_engines(&configs);
        if engines.is_empty() {
            continue;
        }
        plans.push(PlannedClient {
            client_id: id,
            target,
            engines,
        });
    }
    Ok(plans)
}

/// Build ordered chunk specs for a new scan run.
#[must_use]
pub fn plan_chunks_from_clients(
    scan_run_id: &str,
    clients: &[(i64, String, Vec<String>)],
    batch: usize,
) -> Vec<ScanChunkSpec> {
    let mut specs = Vec::new();
    for (client_id, target, engines) in clients {
        for group in chunk_engines(engines, batch) {
            specs.push(ScanChunkSpec {
                scan_run_id: scan_run_id.to_string(),
                chunk_index: specs.len(),
                chunk_total: 0,
                client_id: *client_id,
                target: target.clone(),
                engine_ids: group,
                completed_engines: Vec::new(),
            });
        }
    }
    let total = specs.len();
    for s in &mut specs {
        s.chunk_total = total;
    }
    specs
}

fn spec_to_payload(parent_job_id: Uuid, parent_kind: &str, spec: &ScanChunkSpec) -> Value {
    json!({
        "parent_job_id": parent_job_id.to_string(),
        "parent_kind": parent_kind,
        "scan_run_id": spec.scan_run_id,
        "chunk_index": spec.chunk_index,
        "chunk_total": spec.chunk_total,
        "client_id": spec.client_id,
        "target": spec.target,
        "engine_ids": spec.engine_ids,
        "completed_engines": spec.completed_engines,
        "tenant_id": Value::Null,
    })
}

fn spec_from_payload(payload: &Value) -> Result<ScanChunkSpec, String> {
    let scan_run_id = payload
        .get("scan_run_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "payload.scan_run_id required".to_string())?
        .to_string();
    let client_id = payload
        .get("client_id")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| "payload.client_id required".to_string())?;
    let target = payload
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| "payload.target required".to_string())?
        .to_string();
    let engine_ids: Vec<String> = payload
        .get("engine_ids")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if engine_ids.is_empty() {
        return Err("payload.engine_ids must be a non-empty array".into());
    }
    let completed_engines: Vec<String> = payload
        .get("completed_engines")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    Ok(ScanChunkSpec {
        scan_run_id,
        chunk_index: payload
            .get("chunk_index")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        chunk_total: payload
            .get("chunk_total")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        client_id,
        target,
        engine_ids,
        completed_engines,
    })
}

/// Parent `tenant_full_scan` / `onboarding_tenant_scan`: plan + enqueue chunks, return fast.
pub async fn fanout_tenant_scan(
    app_pool: Arc<PgPool>,
    job: &weissman_db::job_queue::AsyncJob,
) -> Result<Value, String> {
    job_progress::mark("fanout_start");
    let scan_run_id = job
        .payload
        .get("scan_run_id")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    persist_scan_run_id(app_pool.as_ref(), job.tenant_id, job.id, &scan_run_id).await?;

    let clients = load_client_plans(app_pool.as_ref(), job.tenant_id).await?;
    job_progress::mark("fanout_clients_loaded");
    let tuples: Vec<(i64, String, Vec<String>)> = clients
        .into_iter()
        .map(|c| (c.client_id, c.target, c.engines))
        .collect();
    let specs = plan_chunks_from_clients(&scan_run_id, &tuples, engines_per_chunk());
    if specs.is_empty() {
        return Ok(json!({
            "ok": true,
            "chunked": true,
            "scan_run_id": scan_run_id,
            "chunks_enqueued": 0,
            "message": "no clients with enabled production engines",
        }));
    }

    let existing = load_existing_chunks(app_pool.as_ref(), job.tenant_id, &scan_run_id).await?;
    let mut chunk_ids = Vec::new();
    let mut skipped_live = 0u32;
    let mut skipped_done = 0u32;
    let mut resumed = 0u32;
    for spec in &specs {
        if let Some(row) = existing.iter().find(|e| e.chunk_index == spec.chunk_index) {
            match row.status.as_str() {
                "pending" | "running" => {
                    skipped_live += 1;
                    continue;
                }
                "completed" => {
                    skipped_done += 1;
                    continue;
                }
                _ => {
                    let mut next = spec.clone();
                    next.completed_engines = row.completed_engines.clone();
                    let remaining = remaining_engines(&next);
                    if remaining.is_empty() {
                        skipped_done += 1;
                        continue;
                    }
                    next.engine_ids = remaining;
                    next.completed_engines.clear();
                    job_progress::mark(&format!("resume_chunk_{}", next.chunk_index));
                    let id = enqueue_chunk_job(app_pool.as_ref(), job, &next, true).await?;
                    resumed += 1;
                    chunk_ids.push(id.to_string());
                    continue;
                }
            }
        }
        job_progress::mark(&format!(
            "enqueue_chunk_{}/{}",
            spec.chunk_index + 1,
            spec.chunk_total
        ));
        let id = enqueue_chunk_job(app_pool.as_ref(), job, spec, false).await?;
        chunk_ids.push(id.to_string());
    }

    tracing::info!(
        target: "scan_chunking",
        parent_job_id = %job.id,
        tenant_id = job.tenant_id,
        scan_run_id = %scan_run_id,
        chunks = chunk_ids.len(),
        resumed,
        skipped_live,
        skipped_done,
        "tenant_full_scan fanned out / resumed micro-batches"
    );

    Ok(json!({
        "ok": true,
        "chunked": true,
        "resumed": resumed > 0,
        "scan_run_id": scan_run_id,
        "chunks_enqueued": chunk_ids.len(),
        "chunk_job_ids": chunk_ids,
        "resumed_chunks": resumed,
        "skipped_live": skipped_live,
        "skipped_completed": skipped_done,
        "engines_per_chunk": engines_per_chunk(),
        "message": "tenant scan split into claimable chunks; each chunk has its own lease",
    }))
}

#[derive(Debug, Clone)]
struct ExistingChunk {
    chunk_index: usize,
    status: String,
    completed_engines: Vec<String>,
}

async fn persist_scan_run_id(
    pool: &PgPool,
    tenant_id: i64,
    job_id: Uuid,
    scan_run_id: &str,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("persist scan_run_id tx: {e}"))?;
    sqlx::query(
        r#"UPDATE weissman_async_jobs
              SET payload = payload || jsonb_build_object('scan_run_id', $2::text),
                  updated_at = now()
            WHERE id = $1 AND tenant_id = $3"#,
    )
    .bind(job_id)
    .bind(scan_run_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("persist scan_run_id: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("persist scan_run_id commit: {e}"))?;
    Ok(())
}

async fn enqueue_chunk_job(
    pool: &PgPool,
    parent: &weissman_db::job_queue::AsyncJob,
    spec: &ScanChunkSpec,
    resumed: bool,
) -> Result<Uuid, String> {
    let mut payload = spec_to_payload(parent.id, &parent.kind, spec);
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("tenant_id".into(), json!(parent.tenant_id));
        if resumed {
            obj.insert("resumed_from".into(), json!("failed"));
        }
    }
    crate::async_jobs::enqueue(
        pool,
        parent.tenant_id,
        CHUNK_KIND,
        payload,
        parent.trace_id.clone(),
    )
    .await
    .map_err(|e| format!("enqueue {CHUNK_KIND}: {e}"))
}

async fn load_existing_chunks(
    pool: &PgPool,
    tenant_id: i64,
    scan_run_id: &str,
) -> Result<Vec<ExistingChunk>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("list chunks tx: {e}"))?;
    let rows = sqlx::query(
        r#"SELECT status, payload, result_json
             FROM weissman_async_jobs
            WHERE tenant_id = $1
              AND kind = $2
              AND payload->>'scan_run_id' = $3"#,
    )
    .bind(tenant_id)
    .bind(CHUNK_KIND)
    .bind(scan_run_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("list chunks: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("list chunks commit: {e}"))?;

    let mut out = Vec::new();
    for row in rows {
        let status: String = row.try_get("status").unwrap_or_default();
        let payload: Value = row
            .try_get::<sqlx::types::Json<Value>, _>("payload")
            .map(|j| j.0)
            .or_else(|_| row.try_get("payload"))
            .unwrap_or(Value::Null);
        let result_json: Option<Value> = row
            .try_get::<Option<sqlx::types::Json<Value>>, _>("result_json")
            .ok()
            .flatten()
            .map(|j| j.0);
        let chunk_index = payload
            .get("chunk_index")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let mut completed = payload
            .get("completed_engines")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if let Some(ref r) = result_json {
            if let Some(done) = r.get("completed_engines").and_then(Value::as_array) {
                completed = done
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
        }
        out.push(ExistingChunk {
            chunk_index,
            status,
            completed_engines: completed,
        });
    }
    Ok(out)
}

/// After Force-Abort, enqueue a successor chunk with engines that never ran.
pub async fn enqueue_resume_after_abort(
    app_pool: &PgPool,
    job: &weissman_db::job_queue::AsyncJob,
    checkpoint: Option<&Value>,
) -> Result<Option<Uuid>, String> {
    let mut spec = spec_from_payload(&job.payload)?;
    if let Some(cp) = checkpoint {
        if let Some(done) = cp.get("completed_engines").and_then(Value::as_array) {
            spec.completed_engines = done
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
    }
    let remaining = remaining_engines(&spec);
    if remaining.is_empty() {
        return Ok(None);
    }
    spec.engine_ids = remaining;
    spec.completed_engines.clear();
    let mut payload = spec_to_payload(job.id, CHUNK_KIND, &spec);
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("tenant_id".into(), json!(job.tenant_id));
        obj.insert("resumed_after_abort".into(), json!(true));
        if let Some(parent) = job.payload.get("parent_job_id") {
            obj.insert("parent_job_id".into(), parent.clone());
        }
    }
    let id = crate::async_jobs::enqueue(
        app_pool,
        job.tenant_id,
        CHUNK_KIND,
        payload,
        job.trace_id.clone(),
    )
    .await
    .map_err(|e| format!("abort-resume enqueue: {e}"))?;
    tracing::info!(
        target: "scan_chunking",
        aborted_job = %job.id,
        resume_job = %id,
        "enqueued successor chunk after Force-Abort"
    );
    Ok(Some(id))
}

/// Run one claimable chunk: real `run_engine` per remaining engine, checkpoint after each.
pub async fn execute_chunk(
    app_pool: Arc<PgPool>,
    channels: &AsyncJobChannels,
    job: &weissman_db::job_queue::AsyncJob,
    worker_id: &str,
) -> Result<Value, String> {
    let mut spec = spec_from_payload(&job.payload)?;
    if let Some(done) = job
        .payload
        .get("completed_engines")
        .and_then(Value::as_array)
    {
        spec.completed_engines = done
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }
    let remaining = remaining_engines(&spec);
    if remaining.is_empty() {
        return Ok(json!({
            "ok": true,
            "chunk_index": spec.chunk_index,
            "completed_engines": spec.completed_engines,
            "message": "chunk already complete (resume)",
        }));
    }

    let (oast_listener_url, oast_domain, oast_api_key) =
        crate::engine_dispatch::load_tenant_oast_configs(app_pool.as_ref(), job.tenant_id).await;
    let intelligence_bus = crate::ws_intelligence_bus::IntelligenceBus::new_shared();
    let mut cross_job_params = json!({});
    let mut completed = spec.completed_engines.clone();
    let mut results = Vec::new();
    let mut succeeded = 0usize;
    let mut failed = 0usize;

    channels.emit_telemetry(
        job.tenant_id,
        &json!({
            "job_id": job.id.to_string(),
            "scan_run_id": spec.scan_run_id,
            "chunk_index": spec.chunk_index,
            "chunk_total": spec.chunk_total,
            "message": format!(
                "Scan chunk {}/{}: {} engine(s) for client {}",
                spec.chunk_index + 1,
                spec.chunk_total.max(1),
                remaining.len(),
                spec.client_id
            ),
            "status": "running",
        })
        .to_string(),
    );

    for engine_id in &remaining {
        job_progress::mark(&format!("engine_begin:{engine_id}"));
        crate::ws_intelligence_bus::merge_params_artifacts(
            &mut cross_job_params,
            &intelligence_bus,
        );
        let ctx = crate::engine_dispatch::EngineRunContext {
            tenant_id: Some(job.tenant_id),
            target_list: vec![spec.target.clone()],
            app_pool: Some(app_pool.clone()),
            agents: Some(crate::endpoint_agents::AgentRegistry::global()),
            client_id: Some(spec.client_id),
            job_params: cross_job_params.clone(),
            intelligence_bus: Some(intelligence_bus.clone()),
            job_id: Some(job.id.to_string()),
            oast_listener_url: oast_listener_url.clone(),
            oast_domain: oast_domain.clone(),
            oast_api_key: oast_api_key.clone(),
            ..Default::default()
        };
        let ctx_ref = &ctx;
        let eid = engine_id.as_str();
        let target = spec.target.clone();
        let (result, telem) = crate::engine_resilience::run_with_resilience(
            eid,
            &target,
            crate::engine_resilience::DEFAULT_ATTEMPT_TIMEOUT,
            move |variant, hint| {
                let mut c = ctx_ref.clone();
                if hint.force_ghost_network {
                    crate::engine_dispatch::apply_ghost_escalation(&mut c.stealth);
                }
                async move { crate::engine_dispatch::run_engine(eid, &variant, &c).await }
            },
        )
        .await;
        crate::engine_telemetry::record(eid, &telem);
        job_progress::mark(&format!("engine_end:{engine_id}"));

        if result.success {
            succeeded += 1;
        } else {
            failed += 1;
        }
        let _ = crate::findings_persist::persist_engine_findings(
            app_pool.as_ref(),
            job.tenant_id,
            Some(spec.client_id),
            engine_id,
            &spec.target,
            &result.findings,
        )
        .await;
        completed.push(engine_id.clone());
        results.push(json!({
            "engine": engine_id,
            "success": result.success,
            "findings_count": result.findings.len(),
            "summary": result.summary,
            "resilience": telem.to_json(),
        }));
        let checkpoint = json!({
            "ok": false,
            "in_progress": true,
            "scan_run_id": spec.scan_run_id,
            "chunk_index": spec.chunk_index,
            "completed_engines": completed,
            "engines": results,
        });
        let _ = weissman_db::job_queue::checkpoint_running_result(
            app_pool.as_ref(),
            job.id,
            worker_id,
            &checkpoint,
        )
        .await;
        channels.emit_telemetry(
            job.tenant_id,
            &json!({
                "job_id": job.id.to_string(),
                "engine_id": engine_id,
                "message": format!(
                    "Chunk {} engine {} → {} findings",
                    spec.chunk_index + 1,
                    engine_id,
                    result.findings.len()
                ),
                "status": "running",
            })
            .to_string(),
        );
    }

    Ok(json!({
        "ok": true,
        "scan_run_id": spec.scan_run_id,
        "chunk_index": spec.chunk_index,
        "chunk_total": spec.chunk_total,
        "client_id": spec.client_id,
        "target": spec.target,
        "succeeded": succeeded,
        "failed": failed,
        "completed_engines": completed,
        "engines": results,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_engines_splits_and_keeps_order() {
        let ids: Vec<String> = (0..10).map(|i| format!("e{i}")).collect();
        let groups = chunk_engines(&ids, 4);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0], vec!["e0", "e1", "e2", "e3"]);
        assert_eq!(groups[2], vec!["e8", "e9"]);
        assert!(chunk_engines(&[], 4).is_empty());
    }

    #[test]
    fn plan_assigns_contiguous_indices_and_totals() {
        let clients = vec![
            (
                1i64,
                "https://a.example".into(),
                vec!["asm".into(), "osint".into(), "http_feedback_fuzz".into()],
            ),
            (2i64, "https://b.example".into(), vec!["asm".into()]),
        ];
        let specs = plan_chunks_from_clients("run-1", &clients, 2);
        assert_eq!(specs.len(), 3);
        assert!(specs.iter().all(|s| s.chunk_total == 3));
        assert_eq!(specs[0].engine_ids, vec!["asm", "osint"]);
        assert_eq!(specs[1].client_id, 1);
        assert_eq!(specs[1].engine_ids, vec!["http_feedback_fuzz"]);
        assert_eq!(specs[2].client_id, 2);
    }

    #[test]
    fn remaining_engines_skips_completed_for_resume() {
        let spec = ScanChunkSpec {
            scan_run_id: "r".into(),
            chunk_index: 0,
            chunk_total: 1,
            client_id: 9,
            target: "https://t".into(),
            engine_ids: vec!["asm".into(), "osint".into(), "http_feedback_fuzz".into()],
            completed_engines: vec!["asm".into()],
        };
        assert_eq!(
            remaining_engines(&spec),
            vec!["osint".to_string(), "http_feedback_fuzz".to_string()]
        );
        let mut successor = spec.clone();
        successor.engine_ids = remaining_engines(&spec);
        successor.completed_engines.clear();
        let payload = spec_to_payload(Uuid::nil(), "tenant_scan_chunk", &successor);
        let back = spec_from_payload(&payload).expect("parse successor");
        assert_eq!(
            back.engine_ids,
            vec!["osint".to_string(), "http_feedback_fuzz".to_string()]
        );
        assert!(
            back.completed_engines.is_empty(),
            "resume chunk must not re-run completed engines"
        );
    }

    #[test]
    fn spec_round_trips_payload() {
        let spec = ScanChunkSpec {
            scan_run_id: "sr".into(),
            chunk_index: 2,
            chunk_total: 5,
            client_id: 44,
            target: "https://x".into(),
            engine_ids: vec!["asm".into()],
            completed_engines: vec![],
        };
        let p = spec_to_payload(Uuid::nil(), "tenant_full_scan", &spec);
        let back = spec_from_payload(&p).expect("parse");
        assert_eq!(back.scan_run_id, spec.scan_run_id);
        assert_eq!(back.client_id, 44);
        assert_eq!(back.engine_ids, spec.engine_ids);
    }

    #[test]
    fn default_batch_is_micro_not_monolithic() {
        assert!(DEFAULT_ENGINES_PER_CHUNK <= 8);
        assert!(DEFAULT_ENGINES_PER_CHUNK >= 1);
    }
}
