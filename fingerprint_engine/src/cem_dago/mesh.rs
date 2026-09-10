//! Fork-join cognitive mesh executor — dispatch-on-id, isolated lanes, pivot, council.
//!
//! Wave join is **always** `futures::future::join_all` / `tokio::join!`.
//! `try_join!` / `try_join_all` would abort sibling engines on the first timeout
//! (e.g. Modbus failure killing the web half of the same wave).

use super::blackboard::ScanBlackboard;
use super::lanes::partition_lanes;
use super::pivot::{
    alternative_signals_from_cached, fallback_engine_ids, ingest_live_signals, load_risk_graph,
    resident_graph, store_graph, CachedRiskGraph, ResidentRiskGraph,
};
use super::planner::{trigger_supreme_council_planner, PlannerInput};
use super::record_engine_result;
use super::router::next_ready_wave;
use crate::engine_dispatch::{self, EngineRunContext};
use crate::engine_resilience;
use crate::engine_result::EngineResult;
use futures::future::join_all;
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use tokio::sync::{Mutex, Semaphore};

const PIVOT_CAP: usize = 4;
const MAX_WAVES: u32 = 48;

#[derive(Clone)]
pub struct MeshRequest {
    pub pool: Arc<PgPool>,
    pub target: String,
    pub engines: Vec<String>,
    pub ctx: EngineRunContext,
    pub blackboard: Arc<ScanBlackboard>,
    pub read_only_pool: Option<Arc<PgPool>>,
}

impl std::fmt::Debug for MeshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshRequest")
            .field("target", &self.target)
            .field("engines", &self.engines.len())
            .field("blackboard", &*self.blackboard)
            .field("has_ro_pool", &self.read_only_pool.is_some())
            .finish_non_exhaustive()
    }
}

/// Fully owned execution context cloned into lane tasks (`Send + Sync + 'static`).
#[derive(Clone)]
struct MeshExec {
    pool: Arc<PgPool>,
    target: String,
    ctx: EngineRunContext,
    blackboard: Arc<ScanBlackboard>,
    read_only_pool: Option<Arc<PgPool>>,
    enabled: Vec<String>,
    /// Tenant DiGraph in ArcSwap. Pivots load() a snapshot; they never hit Postgres
    /// per failure. Waves ingest live blackboard signals (and optionally reload SQL).
    risk_graph: ResidentRiskGraph,
    /// Worker-wide write lock: SQL reload + ArcSwap store + ingest are a single
    /// critical section so two finishing waves cannot Lost-Update the live graph.
    graph_write: Arc<Mutex<()>>,
}

fn worker_graph_write() -> Arc<Mutex<()>> {
    static LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();
    LOCK.get_or_init(|| Arc::new(Mutex::new(()))).clone()
}

impl MeshExec {
    fn from_request(req: &MeshRequest) -> Self {
        Self {
            pool: req.pool.clone(),
            target: req.target.clone(),
            ctx: req.ctx.clone(),
            blackboard: req.blackboard.clone(),
            read_only_pool: req.read_only_pool.clone(),
            enabled: req.engines.clone(),
            risk_graph: resident_graph(CachedRiskGraph::empty()),
            graph_write: worker_graph_write(),
        }
    }
}

/// Bounded 90-day / 25k-row trie pre-warm. Failures never abort the mesh.
async fn attach_payload_trie(exec: &mut MeshExec) {
    let Some(tid) = exec.ctx.tenant_id else {
        return;
    };
    let (trie, stats) =
        super::payload_trie::prewarm_payload_trie(exec.pool.as_ref(), tid, exec.ctx.client_id)
            .await;
    let trie = Arc::new(trie);
    let hits = trie.lookup_target(&exec.target);
    if !hits.is_empty() {
        let payloads: Vec<String> = hits
            .iter()
            .map(|h| h.payload.clone())
            .filter(|p| !p.is_empty())
            .collect();
        crate::pentest_memory::prepend_memory_payloads(&mut exec.ctx.memory_payloads, &payloads);
        let _ = exec
            .blackboard
            .write_evidence(
                "historical_payloads",
                "payload_trie",
                serde_json::json!({
                    "count": hits.len(),
                    "window_days": super::payload_trie::PREWARM_WINDOW_DAYS,
                    "batch_size": super::payload_trie::PREWARM_BATCH_SIZE,
                    "pages_fetched": stats.pages_fetched,
                    "rows_seen": stats.rows_seen,
                    "inserted": stats.inserted,
                    "hit_hard_cap": stats.hit_hard_cap,
                    "engines": hits.iter().map(|h| h.engine.as_str()).collect::<Vec<_>>(),
                }),
            )
            .await;
    }
    exec.ctx.payload_trie = Some(trie);
}

#[derive(Debug, Clone, Serialize)]
pub struct MeshEngineOutcome {
    pub engine_id: String,
    pub success: bool,
    pub findings: Vec<Value>,
    pub message: String,
    pub pivot_of: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PivotEvent {
    pub failed_engine: String,
    pub fallbacks: Vec<String>,
    pub route_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MeshRunReport {
    pub waves: Vec<Vec<String>>,
    pub outcomes: Vec<MeshEngineOutcome>,
    pub pivots: Vec<PivotEvent>,
    pub council_invoked: bool,
    pub council_degraded: bool,
    pub council_error: Option<String>,
}

/// Run enabled mesh engines as blackboard-gated DAG waves with pivot + council.
pub async fn execute_mesh(req: MeshRequest) -> MeshRunReport {
    let mut exec = MeshExec::from_request(&req);
    attach_payload_trie(&mut exec).await;
    {
        let _write = exec.graph_write.lock().await;
        match load_risk_graph(
            exec.pool.as_ref(),
            exec.blackboard.tenant_id(),
            exec.blackboard.client_id(),
        )
        .await
        {
            Ok(g) => {
                tracing::info!(
                    target: "cem_dago",
                    nodes = g.node_count(),
                    edges = g.edge_count(),
                    "loaded scan-resident risk graph (Dijkstra is RAM-only; ArcSwap for live topology)"
                );
                store_graph(&exec.risk_graph, g);
            }
            Err(e) => {
                tracing::warn!(
                    target: "cem_dago",
                    error = %e,
                    "risk graph load failed — pivots use empty resident graph (no per-failure SQL)"
                );
            }
        }
    }
    let mut remaining: HashSet<String> = req.engines.iter().cloned().collect();
    let mut already: HashSet<String> = HashSet::new();
    let mut waves: Vec<Vec<String>> = Vec::new();
    let mut outcomes: Vec<MeshEngineOutcome> = Vec::new();
    let mut pivots: Vec<PivotEvent> = Vec::new();
    let mut council_invoked = false;
    let mut council_degraded = false;
    let mut council_error = None;

    let _ = exec.blackboard.mark_latest().await;

    let mut wave_n = 0u32;
    while !remaining.is_empty() && wave_n < MAX_WAVES {
        wave_n += 1;
        let present: HashSet<String> = exec
            .blackboard
            .present_signals()
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut ready = next_ready_wave(&remaining, &present);
        if ready.is_empty() {
            let last_fail = exec
                .blackboard
                .list_failures()
                .await
                .ok()
                .and_then(|f| f.last().cloned());
            if let Some(fail) = last_fail {
                let step = execute_orchestration_step(
                    &exec,
                    &fail.engine_id,
                    &fail.error_message,
                    &already,
                )
                .await;
                pivots.push(step.event);
                let pivot_dirty = step.outcomes.iter().any(|o| o.success);
                let launched = step.launched;
                for o in step.outcomes {
                    already.insert(o.engine_id.clone());
                    remaining.remove(&o.engine_id);
                    outcomes.push(o);
                }
                if launched == 0 {
                    let c = invoke_council(&exec, &already).await;
                    council_invoked = c.invoked;
                    council_degraded = c.degraded;
                    council_error = c.error.clone();
                    for o in c.outcomes {
                        already.insert(o.engine_id.clone());
                        remaining.remove(&o.engine_id);
                        outcomes.push(o);
                    }
                    break;
                }
                refresh_live_graph(&exec, pivot_dirty).await;
                flush_quarantine(&exec).await;
                continue;
            }
            let rest: Vec<String> = remaining.iter().cloned().collect();
            ready = rest;
        }

        waves.push(ready.clone());
        metrics::counter!("weissman_cem_dago_waves_total").increment(1);

        let wave_out = run_wave(&exec, &ready, None).await;
        let wave_dirty = wave_out.iter().any(|o| o.success);
        for o in wave_out {
            remaining.remove(&o.engine_id);
            already.insert(o.engine_id.clone());
            if !o.success {
                let step =
                    execute_orchestration_step(&exec, &o.engine_id, &o.message, &already).await;
                pivots.push(step.event);
                for p in step.outcomes {
                    remaining.remove(&p.engine_id);
                    already.insert(p.engine_id.clone());
                    outcomes.push(p);
                }
            }
            outcomes.push(o);
        }
        refresh_live_graph(&exec, wave_dirty).await;
        flush_quarantine(&exec).await;
    }

    if !remaining.is_empty() && !council_invoked {
        let c = invoke_council(&exec, &already).await;
        council_invoked = c.invoked;
        council_degraded = c.degraded;
        council_error = c.error;
        for o in &c.outcomes {
            remaining.remove(&o.engine_id);
        }
        outcomes.extend(c.outcomes);
    }

    flush_quarantine(&exec).await;

    MeshRunReport {
        waves,
        outcomes,
        pivots,
        council_invoked,
        council_degraded,
        council_error,
    }
}

struct PivotStep {
    event: PivotEvent,
    outcomes: Vec<MeshEngineOutcome>,
    launched: usize,
}

async fn execute_orchestration_step(
    exec: &MeshExec,
    failed_engine: &str,
    error_message: &str,
    already: &HashSet<String>,
) -> PivotStep {
    let _ = exec
        .blackboard
        .log_engine_failure(failed_engine, &exec.target, error_message)
        .await;
    tracing::info!(
        target: "cem_dago",
        engine = %failed_engine,
        target = %exec.target,
        "engine failed — resolving dynamic fallback path"
    );
    metrics::counter!("weissman_cem_dago_pivots_total").increment(1);

    let route = {
        let g = exec.risk_graph.load();
        alternative_signals_from_cached(&g)
    };

    let fallbacks = fallback_engine_ids(
        failed_engine,
        &exec.enabled,
        already,
        &route.signals,
        PIVOT_CAP,
    );
    let event = PivotEvent {
        failed_engine: failed_engine.to_string(),
        fallbacks: fallbacks.clone(),
        route_signals: route.signals,
    };
    if fallbacks.is_empty() {
        return PivotStep {
            event,
            outcomes: Vec::new(),
            launched: 0,
        };
    }
    let outcomes = run_wave(exec, &fallbacks, Some(failed_engine.to_string())).await;
    let launched = outcomes.len();
    PivotStep {
        event,
        outcomes,
        launched,
    }
}

struct CouncilStep {
    invoked: bool,
    degraded: bool,
    error: Option<String>,
    outcomes: Vec<MeshEngineOutcome>,
}

async fn invoke_council(exec: &MeshExec, already: &HashSet<String>) -> CouncilStep {
    let input = PlannerInput {
        target: exec.target.clone(),
        llm_base_url: exec.ctx.llm_base_url.clone(),
        llm_model: exec.ctx.llm_model.clone(),
        tenant_id: exec.blackboard.tenant_id(),
        enabled: exec.enabled.clone(),
        already: already.clone(),
    };
    let plan = trigger_supreme_council_planner(
        exec.blackboard.as_ref(),
        &input,
        exec.read_only_pool.as_deref(),
    )
    .await;
    if !plan.invoked {
        return CouncilStep {
            invoked: false,
            degraded: plan.degraded,
            error: plan.error,
            outcomes: Vec::new(),
        };
    }
    let Some(offensive) = plan.plan else {
        return CouncilStep {
            invoked: true,
            degraded: plan.degraded,
            error: plan.error,
            outcomes: Vec::new(),
        };
    };
    tracing::info!(
        target: "cem_dago",
        probes = offensive.probes.len(),
        telemetry_rows = plan.telemetry_rows,
        degraded = plan.degraded,
        "council QueryPlan accepted — launching validated probes only"
    );
    let mut outcomes = Vec::new();
    for probe in offensive.probes {
        let result = run_one(exec, &probe.engine_id, &probe.target).await;
        outcomes.push(MeshEngineOutcome {
            engine_id: probe.engine_id,
            success: result.success,
            findings: result.findings,
            message: result.message,
            pivot_of: Some("supreme_council".into()),
        });
    }
    CouncilStep {
        invoked: true,
        degraded: plan.degraded,
        error: plan.error,
        outcomes,
    }
}

/// Split the wave into OT / APT / web lanes and join them without short-circuit.
async fn run_wave(
    exec: &MeshExec,
    ids: &[String],
    pivot_of: Option<String>,
) -> Vec<MeshEngineOutcome> {
    let (ot, apt, web) = partition_lanes(ids);
    let (ot_out, apt_out, web_out) = tokio::join!(
        run_lane(exec, ot, super::ot_max_parallel(), pivot_of.clone()),
        run_lane(exec, apt, super::apt_max_parallel(), pivot_of.clone()),
        run_lane(exec, web, super::max_parallel(), pivot_of),
    );
    let mut out = Vec::with_capacity(ot_out.len() + apt_out.len() + web_out.len());
    out.extend(ot_out);
    out.extend(apt_out);
    out.extend(web_out);
    out
}

/// Bounded `join_all` — every engine's Result is kept. Never `try_join_all`.
async fn run_lane(
    exec: &MeshExec,
    ids: Vec<String>,
    width: usize,
    pivot_of: Option<String>,
) -> Vec<MeshEngineOutcome> {
    if ids.is_empty() {
        return Vec::new();
    }
    let sem = Arc::new(Semaphore::new(width.max(1)));
    let futs = ids.into_iter().map(|eid| {
        let exec = exec.clone();
        let sem = sem.clone();
        let pivot_of = pivot_of.clone();
        async move {
            let _permit = sem.acquire_owned().await.ok();
            let target = exec.target.clone();
            let result = run_one(&exec, &eid, &target).await;
            MeshEngineOutcome {
                engine_id: eid,
                success: result.success,
                findings: result.findings,
                message: result.message,
                pivot_of,
            }
        }
    });
    join_all(futs).await
}

async fn run_one(exec: &MeshExec, engine_id: &str, target: &str) -> EngineResult {
    let ctx = exec.ctx.clone();
    let eid = engine_id.to_string();
    let (result, telem) = engine_resilience::run_with_resilience(
        engine_id,
        target,
        engine_resilience::DEFAULT_ATTEMPT_TIMEOUT,
        move |variant, hint| {
            let mut c = ctx.clone();
            if hint.force_ghost_network {
                engine_dispatch::apply_ghost_escalation(&mut c.stealth);
            }
            let engine = eid.clone();
            async move { engine_dispatch::run_engine(&engine, &variant, &c).await }
        },
    )
    .await;
    crate::engine_telemetry::record(engine_id, &telem);
    record_engine_result(exec.blackboard.as_ref(), engine_id, target, &result).await;
    result
}

async fn refresh_live_graph(exec: &MeshExec, reload_sql: bool) {
    let _write = exec.graph_write.lock().await;
    if reload_sql {
        match load_risk_graph(
            exec.pool.as_ref(),
            exec.blackboard.tenant_id(),
            exec.blackboard.client_id(),
        )
        .await
        {
            Ok(g) => {
                tracing::debug!(
                    target: "cem_dago",
                    nodes = g.node_count(),
                    edges = g.edge_count(),
                    "reloaded risk graph after dirty wave (one SQL, then RAM Dijkstra)"
                );
                store_graph(&exec.risk_graph, g);
            }
            Err(e) => {
                tracing::debug!(
                    target: "cem_dago",
                    error = %e,
                    "live graph SQL reload skipped — ingesting blackboard signals only"
                );
            }
        }
    }
    let signals = exec.blackboard.present_signals().await.unwrap_or_default();
    ingest_live_signals(&exec.risk_graph, &signals);
}

async fn flush_quarantine(exec: &MeshExec) {
    let blobs = exec
        .blackboard
        .persist_and_take_quarantine(exec.pool.as_ref())
        .await;
    if !blobs.is_empty() {
        tracing::error!(
            target: "cem_dago",
            count = blobs.len(),
            "telemetry integrity violations flushed to RLS quarantine"
        );
    }
}

/// Seed the blackboard for a client scan (discovery / OT / internet edge).
pub async fn seed_scan_context(
    blackboard: &ScanBlackboard,
    target: &str,
    target_list: &[String],
    discovered_paths: &[String],
    ot_present: bool,
) {
    let _ = blackboard
        .write_evidence(
            "internet_exposed",
            "orchestrator",
            serde_json::json!({ "target": target, "targets": target_list }),
        )
        .await;
    if !discovered_paths.is_empty() {
        let _ = blackboard
            .write_evidence(
                "discovery_paths",
                "discovery",
                serde_json::json!(discovered_paths),
            )
            .await;
    }
    if ot_present {
        let _ = blackboard
            .write_evidence("ot_protocol", "ot_ics", serde_json::json!(true))
            .await;
    }
    let _ = blackboard.mark_latest().await;
}

/// JSON catalog for `/api/cem-dago/status`.
pub fn status_json() -> Value {
    serde_json::json!({
        "ok": true,
        "enabled": super::is_enabled(),
        "max_parallel": super::max_parallel(),
        "ot_max_parallel": super::ot_max_parallel(),
        "apt_max_parallel": super::apt_max_parallel(),
        "council_enabled": super::council_enabled(),
        "redis_configured": crate::http::rate_limit_redis::is_enabled(),
        "weissman_ro_configured": super::weissman_ro_pool().is_some(),
        "blackboard_ttl_secs": super::BLACKBOARD_TTL_SECS,
        "blackboard_codec": "msgpack_v1",
        "codec_magic": "0xC1",
        "codec_version": super::blackboard::CODEC_VERSION,
        "redis_pool": "sharded_connection_manager",
        "redis_shards": super::redis_pool::redis_shard_count(),
        "graph_cache": "arcswap_live",
        "graph_write": "tokio_mutex_worker",
        "queryplan_sandbox": "ast_whitelist_limit_200",
        "queryplan_limit": super::sql_ast::AST_STRICT_LIMIT,
        "telemetry_quarantine": true,
        "telemetry_quarantine_global": true,
        "redis_acquire_timeout_ms": super::redis_pool::REDIS_ACQUIRE_TIMEOUT.as_millis() as u64,
        "redis_op_timeout_ms": 50,
        "wave_join": "join_all",
        "dispatch": "id_lookup_not_dyn_trait",
        "pipeline_special_engines": super::PIPELINE_SPECIAL_ENGINES,
        "pattern": "shared_blackboard_plus_active_dag_router",
        "trie_prewarm": {
            "window_days": super::payload_trie::PREWARM_WINDOW_DAYS,
            "batch_size": super::payload_trie::PREWARM_BATCH_SIZE,
            "hard_cap": super::payload_trie::prewarm_hard_cap(),
            "pagination": "keyset_id",
        },
    })
}

/// Manifest dump (id, inputs, outputs, mitre, group) for the UI search table.
pub fn manifests_json(limit: usize) -> Value {
    use weissman_core::models::engine::production_engine_ids;
    let cap = limit.clamp(1, 600);
    let rows: Vec<Value> = production_engine_ids()
        .iter()
        .take(cap)
        .map(|&id| {
            let m = super::manifest_for(id);
            let group = crate::engine_requirements::engine_group(id).unwrap_or("");
            serde_json::json!({
                "id": m.id,
                "group": group,
                "required_inputs": m.required_inputs,
                "output_signals": m.output_signals,
                "mitre_techniques": m.mitre_techniques,
                "edge_kinds": m.edge_kinds,
            })
        })
        .collect();
    serde_json::json!({
        "ok": true,
        "count": rows.len(),
        "manifests": rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_pattern() {
        let v = status_json();
        assert_eq!(v["ok"], true);
        assert_eq!(v["pattern"], "shared_blackboard_plus_active_dag_router");
        assert_eq!(v["wave_join"], "join_all");
        assert_eq!(v["blackboard_codec"], "msgpack_v1");
        assert_eq!(v["codec_magic"], "0xC1");
        assert_eq!(v["redis_pool"], "sharded_connection_manager");
        assert_eq!(v["graph_cache"], "arcswap_live");
        assert_eq!(v["graph_write"], "tokio_mutex_worker");
        assert_eq!(v["queryplan_sandbox"], "ast_whitelist_limit_200");
        assert_eq!(v["queryplan_limit"], 200);
        assert_eq!(v["telemetry_quarantine"], true);
        assert_eq!(v["telemetry_quarantine_global"], true);
        assert_eq!(v["redis_acquire_timeout_ms"], 50);
        assert_eq!(v["redis_op_timeout_ms"], 50);
        assert_eq!(v["dispatch"], "id_lookup_not_dyn_trait");
        assert_eq!(v["trie_prewarm"]["batch_size"], 25_000);
        assert_eq!(v["trie_prewarm"]["window_days"], 90);
        assert_eq!(v["trie_prewarm"]["pagination"], "keyset_id");
    }

    #[tokio::test]
    async fn join_all_keeps_sibling_outcomes_on_failure() {
        // Contract: a failed engine Result must not drop siblings (the try_join trap).
        async fn one(id: &str, ok: bool, msg: &str) -> MeshEngineOutcome {
            MeshEngineOutcome {
                engine_id: id.to_string(),
                success: ok,
                findings: if ok {
                    vec![serde_json::json!({"evidence": true})]
                } else {
                    vec![]
                },
                message: msg.to_string(),
                pivot_of: None,
            }
        }
        let out = join_all(vec![
            one("modbus_tcp", false, "timeout"),
            one("graphql_attack", true, "ok"),
        ])
        .await;
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .any(|o| o.engine_id == "modbus_tcp" && !o.success));
        assert!(out
            .iter()
            .any(|o| o.engine_id == "graphql_attack" && o.success));
    }

    #[tokio::test]
    async fn graph_write_mutex_serializes_store_then_ingest() {
        let cache = resident_graph(CachedRiskGraph::empty());
        let lock = worker_graph_write();
        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let run = |tag_store: &'static str, tag_ingest: &'static str| {
            let cache = cache.clone();
            let lock = lock.clone();
            let order = order.clone();
            async move {
                let _g = lock.lock().await;
                order.lock().await.push(tag_store);
                store_graph(&cache, CachedRiskGraph::empty());
                tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                ingest_live_signals(&cache, &["ot_protocol".into(), "web_port_active".into()]);
                order.lock().await.push(tag_ingest);
            }
        };
        tokio::join!(run("s1", "i1"), run("s2", "i2"));
        let o = order.lock().await.clone();
        assert!(
            o == ["s1", "i1", "s2", "i2"] || o == ["s2", "i2", "s1", "i1"],
            "store+ingest must be a single critical section, got {o:?}"
        );
        let snap = cache.load();
        assert!(snap.has_label("ot_protocol"));
        assert!(snap.has_label("web_port_active"));
    }
}
