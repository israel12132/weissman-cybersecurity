//! Executes rows from `weissman_async_jobs`. The worker binary (`weissman-worker`) is the sole
//! consumer of `execute_job`; the API server does not drain the queue, so with no worker pod
//! running, jobs accumulate as `pending`. Broadcast channels default to no-op sinks when absent.

use crate::db;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

const TOP_TIER_ENGINES: &[&str] = &[
    "nexus_sovereign_swarm",
    "kill_chain",
    "oast_oob",
    "deception_honeypot",
    "digital_twin",
    "zero_day_prediction",
    "threat_emulation",
    "poe_synthesis",
    "satellite_recon",
    "darkweb_intel",
    "financial_osint",
    "blockchain_trace",
    "metadata_harvest",
    "patent_recon",
    "telecom_osint",
    "iot_shodan_scan",
    "job_posting_osint",
    "github_secret_scan",
    "graphql_deep_attack",
    "websocket_attack",
    "grpc_reflection_attack",
    "http2_attack",
];

/// Channels for streaming engines; worker supplies minimal broadcast buses.
#[derive(Clone)]
pub struct AsyncJobChannels {
    pub timing: Arc<broadcast::Sender<String>>,
    pub redteam: Arc<broadcast::Sender<String>>,
    pub radar: Arc<broadcast::Sender<String>>,
    pub swarm: Arc<broadcast::Sender<String>>,
    pub telemetry: Arc<broadcast::Sender<String>>,
}

impl AsyncJobChannels {
    pub fn noop() -> Self {
        fn bus() -> Arc<broadcast::Sender<String>> {
            let (tx, _) = broadcast::channel(8);
            Arc::new(tx)
        }
        Self {
            timing: bus(),
            redteam: bus(),
            radar: bus(),
            swarm: bus(),
            telemetry: bus(),
        }
    }

    /// Broadcast a telemetry payload stamped for `tenant_id` so tenant-scoped SSE/WS
    /// subscribers can filter it (fail-closed: unstamped payloads are dropped downstream).
    pub fn emit_telemetry(&self, tenant_id: i64, raw: &str) {
        let _ = self
            .telemetry
            .send(crate::http::tenant_stream::stamp(tenant_id, raw));
    }

    /// Broadcast a radar payload stamped for `tenant_id`.
    pub fn emit_radar(&self, tenant_id: i64, raw: &str) {
        let _ = self
            .radar
            .send(crate::http::tenant_stream::stamp(tenant_id, raw));
    }

    /// Broadcast a swarm payload stamped for `tenant_id`.
    pub fn emit_swarm(&self, tenant_id: i64, raw: &str) {
        let _ = self
            .swarm
            .send(crate::http::tenant_stream::stamp(tenant_id, raw));
    }

    /// Worker/server channels with Redis cross-replica bridges when `REDIS_URL` is set.
    pub fn from_env() -> Self {
        fn bus(channel: &'static str) -> Arc<broadcast::Sender<String>> {
            let (tx, _) = broadcast::channel(512);
            let arc = Arc::new(tx);
            crate::telemetry_bus::spawn_bridge(channel, (*arc).clone());
            arc
        }
        Self {
            timing: bus("timing"),
            redteam: bus("redteam"),
            radar: bus("radar"),
            swarm: bus("swarm"),
            telemetry: bus("telemetry"),
        }
    }
}

/// Wraps a broadcast sender so every emitted payload is stamped for one tenant.
/// Lets existing `telemetry.send(msg)` call sites stay unchanged while gaining
/// tenant scoping (subscribers drop anything not stamped for their tenant).
#[derive(Clone)]
struct TenantEmitter {
    tx: Arc<broadcast::Sender<String>>,
    tenant_id: i64,
}

impl TenantEmitter {
    fn new(tx: Arc<broadcast::Sender<String>>, tenant_id: i64) -> Self {
        Self { tx, tenant_id }
    }

    fn send(&self, raw: String) {
        let _ = self
            .tx
            .send(crate::http::tenant_stream::stamp(self.tenant_id, &raw));
    }
}

async fn cfg_string_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    key: &str,
) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = $2",
    )
    .bind(tenant_id)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten()
    .filter(|s| !s.is_empty())
}

#[derive(Clone, Default)]
struct TenantRuntimeConfig {
    github_token: Option<String>,
    llm_base_url: Option<String>,
    llm_model: Option<String>,
    oast_listener_url: Option<String>,
    oast_domain: Option<String>,
    oast_api_key: Option<String>,
}

async fn load_tenant_runtime_config(
    pool: Arc<PgPool>,
    tenant_id: i64,
) -> Result<TenantRuntimeConfig, String> {
    let mut tx = db::begin_tenant_tx_arc_retrying(pool, tenant_id, "load_tenant_runtime_config")
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let cfg = TenantRuntimeConfig {
        github_token: cfg_string_tx(&mut tx, tenant_id, "github_token").await,
        llm_base_url: cfg_string_tx(&mut tx, tenant_id, "llm_base_url").await,
        llm_model: cfg_string_tx(&mut tx, tenant_id, "llm_model").await,
        oast_listener_url: cfg_string_tx(&mut tx, tenant_id, "oast_listener_url").await,
        oast_domain: cfg_string_tx(&mut tx, tenant_id, "oast_domain").await,
        oast_api_key: cfg_string_tx(&mut tx, tenant_id, "oast_api_key").await,
    };
    tx.commit()
        .await
        .map_err(|e| format!("tenant config commit: {e}"))?;
    Ok(cfg)
}

/// Reject jobs whose payload carries a conflicting tenant_id (async_jobs table has no RLS).
fn enforce_job_tenant_consistency(job_tenant_id: i64, payload: &Value) -> Result<(), String> {
    if let Some(pt) = payload.get("tenant_id").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    }) {
        if pt != job_tenant_id {
            tracing::error!(
                target: "async_jobs",
                job_tenant_id,
                payload_tenant_id = pt,
                "async job tenant_id mismatch — rejected"
            );
            return Err(format!(
                "payload tenant_id {pt} does not match job tenant {job_tenant_id}"
            ));
        }
    }
    Ok(())
}

async fn enforce_payload_scope_pin_if_present(payload: &Value) -> Result<(), String> {
    let Some(scope) = payload.get("validated_scope") else {
        return Ok(());
    };
    let target = payload
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| "payload.target required when validated_scope is present".to_string())?;
    crate::security_hardening::enforce_execution_scope_pin(target, scope)
        .await
        .map_err(|e| format!("validated_scope pin validation failed: {e}"))
}

fn payload_client_id(p: &Value) -> Option<i64> {
    p.get("client_id").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}

fn engine_job_result_json(
    engine: &str,
    result: &crate::engine_result::EngineResult,
    persisted: u64,
    resilience: Option<Value>,
) -> Value {
    let policy_block = result.is_policy_block();
    json!({
        "engine": engine,
        "status": result.status,
        "findings": result.findings,
        "findings_persisted": persisted,
        "message": result.message,
        "error_code": result.error_code,
        "policy_block": policy_block,
        "reason": if policy_block { Some(result.message.clone()) } else { None },
        "resilience": resilience,
    })
}

async fn persist_findings_best_effort(
    app_pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    engine: &str,
    target: &str,
    findings: &[Value],
) -> u64 {
    if findings.is_empty() || client_id.is_none() {
        return 0;
    }
    crate::findings_persist::persist_engine_findings(
        app_pool, tenant_id, client_id, engine, target, findings,
    )
    .await
    .unwrap_or_else(|e| {
        tracing::error!(
            target: "findings_persist",
            tenant_id,
            engine = %engine,
            error = %e,
            "failed to persist findings"
        );
        0
    })
}

async fn persist_findings_grouped_by_client_field(
    app_pool: &PgPool,
    tenant_id: i64,
    engine: &str,
    default_target: &str,
    findings: &[Value],
) -> u64 {
    use std::collections::HashMap;
    let mut groups: HashMap<i64, Vec<Value>> = HashMap::new();
    for f in findings {
        let Some(cid) = f.get("client_id").and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        }) else {
            continue;
        };
        groups.entry(cid).or_default().push(f.clone());
    }
    let mut total = 0u64;
    for (cid, group) in groups {
        let target = group
            .first()
            .and_then(|f| f.get("target_url").and_then(Value::as_str))
            .unwrap_or(default_target);
        total +=
            persist_findings_best_effort(app_pool, tenant_id, Some(cid), engine, target, &group)
                .await;
    }
    total
}

fn feedback_fuzz_anomaly_to_finding(v: &fuzz_core::ValidatedAnomaly) -> Value {
    let severity = if v.oob_token.is_some() {
        "critical"
    } else {
        "high"
    };
    let title: String = v.anomaly_type.chars().take(500).collect();
    let payload_excerpt: String = v.payload.chars().take(4000).collect();
    let mut description = format!(
        "{}\n\nPayload excerpt:\n{}",
        v.baseline_vs_anomaly, payload_excerpt
    );
    if let Some(ref tok) = v.oob_token {
        description.push_str(&format!("\n\nOAST correlation token: {tok}"));
    }
    if v.llm_user_prompt.is_some() {
        description.push_str(
            "\n\n[Generative] Payload produced by vLLM; see generative_fuzz_winning_payloads.llm_user_prompt.",
        );
    }
    json!({
        "title": title,
        "severity": severity,
        "target_url": v.target_url,
        "description": description,
        "poc": v.payload.chars().take(32_000).collect::<String>(),
        "type": "feedback_fuzz",
        "anomaly_type": v.anomaly_type,
    })
}

/// Run one job to completion JSON (success) or error string (failure).
pub async fn execute_job(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    channels: &AsyncJobChannels,
    job: weissman_db::job_queue::AsyncJob,
) -> Result<Value, String> {
    let scope = crate::fleet_shaping::ProbeScope {
        tenant_id: Some(job.tenant_id),
        shaping_enabled: std::env::var("WEISSMAN_FLEET_SHAPING")
            .ok()
            .map(|v| {
                let l = v.trim().to_ascii_lowercase();
                l != "0" && l != "false" && l != "off"
            })
            .unwrap_or(true),
    };
    let channels = channels.clone();
    // Real scan-duration telemetry: time every job end-to-end and record it as a
    // histogram labelled by kind (feeds the Grafana scan-latency panels + SlowScans alert).
    let kind = job.kind.clone();
    let started = std::time::Instant::now();
    let out = crate::fleet_shaping::with_scope(
        scope,
        execute_job_unscoped(app_pool, intel_pool, auth_pool, channels, job),
    )
    .await;
    metrics::histogram!("weissman_scan_duration_seconds", "kind" => kind)
        .record(started.elapsed().as_secs_f64());
    out
}

async fn execute_job_unscoped(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    channels: AsyncJobChannels,
    job: weissman_db::job_queue::AsyncJob,
) -> Result<Value, String> {
    let tid = job.tenant_id;
    let p = &job.payload;
    enforce_job_tenant_consistency(tid, p)?;
    enforce_payload_scope_pin_if_present(p).await?;
    match job.kind.as_str() {
        "remediation_verify" => {
            // Closed-loop: re-run the engine against the target and confirm the
            // original finding is gone (VERIFIED_FIXED) or still present (REOPENED).
            let engine = p
                .get("engine")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.engine required".to_string())?;
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.target required".to_string())?;
            let finding_id = p
                .get("finding_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.finding_id required".to_string())?;
            let client_id_opt = p.get("client_id").and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            });
            if !weissman_core::models::engine::is_production_engine_id(engine) {
                return Err(format!("engine '{}' is catalog-only or unknown", engine));
            }
            let ctx =
                crate::remediation_verify::verify_context(app_pool.clone(), tid, client_id_opt);
            let outcome = crate::remediation_verify::run_verification(
                app_pool.as_ref(),
                tid,
                client_id_opt,
                engine,
                target,
                finding_id,
                &ctx,
            )
            .await?;
            Ok(serde_json::json!({
                "ok": true,
                "kind": "remediation_verify",
                "finding_id": finding_id,
                "closed": outcome.closed,
                "result_status": outcome.status,
                "rescan_findings": outcome.rescan_finding_count,
            }))
        }
        "command_center_engine" => {
            let engine = p
                .get("engine")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.engine required".to_string())?;
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.target required".to_string())?;
            let client_id_opt = p.get("client_id").and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            });
            let runtime_cfg = load_tenant_runtime_config(app_pool.clone(), tid).await?;
            let mut job_payload = p.clone();
            if let Err(e) = crate::scan_routing::hydrate_stored_job_payload(
                app_pool.as_ref(),
                tid,
                &mut job_payload,
            )
            .await
            {
                tracing::warn!(
                    target: "async_jobs",
                    tenant_id = tid,
                    error = %e,
                    "hydrate_stored_job_payload failed; continuing with stripped payload"
                );
            }
            let job_params = job_payload;
            let discovered_paths: Vec<String> = p
                .get("discovered_paths")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let intelligence_bus = Some(crate::ws_intelligence_bus::IntelligenceBus::new_shared());
            let ctx = crate::engine_dispatch::EngineRunContext {
                tenant_id: Some(tid),
                target_list: vec![target.to_string()],
                discovered_paths,
                github_token: runtime_cfg.github_token,
                llm_base_url: runtime_cfg.llm_base_url.unwrap_or_default(),
                llm_model: runtime_cfg.llm_model.unwrap_or_default(),
                app_pool: Some(app_pool.clone()),
                agents: Some(crate::endpoint_agents::AgentRegistry::global()),
                client_id: client_id_opt,
                job_params,
                job_id: Some(job.id.to_string()),
                swarm_broadcast: Some(channels.swarm.clone()),
                intelligence_bus,
                oast_listener_url: runtime_cfg.oast_listener_url,
                oast_domain: runtime_cfg.oast_domain,
                oast_api_key: runtime_cfg.oast_api_key,
                ..Default::default()
            };
            if !weissman_core::models::engine::is_production_engine_id(engine) {
                return Err(format!("engine '{}' is catalog-only or unknown", engine));
            }
            let _nerve_guard = crate::supreme_nerve_center::RunGuard::start(
                &job.id.to_string(),
                engine,
                target,
                tid,
                client_id_opt,
                "context_hydrate",
                "Tenant config, OAST, stored payload",
            );
            // poe_synthesis has no engine_dispatch runner; route through exploit_synthesis like
            // poe_synthesis_run jobs (scan_routing already uses that kind for direct enqueue).
            let mut last_engine_telemetry: Option<crate::engine_resilience::EngineExecTelemetry> =
                None;
            let result = if engine == "poe_synthesis" {
                let cfg = crate::orchestrator::load_poe_config_http(
                    app_pool.as_ref(),
                    tid,
                    intel_pool.clone(),
                )
                .await
                .map_err(|e| e.to_string())?;
                let wall_secs: u64 = std::env::var("WEISSMAN_POE_JOB_WALL_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(900)
                    .clamp(120, 7200);
                let job_oast_token = p
                    .get("oast_interaction_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                crate::supreme_nerve_center::run_phase(
                    &job.id.to_string(),
                    "executing",
                    Some("poe_synthesis → exploit_synthesis"),
                );
                match tokio::time::timeout(
                    Duration::from_secs(wall_secs),
                    crate::exploit_synthesis_engine::run_exploit_synthesis_async(
                        target,
                        &cfg,
                        None,
                        None,
                        Some(tid),
                        job_oast_token,
                    ),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => crate::engine_result::EngineResult::error(
                        "PoE synthesis exceeded wall-clock budget; check vLLM health and target reachability",
                    ),
                }
            } else {
                // Cross-cutting resilience: panic isolation + adaptive multi-strategy retry +
                // per-attempt timeout. Engine dispatch runs on a large-stack thread so Tokio's
                // default worker stack cannot overflow on deep `dispatch_engine_match` futures.
                let eng = engine.to_string();
                let tgt = target.to_string();
                let ctx_owned = ctx.clone();
                let eng_label = eng.clone();
                crate::supreme_nerve_center::run_phase(
                    &job.id.to_string(),
                    "executing",
                    Some(&format!("dispatch: {engine}")),
                );
                let (res, telem) = crate::engine_stack_runtime::run_on_large_stack(move || {
                    let eng_outer = eng.clone();
                    let tgt = tgt.clone();
                    let ctx_owned = ctx_owned.clone();
                    async move {
                        let eng_ref = eng_outer.clone();
                        crate::engine_resilience::run_with_resilience(
                            &eng_ref,
                            &tgt,
                            crate::engine_resilience::DEFAULT_ATTEMPT_TIMEOUT,
                            move |variant, hint| {
                                let eng = eng_outer.clone();
                                let mut ctx = ctx_owned.clone();
                                // WAF/rate-limit retry → go stealthy on this attempt.
                                if hint.force_ghost_network {
                                    crate::engine_dispatch::apply_ghost_escalation(
                                        &mut ctx.stealth,
                                    );
                                }
                                async move {
                                    crate::engine_dispatch::run_engine(&eng, &variant, &ctx).await
                                }
                            },
                        )
                        .await
                    }
                })
                .await;
                if telem.attempts > 1 || telem.status != "ok" {
                    tracing::info!(
                        target: "engine_resilience",
                        engine = %eng_label,
                        attempts = telem.attempts,
                        status = %telem.status,
                        strategy = %telem.strategy,
                        recovered = telem.recovered,
                        elapsed_ms = telem.elapsed_ms,
                        "resilient engine run"
                    );
                }
                crate::engine_telemetry::record(&eng_label, &telem);
                last_engine_telemetry = Some(telem);
                res
            };

            crate::supreme_nerve_center::run_phase(
                &job.id.to_string(),
                "persisting",
                Some("findings → report_runs + vulnerabilities"),
            );
            // Persist findings into report_runs + vulnerabilities so the Findings Command
            // Center / Vuln Intel / dashboard / CSV export / PDF report all see them. Without
            // this step results live only inside weissman_async_jobs.result_json (effectively
            // invisible to the customer).
            let persisted = persist_findings_best_effort(
                app_pool.as_ref(),
                tid,
                client_id_opt,
                engine,
                target,
                &result.findings,
            )
            .await;

            if crate::engine_resilience::should_retry_status(&result.status) {
                let failure_ctx = json!({
                    "engine": engine,
                    "target": target,
                    "status": result.status,
                    "message": result.message,
                    "telemetry": last_engine_telemetry.as_ref().map(|t| t.to_json()),
                });
                if let Err(e) = crate::sovereign_evolution::maybe_enqueue_learning_on_failure(
                    app_pool.as_ref(),
                    tid,
                    target,
                    &failure_ctx,
                )
                .await
                {
                    tracing::warn!(target: "sovereign_evolution", error = %e, "learning feedback enqueue failed");
                }
            }

            let out = engine_job_result_json(
                engine,
                &result,
                persisted,
                last_engine_telemetry.as_ref().map(|t| t.to_json()),
            );
            let telem_status = if result.is_policy_block() {
                "blocked"
            } else if result.success {
                "completed"
            } else {
                "failed"
            };
            channels.emit_telemetry(
                tid,
                &json!({
                    "job_id": job.id.to_string(),
                    "engine": engine,
                    "message": result.message,
                    "status": telem_status,
                    "policy_block": result.is_policy_block(),
                    "error_code": result.error_code,
                    "findings": result.findings,
                })
                .to_string(),
            );
            Ok(out)
        }
        "top_tier_health_probe" => {
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "payload.target required".to_string())?
                .to_string();

            let runtime_cfg = load_tenant_runtime_config(app_pool.clone(), tid).await?;

            let mut entries: Vec<Value> = Vec::new();
            let mut passed = 0usize;
            let mut failed = 0usize;

            let poe_cfg = crate::orchestrator::load_poe_config_http(
                app_pool.as_ref(),
                tid,
                intel_pool.clone(),
            )
            .await
            .ok();

            channels.emit_telemetry(tid, &
                json!({
                    "job_id": job.id.to_string(),
                    "message": format!("Top-tier health probe started for {} engines", TOP_TIER_ENGINES.len()),
                    "status": "running"
                })
                .to_string(),
            );

            for engine_id in TOP_TIER_ENGINES {
                let started = std::time::Instant::now();
                let canonical = weissman_core::models::engine::resolve_engine_id(engine_id);
                let (probe_status, findings_count, message, raw_status) =
                    if *engine_id == "poe_synthesis" {
                        if let Some(cfg) = poe_cfg.as_ref() {
                            let run = tokio::time::timeout(
                                Duration::from_secs(180),
                                crate::exploit_synthesis_engine::run_exploit_synthesis_async(
                                    &target,
                                    cfg,
                                    None,
                                    None,
                                    Some(tid),
                                    None,
                                ),
                            )
                            .await;
                            match run {
                                Ok(result) => {
                                    let st = result.status.clone();
                                    let msg = result.message.clone();
                                    let fc = result.findings.len();
                                    if st == "ok" {
                                        ("pass", fc, msg, st)
                                    } else {
                                        ("fail", fc, msg, st)
                                    }
                                }
                                Err(_) => (
                                    "fail",
                                    0,
                                    "poe_synthesis timed out (180s)".to_string(),
                                    "timeout".to_string(),
                                ),
                            }
                        } else {
                            (
                                "fail",
                                0,
                                "poe_synthesis config unavailable".to_string(),
                                "error".to_string(),
                            )
                        }
                    } else if !weissman_core::models::engine::is_production_engine_id(engine_id) {
                        (
                            "fail",
                            0,
                            "catalog-only engine (no production runner)".to_string(),
                            "catalog_only".to_string(),
                        )
                    } else {
                        let ctx = crate::engine_dispatch::EngineRunContext {
                            tenant_id: Some(tid),
                            target_list: vec![target.clone()],
                            github_token: runtime_cfg.github_token.clone(),
                            llm_base_url: runtime_cfg.llm_base_url.clone().unwrap_or_default(),
                            llm_model: runtime_cfg.llm_model.clone().unwrap_or_default(),
                            intelligence_bus: Some(
                                crate::ws_intelligence_bus::IntelligenceBus::new_shared(),
                            ),
                            ..Default::default()
                        };
                        let run = tokio::time::timeout(
                            Duration::from_secs(180),
                            crate::engine_dispatch::run_engine(engine_id, &target, &ctx),
                        )
                        .await;
                        match run {
                            Ok(result) => {
                                if result.status == "ok" {
                                    ("pass", result.findings.len(), result.message, result.status)
                                } else if result.is_policy_block() {
                                    (
                                        "blocked",
                                        result.findings.len(),
                                        result.message,
                                        result.status,
                                    )
                                } else {
                                    ("fail", result.findings.len(), result.message, result.status)
                                }
                            }
                            Err(_) => (
                                "fail",
                                0,
                                "engine timed out (180s)".to_string(),
                                "timeout".to_string(),
                            ),
                        }
                    };

                let duration_ms = started.elapsed().as_millis() as u64;
                if probe_status == "pass" {
                    passed += 1;
                } else {
                    failed += 1;
                }

                entries.push(json!({
                    "engine_id": engine_id,
                    "canonical_engine": canonical,
                    "probe_status": probe_status,
                    "status": raw_status,
                    "message": message,
                    "findings_count": findings_count,
                    "duration_ms": duration_ms,
                }));

                channels.emit_telemetry(
                    tid,
                    &json!({
                        "job_id": job.id.to_string(),
                        "engine_id": engine_id,
                        "canonical_engine": canonical,
                        "probe_status": probe_status,
                        "findings_count": findings_count,
                        "duration_ms": duration_ms,
                        "message": message,
                        "status": "running",
                    })
                    .to_string(),
                );
            }

            channels.emit_telemetry(tid, &
                json!({
                    "job_id": job.id.to_string(),
                    "message": format!("Top-tier health probe completed: {}/{} passed", passed, TOP_TIER_ENGINES.len()),
                    "status": "completed",
                    "passed": passed,
                    "failed": failed,
                })
                .to_string(),
            );

            Ok(json!({
                "ok": true,
                "target": target,
                "passed": passed,
                "failed": failed,
                "engines": entries,
            }))
        }
        "tenant_full_scan" | "onboarding_tenant_scan" => {
            let permit = crate::scan_concurrency::acquire_full_scan_permit()
                .await
                .map_err(|_| "scan concurrency timeout".to_string())?;
            let _permit = permit;
            let war = Some(crate::ceo::WarRoomMirror {
                pool: app_pool.clone(),
                tenant_id: tid,
                job_id: job.id,
            });
            let war_terminal = war.clone();
            if let Some(w) = war.as_ref() {
                w.emit(
                    "session",
                    "info",
                    json!({ "message": "Tenant scan cycle started (orchestrator)" }),
                );
            }
            // Passed through to the orchestrator as a raw Arc; that path stamps its own
            // telemetry with `tid` (it already receives the tenant id).
            let telemetry = channels.telemetry.clone();
            let fut = async move {
                crate::orchestrator::run_single_tenant_scan_cycle(
                    app_pool.clone(),
                    intel_pool.clone(),
                    tid,
                    Some(telemetry),
                    war,
                )
                .await
            };
            match crate::panic_shield::catch_unwind_future("tenant_full_scan_job", fut).await {
                crate::panic_shield::CatchOutcome::Completed(Ok(())) => {
                    if let Some(w) = war_terminal.as_ref() {
                        w.emit(
                            "session",
                            "info",
                            json!({ "message": "Tenant scan cycle completed" }),
                        );
                    }
                    Ok(json!({"ok": true, "message": "tenant scan cycle completed"}))
                }
                crate::panic_shield::CatchOutcome::Completed(Err(e)) => {
                    Err(format!("scan cycle failed: {}", e))
                }
                crate::panic_shield::CatchOutcome::Panicked { message, .. } => {
                    Err(format!("scan cycle panicked: {}", message))
                }
                crate::panic_shield::CatchOutcome::CircuitOpen {
                    cooldown_remaining_secs,
                } => Err(format!(
                    "scan cycle skipped: panic circuit breaker open (retry after ~{}s)",
                    cooldown_remaining_secs
                )),
            }
        }
        "scan_all_engines" => {
            // Run all engines for a client in proper order
            let client_id = p
                .get("client_id")
                .and_then(Value::as_i64)
                .ok_or_else(|| "payload.client_id required".to_string())?;
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let engines: Vec<String> = p
                .get("engines")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let telemetry = TenantEmitter::new(channels.telemetry.clone(), tid);
            let app = app_pool.clone();
            let _ = telemetry.send(format!(r#"{{"job_id":"{}","message":"Starting scan-all-engines: {} engines for client {}","status":"running"}}"#, job.id, engines.len(), client_id));

            let mut results = Vec::new();
            let mut succeeded = 0usize;
            let mut failed = 0usize;
            let mut blocked = 0usize;

            let production_engines: Vec<String> = engines
                .iter()
                .filter(|e| weissman_core::models::engine::is_production_engine_id(e))
                .cloned()
                .collect();
            let ordered_engines =
                weissman_core::models::engine::order_engines_by_registry(&production_engines);
            let ordered_engines =
                crate::ws_intelligence_bus::prioritize_ws_intelligence_chain(ordered_engines);
            // Classify THIS target (what / where / who) and select + prioritize the engine
            // set most relevant to it, backed by the authoritative engine→group taxonomy.
            // Reorder-only — no engine is dropped; the profile summary and recommended focus
            // set are surfaced for operator visibility.
            let mut target_profile = crate::target_profile::TargetProfile::classify(&target);
            // Active DNS enrichment (once per job): verify what the host actually
            // resolves to — catches hostnames that map into private/internal
            // space that the passive, string-only tier cannot see. Bounded so a
            // slow/hostile resolver can't stall the whole scan (matches the 3s
            // cap on the `/api/intel/target-profile?enrich=1` handler); on
            // timeout we simply keep the passive profile.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                target_profile.enrich_dns(),
            )
            .await;
            let selection = target_profile.select(&ordered_engines);
            {
                let summary = selection
                    .profile_summary
                    .replace('\\', "/")
                    .replace('"', "'");
                let _ = telemetry.send(format!(
                    r#"{{"job_id":"{}","message":"Target profile → {} · focus {}/{} engines","status":"running"}}"#,
                    job.id,
                    summary,
                    selection.focus.len(),
                    ordered_engines.len()
                ));
            }
            let ordered_engines: Vec<String> =
                selection.ranked.into_iter().map(|c| c.engine_id).collect();

            let intelligence_bus = crate::ws_intelligence_bus::IntelligenceBus::new_shared();
            let mut cross_job_params = serde_json::json!({});

            for engine_id in &ordered_engines {
                let _ = telemetry.send(format!(
                    r#"{{"job_id":"{}","message":"Running engine: {}","status":"running"}}"#,
                    job.id, engine_id
                ));

                crate::ws_intelligence_bus::merge_params_artifacts(
                    &mut cross_job_params,
                    &intelligence_bus,
                );
                let ctx = crate::engine_dispatch::EngineRunContext {
                    tenant_id: Some(tid),
                    target_list: vec![target.clone()],
                    app_pool: Some(app.clone()),
                    agents: Some(crate::endpoint_agents::AgentRegistry::global()),
                    client_id: Some(client_id),
                    job_params: cross_job_params.clone(),
                    intelligence_bus: Some(intelligence_bus.clone()),
                    ..Default::default()
                };
                // Batch isolation: each engine runs with panic/timeout isolation + adaptive retry.
                // A failing, hung, or panicking engine never aborts the batch — every other engine
                // still runs its own scan. Per-engine telemetry is recorded for the reliability view.
                let ctx_ref = &ctx;
                let eid = engine_id.as_str();
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
                crate::ws_intelligence_bus::merge_params_artifacts(
                    &mut cross_job_params,
                    &intelligence_bus,
                );

                if result.is_policy_block() {
                    blocked += 1;
                    let _ = telemetry.send(format!(
                        r#"{{"job_id":"{}","message":"Engine {} RoE denied: {}","status":"blocked"}}"#,
                        job.id, engine_id, result.summary
                    ));
                } else if result.success {
                    succeeded += 1;
                    let _ = telemetry.send(format!(r#"{{"job_id":"{}","message":"Engine {} completed: {} findings","status":"running"}}"#, job.id, engine_id, result.findings.len()));
                } else {
                    failed += 1;
                    let _ = telemetry.send(format!(
                        r#"{{"job_id":"{}","message":"Engine {} failed: {}","status":"running"}}"#,
                        job.id, engine_id, result.summary
                    ));
                }

                results.push(json!({
                    "engine": engine_id,
                    "success": result.success,
                    "status": result.status,
                    "policy_block": result.is_policy_block(),
                    "error_code": result.error_code,
                    "findings_count": result.findings.len(),
                    "summary": result.summary,
                    "resilience": telem.to_json(),
                }));

                let _ = persist_findings_best_effort(
                    app.as_ref(),
                    tid,
                    Some(client_id),
                    engine_id,
                    &target,
                    &result.findings,
                )
                .await;
            }

            let _ = telemetry.send(format!(r#"{{"job_id":"{}","message":"Scan-all-engines completed: {}/{} succeeded","status":"completed"}}"#, job.id, succeeded, ordered_engines.len()));

            if !target.trim().is_empty() {
                let _ = crate::superposition_followup::enqueue_after_batch(
                    app.as_ref(),
                    tid,
                    client_id,
                    &target,
                    "scan_all_engines",
                )
                .await;
            }

            Ok(json!({
                "ok": true,
                "client_id": client_id,
                "engines_total": ordered_engines.len(),
                "succeeded": succeeded,
                "failed": failed,
                "blocked": blocked,
                "results": results,
            }))
        }
        "scan_discovered_domains" => {
            // Scan all discovered domains with specified engines
            let client_id = p
                .get("client_id")
                .and_then(Value::as_i64)
                .ok_or_else(|| "payload.client_id required".to_string())?;
            let domains: Vec<String> = p
                .get("domains")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let engines: Vec<String> = p
                .get("engines")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_else(|| {
                    vec!["osint".to_string(), "asm".to_string(), "recon".to_string()]
                });

            let telemetry = TenantEmitter::new(channels.telemetry.clone(), tid);
            let app = app_pool.clone();
            let _ = telemetry.send(format!(r#"{{"job_id":"{}","message":"Scanning {} domains with {} engines","status":"running"}}"#, job.id, domains.len(), engines.len()));

            let mut total_findings = 0usize;
            let mut scanned_domains = 0usize;

            for domain in &domains {
                let _ = telemetry.send(format!(
                    r#"{{"job_id":"{}","message":"Scanning domain: {}","status":"running"}}"#,
                    job.id, domain
                ));
                scanned_domains += 1;

                for engine_id in &engines {
                    let target = if domain.starts_with("http") {
                        domain.clone()
                    } else {
                        format!("https://{}", domain)
                    };
                    let result = match engine_id.as_str() {
                        "osint" => crate::osint_engine::run_osint_result(&target, None).await,
                        "asm" => crate::asm_engine::run_asm_result(&target).await,
                        "leak_hunter" => {
                            crate::leak_hunter_engine::run_leak_hunter_result(&target).await
                        }
                        "recon" => {
                            let subs = crate::recon::enum_subdomains_default(domain).await;
                            crate::engine_result::EngineResult::ok(
                                subs.iter()
                                    .map(|d| json!({"type": "recon", "subdomain": d}))
                                    .collect(),
                                format!("{} subdomains found", subs.len()),
                            )
                        }
                        "discovery_engine" => {
                            crate::discovery_engine::run_spider_crawl(
                                &[target.clone()],
                                None,
                                &mut std::collections::HashSet::new(),
                                &mut Vec::new(),
                            )
                            .await
                        }
                        _ => continue,
                    };

                    total_findings += result.findings.len();

                    let _ = persist_findings_best_effort(
                        app.as_ref(),
                        tid,
                        Some(client_id),
                        engine_id,
                        &target,
                        &result.findings,
                    )
                    .await;
                }
            }

            let _ = telemetry.send(format!(r#"{{"job_id":"{}","message":"Domain scan completed: {} domains, {} findings","status":"completed"}}"#, job.id, scanned_domains, total_findings));

            Ok(json!({
                "ok": true,
                "client_id": client_id,
                "domains_scanned": scanned_domains,
                "engines_used": engines,
                "total_findings": total_findings,
            }))
        }
        "ascension_wave" => {
            let app = app_pool.clone();
            let tele = channels.telemetry.clone();
            let fut =
                async move { crate::general::run_ascension_wave(app, tid, Some(&tele)).await };
            match crate::panic_shield::catch_unwind_future("ascension_wave_job", fut).await {
                crate::panic_shield::CatchOutcome::Completed(Ok(v)) => Ok(v),
                crate::panic_shield::CatchOutcome::Completed(Err(e)) => Err(e),
                crate::panic_shield::CatchOutcome::Panicked { message, .. } => {
                    Err(format!("ascension wave panicked: {}", message))
                }
                crate::panic_shield::CatchOutcome::CircuitOpen {
                    cooldown_remaining_secs,
                } => Err(format!(
                    "ascension wave skipped: panic circuit open (~{}s)",
                    cooldown_remaining_secs
                )),
            }
        }
        "general_mission" => {
            let domain = p
                .get("domain")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.domain required".to_string())?
                .to_string();
            let client_id = p.get("client_id").and_then(Value::as_i64);
            let app = app_pool.clone();
            let tele = channels.telemetry.clone();
            let fut = async move {
                crate::strategy_engine::execute_general_mission(
                    app,
                    tid,
                    client_id,
                    domain.as_str(),
                    Some(&tele),
                )
                .await
            };
            match crate::panic_shield::catch_unwind_future("general_mission_job", fut).await {
                crate::panic_shield::CatchOutcome::Completed(Ok(v)) => Ok(v),
                crate::panic_shield::CatchOutcome::Completed(Err(e)) => Err(e),
                crate::panic_shield::CatchOutcome::Panicked { message, .. } => {
                    Err(format!("general mission panicked: {}", message))
                }
                crate::panic_shield::CatchOutcome::CircuitOpen {
                    cooldown_remaining_secs,
                } => Err(format!(
                    "general mission skipped: panic circuit open (~{}s)",
                    cooldown_remaining_secs
                )),
            }
        }
        "council_debate" => {
            let target_brief = p
                .get("target_brief")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "payload.target_brief required".to_string())?
                .to_string();
            let failure_log = p
                .get("failure_log")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(std::string::ToString::to_string);
            let max_council_rounds = p
                .get("max_council_rounds")
                .and_then(|v| v.as_u64())
                .unwrap_or(3)
                .clamp(1, 20) as u32;
            let verify_oob = p.get("verify_oob").and_then(|v| v.as_bool()) == Some(true);
            let fallback_oast = p
                .get("fallback_oast_token")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty());

            let supreme_command_protocol =
                p.get("supreme_command_protocol").and_then(|v| v.as_bool()) == Some(true);
            let supreme = p.get("supreme").and_then(|v| v.as_bool()) == Some(true);
            let actor_user_id = p.get("actor_user_id").and_then(|v| v.as_i64());
            let app = app_pool.clone();
            let fut = async move {
                let cfg = crate::council::CouncilConfig::load(app.as_ref(), tid).await?;
                if supreme_command_protocol {
                    let out = crate::council::process_mission(
                        app.as_ref(),
                        tid,
                        &cfg,
                        target_brief.as_str(),
                        actor_user_id,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    return serde_json::to_value(&out).map_err(|e| e.to_string());
                }
                if verify_oob {
                    let pool = crate::fuzz_http_pool::FuzzHttpPool::from_env()
                        .await
                        .map_err(|e| e.to_string())?;
                    let pool = Arc::new(pool);
                    if supreme {
                        crate::council::run_supreme_debate_until_oob_seen(
                            app.as_ref(),
                            pool,
                            &cfg,
                            tid,
                            &target_brief,
                            fallback_oast,
                            max_council_rounds,
                            failure_log.as_deref(),
                        )
                        .await
                        .map_err(|e| e.to_string())
                        .and_then(|r| serde_json::to_value(&r).map_err(|e| e.to_string()))
                    } else {
                        crate::council::run_debate_until_oob_seen(
                            pool,
                            &cfg,
                            tid,
                            &target_brief,
                            fallback_oast,
                            max_council_rounds,
                            failure_log.as_deref(),
                        )
                        .await
                        .map_err(|e| e.to_string())
                        .and_then(|r| serde_json::to_value(&r).map_err(|e| e.to_string()))
                    }
                } else if supreme {
                    let s = crate::council::run_supreme_council_debate(
                        Some(app.as_ref()),
                        &cfg,
                        tid,
                        &target_brief,
                        0,
                        failure_log.as_deref(),
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    serde_json::to_value(&s).map_err(|e| e.to_string())
                } else {
                    crate::council::run_adversarial_debate(
                        &cfg,
                        tid,
                        &target_brief,
                        0,
                        failure_log.as_deref(),
                    )
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|res| serde_json::to_value(&res).map_err(|e| e.to_string()))
                }
            };
            match crate::panic_shield::catch_unwind_future("council_debate_job", fut).await {
                crate::panic_shield::CatchOutcome::Completed(Ok(res)) => Ok(res),
                crate::panic_shield::CatchOutcome::Completed(Err(e)) => Err(e),
                crate::panic_shield::CatchOutcome::Panicked { message, .. } => {
                    Err(format!("council debate panicked: {}", message))
                }
                crate::panic_shield::CatchOutcome::CircuitOpen {
                    cooldown_remaining_secs,
                } => Err(format!(
                    "council debate skipped: panic circuit open (~{}s)",
                    cooldown_remaining_secs
                )),
            }
        }
        "deep_fuzz" => {
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "target required".to_string())?
                .to_string();
            let client_id = p.get("client_id").and_then(Value::as_i64);
            let discovered_paths: Option<Vec<String>> = p
                .get("discovered_paths")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(std::string::ToString::to_string))
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .filter(|v| !v.is_empty());
            let cognitive_dictionary: Vec<String> = p
                .get("cognitive_dictionary")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(std::string::ToString::to_string))
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let merged_paths: Option<Vec<String>> =
                match (cognitive_dictionary.is_empty(), discovered_paths) {
                    (true, None) => None,
                    (true, Some(paths)) => Some(paths),
                    (false, None) => Some(cognitive_dictionary),
                    (false, Some(mut paths)) => {
                        let mut m = cognitive_dictionary;
                        for x in paths.drain(..) {
                            if !m.contains(&x) {
                                m.push(x);
                            }
                        }
                        Some(m)
                    }
                };
            let shadow_preflight =
                p.get("shadow_preflight").and_then(|v| v.as_bool()) == Some(true);
            let autonomous_pivot = p
                .get("autonomous_credential_pivot")
                .and_then(|v| v.as_bool())
                == Some(true);
            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let llm_base_url = cfg_string_tx(&mut tx, tid, "llm_base_url")
                .await
                .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
            let llm_temperature: f64 = cfg_string_tx(&mut tx, tid, "llm_temperature")
                .await
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.2);
            let llm_model = cfg_string_tx(&mut tx, tid, "llm_model")
                .await
                .unwrap_or_default();
            let mut max_depth: usize = cfg_string_tx(&mut tx, tid, "semantic_max_sequence_depth")
                .await
                .and_then(|s| s.parse().ok())
                .unwrap_or(4);
            let _ = tx.commit().await;
            let mut shadow_simulation = Value::Null;
            if shadow_preflight && crate::sovereign_evolution::sovereign_evolution_enabled() {
                match crate::council::CouncilConfig::load(app_pool.as_ref(), tid).await {
                    Ok(cfg) => {
                        let tech = crate::generative_fuzz_llm::tech_stack_hint();
                        match crate::sovereign_evolution::shadow_preflight(
                            &cfg,
                            tid,
                            target.as_str(),
                            tech.as_str(),
                            "semantic_openapi_or_fallback_fuzz",
                        )
                        .await
                        {
                            Ok(s) => {
                                if s.detection_risk_0_100 >= 70 {
                                    max_depth = max_depth.min(2);
                                }
                                if s.reroute_recommended {
                                    max_depth = max_depth.min(1);
                                }
                                shadow_simulation = serde_json::to_value(&s).unwrap_or(json!({}));
                            }
                            Err(e) => {
                                shadow_simulation = json!({ "error": e.to_string() });
                            }
                        }
                    }
                    Err(e) => {
                        shadow_simulation = json!({ "config_error": e });
                    }
                }
            }
            let sem_cfg = crate::semantic_fuzzer::SemanticConfig {
                llm_base_url,
                llm_temperature,
                llm_model,
                max_sequence_depth: max_depth,
            };
            let disc_ref = merged_paths.as_deref();
            let fuzzy = crate::semantic_fuzzer::run_semantic_fuzz_result(
                &target,
                None,
                &sem_cfg,
                disc_ref,
                Some(tid),
            )
            .await;
            if autonomous_pivot && crate::sovereign_evolution::sovereign_evolution_enabled() {
                let blob = json!({
                    "findings": fuzzy.result.findings,
                    "message": fuzzy.result.message,
                });
                let _ = crate::sovereign_evolution::maybe_enqueue_credential_hunt(
                    app_pool.as_ref(),
                    tid,
                    target.as_str(),
                    &blob,
                )
                .await;
            }
            if let Some(cid) = client_id {
                if let Ok(mut tx) = db::begin_tenant_tx(app_pool.as_ref(), tid).await {
                    let log = fuzzy
                        .reasoning_log
                        .chars()
                        .take(120_000)
                        .collect::<String>();
                    let _ = sqlx::query(
                        "INSERT INTO semantic_fuzz_log (tenant_id, client_id, run_id, log_text) VALUES ($1, $2, NULL, $3)",
                    )
                    .bind(tid)
                    .bind(cid)
                    .bind(&log)
                    .execute(&mut *tx)
                    .await;
                    let _ = tx.commit().await;
                }
            }
            let persisted = persist_findings_best_effort(
                app_pool.as_ref(),
                tid,
                client_id,
                "semantic_ai_fuzz",
                &target,
                &fuzzy.result.findings,
            )
            .await;
            Ok(json!({
                "status": fuzzy.result.status,
                "findings": fuzzy.result.findings,
                "findings_persisted": persisted,
                "message": fuzzy.result.message,
                "state_nodes": fuzzy.state_nodes,
                "state_edges": fuzzy.state_edges,
                "reasoning_log": fuzzy.reasoning_log,
                "shadow_simulation": shadow_simulation,
            }))
        }
        "sovereign_learning_feedback" => {
            let target_seed = p
                .get("target_seed")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "payload.target_seed required".to_string())?
                .to_string();
            let failure_context = p
                .get("failure_context")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let cfg = crate::council::CouncilConfig::load(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let (row_id, critic, hacker) = crate::sovereign_evolution::run_recursive_waf_feedback(
                app_pool.as_ref(),
                tid,
                &cfg,
                target_seed.as_str(),
                &failure_context,
            )
            .await
            .map_err(|e| e.to_string())?;
            Ok(json!({
                "learning_buffer_id": row_id,
                "critic_waf_analysis": critic,
                "hacker_polymorphic_synthesis": hacker,
            }))
        }
        "genesis_eternal_fuzz" => {
            crate::hpc_runtime::bind_current_thread_genesis_research();
            let genesis_params =
                crate::ceo::strategy::load_genesis_runtime_params(app_pool.as_ref(), tid).await;
            if genesis_params.kill_switch {
                return Ok(json!({
                    "ok": true,
                    "genesis_kill_switch": true,
                    "message": "CEO genesis_kill_switch active — cycle skipped; workers remain safe to idle",
                }));
            }
            if !genesis_params.protocol_enabled {
                return Ok(json!({
                    "ok": false,
                    "message": "genesis protocol disabled (set genesis_protocol_enabled via PATCH /api/ceo/strategy or WEISSMAN_GENESIS_PROTOCOL=1)",
                }));
            }
            let resume_sid = p.get("resume_suspended_id").and_then(Value::as_i64);
            let dfs_out = crate::eternal_fuzz::run_eternal_fuzz_cycle_with_hibernation(
                app_pool.as_ref(),
                tid,
                resume_sid,
                &genesis_params,
            )
            .await
            .map_err(|e| e.to_string())?;
            let eternal = dfs_out.json;
            if p.get("enqueue_supply_chain_seeds").and_then(Value::as_bool) == Some(true) {
                for t in crate::eternal_fuzz::load_seed_strings_from_params(&genesis_params)
                    .into_iter()
                    .collect::<std::collections::HashSet<_>>()
                {
                    let target = t
                        .splitn(2, ':')
                        .nth(1)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or(t.as_str())
                        .to_string();
                    if target.is_empty() {
                        continue;
                    }
                    let pl = json!({ "engine": "supply_chain", "target": target });
                    let _ = crate::async_jobs::enqueue(
                        app_pool.as_ref(),
                        tid,
                        "command_center_engine",
                        pl,
                        Some("genesis-supply-chain".to_string()),
                    )
                    .await;
                }
            }
            let run_war = p.get("run_council_war_room").and_then(Value::as_bool) != Some(false);
            if eternal.get("hibernation").and_then(Value::as_bool) == Some(true) {
                return Ok(json!({
                    "eternal": eternal,
                    "council_skipped": "hibernated",
                    "suspended_id": dfs_out.suspended_id,
                }));
            }
            if !run_war {
                return Ok(json!({ "eternal": eternal, "council_skipped": true }));
            }
            let cfg = crate::council::CouncilConfig::load(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let fb: Vec<crate::eternal_fuzz::SimFeedbackStep> = serde_json::from_value(
                eternal
                    .get("simulation_feedback")
                    .cloned()
                    .unwrap_or(json!([])),
            )
            .unwrap_or_default();
            let war_room = crate::ceo::war_room::WarRoomContext {
                pool: app_pool.clone(),
                tenant_id: tid,
                session_id: job.id.to_string(),
                async_job_id: Some(job.id),
            };
            let council = match crate::council_synthesis::run_genesis_war_room(
                app_pool.clone(),
                tid,
                &cfg,
                &eternal,
                &fb,
                Some(&war_room),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(
                        target: "genesis_war_room",
                        tenant_id = tid,
                        error = %e,
                        detail = %serde_json::to_string(&e.to_client_value()).unwrap_or_default(),
                        "genesis_eternal_fuzz council phase failed (LLM unreachable, bad JSON, or decode)"
                    );
                    return Err(e.to_string());
                }
            };
            Ok(json!({ "eternal": eternal, "council": council }))
        }
        "genesis_knowledge_match" => {
            let fp = p
                .get("tech_fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if fp.is_empty() {
                return Err("payload.tech_fingerprint required".to_string());
            }
            crate::council_synthesis::genesis_knowledge_match(app_pool.as_ref(), tid, fp)
                .await
                .map_err(|e| e.to_string())
        }
        "timing_scan" => {
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "target required".to_string())?
                .to_string();
            let client_id = p.get("client_id").cloned();
            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let n = cfg_string_tx(&mut tx, tid, "timing_sample_size")
                .await
                .and_then(|s| s.parse().ok())
                .unwrap_or(100)
                .max(50)
                .min(500);
            let z: f64 = cfg_string_tx(&mut tx, tid, "z_score_sensitivity")
                .await
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(3.0)
                .clamp(2.0, 5.0);
            let _ = tx.commit().await;
            let cfg = crate::timing_engine::TimingConfig {
                baseline_sample_size: n,
                payload_sample_size: n.min(100),
                z_score_threshold: z,
                ..Default::default()
            };
            let (tx_stream, mut rx_stream) =
                tokio::sync::mpsc::unbounded_channel::<crate::timing_engine::TimingStreamEvent>();
            let bcast = channels.timing.clone();
            tokio::spawn(async move {
                while let Some(ev) = rx_stream.recv().await {
                    if serde_json::to_string(&ev)
                        .map(|s| bcast.send(s).is_ok())
                        .unwrap_or(false)
                    {}
                }
            });
            let result =
                crate::timing_engine::run_timing_attack(&target, None, &cfg, Some(tx_stream)).await;
            let persisted = persist_findings_best_effort(
                app_pool.as_ref(),
                tid,
                payload_client_id(p),
                "microsecond_timing",
                &target,
                &result.findings,
            )
            .await;
            Ok(json!({
                "status": result.status,
                "findings": result.findings,
                "findings_persisted": persisted,
                "message": result.message,
                "client_id": client_id,
            }))
        }
        "ai_redteam" => {
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "target required".to_string())?
                .to_string();
            let client_id = p.get("client_id").cloned();
            let ai_endpoint = p
                .get("ai_endpoint")
                .and_then(Value::as_str)
                .map(|s| s.to_string());
            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let llm_base_url = cfg_string_tx(&mut tx, tid, "llm_base_url")
                .await
                .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
            let llm_temperature: f64 = cfg_string_tx(&mut tx, tid, "llm_temperature")
                .await
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.3);
            let llm_model = cfg_string_tx(&mut tx, tid, "llm_model")
                .await
                .unwrap_or_default();
            let ai_redteam_endpoint = cfg_string_tx(&mut tx, tid, "ai_redteam_endpoint")
                .await
                .unwrap_or_default();
            let adversarial_strategy = cfg_string_tx(&mut tx, tid, "adversarial_strategy")
                .await
                .unwrap_or_else(|| "data_leak".to_string());
            let _ = tx.commit().await;
            let cfg = crate::ai_redteam_engine::AiRedteamConfig {
                llm_base_url,
                llm_temperature,
                llm_model,
                ai_redteam_endpoint: ai_endpoint
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(ai_redteam_endpoint),
                adversarial_strategy,
            };
            let (tx_stream, mut rx_stream) = tokio::sync::mpsc::unbounded_channel::<
                crate::ai_redteam_engine::RedteamStreamEvent,
            >();
            let bcast = channels.redteam.clone();
            tokio::spawn(async move {
                while let Some(ev) = rx_stream.recv().await {
                    if serde_json::to_string(&ev)
                        .map(|s| bcast.send(s).is_ok())
                        .unwrap_or(false)
                    {}
                }
            });
            let oast_interaction_token = p.get("oast_interaction_token").cloned();
            let result = crate::ai_redteam_engine::run_ai_redteam_attack(
                &target,
                None,
                &cfg,
                Some(tx_stream),
                Some(tid),
            )
            .await;
            let persisted = persist_findings_best_effort(
                app_pool.as_ref(),
                tid,
                payload_client_id(p),
                "ai_adversarial_redteam",
                &target,
                &result.findings,
            )
            .await;
            Ok(json!({
                "status": result.status,
                "findings": result.findings,
                "findings_persisted": persisted,
                "message": result.message,
                "client_id": client_id,
                "oast_interaction_token": oast_interaction_token,
            }))
        }
        "threat_intel_run" => {
            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let mut config = crate::threat_intel_engine::ThreatIntelConfig::default();
            if let Some(u) = cfg_string_tx(&mut tx, tid, "llm_base_url").await {
                config.llm_base_url = u;
            }
            if let Some(m) = cfg_string_tx(&mut tx, tid, "llm_model").await {
                config.llm_model = m;
            }
            if let Some(s) = cfg_string_tx(&mut tx, tid, "enable_zero_day_probing").await {
                config.enable_zero_day_probing = s.to_lowercase() == "true" || s == "1";
            }
            if let Some(s) = cfg_string_tx(&mut tx, tid, "threat_intel_custom_feed_urls").await {
                if let Ok(arr) = serde_json::from_str::<Vec<String>>(&s) {
                    config.custom_feed_urls = arr;
                }
            }
            let rows = sqlx::query("SELECT id::text, domains FROM clients ORDER BY id")
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
            let _ = tx.commit().await;
            let mut targets: Vec<crate::threat_intel_engine::RadarTarget> = Vec::new();
            for r in rows {
                let cid: String = r.try_get("id").unwrap_or_default();
                let doms: String = r.try_get("domains").unwrap_or_else(|_| "[]".to_string());
                if let Ok(arr) = serde_json::from_str::<Vec<String>>(&doms) {
                    if let Some(first) = arr.first() {
                        let u = first.trim();
                        if !u.is_empty() {
                            let url = if u.starts_with("http://") || u.starts_with("https://") {
                                u.to_string()
                            } else {
                                format!("https://{}", u)
                            };
                            targets.push((cid, url));
                        }
                    }
                }
            }
            let (tx_stream, mut rx_stream) = tokio::sync::mpsc::unbounded_channel::<
                crate::threat_intel_engine::RadarStreamEvent,
            >();
            let radar = channels.radar.clone();
            tokio::spawn(async move {
                while let Some(ev) = rx_stream.recv().await {
                    if serde_json::to_string(&ev)
                        .map(|s| {
                            radar
                                .send(crate::http::tenant_stream::stamp(tid, &s))
                                .is_ok()
                        })
                        .unwrap_or(false)
                    {}
                }
            });
            let result = crate::threat_intel_engine::run_zero_day_radar(
                &targets,
                None,
                &config,
                Some(tx_stream),
                Some(tid),
            )
            .await;
            let persisted = persist_findings_grouped_by_client_field(
                app_pool.as_ref(),
                tid,
                "zero_day_radar",
                "tenant-wide radar scan",
                &result.findings,
            )
            .await;
            Ok(json!({
                "status": result.status,
                "findings": result.findings,
                "findings_persisted": persisted,
                "message": result.message,
            }))
        }
        "pipeline_scan" => {
            let repo = p
                .get("repo_url")
                .and_then(Value::as_str)
                .ok_or_else(|| "repo_url required".to_string())?;
            let client_id = p.get("client_id").cloned();
            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let llm_base_url = cfg_string_tx(&mut tx, tid, "llm_base_url")
                .await
                .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
            let llm_model = cfg_string_tx(&mut tx, tid, "llm_model")
                .await
                .unwrap_or_default();
            let github_token = cfg_string_tx(&mut tx, tid, "github_token")
                .await
                .unwrap_or_default();
            let gitlab_api_url = cfg_string_tx(&mut tx, tid, "gitlab_api_url")
                .await
                .unwrap_or_default();
            let gitlab_token = cfg_string_tx(&mut tx, tid, "gitlab_token")
                .await
                .unwrap_or_default();
            let _ = tx.commit().await;
            let config = crate::pipeline_engine::PipelineConfig {
                llm_base_url,
                llm_model,
                github_token,
                gitlab_api_url,
                gitlab_token,
            };
            let repo_owned = repo.to_string();
            let res = tokio::task::spawn_blocking(move || {
                crate::pipeline_engine::run_pipeline_analysis_sync(&repo_owned, &config, Some(tid))
            })
            .await
            .map_err(|e| format!("join: {}", e))?;
            let persisted = persist_findings_best_effort(
                app_pool.as_ref(),
                tid,
                payload_client_id(p),
                "pipeline",
                repo,
                &res.findings,
            )
            .await;
            Ok(json!({
                "status": res.status,
                "findings": res.findings,
                "findings_persisted": persisted,
                "message": res.message,
                "client_id": client_id,
            }))
        }
        "swarm_run" => {
            let client_id = p
                .get("client_id")
                .and_then(Value::as_i64)
                .ok_or_else(|| "client_id required".to_string())?;
            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let ok: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1 AND tenant_id = $2)",
            )
            .bind(client_id)
            .bind(tid)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(false);
            let _ = tx.commit().await;
            if !ok {
                return Err("client not found".into());
            }
            let payload_str = serde_json::to_string(&json!({
                "type": "swarm",
                "agent": "SwarmCoordinator",
                "event": "job_queued",
                "detail": { "client_id": client_id, "tenant_id": tid },
                "ts": chrono::Utc::now().timestamp_millis(),
            }))
            .unwrap_or_default();
            channels.emit_swarm(tid, &payload_str);
            // Detached: spawn_swarm_run already tokio::spawns the work internally and
            // returns a JoinHandle. Drop the handle explicitly to detach the task so the
            // worker dequeues the next job immediately (an ambiguous `let _ = <future>`
            // could silently drop an un-awaited future — this makes the intent explicit).
            drop(crate::swarm_orchestrator::spawn_swarm_run(
                app_pool.clone(),
                tid,
                client_id,
                channels.swarm.clone(),
            ));
            Ok(json!({
                "ok": true,
                "message": "swarm run started (non-blocking); see /ws/swarm for live runs",
                "client_id": client_id,
            }))
        }
        "auto_heal" => {
            let spec_str = p
                .get("spec_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.spec_id required".to_string())?;
            let spec_id = uuid::Uuid::parse_str(spec_str.trim())
                .map_err(|_| "invalid spec_id uuid".to_string())?;
            crate::auto_heal_job::run_auto_heal_job(app_pool.clone(), tid, spec_id).await
        }
        "deception_cloud_deploy" => {
            let dep_str = p
                .get("deployment_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.deployment_id required".to_string())?;
            let deployment_id = uuid::Uuid::parse_str(dep_str.trim())
                .map_err(|_| "invalid deployment_id uuid".to_string())?;
            crate::deception_cloud_deploy_job::run_deception_cloud_deploy(
                app_pool.clone(),
                tid,
                deployment_id,
            )
            .await
        }
        "poe_synthesis_run" => {
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "target required".to_string())?
                .to_string();
            let cfg = crate::orchestrator::load_poe_config_http(
                app_pool.as_ref(),
                tid,
                intel_pool.clone(),
            )
            .await
            .map_err(|e| e.to_string())?;
            let wall_secs: u64 = std::env::var("WEISSMAN_POE_JOB_WALL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(900)
                .clamp(120, 7200);
            let job_oast_token = p
                .get("oast_interaction_token")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let res = match tokio::time::timeout(
                Duration::from_secs(wall_secs),
                crate::exploit_synthesis_engine::run_exploit_synthesis_async(
                    &target,
                    &cfg,
                    None,
                    None,
                    Some(tid),
                    job_oast_token,
                ),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    tracing::error!(
                        target: "poe_job",
                        tenant_id = tid,
                        wall_secs,
                        "poe_synthesis_run wall-clock timeout (WEISSMAN_POE_JOB_WALL_SECS)"
                    );
                    crate::engine_result::EngineResult::error(
                        "PoE synthesis exceeded wall-clock budget; check vLLM health and target reachability",
                    )
                }
            };
            if res.status != "ok" {
                tracing::error!(
                    target: "poe_job",
                    tenant_id = tid,
                    target = %target,
                    message = %res.message,
                    "poe_synthesis_run returned error status"
                );
            } else if res.findings.is_empty() {
                tracing::warn!(
                    target: "poe_job",
                    tenant_id = tid,
                    target = %target,
                    message = %res.message,
                    "poe_synthesis_run finished with zero findings — check logs (poe_llm) if UI stuck on Awaiting PoE; often no crash-like probe fired"
                );
            }
            let persisted = persist_findings_best_effort(
                app_pool.as_ref(),
                tid,
                payload_client_id(p),
                "poe_synthesis",
                &target,
                &res.findings,
            )
            .await;
            Ok(json!({
                "status": res.status,
                "findings": res.findings,
                "findings_persisted": persisted,
                "message": res.message,
            }))
        }
        "threat_ingest_run" => {
            let llm_base = p
                .get("llm_base")
                .and_then(Value::as_str)
                .unwrap_or("http://127.0.0.1:8000/v1")
                .to_string();
            let llm_model = p
                .get("llm_model")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            crate::threat_intel_ingestor::run_ingest_cycle(
                app_pool.clone(),
                intel_pool.clone(),
                auth_pool.clone(),
                channels.telemetry.clone(),
                &llm_base,
                &llm_model,
            )
            .await;
            Ok(json!({"ok": true, "message": "threat ingest cycle completed"}))
        }
        "llm_fuzz_run" => {
            let client_id = p
                .get("client_id")
                .and_then(Value::as_i64)
                .ok_or_else(|| "client_id required".to_string())?;
            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let cfg_row: Option<String> = sqlx::query_scalar(
                "SELECT COALESCE(NULLIF(trim(client_configs), ''), '{}') FROM clients WHERE id = $1 AND tenant_id = $2",
            )
            .bind(client_id)
            .bind(tid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
            let Some(raw) = cfg_row else {
                let _ = tx.rollback().await;
                return Err("client not found".into());
            };
            let llm_cfg = crate::llm_fuzzer_engine::parse_llm_secops(&raw);
            let summary =
                crate::llm_fuzzer_engine::run_and_persist(&mut tx, tid, client_id, &llm_cfg)
                    .await
                    .map_err(|e| e.to_string())?;
            let _ = tx.commit().await;
            Ok(json!({"ok": true, "summary": summary}))
        }
        "cloud_scan_run" => {
            let client_id = p
                .get("client_id")
                .and_then(Value::as_i64)
                .ok_or_else(|| "client_id required".to_string())?;
            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let row = sqlx::query(
                "SELECT COALESCE(trim(aws_cross_account_role_arn),'') AS role_arn, COALESCE(trim(aws_external_id),'') AS ext FROM clients WHERE id = $1",
            )
            .bind(client_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
            let (role_arn, external_id) = match row {
                Some(r) => (
                    r.try_get::<String, _>("role_arn").unwrap_or_default(),
                    r.try_get::<String, _>("ext").unwrap_or_default(),
                ),
                None => {
                    let _ = tx.rollback().await;
                    return Err("client not found".into());
                }
            };
            let _ = tx.commit().await;
            let cfg = crate::cloud_integration_engine::CrossAccountAwsConfig {
                role_arn,
                external_id,
                session_name: String::new(),
            };
            let regions = crate::cloud_integration_engine::ec2_scan_regions_from_env();
            let findings = crate::cloud_integration_engine::scan_aws_agentless(&cfg, &regions)
                .await
                .map_err(|e| e.to_string())?;
            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let _ = sqlx::query("DELETE FROM cloud_scan_findings WHERE client_id = $1")
                .bind(client_id)
                .execute(&mut *tx)
                .await;
            for f in &findings {
                let detail = serde_json::to_string(&f.detail).unwrap_or_else(|_| "{}".to_string());
                let _ = sqlx::query(
                    r#"INSERT INTO cloud_scan_findings (tenant_id, client_id, resource_type, resource_id, region, rule_id, severity, title, detail_json)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
                )
                .bind(tid)
                .bind(client_id)
                .bind(&f.resource_type)
                .bind(&f.resource_id)
                .bind(&f.region)
                .bind(&f.rule_id)
                .bind(&f.severity)
                .bind(&f.title)
                .bind(&detail)
                .execute(&mut *tx)
                .await;
            }
            let _ = tx.commit().await;
            Ok(json!({"ok": true, "findings_count": findings.len()}))
        }
        "payload_sync" => {
            crate::payload_sync_worker::run_sync_cycle_async(
                app_pool.clone(),
                intel_pool.clone(),
                auth_pool.clone(),
            )
            .await;
            Ok(json!({"ok": true, "message": "payload sync cycle completed"}))
        }
        "feedback_fuzz" => {
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "target required".to_string())?
                .to_string();
            let base_payload = p.get("base_payload").and_then(Value::as_str).unwrap_or("");
            let client_id = p
                .get("client_id")
                .and_then(Value::as_i64)
                .ok_or_else(|| "client_id required".to_string())?;
            let job_oast_token = p
                .get("oast_interaction_token")
                .and_then(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            let ok: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1 AND tenant_id = $2)",
            )
            .bind(client_id)
            .bind(tid)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(false);
            let _ = tx.commit().await;
            if !ok {
                return Err("client not found".into());
            }

            let cognitive: Option<String> = p
                .get("cognitive_dictionary")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::trim))
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|s| !s.is_empty());
            let findings = crate::fuzzer::run_fuzzer_collect_tenant(
                &target,
                base_payload,
                Some(tid),
                job_oast_token,
                cognitive.as_deref(),
                Some(app_pool.as_ref()),
            )
            .await;

            let finding_values: Vec<Value> = findings
                .iter()
                .map(feedback_fuzz_anomaly_to_finding)
                .collect();
            let persisted = persist_findings_best_effort(
                app_pool.as_ref(),
                tid,
                Some(client_id),
                "http_feedback_fuzz",
                &target,
                &finding_values,
            )
            .await;

            if findings.iter().any(|v| v.llm_user_prompt.is_some()) {
                if let Ok(mut tx2) = db::begin_tenant_tx(app_pool.as_ref(), tid).await {
                    for v in &findings {
                        if let Some(ref prompt) = v.llm_user_prompt {
                            let _ = sqlx::query(
                                r#"INSERT INTO generative_fuzz_winning_payloads (tenant_id, client_id, run_id, target_url, payload, llm_user_prompt, anomaly_type, baseline_vs_anomaly)
                                   VALUES ($1, $2, NULL, $3, $4, $5, $6, $7)"#,
                            )
                            .bind(tid)
                            .bind(client_id)
                            .bind(&v.target_url)
                            .bind(&v.payload)
                            .bind(prompt)
                            .bind(&v.anomaly_type)
                            .bind(&v.baseline_vs_anomaly)
                            .execute(&mut *tx2)
                            .await;
                        }
                    }
                    let _ = tx2.commit().await;
                }
            }

            if !findings.is_empty() {
                crate::notifications::spawn_ascension_poe_followup(
                    app_pool.clone(),
                    tid,
                    target.clone(),
                );
            }

            Ok(json!({
                "ok": true,
                "findings_count": findings.len(),
                "findings_persisted": persisted,
                "message": "feedback fuzz completed; findings persisted via findings_persist",
            }))
        }
        "self_improvement_apply" => {
            // An approved self-improvement proposal. Opening the pull request is performed
            // out-of-process by an external PR bot (which has git/GitHub credentials); the
            // Rust worker never writes to a repo. This arm simply acknowledges the job so it
            // is not treated as a failure, leaving the queue row APPROVED until the PR bot
            // records the pr_url. `open_pr_only` is always true — never a direct commit.
            let improvement_id = p.get("improvement_id").and_then(Value::as_i64);
            tracing::info!(
                target: "self_improve",
                improvement_id = ?improvement_id,
                "self_improvement_apply acknowledged; awaiting external PR bot (PR-only, main untouched)"
            );
            Ok(json!({
                "ok": true,
                "improvement_id": improvement_id,
                "open_pr_only": true,
                "message": "approved; PR creation handled out-of-process by the PR bot",
            }))
        }
        _ => Err(format!("unknown job kind: {}", job.kind)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_consistency_ok_when_payload_has_no_tenant_id() {
        assert!(enforce_job_tenant_consistency(7, &json!({})).is_ok());
        assert!(enforce_job_tenant_consistency(7, &json!({ "foo": "bar" })).is_ok());
    }

    #[test]
    fn roe_blocked_job_json_is_never_empty_success() {
        let result = crate::engine_result::EngineResult::blocked(
            vec![json!({
                "type": "policy_block",
                "category": "roe_denied",
                "policy_block": true,
                "healthy": false
            })],
            "RoE DENIED (industrial_ot_disabled): OT probing not authorized",
            "roe_denied",
        );
        let v = engine_job_result_json("scada_ics", &result, 0, None);
        assert_eq!(v["status"], "blocked");
        assert_eq!(v["policy_block"], true);
        assert_eq!(v["error_code"], "roe_denied");
        assert!(v["reason"].as_str().unwrap().contains("RoE DENIED"));
        assert_eq!(v["findings"].as_array().unwrap().len(), 1);
        assert_eq!(
            weissman_db::job_queue::terminal_status_for_result(&v),
            "blocked"
        );
    }

    #[test]
    fn tenant_consistency_ok_on_matching_integer() {
        assert!(enforce_job_tenant_consistency(7, &json!({ "tenant_id": 7 })).is_ok());
    }

    #[test]
    fn tenant_consistency_ok_on_matching_numeric_string() {
        assert!(enforce_job_tenant_consistency(7, &json!({ "tenant_id": "7" })).is_ok());
    }

    #[test]
    fn tenant_consistency_err_on_integer_mismatch() {
        let err = enforce_job_tenant_consistency(7, &json!({ "tenant_id": 8 })).unwrap_err();
        assert_eq!(err, "payload tenant_id 8 does not match job tenant 7");
    }

    #[test]
    fn tenant_consistency_err_on_numeric_string_mismatch() {
        let err = enforce_job_tenant_consistency(7, &json!({ "tenant_id": "8" })).unwrap_err();
        assert_eq!(err, "payload tenant_id 8 does not match job tenant 7");
    }

    #[test]
    fn tenant_consistency_ignores_unparseable_tenant_id() {
        // A non-numeric string cannot be parsed to i64, so it is treated as absent
        // and no cross-tenant check fires.
        assert!(enforce_job_tenant_consistency(7, &json!({ "tenant_id": "not-a-number" })).is_ok());
    }

    #[test]
    fn payload_client_id_from_integer() {
        assert_eq!(payload_client_id(&json!({ "client_id": 42 })), Some(42));
    }

    #[test]
    fn payload_client_id_from_numeric_string() {
        assert_eq!(payload_client_id(&json!({ "client_id": "42" })), Some(42));
    }

    #[test]
    fn payload_client_id_none_when_missing_or_invalid() {
        assert_eq!(payload_client_id(&json!({})), None);
        assert_eq!(payload_client_id(&json!({ "client_id": null })), None);
        assert_eq!(payload_client_id(&json!({ "client_id": "abc" })), None);
    }

    fn anomaly(oob: Option<&str>, llm: Option<&str>) -> fuzz_core::ValidatedAnomaly {
        fuzz_core::ValidatedAnomaly {
            target_url: "https://example.com".to_string(),
            payload: "PAYLOAD".to_string(),
            anomaly_type: "sqli".to_string(),
            baseline_vs_anomaly: "base vs anom".to_string(),
            oob_token: oob.map(str::to_string),
            llm_user_prompt: llm.map(str::to_string),
        }
    }

    #[test]
    fn feedback_finding_high_severity_without_oob() {
        let f = feedback_fuzz_anomaly_to_finding(&anomaly(None, None));
        assert_eq!(f["severity"], "high");
        assert_eq!(f["title"], "sqli");
        assert_eq!(f["target_url"], "https://example.com");
        assert_eq!(f["type"], "feedback_fuzz");
        assert_eq!(f["anomaly_type"], "sqli");
        assert_eq!(f["poc"], "PAYLOAD");
        assert_eq!(
            f["description"],
            "base vs anom\n\nPayload excerpt:\nPAYLOAD"
        );
    }

    #[test]
    fn feedback_finding_critical_severity_with_oob_and_llm_annotations() {
        let f = feedback_fuzz_anomaly_to_finding(&anomaly(Some("tok123"), Some("prompt")));
        assert_eq!(f["severity"], "critical");
        assert_eq!(
            f["description"],
            "base vs anom\n\nPayload excerpt:\nPAYLOAD\n\nOAST correlation token: tok123\n\n[Generative] Payload produced by vLLM; see generative_fuzz_winning_payloads.llm_user_prompt."
        );
    }

    #[test]
    fn feedback_finding_oob_only_omits_generative_note() {
        let f = feedback_fuzz_anomaly_to_finding(&anomaly(Some("tok123"), None));
        assert_eq!(f["severity"], "critical");
        assert_eq!(
            f["description"],
            "base vs anom\n\nPayload excerpt:\nPAYLOAD\n\nOAST correlation token: tok123"
        );
    }

    #[test]
    fn feedback_finding_truncates_title_to_500_chars() {
        let mut a = anomaly(None, None);
        a.anomaly_type = "a".repeat(600);
        let f = feedback_fuzz_anomaly_to_finding(&a);
        assert_eq!(f["title"].as_str().unwrap().chars().count(), 500);
    }
}
