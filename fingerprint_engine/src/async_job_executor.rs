//! Executes rows from `weissman_async_jobs` (worker + optional in-process dispatch).
//! Broadcast channels default to no-op sinks when absent (worker binary).

use crate::db;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

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

/// Run one job to completion JSON (success) or error string (failure).
pub async fn execute_job(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    channels: &AsyncJobChannels,
    job: weissman_db::job_queue::AsyncJob,
) -> Result<Value, String> {
    let tid = job.tenant_id;
    let p = &job.payload;
    match job.kind.as_str() {
        "command_center_engine" => {
            let engine = p
                .get("engine")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.engine required".to_string())?;
            let target = p
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "payload.target required".to_string())?;
            let result = match engine {
                "supply_chain" => {
                    crate::supply_chain_engine::run_supply_chain_result(target, None).await
                }
                "osint" => crate::osint_engine::run_osint_result(target, None).await,
                "asm" => crate::asm_engine::run_asm_result(target).await,
                "bola_idor" => {
                    let tl = vec![target.to_string()];
                    crate::bola_idor_engine::run_bola_idor_result_multi(
                        &tl,
                        &[],
                        None,
                        None,
                        Some(tid),
                    )
                    .await
                }
                "llm_path_fuzz" | "ollama_fuzz" => {
                    crate::llm_path_fuzz_engine::run_llm_path_fuzz_result_cli(target, None, Some(tid))
                        .await
                        .into()
                }
                "leak_hunter" => {
                    let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tid)
                        .await
                        .map_err(|e| e.to_string())?;
                    let github_token = cfg_string_tx(&mut tx, tid, "github_token")
                        .await
                        .unwrap_or_default();
                    let _ = tx.commit().await;
                    let target_list = vec![target.to_string()];
                    let r = crate::leak_hunter_engine::run_leak_hunter(&target_list, None).await;
                    let mut all_findings = r.findings.clone();
                    if !github_token.is_empty() {
                        let domain = target.split('/').nth(2).unwrap_or(target);
                        let gh_findings = crate::leak_hunter_engine::github_leak_search(
                            domain,
                            Some(github_token.as_str()),
                        )
                        .await;
                        all_findings.extend(gh_findings);
                    }
                    crate::engine_result::EngineResult::ok(all_findings, r.message)
                }
                _ => return Err(format!("unknown engine {}", engine)),
            };
            Ok(json!({
                "engine": engine,
                "status": result.status,
                "findings": result.findings,
                "message": result.message,
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
                crate::panic_shield::CatchOutcome::Panicked { message, .. } => Err(format!(
                    "scan cycle panicked: {}",
                    message
                )),
                crate::panic_shield::CatchOutcome::CircuitOpen {
                    cooldown_remaining_secs,
                } => Err(format!(
                    "scan cycle skipped: panic circuit breaker open (retry after ~{}s)",
                    cooldown_remaining_secs
                )),
            }
        }
        "ascension_wave" => {
            let app = app_pool.clone();
            let tele = channels.telemetry.clone();
            let fut = async move {
                crate::general::run_ascension_wave(app, tid, Some(&tele)).await
            };
            match crate::panic_shield::catch_unwind_future("ascension_wave_job", fut).await {
                crate::panic_shield::CatchOutcome::Completed(Ok(v)) => Ok(v),
                crate::panic_shield::CatchOutcome::Completed(Err(e)) => Err(e),
                crate::panic_shield::CatchOutcome::Panicked { message, .. } => Err(format!(
                    "ascension wave panicked: {}",
                    message
                )),
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
                crate::panic_shield::CatchOutcome::Panicked { message, .. } => Err(format!(
                    "general mission panicked: {}",
                    message
                )),
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
                crate::panic_shield::CatchOutcome::Panicked { message, .. } => Err(format!(
                    "council debate panicked: {}",
                    message
                )),
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
            let merged_paths: Option<Vec<String>> = match (cognitive_dictionary.is_empty(), discovered_paths) {
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
            let shadow_preflight = p.get("shadow_preflight").and_then(|v| v.as_bool()) == Some(true);
            let autonomous_pivot = p.get("autonomous_credential_pivot").and_then(|v| v.as_bool()) == Some(true);
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
                    let log = fuzzy.reasoning_log.chars().take(120_000).collect::<String>();
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
            Ok(json!({
                "status": fuzzy.result.status,
                "findings": fuzzy.result.findings,
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
            let fb: Vec<crate::eternal_fuzz::SimFeedbackStep> =
                serde_json::from_value(eternal.get("simulation_feedback").cloned().unwrap_or(json!([])))
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
                crate::timing_engine::run_timing_attack(&target, None, &cfg, Some(tx_stream))
                    .await;
            Ok(json!({
                "status": result.status,
                "findings": result.findings,
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
            Ok(json!({
                "status": result.status,
                "findings": result.findings,
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
                        .map(|s| radar.send(s).is_ok())
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
            Ok(json!({
                "status": result.status,
                "findings": result.findings,
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
            Ok(json!({
                "status": res.status,
                "findings": res.findings,
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
            let _ = channels.swarm.send(payload_str);
            // Detached: do not await — worker must dequeue the next job immediately.
            let _ = crate::swarm_orchestrator::spawn_swarm_run(
                app_pool.clone(),
                tid,
                client_id,
                channels.swarm.clone(),
            );
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
            let res = match tokio::time::timeout(
                Duration::from_secs(wall_secs),
                crate::exploit_synthesis_engine::run_exploit_synthesis_async(
                    &target,
                    &cfg,
                    None,
                    None,
                    Some(tid),
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
            Ok(json!({
                "status": res.status,
                "findings": res.findings,
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
            let base_payload = p
                .get("base_payload")
                .and_then(Value::as_str)
                .unwrap_or("");
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
            if !ok {
                let _ = tx.rollback().await;
                return Err("client not found".into());
            }
            let summary = json!({
                "engine": "http_feedback_fuzz",
                "target": &target,
                "async_job_id": job.id.to_string(),
                "oast_interaction_token": job_oast_token.as_deref(),
            })
            .to_string();
            let run_id: i64 = sqlx::query_scalar(
                r#"INSERT INTO report_runs (tenant_id, region, findings_json, summary)
                   VALUES ($1, $2, '[]', $3) RETURNING id"#,
            )
            .bind(tid)
            .bind("async_feedback_fuzz")
            .bind(&summary)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
            let _ = tx.commit().await.map_err(|e| e.to_string())?;

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
            )
            .await;

            let mut tx2 = db::begin_tenant_tx(app_pool.as_ref(), tid)
                .await
                .map_err(|e| e.to_string())?;
            for (i, v) in findings.iter().enumerate() {
                let fid = format!("feedback-fuzz-{}-{}", run_id, i);
                let severity = if v.oob_token.is_some() {
                    "critical"
                } else {
                    "high"
                };
                let title: String = v.anomaly_type.chars().take(500).collect();
                let payload_excerpt: String = v.payload.chars().take(4000).collect();
                let mut description = format!("{}\n\nPayload excerpt:\n{}", v.baseline_vs_anomaly, payload_excerpt);
                if let Some(ref tok) = v.oob_token {
                    description.push_str(&format!("\n\nOAST correlation token: {}", tok));
                }
                if v.llm_user_prompt.is_some() {
                    description.push_str("\n\n[Generative] Payload produced by vLLM; see generative_fuzz_winning_payloads.llm_user_prompt.");
                }
                let poc: String = v.payload.chars().take(32_000).collect();
                let _ = sqlx::query(
                    r#"INSERT INTO vulnerabilities (run_id, tenant_id, client_id, finding_id, title, severity, source, description, status, poc_exploit, discovered_at)
                       VALUES ($1, $2, $3, $4, $5, $6, 'http_feedback_fuzz', $7, 'OPEN', $8, now())"#,
                )
                .bind(run_id)
                .bind(tid)
                .bind(client_id)
                .bind(&fid)
                .bind(&title)
                .bind(severity)
                .bind(&description)
                .bind(&poc)
                .execute(&mut *tx2)
                .await;
                if let Some(ref prompt) = v.llm_user_prompt {
                    let _ = sqlx::query(
                        r#"INSERT INTO generative_fuzz_winning_payloads (tenant_id, client_id, run_id, target_url, payload, llm_user_prompt, anomaly_type, baseline_vs_anomaly)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
                    )
                    .bind(tid)
                    .bind(client_id)
                    .bind(run_id)
                    .bind(&v.target_url)
                    .bind(&v.payload)
                    .bind(prompt)
                    .bind(&v.anomaly_type)
                    .bind(&v.baseline_vs_anomaly)
                    .execute(&mut *tx2)
                    .await;
                }
            }
            let _ = tx2.commit().await.map_err(|e| e.to_string())?;

            if !findings.is_empty() {
                crate::notifications::spawn_ascension_poe_followup(
                    app_pool.clone(),
                    tid,
                    target.clone(),
                );
            }

            Ok(json!({
                "ok": true,
                "run_id": run_id,
                "findings_count": findings.len(),
                "message": "feedback fuzz completed; findings persisted to vulnerabilities",
            }))
        }
        _ => Err(format!("unknown job kind: {}", job.kind)),
    }
}
