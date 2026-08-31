//! Central dispatch for production scan engines — real probes only, no simulated findings.
//! Catalog-only registry IDs resolve via aliases to implemented engines.
//!
//! Alias surface: `alias_engine_runner.rs` (~221 arms). Sovereign/synthesis engines use
//! dedicated modules (`chronos_engine`, `external_exposure_supreme`, `identity_attack_chain_engine`,
//! `pipeline_to_runtime_risk_engine`).

use crate::engine_result::EngineResult;
use crate::stealth_engine::StealthConfig;
use serde_json::json;
use weissman_core::models::engine::{
    dispatch_engine_id, is_production_engine_id, production_engine_ids,
};

/// Context passed from orchestrator / async jobs into engine runners.
#[derive(Clone, Default)]
pub struct EngineRunContext {
    pub stealth: Option<StealthConfig>,
    pub discovered_paths: Vec<String>,
    pub target_list: Vec<String>,
    pub tenant_id: Option<i64>,
    pub github_token: Option<String>,
    pub llm_base_url: String,
    pub llm_model: String,
    pub recon_subdomains: Vec<String>,
    pub asm_ports: Option<Vec<u16>>,
    /// Pool + agent registry, populated by `api_scan` when known. When set, agent-required
    /// engines try to dispatch live to an enrolled agent and queue an `endpoint_agent_tasks` row.
    pub app_pool: Option<std::sync::Arc<sqlx::PgPool>>,
    /// Intel pool (`search_path=intel`) for unbounded discovery_knowledge upserts.
    /// Falls back to `app_pool` when unset (single-DB / CLI / tests).
    pub intel_pool: Option<std::sync::Arc<sqlx::PgPool>>,
    pub agents: Option<std::sync::Arc<crate::endpoint_agents::AgentRegistry>>,
    pub client_id: Option<i64>,
    /// Extra scan parameters forwarded from POST /api/command-center/scan body.
    pub job_params: serde_json::Value,
    /// Async job id when running under `command_center_engine` — used for live SSE/WS telemetry.
    pub job_id: Option<String>,
    /// Live swarm bus (server in-process); worker runs use Redis `publish_bus` instead.
    pub swarm_broadcast: Option<std::sync::Arc<tokio::sync::broadcast::Sender<String>>>,
    /// Cross-protocol Memory Intelligence Bus — WS artifacts shared with HTTP/API engines in the same job.
    pub intelligence_bus: Option<std::sync::Arc<crate::ws_intelligence_bus::IntelligenceBus>>,
    /// Prior winning payloads from pentest_memory (tried first by HTTP offensive engines).
    pub memory_payloads: Vec<String>,
    /// DB ids for replay hit accounting when a memory payload re-confirms.
    pub memory_path_ids: Vec<i64>,
    /// Tenant OAST listener URL from `system_configs` (overrides env per job when set).
    pub oast_listener_url: Option<String>,
    /// Tenant OAST DNS domain from `system_configs`.
    pub oast_domain: Option<String>,
    /// Tenant OAST API key from `system_configs`.
    pub oast_api_key: Option<String>,
    /// Optional CEM-DAGO scan blackboard (worker/orchestrator attach this; engines never peer-chat).
    pub blackboard: Option<std::sync::Arc<crate::cem_dago::ScanBlackboard>>,
    /// Scan correlation id (async job uuid or `run-{id}-c{client}`).
    pub scan_id: Option<String>,
    /// Bounded 90-day payload/target trie pre-warmed by CEM-DAGO (owned Arc, no lifetimes).
    pub payload_trie: Option<std::sync::Arc<crate::cem_dago::PayloadTrie>>,
}

impl EngineRunContext {
    /// Prefer the intel pool for `intel.discovery_knowledge`; fall back to app.
    #[must_use]
    pub fn discovery_knowledge_pool(&self) -> Option<&sqlx::PgPool> {
        self.intel_pool.as_deref().or(self.app_pool.as_deref())
    }
}

/// Escalate a run context into the Ghost Network after a WAF/rate-limit block: enable identity
/// morphing + human-cadence jitter and load the proxy swarm (`WEISSMAN_PROXY_SWARM`) if set.
/// Called by the resilient retry loop when the previous attempt classified as `Waf`.
pub fn apply_ghost_escalation(stealth: &mut Option<StealthConfig>) {
    let s = stealth.get_or_insert_with(StealthConfig::default);
    s.identity_morphing = true;
    if s.jitter_max_ms == 0 {
        s.jitter_min_ms = 200;
        s.jitter_max_ms = 1200;
    }
    if s.proxy_list.is_empty() {
        if let Ok(sw) = std::env::var("WEISSMAN_PROXY_SWARM") {
            s.proxy_list = StealthConfig::parse_proxy_swarm(&sw);
        }
    }
}

/// Load tenant OAST settings from `system_configs` (used by scan workers).
pub async fn load_tenant_oast_configs(
    pool: &sqlx::PgPool,
    tenant_id: i64,
) -> (Option<String>, Option<String>, Option<String>) {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return (None, None, None);
    };
    async fn cfg(
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
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    }
    let listener = cfg(&mut tx, tenant_id, "oast_listener_url").await;
    let domain = cfg(&mut tx, tenant_id, "oast_domain").await;
    let api_key = cfg(&mut tx, tenant_id, "oast_api_key").await;
    let _ = tx.commit().await;
    (listener, domain, api_key)
}

pub fn production_ids_json() -> Vec<serde_json::Value> {
    production_engine_ids()
        .iter()
        .map(|id| json!({ "id": id }))
        .collect()
}

#[path = "engine_dispatch_agent.rs"]
mod engine_dispatch_agent;

pub(crate) use engine_dispatch_agent::merge_agent_hybrid;
pub use engine_dispatch_agent::{
    is_agent_required_engine, run_agent_required_engine, AGENT_REQUIRED_ENGINES,
};

pub async fn run_engine(engine_id: &str, target: &str, ctx: &EngineRunContext) -> EngineResult {
    // Diagnostic breadcrumb: emitted at INFO (captured in the worker log dump) immediately before
    // an engine runs. If an engine aborts the process (e.g. a stack overflow), the LAST such line
    // in the worker log names the culprit engine — the only reliable pinpoint for a fatal abort,
    // which no panic hook can catch.
    tracing::info!(target: "engine_exec", engine = %engine_id, "run_engine begin");
    let _oast_guard = {
        let listener = ctx.oast_listener_url.as_deref().unwrap_or("").trim();
        let domain = ctx.oast_domain.as_deref().unwrap_or("").trim();
        if !listener.is_empty() || !domain.is_empty() {
            Some(crate::fuzz_oob::push_tenant_oast(
                crate::fuzz_oob::TenantOastConfig {
                    listener_url: listener.to_string(),
                    domain: domain.to_string(),
                    api_key: ctx.oast_api_key.as_deref().unwrap_or("").trim().to_string(),
                },
            ))
        } else {
            None
        }
    };

    let raw = engine_id.trim();
    if target.trim().is_empty() && is_production_engine_id(raw) {
        return EngineResult::error("target required");
    }

    // Hybrid: always probe remote attack surface, then dispatch to agent fleet if enrolled.
    if is_agent_required_engine(raw) {
        let remote = crate::agent_remote_surface::run_remote_surface_probe(raw, target, ctx).await;
        let agent = run_agent_required_engine(raw, target, ctx).await;
        return merge_agent_hybrid(remote, agent, raw);
    }
    if !is_production_engine_id(raw) {
        return EngineResult::ok(
            vec![],
            format!(
                "Engine '{}' is catalog-only (no live probe); enable a production engine instead",
                engine_id
            ),
        );
    }
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    if crate::alias_engine_runner::is_alias_engine(raw) {
        return crate::alias_engine_runner::run_alias_engine(raw, target, ctx).await;
    }

    let canonical = dispatch_engine_id(raw);

    // Critical-infrastructure engines: isolated path with mandatory RoE preflight.
    if crate::critical_infra::is_critical_infra_engine(canonical) {
        let roe_input = crate::critical_infra::roe::RoePreflightInput {
            pool: ctx.app_pool.as_deref(),
            tenant_id: ctx.tenant_id,
            client_id: ctx.client_id,
            engine_id: canonical,
            target,
            job_params: &ctx.job_params,
        };
        match crate::critical_infra::roe::preflight(&roe_input).await {
            Ok(authority) => {
                tracing::info!(
                    target: "critical_infra_roe",
                    engine_id = %canonical,
                    probe_target = %target,
                    authority = ?authority,
                    "RoE preflight passed — executing critical infrastructure engine"
                );
            }
            Err(violation) => {
                crate::critical_infra::roe::log_violation(
                    ctx.app_pool.as_deref(),
                    ctx.tenant_id,
                    ctx.client_id,
                    canonical,
                    target,
                    violation,
                )
                .await;
                return EngineResult::error(format!(
                    "RoE VIOLATION: {violation} — critical infrastructure engine '{canonical}' blocked for target '{target}'"
                ));
            }
        }
        let mut result = crate::critical_infra::dispatch(canonical, target, &ctx).await;
        for f in &mut result.findings {
            if let Some(obj) = f.as_object_mut() {
                obj.entry("source_engine".to_string())
                    .or_insert_with(|| serde_json::Value::String(raw.to_string()));
                obj.entry("engine_id".to_string())
                    .or_insert_with(|| serde_json::Value::String(raw.to_string()));
            }
        }
        crate::critical_infra::postprocess_result(canonical, target, &ctx, &mut result).await;
        if raw != canonical && !result.message.contains(raw) {
            result.message = format!("{} (via {})", result.message, raw);
        }
        return result;
    }

    let mut ctx = ctx.clone();
    if crate::pentest_memory::is_http_offensive_engine(canonical) {
        if let (Some(pool), Some(tid)) = (ctx.app_pool.as_ref(), ctx.tenant_id) {
            let winners = crate::pentest_memory::load_memory_for_engine(
                pool.as_ref(),
                tid,
                canonical,
                target,
                12,
            )
            .await;
            ctx.memory_path_ids = winners.iter().map(|w| w.id).collect();
            ctx.memory_payloads = winners.into_iter().map(|w| w.payload).collect();
        }
    }
    if let Some(trie) = ctx.payload_trie.as_ref() {
        let extra = trie.payloads_for_target(target);
        crate::pentest_memory::prepend_memory_payloads(&mut ctx.memory_payloads, &extra);
    }
    let mut result = dispatch_engine_match(canonical, target, &ctx).await;
    if raw != canonical || !result.findings.is_empty() {
        for f in &mut result.findings {
            if let Some(obj) = f.as_object_mut() {
                obj.entry("source_engine".to_string())
                    .or_insert_with(|| serde_json::Value::String(raw.to_string()));
                obj.entry("engine_id".to_string())
                    .or_insert_with(|| serde_json::Value::String(raw.to_string()));
                if raw != canonical {
                    obj.insert(
                        "canonical_engine".to_string(),
                        serde_json::Value::String(canonical.to_string()),
                    );
                }
            }
        }
    }
    if raw != canonical && !result.message.contains(raw) {
        result.message = format!("{} (via {})", result.message, raw);
    }
    result
}

/// Run a canonical production engine (used by alias runner after specialization).
pub(crate) async fn dispatch_canonical_engine(
    canonical: &str,
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    dispatch_engine_match(canonical, target, ctx).await
}

async fn run_poe_synthesis_dispatch(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let Some(tid) = ctx.tenant_id else {
        return EngineResult::error(
            "poe_synthesis requires tenant_id in engine context (enqueue via command center scan)"
                .to_string(),
        );
    };
    let Some(pool) = ctx.app_pool.as_ref() else {
        return EngineResult::error(
            "poe_synthesis requires database pool in engine context".to_string(),
        );
    };
    let cfg =
        match crate::orchestrator::load_poe_config_http(pool.as_ref(), tid, pool.clone()).await {
            Ok(c) => c,
            Err(e) => return EngineResult::error(format!("poe_synthesis config: {e}")),
        };
    crate::exploit_synthesis_engine::run_exploit_synthesis_async(
        target,
        &cfg,
        None,
        None,
        Some(tid),
        ctx.job_params
            .get("oast_interaction_token")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    )
    .await
}

async fn dispatch_engine_match(
    canonical: &str,
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    let stealth = ctx.stealth.as_ref();
    let tl = if ctx.target_list.is_empty() {
        vec![target.to_string()]
    } else {
        ctx.target_list.clone()
    };

    match canonical {
        "osint" => crate::osint_engine::run_osint_result(target, stealth).await,
        "asm" => crate::asm_engine::run_asm_result_ctx(target, ctx, stealth).await,
        "leak_hunter" => {
            let mut r = crate::leak_hunter_engine::run_leak_hunter(&tl, stealth).await;
            if let Some(token) = ctx.github_token.as_deref() {
                if !token.is_empty() {
                    let domain = target.split('/').nth(2).unwrap_or(target);
                    let gh =
                        crate::leak_hunter_engine::github_leak_search(domain, Some(token)).await;
                    r.findings.extend(gh);
                }
            }
            EngineResult::ok(r.findings, r.message)
        }
        "discovery_engine" => {
            let mut paths = std::collections::HashSet::new();
            let mut paths_403 = Vec::new();
            crate::discovery_engine::run_spider_crawl(&tl, stealth, &mut paths, &mut paths_403)
                .await
        }
        "recon" => {
            let host = target
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or(target);
            let subs = crate::recon::enum_subdomains_default(host).await;
            EngineResult::ok(
                subs.iter()
                    .map(|d| json!({"type": "recon", "subdomain": d}))
                    .collect(),
                format!("{} subdomains enumerated", subs.len()),
            )
        }
        "supply_chain" => crate::supply_chain_engine::run_supply_chain_result(target, stealth).await,
        "bola_idor" => {
            crate::bola_idor_engine::run_bola_idor_result_multi(
                &tl,
                &ctx.discovered_paths,
                stealth,
                None,
                ctx.tenant_id,
            )
            .await
        }
        "graphql_attack" => {
            crate::graphql_attack_engine::run_graphql_attack_result_ctx(target, ctx).await
        }
        "jwt_attack" => crate::jwt_attack_engine::run_jwt_attack_result_ctx(target, ctx).await,
        "oauth_oidc" => crate::oauth_oidc_engine::run_oauth_oidc_result(target, ctx).await,
        "http_smuggling" => {
            crate::http_smuggling_engine::run_http_smuggling_result_ctx(target, ctx).await
        }
        "liminal_boundary" => {
            crate::liminal_boundary_engine::run_liminal_boundary_result_ctx(target, ctx).await
        }
        "prototype_pollution" => {
            crate::prototype_pollution_engine::run_prototype_pollution_result_ctx(target, ctx)
                .await
        }
        "ssrf_advanced" => crate::ssrf_advanced_engine::run_ssrf_advanced_result_ctx(target, ctx).await,
        "xxe" => crate::xxe_engine::run_xxe_result_ctx(target, ctx).await,
        "ssti" => crate::ssti_engine::run_ssti_result_ctx(target, ctx).await,
        "file_upload" => crate::file_upload_engine::run_file_upload_result_ctx(target, ctx).await,
        "websocket_attack" => crate::websocket_attack_engine::run_websocket_attack_result_ctx(target, ctx).await,
        "cache_poisoning" => crate::cache_poisoning_engine::run_cache_poisoning_result_ctx(target, ctx).await,
        "llm_path_fuzz" | "ollama_fuzz" => {
            crate::llm_path_fuzz_engine::run_llm_path_fuzz_result_cli(target, stealth, ctx.tenant_id)
                .await
                .into()
        }
        "semantic_ai_fuzz" => {
            let tech = crate::elite_hardening::semantic_gate::fingerprint_target(target);
            if !crate::elite_hardening::semantic_gate::allow_llm_mutation(
                &tech,
                !ctx.discovered_paths.is_empty(),
            ) {
                return crate::engine_result::EngineResult::ok(
                    vec![serde_json::json!({
                        "type": "semantic_ai_fuzz",
                        "title": "Semantic fuzzer waiting for technology fingerprint",
                        "severity": "info",
                        "description": format!(
                            "LLM mutation deferred until OpenAPI/fingerprint is available (tech={})",
                            tech.label
                        ),
                        "target": target,
                    })],
                    "semantic_ai_fuzz: awaiting fingerprint",
                );
            }
            let config = weissman_core::models::semantic::SemanticConfig {
                llm_base_url: if ctx.llm_base_url.trim().is_empty() {
                    "http://127.0.0.1:8000/v1".to_string()
                } else {
                    ctx.llm_base_url.clone()
                },
                llm_model: ctx.llm_model.clone(),
                llm_temperature: 0.7,
                max_sequence_depth: 5,
            };
            let paths = if ctx.discovered_paths.is_empty() {
                None
            } else {
                Some(ctx.discovered_paths.as_slice())
            };
            crate::semantic_fuzzer::run_semantic_fuzz_result(
                target,
                stealth,
                &config,
                paths,
                ctx.tenant_id,
            )
            .await
            .result
        }
        "ai_adversarial_redteam" => {
            let cfg = crate::ai_redteam_engine::AiRedteamConfig::default();
            crate::ai_redteam_engine::run_ai_redteam_attack(
                target,
                stealth,
                &cfg,
                None,
                ctx.tenant_id,
            )
            .await
        }
        "llm_redteam" => crate::llm_redteam_engine::run_llm_redteam_result(target).await,
        "adversarial_ml" => crate::adversarial_ml_engine::run_adversarial_ml_result(target).await,
        "autonomous_pentest" => {
            crate::autonomous_pentest_engine::run_autonomous_pentest_result(target).await
        }
        "nexus_sovereign_swarm" => {
            crate::nexus_sovereign_swarm_engine::run_nexus_sovereign_swarm_result(target, ctx).await
        }
        "aws_attack" => crate::aws_attack_engine::run_aws_attack_result_ctx(target, ctx).await,
        "cloud_posture" => crate::cloud_posture_engine::run_cloud_posture_result_ctx(target, ctx).await,
        "azure_attack" => crate::azure_attack_engine::run_azure_attack_result_ctx(target, ctx).await,
        "gcp_attack" => crate::gcp_attack_engine::run_gcp_attack_result(target).await,
        "k8s_container" => crate::k8s_container_engine::run_k8s_container_result(target, ctx).await,
        "iac_misconfig" => crate::iac_misconfig_engine::run_iac_misconfig_result(target, ctx).await,
        "serverless_attack" => crate::serverless_attack_engine::run_serverless_attack_result_ctx(target, ctx).await,
        "scada_ics" => crate::scada_ics_engine::run_scada_ics_result(target).await,
        "iot_firmware" => crate::iot_firmware_engine::run_iot_firmware_result(target).await,
        "ble_rf" => crate::ble_rf_engine::run_ble_rf_result_ctx(target, ctx).await,
        "edr_evasion" => crate::edr_evasion_engine::run_edr_evasion_result_ctx(target, ctx).await,
        "waf_bypass" => crate::waf_bypass_engine::run_waf_bypass_result_ctx(target, ctx).await,
        "timing_sidechannel" => {
            crate::timing_sidechannel_engine::run_timing_sidechannel_result_ctx(target, ctx).await
        }
        "antiforensics" => crate::antiforensics_engine::run_antiforensics_result(target).await,
        "stealth_engine" => crate::stealth_engine::run_stealth_engine_result(target).await,
        "pki_tls" => crate::pki_tls_engine::run_pki_tls_result_ctx(target, ctx).await,
        "pqc_scanner" => {
            crate::pqc_scanner_engine::run_pqc_scanner_result_ctx(target, ctx).await
        }
        "password_spray" => {
            crate::password_spray_engine::run_password_spray_result_ctx(target, ctx).await
        }
        "kerberoasting" => crate::kerberoasting_engine::run_kerberoasting_result_ctx(target, ctx).await,
        "saml_attack" => crate::saml_attack_engine::run_saml_attack_result_ctx(target, ctx).await,
        "crypto_engine" => crate::crypto_engine::run_crypto_engine_result(target).await,
        "email_dns_posture" => {
            crate::email_dns_posture_engine::run_email_dns_posture_result(target, ctx).await
        }
        "bgp_dns_hijacking" => crate::bgp_dns_hijacking_engine::run_bgp_dns_hijacking_result_ctx(target, ctx).await,
        "ipv6_attack" => crate::ipv6_attack_engine::run_ipv6_attack_result(target).await,
        "mtls_grpc" => crate::mtls_grpc_engine::run_mtls_grpc_result_ctx(target, ctx).await,
        "smb_netbios" => crate::smb_netbios_engine::run_smb_netbios_result(target, ctx).await,
        "cicd_pipeline" => {
            crate::cicd_pipeline_engine::run_cicd_pipeline_result_ctx(target, ctx).await
        }
        "container_registry" => {
            crate::container_registry_engine::run_container_registry_result(target).await
        }
        "sbom_analyzer" => crate::sbom_analyzer_engine::run_sbom_analyzer_result(target).await,
        "typosquatting_monitor" => {
            crate::typosquatting_monitor_engine::run_typosquatting_monitor_result_ctx(target, ctx).await
        }
        "kill_chain" => crate::kill_chain_engine::run_kill_chain_result(target).await,
        "oast_oob" => crate::oast_oob_engine::run_oast_oob_result(target).await,
        "deception_honeypot" => {
            crate::deception_honeypot_engine::run_deception_honeypot_result(target).await
        }
        "digital_twin" => {
            crate::digital_twin_engine::run_digital_twin_result_ctx(target, ctx).await
        }
        "zero_day_prediction" => {
            crate::zero_day_prediction_engine::run_zero_day_prediction_result(target).await
        }
        "threat_emulation" => crate::threat_emulation_engine::run_threat_emulation_result(target).await,
        "microsecond_timing" => {
            // Path fan-out is caller-tunable (`timing_max_urls`) so a live scan can
            // bound its total request budget; defaults to the historical cap of 80.
            let jp = &ctx.job_params;
            let max_urls = jp
                .get("timing_max_urls")
                .and_then(|v| v.as_u64())
                .map(|n| n.clamp(1, 80) as usize)
                .unwrap_or(80);
            let urls: Vec<String> = tl
                .iter()
                .flat_map(|b| {
                    ctx.discovered_paths.iter().take(12).map(move |p| {
                        let b = b.trim_end_matches('/');
                        let p = p.trim();
                        if p.is_empty() || p == "/" {
                            b.to_string()
                        } else {
                            format!("{}/{}", b, p.trim_start_matches('/'))
                        }
                    })
                })
                .take(max_urls)
                .collect();
            let urls_for = if urls.is_empty() {
                vec![tl.first().cloned().unwrap_or_else(|| target.to_string())]
            } else {
                urls
            };
            // Sample sizes, payload breadth and an overall wall-clock budget are all
            // read live from the scan body (falling back to the engine defaults), so
            // an E2E/smoke caller can keep the run inside its poll window without
            // weakening a normal production scan. `run_timing_attack_urls` clamps
            // each field to a safe range.
            let mut cfg = crate::timing_engine::TimingConfig::default();
            if let Some(n) = jp.get("timing_baseline_samples").and_then(|v| v.as_u64()) {
                cfg.baseline_sample_size = n as usize;
            }
            if let Some(n) = jp.get("timing_payload_samples").and_then(|v| v.as_u64()) {
                cfg.payload_sample_size = n as usize;
            }
            if let Some(n) = jp.get("timing_payload_variants").and_then(|v| v.as_u64()) {
                cfg.payload_variants = n as usize;
            }
            if let Some(z) = jp.get("timing_z_threshold").and_then(|v| v.as_f64()) {
                cfg.z_score_threshold = z;
            }
            if let Some(b) = jp.get("timing_budget_secs").and_then(|v| v.as_u64()) {
                cfg.budget_secs = b;
            }
            crate::timing_engine::run_timing_attack_urls(&urls_for, stealth, &cfg, None).await
        }
        "http_feedback_fuzz" => {
            let anomalies = if let Some(tid) = ctx.tenant_id {
                crate::fuzzer::run_fuzzer_collect_tenant(
                    target,
                    "",
                    Some(tid),
                    None,
                    None,
                    ctx.app_pool.as_deref(),
                )
                .await
            } else {
                crate::fuzzer::run_fuzzer_collect(target, "").await
            };
            let verified_oob = anomalies.iter().filter(|a| a.oob_token.is_some()).count();
            let findings: Vec<serde_json::Value> = anomalies
                .iter()
                .map(|a| {
                    let oob = a.oob_token.clone().filter(|s| !s.trim().is_empty());
                    let verified = oob.is_some();
                    json!({
                        "type": "http_feedback_fuzz",
                        "title": a.anomaly_type.clone(),
                        "severity": "high",
                        "description": a.baseline_vs_anomaly.clone(),
                        "url": a.target_url.clone(),
                        "payload": a.payload.clone(),
                        "verified": verified,
                        "verification_method": if verified { "oob_oast_callback" } else { "behavioral_feedback_validation" },
                        "oob_token": oob,
                        "llm_user_prompt": a.llm_user_prompt,
                    })
                })
                .collect();
            EngineResult::ok(
                findings,
                format!(
                    "HTTP feedback fuzz: {} validated anomalies ({} OOB-verified)",
                    anomalies.len(),
                    verified_oob
                ),
            )
        }
        // ── Advanced AI / LLM engines ──────────────────────────────────────────
        "llm_jailbreak" => crate::advanced_ai_engines::run_llm_jailbreak_result(target).await,
        "prompt_injection_chain" => crate::advanced_ai_engines::run_prompt_injection_chain_result(target).await,
        "model_inversion_attack" => crate::advanced_ai_engines::run_model_inversion_attack_result(target).await,
        "ai_supply_chain_attack" => crate::advanced_ai_engines::run_ai_supply_chain_attack_result(target).await,
        "llm_agent_hijack" => crate::advanced_ai_engines::run_llm_agent_hijack_result(target).await,
        "rag_poisoning_engine" => crate::advanced_ai_engines::run_rag_poisoning_engine_result(target).await,
        "adversarial_examples" => crate::advanced_ai_engines::run_adversarial_examples_result(target).await,
        "data_poisoning_engine" => crate::advanced_ai_engines::run_data_poisoning_engine_result(target).await,
        "deepfake_synthesis" => crate::advanced_ai_engines::run_deepfake_synthesis_result(target).await,
        "llm_dos_attack" => crate::advanced_ai_engines::run_llm_dos_attack_result(target).await,
        "multimodal_ai_attack" => crate::advanced_ai_engines::run_multimodal_ai_attack_result(target).await,
        "ai_bias_exploit" => crate::advanced_ai_engines::run_ai_bias_exploit_result(target).await,
        "gpt_plugin_attack" => crate::advanced_ai_engines::run_gpt_plugin_attack_result(target).await,
        "autonomous_ai_escape" => crate::advanced_ai_engines::run_autonomous_ai_escape_result(target).await,
        "llm_memory_extraction" => crate::advanced_ai_engines::run_llm_memory_extraction_result(target).await,
        "neural_backdoor_detect" => crate::advanced_ai_engines::run_neural_backdoor_detect_result(target).await,
        "ai_watermark_bypass" => crate::advanced_ai_engines::run_ai_watermark_bypass_result(target).await,
        "federated_learning_attack" => crate::advanced_ai_engines::run_federated_learning_attack_result(target).await,
        "llm_red_team_advanced" => crate::advanced_ai_engines::run_llm_red_team_advanced_result(target).await,
        "model_stealing_engine" => crate::advanced_ai_engines::run_model_stealing_engine_result(target).await,

        // ── Advanced APT / Top-Tier engines ────────────────────────────────────
        "apt28_techniques" => crate::advanced_apt_engines::run_apt28_techniques_result(target).await,
        "apt29_techniques" => crate::advanced_apt_engines::run_apt29_techniques_result(target).await,
        "apt41_techniques" => crate::advanced_apt_engines::run_apt41_techniques_result(target).await,
        "lazarus_group_ttps" => crate::advanced_apt_engines::run_lazarus_group_ttps_result(target).await,
        "volt_typhoon_ttps" => crate::advanced_apt_engines::run_volt_typhoon_ttps_result(target).await,
        "scattered_spider_ttps" => crate::advanced_apt_engines::run_scattered_spider_ttps_result(target).await,
        "salt_typhoon_ttps" => crate::advanced_apt_engines::run_salt_typhoon_ttps_result(target).await,
        "fin7_techniques" => crate::advanced_apt_engines::run_fin7_techniques_result(target).await,
        "conti_ransomware_ttps" => crate::advanced_apt_engines::run_conti_ransomware_ttps_result(target).await,
        "lockbit_techniques" => crate::advanced_apt_engines::run_lockbit_techniques_result(target).await,
        "cl0p_techniques" => crate::advanced_apt_engines::run_cl0p_techniques_result(target).await,
        "blackcat_alphv_ttps" => crate::advanced_apt_engines::run_blackcat_alphv_ttps_result(target).await,
        "midnight_blizzard_ttps" => crate::advanced_apt_engines::run_midnight_blizzard_ttps_result(target).await,
        "earth_longzhi_ttps" => crate::advanced_apt_engines::run_earth_longzhi_ttps_result(target).await,
        "equation_group_ttps" => crate::advanced_apt_engines::run_equation_group_ttps_result(target).await,
        "sandworm_techniques" => crate::advanced_apt_engines::run_sandworm_techniques_result(target).await,
        "carbon_spider_ttps" => crate::advanced_apt_engines::run_carbon_spider_ttps_result(target).await,
        "wizard_spider_ttps" => crate::advanced_apt_engines::run_wizard_spider_ttps_result(target).await,
        "unc2452_ttps" => crate::advanced_apt_engines::run_unc2452_ttps_result(target).await,
        "unc3944_ttps" => crate::advanced_apt_engines::run_unc3944_ttps_result(target).await,
        "quantum_sovereign_nexus" => crate::advanced_apt_engines::run_quantum_sovereign_nexus_result(target).await,

        // ── Advanced Cloud engines ─────────────────────────────────────────────
        "lambda_escape" => crate::advanced_cloud_engines::run_lambda_escape_result(target).await,
        "terraform_state_attack" => crate::advanced_cloud_engines::run_terraform_state_attack_result(target).await,
        "cloudformation_injection" => crate::advanced_cloud_engines::run_cloudformation_injection_result(target).await,
        "service_mesh_attack" => crate::advanced_cloud_engines::run_service_mesh_attack_result(target).await,
        "cloud_audit_evasion" => crate::advanced_cloud_engines::run_cloud_audit_evasion_result(target).await,
        "ecr_registry_attack" => crate::advanced_cloud_engines::run_ecr_registry_attack_result(target).await,
        "multi_cloud_pivot" => crate::advanced_cloud_engines::run_multi_cloud_pivot_result(target).await,
        "cloud_worm_propagation" => crate::advanced_cloud_engines::run_cloud_worm_propagation_result(target).await,
        "serverless_injection" => crate::advanced_cloud_engines::run_serverless_injection_result(target).await,
        "cloud_data_exfil" => crate::advanced_cloud_engines::run_cloud_data_exfil_result(target).await,
        "cloud_network_attack" => crate::advanced_cloud_engines::run_cloud_network_attack_result(target).await,
        "cloud_privilege_persistence" => crate::advanced_cloud_engines::run_cloud_privilege_persistence_result(target).await,

        // ── Advanced Crypto / Identity engines ────────────────────────────────
        "padding_oracle_attack" => crate::advanced_crypto_engines::run_padding_oracle_attack_result(target).await,
        "hash_extension_attack" => crate::advanced_crypto_engines::run_hash_extension_attack_result(target).await,
        "ecdsa_nonce_bias" => crate::advanced_crypto_engines::run_ecdsa_nonce_bias_result(target).await,
        "rsa_timing_attack" => crate::advanced_crypto_engines::run_rsa_timing_attack_result(target).await,
        "mfa_bypass_engine" => crate::advanced_crypto_engines::run_mfa_bypass_engine_result(target).await,
        "credential_stuffing" => crate::advanced_crypto_engines::run_credential_stuffing_result(target).await,
        "kerberos_attack_suite" => crate::advanced_crypto_engines::run_kerberos_attack_suite_result(target).await,
        "zero_trust_bypass" => crate::advanced_crypto_engines::run_zero_trust_bypass_result(target).await,
        "pki_hierarchy_attack" => crate::advanced_crypto_engines::run_pki_hierarchy_attack_result(target).await,
        "session_fixation_adv" => crate::advanced_crypto_engines::run_session_fixation_adv_result(target).await,
        "password_hash_crack" => crate::advanced_crypto_engines::run_password_hash_crack_result(target).await,
        "quantum_key_attack" => crate::advanced_crypto_engines::run_quantum_key_attack_result(target).await,
        "password_spray_advanced" => crate::advanced_crypto_engines::run_password_spray_advanced_result(target).await,

        // ── Advanced Data Exfiltration engines ────────────────────────────────
        "dns_exfil_engine" => crate::advanced_data_engines::run_dns_exfil_engine_result(target).await,
        "http_covert_exfil" => crate::advanced_data_engines::run_http_covert_exfil_result(target).await,
        "cloud_exfil_engine" => crate::advanced_data_engines::run_cloud_exfil_engine_result(target).await,
        "encrypted_exfil" => crate::advanced_data_engines::run_encrypted_exfil_result(target).await,
        "acoustic_exfil" => crate::advanced_data_engines::run_acoustic_exfil_result(target).await,
        "em_exfil_engine" => crate::advanced_data_engines::run_em_exfil_engine_result(target).await,
        "optical_exfil" => crate::advanced_data_engines::run_optical_exfil_result(target).await,
        "cache_timing_exfil" => crate::advanced_data_engines::run_cache_timing_exfil_result(target).await,
        "keyboard_acoustic" => crate::advanced_data_engines::run_keyboard_acoustic_result(target).await,
        "screen_capture_exfil" => crate::advanced_data_engines::run_screen_capture_exfil_result(target).await,
        "clipboard_hijack" => crate::advanced_data_engines::run_clipboard_hijack_result(target).await,
        "database_exfil" => crate::advanced_data_engines::run_database_exfil_result(target).await,
        "email_exfil" => crate::advanced_data_engines::run_email_exfil_result(target).await,
        "insider_exfil" => crate::advanced_data_engines::run_insider_exfil_result(target).await,
        "storage_covert_channel" => crate::advanced_data_engines::run_storage_covert_channel_result(target).await,

        // ── Advanced Malware / Ransomware engines ─────────────────────────────
        "bootkit_uefi" => crate::advanced_malware_engines::run_bootkit_uefi_result(target).await,
        "fileless_malware_engine" => crate::advanced_malware_engines::run_fileless_malware_engine_result(target).await,
        "polymorphic_engine" => crate::advanced_malware_engines::run_polymorphic_engine_result(target).await,
        "botnet_c2_engine" => crate::advanced_malware_engines::run_botnet_c2_engine_result(target).await,
        "keylogger_engine" => crate::advanced_malware_engines::run_keylogger_engine_result(target).await,
        "spyware_stalkerware" => crate::advanced_malware_engines::run_spyware_stalkerware_result(target).await,
        "worm_propagation" => crate::advanced_malware_engines::run_worm_propagation_result(target).await,
        "rce_exploit_engine" => crate::advanced_malware_engines::run_rce_exploit_engine_result(target).await,
        "persistence_mechanism" => crate::advanced_malware_engines::run_persistence_mechanism_result(target).await,
        "lateral_movement_engine" => crate::advanced_malware_engines::run_lateral_movement_engine_result(target).await,
        "data_staging_engine" => crate::advanced_malware_engines::run_data_staging_engine_result(target).await,
        "exploit_kit_engine" => crate::advanced_malware_engines::run_exploit_kit_engine_result(target).await,
        "trojan_dropper" => crate::advanced_malware_engines::run_trojan_dropper_result(target).await,
        "macro_malware" => crate::advanced_malware_engines::run_macro_malware_result(target).await,

        // ── Advanced Mobile engines ────────────────────────────────────────────
        "android_malware_engine" => crate::advanced_mobile_engines::run_android_malware_engine_result(target).await,
        "ios_exploit_engine" => crate::advanced_mobile_engines::run_ios_exploit_engine_result(target).await,
        "mobile_mitm" => crate::advanced_mobile_engines::run_mobile_mitm_result(target).await,
        "ssl_pinning_bypass" => crate::advanced_mobile_engines::run_ssl_pinning_bypass_result(target).await,
        "android_intent_attack" => crate::advanced_mobile_engines::run_android_intent_attack_result(target).await,
        "ios_url_scheme_attack" => crate::advanced_mobile_engines::run_ios_url_scheme_attack_result(target).await,
        "mobile_overlay_attack" => crate::advanced_mobile_engines::run_mobile_overlay_attack_result(target).await,
        "sim_swap_engine" => crate::advanced_mobile_engines::run_sim_swap_engine_result(target).await,
        "mobile_banking_trojan" => crate::advanced_mobile_engines::run_mobile_banking_trojan_result(target).await,
        "app_store_attack" => crate::advanced_mobile_engines::run_app_store_attack_result(target).await,
        "mdm_bypass_engine" => crate::advanced_mobile_engines::run_mdm_bypass_engine_result(target).await,
        "bluetooth_mobile_attack" => crate::advanced_mobile_engines::run_bluetooth_mobile_attack_result(target).await,
        "nfc_relay_attack" => crate::advanced_mobile_engines::run_nfc_relay_attack_result(target).await,
        "mobile_spyware_engine" => crate::advanced_mobile_engines::run_mobile_spyware_engine_result(target).await,
        "react_native_attack" => crate::advanced_mobile_engines::run_react_native_attack_result(target).await,

        // ── Advanced Network / Protocol engines ───────────────────────────────
        "arp_spoofing_engine" => crate::advanced_network_engines::run_arp_spoofing_engine_result(target).await,
        "vlan_hopping_attack" => crate::advanced_network_engines::run_vlan_hopping_attack_result(target).await,
        "dhcp_attack_engine" => crate::advanced_network_engines::run_dhcp_attack_engine_result(target).await,
        "dns_cache_poisoning" => crate::advanced_network_engines::run_dns_cache_poisoning_result(target).await,
        "dns_rebinding" => crate::advanced_network_engines::run_dns_rebinding_result(target).await,
        "can_bus_surface" => crate::advanced_network_engines::run_can_bus_surface_result(target).await,
        "ntp_amplification" => crate::advanced_network_engines::run_ntp_amplification_result(target).await,
        "snmp_exploitation" => crate::advanced_network_engines::run_snmp_exploitation_result(target).await,
        "rdp_attack_engine" => crate::advanced_network_engines::run_rdp_attack_engine_result(target).await,
        "ldap_injection_engine" => crate::advanced_network_engines::run_ldap_injection_engine_result(target).await,
        "voip_sip_attack" => crate::advanced_network_engines::run_voip_sip_attack_result(target).await,
        "ss7_signaling_probe" => crate::advanced_network_engines::run_ss7_signaling_probe_result(target).await,
        "wifi_attack_engine" => crate::advanced_network_engines::run_wifi_attack_engine_result(target).await,
        "bluetooth_attack_engine" => crate::advanced_network_engines::run_bluetooth_attack_engine_result(target).await,
        "ospf_bgp_hijack" => crate::advanced_network_engines::run_ospf_bgp_hijack_result(target).await,
        "mpls_vpn_attack" => crate::advanced_network_engines::run_mpls_vpn_attack_result(target).await,
        "lte_5g_attack" => crate::advanced_network_engines::run_lte_5g_attack_result(target).await,
        "network_covert_channel" => crate::advanced_network_engines::run_network_covert_channel_result(target).await,
        "wpa3_attack_engine" => crate::advanced_network_engines::run_wpa3_attack_engine_result(target).await,
        "tor_exit_attack" => crate::advanced_network_engines::run_tor_exit_attack_result(target).await,
        "protocol_downgrade" => crate::advanced_network_engines::run_protocol_downgrade_result(target).await,
        "network_baseline_anomaly" => crate::advanced_network_engines::run_network_baseline_anomaly_result(target).await,
        "packet_injection_engine" => crate::advanced_network_engines::run_packet_injection_engine_result(target).await,
        "network_tap_advanced" => crate::advanced_network_engines::run_network_tap_advanced_result(target).await,
        "multicast_attack" => crate::advanced_network_engines::run_multicast_attack_result(target).await,
        "nat_traversal_attack" => crate::advanced_network_engines::run_nat_traversal_attack_result(target).await,

        // ── Advanced OT / ICS engines ──────────────────────────────────────────
        "dnp3_attack" => crate::advanced_ot_engines::run_dnp3_attack_result(target).await,
        "bacnet_attack" => crate::advanced_ot_engines::run_bacnet_attack_result(target).await,
        "zigbee_attack" => crate::advanced_ot_engines::run_zigbee_attack_result(target).await,
        "iec61850_attack" => crate::advanced_ot_engines::run_iec61850_attack_result(target).await,
        "satellite_comm_attack" => crate::advanced_ot_engines::run_satellite_comm_attack_result(target).await,
        "rfid_nfc_attack" => crate::advanced_ot_engines::run_rfid_nfc_attack_result(target).await,

        // ── Advanced Recon engines ─────────────────────────────────────────────
        "threat_intel_fusion" => crate::advanced_recon_engines::run_threat_intel_fusion_result(target).await,
        "attack_surface_quantify" => crate::advanced_recon_engines::run_attack_surface_quantify_result(target).await,
        "external_exposure_supreme" => {
            crate::external_exposure_supreme::run_external_exposure_supreme_result(target, ctx).await
        }
        "fair_exposure_fusion" => {
            crate::fair_exposure_fusion_engine::run_fair_exposure_fusion_result(target, ctx).await
        }
        "supreme_path_fair_rag" => {
            crate::supreme_path_fair_rag_engine::run_supreme_path_fair_rag_result(target, ctx)
                .await
        }
        "identity_attack_chain" => {
            crate::identity_attack_chain_engine::run_identity_attack_chain_result(target, ctx).await
        }
        "privilege_escalation_credential_access" => {
            crate::priv_esc_cred_access::run_priv_esc_cred_access_result(target, ctx).await
        }
        "pipeline_to_runtime_risk" => {
            crate::pipeline_to_runtime_risk_engine::run_pipeline_to_runtime_risk_result(target, ctx)
                .await
        }
        "risk_superposition_collapse" => {
            crate::risk_superposition_collapse_engine::run_risk_superposition_collapse_result(
                target, ctx,
            )
            .await
        }
        "chronos" => crate::chronos_engine::run_chronos_result(target, ctx).await,
        "poe_synthesis" => run_poe_synthesis_dispatch(target, ctx).await,
        "liquid_matrix" => crate::liquid_matrix_engine::run_liquid_matrix_result(target, ctx).await,
        "cognitive_starvation" => {
            crate::cognitive_starvation_engine::run_cognitive_starvation_result(target, ctx).await
        }
        "sovereign_active_defense_fusion" => {
            crate::sovereign_active_defense_fusion_engine::run_sovereign_active_defense_fusion_result(
                target, ctx,
            )
            .await
        }
        "adversarial_threat_emulation" => crate::advanced_recon_engines::run_adversarial_threat_emulation_result(target).await,
        "dark_web_monitor" => crate::advanced_recon_engines::run_dark_web_monitor_result(target).await,
        "passive_dns_forensics" => crate::advanced_recon_engines::run_passive_dns_forensics_result(target).await,

        // ── Advanced Social Engineering engines ───────────────────────────────
        "spear_phishing_engine" => crate::advanced_social_engines::run_spear_phishing_engine_result(target).await,
        "vishing_engine" => crate::advanced_social_engines::run_vishing_engine_result(target).await,
        "smishing_engine" => crate::advanced_social_engines::run_smishing_engine_result(target).await,
        "qr_phishing" => crate::advanced_social_engines::run_qr_phishing_result(target).await,
        "deepfake_voice_engine" => crate::advanced_social_engines::run_deepfake_voice_engine_result(target).await,
        "business_email_compromise" => crate::advanced_social_engines::run_business_email_compromise_result(target).await,
        "watering_hole_attack" => crate::advanced_social_engines::run_watering_hole_attack_result(target).await,
        "pretexting_engine" => crate::advanced_social_engines::run_pretexting_engine_result(target).await,
        "insider_threat_engine" => crate::advanced_social_engines::run_insider_threat_engine_result(target).await,
        "brand_impersonation" => crate::advanced_social_engines::run_brand_impersonation_result(target).await,
        "fake_update_engine" => crate::advanced_social_engines::run_fake_update_engine_result(target).await,
        "linkedin_phishing" => crate::advanced_social_engines::run_linkedin_phishing_result(target).await,
        "callback_phishing" => crate::advanced_social_engines::run_callback_phishing_result(target).await,
        "physical_social_eng" => crate::advanced_social_engines::run_physical_social_eng_result(target).await,
        "typosquatting_phishing" => crate::advanced_social_engines::run_typosquatting_phishing_result(target).await,

        // ── Advanced Stealth / Evasion engines ────────────────────────────────
        "process_hollowing" => crate::advanced_stealth_engines::run_process_hollowing_result(target).await,
        "living_off_land" => crate::advanced_stealth_engines::run_living_off_land_result(target).await,
        "heap_exploitation" => crate::advanced_stealth_engines::run_heap_exploitation_result(target).await,

        // ── Advanced Supply Chain engines ──────────────────────────────────────
        "github_actions_attack" => crate::advanced_supply_chain_engines::run_github_actions_attack_result(target).await,
        "compiler_backdoor" => crate::advanced_supply_chain_engines::run_compiler_backdoor_result(target).await,
        "open_source_backdoor" => crate::advanced_supply_chain_engines::run_open_source_backdoor_result(target).await,
        "cdn_poisoning_engine" => crate::advanced_supply_chain_engines::run_cdn_poisoning_engine_result(target).await,
        "software_signing_attack" => crate::advanced_supply_chain_engines::run_software_signing_attack_result(target).await,
        "build_system_compromise" => crate::advanced_supply_chain_engines::run_build_system_compromise_result(target).await,
        "dependency_confusion" => crate::advanced_supply_chain_engines::run_dependency_confusion_result(target).await,
        "update_hijacking" => crate::advanced_supply_chain_engines::run_update_hijacking_result(target).await,
        "sbom_forgery_engine" => crate::advanced_supply_chain_engines::run_sbom_forgery_engine_result(target).await,
        "third_party_api_attack" => crate::advanced_supply_chain_engines::run_third_party_api_attack_result(target).await,
        "iac_supply_chain" => crate::advanced_supply_chain_engines::run_iac_supply_chain_result(target).await,

        // ── Advanced Web engines ───────────────────────────────────────────────
        "cors_misconfiguration" => crate::advanced_web_engines::run_cors_misconfiguration_result(target).await,
        "swagger_abuse" => crate::advanced_web_engines::run_swagger_abuse_result(target).await,
        "soap_injection" => crate::advanced_web_engines::run_soap_injection_result(target).await,
        "odata_injection" => crate::advanced_web_engines::run_odata_injection_result(target).await,
        "css_injection" => crate::advanced_web_engines::run_css_injection_result(target).await,
        "template_injection_adv" => crate::advanced_web_engines::run_template_injection_adv_result(target).await,
        "http_parameter_pollution" => crate::advanced_web_engines::run_http_parameter_pollution_result(target).await,
        "api_mass_assignment" => crate::advanced_web_engines::run_api_mass_assignment_result(target).await,
        "clickjacking_engine" => crate::advanced_web_engines::run_clickjacking_engine_result(target).await,
        "subdomain_takeover" => crate::advanced_web_engines::run_subdomain_takeover_result(target).await,
        "file_inclusion_rfi" => crate::advanced_web_engines::run_file_inclusion_rfi_result(target).await,
        "deserialization_net" => crate::advanced_web_engines::run_deserialization_net_result(target).await,
        "api_rate_limit_bypass" => crate::advanced_web_engines::run_api_rate_limit_bypass_result(target).await,
        "graphql_subscription_attack" => crate::advanced_web_engines::run_graphql_subscription_attack_result(target).await,
        "webrtc_attack" => crate::advanced_web_engines::run_webrtc_attack_result(target).await,
        "browser_extension_attack" => crate::advanced_web_engines::run_browser_extension_attack_result(target).await,
        "web3_dapp_attack" => crate::advanced_web_engines::run_web3_dapp_attack_result(target).await,
        "api_gateway_bypass" => crate::advanced_web_engines::run_api_gateway_bypass_result(target).await,
        "graphql_deep_attack" => crate::advanced_web_engines::run_graphql_deep_attack_result(target).await,
        "grpc_reflection_attack" => crate::advanced_web_engines::run_grpc_reflection_attack_result(target).await,
        "http2_attack" => crate::advanced_web_engines::run_http2_attack_result(target).await,
        "idor_advanced" => crate::advanced_web_engines::run_idor_advanced_result(target).await,
        "jwt_advanced_attack" => crate::advanced_web_engines::run_jwt_advanced_attack_result(target).await,
        "nosql_deep_injection" => crate::advanced_web_engines::run_nosql_deep_injection_result(target).await,
        "web_cache_poison_adv" => crate::advanced_web_engines::run_web_cache_poison_adv_result(target).await,

        // ── Advanced Recon engines (new live probes) ───────────────────────────
        "satellite_recon" => crate::advanced_recon_engines::run_satellite_recon_result(target).await,
        "darkweb_intel" => crate::advanced_recon_engines::run_darkweb_intel_result(target).await,
        "financial_osint" => crate::advanced_recon_engines::run_financial_osint_result(target).await,
        "blockchain_trace" => crate::advanced_recon_engines::run_blockchain_trace_result(target).await,
        "metadata_harvest" => crate::advanced_recon_engines::run_metadata_harvest_result(target).await,
        "patent_recon" => crate::advanced_recon_engines::run_patent_recon_result(target).await,
        "telecom_osint" => crate::advanced_recon_engines::run_telecom_osint_result(target).await,
        "iot_shodan_scan" => crate::advanced_recon_engines::run_iot_shodan_scan_result(target).await,
        "job_posting_osint" => crate::advanced_recon_engines::run_job_posting_osint_result(target).await,
        "github_secret_scan" => crate::advanced_recon_engines::run_github_secret_scan_result(target).await,

        // ── Advanced Cloud engines (new live probes) ───────────────────────────
        "cloud_metadata_ssrf" => crate::advanced_cloud_engines::run_cloud_metadata_ssrf_result(target).await,
        "s3_bucket_attack" => crate::advanced_cloud_engines::run_s3_bucket_attack_result(target).await,
        "cloud_iam_escalation" => crate::advanced_cloud_engines::run_cloud_iam_escalation_result(target).await,
        "kubernetes_rbac_escape" => crate::advanced_cloud_engines::run_kubernetes_rbac_escape_result(target).await,
        "azure_devops_attack" => crate::advanced_cloud_engines::run_azure_devops_attack_result(target).await,
        "gcp_privilege_attack" => crate::advanced_cloud_engines::run_gcp_privilege_attack_result(target).await,
        "secrets_manager_attack" => crate::advanced_cloud_engines::run_secrets_manager_attack_result(target).await,
        "eks_attack" => crate::advanced_cloud_engines::run_eks_attack_result(target).await,

        // ── Advanced OT engines (new live probes) ──────────────────────────────
        "modbus_attack" => crate::advanced_ot_engines::run_modbus_attack_result(target).await,
        "modbus_exploit" => crate::advanced_ot_engines::run_modbus_exploit_result(target).await,
        "plc_logic_bomb" => crate::advanced_ot_engines::run_plc_logic_bomb_result(target).await,
        "lorawan_attack" | "lora_attack" => crate::advanced_ot_engines::run_lorawan_attack_result(target).await,
        "voltage_glitch_attack" => crate::advanced_ot_engines::run_voltage_glitch_attack_result(target).await,
        "tpm_firmware_attack" => crate::advanced_ot_engines::run_tpm_firmware_attack_result(target).await,
        "cold_boot_attack" => crate::advanced_ot_engines::run_cold_boot_attack_result(target).await,
        "hospital_hl7_attack" => crate::advanced_ot_engines::run_hospital_hl7_attack_result(target).await,
        "mqtt_attack" => crate::advanced_ot_engines::run_mqtt_attack_result(target).await,
        "coap_attack" => crate::advanced_ot_engines::run_coap_attack_result(target).await,
        "opcua_attack" => crate::advanced_ot_engines::run_opcua_attack_result(target).await,
        "plc_logic_attack" => crate::advanced_ot_engines::run_plc_logic_attack_result(target).await,
        "hmi_attack" => crate::advanced_ot_engines::run_hmi_attack_result(target).await,
        "profinet_attack" => crate::advanced_ot_engines::run_profinet_attack_result(target).await,
        "industrial_protocol_fuzz" => crate::advanced_ot_engines::run_industrial_protocol_fuzz_result(target).await,
        "ot_passive_active_safety" => {
            crate::ot_ics_hardening::run_ot_passive_active_safety_result(target, ctx).await
        }
        "ot_crown_jewel_path" => {
            crate::ot_ics_hardening::run_ot_crown_jewel_path_result(target, ctx).await
        }
        "firmware_emulation_attack" => crate::advanced_ot_engines::run_firmware_emulation_attack_result(target).await,

        // ── Advanced Stealth engines (new probes / agent_required) ─────────────
        "dll_hijacking_engine" => crate::advanced_stealth_engines::run_dll_hijacking_engine_result(target).await,
        "sandbox_evasion" => crate::advanced_stealth_engines::run_sandbox_evasion_result(target).await,
        "rootkit_surface_probe" => crate::advanced_stealth_engines::run_rootkit_surface_probe_result(target).await,
        "memory_forensics_evasion" => crate::advanced_stealth_engines::run_memory_forensics_evasion_result(target).await,
        "av_bypass_engine" => crate::advanced_stealth_engines::run_av_bypass_engine_result(target).await,
        "dns_tunneling_c2" => crate::advanced_stealth_engines::run_dns_tunneling_c2_result(target).await,
        "steganography_c2" => crate::advanced_stealth_engines::run_steganography_c2_result(target).await,
        "https_c2_masquerade" => crate::advanced_stealth_engines::run_https_c2_masquerade_result(target).await,
        "icmp_covert" => crate::advanced_stealth_engines::run_icmp_covert_result(target).await,
        "rop_chain_engine" => crate::advanced_stealth_engines::run_rop_chain_engine_result(target).await,
        "timing_evasion_engine" => crate::advanced_stealth_engines::run_timing_evasion_engine_result(target).await,
        "log_tampering_engine" => crate::advanced_stealth_engines::run_log_tampering_engine_result(target).await,
        "jit_spray" => crate::advanced_stealth_engines::run_jit_spray_result(target).await,
        "com_hijacking" => crate::advanced_stealth_engines::run_com_hijacking_result(target).await,
        "network_traffic_masking" => crate::advanced_stealth_engines::run_network_traffic_masking_result(target).await,
        "anti_debug_evasion" => crate::advanced_stealth_engines::run_anti_debug_evasion_result(target).await,
        "parent_pid_spoof" => crate::advanced_stealth_engines::run_parent_pid_spoof_result(target).await,

        // ── Advanced Crypto engines (new probes) ───────────────────────────────
        "oauth_advanced_attack" => crate::advanced_crypto_engines::run_oauth_advanced_attack_result(target).await,
        "saml_advanced_attack" => crate::advanced_crypto_engines::run_saml_advanced_attack_result(target).await,

        // ── Advanced Network engines (new probes / agent_required) ────────────
        "ipv6_advanced_attack" => crate::advanced_network_engines::run_ipv6_advanced_attack_result(target).await,

        // ── Advanced Supply Chain engines (new probes) ─────────────────────────
        "npm_package_attack" => crate::advanced_supply_chain_engines::run_npm_package_attack_result(target).await,
        "pypi_supply_chain" => crate::advanced_supply_chain_engines::run_pypi_supply_chain_result(target).await,
        "maven_supply_chain" => crate::advanced_supply_chain_engines::run_maven_supply_chain_result(target).await,
        "docker_image_poison" => crate::advanced_supply_chain_engines::run_docker_image_poison_result(target).await,

        // ── Advanced Malware engines (new probes / agent_required) ─────────────
        "ransomware_emulation" => crate::advanced_malware_engines::run_ransomware_emulation_result(target).await,

        // ── Next-Gen Arsenal: enterprise core ──────────────────────────────────
        "sap_erp_attack" => crate::enterprise_core_engines::run_sap_erp_attack_result(target, ctx).await,
        "mainframe_zos_attack" => crate::enterprise_core_engines::run_mainframe_zos_attack_result(target, ctx).await,

        // ── Next-Gen Arsenal: initial access / endpoint ────────────────────────
        "malvertising_seo_poison" => crate::initial_access_engines::run_malvertising_seo_poison_result(target, ctx).await,
        "infostealer_emulation" => crate::initial_access_engines::run_infostealer_emulation_result(target, ctx).await,
        "printer_mfp_attack" => crate::initial_access_engines::run_printer_mfp_attack_result(target, ctx).await,
        "radius_nac_bypass" => crate::initial_access_engines::run_radius_nac_bypass_result(target, ctx).await,

        _ => EngineResult::error(
            format!(
                "Engine '{}' is registered in PRODUCTION_ENGINE_IDS but has no dispatch runner in engine_dispatch",
                canonical
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn catalog_only_engine_returns_empty_ok() {
        let ctx = EngineRunContext::default();
        let r = run_engine(
            "totally_unknown_catalog_engine",
            "https://example.com",
            &ctx,
        )
        .await;
        assert!(r.success, "expected ok status: {}", r.message);
        assert!(r.findings.is_empty());
        assert!(
            r.message.contains("catalog-only"),
            "expected catalog-only message, got: {}",
            r.message
        );
    }

    #[tokio::test]
    async fn poe_synthesis_requires_tenant_context() {
        let ctx = EngineRunContext::default();
        let r = run_engine("poe_synthesis", "https://example.com", &ctx).await;
        assert!(!r.success, "expected error without tenant: {}", r.message);
        assert!(r.message.contains("tenant_id"));
    }
}
