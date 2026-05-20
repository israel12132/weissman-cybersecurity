//! Central dispatch for production scan engines — real probes only, no simulated findings.
//! Catalog-only registry IDs resolve via aliases to implemented engines.

use crate::engine_result::EngineResult;
use crate::stealth_engine::StealthConfig;
use serde_json::json;
use weissman_core::models::engine::{
    is_production_engine_id, production_engine_ids, resolve_engine_id,
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
}

pub fn production_ids_json() -> Vec<serde_json::Value> {
    production_engine_ids()
        .iter()
        .map(|id| json!({ "id": id }))
        .collect()
}

/// Run a production engine (or alias). Returns empty ok for unknown catalog-only IDs.
pub async fn run_engine(engine_id: &str, target: &str, ctx: &EngineRunContext) -> EngineResult {
    let canonical = resolve_engine_id(engine_id);
    if !is_production_engine_id(engine_id) {
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

    let stealth = ctx.stealth.as_ref();
    let tl = if ctx.target_list.is_empty() {
        vec![target.to_string()]
    } else {
        ctx.target_list.clone()
    };

    match canonical {
        "osint" => crate::osint_engine::run_osint_result(target, stealth).await,
        "asm" => {
            if let Some(ports) = ctx.asm_ports.as_deref() {
                crate::asm_engine::run_asm_result_with_ports_and_subdomains(
                    target,
                    ports,
                    Some(ctx.recon_subdomains.clone()),
                    stealth,
                )
                .await
            } else {
                crate::asm_engine::run_asm_result(target).await
            }
        }
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
        "graphql_attack" => crate::graphql_attack_engine::run_graphql_attack_result(target).await,
        "jwt_attack" => crate::jwt_attack_engine::run_jwt_attack_result(target).await,
        "oauth_oidc" => crate::oauth_oidc_engine::run_oauth_oidc_result(target).await,
        "http_smuggling" => crate::http_smuggling_engine::run_http_smuggling_result(target).await,
        "prototype_pollution" => {
            crate::prototype_pollution_engine::run_prototype_pollution_result(target).await
        }
        "ssrf_advanced" => crate::ssrf_advanced_engine::run_ssrf_advanced_result(target).await,
        "xxe" => crate::xxe_engine::run_xxe_result(target).await,
        "ssti" => crate::ssti_engine::run_ssti_result(target).await,
        "file_upload" => crate::file_upload_engine::run_file_upload_result(target).await,
        "websocket_attack" => crate::websocket_attack_engine::run_websocket_attack_result(target).await,
        "cache_poisoning" => crate::cache_poisoning_engine::run_cache_poisoning_result(target).await,
        "llm_path_fuzz" | "ollama_fuzz" => {
            crate::llm_path_fuzz_engine::run_llm_path_fuzz_result_cli(target, stealth, ctx.tenant_id)
                .await
                .into()
        }
        "semantic_ai_fuzz" => {
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
        "aws_attack" => crate::aws_attack_engine::run_aws_attack_result(target).await,
        "azure_attack" => crate::azure_attack_engine::run_azure_attack_result(target).await,
        "gcp_attack" => crate::gcp_attack_engine::run_gcp_attack_result(target).await,
        "k8s_container" => crate::k8s_container_engine::run_k8s_container_result(target).await,
        "iac_misconfig" => crate::iac_misconfig_engine::run_iac_misconfig_result(target).await,
        "serverless_attack" => crate::serverless_attack_engine::run_serverless_attack_result(target).await,
        "scada_ics" => crate::scada_ics_engine::run_scada_ics_result(target).await,
        "iot_firmware" => crate::iot_firmware_engine::run_iot_firmware_result(target).await,
        "ble_rf" => crate::ble_rf_engine::run_ble_rf_result(target).await,
        "edr_evasion" => crate::edr_evasion_engine::run_edr_evasion_result(target).await,
        "waf_bypass" => crate::waf_bypass_engine::run_waf_bypass_result(target).await,
        "timing_sidechannel" => {
            crate::timing_sidechannel_engine::run_timing_sidechannel_result(target).await
        }
        "antiforensics" => crate::antiforensics_engine::run_antiforensics_result(target).await,
        "stealth_engine" => crate::stealth_engine::run_stealth_engine_result(target).await,
        "pki_tls" => crate::pki_tls_engine::run_pki_tls_result(target).await,
        "pqc_scanner" => crate::pqc_scanner_engine::run_pqc_scanner_result(target).await,
        "password_spray" => crate::password_spray_engine::run_password_spray_result(target).await,
        "kerberoasting" => crate::kerberoasting_engine::run_kerberoasting_result(target).await,
        "saml_attack" => crate::saml_attack_engine::run_saml_attack_result(target).await,
        "crypto_engine" => crate::crypto_engine::run_crypto_engine_result(target).await,
        "bgp_dns_hijacking" => crate::bgp_dns_hijacking_engine::run_bgp_dns_hijacking_result(target).await,
        "ipv6_attack" => crate::ipv6_attack_engine::run_ipv6_attack_result(target).await,
        "mtls_grpc" => crate::mtls_grpc_engine::run_mtls_grpc_result(target).await,
        "smb_netbios" => crate::smb_netbios_engine::run_smb_netbios_result(target).await,
        "cicd_pipeline" => crate::cicd_pipeline_engine::run_cicd_pipeline_result(target).await,
        "container_registry" => {
            crate::container_registry_engine::run_container_registry_result(target).await
        }
        "sbom_analyzer" => crate::sbom_analyzer_engine::run_sbom_analyzer_result(target).await,
        "typosquatting_monitor" => {
            crate::typosquatting_monitor_engine::run_typosquatting_monitor_result(target).await
        }
        "kill_chain" => crate::kill_chain_engine::run_kill_chain_result(target).await,
        "oast_oob" => crate::oast_oob_engine::run_oast_oob_result(target).await,
        "deception_honeypot" => {
            crate::deception_honeypot_engine::run_deception_honeypot_result(target).await
        }
        "digital_twin" => crate::digital_twin_engine::run_digital_twin_result(target).await,
        "zero_day_prediction" => {
            crate::zero_day_prediction_engine::run_zero_day_prediction_result(target).await
        }
        "threat_emulation" => crate::threat_emulation_engine::run_threat_emulation_result(target).await,
        "microsecond_timing" => {
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
                .take(80)
                .collect();
            let urls_for = if urls.is_empty() {
                vec![tl.first().cloned().unwrap_or_else(|| target.to_string())]
            } else {
                urls
            };
            let cfg = crate::timing_engine::TimingConfig::default();
            crate::timing_engine::run_timing_attack_urls(&urls_for, stealth, &cfg, None).await
        }
        "http_feedback_fuzz" => {
            let anomalies = if let Some(tid) = ctx.tenant_id {
                crate::fuzzer::run_fuzzer_collect_tenant(target, "", Some(tid), None, None).await
            } else {
                crate::fuzzer::run_fuzzer_collect(target, "").await
            };
            let findings: Vec<serde_json::Value> = anomalies
                .iter()
                .map(|a| {
                    json!({
                        "type": "http_feedback_fuzz",
                        "title": a.anomaly_type.clone(),
                        "severity": "high",
                        "description": a.baseline_vs_anomaly.clone(),
                        "url": a.target_url.clone(),
                        "payload": a.payload.clone(),
                    })
                })
                .collect();
            EngineResult::ok(
                findings,
                format!("HTTP feedback fuzz: {} validated anomalies", anomalies.len()),
            )
        }
        _ => EngineResult::ok(
            vec![],
            format!("Engine '{}' has no runner (internal)", canonical),
        ),
    }
}
