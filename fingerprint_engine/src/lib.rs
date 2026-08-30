//! Large HTTP + engine crate: scoped clippy allows so `cargo clippy -- -D warnings` stays green
//! without mass refactors before release (correctness lints like `unwrap` remain enabled).
//!
//! The default `serde_json::json!` macro recursion limit (128) is exceeded by the
//! inline OpenAPI spec in `server_handlers_rest2.inc`; raise it crate-wide.
#![recursion_limit = "512"]
//!
//! # Safety policy
//! Unsafe code is denied crate-wide. The sole exception is `hpc_runtime::linux_affinity`, which
//! calls `libc::sched_setaffinity` for NUMA-aware thread pinning on Linux. That module carries an
//! explicit `#[allow(unsafe_code)]` with documented SAFETY invariants.
#![deny(unsafe_code)]
#![allow(
    clippy::collapsible_if,
    clippy::let_unit_value,
    clippy::manual_clamp,
    clippy::manual_range_contains,
    clippy::manual_strip,
    clippy::match_like_matches_macro,
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    clippy::nonminimal_bool,
    clippy::redundant_closure,
    clippy::redundant_field_names,
    clippy::redundant_pattern_matching,
    clippy::redundant_static_lifetimes,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::useless_asref,
    clippy::useless_format
)]

pub mod agent_remote_surface;
pub mod ai_redteam_engine;
pub mod alias_engine_runner;
pub mod alias_specialized_probes;
pub mod api_docs;
pub mod archival_engine;
pub mod arsenal_catalog;
pub mod arsenal_integrity;
pub mod arsenal_intel;
pub mod async_job_executor;
pub mod async_jobs;
pub mod attack_chain_planner;
pub mod attack_coverage;
pub mod attack_exposure;
pub mod attack_path;
pub mod audit_log;
pub mod auth_bootstrap;
pub mod auth_jwt;
pub mod auth_refresh;
pub mod battlespace_topology;
pub mod benchmark;
pub mod billing;
pub mod ceo;
pub mod chronos_engine;
pub mod client_isolation;
pub mod cloud_hunter;
pub mod cloud_integration_engine;
pub mod cognitive_starvation_engine;
pub mod compliance_engine;
pub mod compliance_posture;
pub mod correlation_rules;
pub mod council;
pub mod council_hitl;
pub mod council_synthesis;
pub mod critical_infra;
pub mod crypto_engine;
pub mod data_retention;
pub mod db;
pub mod db_backup;
pub mod demo_request;
pub mod discovery_engine;
pub mod elite_hardening;
pub mod embeddings;
pub mod engine_accounting;
pub mod engine_capabilities;
pub mod engine_contract;
pub mod engine_dispatch;
pub mod engine_fusion;
pub mod engine_probes;
pub mod engine_requirements;
pub mod engine_resilience;
pub mod engine_result;
pub mod engine_stack_runtime;
pub mod engine_telemetry;
pub mod engine_ui_manifest;
pub mod eternal_fuzz;
pub mod executive_pdf;
pub mod executive_summary;
pub mod exploit_synthesis_engine;
pub mod external_exposure_supreme;
pub mod fair_exposure_fusion_engine;
pub mod financial_risk;
pub mod finding_aging;
pub mod finding_attestation;
pub mod finding_live_verify;
pub mod findings_correlator;
pub mod findings_gate;
pub mod findings_persist;
pub mod fingerprint;
pub mod fleet_shaping;
pub mod fp_feedback;
pub mod fuzz_http_pool;
pub mod fuzz_oob;
pub mod fuzzer;
pub mod generative_fuzz_llm;
pub mod genesis_vault_cache;
pub mod hpc_runtime;
pub mod http;
pub mod identity_attack_chain_engine;
pub mod intel_epss;
pub mod intel_findings_backfill;
pub mod intel_http_cache;
pub mod intel_kev;
pub mod job_orchestration;
pub mod leak_hunter_engine;
pub mod liminal_boundary_engine;
pub mod liquid_matrix_engine;
pub mod nl_query;
pub mod notifications;
pub mod nvd_cve;
pub mod observability;
pub mod oidc_auth;
pub mod orchestrator;
pub mod outbound_http;
pub mod panic_shield;
pub mod payload_sync_worker;
pub mod pdf_report;
pub mod pentest_memory;
pub mod pipeline_context;
pub mod pipeline_engine;
pub mod pipeline_to_runtime_risk_engine;
pub mod poc_sandbox;
pub mod portfolio_posture;
pub mod posture_score;
pub mod priv_esc_cred_access;
pub mod recon;
pub mod regex_util;
pub mod remediation_priority;
pub mod remediation_verify;
pub mod reporter;
pub mod request_trace;
pub mod resilience;
pub mod risk_superposition_collapse_engine;
pub mod saas_idp_discovery;
pub mod safe_probe;
pub mod saml_auth;
pub mod scan_concurrency;
pub mod scan_http_client;
pub mod self_heal_recovery;
pub mod self_heal_shared;
pub mod self_healing;
pub mod semantic_fuzzer;
pub mod server_db;
pub mod signatures;
pub mod signup;
pub mod sla_forecast;
pub mod soar;
pub mod soar_playbook;
pub mod sovereign_active_defense_fusion_engine;
pub mod sovereign_defense_store;
pub mod sovereign_evolution;
pub mod sso_management;
pub mod stealth_engine;
pub mod stealth_queue;
pub mod stealth_scheduler;
pub mod strategic_analyzer;
pub mod superposition_followup;
pub mod supervised;
pub mod target_profile;
pub mod telemetry_bus;
pub mod template_engine;
pub mod template_probe;
pub mod tenant_quota;
pub mod threat_intel_engine;
pub mod timing_engine;
pub mod ueba_detector;
pub mod validator;

pub mod admin_users;
pub mod advanced_ai_engines;
// ── Next-Gen Arsenal (20 world-class additions) ──
pub mod advanced_apt_engines;
pub mod advanced_cloud_engines;
pub mod advanced_crypto_engines;
pub mod advanced_data_engines;
pub mod advanced_malware_engines;
pub mod advanced_mobile_engines;
pub mod advanced_network_engines;
pub mod advanced_ot_engines;
pub mod advanced_recon_engines;
pub mod advanced_social_engines;
pub mod advanced_stealth_engines;
pub mod advanced_supply_chain_engines;
pub mod advanced_web_engines;
pub mod adversarial_ml_engine;
pub mod agent_registry_sync;
pub mod alert_delivery;
pub mod alert_evaluator_worker;
pub mod antiforensics_engine;
pub mod arsenal_config;
pub mod asm_engine;
pub mod auth_mfa;
pub mod auto_domain_discovery_engine;
pub mod auto_heal;
pub mod auto_heal_job;
pub mod autonomous_identity;
pub mod autonomous_pentest_engine;
pub mod aws_attack_engine;
pub mod azure_attack_engine;
pub mod azure_repos_heal;
pub mod bgp_dns_hijacking_engine;
pub mod bitbucket_heal;
pub mod ble_rf_engine;
pub mod bola_idor_engine;
pub mod cache_poisoning_engine;
pub mod cicd_ast_scan;
pub mod cicd_interceptor;
pub mod cicd_pipeline_engine;
pub mod cloud_containment_engine;
pub mod cloud_posture_engine;
pub mod container_registry_engine;
pub mod crypto_policy;
pub mod dag_engine;
pub mod dag_pipeline;
pub mod deception_aws_canary;
pub mod deception_cf_blackhole;
pub mod deception_cloud_deploy_job;
pub mod deception_deploy;
pub mod deception_deployment_engine;
pub mod deception_engine;
pub mod deception_eventbridge;
pub mod deception_honeypot_engine;
pub mod digital_twin_engine;
pub mod ebpf_deploy;
pub mod edge_fuzz_bridge;
pub mod edge_heartbeat_batch;
pub mod edge_swarm_intel;
pub mod edr_evasion_engine;
pub mod email_dns_posture_engine;
pub mod endpoint_agents;
pub mod enterprise_core_engines;
pub mod exploit_crypto;
pub mod file_upload_engine;
pub mod gcp_attack_engine;
pub mod general;
pub mod gitlab_heal;
pub mod graphql_attack_engine;
pub mod heal_attestation;
pub mod heal_channel_select;
pub mod heal_channels;
pub mod heal_export;
pub mod heal_policy;
pub mod heal_priority;
pub mod heal_rate_limit;
pub mod heal_readiness;
pub mod heal_trends;
pub mod http_smuggling_engine;
pub mod iac_misconfig_engine;
pub mod identity_classifier;
pub mod identity_engine;
pub mod initial_access_engines;
pub mod iot_firmware_engine;
pub mod ipv6_attack_engine;
pub mod itdr;
pub mod jwt_attack_engine;
pub mod k8s_container_engine;
pub mod kerberoasting_engine;
pub mod kill_chain_engine;
pub mod leader_election;
pub mod llm_fuzzer_engine;
pub mod llm_path_fuzz_engine;
pub mod llm_redteam_engine;
pub mod mtls_grpc_engine;
pub mod ndr_beacon;
pub mod nexus_sovereign_swarm_engine;
pub mod oast_oob_engine;
pub mod oauth_oidc_engine;
pub mod osint_engine;
pub mod ot_ics_engine;
pub mod password_spray_engine;
pub mod pki_tls_engine;
pub mod pqc_kem;
pub mod pqc_scanner_engine;
pub mod predictive_analyzer;
pub mod prototype_pollution_engine;
pub mod rbac;
pub mod redteam_background_worker;
pub mod remediation_brief;
pub mod remediation_patch;
pub mod remediation_report;
pub mod risk_graph;
pub mod saml_attack_engine;
pub mod sbom_analyzer_engine;
pub mod scada_ics_engine;
pub mod scan_payload_redaction;
pub mod scan_routing;
pub mod scan_schedule_worker;
pub mod security_hardening;
pub mod security_posture;
pub mod security_startup;
pub mod self_improve;
pub mod serverless_attack_engine;
pub mod sigma_rules;
pub mod slack_interactivity;
pub mod smb_netbios_engine;
pub mod sovereign_c2;
pub mod sovereign_phantom_factory;
pub mod sovereign_self_scan;
pub mod ssrf_advanced_engine;
pub mod ssti_engine;
pub mod strategy_engine;
pub mod supply_chain_engine;
pub mod supreme_nerve_center;
pub mod swarm_orchestrator;
pub mod threat_analysis;
pub mod threat_emulation_engine;
pub mod threat_intel_ingestor;
pub mod timing_sidechannel_engine;
pub mod typosquatting_monitor_engine;
pub mod verification_sandbox;
pub mod waf_bypass_engine;
pub mod websocket_attack_engine;
pub mod ws_binary_protocol;
pub mod ws_intelligence_bus;
pub mod ws_race_executor;
pub mod ws_session;
pub mod ws_state_machine;
pub mod xxe_engine;
pub mod zero_day_prediction_engine;

pub use fingerprint::{
    get_top_ports, scan_ip_range, scan_ip_ranges_concurrent,
    scan_ip_ranges_concurrent_with_port_limit, scan_target_tech, scan_targets_concurrent,
};
pub use fuzzer::{
    run_fuzzer, run_fuzzer_collect, run_fuzzer_collect_tenant, Baseline, Mutator, ValidatedAnomaly,
};
pub use recon::{enum_subdomains, enum_subdomains_default, DEFAULT_SUBDOMAINS};
pub use risk_graph::export_risk_graph_json;
pub use safe_probe::{safe_probe, SafeProbeResult};
