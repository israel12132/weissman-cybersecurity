//! Large HTTP + engine crate: scoped clippy allows so `cargo clippy -- -D warnings` stays green
//! without mass refactors before release (correctness lints like `unwrap` remain enabled).
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
    clippy::useless_format,
)]

pub mod async_job_executor;
pub mod async_jobs;
pub mod ai_redteam_engine;
pub mod archival_engine;
pub mod audit_log;
pub mod auth_jwt;
pub mod auth_refresh;
pub mod billing;
pub mod observability;
pub mod request_trace;
pub mod panic_shield;
pub mod scan_concurrency;
pub mod cloud_hunter;
pub mod cloud_integration_engine;
pub mod compliance_engine;
pub mod council;
pub mod council_hitl;
pub mod council_synthesis;
pub mod sso_management;
pub mod ceo;
pub mod crypto_engine;
pub mod eternal_fuzz;
pub mod genesis_vault_cache;
pub mod sovereign_evolution;
pub mod db;
pub mod data_retention;
pub mod db_backup;
pub mod discovery_engine;
pub mod engine_result;
pub mod executive_pdf;
pub mod exploit_synthesis_engine;
pub mod fingerprint;
pub mod fuzz_http_pool;
pub mod fuzz_oob;
pub mod generative_fuzz_llm;
pub mod fuzzer;
pub mod leak_hunter_engine;
pub mod notifications;
pub mod nvd_cve;
pub mod outbound_http;
pub mod intel_http_cache;
pub mod oidc_auth;
pub mod payload_sync_worker;
pub mod pdf_report;
pub mod pipeline_context;
pub mod pipeline_engine;
pub mod recon;
pub mod regex_util;
pub mod reporter;
pub mod resilience;
pub mod safe_probe;
pub mod scan_http_client;
pub mod saml_auth;
pub mod semantic_fuzzer;
pub mod http;
pub mod hpc_runtime;
pub mod orchestrator;
pub mod server_db;
pub mod signatures;
pub mod stealth_engine;
pub mod strategic_analyzer;
pub mod threat_intel_engine;
pub mod timing_engine;
pub mod validator;

pub mod auto_domain_discovery_engine;
pub mod asm_engine;
pub mod auto_heal;
pub mod auto_heal_job;
pub mod scan_routing;
pub mod edge_swarm_intel;
pub mod edge_heartbeat_batch;
pub mod deception_cloud_deploy_job;
pub mod deception_cf_blackhole;
pub mod bola_idor_engine;
pub mod cicd_ast_scan;
pub mod cicd_interceptor;
pub mod cloud_containment_engine;
pub mod crypto_policy;
pub mod dag_engine;
pub mod dag_pipeline;
pub mod deception_aws_canary;
pub mod deception_deploy;
pub mod deception_deployment_engine;
pub mod deception_engine;
pub mod deception_eventbridge;
pub mod sovereign_phantom_factory;
pub mod sovereign_self_scan;
pub mod sovereign_c2;
pub mod ebpf_deploy;
pub mod edge_fuzz_bridge;
pub mod exploit_crypto;
pub mod identity_classifier;
pub mod identity_engine;
pub mod autonomous_identity;
pub mod llm_fuzzer_engine;
pub mod llm_path_fuzz_engine;
pub mod osint_engine;
pub mod ot_ics_engine;
pub mod pqc_kem;
pub mod predictive_analyzer;
pub mod redteam_background_worker;
pub mod risk_graph;
pub mod security_hardening;
pub mod supply_chain_engine;
pub mod swarm_orchestrator;
pub mod strategy_engine;
pub mod general;
pub mod threat_intel_ingestor;
pub mod verification_sandbox;
pub mod graphql_attack_engine;
pub mod jwt_attack_engine;
pub mod oauth_oidc_engine;
pub mod http_smuggling_engine;
pub mod prototype_pollution_engine;
pub mod ssrf_advanced_engine;
pub mod xxe_engine;
pub mod ssti_engine;
pub mod file_upload_engine;
pub mod websocket_attack_engine;
pub mod cache_poisoning_engine;
pub mod adversarial_ml_engine;
pub mod antiforensics_engine;
pub mod autonomous_pentest_engine;
pub mod aws_attack_engine;
pub mod azure_attack_engine;
pub mod bgp_dns_hijacking_engine;
pub mod ble_rf_engine;
pub mod cicd_pipeline_engine;
pub mod container_registry_engine;
pub mod deception_honeypot_engine;
pub mod digital_twin_engine;
pub mod edr_evasion_engine;
pub mod gcp_attack_engine;
pub mod iac_misconfig_engine;
pub mod iot_firmware_engine;
pub mod ipv6_attack_engine;
pub mod k8s_container_engine;
pub mod kerberoasting_engine;
pub mod kill_chain_engine;
pub mod llm_redteam_engine;
pub mod mtls_grpc_engine;
pub mod oast_oob_engine;
pub mod password_spray_engine;
pub mod pki_tls_engine;
pub mod pqc_scanner_engine;
pub mod saml_attack_engine;
pub mod sbom_analyzer_engine;
pub mod scada_ics_engine;
pub mod serverless_attack_engine;
pub mod smb_netbios_engine;
pub mod threat_emulation_engine;
pub mod timing_sidechannel_engine;
pub mod typosquatting_monitor_engine;
pub mod waf_bypass_engine;
pub mod zero_day_prediction_engine;
pub mod admin_users;

pub use fingerprint::{
    get_top_ports, scan_ip_range, scan_ip_ranges_concurrent,
    scan_ip_ranges_concurrent_with_port_limit, scan_target_tech, scan_targets_concurrent,
};
pub use fuzzer::{
    run_fuzzer, run_fuzzer_collect, run_fuzzer_collect_tenant, Baseline, Mutator, ValidatedAnomaly,
};
pub use recon::{enum_subdomains, enum_subdomains_default, DEFAULT_SUBDOMAINS};
pub use safe_probe::{safe_probe, SafeProbeResult};
pub use risk_graph::export_risk_graph_json;
