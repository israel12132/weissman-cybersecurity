//! API route mounting — split from serve.rs for maintainability.
use super::*;
use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};
use std::sync::Arc;

/// Mount all API routes (handlers live in serve via handler_fragments includes).
pub fn mount_api_routes(root_routes: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    root_routes
        .route("/ws/command-center", get(ws_command_center))
        .route("/api/dashboard/stats", get(api_dashboard_stats))
        .route("/api/dashboard/exec-kpis", get(api_dashboard_exec_kpis))
        .route("/api/findings", get(api_findings))
        .route("/api/findings/clusters", get(api_findings_clusters))
        .route("/api/findings/export/csv", get(api_findings_export_csv))
        .route("/api/export/findings", get(api_findings_export_csv))
        .route(
            "/api/findings/:id/status",
            patch(api_findings_update_status),
        )
        .route("/api/findings/:id/verify", post(api_findings_verify_live))
        .route("/api/intel/status", get(api_intel_status))
        .route("/api/attack-coverage", get(api_attack_coverage))
        .route("/api/intel/suppressions", get(api_intel_suppressions))
        .route(
            "/api/intel/suppressions/:id",
            delete(api_intel_suppression_delete),
        )
        // Attack-path inference (Dijkstra over risk_graph weighted by CVSS+EPSS+KEV).
        .route(
            "/api/attack-paths/:client_id",
            get(api_attack_paths_for_client),
        )
        .route("/api/cem-dago/status", get(api_cem_dago_status))
        .route("/api/cem-dago/manifests", get(api_cem_dago_manifests))
        .route("/api/cem-dago/waves", get(api_cem_dago_waves))
        .route("/api/cem-dago/blackboard", get(api_cem_dago_blackboard))
        .route(
            "/api/attack-paths/:client_id/what-if",
            post(api_attack_paths_what_if),
        )
        .route(
            "/api/supreme-brain/:client_id",
            get(api_supreme_brain_for_client),
        )
        .route("/api/pentest-memory/stats", get(api_pentest_memory_stats))
        .route(
            "/api/battlespace/topology/:client_id",
            get(api_battlespace_topology),
        )
        .route(
            "/api/battlespace/techniques",
            get(api_battlespace_techniques),
        )
        .route(
            "/api/battlespace/shadow-preview",
            post(api_battlespace_shadow_preview),
        )
        // Unified threat analysis: attack-chain plan + multi-stage correlation over live findings.
        .route(
            "/api/threat-analysis/:client_id",
            get(api_threat_analysis_for_client),
        )
        // Global remediation priority: one ranked, root-cause-deduplicated "fix-first" program
        // fusing effective_risk (EPSS/KEV) + attack-graph choke points across all findings.
        .route(
            "/api/remediation/priority/:client_id",
            get(api_remediation_priority_for_client),
        )
        // Live per-client MITRE ATT&CK exposure: technique ranking + tactic rollup over findings.
        .route(
            "/api/attack-exposure/:client_id",
            get(api_attack_exposure_for_client),
        )
        // Board-level security posture score (0..100 + A–F) distilled from the fix-first program.
        .route(
            "/api/posture/score/:client_id",
            get(api_posture_score_for_client),
        )
        // Per-client compliance-framework posture: open findings rolled up per framework control.
        .route(
            "/api/compliance/posture/:client_id",
            get(api_compliance_posture_for_client),
        )
        // Proactive SLA breach forecast: cumulative breaches by 7/14/30/60/90-day horizons.
        .route(
            "/api/remediation/sla-forecast/:client_id",
            get(api_sla_forecast_for_client),
        )
        // Unified exec summary: posture + projection + SLA forecast + top actions in one query.
        .route(
            "/api/executive-summary/:client_id",
            get(api_executive_summary_for_client),
        )
        // Backlog-aging analytics: open findings bucketed by age x severity + aged-critical flags.
        .route(
            "/api/remediation/aging/:client_id",
            get(api_finding_aging_for_client),
        )
        // Complete arsenal inventory: every production engine + classification + category + ATT&CK.
        .route("/api/arsenal/catalog", get(api_arsenal_catalog))
        // Arsenal integrity/de-dup audit: distinct engines vs 100%-duplicate aliases (anti-fluff).
        .route("/api/arsenal/integrity", get(api_arsenal_integrity))
        // Stealth dispatch plan preview: how a batch of N engines drips out (concurrency/jitter/UA).
        .route("/api/arsenal/deploy-plan", get(api_arsenal_deploy_plan))
        // Stealth batch deploy: "run all" → backend drips the engines under concurrency/jitter/UA.
        .route("/api/arsenal/deploy", post(api_arsenal_deploy))
        // Arsenal recommendation: cross client exposure vs the engine arsenal → one-click plan + gaps.
        .route(
            "/api/arsenal/recommendation/:client_id",
            get(api_arsenal_recommendation_for_client),
        )
        // Portfolio (fleet-wide) posture: every client's grade rolled into one MSSP summary.
        .route("/api/portfolio/posture", get(api_portfolio_posture))
        // Portfolio (fleet-wide) ATT&CK exposure: technique ranking merged across all clients.
        .route(
            "/api/portfolio/attack-exposure",
            get(api_portfolio_attack_exposure),
        )
        .route(
            "/api/risk-graph/nodes/:node_id/flags",
            patch(api_risk_node_flags_patch),
        )
        // SOAR playbooks (DSL-driven automation; on-event dispatch + run history).
        .route(
            "/api/playbooks",
            get(api_playbooks_list).post(api_playbooks_create),
        )
        .route(
            "/api/playbooks/:id",
            patch(api_playbooks_update).delete(api_playbooks_delete),
        )
        .route("/api/playbooks/fire", post(api_playbooks_fire))
        .route("/api/playbooks/:id/runs", get(api_playbook_runs))
        .route("/api/soar/executions", get(api_soar_executions_list))
        .route("/api/soar/executions/:id", get(api_soar_execution_get))
        .route(
            "/api/soar/executions/:id/revert",
            post(api_soar_execution_revert),
        )
        .route(
            "/api/soar/executions/:id/hitl/approve",
            post(api_soar_hitl_approve),
        )
        .route(
            "/api/soar/executions/:id/hitl/deny",
            post(api_soar_hitl_deny),
        )
        // Financial blast-radius
        .route(
            "/api/financial-risk/:client_id",
            get(api_financial_risk_for_client),
        )
        .route(
            "/api/financial-risk/:client_id/apply-tags",
            post(api_apply_asset_tag_rules),
        )
        // Ask Weissman (NL → safe SQL)
        .route("/api/ask", post(api_ask))
        .route(
            "/api/elite-hardening/status",
            get(api_elite_hardening_status),
        )
        // UEBA + baseline/drift dashboard
        .route("/api/ueba/ingest", post(api_ueba_ingest))
        // NDR / ITDR live data ingest (feeds network beaconing/exfil + identity-threat detectors).
        .route("/api/ndr/flows", post(api_ndr_flows_ingest))
        .route("/api/itdr/auth-events", post(api_itdr_auth_ingest))
        .route("/api/ueba/anomalies", get(api_ueba_anomalies))
        .route("/api/baseline/summary", get(api_baseline_summary))
        .route("/api/baseline/drift", get(api_baseline_drift))
        .route("/api/baseline/anomalies", get(api_baseline_anomalies))
        .route("/api/config/public", get(api_config_public))
        .route("/api/engines/production", get(api_engines_production))
        .route("/api/engines/accounting", get(api_engines_accounting))
        .route("/api/engines/capabilities", get(api_engines_capabilities))
        .route("/api/engines/ui-manifests", get(api_engines_ui_manifests))
        .route(
            "/api/engines/ui-manifests/by-route",
            get(api_engines_ui_manifest_by_route),
        )
        .route(
            "/api/forensic/provenance-key",
            get(api_forensic_provenance_key),
        )
        .route("/api/engines/requirements", get(api_engines_requirements))
        .route("/api/intel/target-profile", get(api_intel_target_profile))
        .route("/api/stealth/status", get(api_stealth_status))
        .route("/api/stealth/config", post(api_stealth_config))
        .route(
            "/api/onboarding/tenant-status",
            get(api_onboarding_tenant_status),
        )
        .route("/api/onboarding/oast-test", post(api_onboarding_oast_test))
        .route(
            "/api/engines/nexus_sovereign_swarm/schema",
            get(api_nssi_config_schema),
        )
        .route("/api/engines/telemetry", get(api_engines_telemetry))
        .route("/api/openapi.json", get(api_openapi_spec))
        .route("/api/docs", get(crate::api_docs::api_docs_swagger))
        .route("/api/docs/", get(crate::api_docs::api_docs_swagger))
        .route("/api/auth/signup", post(crate::signup::api_signup))
        .route("/api/auth/verify", get(crate::signup::api_verify))
        .route(
            "/api/public/demo-request",
            post(crate::demo_request::api_demo_request),
        )
        .route("/api/reports", get(api_reports))
        .route("/api/command-center/scan", post(api_scan))
        .route(
            "/api/engines/top-tier/audit",
            get(api_engines_top_tier_audit),
        )
        .route(
            "/api/engines/top-tier/health-probe",
            post(api_top_tier_health_probe_start),
        )
        .route(
            "/api/engines/top-tier/:engine_id/history",
            get(api_top_tier_engine_history),
        )
        .route(
            "/api/engines/top-tier/:engine_id/export",
            get(api_top_tier_engine_export),
        )
        .route(
            "/api/engines/history-summary",
            get(api_engine_history_summary),
        )
        .route("/api/engines/history/:engine_id", get(api_engine_history))
        .route("/api/engines/export/:engine_id", get(api_engine_export))
        .route("/api/command-center/ticker", get(api_command_center_ticker))
        .route("/hooks/cicd/github", post(hook_cicd_github))
        .route("/hooks/cicd/gitlab", post(hook_cicd_gitlab))
        .route("/hooks/cicd/bitbucket", post(hook_cicd_bitbucket))
        .route("/hooks/cicd/scan", post(hook_cicd_generic))
        .route(
            "/api/metrics",
            get(crate::observability::api_prometheus_metrics_endpoint),
        )
        .route("/api/metrics/dashboard", get(api_metrics_dashboard))
        .route(
            "/api/rate-limits/status",
            get(crate::http::rate_limit_metrics::api_rate_limits_status),
        )
        .route(
            "/api/rate-limits/analytics",
            get(crate::http::rate_limit_metrics::api_rate_limits_analytics),
        )
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route("/api/auth/refresh", post(api_auth_refresh))
        .route("/api/auth/mfa/verify", post(api_auth_mfa_verify))
        .route("/api/auth/mfa/setup", post(api_auth_mfa_setup))
        .route("/api/auth/mfa/enable", post(api_auth_mfa_enable))
        .route("/api/auth/mfa/disable", post(api_auth_mfa_disable))
        .route("/api/auth/mfa/status", get(api_auth_mfa_status))
        // Endpoint Agent
        .route(
            "/api/agents/enrollment-tokens",
            post(api_agents_create_token),
        )
        .route("/api/agents/enroll", post(api_agents_enroll))
        // Renewal: an agent exchanges its long-lived secret for a fresh short-lived JWT.
        // Unauthenticated like /enroll — the secret is the credential — and rate-limited
        // alongside it in http/login_rate_limit.rs.
        .route("/api/agents/session", post(api_agents_session))
        .route("/api/agents/status", get(api_agents_status))
        .route("/api/agents/dispatch", post(api_agents_dispatch_task))
        .route("/api/agents/:id/kill-switch", post(api_agents_kill_switch))
        .route("/install/agent.sh", get(install_agent_sh))
        .route("/install/agent.ps1", get(install_agent_ps1))
        .route(
            "/install/binaries/:platform/weissman-agent",
            get(install_agent_binary),
        )
        .route(
            "/install/binaries/:platform/weissman-agent.sha256",
            get(install_agent_binary_sha256),
        )
        .route("/ws/agent", get(ws_agent))
        // Onboarding + billing (Paddle + self-serve register).
        .route("/api/onboarding/register", post(api_onboarding_register))
        .route("/api/onboarding/target", post(api_onboarding_target))
        .route(
            "/api/onboarding/launch-scan",
            post(api_onboarding_launch_scan),
        )
        .route("/api/billing/usage", get(api_billing_usage))
        .route(
            "/api/billing/checkout-session",
            post(api_billing_checkout_session),
        )
        .route("/api/billing/sync-paddle", post(api_billing_sync_paddle))
        .route("/api/webhooks/paddle", post(api_paddle_webhook))
        .route("/api/auth/oidc/begin", get(crate::oidc_auth::oidc_begin))
        .route(
            "/api/auth/oidc/callback",
            get(crate::oidc_auth::oidc_callback),
        )
        .route("/api/auth/saml/begin", get(crate::saml_auth::saml_begin))
        .route("/api/auth/saml/acs", post(crate::saml_auth::saml_acs))
        .route("/api/health", get(api_health))
        // Public status page promised by SLA_AND_STATUS.md §4 and linked from the site
        // footer and Terms of Service. Unauthenticated: nobody can read a status page
        // during an incident if it needs a login.
        .route("/status", get(public_status))
        .route("/api/ready", get(api_ready))
        .route("/api/quota", get(api_quota))
        .route("/api/audit-logs", get(api_audit_logs))
        .route("/api/audit/export", get(api_audit_export))
        .route("/api/auth/me", get(api_auth_me))
        // ── Admin user management (CEO/Superadmin only) ───────────────────────
        .route(
            "/api/admin/users",
            get(crate::admin_users::api_admin_users_list)
                .post(crate::admin_users::api_admin_users_create),
        )
        .route(
            "/api/admin/users/:id",
            patch(crate::admin_users::api_admin_users_update),
        )
        .route(
            "/api/admin/users/:id/deactivate",
            post(crate::admin_users::api_admin_users_deactivate),
        )
        .route(
            "/api/enterprise/settings",
            get(api_enterprise_settings_get).patch(api_enterprise_settings_patch),
        )
        .route("/api/system/backup", post(api_system_backup))
        .route(
            "/api/clients",
            get(api_clients_list).post(api_clients_create),
        )
        .route(
            "/api/clients/:id",
            get(api_clients_get)
                .post(api_clients_update)
                .delete(api_clients_delete),
        )
        .route(
            "/api/clients/:id/scan/run-all",
            post(api_clients_scan_run_all),
        )
        .route(
            "/api/clients/:id/config",
            get(api_client_config_get).patch(api_client_config_patch),
        )
        .route("/api/clients/:id/readiness", get(api_clients_readiness))
        .route(
            "/api/clients/:id/engagements",
            get(api_client_engagements_list).post(api_client_engagements_create),
        )
        .route(
            "/api/engagements/:id",
            get(api_engagement_get).patch(api_engagement_patch),
        )
        .route(
            "/api/clients/:id/evidence",
            get(api_client_evidence_list).post(api_client_evidence_upload),
        )
        .route(
            "/api/clients/:id/discovery/saas-idp",
            get(api_client_saas_idp_discovery),
        )
        .route("/api/evidence/:id/download", get(api_evidence_download))
        .route("/api/evidence/:id", delete(api_evidence_delete))
        .route(
            "/api/roe/override-requests",
            get(api_roe_override_requests_list),
        )
        .route(
            "/api/roe/override-requests/:id/approve",
            post(api_roe_override_request_approve),
        )
        .route(
            "/api/roe/override-requests/:id/reject",
            post(api_roe_override_request_reject),
        )
        .route("/api/clients/:id/findings", get(api_client_findings_all))
        .route("/api/clients/:id/export/csv", get(api_client_export_csv))
        .route("/api/clients/:id/report/pdf", get(api_client_report_pdf))
        .route(
            "/api/clients/:id/report/crypto-proof",
            get(api_client_report_crypto_proof),
        )
        .route(
            "/api/clients/:id/attack-surface-graph",
            get(api_client_attack_surface_graph),
        )
        .route(
            "/api/clients/:id/semantic-state-machine",
            get(api_client_semantic_state_machine),
        )
        .route(
            "/api/clients/:id/semantic-logic/reasoning",
            get(api_client_semantic_reasoning),
        )
        .route("/api/verify-audit/:hash", get(api_verify_audit))
        .route("/api/scan/status", get(api_scan_status))
        .route("/api/scan/start", post(api_scan_start))
        .route("/api/scan/stop", post(api_scan_stop))
        .route("/api/scan/run-all", post(api_scan_run_all))
        .route("/api/scan/all-engines", post(api_scan_all_engines))
        .route("/api/discovery/domains", post(api_discovery_domains))
        .route(
            "/api/scan/discovered-domains",
            post(api_scan_discovered_domains),
        )
        .route(
            "/api/system/configs",
            get(api_system_configs_get).post(api_system_configs_post),
        )
        .route("/api/command-center/deep-fuzz", post(api_deep_fuzz))
        .route("/api/general/mission", post(api_general_mission))
        .route("/api/council/debate", post(api_council_debate))
        // ── Council HITL approval queue ───────────────────────────────────────
        .route("/api/council/hitl/propose", post(api_council_hitl_propose))
        .route("/api/council/hitl/queue", get(api_council_hitl_queue))
        .route(
            "/api/council/hitl/:id/approve",
            post(api_council_hitl_approve),
        )
        .route(
            "/api/council/hitl/:id/reject",
            post(api_council_hitl_reject),
        )
        // ── Autonomous self-improvement engine console ───────────────────────
        .route("/api/self-improve/status", get(api_self_improve_status))
        .route("/api/self-improve/queue", get(api_self_improve_queue))
        .route("/api/self-improve/toggle", post(api_self_improve_toggle))
        .route("/api/self-improve/run-now", post(api_self_improve_run_now))
        .route(
            "/api/self-improve/:id/approve",
            post(api_self_improve_approve),
        )
        .route(
            "/api/self-improve/:id/reject",
            post(api_self_improve_reject),
        )
        // ── Structured OAST probe token registry ─────────────────────────────
        .route("/api/oast/probe", post(api_oast_probe_mint))
        .route("/api/oast/callbacks", get(api_oast_callbacks))
        .route("/api/oast/verify/:token", get(api_oast_probe_verify))
        // ── Template Engine (YAML) ──────────────────────────────────────────
        .route(
            "/api/template-engine/templates",
            get(api_template_engine_templates_list),
        )
        .route(
            "/api/template-engine/templates/:id",
            get(api_template_engine_template_get),
        )
        .route("/api/template-engine/run", post(api_template_engine_run))
        // ── AST smart fuzz preview (no traffic) ─────────────────────────────
        .route("/api/fuzz/ast-preview", post(api_fuzz_ast_preview))
        // ── Enterprise SSO management ─────────────────────────────────────────
        .route(
            "/api/sso/idps",
            get(crate::sso_management::api_sso_idps_list)
                .post(crate::sso_management::api_sso_idps_create),
        )
        .route(
            "/api/sso/idps/:id",
            get(crate::sso_management::api_sso_idp_get)
                .patch(crate::sso_management::api_sso_idp_patch)
                .delete(crate::sso_management::api_sso_idp_delete),
        )
        .route(
            "/api/sso/idps/:id/test",
            post(crate::sso_management::api_sso_idp_test),
        )
        .route(
            "/api/sso/idps/:id/toggle",
            post(crate::sso_management::api_sso_idp_toggle),
        )
        .route("/api/general/ascension", post(api_general_ascension))
        .route("/api/general/self-audit", post(api_general_self_audit))
        .route("/api/timing-scan/run", post(api_timing_scan_run))
        .route("/ws/timing", get(ws_timing))
        .route("/api/ai-redteam/run", post(api_ai_redteam_run))
        .route("/ws/ai-redteam", get(ws_ai_redteam))
        .route("/api/threat-intel/feed", get(api_threat_intel_feed))
        .route("/api/threat-intel/run", post(api_threat_intel_run))
        .route("/ws/threat-intel", get(ws_threat_intel))
        .route("/ws/swarm", get(ws_swarm))
        .route("/api/pipeline-scan/run", post(api_pipeline_scan_run))
        .route(
            "/api/clients/:id/cicd-findings",
            get(api_client_cicd_findings),
        )
        .route("/api/telemetry/stream", get(api_telemetry_stream))
        .route("/api/latency-probe", post(api_latency_probe))
        .route("/api/poe-scan/run", post(api_poe_scan_run))
        .route("/api/jobs", get(api_async_jobs_list))
        .route("/api/jobs/:job_id", get(api_async_job_status))
        .route("/api/poe-scan/status/:job_id", get(api_poe_scan_status))
        .route("/api/poe-scan/stream/:job_id", get(api_poe_scan_stream))
        .route(
            "/api/clients/:id/poe-findings",
            get(api_client_poe_findings),
        )
        .route(
            "/api/clients/:id/attack-chain",
            get(api_client_attack_chain),
        )
        .route("/api/identity/contexts", get(api_identity_contexts_alias))
        .route(
            "/api/clients/:id/identity-contexts",
            get(api_identity_contexts_list).post(api_identity_contexts_add),
        )
        .route(
            "/api/clients/:id/identity-contexts/:ctx_id",
            delete(api_identity_contexts_delete),
        )
        .route(
            "/api/clients/:id/privilege-escalation",
            get(api_privilege_escalation),
        )
        .route("/api/dag", get(api_dag_get))
        .route(
            "/api/pipeline/state",
            get(api_pipeline_state_get).patch(api_pipeline_state_patch),
        )
        .route("/api/risk/graph", get(api_risk_graph_alias))
        .route(
            "/api/clients/:id/risk-graph",
            get(api_risk_graph_get).post(api_risk_graph_build),
        )
        .route(
            "/api/clients/:id/risk-graph/export",
            get(api_risk_graph_export),
        )
        .route(
            "/api/clients/:id/runtime-traces",
            get(api_runtime_traces_list).post(api_runtime_traces_ingest),
        )
        .route(
            "/api/sovereign-defense/:client_id/dashboard",
            get(api_sovereign_defense_dashboard),
        )
        .route(
            "/api/sovereign-defense/:client_id/liquid-matrix/rotate",
            post(api_sovereign_defense_rotate),
        )
        .route(
            "/api/sovereign-defense/:client_id/chronos/events",
            get(api_sovereign_defense_chronos_events),
        )
        .route(
            "/api/sovereign-defense/:client_id/cognitive/sessions",
            get(api_sovereign_defense_cognitive_sessions),
        )
        .route(
            "/api/sovereign-defense/poison-library",
            get(api_sovereign_defense_poison_library),
        )
        .route("/api/clients/:id/auto-heal", post(api_auto_heal))
        .route(
            "/api/clients/:id/findings/:finding_id/brief",
            get(api_finding_brief).post(api_finding_brief),
        )
        .route(
            "/api/clients/:id/heal-requests",
            get(api_heal_requests_list),
        )
        .route("/api/clients/:id/heal-stats", get(api_heal_stats))
        .route("/api/clients/:id/heal-revert", post(api_heal_revert))
        .route("/api/clients/:id/heal-batch", post(api_heal_batch))
        .route("/api/clients/:id/deception", get(api_deception_list))
        .route(
            "/api/clients/:id/deception/generate",
            post(api_deception_generate),
        )
        .route(
            "/api/clients/:id/cloud-integration",
            patch(api_client_cloud_integration_patch),
        )
        .route(
            "/api/clients/:id/integrations",
            get(api_client_integrations_get).patch(api_client_integrations_patch),
        )
        .route(
            "/api/clients/:id/cloud-scan/run",
            post(api_client_cloud_scan_run),
        )
        .route("/api/compliance/posture", get(api_compliance_posture))
        .route(
            "/api/compliance/control-mappings",
            get(api_compliance_control_mappings),
        )
        .route(
            "/api/compliance/control-mappings/coverage",
            get(api_compliance_control_mappings_coverage),
        )
        // UI aliases: SystemConfiguration page + ComplianceFrameworks page expect these paths.
        .route(
            "/api/system/config",
            get(api_system_config_alias).put(api_system_config_put_alias),
        )
        .route(
            "/api/compliance/frameworks",
            get(api_compliance_frameworks_list),
        )
        .route(
            "/api/compliance/frameworks/:framework_id/controls",
            get(api_compliance_frameworks_controls),
        )
        .route(
            "/api/compliance/frameworks/:framework_id/report",
            get(api_compliance_frameworks_report),
        )
        .route("/api/search", get(api_global_search))
        .route(
            "/api/scans/schedules",
            get(api_scan_schedules_list).post(api_scan_schedules_create),
        )
        .route(
            "/api/scans/schedules/:id",
            put(api_scan_schedules_update)
                .patch(api_scan_schedules_patch)
                .delete(api_scan_schedules_delete),
        )
        .route("/api/scans/schedules/:id/run", post(api_scan_schedules_run))
        .route(
            "/api/alerts/rules",
            get(api_alert_rules_list).post(api_alert_rules_create),
        )
        .route(
            "/api/alerts/rules/:id",
            put(api_alert_rules_put)
                .patch(api_alert_rules_patch)
                .delete(api_alert_rules_delete),
        )
        .route("/api/alerts/rules/:id/test", post(api_alert_rules_test))
        .route(
            "/api/integrations",
            get(api_integrations_list).post(api_integrations_post),
        )
        .route("/api/integrations/:id/test", post(api_integrations_test))
        .route("/api/integrations/:id", delete(api_integrations_delete))
        .route("/api/ot-ics/devices", get(api_ot_ics_devices))
        .route("/api/mobile-security/apps", get(api_mobile_security_apps))
        .route("/api/soc/incidents", get(api_soc_incidents))
        .route(
            "/api/soc/incidents/:id/playbook-steps",
            patch(api_soc_incident_playbook_steps_patch),
        )
        .route("/api/soc/hunts", get(api_soc_hunts))
        .route("/api/soc/iocs", get(api_soc_iocs))
        .route("/api/soc/kill-chains", get(api_soc_kill_chains))
        .route("/api/soc/exploit-lab", get(api_soc_exploit_lab))
        .route("/api/soc/ai-patterns", get(api_soc_ai_patterns))
        .route(
            "/api/soc/social-engineering",
            get(api_soc_social_engineering),
        )
        .route(
            "/api/soc/social-engineering/campaigns",
            post(api_soc_social_engineering_campaigns_post),
        )
        .route("/api/soc/network-protocols", get(api_soc_network_protocols))
        .route("/api/reports/executive", get(api_reports_executive))
        .route(
            "/api/sovereign/phantom-trap",
            post(api_sovereign_phantom_trap),
        )
        .route("/api/deception/triggered", post(api_deception_triggered))
        .route("/api/deception/aws-events", post(api_deception_aws_events))
        .route(
            "/api/integrations/slack/interactivity",
            post(api_slack_interactivity),
        )
        .route("/api/v1/alerts/aws-canary", post(api_v1_alerts_aws_canary))
        .route(
            "/api/clients/:id/deception/deploy-cloud",
            post(api_deception_deploy_cloud),
        )
        .route("/api/heal-verify/:job_id/steps", get(api_heal_verify_steps))
        .route("/api/heal-verify/:job_id", get(api_heal_verify_status))
        .route("/api/heal-verify/:job_id/patch", get(api_heal_verify_patch))
        .route(
            "/api/heal-verify/:job_id/attestation",
            get(api_heal_verify_attestation),
        )
        .route(
            "/api/heal-verify/:job_id/report",
            get(api_heal_verify_report),
        )
        .route(
            "/api/heal-verify/:job_id/report.json",
            get(api_heal_verify_report_json),
        )
        .route("/api/heal-verify/:job_id/sarif", get(api_heal_verify_sarif))
        .route("/api/heal-readiness", get(api_heal_readiness))
        .route("/api/clients/:id/heal-trends", get(api_heal_trends))
        .route("/api/clients/:id/heal-priorities", get(api_heal_priorities))
        .route(
            "/api/clients/:id/findings/:finding_id/channel-suggestion",
            get(api_channel_suggestion),
        )
        .route("/api/clients/:id/swarm/run", post(api_swarm_run))
        .route("/api/swarm/events", get(api_swarm_events))
        .route("/api/threat-ingest/run", post(api_threat_ingest_run))
        .route("/api/sbom/components", get(api_sbom_components_alias))
        .route("/api/sbom/export", get(api_sbom_export_alias))
        .route(
            "/api/clients/:id/sbom/components",
            get(api_client_sbom_list).post(api_client_sbom_post),
        )
        .route("/api/clients/:id/sbom/export", get(api_client_sbom_export))
        .route(
            "/api/containment/rules",
            get(api_containment_rules_alias).post(api_containment_rules_post_alias),
        )
        .route(
            "/api/containment/rules/:id",
            patch(api_containment_rules_patch_alias)
                .put(api_containment_rules_patch_alias)
                .delete(api_containment_rules_delete_alias),
        )
        .route(
            "/api/clients/:id/containment-rules",
            get(api_containment_rules_list).post(api_containment_rules_post),
        )
        .route(
            "/api/clients/:id/containment/execute",
            post(api_containment_execute),
        )
        .route("/api/clients/:id/llm-fuzz/run", post(api_llm_fuzz_run))
        .route("/api/clients/:id/llm-fuzz/events", get(api_llm_fuzz_events))
        .route(
            "/api/clients/:id/llm-fuzz/summary",
            get(api_llm_fuzz_summary),
        )
        .route(
            "/api/clients/:id/vulnerabilities/:vid/decrypt-poc",
            post(api_decrypt_sealed_poc),
        )
        .route("/api/payload-sync/status", get(api_payload_sync_status))
        .route("/api/payload-sync/payloads", get(api_payload_sync_payloads))
        .route("/api/payload-sync/run", post(api_payload_sync_run))
        .route(
            "/api/discovery-knowledge/stats",
            get(api_discovery_knowledge_stats),
        )
        .route("/api/edge-swarm/nodes", get(api_edge_swarm_nodes))
        .route("/api/edge-swarm/heartbeat", post(api_edge_swarm_heartbeat))
        .route("/api/edge-fuzz/manifest", get(api_edge_fuzz_manifest))
        .route("/api/crypto/capabilities", get(api_crypto_capabilities))
        .route("/api/crypto/pqc-selftest", get(api_crypto_pqc_selftest))
        .route(
            "/api/clients/:id/ot-ics/fingerprints",
            get(api_client_ot_ics_fingerprints),
        )
        .route(
            "/api/ceo/council/sessions/:job_id/stream",
            get(api_ceo_council_session_sse),
        )
        .route(
            "/api/ceo/strategy",
            get(api_ceo_strategy_get).patch(api_ceo_strategy_patch),
        )
        .route("/api/ceo/war-room/stream", get(api_ceo_war_room_sse))
        .route("/api/ceo/telemetry", get(api_ceo_telemetry_get))
        .route(
            "/api/ceo/supreme/nerve-center",
            get(api_ceo_supreme_nerve_center_get),
        )
        .route("/api/ceo/jobs/live", get(api_ceo_jobs_live_get))
        .route(
            "/api/ceo/global-safe-mode",
            patch(api_ceo_global_safe_patch),
        )
        .route(
            "/api/ceo/god-mode/snapshot",
            get(api_ceo_god_mode_snapshot_get),
        )
        .route(
            "/api/ceo/tenant/engines",
            get(api_ceo_tenant_engines_get)
                .put(api_ceo_tenant_engines_put)
                .patch(api_ceo_tenant_engines_put),
        )
        .route(
            "/api/ceo/god-mode/scan-interval",
            patch(api_ceo_god_mode_scan_interval_patch).post(api_ceo_god_mode_scan_interval_patch),
        )
        .route(
            "/api/ceo/hpc/policy",
            get(api_ceo_hpc_policy_get)
                .put(api_ceo_hpc_policy_put)
                .post(api_ceo_hpc_policy_put),
        )
        .route(
            "/api/ceo/vault/export/criticals",
            get(api_ceo_vault_export_criticals),
        )
        .route(
            "/api/ceo/vault/secrets",
            get(api_ceo_vault_secrets_alias).post(api_ceo_vault_secrets_post),
        )
        .route(
            "/api/ceo/vault/secrets/:id/access",
            post(api_ceo_vault_secrets_access),
        )
        .route(
            "/api/ceo/vault/secrets/:id/copy",
            post(api_ceo_vault_secrets_copy),
        )
        .route(
            "/api/ceo/vault/secrets/:id",
            put(api_ceo_vault_secrets_put).delete(api_ceo_vault_secrets_delete),
        )
        .route(
            "/api/ceo/vault",
            get(api_ceo_vault_list).post(api_ceo_vault_post),
        )
        .route("/api/ceo/vault/:id/match", post(api_ceo_vault_match))
        .route(
            "/api/ceo/genesis/vault/:id/match",
            post(api_ceo_vault_match),
        )
        .route("/api/ceo/vault/:id", get(api_ceo_vault_get))
        .route(
            "/api/ceo/sovereign/buffer",
            get(api_ceo_sovereign_buffer_get),
        )
        .route(
            "/api/ceo/sovereign/trigger",
            post(api_ceo_sovereign_trigger_post),
        )
        .route("/api/ceo/suspended-graphs", get(api_ceo_suspended_list))
        .route(
            "/api/ceo/suspended-graphs/:id/resume",
            post(api_ceo_suspended_resume),
        )
        .route("/api/ceo/suspended-graphs/:id", get(api_ceo_suspended_get))
        .route(
            "/api/sovereign/operator/chat",
            post(api_sovereign_operator_chat),
        )
        .route(
            "/api/sovereign/operator/session",
            get(api_sovereign_operator_session_get),
        )
        .route(
            "/api/sovereign/operator/knowledge",
            get(api_sovereign_operator_knowledge_get),
        )
        .route(
            "/api/sovereign/operator/logs",
            get(api_sovereign_operator_logs_get),
        )
        .route(
            "/api/sovereign/operator/windows",
            get(api_sovereign_operator_windows_get),
        )
        .route(
            "/api/sovereign/operator/tools",
            post(api_sovereign_operator_tools_post),
        )
        .route(
            "/api/sovereign/operator/tune",
            post(api_sovereign_operator_tune_post),
        )
        .route(
            "/api/sovereign/operator/race",
            post(api_sovereign_operator_race_post),
        )
        .route(
            "/api/sovereign/operator/stream",
            get(api_sovereign_operator_stream),
        )
        .route(
            "/api/sovereign/operator/stream-ticket",
            post(api_sovereign_operator_stream_ticket),
        )
        .route(
            "/api/sovereign/operator/memory",
            get(api_sovereign_operator_memory_get),
        )
        .route(
            "/api/sovereign/operator/forge",
            get(api_sovereign_operator_forge_get),
        )
        .route(
            "/api/sovereign/operator/scripts",
            get(api_sovereign_operator_scripts_get),
        )
        .route(
            "/api/security/posture-score",
            get(api_security_posture_score),
        )
        .route("/api/engines/:engine_id/contract", get(api_engine_contract))
        .route(
            "/api/compliance/evidence-pack/:client_id",
            get(api_compliance_evidence_pack),
        )
}
