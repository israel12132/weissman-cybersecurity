//! Live Palo Alto displacement map — code-backed SKU overlap, not marketing scores.
//!
//! Weissman is an assessment + autonomous-response platform. PANW NGFW / Prisma Access /
//! WildFire are **non-goals**. Overlap SKUs (Prisma Cloud, Xpanse, Cortex XDR) are scored
//! only from live tenant connectors, snapshots, and engine capability kinds.
//! Empty connectors yield `unproven_*` or `unavailable` — never a fabricated win.

use crate::engine_capabilities;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

pub const API_PATH: &str = "/api/competitive/panw-displacement";

/// Product absences proven by repository search — not tenant telemetry.
pub const CODE_ABSENCES: &[&str] = &[
    "scim",
    "chronicle_siem_adapter",
    "tenant_residency_column",
    "prisma_access_ngfw_product",
    "wildfire_sandbox_product",
    "dedicated_ciem_identity_graph",
    "continuous_multi_cloud_cnapp_connector",
];

const CATEGORY_TRUTH: &str = "Weissman is live-evidence assessment and autonomous response. \
Palo Alto Networks sells prevention at the network edge (NGFW, Prisma Access, WildFire). \
Competing as a firewall replacement is a category error. Win the overlap (CNAPP / EASM / XDR) \
with live proof, then sell the loop PANW cannot ship: first-seen surface delta fused with \
HTTP/1↔HTTP/2 protocol schism evidence on only the new hosts.";

#[derive(Debug, Clone)]
pub struct LiveSignals {
    pub client_id: Option<i64>,
    pub db_ok: bool,
    pub client_found: bool,
    pub aws_role_configured: bool,
    pub gcp_project_configured: bool,
    pub azure_configured: bool,
    pub sso_idp_count: i64,
    pub enrolled_agents_online: i64,
    pub enrolled_agents_total: i64,
    pub soar_providers: Vec<String>,
    pub surface_snapshot_count: i64,
    pub surface_baseline_only: bool,
    pub surface_added: i64,
    pub surface_unavailable: bool,
    pub certstream_connected: bool,
    pub certstream_enabled: bool,
    pub oast_configured: bool,
    pub nvd_api_key: bool,
}

impl Default for LiveSignals {
    fn default() -> Self {
        Self {
            client_id: None,
            db_ok: true,
            client_found: false,
            aws_role_configured: false,
            gcp_project_configured: false,
            azure_configured: false,
            sso_idp_count: 0,
            enrolled_agents_online: 0,
            enrolled_agents_total: 0,
            soar_providers: Vec::new(),
            surface_snapshot_count: 0,
            surface_baseline_only: false,
            surface_added: 0,
            surface_unavailable: false,
            certstream_connected: false,
            certstream_enabled: false,
            oast_configured: false,
            nvd_api_key: false,
        }
    }
}

struct SkuSpec {
    id: &'static str,
    panw_sku: &'static str,
    panw_label: &'static str,
    role: &'static str,
    engines: &'static [&'static str],
    honest_gap: &'static str,
}

const SKUS: &[SkuSpec] = &[
    SkuSpec {
        id: "prisma_cloud",
        panw_sku: "Prisma Cloud",
        panw_label: "CNAPP (CSPM / CWPP / CIEM / IaC)",
        role: "overlap",
        engines: &[
            "cloud_posture",
            "aws_attack",
            "azure_attack",
            "gcp_attack",
            "iac_misconfig",
            "k8s_container",
            "serverless_attack",
            "cnapp_continuous",
            "cloud_iam_escalation",
        ],
        honest_gap: "cloud_posture is live AWS AssumeRole CSPM and refuses without aws_cross_account_role_arn. \
Azure/GCP are dual-plane attack engines, not a Prisma-class continuous multi-cloud connector. \
cnapp_continuous tags a fusion; cloud_iam_escalation is an alias into aws_attack — no dedicated CIEM graph.",
    },
    SkuSpec {
        id: "cortex_xpanse",
        panw_sku: "Cortex Xpanse",
        panw_label: "External attack surface management",
        role: "overlap",
        engines: &[
            "osint",
            "asm",
            "first_mover_surface_delta",
            "first_mover_delta_fusion",
            "exposure_schism_fusion",
            "subdomain_takeover",
            "liminal_boundary",
        ],
        honest_gap: "Xpanse wins org-hierarchy / M&A attribution at planetary scale. Weissman wins \
first-seen host diffs plus protocol-schism proof on those hosts. Empty snapshots are unproven, not a loss.",
    },
    SkuSpec {
        id: "cortex_xdr",
        panw_sku: "Cortex XDR / XSIAM",
        panw_label: "Endpoint detection, NDR, SIEM-class correlation",
        role: "overlap",
        engines: &["kill_chain", "itdr", "fair_exposure_fusion"],
        honest_gap: "UEBA/NDR/SOAR exist as platform subsystems, not a Cortex sensor SKU. \
ITDR is feed-dependent. Without enrolled agents the XDR RFP row is a live gap.",
    },
    SkuSpec {
        id: "prisma_access",
        panw_sku: "Prisma Access / NGFW",
        panw_label: "SASE and next-gen firewall",
        role: "non_goal",
        engines: &["ngfw_posture", "weissman_vngfw", "sase_security_bypass"],
        honest_gap: "Those engines fingerprint someone else's management plane over HTTP/TCP. \
Weissman does not terminate traffic, inspect WildFire samples, or replace Prisma Access.",
    },
    SkuSpec {
        id: "wildfire",
        panw_sku: "WildFire / URL filtering",
        panw_label: "Sandbox and cloud security services",
        role: "non_goal",
        engines: &[],
        honest_gap: "No malware detonation cloud and no URL category database. Do not claim this SKU.",
    },
    SkuSpec {
        id: "iot_ot",
        panw_sku: "PANW IoT / OT Security",
        panw_label: "Industrial and IoT visibility",
        role: "overlap",
        engines: &[
            "scada_ics",
            "modbus_attack",
            "bacnet_attack",
            "dnp3_attack",
            "ot_sis_triton_attack",
            "iot_shodan_scan",
        ],
        honest_gap: "RoE-gated industrial probes, not a Claroty/Dragos or PANW IoT product replacement. \
Safe-proof findings only — no weaponized PLC writes.",
    },
    SkuSpec {
        id: "ai_security",
        panw_sku: "PANW AI security",
        panw_label: "AI runtime / LLM attack surface",
        role: "overlap",
        engines: &[
            "llm_jailbreak",
            "llm_redteam",
            "llm_red_team_advanced",
            "llm_agent_hijack",
            "prompt_injection_chain",
        ],
        honest_gap: "Live LLM attack engines on main. llm_ultra_guard is an open PR, not this checkout.",
    },
];

#[derive(Debug, Clone, Serialize)]
struct EngineKindRow {
    id: String,
    kind: String,
    remote_detection: bool,
}

fn engine_rows(ids: &[&str]) -> Vec<EngineKindRow> {
    ids.iter()
        .map(|id| {
            let kind = engine_capabilities::classify(id);
            EngineKindRow {
                id: (*id).to_string(),
                kind: kind.to_string(),
                remote_detection: engine_capabilities::detects_remotely(kind, id),
            }
        })
        .collect()
}

/// Structured Prisma Cloud honesty — AWS AssumeRole CSPM only.
/// Azure/GCP onboarding flags are attack-engine dual-planes, never a Prisma-class CNAPP.
fn prisma_cloud_honesty(s: &LiveSignals) -> Value {
    let verdict = verdict_for("prisma_cloud", s);
    let scope = if s.aws_role_configured {
        "aws_assumerole_only"
    } else {
        "no_aws_assumerole"
    };
    json!({
        "sku_id": "prisma_cloud",
        "cspm_plane": "aws_assumerole",
        "cspm_engine": "cloud_posture",
        "cspm_refuses_without_role": true,
        "aws_role_configured": s.aws_role_configured,
        "azure_configured": s.azure_configured,
        "gcp_project_configured": s.gcp_project_configured,
        "azure_is_cnapp_connector": false,
        "gcp_is_cnapp_connector": false,
        "continuous_multi_cloud_cnapp": false,
        "cnapp_continuous_is_fusion_tag": true,
        "cloud_iam_escalation_is_aws_attack_alias": true,
        "replacement_claim": false,
        "scope": scope,
        "verdict": verdict,
    })
}

pub fn verdict_for(sku_id: &str, s: &LiveSignals) -> &'static str {
    match sku_id {
        "prisma_access" | "wildfire" => "non_goal",
        "iot_ot" | "ai_security" => "overlap_probe",
        "prisma_cloud" => {
            if !s.db_ok {
                "unavailable"
            } else if s.client_id.is_some() && !s.client_found {
                "unavailable"
            } else if s.aws_role_configured {
                "live_partial"
            } else if s.client_id.is_none() {
                "unproven_no_client"
            } else {
                "unproven_connector"
            }
        }
        "cortex_xpanse" => {
            if !s.db_ok || s.surface_unavailable {
                "unavailable"
            } else if s.client_id.is_none() {
                "unproven_no_client"
            } else if s.surface_snapshot_count == 0 {
                "unproven"
            } else if s.surface_baseline_only {
                "unproven_baseline"
            } else {
                "live_win"
            }
        }
        "cortex_xdr" => {
            if !s.db_ok {
                "unavailable"
            } else if s.enrolled_agents_online > 0 {
                "live_partial"
            } else if s.enrolled_agents_total > 0 {
                "live_gap_sensor_offline"
            } else {
                "live_gap_sensor"
            }
        }
        _ => "unproven",
    }
}

/// Build the operator JSON. Pure function of live signals — no I/O.
pub fn displacement_json(s: &LiveSignals) -> Value {
    let mut live_win = 0u32;
    let mut live_partial = 0u32;
    let mut live_gap = 0u32;
    let mut unproven = 0u32;
    let mut non_goal = 0u32;
    let mut overlap_probe = 0u32;
    let mut unavailable = 0u32;

    let skus: Vec<Value> = SKUS
        .iter()
        .map(|spec| {
            let verdict = verdict_for(spec.id, s);
            match verdict {
                "live_win" => live_win += 1,
                "live_partial" => live_partial += 1,
                v if v.starts_with("live_gap") => live_gap += 1,
                "non_goal" => non_goal += 1,
                "overlap_probe" => overlap_probe += 1,
                "unavailable" => unavailable += 1,
                _ => unproven += 1,
            }
            let engines = engine_rows(spec.engines);
            json!({
                "id": spec.id,
                "panw_sku": spec.panw_sku,
                "panw_label": spec.panw_label,
                "role": spec.role,
                "verdict": verdict,
                "weissman_engines": engines,
                "honest_gap": spec.honest_gap,
            })
        })
        .collect();

    json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "category_truth": CATEGORY_TRUTH,
        "client_id": s.client_id,
        "db_ok": s.db_ok,
        "client_found": s.client_found,
        "live_connectors": {
            "aws_role_configured": s.aws_role_configured,
            "gcp_project_configured": s.gcp_project_configured,
            "azure_configured": s.azure_configured,
            "sso_idp_count": s.sso_idp_count,
            "enrolled_agents_online": s.enrolled_agents_online,
            "enrolled_agents_total": s.enrolled_agents_total,
            "soar_providers": s.soar_providers,
            "surface": {
                "snapshot_count": s.surface_snapshot_count,
                "baseline_only": s.surface_baseline_only,
                "added": s.surface_added,
                "unavailable": s.surface_unavailable,
            },
            "first_mover_nerve": {
                "certstream_enabled": s.certstream_enabled,
                "certstream_connected": s.certstream_connected,
                "oast_configured": s.oast_configured,
                "nvd_api_key": s.nvd_api_key,
            },
        },
        "code_absences": CODE_ABSENCES,
        "prisma_cloud_honesty": prisma_cloud_honesty(s),
        "unique_moat": {
            "engine_id": "exposure_schism_fusion",
            "why_panw_cannot_copy": "Xpanse inventories. Prisma postures accounts. Cortex detects endpoints. \
    None ship a single agentless product that diffs first-seen internet hosts and then proves \
    HTTP/1.1↔HTTP/2 / Vary / rewrite-header schisms on only those new hosts with kill-chain evidence.",
        },
        "counts": {
            "live_win": live_win,
            "live_partial": live_partial,
            "live_gap": live_gap,
            "unproven": unproven,
            "non_goal": non_goal,
            "overlap_probe": overlap_probe,
            "unavailable": unavailable,
            "skus": skus.len(),
        },
        "skus": skus,
    })
}

pub async fn load_live_signals(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> LiveSignals {
    let mut s = LiveSignals {
        client_id,
        db_ok: true,
        ..LiveSignals::default()
    };

    let cs = crate::certstream_watcher::watcher_status_json();
    s.certstream_enabled = cs.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    s.certstream_connected = cs
        .get("connected")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    s.oast_configured = crate::fuzz_oob::oast_correlation_enabled();
    s.nvd_api_key = crate::nvd_cve::nvd_api_key_present();

    // Integrations open their own tenant tx — run before ours.
    let integrations = crate::soar::integrations::load_integrations(pool, tenant_id).await;
    let mut providers: Vec<String> = integrations
        .into_iter()
        .map(|i| i.provider_type)
        .filter(|p| !p.is_empty())
        .collect();
    providers.sort();
    providers.dedup();
    s.soar_providers = providers;

    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        s.db_ok = false;
        return s;
    };

    s.sso_idp_count = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM tenant_idps WHERE tenant_id = $1 AND active = true",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    if let Some(cid) = client_id {
        let row = sqlx::query(
            r#"SELECT
                COALESCE(trim(aws_cross_account_role_arn),'') AS aws_arn,
                COALESCE(trim(gcp_project_id),'') AS gcp,
                COALESCE(NULLIF(trim(client_configs), ''), '{}') AS client_configs
               FROM clients WHERE id = $1"#,
        )
        .bind(cid)
        .fetch_optional(&mut *tx)
        .await;

        match row {
            Ok(Some(r)) => {
                s.client_found = true;
                let aws: String = r.try_get("aws_arn").unwrap_or_default();
                let gcp: String = r.try_get("gcp").unwrap_or_default();
                s.aws_role_configured = !aws.is_empty();
                s.gcp_project_configured = !gcp.is_empty();
                let config_str: String = r
                    .try_get("client_configs")
                    .unwrap_or_else(|_| "{}".to_string());
                let config_val: Value = serde_json::from_str(&config_str).unwrap_or(json!({}));
                let onboarding = config_val.get("onboarding").cloned().unwrap_or(json!({}));
                let azure_sub = onboarding
                    .get("azure_subscription_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let azure_tenant = onboarding
                    .get("azure_tenant_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                s.azure_configured = !azure_sub.is_empty() || !azure_tenant.is_empty();
            }
            Ok(None) => s.client_found = false,
            Err(_) => s.db_ok = false,
        }

        s.enrolled_agents_total = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM endpoint_agents
               WHERE client_id = $1 AND revoked_at IS NULL"#,
        )
        .bind(cid)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);

        s.enrolled_agents_online = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM endpoint_agents
               WHERE client_id = $1 AND revoked_at IS NULL
                 AND last_seen_at > now() - interval '5 minutes'"#,
        )
        .bind(cid)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);

        s.surface_snapshot_count = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM surface_snapshots WHERE tenant_id = $1 AND client_id = $2",
        )
        .bind(tenant_id)
        .bind(cid)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
    } else {
        s.enrolled_agents_total = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM endpoint_agents
               WHERE tenant_id = $1 AND revoked_at IS NULL"#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
        s.enrolled_agents_online = sqlx::query_scalar(
            r#"SELECT COUNT(*)::bigint FROM endpoint_agents
               WHERE tenant_id = $1 AND revoked_at IS NULL
                 AND last_seen_at > now() - interval '5 minutes'"#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
    }

    let _ = tx.commit().await;

    if let Some(cid) = client_id {
        match crate::first_mover_surface_delta::api_surface_diff_json(pool, tenant_id, cid).await {
            Ok(diff) => {
                s.surface_unavailable = diff
                    .get("unavailable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                s.surface_baseline_only = diff
                    .get("baseline_only")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                s.surface_added = diff
                    .get("added")
                    .and_then(Value::as_array)
                    .map(|a| a.len() as i64)
                    .unwrap_or(0);
            }
            Err(_) => s.surface_unavailable = true,
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ngfw_is_always_non_goal() {
        let mut s = LiveSignals::default();
        s.aws_role_configured = true;
        s.enrolled_agents_online = 12;
        assert_eq!(verdict_for("prisma_access", &s), "non_goal");
        assert_eq!(verdict_for("wildfire", &s), "non_goal");
    }

    #[test]
    fn prisma_cloud_partial_only_with_live_aws_role() {
        let mut s = LiveSignals {
            client_id: Some(7),
            client_found: true,
            ..LiveSignals::default()
        };
        assert_eq!(verdict_for("prisma_cloud", &s), "unproven_connector");
        s.aws_role_configured = true;
        assert_eq!(verdict_for("prisma_cloud", &s), "live_partial");
    }

    #[test]
    fn prisma_cloud_honesty_is_assumerole_only_even_when_azure_gcp_onboarded() {
        let mut s = LiveSignals {
            client_id: Some(4),
            client_found: true,
            azure_configured: true,
            gcp_project_configured: true,
            ..LiveSignals::default()
        };
        let body = displacement_json(&s);
        let h = &body["prisma_cloud_honesty"];
        assert_eq!(h["sku_id"], "prisma_cloud");
        assert_eq!(h["cspm_plane"], "aws_assumerole");
        assert_eq!(h["cspm_engine"], "cloud_posture");
        assert_eq!(h["cspm_refuses_without_role"], true);
        assert_eq!(h["scope"], "no_aws_assumerole");
        assert_eq!(h["verdict"], "unproven_connector");
        assert_eq!(h["azure_configured"], true);
        assert_eq!(h["gcp_project_configured"], true);
        assert_eq!(h["azure_is_cnapp_connector"], false);
        assert_eq!(h["gcp_is_cnapp_connector"], false);
        assert_eq!(h["continuous_multi_cloud_cnapp"], false);
        assert_eq!(h["replacement_claim"], false);
        assert_eq!(h["cnapp_continuous_is_fusion_tag"], true);

        s.aws_role_configured = true;
        let h = &displacement_json(&s)["prisma_cloud_honesty"];
        assert_eq!(h["scope"], "aws_assumerole_only");
        assert_eq!(h["verdict"], "live_partial");
        assert_eq!(h["continuous_multi_cloud_cnapp"], false);
        assert_eq!(h["replacement_claim"], false);
        assert_eq!(h["azure_is_cnapp_connector"], false);
    }

    #[test]
    fn xpanse_win_requires_non_baseline_snapshots() {
        let mut s = LiveSignals {
            client_id: Some(3),
            client_found: true,
            surface_snapshot_count: 2,
            surface_baseline_only: true,
            ..LiveSignals::default()
        };
        assert_eq!(verdict_for("cortex_xpanse", &s), "unproven_baseline");
        s.surface_baseline_only = false;
        assert_eq!(verdict_for("cortex_xpanse", &s), "live_win");
    }

    #[test]
    fn xdr_gap_without_agents_is_honest() {
        let s = LiveSignals::default();
        assert_eq!(verdict_for("cortex_xdr", &s), "live_gap_sensor");
    }

    #[test]
    fn db_down_is_unavailable_not_a_fake_gap() {
        let s = LiveSignals {
            db_ok: false,
            ..LiveSignals::default()
        };
        assert_eq!(verdict_for("prisma_cloud", &s), "unavailable");
        assert_eq!(verdict_for("cortex_xpanse", &s), "unavailable");
        assert_eq!(verdict_for("cortex_xdr", &s), "unavailable");
        assert_eq!(verdict_for("prisma_access", &s), "non_goal");
    }

    #[test]
    fn json_never_claims_scim_or_firewall() {
        let body = displacement_json(&LiveSignals::default());
        let absences = body["code_absences"].as_array().unwrap();
        assert!(absences.iter().any(|v| v.as_str() == Some("scim")));
        let skus = body["skus"].as_array().unwrap();
        let access = skus
            .iter()
            .find(|s| s["id"].as_str() == Some("prisma_access"))
            .unwrap();
        assert_eq!(access["verdict"], "non_goal");
        assert_eq!(access["role"], "non_goal");
        assert!(body["unique_moat"]["engine_id"]
            .as_str()
            .unwrap()
            .contains("exposure_schism"));
    }

    #[test]
    fn counts_add_up() {
        let body = displacement_json(&LiveSignals::default());
        let c = &body["counts"];
        let sum = c["live_win"].as_u64().unwrap()
            + c["live_partial"].as_u64().unwrap()
            + c["live_gap"].as_u64().unwrap()
            + c["unproven"].as_u64().unwrap()
            + c["non_goal"].as_u64().unwrap()
            + c["overlap_probe"].as_u64().unwrap()
            + c["unavailable"].as_u64().unwrap();
        assert_eq!(sum, c["skus"].as_u64().unwrap());
        assert_eq!(sum, SKUS.len() as u64);
    }
}
