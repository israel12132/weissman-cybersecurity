//! Honest competitive delta — live catalog + tenant facts, no invented vendor scores.
//!
//! Weissman is the live-evidence assessment + autonomous loop. It is **not** a
//! packet-path NGFW (Palo Alto Strata / Prisma Access / Cortex XDR). This surface
//! composes what this binary and this tenant actually have: production engines,
//! OT safety catalog membership, fusion count, SSO/agent counts, env booleans,
//! and whether campaign/proof tables exist on *this* revision.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use weissman_core::models::engine::PRODUCTION_ENGINE_IDS;

use crate::auth_jwt::AuthContext;
use crate::db;
use crate::engine_fusion::FUSION_ENGINE_IDS;
use crate::http::AppState;
use crate::ot_ics_hardening::{ENGINE_CROWN, ENGINE_SAFETY};

const OT_SAFETY_IDS: &[&str] = &[ENGINE_SAFETY, ENGINE_CROWN];

const CAMPAIGN_TABLE: &str = "weissman_campaigns";
const PROOF_TABLE: &str = "weissman_proof_artifacts";
const OT_SAFETY_EVENTS_TABLE: &str = "ot_ics_safety_events";
const TENANT_IDPS_TABLE: &str = "tenant_idps";
const ENDPOINT_AGENTS_TABLE: &str = "endpoint_agents";

/// Compile-time catalog facts (no I/O). Used by unit tests and as the API base.
pub fn catalog_snapshot() -> Value {
    let accounting = crate::engine_accounting::compute();
    let moat = crate::elite_hardening::moat::snapshot();
    let ot_in_catalog: Vec<&str> = OT_SAFETY_IDS
        .iter()
        .copied()
        .filter(|id| PRODUCTION_ENGINE_IDS.contains(id))
        .collect();
    let network_lane = moat["lanes"]
        .as_array()
        .and_then(|lanes| {
            lanes
                .iter()
                .find(|l| l.get("id").and_then(Value::as_str) == Some("network_prevention"))
                .cloned()
        })
        .unwrap_or(Value::Null);

    json!({
        "ok": true,
        "live": true,
        "category": "live_evidence_assessment",
        "not_a_panos_replacement": true,
        "panos_posture": "companion evidence plane — does not replace Strata / Prisma Access / Cortex XDR packet path",
        "engines": {
            "total_ids": accounting.total_ids,
            "distinct_canonical": accounting.distinct_canonical,
            "real_probe_accounting": accounting.remotely_detecting,
            "alias_ids": accounting.alias_ids,
            "agent_required": accounting.agent_required,
        },
        "fusion_engines": FUSION_ENGINE_IDS.len(),
        "fusion_ids": FUSION_ENGINE_IDS,
        "ot_safety": {
            "ids": OT_SAFETY_IDS,
            "in_production_catalog": ot_in_catalog.len() == OT_SAFETY_IDS.len(),
            "catalogued_ids": ot_in_catalog,
        },
        "ops_env": {
            "oast_configured": crate::fuzz_oob::oast_correlation_enabled(),
            "nvd_api_key_present": crate::nvd_cve::nvd_api_key_present(),
            "vngfw_admin_configured": env_nonempty("WEISSMAN_VNGFW_ADMIN"),
        },
        "moat": moat,
        "network_prevention_lane": network_lane,
    })
}

pub async fn live_snapshot(pool: &PgPool, tenant_id: i64) -> Value {
    let mut body = catalog_snapshot();
    let campaign = table_fact(pool, CAMPAIGN_TABLE).await;
    let proof = table_fact(pool, PROOF_TABLE).await;
    let ot_events = table_fact(pool, OT_SAFETY_EVENTS_TABLE).await;
    let idps_table = table_fact(pool, TENANT_IDPS_TABLE).await;
    let agents_table = table_fact(pool, ENDPOINT_AGENTS_TABLE).await;

    let (agent_count, idp_active, idp_total, db_ok) =
        tenant_counts(pool, tenant_id, agents_table, idps_table).await;

    body["revision"] = json!({
        "campaign_fabric": revision_status(campaign, "Campaign Fabric tables are not on this git revision — open PRs #333/#334, do not invent campaign rows"),
        "proof_artifacts": revision_status(proof, "Proof-layer tables are not on this git revision — wait for the proof PR, do not fabricate attestations"),
        "ot_ics_safety_events": revision_status(ot_events, "OT safety event table missing — migration 20260827160000_ot_ics_hardening_safety.sql"),
        "tenant_idps": revision_status(idps_table, "tenant_idps missing — SSO exists in code (sso_management.rs) but this database has not applied the IdP migration"),
        "endpoint_agents": revision_status(agents_table, "endpoint_agents missing — agent fleet table not migrated on this database"),
    });
    body["tenant"] = json!({
        "database_reachable": db_ok,
        "endpoint_agents_enrolled": agent_count,
        "sso_idps_total": idp_total,
        "sso_idps_active": idp_active,
        "sso_configured": idp_active > 0,
    });
    body
}

pub async fn api_competitive_delta(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let body = live_snapshot(state.app_pool.as_ref(), auth.tenant_id).await;
    (StatusCode::OK, Json(body)).into_response()
}

fn env_nonempty(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

async fn table_fact(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = $1
        )"#,
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or(false)
}

fn revision_status(present: bool, absent_detail: &str) -> Value {
    if present {
        json!({
            "on_this_revision": true,
            "status": "present",
        })
    } else {
        json!({
            "on_this_revision": false,
            "status": "not_on_this_revision",
            "detail": absent_detail,
        })
    }
}

async fn tenant_counts(
    pool: &PgPool,
    tenant_id: i64,
    agents_table: bool,
    idps_table: bool,
) -> (i64, i64, i64, bool) {
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return (0, 0, 0, false);
    };
    let agents: i64 = if agents_table {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*)::bigint FROM endpoint_agents WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or(0)
    } else {
        0
    };
    let idp_total: i64 = if idps_table {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*)::bigint FROM tenant_idps WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or(0)
    } else {
        0
    };
    let idp_active: i64 = if idps_table {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*)::bigint FROM tenant_idps WHERE tenant_id = $1 AND active = true",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or(0)
    } else {
        0
    };
    let _ = tx.rollback().await;
    (agents, idp_active, idp_total, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_snapshot_is_live_and_honest_about_panos() {
        let snap = catalog_snapshot();
        assert_eq!(snap["live"], true);
        assert_eq!(snap["ok"], true);
        assert_eq!(snap["not_a_panos_replacement"], true);
        assert_eq!(
            snap["engines"]["total_ids"].as_u64().unwrap() as usize,
            PRODUCTION_ENGINE_IDS.len()
        );
        assert_eq!(snap["fusion_engines"], FUSION_ENGINE_IDS.len());
        assert_eq!(snap["ot_safety"]["in_production_catalog"], true);
        assert!(snap["ops_env"]["oast_configured"].is_boolean());
        assert!(snap["ops_env"]["nvd_api_key_present"].is_boolean());
        assert_eq!(snap["moat"]["live"], true);
        assert_eq!(snap["moat"]["market_research"]["live"], false);
        assert!(
            snap["network_prevention_lane"]["live_engine_count"]
                .as_u64()
                .unwrap()
                >= 1
        );
        let panos = snap["panos_posture"].as_str().unwrap_or("");
        assert!(panos.contains("does not replace"));
    }

    #[test]
    fn ot_safety_engines_are_production_ids() {
        for id in OT_SAFETY_IDS {
            assert!(
                PRODUCTION_ENGINE_IDS.contains(id),
                "{id} missing from PRODUCTION_ENGINE_IDS"
            );
        }
    }

    #[test]
    fn revision_status_does_not_invent_absent_tables() {
        let absent = revision_status(false, "not shipped");
        assert_eq!(absent["on_this_revision"], false);
        assert_eq!(absent["status"], "not_on_this_revision");
        let present = revision_status(true, "unused");
        assert_eq!(present["on_this_revision"], true);
        assert_eq!(present["status"], "present");
        assert!(present.get("detail").is_none());
    }
}
