//! Adversary Campaign Fabric (P0) — sync layer that turns isolated engines into a
//! coordinated, evidence-grounded campaign.
//!
//! Flow:
//!   1. Seed WorldState from live client findings via [`attack_chain_planner::facts_from_findings`].
//!   2. [`attack_chain_planner::plan`] toward an allowed goal fact (never invent capability).
//!   3. Dispatch the next STRIPS technique as a `command_center_engine` job **inside** the
//!      authorized client scope (`scan_routing` + `validate_scan_target_in_scope`).
//!   4. On persist/job completion, rebuild facts from findings (FP-suppressed rows excluded)
//!      and replan or complete.
//!
//! Invariants:
//!   * Tenant + client scoped. Never widen scan target beyond approved domains.
//!   * No fabricated findings. Planner already refuses unreachable goals.
//!   * Novel/sensitive findings stay in-product; this module does not auto-disclose.

use crate::attack_chain_planner::{self, AttackChain, Fact};
use crate::fp_feedback::{self, SuppressionRule};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;
use weissman_core::models::engine::is_production_engine_id;

/// Versioned campaign event kinds (v1). Durable in `weissman_campaign_events`.
/// Live projection: CEM-DAGO blackboard keyed `campaign:{uuid}`.
/// Engine jobs inherit `campaign_id` on the existing weissman-job-bus envelope.
pub const CAMPAIGN_EVENT_VERSION: i32 = 1;

pub const CAMPAIGN_EVENT_KINDS: &[&str] = &[
    "campaign_created",
    "campaign_started",
    "campaign_paused",
    "world_state_snapshot",
    "finding_observed",
    "path_snapshot_taken",
    "technique_planned",
    "technique_dispatched",
    "technique_proven",
    "technique_failed",
    "goal_reached",
    "campaign_blocked",
    "mesh_blackboard_seeded",
    "remediation_verified",
];

/// Goal facts the operator may request. All appear in the default STRIPS library.
pub const ALLOWED_GOALS: &[&str] = &[
    "access:foothold",
    "access:privileged",
    "access:internal",
    "access:crown_jewel",
    "data:db_read",
    "cred:leaked",
    "impact:objective",
];

pub const DEFAULT_GOAL: &str = "impact:objective";

const CAMPAIGN_STATUSES: &[&str] = &[
    "draft",
    "running",
    "paused",
    "completed",
    "blocked",
    "failed",
];

/// STRIPS technique id → production engine dispatched for that operator.
/// Effects are never assumed from a successful job — WorldState only updates from findings.
pub fn engine_for_technique(technique_id: &str) -> Option<&'static str> {
    let engine = match technique_id {
        "exploit_rce_web" => "rce_exploit_engine",
        "exploit_sqli_web" => "sqli_advanced",
        "exploit_ssrf_metadata" => "ssrf_advanced",
        "valid_accounts" => "credential_stuffing",
        "abuse_authz" => "bola_idor",
        "privilege_escalation" => "host_privilege_escalation",
        "lateral_movement" => "lateral_movement",
        "reach_crown_jewel" => "kill_chain",
        "exfiltrate_db" => "database_exfil",
        "exfiltrate_crown_jewel" => "cloud_data_exfil",
        _ => return None,
    };
    if is_production_engine_id(engine) {
        Some(engine)
    } else {
        None
    }
}

/// Council / HITL may propose technique ids; only library techniques with a production
/// engine mapping are kept. P0 never auto-dispatches Council proposals.
#[must_use]
pub fn allowlisted_techniques(proposed: &[String]) -> Vec<String> {
    proposed
        .iter()
        .filter(|id| engine_for_technique(id).is_some())
        .cloned()
        .collect()
}

/// STRIPS-shaped ids (`lowercase_with_underscores`). Council narrative / MITRE
/// prose is left alone — those steps are HITL debate material, not engine maps.
#[must_use]
pub fn looks_like_technique_id(s: &str) -> bool {
    let s = s.trim();
    (3..=64).contains(&s.len())
        && s.contains('_')
        && s.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

/// Technique-shaped steps that are **not** in the production library.
/// Used when a HITL proposal is campaign-scoped: reject freestyle engine ids,
/// keep narrative chain_steps.
#[must_use]
pub fn unauthorized_technique_shaped_steps(steps: &[String]) -> Vec<String> {
    steps
        .iter()
        .filter(|s| looks_like_technique_id(s) && engine_for_technique(s).is_none())
        .cloned()
        .collect()
}

#[must_use]
pub fn parse_campaign_id(v: &Value) -> Option<Uuid> {
    v.get("campaign_id")
        .or_else(|| v.get("extras").and_then(|e| e.get("campaign_id")))
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// Stamp `campaign_id` onto finding JSON so persist/SOAR/WorldState share one spine.
#[must_use]
pub fn stamp_campaign_id_on_findings(findings: &[Value], campaign_id: Option<Uuid>) -> Vec<Value> {
    let Some(id) = campaign_id else {
        return findings.to_vec();
    };
    findings
        .iter()
        .map(|f| {
            let mut v = f.clone();
            if let Some(obj) = v.as_object_mut() {
                obj.insert("campaign_id".into(), json!(id.to_string()));
            }
            v
        })
        .collect()
}

#[must_use]
pub fn hash_campaign_event(
    campaign_id: Uuid,
    kind: &str,
    payload: &Value,
    prev_hash: Option<&str>,
) -> String {
    let mut h = Sha256::new();
    h.update(campaign_id.as_bytes());
    h.update(CAMPAIGN_EVENT_VERSION.to_le_bytes());
    h.update(kind.as_bytes());
    if let Ok(p) = serde_json::to_vec(payload) {
        h.update(&p);
    }
    if let Some(p) = prev_hash {
        h.update(p.as_bytes());
    }
    format!("{:x}", h.finalize())
}

#[must_use]
pub fn campaign_blackboard_scan_id(campaign_id: Uuid) -> String {
    format!("campaign:{campaign_id}")
}

/// Scan → Path → Emulation → Remediate correlation for API/UI. In-product only.
#[must_use]
pub fn spine_json(campaign_id: Uuid) -> Value {
    json!({
        "campaign_id": campaign_id.to_string(),
        "job_correlation": format!("campaign:{campaign_id}"),
        "blackboard_scan_id": campaign_blackboard_scan_id(campaign_id),
        "event_bus": "weissman_campaign_events",
        "job_bus": "weissman-job-bus",
        "probe_executor": "engine_dispatch",
        "disclose_externally": false,
        "scope": "tenant+client+execution_scope_pin",
        "roe": "authorized-tenant+scope_pin+no_auto_disclosure",
    })
}

/// Append a versioned campaign event. Looks up client_id from the campaign row.
pub async fn emit_kind(
    pool: &PgPool,
    tenant_id: i64,
    campaign_id: Uuid,
    kind: &str,
    payload: Value,
) -> Result<(), String> {
    if !CAMPAIGN_EVENT_KINDS.contains(&kind) {
        return Err(format!("unknown campaign event kind '{kind}'"));
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let client_id: Option<i64> = sqlx::query_scalar(
        "SELECT client_id FROM weissman_campaigns WHERE id = $1 AND tenant_id = $2",
    )
    .bind(campaign_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("campaign lookup: {e}"))?;
    let Some(client_id) = client_id else {
        let _ = tx.rollback().await;
        return Err("campaign not found".into());
    };
    insert_event(&mut tx, campaign_id, tenant_id, client_id, kind, payload).await?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(())
}

#[must_use]
pub fn is_allowed_goal(goal: &str) -> bool {
    ALLOWED_GOALS.contains(&goal)
}

#[must_use]
pub fn can_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("draft", "running")
            | ("paused", "running")
            | ("blocked", "running")
            | ("failed", "running")
            | ("running", "paused")
            | ("running", "completed")
            | ("running", "blocked")
            | ("running", "failed")
            | ("draft", "failed")
            | ("paused", "blocked")
            | ("paused", "failed")
    )
}

/// Merge two evidence maps: union of finding ids per fact. Used by unit tests and snapshots.
pub fn merge_evidence(
    mut acc: HashMap<Fact, Vec<String>>,
    extra: HashMap<Fact, Vec<String>>,
) -> HashMap<Fact, Vec<String>> {
    for (fact, ids) in extra {
        let slot = acc.entry(fact).or_default();
        for id in ids {
            if !slot.iter().any(|x| x == &id) {
                slot.push(id);
            }
        }
    }
    acc
}

/// Drop findings the analyst (or 3-FP auto-suppression) already marked as noise so they cannot
/// seed WorldState.
pub fn filter_findings_for_world_state(
    findings: Vec<Value>,
    suppressions_by_engine: &HashMap<String, Vec<SuppressionRule>>,
) -> Vec<Value> {
    findings
        .into_iter()
        .filter(|f| {
            let status = f
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("OPEN")
                .to_ascii_uppercase();
            if status == "FALSE_POSITIVE" || status == "FIXED" {
                return false;
            }
            let engine = f
                .get("source")
                .or_else(|| f.get("engine"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let sig = f
                .get("signature_hash")
                .and_then(Value::as_str)
                .unwrap_or("");
            if engine.is_empty() || sig.is_empty() {
                return true;
            }
            let target = f
                .get("target")
                .or_else(|| f.get("url"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let rules = suppressions_by_engine
                .get(&engine)
                .cloned()
                .unwrap_or_default();
            !fp_feedback::is_suppressed_by(&rules, sig, target)
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCampaignRequest {
    pub client_id: i64,
    #[serde(default)]
    pub goal: Option<String>,
    #[serde(default)]
    pub profile: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct CampaignRecord {
    pub id: Uuid,
    pub tenant_id: i64,
    pub client_id: i64,
    pub goal_fact: String,
    pub status: String,
    pub profile_stub: Value,
    pub created_by: Option<i64>,
    pub asset_key: String,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl CampaignRecord {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id.to_string(),
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "goal_fact": self.goal_fact,
            "status": self.status,
            "profile_stub": self.profile_stub,
            "created_by": self.created_by,
            "asset_key": self.asset_key,
            "last_error": self.last_error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }
}

fn row_campaign(r: &sqlx::postgres::PgRow) -> Result<CampaignRecord, String> {
    Ok(CampaignRecord {
        id: r.try_get("id").map_err(|e| e.to_string())?,
        tenant_id: r.try_get("tenant_id").map_err(|e| e.to_string())?,
        client_id: r.try_get("client_id").map_err(|e| e.to_string())?,
        goal_fact: r.try_get("goal_fact").map_err(|e| e.to_string())?,
        status: r.try_get("status").map_err(|e| e.to_string())?,
        profile_stub: r
            .try_get::<Value, _>("profile_stub")
            .unwrap_or_else(|_| json!({})),
        created_by: r.try_get("created_by").ok(),
        asset_key: r.try_get("asset_key").unwrap_or_default(),
        last_error: r.try_get("last_error").ok(),
        created_at: r
            .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .map(|d| d.to_rfc3339())
            .unwrap_or_default(),
        updated_at: r
            .try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
            .map(|d| d.to_rfc3339())
            .unwrap_or_default(),
    })
}

async fn require_client(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    client_id: i64,
) -> Result<(), String> {
    let ok: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1 AND tenant_id = $2)")
            .bind(client_id)
            .bind(tenant_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| format!("client lookup: {e}"))?;
    if ok {
        Ok(())
    } else {
        Err("client not found in tenant".into())
    }
}

async fn insert_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
    tenant_id: i64,
    client_id: i64,
    from_status: Option<&str>,
    to_status: &str,
    actor_user_id: Option<i64>,
    reason: &str,
    detail: Value,
) -> Result<(), String> {
    sqlx::query(
        r#"INSERT INTO weissman_campaign_audit
             (campaign_id, tenant_id, client_id, from_status, to_status, actor_user_id, reason, detail)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(campaign_id)
    .bind(tenant_id)
    .bind(client_id)
    .bind(from_status)
    .bind(to_status)
    .bind(actor_user_id)
    .bind(reason)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("audit: {e}"))?;
    Ok(())
}

async fn insert_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
    tenant_id: i64,
    client_id: i64,
    kind: &str,
    payload: Value,
) -> Result<(), String> {
    if !CAMPAIGN_EVENT_KINDS.contains(&kind) {
        return Err(format!("unknown campaign event kind {kind}"));
    }
    let prev_hash: Option<String> = sqlx::query_scalar(
        r#"SELECT event_hash FROM weissman_campaign_events
            WHERE campaign_id = $1 ORDER BY id DESC LIMIT 1"#,
    )
    .bind(campaign_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("event prev: {e}"))?;
    let event_hash = hash_campaign_event(campaign_id, kind, &payload, prev_hash.as_deref());
    sqlx::query(
        r#"INSERT INTO weissman_campaign_events
             (campaign_id, tenant_id, client_id, event_version, kind, payload, event_hash, prev_hash)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(campaign_id)
    .bind(tenant_id)
    .bind(client_id)
    .bind(CAMPAIGN_EVENT_VERSION)
    .bind(kind)
    .bind(payload)
    .bind(event_hash)
    .bind(prev_hash)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("event: {e}"))?;
    Ok(())
}

async fn set_status(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign: &CampaignRecord,
    to: &str,
    actor_user_id: Option<i64>,
    reason: &str,
    detail: Value,
    last_error: Option<&str>,
) -> Result<(), String> {
    if campaign.status == to {
        return Ok(());
    }
    if !can_transition(&campaign.status, to) {
        return Err(format!(
            "illegal campaign transition {} → {}",
            campaign.status, to
        ));
    }
    sqlx::query(
        r#"UPDATE weissman_campaigns
              SET status = $2, last_error = $3, updated_at = now()
            WHERE id = $1 AND tenant_id = $4"#,
    )
    .bind(campaign.id)
    .bind(to)
    .bind(last_error)
    .bind(campaign.tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("status: {e}"))?;
    insert_audit(
        tx,
        campaign.id,
        campaign.tenant_id,
        campaign.client_id,
        Some(&campaign.status),
        to,
        actor_user_id,
        reason,
        detail.clone(),
    )
    .await?;
    let kind = match to {
        "running" => "campaign_started",
        "paused" => "campaign_paused",
        "completed" => "goal_reached",
        "blocked" => "campaign_blocked",
        "failed" => "campaign_blocked",
        _ => "",
    };
    if !kind.is_empty() {
        insert_event(
            tx,
            campaign.id,
            campaign.tenant_id,
            campaign.client_id,
            kind,
            json!({ "reason": reason, "detail": detail, "from": campaign.status, "to": to }),
        )
        .await?;
    }
    Ok(())
}

pub async fn create_campaign(
    pool: &PgPool,
    tenant_id: i64,
    actor_user_id: Option<i64>,
    req: &CreateCampaignRequest,
) -> Result<Value, String> {
    let goal = req
        .goal
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_GOAL);
    if !is_allowed_goal(goal) {
        return Err(format!(
            "unsupported goal '{goal}'; allowed: {}",
            ALLOWED_GOALS.join(", ")
        ));
    }
    let mut profile = req
        .profile
        .clone()
        .unwrap_or_else(|| json!({ "stub": true }));
    if let Some(obj) = profile.as_object_mut() {
        obj.entry("stub").or_insert(json!(true));
        obj.insert("disclose_externally".into(), json!(false));
        obj.insert("council_hitl_required".into(), json!(true));
    }
    if let Some(arr) = profile
        .get("council_proposed_techniques")
        .and_then(Value::as_array)
        .cloned()
    {
        let proposed: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        let allowed = allowlisted_techniques(&proposed);
        if let Some(obj) = profile.as_object_mut() {
            obj.insert("council_proposed_techniques".into(), json!(allowed));
        }
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    require_client(&mut tx, tenant_id, req.client_id).await?;
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO weissman_campaigns
             (tenant_id, client_id, goal_fact, status, profile_stub, created_by)
           VALUES ($1, $2, $3, 'draft', $4, $5)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(req.client_id)
    .bind(goal)
    .bind(profile)
    .bind(actor_user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("insert campaign: {e}"))?;
    insert_audit(
        &mut tx,
        id,
        tenant_id,
        req.client_id,
        None,
        "draft",
        actor_user_id,
        "created",
        json!({ "goal": goal }),
    )
    .await?;
    insert_event(
        &mut tx,
        id,
        tenant_id,
        req.client_id,
        "campaign_created",
        json!({ "goal": goal }),
    )
    .await?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    get_campaign(pool, tenant_id, id).await
}

pub async fn list_campaigns(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let rows = if let Some(cid) = client_id {
        sqlx::query(
            r#"SELECT id, tenant_id, client_id, goal_fact, status, profile_stub, created_by,
                      asset_key, last_error, created_at, updated_at
                 FROM weissman_campaigns
                WHERE tenant_id = $1 AND client_id = $2
                ORDER BY updated_at DESC
                LIMIT 100"#,
        )
        .bind(tenant_id)
        .bind(cid)
        .fetch_all(&mut *tx)
        .await
    } else {
        sqlx::query(
            r#"SELECT id, tenant_id, client_id, goal_fact, status, profile_stub, created_by,
                      asset_key, last_error, created_at, updated_at
                 FROM weissman_campaigns
                WHERE tenant_id = $1
                ORDER BY updated_at DESC
                LIMIT 100"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await
    }
    .map_err(|e| format!("list: {e}"))?;
    let _ = tx.commit().await;
    let campaigns: Vec<Value> = rows
        .iter()
        .filter_map(|r| row_campaign(r).ok().map(|c| c.to_json()))
        .collect();
    Ok(json!({
        "ok": true,
        "campaigns": campaigns,
        "allowed_goals": ALLOWED_GOALS,
        "technique_engines": technique_engine_catalog(),
    }))
}

fn technique_engine_catalog() -> Value {
    let lib = attack_chain_planner::default_technique_library();
    json!(lib
        .iter()
        .map(|t| json!({
            "technique_id": t.id,
            "name": t.name,
            "mitre": t.mitre,
            "engine_id": engine_for_technique(&t.id),
        }))
        .collect::<Vec<_>>())
}

pub async fn get_campaign(pool: &PgPool, tenant_id: i64, id: Uuid) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let row = sqlx::query(
        r#"SELECT id, tenant_id, client_id, goal_fact, status, profile_stub, created_by,
                  asset_key, last_error, created_at, updated_at
             FROM weissman_campaigns WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("get: {e}"))?;
    let Some(row) = row else {
        let _ = tx.commit().await;
        return Err("campaign not found".into());
    };
    let campaign = row_campaign(&row)?;
    let world = load_latest_world(&mut tx, id).await?;
    let steps = load_steps(&mut tx, id).await?;
    let audit = load_audit(&mut tx, id).await?;
    let events = load_events(&mut tx, id).await?;
    let _ = tx.commit().await;
    let mesh = mesh_status_json(
        campaign.tenant_id,
        campaign.client_id,
        campaign.id,
        &steps,
        &world,
    )
    .await;
    let council = council_status_json(&campaign);
    Ok(json!({
        "ok": true,
        "campaign": campaign.to_json(),
        "world_state": world,
        "steps": steps,
        "audit": audit,
        "events": events,
        "plan": plan_json_from_steps(&campaign, &steps, &world),
        "allowed_goals": ALLOWED_GOALS,
        "mesh": mesh,
        "spine": spine_json(campaign.id),
        "council": council,
    }))
}

async fn load_latest_world(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
) -> Result<Value, String> {
    let row = sqlx::query(
        r#"SELECT facts, evidence, asset_key, created_at
             FROM weissman_campaign_world_states
            WHERE campaign_id = $1
            ORDER BY created_at DESC
            LIMIT 1"#,
    )
    .bind(campaign_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("world: {e}"))?;
    Ok(match row {
        Some(r) => json!({
            "facts": r.try_get::<Value, _>("facts").unwrap_or_else(|_| json!([])),
            "evidence": r.try_get::<Value, _>("evidence").unwrap_or_else(|_| json!({})),
            "asset_key": r.try_get::<String, _>("asset_key").unwrap_or_default(),
            "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                .map(|d| d.to_rfc3339())
                .unwrap_or_default(),
        }),
        None => json!({ "facts": [], "evidence": {}, "asset_key": "" }),
    })
}

async fn load_steps(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
) -> Result<Vec<Value>, String> {
    let rows = sqlx::query(
        r#"SELECT id, seq, technique_id, technique_name, mitre, engine_id, job_id, status,
                  planned_gained, outcome_facts, target, last_error, created_at, updated_at
             FROM weissman_campaign_steps
            WHERE campaign_id = $1
            ORDER BY seq ASC"#,
    )
    .bind(campaign_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("steps: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<Uuid, _>("id").ok().map(|u| u.to_string()),
                "seq": r.try_get::<i32, _>("seq").unwrap_or(0),
                "technique_id": r.try_get::<String, _>("technique_id").unwrap_or_default(),
                "technique_name": r.try_get::<String, _>("technique_name").unwrap_or_default(),
                "mitre": r.try_get::<String, _>("mitre").unwrap_or_default(),
                "engine_id": r.try_get::<String, _>("engine_id").unwrap_or_default(),
                "job_id": r.try_get::<Option<Uuid>, _>("job_id").ok().flatten().map(|u| u.to_string()),
                "status": r.try_get::<String, _>("status").unwrap_or_default(),
                "planned_gained": r.try_get::<Value, _>("planned_gained").unwrap_or_else(|_| json!([])),
                "outcome_facts": r.try_get::<Value, _>("outcome_facts").unwrap_or_else(|_| json!([])),
                "target": r.try_get::<String, _>("target").unwrap_or_default(),
                "last_error": r.try_get::<Option<String>, _>("last_error").ok().flatten(),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
                "updated_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect())
}

async fn load_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
) -> Result<Vec<Value>, String> {
    let rows = sqlx::query(
        r#"SELECT from_status, to_status, actor_user_id, reason, detail, created_at
             FROM weissman_campaign_audit
            WHERE campaign_id = $1
            ORDER BY created_at DESC
            LIMIT 50"#,
    )
    .bind(campaign_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("audit: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "from_status": r.try_get::<Option<String>, _>("from_status").ok().flatten(),
                "to_status": r.try_get::<String, _>("to_status").unwrap_or_default(),
                "actor_user_id": r.try_get::<Option<i64>, _>("actor_user_id").ok().flatten(),
                "reason": r.try_get::<String, _>("reason").unwrap_or_default(),
                "detail": r.try_get::<Value, _>("detail").unwrap_or_else(|_| json!({})),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect())
}

async fn load_events(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
) -> Result<Vec<Value>, String> {
    let rows = sqlx::query(
        r#"SELECT event_version, kind, payload, event_hash, prev_hash, created_at
             FROM weissman_campaign_events
            WHERE campaign_id = $1
            ORDER BY id DESC
            LIMIT 80"#,
    )
    .bind(campaign_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("events: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "event_version": r.try_get::<i32, _>("event_version").unwrap_or(CAMPAIGN_EVENT_VERSION),
                "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
                "payload": r.try_get::<Value, _>("payload").unwrap_or_else(|_| json!({})),
                "event_hash": r.try_get::<String, _>("event_hash").unwrap_or_default(),
                "prev_hash": r.try_get::<Option<String>, _>("prev_hash").ok().flatten(),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect())
}

pub async fn list_events(pool: &PgPool, tenant_id: i64, id: Uuid) -> Result<Value, String> {
    let bundle = get_campaign(pool, tenant_id, id).await?;
    Ok(json!({
        "ok": true,
        "campaign_id": id.to_string(),
        "events": bundle.get("events").cloned().unwrap_or(json!([])),
        "event_version": CAMPAIGN_EVENT_VERSION,
        "kinds": CAMPAIGN_EVENT_KINDS,
    }))
}

async fn mesh_status_json(
    tenant_id: i64,
    client_id: i64,
    campaign_id: Uuid,
    steps: &[Value],
    world: &Value,
) -> Value {
    let scan_id = campaign_blackboard_scan_id(campaign_id);
    let mut facts_on_board = false;
    if crate::cem_dago::is_enabled() {
        if let Ok(bb) = crate::cem_dago::blackboard::open_scan(tenant_id, client_id, &scan_id).await
        {
            if let Ok(Some(_)) = bb.read_evidence("world_state").await {
                facts_on_board = true;
            }
        }
    }
    let mut engine_ids: Vec<String> = steps
        .iter()
        .filter_map(|s| {
            s.get("engine_id")
                .and_then(Value::as_str)
                .map(|s| s.to_string())
        })
        .filter(|id| is_production_engine_id(id))
        .collect();
    if engine_ids.is_empty() {
        engine_ids = attack_chain_planner::default_technique_library()
            .iter()
            .filter_map(|t| engine_for_technique(&t.id).map(|s| s.to_string()))
            .collect();
    }
    engine_ids.sort();
    engine_ids.dedup();
    let mut present = HashSet::new();
    present.insert("internet_exposed".to_string());
    if let Some(facts) = world.get("facts").and_then(Value::as_array) {
        for f in facts {
            if let Some(fact) = f.as_str() {
                if fact.contains("web") || fact.starts_with("vuln:") || fact.starts_with("service:")
                {
                    present.insert("web_port_active".to_string());
                }
            }
        }
    }
    let waves = crate::cem_dago::schedule_waves(&engine_ids, &present);
    json!({
        "enabled": crate::cem_dago::is_enabled(),
        "scan_id": scan_id,
        "world_state_on_blackboard": facts_on_board,
        "waves": waves,
        "waves_are_preview": true,
        "probe_executor": "engine_dispatch",
        "note": "CEM-DAGO blackboard is the live projection; Postgres campaign events are durable. engine_dispatch remains the only probe executor. Waves are a schedule preview — they do not enqueue engines.",
    })
}

fn council_status_json(campaign: &CampaignRecord) -> Value {
    let proposed = campaign
        .profile_stub
        .get("council_proposed_techniques")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "hitl_required": true,
        "auto_dispatch": false,
        "allowlisted_techniques": allowlisted_techniques(&proposed),
        "queue_path": format!("/council-queue?campaign_id={}", campaign.id),
    })
}

fn plan_json_from_steps(campaign: &CampaignRecord, steps: &[Value], world: &Value) -> Value {
    let facts = world
        .get("facts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({
        "goal": campaign.goal_fact,
        "reached_goal": facts.iter().any(|f| f.as_str() == Some(campaign.goal_fact.as_str())),
        "asset_key": campaign.asset_key,
        "steps": steps,
    })
}

pub async fn list_steps(pool: &PgPool, tenant_id: i64, id: Uuid) -> Result<Value, String> {
    let bundle = get_campaign(pool, tenant_id, id).await?;
    Ok(json!({
        "ok": true,
        "campaign_id": id.to_string(),
        "steps": bundle.get("steps").cloned().unwrap_or(json!([])),
    }))
}

pub async fn get_plan(pool: &PgPool, tenant_id: i64, id: Uuid) -> Result<Value, String> {
    let bundle = get_campaign(pool, tenant_id, id).await?;
    Ok(json!({
        "ok": true,
        "campaign": bundle.get("campaign").cloned(),
        "world_state": bundle.get("world_state").cloned(),
        "plan": bundle.get("plan").cloned(),
        "steps": bundle.get("steps").cloned(),
    }))
}

pub async fn start_campaign(
    pool: &PgPool,
    tenant_id: i64,
    id: Uuid,
    actor_user_id: Option<i64>,
) -> Result<Value, String> {
    tick_one(pool, tenant_id, id, actor_user_id, true, None).await?;
    get_campaign(pool, tenant_id, id).await
}

pub async fn pause_campaign(
    pool: &PgPool,
    tenant_id: i64,
    id: Uuid,
    actor_user_id: Option<i64>,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let campaign = lock_campaign(&mut tx, tenant_id, id).await?;
    if campaign.status != "running" {
        let _ = tx.commit().await;
        return Err(format!("cannot pause from {}", campaign.status));
    }
    set_status(
        &mut tx,
        &campaign,
        "paused",
        actor_user_id,
        "operator_pause",
        json!({}),
        None,
    )
    .await?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    get_campaign(pool, tenant_id, id).await
}

async fn lock_campaign(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    id: Uuid,
) -> Result<CampaignRecord, String> {
    let row = sqlx::query(
        r#"SELECT id, tenant_id, client_id, goal_fact, status, profile_stub, created_by,
                  asset_key, last_error, created_at, updated_at
             FROM weissman_campaigns
            WHERE id = $1 AND tenant_id = $2
            FOR UPDATE"#,
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("lock: {e}"))?;
    row.ok_or_else(|| "campaign not found".to_string())
        .and_then(|r| row_campaign(&r))
}

async fn load_live_findings(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    client_id: i64,
) -> Result<Vec<Value>, String> {
    let rows = sqlx::query(
        r#"SELECT finding_id, signature_hash, source, status, title, severity,
                  raw_data, effective_risk, kev_listed,
                  COALESCE(raw_data->>'target', '') AS target
             FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2
              AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE')
            ORDER BY id DESC
            LIMIT 500"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("findings: {e}"))?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let mut v = r.try_get::<Value, _>("raw_data").ok()?;
            let obj = v.as_object_mut()?;
            if let Ok(fid) = r.try_get::<String, _>("finding_id") {
                obj.insert("finding_id".into(), json!(fid));
            }
            if let Ok(Some(sig)) = r.try_get::<Option<String>, _>("signature_hash") {
                obj.insert("signature_hash".into(), json!(sig));
            }
            if let Ok(src) = r.try_get::<String, _>("source") {
                obj.entry("source").or_insert(Value::String(src));
            }
            if let Ok(st) = r.try_get::<String, _>("status") {
                obj.insert("status".into(), json!(st));
            }
            if let Ok(sev) = r.try_get::<String, _>("severity") {
                obj.entry("severity").or_insert(Value::String(sev));
            }
            if let Ok(Some(eff)) = r.try_get::<Option<f64>, _>("effective_risk") {
                obj.insert("effective_risk".into(), json!(eff));
            }
            if let Ok(kev) = r.try_get::<bool, _>("kev_listed") {
                obj.insert("kev_listed".into(), json!(kev));
            }
            if let Ok(tgt) = r.try_get::<String, _>("target") {
                if !tgt.is_empty() {
                    obj.entry("target").or_insert(Value::String(tgt));
                }
            }
            Some(v)
        })
        .collect())
}

async fn load_suppressions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> HashMap<String, Vec<SuppressionRule>> {
    let rows = sqlx::query(
        r#"SELECT engine, signature_hash, target_glob
             FROM finding_suppressions
            WHERE tenant_id = $1
              AND (expires_at IS NULL OR expires_at > now())"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await
    .unwrap_or_default();
    let mut map: HashMap<String, Vec<SuppressionRule>> = HashMap::new();
    for r in rows {
        let engine = r
            .try_get::<String, _>("engine")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let signature_hash = r.try_get::<String, _>("signature_hash").unwrap_or_default();
        let target_glob = r.try_get::<Option<String>, _>("target_glob").ok().flatten();
        map.entry(engine).or_default().push(SuppressionRule {
            signature_hash,
            target_glob,
        });
    }
    map
}

async fn persist_world_snapshot(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign: &CampaignRecord,
    evidence: &HashMap<Fact, Vec<String>>,
    asset_key: &str,
) -> Result<Vec<Fact>, String> {
    let mut facts: Vec<Fact> = evidence.keys().cloned().collect();
    facts.sort();
    let facts_json = json!(facts);
    let evidence_json = json!(evidence);
    sqlx::query(
        r#"INSERT INTO weissman_campaign_world_states
             (campaign_id, tenant_id, client_id, facts, evidence, asset_key)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(campaign.id)
    .bind(campaign.tenant_id)
    .bind(campaign.client_id)
    .bind(&facts_json)
    .bind(&evidence_json)
    .bind(asset_key)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("world snapshot: {e}"))?;
    sqlx::query(
        r#"UPDATE weissman_campaigns SET asset_key = $2, updated_at = now() WHERE id = $1"#,
    )
    .bind(campaign.id)
    .bind(asset_key)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("asset_key: {e}"))?;
    insert_event(
        tx,
        campaign.id,
        campaign.tenant_id,
        campaign.client_id,
        "world_state_snapshot",
        json!({ "asset_key": asset_key, "facts": facts, "evidence": evidence_json }),
    )
    .await?;
    Ok(facts)
}

async fn next_seq(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
) -> Result<i32, String> {
    let n: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0)::int FROM weissman_campaign_steps WHERE campaign_id = $1",
    )
    .bind(campaign_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| format!("seq: {e}"))?;
    Ok(n + 1)
}

async fn existing_technique_ids(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
) -> Result<HashSet<String>, String> {
    let rows: Vec<String> = sqlx::query_scalar(
        r#"SELECT technique_id FROM weissman_campaign_steps
            WHERE campaign_id = $1 AND status IN ('planned', 'dispatched', 'succeeded')"#,
    )
    .bind(campaign_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("techniques: {e}"))?;
    Ok(rows.into_iter().collect())
}

async fn inflight_count(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
) -> Result<i64, String> {
    sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM weissman_campaign_steps
            WHERE campaign_id = $1 AND status = 'dispatched'"#,
    )
    .bind(campaign_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| format!("inflight: {e}"))
}

async fn insert_planned_steps(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign: &CampaignRecord,
    chain: &AttackChain,
    target: &str,
) -> Result<usize, String> {
    let existing = existing_technique_ids(tx, campaign.id).await?;
    let mut seq = next_seq(tx, campaign.id).await?;
    let mut added = 0usize;
    for step in &chain.steps {
        if existing.contains(&step.technique_id) {
            continue;
        }
        let Some(engine) = engine_for_technique(&step.technique_id) else {
            continue;
        };
        sqlx::query(
            r#"INSERT INTO weissman_campaign_steps
                 (campaign_id, tenant_id, client_id, seq, technique_id, technique_name, mitre,
                  engine_id, status, planned_gained, target)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'planned', $9, $10)"#,
        )
        .bind(campaign.id)
        .bind(campaign.tenant_id)
        .bind(campaign.client_id)
        .bind(seq)
        .bind(&step.technique_id)
        .bind(&step.name)
        .bind(&step.mitre)
        .bind(engine)
        .bind(json!(step.gained))
        .bind(target)
        .execute(&mut **tx)
        .await
        .map_err(|e| format!("insert step: {e}"))?;
        seq += 1;
        added += 1;
    }
    if added > 0 {
        insert_event(
            tx,
            campaign.id,
            campaign.tenant_id,
            campaign.client_id,
            "technique_planned",
            json!({
                "added": added,
                "techniques": chain.steps.iter().map(|s| &s.technique_id).collect::<Vec<_>>(),
            }),
        )
        .await?;
    }
    Ok(added)
}

async fn client_authorized_targets(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    client_id: i64,
) -> Result<Vec<String>, String> {
    let raw: String = sqlx::query_scalar(
        "SELECT COALESCE(domains, '[]') FROM clients WHERE id = $1 AND tenant_id = $2",
    )
    .bind(client_id)
    .bind(tenant_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| format!("domains: {e}"))?;
    let domains: Vec<String> = serde_json::from_str(raw.trim()).unwrap_or_default();
    let urls: Vec<String> = domains
        .into_iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .map(|d| {
            if d.starts_with("http://") || d.starts_with("https://") {
                d
            } else {
                format!("https://{d}")
            }
        })
        .collect();
    if urls.is_empty() {
        Err("client has no authorized domains — cannot dispatch".into())
    } else {
        Ok(urls)
    }
}

fn target_from_asset(asset_key: &str, fallback: &str) -> String {
    let a = asset_key.trim();
    if a.is_empty() {
        return fallback.to_string();
    }
    if a.starts_with("http://") || a.starts_with("https://") {
        a.to_string()
    } else {
        format!("https://{a}")
    }
}

/// Host of `candidate` must match `authorized` (same host or subdomain). Never widen.
pub fn target_stays_in_scope(candidate: &str, authorized_url: &str) -> bool {
    let c = crate::engine_probes::extract_host(candidate).to_ascii_lowercase();
    let a = crate::engine_probes::extract_host(authorized_url).to_ascii_lowercase();
    if c.is_empty() || a.is_empty() {
        return false;
    }
    c == a || c.ends_with(&format!(".{a}"))
}

async fn pick_dispatch_target(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign: &CampaignRecord,
    asset_key: &str,
) -> Result<String, String> {
    let authorized = client_authorized_targets(tx, campaign.tenant_id, campaign.client_id).await?;
    let fallback = authorized[0].clone();
    if asset_key.trim().is_empty() {
        return Ok(fallback);
    }
    let candidate = target_from_asset(asset_key, &fallback);
    if authorized
        .iter()
        .any(|u| target_stays_in_scope(&candidate, u))
    {
        Ok(candidate)
    } else {
        Ok(fallback)
    }
}

async fn reconcile_jobs(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
) -> Result<(), String> {
    let rows = sqlx::query(
        r#"SELECT s.id, s.status, s.job_id, j.status AS job_status
             FROM weissman_campaign_steps s
             LEFT JOIN weissman_async_jobs j ON j.id = s.job_id
            WHERE s.campaign_id = $1 AND s.status = 'dispatched'"#,
    )
    .bind(campaign_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("reconcile: {e}"))?;
    for r in rows {
        let step_id: Uuid = r.try_get("id").map_err(|e| e.to_string())?;
        let job_status: Option<String> = r.try_get("job_status").ok();
        match job_status.as_deref() {
            Some("completed") => {
                sqlx::query(
                    r#"UPDATE weissman_campaign_steps
                          SET status = 'succeeded', updated_at = now()
                        WHERE id = $1 AND status = 'dispatched'"#,
                )
                .bind(step_id)
                .execute(&mut **tx)
                .await
                .map_err(|e| format!("succeed step: {e}"))?;
            }
            Some("failed") | Some("dead_letter") => {
                let err = "engine job failed".to_string();
                sqlx::query(
                    r#"UPDATE weissman_campaign_steps
                          SET status = 'failed', last_error = $2, updated_at = now()
                        WHERE id = $1 AND status = 'dispatched'"#,
                )
                .bind(step_id)
                .bind(&err)
                .execute(&mut **tx)
                .await
                .map_err(|e| format!("fail step: {e}"))?;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn bind_job_outcome(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: Uuid,
    succeeded: bool,
    detail: &str,
) -> Result<Option<Uuid>, String> {
    let row = sqlx::query(
        r#"SELECT id, campaign_id, tenant_id, client_id, technique_id
             FROM weissman_campaign_steps
            WHERE job_id = $1 AND status = 'dispatched'"#,
    )
    .bind(job_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("bind job: {e}"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let step_id: Uuid = row.try_get("id").map_err(|e| e.to_string())?;
    let campaign_id: Uuid = row.try_get("campaign_id").map_err(|e| e.to_string())?;
    let tenant_id: i64 = row.try_get("tenant_id").map_err(|e| e.to_string())?;
    let client_id: i64 = row.try_get("client_id").map_err(|e| e.to_string())?;
    let technique_id: String = row.try_get("technique_id").unwrap_or_default();
    if succeeded {
        sqlx::query(
            r#"UPDATE weissman_campaign_steps
                  SET status = 'succeeded', updated_at = now()
                WHERE id = $1"#,
        )
        .bind(step_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| format!("job succeed: {e}"))?;
    } else {
        sqlx::query(
            r#"UPDATE weissman_campaign_steps
                  SET status = 'failed', last_error = $2, updated_at = now()
                WHERE id = $1"#,
        )
        .bind(step_id)
        .bind(detail)
        .execute(&mut **tx)
        .await
        .map_err(|e| format!("job fail: {e}"))?;
        insert_event(
            tx,
            campaign_id,
            tenant_id,
            client_id,
            "technique_failed",
            json!({
                "job_id": job_id.to_string(),
                "technique_id": technique_id,
                "detail": detail,
            }),
        )
        .await?;
    }
    Ok(Some(campaign_id))
}

/// Enqueue the mapped engine through the real scan router (scope pin + entitlements).
async fn enqueue_step_job(
    pool: &PgPool,
    campaign: &CampaignRecord,
    step_id: Uuid,
    engine: &str,
    target: &str,
) -> Result<Uuid, String> {
    if let Err(detail) = crate::billing::gate_scan_enqueue(pool, campaign.tenant_id).await {
        return Err(detail);
    }
    let body = json!({
        "engine": engine,
        "target": target,
        "client_id": campaign.client_id,
        "campaign_id": campaign.id.to_string(),
        "campaign_step_id": step_id.to_string(),
        "safety_rails_no_shells": true,
    });
    let (kind, payload) = crate::scan_routing::route_scan_job(&body, campaign.tenant_id, pool)
        .await
        .map_err(|e| e.detail().to_string())?;
    crate::async_jobs::enqueue(
        pool,
        campaign.tenant_id,
        kind.as_str(),
        payload,
        Some(format!("campaign:{}", campaign.id)),
    )
    .await
    .map_err(|e| format!("enqueue: {e}"))
}

async fn skip_stale_planned_steps(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign: &CampaignRecord,
    chain: &AttackChain,
) -> Result<(), String> {
    let keep: HashSet<&str> = chain
        .steps
        .iter()
        .map(|s| s.technique_id.as_str())
        .collect();
    let rows = sqlx::query(
        r#"SELECT id, technique_id FROM weissman_campaign_steps
            WHERE campaign_id = $1 AND status = 'planned'"#,
    )
    .bind(campaign.id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("stale: {e}"))?;
    for r in rows {
        let technique_id: String = r.try_get("technique_id").unwrap_or_default();
        if keep.contains(technique_id.as_str()) {
            continue;
        }
        let step_id: Uuid = r.try_get("id").map_err(|e| e.to_string())?;
        sqlx::query(
            r#"UPDATE weissman_campaign_steps
                  SET status = 'skipped', last_error = 'not in current evidenced plan', updated_at = now()
                WHERE id = $1 AND status = 'planned'"#,
        )
        .bind(step_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| format!("skip stale: {e}"))?;
    }
    Ok(())
}

/// First planned step that is still in the current chain AND whose STRIPS
/// preconditions are already in WorldState. Never jumps ahead of an unmet step.
async fn pick_dispatchable_step(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign_id: Uuid,
    chain: &AttackChain,
    facts: &HashSet<Fact>,
) -> Result<Option<(Uuid, String, String)>, String> {
    let keep: HashSet<&str> = chain
        .steps
        .iter()
        .map(|s| s.technique_id.as_str())
        .collect();
    let rows = sqlx::query(
        r#"SELECT id, engine_id, technique_id FROM weissman_campaign_steps
            WHERE campaign_id = $1 AND status = 'planned'
            ORDER BY seq ASC"#,
    )
    .bind(campaign_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("pick: {e}"))?;
    for r in rows {
        let technique_id: String = r.try_get("technique_id").unwrap_or_default();
        if !keep.contains(technique_id.as_str()) {
            continue;
        }
        if !attack_chain_planner::technique_preconditions_met(&technique_id, facts) {
            return Ok(None);
        }
        let id: Uuid = r.try_get("id").map_err(|e| e.to_string())?;
        let engine: String = r.try_get("engine_id").unwrap_or_default();
        return Ok(Some((id, engine, technique_id)));
    }
    Ok(None)
}

/// Job success does not invent capability. TechniqueProven only when planned_gained
/// facts are present in the rebuilt WorldState (finding-grounded).
async fn prove_techniques_from_facts(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    campaign: &CampaignRecord,
    facts: &HashSet<Fact>,
) -> Result<(), String> {
    let rows = sqlx::query(
        r#"SELECT id, technique_id, planned_gained, outcome_facts
             FROM weissman_campaign_steps
            WHERE campaign_id = $1 AND status = 'succeeded'"#,
    )
    .bind(campaign.id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("prove: {e}"))?;
    for r in rows {
        let planned: Vec<String> = r
            .try_get::<Value, _>("planned_gained")
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        if planned.is_empty() {
            continue;
        }
        let observed: Vec<String> = planned
            .iter()
            .filter(|f| facts.contains(*f))
            .cloned()
            .collect();
        let step_id: Uuid = r.try_get("id").map_err(|e| e.to_string())?;
        sqlx::query(
            r#"UPDATE weissman_campaign_steps SET outcome_facts = $2, updated_at = now() WHERE id = $1"#,
        )
        .bind(step_id)
        .bind(json!(observed))
        .execute(&mut **tx)
        .await
        .map_err(|e| format!("outcome: {e}"))?;
        let already: Vec<String> = r
            .try_get::<Value, _>("outcome_facts")
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        if observed.len() == planned.len() && observed != already {
            let technique_id: String = r.try_get("technique_id").unwrap_or_default();
            insert_event(
                tx,
                campaign.id,
                campaign.tenant_id,
                campaign.client_id,
                "technique_proven",
                json!({ "technique_id": technique_id, "facts": observed }),
            )
            .await?;
        }
    }
    Ok(())
}

fn spawn_fabric_projections(
    pool: PgPool,
    campaign: CampaignRecord,
    facts: Vec<Fact>,
    finding_ids: Vec<String>,
) {
    tokio::spawn(async move {
        seed_campaign_blackboard(&campaign, &facts).await;
        if let Ok(mut tx) = crate::db::begin_tenant_tx(&pool, campaign.tenant_id).await {
            let _ = insert_event(
                &mut tx,
                campaign.id,
                campaign.tenant_id,
                campaign.client_id,
                "mesh_blackboard_seeded",
                json!({ "scan_id": campaign_blackboard_scan_id(campaign.id) }),
            )
            .await;
            let _ = tx.commit().await;
        }
        let snap = crate::attack_path::compute_and_store(
            &pool,
            campaign.tenant_id,
            campaign.client_id,
            Some(10),
        )
        .await;
        if let Ok(s) = snap {
            let snapshot_id = tag_latest_attack_path_snapshot(
                &pool,
                campaign.tenant_id,
                campaign.client_id,
                campaign.id,
            )
            .await;
            if let Ok(mut tx) = crate::db::begin_tenant_tx(&pool, campaign.tenant_id).await {
                let _ = insert_event(
                    &mut tx,
                    campaign.id,
                    campaign.tenant_id,
                    campaign.client_id,
                    "path_snapshot_taken",
                    json!({
                        "path_count": s.paths.len(),
                        "max_risk": s.max_path_score,
                        "entry_count": s.entry_count,
                        "jewel_count": s.jewel_count,
                        "finding_ids": finding_ids,
                        "snapshot_id": snapshot_id,
                        "campaign_id": campaign.id.to_string(),
                    }),
                )
                .await;
                let _ = tx.commit().await;
            }
        }
    });
}

/// Correlation only — does not change graph scope or Dijkstra inputs.
async fn tag_latest_attack_path_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    campaign_id: Uuid,
) -> Option<i64> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await.ok()?;
    let id = sqlx::query_scalar::<_, i64>(
        r#"UPDATE attack_path_snapshots SET campaign_id = $3
           WHERE id = (
             SELECT id FROM attack_path_snapshots
              WHERE tenant_id = $1 AND client_id = $2
              ORDER BY computed_at DESC
              LIMIT 1
           )
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(campaign_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    id
}

async fn seed_campaign_blackboard(campaign: &CampaignRecord, facts: &[Fact]) {
    if !crate::cem_dago::is_enabled() {
        return;
    }
    let scan_id = campaign_blackboard_scan_id(campaign.id);
    let Ok(bb) =
        crate::cem_dago::blackboard::open_scan(campaign.tenant_id, campaign.client_id, &scan_id)
            .await
    else {
        return;
    };
    let _ = bb
        .write_evidence(
            "world_state",
            "adversary_campaign",
            json!({
                "campaign_id": campaign.id.to_string(),
                "goal": campaign.goal_fact,
                "facts": facts,
            }),
        )
        .await;
    let _ = bb
        .write_evidence("goal", "adversary_campaign", json!(campaign.goal_fact))
        .await;
}

async fn tick_one(
    pool: &PgPool,
    tenant_id: i64,
    id: Uuid,
    actor_user_id: Option<i64>,
    want_running: bool,
    job_outcome: Option<(Uuid, bool, String)>,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let mut campaign = lock_campaign(&mut tx, tenant_id, id).await?;

    if let Some((job_id, ok, detail)) = job_outcome.as_ref() {
        let _ = bind_job_outcome(&mut tx, *job_id, *ok, detail).await?;
    }
    reconcile_jobs(&mut tx, campaign.id).await?;

    if want_running
        && matches!(
            campaign.status.as_str(),
            "draft" | "paused" | "blocked" | "failed"
        )
    {
        set_status(
            &mut tx,
            &campaign,
            "running",
            actor_user_id,
            "start",
            json!({}),
            None,
        )
        .await?;
        campaign.status = "running".into();
    }
    if campaign.status != "running" {
        tx.commit().await.map_err(|e| format!("commit: {e}"))?;
        return Ok(());
    }

    let suppressions = load_suppressions(&mut tx, tenant_id).await;
    let raw_findings = load_live_findings(&mut tx, tenant_id, campaign.client_id).await?;
    let findings = filter_findings_for_world_state(raw_findings, &suppressions);
    let finding_ids: Vec<String> = findings
        .iter()
        .filter_map(|f| {
            f.get("finding_id")
                .and_then(Value::as_str)
                .map(|s| s.to_string())
        })
        .take(50)
        .collect();
    insert_event(
        &mut tx,
        campaign.id,
        campaign.tenant_id,
        campaign.client_id,
        "finding_observed",
        json!({ "count": findings.len(), "finding_ids": finding_ids }),
    )
    .await?;

    let planned = attack_chain_planner::plan_strongest_asset(&findings, &campaign.goal_fact);
    let (asset_key, chain, _facts) = match planned {
        Some(t) => t,
        None => {
            let evidence = attack_chain_planner::facts_from_findings_with_evidence(&findings);
            persist_world_snapshot(&mut tx, &campaign, &evidence, &campaign.asset_key).await?;
            let facts: HashSet<Fact> = evidence.keys().cloned().collect();
            prove_techniques_from_facts(&mut tx, &campaign, &facts).await?;
            if facts.contains(&campaign.goal_fact) {
                set_status(
                    &mut tx,
                    &campaign,
                    "completed",
                    actor_user_id,
                    "goal_already_observed",
                    json!({ "goal": campaign.goal_fact }),
                    None,
                )
                .await?;
            } else {
                set_status(
                    &mut tx,
                    &campaign,
                    "blocked",
                    actor_user_id,
                    "goal_unreachable_from_observed_facts",
                    json!({ "goal": campaign.goal_fact }),
                    Some("planner returned no chain — refusing to invent capability"),
                )
                .await?;
            }
            tx.commit().await.map_err(|e| format!("commit: {e}"))?;
            return Ok(());
        }
    };

    let asset_findings: Vec<Value> = findings
        .iter()
        .filter(|f| attack_chain_planner::finding_asset_key(f) == asset_key)
        .cloned()
        .collect();
    let evidence = attack_chain_planner::facts_from_findings_with_evidence(&asset_findings);
    persist_world_snapshot(&mut tx, &campaign, &evidence, &asset_key).await?;
    let facts: HashSet<Fact> = evidence.keys().cloned().collect();
    prove_techniques_from_facts(&mut tx, &campaign, &facts).await?;

    if evidence.contains_key(&campaign.goal_fact) || chain.steps.is_empty() && chain.reached_goal {
        set_status(
            &mut tx,
            &campaign,
            "completed",
            actor_user_id,
            "goal_reached",
            json!({ "goal": campaign.goal_fact, "asset_key": asset_key }),
            None,
        )
        .await?;
        tx.commit().await.map_err(|e| format!("commit: {e}"))?;
        spawn_fabric_projections(
            pool.clone(),
            campaign.clone(),
            facts.into_iter().collect(),
            finding_ids,
        );
        return Ok(());
    }

    let target = pick_dispatch_target(&mut tx, &campaign, &asset_key).await?;
    insert_planned_steps(&mut tx, &campaign, &chain, &target).await?;
    skip_stale_planned_steps(&mut tx, &campaign, &chain).await?;

    let dispatch = if inflight_count(&mut tx, campaign.id).await? == 0 {
        pick_dispatchable_step(&mut tx, campaign.id, &chain, &facts).await?
    } else {
        None
    };

    if dispatch.is_none() && inflight_count(&mut tx, campaign.id).await? == 0 {
        let failed: Vec<String> = sqlx::query_scalar(
            r#"SELECT technique_id FROM weissman_campaign_steps
                WHERE campaign_id = $1 AND status = 'failed'"#,
        )
        .bind(campaign.id)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
        let needed: HashSet<&str> = chain
            .steps
            .iter()
            .map(|s| s.technique_id.as_str())
            .collect();
        if failed.iter().any(|t| needed.contains(t.as_str())) {
            set_status(
                &mut tx,
                &campaign,
                "blocked",
                actor_user_id,
                "technique_failed",
                json!({ "failed": failed }),
                Some("required technique failed; refusing to invent a substitute"),
            )
            .await?;
        }
    }

    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    spawn_fabric_projections(
        pool.clone(),
        campaign.clone(),
        facts.iter().cloned().collect(),
        finding_ids,
    );

    if let Some((step_id, engine, technique_id)) = dispatch {
        match enqueue_step_job(pool, &campaign, step_id, &engine, &target).await {
            Ok(job_id) => {
                let mut tx2 = crate::db::begin_tenant_tx(pool, tenant_id)
                    .await
                    .map_err(|e| format!("tx2: {e}"))?;
                sqlx::query(
                    r#"UPDATE weissman_campaign_steps
                          SET status = 'dispatched', job_id = $2, target = $3, updated_at = now()
                        WHERE id = $1 AND status = 'planned'"#,
                )
                .bind(step_id)
                .bind(job_id)
                .bind(&target)
                .execute(&mut *tx2)
                .await
                .map_err(|e| format!("mark dispatched: {e}"))?;
                insert_event(
                    &mut tx2,
                    campaign.id,
                    campaign.tenant_id,
                    campaign.client_id,
                    "technique_dispatched",
                    json!({
                        "step_id": step_id.to_string(),
                        "job_id": job_id.to_string(),
                        "engine_id": engine,
                        "technique_id": technique_id,
                        "target": target,
                    }),
                )
                .await?;
                let _ = tx2.commit().await;
            }
            Err(e) => {
                let mut tx2 = crate::db::begin_tenant_tx(pool, tenant_id)
                    .await
                    .map_err(|e| format!("tx2: {e}"))?;
                sqlx::query(
                    r#"UPDATE weissman_campaign_steps
                          SET status = 'failed', last_error = $2, updated_at = now()
                        WHERE id = $1 AND status = 'planned'"#,
                )
                .bind(step_id)
                .bind(&e)
                .execute(&mut *tx2)
                .await
                .map_err(|e| format!("mark failed: {e}"))?;
                let locked = lock_campaign(&mut tx2, tenant_id, campaign.id).await?;
                set_status(
                    &mut tx2,
                    &locked,
                    "blocked",
                    actor_user_id,
                    "dispatch_failed",
                    json!({ "error": e }),
                    Some(&e),
                )
                .await?;
                tx2.commit().await.map_err(|e| format!("commit: {e}"))?;
            }
        }
    }
    Ok(())
}

/// Fire-and-forget after findings persist so running campaigns absorb new evidence.
pub fn spawn_after_persist(pool: Arc<PgPool>, tenant_id: i64, client_id: i64) {
    tokio::spawn(async move {
        if let Err(e) = tick_running_for_client(&pool, tenant_id, client_id, None).await {
            tracing::debug!(target: "adversary_campaign", error = %e, "tick after persist skipped");
        }
    });
}

/// After a campaign-tagged engine job completes (or fails).
pub fn spawn_after_engine_job(
    pool: Arc<PgPool>,
    tenant_id: i64,
    client_id: Option<i64>,
    job_id: Uuid,
    payload: &Value,
    succeeded: bool,
    detail: String,
) {
    let campaign_id = parse_campaign_id(payload);
    let cid = client_id;
    tokio::spawn(async move {
        if let Some(cid) = campaign_id {
            if let Err(e) = tick_one(
                &pool,
                tenant_id,
                cid,
                None,
                false,
                Some((job_id, succeeded, detail)),
            )
            .await
            {
                tracing::debug!(target: "adversary_campaign", error = %e, "tick after job skipped");
            }
            return;
        }
        if let Some(client_id) = cid {
            if let Err(e) = tick_running_for_client(
                &pool,
                tenant_id,
                client_id,
                Some((job_id, succeeded, detail)),
            )
            .await
            {
                tracing::debug!(target: "adversary_campaign", error = %e, "tick after job skipped");
            }
        }
    });
}

async fn tick_running_for_client(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    job_outcome: Option<(Uuid, bool, String)>,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM weissman_campaigns
            WHERE tenant_id = $1 AND client_id = $2 AND status = 'running'"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("running: {e}"))?;
    let _ = tx.commit().await;
    for id in ids {
        tick_one(pool, tenant_id, id, None, false, job_outcome.clone()).await?;
    }
    Ok(())
}

/// Payload helper for tests / OpenAPI examples.
pub fn allowed_goals_json() -> Value {
    json!(ALLOWED_GOALS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_goals_match_technique_library_effects() {
        let lib = attack_chain_planner::default_technique_library();
        let mut effects: HashSet<String> = HashSet::new();
        for t in &lib {
            for e in &t.effects {
                effects.insert(e.clone());
            }
        }
        for g in ALLOWED_GOALS {
            assert!(
                effects.contains(*g) || *g == "cred:leaked",
                "goal {g} missing from library effects"
            );
            assert!(is_allowed_goal(g));
        }
        assert!(!is_allowed_goal("made_up:fact"));
        assert!(!is_allowed_goal("DROP TABLE"));
    }

    #[test]
    fn every_library_technique_maps_to_a_production_engine() {
        for t in attack_chain_planner::default_technique_library() {
            let engine =
                engine_for_technique(&t.id).unwrap_or_else(|| panic!("no engine map for {}", t.id));
            assert!(
                is_production_engine_id(engine),
                "technique {} mapped to non-production {engine}",
                t.id
            );
        }
    }

    #[test]
    fn state_machine_allows_operator_loop_not_completed_restart() {
        assert!(can_transition("draft", "running"));
        assert!(can_transition("running", "paused"));
        assert!(can_transition("paused", "running"));
        assert!(can_transition("running", "completed"));
        assert!(can_transition("running", "blocked"));
        assert!(can_transition("blocked", "running"));
        assert!(!can_transition("completed", "running"));
        assert!(!can_transition("draft", "paused"));
        assert!(!CAMPAIGN_STATUSES.is_empty());
    }

    #[test]
    fn fp_suppressed_findings_do_not_enter_world_state() {
        let findings = vec![
            json!({
                "finding_id": "keep",
                "source": "sqli_advanced",
                "signature_hash": "aaa",
                "title": "SQL injection",
                "type": "sqli",
                "severity": "high",
                "target": "https://app.example",
            }),
            json!({
                "finding_id": "noise",
                "source": "sqli_advanced",
                "signature_hash": "bbb",
                "title": "SQL injection",
                "type": "sqli",
                "severity": "high",
                "target": "https://app.example",
            }),
        ];
        let mut sup = HashMap::new();
        sup.insert(
            "sqli_advanced".into(),
            vec![SuppressionRule {
                signature_hash: "bbb".into(),
                target_glob: None,
            }],
        );
        let kept = filter_findings_for_world_state(findings, &sup);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["finding_id"], "keep");
        let facts = attack_chain_planner::facts_from_findings_with_evidence(&kept);
        assert!(facts.contains_key("vuln:sqli"));
        assert_eq!(facts["vuln:sqli"], vec!["keep".to_string()]);
    }

    #[test]
    fn merge_evidence_unions_ids_without_dupes() {
        let mut a = HashMap::new();
        a.insert("service:web".into(), vec!["1".into()]);
        let mut b = HashMap::new();
        b.insert("service:web".into(), vec!["1".into(), "2".into()]);
        b.insert("vuln:rce".into(), vec!["3".into()]);
        let m = merge_evidence(a, b);
        assert_eq!(m["service:web"], vec!["1".to_string(), "2".to_string()]);
        assert_eq!(m["vuln:rce"], vec!["3".to_string()]);
    }

    #[test]
    fn planner_bridge_never_invents_path() {
        let findings = vec![json!({
            "finding_id": "web-only",
            "type": "tls",
            "title": "HTTPS service",
            "severity": "info",
        })];
        assert!(
            attack_chain_planner::plan_strongest_asset(&findings, "impact:objective").is_none()
        );
    }

    #[test]
    fn target_stays_in_scope_rejects_foreign_host() {
        assert!(target_stays_in_scope(
            "https://app.customer.test/login",
            "https://customer.test"
        ));
        assert!(!target_stays_in_scope(
            "https://evil.other.test",
            "https://customer.test"
        ));
    }

    #[test]
    fn api_create_request_contract() {
        let req: CreateCampaignRequest = serde_json::from_value(json!({
            "client_id": 7,
            "goal": "access:foothold"
        }))
        .unwrap();
        assert_eq!(req.client_id, 7);
        assert_eq!(req.goal.as_deref(), Some("access:foothold"));
        let list = json!({
            "ok": true,
            "campaigns": [],
            "allowed_goals": ALLOWED_GOALS,
        });
        assert_eq!(list["ok"], true);
        assert!(list["allowed_goals"].as_array().unwrap().len() >= 5);
    }

    #[test]
    fn campaign_id_stamps_findings_for_persist_and_soar() {
        let id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let stamped = stamp_campaign_id_on_findings(
            &[json!({ "finding_id": "f1", "title": "RCE" })],
            Some(id),
        );
        assert_eq!(
            stamped[0].get("campaign_id").and_then(Value::as_str),
            Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        );
        assert_eq!(
            parse_campaign_id(&json!({ "campaign_id": id.to_string() })),
            Some(id)
        );
        assert_eq!(
            parse_campaign_id(&json!({
                "extras": { "campaign_id": id.to_string() }
            })),
            Some(id)
        );
        assert!(parse_campaign_id(&json!({})).is_none());
    }

    #[test]
    fn spine_and_event_kinds_include_remediation_verified() {
        assert!(CAMPAIGN_EVENT_KINDS.contains(&"remediation_verified"));
        let id = Uuid::nil();
        let s = spine_json(id);
        assert_eq!(s["disclose_externally"], false);
        assert_eq!(s["probe_executor"], "engine_dispatch");
        assert_eq!(s["event_bus"], "weissman_campaign_events");
        assert_eq!(s["job_bus"], "weissman-job-bus");
        assert_eq!(s["roe"], "authorized-tenant+scope_pin+no_auto_disclosure");
    }

    #[test]
    fn mesh_wave_preview_does_not_enqueue() {
        let engines = vec!["rce_exploit_engine".into(), "sqli_advanced".into()];
        let mut present = HashSet::new();
        present.insert("internet_exposed".into());
        let waves = crate::cem_dago::schedule_waves(&engines, &present);
        assert!(!waves.is_empty());
        assert!(
            json!({ "waves": waves, "waves_are_preview": true })["waves_are_preview"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn campaign_scoped_council_rejects_only_technique_shaped_unauthorized_ids() {
        let rejected = unauthorized_technique_shaped_steps(&[
            "Phish CFO via spear-phish".into(),
            "invented_zero_click".into(),
            "exploit_rce_web".into(),
            "T1190".into(),
        ]);
        assert_eq!(rejected, vec!["invented_zero_click".to_string()]);
        assert!(looks_like_technique_id("invented_zero_click"));
        assert!(!looks_like_technique_id("Phish CFO via spear-phish"));
        assert!(!looks_like_technique_id("T1190"));
    }

    #[test]
    fn council_proposals_are_allowlisted_never_freestyle() {
        let proposed = vec![
            "exploit_rce_web".into(),
            "invented_zero_click".into(),
            "lateral_movement".into(),
        ];
        let kept = allowlisted_techniques(&proposed);
        assert_eq!(kept, vec!["exploit_rce_web", "lateral_movement"]);
        assert!(!kept.iter().any(|t| t == "invented_zero_click"));
    }

    #[test]
    fn event_hash_is_stable_and_versioned() {
        let id = Uuid::nil();
        let p = json!({ "goal": "impact:objective" });
        let a = hash_campaign_event(id, "campaign_created", &p, None);
        let b = hash_campaign_event(id, "campaign_created", &p, None);
        assert_eq!(a, b);
        let c = hash_campaign_event(id, "campaign_created", &p, Some(&a));
        assert_ne!(a, c);
        assert!(CAMPAIGN_EVENT_KINDS.contains(&"technique_proven"));
        assert!(CAMPAIGN_EVENT_KINDS.contains(&"finding_observed"));
        assert_eq!(CAMPAIGN_EVENT_VERSION, 1);
        assert_eq!(
            campaign_blackboard_scan_id(id),
            "campaign:00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn dispatch_requires_evidenced_preconditions() {
        let facts: HashSet<Fact> = ["service:web".into()].into_iter().collect();
        assert!(!attack_chain_planner::technique_preconditions_met(
            "exploit_rce_web",
            &facts
        ));
        let ready: HashSet<Fact> = ["service:web".into(), "vuln:rce".into()]
            .into_iter()
            .collect();
        assert!(attack_chain_planner::technique_preconditions_met(
            "exploit_rce_web",
            &ready
        ));
    }
}
