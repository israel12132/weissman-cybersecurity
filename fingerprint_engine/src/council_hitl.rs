//! Human-In-The-Loop (HITL) approval queue for Council-proposed attack chains.
//!
//! The Council (Alpha → Beta → Gamma → Sovereign General) produces `chain_steps` and a
//! `payload_preview`; those are inserted as `PENDING_APPROVAL` rows. An authenticated operator
//! must call `approve` before any async job is fired. Rejection is recorded permanently.
//!
//! **Safety invariant**: `safety_rails_no_shells` is **always** `true` for every fired job.
//! This module never persists or transmits a weaponized payload.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ─── Proposal ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct HitlProposal {
    pub target_brief: String,
    pub chain_steps: Vec<String>,
    /// Safe excerpt — must not contain weaponized payloads (shells, stagers, etc.).
    pub payload_preview: String,
    pub rationale: String,
    pub estimated_severity: String,
    pub council_job_id: Option<Uuid>,
    pub client_id: Option<i64>,
}

/// Clamp a `payload_preview` to a safe, fixed length and strip common shell markers.
/// This is a defense-in-depth measure on top of the LLM safety prompt.
fn sanitize_preview(raw: &str) -> String {
    const MAX_LEN: usize = 800;
    let truncated: String = raw.chars().take(MAX_LEN).collect();
    // Case-insensitive check for tokens associated with shell escapes / stager patterns.
    let lower = truncated.to_ascii_lowercase();
    for bad in &["/bin/sh", "/bin/bash", "cmd.exe", "powershell", "nc -e", "bash -i"] {
        if lower.contains(bad) {
            return "[preview redacted — shell keyword detected]".to_string();
        }
    }
    truncated
}

fn norm_severity(s: &str) -> String {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "low" => "low",
        _ => "medium",
    }
    .to_string()
}

// ─── Proposal ─────────────────────────────────────────────────────────────────

/// Insert a new `PENDING_APPROVAL` row.
/// Returns the HITL queue row `id`.
pub async fn propose(pool: &PgPool, tenant_id: i64, p: &HitlProposal) -> Result<i64, sqlx::Error> {
    let steps = serde_json::to_value(&p.chain_steps).unwrap_or(json!([]));
    let preview = sanitize_preview(&p.payload_preview);
    let sev = norm_severity(&p.estimated_severity);

    let mut tx = weissman_db::begin_tenant_tx(pool, tenant_id).await?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO council_hitl_queue
               (tenant_id, client_id, target_brief, chain_steps, payload_preview,
                rationale, estimated_severity, council_job_id, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'PENDING_APPROVAL')
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(p.client_id)
    .bind(p.target_brief.trim())
    .bind(steps)
    .bind(&preview)
    .bind(p.rationale.trim())
    .bind(&sev)
    .bind(p.council_job_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

// ─── Queue listing ────────────────────────────────────────────────────────────

/// Return pending (and recently reviewed) HITL items for the operator dashboard.
pub async fn list_queue(
    pool: &PgPool,
    tenant_id: i64,
    status_filter: Option<&str>,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = weissman_db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, client_id, target_brief, chain_steps, payload_preview,
                  rationale, estimated_severity, council_job_id,
                  status, review_note, fired_job_id,
                  proposed_at, reviewed_at, fired_at
           FROM council_hitl_queue
           WHERE tenant_id = $1
             AND ($2::text IS NULL OR status = $2)
           ORDER BY proposed_at DESC
           LIMIT 200"#,
    )
    .bind(tenant_id)
    .bind(status_filter)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    let mut out = Vec::new();
    for r in &rows {
        out.push(json!({
            "id":                  r.try_get::<i64,_>("id").ok(),
            "client_id":           r.try_get::<Option<i64>,_>("client_id").ok().flatten(),
            "target_brief":        r.try_get::<String,_>("target_brief").ok(),
            "chain_steps":         r.try_get::<Value,_>("chain_steps").ok(),
            "payload_preview":     r.try_get::<String,_>("payload_preview").ok(),
            "rationale":           r.try_get::<String,_>("rationale").ok(),
            "estimated_severity":  r.try_get::<String,_>("estimated_severity").ok(),
            "council_job_id":      r.try_get::<Option<Uuid>,_>("council_job_id").ok().flatten().map(|u| u.to_string()),
            "status":              r.try_get::<String,_>("status").ok(),
            "review_note":         r.try_get::<Option<String>,_>("review_note").ok().flatten(),
            "fired_job_id":        r.try_get::<Option<Uuid>,_>("fired_job_id").ok().flatten().map(|u| u.to_string()),
            "proposed_at":         r.try_get::<chrono::DateTime<chrono::Utc>,_>("proposed_at").ok(),
            "reviewed_at":         r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("reviewed_at").ok().flatten(),
            "fired_at":            r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("fired_at").ok().flatten(),
        }));
    }
    Ok(out)
}

// ─── Approval & firing ────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ApproveError {
    NotFound,
    WrongStatus(String),
    Db(sqlx::Error),
    Enqueue(sqlx::Error),
}

impl std::fmt::Display for ApproveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "item not found"),
            Self::WrongStatus(s) => write!(f, "wrong status: {s}"),
            Self::Db(e) => write!(f, "db: {e}"),
            Self::Enqueue(e) => write!(f, "enqueue: {e}"),
        }
    }
}

/// Approve a HITL item and enqueue a `council_debate` async job.
///
/// **Safety contract**: `safety_rails_no_shells` is forced `true` in the enqueued payload,
/// regardless of any system config. The operator cannot override this here.
pub async fn approve_and_fire(
    pool: &PgPool,
    tenant_id: i64,
    item_id: i64,
    reviewed_by: i64,
    review_note: Option<&str>,
) -> Result<Uuid, ApproveError> {
    let mut tx = weissman_db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(ApproveError::Db)?;

    // Fetch + lock
    let row = sqlx::query(
        r#"SELECT id, status, target_brief, chain_steps, client_id, council_job_id
           FROM council_hitl_queue
           WHERE id = $1 AND tenant_id = $2
           FOR UPDATE"#,
    )
    .bind(item_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApproveError::Db)?;

    let Some(row) = row else {
        let _ = tx.rollback().await;
        return Err(ApproveError::NotFound);
    };
    let status: String = row.try_get("status").unwrap_or_default();
    if status != "PENDING_APPROVAL" {
        let _ = tx.rollback().await;
        return Err(ApproveError::WrongStatus(status));
    }

    let brief: String = row.try_get("target_brief").unwrap_or_default();
    let chain: Value = row.try_get("chain_steps").unwrap_or(json!([]));
    let client_id: Option<i64> = row.try_get("client_id").ok().flatten();

    // Build async job payload — safety_rails_no_shells is ALWAYS true
    let job_payload = serde_json::to_value(serde_json::json!({
        "target_brief": brief,
        "chain_steps_hint": chain,
        "client_id": client_id,
        "safety_rails_no_shells": true,   // non-negotiable
        "hitl_approved": true,
        "reviewed_by": reviewed_by,
        "source": "hitl_approved",
    }))
    .unwrap_or(json!({}));

    // Enqueue the council_debate job within the same transaction
    let job_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs (tenant_id, kind, payload, status)
           VALUES ($1, 'council_debate', $2, 'pending')
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&job_payload)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApproveError::Enqueue)?;

    // Update HITL row
    sqlx::query(
        r#"UPDATE council_hitl_queue
           SET status = 'FIRED', reviewed_by = $1, review_note = $2,
               fired_job_id = $3, reviewed_at = now(), fired_at = now()
           WHERE id = $4 AND tenant_id = $5"#,
    )
    .bind(reviewed_by)
    .bind(review_note)
    .bind(job_id)
    .bind(item_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(ApproveError::Db)?;

    tx.commit().await.map_err(ApproveError::Db)?;
    Ok(job_id)
}

/// Reject a HITL item (no job is fired).
pub async fn reject(
    pool: &PgPool,
    tenant_id: i64,
    item_id: i64,
    reviewed_by: i64,
    review_note: Option<&str>,
) -> Result<(), ApproveError> {
    let mut tx = weissman_db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(ApproveError::Db)?;

    let row = sqlx::query(
        "SELECT status FROM council_hitl_queue WHERE id = $1 AND tenant_id = $2",
    )
    .bind(item_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApproveError::Db)?;

    let Some(row) = row else {
        let _ = tx.rollback().await;
        return Err(ApproveError::NotFound);
    };
    let status: String = row.try_get("status").unwrap_or_default();
    if status != "PENDING_APPROVAL" {
        let _ = tx.rollback().await;
        return Err(ApproveError::WrongStatus(status));
    }

    sqlx::query(
        r#"UPDATE council_hitl_queue
           SET status = 'REJECTED', reviewed_by = $1, review_note = $2, reviewed_at = now()
           WHERE id = $3 AND tenant_id = $4"#,
    )
    .bind(reviewed_by)
    .bind(review_note)
    .bind(item_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(ApproveError::Db)?;

    tx.commit().await.map_err(ApproveError::Db)?;
    Ok(())
}

// ─── OAST probe token registry ────────────────────────────────────────────────

/// Mint a structured OAST probe token and persist it, linked to client/finding.
pub async fn mint_oast_probe(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    finding_id: Option<&str>,
    hitl_queue_id: Option<i64>,
    probe_type: &str,
    target_url: &str,
    label: &str,
) -> Result<Uuid, sqlx::Error> {
    let valid_type = match probe_type {
        "log4shell" | "blind_xss" | "blind_xxe" | "blind_ssrf" => probe_type,
        _ => "generic",
    };
    let mut tx = weissman_db::begin_tenant_tx(pool, tenant_id).await?;
    let token: Uuid = sqlx::query_scalar(
        r#"INSERT INTO oast_probe_tokens
               (tenant_id, client_id, finding_id, hitl_queue_id,
                probe_type, target_url, label)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING token"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(finding_id)
    .bind(hitl_queue_id)
    .bind(valid_type)
    .bind(target_url.trim())
    .bind(label.trim())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(token)
}

/// Poll `oast_interaction_hits` for the given token, update `oast_probe_tokens.hit_count`.
/// Returns a JSON summary with `oob_confirmed`, `hit_count`, and `first_hit_at`.
pub async fn poll_oast_token(
    pool: &PgPool,
    tenant_id: i64,
    token: Uuid,
) -> Result<Value, sqlx::Error> {
    let mut tx = weissman_db::begin_tenant_tx(pool, tenant_id).await?;

    // Verify the token belongs to this tenant (RLS enforced by the tenant transaction)
    let probe_row = sqlx::query(
        r#"SELECT id, probe_type, target_url, label, client_id, finding_id, hit_count, first_hit_at, created_at
           FROM oast_probe_tokens
           WHERE token = $1 AND tenant_id = $2"#,
    )
    .bind(token)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(probe) = probe_row else {
        let _ = tx.rollback().await;
        return Ok(json!({"error":"token_not_found"}));
    };

    // Count live hits from the OAST listener table (not tenant-scoped, global service)
    let hit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM oast_interaction_hits WHERE interaction_token = $1",
    )
    .bind(token)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let first_hit: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT MIN(created_at) FROM oast_interaction_hits WHERE interaction_token = $1",
    )
    .bind(token)
    .fetch_one(&mut *tx)
    .await
    .ok()
    .flatten();

    // Update the cache columns in oast_probe_tokens
    sqlx::query(
        r#"UPDATE oast_probe_tokens
           SET hit_count = $1, first_hit_at = COALESCE(first_hit_at, $2), last_polled_at = now()
           WHERE token = $3 AND tenant_id = $4"#,
    )
    .bind(hit_count as i32)
    .bind(first_hit)
    .bind(token)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(json!({
        "token":          token.to_string(),
        "probe_type":     probe.try_get::<String,_>("probe_type").ok(),
        "target_url":     probe.try_get::<String,_>("target_url").ok(),
        "label":          probe.try_get::<String,_>("label").ok(),
        "client_id":      probe.try_get::<Option<i64>,_>("client_id").ok().flatten(),
        "finding_id":     probe.try_get::<Option<String>,_>("finding_id").ok().flatten(),
        "hit_count":      hit_count,
        "oob_confirmed":  hit_count > 0,
        "first_hit_at":   first_hit,
        "created_at":     probe.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").ok(),
        "safety_rails_no_shells": true,
    }))
}

