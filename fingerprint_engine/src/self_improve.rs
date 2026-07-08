//! Autonomous self-improvement engine.
//!
//! Runs on an hourly leader-only loop (toggled live from the Command Center via the
//! `self_improve_enabled` system config). Each cycle analyses the platform and proposes
//! concrete improvements across seven categories — new engines, engine improvements, new
//! modules, smarter wiring, better synchronisation, gap-closing, and code/doc cleanliness —
//! inserting them as `PENDING_APPROVAL` rows in `system_improvement_queue`.
//!
//! **Safety invariant**: approval NEVER mutates the codebase in-process. Approving a proposal
//! enqueues a `self_improvement_apply` job that opens a PULL REQUEST for human review + CI;
//! `main` is never written directly. Every cycle is recorded to `audit_logs`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tokio::sync::broadcast::Sender;
use uuid::Uuid;

/// One improvement suggestion produced by a cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImprovementProposal {
    pub category: String,
    pub title: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default = "default_low")]
    pub risk: String,
    #[serde(default = "default_medium")]
    pub impact: String,
    #[serde(default = "default_medium")]
    pub effort: String,
    #[serde(default)]
    pub proposed_diff_summary: String,
    #[serde(default)]
    pub affected_files: Vec<String>,
    #[serde(default = "default_analyzer")]
    pub source: String,
}

fn default_low() -> String {
    "low".into()
}
fn default_medium() -> String {
    "medium".into()
}
fn default_analyzer() -> String {
    "analyzer".into()
}

const VALID_CATEGORIES: &[&str] = &[
    "new_engine",
    "improve_engine",
    "new_module",
    "improve_module",
    "wiring",
    "sync",
    "gap",
    "cleanliness",
];

fn norm_category(c: &str) -> String {
    let c = c.trim().to_ascii_lowercase();
    if VALID_CATEGORIES.contains(&c.as_str()) {
        c
    } else {
        "gap".to_string()
    }
}

fn norm_level(s: &str) -> String {
    match s.trim().to_ascii_lowercase().as_str() {
        "high" => "high",
        "low" => "low",
        _ => "medium",
    }
    .to_string()
}

// ─── Toggle (live GUI control) ──────────────────────────────────────────────────

/// Whether the autonomous engine is enabled for this tenant (system config
/// `self_improve_enabled` = "1"/"true"/"yes"). Defaults to disabled (opt-in).
pub async fn is_enabled(pool: &PgPool, tenant_id: i64) -> bool {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return false;
    };
    let val: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'self_improve_enabled'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    matches!(
        val.as_deref().map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

// ─── Queue operations (mirror council_hitl) ─────────────────────────────────────

/// Insert a batch of proposals for one cycle. Returns the number inserted.
pub async fn insert_proposals(
    pool: &PgPool,
    tenant_id: i64,
    cycle_id: Uuid,
    proposals: &[ImprovementProposal],
) -> Result<u64, sqlx::Error> {
    if proposals.is_empty() {
        return Ok(0);
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let mut n = 0u64;
    for p in proposals {
        let category = norm_category(&p.category);
        let files = serde_json::to_value(&p.affected_files).unwrap_or(json!([]));
        sqlx::query(
            r#"INSERT INTO system_improvement_queue
                   (tenant_id, category, title, rationale, risk, impact, effort,
                    proposed_diff_summary, affected_files, source, cycle_id, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'PENDING_APPROVAL')"#,
        )
        .bind(tenant_id)
        .bind(&category)
        .bind(p.title.trim())
        .bind(p.rationale.trim())
        .bind(norm_level(&p.risk))
        .bind(norm_level(&p.impact))
        .bind(norm_level(&p.effort))
        .bind(p.proposed_diff_summary.trim())
        .bind(files)
        .bind(p.source.trim())
        .bind(cycle_id)
        .execute(&mut *tx)
        .await?;
        n += 1;
    }
    tx.commit().await?;
    Ok(n)
}

/// List queue items for the Command Center console.
pub async fn list_queue(
    pool: &PgPool,
    tenant_id: i64,
    status_filter: Option<&str>,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, category, title, rationale, risk, impact, effort,
                  proposed_diff_summary, affected_files, status, source, cycle_id,
                  review_note, pr_url, proposed_at, reviewed_at
           FROM system_improvement_queue
           WHERE tenant_id = $1
             AND ($2::text IS NULL OR status = $2)
           ORDER BY proposed_at DESC
           LIMIT 200"#,
    )
    .bind(tenant_id)
    .bind(status_filter)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;

    let mut out = Vec::new();
    for r in &rows {
        out.push(json!({
            "id":                    r.try_get::<i64,_>("id").ok(),
            "category":              r.try_get::<String,_>("category").ok(),
            "title":                 r.try_get::<String,_>("title").ok(),
            "rationale":             r.try_get::<String,_>("rationale").ok(),
            "risk":                  r.try_get::<String,_>("risk").ok(),
            "impact":                r.try_get::<String,_>("impact").ok(),
            "effort":                r.try_get::<String,_>("effort").ok(),
            "proposed_diff_summary": r.try_get::<String,_>("proposed_diff_summary").ok(),
            "affected_files":        r.try_get::<Value,_>("affected_files").ok(),
            "status":                r.try_get::<String,_>("status").ok(),
            "source":                r.try_get::<String,_>("source").ok(),
            "cycle_id":              r.try_get::<Option<Uuid>,_>("cycle_id").ok().flatten().map(|u| u.to_string()),
            "review_note":           r.try_get::<Option<String>,_>("review_note").ok().flatten(),
            "pr_url":                r.try_get::<Option<String>,_>("pr_url").ok().flatten(),
            "proposed_at":           r.try_get::<chrono::DateTime<chrono::Utc>,_>("proposed_at").ok(),
            "reviewed_at":           r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("reviewed_at").ok().flatten(),
        }));
    }
    Ok(out)
}

#[derive(Debug)]
pub enum ReviewError {
    NotFound,
    WrongStatus(String),
    Db(sqlx::Error),
}

impl std::fmt::Display for ReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "item not found"),
            Self::WrongStatus(s) => write!(f, "wrong status: {s}"),
            Self::Db(e) => write!(f, "db: {e}"),
        }
    }
}

/// Approve a proposal: mark APPROVED and enqueue a `self_improvement_apply` job that
/// will open a PULL REQUEST. Never mutates code in-process, never writes to main.
/// Returns the enqueued apply-job id.
pub async fn approve(
    pool: &PgPool,
    tenant_id: i64,
    item_id: i64,
    reviewed_by: i64,
    review_note: Option<&str>,
) -> Result<Uuid, ReviewError> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(ReviewError::Db)?;

    let row = sqlx::query(
        r#"SELECT status, category, title, proposed_diff_summary, affected_files
           FROM system_improvement_queue
           WHERE id = $1 AND tenant_id = $2
           FOR UPDATE"#,
    )
    .bind(item_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ReviewError::Db)?;

    let Some(row) = row else {
        let _ = tx.rollback().await;
        return Err(ReviewError::NotFound);
    };
    let status: String = row.try_get("status").unwrap_or_default();
    if status != "PENDING_APPROVAL" {
        let _ = tx.rollback().await;
        return Err(ReviewError::WrongStatus(status));
    }

    let title: String = row.try_get("title").unwrap_or_default();
    let category: String = row.try_get("category").unwrap_or_default();
    let diff_summary: String = row.try_get("proposed_diff_summary").unwrap_or_default();
    let affected: Value = row.try_get("affected_files").unwrap_or(json!([]));

    // Enqueue the apply job. The out-of-process executor turns this into a PR — it must
    // never merge to main; approval here only authorises opening a PR for human review.
    let job_payload = json!({
        "improvement_id": item_id,
        "category": category,
        "title": title,
        "proposed_diff_summary": diff_summary,
        "affected_files": affected,
        "approved_by": reviewed_by,
        "open_pr_only": true,        // non-negotiable: PR, never a direct commit to main
        "source": "self_improvement_approved",
    });
    let job_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs (tenant_id, kind, payload, status)
           VALUES ($1, 'self_improvement_apply', $2, 'pending')
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&job_payload)
    .fetch_one(&mut *tx)
    .await
    .map_err(ReviewError::Db)?;

    sqlx::query(
        r#"UPDATE system_improvement_queue
           SET status = 'APPROVED', reviewed_by = $1, review_note = $2,
               apply_job_id = $3, reviewed_at = now()
           WHERE id = $4 AND tenant_id = $5"#,
    )
    .bind(reviewed_by)
    .bind(review_note)
    .bind(job_id)
    .bind(item_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(ReviewError::Db)?;

    tx.commit().await.map_err(ReviewError::Db)?;
    Ok(job_id)
}

/// Reject a proposal (no job is enqueued).
pub async fn reject(
    pool: &PgPool,
    tenant_id: i64,
    item_id: i64,
    reviewed_by: i64,
    review_note: Option<&str>,
) -> Result<(), ReviewError> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(ReviewError::Db)?;
    let row = sqlx::query(
        "SELECT status FROM system_improvement_queue WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(item_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ReviewError::Db)?;
    let Some(row) = row else {
        let _ = tx.rollback().await;
        return Err(ReviewError::NotFound);
    };
    let status: String = row.try_get("status").unwrap_or_default();
    if status != "PENDING_APPROVAL" {
        let _ = tx.rollback().await;
        return Err(ReviewError::WrongStatus(status));
    }
    sqlx::query(
        r#"UPDATE system_improvement_queue
           SET status = 'REJECTED', reviewed_by = $1, review_note = $2, reviewed_at = now()
           WHERE id = $3 AND tenant_id = $4"#,
    )
    .bind(reviewed_by)
    .bind(review_note)
    .bind(item_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(ReviewError::Db)?;
    tx.commit().await.map_err(ReviewError::Db)?;
    Ok(())
}

// ─── Analysis cycle ─────────────────────────────────────────────────────────────

/// Gather deterministic, always-available signals for one tenant.
async fn gather_signals(pool: &PgPool, tenant_id: i64) -> Vec<(String, i64)> {
    let mut sig = Vec::new();
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return sig;
    };

    let open_critical: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM vulnerabilities WHERE tenant_id = $1 \
         AND severity IN ('critical','high') AND status NOT IN ('FIXED','FALSE_POSITIVE')",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    sig.push(("open_critical_high".to_string(), open_critical));

    let dead_jobs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM weissman_async_jobs WHERE tenant_id = $1 AND status = 'dead'",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    sig.push(("dead_jobs".to_string(), dead_jobs));

    let false_positives: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM vulnerabilities WHERE tenant_id = $1 AND status = 'FALSE_POSITIVE'",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    sig.push(("false_positives".to_string(), false_positives));

    let _ = tx.commit().await;
    sig
}

/// Deterministic proposals derived purely from live signals (no LLM needed).
fn deterministic_proposals(signals: &[(String, i64)]) -> Vec<ImprovementProposal> {
    let mut out = Vec::new();
    let get = |k: &str| signals.iter().find(|(n, _)| n == k).map(|(_, v)| *v).unwrap_or(0);

    if get("dead_jobs") > 0 {
        out.push(ImprovementProposal {
            category: "gap".into(),
            title: format!("Investigate {} dead async jobs", get("dead_jobs")),
            rationale: "Jobs in status='dead' exhausted their retries — a reliability gap worth root-causing (timeout, panic, or bad payload).".into(),
            risk: "low".into(),
            impact: "medium".into(),
            effort: "medium".into(),
            proposed_diff_summary: "Add a dead-letter triage report and, where reproducible, fix the failing job kind's handler or raise its per-kind timeout.".into(),
            affected_files: vec!["crates/weissman-worker/src/main.rs".into(), "fingerprint_engine/src/async_job_executor.rs".into()],
            source: "deterministic".into(),
        });
    }
    if get("false_positives") >= 10 {
        out.push(ImprovementProposal {
            category: "improve_engine".into(),
            title: "Tune engines with high false-positive volume".into(),
            rationale: format!("{} findings are marked FALSE_POSITIVE — the engines producing them are candidates for tighter evidence gating or auto-suppression.", get("false_positives")),
            risk: "low".into(),
            impact: "high".into(),
            effort: "medium".into(),
            proposed_diff_summary: "Cross-reference fp_feedback to rank the noisiest (engine, signature) pairs and tighten their probe evidence thresholds.".into(),
            affected_files: vec!["fingerprint_engine/src/fp_feedback.rs".into()],
            source: "deterministic".into(),
        });
    }
    out
}

/// Run one improvement cycle for a tenant: gather signals, ask the LLM (if configured)
/// for structured proposals across all categories, merge with deterministic proposals,
/// insert as PENDING_APPROVAL, write an audit report row, and emit telemetry.
pub async fn run_cycle(
    pool: &PgPool,
    telemetry: &Sender<String>,
    tenant_id: i64,
) -> Result<u64, String> {
    let cycle_id = Uuid::new_v4();
    let signals = gather_signals(pool, tenant_id).await;
    let mut proposals = deterministic_proposals(&signals);

    // LLM augmentation (optional — cycle still produces deterministic proposals without it).
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let llm_base: String = sqlx::query_scalar(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or_default();
    let llm_model: String = sqlx::query_scalar(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or_default();
    let _ = tx.commit().await;

    if !llm_base.trim().is_empty() {
        let signal_summary = signals
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let client = weissman_engines::openai_chat::llm_http_client(90);
        let model = weissman_engines::openai_chat::resolve_llm_model(&llm_model);
        let user = format!(
            "You are the lead architect of an autonomous offensive-security platform (Rust + React, \
             563 engine IDs, Postgres+RLS). Propose concrete, safe improvements. Categories allowed: \
             new_engine, improve_engine, new_module, improve_module, wiring, sync, gap, cleanliness. \
             Live signals: {signal_summary}. \
             Respond ONLY minified JSON: {{\"proposals\":[{{\"category\":\"...\",\"title\":\"...\",\
             \"rationale\":\"...\",\"risk\":\"low|medium|high\",\"impact\":\"low|medium|high\",\
             \"effort\":\"low|medium|high\",\"proposed_diff_summary\":\"...\",\"affected_files\":[\"...\"]}}]}}. \
             Max 8 proposals, highest impact first."
        );
        match weissman_engines::openai_chat::chat_completion_text(
            &client,
            &llm_base,
            &model,
            Some("JSON only. No markdown. No prose."),
            &user,
            0.2,
            2048,
            Some(tenant_id),
            "self_improvement_cycle",
            true,
        )
        .await
        {
            Ok(text) => {
                let v: Value = serde_json::from_str(text.trim())
                    .or_else(|_| {
                        let s = text.trim();
                        let start = s.find('{').unwrap_or(0);
                        let end = s.rfind('}').map(|i| i + 1).unwrap_or(s.len());
                        serde_json::from_str(&s[start..end])
                    })
                    .unwrap_or(json!({}));
                if let Some(arr) = v.get("proposals").and_then(|p| p.as_array()) {
                    for item in arr.iter().take(8) {
                        if let Ok(mut p) =
                            serde_json::from_value::<ImprovementProposal>(item.clone())
                        {
                            if p.title.trim().is_empty() {
                                continue;
                            }
                            p.source = "llm".into();
                            proposals.push(p);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target: "self_improve", error = %e, "LLM augmentation failed; deterministic proposals only");
            }
        }
    }

    let inserted = insert_proposals(pool, tenant_id, cycle_id, &proposals)
        .await
        .map_err(|e| e.to_string())?;

    // Signed audit report row + telemetry event (the hourly "what I found" report).
    let report = json!({
        "cycle_id": cycle_id.to_string(),
        "signals": signals.iter().map(|(k, v)| json!({"metric": k, "value": v})).collect::<Vec<_>>(),
        "proposals_generated": inserted,
    });
    if let Ok(mut atx) = crate::db::begin_tenant_tx(pool, tenant_id).await {
        let _ = crate::audit_log::insert_audit(
            &mut atx,
            tenant_id,
            None,
            "self-improve-engine",
            "self_improvement_cycle",
            &report.to_string(),
            "",
        )
        .await;
        let _ = atx.commit().await;
    }
    let _ = telemetry.send(
        json!({
            "event": "self_improvement_cycle",
            "severity": "info",
            "cycle_id": cycle_id.to_string(),
            "proposals": inserted,
        })
        .to_string(),
    );

    Ok(inserted)
}

// ─── Hourly loop ────────────────────────────────────────────────────────────────

/// Spawn the hourly self-improvement loop. Leader-gated by the caller. The loop checks
/// the live `self_improve_enabled` toggle every tick, so the Command Center switch takes
/// effect immediately with no restart. Interval defaults to 3600s (hourly), min 300s.
pub fn spawn_self_improve_loop(app_pool: Arc<PgPool>, telemetry: Arc<Sender<String>>) {
    let interval_secs = std::env::var("WEISSMAN_SELF_IMPROVE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600)
        .max(300);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // consume the immediate first tick
        loop {
            tick.tick().await;
            // Run for every active tenant that has the toggle on.
            let tenants: Vec<i64> = sqlx::query_scalar(
                "SELECT id FROM tenants WHERE active = true ORDER BY id",
            )
            .fetch_all(app_pool.as_ref())
            .await
            .unwrap_or_default();
            for tenant_id in tenants {
                if !is_enabled(app_pool.as_ref(), tenant_id).await {
                    continue;
                }
                if let Err(e) = run_cycle(app_pool.as_ref(), telemetry.as_ref(), tenant_id).await {
                    tracing::warn!(target: "self_improve", tenant_id, error = %e, "cycle failed");
                }
            }
        }
    });
}
