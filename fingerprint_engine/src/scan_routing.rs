//! Maps Command Center `engine` + JSON body to `weissman_async_jobs.kind` + payload.
//! Registry-based validation (declarative [`Requires`]), entitlement gate, and pre-injected OAST tokens.
//!
//! **Edge swarm:** After routing, the HTTP scan handler enriches payloads with vLLM-assisted
//! [`crate::edge_swarm_intel::enrich_scan_payload_with_edge_node`] (region proximity + lowest
//! `active_jobs`, RLS-scoped reads on `edge_swarm_nodes`). The orchestrator logs the same assignment
//! at cycle start for telemetry parity.
//!
//! ## AI-heavy entitlement (live DB; no env stubs)
//! Per-tenant `system_configs`:
//! - `ai_heavy_entitled` — if `false`/`0`/`no`, AI-heavy routes return 402. Absent → allowed (self-hosted default).
//! - `ai_daily_scan_quota` — positive integer caps AI-heavy-related job **enqueues** per UTC day (count from `weissman_async_jobs`). `0` or absent → unlimited.

use axum::http::StatusCode;
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;
use weissman_core::models::engine::is_known_engine_id;

/// Extra engine ids accepted by the scan API beyond [`KNOWN_ENGINE_IDS`] (DAG / Engine Room).
pub const EXTRA_SCAN_ENGINE_IDS: &[&str] = &[
    "ollama_fuzz",
    "zero_day_radar",
    "poe_synthesis",
    "pipeline",
    "http_feedback_fuzz",
];

#[must_use]
pub fn is_allowed_scan_engine(engine: &str) -> bool {
    let e = engine.trim();
    is_known_engine_id(e) || EXTRA_SCAN_ENGINE_IDS.iter().any(|&k| k == e)
}

// --- Declarative requirements ------------------------------------------------

/// Fields the router validates before building a job payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requires {
    NonEmptyTarget,
    ClientId,
    /// `repo_url` or non-empty `target` (used as repository URL).
    RepoUrlOrTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntitlementTier {
    Standard,
    /// Premium / quota-gated (LLM-heavy or high-cost offensive paths).
    AiHeavy,
}

#[derive(Debug, Clone)]
pub enum RouteError {
    BadRequest(String),
    PaymentRequired { detail: String },
    Forbidden { detail: String },
    Internal { detail: String },
}

impl RouteError {
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            RouteError::BadRequest(_) => StatusCode::BAD_REQUEST,
            RouteError::PaymentRequired { .. } => StatusCode::PAYMENT_REQUIRED,
            RouteError::Forbidden { .. } => StatusCode::FORBIDDEN,
            RouteError::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            RouteError::BadRequest(s) => s.as_str(),
            RouteError::PaymentRequired { detail } => detail.as_str(),
            RouteError::Forbidden { detail } => detail.as_str(),
            RouteError::Internal { detail } => detail.as_str(),
        }
    }

    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            RouteError::BadRequest(_) => "bad_request",
            RouteError::PaymentRequired { .. } => "payment_required",
            RouteError::Forbidden { .. } => "forbidden",
            RouteError::Internal { .. } => "internal_error",
        }
    }
}

fn parse_boolish(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

/// Jobs that count toward `ai_daily_scan_quota` (UTC day window).
const AI_QUOTA_COUNT_SQL: &str = r#"
    (
        kind IN (
            'deep_fuzz', 'ai_redteam', 'poe_synthesis_run', 'feedback_fuzz',
            'council_debate', 'genesis_eternal_fuzz'
        )
        OR (
            kind = 'command_center_engine'
            AND COALESCE(payload->>'engine', '') IN (
                'semantic_ai_fuzz', 'ai_adversarial_redteam', 'llm_path_fuzz', 'ollama_fuzz',
                'http_feedback_fuzz', 'poe_synthesis'
            )
        )
    )
"#;

async fn count_ai_heavy_jobs_today_utc(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<i64, sqlx::Error> {
    let now = Utc::now();
    let day_start = match now.date_naive().and_hms_opt(0, 0, 0) {
        Some(dt) => dt.and_utc(),
        None => {
            tracing::error!(target: "scan_routing", "utc day_start: invalid midnight; using current time (quota count may be inaccurate)");
            now
        }
    };
    let q = format!(
        r#"SELECT COUNT(*)::bigint FROM weissman_async_jobs
           WHERE tenant_id = $1 AND created_at >= $2 AND {}"#,
        AI_QUOTA_COUNT_SQL
    );
    sqlx::query_scalar(&q)
        .bind(tenant_id)
        .bind(day_start)
        .fetch_one(pool)
        .await
}

async fn try_audit_entitlement_denial(
    pool: &PgPool,
    tenant_id: i64,
    action: &str,
    details: &str,
) {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        tracing::error!(target: "scan_routing", tenant_id, %action, "begin_tenant_tx failed for entitlement audit");
        return;
    };
    if let Err(e) = crate::audit_log::insert_audit(
        &mut tx,
        tenant_id,
        None,
        "system",
        action,
        details,
        "",
    )
    .await
    {
        tracing::error!(target: "scan_routing", tenant_id, error = %e, "insert_audit entitlement denial failed");
    }
    let _ = tx.commit().await;
}

/// Enforces `system_configs` + daily AI job counts. Fails closed on DB errors (502-style via RouteError::Internal).
pub async fn check_tenant_entitlement(
    pool: &PgPool,
    tenant_id: i64,
    engine: &str,
    tier: EntitlementTier,
) -> Result<(), RouteError> {
    match tier {
        EntitlementTier::Standard => Ok(()),
        EntitlementTier::AiHeavy => {
            let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await.map_err(|e| {
                tracing::error!(
                    target: "scan_routing",
                    tenant_id,
                    error = %e,
                    "begin_tenant_tx for ai_heavy_entitled read failed"
                );
                RouteError::Internal {
                    detail: format!("database error (tenant tx): {e}"),
                }
            })?;

            let entitled_raw: Option<String> = sqlx::query_scalar(
                "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'ai_heavy_entitled'",
            )
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(
                    target: "scan_routing",
                    tenant_id,
                    error = %e,
                    "read ai_heavy_entitled failed"
                );
                RouteError::Internal {
                    detail: format!("database error: {e}"),
                }
            })?;

            let quota_raw: Option<String> = sqlx::query_scalar(
                "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'ai_daily_scan_quota'",
            )
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(
                    target: "scan_routing",
                    tenant_id,
                    error = %e,
                    "read ai_daily_scan_quota failed"
                );
                RouteError::Internal {
                    detail: format!("database error: {e}"),
                }
            })?;

            let _ = tx.commit().await;

            let explicitly_denied = entitled_raw
                .as_deref()
                .and_then(parse_boolish)
                == Some(false);
            if explicitly_denied {
                let detail = format!(
                    "AI-heavy engine '{engine}' blocked: system_configs.ai_heavy_entitled is false for tenant {tenant_id}"
                );
                tracing::warn!(target: "scan_routing", tenant_id, engine = %engine, "ai_heavy_entitlement denied (config)");
                try_audit_entitlement_denial(
                    pool,
                    tenant_id,
                    "ai_scan_entitlement_denied",
                    &detail,
                )
                .await;
                return Err(RouteError::PaymentRequired { detail });
            }

            let quota_limit: u64 = quota_raw
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            if quota_limit > 0 {
                let used = count_ai_heavy_jobs_today_utc(pool, tenant_id).await.map_err(|e| {
                    tracing::error!(
                        target: "scan_routing",
                        tenant_id,
                        error = %e,
                        "ai_daily_scan_quota count query failed"
                    );
                    RouteError::Internal {
                        detail: format!("database error (quota count): {e}"),
                    }
                })?;
                let used_u = used.max(0) as u64;
                if used_u >= quota_limit {
                    let detail = format!(
                        "AI-heavy daily quota exhausted: {used_u}/{quota_limit} jobs (UTC day) for tenant {tenant_id}; engine '{engine}'"
                    );
                    tracing::warn!(target: "scan_routing", tenant_id, used = used_u, limit = quota_limit, "ai_daily_scan_quota exceeded");
                    try_audit_entitlement_denial(
                        pool,
                        tenant_id,
                        "ai_scan_quota_exhausted",
                        &detail,
                    )
                    .await;
                    return Err(RouteError::Forbidden { detail });
                }
            }

            Ok(())
        }
    }
}

// --- Extracted body (single pass) -------------------------------------------

#[derive(Debug, Clone)]
struct ScanBodyFields {
    target: String,
    client_id: Option<Value>,
    ai_endpoint: Option<Value>,
    repo_url: Option<String>,
    base_payload: String,
}

fn extract_fields(body: &Value) -> ScanBodyFields {
    let target = body
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let client_id = body.get("client_id").cloned().filter(|v| !v.is_null());
    let ai_endpoint = body.get("ai_endpoint").cloned();
    let repo_url = body
        .get("repo_url")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let base_payload = body
        .get("base_payload")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    ScanBodyFields {
        target,
        client_id,
        ai_endpoint,
        repo_url,
        base_payload,
    }
}

fn validate_requires(reqs: &[Requires], ctx: &ScanBodyFields, engine_label: &str) -> Result<(), RouteError> {
    for r in reqs {
        match r {
            Requires::NonEmptyTarget => {
                if ctx.target.is_empty() {
                    return Err(RouteError::BadRequest(format!(
                        "target required for {engine_label}"
                    )));
                }
            }
            Requires::ClientId => {
                if ctx.client_id.is_none() {
                    return Err(RouteError::BadRequest(format!(
                        "client_id required for {engine_label}"
                    )));
                }
            }
            Requires::RepoUrlOrTarget => {
                let has_repo = ctx.repo_url.as_ref().is_some_and(|s| !s.is_empty());
                if !has_repo && ctx.target.is_empty() {
                    return Err(RouteError::BadRequest(format!(
                        "repo_url or target (repository URL) required for {engine_label}"
                    )));
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PayloadKind {
    DeepFuzz,
    TimingScan,
    AiRedteam,
    ThreatIntelRun,
    PoeSynthesis,
    PipelineScan,
    FeedbackFuzz,
    CommandCenterDefault,
}

struct RouteDef {
    engines: &'static [&'static str],
    job_kind: &'static str,
    requires: &'static [Requires],
    entitlement: EntitlementTier,
    inject_oast: bool,
    payload: PayloadKind,
}

static ROUTES: &[RouteDef] = &[
    RouteDef {
        engines: &["semantic_ai_fuzz"],
        job_kind: "deep_fuzz",
        requires: &[Requires::NonEmptyTarget],
        entitlement: EntitlementTier::AiHeavy,
        inject_oast: false,
        payload: PayloadKind::DeepFuzz,
    },
    RouteDef {
        engines: &["microsecond_timing"],
        job_kind: "timing_scan",
        requires: &[Requires::NonEmptyTarget],
        entitlement: EntitlementTier::Standard,
        inject_oast: false,
        payload: PayloadKind::TimingScan,
    },
    RouteDef {
        engines: &["ai_adversarial_redteam"],
        job_kind: "ai_redteam",
        requires: &[Requires::NonEmptyTarget],
        entitlement: EntitlementTier::AiHeavy,
        inject_oast: true,
        payload: PayloadKind::AiRedteam,
    },
    RouteDef {
        engines: &["zero_day_radar"],
        job_kind: "threat_intel_run",
        requires: &[],
        entitlement: EntitlementTier::Standard,
        inject_oast: false,
        payload: PayloadKind::ThreatIntelRun,
    },
    RouteDef {
        engines: &["poe_synthesis"],
        job_kind: "poe_synthesis_run",
        requires: &[Requires::NonEmptyTarget],
        entitlement: EntitlementTier::AiHeavy,
        inject_oast: false,
        payload: PayloadKind::PoeSynthesis,
    },
    RouteDef {
        engines: &["pipeline"],
        job_kind: "pipeline_scan",
        requires: &[Requires::RepoUrlOrTarget],
        entitlement: EntitlementTier::Standard,
        inject_oast: false,
        payload: PayloadKind::PipelineScan,
    },
    RouteDef {
        engines: &["http_feedback_fuzz"],
        job_kind: "feedback_fuzz",
        requires: &[Requires::NonEmptyTarget, Requires::ClientId],
        entitlement: EntitlementTier::AiHeavy,
        inject_oast: true,
        payload: PayloadKind::FeedbackFuzz,
    },
];

fn find_route_def(engine: &str) -> Option<&'static RouteDef> {
    ROUTES
        .iter()
        .find(|d| d.engines.iter().any(|&e| e == engine))
}

fn entitlement_for_fallback_engine(engine: &str) -> EntitlementTier {
    if matches!(
        engine,
        "semantic_ai_fuzz"
            | "ai_adversarial_redteam"
            | "llm_path_fuzz"
            | "ollama_fuzz"
            | "http_feedback_fuzz"
            | "poe_synthesis"
    ) {
        EntitlementTier::AiHeavy
    } else {
        EntitlementTier::Standard
    }
}

fn build_payload(
    kind: PayloadKind,
    ctx: &ScanBodyFields,
    engine_for_default: &str,
) -> Result<Value, RouteError> {
    fn obj_mut(v: &mut Value) -> Result<&mut serde_json::Map<String, Value>, RouteError> {
        v.as_object_mut()
            .ok_or_else(|| RouteError::Internal {
                detail: "scan payload: expected JSON object".into(),
            })
    }
    match kind {
        PayloadKind::DeepFuzz => {
            let mut p = json!({ "target": &ctx.target });
            if let Some(ref cid) = ctx.client_id {
                obj_mut(&mut p)?.insert("client_id".into(), cid.clone());
            }
            Ok(p)
        }
        PayloadKind::TimingScan => {
            let mut p = json!({ "target": &ctx.target });
            if let Some(ref cid) = ctx.client_id {
                obj_mut(&mut p)?.insert("client_id".into(), cid.clone());
            }
            Ok(p)
        }
        PayloadKind::AiRedteam => {
            let mut p = json!({ "target": &ctx.target });
            if let Some(ref cid) = ctx.client_id {
                obj_mut(&mut p)?.insert("client_id".into(), cid.clone());
            }
            if let Some(ref ep) = ctx.ai_endpoint {
                obj_mut(&mut p)?.insert("ai_endpoint".into(), ep.clone());
            }
            Ok(p)
        }
        PayloadKind::ThreatIntelRun => Ok(json!({})),
        PayloadKind::PoeSynthesis => Ok(json!({ "target": &ctx.target })),
        PayloadKind::PipelineScan => {
            let repo = ctx
                .repo_url
                .clone()
                .or_else(|| {
                    if ctx.target.is_empty() {
                        None
                    } else {
                        Some(ctx.target.clone())
                    }
                })
                .unwrap_or_default();
            let mut p = json!({ "repo_url": repo });
            if let Some(ref cid) = ctx.client_id {
                obj_mut(&mut p)?.insert("client_id".into(), cid.clone());
            }
            Ok(p)
        }
        PayloadKind::FeedbackFuzz => {
            let Some(cid) = ctx.client_id.as_ref() else {
                return Err(RouteError::BadRequest(
                    "client_id required for feedback fuzz payload".into(),
                ));
            };
            Ok(json!({
                "target": &ctx.target,
                "base_payload": &ctx.base_payload,
                "client_id": cid.clone(),
            }))
        }
        PayloadKind::CommandCenterDefault => {
            let engine_norm = if engine_for_default == "ollama_fuzz" {
                "llm_path_fuzz"
            } else {
                engine_for_default
            };
            Ok(json!({ "engine": engine_norm, "target": &ctx.target }))
        }
    }
}

fn inject_oast_token(mut payload: Value, token: Uuid) -> Value {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(
            "oast_interaction_token".into(),
            json!(token.to_string()),
        );
    } else {
        tracing::error!(target: "scan_routing", "inject_oast_token: payload is not a JSON object; OAST token not inserted");
    }
    payload
}

/// Returns `(job_kind, job_payload)` after registry validation, entitlement check, and optional OAST injection.
pub async fn route_scan_job(
    body: &Value,
    tenant_id: i64,
    pool: &PgPool,
) -> Result<(String, Value), RouteError> {
    let engine_raw = body
        .get("engine")
        .and_then(Value::as_str)
        .ok_or_else(|| RouteError::BadRequest("engine required".into()))?;
    let engine = engine_raw.trim();
    if !is_allowed_scan_engine(engine) {
        return Err(RouteError::BadRequest(format!(
            "unknown or disallowed engine: {engine_raw}"
        )));
    }

    let ctx = extract_fields(body);

    if let Some(def) = find_route_def(engine) {
        validate_requires(def.requires, &ctx, engine)?;
        check_tenant_entitlement(pool, tenant_id, engine, def.entitlement).await?;

        let oast = if def.inject_oast {
            Some(Uuid::new_v4())
        } else {
            None
        };
        let mut payload = build_payload(def.payload, &ctx, engine)?;
        if let Some(t) = oast {
            payload = inject_oast_token(payload, t);
        }
        return Ok((def.job_kind.to_string(), payload));
    }

    // Default: command_center_engine (known engines + extras not in explicit table)
    validate_requires(&[Requires::NonEmptyTarget], &ctx, engine)?;
    let ent = entitlement_for_fallback_engine(engine);
    check_tenant_entitlement(pool, tenant_id, engine, ent).await?;

    let payload = build_payload(PayloadKind::CommandCenterDefault, &ctx, engine)?;
    Ok(("command_center_engine".to_string(), payload))
}
