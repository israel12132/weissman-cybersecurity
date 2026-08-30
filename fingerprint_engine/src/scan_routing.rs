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
use sqlx::{PgPool, Row};
use uuid::Uuid;
use weissman_core::models::engine::is_production_engine_id;

/// Extra engine ids accepted by the scan API beyond `PRODUCTION_ENGINE_IDS` (DAG / Engine Room).
/// All entries here are legacy/alias IDs that aren't in the production set but are still wired.
pub const EXTRA_SCAN_ENGINE_IDS: &[&str] =
    &["ollama_fuzz", "zero_day_radar", "poe_synthesis", "pipeline"];

#[must_use]
pub fn is_allowed_scan_engine(engine: &str) -> bool {
    let e = engine.trim();
    // Production + explicit legacy aliases only — catalog-only engines cannot be enqueued via HTTP.
    is_production_engine_id(e) || EXTRA_SCAN_ENGINE_IDS.iter().any(|&k| k == e)
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
    PaymentRequired {
        detail: String,
    },
    Forbidden {
        detail: String,
    },
    /// 429: AI-heavy daily quota exceeded. `reset_at_unix` is the next UTC midnight.
    QuotaExceeded {
        detail: String,
        reset_at_unix: i64,
        limit: u64,
        used: u64,
    },
    Internal {
        detail: String,
    },
}

impl RouteError {
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            RouteError::BadRequest(_) => StatusCode::BAD_REQUEST,
            RouteError::PaymentRequired { .. } => StatusCode::PAYMENT_REQUIRED,
            RouteError::Forbidden { .. } => StatusCode::FORBIDDEN,
            RouteError::QuotaExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
            RouteError::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            RouteError::BadRequest(s) => s.as_str(),
            RouteError::PaymentRequired { detail } => detail.as_str(),
            RouteError::Forbidden { detail } => detail.as_str(),
            RouteError::QuotaExceeded { detail, .. } => detail.as_str(),
            RouteError::Internal { detail } => detail.as_str(),
        }
    }

    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            RouteError::BadRequest(_) => "bad_request",
            RouteError::PaymentRequired { .. } => "payment_required",
            RouteError::Forbidden { .. } => "forbidden",
            RouteError::QuotaExceeded { .. } => "quota_exceeded",
            RouteError::Internal { .. } => "internal_error",
        }
    }

    /// Quota-related metadata for `Retry-After` header / JSON body.
    #[must_use]
    pub fn quota_metadata(&self) -> Option<(i64, u64, u64)> {
        match self {
            RouteError::QuotaExceeded {
                reset_at_unix,
                limit,
                used,
                ..
            } => Some((*reset_at_unix, *limit, *used)),
            _ => None,
        }
    }
}

/// Default daily quota for AI-heavy scans when the tenant has no explicit `ai_daily_scan_quota`.
pub const DEFAULT_AI_DAILY_SCAN_QUOTA: u64 = 50;

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
                'http_feedback_fuzz', 'poe_synthesis', 'nexus_sovereign_swarm'
            )
        )
    )
"#;

async fn count_ai_heavy_jobs_today_utc(pool: &PgPool, tenant_id: i64) -> Result<i64, sqlx::Error> {
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

async fn try_audit_entitlement_denial(pool: &PgPool, tenant_id: i64, action: &str, details: &str) {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        tracing::error!(target: "scan_routing", tenant_id, %action, "begin_tenant_tx failed for entitlement audit");
        return;
    };
    if let Err(e) =
        crate::audit_log::insert_audit(&mut tx, tenant_id, None, "system", action, details, "")
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
            let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
                .await
                .map_err(|e| {
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

            let explicitly_denied = entitled_raw.as_deref().and_then(parse_boolish) == Some(false);
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

            // Quota: explicit positive integer → use it.
            // 0 in config → unlimited (legacy behaviour kept for paid plans).
            // Missing in config → DEFAULT_AI_DAILY_SCAN_QUOTA (50).
            let quota_limit: u64 = match quota_raw.as_deref().map(str::trim) {
                Some("") | None => DEFAULT_AI_DAILY_SCAN_QUOTA,
                Some(s) => s.parse::<u64>().unwrap_or(DEFAULT_AI_DAILY_SCAN_QUOTA),
            };

            if quota_limit > 0 {
                let used = count_ai_heavy_jobs_today_utc(pool, tenant_id)
                    .await
                    .map_err(|e| {
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
                    // Compute next UTC midnight as reset point.
                    let now = Utc::now();
                    let tomorrow = now
                        .date_naive()
                        .succ_opt()
                        .unwrap_or_else(|| now.date_naive());
                    let reset_at = tomorrow
                        .and_hms_opt(0, 0, 0)
                        .map(|dt| dt.and_utc().timestamp())
                        .unwrap_or_else(|| now.timestamp() + 3600);
                    let detail = format!(
                        "AI-heavy daily quota exhausted: {used_u}/{quota_limit} jobs (UTC day) for tenant {tenant_id}; engine '{engine}'. Resets at {reset_at} (UTC midnight)."
                    );
                    tracing::warn!(
                        target: "scan_routing",
                        tenant_id,
                        used = used_u,
                        limit = quota_limit,
                        reset_at,
                        "ai_daily_scan_quota exceeded"
                    );
                    try_audit_entitlement_denial(
                        pool,
                        tenant_id,
                        "ai_scan_quota_exhausted",
                        &detail,
                    )
                    .await;
                    return Err(RouteError::QuotaExceeded {
                        detail,
                        reset_at_unix: reset_at,
                        limit: quota_limit,
                        used: used_u,
                    });
                }
            }

            Ok(())
        }
    }
}

// --- Extracted body (single pass) -------------------------------------------

const MASKED_SECRET: &str = "••••••••";

fn is_masked_secret_value(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        let t = s.trim();
        t == MASKED_SECRET || t.starts_with("••••")
    })
}

fn extra_value_usable(v: &Value) -> bool {
    if v.is_null() {
        return false;
    }
    if is_masked_secret_value(v) {
        return false;
    }
    if let Some(s) = v.as_str() {
        return !s.trim().is_empty();
    }
    true
}

#[derive(Debug, Clone)]
struct ClientCredentialSnapshot {
    aws_role_arn: String,
    aws_external_id: String,
    gcp_project_id: String,
    azure_subscription_id: String,
    azure_tenant_id: String,
    ad_domain: String,
    first_repo_url: String,
    ebpf_ssh_host: String,
    ebpf_ssh_user: String,
}

#[derive(Debug, Clone, Default)]
struct TenantScanSecrets {
    github_token: String,
    oast_domain: String,
    oast_api_key: String,
}

async fn tenant_config_string(pool: &PgPool, tenant_id: i64, key: &str) -> Result<String, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx for {key}: {e}"))?;
    let val: Option<String> =
        sqlx::query_scalar("SELECT value FROM system_configs WHERE tenant_id = $1 AND key = $2")
            .bind(tenant_id)
            .bind(key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("read system_configs.{key}: {e}"))?;
    let _ = tx.commit().await;
    Ok(val.unwrap_or_default().trim().to_string())
}

async fn load_tenant_scan_secrets(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<TenantScanSecrets, String> {
    let github_token = tenant_config_string(pool, tenant_id, "github_token").await?;
    let mut oast_domain = tenant_config_string(pool, tenant_id, "oast_domain").await?;
    let oast_api_key = tenant_config_string(pool, tenant_id, "oast_api_key").await?;
    if oast_domain.is_empty() {
        oast_domain = std::env::var("WEISSMAN_OAST_DOMAIN")
            .or_else(|_| std::env::var("WEISSMAN_OAST_BASE_DOMAIN"))
            .unwrap_or_default()
            .trim()
            .to_string();
    }
    let github_token = if github_token.is_empty() {
        std::env::var("GITHUB_TOKEN")
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        github_token
    };
    let oast_api_key = if oast_api_key.is_empty() {
        std::env::var("WEISSMAN_OAST_API_KEY")
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        oast_api_key
    };
    Ok(TenantScanSecrets {
        github_token,
        oast_domain,
        oast_api_key,
    })
}

async fn load_client_credentials(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Option<ClientCredentialSnapshot>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx for client credentials: {e}"))?;
    let row = sqlx::query(
        r#"SELECT
            COALESCE(trim(aws_cross_account_role_arn),'') AS aws_arn,
            COALESCE(trim(aws_external_id),'') AS aws_ext,
            COALESCE(trim(gcp_project_id),'') AS gcp,
            COALESCE(NULLIF(trim(client_configs), ''), '{}') AS client_configs
           FROM clients WHERE id = $1"#,
    )
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("read client credentials: {e}"))?;
    let _ = tx.commit().await;
    let Some(r) = row else {
        return Ok(None);
    };
    let aws_arn: String = r.try_get("aws_arn").unwrap_or_default();
    let aws_ext: String = r.try_get("aws_ext").unwrap_or_default();
    let gcp: String = r.try_get("gcp").unwrap_or_default();
    let config_str: String = r
        .try_get("client_configs")
        .unwrap_or_else(|_| "{}".to_string());
    let config_val: Value = serde_json::from_str(&config_str).unwrap_or(json!({}));
    let onboarding = config_val.get("onboarding").cloned().unwrap_or(json!({}));
    let azure_subscription_id = onboarding
        .get("azure_subscription_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let azure_tenant_id = onboarding
        .get("azure_tenant_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let ad_domain = onboarding
        .get("ad_domain")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let first_repo_url = onboarding
        .get("repo_urls")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .find(|s| !s.trim().is_empty())
        })
        .unwrap_or("")
        .trim()
        .to_string();
    let ebpf_ssh_host = onboarding
        .get("ebpf_ssh_host")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let ebpf_ssh_user = onboarding
        .get("ebpf_ssh_user")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    Ok(Some(ClientCredentialSnapshot {
        aws_role_arn: aws_arn,
        aws_external_id: aws_ext,
        gcp_project_id: gcp,
        azure_subscription_id,
        azure_tenant_id,
        ad_domain,
        first_repo_url,
        ebpf_ssh_host,
        ebpf_ssh_user,
    }))
}

fn hydrate_extras_from_client(
    extras: &mut std::collections::HashMap<String, Value>,
    creds: &ClientCredentialSnapshot,
) {
    fn insert_if_absent(
        extras: &mut std::collections::HashMap<String, Value>,
        key: &str,
        val: &str,
    ) {
        if val.trim().is_empty() {
            return;
        }
        let needs = extras
            .get(key)
            .map(|v| !extra_value_usable(v))
            .unwrap_or(true);
        if needs {
            extras.insert(key.to_string(), json!(val));
        }
    }
    insert_if_absent(extras, "aws_cross_account_role_arn", &creds.aws_role_arn);
    insert_if_absent(extras, "aws_role_arn", &creds.aws_role_arn);
    insert_if_absent(extras, "aws_external_id", &creds.aws_external_id);
    insert_if_absent(extras, "gcp_project", &creds.gcp_project_id);
    insert_if_absent(extras, "gcp_project_id", &creds.gcp_project_id);
    insert_if_absent(
        extras,
        "azure_subscription_id",
        &creds.azure_subscription_id,
    );
    insert_if_absent(extras, "azure_tenant_id", &creds.azure_tenant_id);
    insert_if_absent(extras, "ad_domain", &creds.ad_domain);
    insert_if_absent(extras, "domain", &creds.ad_domain);
    insert_if_absent(extras, "repo_url", &creds.first_repo_url);
    insert_if_absent(extras, "ebpf_ssh_host", &creds.ebpf_ssh_host);
    insert_if_absent(extras, "ebpf_ssh_user", &creds.ebpf_ssh_user);
}

fn hydrate_extras_from_tenant(
    extras: &mut std::collections::HashMap<String, Value>,
    secrets: &TenantScanSecrets,
) {
    fn insert_if_absent(
        extras: &mut std::collections::HashMap<String, Value>,
        key: &str,
        val: &str,
    ) {
        if val.trim().is_empty() {
            return;
        }
        let needs = extras
            .get(key)
            .map(|v| !extra_value_usable(v))
            .unwrap_or(true);
        if needs {
            extras.insert(key.to_string(), json!(val));
        }
    }
    insert_if_absent(extras, "github_token", &secrets.github_token);
    insert_if_absent(extras, "oast_domain", &secrets.oast_domain);
    insert_if_absent(extras, "oast_api_key", &secrets.oast_api_key);
}

#[derive(Debug, Clone)]
struct ScanBodyFields {
    target: String,
    client_id: Option<Value>,
    ai_endpoint: Option<Value>,
    repo_url: Option<String>,
    base_payload: String,
    extras: std::collections::HashMap<String, Value>,
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
    let reserved = [
        "target",
        "client_id",
        "ai_endpoint",
        "repo_url",
        "base_payload",
        "engine",
        "timeout",
    ];
    let mut extras = std::collections::HashMap::new();
    if let Some(obj) = body.as_object() {
        for (k, v) in obj {
            if !reserved.contains(&k.as_str()) && extra_value_usable(v) {
                extras.insert(k.clone(), v.clone());
            }
        }
    }
    ScanBodyFields {
        target,
        client_id,
        ai_endpoint,
        repo_url,
        base_payload,
        extras,
    }
}

fn validate_requires(
    reqs: &[Requires],
    ctx: &ScanBodyFields,
    engine_label: &str,
) -> Result<(), RouteError> {
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
            | "nexus_sovereign_swarm"
    ) {
        EntitlementTier::AiHeavy
    } else {
        EntitlementTier::Standard
    }
}

fn enforce_scope_validation_for_engine(engine: &str) -> bool {
    !matches!(engine, "pipeline" | "zero_day_radar")
}

/// Read `system_configs.enforce_scope_strict` for the tenant. Default = `true`.
/// Returns Err on database error so we *fail closed* if the policy can't be read.
async fn enforce_scope_strict(pool: &PgPool, tenant_id: i64) -> Result<bool, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx for enforce_scope_strict: {e}"))?;
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'enforce_scope_strict'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("read enforce_scope_strict: {e}"))?;
    let _ = tx.commit().await;
    Ok(match raw.as_deref().map(str::trim) {
        Some("false") | Some("0") | Some("no") => false,
        _ => true,
    })
}

fn build_payload(
    kind: PayloadKind,
    ctx: &ScanBodyFields,
    engine_for_default: &str,
) -> Result<Value, RouteError> {
    fn obj_mut(v: &mut Value) -> Result<&mut serde_json::Map<String, Value>, RouteError> {
        v.as_object_mut().ok_or_else(|| RouteError::Internal {
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
        PayloadKind::PoeSynthesis => {
            let mut p = json!({ "target": &ctx.target });
            if let Some(ref cid) = ctx.client_id {
                obj_mut(&mut p)?.insert("client_id".into(), cid.clone());
            }
            Ok(p)
        }
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
            let mut p = json!({ "engine": engine_norm, "target": &ctx.target });
            if let Some(ref cid) = ctx.client_id {
                obj_mut(&mut p)?.insert("client_id".into(), cid.clone());
            }
            {
                let obj = obj_mut(&mut p)?;
                for (k, v) in &ctx.extras {
                    obj.insert(k.clone(), v.clone());
                }
            }
            Ok(p)
        }
    }
}

fn inject_oast_token(mut payload: Value, token: Uuid) -> Value {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("oast_interaction_token".into(), json!(token.to_string()));
    } else {
        tracing::error!(target: "scan_routing", "inject_oast_token: payload is not a JSON object; OAST token not inserted");
    }
    payload
}

fn parse_client_id(ctx: &ScanBodyFields) -> Option<i64> {
    let v = ctx.client_id.as_ref()?;
    if let Some(id) = v.as_i64() {
        return Some(id);
    }
    v.as_str().and_then(|s| s.trim().parse::<i64>().ok())
}

fn inject_scope_validation(
    mut payload: Value,
    scope: &crate::security_hardening::ScopeValidationOutcome,
) -> Value {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(
            "validated_scope".into(),
            json!({
                "host": scope.normalized_host,
                "resolved_ips": scope.resolved_ips,
            }),
        );
    } else {
        tracing::error!(target: "scan_routing", "inject_scope_validation: payload is not a JSON object");
    }
    payload
}

/// Strip hydrated secrets before the async-job row is written; workers re-hydrate live from DB.
fn seal_payload_for_queue(payload: Value) -> Value {
    crate::scan_payload_redaction::strip_secrets_for_storage(payload)
}

/// Re-hydrate client/tenant credentials into an in-memory job payload (worker execution only).
pub async fn hydrate_stored_job_payload(
    pool: &PgPool,
    tenant_id: i64,
    payload: &mut Value,
) -> Result<(), String> {
    let client_id = payload.get("client_id").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
    });
    let reserved = [
        "target",
        "client_id",
        "engine",
        "validated_scope",
        "oast_interaction_token",
        "repo_url",
        "base_payload",
        "ai_endpoint",
        "timeout",
    ];
    let mut extras = std::collections::HashMap::new();
    if let Some(obj) = payload.as_object() {
        for (k, v) in obj {
            if !reserved.contains(&k.as_str()) {
                extras.insert(k.clone(), v.clone());
            }
        }
    }
    if let Some(cid) = client_id {
        if let Ok(Some(creds)) = load_client_credentials(pool, tenant_id, cid).await {
            hydrate_extras_from_client(&mut extras, &creds);
        }
    }
    if let Ok(secrets) = load_tenant_scan_secrets(pool, tenant_id).await {
        hydrate_extras_from_tenant(&mut extras, &secrets);
    }
    if let Some(obj) = payload.as_object_mut() {
        for (k, v) in extras {
            obj.insert(k, v);
        }
    }
    Ok(())
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

    let mut ctx = extract_fields(body);
    let client_id = parse_client_id(&ctx);

    if let Some(cid) = client_id {
        if let Ok(Some(creds)) = load_client_credentials(pool, tenant_id, cid).await {
            hydrate_extras_from_client(&mut ctx.extras, &creds);
        }
    }
    if let Ok(secrets) = load_tenant_scan_secrets(pool, tenant_id).await {
        hydrate_extras_from_tenant(&mut ctx.extras, &secrets);
    }

    // ── BLOCKER #1: Strict scope validation ──────────────────────────────────
    //
    // Every scan with a target MUST be inside the client's approved scope
    // unless the engine is explicitly exempt (`pipeline` operates on repo
    // URLs, `zero_day_radar` is intel-only). In all other cases:
    //   - target must be non-empty AND
    //   - client_id must be supplied AND
    //   - target must resolve to / match an approved domain or IP range
    //
    // `enforce_scope_strict` system_config can be set to `false` for a
    // tenant to opt out (e.g. red-team-as-a-service mode). Default = strict.
    let enforce_strict = enforce_scope_strict(pool, tenant_id)
        .await
        .map_err(|e| RouteError::Internal { detail: e })?;
    let scope_outcome = if enforce_scope_validation_for_engine(engine) {
        if ctx.target.is_empty() {
            return Err(RouteError::BadRequest(format!(
                "target required for engine '{engine}' (scope-enforced)"
            )));
        }
        if enforce_strict && client_id.is_none() {
            return Err(RouteError::BadRequest(format!(
                "client_id required for engine '{engine}' (scope is enforced per-client)"
            )));
        }
        Some(
            crate::security_hardening::validate_scan_target_in_scope(
                pool,
                tenant_id,
                &ctx.target,
                client_id,
            )
            .await
            .map_err(|detail| RouteError::Forbidden { detail })?,
        )
    } else {
        None
    };

    if let Some(def) = find_route_def(engine) {
        validate_requires(def.requires, &ctx, engine)?;
        check_tenant_entitlement(pool, tenant_id, engine, def.entitlement).await?;

        let oast = if def.inject_oast {
            Some(Uuid::new_v4())
        } else {
            None
        };
        let mut payload = build_payload(def.payload, &ctx, engine)?;
        if let Some(scope) = scope_outcome.as_ref() {
            payload = inject_scope_validation(payload, scope);
        }
        if let Some(t) = oast {
            payload = inject_oast_token(payload, t);
        }
        return Ok((def.job_kind.to_string(), seal_payload_for_queue(payload)));
    }

    // Default: command_center_engine (known engines + extras not in explicit table)
    validate_requires(&[Requires::NonEmptyTarget], &ctx, engine)?;
    let ent = entitlement_for_fallback_engine(engine);
    check_tenant_entitlement(pool, tenant_id, engine, ent).await?;

    let mut payload = build_payload(PayloadKind::CommandCenterDefault, &ctx, engine)?;
    if let Some(scope) = scope_outcome.as_ref() {
        payload = inject_scope_validation(payload, scope);
    }
    Ok((
        "command_center_engine".to_string(),
        seal_payload_for_queue(payload),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn masked_secret_values_are_not_usable() {
        assert!(is_masked_secret_value(&json!("••••••••")));
        assert!(is_masked_secret_value(&json!("••••abcd")));
        assert!(!is_masked_secret_value(&json!("real-token")));
        assert!(!extra_value_usable(&json!("••••••••")));
        assert!(!extra_value_usable(&json!("")));
        assert!(extra_value_usable(&json!("live-value")));
    }

    #[test]
    fn extract_fields_strips_masked_extras() {
        let body = json!({
            "engine": "osint",
            "target": "https://example.com",
            "client_id": 1,
            "github_token": "••••••••",
            "depth": "2"
        });
        let ctx = extract_fields(&body);
        assert_eq!(ctx.target, "https://example.com");
        assert!(ctx.extras.contains_key("depth"));
        assert!(!ctx.extras.contains_key("github_token"));
    }

    #[test]
    fn hydrate_client_skips_masked_overrides() {
        let creds = ClientCredentialSnapshot {
            aws_role_arn: "arn:aws:iam::123:role/scan".into(),
            aws_external_id: "ext-from-db".into(),
            gcp_project_id: String::new(),
            azure_subscription_id: String::new(),
            azure_tenant_id: String::new(),
            ad_domain: String::new(),
            first_repo_url: String::new(),
            ebpf_ssh_host: String::new(),
            ebpf_ssh_user: String::new(),
        };
        let mut extras = std::collections::HashMap::from([
            ("aws_external_id".into(), json!("••••••••")),
            ("aws_role_arn".into(), json!("")),
        ]);
        hydrate_extras_from_client(&mut extras, &creds);
        assert_eq!(
            extras.get("aws_external_id").and_then(Value::as_str),
            Some("ext-from-db")
        );
        assert_eq!(
            extras.get("aws_role_arn").and_then(Value::as_str),
            Some("arn:aws:iam::123:role/scan")
        );
    }

    #[test]
    fn hydrate_tenant_fills_absent_github_token() {
        let secrets = TenantScanSecrets {
            github_token: "ghp_live".into(),
            oast_domain: "oast.example".into(),
            oast_api_key: String::new(),
        };
        let mut extras =
            std::collections::HashMap::from([("github_token".into(), json!("••••••••"))]);
        hydrate_extras_from_tenant(&mut extras, &secrets);
        assert_eq!(
            extras.get("github_token").and_then(Value::as_str),
            Some("ghp_live")
        );
        assert_eq!(
            extras.get("oast_domain").and_then(Value::as_str),
            Some("oast.example")
        );
    }

    #[test]
    fn enforce_scope_validation_exemptions() {
        assert!(!enforce_scope_validation_for_engine("pipeline"));
        assert!(!enforce_scope_validation_for_engine("zero_day_radar"));
        assert!(enforce_scope_validation_for_engine("osint"));
    }

    #[test]
    fn http_feedback_fuzz_routes_to_feedback_fuzz_job() {
        let def = find_route_def("http_feedback_fuzz").expect("http_feedback_fuzz must be routed");
        assert_eq!(def.job_kind, "feedback_fuzz");
        assert!(def.requires.contains(&Requires::ClientId));
        assert!(def.requires.contains(&Requires::NonEmptyTarget));
        assert!(def.inject_oast);
        assert_eq!(def.entitlement, EntitlementTier::AiHeavy);
    }

    #[test]
    fn alias_fuzz_engines_are_not_dedicated_feedback_job() {
        for id in [
            "xss_advanced",
            "csrf_exploit",
            "race_condition_web",
            "open_redirect",
        ] {
            assert!(
                find_route_def(id).is_none(),
                "{id} must stay on command_center_engine (15min) with a campaign wall, not remap to feedback_fuzz"
            );
        }
    }

    #[test]
    fn seal_payload_strips_secrets_before_queue() {
        let raw = json!({
            "engine": "osint",
            "target": "https://example.com",
            "github_token": "ghp_live",
            "depth": "1"
        });
        let sealed = seal_payload_for_queue(raw);
        assert!(sealed.get("github_token").is_none());
        assert_eq!(sealed.get("depth").and_then(Value::as_str), Some("1"));
    }
}
