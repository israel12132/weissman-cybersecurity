//! Natural-language → safe-SQL planner.
//!
//! Pipeline:
//!   1. User asks a question ("show me critical KEV findings on prod assets").
//!   2. LLM is given a STRICT schema + the question, and instructed to emit a
//!      JSON `QueryPlan` (NOT raw SQL). The LLM never writes SQL.
//!   3. We validate the plan against an allow-list:
//!        * `table`     must be in [`ALLOWED_TABLES`]
//!        * every `select` column must be in [`ALLOWED_COLUMNS[table]`]
//!        * every `filter` operator must be in [`ALLOWED_OPS`]
//!        * `order_by` must be an allowed column; `limit` capped at 200
//!   4. The validated plan is compiled to a parameterised SQL string with
//!      bound parameters via sqlx — no string-format of values into SQL.
//!   5. The compiled SQL is executed against `weissman_ro` (read-only role)
//!      with a 15 s `statement_timeout`. Defence in depth: even if validation
//!      slips, the database refuses anything non-SELECT.
//!   6. Result rows are JSON-serialised and returned with the compiled SQL +
//!      the original plan so the UI can show "I ran this SQL → here are the rows".
//!
//! Tenant scoping: every plan is rewritten to include `tenant_id = $tenant`
//! before compilation. Users never see another tenant's data.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::{Column, PgPool, Row};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

/// Bounded Ask Weissman audit lane. try_send so a slow DB never blocks the analyst.
const NL_AUDIT_MPSC_CAPACITY: usize = 1024;

struct NlAuditEvent {
    tenant_id: i64,
    user_id: Option<i64>,
    question: String,
    plan_json: Value,
    sql: String,
    rows_returned: i32,
    elapsed_ms: i32,
    error: String,
}

static NL_AUDIT_TX: OnceLock<mpsc::Sender<NlAuditEvent>> = OnceLock::new();

/// Start the background writer that appends SHA-256-chained `nl_query_audit` rows.
/// Safe to call more than once; later calls are no-ops.
pub fn spawn_audit_worker(pool: Arc<PgPool>) {
    if NL_AUDIT_TX.get().is_some() {
        return;
    }
    let (tx, mut rx) = mpsc::channel::<NlAuditEvent>(NL_AUDIT_MPSC_CAPACITY);
    if NL_AUDIT_TX.set(tx).is_err() {
        return;
    }
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            persist_nl_audit(&pool, ev).await;
        }
    });
}

fn question_fingerprint(question: &str) -> String {
    hex::encode(Sha256::digest(question.as_bytes()))
}

/// SIEM-visible emergency log when the audit MPSC is full or closed.
/// Dropping the DB write must never be silent — that is an audit-tamper signal.
fn report_audit_channel_saturated(ev: &NlAuditEvent, kind: &str) {
    tracing::error!(
        target: "nl_query_audit",
        tenant_id = ev.tenant_id,
        user_id = ev.user_id,
        question_sha256 = %question_fingerprint(&ev.question),
        elapsed_ms = ev.elapsed_ms,
        rows_returned = ev.rows_returned,
        has_error = !ev.error.is_empty(),
        drop_kind = kind,
        "Ask Weissman audit MPSC saturated — event dropped to keep /api/ask hot. Possible audit flood / trace-wiping. SIEM must page."
    );
}

fn try_enqueue_nl_audit(
    tx: &mpsc::Sender<NlAuditEvent>,
    ev: NlAuditEvent,
) -> Result<(), NlAuditEvent> {
    match tx.try_send(ev) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(ev)) => {
            report_audit_channel_saturated(&ev, "full");
            Err(ev)
        }
        Err(TrySendError::Closed(ev)) => {
            report_audit_channel_saturated(&ev, "closed");
            Err(ev)
        }
    }
}

fn enqueue_audit(tenant_id: i64, user_id: Option<i64>, question: &str, res: &AskResult) {
    let ev = NlAuditEvent {
        tenant_id,
        user_id,
        question: question.chars().take(2000).collect(),
        plan_json: serde_json::to_value(&res.plan).unwrap_or(json!({})),
        sql: res.sql.clone(),
        rows_returned: res.row_count as i32,
        elapsed_ms: res.elapsed_ms as i32,
        error: res.error.clone().unwrap_or_default(),
    };
    match NL_AUDIT_TX.get() {
        Some(tx) => {
            let _ = try_enqueue_nl_audit(tx, ev);
        }
        None => {
            tracing::error!(
                target: "nl_query_audit",
                tenant_id,
                question_sha256 = %question_fingerprint(question),
                "Ask Weissman audit worker not started; event not queued"
            );
        }
    }
}

fn nl_audit_canonical(
    prev_hash: &str,
    tenant_id: i64,
    user_id: Option<i64>,
    question: &str,
    sql: &str,
    error: &str,
    asked_at: DateTime<Utc>,
) -> String {
    format!(
        "nlqav1|{prev_hash}|{tenant_id}|{}|{question}|{sql}|{error}|{}",
        user_id.unwrap_or(0),
        asked_at.to_rfc3339()
    )
}

async fn persist_nl_audit(pool: &PgPool, ev: NlAuditEvent) {
    let asked_at = Utc::now();
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, ev.tenant_id).await else {
        tracing::error!(
            target: "nl_query_audit",
            tenant_id = ev.tenant_id,
            "Ask Weissman audit persist: tenant tx failed"
        );
        return;
    };
    if let Err(e) = weissman_db::advisory_lock::advisory_xact_lock_text(
        &mut *tx,
        &format!("nlqa:{}", ev.tenant_id),
    )
    .await
    {
        tracing::error!(
            target: "nl_query_audit",
            tenant_id = ev.tenant_id,
            error = %e,
            "Ask Weissman audit persist: advisory lock failed"
        );
        let _ = tx.rollback().await;
        return;
    }
    let prev_hash: String = sqlx::query_scalar(
        r#"SELECT COALESCE(event_hash, '') FROM nl_query_audit
           WHERE tenant_id = $1 AND event_hash <> ''
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(ev.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    let event_hash = hex::encode(Sha256::digest(
        nl_audit_canonical(
            &prev_hash,
            ev.tenant_id,
            ev.user_id,
            &ev.question,
            &ev.sql,
            &ev.error,
            asked_at,
        )
        .as_bytes(),
    ));
    if let Err(e) = sqlx::query(
        "INSERT INTO nl_query_audit
            (tenant_id, user_id, asked_at, question, plan_json, compiled_sql,
             rows_returned, elapsed_ms, error, prev_hash, event_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(ev.tenant_id)
    .bind(ev.user_id)
    .bind(asked_at)
    .bind(&ev.question)
    .bind(&ev.plan_json)
    .bind(&ev.sql)
    .bind(ev.rows_returned)
    .bind(ev.elapsed_ms)
    .bind(&ev.error)
    .bind(&prev_hash)
    .bind(&event_hash)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(
            target: "nl_query_audit",
            tenant_id = ev.tenant_id,
            error = %e,
            "Ask Weissman audit persist: insert failed"
        );
        let _ = tx.rollback().await;
        return;
    }
    if let Err(e) = tx.commit().await {
        tracing::error!(
            target: "nl_query_audit",
            tenant_id = ev.tenant_id,
            error = %e,
            "Ask Weissman audit persist: commit failed"
        );
    }
}

// ─── Allow-list schema ───────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct TableSpec {
    /// SQL identifier (already known-safe).
    table: &'static str,
    /// Columns the user can SELECT or FILTER on (also safe — fully enumerated).
    columns: &'static [&'static str],
    /// Optional safe ORDER BY columns (defaults to columns).
    order_by: &'static [&'static str],
    /// JOIN clauses we'll add transparently. Keyed by extra table name → ON.
    /// Currently only used to bring `clients.name` into vulnerabilities/etc.
    #[allow(dead_code)]
    joins: &'static [(&'static str, &'static str)],
}

static SCHEMA: LazyLock<HashMap<&'static str, TableSpec>> = LazyLock::new(|| {
    use std::collections::HashMap;
    let mut m: HashMap<&'static str, TableSpec> = HashMap::new();
    m.insert(
        "vulnerabilities",
        TableSpec {
            table: "vulnerabilities",
            columns: &[
                "id",
                "finding_id",
                "title",
                "severity",
                "source",
                "status",
                "client_id",
                "discovered_at",
                "cluster_id",
                "epss_score",
                "epss_percentile",
                "kev_listed",
                "kev_known_ransomware",
                "kev_due_date",
                "seen_count",
                "signature_hash",
                "watermark_severity",
            ],
            order_by: &["discovered_at", "epss_score", "seen_count", "id"],
            joins: &[],
        },
    );
    m.insert(
        "weissman_finding_clusters",
        TableSpec {
            table: "weissman_finding_clusters",
            columns: &[
                "id",
                "client_id",
                "target",
                "cwe",
                "vuln_signature",
                "title",
                "member_count",
                "max_severity",
                "max_cvss",
                "max_epss",
                "kev_listed",
                "status",
                "first_seen_at",
                "last_seen_at",
            ],
            order_by: &["last_seen_at", "max_cvss", "max_epss", "member_count"],
            joins: &[],
        },
    );
    m.insert(
        "clients",
        TableSpec {
            table: "clients",
            columns: &[
                "id",
                "name",
                "default_asset_value_usd",
                "risk_loss_discount",
            ],
            order_by: &["id", "name"],
            joins: &[],
        },
    );
    m.insert(
        "risk_graph_nodes",
        TableSpec {
            table: "risk_graph_nodes",
            columns: &[
                "id",
                "client_id",
                "node_type",
                "label",
                "graph_key",
                "risk_score",
                "is_choke_point",
                "internet_exposed",
                "crown_jewel",
                "asset_value",
                "business_value_usd",
            ],
            order_by: &["risk_score", "business_value_usd", "id"],
            joins: &[],
        },
    );
    m.insert(
        "agent_anomalies",
        TableSpec {
            table: "agent_anomalies",
            columns: &[
                "id",
                "agent_id",
                "client_id",
                "metric_name",
                "observed",
                "baseline_mean",
                "baseline_stddev",
                "z_score",
                "severity",
                "detail",
                "detected_at",
            ],
            order_by: &["detected_at", "z_score"],
            joins: &[],
        },
    );
    m.insert(
        "attack_path_snapshots",
        TableSpec {
            table: "attack_path_snapshots",
            columns: &[
                "id",
                "client_id",
                "computed_at",
                "entry_count",
                "jewel_count",
                "path_count",
                "max_risk",
            ],
            order_by: &["computed_at", "max_risk"],
            joins: &[],
        },
    );
    m
});

const ALLOWED_OPS: &[&str] = &[
    "=",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "in",
    "like",
    "is_null",
    "is_not_null",
];
const MAX_LIMIT: i64 = 200;

// ─── Plan structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QueryPlan {
    pub table: String,
    #[serde(default)]
    pub select: Vec<String>,
    #[serde(default)]
    pub filters: Vec<Filter>,
    #[serde(default)]
    pub order_by: Option<String>,
    #[serde(default)]
    pub order_desc: bool,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Filter {
    pub column: String,
    pub op: String,
    #[serde(default)]
    pub value: Value,
}

// ─── Plan → safe SQL ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Compiled {
    pub sql: String,
    pub params: Vec<Value>,
}

pub fn compile_plan(plan: &QueryPlan, tenant_id: i64) -> Result<Compiled, String> {
    // 1) Validate table.
    let spec = SCHEMA
        .get(plan.table.as_str())
        .ok_or_else(|| format!("table '{}' is not exposed to NL queries", plan.table))?;

    // 2) Validate SELECT columns (default to spec.columns if empty).
    let select_cols: Vec<&str> = if plan.select.is_empty() {
        spec.columns.iter().copied().collect()
    } else {
        let mut out = Vec::with_capacity(plan.select.len());
        for c in &plan.select {
            if !spec.columns.contains(&c.as_str()) {
                return Err(format!(
                    "column '{}' not allowed on table '{}'",
                    c, spec.table
                ));
            }
            out.push(c.as_str());
        }
        out
    };

    // 3) Validate ORDER BY (optional).
    let order = match &plan.order_by {
        Some(c) => {
            let allowed: &[&str] = if spec.order_by.is_empty() {
                spec.columns
            } else {
                spec.order_by
            };
            if !allowed.contains(&c.as_str()) {
                return Err(format!("order_by '{}' not allowed on '{}'", c, spec.table));
            }
            Some(c.as_str())
        }
        None => None,
    };

    // 4) Validate LIMIT (cap at MAX_LIMIT).
    let limit = plan.limit.unwrap_or(50).clamp(1, MAX_LIMIT);

    // 5) Build SQL fragments.
    let select_sql = select_cols.join(", ");
    let mut where_parts: Vec<String> = Vec::new();
    let mut params: Vec<Value> = Vec::new();

    // Tenant scope is FORCED — non-negotiable. $1 always = tenant_id.
    where_parts.push("tenant_id = $1".to_string());
    params.push(Value::from(tenant_id));

    // Filters.
    for f in &plan.filters {
        if !spec.columns.contains(&f.column.as_str()) {
            return Err(format!("filter column '{}' not allowed", f.column));
        }
        let op_norm = f.op.trim().to_ascii_lowercase();
        if !ALLOWED_OPS.contains(&op_norm.as_str()) {
            return Err(format!("operator '{}' not allowed", f.op));
        }
        match op_norm.as_str() {
            "is_null" => {
                where_parts.push(format!("{} IS NULL", f.column));
            }
            "is_not_null" => {
                where_parts.push(format!("{} IS NOT NULL", f.column));
            }
            "in" => {
                // value must be array.
                let arr = f
                    .value
                    .as_array()
                    .ok_or_else(|| "IN value must be array".to_string())?;
                if arr.is_empty() {
                    return Err("IN value array is empty".to_string());
                }
                let mut placeholders = Vec::new();
                for v in arr {
                    params.push(v.clone());
                    placeholders.push(format!("${}", params.len()));
                }
                where_parts.push(format!("{} IN ({})", f.column, placeholders.join(", ")));
            }
            "like" => {
                let s = f
                    .value
                    .as_str()
                    .ok_or_else(|| "LIKE value must be string".to_string())?;
                // Wrap in % unless the user already supplied them.
                let pattern = if s.contains('%') {
                    s.to_string()
                } else {
                    format!("%{}%", s)
                };
                params.push(Value::String(pattern));
                where_parts.push(format!("{} ILIKE ${}", f.column, params.len()));
            }
            sql_op @ ("=" | "!=" | "<" | "<=" | ">" | ">=") => {
                params.push(f.value.clone());
                where_parts.push(format!("{} {} ${}", f.column, sql_op, params.len()));
            }
            // Self-defending: if a new operator is ever added to ALLOWED_OPS without a match arm
            // here, reject the query instead of panicking the request.
            other => return Err(format!("unsupported query operator '{other}'")),
        }
    }

    let order_sql = match order {
        Some(c) => format!(
            " ORDER BY {} {}",
            c,
            if plan.order_desc { "DESC" } else { "ASC" }
        ),
        None => String::new(),
    };
    let sql = format!(
        "SELECT {} FROM {} WHERE {}{} LIMIT {}",
        select_sql,
        spec.table,
        where_parts.join(" AND "),
        order_sql,
        limit,
    );
    Ok(Compiled { sql, params })
}

// ─── Execution against the read-only pool ────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AskResult {
    pub plan: QueryPlan,
    pub sql: String,
    pub rows: Vec<Value>,
    pub row_count: usize,
    pub elapsed_ms: i64,
    pub error: Option<String>,
}

/// Execute a validated plan. We bind every parameter explicitly through sqlx;
/// the underlying connection is a read-only role with a 15 s statement timeout.
pub async fn execute_plan(
    ro_pool: &PgPool,
    tenant_id: i64,
    plan: QueryPlan,
) -> Result<AskResult, String> {
    let start = Instant::now();
    let compiled = compile_plan(&plan, tenant_id)?;

    // Set the per-statement RLS GUC so policies see our tenant. set_config(..., true) is
    // transaction-local, so the SELECT MUST run inside the SAME transaction: on a bare pooled
    // connection every statement autocommits, which would discard the GUC before the query and
    // collapse RLS to the database default tenant (0) — returning zero rows for every real tenant.
    let mut tx = ro_pool.begin().await.map_err(|e| format!("begin: {e}"))?;
    sqlx::query("SELECT set_config('app.current_tenant_id', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("set tenant guc: {e}"))?;

    let mut q = sqlx::query(&compiled.sql);
    for p in &compiled.params {
        q = bind_json(q, p);
    }
    let rows = q
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("execute: {e}"))?;
    // Read-only plan — commit simply releases the connection (no writes were made).
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    let elapsed_ms = start.elapsed().as_millis() as i64;

    let json_rows: Vec<Value> = rows.iter().map(row_to_json).collect();
    Ok(AskResult {
        plan,
        sql: compiled.sql,
        row_count: json_rows.len(),
        rows: json_rows,
        elapsed_ms,
        error: None,
    })
}

/// Run a free-form question end-to-end: LLM → plan → validate → execute.
pub async fn ask(
    _app_pool: &PgPool,
    ro_pool: &PgPool,
    tenant_id: i64,
    user_id: Option<i64>,
    question: &str,
) -> AskResult {
    let start = Instant::now();
    let bad = |err: &str| AskResult {
        plan: QueryPlan {
            table: String::new(),
            select: vec![],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: None,
        },
        sql: String::new(),
        rows: vec![],
        row_count: 0,
        elapsed_ms: start.elapsed().as_millis() as i64,
        error: Some(err.to_string()),
    };
    let q = question.trim();
    if q.is_empty() {
        return bad("question is empty");
    }
    if q.len() > 2000 {
        return bad("question too long (max 2000 chars)");
    }

    // 1) LLM → plan JSON.
    let plan_json = match llm_to_plan(q, tenant_id).await {
        Ok(v) => v,
        Err(e) => {
            let r = bad(&format!("plan generation failed: {e}"));
            enqueue_audit(tenant_id, user_id, question, &r);
            return r;
        }
    };
    let plan: QueryPlan = match serde_json::from_value(plan_json.clone()) {
        Ok(p) => p,
        Err(e) => {
            let r = bad(&format!("plan is not a valid QueryPlan JSON: {e}"));
            enqueue_audit(tenant_id, user_id, question, &r);
            return r;
        }
    };

    // 2) Validate + execute.
    let res = match execute_plan(ro_pool, tenant_id, plan.clone()).await {
        Ok(mut r) => {
            r.elapsed_ms = start.elapsed().as_millis() as i64;
            r
        }
        Err(e) => bad(&e),
    };

    enqueue_audit(tenant_id, user_id, question, &res);
    res
}

fn bind_json<'a>(
    q: sqlx::query::Query<'a, sqlx::Postgres, sqlx::postgres::PgArguments>,
    v: &'a Value,
) -> sqlx::query::Query<'a, sqlx::Postgres, sqlx::postgres::PgArguments> {
    match v {
        Value::Null => q.bind(Option::<String>::None),
        Value::Bool(b) => q.bind(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                q.bind(i)
            } else if let Some(f) = n.as_f64() {
                q.bind(f)
            } else {
                q.bind(n.to_string())
            }
        }
        Value::String(s) => q.bind(s.clone()),
        other => q.bind(other.to_string()),
    }
}

fn row_to_json(row: &sqlx::postgres::PgRow) -> Value {
    let mut obj = Map::new();
    for (i, col) in row.columns().iter().enumerate() {
        let name = col.name().to_string();
        // Try the most common types in order; fall back to text/null.
        let val: Value = if let Ok(v) = row.try_get::<i64, _>(i) {
            Value::from(v)
        } else if let Ok(v) = row.try_get::<i32, _>(i) {
            Value::from(v)
        } else if let Ok(v) = row.try_get::<f64, _>(i) {
            Value::from(v)
        } else if let Ok(v) = row.try_get::<f32, _>(i) {
            Value::from(v as f64)
        } else if let Ok(v) = row.try_get::<bool, _>(i) {
            Value::from(v)
        } else if let Ok(v) = row.try_get::<String, _>(i) {
            Value::String(v)
        } else if let Ok(v) = row.try_get::<chrono::DateTime<chrono::Utc>, _>(i) {
            Value::String(v.to_rfc3339())
        } else if let Ok(v) = row.try_get::<chrono::NaiveDate, _>(i) {
            Value::String(v.to_string())
        } else {
            Value::Null
        };
        obj.insert(name, val);
    }
    Value::Object(obj)
}

// ─── LLM call (OpenAI / vLLM / Ollama compatible) ────────────────────────────

const PLANNER_PROMPT: &str = r#"You are the Weissman NL-to-Plan planner. Convert the user's question into a JSON QueryPlan.

You MUST output a single JSON object — nothing else (no ```json fences, no prose).

Schema:
{
  "table":     "<one of vulnerabilities|weissman_finding_clusters|clients|risk_graph_nodes|agent_anomalies|attack_path_snapshots>",
  "select":    ["col1","col2", ...]           // optional; default = all columns
  "filters":   [
     {"column":"severity","op":"in","value":["critical","high"]},
     {"column":"kev_listed","op":"=","value":true},
     {"column":"discovered_at","op":">","value":"2026-01-01"}
  ],
  "order_by":  "discovered_at",                // optional
  "order_desc": true,                          // optional, default false
  "limit":     50                              // optional, max 200
}

Operators allowed: =, !=, <, <=, >, >=, in, like, is_null, is_not_null.
Tables and columns are case-sensitive. Use only the schema below.

Schema:
- vulnerabilities(id, finding_id, title, severity, source, status, client_id, discovered_at, cluster_id, epss_score, epss_percentile, kev_listed, kev_known_ransomware, kev_due_date, seen_count, signature_hash)
- weissman_finding_clusters(id, client_id, target, cwe, vuln_signature, title, member_count, max_severity, max_cvss, max_epss, kev_listed, status, first_seen_at, last_seen_at)
- clients(id, name, default_asset_value_usd, risk_loss_discount)
- risk_graph_nodes(id, client_id, node_type, label, graph_key, risk_score, is_choke_point, internet_exposed, crown_jewel, asset_value, business_value_usd)
- agent_anomalies(id, agent_id, client_id, metric_name, observed, baseline_mean, baseline_stddev, z_score, severity, detail, detected_at)
- attack_path_snapshots(id, client_id, computed_at, entry_count, jewel_count, path_count, max_risk)

If you cannot map the question to a valid plan, output {"table":"","select":[],"filters":[]}.
"#;

async fn llm_to_plan(question: &str, tenant_id: i64) -> Result<Value, String> {
    // Ask Weissman planner. Routes through the multi-provider failover chain
    // (`weissman_engines::llm_router`, configured by WEISSMAN_LLM_ENDPOINTS) so the planner now
    // inherits per-endpoint retry, circuit breaking, cross-provider failover, and per-tenant LLM
    // usage metering — none of which the previous hand-rolled HTTP call had. With no chain set it
    // resolves to the same single default endpoint (local-first "sovereign" vLLM), so on-box
    // behavior is unchanged. Strict-JSON mode keeps the plan parseable; the question is untrusted
    // user input, so it is sanitized. WEISSMAN_NL_QUERY_MODEL still selects a dedicated planner
    // model (applied to any endpoint that does not name its own).
    let model_override = std::env::var("WEISSMAN_NL_QUERY_MODEL")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let max_tokens: u32 = std::env::var("WEISSMAN_NL_QUERY_MAX_TOKENS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024)
        .clamp(256, 8192);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let text = weissman_engines::llm_router::routed_chat_completion_text_json_object(
        &client,
        Some(PLANNER_PROMPT),
        question,
        0.0,
        max_tokens,
        Some(tenant_id),
        "nl_query_plan",
        true,
        model_override.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())?;
    serde_json::from_str::<Value>(text.trim()).map_err(|e| format!("invalid JSON from LLM: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_simple_severity_in() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into(), "title".into(), "severity".into()],
            filters: vec![Filter {
                column: "severity".into(),
                op: "in".into(),
                value: json!(["critical", "high"]),
            }],
            order_by: Some("discovered_at".into()),
            order_desc: true,
            limit: Some(50),
        };
        let c = compile_plan(&plan, 1).unwrap();
        // Tenant scope ALWAYS first param.
        assert_eq!(c.params[0], Value::from(1));
        assert!(c
            .sql
            .starts_with("SELECT id, title, severity FROM vulnerabilities WHERE tenant_id = $1"));
        assert!(c.sql.contains("severity IN ($2, $3)"));
        assert!(c.sql.contains("ORDER BY discovered_at DESC"));
        assert!(c.sql.ends_with("LIMIT 50"));
    }

    #[test]
    fn rejects_unknown_table() {
        let plan = QueryPlan {
            table: "users".into(),
            select: vec![],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: None,
        };
        let err = compile_plan(&plan, 1).unwrap_err();
        assert!(err.contains("not exposed"));
    }

    #[test]
    fn rejects_unknown_column() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["password_hash".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: None,
        };
        let err = compile_plan(&plan, 1).unwrap_err();
        assert!(err.contains("not allowed"));
    }

    #[test]
    fn rejects_bad_operator() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![Filter {
                column: "severity".into(),
                op: "DROP TABLE".into(),
                value: json!("critical"),
            }],
            order_by: None,
            order_desc: false,
            limit: None,
        };
        let err = compile_plan(&plan, 1).unwrap_err();
        assert!(err.contains("operator"));
    }

    #[test]
    fn caps_limit_at_max() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: Some(99_999),
        };
        let c = compile_plan(&plan, 1).unwrap();
        assert!(c.sql.ends_with(&format!("LIMIT {}", MAX_LIMIT)));
    }

    #[test]
    fn mpsc_full_is_detected_and_try_enqueue_returns_err() {
        let (tx, _rx) = mpsc::channel::<NlAuditEvent>(1);
        let ev = || NlAuditEvent {
            tenant_id: 1,
            user_id: Some(9),
            question: "show critical kev".into(),
            plan_json: json!({}),
            sql: "SELECT 1".into(),
            rows_returned: 0,
            elapsed_ms: 3,
            error: String::new(),
        };
        assert!(try_enqueue_nl_audit(&tx, ev()).is_ok());
        assert!(
            try_enqueue_nl_audit(&tx, ev()).is_err(),
            "second try_send on capacity-1 must be Full"
        );
    }

    #[test]
    fn nl_audit_canonical_is_stable() {
        let ts = DateTime::parse_from_rfc3339("2026-08-28T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let a = nl_audit_canonical("prev", 7, Some(1), "q", "sql", "", ts);
        let b = nl_audit_canonical("prev", 7, Some(1), "q", "sql", "", ts);
        assert_eq!(a, b);
        assert!(a.starts_with("nlqav1|"));
        assert_ne!(
            a,
            nl_audit_canonical("other", 7, Some(1), "q", "sql", "", ts)
        );
    }
}
