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

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::{Column, PgPool, Row};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Instant;
use tokio::sync::{mpsc, Semaphore};

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
    /// Feed/intel tables have no tenant_id; RLS still applies via GRANTs + GUC.
    has_tenant: bool,
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
            ],
            order_by: &["discovered_at", "epss_score", "seen_count", "id"],
            joins: &[],
            has_tenant: true,
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
            has_tenant: true,
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
            has_tenant: true,
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
            has_tenant: true,
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
            has_tenant: true,
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
            has_tenant: true,
        },
    );
    m.insert(
        "risk_graph_edges",
        TableSpec {
            table: "risk_graph_edges",
            columns: &["id", "client_id", "from_node_id", "to_node_id", "edge_type"],
            order_by: &["id", "edge_type"],
            joins: &[],
            has_tenant: true,
        },
    );
    m.insert(
        "client_financial_risk_snapshots",
        TableSpec {
            table: "client_financial_risk_snapshots",
            columns: &[
                "id",
                "client_id",
                "computed_at",
                "total_asset_value_usd",
                "sle_worst_usd",
                "ale_annualised_usd",
                "crown_jewel_value_usd",
                "currency_code",
            ],
            order_by: &["computed_at", "ale_annualised_usd", "id"],
            joins: &[],
            has_tenant: true,
        },
    );
    m.insert(
        "endpoint_agents",
        TableSpec {
            table: "endpoint_agents",
            columns: &[
                "id",
                "client_id",
                "hostname",
                "os",
                "agent_version",
                "status",
                "last_seen_at",
            ],
            order_by: &["last_seen_at", "id"],
            joins: &[],
            has_tenant: true,
        },
    );
    m.insert(
        "weissman_async_jobs",
        TableSpec {
            table: "weissman_async_jobs",
            columns: &["id", "kind", "status", "created_at", "updated_at"],
            order_by: &["created_at", "updated_at"],
            joins: &[],
            has_tenant: true,
        },
    );
    m.insert(
        "epss_intel",
        TableSpec {
            table: "epss_intel",
            columns: &["cve", "score", "percentile", "epss_date", "refreshed_at"],
            order_by: &["score", "refreshed_at", "cve"],
            joins: &[],
            has_tenant: false,
        },
    );
    m.insert(
        "kev_intel",
        TableSpec {
            table: "kev_intel",
            columns: &[
                "cve",
                "vendor_project",
                "product",
                "date_added",
                "known_ransomware_use",
                "due_date",
            ],
            order_by: &["date_added", "cve"],
            joins: &[],
            has_tenant: false,
        },
    );
    m.insert(
        "audit_logs",
        TableSpec {
            table: "audit_logs",
            columns: &[
                "id",
                "created_at",
                "user_label",
                "action_type",
                "details",
                "ip_address",
            ],
            order_by: &["created_at", "id"],
            joins: &[],
            has_tenant: true,
        },
    );
    m
});

/// Spec §10: Ask Weissman allow-list is 13 tables.
pub fn allowed_table_count() -> usize {
    SCHEMA.len()
}

/// Hermetic QueryPlan sandbox: table must be one of the 13 weissman_ro names.
#[must_use]
pub fn is_allowlisted_table(name: &str) -> bool {
    SCHEMA.contains_key(name)
}

/// Sorted allow-list names for AST table extraction (never a parallel hand list).
#[must_use]
pub fn allowlisted_table_names() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = SCHEMA.keys().copied().collect();
    v.sort_unstable();
    v
}

/// Hermetic QueryPlan sandbox: column must be enumerated on that table.
#[must_use]
pub fn is_allowlisted_column(table: &str, column: &str) -> bool {
    SCHEMA
        .get(table)
        .is_some_and(|s| s.columns.contains(&column))
}

/// Hermetic QueryPlan sandbox: filter operator must be in the static op list.
#[must_use]
pub fn is_allowlisted_op(op: &str) -> bool {
    ALLOWED_OPS.contains(&op)
}

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
const ALLOWED_AGGREGATES: &[&str] = &["count", "avg", "sum", "min", "max"];

/// Postgres-side defence: wrap a compiled plan so a slipped LIMIT cannot
/// return more than [`MAX_LIMIT`] rows even if the inner SQL is wrong.
#[must_use]
pub fn wrap_nl_sql(inner: &str) -> String {
    format!("SELECT * FROM ({inner}) AS weissman_nl_q LIMIT {MAX_LIMIT}")
}

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
    /// Allow-listed aggregate: `count` / `avg` / `sum` / `min` / `max`.
    /// `count` may omit `aggregate_column` (COUNT(*)).
    #[serde(default)]
    pub aggregate: Option<String>,
    #[serde(default)]
    pub aggregate_column: Option<String>,
    #[serde(default)]
    pub group_by: Option<String>,
}

impl Default for QueryPlan {
    fn default() -> Self {
        Self {
            table: String::new(),
            select: vec![],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: None,
            aggregate: None,
            aggregate_column: None,
            group_by: None,
        }
    }
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

    let agg = plan
        .aggregate
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|s| !s.is_empty());
    if let Some(ref fn_name) = agg {
        if !ALLOWED_AGGREGATES.contains(&fn_name.as_str()) {
            return Err(format!("aggregate '{fn_name}' is not allowed"));
        }
        if fn_name != "count" {
            let col = plan
                .aggregate_column
                .as_deref()
                .ok_or_else(|| format!("aggregate '{fn_name}' requires aggregate_column"))?;
            if !spec.columns.contains(&col) {
                return Err(format!("aggregate column '{col}' not allowed"));
            }
        } else if let Some(col) = plan.aggregate_column.as_deref() {
            if !col.is_empty() && !spec.columns.contains(&col) {
                return Err(format!("aggregate column '{col}' not allowed"));
            }
        }
        if let Some(g) = plan.group_by.as_deref() {
            if !spec.columns.contains(&g) {
                return Err(format!("group_by '{g}' not allowed"));
            }
        }
    }

    // 2) Validate SELECT columns (default to spec.columns if empty).
    let select_cols: Vec<&str> = if agg.is_some() {
        Vec::new()
    } else if plan.select.is_empty() {
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

    // 4) Validate LIMIT after filters so operator errors surface first.
    // 5) Build SQL fragments.
    let select_sql = select_cols.join(", ");
    let mut where_parts: Vec<String> = Vec::new();
    let mut params: Vec<Value> = Vec::new();

    // Tenant scope is FORCED on tenant-keyed tables — non-negotiable.
    if spec.has_tenant {
        where_parts.push("tenant_id = $1".to_string());
        params.push(Value::from(tenant_id));
    }

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

    let limit = crate::elite_hardening::nl_guard::require_limit(plan.limit, MAX_LIMIT)?;

    let order_sql = match order {
        Some(c) if agg.is_none() => format!(
            " ORDER BY {} {}",
            c,
            if plan.order_desc { "DESC" } else { "ASC" }
        ),
        _ => String::new(),
    };
    let where_sql = if where_parts.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_parts.join(" AND "))
    };
    let sql = if let Some(fn_name) = agg {
        let agg_sql = match fn_name.as_str() {
            "count" => match plan.aggregate_column.as_deref().filter(|c| !c.is_empty()) {
                Some(c) => format!("COUNT({c}) AS value"),
                None => "COUNT(*) AS value".to_string(),
            },
            other => {
                let c = plan.aggregate_column.as_deref().unwrap_or("id");
                format!("{}({c}) AS value", other.to_ascii_uppercase())
            }
        };
        let (select_head, group_sql) = match plan.group_by.as_deref() {
            Some(g) => (format!("{g}, {agg_sql}"), format!(" GROUP BY {g}")),
            None => (agg_sql, String::new()),
        };
        format!(
            "SELECT {select_head} FROM {}{where_sql}{group_sql} LIMIT {limit}",
            spec.table
        )
    } else {
        format!(
            "SELECT {} FROM {}{}{} LIMIT {}",
            select_sql, spec.table, where_sql, order_sql, limit,
        )
    };
    crate::elite_hardening::nl_guard::reject_unsafe_sql(&sql)?;
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

    let wrapped = wrap_nl_sql(&compiled.sql);
    let mut q = sqlx::query(&wrapped);
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
        sql: wrapped,
        row_count: json_rows.len(),
        rows: json_rows,
        elapsed_ms,
        error: None,
    })
}

/// Run a free-form question end-to-end: LLM → plan → validate → execute.
pub async fn ask(
    app_pool: &PgPool,
    ro_pool: &PgPool,
    tenant_id: i64,
    user_id: Option<i64>,
    question: &str,
) -> AskResult {
    let start = Instant::now();
    let bad = |err: &str| AskResult {
        plan: QueryPlan::default(),
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
    if crate::elite_hardening::ai_supply::prompt_contains_secret(q) {
        return bad("fail-closed: question contains secret material");
    }
    if q.len() > 2000 {
        return bad("question too long (max 2000 chars)");
    }

    match crate::nl_audit_chain::ask_path_is_locked(app_pool, tenant_id).await {
        Ok(true) => {
            return bad(
                "Ask Weissman is fail-closed: audit-chain epoch cap (SOC alert nl_audit_epoch_fragmentation)",
            );
        }
        Ok(false) => {}
        Err(e) => {
            tracing::error!(target: "nl_query", error = %e, "ask fail-closed lock check failed");
            return bad("Ask Weissman is fail-closed: audit chain lock unavailable");
        }
    }

    // 1) LLM → plan JSON.
    let plan_json = match llm_to_plan(q, tenant_id).await {
        Ok(v) => v,
        Err(e) => {
            let r = bad(&format!("plan generation failed: {e}"));
            audit_query(app_pool, tenant_id, user_id, question, &r);
            return r;
        }
    };
    let plan: QueryPlan = match serde_json::from_value(plan_json.clone()) {
        Ok(p) => p,
        Err(e) => {
            let r = bad(&format!("plan is not a valid QueryPlan JSON: {e}"));
            audit_query(app_pool, tenant_id, user_id, question, &r);
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

    audit_query(app_pool, tenant_id, user_id, question, &res);
    res
}

struct NlqaEvent {
    tenant_id: i64,
    user_id: Option<i64>,
    question: String,
    plan_json: Value,
    compiled_sql: String,
    rows_returned: i32,
    elapsed_ms: i32,
    error: String,
}

const NLQA_CHANNEL_CAP: usize = 1024;
static NLQA_TX: OnceLock<mpsc::Sender<NlqaEvent>> = OnceLock::new();
static NLQA_GLOBAL_PERSIST: OnceLock<Arc<Semaphore>> = OnceLock::new();
static NLQA_TENANT_PERSIST: OnceLock<DashMap<i64, Arc<Semaphore>>> = OnceLock::new();

fn nlqa_global_persist() -> Arc<Semaphore> {
    NLQA_GLOBAL_PERSIST
        .get_or_init(|| {
            Arc::new(Semaphore::new(
                crate::elite_hardening::nlqa_chain::NLQA_GLOBAL_PERSIST_PERMITS,
            ))
        })
        .clone()
}

fn nlqa_tenant_persist(tenant_id: i64) -> Arc<Semaphore> {
    NLQA_TENANT_PERSIST
        .get_or_init(DashMap::new)
        .entry(tenant_id)
        .or_insert_with(|| {
            Arc::new(Semaphore::new(
                crate::elite_hardening::nlqa_chain::NLQA_TENANT_PERSIST_PERMITS,
            ))
        })
        .clone()
}

/// Start the per-process nlqa1 hash-chain worker. Ask never waits on this lock.
pub fn spawn_audit_worker(pool: Arc<PgPool>) {
    crate::nlqa_syslog::init();
    let (tx, rx) = mpsc::channel::<NlqaEvent>(NLQA_CHANNEL_CAP);
    if NLQA_TX.set(tx).is_ok() {
        tokio::spawn(nlqa_worker_loop(pool, rx));
        tracing::info!(target: "nlqa1", "Ask audit hash-chain worker started");
    }
}

fn audit_query(
    app_pool: &PgPool,
    tenant_id: i64,
    user_id: Option<i64>,
    question: &str,
    res: &AskResult,
) {
    if NLQA_TX.get().is_none() {
        spawn_audit_worker(Arc::new(app_pool.clone()));
    }
    let ev = NlqaEvent {
        tenant_id,
        user_id,
        question: question.chars().take(2000).collect(),
        plan_json: serde_json::to_value(&res.plan).unwrap_or(json!({})),
        compiled_sql: res.sql.clone(),
        rows_returned: res.row_count as i32,
        elapsed_ms: res.elapsed_ms as i32,
        error: res.error.clone().unwrap_or_default(),
    };
    match NLQA_TX.get() {
        Some(tx) => {
            if let Err(e) = tx.try_send(ev) {
                let (ev, reason) = match e {
                    mpsc::error::TrySendError::Full(ev) => (ev, "channel_full"),
                    mpsc::error::TrySendError::Closed(ev) => (ev, "channel_closed"),
                };
                emit_nlqa_fallback(&ev, reason);
            }
        }
        None => {
            emit_nlqa_fallback(&ev, "worker_not_running");
        }
    }
}

fn emit_nlqa_fallback(ev: &NlqaEvent, reason: &str) {
    let payload = crate::elite_hardening::nlqa_chain::fallback_audit_json(
        ev.tenant_id,
        ev.user_id,
        &ev.question,
        &ev.plan_json,
        &ev.compiled_sql,
        ev.rows_returned,
        ev.elapsed_ms,
        &ev.error,
        reason,
    );
    crate::elite_hardening::nlqa_chain::emit_ask_audit_fallback(&payload, reason);
    let qfp = hex::encode(Sha256::digest(ev.question.as_bytes()));
    let q_preview: String = ev.question.chars().take(180).collect();
    crate::nlqa_syslog::page_audit_overflow(&format!(
        "nlqa1 Ask Weissman audit MPSC saturated kind={reason} tenant_id={} user_id={} question_sha256={qfp} elapsed_ms={} rows_returned={} has_error={} question_preview={q_preview}",
        ev.tenant_id,
        ev.user_id.unwrap_or(0),
        ev.elapsed_ms,
        ev.rows_returned,
        !ev.error.is_empty(),
    ));
}

async fn nlqa_worker_loop(pool: Arc<PgPool>, mut rx: mpsc::Receiver<NlqaEvent>) {
    while let Some(ev) = rx.recv().await {
        let pool = pool.clone();
        tokio::spawn(async move {
            persist_nlqa_isolated(pool, ev).await;
        });
    }
}

/// Isolate advisory-lock waits: at most 4 persists process-wide and 1 per
/// tenant. Waiters are async tasks (not OS threads), so a flooded tenant cannot
/// starve the Tokio pool used by UEBA / SOAR / scans. Ask still never blocks.
async fn persist_nlqa_isolated(pool: Arc<PgPool>, ev: NlqaEvent) {
    let global = nlqa_global_persist();
    let Ok(_global_permit) = global.acquire_owned().await else {
        emit_nlqa_fallback(&ev, "persist_pool_closed");
        return;
    };
    let tenant = nlqa_tenant_persist(ev.tenant_id);
    let Ok(_tenant_permit) = tenant.acquire_owned().await else {
        emit_nlqa_fallback(&ev, "tenant_lock_closed");
        return;
    };
    if let Err(e) = persist_nlqa_chained(&pool, &ev).await {
        tracing::error!(target: "nlqa1", error = %e, "Ask audit chain append failed");
        emit_nlqa_fallback(&ev, "persist_failed");
    }
}

async fn persist_nlqa_chained(pool: &PgPool, ev: &NlqaEvent) -> Result<(), String> {
    // HTTP/Ask never waits on FOR UPDATE. Insert a sealed unchained row; the
    // `nl_audit_chain` worker stamps prev/event hash + chain_epoch (epoch cap).
    let mut tx = crate::db::begin_tenant_tx(pool, ev.tenant_id)
        .await
        .map_err(|e| format!("nlqa1 tenant tx: {e}"))?;
    let sealed_q = crate::nl_audit_crypto::seal_text(&ev.question);
    let sealed_sql = crate::nl_audit_crypto::seal_text(&ev.compiled_sql);
    let sealed_plan = crate::nl_audit_crypto::seal_plan(&ev.plan_json);
    sqlx::query(
        "INSERT INTO nl_query_audit
            (tenant_id, user_id, asked_at, question, plan_json, compiled_sql,
             rows_returned, elapsed_ms, error, prev_hash, event_hash)
         VALUES ($1, $2, now(), $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(ev.tenant_id)
    .bind(ev.user_id)
    .bind(&sealed_q)
    .bind(&sealed_plan)
    .bind(&sealed_sql)
    .bind(ev.rows_returned)
    .bind(ev.elapsed_ms)
    .bind(&ev.error)
    .bind(crate::nl_audit_chain::UNCHAINED)
    .bind(crate::nl_audit_chain::UNCHAINED)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("nlqa1 insert: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("nlqa1 commit: {e}"))?;
    crate::nl_audit_chain::notify(ev.tenant_id);
    Ok(())
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
  "table":     "<one of vulnerabilities|weissman_finding_clusters|clients|risk_graph_nodes|agent_anomalies|attack_path_snapshots|risk_graph_edges|client_financial_risk_snapshots|endpoint_agents|weissman_async_jobs|epss_intel|kev_intel|audit_logs>",
  "select":    ["col1","col2", ...]           // optional; default = all columns
  "filters":   [
     {"column":"severity","op":"in","value":["critical","high"]},
     {"column":"kev_listed","op":"=","value":true},
     {"column":"discovered_at","op":">","value":"2026-01-01"}
  ],
  "order_by":  "discovered_at",                // optional
  "order_desc": true,                          // optional, default false
  "limit":     50,                             // REQUIRED integer 1-200 (fail-closed)
  "aggregate": "count",                        // optional: count|avg|sum|min|max
  "aggregate_column": "id",                    // optional; omit for COUNT(*)
  "group_by":  "severity"                      // optional allow-listed column
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
- risk_graph_edges(id, client_id, from_node_id, to_node_id, edge_type)
- client_financial_risk_snapshots(id, client_id, computed_at, total_asset_value_usd, sle_worst_usd, ale_annualised_usd, crown_jewel_value_usd, currency_code)
- endpoint_agents(id, client_id, hostname, os, agent_version, status, last_seen_at)
- weissman_async_jobs(id, kind, status, created_at, updated_at)
- epss_intel(cve, score, percentile, epss_date, refreshed_at)
- kev_intel(cve, vendor_project, product, date_added, known_ransomware_use, due_date)
- audit_logs(id, created_at, user_label, action_type, details, ip_address)

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
            aggregate: None,
            aggregate_column: None,
            group_by: None,
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
            aggregate: None,
            aggregate_column: None,
            group_by: None,
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
            aggregate: None,
            aggregate_column: None,
            group_by: None,
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
            aggregate: None,
            aggregate_column: None,
            group_by: None,
        };
        let err = compile_plan(&plan, 1).unwrap_err();
        assert!(err.contains("operator"));
    }

    #[test]
    fn allowlist_is_thirteen_tables() {
        assert_eq!(allowed_table_count(), 13);
        assert_eq!(
            allowed_table_count(),
            crate::elite_hardening::nl_guard::ASK_WEISSMAN_TABLE_COUNT
        );
    }

    #[test]
    fn rejects_missing_limit() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: None,
            aggregate: None,
            aggregate_column: None,
            group_by: None,
        };
        let err = compile_plan(&plan, 1).unwrap_err();
        assert!(err.contains("limit"));
    }

    #[test]
    fn intel_tables_skip_tenant_predicate() {
        let plan = QueryPlan {
            table: "epss_intel".into(),
            select: vec!["cve".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: Some(10),
            aggregate: None,
            aggregate_column: None,
            group_by: None,
        };
        let c = compile_plan(&plan, 1).unwrap();
        assert!(!c.sql.contains("tenant_id"));
        assert!(c.sql.contains("LIMIT 10"));
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
            aggregate: None,
            aggregate_column: None,
            group_by: None,
        };
        let c = compile_plan(&plan, 1).unwrap();
        assert!(c.sql.ends_with(&format!("LIMIT {}", MAX_LIMIT)));
    }

    #[test]
    fn compile_count_star() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec![],
            filters: vec![Filter {
                column: "severity".into(),
                op: "=".into(),
                value: json!("critical"),
            }],
            order_by: None,
            order_desc: false,
            limit: Some(1),
            aggregate: Some("count".into()),
            aggregate_column: None,
            group_by: None,
        };
        let c = compile_plan(&plan, 1).unwrap();
        assert!(c.sql.contains("COUNT(*) AS value"));
        assert!(!c.sql.contains("SELECT id,"));
    }

    #[test]
    fn wrap_enforces_postgres_limit() {
        let inner = "SELECT id FROM vulnerabilities WHERE tenant_id = $1 LIMIT 9999";
        let w = wrap_nl_sql(inner);
        assert!(w.starts_with("SELECT * FROM ("));
        assert!(w.ends_with(&format!("LIMIT {MAX_LIMIT}")));
    }

    #[test]
    fn rejects_unknown_aggregate() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            aggregate: Some("drop".into()),
            ..QueryPlan::default()
        };
        assert!(compile_plan(&plan, 1).unwrap_err().contains("aggregate"));
    }
}
