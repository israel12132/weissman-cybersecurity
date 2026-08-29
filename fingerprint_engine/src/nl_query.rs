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

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::{Column, PgPool, Row};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;
/// v2 binds unix timestamp + nonce into the MAC so a captured v1 signature cannot replay.
const QUERYPLAN_HMAC_DOMAIN: &[u8] = b"weissman-queryplan-v2\0";
/// Maximum |server_now − plan_ts| accepted for S2S QueryPlan HMAC (seconds).
/// 15s absorbs NTP/cluster clock skew without opening a useful replay window.
pub const QUERYPLAN_HMAC_MAX_SKEW_SECS: i64 = 15;
/// Redis / local nonce TTL. 2× the skew window so a packet at the edge cannot
/// be replayed after the store forgets it.
pub const QUERYPLAN_NONCE_TTL_SECS: u64 = 30;
const QUERYPLAN_NONCE_MIN_HEX: usize = 16;
const QUERYPLAN_NONCE_MAX_HEX: usize = 64;

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

// ─── Plan → typed AST → bound SQL ────────────────────────────────────────────
//
// Security boundary: user/LLM strings never reach SQL except as sqlx bound
// parameters. Table/column/operator tokens are interned `&'static str` from
// SCHEMA / FilterOp. The wordlist in `reject_raw_sql_or_injection` is only a
// pre-LLM filter for natural language — it is not the injection control.

#[derive(Debug, Clone, Copy)]
enum FilterOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Like,
    IsNull,
    IsNotNull,
}

struct AstFilter {
    column: &'static str,
    op: FilterOp,
    value: Value,
}

struct PlanAst {
    table: &'static str,
    select: Vec<&'static str>,
    filters: Vec<AstFilter>,
    order_by: Option<&'static str>,
    order_desc: bool,
    limit: i64,
    tenant_id: i64,
}

#[derive(Debug)]
pub struct Compiled {
    pub sql: String,
    pub params: Vec<Value>,
}

fn is_sql_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c == '_' => {
            chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        }
        _ => false,
    }
}

fn intern_ident(allowed: &[&'static str], raw: &str, what: &str) -> Result<&'static str, String> {
    if !is_sql_ident(raw) {
        return Err(format!("{what} '{raw}' not allowed"));
    }
    allowed
        .iter()
        .copied()
        .find(|&c| c == raw)
        .ok_or_else(|| format!("{what} '{raw}' not allowed"))
}

fn parse_filter_op(raw: &str) -> Result<FilterOp, String> {
    let op_norm = raw.trim().to_ascii_lowercase();
    if !ALLOWED_OPS.contains(&op_norm.as_str()) {
        return Err(format!("operator '{raw}' not allowed"));
    }
    Ok(match op_norm.as_str() {
        "=" => FilterOp::Eq,
        "!=" => FilterOp::Ne,
        "<" => FilterOp::Lt,
        "<=" => FilterOp::Le,
        ">" => FilterOp::Gt,
        ">=" => FilterOp::Ge,
        "in" => FilterOp::In,
        "like" => FilterOp::Like,
        "is_null" => FilterOp::IsNull,
        "is_not_null" => FilterOp::IsNotNull,
        other => return Err(format!("unsupported query operator '{other}'")),
    })
}

fn plan_to_ast(plan: &QueryPlan, tenant_id: i64) -> Result<PlanAst, String> {
    if !is_sql_ident(&plan.table) {
        return Err(format!("table '{}' is not a valid identifier", plan.table));
    }
    let spec = SCHEMA
        .get(plan.table.as_str())
        .ok_or_else(|| format!("table '{}' is not exposed to NL queries", plan.table))?;

    let select = if plan.select.is_empty() {
        spec.columns.iter().copied().collect()
    } else {
        let mut out = Vec::with_capacity(plan.select.len());
        for c in &plan.select {
            out.push(intern_ident(spec.columns, c, "column")?);
        }
        out
    };

    let order_allowed: &[&str] = if spec.order_by.is_empty() {
        spec.columns
    } else {
        spec.order_by
    };
    let order_by = match &plan.order_by {
        Some(c) => Some(intern_ident(order_allowed, c, "order_by")?),
        None => None,
    };

    let mut filters = Vec::with_capacity(plan.filters.len());
    for f in &plan.filters {
        let column = intern_ident(spec.columns, &f.column, "filter column")?;
        let op = parse_filter_op(&f.op)?;
        filters.push(AstFilter {
            column,
            op,
            value: f.value.clone(),
        });
    }

    Ok(PlanAst {
        table: spec.table,
        select,
        filters,
        order_by,
        order_desc: plan.order_desc,
        limit: plan.limit.unwrap_or(50).clamp(1, MAX_LIMIT),
        tenant_id,
    })
}

fn ast_to_sql(ast: &PlanAst) -> Result<Compiled, String> {
    let select_sql = ast.select.join(", ");
    let mut where_parts: Vec<String> = Vec::new();
    let mut params: Vec<Value> = Vec::new();

    where_parts.push("tenant_id = $1".to_string());
    params.push(Value::from(ast.tenant_id));

    for f in &ast.filters {
        match f.op {
            FilterOp::IsNull => where_parts.push(format!("{} IS NULL", f.column)),
            FilterOp::IsNotNull => where_parts.push(format!("{} IS NOT NULL", f.column)),
            FilterOp::In => {
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
            FilterOp::Like => {
                let s = f
                    .value
                    .as_str()
                    .ok_or_else(|| "LIKE value must be string".to_string())?;
                let pattern = if s.contains('%') {
                    s.to_string()
                } else {
                    format!("%{}%", s)
                };
                params.push(Value::String(pattern));
                where_parts.push(format!("{} ILIKE ${}", f.column, params.len()));
            }
            FilterOp::Eq
            | FilterOp::Ne
            | FilterOp::Lt
            | FilterOp::Le
            | FilterOp::Gt
            | FilterOp::Ge => {
                let sql_op = match f.op {
                    FilterOp::Eq => "=",
                    FilterOp::Ne => "!=",
                    FilterOp::Lt => "<",
                    FilterOp::Le => "<=",
                    FilterOp::Gt => ">",
                    FilterOp::Ge => ">=",
                    _ => unreachable!(),
                };
                params.push(f.value.clone());
                where_parts.push(format!("{} {} ${}", f.column, sql_op, params.len()));
            }
        }
    }

    let order_sql = match ast.order_by {
        Some(c) => format!(
            " ORDER BY {} {}",
            c,
            if ast.order_desc { "DESC" } else { "ASC" }
        ),
        None => String::new(),
    };
    let sql = format!(
        "SELECT {} FROM {} WHERE {}{} LIMIT {}",
        select_sql,
        ast.table,
        where_parts.join(" AND "),
        order_sql,
        ast.limit,
    );
    Ok(Compiled { sql, params })
}

/// Compile a QueryPlan to parameterised SQL. This is the **only** function that
/// emits SQL for `/api/ask`.
pub fn compile_plan(plan: &QueryPlan, tenant_id: i64) -> Result<Compiled, String> {
    ast_to_sql(&plan_to_ast(plan, tenant_id)?)
}

// ─── Question ingest (raw SQL / injection rejected; signed QueryPlan is S2S) ─

/// Result of admitting a user question before any LLM call or SQL execution.
#[derive(Debug, Clone)]
pub enum QuestionIngest {
    /// Natural language that must be compiled to a QueryPlan by the planner LLM.
    NaturalLanguage(String),
}

/// Admit a **user** question. Direct JSON QueryPlan in the question string is
/// rejected — that path is service-to-service and requires
/// [`ingest_signed_query_plan`]. Raw SQL and injection payloads are rejected;
/// everything else is natural language for the planner.
pub fn ingest_question(question: &str) -> Result<QuestionIngest, String> {
    let q = question.trim();
    if q.is_empty() {
        return Err("question is empty".into());
    }
    if q.len() > 2000 {
        return Err("question too long (max 2000 chars)".into());
    }
    if q.starts_with('{') {
        return Err(
            "direct QueryPlan JSON is service-to-service only and requires a vault HMAC".into(),
        );
    }
    reject_raw_sql_or_injection(q)?;
    Ok(QuestionIngest::NaturalLanguage(q.to_string()))
}

/// HMAC-SHA256 over canonical QueryPlan JSON, keyed from the sovereign vault.
pub fn queryplan_hmac_key() -> Result<[u8; 32], String> {
    for (name, min_len) in [
        ("WEISSMAN_QUERYPLAN_HMAC_SECRET", 32usize),
        ("WEISSMAN_VAULT_KEY", 32),
        ("WEISSMAN_INTEGRATIONS_VAULT_KEY", 32),
    ] {
        if let Ok(raw) = std::env::var(name) {
            let t = raw.trim();
            if t.len() >= min_len {
                return Ok(derive_queryplan_key(t));
            }
        }
    }
    Err(
        "query plan HMAC key unavailable (set WEISSMAN_VAULT_KEY or WEISSMAN_QUERYPLAN_HMAC_SECRET)"
            .into(),
    )
}

fn derive_queryplan_key(material: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"weissman-queryplan-hmac-v1|");
    h.update(material.as_bytes());
    let digest = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&digest);
    k
}

/// Canonical bytes signed by S2S callers (deterministic serde field order).
pub fn canonical_query_plan_bytes(plan: &QueryPlan) -> Result<Vec<u8>, String> {
    serde_json::to_vec(plan).map_err(|e| format!("canonicalize plan: {e}"))
}

/// Unix seconds used to bind QueryPlan HMACs.
#[must_use]
pub fn queryplan_unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 16-byte (32 hex char) nonce for one S2S QueryPlan admission.
#[must_use]
pub fn new_queryplan_nonce() -> String {
    hex::encode(uuid::Uuid::new_v4().as_bytes())
}

pub fn validate_queryplan_nonce(nonce: &str) -> Result<(), String> {
    let n = nonce.trim();
    if n.len() < QUERYPLAN_NONCE_MIN_HEX || n.len() > QUERYPLAN_NONCE_MAX_HEX {
        return Err("query plan nonce must be 16-64 hex characters".into());
    }
    if !n.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("query plan nonce must be hexadecimal".into());
    }
    Ok(())
}

/// Sign a QueryPlan with an explicit 32-byte key (tests + S2S helpers).
///
/// The MAC covers `domain || canonical_plan || ts_be_i64 || nonce_utf8`.
pub fn sign_query_plan_with_key(
    plan: &QueryPlan,
    key: &[u8; 32],
    ts: i64,
    nonce: &str,
) -> Result<String, String> {
    validate_queryplan_nonce(nonce)?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| e.to_string())?;
    mac.update(QUERYPLAN_HMAC_DOMAIN);
    mac.update(&canonical_query_plan_bytes(plan)?);
    mac.update(&ts.to_be_bytes());
    mac.update(nonce.trim().as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub fn sign_query_plan(plan: &QueryPlan, ts: i64, nonce: &str) -> Result<String, String> {
    sign_query_plan_with_key(plan, &queryplan_hmac_key()?, ts, nonce)
}

pub fn verify_query_plan_hmac_with_key(
    plan: &QueryPlan,
    hmac_hex: &str,
    ts: i64,
    nonce: &str,
    key: &[u8; 32],
) -> Result<(), String> {
    verify_query_plan_hmac_with_key_at(plan, hmac_hex, ts, nonce, key, queryplan_unix_now())
}

pub fn verify_query_plan_hmac_with_key_at(
    plan: &QueryPlan,
    hmac_hex: &str,
    ts: i64,
    nonce: &str,
    key: &[u8; 32],
    now: i64,
) -> Result<(), String> {
    validate_queryplan_nonce(nonce)?;
    if now.abs_diff(ts) > QUERYPLAN_HMAC_MAX_SKEW_SECS as u64 {
        return Err(format!(
            "query plan timestamp is outside the {QUERYPLAN_HMAC_MAX_SKEW_SECS} second replay window"
        ));
    }
    let expected_hex = sign_query_plan_with_key(plan, key, ts, nonce)?;
    let expected = hex::decode(&expected_hex).unwrap_or_default();
    if !crate::security_hardening::constant_time_hmac_hex_eq(&expected, hmac_hex) {
        return Err("query plan HMAC is invalid".into());
    }
    Ok(())
}

pub fn verify_query_plan_hmac(
    plan: &QueryPlan,
    hmac_hex: &str,
    ts: i64,
    nonce: &str,
) -> Result<(), String> {
    verify_query_plan_hmac_with_key(plan, hmac_hex, ts, nonce, &queryplan_hmac_key()?)
}

static LOCAL_QUERYPLAN_NONCES: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Process-local nonce consume (unit tests + single-node when Redis is unset).
pub fn consume_queryplan_nonce_local(nonce: &str) -> Result<(), String> {
    validate_queryplan_nonce(nonce)?;
    let ttl = Duration::from_secs(QUERYPLAN_NONCE_TTL_SECS);
    let mut g = LOCAL_QUERYPLAN_NONCES
        .lock()
        .map_err(|_| "query plan nonce store poisoned".to_string())?;
    g.retain(|_, seen| seen.elapsed() < ttl);
    let key = nonce.trim().to_ascii_lowercase();
    if g.contains_key(&key) {
        return Err("query plan HMAC nonce has already been used".into());
    }
    g.insert(key, Instant::now());
    Ok(())
}

/// Admit a service-to-service QueryPlan after vault HMAC + replay checks.
///
/// Consumes the nonce via Redis `SET NX` when `REDIS_URL` is set; otherwise
/// a process-local map (fail-closed when production distributed Redis is required).
pub async fn ingest_signed_query_plan(
    plan: QueryPlan,
    hmac_hex: &str,
    ts: i64,
    nonce: &str,
) -> Result<QueryPlan, String> {
    verify_query_plan_hmac(&plan, hmac_hex, ts, nonce)?;
    crate::http::rate_limit_redis::claim_queryplan_nonce(nonce).await?;
    Ok(plan)
}

pub fn ingest_signed_query_plan_with_key(
    plan: QueryPlan,
    hmac_hex: &str,
    ts: i64,
    nonce: &str,
    key: &[u8; 32],
) -> Result<QueryPlan, String> {
    verify_query_plan_hmac_with_key(&plan, hmac_hex, ts, nonce, key)?;
    consume_queryplan_nonce_local(nonce)?;
    Ok(plan)
}

/// Reject raw SQL, classic injection, and code-exec payloads. Natural language
/// that happens to contain the substring "select" (e.g. "selected findings")
/// is allowed — we match SQL verbs, not English.
pub fn reject_raw_sql_or_injection(question: &str) -> Result<(), String> {
    let compact = question
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    let lower = question.to_ascii_lowercase();

    const SQL_MARKERS: &[&str] = &[
        "SELECT ",
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "DROP TABLE",
        "DROP DATABASE",
        "ALTER TABLE",
        "UNION SELECT",
        "TRUNCATE ",
        "CREATE TABLE",
        "; SELECT",
        "; DROP",
        "' OR '1'='1",
        "' OR 1=1",
        "INFORMATION_SCHEMA",
        "PG_SLEEP",
        "PG_CATALOG",
        "XP_CMDSHELL",
        "WEISSMAN_APP.SECRET",
    ];
    if SQL_MARKERS.iter().any(|m| compact.contains(m)) {
        return Err(
            "raw SQL is rejected; questions must be natural language (JSON QueryPlan is S2S HMAC only)".into(),
        );
    }

    const CODE_MARKERS: &[&str] = &[
        "<script",
        "javascript:",
        "eval(",
        "onerror=",
        "${",
        "{{constructor",
        "rm -rf",
        "/etc/passwd",
        "fromcharcode",
    ];
    if CODE_MARKERS.iter().any(|m| lower.contains(m)) {
        return Err(
            "injection payload rejected; queries must compile through a vault-HMAC QueryPlan"
                .into(),
        );
    }
    Ok(())
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
/// Direct QueryPlan execution requires [`admitted_plan`] (HMAC + ts + nonce already verified).
pub async fn ask(
    app_pool: &PgPool,
    ro_pool: &PgPool,
    tenant_id: i64,
    user_id: Option<i64>,
    question: &str,
    admitted_plan: Option<QueryPlan>,
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
    if q.len() > 2000 {
        return bad("question too long (max 2000 chars)");
    }

    let plan: QueryPlan = if let Some(plan) = admitted_plan {
        if !q.is_empty() {
            let r = bad("signed QueryPlan must not be mixed with a natural-language question");
            audit_query(app_pool, tenant_id, user_id, question, &r).await;
            return r;
        }
        plan
    } else {
        if q.is_empty() {
            return bad("question is empty");
        }
        let ingested = match ingest_question(q) {
            Ok(v) => v,
            Err(e) => {
                let r = bad(&e);
                audit_query(app_pool, tenant_id, user_id, question, &r).await;
                return r;
            }
        };
        match ingested {
            QuestionIngest::NaturalLanguage(nl) => {
                let plan_json = match llm_to_plan(&nl, tenant_id).await {
                    Ok(v) => v,
                    Err(e) => {
                        let r = bad(&format!("plan generation failed: {e}"));
                        audit_query(app_pool, tenant_id, user_id, question, &r).await;
                        return r;
                    }
                };
                match serde_json::from_value(plan_json) {
                    Ok(p) => p,
                    Err(e) => {
                        let r = bad(&format!("plan is not a valid QueryPlan JSON: {e}"));
                        audit_query(app_pool, tenant_id, user_id, question, &r).await;
                        return r;
                    }
                }
            }
        }
    };

    // 2) Validate + execute (compile_plan is the only path to SQL).
    let res = match execute_plan(ro_pool, tenant_id, plan.clone()).await {
        Ok(mut r) => {
            r.elapsed_ms = start.elapsed().as_millis() as i64;
            r
        }
        Err(e) => bad(&e),
    };

    audit_query(app_pool, tenant_id, user_id, question, &res).await;
    res
}

async fn audit_query(
    app_pool: &PgPool,
    tenant_id: i64,
    user_id: Option<i64>,
    question: &str,
    res: &AskResult,
) {
    if let Ok(mut tx) = crate::db::begin_tenant_tx(app_pool, tenant_id).await {
        let _ = sqlx::query(
            "INSERT INTO nl_query_audit
                (tenant_id, user_id, asked_at, question, plan_json, compiled_sql,
                 rows_returned, elapsed_ms, error)
             VALUES ($1, $2, now(), $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(question.chars().take(2000).collect::<String>())
        .bind(serde_json::to_value(&res.plan).unwrap_or(json!({})))
        .bind(&res.sql)
        .bind(res.row_count as i32)
        .bind(res.elapsed_ms as i32)
        .bind(res.error.clone().unwrap_or_default())
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
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
    use hmac::Mac;

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
    fn ingest_rejects_raw_sql_and_injection() {
        for q in [
            "SELECT * FROM weissman_app.secret_keys; -- Exploit",
            "DROP TABLE vulnerabilities",
            "1'; DROP TABLE clients; --",
            "UNION SELECT password FROM users",
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "eval('fetch(\"/api/login\")')",
        ] {
            let err = ingest_question(q).unwrap_err();
            assert!(
                err.contains("rejected") || err.contains("SQL") || err.contains("injection"),
                "expected reject for {q:?}, got {err}"
            );
        }
    }

    #[test]
    fn ingest_allows_natural_language_and_rejects_unsigned_plan_json() {
        match ingest_question("show me selected critical findings on prod").unwrap() {
            QuestionIngest::NaturalLanguage(s) => assert!(s.contains("selected")),
        }
        let json = r#"{"table":"vulnerabilities","select":["id","title"],"filters":[],"limit":10}"#;
        let err = ingest_question(json).unwrap_err();
        assert!(
            err.contains("HMAC") || err.contains("service-to-service"),
            "unsigned JSON plan must be rejected, got {err}"
        );
    }

    #[test]
    fn signed_query_plan_hmac_is_required_and_verified() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into(), "title".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: Some(10),
        };
        let key = [0x11u8; 32];
        let ts = queryplan_unix_now();
        let nonce = new_queryplan_nonce();
        let mac = sign_query_plan_with_key(&plan, &key, ts, &nonce).expect("sign");
        let admitted = ingest_signed_query_plan_with_key(plan.clone(), &mac, ts, &nonce, &key)
            .expect("valid hmac");
        assert_eq!(admitted.table, "vulnerabilities");
        assert!(verify_query_plan_hmac_with_key(&plan, "deadbeef", ts, &nonce, &key).is_err());
        let compiled = compile_plan(&admitted, 1).expect("compile");
        assert!(compiled.sql.contains("tenant_id = $1"));
    }

    #[test]
    fn signed_query_plan_rejects_stale_timestamp() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: Some(1),
        };
        let key = [0x22u8; 32];
        let nonce = new_queryplan_nonce();
        let now = 1_700_000_000i64;
        let ts = now - QUERYPLAN_HMAC_MAX_SKEW_SECS - 1;
        let mac = sign_query_plan_with_key(&plan, &key, ts, &nonce).expect("sign");
        let err = verify_query_plan_hmac_with_key_at(&plan, &mac, ts, &nonce, &key, now)
            .expect_err("stale");
        assert!(
            err.contains("timestamp"),
            "stale timestamp must be rejected, got {err}"
        );
        let future = now + QUERYPLAN_HMAC_MAX_SKEW_SECS + 1;
        let mac_f = sign_query_plan_with_key(&plan, &key, future, &nonce).expect("sign");
        let err_f = verify_query_plan_hmac_with_key_at(&plan, &mac_f, future, &nonce, &key, now)
            .expect_err("future");
        assert!(err_f.contains("timestamp"), "got {err_f}");
        let edge = now - QUERYPLAN_HMAC_MAX_SKEW_SECS;
        let mac_ok = sign_query_plan_with_key(&plan, &key, edge, &nonce).expect("sign");
        verify_query_plan_hmac_with_key_at(&plan, &mac_ok, edge, &nonce, &key, now)
            .expect("edge of window must pass");
        // Architect gate: 3s NTP/cluster skew must not starve S2S Ask.
        let skew3 = now - 3;
        let mac3 = sign_query_plan_with_key(&plan, &key, skew3, &nonce).expect("sign");
        verify_query_plan_hmac_with_key_at(&plan, &mac3, skew3, &nonce, &key, now)
            .expect("3s clock skew must be inside the 15s window");
    }

    #[test]
    fn queryplan_hmac_skew_window_is_twice_nonce_ttl() {
        assert_eq!(QUERYPLAN_HMAC_MAX_SKEW_SECS, 15);
        assert_eq!(QUERYPLAN_NONCE_TTL_SECS, 30);
        assert!(QUERYPLAN_NONCE_TTL_SECS as i64 >= QUERYPLAN_HMAC_MAX_SKEW_SECS * 2);
    }

    #[test]
    fn signed_query_plan_rejects_replayed_nonce() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: Some(1),
        };
        let key = [0x33u8; 32];
        let ts = queryplan_unix_now();
        let nonce = new_queryplan_nonce();
        let mac = sign_query_plan_with_key(&plan, &key, ts, &nonce).expect("sign");
        ingest_signed_query_plan_with_key(plan.clone(), &mac, ts, &nonce, &key).expect("first");
        let err =
            ingest_signed_query_plan_with_key(plan, &mac, ts, &nonce, &key).expect_err("replay");
        assert!(
            err.contains("already been used"),
            "replay must fail-closed, got {err}"
        );
    }

    #[test]
    fn signed_query_plan_v1_mac_without_ts_binding_is_rejected() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: Some(1),
        };
        let key = [0x44u8; 32];
        let ts = queryplan_unix_now();
        let nonce = new_queryplan_nonce();
        // v1 MAC: domain v1 || plan only — must not verify under v2.
        let mut mac = HmacSha256::new_from_slice(&key).expect("key");
        mac.update(b"weissman-queryplan-v1\0");
        mac.update(&canonical_query_plan_bytes(&plan).expect("canon"));
        let v1 = hex::encode(mac.finalize().into_bytes());
        let err = verify_query_plan_hmac_with_key(&plan, &v1, ts, &nonce, &key).expect_err("v1");
        assert!(
            err.contains("HMAC") || err.contains("invalid"),
            "v1 signature must die, got {err}"
        );
    }

    #[test]
    fn compile_plan_rejects_sql_smuggled_as_table_or_column() {
        let plan = QueryPlan {
            table: "secret_keys".into(),
            select: vec![],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: None,
        };
        assert!(compile_plan(&plan, 1).unwrap_err().contains("not exposed"));

        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id; DROP TABLE clients".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: None,
        };
        assert!(compile_plan(&plan, 1).unwrap_err().contains("not allowed"));

        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![Filter {
                column: "severity".into(),
                op: "OR 1=1".into(),
                value: json!("x"),
            }],
            order_by: None,
            order_desc: false,
            limit: None,
        };
        assert!(compile_plan(&plan, 1)
            .unwrap_err()
            .to_ascii_lowercase()
            .contains("operator"));
    }

    #[test]
    fn filter_values_are_bound_not_interpolated() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![Filter {
                column: "title".into(),
                op: "=".into(),
                value: json!("'; DROP TABLE clients; --"),
            }],
            order_by: None,
            order_desc: false,
            limit: Some(10),
        };
        let c = compile_plan(&plan, 7).unwrap();
        assert!(!c.sql.to_ascii_lowercase().contains("drop table"));
        assert!(c.sql.contains("title = $2"));
        assert_eq!(c.params[0], Value::from(7));
        assert_eq!(c.params[1], json!("'; DROP TABLE clients; --"));
    }
}
