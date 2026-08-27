//! Natural-language → safe-SQL planner.
//!
//! Pipeline:
//!   1. User asks a question ("show me critical KEV findings on prod assets").
//!   2. LLM is given a STRICT schema + the question, and instructed to emit a
//!      JSON `QueryPlan` (NOT raw SQL). The LLM never writes SQL.
//!   3. The planner payload is **blocked** if it contains raw SQL or extra SQL-shaped
//!      fields, then **sealed** (HMAC-SHA256 bound to `tenant_id`) and optionally
//!      AES-256-GCM encrypted at rest in `nl_query_audit`.
//!   4. The validator sanitizes every filter value (type, length, control chars,
//!      LIKE wildcards) so parametric values cannot carry second-order injection.
//!   5. Compilation always injects `"tenant_id" = $1` as the **inner** predicate
//!      of a subquery. User filters run only on that already-scoped set. `$1` is
//!      the authenticated tenant — never a value from the LLM.
//!   6. The compiled SQL runs on the `weissman_ro` pool with `statement_timeout =
//!      15000` (SET LOCAL + after_connect + role default) and a hard `LIMIT 200`
//!      on both the compiled statement and an outer row-cap wrapper.
//!   7. HMAC sealing uses **HKDF-SHA256** (RFC 5869) from the vault master and
//!      `tenant_id` so a leaked JWT signing secret cannot forge another tenant's plan.
//!   8. Validator / Postgres errors are logged and AES-GCM encrypted in
//!      `nl_query_audit`; the client only ever sees [`CLIENT_GENERIC_ERROR`].
//!   9. Planner JSON is depth-capped **during** serde (stream visitor), not by
//!      scanning raw `{`/`[` bytes. AND/OR trees above [`MAX_CONDITION_DEPTH`]
//!      are rejected. RAG tables are not on the NL allow-list; contextual memory
//!      is fetched separately via [`crate::ask_rag`] on the app pool.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as HmacMac};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::{Column, PgPool, Row};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Instant;
use weissman_core::tls_policy::is_production_environment;
use weissman_db::{READ_ONLY_MAX_ROWS, READ_ONLY_ROLE, READ_ONLY_STATEMENT_TIMEOUT_MS};

type HmacSha256 = Hmac<Sha256>;

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
const MAX_LIMIT: i64 = READ_ONLY_MAX_ROWS;
const MAX_FILTERS: usize = 16;
const MAX_IN_VALUES: usize = 32;
const MAX_FILTER_STRING_CHARS: usize = 512;
/// Nesting cap applied by the stream deserializer (after Unicode unescape).
/// A 4-deep AND/OR tree is ~10 containers; 12 rejects a depth bomb.
pub const MAX_JSON_DEPTH: usize = 12;
/// Nested boolean condition cap (`and`/`or`/`not`/`all`/`any` trees).
pub const MAX_CONDITION_DEPTH: usize = 4;
/// The only validator/DB failure string the client is allowed to see.
pub const CLIENT_GENERIC_ERROR: &str =
    "Query processing failed due to authorization or syntax constraint.";
const TENANT_SCOPE_ALIAS: &str = "_ask_tenant_scope";
const ROWCAP_ALIAS: &str = "_ask_rowcap";
const BLOCKED_PLAN_FIELDS: &[&str] = &[
    "sql",
    "query",
    "raw_sql",
    "statement",
    "statements",
    "union",
    "cte",
    "with",
    "execute",
    "exec",
];

// ─── Plan structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub column: String,
    pub op: String,
    #[serde(default)]
    pub value: Value,
}

/// HMAC-sealed QueryPlan bound to a tenant. Compilation and execution refuse
/// an unsealed or cross-tenant payload.
#[derive(Debug, Clone)]
pub struct SealedQueryPlan {
    plan: QueryPlan,
    tenant_id: i64,
    mac: Vec<u8>,
}

impl SealedQueryPlan {
    #[must_use]
    pub fn plan(&self) -> &QueryPlan {
        &self.plan
    }
}

// ─── Identifier + filter-value sanitization ──────────────────────────────────

fn is_safe_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z' | '_'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
        && s.len() <= 64
        && !s.is_empty()
}

fn quote_ident(s: &str) -> Result<String, String> {
    if !is_safe_ident(s) {
        return Err(format!("unsafe identifier '{s}'"));
    }
    Ok(format!("\"{s}\""))
}

fn looks_like_raw_sql(s: &str) -> bool {
    let t = s.trim_start();
    let lower = t.to_ascii_lowercase();
    const HEADS: &[&str] = &[
        "select ",
        "select\n",
        "select\t",
        "with ",
        "insert ",
        "update ",
        "delete ",
        "drop ",
        "alter ",
        "copy ",
        "grant ",
        "revoke ",
        "truncate ",
        "execute ",
        "create ",
        "vacuum ",
        "analyze ",
        "explain ",
    ];
    HEADS.iter().any(|h| lower.starts_with(h))
}

fn reject_control_chars(s: &str, ctx: &str) -> Result<(), String> {
    if s.chars()
        .any(|c| c == '\0' || (c.is_control() && c != '\t'))
    {
        return Err(format!("{ctx}: control characters are not allowed"));
    }
    Ok(())
}

fn sanitize_scalar(v: &Value, ctx: &str) -> Result<Value, String> {
    match v {
        Value::Bool(b) => Ok(Value::Bool(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::from(i))
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() || f.abs() > 1e15 {
                    return Err(format!("{ctx}: numeric value out of range"));
                }
                Ok(serde_json::Number::from_f64(f)
                    .map(Value::Number)
                    .ok_or_else(|| format!("{ctx}: numeric value out of range"))?)
            } else {
                Err(format!("{ctx}: unsupported number"))
            }
        }
        Value::String(s) => {
            if s.chars().count() > MAX_FILTER_STRING_CHARS {
                return Err(format!(
                    "{ctx}: string exceeds {MAX_FILTER_STRING_CHARS} characters"
                ));
            }
            reject_control_chars(s, ctx)?;
            Ok(Value::String(s.clone()))
        }
        Value::Null => Err(format!("{ctx}: null is not a valid comparison value")),
        Value::Array(_) | Value::Object(_) => Err(format!(
            "{ctx}: nested JSON is not allowed in filter values"
        )),
    }
}

/// Escape `\`, `%`, `_` so LIKE values cannot expand into table-wide wildcard scans.
fn escape_like_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Strip tenant-scoped columns the LLM must never control, cap limit, sanitize values.
fn sanitize_plan(plan: &mut QueryPlan) -> Result<(), String> {
    if plan.filters.len() > MAX_FILTERS {
        return Err(format!("too many filters (max {MAX_FILTERS})"));
    }
    // Physical tenant isolation: the LLM cannot filter, select, or order by tenant_id.
    plan.filters.retain(|f| f.column != "tenant_id");
    plan.select.retain(|c| c != "tenant_id");
    if plan.order_by.as_deref() == Some("tenant_id") {
        plan.order_by = None;
    }
    if let Some(lim) = plan.limit {
        if lim < 1 {
            return Err("limit must be >= 1".into());
        }
        plan.limit = Some(lim.min(MAX_LIMIT));
    }
    for f in &mut plan.filters {
        if !is_safe_ident(&f.column) {
            return Err(format!("unsafe filter column '{}'", f.column));
        }
        let op_norm = f.op.trim().to_ascii_lowercase();
        if !ALLOWED_OPS.contains(&op_norm.as_str()) {
            return Err(format!("operator '{}' not allowed", f.op));
        }
        f.op = op_norm.clone();
        match op_norm.as_str() {
            "is_null" | "is_not_null" => {
                f.value = Value::Null;
            }
            "in" => {
                let arr = f
                    .value
                    .as_array()
                    .ok_or_else(|| "IN value must be array".to_string())?;
                if arr.is_empty() {
                    return Err("IN value array is empty".to_string());
                }
                if arr.len() > MAX_IN_VALUES {
                    return Err(format!("IN value array exceeds {MAX_IN_VALUES} items"));
                }
                let mut clean = Vec::with_capacity(arr.len());
                for (i, v) in arr.iter().enumerate() {
                    clean.push(sanitize_scalar(v, &format!("IN[{i}]"))?);
                }
                f.value = Value::Array(clean);
            }
            "like" => {
                let s = f
                    .value
                    .as_str()
                    .ok_or_else(|| "LIKE value must be string".to_string())?;
                if s.chars().count() > MAX_FILTER_STRING_CHARS {
                    return Err(format!(
                        "LIKE value exceeds {MAX_FILTER_STRING_CHARS} characters"
                    ));
                }
                reject_control_chars(s, "LIKE")?;
                f.value = Value::String(s.to_string());
            }
            "=" | "!=" | "<" | "<=" | ">" | ">=" => {
                f.value = sanitize_scalar(&f.value, "filter")?;
            }
            other => return Err(format!("unsupported query operator '{other}'")),
        }
    }
    Ok(())
}

/// Stream-parse JSON with a live depth cap. Unicode escapes (`\u007b` / `\u005b`)
/// are decoded by serde into string content and **do not** increment depth.
/// Structural nesting is counted only as serde yields maps/arrays.
pub fn parse_json_capped(raw: &str) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_str(raw);
    let v = DepthSeed { depth: 0 }.deserialize(&mut de).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("nesting limit") {
            "blocked: QueryPlan JSON exceeds nesting limit".into()
        } else {
            format!("invalid JSON from LLM: {msg}")
        }
    })?;
    de.end()
        .map_err(|e| format!("invalid JSON from LLM: {e}"))?;
    Ok(v)
}

struct DepthSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for DepthSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(DepthVisitor { depth: self.depth })
    }
}

struct DepthVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for DepthVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a JSON value within the QueryPlan nesting limit")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        DepthSeed { depth: self.depth }.deserialize(deserializer)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(de::Error::custom(
                "blocked: QueryPlan JSON exceeds nesting limit",
            ));
        }
        let mut arr = Vec::new();
        while let Some(v) = seq.next_element_seed(DepthSeed {
            depth: self.depth + 1,
        })? {
            arr.push(v);
        }
        Ok(Value::Array(arr))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(de::Error::custom(
                "blocked: QueryPlan JSON exceeds nesting limit",
            ));
        }
        let mut obj = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            let v = map.next_value_seed(DepthSeed {
                depth: self.depth + 1,
            })?;
            obj.insert(k, v);
        }
        Ok(Value::Object(obj))
    }
}

fn condition_nesting_depth(v: &Value) -> usize {
    match v {
        Value::Object(m) => {
            let mut d = 0;
            for (k, child) in m {
                let child_d = condition_nesting_depth(child);
                if matches!(k.as_str(), "and" | "or" | "not" | "all" | "any") {
                    d = d.max(1 + child_d);
                } else {
                    d = d.max(child_d);
                }
            }
            d
        }
        Value::Array(a) => a.iter().map(condition_nesting_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Block raw SQL and extra SQL-shaped keys; keep only the QueryPlan allow-list.
pub fn ingest_planner_output(raw: &str) -> Result<QueryPlan, String> {
    let text = raw.trim();
    if text.is_empty() {
        return Err("planner returned an empty payload".into());
    }
    if looks_like_raw_sql(text) {
        return Err("blocked: planner returned raw SQL; QueryPlan JSON is required".into());
    }
    let v = parse_json_capped(text)?;
    if condition_nesting_depth(&v) > MAX_CONDITION_DEPTH {
        return Err("blocked: QueryPlan condition tree exceeds nesting limit".into());
    }
    ingest_plan_value(v)
}

fn value_tree_depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(value_tree_depth).max().unwrap_or(0),
        Value::Object(m) => 1 + m.values().map(value_tree_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn ingest_plan_value(v: Value) -> Result<QueryPlan, String> {
    if value_tree_depth(&v) > MAX_JSON_DEPTH {
        return Err("blocked: QueryPlan JSON exceeds nesting limit".into());
    }
    if condition_nesting_depth(&v) > MAX_CONDITION_DEPTH {
        return Err("blocked: QueryPlan condition tree exceeds nesting limit".into());
    }
    let mut obj = match v {
        Value::Object(m) => m,
        Value::String(s) if looks_like_raw_sql(&s) => {
            return Err("blocked: planner returned raw SQL; QueryPlan JSON is required".into());
        }
        _ => return Err("QueryPlan must be a JSON object".into()),
    };
    if !obj.contains_key("table") {
        if let Some(Value::Object(inner)) = obj.remove("plan") {
            obj = inner;
        }
    }
    for k in BLOCKED_PLAN_FIELDS {
        if obj.contains_key(*k) {
            return Err(format!("blocked QueryPlan payload field '{k}'"));
        }
    }
    let filters_in = obj.get("filters").cloned().unwrap_or(Value::Array(vec![]));
    let filters = match filters_in {
        Value::Array(arr) => {
            if arr.len() > MAX_FILTERS {
                return Err(format!("too many filters (max {MAX_FILTERS})"));
            }
            let mut out = Vec::with_capacity(arr.len());
            for f in arr {
                let fo = f
                    .as_object()
                    .ok_or_else(|| "filter must be a JSON object".to_string())?;
                for k in BLOCKED_PLAN_FIELDS {
                    if fo.contains_key(*k) {
                        return Err(format!("blocked filter payload field '{k}'"));
                    }
                }
                let mut slim = Map::new();
                if let Some(c) = fo.get("column") {
                    slim.insert("column".into(), c.clone());
                }
                if let Some(o) = fo.get("op") {
                    slim.insert("op".into(), o.clone());
                }
                if let Some(val) = fo.get("value") {
                    slim.insert("value".into(), val.clone());
                }
                out.push(Value::Object(slim));
            }
            Value::Array(out)
        }
        Value::Null => Value::Array(vec![]),
        _ => return Err("filters must be an array".into()),
    };
    let mut slim = Map::new();
    if let Some(t) = obj.get("table") {
        slim.insert("table".into(), t.clone());
    }
    if let Some(s) = obj.get("select") {
        slim.insert("select".into(), s.clone());
    }
    slim.insert("filters".into(), filters);
    if let Some(o) = obj.get("order_by") {
        slim.insert("order_by".into(), o.clone());
    }
    if let Some(o) = obj.get("order_desc") {
        slim.insert("order_desc".into(), o.clone());
    }
    if let Some(l) = obj.get("limit") {
        slim.insert("limit".into(), l.clone());
    }
    let mut plan: QueryPlan = serde_json::from_value(Value::Object(slim))
        .map_err(|e| format!("plan is not a valid QueryPlan JSON: {e}"))?;
    if crate::ask_vector_caps::is_blocked_vector_table(&plan.table) {
        return Err("blocked: vector/RAG tables are not exposed to NL queries".into());
    }
    sanitize_plan(&mut plan)?;
    Ok(plan)
}

fn hex32_key(raw: &str) -> Option<[u8; 32]> {
    let b = hex::decode(raw.trim()).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&b);
    Some(k)
}

/// Vault master for Ask seals. Prefers `WEISSMAN_VAULT_KEY` so a leaked JWT
/// signing secret cannot mint another tenant's HMAC. JWT is a non-prod fallback.
fn seal_master_key() -> Result<Vec<u8>, String> {
    if let Ok(raw) = std::env::var("WEISSMAN_VAULT_KEY") {
        if let Some(k) = hex32_key(raw.trim()) {
            return Ok(k.to_vec());
        }
        if raw.trim().len() >= 32 {
            let mut h = Sha256::new();
            h.update(b"weissman-ask-vault-passphrase-v1|");
            h.update(raw.trim().as_bytes());
            return Ok(h.finalize().to_vec());
        }
    }
    if let Ok(raw) = std::env::var("WEISSMAN_INTEGRATIONS_VAULT_KEY") {
        if raw.trim().len() >= 32 {
            let mut h = Sha256::new();
            h.update(b"weissman-ask-integrations-vault-v1|");
            h.update(raw.trim().as_bytes());
            return Ok(h.finalize().to_vec());
        }
    }
    if let Ok(s) = std::env::var("WEISSMAN_JWT_SECRET") {
        let t = s.trim();
        if t.len() >= 16 {
            if is_production_environment() {
                return Err("QueryPlan sealing requires WEISSMAN_VAULT_KEY".into());
            }
            let mut h = Sha256::new();
            h.update(b"weissman-ask-queryplan-master-fallback-v1|");
            h.update(t.as_bytes());
            return Ok(h.finalize().to_vec());
        }
    }
    if is_production_environment() {
        return Err("QueryPlan sealing requires WEISSMAN_VAULT_KEY".into());
    }
    Ok(b"weissman-ask-queryplan-dev-hmac-key".to_vec())
}

/// HKDF-SHA256 extract+expand (RFC 5869). Salt domains the purpose; info binds tenant.
fn hkdf_okm(master: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(Some(b"weissman-ask-hkdf-v3"), master);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(okm)
}

fn tenant_info(label: &[u8], tenant_id: i64) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 8);
    info.extend_from_slice(label);
    info.extend_from_slice(&tenant_id.to_le_bytes());
    info
}

fn tenant_seal_key(tenant_id: i64) -> Result<Vec<u8>, String> {
    let master = seal_master_key()?;
    Ok(hkdf_okm(&master, &tenant_info(b"ask-queryplan-hmac-v3", tenant_id))?.to_vec())
}

fn tenant_aes_key(tenant_id: i64) -> Option<[u8; 32]> {
    let master = seal_master_key().ok()?;
    hkdf_okm(&master, &tenant_info(b"ask-queryplan-aes-v3", tenant_id)).ok()
}

/// Load vault material and seed the audit-nonce RNG. Env + HKDF only — no blocking getrandom.
pub fn warm_ask_crypto() {
    let _ = seal_master_key();
    let _ = audit_nonce();
}

fn chacha_seed() -> [u8; 32] {
    if let Ok(master) = seal_master_key() {
        if let Ok(k) = hkdf_okm(&master, b"ask-audit-nonce-chacha8-v1") {
            return k;
        }
    }
    let mut h = Sha256::new();
    h.update(b"ask-audit-nonce-chacha8-fallback-v1");
    h.update(std::process::id().to_le_bytes());
    if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        h.update(d.as_nanos().to_le_bytes());
    }
    let out = h.finalize();
    let mut s = [0u8; 32];
    s.copy_from_slice(&out);
    s
}

/// 96-bit AES-GCM nonce from ChaCha8Rng (vault-seeded) + a process counter.
/// Never calls `getrandom` / `OsRng`, so a cold-boot entropy stall cannot hang Ask.
fn audit_nonce() -> Nonce<Aes256Gcm> {
    static RNG: OnceLock<Mutex<ChaCha8Rng>> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let mut rng = RNG
        .get_or_init(|| Mutex::new(ChaCha8Rng::from_seed(chacha_seed())))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut bytes = [0u8; 12];
    rng.fill_bytes(&mut bytes[..8]);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed) as u32;
    bytes[8..12].copy_from_slice(&n.to_le_bytes());
    *Nonce::<Aes256Gcm>::from_slice(&bytes)
}

fn plan_hmac(plan: &QueryPlan, tenant_id: i64) -> Result<Vec<u8>, String> {
    let key = tenant_seal_key(tenant_id)?;
    let mut mac = <HmacSha256 as HmacMac>::new_from_slice(&key).map_err(|e| e.to_string())?;
    mac.update(&tenant_id.to_le_bytes());
    mac.update(&[0xff]);
    let canonical = serde_json::to_vec(plan).map_err(|e| e.to_string())?;
    mac.update(&canonical);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Sanitize, then HMAC-seal the plan to `tenant_id` so it cannot be swapped or replayed.
pub fn seal_plan(mut plan: QueryPlan, tenant_id: i64) -> Result<SealedQueryPlan, String> {
    if tenant_id <= 0 {
        return Err("invalid tenant_id".into());
    }
    sanitize_plan(&mut plan)?;
    let mac = plan_hmac(&plan, tenant_id)?;
    Ok(SealedQueryPlan {
        plan,
        tenant_id,
        mac,
    })
}

fn verify_seal(sealed: &SealedQueryPlan, tenant_id: i64) -> Result<(), String> {
    if sealed.tenant_id != tenant_id {
        return Err("blocked: QueryPlan tenant seal mismatch".into());
    }
    let key = tenant_seal_key(tenant_id)?;
    let mut mac = <HmacSha256 as HmacMac>::new_from_slice(&key).map_err(|e| e.to_string())?;
    mac.update(&tenant_id.to_le_bytes());
    mac.update(&[0xff]);
    let canonical = serde_json::to_vec(&sealed.plan).map_err(|e| e.to_string())?;
    mac.update(&canonical);
    mac.verify_slice(&sealed.mac)
        .map_err(|_| "blocked: QueryPlan HMAC invalid".to_string())
}

fn encrypt_bytes_for_audit(tenant_id: i64, plaintext: &[u8]) -> Option<String> {
    let key = tenant_aes_key(tenant_id)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = audit_nonce();
    let ct = cipher.encrypt(&nonce, plaintext).ok()?;
    let mut packed = nonce.to_vec();
    packed.extend_from_slice(&ct);
    Some(format!(
        "wzaqp1:{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &packed)
    ))
}

fn encrypt_plan_for_audit(plan: &QueryPlan, tenant_id: i64) -> Value {
    let Ok(plaintext) = serde_json::to_vec(plan) else {
        return json!({"_sealed": false, "error": "serialize"});
    };
    match encrypt_bytes_for_audit(tenant_id, &plaintext) {
        Some(enc) => json!({
            "_enc": enc,
            "alg": "aes-256-gcm",
            "sealed": true,
        }),
        None => json!({"_sealed": false, "plan": plan}),
    }
}

fn encrypt_error_for_audit(tenant_id: i64, internal: &str) -> String {
    match encrypt_bytes_for_audit(tenant_id, internal.as_bytes()) {
        Some(enc) => enc,
        None => String::new(),
    }
}

// ─── Plan → safe SQL ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Compiled {
    pub sql: String,
    pub params: Vec<Value>,
}

pub fn compile_plan(plan: &QueryPlan, tenant_id: i64) -> Result<Compiled, String> {
    if tenant_id <= 0 {
        return Err("invalid tenant_id".into());
    }
    let mut plan = plan.clone();
    sanitize_plan(&mut plan)?;

    if crate::ask_vector_caps::is_blocked_vector_table(&plan.table) {
        return Err("blocked: vector/RAG tables are not exposed to NL queries".into());
    }

    // 1) Validate table.
    if !is_safe_ident(&plan.table) {
        return Err(format!(
            "table '{}' is not exposed to NL queries",
            plan.table
        ));
    }
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
            if !is_safe_ident(c) {
                return Err(format!("unsafe select column '{c}'"));
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
            if !is_safe_ident(c) {
                return Err(format!("unsafe order_by '{c}'"));
            }
            Some(c.as_str())
        }
        None => None,
    };

    // 4) Validate LIMIT (cap at MAX_LIMIT).
    let limit = plan.limit.unwrap_or(50).clamp(1, MAX_LIMIT);

    let select_sql = select_cols
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Result<Vec<_>, _>>()?
        .join(", ");
    let table_sql = quote_ident(spec.table)?;
    let mut outer_where: Vec<String> = Vec::new();
    let mut params: Vec<Value> = Vec::new();

    // Tenant scope is FORCED as the inner predicate — non-negotiable. $1 always = tenant_id
    // from the authenticated session, never from the LLM plan.
    params.push(Value::from(tenant_id));

    for f in &plan.filters {
        if !spec.columns.contains(&f.column.as_str()) {
            return Err(format!("filter column '{}' not allowed", f.column));
        }
        let col = quote_ident(&f.column)?;
        let op_norm = f.op.trim().to_ascii_lowercase();
        if !ALLOWED_OPS.contains(&op_norm.as_str()) {
            return Err(format!("operator '{}' not allowed", f.op));
        }
        match op_norm.as_str() {
            "is_null" => {
                outer_where.push(format!("{col} IS NULL"));
            }
            "is_not_null" => {
                outer_where.push(format!("{col} IS NOT NULL"));
            }
            "in" => {
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
                outer_where.push(format!("{col} IN ({})", placeholders.join(", ")));
            }
            "like" => {
                let s = f
                    .value
                    .as_str()
                    .ok_or_else(|| "LIKE value must be string".to_string())?;
                let pattern = format!("%{}%", escape_like_literal(s));
                params.push(Value::String(pattern));
                outer_where.push(format!("{col} ILIKE ${} ESCAPE '\\'", params.len()));
            }
            sql_op @ ("=" | "!=" | "<" | "<=" | ">" | ">=") => {
                params.push(f.value.clone());
                outer_where.push(format!("{col} {sql_op} ${}", params.len()));
            }
            other => return Err(format!("unsupported query operator '{other}'")),
        }
    }

    let order_sql = match order {
        Some(c) => format!(
            " ORDER BY {} {}",
            quote_ident(c)?,
            if plan.order_desc { "DESC" } else { "ASC" }
        ),
        None => String::new(),
    };
    let outer_pred = if outer_where.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", outer_where.join(" AND "))
    };
    let inner = format!("SELECT {select_sql} FROM {table_sql} WHERE \"tenant_id\" = $1");
    let sql = format!(
        "SELECT {select_sql} FROM ({inner}) AS \"{TENANT_SCOPE_ALIAS}\"{outer_pred}{order_sql} LIMIT {limit}"
    );

    if !sql.contains("WHERE \"tenant_id\" = $1") {
        return Err("internal error: tenant filter missing from compiled SQL".into());
    }
    if params.first() != Some(&Value::from(tenant_id)) {
        return Err("internal error: $1 is not tenant_id".into());
    }
    if !sql.ends_with(&format!("LIMIT {limit}")) || limit > MAX_LIMIT {
        return Err("internal error: LIMIT cap missing".into());
    }
    // Compiled SQL is placeholders only — never interpolate filter strings into the statement.
    for p in params.iter().skip(1) {
        if let Value::String(s) = p {
            if s.len() >= 8 && sql.contains(s.as_str()) {
                return Err("internal error: filter value leaked into SQL text".into());
            }
        }
    }

    Ok(Compiled { sql, params })
}

fn wrap_rowcap(sql: &str) -> String {
    format!(
        "SELECT * FROM ({}) AS \"{ROWCAP_ALIAS}\" LIMIT {MAX_LIMIT}",
        sql.trim().trim_end_matches(';')
    )
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
    pub tenant_bound: i64,
    pub statement_timeout_ms: u64,
    pub row_cap: i64,
    pub exec_role: String,
    pub plan_sealed: bool,
    pub filters_sanitized: bool,
}

fn empty_plan() -> QueryPlan {
    QueryPlan {
        table: String::new(),
        select: vec![],
        filters: vec![],
        order_by: None,
        order_desc: false,
        limit: None,
    }
}

fn safeguards(
    tenant_id: i64,
    sealed: bool,
    sanitized: bool,
) -> (i64, u64, i64, String, bool, bool) {
    (
        tenant_id,
        READ_ONLY_STATEMENT_TIMEOUT_MS,
        MAX_LIMIT,
        READ_ONLY_ROLE.to_string(),
        sealed,
        sanitized,
    )
}

/// Execute a validated plan. We bind every parameter explicitly through sqlx;
/// the underlying connection is a read-only role with a 15 s statement timeout.
pub async fn execute_plan(
    ro_pool: &PgPool,
    tenant_id: i64,
    plan: QueryPlan,
) -> Result<AskResult, String> {
    let sealed = seal_plan(plan, tenant_id)?;
    execute_sealed(ro_pool, tenant_id, sealed).await
}

async fn execute_sealed(
    ro_pool: &PgPool,
    tenant_id: i64,
    sealed: SealedQueryPlan,
) -> Result<AskResult, String> {
    verify_seal(&sealed, tenant_id)?;
    let start = Instant::now();
    let compiled = compile_plan(&sealed.plan, tenant_id)?;
    let exec_sql = wrap_rowcap(&compiled.sql);

    // SET LOCAL statement_timeout / tenant GUC inside the same transaction as the SELECT
    // so they cannot leak onto the pooled connection and cannot be skipped.
    let mut tx = ro_pool.begin().await.map_err(|e| format!("begin: {e}"))?;

    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("role check: {e}"))?;
    if role != READ_ONLY_ROLE {
        let _ = tx.rollback().await;
        return Err(format!(
            "Ask Weissman queries must run as {READ_ONLY_ROLE}, got '{role}'"
        ));
    }

    sqlx::query(
        "SELECT set_config('statement_timeout', $1, true), \
                set_config('lock_timeout', $2, true), \
                set_config('idle_in_transaction_session_timeout', $3, true), \
                set_config('app.current_tenant_id', $4, true)",
    )
    .bind(READ_ONLY_STATEMENT_TIMEOUT_MS.to_string())
    .bind("5s")
    .bind("30s")
    .bind(tenant_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("set tenant guc: {e}"))?;

    let mut q = sqlx::query(&exec_sql);
    for p in &compiled.params {
        q = bind_json(q, p);
    }
    let rows = q
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("execute: {e}"))?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    let elapsed_ms = start.elapsed().as_millis() as i64;

    let json_rows: Vec<Value> = rows.iter().map(row_to_json).collect();
    let (tenant_bound, statement_timeout_ms, row_cap, exec_role, plan_sealed, filters_sanitized) =
        safeguards(tenant_id, true, true);
    Ok(AskResult {
        plan: sealed.plan,
        sql: compiled.sql,
        row_count: json_rows.len(),
        rows: json_rows,
        elapsed_ms,
        error: None,
        tenant_bound,
        statement_timeout_ms,
        row_cap,
        exec_role,
        plan_sealed,
        filters_sanitized,
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
    let fail = |internal: &str| {
        let (
            tenant_bound,
            statement_timeout_ms,
            row_cap,
            exec_role,
            plan_sealed,
            filters_sanitized,
        ) = safeguards(tenant_id, false, false);
        tracing::warn!(
            target: "nl_query",
            tenant_id,
            error = %internal,
            "Ask Weissman query failed (masked to client)"
        );
        (
            AskResult {
                plan: empty_plan(),
                sql: String::new(),
                rows: vec![],
                row_count: 0,
                elapsed_ms: start.elapsed().as_millis() as i64,
                error: Some(mask_client_error(internal)),
                tenant_bound,
                statement_timeout_ms,
                row_cap,
                exec_role,
                plan_sealed,
                filters_sanitized,
            },
            internal.to_string(),
        )
    };
    let q = question.trim();
    if q.is_empty() {
        let (r, internal) = fail("question is empty");
        audit_query(app_pool, tenant_id, user_id, question, &r, Some(&internal)).await;
        return r;
    }
    if q.len() > 2000 {
        let (r, internal) = fail("question too long (max 2000 chars)");
        audit_query(app_pool, tenant_id, user_id, question, &r, Some(&internal)).await;
        return r;
    }
    if q.chars().any(|c| c == '\0') {
        let (r, internal) = fail("question contains NUL");
        audit_query(app_pool, tenant_id, user_id, question, &r, Some(&internal)).await;
        return r;
    }

    // 1) Optional server-side RAG context (app pool, fixed SQL) then LLM → plan.
    let rag = crate::ask_rag::planner_context(app_pool, tenant_id, q).await;
    let plan_json = match llm_to_plan(q, tenant_id, rag.as_deref()).await {
        Ok(v) => v,
        Err(e) => {
            let (r, internal) = fail(&format!("plan generation failed: {e}"));
            audit_query(app_pool, tenant_id, user_id, question, &r, Some(&internal)).await;
            return r;
        }
    };
    let plan = match ingest_plan_value(plan_json) {
        Ok(p) => p,
        Err(e) => {
            let (r, internal) = fail(&e);
            audit_query(app_pool, tenant_id, user_id, question, &r, Some(&internal)).await;
            return r;
        }
    };
    let sealed = match seal_plan(plan, tenant_id) {
        Ok(s) => s,
        Err(e) => {
            let (r, internal) = fail(&e);
            audit_query(app_pool, tenant_id, user_id, question, &r, Some(&internal)).await;
            return r;
        }
    };

    // 2) Validate + execute on weissman_ro only.
    let (res, internal) = match execute_sealed(ro_pool, tenant_id, sealed).await {
        Ok(mut r) => {
            r.elapsed_ms = start.elapsed().as_millis() as i64;
            (r, None)
        }
        Err(e) => {
            let (r, internal) = fail(&e);
            (r, Some(internal))
        }
    };

    audit_query(
        app_pool,
        tenant_id,
        user_id,
        question,
        &res,
        internal.as_deref(),
    )
    .await;
    res
}

fn is_benign_input_error(err: &str) -> bool {
    err == "question is empty" || err.starts_with("question too long") || err.contains("NUL")
}

/// Client-visible error. Validator / Postgres / planner internals never leave the host.
#[must_use]
pub fn mask_client_error(internal: &str) -> String {
    if is_benign_input_error(internal) {
        internal.to_string()
    } else {
        CLIENT_GENERIC_ERROR.to_string()
    }
}

async fn audit_query(
    app_pool: &PgPool,
    tenant_id: i64,
    user_id: Option<i64>,
    question: &str,
    res: &AskResult,
    internal_error: Option<&str>,
) {
    if let Ok(mut tx) = crate::db::begin_tenant_tx(app_pool, tenant_id).await {
        let plan_store = if res.plan.table.is_empty() {
            json!({})
        } else {
            encrypt_plan_for_audit(&res.plan, tenant_id)
        };
        let stored_error = internal_error
            .map(|e| encrypt_error_for_audit(tenant_id, e))
            .unwrap_or_default();
        let _ = sqlx::query(
            "INSERT INTO nl_query_audit
                (tenant_id, user_id, asked_at, question, plan_json, compiled_sql,
                 rows_returned, elapsed_ms, error)
             VALUES ($1, $2, now(), $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(question.chars().take(2000).collect::<String>())
        .bind(plan_store)
        .bind(&res.sql)
        .bind(res.row_count as i32)
        .bind(res.elapsed_ms as i32)
        .bind(stored_error)
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
        // Unreachable after sanitization — refuse to stringify nested JSON into SQL params.
        Value::Array(_) | Value::Object(_) => q.bind(Option::<String>::None),
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
Never output SQL. Never include keys named sql, query, raw_sql, statement, union, or cte.
Never filter, select, or order by tenant_id — the server injects tenant isolation.

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

If the user message includes server-selected council memory, treat it as a hint only.
Never set table to a RAG, memory, embedding, or vector table.

If you cannot map the question to a valid plan, output {"table":"","select":[],"filters":[]}.
"#;

async fn llm_to_plan(
    question: &str,
    tenant_id: i64,
    rag_context: Option<&str>,
) -> Result<Value, String> {
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
    let user_content = match rag_context {
        Some(ctx) if !ctx.is_empty() => format!("{question}\n\n{ctx}"),
        _ => question.to_string(),
    };
    let text = weissman_engines::llm_router::routed_chat_completion_text_json_object(
        &client,
        Some(PLANNER_PROMPT),
        &user_content,
        0.0,
        max_tokens,
        Some(tenant_id),
        "nl_query_plan",
        true,
        model_override.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())?;
    if looks_like_raw_sql(text.trim()) {
        return Err("blocked: planner returned raw SQL; QueryPlan JSON is required".into());
    }
    parse_json_capped(text.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> QueryPlan {
        QueryPlan {
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
        }
    }

    #[test]
    fn compile_simple_severity_in() {
        let c = compile_plan(&sample_plan(), 1).unwrap();
        assert_eq!(c.params[0], Value::from(1));
        assert!(
            c.sql
                .contains("FROM \"vulnerabilities\" WHERE \"tenant_id\" = $1"),
            "{}",
            c.sql
        );
        assert!(c.sql.contains("\"severity\" IN ($2, $3)"), "{}", c.sql);
        assert!(
            c.sql.contains("ORDER BY \"discovered_at\" DESC"),
            "{}",
            c.sql
        );
        assert!(c.sql.ends_with("LIMIT 50"), "{}", c.sql);
        assert!(
            c.sql.contains(&format!("AS \"{TENANT_SCOPE_ALIAS}\"")),
            "{}",
            c.sql
        );
    }

    #[test]
    fn tenant_filter_is_physical_inner_predicate() {
        let mut plan = sample_plan();
        plan.filters.push(Filter {
            column: "tenant_id".into(),
            op: "=".into(),
            value: json!(999),
        });
        let c = compile_plan(&plan, 7).unwrap();
        assert_eq!(c.params[0], Value::from(7));
        assert!(!c.params.iter().any(|p| p == &Value::from(999)));
        let inner_at = c
            .sql
            .find("WHERE \"tenant_id\" = $1")
            .expect("inner tenant");
        let outer_at = c.sql.find("\"severity\" IN").expect("outer filter");
        assert!(
            inner_at < outer_at,
            "tenant predicate must precede user filters"
        );
        assert_eq!(c.sql.matches("tenant_id").count(), 1);
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
        assert!(c.sql.ends_with(&format!("LIMIT {MAX_LIMIT}")));
        assert_eq!(MAX_LIMIT, 200);
        assert!(wrap_rowcap(&c.sql).ends_with("LIMIT 200"));
    }

    #[test]
    fn rejects_nested_json_filter_values() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![Filter {
                column: "title".into(),
                op: "=".into(),
                value: json!({"$gt": "1 OR 1=1"}),
            }],
            order_by: None,
            order_desc: false,
            limit: None,
        };
        let err = compile_plan(&plan, 1).unwrap_err();
        assert!(err.contains("nested JSON"), "{err}");
    }

    #[test]
    fn like_escapes_wildcards() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![Filter {
                column: "title".into(),
                op: "like".into(),
                value: json!("100%_off"),
            }],
            order_by: None,
            order_desc: false,
            limit: Some(10),
        };
        let c = compile_plan(&plan, 3).unwrap();
        assert_eq!(c.params[0], Value::from(3));
        assert_eq!(c.params[1], Value::String("%100\\%\\_off%".into()));
        assert!(c.sql.contains("ILIKE $2 ESCAPE '\\'"), "{}", c.sql);
        assert!(!c.sql.contains("100%_off"), "{}", c.sql);
    }

    #[test]
    fn blocks_raw_sql_planner_payload() {
        let err = ingest_planner_output("SELECT * FROM users WHERE 1=1").unwrap_err();
        assert!(err.contains("raw SQL"), "{err}");
        let err = ingest_planner_output(
            r#"{"table":"vulnerabilities","sql":"SELECT 1","select":["id"]}"#,
        )
        .unwrap_err();
        assert!(err.contains("blocked QueryPlan payload field"), "{err}");
    }

    #[test]
    fn ingest_strips_unknown_keys_and_sanitizes() {
        let plan = ingest_planner_output(
            r#"{"table":"vulnerabilities","select":["id"],"filters":[{"column":"severity","op":"=","value":"high","extra":1}],"reasoning":"n/a","limit":5}"#,
        )
        .unwrap();
        assert_eq!(plan.table, "vulnerabilities");
        assert_eq!(plan.limit, Some(5));
        assert_eq!(plan.filters[0].value, json!("high"));
    }

    #[test]
    fn seal_binds_plan_to_tenant() {
        let sealed = seal_plan(sample_plan(), 11).unwrap();
        verify_seal(&sealed, 11).unwrap();
        assert!(verify_seal(&sealed, 12).is_err());
        let mut stolen = sealed.clone();
        stolen.tenant_id = 12;
        assert!(verify_seal(&stolen, 12).is_err());
    }

    #[test]
    fn rejects_nul_and_overlong_filter_strings() {
        let plan = QueryPlan {
            table: "vulnerabilities".into(),
            select: vec!["id".into()],
            filters: vec![Filter {
                column: "title".into(),
                op: "=".into(),
                value: Value::String("a\0b".into()),
            }],
            order_by: None,
            order_desc: false,
            limit: None,
        };
        let err = compile_plan(&plan, 1).unwrap_err();
        assert!(err.contains("control"), "{err}");
    }

    #[test]
    fn rejects_unsafe_identifiers() {
        let plan = QueryPlan {
            table: "vulnerabilities;drop".into(),
            select: vec![],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: None,
        };
        assert!(compile_plan(&plan, 1).is_err());
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn restore_env(name: &str, prev: Option<String>) {
        match prev {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }

    #[test]
    fn encrypt_plan_envelope_is_aes_gcm_ciphertext() {
        let _g = env_lock();
        let prev_j = std::env::var("WEISSMAN_JWT_SECRET").ok();
        let prev_v = std::env::var("WEISSMAN_VAULT_KEY").ok();
        std::env::remove_var("WEISSMAN_VAULT_KEY");
        std::env::set_var("WEISSMAN_JWT_SECRET", "test-jwt-secret-16chars");
        let env = encrypt_plan_for_audit(&sample_plan(), 9);
        assert_eq!(env.get("sealed"), Some(&json!(true)));
        let enc = env.get("_enc").and_then(|v| v.as_str()).unwrap_or("");
        assert!(enc.starts_with("wzaqp1:"), "{env}");
        restore_env("WEISSMAN_JWT_SECRET", prev_j);
        restore_env("WEISSMAN_VAULT_KEY", prev_v);
    }

    #[test]
    fn tenant_hmac_keys_differ_and_do_not_verify_across_tenants() {
        let a = seal_plan(sample_plan(), 1).unwrap();
        let b = seal_plan(sample_plan(), 2).unwrap();
        assert_ne!(a.mac, b.mac);
        verify_seal(&a, 1).unwrap();
        verify_seal(&b, 2).unwrap();
        assert!(verify_seal(&a, 2).is_err());
        assert!(verify_seal(&b, 1).is_err());
    }

    #[test]
    fn vault_key_change_invalidates_existing_seal() {
        let _g = env_lock();
        let prev_v = std::env::var("WEISSMAN_VAULT_KEY").ok();
        let prev_i = std::env::var("WEISSMAN_INTEGRATIONS_VAULT_KEY").ok();
        let prev_j = std::env::var("WEISSMAN_JWT_SECRET").ok();
        std::env::remove_var("WEISSMAN_INTEGRATIONS_VAULT_KEY");
        std::env::remove_var("WEISSMAN_JWT_SECRET");
        std::env::set_var("WEISSMAN_VAULT_KEY", "a".repeat(32));
        let sealed = seal_plan(sample_plan(), 4).unwrap();
        verify_seal(&sealed, 4).unwrap();
        std::env::set_var("WEISSMAN_VAULT_KEY", "b".repeat(32));
        assert!(verify_seal(&sealed, 4).is_err());
        restore_env("WEISSMAN_VAULT_KEY", prev_v);
        restore_env("WEISSMAN_INTEGRATIONS_VAULT_KEY", prev_i);
        restore_env("WEISSMAN_JWT_SECRET", prev_j);
    }

    #[test]
    fn rejects_json_depth_bomb_during_stream_parse() {
        let bomb = format!(
            "{}{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        let err = ingest_planner_output(&bomb).unwrap_err();
        assert!(err.contains("nesting limit"), "{err}");
        assert!(parse_json_capped(&bomb).is_err());
    }

    #[test]
    fn rejects_and_or_trees_deeper_than_four() {
        let mut inner = String::from("true");
        for i in 0..5 {
            let key = if i % 2 == 0 { "and" } else { "or" };
            inner = format!(r#"{{"{key}":[{inner}]}}"#);
        }
        let raw = format!(r#"{{"table":"vulnerabilities","filters":[{inner}]}}"#);
        let err = ingest_planner_output(&raw).unwrap_err();
        assert!(err.contains("condition tree"), "{err}");
    }

    #[test]
    fn accepts_four_level_condition_tree_then_fails_shape() {
        let mut inner = String::from("true");
        for i in 0..4 {
            let key = if i % 2 == 0 { "and" } else { "or" };
            inner = format!(r#"{{"{key}":[{inner}]}}"#);
        }
        let raw = format!(r#"{{"table":"vulnerabilities","filters":[{inner}]}}"#);
        assert!(parse_json_capped(&raw).is_ok());
        let err = ingest_planner_output(&raw).unwrap_err();
        assert!(!err.contains("condition tree"), "{err}");
        assert!(!err.contains("nesting limit"), "{err}");
    }

    #[test]
    fn rejects_vector_and_rag_tables() {
        let err =
            ingest_planner_output(r#"{"table":"supreme_council_memory","select":[],"filters":[]}"#)
                .unwrap_err();
        assert!(err.contains("vector/RAG"), "{err}");
        let plan = QueryPlan {
            table: "supreme_council_memory".into(),
            select: vec![],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: Some(5),
        };
        let err = compile_plan(&plan, 1).unwrap_err();
        assert!(err.contains("vector/RAG"), "{err}");
    }

    #[test]
    fn client_never_sees_validator_or_postgres_internals() {
        assert_eq!(
            mask_client_error("column 'password_hash' not allowed on table 'users'"),
            CLIENT_GENERIC_ERROR
        );
        assert_eq!(
            mask_client_error("execute: permission denied for table secrets"),
            CLIENT_GENERIC_ERROR
        );
        assert_eq!(
            mask_client_error("blocked: QueryPlan JSON exceeds nesting limit"),
            CLIENT_GENERIC_ERROR
        );
        assert_eq!(mask_client_error("question is empty"), "question is empty");
        assert_eq!(
            mask_client_error("question too long (max 2000 chars)"),
            "question too long (max 2000 chars)"
        );
    }

    #[test]
    fn unicode_escaped_braces_in_strings_do_not_count_as_nesting() {
        let raw = r#"{"table":"vulnerabilities","select":["id"],"filters":[{"column":"title","op":"=","value":"\u007b\u005b\u007b\u005b\u007b\u005b\u007b\u005b\u007b\u005b\u007b\u005b\u007b"}]} "#;
        let plan = ingest_planner_output(raw.trim()).unwrap();
        assert_eq!(plan.table, "vulnerabilities");
        assert!(plan.filters[0].value.as_str().unwrap().contains('{'));
        assert!(plan.filters[0].value.as_str().unwrap().contains('['));
    }

    #[test]
    fn unicode_escaped_payload_is_not_reparsed_as_structure() {
        let raw = r#""\u007b\"table\":\"vulnerabilities\",\"filters\":[]\u007d""#;
        let v = parse_json_capped(raw).unwrap();
        assert!(v.is_string());
        let err = ingest_planner_output(raw).unwrap_err();
        assert!(
            err.contains("QueryPlan must be a JSON object") || err.contains("raw SQL"),
            "{err}"
        );
    }

    #[test]
    fn hkdf_separates_hmac_and_aes_and_tenants() {
        let _g = env_lock();
        let prev_v = std::env::var("WEISSMAN_VAULT_KEY").ok();
        std::env::set_var("WEISSMAN_VAULT_KEY", "c".repeat(32));
        let h1 = tenant_seal_key(1).unwrap();
        let h2 = tenant_seal_key(2).unwrap();
        let a1 = tenant_aes_key(1).unwrap();
        assert_ne!(h1, h2);
        assert_ne!(h1.as_slice(), a1.as_slice());
        restore_env("WEISSMAN_VAULT_KEY", prev_v);
    }

    #[test]
    fn audit_nonces_differ_without_osrng() {
        warm_ask_crypto();
        let n1 = audit_nonce();
        let n2 = audit_nonce();
        assert_ne!(n1.as_slice(), n2.as_slice());
    }
}
