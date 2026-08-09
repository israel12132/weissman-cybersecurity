//! GraphQL & API Security Engine — world-class, agentless, evidence-only remote assessment.
//!
//! API security is the fastest-growing attack surface and a flagship domain for the top API-security
//! vendors (Salt Security, Noname, Wallarm, Escape, StackHawk, 42Crunch). This engine maps the
//! reachable GraphQL attack surface of a target and grades it against the **OWASP API Security
//! Top-10 (2023)** — then performs attack-path synthesis (toxic combinations) and computes a single
//! 0–100 API exposure score.
//!
//! Honesty contract (identical to the rest of the arsenal): **every finding is backed by a real
//! HTTP observation** — nothing is fabricated. All probes are read-only (queries / safe malformed
//! requests); no mutations are ever executed.
//!
//! Capabilities (all live):
//!   * Endpoint discovery & implementation fingerprinting (Apollo, Hasura, graphql-ruby, graphene,
//!     Yoga, Mercurius, AWS AppSync …).
//!   * Full introspection extraction → schema graph (types/fields/queries/mutations/subscriptions)
//!     and **sensitive-field** detection (password / token / secret / ssn / card …).
//!   * Clairvoyance-style **schema reconstruction** from `did you mean` field suggestions when
//!     introspection is disabled — the capability that separates world-class tooling from a single
//!     introspection POST.
//!   * Denial-of-service surface — alias amplification (amount limit), array batching, and
//!     introspection depth (query-cost limit).
//!   * CSRF surface — query (and mutation) execution over GET / form-urlencoded POST.
//!   * Error-verbosity / debug-mode disclosure (stack traces, DB errors) from safe malformed queries.
//!   * Exposed developer consoles — GraphiQL / GraphQL Playground / Apollo Sandbox / Voyager / Altair.
//!   * Apollo Federation SDL exposure (`_service { sdl }`), APQ / persisted-query bypass, introspection
//!     partial-disable bypass (`__type`), fragment-cycle / field-duplication DoS, directive abuse,
//!     multi-operation requests, `application/graphql` content-type acceptance, Apollo tracing leak,
//!     rate-limit absence (burst probe), auth-differential schema exposure, subscription WebSocket
//!     upgrade (graphql-ws / graphql-transport-ws), GraphQL multipart upload scalar detection,
//!     **BOLA/IDOR surface** probing via schema-derived ID arguments, **@defer / @stream** incremental
//!     delivery abuse, **subscription-over-SSE** transport discovery, **alias-batch BOLA enumeration**,
//!     **CORS / CSWSH** cross-origin abuse, **variable tampering**, **query-cost leaks**, **GET cache
//!     poisoning**, **field-level auth differential**, **interface/union possibleTypes leak**, and an
//!     **OWASP API compliance scorecard** with prioritized remediation output,
//!     **nested BOLA chains** (parent→child ID gates from schema), **persisted-operation /
//!     operationName allowlist bypass**, **Hasura role/header hardening** probes,
//!     **Relay global-ID BOLA**, **connection pagination abuse**, **alias/depth limit fingerprinting**,
//!     **WAF/introspection evasion variants**, and **live sensitive-data exposure** probes.
//!
//! Every operational knob is driven from the live scan request body
//! (`POST /api/command-center/scan` → `EngineRunContext::job_params`). MITRE: T1046 (Network Service
//! Discovery), T1190 (Exploit Public-Facing Application), T1213 (Data from Information Repositories).

use crate::cloud_hunter::{GraphEdge, GraphNode};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{extract_host, header_value, HttpProbe};
use crate::engine_result::{print_result, EngineResult};

#[path = "graphql_attack_supreme.rs"]
mod supreme;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const ENGINE_ID: &str = "graphql_attack";

// ── job_params accessors (top-level or nested `options: { … }`) ───────────────────────────────────

fn jp_lookup<'a>(p: &'a Value, key: &str) -> Option<&'a Value> {
    p.get(key)
        .or_else(|| p.get("options").and_then(|o| o.get(key)))
}

fn jp_bool(p: &Value, key: &str, default: bool) -> bool {
    match jp_lookup(p, key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "enabled"
        ),
        Some(Value::Number(n)) => n.as_i64().map(|x| x != 0).unwrap_or(default),
        _ => default,
    }
}

fn jp_u64(p: &Value, key: &str, default: u64) -> u64 {
    match jp_lookup(p, key) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(default),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(default),
        _ => default,
    }
}

fn jp_str(p: &Value, key: &str) -> Option<String> {
    jp_lookup(p, key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn jp_list(p: &Value, key: &str) -> Vec<String> {
    match jp_lookup(p, key) {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Some(Value::String(s)) => s
            .split([',', '\n'])
            .map(|x| x.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn jp_list_or<'a>(p: &Value, key: &str, default: &[&'a str]) -> Vec<String> {
    let v = jp_list(p, key);
    if v.is_empty() {
        default.iter().map(|s| s.to_string()).collect()
    } else {
        v
    }
}

fn jp_headers(p: &Value, key: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut push_pair = |raw: &str| {
        if let Some((k, v)) = raw.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if !k.is_empty() && !v.is_empty() {
                out.push((k.to_string(), v.to_string()));
            }
        }
    };
    match jp_lookup(p, key) {
        Some(Value::Object(map)) => {
            for (k, v) in map {
                let val = v
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string());
                let k = k.trim();
                if !k.is_empty() && !val.trim().is_empty() {
                    out.push((k.to_string(), val.trim().to_string()));
                }
            }
        }
        Some(Value::Array(arr)) => {
            for v in arr {
                if let Some(s) = v.as_str() {
                    push_pair(s);
                }
            }
        }
        Some(Value::String(s)) => {
            for line in s.split(['\n', ',']) {
                push_pair(line);
            }
        }
        _ => {}
    }
    out
}

// ── Engine configuration ─────────────────────────────────────────────────────────────────────────

const DEFAULT_GRAPHQL_PATHS: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/v1/graphql",
    "/v1/query",
    "/query",
    "/api/v1/graphql",
    "/graphql/console",
    "/graphql-api",
    "/gql",
    "/api/gql",
    "/index.php?graphql",
    "/graphql.php",
    "/subscriptions",
    "/graphiql",
    "/playground",
    "/voyager",
    "/altair",
    "/graphql/playground",
    "/api/graphiql",
];

const FEDERATION_SDL_QUERY: &str = "{ _service { sdl } }";
const INTROSPECTION_BYPASS_QUERY: &str =
    r#"{ __type(name: "Query") { name kind fields { name type { name kind } } } }"#;
const TRACING_INTROSPECTION: &str = r#"query { __schema { queryType { name } } }"#;

const IDE_SIBLING_PATHS: &[&str] = &[
    "/graphiql",
    "/playground",
    "/voyager",
    "/altair",
    "/graphql/playground",
    "/graphql/voyager",
    "/sandbox",
    "/apollo-sandbox",
];

/// Wordlist used for Clairvoyance-style schema reconstruction when introspection is disabled.
const DEFAULT_RECON_FIELDS: &[&str] = &[
    "user",
    "users",
    "me",
    "account",
    "accounts",
    "profile",
    "admin",
    "node",
    "nodes",
    "viewer",
    "customer",
    "customers",
    "order",
    "orders",
    "product",
    "products",
    "payment",
    "payments",
    "invoice",
    "invoices",
    "secret",
    "secrets",
    "token",
    "tokens",
    "apiKey",
    "apiKeys",
    "setting",
    "settings",
    "config",
    "role",
    "roles",
    "permission",
    "permissions",
    "session",
    "sessions",
    "file",
    "files",
    "document",
    "documents",
    "message",
    "messages",
    "transaction",
    "transactions",
    "subscription",
    "wallet",
    "balance",
    "credential",
    "credentials",
    "key",
    "keys",
    "search",
];

/// Mutation field-name substrings that indicate high-impact state change if reachable.
const DANGEROUS_MUTATION_TOKENS: &[&str] = &[
    "delete",
    "remove",
    "destroy",
    "purge",
    "admin",
    "grant",
    "revoke",
    "resetpassword",
    "reset_password",
    "changepassword",
    "change_password",
    "setrole",
    "set_role",
    "impersonate",
    "elevate",
    "createuser",
    "create_user",
    "updateuser",
    "update_user",
    "disable",
    "enable",
    "ban",
    "suspend",
    "transfer",
    "withdraw",
    "refund",
    "execute",
    "runas",
    "sudo",
];

/// Field-name substrings that mark a schema field as exposing sensitive data.
const SENSITIVE_FIELD_TOKENS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "privatekey",
    "private_key",
    "ssn",
    "socialsecurity",
    "creditcard",
    "credit_card",
    "cardnumber",
    "card_number",
    "cvv",
    "cvc",
    "salary",
    "passport",
    "session",
    "hash",
    "credential",
    "mfa",
    "otp",
    "pin",
    "dateofbirth",
    "dob",
];

/// Every operational knob the engine reads from the scan request body.
#[derive(Clone, Debug)]
pub struct GraphqlScanConfig {
    // Scope
    pub probe_introspection: bool,
    pub probe_suggestions: bool,
    pub probe_schema_recon: bool,
    pub probe_batching: bool,
    pub probe_alias_overload: bool,
    pub probe_depth: bool,
    pub probe_csrf_get: bool,
    pub probe_error_verbosity: bool,
    pub probe_ide_exposure: bool,
    pub probe_fingerprint: bool,
    pub probe_federation: bool,
    pub probe_apq: bool,
    pub probe_introspection_bypass: bool,
    pub probe_field_duplication: bool,
    pub probe_fragment_cycle: bool,
    pub probe_directive_abuse: bool,
    pub probe_content_type_graphql: bool,
    pub probe_multi_operation: bool,
    pub probe_tracing: bool,
    pub probe_rate_limit: bool,
    pub probe_auth_differential: bool,
    pub probe_subscription_ws: bool,
    pub probe_upload_scalar: bool,
    pub probe_bola: bool,
    pub probe_defer_stream: bool,
    pub probe_subscription_sse: bool,
    pub probe_bola_batch: bool,
    pub probe_cors: bool,
    pub probe_cswsh: bool,
    pub probe_variable_tampering: bool,
    pub probe_query_cost: bool,
    pub probe_get_cache: bool,
    pub probe_field_auth_diff: bool,
    pub probe_interface_leak: bool,
    pub probe_bola_nested: bool,
    pub probe_operation_allowlist: bool,
    pub probe_hasura_surface: bool,
    pub probe_relay_global_id: bool,
    pub probe_pagination_abuse: bool,
    pub probe_limit_fingerprint: bool,
    pub probe_waf_evasion: bool,
    pub probe_live_data_leak: bool,
    pub probe_get_batch: bool,
    pub probe_ws_query: bool,
    pub probe_union_fragment_bola: bool,
    pub probe_dual_auth_bola: bool,
    pub probe_custom_scalar_leak: bool,
    // Surface
    pub graphql_paths: Vec<String>,
    pub recon_fields: Vec<String>,
    pub max_recon_fields: usize,
    pub alias_count: u64,
    pub batch_count: u64,
    pub depth_levels: u64,
    pub field_duplication_count: u64,
    pub burst_count: u64,
    pub fragment_spread_depth: u64,
    pub bola_test_ids: Vec<String>,
    pub bola_id_range_start: u64,
    pub bola_id_range_end: u64,
    pub max_bola_probes: usize,
    pub bola_batch_size: u64,
    // Posture
    pub attack_path_synthesis: bool,
    // Transport
    pub timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub max_concurrency: usize,
    pub verify_tls: bool,
    pub follow_redirects: bool,
    pub user_agent: Option<String>,
    pub bearer_token: Option<String>,
    pub api_key: Option<String>,
    pub api_key_header: Option<String>,
    pub cookie: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    // Output
    pub min_severity: String,
    pub dedupe_findings: bool,
    pub max_findings: usize,
    pub tags: Vec<String>,
    pub dry_run: bool,
    pub emit_metrics: bool,
}

impl Default for GraphqlScanConfig {
    fn default() -> Self {
        Self {
            probe_introspection: true,
            probe_suggestions: true,
            probe_schema_recon: true,
            probe_batching: true,
            probe_alias_overload: true,
            probe_depth: true,
            probe_csrf_get: true,
            probe_error_verbosity: true,
            probe_ide_exposure: true,
            probe_fingerprint: true,
            probe_federation: true,
            probe_apq: true,
            probe_introspection_bypass: true,
            probe_field_duplication: true,
            probe_fragment_cycle: true,
            probe_directive_abuse: true,
            probe_content_type_graphql: true,
            probe_multi_operation: true,
            probe_tracing: true,
            probe_rate_limit: true,
            probe_auth_differential: true,
            probe_subscription_ws: true,
            probe_upload_scalar: true,
            probe_bola: true,
            probe_defer_stream: true,
            probe_subscription_sse: true,
            probe_bola_batch: true,
            probe_cors: true,
            probe_cswsh: true,
            probe_variable_tampering: true,
            probe_query_cost: true,
            probe_get_cache: true,
            probe_field_auth_diff: true,
            probe_interface_leak: true,
            probe_bola_nested: true,
            probe_operation_allowlist: true,
            probe_hasura_surface: true,
            probe_relay_global_id: true,
            probe_pagination_abuse: true,
            probe_limit_fingerprint: true,
            probe_waf_evasion: true,
            probe_live_data_leak: true,
            probe_get_batch: true,
            probe_ws_query: true,
            probe_union_fragment_bola: true,
            probe_dual_auth_bola: true,
            probe_custom_scalar_leak: true,
            graphql_paths: DEFAULT_GRAPHQL_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            recon_fields: DEFAULT_RECON_FIELDS.iter().map(|s| s.to_string()).collect(),
            max_recon_fields: 48,
            alias_count: 100,
            batch_count: 10,
            depth_levels: 12,
            field_duplication_count: 200,
            burst_count: 15,
            fragment_spread_depth: 8,
            bola_test_ids: vec!["1".into(), "2".into(), "100".into()],
            bola_id_range_start: 0,
            bola_id_range_end: 0,
            max_bola_probes: 8,
            bola_batch_size: 5,
            attack_path_synthesis: true,
            timeout_ms: 9000,
            connect_timeout_ms: 4000,
            max_concurrency: 12,
            verify_tls: false,
            follow_redirects: false,
            user_agent: None,
            bearer_token: None,
            api_key: None,
            api_key_header: None,
            cookie: None,
            extra_headers: Vec::new(),
            min_severity: "info".to_string(),
            dedupe_findings: true,
            max_findings: 500,
            tags: Vec::new(),
            dry_run: false,
            emit_metrics: true,
        }
    }
}

impl GraphqlScanConfig {
    fn from_params(p: &Value) -> Self {
        let d = Self::default();
        let mut extra_headers = jp_headers(p, "extra_headers");
        if let Some(token) = jp_str(p, "bearer_token") {
            if !extra_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            {
                extra_headers.push(("Authorization".to_string(), format!("Bearer {token}")));
            }
        }
        if let Some(key) = jp_str(p, "api_key") {
            let hdr = jp_str(p, "api_key_header").unwrap_or_else(|| "X-API-Key".to_string());
            if !extra_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(&hdr))
            {
                extra_headers.push((hdr, key));
            }
        }
        if let Some(cookie) = jp_str(p, "cookie") {
            if !extra_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            {
                extra_headers.push(("Cookie".to_string(), cookie));
            }
        }
        crate::ws_intelligence_bus::apply_intelligence_artifacts_to_headers(p, &mut extra_headers);
        Self {
            probe_introspection: jp_bool(p, "probe_introspection", d.probe_introspection),
            probe_suggestions: jp_bool(p, "probe_suggestions", d.probe_suggestions),
            probe_schema_recon: jp_bool(p, "probe_schema_recon", d.probe_schema_recon),
            probe_batching: jp_bool(p, "probe_batching", d.probe_batching),
            probe_alias_overload: jp_bool(p, "probe_alias_overload", d.probe_alias_overload),
            probe_depth: jp_bool(p, "probe_depth", d.probe_depth),
            probe_csrf_get: jp_bool(p, "probe_csrf_get", d.probe_csrf_get),
            probe_error_verbosity: jp_bool(p, "probe_error_verbosity", d.probe_error_verbosity),
            probe_ide_exposure: jp_bool(p, "probe_ide_exposure", d.probe_ide_exposure),
            probe_fingerprint: jp_bool(p, "probe_fingerprint", d.probe_fingerprint),
            probe_federation: jp_bool(p, "probe_federation", d.probe_federation),
            probe_apq: jp_bool(p, "probe_apq", d.probe_apq),
            probe_introspection_bypass: jp_bool(
                p,
                "probe_introspection_bypass",
                d.probe_introspection_bypass,
            ),
            probe_field_duplication: jp_bool(
                p,
                "probe_field_duplication",
                d.probe_field_duplication,
            ),
            probe_fragment_cycle: jp_bool(p, "probe_fragment_cycle", d.probe_fragment_cycle),
            probe_directive_abuse: jp_bool(p, "probe_directive_abuse", d.probe_directive_abuse),
            probe_content_type_graphql: jp_bool(
                p,
                "probe_content_type_graphql",
                d.probe_content_type_graphql,
            ),
            probe_multi_operation: jp_bool(p, "probe_multi_operation", d.probe_multi_operation),
            probe_tracing: jp_bool(p, "probe_tracing", d.probe_tracing),
            probe_rate_limit: jp_bool(p, "probe_rate_limit", d.probe_rate_limit),
            probe_auth_differential: jp_bool(
                p,
                "probe_auth_differential",
                d.probe_auth_differential,
            ),
            probe_subscription_ws: jp_bool(p, "probe_subscription_ws", d.probe_subscription_ws),
            probe_upload_scalar: jp_bool(p, "probe_upload_scalar", d.probe_upload_scalar),
            probe_bola: jp_bool(p, "probe_bola", d.probe_bola),
            probe_defer_stream: jp_bool(p, "probe_defer_stream", d.probe_defer_stream),
            probe_subscription_sse: jp_bool(p, "probe_subscription_sse", d.probe_subscription_sse),
            probe_bola_batch: jp_bool(p, "probe_bola_batch", d.probe_bola_batch),
            probe_cors: jp_bool(p, "probe_cors", d.probe_cors),
            probe_cswsh: jp_bool(p, "probe_cswsh", d.probe_cswsh),
            probe_variable_tampering: jp_bool(
                p,
                "probe_variable_tampering",
                d.probe_variable_tampering,
            ),
            probe_query_cost: jp_bool(p, "probe_query_cost", d.probe_query_cost),
            probe_get_cache: jp_bool(p, "probe_get_cache", d.probe_get_cache),
            probe_field_auth_diff: jp_bool(p, "probe_field_auth_diff", d.probe_field_auth_diff),
            probe_interface_leak: jp_bool(p, "probe_interface_leak", d.probe_interface_leak),
            probe_bola_nested: jp_bool(p, "probe_bola_nested", d.probe_bola_nested),
            probe_operation_allowlist: jp_bool(
                p,
                "probe_operation_allowlist",
                d.probe_operation_allowlist,
            ),
            probe_hasura_surface: jp_bool(p, "probe_hasura_surface", d.probe_hasura_surface),
            probe_relay_global_id: jp_bool(p, "probe_relay_global_id", d.probe_relay_global_id),
            probe_pagination_abuse: jp_bool(p, "probe_pagination_abuse", d.probe_pagination_abuse),
            probe_limit_fingerprint: jp_bool(
                p,
                "probe_limit_fingerprint",
                d.probe_limit_fingerprint,
            ),
            probe_waf_evasion: jp_bool(p, "probe_waf_evasion", d.probe_waf_evasion),
            probe_live_data_leak: jp_bool(p, "probe_live_data_leak", d.probe_live_data_leak),
            probe_get_batch: jp_bool(p, "probe_get_batch", d.probe_get_batch),
            probe_ws_query: jp_bool(p, "probe_ws_query", d.probe_ws_query),
            probe_union_fragment_bola: jp_bool(
                p,
                "probe_union_fragment_bola",
                d.probe_union_fragment_bola,
            ),
            probe_dual_auth_bola: jp_bool(p, "probe_dual_auth_bola", d.probe_dual_auth_bola),
            probe_custom_scalar_leak: jp_bool(
                p,
                "probe_custom_scalar_leak",
                d.probe_custom_scalar_leak,
            ),
            graphql_paths: jp_list_or(p, "graphql_paths", DEFAULT_GRAPHQL_PATHS),
            recon_fields: {
                let mut base: Vec<String> =
                    DEFAULT_RECON_FIELDS.iter().map(|s| s.to_string()).collect();
                base.extend(jp_list(p, "recon_fields"));
                base.sort();
                base.dedup();
                base
            },
            max_recon_fields: jp_u64(p, "max_recon_fields", d.max_recon_fields as u64).clamp(1, 500)
                as usize,
            alias_count: jp_u64(p, "alias_count", d.alias_count).clamp(2, 5000),
            batch_count: jp_u64(p, "batch_count", d.batch_count).clamp(2, 1000),
            depth_levels: jp_u64(p, "depth_levels", d.depth_levels).clamp(2, 60),
            field_duplication_count: jp_u64(
                p,
                "field_duplication_count",
                d.field_duplication_count,
            )
            .clamp(2, 5000),
            burst_count: jp_u64(p, "burst_count", d.burst_count).clamp(2, 100),
            fragment_spread_depth: jp_u64(p, "fragment_spread_depth", d.fragment_spread_depth)
                .clamp(2, 40),
            bola_test_ids: {
                let mut ids = jp_list(p, "bola_test_ids");
                if ids.is_empty() {
                    ids = d.bola_test_ids.clone();
                }
                ids
            },
            bola_id_range_start: jp_u64(p, "bola_id_range_start", d.bola_id_range_start),
            bola_id_range_end: jp_u64(p, "bola_id_range_end", d.bola_id_range_end),
            max_bola_probes: jp_u64(p, "max_bola_probes", d.max_bola_probes as u64).clamp(1, 32)
                as usize,
            bola_batch_size: jp_u64(p, "bola_batch_size", d.bola_batch_size).clamp(2, 32),
            attack_path_synthesis: jp_bool(p, "attack_path_synthesis", d.attack_path_synthesis),
            timeout_ms: jp_u64(p, "timeout_ms", d.timeout_ms).clamp(500, 60_000),
            connect_timeout_ms: jp_u64(p, "connect_timeout_ms", d.connect_timeout_ms)
                .clamp(200, 30_000),
            max_concurrency: jp_u64(p, "max_concurrency", d.max_concurrency as u64).clamp(1, 64)
                as usize,
            verify_tls: jp_bool(p, "verify_tls", d.verify_tls),
            follow_redirects: jp_bool(p, "follow_redirects", d.follow_redirects),
            user_agent: jp_str(p, "user_agent"),
            bearer_token: jp_str(p, "bearer_token"),
            api_key: jp_str(p, "api_key"),
            api_key_header: jp_str(p, "api_key_header"),
            cookie: jp_str(p, "cookie"),
            extra_headers,
            min_severity: jp_str(p, "min_severity").unwrap_or(d.min_severity),
            dedupe_findings: jp_bool(p, "dedupe_findings", d.dedupe_findings),
            max_findings: jp_u64(p, "max_findings", d.max_findings as u64).clamp(1, 5000) as usize,
            tags: jp_list(p, "tags"),
            dry_run: jp_bool(p, "dry_run", d.dry_run),
            emit_metrics: jp_bool(p, "emit_metrics", d.emit_metrics),
        }
    }

    fn has_auth_credentials(&self) -> bool {
        self.bearer_token.is_some()
            || self.api_key.is_some()
            || self.cookie.is_some()
            || self.extra_headers.iter().any(|(k, _)| is_auth_header(k))
    }

    fn enabled_components(&self) -> u32 {
        [
            self.probe_introspection,
            self.probe_suggestions,
            self.probe_schema_recon,
            self.probe_batching,
            self.probe_alias_overload,
            self.probe_depth,
            self.probe_csrf_get,
            self.probe_error_verbosity,
            self.probe_ide_exposure,
            self.probe_fingerprint,
            self.probe_federation,
            self.probe_apq,
            self.probe_introspection_bypass,
            self.probe_field_duplication,
            self.probe_fragment_cycle,
            self.probe_directive_abuse,
            self.probe_content_type_graphql,
            self.probe_multi_operation,
            self.probe_tracing,
            self.probe_rate_limit,
            self.probe_auth_differential,
            self.probe_subscription_ws,
            self.probe_upload_scalar,
            self.probe_bola,
            self.probe_defer_stream,
            self.probe_subscription_sse,
            self.probe_bola_batch,
            self.probe_cors,
            self.probe_cswsh,
            self.probe_variable_tampering,
            self.probe_query_cost,
            self.probe_get_cache,
            self.probe_field_auth_diff,
            self.probe_interface_leak,
            self.probe_bola_nested,
            self.probe_operation_allowlist,
            self.probe_hasura_surface,
            self.probe_relay_global_id,
            self.probe_pagination_abuse,
            self.probe_limit_fingerprint,
            self.probe_waf_evasion,
            self.probe_live_data_leak,
            self.probe_get_batch,
            self.probe_ws_query,
            self.probe_union_fragment_bola,
            self.probe_dual_auth_bola,
            self.probe_custom_scalar_leak,
        ]
        .iter()
        .filter(|x| **x)
        .count() as u32
    }

    /// Merge explicit BOLA test IDs with an optional numeric range (capped for safety).
    fn effective_bola_test_ids(&self) -> Vec<String> {
        let mut ids = self.bola_test_ids.clone();
        if self.bola_id_range_end > self.bola_id_range_start {
            let span = self.bola_id_range_end - self.bola_id_range_start;
            let cap = span.min(32);
            for i in 0..=cap {
                ids.push((self.bola_id_range_start + i).to_string());
            }
        }
        ids.sort();
        ids.dedup();
        ids.truncate(48);
        ids
    }
}

fn is_auth_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "x-api-key" | "x-auth-token" | "api-key"
    )
}

// ── HTTP / severity helpers ─────────────────────────────────────────────────────────────────────

fn build_client(cfg: &GraphqlScanConfig) -> reqwest::Client {
    let mut headers = HeaderMap::new();
    for (k, v) in &cfg.extra_headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }
    let redirect = if cfg.follow_redirects {
        reqwest::redirect::Policy::limited(3)
    } else {
        reqwest::redirect::Policy::none()
    };
    reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms))
        .connect_timeout(Duration::from_millis(cfg.connect_timeout_ms))
        .danger_accept_invalid_certs(
            !cfg.verify_tls || weissman_core::tls_policy::danger_accept_invalid_certs(),
        )
        .user_agent(
            cfg.user_agent
                .clone()
                .unwrap_or_else(|| "Weissman-GraphQLSec/2.0".to_string()),
        )
        .default_headers(headers)
        .redirect(redirect)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn probe_to_http(resp: reqwest::Response) -> HttpProbe {
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 262_144 {
        body[..262_144].to_string()
    } else {
        body
    };
    HttpProbe {
        status,
        headers,
        body,
        final_url,
    }
}

async fn post_json(client: &reqwest::Client, url: &str, payload: &Value) -> Option<HttpProbe> {
    let resp = client.post(url).json(payload).send().await.ok()?;
    Some(probe_to_http(resp).await)
}

async fn post_json_ct(
    client: &reqwest::Client,
    url: &str,
    payload: &Value,
    content_type: &str,
) -> Option<HttpProbe> {
    let body = serde_json::to_string(payload).ok()?;
    let resp = client
        .post(url)
        .header("content-type", content_type)
        .body(body)
        .send()
        .await
        .ok()?;
    Some(probe_to_http(resp).await)
}

async fn post_form(client: &reqwest::Client, url: &str, body: String) -> Option<HttpProbe> {
    let resp = client
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .ok()?;
    Some(probe_to_http(resp).await)
}

async fn get(client: &reqwest::Client, url: &str) -> Option<HttpProbe> {
    let resp = client.get(url).send().await.ok()?;
    Some(probe_to_http(resp).await)
}

async fn get_with_accept(client: &reqwest::Client, url: &str, accept: &str) -> Option<HttpProbe> {
    let resp = client.get(url).header("accept", accept).send().await.ok()?;
    Some(probe_to_http(resp).await)
}

async fn post_sse(client: &reqwest::Client, url: &str, payload: &Value) -> Option<HttpProbe> {
    let resp = client
        .post(url)
        .header("accept", "text/event-stream")
        .json(payload)
        .send()
        .await
        .ok()?;
    Some(probe_to_http(resp).await)
}

async fn post_json_with_headers(
    client: &reqwest::Client,
    url: &str,
    payload: &Value,
    extra: &[(&str, &str)],
) -> Option<HttpProbe> {
    let mut req = client.post(url).json(payload);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.ok()?;
    Some(probe_to_http(resp).await)
}

async fn post_graphql_ct(client: &reqwest::Client, url: &str, document: &str) -> Option<HttpProbe> {
    let resp = client
        .post(url)
        .header("content-type", "application/graphql")
        .body(document.to_string())
        .send()
        .await
        .ok()?;
    Some(probe_to_http(resp).await)
}

async fn post_multipart_graphql(client: &reqwest::Client, url: &str) -> Option<HttpProbe> {
    let boundary = "weissmanGraphqlBoundary";
    let ops = r#"{"query":"{ __typename }"}"#;
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n{ops}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"map\"\r\n\r\n{{}}\r\n--{boundary}--\r\n"
    );
    let resp = client
        .post(url)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
        .ok()?;
    Some(probe_to_http(resp).await)
}

fn random_ws_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut buf = [0u8; 16];
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        ^ (buf.as_ptr() as u64);
    let mut x = seed | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xff) as u8;
    }
    openssl::base64::encode_block(&buf)
}

fn ws_accept(key: &str) -> String {
    use openssl::sha::Sha1;
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = hasher.finish();
    openssl::base64::encode_block(&digest)
}

fn http_to_ws_url(http_url: &str) -> String {
    if let Some(rest) = http_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = http_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        http_url.to_string()
    }
}

fn field_duplication_query(n: u64) -> String {
    let mut q = String::from("query {");
    for _ in 0..n {
        q.push_str(" __typename");
    }
    q.push_str(" }");
    q
}

fn fragment_cycle_query(_depth: u64) -> String {
    "query { ...FragA } fragment FragA on Query { ...FragB __typename } fragment FragB on Query { ...FragA __typename }".to_string()
}

fn site_origin(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| {
            let scheme = u.scheme();
            let host = u.host_str()?;
            Some(format!(
                "{}://{}{}",
                scheme,
                host,
                u.port().map(|p| format!(":{p}")).unwrap_or_default()
            ))
        })
        .unwrap_or_else(|| url.trim_end_matches('/').to_string())
}

fn directive_abuse_query(repeats: u64) -> String {
    let mut q = String::from("query { __typename");
    for _ in 0..repeats {
        q.push_str(" @include(if: true)");
    }
    q.push_str(" }");
    q
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

#[allow(clippy::too_many_arguments)]
fn finding(
    component: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    owasp: &str,
    description: &str,
    url: &str,
    target: &str,
    vuln_class: &str,
    remediation: &str,
) -> Value {
    json!({
        "type": ENGINE_ID,
        "engine_id": ENGINE_ID,
        "component": component,
        "title": title,
        "severity": severity,
        "mitre_attack": mitre,
        "owasp_api": owasp,
        "vuln_class": vuln_class,
        "description": description,
        "url": url,
        "target": target,
        "category": "api_security",
        "remediation": remediation,
        "compliance": ["OWASP-API-Top10-2023", "SOC2:CC6.1", "ISO27001:A.14", "PCI:6.5"],
    })
}

/// Does this HTTP response look like it came from a GraphQL engine?
fn looks_like_graphql(p: &HttpProbe) -> bool {
    if let Ok(v) = serde_json::from_str::<Value>(&p.body) {
        if v.get("data").is_some() || v.get("errors").is_some() {
            return true;
        }
    }
    let bl = p.body.to_ascii_lowercase();
    bl.contains("must provide query string")
        || bl.contains("get query missing")
        || bl.contains("cannot query field")
        || bl.contains("must provide an operation")
        || bl.contains("graphql")
            && (bl.contains("syntax error") || bl.contains("query") || bl.contains("\"errors\""))
}

// ── Introspection / schema parsing ───────────────────────────────────────────────────────────────

const INTROSPECTION_QUERY: &str = r#"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name } } } }"#;

/// Richer introspection — Query-root field arguments for BOLA / IDOR surface mapping.
const INTROSPECTION_ARGS_QUERY: &str = r#"query { __schema { queryType { fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } } } } }"#;

/// One-level nested introspection — parent Query field → child fields with ID args (nested BOLA).
const INTROSPECTION_NESTED_ARGS_QUERY: &str = r#"query { __schema { queryType { fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } type { kind name ofType { kind name ofType { kind name fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } } } fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } } } } } } }"#;

const INTERFACE_INTROSPECTION_QUERY: &str =
    r#"query { __schema { types { name kind possibleTypes { name } } } }"#;

const CORS_PROBE_ORIGIN: &str = "https://weissman-cors-probe.invalid";
const CSWSH_PROBE_ORIGIN: &str = "https://evil.weissman-cswsh.invalid";

const FIELD_AUTH_ROOT_PROBES: &[&str] = &[
    "{ me { __typename id } }",
    "{ viewer { __typename id } }",
    "{ currentUser { __typename id } }",
    "{ account { __typename id } }",
    "{ profile { __typename id } }",
];

/// Query-root field names that commonly accept object IDs (fallback when args introspection fails).
const BOLA_HEURISTIC_FIELDS: &[&str] = &[
    "user",
    "users",
    "node",
    "account",
    "order",
    "customer",
    "profile",
    "invoice",
    "document",
    "message",
    "payment",
    "transaction",
    "session",
    "file",
    "project",
    "team",
    "member",
    "userById",
    "getUser",
    "getOrder",
    "getAccount",
    "viewer",
    "me",
];

/// Argument names that indicate an object identifier.
const BOLA_ID_ARG_TOKENS: &[&str] = &[
    "id",
    "uuid",
    "guid",
    "userid",
    "user_id",
    "orderid",
    "order_id",
    "accountid",
    "account_id",
    "nodeid",
    "node_id",
    "key",
    "ref",
    "slug",
];

#[derive(Clone, Debug)]
struct IdAccessor {
    field: String,
    arg: String,
    numeric: bool,
}

/// Parent Query field with ID arg → nested object field with ID arg (two-hop BOLA).
#[derive(Clone, Debug)]
struct NestedIdChain {
    root: IdAccessor,
    nested: IdAccessor,
}

/// Common operation names probed for allowlist / persisted-operation bypass surfaces.
const OPERATION_ALLOWLIST_NAMES: &[&str] = &[
    "IntrospectionQuery",
    "GetUser",
    "GetUsers",
    "Me",
    "Viewer",
    "Login",
    "Search",
    "Query",
    "Mutation",
    "HealthCheck",
    "GetOrder",
    "GetAccount",
];

#[derive(Default)]
struct SchemaSummary {
    types: usize,
    object_types: usize,
    query_fields: usize,
    mutation_fields: usize,
    has_subscriptions: bool,
    sensitive_fields: Vec<String>,
    dangerous_mutations: Vec<String>,
    #[allow(dead_code)] // collected during schema parse; not read after refactor
    id_accessors: Vec<IdAccessor>,
    graph: Vec<Value>,
}

fn parse_schema(body: &str) -> Option<SchemaSummary> {
    let v: Value = serde_json::from_str(body).ok()?;
    let schema = v.get("data")?.get("__schema")?;
    let types = schema.get("types")?.as_array()?;
    let query_type = schema
        .get("queryType")
        .and_then(|q| q.get("name"))
        .and_then(Value::as_str);
    let mutation_type = schema
        .get("mutationType")
        .and_then(|q| q.get("name"))
        .and_then(Value::as_str);
    let mut s = SchemaSummary {
        has_subscriptions: schema
            .get("subscriptionType")
            .map(|x| !x.is_null())
            .unwrap_or(false),
        ..Default::default()
    };
    for t in types {
        let name = t.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() || name.starts_with("__") {
            continue;
        }
        s.types += 1;
        let kind = t.get("kind").and_then(Value::as_str).unwrap_or("");
        let fields = t.get("fields").and_then(Value::as_array);
        if kind == "OBJECT" {
            s.object_types += 1;
        }
        let field_names: Vec<String> = fields
            .map(|f| {
                f.iter()
                    .filter_map(|x| x.get("name").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if Some(name) == query_type {
            s.query_fields = field_names.len();
        }
        if Some(name) == mutation_type {
            s.mutation_fields = field_names.len();
            for fname in &field_names {
                let fl = fname.to_ascii_lowercase();
                if DANGEROUS_MUTATION_TOKENS.iter().any(|tok| fl.contains(tok)) {
                    s.dangerous_mutations.push(fname.clone());
                }
            }
        }
        for fname in &field_names {
            let fl = fname.to_ascii_lowercase();
            if SENSITIVE_FIELD_TOKENS.iter().any(|tok| fl.contains(tok)) {
                s.sensitive_fields.push(format!("{}.{}", name, fname));
            }
        }
        if s.graph.len() < 60 {
            s.graph.push(json!({
                "type": name,
                "kind": kind,
                "fields": field_names.iter().take(12).cloned().collect::<Vec<_>>(),
                "field_count": field_names.len(),
            }));
        }
    }
    s.sensitive_fields.sort();
    s.sensitive_fields.dedup();
    s.sensitive_fields.truncate(40);
    s.dangerous_mutations.sort();
    s.dangerous_mutations.dedup();
    s.dangerous_mutations.truncate(24);
    Some(s)
}

fn scalar_is_numeric(kind: &str, name: &str) -> bool {
    matches!(kind, "INT" | "FLOAT")
        || name.eq_ignore_ascii_case("Int")
        || name.eq_ignore_ascii_case("Float")
}

fn type_is_id_like(kind: &str, name: &str) -> bool {
    kind == "SCALAR"
        && (name.eq_ignore_ascii_case("ID")
            || name.eq_ignore_ascii_case("UUID")
            || name.eq_ignore_ascii_case("String")
            || name.eq_ignore_ascii_case("Int")
            || scalar_is_numeric(kind, name))
}

/// Walk introspection output and collect Query-root fields that accept ID-like arguments.
fn parse_id_accessors(body: &str) -> Vec<IdAccessor> {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let fields = v
        .get("data")
        .and_then(|d| d.get("__schema"))
        .and_then(|s| s.get("queryType"))
        .and_then(|q| q.get("fields"))
        .and_then(Value::as_array);
    let Some(fields) = fields else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for f in fields {
        let fname = f.get("name").and_then(Value::as_str).unwrap_or("");
        if fname.is_empty() {
            continue;
        }
        let args = f.get("args").and_then(Value::as_array);
        let Some(args) = args else { continue };
        for arg in args {
            let aname = arg.get("name").and_then(Value::as_str).unwrap_or("");
            if aname.is_empty() {
                continue;
            }
            let al = aname.to_ascii_lowercase();
            if !BOLA_ID_ARG_TOKENS.iter().any(|t| al.contains(t)) {
                continue;
            }
            let ty = arg.get("type");
            let (kind, name) = resolve_type(ty);
            if type_is_id_like(&kind, &name) {
                out.push(IdAccessor {
                    field: fname.to_string(),
                    arg: aname.to_string(),
                    numeric: scalar_is_numeric(&kind, &name),
                });
            }
        }
    }
    out.sort_by(|a, b| a.field.cmp(&b.field));
    out.dedup_by(|a, b| a.field == b.field && a.arg == b.arg);
    out
}

fn resolve_type(ty: Option<&Value>) -> (String, String) {
    let mut cur = ty;
    loop {
        let Some(t) = cur else {
            return (String::new(), String::new());
        };
        let kind = t.get("kind").and_then(Value::as_str).unwrap_or("");
        let name = t.get("name").and_then(Value::as_str).unwrap_or("");
        if kind == "NON_NULL" || kind == "LIST" {
            cur = t.get("ofType");
            continue;
        }
        return (kind.to_string(), name.to_string());
    }
}

fn graphql_arg_literal(numeric: bool, id: &str) -> String {
    if numeric {
        id.chars()
            .all(|c| c.is_ascii_digit() || c == '-')
            .then(|| id.to_string())
            .unwrap_or_else(|| "1".to_string())
    } else {
        format!("\"{}\"", id.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn build_bola_query(accessor: &IdAccessor, test_id: &str) -> String {
    let lit = graphql_arg_literal(accessor.numeric, test_id);
    format!(
        "query {{ {}({}: {}) {{ __typename id }} }}",
        accessor.field, accessor.arg, lit
    )
}

/// Alias-batch BOLA: enumerate multiple IDs in a single operation (rate-limit bypass).
fn build_bola_batch_query(accessor: &IdAccessor, ids: &[String]) -> String {
    let mut q = String::from("query {");
    for (i, id) in ids.iter().enumerate() {
        let lit = graphql_arg_literal(accessor.numeric, id);
        q.push_str(&format!(
            " b{i}:{}({}: {}) {{ __typename id }}",
            accessor.field, accessor.arg, lit
        ));
    }
    q.push_str(" }");
    q
}

fn count_bola_batch_hits(body: &str, _accessor: &IdAccessor, batch_size: usize) -> usize {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return 0;
    };
    let Some(data) = v.get("data").and_then(Value::as_object) else {
        return 0;
    };
    data.keys()
        .filter(|k| k.starts_with('b') && data.get(*k).map_or(false, |n| n.is_object()))
        .take(batch_size)
        .count()
}

fn unwrap_object_fields(ty: Option<&Value>) -> Option<&Vec<Value>> {
    let mut cur = ty?;
    for _ in 0..6 {
        let kind = cur.get("kind").and_then(Value::as_str).unwrap_or("");
        if kind == "NON_NULL" || kind == "LIST" {
            cur = cur.get("ofType")?;
            continue;
        }
        if kind == "OBJECT" {
            return cur.get("fields").and_then(Value::as_array);
        }
        return None;
    }
    None
}

fn field_id_accessor(field: &Value) -> Option<IdAccessor> {
    let fname = field.get("name").and_then(Value::as_str)?;
    let args = field.get("args").and_then(Value::as_array)?;
    for arg in args {
        let aname = arg.get("name").and_then(Value::as_str).unwrap_or("");
        if aname.is_empty() {
            continue;
        }
        let al = aname.to_ascii_lowercase();
        if !BOLA_ID_ARG_TOKENS.iter().any(|t| al.contains(t)) {
            continue;
        }
        let (kind, name) = resolve_type(arg.get("type"));
        if type_is_id_like(&kind, &name) {
            return Some(IdAccessor {
                field: fname.to_string(),
                arg: aname.to_string(),
                numeric: scalar_is_numeric(&kind, &name),
            });
        }
    }
    None
}

fn parse_nested_id_chains(body: &str) -> Vec<NestedIdChain> {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let root_fields = v
        .get("data")
        .and_then(|d| d.get("__schema"))
        .and_then(|s| s.get("queryType"))
        .and_then(|q| q.get("fields"))
        .and_then(Value::as_array);
    let Some(root_fields) = root_fields else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for rf in root_fields {
        let Some(root_acc) = field_id_accessor(rf) else {
            continue;
        };
        let nested_fields = rf.get("type").and_then(|t| unwrap_object_fields(Some(t)));
        let Some(nested_fields) = nested_fields else {
            continue;
        };
        for nf in nested_fields {
            if let Some(nested_acc) = field_id_accessor(nf) {
                out.push(NestedIdChain {
                    root: root_acc.clone(),
                    nested: nested_acc,
                });
            }
        }
    }
    out.sort_by(|a, b| {
        a.root
            .field
            .cmp(&b.root.field)
            .then(a.nested.field.cmp(&b.nested.field))
    });
    out.dedup_by(|a, b| a.root.field == b.root.field && a.nested.field == b.nested.field);
    out.truncate(16);
    out
}

fn build_nested_bola_query(chain: &NestedIdChain, root_id: &str, nested_id: &str) -> String {
    let r = graphql_arg_literal(chain.root.numeric, root_id);
    let n = graphql_arg_literal(chain.nested.numeric, nested_id);
    format!(
        "query {{ {}({}: {}) {{ {}({}: {}) {{ __typename id }} }} }}",
        chain.root.field, chain.root.arg, r, chain.nested.field, chain.nested.arg, n
    )
}

fn nested_bola_resolved(body: &str, root_field: &str, nested_field: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let root = v.get("data").and_then(|d| d.get(root_field));
    let Some(root) = root.and_then(Value::as_object) else {
        return false;
    };
    root.get(nested_field)
        .map(|n| n.is_object())
        .unwrap_or(false)
}

async fn probe_bola_nested_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    cfg: &GraphqlScanConfig,
    chains: &[NestedIdChain],
) -> Vec<Value> {
    let mut out = Vec::new();
    if chains.is_empty() || cfg.bola_test_ids.len() < 2 {
        return out;
    }
    let root_id = &cfg.bola_test_ids[0];
    let nested_id = cfg.bola_test_ids.get(1).unwrap_or(root_id);
    let mut hits = Vec::new();
    for chain in chains.iter().take(6) {
        let q = build_nested_bola_query(chain, root_id, nested_id);
        let Some(p) = post_json(client, url, &json!({ "query": q })).await else {
            continue;
        };
        if (200..300).contains(&p.status)
            && nested_bola_resolved(&p.body, &chain.root.field, &chain.nested.field)
        {
            hits.push(format!(
                "{}({})→{}({})",
                chain.root.field, root_id, chain.nested.field, nested_id
            ));
        }
    }
    if !hits.is_empty() {
        out.push(finding(
            "bola",
            &format!("Nested BOLA chain — {} two-hop ID path(s) resolved", hits.len()),
            "critical",
            "T1213",
            "API1:2023 Broken Object Level Authorization",
            &format!(
                "On {}, nested ID probes resolved objects through parent→child paths: {} — cross-object authorization gaps (e.g. user→orders) are exploitable.",
                url,
                hits.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
            ),
            url,
            target,
            "bola_nested_chain",
            "Enforce authorization at every resolver hop; nested fields must verify ownership of the parent object.",
        ));
    }
    out
}

async fn probe_operation_allowlist_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    schema_query_fields: &[String],
) -> Vec<Value> {
    let mut out = Vec::new();
    // APQ hash-only (no inline query) — persisted operation gate bypass.
    let apq_only = json!({
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "weissman-apq-only-deadbeef000000000000000000000000000000000000000000"
            }
        }
    });
    if let Some(p) = post_json(client, url, &apq_only).await {
        let bl = p.body.to_ascii_lowercase();
        let rejected = bl.contains("persistedquerynotfound")
            || bl.contains("must provide query")
            || bl.contains("query is required");
        if (200..300).contains(&p.status) && p.body.contains("\"data\"") && !rejected {
            out.push(finding(
                "allowlist",
                "Persisted-query allowlist accepts hash-only requests (no inline query)",
                "high",
                "T1190",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "{} returned data for an APQ envelope with sha256 hash only — unregistered operations may execute if hash validation is weak.",
                    p.final_url
                ),
                &p.final_url,
                target,
                "persisted_query_hash_only",
                "Reject APQ requests without a pre-registered hash; never execute from hash alone unless strictly allowlisted.",
            ));
        }
    }
    // operationName fuzz — does a mismatched name still execute?
    let mut names: Vec<String> = OPERATION_ALLOWLIST_NAMES
        .iter()
        .map(|s| s.to_string())
        .collect();
    for f in schema_query_fields.iter().take(8) {
        if !f.is_empty() {
            names.push(f.clone());
            let pascal: String = f
                .chars()
                .enumerate()
                .map(|(i, c)| if i == 0 { c.to_ascii_uppercase() } else { c })
                .collect();
            names.push(format!("Get{pascal}"));
        }
    }
    names.sort();
    names.dedup();
    for op_name in names.iter().take(12) {
        let payload = json!({
            "operationName": op_name,
            "query": "query WeissmanAllowlistProbe { __typename }"
        });
        if let Some(p) = post_json(client, url, &payload).await {
            if (200..300).contains(&p.status)
                && p.body.contains("\"data\"")
                && p.body.contains("__typename")
            {
                // GET with operationName (CSRF / cache surface).
                let get_url = format!(
                    "{}?operationName={}&query={}",
                    url.trim_end_matches('/'),
                    urlencoding::encode(op_name),
                    urlencoding::encode("query { __typename }")
                );
                if let Some(g) = get(client, &get_url).await {
                    if (200..300).contains(&g.status) && g.body.contains("\"data\"") {
                        out.push(finding(
                            "allowlist",
                            &format!("Named operation executable over GET (operationName={})", op_name),
                            "medium",
                            "T1190",
                            "API8:2023 Security Misconfiguration",
                            &format!(
                                "{} executed `operationName={}` via URL query-string — named-operation allowlists may be CSRF/cache bypassable.",
                                g.final_url, op_name
                            ),
                            &g.final_url,
                            target,
                            "operation_name_get",
                            "Block GET execution; bind operationName to server-side allowlists; require non-simple headers.",
                        ));
                        break;
                    }
                }
            }
        }
    }
    out
}

async fn probe_hasura_hardening_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    implementation: Option<&str>,
) -> Vec<Value> {
    let mut out = Vec::new();
    let url_l = url.to_ascii_lowercase();
    let is_hasura = implementation == Some("Hasura")
        || url_l.contains("hasura")
        || url_l.contains("/v1/graphql")
        || url_l.contains("/v2/query");
    if !is_hasura {
        return out;
    }
    for role in ["admin", "user", "anonymous"] {
        let Some(p) = post_json_with_headers(
            client,
            url,
            &json!({ "query": "{ __typename }" }),
            &[("x-hasura-role", role)],
        )
        .await
        else {
            continue;
        };
        if (200..300).contains(&p.status)
            && p.body.contains("\"data\"")
            && !p
                .body
                .to_ascii_lowercase()
                .contains("invalid x-hasura-admin-secret")
        {
            let sev = if role == "admin" { "critical" } else { "high" };
            out.push(finding(
                "hasura",
                &format!("Hasura accepts x-hasura-role `{}` without admin secret", role),
                sev,
                "T1190",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "{} processed a GraphQL query with `x-hasura-role: {}` and returned data — role headers must never be client-controlled in production.",
                    p.final_url, role
                ),
                &p.final_url,
                target,
                "hasura_role_spoof",
                "Disable client-supplied x-hasura-* headers; enforce roles from JWT/session only; protect admin secret.",
            ));
            break;
        }
    }
    // Metadata / console sibling paths (inventory only — GET probe).
    let origin = site_origin(url);
    for path in ["/console", "/v1/metadata", "/healthz"] {
        let candidate = format!("{origin}{path}");
        if let Some(p) = get(client, &candidate).await {
            if (200..300).contains(&p.status) {
                let bl = p.body.to_ascii_lowercase();
                if bl.contains("hasura") || bl.contains("metadata") || bl.contains("graphql-engine")
                {
                    out.push(finding(
                        "hasura",
                        &format!("Hasura management surface reachable: {}", path),
                        "medium",
                        "T1046",
                        "API9:2023 Improper Inventory Management",
                        &format!(
                            "{} returned Hasura-related content — management/metadata endpoints expand attack surface.",
                            p.final_url
                        ),
                        &p.final_url,
                        target,
                        "hasura_mgmt_exposed",
                        "Restrict Hasura console/metadata to internal networks; require auth for all admin APIs.",
                    ));
                    break;
                }
            }
        }
    }
    out
}

/// Fallback BOLA probes when full args introspection is unavailable.
fn heuristic_id_accessors(recovered_fields: &[String]) -> Vec<IdAccessor> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for name in recovered_fields {
        let nl = name.to_ascii_lowercase();
        if BOLA_ID_ARG_TOKENS.iter().any(|t| nl.contains(t))
            || nl.ends_with("byid")
            || nl.starts_with("get")
        {
            if seen.insert(name.clone()) {
                out.push(IdAccessor {
                    field: name.clone(),
                    arg: "id".to_string(),
                    numeric: false,
                });
            }
        }
    }
    for &field in BOLA_HEURISTIC_FIELDS {
        if field == "me" || field == "viewer" || field == "users" {
            continue;
        }
        if seen.insert(field.to_string()) {
            out.push(IdAccessor {
                field: field.to_string(),
                arg: "id".to_string(),
                numeric: field == "node" || field.ends_with("Id"),
            });
        }
    }
    out
}

/// Did the response resolve a non-null object for `field`? (evidence of object fetch, not guessing).
fn bola_object_resolved(body: &str, field: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let data = v.get("data").and_then(Value::as_object);
    let Some(data) = data else { return false };
    let node = data.get(field);
    match node {
        Some(Value::Object(_)) => true,
        Some(Value::Null) | None => false,
        _ => false,
    }
}

async fn probe_bola_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    cfg: &GraphqlScanConfig,
    accessors: &[IdAccessor],
) -> Vec<Value> {
    let mut out = Vec::new();
    let test_ids = cfg.effective_bola_test_ids();
    if accessors.is_empty() || test_ids.is_empty() {
        return out;
    }
    let mut hits: Vec<String> = Vec::new();
    for acc in accessors.iter().take(cfg.max_bola_probes) {
        for test_id in &test_ids {
            let q = build_bola_query(acc, test_id);
            let Some(p) = post_json(client, url, &json!({ "query": q })).await else {
                continue;
            };
            if (200..300).contains(&p.status) && bola_object_resolved(&p.body, &acc.field) {
                hits.push(format!("{}(id={})", acc.field, test_id));
                break;
            }
        }
    }
    if !hits.is_empty() {
        out.push(finding(
            "bola",
            &format!("BOLA/IDOR surface — {} ID-gated field(s) returned objects", hits.len()),
            "high",
            "T1213",
            "API1:2023 Broken Object Level Authorization",
            &format!(
                "On {}, predictable ID probes resolved real objects for: {}. An attacker can enumerate IDs to access other users' records (BOLA).",
                url,
                hits.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
            ),
            url,
            target,
            "bola_idor_surface",
            "Enforce object-level authorization on every resolver; reject cross-tenant / cross-user ID access; use opaque non-sequential IDs.",
        ));
    }
    out
}

async fn probe_bola_batch_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    cfg: &GraphqlScanConfig,
    accessors: &[IdAccessor],
) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(acc) = accessors.first() else {
        return out;
    };
    let ids: Vec<String> = cfg
        .effective_bola_test_ids()
        .iter()
        .take(cfg.bola_batch_size as usize)
        .cloned()
        .collect();
    if ids.len() < 2 {
        return out;
    }
    let q = build_bola_batch_query(acc, &ids);
    let Some(p) = post_json(client, url, &json!({ "query": q })).await else {
        return out;
    };
    let hit_count = count_bola_batch_hits(&p.body, acc, ids.len());
    if (200..300).contains(&p.status) && hit_count >= 2 {
        out.push(finding(
            "bola",
            &format!(
                "BOLA alias-batch enumeration — {}/{} IDs resolved in one request",
                hit_count, ids.len()
            ),
            "high",
            "T1213",
            "API1:2023 Broken Object Level Authorization",
            &format!(
                "{} accepted a single query aliasing {} ID probes on `{}` and resolved {} objects — IDOR enumeration at scale with one HTTP request (rate-limit bypass).",
                p.final_url, ids.len(), acc.field, hit_count
            ),
            &p.final_url,
            target,
            "bola_batch_enumeration",
            "Enforce per-object authorization; cap aliases; apply query cost limits; use non-sequential opaque IDs.",
        ));
    }
    out
}

async fn probe_cors_misconfig(client: &reqwest::Client, url: &str, target: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let origin = CORS_PROBE_ORIGIN;
    let preflight = client
        .request(reqwest::Method::OPTIONS, url)
        .header("Origin", origin)
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "content-type, authorization",
        )
        .send()
        .await;
    if let Ok(resp) = preflight {
        let p = probe_to_http(resp).await;
        let acao = header_value(&p.headers, "access-control-allow-origin");
        let acac = header_value(&p.headers, "access-control-allow-credentials");
        let reflects = acao.as_deref() == Some(origin) || acao.as_deref() == Some("*");
        if reflects && (200..300).contains(&p.status) {
            let creds_risk = acac.as_deref() == Some("true") && acao.as_deref() == Some("*");
            out.push(finding(
                "cors",
                if creds_risk {
                    "CORS misconfiguration: wildcard origin with credentials"
                } else {
                    "CORS reflects arbitrary Origin on GraphQL preflight"
                },
                if creds_risk { "critical" } else { "high" },
                "T1190",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "OPTIONS {} returned Access-Control-Allow-Origin: {:?}{} — a malicious site can invoke the GraphQL API from a victim browser.",
                    p.final_url,
                    acao,
                    if acac.is_some() {
                        format!(" with Allow-Credentials: {acac:?}")
                    } else {
                        String::new()
                    }
                ),
                &p.final_url,
                target,
                if creds_risk {
                    "cors_wildcard_credentials"
                } else {
                    "cors_origin_reflection"
                },
                "Restrict Access-Control-Allow-Origin to trusted origins; never combine `*` with credentials; reject foreign Origins on GraphQL.",
            ));
        }
    }
    if let Some(p) = post_json(client, url, &json!({ "query": "{ __typename }" })).await {
        let acao = header_value(&p.headers, "access-control-allow-origin");
        if acao.as_deref() == Some(origin) || acao.as_deref() == Some("*") {
            if out.is_empty() {
                out.push(finding(
                    "cors",
                    "CORS reflects arbitrary Origin on GraphQL POST",
                    "high",
                    "T1190",
                    "API8:2023 Security Misconfiguration",
                    &format!(
                        "POST {} echoed Access-Control-Allow-Origin: {:?} for foreign Origin `{}`.",
                        p.final_url, acao, origin
                    ),
                    &p.final_url,
                    target,
                    "cors_post_reflection",
                    "Restrict CORS on GraphQL to explicit trusted origins.",
                ));
            }
        }
    }
    out
}

async fn probe_graphql_cswsh(client: &reqwest::Client, http_url: &str, target: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let ws_url = http_to_ws_url(http_url);
    let origin = CSWSH_PROBE_ORIGIN;
    for proto in ["graphql-transport-ws", "graphql-ws"] {
        let key = random_ws_key();
        let expected = ws_accept(&key);
        let resp = client
            .get(&ws_url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", key.clone())
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Protocol", proto)
            .header("Origin", origin)
            .send()
            .await;
        let Some(resp) = resp.ok() else {
            continue;
        };
        let status = resp.status().as_u16();
        let accept = resp
            .headers()
            .get("sec-websocket-accept")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if status == 101 && accept == expected {
            out.push(finding(
                "cswsh",
                &format!("GraphQL CSWSH — WebSocket accepts foreign Origin ({})", proto),
                "high",
                "T1189",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "{} completed RFC 6455 upgrade with Origin `{}` and protocol `{}` — cross-site WebSocket hijacking can drive live subscription abuse from a victim browser.",
                    ws_url, origin, proto
                ),
                &ws_url,
                target,
                "graphql_cswsh",
                "Validate Origin on WebSocket upgrade; require auth before subscription; use SameSite cookies and CSRF tokens.",
            ));
            break;
        }
    }
    out
}

async fn probe_variable_tampering(client: &reqwest::Client, url: &str, target: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let probes: Vec<(&str, Value)> = vec![
        (
            "type_confusion",
            json!({
                "query": "query WeissmanVar($n: Int!) { __typename }",
                "variables": { "n": "not-an-integer" }
            }),
        ),
        (
            "injection_string",
            json!({
                "query": "query WeissmanVar($s: String!) { __typename }",
                "variables": { "s": "1' OR '1'='1" }
            }),
        ),
        (
            "null_byte",
            json!({
                "query": "query WeissmanVar($s: String!) { __typename }",
                "variables": { "s": "test\x00admin" }
            }),
        ),
    ];
    for (kind, payload) in probes {
        let Some(p) = post_json(client, url, &payload).await else {
            continue;
        };
        let bl = p.body.to_ascii_lowercase();
        let verbose = bl.contains("sqlstate")
            || bl.contains("syntax error at or near")
            || bl.contains("sqlexception")
            || bl.contains("mysql")
            || bl.contains("postgres")
            || bl.contains("sqlite")
            || bl.contains("stacktrace")
            || bl.contains("unexpected token");
        let unexpected_data =
            bl.contains("\"data\"") && !bl.contains("\"errors\"") && kind == "type_confusion";
        if verbose || unexpected_data {
            out.push(finding(
                "variable_tampering",
                &format!("GraphQL variable tampering surface ({})", kind),
                if verbose { "medium" } else { "low" },
                "T1190",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "Malformed variables probe `{}` on {} produced {} — resolver/validation may pass untrusted input to backends.",
                    kind,
                    p.final_url,
                    if verbose {
                        "verbose backend errors"
                    } else {
                        "unexpected successful execution"
                    }
                ),
                &p.final_url,
                target,
                &format!("variable_tampering_{kind}"),
                "Strictly validate variable types server-side; strip debug errors; use parameterized resolvers/ORM — never concatenate variables into SQL/commands.",
            ));
        }
    }
    out
}

fn extract_query_cost_signals(body: &str, headers: &[(String, String)]) -> Option<String> {
    let bl = body.to_ascii_lowercase();
    for sig in [
        "\"complexity\"",
        "\"cost\"",
        "\"depth\"",
        "query-complexity",
        "graphql-cost",
    ] {
        if bl.contains(sig) {
            return Some(format!("body matched {sig}"));
        }
    }
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if kl.contains("graphql-cost") || kl.contains("query-cost") || kl.contains("complexity") {
            return Some(format!("header {k}: {v}"));
        }
    }
    None
}

async fn probe_query_cost_leak(client: &reqwest::Client, url: &str, target: &str) -> Option<Value> {
    let p = post_json(client, url, &json!({ "query": INTROSPECTION_QUERY })).await?;
    if !(200..300).contains(&p.status) {
        return None;
    }
    let sig = extract_query_cost_signals(&p.body, &p.headers)?;
    Some(finding(
        "query_cost",
        "GraphQL query cost / complexity metadata exposed",
        "low",
        "T1190",
        "API8:2023 Security Misconfiguration",
        &format!(
            "Response from {} leaks cost/complexity metadata ({sig}) — aids attackers in crafting maximal-cost queries just under limits.",
            p.final_url
        ),
        &p.final_url,
        target,
        "query_cost_leak",
        "Do not expose internal cost/complexity scores to clients; enforce limits server-side only.",
    ))
}

async fn probe_get_cache_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
) -> Option<Value> {
    let get_url = format!("{}?query=%7B__typename%7D", url.trim_end_matches('/'));
    let p = get(client, &get_url).await?;
    if !(200..300).contains(&p.status) || !p.body.contains("\"data\"") {
        return None;
    }
    let cc = header_value(&p.headers, "cache-control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let cacheable = cc.contains("public")
        || (cc.contains("max-age") && !cc.contains("no-store") && !cc.contains("private"));
    if cacheable {
        Some(finding(
            "cache",
            "GraphQL GET response appears cacheable (cache poisoning / CSRF amplification)",
            "medium",
            "T1190",
            "API8:2023 Security Misconfiguration",
            &format!(
                "GET {} returned GraphQL data with Cache-Control: `{cc}` — shared caches may store personalized query results.",
                p.final_url
            ),
            &p.final_url,
            target,
            "get_cache_poisoning",
            "Never cache GraphQL GET responses; use Cache-Control: no-store; disable GET queries in production.",
        ))
    } else {
        None
    }
}

fn root_query_returns_data(body: &str, root_keys: &[&str]) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let Some(data) = v.get("data").and_then(Value::as_object) else {
        return false;
    };
    root_keys.iter().any(|k| {
        data.get(*k)
            .map(|n| !n.is_null() && (n.is_object() || n.is_array()))
            .unwrap_or(false)
    })
}

async fn probe_field_level_auth_differential(
    auth_client: &reqwest::Client,
    unauth_client: &reqwest::Client,
    url: &str,
    target: &str,
) -> Vec<Value> {
    let mut out = Vec::new();
    for q in FIELD_AUTH_ROOT_PROBES {
        let auth_p = post_json(auth_client, url, &json!({ "query": q })).await;
        let unauth_p = post_json(unauth_client, url, &json!({ "query": q })).await;
        let (Some(a), Some(u)) = (auth_p, unauth_p) else {
            continue;
        };
        let keys = ["me", "viewer", "currentUser", "account", "profile"];
        let auth_data = root_query_returns_data(&a.body, &keys);
        let unauth_data = root_query_returns_data(&u.body, &keys);
        if unauth_data && !auth_data {
            out.push(finding(
                "authz",
                "User-scoped root field accessible without authentication",
                "critical",
                "T1213",
                "API2:2023 Broken Authentication",
                &format!(
                    "Query `{}` returned user-scoped data unauthenticated on {} while authenticated probe did not — broken auth boundary on session fields.",
                    q.trim(), u.final_url
                ),
                &u.final_url,
                target,
                "unauth_user_field",
                "Require authentication for all user-scoped root fields; return null/401 for anonymous callers.",
            ));
            break;
        }
        if auth_data && unauth_data {
            out.push(finding(
                "authz",
                "User-scoped root field returns identical data with and without auth",
                "high",
                "T1213",
                "API2:2023 Broken Authentication",
                &format!(
                    "Query `{}` on {} returns user-scoped data both with and without credentials — session/auth may not gate GraphQL resolvers.",
                    q.trim(), u.final_url
                ),
                &u.final_url,
                target,
                "auth_noop_user_field",
                "Ensure resolvers enforce auth context; anonymous callers must not receive user-scoped objects.",
            ));
            break;
        }
    }
    out
}

async fn probe_interface_union_leak(
    client: &reqwest::Client,
    url: &str,
    target: &str,
) -> Option<Value> {
    let p = post_json(
        client,
        url,
        &json!({ "query": INTERFACE_INTROSPECTION_QUERY }),
    )
    .await?;
    if !(200..300).contains(&p.status) {
        return None;
    }
    let v: Value = serde_json::from_str(&p.body).ok()?;
    let types = v
        .get("data")
        .and_then(|d| d.get("__schema"))
        .and_then(|s| s.get("types"))
        .and_then(Value::as_array)?;
    let mut iface_count = 0usize;
    let mut union_count = 0usize;
    let mut leaked: Vec<String> = Vec::new();
    for t in types {
        let kind = t.get("kind").and_then(Value::as_str).unwrap_or("");
        let name = t.get("name").and_then(Value::as_str).unwrap_or("");
        let pts = t
            .get("possibleTypes")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        if pts == 0 {
            continue;
        }
        if kind == "INTERFACE" {
            iface_count += 1;
        } else if kind == "UNION" {
            union_count += 1;
        }
        if leaked.len() < 8 {
            leaked.push(format!("{}({pts})", name));
        }
    }
    if iface_count + union_count > 0 {
        Some(finding(
            "schema",
            &format!(
                "Interface/union possibleTypes exposed ({} interfaces, {} unions)",
                iface_count, union_count
            ),
            "medium",
            "T1213",
            "API9:2023 Improper Inventory Management",
            &format!(
                "{} returned possibleTypes for polymorphic schema nodes: {} — aids fragment-spread attacks and hidden type discovery.",
                p.final_url,
                leaked.join(", ")
            ),
            &p.final_url,
            target,
            "interface_union_leak",
            "Disable introspection in production; restrict possibleTypes metadata to authenticated schema tooling only.",
        ))
    } else {
        None
    }
}

async fn probe_defer_stream_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
) -> Option<Value> {
    let probes = [
        (
            "@defer",
            r#"query WeissmanDefer { __typename @defer(label: "w1") }"#,
        ),
        (
            "@stream",
            r#"query WeissmanStream { __schema { types @stream(initialCount: 1) { name } } }"#,
        ),
    ];
    for (label, q) in probes {
        let p = post_json(client, url, &json!({ "query": q })).await?;
        if !(200..300).contains(&p.status) {
            continue;
        }
        let bl = p.body.to_ascii_lowercase();
        if bl.contains("unknown directive")
            || bl.contains("cannot query directive")
            || bl.contains("directive") && bl.contains("not supported")
        {
            continue;
        }
        let ct = header_value(&p.headers, "content-type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let incremental = bl.contains("hasnext")
            || bl.contains("\"incremental\"")
            || bl.contains("multipart/mixed")
            || ct.contains("multipart/mixed");
        if incremental || (bl.contains("\"data\"") && !bl.contains("\"errors\"")) {
            return Some(finding(
                "defer_stream",
                &format!("GraphQL {} incremental delivery enabled", label),
                "medium",
                "T1499",
                "API4:2023 Unrestricted Resource Consumption",
                &format!(
                    "{} accepted a {} query{} — attackers can hold connections open and amplify server load.",
                    p.final_url,
                    label,
                    if incremental { " (multipart/incremental response observed)" } else { "" }
                ),
                &p.final_url,
                target,
                "defer_stream_enabled",
                "Disable @defer/@stream in production or enforce strict cost/time limits on incremental responses.",
            ));
        }
    }
    None
}

async fn probe_subscription_sse_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
) -> Vec<Value> {
    let mut out = Vec::new();
    // POST + Accept: text/event-stream (GraphQL Yoga / WunderGraph pattern).
    let sub_q = json!({ "query": "subscription { __typename }" });
    if let Some(p) = post_sse(client, url, &sub_q).await {
        let ct = header_value(&p.headers, "content-type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let bl = p.body.to_ascii_lowercase();
        if ct.contains("text/event-stream")
            || bl.starts_with("data:")
            || bl.contains("\ndata:")
            || bl.contains("event:")
        {
            out.push(finding(
                "subscription",
                "GraphQL subscription over Server-Sent Events (SSE) reachable",
                "medium",
                "T1190",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "{} accepted a subscription with `Accept: text/event-stream` and returned SSE framing — live event stream without WebSocket.",
                    p.final_url
                ),
                &p.final_url,
                target,
                "subscription_sse_open",
                "Require authentication on SSE subscription endpoints; disable public SSE GraphQL in production.",
            ));
            return out;
        }
    }
    // GET subscription over query-string + SSE (some gateways).
    let get_url = format!(
        "{}?query={}",
        url.trim_end_matches('/'),
        urlencoding::encode("subscription { __typename }")
    );
    if let Some(p) = get_with_accept(client, &get_url, "text/event-stream").await {
        let ct = header_value(&p.headers, "content-type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if ct.contains("text/event-stream") || p.body.starts_with("data:") {
            out.push(finding(
                "subscription",
                "GraphQL GET subscription over SSE reachable",
                "medium",
                "T1190",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "{} served SSE on a GET subscription query — cache/CDN misconfigurations can amplify exposure.",
                    p.final_url
                ),
                &p.final_url,
                target,
                "subscription_sse_get",
                "Block GET-based subscriptions; require authenticated POST for any streaming GraphQL transport.",
            ));
        }
    }
    out
}

fn relay_global_id(type_name: &str, id: &str) -> String {
    B64.encode(format!("{type_name}:{id}"))
}

fn infer_relay_type(field: &str) -> String {
    let base = field.trim();
    if base.is_empty() {
        return "Node".to_string();
    }
    let stem = if base.ends_with('s') && base.len() > 1 {
        &base[..base.len() - 1]
    } else {
        base
    };
    let mut ch = stem.chars();
    match ch.next() {
        Some(c) => {
            let rest: String = ch.collect();
            format!("{}{}", c.to_ascii_uppercase(), rest)
        }
        None => "Node".to_string(),
    }
}

fn build_relay_bola_query(accessor: &IdAccessor, relay_id: &str) -> String {
    let escaped = relay_id.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "query {{ {}({}: \"{}\") {{ __typename id }} }}",
        accessor.field, accessor.arg, escaped
    )
}

async fn probe_relay_bola_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    cfg: &GraphqlScanConfig,
    accessors: &[IdAccessor],
) -> Vec<Value> {
    let mut out = Vec::new();
    let test_ids = cfg.effective_bola_test_ids();
    if accessors.is_empty() || test_ids.is_empty() {
        return out;
    }
    let mut hits: Vec<String> = Vec::new();
    for acc in accessors.iter().take(cfg.max_bola_probes.min(4)) {
        if acc.numeric {
            continue;
        }
        let relay_type = infer_relay_type(&acc.field);
        for test_id in test_ids.iter().take(3) {
            let gid = relay_global_id(&relay_type, test_id);
            let q = build_relay_bola_query(acc, &gid);
            let Some(p) = post_json(client, url, &json!({ "query": q })).await else {
                continue;
            };
            if (200..300).contains(&p.status) && bola_object_resolved(&p.body, &acc.field) {
                hits.push(format!("{}(relayId={})", acc.field, test_id));
                break;
            }
        }
    }
    if !hits.is_empty() {
        out.push(finding(
            "bola",
            &format!(
                "Relay global-ID BOLA — {} field(s) resolved via base64 global IDs",
                hits.len()
            ),
            "high",
            "T1213",
            "API1:2023 Broken Object Level Authorization",
            &format!(
                "On {}, Relay-style global IDs (base64 type:id) resolved objects for: {}. Common in Apollo/Relay APIs — sequential IDs inside global IDs enable cross-user access.",
                url,
                hits.join(", ")
            ),
            url,
            target,
            "relay_global_id_bola",
            "Use opaque non-guessable global IDs; enforce object-level authorization on every node resolver.",
        ));
    }
    out
}

fn parse_connection_roots(body: &str) -> Vec<String> {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let fields = v
        .get("data")
        .and_then(|d| d.get("__schema"))
        .and_then(|s| s.get("queryType"))
        .and_then(|q| q.get("fields"))
        .and_then(Value::as_array);
    let Some(fields) = fields else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for f in fields {
        let fname = f.get("name").and_then(Value::as_str).unwrap_or("");
        if fname.is_empty() {
            continue;
        }
        let args = f.get("args").and_then(Value::as_array);
        let Some(args) = args else { continue };
        let paginated = args.iter().any(|a| {
            matches!(
                a.get("name").and_then(Value::as_str).unwrap_or(""),
                "first" | "after" | "last" | "before"
            )
        });
        if paginated {
            out.push(fname.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

async fn probe_pagination_abuse_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    introspection_body: Option<&str>,
) -> Vec<Value> {
    let mut out = Vec::new();
    let roots = introspection_body
        .map(parse_connection_roots)
        .unwrap_or_default();
    let candidates: Vec<&str> = if roots.is_empty() {
        vec!["users", "nodes", "accounts", "orders", "products"]
    } else {
        roots.iter().map(String::as_str).collect()
    };
    for root in candidates.iter().take(4) {
        let q = format!(
            "query {{ {}(first: 9999) {{ edges {{ node {{ __typename id }} }} pageInfo {{ hasNextPage endCursor }} }} }}",
            root
        );
        let Some(p) = post_json(client, url, &json!({ "query": q })).await else {
            continue;
        };
        if !(200..300).contains(&p.status) {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(&p.body) else {
            continue;
        };
        let edge_count = v
            .get("data")
            .and_then(|d| d.get(*root))
            .and_then(|c| c.get("edges"))
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        if edge_count >= 1 {
            out.push(finding(
                "authz",
                &format!(
                    "Unbounded connection pagination — `{}` returned {} edge(s) with first:9999",
                    root, edge_count
                ),
                if edge_count >= 10 { "high" } else { "medium" },
                "T1213",
                "API4:2023 Unrestricted Resource Consumption",
                &format!(
                    "POST {} accepted `first:9999` on connection field `{}` and returned {} edge(s). Attackers can bulk-exfiltrate paginated collections in one query.",
                    p.final_url, root, edge_count
                ),
                &p.final_url,
                target,
                "pagination_unbounded",
                "Enforce max page size (first/last caps); apply query cost limits and rate limiting on connection fields.",
            ));
            break;
        }
    }
    out
}

fn extract_limit_from_error(body: &str) -> Option<u64> {
    let bl = body.to_ascii_lowercase();
    if !(bl.contains("alias")
        || bl.contains("depth")
        || bl.contains("complexity")
        || bl.contains("limit"))
    {
        return None;
    }
    for token in bl.split(|c: char| !c.is_ascii_digit()) {
        if let Ok(n) = token.parse::<u64>() {
            if (2..=10_000).contains(&n) {
                return Some(n);
            }
        }
    }
    None
}

async fn probe_limit_fingerprint_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    cfg: &GraphqlScanConfig,
) -> Option<Value> {
    let tiers = [50_u64, 200, cfg.alias_count.min(500)];
    let mut highest_ok = 0_u64;
    let mut disclosed_limit = None;
    for n in tiers {
        if n < 2 {
            continue;
        }
        let q = alias_overload_query(n);
        let Some(p) = post_json(client, url, &json!({ "query": q })).await else {
            continue;
        };
        if (200..300).contains(&p.status) && p.body.contains("\"data\"") {
            highest_ok = n;
        } else if let Some(lim) = extract_limit_from_error(&p.body) {
            disclosed_limit = Some(lim);
            break;
        }
    }
    if let Some(lim) = disclosed_limit {
        return Some(finding(
            "dos",
            &format!("GraphQL alias/depth limit disclosed in error ({lim})"),
            "medium",
            "T1190",
            "API8:2023 Security Misconfiguration",
            &format!(
                "Alias-amplification probe on {} triggered an error revealing a server limit of ~{lim}. Attackers can craft queries just under the threshold.",
                url
            ),
            url,
            target,
            "limit_disclosed",
            "Return generic errors without numeric limits; enforce limits silently and log server-side.",
        ));
    }
    if highest_ok >= 200 {
        return Some(finding(
            "dos",
            &format!("No effective alias limit detected ({} aliases accepted)", highest_ok),
            "high",
            "T1190",
            "API4:2023 Unrestricted Resource Consumption",
            &format!(
                "POST {} accepted a query with {highest_ok} aliases and returned data — alias amplification DoS is likely viable.",
                url
            ),
            url,
            target,
            "alias_limit_absent",
            "Configure alias/depth/complexity limits (GraphQL Armor, Apollo safeguards, Hasura limits).",
        ));
    }
    None
}

async fn probe_waf_evasion_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
) -> Option<Value> {
    let baseline = post_json(client, url, &json!({ "query": INTROSPECTION_QUERY })).await?;
    if parse_schema(&baseline.body).is_some() {
        return None;
    }
    let variants: Vec<(&str, Value)> = vec![
        (
            "charset=utf-8 content-type",
            json!({ "query": INTROSPECTION_QUERY }),
        ),
        (
            "whitespace/comment query",
            json!({ "query": "query IntrospectionQuery { __schema #bypass\n { queryType { name } types { name kind } } }" }),
        ),
        (
            "operationName split",
            json!({ "operationName": "IntrospectionQuery", "query": INTROSPECTION_QUERY }),
        ),
    ];
    for (label, payload) in variants {
        let p = if label.starts_with("charset") {
            post_json_ct(client, url, &payload, "application/json; charset=utf-8").await
        } else {
            post_json(client, url, &payload).await
        };
        let Some(p) = p else { continue };
        if let Some(schema) = parse_schema(&p.body) {
            return Some(finding(
                "introspection",
                &format!("Introspection WAF bypass via {label}"),
                "critical",
                "T1213",
                "API9:2023 Improper Inventory Management",
                &format!(
                    "Standard introspection was blocked on {} but variant `{label}` recovered __schema ({} types). WAF/allowlist is bypassable.",
                    p.final_url, schema.types
                ),
                &p.final_url,
                target,
                "waf_introspection_bypass",
                "Block introspection at the GraphQL engine layer, not only via WAF signatures; reject all introspection query shapes.",
            ));
        }
    }
    None
}

const LIVE_DATA_ROOT_FIELDS: &[(&str, &str)] = &[
    ("users", "id email name"),
    ("user", "id email name"),
    ("me", "id email name"),
    ("viewer", "id email name"),
    ("accounts", "id name email"),
    ("customers", "id email name"),
    ("orders", "id total status"),
];

fn live_data_returned(body: &str, field: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let node = v.get("data").and_then(|d| d.get(field));
    match node {
        Some(Value::Array(arr)) => arr.iter().any(|item| {
            item.as_object()
                .map(|o| o.keys().filter(|k| *k != "__typename").count() > 0)
                .unwrap_or(false)
        }),
        Some(Value::Object(obj)) => obj.keys().filter(|k| *k != "__typename").count() > 0,
        _ => false,
    }
}

async fn probe_live_data_leak_surface(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    introspection_body: Option<&str>,
) -> Vec<Value> {
    let mut out = Vec::new();
    let mut fields: Vec<(String, &'static str)> = LIVE_DATA_ROOT_FIELDS
        .iter()
        .map(|(a, b)| (a.to_string(), *b))
        .collect();
    if let Some(body) = introspection_body {
        for root in parse_connection_roots(body).iter().take(3) {
            fields.push((root.clone(), "id __typename"));
        }
    }
    let mut seen = std::collections::HashSet::new();
    for (root, subfields) in fields {
        if !seen.insert(root.clone()) {
            continue;
        }
        let q = format!("query {{ {} {{ {} }} }}", root, subfields);
        let Some(p) = post_json(client, url, &json!({ "query": q })).await else {
            continue;
        };
        if (200..300).contains(&p.status) && live_data_returned(&p.body, &root) {
            out.push(finding(
                "authz",
                &format!("Live sensitive data returned from `{root}` without evidence of auth gate"),
                "critical",
                "T1213",
                "API3:2023 Broken Object Property Level Authorization",
                &format!(
                    "Query `{q}` on {} returned populated `{}` data in the response body — real records may be exposed to anonymous callers.",
                    p.final_url, root
                ),
                &p.final_url,
                target,
                "live_data_exposure",
                "Require authentication for all collection/user root fields; return empty/null for anonymous sessions.",
            ));
            if out.len() >= 2 {
                break;
            }
        }
    }
    out
}

/// Build a nested introspection query of `depth` levels to test query-depth/cost limits.
fn nested_introspection_query(depth: u64) -> String {
    let mut inner = String::from("name");
    for _ in 0..depth {
        inner = format!("ofType {{ {} }}", inner);
    }
    format!(
        "query {{ __schema {{ types {{ fields {{ type {{ {} }} }} }} }} }}",
        inner
    )
}

/// Build an alias-amplification query with `n` aliases of `__typename`.
fn alias_overload_query(n: u64) -> String {
    let mut q = String::from("query {");
    for i in 0..n {
        q.push_str(&format!(" a{}:__typename", i));
    }
    q.push_str(" }");
    q
}

// ── The single endpoint assessment (run per discovered GraphQL endpoint) ──────────────────────────

#[allow(clippy::too_many_lines)]
async fn assess_endpoint(
    client: &reqwest::Client,
    url: &str,
    cfg: &GraphqlScanConfig,
    target: &str,
    out: &mut Vec<Value>,
    state: &mut EndpointState,
) {
    // 1. Introspection.
    if cfg.probe_introspection {
        if let Some(p) = post_json(client, url, &json!({ "query": INTROSPECTION_QUERY })).await {
            if let Some(schema) = parse_schema(&p.body) {
                state.introspection = true;
                state.introspection_body = Some(p.body.clone());
                state.types = schema.types;
                state.mutations = schema.mutation_fields;
                state.sensitive = schema.sensitive_fields.len();
                state.schema_graph = schema.graph.clone();
                out.push(finding(
                    "introspection",
                    "GraphQL introspection enabled in production",
                    "high",
                    "T1213",
                    "API9:2023 Improper Inventory Management",
                    &format!(
                        "POST {} returned a full __schema ({} types, {} query fields, {} mutation fields{}). Introspection hands an attacker the complete API contract.",
                        p.final_url,
                        schema.types,
                        schema.query_fields,
                        schema.mutation_fields,
                        if schema.has_subscriptions { ", subscriptions present" } else { "" }
                    ),
                    &p.final_url,
                    target,
                    "introspection_enabled",
                    "Disable introspection in production (Apollo: `introspection:false`; Hasura: lock down with allow-lists). Keep it on only in non-prod.",
                ));
                if !schema.sensitive_fields.is_empty() {
                    out.push(finding(
                        "schema",
                        &format!("Sensitive fields exposed in schema ({})", schema.sensitive_fields.len()),
                        "high",
                        "T1213",
                        "API3:2023 Broken Object Property Level Authorization",
                        &format!(
                            "The schema exposes sensitive-looking fields: {}. Verify field-level authorization so these are never returned to unauthorized callers.",
                            schema.sensitive_fields.iter().take(12).cloned().collect::<Vec<_>>().join(", ")
                        ),
                        &p.final_url,
                        target,
                        "sensitive_schema_fields",
                        "Apply field-level authorization (e.g. directive-based or resolver guards); never expose password/token/secret fields in the public schema.",
                    ));
                }
                if !schema.dangerous_mutations.is_empty() {
                    out.push(finding(
                        "schema",
                        &format!(
                            "High-impact mutations exposed in schema ({})",
                            schema.dangerous_mutations.len()
                        ),
                        "high",
                        "T1213",
                        "API3:2023 Broken Object Property Level Authorization",
                        &format!(
                            "Mutation root exposes state-changing operations: {}. Combined with CSRF/GET or weak auth these enable account takeover, deletion, or privilege escalation.",
                            schema.dangerous_mutations.iter().take(12).cloned().collect::<Vec<_>>().join(", ")
                        ),
                        &p.final_url,
                        target,
                        "dangerous_mutations_exposed",
                        "Gate destructive/admin mutations behind strong authN/Z; disable introspection; never allow mutations over GET.",
                    ));
                }
                if cfg.probe_bola {
                    if let Some(args_p) =
                        post_json(client, url, &json!({ "query": INTROSPECTION_ARGS_QUERY })).await
                    {
                        state.id_accessors = parse_id_accessors(&args_p.body);
                    }
                    if cfg.probe_bola_nested {
                        if let Some(nested_p) = post_json(
                            client,
                            url,
                            &json!({ "query": INTROSPECTION_NESTED_ARGS_QUERY }),
                        )
                        .await
                        {
                            state.nested_chains = parse_nested_id_chains(&nested_p.body);
                        }
                    }
                }
            }
        }
    }

    // 2. Field suggestions leak + Clairvoyance-style schema reconstruction.
    if cfg.probe_suggestions || (cfg.probe_schema_recon && !state.introspection) {
        if let Some(p) = post_json(
            client,
            url,
            &json!({ "query": "{ weissmanNonExistentField_zzz }" }),
        )
        .await
        {
            let bl = p.body.to_ascii_lowercase();
            let suggestions_on = bl.contains("did you mean") || bl.contains("suggest");
            if suggestions_on && cfg.probe_suggestions {
                out.push(finding(
                    "suggestions",
                    "GraphQL field suggestions enabled (schema inference)",
                    "medium",
                    "T1213",
                    "API9:2023 Improper Inventory Management",
                    &format!(
                        "Invalid-field probe on {} produced 'Did you mean' suggestions — the schema can be reconstructed field-by-field even with introspection disabled.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "field_suggestions",
                    "Disable 'Did you mean' field suggestions in production (e.g. Apollo plugin to strip suggestions, or a validation rule).",
                ));
            }
            if cfg.probe_schema_recon && !state.introspection && suggestions_on {
                let recovered = clairvoyance_recon(client, url, cfg).await;
                if !recovered.is_empty() {
                    state.recon_fields = recovered.len();
                    state.recovered_field_names = recovered.clone();
                    out.push(finding(
                        "schema_recon",
                        &format!("Schema reconstructed via suggestions ({} root fields recovered)", recovered.len()),
                        "high",
                        "T1213",
                        "API9:2023 Improper Inventory Management",
                        &format!(
                            "With introspection disabled, {} Query-root fields were recovered from suggestion errors on {}: {}. The 'hidden' schema is effectively public.",
                            recovered.len(),
                            p.final_url,
                            recovered.iter().take(15).cloned().collect::<Vec<_>>().join(", ")
                        ),
                        &p.final_url,
                        target,
                        "schema_reconstruction",
                        "Disable field suggestions AND introspection; suggestions alone defeat 'security by introspection-off'.",
                    ));
                }
            }
        }
    }

    // 3. Batching (array of operations).
    if cfg.probe_batching {
        let batch: Vec<Value> = (0..cfg.batch_count)
            .map(|_| json!({ "query": "{__typename}" }))
            .collect();
        if let Some(p) = post_json(client, url, &json!(batch)).await {
            if (200..300).contains(&p.status)
                && p.body.trim_start().starts_with('[')
                && p.body.matches("__typename").count() >= 2
            {
                state.dos_vectors += 1;
                out.push(finding(
                    "dos",
                    "GraphQL query batching enabled (brute-force / DoS amplification)",
                    "medium",
                    "T1499",
                    "API4:2023 Unrestricted Resource Consumption",
                    &format!(
                        "{} accepted a JSON array of {} operations and returned a batched response — enables rate-limit bypass (credential brute-force) and request amplification.",
                        p.final_url, cfg.batch_count
                    ),
                    &p.final_url,
                    target,
                    "batching_enabled",
                    "Disable array-batching or cap batch size; apply per-operation cost accounting and rate limiting.",
                ));
            }
        }
    }

    // 4. Alias amplification (amount limit).
    if cfg.probe_alias_overload {
        if let Some(p) = post_json(
            client,
            url,
            &json!({ "query": alias_overload_query(cfg.alias_count) }),
        )
        .await
        {
            let count = p.body.matches("\"a").count();
            if (200..300).contains(&p.status) && count as u64 >= cfg.alias_count / 2 {
                state.dos_vectors += 1;
                out.push(finding(
                    "dos",
                    &format!("No alias/amount limit ({} aliases accepted)", cfg.alias_count),
                    "high",
                    "T1499",
                    "API4:2023 Unrestricted Resource Consumption",
                    &format!(
                        "{} executed {} aliased fields in a single operation without rejection. Alias amplification multiplies resolver work and bypasses field-level rate limits (DoS).",
                        p.final_url, cfg.alias_count
                    ),
                    &p.final_url,
                    target,
                    "alias_amplification",
                    "Enforce a maximum alias / field count and per-request cost limit (e.g. graphql-cost-analysis, Apollo operation limits).",
                ));
            }
        }
    }

    // 5. Depth / query-cost limit (via nested introspection).
    if cfg.probe_depth && state.introspection {
        if let Some(p) = post_json(
            client,
            url,
            &json!({ "query": nested_introspection_query(cfg.depth_levels) }),
        )
        .await
        {
            let bl = p.body.to_ascii_lowercase();
            let rejected = bl.contains("depth")
                || bl.contains("too deep")
                || bl.contains("complexity")
                || bl.contains("cost")
                || bl.contains("maximum");
            if (200..300).contains(&p.status) && p.body.contains("\"data\"") && !rejected {
                state.dos_vectors += 1;
                out.push(finding(
                    "dos",
                    &format!("No query depth/cost limit (depth {} accepted)", cfg.depth_levels),
                    "high",
                    "T1499",
                    "API4:2023 Unrestricted Resource Consumption",
                    &format!(
                        "A {}-level nested query on {} executed without a depth/complexity error — a deeply-nested malicious query can exhaust CPU/memory (DoS).",
                        cfg.depth_levels, p.final_url
                    ),
                    &p.final_url,
                    target,
                    "no_depth_limit",
                    "Add a query-depth limit and complexity/cost analysis (graphql-depth-limit, graphql-cost-analysis, Apollo `validationRules`).",
                ));
            }
        }
    }

    // 6. CSRF — query execution over GET / form-urlencoded POST.
    if cfg.probe_csrf_get {
        let get_url = format!("{}?query=%7B__typename%7D", url);
        if let Some(p) = get(client, &get_url).await {
            if (200..300).contains(&p.status)
                && p.body.contains("__typename")
                && p.body.contains("data")
            {
                state.csrf = true;
                let elevated = state.mutations > 0;
                out.push(finding(
                    "csrf",
                    "GraphQL queries executable over HTTP GET (CSRF surface)",
                    if elevated { "high" } else { "medium" },
                    "T1190",
                    "API8:2023 Security Misconfiguration",
                    &format!(
                        "{} executed a query supplied via the URL query-string. GET-based execution is cacheable and CSRF-able{}.",
                        p.final_url,
                        if elevated { " — and the schema exposes mutations, so state-changing CSRF may be possible" } else { "" }
                    ),
                    &p.final_url,
                    target,
                    "csrf_get",
                    "Reject queries over GET (allow only POST application/json), require a CSRF token / custom header, and never allow mutations over GET.",
                ));
            }
        }
        // form-urlencoded POST (also CSRF-able from a simple HTML form).
        if let Some(p) = post_form(client, url, "query={__typename}".to_string()).await {
            if (200..300).contains(&p.status)
                && p.body.contains("__typename")
                && p.body.contains("data")
            {
                state.csrf = true;
                out.push(finding(
                    "csrf",
                    "GraphQL accepts form-urlencoded POST (CSRF surface)",
                    "medium",
                    "T1190",
                    "API8:2023 Security Misconfiguration",
                    &format!(
                        "{} executed a query sent as application/x-www-form-urlencoded — a plain HTML form can forge requests (CSRF).",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "csrf_form",
                    "Only accept application/json content-type and require a non-simple header / CSRF token.",
                ));
            }
        }
    }

    // 7. Error verbosity / debug-mode disclosure (safe malformed query).
    if cfg.probe_error_verbosity {
        if let Some(p) =
            post_json(client, url, &json!({ "query": "{ __typename __typename(" })).await
        {
            let bl = p.body.to_ascii_lowercase();
            let leaks = [
                "at /",
                "traceback",
                "stacktrace",
                "stack trace",
                ".rb:",
                ".py",
                ".js:",
                "node_modules",
                "sqlstate",
                "syntax error at or near",
                "exception in",
                "\"extensions\"",
                "\"stacktrace\"",
            ];
            if let Some(sig) = leaks.iter().find(|s| bl.contains(**s)) {
                out.push(finding(
                    "error_verbosity",
                    "Verbose GraphQL errors / debug mode (stack traces leaked)",
                    "medium",
                    "T1190",
                    "API8:2023 Security Misconfiguration",
                    &format!(
                        "A malformed query on {} returned a verbose error (matched '{}') exposing server internals (paths / stack traces / DB errors).",
                        p.final_url, sig
                    ),
                    &p.final_url,
                    target,
                    "verbose_errors",
                    "Disable debug mode in production; strip stack traces and `extensions.exception` from client-facing error responses.",
                ));
            }
        }
    }

    // 8. Apollo Federation SDL exposure.
    if cfg.probe_federation {
        if let Some(p) = post_json(client, url, &json!({ "query": FEDERATION_SDL_QUERY })).await {
            if p.body.contains("\"sdl\"") && p.body.contains("data") {
                out.push(finding(
                    "federation",
                    "Apollo Federation subgraph SDL exposed via _service",
                    "high",
                    "T1213",
                    "API9:2023 Improper Inventory Management",
                    &format!(
                        "{} returned `_service {{ sdl }}` data — the full federated subgraph schema is exposed to unauthenticated callers.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "federation_sdl_exposed",
                    "Disable `_service` SDL exposure in production; gate federation introspection behind auth and network policy.",
                ));
            }
        }
    }

    // 9. Automatic Persisted Queries (APQ) bypass surface.
    if cfg.probe_apq {
        let payload = json!({
            "query": "{ __typename }",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "weissman-probe-deadbeef0000000000000000000000000000000000000000000000"
                }
            }
        });
        if let Some(p) = post_json(client, url, &payload).await {
            let bl = p.body.to_ascii_lowercase();
            let not_found = bl.contains("persistedquerynotfound")
                || bl.contains("persisted query not found")
                || bl.contains("unknown query");
            if (200..300).contains(&p.status) && p.body.contains("\"data\"") && !not_found {
                out.push(finding(
                    "apq",
                    "APQ / persisted-query gate accepts arbitrary query+hash pairs",
                    "medium",
                    "T1190",
                    "API8:2023 Security Misconfiguration",
                    &format!(
                        "{} accepted an APQ envelope with an unregistered sha256 hash alongside an inline query — persisted-query allowlists may be bypassable.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "apq_bypass",
                    "Enforce strict persisted-query registration; reject inline queries when APQ extensions are present unless hash is pre-registered.",
                ));
            }
        }
    }

    // 10. Partial introspection disable bypass (`__type` when `__schema` is blocked).
    if cfg.probe_introspection_bypass && !state.introspection {
        if let Some(p) =
            post_json(client, url, &json!({ "query": INTROSPECTION_BYPASS_QUERY })).await
        {
            if p.body.contains("\"fields\"") && p.body.contains("\"data\"") {
                state.introspection = true;
                out.push(finding(
                    "introspection",
                    "Partial introspection bypass via __type(name:\"Query\")",
                    "high",
                    "T1213",
                    "API9:2023 Improper Inventory Management",
                    &format!(
                        "Although full __schema introspection failed, {} returned Query root fields via __type — 'introspection disabled' is incomplete.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "introspection_bypass",
                    "Disable ALL introspection entry points (__schema, __type, __typename on schema types) in production.",
                ));
            }
        }
    }

    // 11. Field duplication DoS (same field repeated — distinct from alias amplification).
    if cfg.probe_field_duplication {
        if let Some(p) = post_json(
            client,
            url,
            &json!({ "query": field_duplication_query(cfg.field_duplication_count) }),
        )
        .await
        {
            let count = p.body.matches("__typename").count();
            if (200..300).contains(&p.status) && count as u64 >= cfg.field_duplication_count / 2 {
                state.dos_vectors += 1;
                out.push(finding(
                    "dos",
                    &format!(
                        "No duplicate-field limit ({} identical fields accepted)",
                        cfg.field_duplication_count
                    ),
                    "medium",
                    "T1499",
                    "API4:2023 Unrestricted Resource Consumption",
                    &format!(
                        "{} executed a query repeating __typename {} times — duplicate-field fan-out can amplify resolver work.",
                        p.final_url, cfg.field_duplication_count
                    ),
                    &p.final_url,
                    target,
                    "field_duplication",
                    "Enforce maximum field count / query cost limits; reject queries with excessive duplicate selections.",
                ));
            }
        }
    }

    // 12. Circular fragment spread DoS surface.
    if cfg.probe_fragment_cycle {
        let q = fragment_cycle_query(cfg.fragment_spread_depth);
        if let Some(p) = post_json(client, url, &json!({ "query": q })).await {
            let bl = p.body.to_ascii_lowercase();
            let rejected = bl.contains("fragment")
                && (bl.contains("cycle") || bl.contains("spread") || bl.contains("maximum"));
            if (200..300).contains(&p.status) && p.body.contains("\"data\"") && !rejected {
                state.dos_vectors += 1;
                out.push(finding(
                    "dos",
                    "Circular fragment spreads accepted (fragment-cycle DoS)",
                    "high",
                    "T1499",
                    "API4:2023 Unrestricted Resource Consumption",
                    &format!(
                        "{} accepted mutually-referencing fragments (A↔B cycle) — a fragment-cycle can exhaust parser/resolver stacks.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "fragment_cycle",
                    "Reject cyclic fragment spreads; cap fragment depth and spread count.",
                ));
            }
        }
    }

    // 13. Directive overloading (@include/@skip stacking).
    if cfg.probe_directive_abuse {
        let q = directive_abuse_query(50);
        if let Some(p) = post_json(client, url, &json!({ "query": q })).await {
            if (200..300).contains(&p.status) && p.body.contains("\"data\"") {
                state.dos_vectors += 1;
                out.push(finding(
                    "dos",
                    "Directive stacking accepted (@include/@skip overload)",
                    "medium",
                    "T1499",
                    "API4:2023 Unrestricted Resource Consumption",
                    &format!(
                        "{} executed a query with 50 stacked @include directives — directive evaluation can amplify CPU cost.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "directive_abuse",
                    "Cap directive count per field; apply query-cost analysis that accounts for directive evaluation.",
                ));
            }
        }
    }

    // 14. application/graphql content-type acceptance.
    if cfg.probe_content_type_graphql {
        if let Some(p) = post_graphql_ct(client, url, "{ __typename }").await {
            if (200..300).contains(&p.status)
                && p.body.contains("__typename")
                && p.body.contains("data")
            {
                out.push(finding(
                    "transport",
                    "GraphQL accepts application/graphql content-type",
                    "info",
                    "T1190",
                    "API8:2023 Security Misconfiguration",
                    &format!(
                        "{} executed a query sent as `application/graphql` — alternate content-types expand the CSRF / cache-poisoning surface.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "content_type_graphql",
                    "Document all accepted content-types; restrict to application/json in production if possible.",
                ));
            }
        }
    }

    // 15. Multiple named operations in a single request string.
    if cfg.probe_multi_operation {
        let q = "query WeissmanOpA { __typename } query WeissmanOpB { __typename }";
        if let Some(p) = post_json(client, url, &json!({ "query": q })).await {
            if (200..300).contains(&p.status) && p.body.contains("\"data\"") {
                out.push(finding(
                    "transport",
                    "Multiple named operations accepted in one request",
                    "low",
                    "T1190",
                    "API4:2023 Unrestricted Resource Consumption",
                    &format!(
                        "{} accepted two named operations in a single query string — multi-op requests can bypass per-operation rate limits.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "multi_operation",
                    "Restrict to one operation per request or enforce per-operation cost accounting.",
                ));
            }
        }
    }

    // 16. Apollo tracing / performance extension leak.
    if cfg.probe_tracing {
        if let Some(p) = post_json(client, url, &json!({ "query": TRACING_INTROSPECTION })).await {
            let bl = p.body.to_ascii_lowercase();
            if bl.contains("\"tracing\"")
                || bl.contains("\"ftv1\"")
                || (bl.contains("\"extensions\"") && bl.contains("duration"))
            {
                out.push(finding(
                    "tracing",
                    "GraphQL tracing / performance extensions exposed",
                    "medium",
                    "T1190",
                    "API8:2023 Security Misconfiguration",
                    &format!(
                        "Response from {} includes tracing/performance extensions — resolver timing data aids targeted exploitation.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "tracing_exposed",
                    "Disable Apollo tracing and performance extensions in production responses.",
                ));
            }
        }
    }

    // 17. Rate-limit absence — burst identical tiny queries.
    if cfg.probe_rate_limit {
        let mut ok_count = 0u64;
        let mut limited = 0u64;
        for _ in 0..cfg.burst_count {
            if let Some(p) = post_json(client, url, &json!({ "query": "{__typename}" })).await {
                if p.status == 429 {
                    limited += 1;
                } else if (200..300).contains(&p.status) {
                    ok_count += 1;
                }
            }
        }
        if ok_count >= cfg.burst_count.saturating_sub(1) && limited == 0 {
            out.push(finding(
                "rate_limit",
                &format!("No rate limiting observed ({} rapid queries accepted)", cfg.burst_count),
                "medium",
                "T1499",
                "API4:2023 Unrestricted Resource Consumption",
                &format!(
                    "{} accepted {}/{} back-to-back identical queries with no HTTP 429 — brute-force and DoS amplification are unthrottled.",
                    url, ok_count, cfg.burst_count
                ),
                url,
                target,
                "rate_limit_absent",
                "Apply per-IP and per-token rate limits at the API gateway; return 429 with Retry-After.",
            ));
        }
    }

    // 18. GraphQL multipart / Upload scalar surface.
    if cfg.probe_upload_scalar {
        let schema_has_upload = state.schema_graph.iter().any(|t| {
            t.get("type")
                .and_then(Value::as_str)
                .is_some_and(|n| n.eq_ignore_ascii_case("Upload"))
        });
        if schema_has_upload {
            out.push(finding(
                "upload",
                "Upload scalar present in schema (file-upload attack surface)",
                "medium",
                "T1190",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "Schema on {} defines an Upload scalar — GraphQL file uploads enable SSRF / malware staging if misconfigured.",
                    url
                ),
                url,
                target,
                "upload_scalar",
                "Disable Upload scalar in production or gate file uploads behind strict auth, size limits, and content scanning.",
            ));
        }
        if let Some(p) = post_multipart_graphql(client, url).await {
            if (200..300).contains(&p.status) && p.body.contains("\"data\"") {
                out.push(finding(
                    "upload",
                    "GraphQL multipart upload transport accepted",
                    "medium",
                    "T1190",
                    "API8:2023 Security Misconfiguration",
                    &format!(
                        "{} accepted a multipart GraphQL request (operations/map) — file-upload transport is live.",
                        p.final_url
                    ),
                    &p.final_url,
                    target,
                    "multipart_upload",
                    "Restrict multipart GraphQL to authenticated callers; validate file types and scan uploads.",
                ));
            }
        }
    }

    // 19. BOLA / IDOR — schema-derived ID argument probes (read-only).
    if cfg.probe_bola {
        let mut accessors = state.id_accessors.clone();
        if accessors.is_empty() {
            accessors = heuristic_id_accessors(&state.recovered_field_names);
        }
        out.extend(probe_bola_surface(client, url, target, cfg, &accessors).await);
        if cfg.probe_bola_batch {
            out.extend(probe_bola_batch_surface(client, url, target, cfg, &accessors).await);
        }
        if cfg.probe_bola_nested {
            out.extend(
                probe_bola_nested_surface(client, url, target, cfg, &state.nested_chains).await,
            );
        }
        if cfg.probe_relay_global_id {
            out.extend(probe_relay_bola_surface(client, url, target, cfg, &accessors).await);
        }
    }

    // 20. Persisted-operation / operationName allowlist bypass surface.
    if cfg.probe_operation_allowlist {
        let names: Vec<String> = state
            .id_accessors
            .iter()
            .map(|a| a.field.clone())
            .chain(state.recovered_field_names.iter().cloned())
            .collect();
        out.extend(probe_operation_allowlist_surface(client, url, target, &names).await);
    }

    // 21. CORS misconfiguration on GraphQL transport.
    if cfg.probe_cors {
        out.extend(probe_cors_misconfig(client, url, target).await);
    }

    // 21. Variable tampering / type confusion (safe malformed variables).
    if cfg.probe_variable_tampering {
        out.extend(probe_variable_tampering(client, url, target).await);
    }

    // 22. Query cost / complexity metadata leak.
    if cfg.probe_query_cost {
        if let Some(f) = probe_query_cost_leak(client, url, target).await {
            out.push(f);
        }
    }

    // 23. GET cache poisoning surface.
    if cfg.probe_get_cache {
        if let Some(f) = probe_get_cache_surface(client, url, target).await {
            out.push(f);
        }
    }

    // 24. Interface / union possibleTypes metadata leak.
    if cfg.probe_interface_leak {
        if let Some(f) = probe_interface_union_leak(client, url, target).await {
            out.push(f);
        }
    }

    // 25. @defer / @stream incremental delivery surface.
    if cfg.probe_defer_stream {
        if let Some(f) = probe_defer_stream_surface(client, url, target).await {
            state.dos_vectors += 1;
            out.push(f);
        }
    }

    let intro_body = state.introspection_body.as_deref();
    if cfg.probe_pagination_abuse {
        out.extend(probe_pagination_abuse_surface(client, url, target, intro_body).await);
    }
    if cfg.probe_limit_fingerprint {
        if let Some(f) = probe_limit_fingerprint_surface(client, url, target, cfg).await {
            state.dos_vectors += 1;
            out.push(f);
        }
    }
    if cfg.probe_waf_evasion && !state.introspection {
        if let Some(f) = probe_waf_evasion_surface(client, url, target).await {
            state.introspection = true;
            out.push(f);
        }
    }
    if cfg.probe_live_data_leak {
        out.extend(probe_live_data_leak_surface(client, url, target, intro_body).await);
    }
}

/// Clairvoyance-style schema reconstruction: harvest 'did you mean' suggestions from the Query root.
async fn clairvoyance_recon(
    client: &reqwest::Client,
    url: &str,
    cfg: &GraphqlScanConfig,
) -> Vec<String> {
    let mut recovered = std::collections::BTreeSet::new();
    for field in cfg.recon_fields.iter().take(cfg.max_recon_fields) {
        let q = json!({ "query": format!("{{ {} }}", field) });
        if let Some(p) = post_json(client, url, &q).await {
            // Extract suggestions like: Cannot query field "x". Did you mean "userById" or "users"?
            if let Some(idx) = p.body.to_ascii_lowercase().find("did you mean") {
                let tail = &p.body[idx..];
                for token in tail.split('"').skip(1).step_by(2).take(6) {
                    let t = token.trim();
                    if !t.is_empty()
                        && t.len() <= 60
                        && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        recovered.insert(t.to_string());
                    }
                }
            }
        }
        if recovered.len() >= 200 {
            break;
        }
    }
    recovered.into_iter().collect()
}

/// Per-endpoint accumulated state used for attack-path synthesis + metrics.
#[derive(Default)]
struct EndpointState {
    introspection: bool,
    introspection_body: Option<String>,
    types: usize,
    mutations: usize,
    sensitive: usize,
    recon_fields: usize,
    dos_vectors: usize,
    csrf: bool,
    schema_graph: Vec<Value>,
    id_accessors: Vec<IdAccessor>,
    nested_chains: Vec<NestedIdChain>,
    recovered_field_names: Vec<String>,
}

async fn probe_ide_exposure(client: &reqwest::Client, url: &str, target: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut checked = std::collections::HashSet::new();
    let base = url.trim_end_matches('/');
    let origin = site_origin(url);
    let candidates: Vec<String> = std::iter::once(base.to_string())
        .chain(IDE_SIBLING_PATHS.iter().map(|p| format!("{origin}{p}")))
        .collect();
    for candidate in candidates {
        if !checked.insert(candidate.clone()) {
            continue;
        }
        let Some(p) = get(client, &candidate).await else {
            continue;
        };
        let bl = p.body.to_ascii_lowercase();
        let ide = if bl.contains("graphiql") {
            Some("GraphiQL")
        } else if bl.contains("graphql playground") || bl.contains("playground") {
            Some("GraphQL Playground")
        } else if bl.contains("apollo") && bl.contains("sandbox") {
            Some("Apollo Sandbox")
        } else if bl.contains("voyager") {
            Some("GraphQL Voyager")
        } else if bl.contains("altair") {
            Some("Altair GraphQL Client")
        } else {
            None
        };
        if let Some(name) = ide {
            out.push(finding(
                "ide",
                &format!("Exposed GraphQL developer console: {}", name),
                "medium",
                "T1190",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "{} serves the {} in-browser IDE. A public query console accelerates exploration and (with mutations) abuse.",
                    p.final_url, name
                ),
                &p.final_url,
                target,
                "ide_exposed",
                "Disable the GraphQL IDE in production or gate it behind authentication / an internal network.",
            ));
        }
    }
    out
}

async fn probe_subscription_ws(
    client: &reqwest::Client,
    http_url: &str,
    target: &str,
) -> Vec<Value> {
    let mut out = Vec::new();
    let ws_url = http_to_ws_url(http_url);
    for proto in [
        "graphql-transport-ws",
        "graphql-ws",
        "subscriptions-transport-ws",
    ] {
        let key = random_ws_key();
        let expected = ws_accept(&key);
        let resp = client
            .get(&ws_url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", key.clone())
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Protocol", proto)
            .send()
            .await;
        let Some(resp) = resp.ok() else {
            continue;
        };
        let status = resp.status().as_u16();
        let accept = resp
            .headers()
            .get("sec-websocket-accept")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if status == 101 && accept == expected {
            out.push(finding(
                "subscription",
                &format!("GraphQL subscription WebSocket open ({})", proto),
                "medium",
                "T1190",
                "API8:2023 Security Misconfiguration",
                &format!(
                    "{} upgraded to WebSocket with protocol `{}` — live subscription transport is reachable.",
                    ws_url, proto
                ),
                &ws_url,
                target,
                "subscription_ws_open",
                "Require authentication on subscription WebSocket handshakes; disable public subscription endpoints in production.",
            ));
            break;
        }
    }
    out
}

async fn probe_auth_differential(
    auth_client: &reqwest::Client,
    unauth_client: &reqwest::Client,
    url: &str,
    target: &str,
) -> Vec<Value> {
    let mut out = Vec::new();
    let auth = post_json(auth_client, url, &json!({ "query": INTROSPECTION_QUERY })).await;
    let unauth = post_json(unauth_client, url, &json!({ "query": INTROSPECTION_QUERY })).await;
    let (Some(auth_p), Some(unauth_p)) = (auth, unauth) else {
        return out;
    };
    let auth_schema = parse_schema(&auth_p.body);
    let unauth_schema = parse_schema(&unauth_p.body);
    match (auth_schema, unauth_schema) {
        (Some(a), Some(u)) if u.types >= a.types.saturating_sub(2) => {
            out.push(finding(
                "authz",
                "Authenticated session does not reduce schema exposure",
                "high",
                "T1213",
                "API3:2023 Broken Object Property Level Authorization",
                &format!(
                    "Introspection on {} returns ~{} types with auth vs ~{} without — elevated credentials do not hide the schema from lower-privilege callers.",
                    url, a.types, u.types
                ),
                url,
                target,
                "auth_schema_leak",
                "Ensure introspection and sensitive schema metadata require strong auth; different roles should see different schema views.",
            ));
        }
        (None, Some(u)) if u.types > 0 => {
            out.push(finding(
                "authz",
                "Full schema introspection available without authentication",
                "critical",
                "T1213",
                "API3:2023 Broken Object Property Level Authorization",
                &format!(
                    "Unauthenticated introspection on {} exposes {} types while authenticated introspection failed — the public attack surface is wider than the credentialed view.",
                    url, u.types
                ),
                url,
                target,
                "unauth_introspection",
                "Require authentication for all GraphQL access including introspection; never expose schema metadata anonymously.",
            ));
        }
        _ => {}
    }
    out
}

fn fingerprint_impl(p: &HttpProbe) -> Option<&'static str> {
    let bl = p.body.to_ascii_lowercase();
    if header_value(&p.headers, "x-hasura-admin-secret").is_some()
        || bl.contains("hasura")
        || bl.contains("x-hasura")
    {
        return Some("Hasura");
    }
    if bl.contains("apollo") || header_value(&p.headers, "apollo-require-preflight").is_some() {
        return Some("Apollo Server");
    }
    if bl.contains("graphql-ruby") || bl.contains("graphql_ruby") {
        return Some("graphql-ruby");
    }
    if bl.contains("graphene") {
        return Some("Graphene (Python)");
    }
    if bl.contains("mercurius") {
        return Some("Mercurius (Fastify)");
    }
    if bl.contains("appsync") || header_value(&p.headers, "x-amzn-requestid").is_some() {
        return Some("AWS AppSync");
    }
    None
}

// ── Attack-path synthesis ────────────────────────────────────────────────────────────────────────

fn has_class(findings: &[Value], class: &str) -> bool {
    findings
        .iter()
        .any(|f| f.get("vuln_class").and_then(Value::as_str) == Some(class))
}

fn count_sev(findings: &[Value], sev: &str) -> usize {
    findings
        .iter()
        .filter(|f| f.get("severity").and_then(Value::as_str) == Some(sev))
        .count()
}

/// Aggregate findings by OWASP API Top-10 category for posture dashboards.
fn compute_owasp_posture(findings: &[Value]) -> Value {
    let mut buckets: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for f in findings {
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        if cat == "attack_path" || cat == "graphql_metrics" || cat == "dry_run" {
            continue;
        }
        let Some(owasp) = f.get("owasp_api").and_then(Value::as_str) else {
            continue;
        };
        let key = owasp.split(':').next().unwrap_or(owasp).trim().to_string();
        *buckets.entry(key).or_insert(0) += 1;
    }
    json!(buckets)
}

/// Letter grade for an OWASP API category based on finding severities in that bucket.
fn owasp_category_grade(findings: &[Value], api_key: &str) -> &'static str {
    let mut worst = 0u8;
    for f in findings {
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        if cat == "attack_path" || cat == "graphql_metrics" || cat == "dry_run" {
            continue;
        }
        let Some(owasp) = f.get("owasp_api").and_then(Value::as_str) else {
            continue;
        };
        if !owasp.starts_with(api_key) {
            continue;
        }
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("info");
        worst = worst.max(sev_rank(sev));
    }
    match worst {
        0 => "A",
        1 | 2 => "B",
        3 => "C",
        4 => "D",
        _ => "F",
    }
}

/// OWASP API Top-10 compliance scorecard (A–F per category + overall).
fn compute_compliance_scorecard(findings: &[Value]) -> Value {
    let categories = [
        ("API1", "Broken Object Level Authorization"),
        ("API2", "Broken Authentication"),
        ("API3", "Broken Object Property Level Authorization"),
        ("API4", "Unrestricted Resource Consumption"),
        ("API5", "Broken Function Level Authorization"),
        ("API6", "Unrestricted Access to Sensitive Business Flows"),
        ("API7", "Server Side Request Forgery"),
        ("API8", "Security Misconfiguration"),
        ("API9", "Improper Inventory Management"),
        ("API10", "Unsafe Consumption of APIs"),
    ];
    let mut rows = Vec::new();
    let mut grade_scores: Vec<u8> = Vec::new();
    for (key, label) in categories {
        let grade = owasp_category_grade(findings, key);
        let score = match grade {
            "A" => 100,
            "B" => 85,
            "C" => 70,
            "D" => 55,
            _ => 30,
        };
        grade_scores.push(score);
        rows.push(json!({
            "category": key,
            "label": label,
            "grade": grade,
            "score": score,
        }));
    }
    let overall = if grade_scores.is_empty() {
        100
    } else {
        *grade_scores.iter().min().unwrap_or(&100)
    };
    let overall_grade = if overall >= 95 {
        "A"
    } else if overall >= 85 {
        "B"
    } else if overall >= 70 {
        "C"
    } else if overall >= 55 {
        "D"
    } else {
        "F"
    };
    json!({
        "overall_grade": overall_grade,
        "overall_score": overall,
        "categories": rows,
    })
}

/// Top remediation actions sorted by severity (for executive dashboards).
fn compute_remediation_priorities(findings: &[Value], limit: usize) -> Vec<Value> {
    let mut items: Vec<Value> = findings
        .iter()
        .filter(|f| {
            let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
            cat != "attack_path" && cat != "graphql_metrics" && cat != "dry_run"
        })
        .filter(|f| f.get("remediation").and_then(Value::as_str).is_some())
        .cloned()
        .collect();
    items.sort_by(|a, b| {
        let sa = sev_rank(a.get("severity").and_then(Value::as_str).unwrap_or("info"));
        let sb = sev_rank(b.get("severity").and_then(Value::as_str).unwrap_or("info"));
        sb.cmp(&sa)
    });
    items.truncate(limit);
    items
        .into_iter()
        .map(|f| {
            json!({
                "title": f.get("title"),
                "severity": f.get("severity"),
                "component": f.get("component"),
                "owasp_api": f.get("owasp_api"),
                "remediation": f.get("remediation"),
                "url": f.get("url"),
            })
        })
        .collect()
}

fn compute_executive_summary(
    exposure_score: u32,
    compliance: &Value,
    criticals: usize,
    highs: usize,
    endpoints: usize,
    components: u32,
    implementation: Option<&str>,
    remediation: &[Value],
) -> Value {
    let grade = compliance
        .get("overall_grade")
        .and_then(Value::as_str)
        .unwrap_or("—");
    let first_fix = remediation
        .first()
        .and_then(|r| r.get("remediation"))
        .and_then(Value::as_str)
        .unwrap_or(
            "Disable introspection and enforce object-level authorization on all resolvers.",
        );
    let risk_tier = if exposure_score >= 70 || criticals > 0 {
        "critical"
    } else if exposure_score >= 40 || highs > 0 {
        "elevated"
    } else {
        "moderate"
    };
    json!({
        "headline": format!(
            "GraphQL exposure {}/100 · OWASP grade {} · {} endpoint(s)",
            exposure_score, grade, endpoints
        ),
        "risk_tier": risk_tier,
        "exposure_score": exposure_score,
        "owasp_grade": grade,
        "endpoints_assessed": endpoints,
        "components_probed": components,
        "implementation": implementation,
        "critical_findings": criticals,
        "high_findings": highs,
        "recommended_first_action": first_fix,
    })
}

fn synthesize_attack_paths(findings: &[Value], target: &str) -> (Vec<Value>, u32) {
    let mut paths: Vec<Value> = Vec::new();
    let mut score: u32 = 0;
    let mk = |title: &str, sev: &str, steps: Vec<&str>, impact: &str| -> Value {
        json!({
            "type": ENGINE_ID,
            "engine_id": ENGINE_ID,
            "component": "attack_path",
            "category": "attack_path",
            "title": title,
            "severity": sev,
            "mitre_attack": "T1190",
            "owasp_api": "OWASP API Top-10 2023",
            "vuln_class": "attack_path",
            "description": format!("{}  |  Impact: {}", steps.join("  →  "), impact),
            "path_steps": steps,
            "target": target,
            "remediation": "Break the chain by remediating any single step; prioritise the first (discovery) node.",
        })
    };

    let schema_known = has_class(findings, "introspection_enabled")
        || has_class(findings, "schema_reconstruction");
    if schema_known && has_class(findings, "sensitive_schema_fields") {
        score += 80;
        paths.push(mk(
            "Targeted data exfiltration via exposed schema",
            "high",
            vec![
                "Recover full schema (introspection / suggestions)",
                "Locate sensitive fields (token/password/PII)",
                "Craft precise queries against weak field-authz",
                "Exfiltrate sensitive data",
            ],
            "Confidential data exposure (BOLA / BOPLA).",
        ));
    }
    if findings
        .iter()
        .filter(|f| f.get("component").and_then(Value::as_str) == Some("dos"))
        .count()
        >= 2
    {
        score += 55;
        paths.push(mk(
            "GraphQL denial-of-service amplification",
            "high",
            vec![
                "No depth/cost limit + alias amplification",
                "Array batching multiplies operations",
                "Single request → massive resolver fan-out",
                "Backend resource exhaustion",
            ],
            "Service outage from a single crafted request.",
        ));
    }
    if has_class(findings, "csrf_get") && schema_known {
        score += 45;
        paths.push(mk(
            "Brute-force / CSRF via GET + batching",
            "medium",
            vec![
                "Queries executable over GET",
                "Batching bypasses per-request rate limits",
                "Automate credential / IDOR brute-force",
            ],
            "Authentication brute-force and CSRF.",
        ));
    }
    if has_class(findings, "ide_exposed") && schema_known {
        score += 35;
        paths.push(mk(
            "Rapid exploitation via exposed console + schema",
            "medium",
            vec![
                "Open exposed GraphiQL/Playground",
                "Use known schema to build queries",
                "Iterate attacks interactively",
            ],
            "Lowered barrier to data access / abuse.",
        ));
    }
    if has_class(findings, "federation_sdl_exposed") {
        score += 50;
        paths.push(mk(
            "Federated subgraph takeover via exposed SDL",
            "high",
            vec![
                "Fetch _service { sdl }",
                "Map federated entities & resolvers",
                "Target weak @requires / @external fields",
                "Cross-subgraph data exfiltration",
            ],
            "Full federated API contract exposure.",
        ));
    }
    if has_class(findings, "rate_limit_absent")
        && (has_class(findings, "batching_enabled") || has_class(findings, "alias_amplification"))
    {
        score += 40;
        paths.push(mk(
            "Unthrottled brute-force / amplification",
            "high",
            vec![
                "No HTTP 429 on burst traffic",
                "Batching / alias amplification available",
                "Credential stuffing or DoS at wire speed",
            ],
            "Authentication bypass and outage.",
        ));
    }
    if has_class(findings, "unauth_introspection") || has_class(findings, "auth_schema_leak") {
        score += 60;
        paths.push(mk(
            "Broken auth boundary on schema metadata",
            "critical",
            vec![
                "Anonymous introspection succeeds",
                "Map mutations & sensitive fields",
                "Craft targeted queries without guessing",
            ],
            "Complete API contract leak to unauthenticated actors.",
        ));
    }
    if has_class(findings, "dangerous_mutations_exposed")
        && (has_class(findings, "csrf_get") || has_class(findings, "csrf_form"))
    {
        score += 55;
        paths.push(mk(
            "State-changing CSRF via exposed admin/delete mutations",
            "critical",
            vec![
                "Schema reveals delete/admin/grant mutations",
                "Queries or mutations reachable via GET/form CSRF",
                "Victim browser executes state-changing operation",
            ],
            "Account deletion, privilege escalation, or data destruction via CSRF.",
        ));
    }
    if has_class(findings, "bola_batch_enumeration") {
        score += 50;
        paths.push(mk(
            "Mass IDOR via alias-batch in single request",
            "critical",
            vec![
                "Schema reveals ID-gated Query field",
                "Alias-batch resolves multiple IDs at once",
                "Rate limits bypassed (one HTTP request)",
                "Horizontal privilege escalation at scale",
            ],
            "Large-scale BOLA without throttling.",
        ));
    }
    if has_class(findings, "graphql_cswsh") || has_class(findings, "cors_origin_reflection") {
        score += 45;
        paths.push(mk(
            "Cross-site GraphQL hijacking (CSWSH / CORS)",
            "high",
            vec![
                "Foreign Origin accepted on WebSocket or CORS",
                "Victim browser sends credentialed GraphQL calls",
                "Attacker site drives API queries/mutations",
            ],
            "Session-riding and data exfiltration from victim browser.",
        ));
    }
    if has_class(findings, "bola_idor_surface") && schema_known {
        score += 65;
        paths.push(mk(
            "Cross-user data access via predictable GraphQL IDs",
            "critical",
            vec![
                "Map ID-gated Query fields from schema",
                "Probe sequential / predictable object IDs",
                "Objects resolve without ownership check",
                "Enumerate IDs → mass data exfiltration",
            ],
            "Broken Object Level Authorization (BOLA) at scale.",
        ));
    }
    if has_class(findings, "unauth_user_field") || has_class(findings, "auth_noop_user_field") {
        score += 55;
        paths.push(mk(
            "Broken authentication on user-scoped GraphQL fields",
            "critical",
            vec![
                "Probe me/viewer/currentUser root fields",
                "Anonymous session receives user-scoped data",
                "Craft queries against weak auth context",
            ],
            "Session bypass and unauthorized profile access.",
        ));
    }
    if has_class(findings, "bola_nested_chain") {
        score += 70;
        paths.push(mk(
            "Cross-object exfiltration via nested BOLA chain",
            "critical",
            vec![
                "Schema maps parent→child ID gates",
                "Two-hop query resolves nested object",
                "Access other users' child records via parent ID",
            ],
            "Deep BOLA across object graph (e.g. user→orders).",
        ));
    }
    if has_class(findings, "hasura_role_spoof") {
        score += 75;
        paths.push(mk(
            "Hasura privilege escalation via role header spoof",
            "critical",
            vec![
                "x-hasura-role accepted from client",
                "Elevated role executes GraphQL resolvers",
                "Full data access / admin operations",
            ],
            "Complete GraphQL authorization bypass on Hasura.",
        ));
    }
    if has_class(findings, "persisted_query_hash_only") || has_class(findings, "operation_name_get")
    {
        score += 35;
        paths.push(mk(
            "Operation allowlist / persisted-query bypass",
            "high",
            vec![
                "APQ hash-only or GET operationName accepted",
                "Unregistered or CSRF-able operations execute",
                "Bypass WAF / allowlist controls",
            ],
            "Execution of non-allowlisted GraphQL operations.",
        ));
    }
    if has_class(findings, "defer_stream_enabled") {
        score += 25;
        paths.push(mk(
            "Long-lived incremental GraphQL exhaustion (@defer / @stream)",
            "medium",
            vec![
                "Server accepts @defer / @stream directives",
                "Attacker opens incremental/multipart response",
                "Connection held → resolver fan-out / memory pressure",
            ],
            "DoS via incremental delivery abuse.",
        ));
    }
    if has_class(findings, "subscription_ws_open") && schema_known {
        score += 30;
        paths.push(mk(
            "Live data stream abuse via WebSocket subscriptions",
            "medium",
            vec![
                "WebSocket subscription transport open",
                "Known schema drives subscription selection",
                "Real-time data exfiltration / event spam",
            ],
            "Continuous unauthorized data streaming.",
        ));
    }
    if (has_class(findings, "subscription_sse_open") || has_class(findings, "subscription_sse_get"))
        && schema_known
    {
        score += 25;
        paths.push(mk(
            "Live data stream abuse via SSE subscriptions",
            "medium",
            vec![
                "SSE subscription transport reachable",
                "Schema guides subscription field selection",
                "Event stream exfiltration without WebSocket",
            ],
            "Continuous unauthorized data streaming over HTTP.",
        ));
    }
    if has_class(findings, "relay_global_id_bola") {
        score += 60;
        paths.push(mk(
            "Apollo/Relay global-ID BOLA chain",
            "critical",
            vec![
                "Schema reveals ID-gated node fields",
                "Relay global IDs encode predictable type:id pairs",
                "Cross-user object resolution without authZ",
            ],
            "BOLA on Relay-style APIs at scale.",
        ));
    }
    if has_class(findings, "live_data_exposure") && schema_known {
        score += 70;
        paths.push(mk(
            "Anonymous bulk data harvest via open root fields",
            "critical",
            vec![
                "Schema + live query confirm populated collections",
                "No auth gate on users/orders/me root fields",
                "Mass exfiltration in a single read-only query",
            ],
            "Real PII/records exposed to unauthenticated callers.",
        ));
    }
    if has_class(findings, "waf_introspection_bypass") {
        score += 65;
        paths.push(mk(
            "WAF bypass → full schema recovery",
            "critical",
            vec![
                "Standard introspection blocked at edge",
                "Encoding/CT/comment variant bypasses WAF",
                "Complete API contract recovered",
            ],
            "Defense-in-depth failure — engine-level introspection still on.",
        ));
    }
    if has_class(findings, "pagination_unbounded") {
        score += 40;
        paths.push(mk(
            "Connection pagination bulk exfiltration",
            "high",
            vec![
                "Relay-style connection accepts huge first:N",
                "Single query returns large edge sets",
                "Bypasses rate limits vs many paginated requests",
            ],
            "Unrestricted collection harvesting.",
        ));
    }
    if has_class(findings, "alias_limit_absent") {
        score += 35;
        paths.push(mk(
            "Alias amplification DoS without effective ceiling",
            "high",
            vec![
                "200+ aliases accepted in one operation",
                "Combine with batching / subscriptions",
                "Resolver fan-out exhausts backend",
            ],
            "Single-request DoS.",
        ));
    }

    score += (count_sev(findings, "critical") as u32) * 14;
    score += (count_sev(findings, "high") as u32) * 8;
    score += (count_sev(findings, "medium") as u32) * 3;
    (paths, score.min(100))
}

// ── Public entry points ──────────────────────────────────────────────────────────────────────────

/// Back-compat entry (CLI / orchestrator default path) — runs with default config.
pub async fn run_graphql_attack_result(target: &str) -> EngineResult {
    run_graphql_attack_result_ctx(target, &EngineRunContext::default()).await
}

/// Full, parameter-driven GraphQL & API security assessment.
pub async fn run_graphql_attack_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = GraphqlScanConfig::from_params(&ctx.job_params);
    let host = extract_host(target);
    let base = crate::engine_probes::normalize_url(target);

    if cfg.dry_run {
        let plan = json!({
            "type": ENGINE_ID,
            "component": "plan",
            "category": "dry_run",
            "title": "GraphQL security scan plan (dry-run — no requests sent)",
            "severity": "info",
            "target": target,
            "host": host,
            "components": cfg.enabled_components(),
            "graphql_paths": cfg.graphql_paths,
            "alias_count": cfg.alias_count,
            "batch_count": cfg.batch_count,
            "depth_levels": cfg.depth_levels,
            "field_duplication_count": cfg.field_duplication_count,
            "burst_count": cfg.burst_count,
            "fragment_spread_depth": cfg.fragment_spread_depth,
            "bola_test_ids": cfg.bola_test_ids,
            "bola_id_range_start": cfg.bola_id_range_start,
            "bola_id_range_end": cfg.bola_id_range_end,
            "max_bola_probes": cfg.max_bola_probes,
            "has_auth": cfg.has_auth_credentials(),
            "recon_fields": cfg.recon_fields.len().min(cfg.max_recon_fields),
            "attack_path_synthesis": cfg.attack_path_synthesis,
        });
        return EngineResult::ok(
            vec![plan],
            format!(
                "graphql_attack dry-run: {} components across {} candidate paths for {}",
                cfg.enabled_components(),
                cfg.graphql_paths.len(),
                host
            ),
        );
    }

    let started = Instant::now();
    let client = build_client(&cfg);
    let unauth_client = if cfg.probe_auth_differential && cfg.has_auth_credentials() {
        let mut unauth_cfg = cfg.clone();
        unauth_cfg.bearer_token = None;
        unauth_cfg.api_key = None;
        unauth_cfg.cookie = None;
        unauth_cfg.extra_headers.retain(|(k, _)| !is_auth_header(k));
        Some(build_client(&unauth_cfg))
    } else {
        None
    };
    let base_trim = base.trim_end_matches('/').to_string();

    let mut findings: Vec<Value> = Vec::new();
    let mut endpoints_found = 0usize;
    let mut introspectable = 0usize;
    let mut total_dos = 0usize;
    let mut implementation: Option<&'static str> = None;
    let mut schema_graph: Vec<Value> = Vec::new();

    for path in &cfg.graphql_paths {
        let url = format!("{}{}", base_trim, path);
        // Cheap detection probe first.
        let Some(detect) = post_json(&client, &url, &json!({ "query": "{__typename}" })).await
        else {
            continue;
        };
        if !looks_like_graphql(&detect) {
            continue;
        }
        endpoints_found += 1;
        findings.push(finding(
            "endpoint",
            &format!("GraphQL endpoint discovered: {}", path),
            "info",
            "T1046",
            "API9:2023 Improper Inventory Management",
            &format!("{} responds as a GraphQL endpoint (HTTP {}). Inventory it and ensure it is governed by the API gateway / WAF.", detect.final_url, detect.status),
            &detect.final_url,
            target,
            "endpoint_discovered",
            "Inventory every GraphQL endpoint; route it through the API gateway with authN/Z, rate limiting and a WAF.",
        ));

        if cfg.probe_fingerprint && implementation.is_none() {
            implementation = fingerprint_impl(&detect);
            if let Some(name) = implementation {
                findings.push(finding(
                    "fingerprint",
                    &format!("GraphQL implementation fingerprinted: {}", name),
                    "info",
                    "T1046",
                    "API9:2023 Improper Inventory Management",
                    &format!("Response signatures identify the server as {}. Track its CVEs and harden per vendor guidance.", name),
                    &detect.final_url,
                    target,
                    "implementation_fingerprint",
                    "Keep the GraphQL server patched; apply the vendor's production hardening checklist.",
                ));
            }
        }

        let mut state = EndpointState::default();
        assess_endpoint(&client, &url, &cfg, target, &mut findings, &mut state).await;
        if cfg.probe_ide_exposure {
            findings.extend(probe_ide_exposure(&client, &url, target).await);
        }
        if cfg.probe_subscription_ws {
            findings.extend(probe_subscription_ws(&client, &url, target).await);
        }
        if cfg.probe_subscription_sse {
            findings.extend(probe_subscription_sse_surface(&client, &url, target).await);
        }
        if cfg.probe_cswsh {
            findings.extend(probe_graphql_cswsh(&client, &url, target).await);
        }
        if cfg.probe_hasura_surface {
            findings.extend(
                probe_hasura_hardening_surface(&client, &url, target, implementation).await,
            );
        }
        if cfg.probe_auth_differential || cfg.probe_field_auth_diff {
            if let Some(ref uc) = unauth_client {
                if cfg.has_auth_credentials() {
                    if cfg.probe_auth_differential {
                        findings.extend(probe_auth_differential(&client, uc, &url, target).await);
                    }
                    if cfg.probe_field_auth_diff {
                        findings.extend(
                            probe_field_level_auth_differential(&client, uc, &url, target).await,
                        );
                    }
                }
            }
        }
        if state.introspection {
            introspectable += 1;
        }
        total_dos += state.dos_vectors;
        if schema_graph.is_empty() && !state.schema_graph.is_empty() {
            schema_graph = state.schema_graph.clone();
        }
    }

    if endpoints_found == 0 {
        return EngineResult::ok(
            vec![],
            format!("graphql_attack: no GraphQL endpoint observed on {}", host),
        );
    }

    let (attack_paths, exposure_score) = if cfg.attack_path_synthesis {
        synthesize_attack_paths(&findings, target)
    } else {
        (Vec::new(), 0)
    };
    let surfaces = findings.len();
    findings.extend(attack_paths.iter().cloned());

    // Filter by min severity (keep attack paths), tag, dedupe, sort, cap.
    let min_rank = sev_rank(&cfg.min_severity);
    if min_rank > 1 {
        findings.retain(|f| {
            let s = f.get("severity").and_then(Value::as_str).unwrap_or("info");
            f.get("category").and_then(Value::as_str) == Some("attack_path")
                || sev_rank(s) >= min_rank
        });
    }
    if !cfg.tags.is_empty() {
        for f in &mut findings {
            if let Some(obj) = f.as_object_mut() {
                obj.insert("tags".to_string(), json!(cfg.tags));
            }
        }
    }
    if cfg.dedupe_findings {
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| {
            let key = format!(
                "{}|{}|{}",
                f.get("component").and_then(Value::as_str).unwrap_or(""),
                f.get("title").and_then(Value::as_str).unwrap_or(""),
                f.get("url").and_then(Value::as_str).unwrap_or("")
            );
            seen.insert(key)
        });
    }
    findings.sort_by(|a, b| {
        let sa = sev_rank(a.get("severity").and_then(Value::as_str).unwrap_or("info"));
        let sb = sev_rank(b.get("severity").and_then(Value::as_str).unwrap_or("info"));
        sb.cmp(&sa)
    });
    if findings.len() > cfg.max_findings {
        findings.truncate(cfg.max_findings);
    }

    let criticals = count_sev(&findings, "critical");
    let highs = count_sev(&findings, "high");

    let sig = supreme::collect_signals(&findings, endpoints_found);
    if cfg.attack_path_synthesis {
        supreme::extend_attack_paths(target, &sig, &mut findings);
    }
    supreme::emit_toxic_headline(target, &sig, &mut findings);
    supreme::emit_remediation_roadmap(target, &sig, &mut findings);
    if jp_bool(&ctx.job_params, "emit_agent_guidance", true) {
        supreme::emit_agent_guidance(target, &mut findings);
    }
    let category_scores = supreme::finalize_category_scores(&sig);
    let (graph_nodes, graph_edges) = supreme::build_security_graph(target, &sig, &host);

    if cfg.emit_metrics {
        let owasp_posture = compute_owasp_posture(&findings);
        let compliance = compute_compliance_scorecard(&findings);
        let remediation_priorities = compute_remediation_priorities(&findings, 12);
        let executive_summary = compute_executive_summary(
            exposure_score,
            &compliance,
            criticals,
            highs,
            endpoints_found,
            cfg.enabled_components(),
            implementation,
            &remediation_priorities,
        );
        findings.push(json!({
            "type": ENGINE_ID,
            "component": "summary",
            "category": "graphql_metrics",
            "title": "GraphQL API Exposure Summary",
            "severity": "info",
            "target": target,
            "graphql_metrics": {
                "host": host,
                "components_probed": cfg.enabled_components(),
                "endpoints_found": endpoints_found,
                "introspectable_endpoints": introspectable,
                "dos_vectors": total_dos,
                "surfaces_exposed": surfaces,
                "criticals": criticals,
                "highs": highs,
                "mediums": count_sev(&findings, "medium"),
                "attack_paths": attack_paths.len(),
                "exposure_score": exposure_score,
                "implementation": implementation,
                "schema_graph": schema_graph,
                "owasp_posture": owasp_posture,
                "compliance_scorecard": compliance,
                "remediation_priorities": remediation_priorities,
                "executive_summary": executive_summary,
                "has_auth": cfg.has_auth_credentials(),
                "scan_ms": started.elapsed().as_millis() as u64,
                "category_scores": category_scores.to_json(),
            },
        }));
    }

    let msg = format!(
        "graphql_attack: {} finding(s) ({} critical / {} high) · {} endpoint(s) · exposure {} · {} attack path(s) in {} ms",
        findings.len().saturating_sub(if cfg.emit_metrics { 1 } else { 0 }),
        criticals,
        highs,
        endpoints_found,
        exposure_score,
        attack_paths.len(),
        started.elapsed().as_millis()
    );
    let toxic = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) == Some("toxic_combination"))
        .count();
    EngineResult::ok_with_graph(
        findings,
        format!(
            "{msg}{}",
            if toxic > 0 {
                format!(", {toxic} toxic combo(s)")
            } else {
                String::new()
            }
        ),
        graph_nodes,
        graph_edges,
    )
}

pub async fn run_graphql_attack(target: &str) {
    print_result(run_graphql_attack_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_scorecard_grades_categories() {
        let findings = vec![
            json!({"owasp_api":"API1:2023 Broken Object Level Authorization","severity":"high","category":"api_security"}),
            json!({"owasp_api":"API8:2023 Security Misconfiguration","severity":"medium","category":"api_security"}),
        ];
        let card = compute_compliance_scorecard(&findings);
        assert_eq!(card.get("overall_grade").and_then(Value::as_str), Some("D"));
        let cats = card.get("categories").and_then(Value::as_array).unwrap();
        assert_eq!(cats.len(), 10);
    }

    fn parse_nested_id_chains_from_introspection() {
        let body = json!({
            "data": { "__schema": { "queryType": { "fields": [{
                "name": "user",
                "args": [{"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}],
                "type": {"kind": "OBJECT", "name": "User", "fields": [
                    {"name": "orders", "args": [{"name": "orderId", "type": {"kind": "SCALAR", "name": "ID"}}]}
                ]}
            }]}}}
        }).to_string();
        let chains = parse_nested_id_chains(&body);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].root.field, "user");
        assert_eq!(chains[0].nested.field, "orders");
    }

    #[test]
    fn config_defaults_enable_all_components() {
        let cfg = GraphqlScanConfig::default();
        assert_eq!(cfg.enabled_components(), 47);
        assert!(cfg.graphql_paths.iter().any(|p| p == "/graphql"));
    }

    #[test]
    fn config_parses_overrides_and_nested_options() {
        let p = json!({
            "probe_batching": false,
            "options": { "alias_count": 250, "graphql_paths": "/gql, /api/graphql" },
            "min_severity": "high",
            "extra_headers": { "Authorization": "Bearer t" }
        });
        let cfg = GraphqlScanConfig::from_params(&p);
        assert!(!cfg.probe_batching);
        assert_eq!(cfg.alias_count, 250);
        assert_eq!(cfg.graphql_paths, vec!["/gql", "/api/graphql"]);
        assert_eq!(cfg.min_severity, "high");
        assert_eq!(cfg.extra_headers.len(), 1);
    }

    #[test]
    fn alias_overload_and_nested_queries_build() {
        let q = alias_overload_query(3);
        assert!(q.contains("a0:__typename") && q.contains("a2:__typename"));
        let d = nested_introspection_query(2);
        assert!(d.contains("__schema") && d.matches("ofType").count() == 2);
    }

    #[test]
    fn looks_like_graphql_detects_shapes() {
        let json_resp = HttpProbe {
            status: 200,
            headers: vec![],
            body: r#"{"data":{"__typename":"Query"}}"#.to_string(),
            final_url: "u".to_string(),
        };
        assert!(looks_like_graphql(&json_resp));
        let err_resp = HttpProbe {
            status: 400,
            headers: vec![],
            body: "Must provide query string.".to_string(),
            final_url: "u".to_string(),
        };
        assert!(looks_like_graphql(&err_resp));
        let html = HttpProbe {
            status: 200,
            headers: vec![],
            body: "<html>hello</html>".to_string(),
            final_url: "u".to_string(),
        };
        assert!(!looks_like_graphql(&html));
    }

    #[test]
    fn parse_schema_counts_types_and_sensitive_fields() {
        let body = json!({
            "data": { "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": null,
                "types": [
                    {"name": "Query", "kind": "OBJECT", "fields": [{"name":"users"},{"name":"me"}]},
                    {"name": "Mutation", "kind": "OBJECT", "fields": [{"name":"login"}]},
                    {"name": "User", "kind": "OBJECT", "fields": [{"name":"id"},{"name":"passwordHash"},{"name":"apiKey"}]},
                    {"name": "__Type", "kind": "OBJECT", "fields": [{"name":"x"}]}
                ]
            }}
        }).to_string();
        let s = parse_schema(&body).unwrap();
        assert_eq!(s.types, 3); // __Type excluded
        assert_eq!(s.query_fields, 2);
        assert_eq!(s.mutation_fields, 1);
        assert!(s
            .sensitive_fields
            .iter()
            .any(|f| f.contains("passwordHash")));
        assert!(s.sensitive_fields.iter().any(|f| f.contains("apiKey")));
    }

    #[test]
    fn parse_schema_flags_dangerous_mutations() {
        let body = json!({
            "data": { "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": null,
                "types": [
                    {"name": "Query", "kind": "OBJECT", "fields": [{"name":"users"}]},
                    {"name": "Mutation", "kind": "OBJECT", "fields": [
                        {"name":"deleteUser"},
                        {"name":"updateProfile"},
                        {"name":"grantAdminRole"}
                    ]},
                ]
            }}
        })
        .to_string();
        let s = parse_schema(&body).unwrap();
        assert_eq!(s.dangerous_mutations.len(), 2);
        assert!(s.dangerous_mutations.iter().any(|m| m == "deleteUser"));
        assert!(s.dangerous_mutations.iter().any(|m| m == "grantAdminRole"));
    }

    #[test]
    fn owasp_posture_buckets_findings() {
        let findings = vec![
            json!({"owasp_api":"API3:2023 Broken Object Property Level Authorization","category":"api_security"}),
            json!({"owasp_api":"API4:2023 Unrestricted Resource Consumption","category":"api_security"}),
            json!({"owasp_api":"API4:2023 Unrestricted Resource Consumption","category":"api_security"}),
            json!({"category":"attack_path"}),
        ];
        let posture = compute_owasp_posture(&findings);
        assert_eq!(posture.get("API3").and_then(Value::as_u64), Some(1));
        assert_eq!(posture.get("API4").and_then(Value::as_u64), Some(2));
    }

    #[test]
    fn build_bola_query_formats_args() {
        let acc = IdAccessor {
            field: "user".into(),
            arg: "id".into(),
            numeric: false,
        };
        let q = build_bola_query(&acc, "42");
        assert!(q.contains("user(id: \"42\")"));
    }

    #[test]
    fn relay_global_id_and_connection_roots() {
        assert_eq!(relay_global_id("User", "42"), B64.encode("User:42"));
        let body = json!({
            "data": { "__schema": { "queryType": { "fields": [
                {"name": "users", "args": [{"name": "first", "type": {"kind": "SCALAR", "name": "Int"}}]},
                {"name": "node", "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID"}}]}
            ]}}}
        }).to_string();
        let roots = parse_connection_roots(&body);
        assert_eq!(roots, vec!["users".to_string()]);
    }

    #[test]
    fn effective_bola_ids_merge_range() {
        let mut cfg = GraphqlScanConfig::default();
        cfg.bola_test_ids = vec!["99".into()];
        cfg.bola_id_range_start = 1;
        cfg.bola_id_range_end = 3;
        let ids = cfg.effective_bola_test_ids();
        assert!(ids.contains(&"99".to_string()));
        assert!(ids.contains(&"1".to_string()));
        assert!(ids.contains(&"3".to_string()));
    }

    #[test]
    fn parse_id_accessors_from_introspection() {
        let body = json!({
            "data": { "__schema": { "queryType": { "fields": [
                {"name": "user", "args": [{"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
                {"name": "health", "args": []}
            ]}}}
        }).to_string();
        let acc = parse_id_accessors(&body);
        assert_eq!(acc.len(), 1);
        assert_eq!(acc[0].field, "user");
    }

    #[test]
    fn synthesize_attack_paths_from_findings() {
        let findings = vec![
            json!({"vuln_class":"introspection_enabled","severity":"high","component":"introspection"}),
            json!({"vuln_class":"sensitive_schema_fields","severity":"high","component":"schema"}),
        ];
        let (paths, score) = synthesize_attack_paths(&findings, "https://x.test");
        assert!(!paths.is_empty());
        assert!(score >= 80);
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_graphql_attack_result("").await;
        assert!(!r.success);
    }

    #[tokio::test]
    async fn dry_run_emits_plan_without_requests() {
        let ctx = EngineRunContext {
            job_params: json!({ "dry_run": true }),
            ..Default::default()
        };
        let r = run_graphql_attack_result_ctx("https://api.example", &ctx).await;
        assert!(r.success);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0]["category"], "dry_run");
    }
}
