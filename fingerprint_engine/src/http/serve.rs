//! Full-stack live server: API + dashboard from Rust. Live data only; no dummy.
//! Auth: POST /api/login returns JWT in HttpOnly cookie (+ `access_token` in JSON for SPA Bearer).
//! API/WS/SSE use cookie or `Authorization: Bearer` only — never query-string credentials.
//! `/ws/agent` agent sessions (`?token=` agent JWT only). See [`crate::auth_jwt`].
//! Set `WEISSMAN_COOKIE_SECURE=1` when serving only over HTTPS; default is off so `http://127.0.0.1` dev accepts cookies.
//!
//! Environment (Postgres):
//! - `DATABASE_URL` — pooled app role (`weissman_app`, RLS via `app.current_tenant_id`).
//! - `WEISSMAN_AUTH_DATABASE_URL` — optional; defaults to `DATABASE_URL`; use `weissman_auth` for login/bootstrap.
//! - `WEISSMAN_MIGRATE_URL` — optional superuser URL; `weissman-server` runs migrations at startup when set.
//! - `WEISSMAN_PG_BACKUP_DIR` + `WEISSMAN_PG_DUMP_PATH` — optional periodic / manual `pg_dump` backups.

use async_stream::stream;
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Extension, Path, Query, Request, State,
    },
    http::{
        header::CONTENT_DISPOSITION, header::CONTENT_TYPE, HeaderMap, HeaderValue, Method,
        StatusCode,
    },
    middleware::{self, Next},
    response::sse::{Event, Sse},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{delete, get, patch, post, put},
    Router,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use chrono_tz::Asia::Jerusalem;
use dashmap::DashMap;
use flume::TrySendError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use sqlx::Row;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tower::util::ServiceExt;
use tower_http::services::ServeDir;

use crate::audit_log;
use crate::auth_jwt::{self, AuthContext};
use crate::auto_heal;
use crate::dag_engine;
use crate::dag_pipeline;
use crate::db;
use crate::deception_engine;
use crate::exploit_synthesis_engine;
use crate::risk_graph;
use crate::threat_intel_engine;

use super::client_ip::extract_client_ip;

/// Persisted in poe_jobs table; broadcast for SSE.
#[derive(Clone, Serialize)]
struct PoEJobState {
    job_id: String,
    status: String,
    run_id: Option<i64>,
    findings_count: Option<usize>,
    message: Option<String>,
    error: Option<String>,
}

/// Bounded central channel for PoE job updates; try_send prevents slow clients from exhausting RAM.
const POE_UPDATES_CHANNEL_CAPACITY: usize = 100;
type PoeJobRegistry = Arc<DashMap<String, Vec<flume::Sender<String>>>>;

/// Global error/telemetry broadcast: engine failures (timeout, DB lock, LLM unreachable, etc.) so UI can show Toast.
const TELEMETRY_BROADCAST_CAPACITY: usize = 128;

pub struct AppState {
    pub app_pool: Arc<PgPool>,
    pub intel_pool: Arc<PgPool>,
    pub auth_pool: Arc<PgPool>,
    /// Optional read-only pool (separate role with SELECT-only grants).
    /// When `Some`, Ask Weissman and Command Center dashboard reads use this
    /// pool (`weissman_ro`). Defense-in-depth: even if validation breaks, Postgres rejects writes.
    pub read_only_pool: Option<Arc<PgPool>>,
    started_at: Instant,
    timing_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    redteam_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    radar_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    /// PoE SSE: registry job_id -> list of bounded client channels; updates_tx feeds distributor that sends only to that job's subscribers.
    poe_job_registry: PoeJobRegistry,
    poe_job_updates_tx: flume::Sender<(String, String)>,
    /// Global error telemetry: broadcast to all connected Cockpit clients for Toast. Payload: JSON { engine, message, severity }.
    telemetry_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    /// Sequenced Command Center telemetry: raw telemetry tagged with a monotonic `_seq` by the
    /// replay recorder; consumed by `/ws/command-center` so a live client can track its position.
    cc_sequenced_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    /// Bounded per-tenant telemetry history for reconnect replay (Last-Event-ID).
    pub replay_buffer: Arc<crate::http::event_replay::EventReplayBuffer>,
    /// Phase 5: multi-agent swarm events for `/ws/swarm`.
    pub swarm_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    /// Batched edge swarm heartbeats (30s flush) to reduce Postgres churn.
    pub edge_heartbeat_batcher: crate::edge_heartbeat_batch::EdgeHeartbeatBatcher,
    /// Optional sovereign C2: outbound commands to in-process swarm consumers (`WEISSMAN_SOVEREIGN_MPSC_CAPACITY`).
    pub sovereign_swarm_tx:
        Option<Arc<tokio::sync::mpsc::Sender<crate::sovereign_c2::SovereignSwarmCmd>>>,
    sovereign_swarm_rx: std::sync::Mutex<
        Option<tokio::sync::mpsc::Receiver<crate::sovereign_c2::SovereignSwarmCmd>>,
    >,
    /// Endpoint-agent live session registry (one entry per online agent_uuid).
    pub endpoint_agents: Arc<crate::endpoint_agents::AgentRegistry>,
}

impl AppState {
    /// Dashboard and other read-only surfaces. Prefers `weissman_ro` when configured.
    #[must_use]
    pub fn read_pool(&self) -> &PgPool {
        self.read_only_pool
            .as_deref()
            .unwrap_or(self.app_pool.as_ref())
    }

    pub(crate) fn take_sovereign_swarm_rx(
        &self,
    ) -> Option<tokio::sync::mpsc::Receiver<crate::sovereign_c2::SovereignSwarmCmd>> {
        self.sovereign_swarm_rx
            .lock()
            .ok()
            .and_then(|mut g| g.take())
    }
}

/// Format UTC datetime string from DB to Israel time (Asia/Jerusalem).
fn utc_str_to_israel(utc_str: &str) -> String {
    let s = utc_str.trim();
    if s.is_empty() {
        return "—".to_string();
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        let utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        let il = utc.with_timezone(&Jerusalem);
        return il.format("%d/%m/%Y %H:%M Israel").to_string();
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        let utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        let il = utc.with_timezone(&Jerusalem);
        return il.format("%d/%m/%Y %H:%M Israel").to_string();
    }
    s.to_string()
}

/// Where a bearer token was read from (for path-specific validation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenSource {
    HeaderOrCookie,
    QueryAgentWsToken,
}

/// Extract JWT from Cookie (`weissman_token`) or `Authorization: Bearer` only.
fn extract_token_from_request<B>(req: &Request<B>, path: &str) -> Option<(String, TokenSource)> {
    // Agent WS: prefer `?token=` so a human session cookie cannot shadow the agent JWT.
    if path == "/ws/agent" {
        if let Some(q) = req.uri().query() {
            for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
                if k == "token" {
                    let t = v.trim();
                    if !t.is_empty() {
                        return Some((t.to_owned(), TokenSource::QueryAgentWsToken));
                    }
                }
            }
        }
    }
    if let Some(cookie_h) = req.headers().get(axum::http::header::COOKIE) {
        if let Ok(s) = cookie_h.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                let prefix = format!("{}=", auth_jwt::WEISSMAN_COOKIE_NAME);
                if part.starts_with(&prefix) {
                    let t = part[prefix.len()..].trim();
                    if !t.is_empty() {
                        return Some((t.to_string(), TokenSource::HeaderOrCookie));
                    }
                }
            }
        }
    }
    if let Some(auth_h) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = auth_h.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                let t = t.trim();
                if !t.is_empty() {
                    return Some((t.to_string(), TokenSource::HeaderOrCookie));
                }
            }
        }
    }
    None
}

fn verify_token_for_request(token: &str, path: &str, source: TokenSource) -> Option<AuthContext> {
    match source {
        TokenSource::HeaderOrCookie => {
            if path == "/ws/agent" {
                auth_jwt::verify_agent_session_token(token)
            } else {
                auth_jwt::verify_access_token(token).filter(auth_jwt::is_user_access_context)
            }
        }
        TokenSource::QueryAgentWsToken => {
            if path != "/ws/agent" {
                return None;
            }
            auth_jwt::verify_agent_session_token(token)
        }
    }
}

/// Whether an unauthenticated route is always public or only reachable outside production.
#[derive(Clone, Copy)]
enum RouteGate {
    Always,
    /// Public only when NOT running in production (interactive API docs / OpenAPI JSON).
    NonProdOnly,
}

/// Declarative allow-list of routes reachable WITHOUT authentication. This replaces a
/// hand-maintained chain of `if path == "…" && method == …` blocks inside `auth_guard`,
/// where a single typo or omission silently changed the security posture. Adding a public
/// route means adding one row here, and `public_route_guard_tests` assert the table stays
/// honest. (Login + MFA-verify are matched separately by `is_account_lockout_post`, which
/// intentionally spans several paths.)
static PUBLIC_ROUTES: &[(Method, &str, RouteGate)] = &[
    (Method::GET, "/api/health", RouteGate::Always),
    (Method::POST, "/api/logout", RouteGate::Always),
    (Method::POST, "/api/auth/refresh", RouteGate::Always),
    (Method::POST, "/api/onboarding/register", RouteGate::Always),
    (Method::POST, "/api/webhooks/paddle", RouteGate::Always),
    (Method::GET, "/api/auth/oidc/begin", RouteGate::Always),
    (Method::GET, "/api/auth/oidc/callback", RouteGate::Always),
    (Method::POST, "/api/auth/saml/acs", RouteGate::Always),
    (Method::GET, "/api/auth/saml/begin", RouteGate::Always),
    (Method::POST, "/api/deception/aws-events", RouteGate::Always),
    // Slack interactivity callback — authenticated by Slack's request signature, not a JWT.
    (
        Method::POST,
        "/api/integrations/slack/interactivity",
        RouteGate::Always,
    ),
    (Method::POST, "/api/auth/signup", RouteGate::Always),
    (Method::GET, "/api/auth/verify", RouteGate::Always),
    (Method::POST, "/api/public/demo-request", RouteGate::Always),
    (Method::POST, "/api/v1/alerts/aws-canary", RouteGate::Always),
    // Public service status (SLA_AND_STATUS.md §4) — must be readable during an incident.
    (Method::GET, "/status", RouteGate::Always),
    (Method::POST, "/api/agents/enroll", RouteGate::Always),
    // Session renewal: unauthenticated for the same reason as /enroll — the agent presents
    // its own long-lived secret, which IS the credential. Without a public renewal path an
    // agent goes permanently dark when its 4h session JWT expires.
    (Method::POST, "/api/agents/session", RouteGate::Always),
    // Prometheus scrape endpoint — authenticated by the metrics token (WEISSMAN_METRICS_TOKEN),
    // not a user JWT. The handler (observability::api_prometheus_metrics_endpoint) enforces the
    // token itself and fails closed (401) when the token is unset or < 32 chars, so deferring the
    // JWT guard here is what lets Prometheus scrape at all.
    (Method::GET, "/api/metrics", RouteGate::Always),
    (Method::GET, "/api/openapi.json", RouteGate::NonProdOnly),
    (Method::GET, "/api/docs", RouteGate::NonProdOnly),
    (Method::GET, "/api/docs/", RouteGate::NonProdOnly),
];

/// True when `(method, path)` is an exact match on the unauthenticated allow-list.
fn is_public_route(method: &Method, path: &str) -> bool {
    PUBLIC_ROUTES.iter().any(|(m, p, gate)| {
        m == method
            && *p == path
            && match gate {
                RouteGate::Always => true,
                RouteGate::NonProdOnly => !weissman_core::tls_policy::is_production_environment(),
            }
    })
}

/// Auth middleware: allow only the declared public routes; all other /api/* require valid JWT.
async fn auth_guard(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let method = request.method();
    // Unauthenticated login + MFA verify (per-IP rate limit + per-email lockout in handlers).
    if crate::http::is_account_lockout_post(method, path) {
        return next.run(request).await;
    }
    // Everything else reachable without a JWT is declared once in PUBLIC_ROUTES.
    if is_public_route(method, path) {
        return next.run(request).await;
    }
    if path.starts_with("/api/") || path.starts_with("/ws/") {
        let extracted = extract_token_from_request(&request, path);
        if let Some((t, source)) = extracted {
            if let Some(mut ctx) = verify_token_for_request(&t, path, source) {
                if auth_jwt::is_user_access_context(&ctx) {
                    let Some(ref jti) = ctx.jti else {
                        tracing::debug!(
                            target: "auth_guard",
                            path = %path,
                            "Access token missing jti — re-login required"
                        );
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "detail": "Token missing jti; re-login required",
                                "ok": false,
                                "code": "token_missing_jti",
                            })),
                        )
                            .into_response();
                    };
                    match crate::auth_refresh::is_access_jti_revoked(state.auth_pool.as_ref(), jti)
                        .await
                    {
                        Ok(true) => {
                            tracing::debug!(
                                target: "auth_guard",
                                path = %path,
                                "Access token jti revoked"
                            );
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({"detail": "Unauthorized", "ok": false})),
                            )
                                .into_response();
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::error!(
                                target: "auth_guard",
                                error = %e,
                                "revocation lookup failed"
                            );
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({"detail": "Auth service unavailable", "ok": false})),
                            )
                                .into_response();
                        }
                    }
                    // Live RBAC revalidation: demoted/deactivated users lose privileges immediately.
                    ctx = match crate::auth_refresh::revalidate_auth_context(
                        state.auth_pool.as_ref(),
                        &ctx,
                    )
                    .await
                    {
                        Ok(Some(fresh)) => fresh,
                        Ok(None) => {
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({
                                    "detail": "User inactive or removed",
                                    "ok": false,
                                    "code": "user_inactive",
                                })),
                            )
                                .into_response();
                        }
                        Err(e) => {
                            tracing::error!(
                                target: "auth_guard",
                                error = %e,
                                "RBAC revalidation failed"
                            );
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({"detail": "Auth service unavailable", "ok": false})),
                            )
                                .into_response();
                        }
                    };
                }
                request.extensions_mut().insert(ctx);
                return next.run(request).await;
            }
            // Token was provided but validation failed
            tracing::debug!(
                target: "auth_guard",
                path = %path,
                method = %method,
                token_source = ?source,
                "JWT token validation failed for request"
            );
        } else {
            // No token found at all
            tracing::debug!(
                target: "auth_guard",
                path = %path,
                method = %method,
                "No auth token found in request (cookie or Authorization header; agent WS may use ?token=)"
            );
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail": "Unauthorized", "ok": false})),
        )
            .into_response();
    }
    next.run(request).await
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
    /// Optional. Empty ⇒ resolve the user by email (unique active account, preferring `default`).
    #[serde(default)]
    tenant_slug: String,
}

async fn default_tenant_id(auth_pool: &PgPool) -> Option<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
    )
    .fetch_optional(auth_pool)
    .await
    .ok()
    .flatten()
}

/// Read PoE job from DB (RLS-scoped). Returns None if not found.
async fn poe_job_from_db(pool: &PgPool, tenant_id: i64, job_id: &str) -> Option<PoEJobState> {
    let mut tx = db::begin_tenant_tx(pool, tenant_id).await.ok()?;
    let row = sqlx::query(
        "SELECT job_id, status, run_id, message, error, COALESCE(findings_json,'[]') AS findings_json FROM poe_jobs WHERE job_id = $1",
    )
    .bind(job_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()??;
    let _ = tx.commit().await;
    let findings_json: String = row.try_get("findings_json").ok()?;
    let findings_count = serde_json::from_str::<Vec<Value>>(&findings_json)
        .map(|v| v.len())
        .unwrap_or(0);
    Some(PoEJobState {
        job_id: row.try_get("job_id").ok()?,
        status: row.try_get("status").ok()?,
        run_id: row.try_get("run_id").ok()?,
        findings_count: Some(findings_count),
        message: row.try_get("message").ok()?,
        error: row.try_get("error").ok()?,
    })
}

async fn poe_job_json_from_db(pool: &PgPool, tenant_id: i64, job_id: &str) -> Option<String> {
    poe_job_from_db(pool, tenant_id, job_id)
        .await
        .map(|s| serde_json::to_string(&s).unwrap_or_default())
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Redirect to the canonical, most up-to-date dashboard: Command Center (React) at /command-center/.
/// That is the only full UI (Globe, CyberRadar, CommandBar, System Core, Memory Lab, Zero-Day Radar, etc.).
async fn redirect_to_command_center() -> Redirect {
    Redirect::to("/command-center/")
}

/// What `/` should say when this process cannot serve the Command Center itself.
///
/// In the deployed topology the SPA is served by the nginx gateway, and the backend image ships
/// no `frontend/dist` — so redirecting `/` to `/command-center/` sent the caller to a path this
/// process then 404s. Verified against the live backend:
///
/// ```text
/// /                 -> 303  Location: /command-center/
/// /command-center/  -> 404
/// ```
///
/// A browser coming through the gateway never reaches this route (the gateway serves `/` itself),
/// so the redirect only ever misled something talking to the backend directly — a probe, an
/// operator with a port-forward, an internal tool. Answering honestly costs nothing and stops the
/// backend from advertising a UI it does not have.
async fn command_center_served_elsewhere() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        r#"{"ok":true,"service":"weissman-server","ui":"served by the gateway at /command-center/, not by this process (no frontend/dist in this image)","api":"/api/health"}"#,
    )
}

/// Serves the React SPA index.html for any /command-center/* path so client-side routing works.
async fn command_center_spa_index(Extension(html): Extension<String>) -> Html<String> {
    Html(html)
}

/// Dashboard page at / : stats + findings table + clients table (default tenant, legacy HTML view).
async fn dashboard_page(State(state): State<Arc<AppState>>) -> Response {
    let (vulns, client_count, score, findings_rows, clients_rows) = match default_tenant_id(
        &state.auth_pool,
    )
    .await
    {
        Some(tid) => match db::begin_tenant_tx(state.read_pool(), tid).await {
            Ok(mut tx) => {
                let v: i64 =
                    sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM vulnerabilities")
                        .fetch_one(&mut *tx)
                        .await
                        .unwrap_or(0);
                let c: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM clients")
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap_or(0);
                let s: i64 = sqlx::query_scalar::<_, String>(
                    "SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1",
                )
                .fetch_optional(&mut *tx)
                .await
                .ok()
                .flatten()
                .and_then(|x| serde_json::from_str::<Value>(&x).ok())
                .and_then(|j| {
                    j.get("by_severity").and_then(|b| b.as_object()).map(|by| {
                        (100i64
                            - by.get("critical").and_then(Value::as_i64).unwrap_or(0) * 25
                            - by.get("high").and_then(Value::as_i64).unwrap_or(0) * 15
                            - by.get("medium").and_then(Value::as_i64).unwrap_or(0) * 5)
                            .max(0)
                    })
                })
                .unwrap_or(0);
                let findings_data = sqlx::query(
                    "SELECT id, title, severity, source, client_id::text, discovered_at FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 50",
                )
                .fetch_all(&mut *tx)
                .await
                .unwrap_or_default();
                let mut findings_rows = String::new();
                for r in &findings_data {
                    let id: i64 = r.try_get("id").unwrap_or(0);
                    let title: String = r.try_get("title").unwrap_or_else(|_| "—".to_string());
                    let severity: String =
                        r.try_get("severity").unwrap_or_else(|_| "—".to_string());
                    let source: String = r.try_get("source").unwrap_or_else(|_| "—".to_string());
                    let client_id: String =
                        r.try_get("client_id").unwrap_or_else(|_| "—".to_string());
                    let discovered: chrono::DateTime<Utc> =
                        r.try_get("discovered_at").unwrap_or_else(|_| Utc::now());
                    let discovered_il =
                        utc_str_to_israel(&discovered.format("%Y-%m-%d %H:%M:%S").to_string());
                    findings_rows.push_str(&format!(
                        "<tr><td>VLN-{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"time-cell\">{}</td></tr>",
                        id,
                        escape_html(&title),
                        escape_html(&severity),
                        escape_html(&source),
                        escape_html(&client_id),
                        escape_html(&discovered_il),
                    ));
                }
                if findings_rows.is_empty() {
                    findings_rows =
                        "<tr><td colspan=\"6\">No findings. Data is live from DB.</td></tr>"
                            .to_string();
                }
                let last_rows = sqlx::query("SELECT client_id, MAX(discovered_at) AS mx FROM vulnerabilities GROUP BY client_id")
                    .fetch_all(&mut *tx)
                    .await
                    .unwrap_or_default();
                let mut last_scan: HashMap<i64, String> = HashMap::new();
                for r in last_rows {
                    if let (Ok(cid), Ok(dt)) = (
                        r.try_get::<i64, _>("client_id"),
                        r.try_get::<chrono::DateTime<Utc>, _>("mx"),
                    ) {
                        last_scan.insert(cid, dt.format("%Y-%m-%d %H:%M:%S").to_string());
                    }
                }
                let clients = sqlx::query("SELECT id, name, domains FROM clients ORDER BY id")
                    .fetch_all(&mut *tx)
                    .await
                    .unwrap_or_default();
                let mut clients_rows = String::new();
                for r in clients {
                    let id: i64 = r.try_get("id").unwrap_or(0);
                    let name: String = r.try_get("name").unwrap_or_else(|_| "—".to_string());
                    let domains: String = r.try_get("domains").unwrap_or_else(|_| "[]".to_string());
                    let dom_short = if domains.len() > 60 {
                        // char-safe truncation — byte slicing panics on a multibyte boundary (IDN/non-ASCII domains)
                        format!("{}…", domains.chars().take(57).collect::<String>())
                    } else {
                        domains.clone()
                    };
                    let last_il = last_scan
                        .get(&id)
                        .map(|s| utc_str_to_israel(s))
                        .unwrap_or_else(|| "—".to_string());
                    clients_rows.push_str(&format!(
                        r#"<tr><td>{}</td><td>{}</td><td class="domains-cell">{}</td><td class="time-cell">{}</td><td class="actions-cell"><a href="/command-center/report/{}" class="btn-sm btn-view">View</a> <a href="/command-center/attack-surface-graph/{}" class="btn-sm btn-graph">Graph</a> <a href="/command-center/semantic-logic/{}" class="btn-sm btn-logic">Logic</a> <a href="/command-center/timing-profiler/{}" class="btn-sm btn-timing">Timing</a> <a href="/command-center/ai-arena/{}" class="btn-sm btn-arena">Arena</a> <a href="/command-center/cicd-matrix/{}" class="btn-sm btn-pipeline">Pipeline</a> <a href="/command-center/memory-lab/{}" class="btn-sm btn-memorylab">Memory Lab</a> <a href="/api/clients/{}/report/pdf" class="btn-sm btn-pdf" download>PDF</a> <a href="/api/clients/{}/export/csv" class="btn-sm btn-excel" download>Excel</a></td></tr>"#,
                        id,
                        escape_html(&name),
                        escape_html(&dom_short),
                        escape_html(&last_il),
                        id,
                        id,
                        id,
                        id,
                        id,
                        id,
                        id,
                        id,
                        id,
                    ));
                }
                if clients_rows.is_empty() {
                    clients_rows =
                        r#"<tr><td colspan="5">No clients yet. Add one below.</td></tr>"#
                            .to_string();
                }
                let _ = tx.commit().await;
                (v, c, s, findings_rows, clients_rows)
            }
            Err(_) => (
                0,
                0,
                0,
                "<tr><td colspan=\"6\">DB unavailable.</td></tr>".to_string(),
                r#"<tr><td colspan="5">DB unavailable.</td></tr>"#.to_string(),
            ),
        },
        None => (
            0,
            0,
            0,
            "<tr><td colspan=\"6\">No default tenant.</td></tr>".to_string(),
            r#"<tr><td colspan="5">No default tenant.</td></tr>"#.to_string(),
        ),
    };
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Weissman Dashboard</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: linear-gradient(135deg, #0a0e17 0%, #0f172a 50%, #0c1222 100%); color: #e2e8f0; margin: 0; min-height: 100vh; padding: 0; }}
    .layout {{ max-width: 1400px; margin: 0 auto; padding: 1.5rem 2rem 3rem; }}
    .topbar {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; margin-bottom: 2rem; padding: 1rem 1.5rem; background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(12px); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 12px; }}
    .topbar h1 {{ margin: 0; font-size: 1.5rem; font-weight: 700; color: #38bdf8; letter-spacing: 0.02em; }}
    .topbar .tagline {{ color: #94a3b8; font-size: 0.85rem; margin-top: 0.2rem; }}
    a.btn {{ display: inline-block; background: linear-gradient(180deg, #0ea5e9, #0284c7); color: #fff; padding: 0.6rem 1.2rem; border-radius: 8px; text-decoration: none; font-weight: 600; margin-left: 0.5rem; border: 1px solid rgba(255,255,255,0.1); }}
    a.btn:hover {{ background: #0284c7; box-shadow: 0 0 12px rgba(56, 189, 248, 0.3); }}
    a.cmd {{ background: linear-gradient(180deg, #10b981, #059669); }}
    a.cmd:hover {{ background: #059669; box-shadow: 0 0 12px rgba(16, 185, 129, 0.3); }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .card {{ background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(8px); border: 1px solid rgba(51, 65, 85, 0.8); border-radius: 10px; padding: 1.25rem; }}
    .card .val {{ font-size: 1.75rem; font-weight: 700; color: #38bdf8; }}
    .card .label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
    .panel {{ background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(51, 65, 85, 0.8); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
    .panel h2 {{ color: #94a3b8; font-size: 0.95rem; font-weight: 600; margin: 0 0 1rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 0.65rem 0.85rem; text-align: left; border-bottom: 1px solid rgba(51, 65, 85, 0.6); }}
    th {{ background: rgba(15, 23, 42, 0.9); color: #38bdf8; font-weight: 600; font-size: 0.8rem; }}
    .domains-cell {{ max-width: 280px; word-break: break-all; font-size: 0.9rem; }}
    .actions-cell {{ white-space: nowrap; }}
    a.btn-sm {{ display: inline-block; padding: 0.35rem 0.65rem; border-radius: 6px; font-size: 0.8rem; font-weight: 600; text-decoration: none; margin-right: 0.35rem; }}
    a.btn-pdf {{ background: #dc2626; color: #fff; border: 1px solid rgba(255,255,255,0.2); }}
    a.btn-pdf:hover {{ background: #b91c1c; }}
    a.btn-excel {{ background: #16a34a; color: #fff; border: 1px solid rgba(255,255,255,0.2); }}
    a.btn-excel:hover {{ background: #15803d; }}
    a.btn-view {{ background: #0ea5e9; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; }}
    a.btn-view:hover {{ background: #0284c7; }}
    a.btn-graph {{ background: #6366f1; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-graph:hover {{ background: #4f46e5; }}
    a.btn-logic {{ background: #0d9488; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-logic:hover {{ background: #0f766e; }}
    a.btn-timing {{ background: #b45309; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-timing:hover {{ background: #d97706; }}
    a.btn-arena {{ background: #be185d; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-arena:hover {{ background: #9d174d; }}
    a.btn-pipeline {{ background: #0d9488; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-pipeline:hover {{ background: #0f766e; }}
    a.btn-memorylab {{ background: #7c3aed; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-memorylab:hover {{ background: #6d28d9; }}
    .control-row {{ display: flex; align-items: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }}
    .control-row button {{ padding: 0.6rem 1.2rem; border-radius: 8px; font-weight: 600; cursor: pointer; border: none; font-size: 0.9rem; }}
    .control-row .btn-start {{ background: #10b981; color: #fff; }}
    .control-row .btn-stop {{ background: #dc2626; color: #fff; }}
    .control-row .status {{ padding: 0.4rem 0.8rem; border-radius: 6px; font-size: 0.85rem; font-weight: 500; }}
    .control-row .status.active {{ background: rgba(16, 185, 129, 0.2); color: #34d399; }}
    .control-row .status.inactive {{ background: rgba(100, 116, 139, 0.3); color: #94a3b8; }}
    .control-row .btn-runall {{ background: #7c3aed; color: #fff; }}
    .control-row .btn-runall:hover {{ background: #6d28d9; }}
    .control-desc {{ margin: 0; font-size: 0.8rem; color: #64748b; }}
    .time-cell {{ font-size: 0.85rem; color: #94a3b8; white-space: nowrap; }}
    .add-form {{ display: grid; grid-template-columns: 1fr 1fr auto; gap: 0.75rem; align-items: end; margin-top: 1rem; }}
    .add-form input {{ padding: 0.5rem 0.75rem; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; font-size: 0.9rem; }}
    .add-form button {{ padding: 0.5rem 1rem; background: #0ea5e9; color: #fff; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }}
  </style>
</head>
<body>
    <div class="layout">
    <header class="topbar">
      <div>
        <h1>WEISSMAN CYBERSECURITY</h1>
        <p class="tagline">Command Center — live data only (no dummy, no fake)</p>
      </div>
      <div>
        <a href="/" class="btn">Dashboard</a>
        <a href="/command-center/" class="btn cmd">Open War Room</a>
      </div>
    </header>
    <div style="background:#1e3a5f;color:#93c5fd;padding:10px 16px;margin:0 0 16px;border-radius:8px;text-align:center;">
      <strong>Legacy view.</strong> Full dashboard (Globe, Radar, Memory Lab, System Core, Zero-Day Radar): 
      <a href="/command-center/" style="color:#67e8f9;font-weight:bold;margin-left:6px;">→ Open Command Center</a>
    </div>
    <div class="cards">
      <div class="card"><span class="val">{vulns}</span><br/><span class="label">Vulnerabilities</span></div>
      <div class="card"><span class="val">{client_count}</span><br/><span class="label">Clients</span></div>
      <div class="card"><span class="val">{score}</span><br/><span class="label">Security Score</span></div>
    </div>
    <div class="panel">
      <h2>Global scan control</h2>
      <div class="control-row">
        <button type="button" class="btn-start" id="scanStart">Start continuous scan</button>
        <button type="button" class="btn-stop" id="scanStop">Stop scan</button>
        <button type="button" class="btn-runall" id="scanRunAll">Run full scan now (all clients, all 5 engines)</button>
        <span class="status inactive" id="scanStatus">—</span>
      </div>
      <p class="control-desc">Scans use client domains from the table below. No manual target needed. Engines: OSINT, ASM, Supply Chain, BOLA/IDOR, AI Fuzz.</p>
    </div>
    <div class="panel">
      <h2>Clients (live from DB)</h2>
      <table><thead><tr><th>ID</th><th>Name</th><th>Domains</th><th>Last scan (Israel)</th><th>Actions</th></tr></thead><tbody>{clients_rows}</tbody></table>
      <h2 style="margin-top: 1.5rem;">Add client</h2>
      <form class="add-form" id="addClientForm">
        <input type="text" name="name" placeholder="Company name" required />
        <input type="text" name="domains" placeholder='Domains JSON e.g. ["example.com"]' />
        <button type="submit">Add</button>
      </form>
    </div>
    <div class="panel">
      <h2>Recent findings (live from DB)</h2>
      <table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Source</th><th>Client</th><th>Discovered (Israel)</th></tr></thead><tbody>{findings_rows}</tbody></table>
    </div>
  </div>
  <script>
    (function() {{
      function setStatus(active) {{
        var el = document.getElementById('scanStatus');
        el.textContent = active ? 'Scanning active' : 'Stopped';
        el.className = 'status ' + (active ? 'active' : 'inactive');
      }}
      fetch('/api/scan/status').then(function(r) {{ return r.json(); }}).then(function(d) {{ setStatus(d.scanning_active); }}).catch(function() {{ setStatus(false); }});
      document.getElementById('scanStart').onclick = function() {{
        fetch('/api/scan/start', {{ method: 'POST' }}).then(function() {{ setStatus(true); }});
      }};
      document.getElementById('scanStop').onclick = function() {{
        fetch('/api/scan/stop', {{ method: 'POST' }}).then(function() {{ setStatus(false); }});
      }};
      document.getElementById('scanRunAll').onclick = function() {{
        var btn = this;
        btn.disabled = true;
        fetch('/api/scan/run-all', {{ method: 'POST' }}).then(function(r) {{ return r.json(); }}).then(function() {{ btn.disabled = false; setStatus(true); setTimeout(function() {{ location.reload(); }}, 3000); }}).catch(function() {{ btn.disabled = false; }});
      }};
      document.getElementById('addClientForm').onsubmit = function(e) {{
        e.preventDefault();
        var name = this.name.value.trim();
        var domains = this.domains.value.trim() || '[]';
        if (!name) return;
        fetch('/api/clients', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ name: name, domains: domains }})
        }}).then(function(r) {{ return r.json(); }}).then(function(d) {{ if (d.ok) location.reload(); }});
      }};
    }})();
  </script>
</body>
</html>"##,
        vulns = vulns,
        client_count = client_count,
        score = score,
        findings_rows = findings_rows,
        clients_rows = clients_rows,
    );
    Html(html).into_response()
}

/// Normalize internal telemetry JSON to Command Center `{ kind, payload, ts }` shape.
fn normalize_cc_event(raw: &str) -> Option<String> {
    let mut v: Value = serde_json::from_str(raw).ok()?;
    // Internal fields must never reach the client: `_tid` is the tenant scoping stamp and `_seq`
    // is the server sequence. Strip both up-front so neither the kind-passthrough below nor a
    // nested `payload` (the `v.clone()` branch) can leak them. `_seq` is reattached at the top
    // level by `cc_with_seq` for the client's Last-Event-ID, so removing it here is safe.
    if let Value::Object(ref mut m) = v {
        m.remove("_tid");
        m.remove("_seq");
    }
    if v.get("kind").is_some() {
        // Already client-shaped (ticker refreshes, resync markers): pass through unchanged.
        return Some(v.to_string());
    }
    let ts = chrono::Utc::now().timestamp_millis();
    if let Some(event) = v.get("event").and_then(Value::as_str) {
        let kind = match event {
            "finding_created" => {
                let sev = v
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or("info")
                    .to_ascii_lowercase();
                if sev == "critical" || sev == "high" {
                    "critical_cve"
                } else {
                    "scan_pulse"
                }
            }
            "new_target" => "new_source_discovered",
            "progress" => "scan_pulse",
            "engine_error" | "error" => "emergency_alert",
            _ => "audit",
        };
        let payload = if event == "finding_created" {
            json!({
                "message": format!(
                    "Finding: {}",
                    v.get("title").and_then(Value::as_str).unwrap_or("—")
                ),
                "severity": v.get("severity").cloned().unwrap_or(json!("info")),
                "client_id": v.get("client_id").cloned().unwrap_or(Value::Null),
                "target": v.get("client_id").cloned().unwrap_or(Value::Null),
                "finding_id": v.get("finding_id").cloned().unwrap_or(Value::Null),
            })
        } else {
            v.clone()
        };
        return Some(json!({ "kind": kind, "payload": payload, "ts": ts }).to_string());
    }
    if v.get("message").is_some() || v.get("job_id").is_some() {
        let msg = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("job update");
        return Some(
            json!({
                "kind": "audit",
                "payload": {
                    "action": msg,
                    "message": msg,
                    "severity": v.get("status").and_then(Value::as_str).unwrap_or("info"),
                    "job_id": v.get("job_id").cloned().unwrap_or(Value::Null),
                },
                "ts": ts,
            })
            .to_string(),
        );
    }
    None
}

/// Resync notice sent to a Command Center socket after the broadcast ring dropped
/// `dropped` telemetry events for this (slow) client. The client treats `type: "resync"`
/// as a signal to refetch authoritative state rather than trust its now-gapped live feed —
/// in a SOC a silently missing event can be the one critical alert that mattered.
fn stream_lag_notice(dropped: u64) -> String {
    json!({
        "type": "resync",
        "kind": "stream_lagged",
        "dropped": dropped,
        "ts": chrono::Utc::now().timestamp_millis(),
    })
    .to_string()
}

/// Read the monotonic `_seq` the replay recorder stamped onto a sequenced telemetry event.
fn cc_extract_seq(raw: &str) -> Option<u64> {
    serde_json::from_str::<Value>(raw)
        .ok()?
        .get("_seq")
        .and_then(Value::as_u64)
}

/// Attach `_seq` to a normalized Command Center frame so the client can record its position
/// (the value it echoes back as `last_event_id` on reconnect). Non-object frames pass through.
fn cc_with_seq(normalized: &str, seq: u64) -> String {
    match serde_json::from_str::<Value>(normalized) {
        Ok(Value::Object(mut m)) => {
            m.insert("_seq".to_string(), Value::from(seq));
            Value::Object(m).to_string()
        }
        _ => normalized.to_string(),
    }
}

/// WebSocket: init handshake + live telemetry stream for Command Center.
async fn ws_command_center(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let pool = state.app_pool.clone();
    let sequenced = state.cc_sequenced_tx.clone();
    let replay = state.replay_buffer.clone();
    let last_event_id = crate::http::event_replay::parse_last_event_id(query.as_deref());
    let tenant_id = auth.tenant_id;
    let assigned_client_id = auth.assigned_client_id;
    ws.on_upgrade(move |socket| async move {
        handle_ws_command_center(
            socket,
            pool,
            tenant_id,
            assigned_client_id,
            sequenced,
            replay,
            last_event_id,
        )
        .await;
    })
}

async fn handle_ws_command_center(
    mut socket: WebSocket,
    pool: Arc<PgPool>,
    tenant_id: i64,
    assigned_client_id: Option<i64>,
    sequenced: Arc<tokio::sync::broadcast::Sender<String>>,
    replay: Arc<crate::http::event_replay::EventReplayBuffer>,
    last_event_id: Option<u64>,
) {
    // Subscribe BEFORE the init snapshot + replay so no live event can slip through the gap
    // between "replay up to seq N" and "start listening". Duplicates are removed by seq below.
    let mut rx = sequenced.subscribe();
    let Ok(mut tx) =
        weissman_db::begin_tenant_tx_scoped(pool.as_ref(), tenant_id, assigned_client_id).await
    else {
        return;
    };
    let vuln_count: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM vulnerabilities")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
    let client_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM clients")
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
    let score: i64 = if assigned_client_id.is_some() {
        live_security_score_from_vulns(&mut tx).await
    } else {
        sqlx::query_scalar::<_, String>(
            "SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|j| {
            j.get("by_severity").and_then(|b| b.as_object()).map(|by| {
                (100i64
                    - by.get("critical").and_then(Value::as_i64).unwrap_or(0) * 25
                    - by.get("high").and_then(Value::as_i64).unwrap_or(0) * 15
                    - by.get("medium").and_then(Value::as_i64).unwrap_or(0) * 5)
                    .max(0)
            })
        })
        .unwrap_or(0)
    };
    let _ = tx.commit().await;
    let globe = json!({
        "scanPulses": [],
        "criticalVulns": [],
        "intelNodes": [{ "lat": 37.77, "lon": -122.42 }, { "lat": 52.52, "lon": 13.4 }],
    });
    let score_payload = json!({
        "security_score": score,
        "total_vulnerabilities": vuln_count,
        "assets_monitored": client_count,
    });
    let score_payload_ticker = score_payload.clone();
    let init = json!({ "type": "init", "globe": globe, "score": score_payload });
    if let Ok(s) = serde_json::to_string(&init) {
        let _ = socket.send(Message::Text(s)).await;
    }

    // Reconnect replay: if the client sent last_event_id, resend everything it missed
    // (tenant-scoped) before going live. `last_delivered` then dedups any of those events
    // that are also still buffered in the live channel we subscribed to above.
    let mut last_delivered = last_event_id.unwrap_or(0);
    if let Some(last_id) = last_event_id {
        let slice = replay.replay_since_scoped(tenant_id, assigned_client_id, last_id);
        if slice.gap {
            // Buffer no longer covers the client's position — have it refetch source-of-truth.
            let dropped = slice.latest_seq.saturating_sub(last_id);
            let _ = socket.send(Message::Text(stream_lag_notice(dropped))).await;
        }
        for (seq, payload) in slice.events {
            if let Some(normalized) = normalize_cc_event(&payload) {
                if socket
                    .send(Message::Text(cc_with_seq(&normalized, seq)))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            last_delivered = last_delivered.max(seq);
        }
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(15));

    loop {
        tokio::select! {
            inbound = socket.recv() => {
                match inbound {
                    None => break,
                    Some(Ok(Message::Text(text))) => {
                        if text.contains("\"type\":\"ping\"") || text.contains("\"ping\"") {
                            let _ = socket.send(Message::Text(json!({"type":"pong"}).to_string())).await;
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = socket.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            telemetry_msg = rx.recv() => {
                match telemetry_msg {
                    Ok(raw) => {
                        let seq = cc_extract_seq(&raw);
                        // Dedup: skip events already sent during reconnect replay above.
                        if seq.is_none_or(|s| s > last_delivered) {
                            // Tenant isolation: only forward events stamped for this socket's tenant.
                            if let Some(scoped) = crate::http::tenant_stream::visible_to_scoped(
                                &raw,
                                tenant_id,
                                assigned_client_id,
                            ) {
                                if let Some(normalized) = normalize_cc_event(&scoped) {
                                    let frame = match seq {
                                        Some(s) => cc_with_seq(&normalized, s),
                                        None => normalized,
                                    };
                                    if socket.send(Message::Text(frame)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            if let Some(s) = seq {
                                last_delivered = last_delivered.max(s);
                            }
                        }
                    }
                    // Slow-consumer backpressure: this receiver fell behind the broadcast
                    // ring and `dropped` telemetry events were discarded before we could read
                    // them. Never let that loss be silent — count it for observability and tell
                    // the client to resync from source-of-truth instead of trusting a gapped feed.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(dropped)) => {
                        metrics::counter!("weissman_ws_command_center_lagged_events_total")
                            .increment(dropped);
                        if socket
                            .send(Message::Text(stream_lag_notice(dropped)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    // Sender dropped (server shutting down) — no further events will arrive.
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = ticker.tick() => {
                let Ok(mut tx) = weissman_db::begin_tenant_tx_scoped(
                    pool.as_ref(),
                    tenant_id,
                    assigned_client_id,
                )
                .await else { continue; };
                let row = sqlx::query(
                    "SELECT id, title, severity, client_id::text AS client_id FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 1",
                )
                .fetch_optional(&mut *tx)
                .await
                .ok()
                .flatten();
                let _ = tx.commit().await;
                if let Some(r) = row {
                    let title: String = r.try_get("title").unwrap_or_default();
                    let severity: String = r.try_get("severity").unwrap_or_else(|_| "info".into());
                    let client_id: String = r.try_get("client_id").unwrap_or_else(|_| "—".into());
                    let kind = if severity == "critical" || severity == "high" { "critical_cve" } else { "scan_pulse" };
                    let pulse = json!({
                        "type": "refresh",
                        "kind": kind,
                        "payload": {
                            "message": title,
                            "severity": severity,
                            "target": client_id,
                            "client_id": client_id,
                        },
                        "score": score_payload_ticker,
                    });
                    if let Ok(s) = serde_json::to_string(&pulse) {
                        let _ = socket.send(Message::Text(s)).await;
                    }
                }
            }
        }
    }
}

/// Ticker events for Command Center (live from DB — recent findings as events).
async fn api_command_center_ticker(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(state.read_pool(), auth.tenant_id).await else {
        return (StatusCode::OK, Json(json!({ "events": [] }))).into_response();
    };
    let rows = sqlx::query(
        "SELECT id, title, severity, source, client_id::text, discovered_at FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 100",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let mut events = vec![];
    for r in rows {
        let discovered: chrono::DateTime<Utc> =
            r.try_get("discovered_at").unwrap_or_else(|_| Utc::now());
        let ds = discovered.format("%Y-%m-%d %H:%M:%S").to_string();
        let time = if ds.len() >= 19 {
            ds[11..19].to_string()
        } else {
            "00:00:00".to_string()
        };
        events.push(serde_json::json!({
            "id": format!("ev-{}", r.try_get::<i64, _>("id").unwrap_or(0)),
            "time": time,
            "target": r.try_get::<String, _>("client_id").unwrap_or_else(|_| "—".to_string()),
            "target_ip": "—",
            "agentId": "Discovery",
            "severity": r.try_get::<String, _>("severity").unwrap_or_else(|_| "info".to_string()),
            "message": r.try_get::<String, _>("title").unwrap_or_else(|_| "Finding".to_string()),
        }));
    }
    (StatusCode::OK, Json(json!({ "events": events }))).into_response()
}

#[derive(Deserialize)]
struct EnterpriseSettingsPatch {
    global_safe_mode: Option<bool>,
    alert_webhook_url: Option<String>,
}

#[derive(Deserialize)]
struct ClientBody {
    name: Option<String>,
    domains: Option<String>,
    tech_stack: Option<String>,
    ip_ranges: Option<String>,
    contact_email: Option<String>,
    #[serde(default)]
    auto_detect_tech_stack: Option<bool>,
    aws_cross_account_role_arn: Option<String>,
    aws_external_id: Option<String>,
    gcp_project_id: Option<String>,
    /// Engagement modules (baseline_asm, cloud_aws, endpoint_agent, …) stored in client_configs.
    engagement_modules: Option<Vec<String>>,
    /// Nested onboarding payload merged into client_configs.onboarding.
    onboarding: Option<Value>,
}

#[derive(Deserialize)]
struct ClientConfigBody {
    enabled_engines: Option<Vec<String>>,
    roe_mode: Option<String>,
    stealth_level: Option<u8>,
    auto_harvest: Option<bool>,
    /// When true, orchestrator runs passive Modbus/ENIP/S7 probes against domains + ip_ranges only.
    industrial_ot_enabled: Option<bool>,
    /// Explicit authorization for RoE-gated critical-infrastructure engines (requires weaponized RoE + whitelist).
    critical_infra_probe_authorized: Option<bool>,
    /// Target whitelist for critical-infrastructure probes (hosts, CIDRs, domains).
    critical_infra_targets: Option<Vec<String>>,
    #[serde(default, skip_serializing)]
    destructive_confirm: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TimingScanRunBody {
    target: Option<String>,
    client_id: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AiRedteamRunBody {
    target: Option<String>,
    client_id: Option<String>,
    ai_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct PipelineScanRunBody {
    client_id: String,
    repo_url: String,
}

#[derive(Deserialize)]
struct PoEScanRunBody {
    client_id: String,
    target_url: String,
}

#[derive(Deserialize)]
struct LatencyProbeBody {
    url: String,
}

#[derive(Deserialize)]
struct DeepFuzzBody {
    target: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
    /// Optional paths from a prior ASM / General pass for semantic fuzz seeding.
    #[serde(default)]
    discovered_paths: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct GeneralMissionBody {
    domain: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
}

/// POST /api/council/debate — enqueues `council_debate` async job (Alpha → Beta → Gamma; optional OAST self-correction).
#[derive(Deserialize)]
struct CouncilDebateBody {
    /// Authorized target / mission brief for the council.
    target_brief: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
    /// Seed self-correction (e.g. prior listener miss) before the first round.
    #[serde(default)]
    failure_log: Option<String>,
    /// When true, re-run full council until `verify_oob_token_seen` succeeds or rounds exhausted.
    #[serde(default)]
    verify_oob: Option<bool>,
    /// Weissman Supreme Council: Proposer ∥ Critic, Sovereign General, optional phased CPU affinity + semantic memory.
    #[serde(default)]
    supreme: Option<bool>,
    /// Supreme Command Protocol: phased `process_mission` + signed `COUNCIL_DEBATE` audit rows.
    #[serde(default)]
    supreme_command_protocol: Option<bool>,
    #[serde(default)]
    max_council_rounds: Option<u32>,
    #[serde(default)]
    fallback_oast_token: Option<String>,
}

#[derive(Deserialize)]
struct PipelineStateQuery {
    run_id: i64,
    client_id: String,
}

#[derive(Deserialize)]
struct IdentityContextBody {
    role_name: String,
    #[serde(default)]
    privilege_order: i32,
    #[serde(default = "default_token_type")]
    token_type: String,
    token_value: String,
}

fn default_token_type() -> String {
    "bearer".to_string()
}

#[derive(Deserialize)]
struct PipelineStatePatchBody {
    run_id: Option<i64>,
    client_id: String,
    paused: Option<bool>,
    skip_to_stage: Option<i32>,
}

#[derive(Deserialize)]
struct RuntimeTraceBody {
    run_id: Option<i64>,
    finding_id: Option<String>,
    trace_id: Option<String>,
    source_file: Option<String>,
    line_number: Option<i32>,
    function_name: Option<String>,
    payload_hash: Option<String>,
    metadata: Option<Value>,
}

#[derive(Deserialize)]
struct AutoHealBody {
    finding_id: String,
    git_token: Option<String>,
    repo_slug: Option<String>,
    base_branch: Option<String>,
    docker_socket: Option<String>,
    image: Option<String>,
    container_port: Option<u16>,
    poc_exploit: Option<String>,
    /// Delivery channel id: github_pr (default) | github_direct_commit | diff_download | virtual_patch.
    channel: Option<String>,
    /// Optional curl for the post-patch health/control probe; empty ⇒ GET the app root.
    health_check_curl: Option<String>,
    #[serde(default, skip_serializing)]
    destructive_confirm: String,
    #[serde(default)]
    dual_approve: String,
}

#[derive(Deserialize)]
struct HealRevertBody {
    finding_id: String,
    git_token: Option<String>,
    repo_slug: Option<String>,
    channel: Option<String>,
    gitlab_host: Option<String>,
    #[serde(default)]
    delete_branch: Option<bool>,
    #[serde(default, skip_serializing)]
    destructive_confirm: String,
    #[serde(default)]
    dual_approve: String,
}

#[derive(Deserialize)]
struct HealBatchBody {
    finding_ids: Vec<String>,
    git_token: Option<String>,
    repo_slug: Option<String>,
    base_branch: Option<String>,
    channel: Option<String>,
    health_check_curl: Option<String>,
    #[serde(default, skip_serializing)]
    destructive_confirm: String,
    #[serde(default)]
    dual_approve: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct DeceptionGenerateBody {
    types: Option<Vec<String>>,
    tech_hint: Option<String>,
    aws_access_key_id: Option<String>,
    aws_secret_access_key: Option<String>,
    aws_region: Option<String>,
    /// When true, mint a real deny-all IAM user + access key in the control-plane account (default chain).
    #[serde(default)]
    real_aws_canary: Option<bool>,
    /// When false, skip vLLM and use a template decoy (keys still real if `real_aws_canary`).
    #[serde(default)]
    use_llm_decoy: Option<bool>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SovereignPhantomBody {
    /// Target fingerprint / scan summary JSON for vLLM classification.
    fingerprint: serde_json::Value,
}

#[derive(Deserialize)]
struct DeceptionTriggeredBody {
    asset_id: Option<i64>,
    /// Accepted from deception webhooks for forward compatibility (not yet used server-side).
    #[allow(dead_code)]
    token_value: Option<String>,
    fingerprint: Option<String>,
    request_meta: Option<Value>,
}

#[derive(Deserialize, Serialize)]
struct DeceptionDeployCloudBody {
    asset_ids: Vec<i64>,
    s3_bucket: Option<String>,
    s3_object_key: Option<String>,
    s3_region: Option<String>,
    ssm_parameter_path: Option<String>,
    #[serde(default, skip_serializing)]
    destructive_confirm: String,
}

const DEFAULT_CLIENT_CONFIGS_JSON: &str = r#"{"enabled_engines":["osint","asm","supply_chain","bola_idor","llm_path_fuzz","semantic_ai_fuzz","microsecond_timing","ai_adversarial_redteam","nexus_sovereign_swarm"],"roe_mode":"safe_proofs","stealth_level":50,"industrial_ot_enabled":false}"#;

// Logs an internal error server-side and returns a generic, non-leaking detail string
// for the client. Used at `INTERNAL_SERVER_ERROR` sites so raw sqlx/internal error text
// (table names, SQL, connection strings) never reaches API consumers.
#[inline]
fn scrub_internal_error<E: std::fmt::Display>(e: E) -> &'static str {
    tracing::error!(target: "http", error = %e, "internal server error");
    "internal error"
}

// Handlers: see `handler_fragments.rs` (single wiring point for all `.inc` fragments).
#[path = "serve_route_groups.rs"]
mod serve_route_groups;
include!("handler_fragments.rs");

pub fn new_app_state(
    app_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    read_only_pool: Option<Arc<PgPool>>,
) -> Arc<AppState> {
    let (timing_tx, _) = tokio::sync::broadcast::channel::<String>(256);
    let (redteam_tx, _) = tokio::sync::broadcast::channel::<String>(256);
    let (radar_tx, _) = tokio::sync::broadcast::channel::<String>(256);
    let (poe_updates_tx, poe_updates_rx) =
        flume::bounded::<(String, String)>(POE_UPDATES_CHANNEL_CAPACITY);
    let poe_job_registry: PoeJobRegistry = Arc::new(DashMap::new());
    let registry_clone = poe_job_registry.clone();
    tokio::spawn(async move {
        while let Ok((job_id, json)) = poe_updates_rx.recv_async().await {
            // Prune disconnected SSE subscribers as we forward. If no subscribers remain
            // for this job_id after pruning, drop the map entry too — otherwise the
            // DashMap accumulates one orphan key per scan forever (slow leak).
            let drop_key = {
                let Some(mut senders) = registry_clone.get_mut(&job_id) else {
                    continue;
                };
                senders.retain(|tx| match tx.try_send(json.clone()) {
                    Ok(()) => true,
                    Err(TrySendError::Disconnected(_)) => false,
                    Err(TrySendError::Full(_)) => true,
                });
                senders.is_empty()
            };
            if drop_key {
                registry_clone.remove(&job_id);
            }
        }
    });
    let (telemetry_tx, _) = tokio::sync::broadcast::channel::<String>(TELEMETRY_BROADCAST_CAPACITY);
    let telemetry_broadcast_tx = Arc::new(telemetry_tx);
    // Command Center replay: a single recorder assigns each telemetry event a monotonic
    // sequence, stores it in a bounded per-tenant buffer, and re-emits it (with `_seq`) on
    // cc_sequenced_tx for the /ws/command-center live feed. One sequencer => live and replay
    // share the same seq space, so a reconnecting client resumes exactly where it left off.
    let replay_buffer = crate::http::event_replay::EventReplayBuffer::shared_from_env();
    let (cc_sequenced_tx, _) =
        tokio::sync::broadcast::channel::<String>(TELEMETRY_BROADCAST_CAPACITY);
    let cc_sequenced_tx = Arc::new(cc_sequenced_tx);
    crate::http::event_replay::spawn_recorder(
        telemetry_broadcast_tx.subscribe(),
        cc_sequenced_tx.clone(),
        replay_buffer.clone(),
    );
    let edge_heartbeat_batcher =
        crate::edge_heartbeat_batch::spawn(app_pool.clone(), Some(telemetry_broadcast_tx.clone()));
    let (swarm_tx, _) = tokio::sync::broadcast::channel::<String>(512);
    let mpsc_cap = std::env::var("WEISSMAN_SOVEREIGN_MPSC_CAPACITY")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0);
    let (sovereign_swarm_tx, sovereign_swarm_rx) = match mpsc_cap {
        Some(cap) => {
            let (tx, rx) = tokio::sync::mpsc::channel(cap);
            (Some(Arc::new(tx)), std::sync::Mutex::new(Some(rx)))
        }
        None => (None, std::sync::Mutex::new(None)),
    };
    Arc::new(AppState {
        app_pool,
        intel_pool,
        auth_pool,
        read_only_pool,
        started_at: Instant::now(),
        timing_broadcast_tx: Arc::new(timing_tx),
        redteam_broadcast_tx: Arc::new(redteam_tx),
        radar_broadcast_tx: Arc::new(radar_tx),
        poe_job_registry,
        poe_job_updates_tx: poe_updates_tx,
        telemetry_broadcast_tx,
        cc_sequenced_tx,
        replay_buffer,
        swarm_broadcast_tx: Arc::new(swarm_tx),
        edge_heartbeat_batcher,
        sovereign_swarm_tx,
        sovereign_swarm_rx,
        endpoint_agents: crate::endpoint_agents::AgentRegistry::global(),
    })
}

pub fn spawn_http_background_tasks(state: &Arc<AppState>, job_control_pool: Arc<PgPool>) {
    let app_pool = state.app_pool.clone();
    let intel_pool = state.intel_pool.clone();
    let auth_pool = state.auth_pool.clone();
    // Leader election: only ONE replica runs the singleton workers (scan cycles,
    // backups, cron, intel refresh). Holds a Postgres session advisory lock for its
    // lifetime; followers skip those loops so multi-replica deploys don't duplicate work.
    let is_leader = crate::leader_election::acquire_singleton_leadership_blocking();
    if is_leader {
        tracing::info!(target: "leader", "this replica holds singleton-worker leadership");
    } else {
        tracing::info!(target: "leader", "another replica is leader — skipping scan/backup/cron/intel loops");
    }
    // SSO redirect URIs are built from WEISSMAN_PUBLIC_BASE_URL and are resolved by the identity
    // provider, not by us — so a localhost or non-TLS value makes login impossible in a way that
    // only ever surfaces as an opaque redirect-mismatch at the IdP.
    crate::oidc_auth::warn_if_sso_base_url_unusable();
    crate::nl_query::spawn_audit_worker(app_pool.clone());
    crate::endpoint_agents::spawn_pending_task_pusher(
        app_pool.clone(),
        state.endpoint_agents.clone(),
    );
    if is_leader {
        crate::endpoint_agents::spawn_ueba_baseline_scheduler(
            app_pool.clone(),
            state.endpoint_agents.clone(),
        );
    }
    crate::agent_registry_sync::spawn_agent_registry_redis_sync(state.endpoint_agents.clone());
    // Every replica: Ask Weissman hash-chain is per-process mpsc + DB sweep.
    // FOR UPDATE lives here, never on the HTTP insert path.
    crate::nl_audit_chain::spawn(app_pool.clone());
    // Cross-replica real-time: bridge the live telemetry broadcast over Redis pub/sub so
    // SSE/WS clients on every replica see events produced on any replica (no-op without REDIS_URL).
    crate::telemetry_bus::spawn_bridge("telemetry", (*state.telemetry_broadcast_tx).clone());
    crate::telemetry_bus::spawn_bridge("swarm", (*state.swarm_broadcast_tx).clone());
    // The timing / redteam / radar live streams are produced by the async worker (a separate
    // process), which publishes to the Redis topics `weissman:bus:{timing,redteam,radar}` (see
    // async_job_executor::from_env). The WS handlers here subscribe to the matching in-process
    // broadcast channels, so without these bridges the server never feeds them and every client
    // of /ws/timing, /ws/ai-redteam and /ws/threat-intel receives nothing. Bridge them exactly
    // like telemetry/swarm above (no-op when REDIS_URL is unset).
    crate::telemetry_bus::spawn_bridge("timing", (*state.timing_broadcast_tx).clone());
    crate::telemetry_bus::spawn_bridge("redteam", (*state.redteam_broadcast_tx).clone());
    crate::telemetry_bus::spawn_bridge("radar", (*state.radar_broadcast_tx).clone());
    tokio::spawn(async {
        let wid = format!("server:{}", std::process::id());
        let fleet =
            std::sync::Arc::new(weissman_fleet_shaping::FleetCoordinator::from_env(wid).await);
        crate::fleet_shaping::install_global(fleet);
        tracing::info!(target: "fleet_shaping", "server fleet traffic shaper installed");
    });
    crate::observability::register_llm_tenant_metering(app_pool.clone());
    crate::observability::spawn_pool_metrics_loop(
        app_pool.clone(),
        auth_pool.clone(),
        intel_pool.clone(),
    );
    if is_leader {
        crate::db_backup::spawn_database_backup_scheduler(auth_pool.clone(), app_pool.clone());
    }
    crate::server_db::init_db(std::path::Path::new("."));
    crate::orchestrator::spawn_orchestrator(
        app_pool.clone(),
        intel_pool.clone(),
        auth_pool.clone(),
        Some(state.telemetry_broadcast_tx.clone()),
    );
    // Enable orchestrator scanning by default (disable with WEISSMAN_SCANNING_ENABLED=0).
    // Leader-only: followers spawn the orchestrator but never run scan cycles.
    if is_leader
        && !matches!(
            std::env::var("WEISSMAN_SCANNING_ENABLED").as_deref(),
            Ok("0") | Ok("false") | Ok("no")
        )
    {
        crate::orchestrator::set_scanning_active(true);
        tracing::info!(target: "orchestrator", "Scanning enabled at boot (leader)");
    }
    let auth_pool_boot = auth_pool.clone();
    let app_pool_boot = app_pool.clone();
    tokio::spawn(async move {
        crate::auth_bootstrap::sync_admin_credentials(
            auth_pool_boot.as_ref(),
            app_pool_boot.as_ref(),
        )
        .await;
    });
    // ── Singleton workers — leader replica only ────────────────────────────────
    if is_leader {
        let pool_audit = app_pool.clone();
        tokio::spawn(async move {
            // Report the tamper-evidence boundary; never try to move it. `audit_logs` is
            // append-only by design (audit_logs_block_update/_delete triggers, and weissman_app
            // holds only INSERT+SELECT), so the former `backfill_missing_hashes` failed at every
            // boot with `permission denied for table audit_logs` — and had it succeeded it would
            // have back-dated digests over rows that were never actually protected, turning
            // "predates the chain" into a false "chain-verified". See `unchained_legacy_summary`.
            match crate::audit_log::unchained_legacy_summary(pool_audit.as_ref()).await {
                Ok(rows) if rows.is_empty() => {}
                Ok(rows) => {
                    for (tenant_id, unchained, last_id) in rows {
                        match crate::audit_log::unchained_rows_are_a_legacy_prefix(
                            pool_audit.as_ref(),
                            tenant_id,
                        )
                        .await
                        {
                            Ok(true) => tracing::info!(
                                target: "security_audit", tenant_id, unchained, last_id,
                                "audit rows predating the hash chain (legacy prefix, not covered by tamper-evidence)"
                            ),
                            // A NULL hash *after* the chain started is exactly what nulling a
                            // digest to force the verifier to re-anchor would look like.
                            Ok(false) => tracing::error!(
                                target: "security_audit", tenant_id, unchained, last_id,
                                "audit rows with a NULL hash AFTER the chain started — possible truncation or tampering"
                            ),
                            Err(e) => tracing::warn!(
                                target: "security_audit", tenant_id, error = %e,
                                "could not classify unchained audit rows"
                            ),
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(target: "security_audit", error = %e, "audit chain boundary check failed");
                }
            }
        });
        crate::audit_log::spawn_audit_checkpoint_worker(app_pool.clone(), auth_pool.clone());
        tokio::spawn(crate::payload_sync_worker::run_worker_loop(
            app_pool.clone(),
            intel_pool.clone(),
            auth_pool.clone(),
        ));
        crate::redteam_background_worker::spawn_cron_worker(
            app_pool.clone(),
            auth_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
        );
        crate::scan_schedule_worker::spawn_scan_schedule_worker(
            app_pool.clone(),
            auth_pool.clone(),
        );
        crate::alert_evaluator_worker::spawn_alert_evaluator_worker(
            app_pool.clone(),
            auth_pool.clone(),
        );
        crate::soar::worker::spawn_soar_verification_worker(app_pool.clone(), auth_pool.clone());
        crate::threat_intel_ingestor::spawn_ingest_worker(
            app_pool.clone(),
            intel_pool.clone(),
            auth_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
        );
        crate::data_retention::spawn_data_retention_loop(app_pool.clone(), intel_pool.clone());
        crate::async_jobs::spawn_stale_lock_reclaim_loop(job_control_pool);
        // Threat-intel mirrors (CISA KEV + FIRST EPSS). Both are best-effort, idempotent,
        // and gated by env vars so dev/offline runs can skip outbound HTTP.
        crate::intel_kev::bootstrap_kev_catalog(app_pool.clone());
        crate::intel_kev::spawn_kev_refresh_worker(app_pool.clone());
        crate::intel_epss::bootstrap_epss_backfill(app_pool.clone());
        crate::intel_epss::spawn_epss_backfill_worker(app_pool.clone());
        crate::intel_findings_backfill::bootstrap_findings_intel_backfill(
            app_pool.clone(),
            auth_pool.clone(),
        );
        // UEBA — purge old samples once an hour so the table stays bounded.
        crate::ueba_detector::spawn_retention_loop(app_pool.clone());
        crate::sovereign_self_scan::spawn_sovereign_self_scan_loop(
            app_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
        );
        // Autonomous self-improvement engine — hourly, toggled live from the Command Center
        // (`self_improve_enabled`). Proposes improvements; approval opens a PR, never touches main.
        crate::self_improve::spawn_self_improve_loop(
            app_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
        );
        crate::predictive_analyzer::spawn_security_events_llm_loop(
            app_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
        );
        crate::sovereign_c2::spawn_sovereign_stack(
            app_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
            state.take_sovereign_swarm_rx(),
            state.sovereign_swarm_tx.clone(),
        );
    } // ── end singleton-leader workers ──────────────────────────────────────────
    if let Some(secs) = std::env::var("WEISSMAN_GENERAL_SELF_AUDIT_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        if secs > 0 && is_leader {
            if let Some(tid) = std::env::var("WEISSMAN_GENERAL_SELF_AUDIT_TENANT_ID")
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
            {
                let pool = app_pool.clone();
                tokio::spawn(async move {
                    let mut tick =
                        tokio::time::interval(std::time::Duration::from_secs(secs.max(600)));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tick.tick().await;
                        let _ = crate::strategy_engine::run_self_defense_audit(
                            pool.as_ref(),
                            tid,
                            None,
                            "system_self_audit",
                            "127.0.0.1",
                        )
                        .await;
                    }
                });
            }
        }
    }
}

/// Marketing / legal static pages (`deploy/public`) for go-live checks and direct backend access.
fn resolve_deploy_public_dir() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("WEISSMAN_PUBLIC_DIR") {
        let p = PathBuf::from(v);
        if p.is_dir() {
            return Some(p);
        }
    }
    let cwd = std::env::current_dir().ok()?;
    for mut p in [cwd.clone(), cwd.join("..")] {
        p.push("deploy");
        p.push("public");
        if p.is_dir() {
            return p.canonicalize().ok().or(Some(p));
        }
    }
    None
}

const LEGAL_STATIC_FILES: &[&str] = &[
    "terms-he.html",
    "terms.html",
    "privacy-he.html",
    "privacy.html",
    "dpa.html",
    "subprocessors.html",
    "pricing.html",
    "_shared.css",
    "favicon.svg",
    "sitemap.xml",
];

fn legal_content_type(path: &str) -> &'static str {
    if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".xml") {
        "application/xml; charset=utf-8"
    } else {
        "text/html; charset=utf-8"
    }
}

async fn serve_legal_static_named(dir: Arc<PathBuf>, file: &'static str) -> Response {
    let path = dir.join(file);
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = StatusCode::OK;
    if let Ok(v) = HeaderValue::from_str(legal_content_type(file)) {
        resp.headers_mut().insert(CONTENT_TYPE, v);
    }
    resp
}

fn mount_legal_static(api: Router) -> Router {
    let Some(dir) = resolve_deploy_public_dir() else {
        return api;
    };
    eprintln!(
        "[Weissman] Legal/marketing static: {} → /terms-he.html, /privacy.html, …",
        dir.display()
    );
    let dir = Arc::new(dir);
    let mut legal = Router::new();
    for &name in LEGAL_STATIC_FILES {
        let dir_clone = Arc::clone(&dir);
        legal = legal.route(
            &format!("/{name}"),
            get(move || serve_legal_static_named(Arc::clone(&dir_clone), name)),
        );
    }
    api.merge(legal)
}

/// Builds the full Axum router (API, static Command Center, WebSockets).
///
/// CORS and global rate limiting are applied by the **`weissman-server`** binary only — this keeps
/// production policy in one place. Do not run a second HTTP entrypoint; use `weissman-server`.
pub async fn build_http_router(state: Arc<AppState>, static_dir: Option<PathBuf>) -> Router {
    crate::observability::init_prometheus_recorder();
    // Canonical dashboard = /command-center/ (React: Globe, Radar, Memory Lab, System Core, etc.).
    // When frontend/dist exists we redirect / and /dashboard there; /command-center is served by static_router (no duplicate route).
    let root_routes = if static_dir.is_some() {
        Router::new()
            .route("/", get(redirect_to_command_center))
            .route("/dashboard", get(redirect_to_command_center))
    } else if weissman_core::tls_policy::is_production_environment() {
        // No static dir: this process CANNOT serve /command-center/, so redirecting there
        // produced 303 -> 404. Say where the UI actually lives instead.
        Router::new()
            .route("/", get(command_center_served_elsewhere))
            .route("/dashboard", get(command_center_served_elsewhere))
    } else {
        Router::new()
            .route("/", get(dashboard_page))
            .route("/dashboard", get(dashboard_page))
    };
    let api = serve_route_groups::mount_api_routes(root_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::http::tenant_scan_limit::tenant_scan_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(
            crate::http::ceo_rbac::ceo_rbac_middleware,
        ))
        .layer(middleware::from_fn(crate::rbac::mutation_rbac_middleware))
        .layer(middleware::from_fn(
            crate::http::client_scope::client_scope_middleware,
        ))
        .layer(middleware::from_fn(
            crate::http::sse_context::sse_context_middleware,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), auth_guard))
        .layer(middleware::from_fn(crate::http::api_rate_limit_middleware))
        // Pre-auth: later `.layer()` is outer (runs first). Login rate-limit must
        // sit outside `auth_guard` so a password-spray is rejected before any
        // weissman_auth pool checkout / bcrypt.
        .layer(middleware::from_fn(
            crate::http::login_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(
            crate::observability::http_metrics_middleware,
        ))
        .layer(middleware::from_fn(
            crate::request_trace::trace_http_middleware,
        ))
        .layer(middleware::from_fn(
            crate::http::privilege_header_proxy_middleware,
        ))
        .with_state(state);
    // Frontend is built with base: '/command-center/' so assets at /command-center/assets/...
    let app = if let Some(dir) = static_dir {
        eprintln!("[Weissman] Command Center (React) enabled: {} → / and /dashboard redirect to /command-center/", dir.display());
        let index_path = dir.join("index.html");
        let index_html = tokio::fs::read_to_string(&index_path)
            .await
            .unwrap_or_else(|_| {
                eprintln!(
                    "[Weissman] Could not read {} for SPA fallback",
                    index_path.display()
                );
                String::from(
                    "<!DOCTYPE html><html><body>Command Center index not found.</body></html>",
                )
            });
        let spa_fallback = Router::new()
            .route("/", get(command_center_spa_index))
            .route("/*path", get(command_center_spa_index))
            .layer(Extension(index_html))
            .into_service();
        let serve_dir = ServeDir::new(dir)
            .fallback(spa_fallback)
            .map_response(|response| response.map(Body::new));
        let static_router = Router::new().nest_service("/command-center", serve_dir);
        mount_legal_static(api.merge(static_router))
    } else {
        eprintln!("[Weissman] Command Center not found (no frontend/dist). Using legacy dashboard at /. Set WEISSMAN_STATIC or run from project root with frontend/dist built.");
        mount_legal_static(api)
    };
    app
}

pub async fn run_http_tcp_listener(app: Router, port: u16) {
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.raw_os_error() == Some(98) => {
            eprintln!(
                "[Weissman] Port {} in use. Set PORT=8001 or stop the other process.",
                port
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[Weissman] FATAL: bind {}: {}", addr, e);
            std::process::exit(1);
        }
    };
    eprintln!(
        "[Weissman] Listening on http://0.0.0.0:{} (set PORT in .env to change; Nginx must proxy the same port)",
        port
    );
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        eprintln!("[Weissman] FATAL: server exited: {}", e);
        std::process::exit(1);
    }
    eprintln!("[Weissman] Graceful shutdown complete — in-flight requests drained.");
}

/// Resolves on SIGINT (Ctrl-C) or SIGTERM (container/systemd stop) so Axum drains
/// in-flight requests before the process exits — deploys/redeploys no longer cut
/// active scans, SSE streams, or agent dispatches mid-flight.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    eprintln!("[Weissman] Shutdown signal received — draining connections…");
}

#[cfg(test)]
mod public_route_guard_tests {
    use super::{is_public_route, Method};

    /// Every route that was historically reachable without auth must still be public.
    /// (Only the `Always` entries are asserted here so the test is env-independent; the
    /// `NonProdOnly` docs routes depend on `is_production_environment()`.)
    #[test]
    fn public_routes_cover_historical_allowlist() {
        let expected: &[(Method, &str)] = &[
            (Method::GET, "/api/health"),
            (Method::POST, "/api/logout"),
            (Method::POST, "/api/auth/refresh"),
            (Method::POST, "/api/onboarding/register"),
            (Method::POST, "/api/webhooks/paddle"),
            (Method::GET, "/api/auth/oidc/begin"),
            (Method::GET, "/api/auth/oidc/callback"),
            (Method::POST, "/api/auth/saml/acs"),
            (Method::GET, "/api/auth/saml/begin"),
            (Method::POST, "/api/deception/aws-events"),
            (Method::POST, "/api/integrations/slack/interactivity"),
            (Method::POST, "/api/auth/signup"),
            (Method::GET, "/api/auth/verify"),
            (Method::POST, "/api/public/demo-request"),
            (Method::POST, "/api/v1/alerts/aws-canary"),
            (Method::GET, "/status"),
            (Method::POST, "/api/agents/enroll"),
            (Method::POST, "/api/agents/session"),
        ];
        for (m, p) in expected {
            assert!(is_public_route(m, p), "expected {m} {p} to be public");
        }
    }

    /// Protected routes must never be public, and a public path with the wrong method
    /// must not slip through.
    #[test]
    fn protected_routes_are_not_public() {
        assert!(!is_public_route(&Method::GET, "/api/findings"));
        assert!(!is_public_route(&Method::POST, "/api/command-center/scan"));
        assert!(!is_public_route(&Method::DELETE, "/api/clients/1"));
        // Correct public path but wrong method is not public.
        assert!(!is_public_route(&Method::GET, "/api/logout"));
        assert!(!is_public_route(&Method::POST, "/api/health"));
    }

    /// Axum runs the *last* `.layer()` first. Login rate-limit must be layered
    /// after `auth_guard` so brute-force POSTs never check out a weissman_auth
    /// connection before the in-process governor.
    #[test]
    fn login_rate_limit_layer_is_outside_auth_guard() {
        let src = include_str!("serve.rs");
        let start = src
            .find("pub async fn build_http_router")
            .expect("build_http_router");
        let chunk = &src[start..];
        let end = chunk.find(".with_state(state)").unwrap_or(chunk.len());
        let layers = &chunk[..end];
        let auth = layers
            .find("from_fn_with_state(state.clone(), auth_guard)")
            .expect("auth_guard layer");
        let login = layers
            .find("login_rate_limit_middleware")
            .expect("login_rate_limit layer");
        assert!(
            login > auth,
            "login_rate_limit_middleware must be layered after auth_guard (outer / pre-auth)"
        );
    }
}

#[cfg(test)]
mod cc_stream_tests {
    use super::{normalize_cc_event, stream_lag_notice};
    use serde_json::Value;

    /// A lag notice must be a well-formed resync signal the client can act on:
    /// stable `type`/`kind` discriminators plus the dropped count and a timestamp.
    #[test]
    fn lag_notice_is_a_well_formed_resync_signal() {
        let v: Value = serde_json::from_str(&stream_lag_notice(7)).expect("valid JSON");
        assert_eq!(v["type"], "resync");
        assert_eq!(v["kind"], "stream_lagged");
        assert_eq!(v["dropped"], 7);
        assert!(
            v["ts"].as_i64().unwrap_or(0) > 0,
            "timestamp must be present"
        );
    }

    /// The resync notice must NOT be mistaken for a normal telemetry event: it already
    /// carries `kind`, so normalize passes it through untouched (no double-wrapping).
    #[test]
    fn lag_notice_passes_through_normalize_unchanged() {
        let notice = stream_lag_notice(3);
        let normalized = normalize_cc_event(&notice).expect("kinded event passes through");
        let v: Value = serde_json::from_str(&normalized).unwrap();
        assert_eq!(v["kind"], "stream_lagged");
        assert_eq!(v["dropped"], 3);
    }

    /// A kind-shaped frame that still carries the internal `_tid` tenant stamp (e.g. the
    /// recorder's system-tenant resync marker) must have `_tid` stripped on the way out —
    /// the scoping field is server-internal and must never reach the client.
    #[test]
    fn normalize_strips_internal_tid_from_kinded_frames() {
        let stamped = r#"{"_tid":0,"type":"resync","kind":"stream_lagged","dropped":5}"#;
        let normalized = normalize_cc_event(stamped).expect("kinded event passes through");
        let v: Value = serde_json::from_str(&normalized).unwrap();
        assert!(
            v.get("_tid").is_none(),
            "internal _tid must not reach client"
        );
        assert_eq!(v["kind"], "stream_lagged");
        assert_eq!(v["dropped"], 5);
    }

    /// A normal telemetry frame whose payload is passed through via `v.clone()` (non-finding
    /// events) must not smuggle the internal `_tid`/`_seq` into the nested `payload` — the
    /// up-front strip guards every branch, not just the kind-passthrough.
    #[test]
    fn normalize_does_not_leak_tid_or_seq_into_nested_payload() {
        let stamped = r#"{"_tid":9,"_seq":123,"event":"progress","message":"scanning"}"#;
        let normalized = normalize_cc_event(stamped).expect("event frame normalizes");
        let v: Value = serde_json::from_str(&normalized).unwrap();
        assert!(v.get("_tid").is_none(), "top-level _tid must not leak");
        assert!(v.get("_seq").is_none(), "top-level _seq must not leak");
        let payload = &v["payload"];
        assert!(payload.get("_tid").is_none(), "nested _tid must not leak");
        assert!(payload.get("_seq").is_none(), "nested _seq must not leak");
    }
}
