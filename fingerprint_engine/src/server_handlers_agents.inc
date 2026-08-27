// Endpoint-agent HTTP + WebSocket handlers (included from handler_fragments.rs).

fn agent_bin_root() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("WEISSMAN_AGENT_BIN_DIR") {
        if !dir.trim().is_empty() {
            return std::path::PathBuf::from(dir.trim());
        }
    }
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let workspace = std::path::Path::new(&manifest).join("..").join("..");
        let packaged = workspace.join("bin").join("agents");
        if packaged.is_dir() {
            return packaged;
        }
        let release = workspace.join("target").join("release").join("weissman-agent");
        if release.is_file() {
            return release.parent().unwrap_or(&release).to_path_buf();
        }
    }
    std::path::PathBuf::from("./bin/agents")
}

/// `/install/binaries/:platform/weissman-agent` is a public, unauthenticated route, so
/// `platform` is attacker-controlled and is used as a path segment under the agent-binary
/// root. Accept only a conservative charset — no separators, no `..`, no NUL, no absolute
/// paths — so a crafted segment cannot escape the root.
fn sanitize_agent_platform(platform: &str) -> Option<String> {
    let p = platform.trim().to_ascii_lowercase();
    if p.is_empty() || p.len() > 64 {
        return None;
    }
    if !p
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return None;
    }
    // "." and ".." pass the charset check above but are traversal, not platform names.
    if p.chars().all(|c| c == '.') {
        return None;
    }
    Some(p)
}

/// Locate the endpoint-agent binary for `platform`, or `None` when we have nothing safe and
/// architecture-correct to serve (the caller turns that into a 404).
fn resolve_agent_binary(platform: &str) -> Option<std::path::PathBuf> {
    let platform = sanitize_agent_platform(platform)?;
    let root = agent_bin_root();
    let file_name = if platform.contains("windows") {
        "weissman-agent.exe"
    } else {
        "weissman-agent"
    };

    let named = root.join(&platform).join(file_name);
    if named.is_file() {
        return Some(named);
    }

    // Legacy flat layout (bare-metal dev, where agent_bin_root() resolves to
    // target/release). Only serve it when the requested platform actually matches the
    // architecture this process is running on — otherwise an aarch64 endpoint asking an
    // x86-64 server would download an ELF it cannot execute.
    if platform.contains(std::env::consts::ARCH) {
        let flat = root.join(file_name);
        if flat.is_file() {
            return Some(flat);
        }
    }
    None
}

/// Return the bash installer. Path: GET /install/agent.sh.
async fn install_agent_sh() -> Response {
    let script = include_str!("../../scripts/agent/install.sh");
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
    );
    (StatusCode::OK, h, script).into_response()
}

async fn install_agent_ps1() -> Response {
    let script = include_str!("../../scripts/agent/install.ps1");
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-powershell; charset=utf-8"),
    );
    (StatusCode::OK, h, script).into_response()
}

async fn install_agent_binary(axum::extract::Path(platform): axum::extract::Path<String>) -> Response {
    let Some(file_path) = resolve_agent_binary(&platform) else {
        // `platform` is attacker-controlled: report it as an escaped JSON value only, never
        // interpolated into a copy-pasteable shell command.
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "detail": format!("No agent binary published for platform '{platform}'."),
                "hint": "Build it with `cargo build -p weissman-agent --release` and install it at $WEISSMAN_AGENT_BIN_DIR/<platform>/weissman-agent, or run scripts/package_agent_binaries.sh to cross-compile every supported target.",
            })),
        )
            .into_response();
    };
    match tokio::fs::read(&file_path).await {
        Ok(bytes) => {
            let mut h = axum::http::HeaderMap::new();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/octet-stream"),
            );
            h.insert(
                axum::http::header::CONTENT_DISPOSITION,
                axum::http::HeaderValue::from_static("attachment; filename=\"weissman-agent\""),
            );
            (StatusCode::OK, h, bytes).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
        )
            .into_response(),
    }
}

async fn install_agent_binary_sha256(
    axum::extract::Path(platform): axum::extract::Path<String>,
) -> Response {
    let Some(file_path) = resolve_agent_binary(&platform) else {
        return (StatusCode::NOT_FOUND, "binary missing").into_response();
    };
    match tokio::fs::read(&file_path).await {
        Ok(bytes) => {
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, &bytes);
            let digest = hex::encode(sha2::Digest::finalize(h));
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            (StatusCode::OK, headers, format!("{digest}  weissman-agent\n")).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
        )
            .into_response(),
    }
}

//
// Routes:
//   POST /api/agents/enrollment-tokens       → admin creates a one-time enrollment token
//   POST /api/agents/enroll                  → agent exchanges plaintext token for session JWT (unauth)
//   GET  /api/agents/status                  → list of agents per tenant
//   POST /api/agents/dispatch                → analyst queues detection task (fleet round-robin)
//   GET  /ws/agent                           → WebSocket session (agent JWT only)
//       Auth: prefer `Authorization: Bearer <session_jwt>`; `?token=<session_jwt>` is allowed for
//       agents that cannot set WS headers. Human user access JWTs are rejected from query strings.

#[derive(serde::Deserialize)]
struct CreateAgentTokenBody {
    client_id: i64,
    #[serde(default = "default_token_validity_minutes")]
    valid_minutes: i64,
}
fn default_token_validity_minutes() -> i64 {
    60
}

async fn api_agents_create_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Json(body): axum::extract::Json<CreateAgentTokenBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    if !crate::endpoint_agents::client_exists(state.app_pool.as_ref(), auth.tenant_id, body.client_id)
        .await
        .unwrap_or(false)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "client_id not found for tenant"})),
        )
            .into_response();
    }
    let validity = body.valid_minutes.clamp(5, 10_080);
    let plaintext = match crate::endpoint_agents::create_enrollment_token(
        state.app_pool.as_ref(),
        auth.tenant_id,
        body.client_id,
        Some(auth.user_id),
        validity,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(target: "agents", error = %e, "create_enrollment_token failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "enrollment_token": plaintext,
            "expires_in_minutes": validity,
            "client_id": body.client_id,
            "install_hint": "Distribute this single-use token to the admin running the install script. Server keeps only the hash.",
        })),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct AgentEnrollBody {
    enrollment_token: String,
    hostname: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    arch: String,
    #[serde(default)]
    agent_version: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    client_id: Option<i64>,
}

async fn api_agents_enroll(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<AgentEnrollBody>,
) -> Response {
    let client_ip = crate::http::extract_client_ip(&headers, addr);
    let consumed = match crate::endpoint_agents::consume_enrollment_token(
        state.app_pool.as_ref(),
        body.enrollment_token.trim(),
        Some(&client_ip),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "detail": e})),
            )
                .into_response();
        }
    };
    if let Some(cid) = body.client_id {
        if cid != consumed.client_id {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "client_id mismatch with token"})),
            )
                .into_response();
        }
    }
    let caps = if body.capabilities.is_empty() {
        crate::engine_dispatch::AGENT_REQUIRED_ENGINES
            .iter()
            .map(|s| (*s).to_string())
            .chain(std::iter::once("ueba_baseline".to_string()))
            .collect::<Vec<_>>()
    } else {
        body.capabilities.clone()
    };
    let (agent_uuid, agent_secret) = match crate::endpoint_agents::register_agent(
        state.app_pool.as_ref(),
        consumed.tenant_id,
        consumed.client_id,
        &body.hostname,
        &body.device_name,
        &body.os,
        &body.arch,
        &body.agent_version,
        &caps,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(target: "agents", error = %e, "register_agent failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
            )
                .into_response();
        }
    };
    let session_jwt = match crate::auth_jwt::create_agent_session_token(
        &agent_uuid.to_string(),
        consumed.tenant_id,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(target: "agents", error = %e, "agent jwt build failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "agent jwt failed"})),
            )
                .into_response();
        }
    };
    let resp = crate::endpoint_agents::EnrollResponse {
        agent_id: agent_uuid.to_string(),
        tenant_id: consumed.tenant_id,
        client_id: consumed.client_id,
        session_jwt,
        // Returned exactly once — only its hash is stored. The agent persists it so it can renew
        // its short-lived session JWT without a second (single-use) enrollment token.
        agent_secret,
        ws_path: "/ws/agent".into(),
        server_message: Some(format!("welcome host={}", body.hostname)),
    };
    (StatusCode::OK, Json(serde_json::to_value(&resp).unwrap_or(json!({})))).into_response()
}

#[derive(serde::Deserialize)]
struct AgentSessionBody {
    agent_id: String,
    agent_secret: String,
}

/// `POST /api/agents/session` — exchange an agent's long-lived renewal secret for a fresh
/// short-lived session JWT.
///
/// Unauthenticated by design: the secret IS the credential, exactly like `/api/agents/enroll`.
/// It exists because enrollment tokens are single-use and the session JWT expires (default 4h),
/// so before this an agent had one session for its whole lifetime and then went dark permanently
/// with no way back short of a human issuing a new token and re-running the installer.
///
/// Deliberately uniform failure: unknown agent, revoked agent and wrong secret all return the
/// same 401 with the same body, so this cannot be used to enumerate which agent ids exist.
async fn api_agents_session(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AgentSessionBody>,
) -> Response {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "detail": "invalid agent credentials"})),
        )
            .into_response()
    };
    let Ok(agent_uuid) = body.agent_id.trim().parse::<uuid::Uuid>() else {
        return unauthorized();
    };
    if body.agent_secret.trim().is_empty() {
        return unauthorized();
    }
    let renewed = crate::endpoint_agents::renew_agent_session(
        state.app_pool.as_ref(),
        agent_uuid,
        body.agent_secret.trim(),
    )
    .await;
    let (tenant_id, client_id) = match renewed {
        Ok(Some(v)) => v,
        Ok(None) => return unauthorized(),
        Err(e) => {
            tracing::error!(target: "agents", error = %e, "agent session renewal lookup failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
            )
                .into_response();
        }
    };
    let session_jwt =
        match crate::auth_jwt::create_agent_session_token(&agent_uuid.to_string(), tenant_id) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(target: "agents", error = %e, "agent jwt build failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "detail": "agent jwt failed"})),
                )
                    .into_response();
            }
        };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "agent_id": agent_uuid.to_string(),
            "tenant_id": tenant_id,
            "client_id": client_id,
            "session_jwt": session_jwt,
            "ws_path": "/ws/agent",
        })),
    )
        .into_response()
}

async fn api_agents_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let online: std::collections::HashSet<String> = state
        .endpoint_agents
        .online_agents()
        .await
        .into_iter()
        .collect();
    let rows = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(mut tx) => {
            let r = sqlx::query(
                r#"SELECT agent_uuid::text AS agent_uuid, client_id, hostname, device_name, os, arch,
                          agent_version, capabilities, enrolled_at, last_seen_at, status
                     FROM endpoint_agents
                    ORDER BY last_seen_at DESC
                    LIMIT $1"#,
            )
            .bind(crate::endpoint_agents::AGENT_STATUS_LIMIT)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default();
            let _ = tx.commit().await;
            r
        }
        Err(_) => Vec::new(),
    };
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let uuid: String = r.try_get("agent_uuid").unwrap_or_default();
            let is_online = online.contains(&uuid);
            json!({
                "agent_id": uuid,
                "client_id": r.try_get::<i64, _>("client_id").unwrap_or(0),
                "hostname": r.try_get::<String, _>("hostname").unwrap_or_default(),
                "device_name": r.try_get::<String, _>("device_name").unwrap_or_default(),
                "os": r.try_get::<String, _>("os").unwrap_or_default(),
                "arch": r.try_get::<String, _>("arch").unwrap_or_default(),
                "agent_version": r.try_get::<String, _>("agent_version").unwrap_or_default(),
                "capabilities": r.try_get::<Value, _>("capabilities").unwrap_or(Value::Array(vec![])),
                "enrolled_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("enrolled_at").ok().map(|d| d.to_rfc3339()),
                "last_seen_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("last_seen_at").ok().map(|d| d.to_rfc3339()),
                "status": r.try_get::<String, _>("status").unwrap_or_default(),
                "online": is_online,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "agents": out,
            "online_count": online.len(),
            "fleet_max": crate::endpoint_agents::FLEET_MAX_AGENTS,
        })),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct DispatchAgentTaskBody {
    client_id: i64,
    engine: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    fleet_broadcast: bool,
}

async fn api_agents_dispatch_task(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Json(body): axum::extract::Json<DispatchAgentTaskBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let params = if body.params.is_null() {
        json!({})
    } else {
        body.params.clone()
    };
    if body.fleet_broadcast {
        let engines = crate::endpoint_agents::NSSI_BRIDGE_ENGINES;
        let mut dispatched = 0u32;
        for (i, engine) in engines.iter().enumerate() {
            if let Ok((_, live)) = crate::endpoint_agents::enqueue_and_dispatch_fleet(
                state.app_pool.as_ref(),
                &state.endpoint_agents,
                auth.tenant_id,
                body.client_id,
                engine,
                body.target.as_deref(),
                &params,
            )
            .await
            {
                if live {
                    dispatched += 1;
                }
            }
            if (i as i32) >= crate::endpoint_agents::FLEET_MAX_AGENTS {
                break;
            }
        }
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "fleet_broadcast": true,
                "engines_dispatched": engines.len(),
                "live_dispatched": dispatched,
            })),
        )
            .into_response();
    }
    let (task_uuid, live) = match crate::endpoint_agents::enqueue_and_dispatch_fleet(
        state.app_pool.as_ref(),
        &state.endpoint_agents,
        auth.tenant_id,
        body.client_id,
        &body.engine,
        body.target.as_deref(),
        &params,
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "task_id": task_uuid.to_string(),
            "live_dispatched": live,
        })),
    )
        .into_response()
}

// WebSocket handler. Authentication uses agent session JWT (`typ: agent`) via header or `?token=`.
async fn ws_agent(
    ws: axum::extract::WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_agent(&auth) {
        return r;
    }
    // Revocation. Agent tokens carry no jti and the request path's revocation branch only runs
    // for user contexts, so a revoked agent's token stayed valid for the remainder of its 4-hour
    // TTL — during which it could still inject findings and close tasks. This is the only
    // long-lived agent entry point, so it is the right place to check.
    if let Some(ref aid) = auth.agent_id {
        if let Ok(uuid) = aid.trim().parse::<uuid::Uuid>() {
            if crate::endpoint_agents::agent_is_revoked(state.app_pool.as_ref(), uuid).await {
                tracing::warn!(target: "agents", agent_id = %aid, "rejected websocket from a revoked agent");
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"ok": false, "detail": "agent revoked"})),
                )
                    .into_response();
            }
        }
    }
    let expected_agent_id = auth.agent_id.clone();
    let app_pool = state.app_pool.clone();
    let registry = state.endpoint_agents.clone();
    let tenant_id = auth.tenant_id;
    crate::http::bounded_codec::constrain_ws(ws).on_upgrade(move |mut socket| async move {
        let (tx_to_agent, mut rx_to_agent) =
            tokio::sync::mpsc::channel::<crate::endpoint_agents::ServerToAgent>(256);
        let mut agent_uuid: Option<String> = None;
        let mut client_id: Option<i64> = None;
        let mut local_session: u64 = 0;

        loop {
            tokio::select! {
                outbound = rx_to_agent.recv() => {
                    let Some(msg) = outbound else { break; };
                    let line = crate::http::simd_json::to_string(&msg).unwrap_or_default();
                    if socket.send(axum::extract::ws::Message::Text(line)).await.is_err() {
                        break;
                    }
                }
                frame = socket.recv() => {
                    let Some(frame) = frame else { break; };
                    let Ok(frame) = frame else { break; };
                    use axum::extract::ws::Message;
                    match frame {
                        Message::Text(s) => {
                            let v: serde_json::Value = match crate::http::simd_json::from_slice(s.as_bytes()) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
                            match kind {
                                "hello" => {
                                    let aid = v.get("agent_id").and_then(Value::as_str).unwrap_or("").to_string();
                                    if aid.is_empty() {
                                        let _ = socket.send(Message::Close(None)).await;
                                        return;
                                    }
                                    if let Some(ref expected) = expected_agent_id {
                                        if expected != &aid {
                                            let _ = socket.send(Message::Close(None)).await;
                                            return;
                                        }
                                    }
                                    let Ok(agent_u) = uuid::Uuid::parse_str(&aid) else {
                                        let _ = socket.send(Message::Close(None)).await;
                                        return;
                                    };
                                    let db_cid = match crate::endpoint_agents::registered_client_id(
                                        app_pool.as_ref(),
                                        tenant_id,
                                        &agent_u,
                                    )
                                    .await
                                    {
                                        Ok(Some(c)) => c,
                                        _ => {
                                            let _ = socket.send(Message::Close(None)).await;
                                            return;
                                        }
                                    };
                                    let hello_cid = v.get("client_id").and_then(Value::as_i64).unwrap_or(0);
                                    if hello_cid != 0 && hello_cid != db_cid {
                                        let _ = socket.send(Message::Close(None)).await;
                                        return;
                                    }
                                    agent_uuid = Some(aid.clone());
                                    client_id = Some(db_cid);
                                    local_session = registry.attach(&aid, tenant_id, tx_to_agent.clone()).await;
                                    if let Ok(u) = uuid::Uuid::parse_str(&aid) {
                                        let _ = crate::endpoint_agents::mark_seen(app_pool.as_ref(), tenant_id, &u, "online").await;
                                        registry.notify_status(&aid, tenant_id, "online").await;
                                    }
                                    let welcome = crate::endpoint_agents::ServerToAgent::Welcome {
                                        scan_concurrency: Some(8),
                                        heartbeat_secs: Some(20),
                                    };
                                    let line = crate::http::simd_json::to_string(&welcome).unwrap_or_default();
                                    let _ = socket.send(Message::Text(line)).await;
                                    if let Ok(pending) = crate::endpoint_agents::pending_tasks_for_client(
                                        app_pool.as_ref(),
                                        tenant_id,
                                        db_cid,
                                    )
                                    .await
                                    {
                                        for t in pending {
                                            let _ = tx_to_agent.send(t).await;
                                        }
                                    }
                                }
                                "heartbeat" => {
                                    if let Some(aid) = agent_uuid.as_deref() {
                                        if let Ok(u) = uuid::Uuid::parse_str(aid) {
                                            let _ = crate::endpoint_agents::mark_seen(app_pool.as_ref(), tenant_id, &u, "online").await;
                                            registry.notify_status(aid, tenant_id, "online").await;
                                        }
                                    }
                                }
                                "finding" => {
                                    let engine = v.get("engine").and_then(Value::as_str).unwrap_or("agent_finding").to_string();
                                    let task_id = v.get("task_id").and_then(Value::as_str);
                                    let mut finding = v.get("finding").cloned().unwrap_or(Value::Null);
                                    if let (Some(aid), Value::Object(ref mut map)) =
                                        (agent_uuid.as_deref(), &mut finding)
                                    {
                                        map.entry("agent_id".to_string())
                                            .or_insert_with(|| json!(aid));
                                    }
                                    if let Some(cid) = client_id {
                                        let _ = crate::endpoint_agents::store_finding_for_task(
                                            app_pool.as_ref(),
                                            tenant_id,
                                            cid,
                                            &engine,
                                            &finding,
                                            task_id,
                                        )
                                        .await;
                                    }
                                }
                                "task_done" | "task_error" => {
                                    let task_id = v.get("task_id").and_then(Value::as_str).unwrap_or("").to_string();
                                    let status = if kind == "task_done" { "done" } else { "failed" };
                                    let count = v.get("findings_count").and_then(Value::as_i64).unwrap_or(0) as i32;
                                    let err = v.get("error").and_then(Value::as_str).map(|s| s.to_string());
                                    if let Ok(u) = uuid::Uuid::parse_str(&task_id) {
                                        let _ = crate::endpoint_agents::mark_task_status(
                                            app_pool.as_ref(),
                                            tenant_id,
                                            &u,
                                            status,
                                            count,
                                            err.as_deref(),
                                        )
                                        .await;
                                    }
                                }
                                _ => {}
                            }
                        }
                        Message::Close(_) | Message::Binary(_) => break,
                        _ => {}
                    }
                }
            }
        }

        if let Some(aid) = agent_uuid.as_deref() {
            if registry.detach(aid, local_session).await {
                if let Ok(u) = uuid::Uuid::parse_str(aid) {
                    let _ = crate::endpoint_agents::mark_seen(app_pool.as_ref(), tenant_id, &u, "offline").await;
                    registry.notify_status(aid, tenant_id, "offline").await;
                }
            }
        }
    })
}
