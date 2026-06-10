// Endpoint-agent HTTP + WebSocket handlers (included from handler_fragments.rs).

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

//
// Routes:
//   POST /api/agents/enrollment-tokens       → admin creates a one-time enrollment token (JSON: client_id, valid_minutes)
//   POST /api/agents/enroll                  → agent exchanges plaintext token for session JWT (unauth)
//   GET  /api/agents/status                  → list of agents per tenant, with online flag + last_seen
//   GET  /ws/agent                           → WebSocket session (token=session_jwt)
//   POST /api/agents/:agent_id/task          → admin queues an immediate detection task

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
    let validity = body.valid_minutes.clamp(5, 1440);
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
                Json(json!({"ok": false, "detail": format!("{}", e)})),
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
    axum::extract::Json(body): axum::extract::Json<AgentEnrollBody>,
) -> Response {
    let consumed = match crate::endpoint_agents::consume_enrollment_token(
        state.app_pool.as_ref(),
        body.enrollment_token.trim(),
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
    let agent_uuid = match crate::endpoint_agents::register_agent(
        state.app_pool.as_ref(),
        consumed.tenant_id,
        consumed.client_id,
        &body.hostname,
        &body.device_name,
        &body.os,
        &body.arch,
        &body.agent_version,
        &body.capabilities,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(target: "agents", error = %e, "register_agent failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("{}", e)})),
            )
                .into_response();
        }
    };
    let session_jwt = match crate::auth_jwt::create_access_token(
        0, // user_id 0 = agent (no human owner)
        consumed.tenant_id,
        "agent",
        false,
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
        ws_path: "/ws/agent".into(),
        server_message: Some(format!("welcome host={}", body.hostname)),
    };
    (StatusCode::OK, Json(serde_json::to_value(&resp).unwrap_or(json!({})))).into_response()
}

async fn api_agents_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
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
                    LIMIT 500"#,
            )
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
    (StatusCode::OK, Json(json!({"ok": true, "agents": out, "online_count": online.len()}))).into_response()
}

#[derive(serde::Deserialize)]
struct DispatchAgentTaskBody {
    client_id: i64,
    engine: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    params: Value,
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
    let task_uuid = match crate::endpoint_agents::enqueue_task(
        state.app_pool.as_ref(),
        auth.tenant_id,
        body.client_id,
        &body.engine,
        body.target.as_deref(),
        &params,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("{}", e)})),
            )
                .into_response();
        }
    };
    // Best-effort live delivery: if any agent for this client is online, push the task.
    let dispatched = dispatch_to_first_live_agent(
        state.app_pool.as_ref(),
        &state.endpoint_agents,
        auth.tenant_id,
        body.client_id,
        crate::endpoint_agents::ServerToAgent::Task {
            task_id: task_uuid.to_string(),
            engine: body.engine.clone(),
            target: body.target.clone(),
            params,
        },
    )
    .await;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "task_id": task_uuid.to_string(),
            "live_dispatched": dispatched,
        })),
    )
        .into_response()
}

async fn dispatch_to_first_live_agent(
    pool: &PgPool,
    registry: &Arc<crate::endpoint_agents::AgentRegistry>,
    tenant_id: i64,
    client_id: i64,
    msg: crate::endpoint_agents::ServerToAgent,
) -> bool {
    if let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await {
        let row = sqlx::query_scalar::<_, String>(
            r#"SELECT agent_uuid::text FROM endpoint_agents
                WHERE tenant_id = $1 AND client_id = $2
                  AND status IN ('online','enrolled')
                ORDER BY last_seen_at DESC
                LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        let _ = tx.commit().await;
        if let Some(uuid) = row {
            if registry.send(&uuid, msg).await.is_ok() {
                return true;
            }
        }
    }
    false
}

// WebSocket handler. Authentication uses `access_token` from the query string (JWT). We treat
// `agent_id` as the next URL path segment (?agent_id=…). The agent's first frame must be a
// `hello` containing the agent_id; we verify it matches the JWT-bound tenant_id.
async fn ws_agent(
    ws: axum::extract::WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if auth.role != "agent" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "detail": "agent JWT required"})),
        )
            .into_response();
    }
    let app_pool = state.app_pool.clone();
    let registry = state.endpoint_agents.clone();
    let tenant_id = auth.tenant_id;
    ws.on_upgrade(move |mut socket| async move {
        let (tx_to_agent, mut rx_to_agent) =
            tokio::sync::mpsc::channel::<crate::endpoint_agents::ServerToAgent>(128);
        let mut agent_uuid: Option<String> = None;
        let mut client_id: Option<i64> = None;
        // Welcome message will be sent after we see the hello frame.

        loop {
            tokio::select! {
                outbound = rx_to_agent.recv() => {
                    let Some(msg) = outbound else { break; };
                    let line = serde_json::to_string(&msg).unwrap_or_default();
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
                            let v: serde_json::Value = match serde_json::from_str(&s) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
                            match kind {
                                "hello" => {
                                    let aid = v.get("agent_id").and_then(Value::as_str).unwrap_or("").to_string();
                                    let cid = v.get("client_id").and_then(Value::as_i64).unwrap_or(0);
                                    if aid.is_empty() {
                                        let _ = socket.send(Message::Close(None)).await;
                                        return;
                                    }
                                    agent_uuid = Some(aid.clone());
                                    client_id = Some(cid);
                                    registry.attach(&aid, tx_to_agent.clone()).await;
                                    if let Ok(u) = uuid::Uuid::parse_str(&aid) {
                                        let _ = crate::endpoint_agents::mark_seen(app_pool.as_ref(), &u, "online").await;
                                    }
                                    // Welcome + replay pending tasks.
                                    let welcome = crate::endpoint_agents::ServerToAgent::Welcome {
                                        scan_concurrency: Some(2),
                                        heartbeat_secs: Some(30),
                                    };
                                    let line = serde_json::to_string(&welcome).unwrap_or_default();
                                    let _ = socket.send(Message::Text(line)).await;
                                    if let Ok(pending) = crate::endpoint_agents::pending_tasks_for_client(
                                        app_pool.as_ref(),
                                        tenant_id,
                                        cid,
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
                                            let _ = crate::endpoint_agents::mark_seen(app_pool.as_ref(), &u, "online").await;
                                        }
                                    }
                                }
                                "finding" => {
                                    let engine = v.get("engine").and_then(Value::as_str).unwrap_or("agent_finding").to_string();
                                    let mut finding = v.get("finding").cloned().unwrap_or(Value::Null);
                                    if engine == "ueba_baseline" {
                                        if let (Some(aid), Value::Object(ref mut map)) =
                                            (agent_uuid.as_deref(), &mut finding)
                                        {
                                            map.entry("agent_id".to_string())
                                                .or_insert_with(|| json!(aid));
                                        }
                                    }
                                    if let Some(cid) = client_id {
                                        let _ = crate::endpoint_agents::store_finding(
                                            app_pool.as_ref(),
                                            tenant_id,
                                            cid,
                                            &engine,
                                            &finding,
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

        // Cleanup.
        if let Some(aid) = agent_uuid.as_deref() {
            registry.detach(aid).await;
            if let Ok(u) = uuid::Uuid::parse_str(aid) {
                let _ = crate::endpoint_agents::mark_seen(app_pool.as_ref(), &u, "offline").await;
            }
        }
    })
}
