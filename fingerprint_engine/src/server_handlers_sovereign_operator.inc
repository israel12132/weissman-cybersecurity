use crate::sovereign_operator::{
    chat as sov_chat, forge as sov_forge, knowledge as sov_knowledge, log_stream as sov_logs,
    memory as sov_memory, scripts as sov_scripts, tools as sov_tools,
};
use uuid::Uuid;

#[derive(Deserialize, Default)]
struct SovereignChatBody {
    #[serde(default)]
    question: String,
    #[serde(default)]
    session_id: Option<Uuid>,
    #[serde(default)]
    shift: Option<String>,
}

#[derive(Deserialize, Default)]
struct SovereignSessionQuery {
    #[serde(default)]
    session_id: Option<Uuid>,
    #[serde(default)]
    shift: Option<String>,
}

#[derive(Deserialize, Default)]
struct SovereignLogQuery {
    #[serde(default)]
    since: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Deserialize, Default)]
struct SovereignToolBody {
    #[serde(default)]
    name: String,
    #[serde(default)]
    args: Value,
    #[serde(default)]
    session_id: Option<Uuid>,
}

#[derive(Deserialize, Default)]
struct SovereignSseQuery {
    #[serde(default)]
    since: Option<i64>,
}

#[derive(Deserialize, Default)]
struct SovereignMemoryQuery {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Deserialize, Default)]
struct SovereignLimitQuery {
    #[serde(default)]
    limit: Option<i64>,
}

fn sov_trace(trace_ext: Option<Extension<crate::request_trace::TraceId>>) -> Option<String> {
    trace_ext.map(|Extension(t)| t.0)
}

async fn api_sovereign_operator_chat(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(body): Json<SovereignChatBody>,
) -> Response {
    let q = body.question.trim();
    if q.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": "question required" })),
        )
            .into_response();
    }
    let ip = crate::http::extract_client_ip(&headers, addr);
    match sov_chat::run_chat(
        state.app_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        body.session_id,
        body.shift.as_deref(),
        q,
        sov_trace(trace_ext),
    )
    .await
    {
        Ok(r) => {
            let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
                Ok(t) => t,
                Err(_) => {
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "ok": true,
                            "session_id": r.session_id,
                            "thought": r.thought,
                            "reply": r.reply,
                            "tools": r.tools.iter().map(|t| json!({"name": t.name, "ok": t.ok, "detail": t.detail, "payload": t.payload})).collect::<Vec<_>>(),
                        })),
                    )
                        .into_response();
                }
            };
            let actor = crate::audit_log::user_email_for_id(state.auth_pool.as_ref(), auth.user_id).await;
            let _ = crate::audit_log::insert_audit(
                &mut tx,
                auth.tenant_id,
                Some(auth.user_id),
                &actor,
                "sovereign_operator_chat",
                &format!("session={} tools={}", r.session_id, r.tools.len()),
                &ip,
            )
            .await;
            let _ = tx.commit().await;
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "session_id": r.session_id,
                    "thought": r.thought,
                    "reply": r.reply,
                    "tools": r.tools.iter().map(|t| json!({
                        "name": t.name,
                        "ok": t.ok,
                        "detail": t.detail,
                        "payload": t.payload
                    })).collect::<Vec<_>>(),
                })),
            )
                .into_response()
        }
        Err(e) => {
            let unavailable = e.contains("requires a live LLM") || e.contains("LLM unreachable");
            let code = if unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::BAD_GATEWAY
            };
            (code, Json(json!({ "ok": false, "detail": e }))).into_response()
        }
    }
}

async fn api_sovereign_operator_session_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<SovereignSessionQuery>,
) -> Response {
    let sid = match q.session_id {
        Some(id) => id,
        None => match sov_chat::latest_session(state.app_pool.as_ref(), auth.tenant_id, auth.user_id)
            .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                match sov_chat::ensure_session(
                    state.app_pool.as_ref(),
                    auth.tenant_id,
                    auth.user_id,
                    None,
                    q.shift.as_deref(),
                )
                .await
                {
                    Ok(id) => id,
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "ok": false, "detail": e })),
                        )
                            .into_response();
                    }
                }
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "ok": false, "detail": e })),
                )
                    .into_response();
            }
        },
    };
    match sov_chat::list_messages(state.app_pool.as_ref(), auth.tenant_id, sid, 120).await {
        Ok(messages) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "session_id": sid, "messages": messages })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_sovereign_operator_knowledge_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match sov_knowledge::build_snapshot(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(snap) => (StatusCode::OK, Json(json!({ "ok": true, "knowledge": snap }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_sovereign_operator_logs_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<SovereignLogQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(100);
    let listed = if let Some(since) = q.since.filter(|s| *s > 0) {
        sov_logs::list_since(state.app_pool.as_ref(), auth.tenant_id, since, limit).await
    } else {
        sov_logs::list_recent(state.app_pool.as_ref(), auth.tenant_id, limit).await
    };
    match listed {
        Ok(events) => (StatusCode::OK, Json(json!({ "ok": true, "events": events }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_sovereign_operator_windows_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match sov_logs::live_windows(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(windows) => (StatusCode::OK, Json(json!({ "ok": true, "windows": windows }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_sovereign_operator_tools_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(body): Json<SovereignToolBody>,
) -> Response {
    let name = body.name.trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": "name required" })),
        )
            .into_response();
    }
    let out = sov_tools::execute_tool(
        state.app_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        sov_trace(trace_ext),
        name,
        &body.args,
    )
    .await;
    let ip = crate::http::extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        let actor = crate::audit_log::user_email_for_id(state.auth_pool.as_ref(), auth.user_id).await;
        let _ = crate::audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            "sovereign_operator_tool",
            &format!("tool={} ok={} {}", out.name, out.ok, out.detail),
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }
    if let Some(sid) = body.session_id {
        let _ = sov_chat::insert_message(
            state.app_pool.as_ref(),
            auth.tenant_id,
            sid,
            "tool",
            &out.detail,
            None,
            Some(&out.name),
            out.payload.clone(),
        )
        .await;
    }
    let code = if out.ok {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        code,
        Json(json!({
            "ok": out.ok,
            "name": out.name,
            "detail": out.detail,
            "payload": out.payload,
        })),
    )
        .into_response()
}

async fn api_sovereign_operator_tune_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(args): Json<Value>,
) -> Response {
    let out = sov_tools::execute_tool(
        state.app_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        sov_trace(trace_ext),
        "tune",
        &args,
    )
    .await;
    let ip = crate::http::extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        let actor = crate::audit_log::user_email_for_id(state.auth_pool.as_ref(), auth.user_id).await;
        let _ = crate::audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            "sovereign_operator_tune",
            &out.detail,
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }
    let code = if out.ok {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        code,
        Json(json!({
            "ok": out.ok,
            "detail": out.detail,
            "payload": out.payload,
        })),
    )
        .into_response()
}

async fn api_sovereign_operator_race_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(args): Json<Value>,
) -> Response {
    let out = sov_tools::execute_tool(
        state.app_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        sov_trace(trace_ext),
        "race",
        &args,
    )
    .await;
    let ip = crate::http::extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        let actor = crate::audit_log::user_email_for_id(state.auth_pool.as_ref(), auth.user_id).await;
        let _ = crate::audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            "sovereign_operator_race",
            &out.detail,
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }
    let code = if out.ok {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        code,
        Json(json!({
            "ok": out.ok,
            "detail": out.detail,
            "payload": out.payload,
        })),
    )
        .into_response()
}

async fn api_sovereign_operator_stream(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<SovereignSseQuery>,
) -> Response {
    let pool = state.app_pool.clone();
    let tenant_id = auth.tenant_id;
    let mut since_id = q.since.unwrap_or(0);
    let stream = async_stream::stream! {
        let hello = json!({
            "type": "connected",
            "message": "Sovereign Operator SSE — live rows from weissman_sovereign_engine_logs",
        });
        if let Ok(s) = serde_json::to_string(&hello) {
            yield Ok::<axum::response::sse::Event, std::convert::Infallible>(axum::response::sse::Event::default().event("connected").data(s));
        }
        let mut first = true;
        loop {
            if !first {
                tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            }
            first = false;
            match sov_logs::list_since(pool.as_ref(), tenant_id, since_id, 64).await {
                Ok(events) => {
                    for ev in events {
                        if let Some(id) = ev.get("id").and_then(Value::as_i64) {
                            since_id = since_id.max(id);
                        }
                        if let Ok(s) = serde_json::to_string(&ev) {
                            yield Ok::<axum::response::sse::Event, std::convert::Infallible>(axum::response::sse::Event::default().event("engine_log").data(s));
                        }
                    }
                }
                Err(e) => {
                    let err = json!({ "type": "error", "message": e.to_string() });
                    yield Ok::<axum::response::sse::Event, std::convert::Infallible>(axum::response::sse::Event::default().event("error").data(err.to_string()));
                }
            }
        }
    };
    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(20)))
        .into_response()
}

async fn api_sovereign_operator_memory_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<SovereignMemoryQuery>,
) -> Response {
    let kind = q.kind.as_deref().map(str::trim).filter(|s| !s.is_empty());
    match sov_memory::list_recent(
        state.app_pool.as_ref(),
        auth.tenant_id,
        kind,
        q.limit.unwrap_or(80),
    )
    .await
    {
        Ok(rows) => (StatusCode::OK, Json(json!({ "ok": true, "memory": rows }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_sovereign_operator_forge_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<SovereignLimitQuery>,
) -> Response {
    match sov_forge::list_forge(state.app_pool.as_ref(), auth.tenant_id, q.limit.unwrap_or(40))
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(json!({ "ok": true, "forge": rows }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_sovereign_operator_scripts_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<SovereignLimitQuery>,
) -> Response {
    match sov_scripts::list_scripts(state.app_pool.as_ref(), auth.tenant_id, q.limit.unwrap_or(40))
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(json!({ "ok": true, "scripts": rows }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}
