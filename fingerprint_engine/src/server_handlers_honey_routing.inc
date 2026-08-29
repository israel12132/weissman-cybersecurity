// REST handlers for Honey-Routing Gateway SOC dashboard (authenticated).

async fn api_honey_routing_dashboard(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    match crate::honey_routing_store::dashboard_snapshot(
        &state.app_pool,
        auth.tenant_id,
        client_id,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e, "ok": false })),
        )
            .into_response(),
    }
}

async fn api_honey_routing_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((client_id, session_id)): Path<(i64, i64)>,
) -> Response {
    match crate::honey_routing_store::session_payloads(
        &state.app_pool,
        auth.tenant_id,
        client_id,
        session_id,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(json!({ "ok": true, "payloads": v }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e, "ok": false })),
        )
            .into_response(),
    }
}

async fn api_honey_routing_isolate_request(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((client_id, session_id)): Path<(i64, i64)>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    match crate::honey_routing_store::request_isolate(
        &state.app_pool,
        auth.tenant_id,
        client_id,
        session_id,
        auth.user_id,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e, "ok": false })),
        )
            .into_response(),
    }
}

async fn api_honey_routing_isolate_approve(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((client_id, session_id)): Path<(i64, i64)>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let confirm = body
        .get("confirm")
        .and_then(Value::as_str)
        .unwrap_or("");
    match crate::honey_routing_store::approve_isolate(
        &state.app_pool,
        auth.tenant_id,
        client_id,
        session_id,
        auth.user_id,
        confirm,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e, "ok": false })),
        )
            .into_response(),
    }
}
