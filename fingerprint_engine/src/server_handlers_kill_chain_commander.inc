async fn api_kill_chain_commander(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let requested = q.get("client_id").and_then(|s| s.parse::<i64>().ok());
    let client_id = match crate::client_isolation::bind_requested_client(&auth, requested) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match crate::kill_chain_commander::load_snapshot(
        state.app_pool.as_ref(),
        auth.tenant_id,
        client_id,
    )
    .await
    {
        Ok(snap) => (StatusCode::OK, Json(crate::kill_chain_commander::snapshot_json(&snap)))
            .into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": e, "live": false})),
        )
            .into_response(),
    }
}

async fn api_kill_chain_commander_compose(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<crate::kill_chain_commander::ComposeRequest>,
) -> Response {
    let client_id = match crate::client_isolation::bind_requested_client(&auth, body.client_id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let snap = match crate::kill_chain_commander::load_snapshot(
        state.app_pool.as_ref(),
        auth.tenant_id,
        client_id,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": e, "live": false})),
            )
                .into_response();
        }
    };
    match crate::kill_chain_commander::compose_or_conflict(&snap) {
        Ok(_) => (
            StatusCode::OK,
            Json(crate::kill_chain_commander::snapshot_json(&snap)),
        )
            .into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error_code": "kill_chain_corpus_empty",
                "empty_reason": e,
                "detail": e,
                "live": true,
            })),
        )
            .into_response(),
    }
}
