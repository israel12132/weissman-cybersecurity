// Route wiring for previously-orphaned frontend contracts.
// Handlers here are `include!`d into the serve module scope (see handler_fragments.rs),
// so axum extractors, `Json`, `StatusCode`, `Response`, `json!`, and
// `scrub_internal_error` resolve from that scope.

/// GET /api/competitive/panw-displacement?client_id= — live PANW displacement
/// signals; honest empty/degraded payload when the store is unreachable.
async fn api_panw_displacement(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let client_id = q.get("client_id").and_then(|s| s.parse::<i64>().ok());
    let signals =
        crate::panw_displacement::load_live_signals(&state.app_pool, auth.tenant_id, client_id)
            .await;
    (
        StatusCode::OK,
        Json(crate::panw_displacement::displacement_json(&signals)),
    )
        .into_response()
}

/// GET /api/board-pack?client_id= — live board evidence pack summary for the
/// selected client. No client selected → honest needs_client payload, never
/// fabricated demo data. Store-down → 503.
async fn api_board_pack(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let client_id = q.get("client_id").and_then(|s| s.parse::<i64>().ok());
    let Some(client_id) = client_id else {
        return (
            StatusCode::OK,
            Json(json!({
                "ok": false,
                "needs_client": true,
                "detail": "Select a client to build the board evidence pack.",
            })),
        )
            .into_response();
    };
    let lang = crate::board_pack::PackLang::parse(q.get("lang").map(|s| s.as_str()));
    match crate::board_pack::compose(&state.app_pool, auth.tenant_id, client_id, lang).await {
        Ok(pack) => (StatusCode::OK, Json(crate::board_pack::preview_json(&pack))).into_response(),
        Err(e) if e == "client not found" => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "client not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
        )
            .into_response(),
    }
}
