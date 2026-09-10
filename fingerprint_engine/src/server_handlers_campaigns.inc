// Adversary Campaign Fabric (P0) — Command Center API.
// Mounted from serve_route_groups.rs. Handlers share serve.rs module scope.

fn campaign_err_status(detail: &str) -> StatusCode {
    if detail.contains("not found") {
        StatusCode::NOT_FOUND
    } else if detail.contains("illegal campaign transition") || detail.contains("cannot pause") {
        StatusCode::CONFLICT
    } else if detail.contains("unsupported goal")
        || detail.contains("no authorized domains")
        || detail.contains("client_id")
        || detail.contains("planner returned")
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn api_campaigns_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let mut client_id = q.get("client_id").and_then(|s| s.parse::<i64>().ok());
    if let Some(cid) = auth.assigned_client_id {
        client_id = Some(cid);
    }
    match crate::adversary_campaign::list_campaigns(&state.app_pool, auth.tenant_id, client_id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": scrub_internal_error(&e) })),
        )
            .into_response(),
    }
}

async fn api_campaigns_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(mut body): Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    if let Err(r) = crate::client_isolation::force_json_client_id(&auth, &mut body) {
        return r;
    }
    let req: crate::adversary_campaign::CreateCampaignRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "detail": "client_id required" })),
            )
                .into_response();
        }
    };
    match crate::adversary_campaign::create_campaign(
        &state.app_pool,
        auth.tenant_id,
        Some(auth.user_id),
        &req,
    )
    .await
    {
        Ok(v) => (StatusCode::CREATED, Json(v)).into_response(),
        Err(e) => {
            let status = campaign_err_status(&e);
            let detail = if status == StatusCode::INTERNAL_SERVER_ERROR {
                json!(scrub_internal_error(&e))
            } else {
                json!(e)
            };
            (status, Json(json!({ "ok": false, "detail": detail }))).into_response()
        }
    }
}

async fn api_campaigns_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    match crate::adversary_campaign::get_campaign(&state.app_pool, auth.tenant_id, id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            let status = campaign_err_status(&e);
            let detail = if matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST | StatusCode::CONFLICT) {
                json!(e)
            } else {
                json!(scrub_internal_error(&e))
            };
            (status, Json(json!({ "ok": false, "detail": detail }))).into_response()
        }
    }
}

async fn api_campaigns_start(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    match crate::adversary_campaign::start_campaign(
        &state.app_pool,
        auth.tenant_id,
        id,
        Some(auth.user_id),
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            let status = campaign_err_status(&e);
            let detail = if matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST | StatusCode::CONFLICT) {
                json!(e)
            } else {
                json!(scrub_internal_error(&e))
            };
            (status, Json(json!({ "ok": false, "detail": detail }))).into_response()
        }
    }
}

async fn api_campaigns_pause(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    match crate::adversary_campaign::pause_campaign(
        &state.app_pool,
        auth.tenant_id,
        id,
        Some(auth.user_id),
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            let status = campaign_err_status(&e);
            let detail = if matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST | StatusCode::CONFLICT) {
                json!(e)
            } else {
                json!(scrub_internal_error(&e))
            };
            (status, Json(json!({ "ok": false, "detail": detail }))).into_response()
        }
    }
}

async fn api_campaigns_plan(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    match crate::adversary_campaign::get_plan(&state.app_pool, auth.tenant_id, id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            let status = campaign_err_status(&e);
            let detail = if matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST | StatusCode::CONFLICT) {
                json!(e)
            } else {
                json!(scrub_internal_error(&e))
            };
            (status, Json(json!({ "ok": false, "detail": detail }))).into_response()
        }
    }
}

async fn api_campaigns_steps(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    match crate::adversary_campaign::list_steps(&state.app_pool, auth.tenant_id, id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            let status = campaign_err_status(&e);
            let detail = if matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST | StatusCode::CONFLICT) {
                json!(e)
            } else {
                json!(scrub_internal_error(&e))
            };
            (status, Json(json!({ "ok": false, "detail": detail }))).into_response()
        }
    }
}

async fn api_campaigns_events(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    match crate::adversary_campaign::list_events(&state.app_pool, auth.tenant_id, id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            let status = campaign_err_status(&e);
            let detail = if matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST | StatusCode::CONFLICT) {
                json!(e)
            } else {
                json!(scrub_internal_error(&e))
            };
            (status, Json(json!({ "ok": false, "detail": detail }))).into_response()
        }
    }
}
