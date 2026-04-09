// CEO Command Center — strategy, war-room SSE, HPC policy, vaccine vault (live DB only).

#[derive(Deserialize, Default)]
struct CeoWarRoomSseQuery {
    #[serde(default)]
    since: Option<i64>,
    #[serde(default)]
    session: Option<String>,
}

#[derive(Deserialize, Default)]
struct CeoJobsLiveQuery {
    #[serde(default)]
    client_id: Option<i64>,
}

#[derive(Deserialize)]
struct CeoVaultListQuery {
    #[serde(default = "ceo_default_vault_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn ceo_default_vault_limit() -> i64 {
    50
}

#[derive(Deserialize)]
struct CeoSuspendedListQuery {
    #[serde(default = "ceo_default_suspended_limit")]
    limit: i64,
}

fn ceo_default_suspended_limit() -> i64 {
    50
}

async fn api_ceo_strategy_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let j =
        crate::ceo::strategy::get_ceo_strategy_json(state.app_pool.as_ref(), auth.tenant_id).await;
    (StatusCode::OK, Json(j)).into_response()
}

async fn api_ceo_strategy_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    match crate::ceo::strategy::patch_ceo_strategy(
        state.app_pool.as_ref(),
        auth.tenant_id,
        &body,
    )
    .await
    {
        Ok(()) => {
            let j = crate::ceo::strategy::get_ceo_strategy_json(
                state.app_pool.as_ref(),
                auth.tenant_id,
            )
            .await;
            (StatusCode::OK, Json(json!({ "ok": true, "strategy": j }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_ceo_war_room_sse(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CeoWarRoomSseQuery>,
) -> Response {
    let since = q.since.unwrap_or(0);
    let stream = crate::ceo::war_room::sse_war_room_stream(
        state.app_pool.clone(),
        auth.tenant_id,
        since,
        q.session,
    );
    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(20)))
        .into_response()
}

async fn api_ceo_hpc_policy_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match crate::ceo::hpc::get_hpc_policy(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_ceo_hpc_policy_put(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<crate::ceo::hpc::HpcPolicyPutBody>,
) -> Response {
    match crate::ceo::hpc::put_hpc_policy(state.app_pool.as_ref(), auth.tenant_id, &body).await {
        Ok(row) => (StatusCode::OK, Json(row)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_ceo_vault_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CeoVaultListQuery>,
) -> Response {
    match crate::ceo::vault::list_vault_rows(
        state.app_pool.as_ref(),
        auth.tenant_id,
        q.limit,
        q.offset,
    )
    .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_ceo_vault_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    match crate::ceo::vault::get_vault_row(state.app_pool.as_ref(), auth.tenant_id, id).await {
        Ok(Some(row)) => (StatusCode::OK, Json(row)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": "not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_ceo_vault_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<crate::ceo::vault::VaultInsertBody>,
) -> Response {
    match crate::ceo::vault::post_vault_row(state.app_pool.as_ref(), auth.tenant_id, &body).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "ok": true, "id": id }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_ceo_vault_match(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    match crate::ceo::vault::match_vault_row(state.app_pool.as_ref(), auth.tenant_id, id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_ceo_vault_export_criticals(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match crate::ceo::vault::export_vault_criticals_csv(state.app_pool.as_ref(), auth.tenant_id).await
    {
        Ok(csv) => {
            let mut headers = HeaderMap::new();
            let _ = headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/csv; charset=utf-8"),
            );
            let _ = headers.insert(
                CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"genesis_vault_criticals.csv\""),
            );
            (headers, csv).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_ceo_suspended_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CeoSuspendedListQuery>,
) -> Response {
    match crate::ceo::vault::list_suspended_graphs(
        state.app_pool.as_ref(),
        auth.tenant_id,
        q.limit,
    )
    .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_ceo_suspended_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    match crate::ceo::vault::get_suspended_graph(state.app_pool.as_ref(), auth.tenant_id, id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": "not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_ceo_council_session_sse(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
    Query(q): Query<CeoWarRoomSseQuery>,
) -> Response {
    let since = q.since.unwrap_or(0);
    let jid = job_id.trim().to_string();
    if jid.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": "job_id required" })),
        )
            .into_response();
    }
    let stream = crate::ceo::war_room::sse_war_room_stream(
        state.app_pool.clone(),
        auth.tenant_id,
        since,
        Some(jid),
    );
    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(20)))
        .into_response()
}

#[derive(Deserialize)]
struct CeoSovereignBufferQuery {
    #[serde(default = "ceo_default_sovereign_limit")]
    limit: i64,
}

fn ceo_default_sovereign_limit() -> i64 {
    100
}

async fn api_ceo_sovereign_buffer_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CeoSovereignBufferQuery>,
) -> Response {
    match crate::ceo::sovereign::list_sovereign_buffer(
        state.app_pool.as_ref(),
        auth.tenant_id,
        q.limit,
    )
    .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_ceo_sovereign_trigger_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    let Some(buffer_id) = body.get("buffer_id").and_then(|v| v.as_i64()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": "buffer_id required" })),
        )
            .into_response();
    };
    let trace = body
        .get("trace")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match crate::ceo::sovereign::enqueue_sovereign_from_buffer_row(
        state.app_pool.as_ref(),
        auth.tenant_id,
        buffer_id,
        trace,
    )
    .await
    {
        Ok(job_id) => {
            (StatusCode::ACCEPTED, Json(json!({ "ok": true, "job_id": job_id }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_ceo_suspended_resume(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    let trace = body
        .get("trace")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match crate::ceo::vault::post_resume_suspended_job(
        state.app_pool.as_ref(),
        auth.tenant_id,
        id,
        trace,
    )
    .await
    {
        Ok(job_id) => {
            (StatusCode::ACCEPTED, Json(json!({ "ok": true, "job_id": job_id }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_ceo_telemetry_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let uptime = state.started_at.elapsed().as_secs();
    let j = crate::ceo::ops_status::build_ceo_telemetry_json(
        state.app_pool.as_ref(),
        auth.tenant_id,
        uptime,
    )
    .await;
    (StatusCode::OK, Json(j)).into_response()
}

async fn api_ceo_jobs_live_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CeoJobsLiveQuery>,
) -> Response {
    match crate::ceo::ops_status::list_live_async_jobs(
        state.app_pool.as_ref(),
        auth.tenant_id,
        q.client_id,
    )
    .await
    {
        Ok(jobs) => (StatusCode::OK, Json(json!({ "ok": true, "jobs": jobs }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct CeoGlobalSafeBody {
    global_safe_mode: bool,
}

async fn api_ceo_global_safe_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CeoGlobalSafeBody>,
) -> Response {
    let ip = crate::http::client_ip::extract_client_ip(&headers, addr);
    match crate::ceo::safe_mode::set_tenant_global_safe_mode(
        state.app_pool.as_ref(),
        state.auth_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        body.global_safe_mode,
        &ip,
    )
    .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "global_safe_mode": body.global_safe_mode,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_ceo_god_mode_snapshot_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let policy_tid = match crate::ceo::default_tenant_id(state.auth_pool.as_ref()).await {
        Ok(Some(id)) => id,
        Ok(None) => auth.tenant_id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "detail": format!("resolve default tenant: {e}") })),
            )
                .into_response();
        }
    };
    match crate::ceo::god_mode::build_god_mode_snapshot_json(
        state.app_pool.as_ref(),
        auth.tenant_id,
        policy_tid,
    )
    .await
    {
        Ok(j) => (StatusCode::OK, Json(j)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct CeoScanIntervalBody {
    scan_interval_secs: u64,
}

async fn api_ceo_god_mode_scan_interval_patch(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
    Json(body): Json<CeoScanIntervalBody>,
) -> Response {
    match crate::ceo::god_mode::default_scan_interval_secs_set(
        state.app_pool.as_ref(),
        body.scan_interval_secs,
    )
    .await
    {
        Ok(()) => {
            let v =
                crate::ceo::god_mode::default_scan_interval_secs_get(state.app_pool.as_ref()).await;
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "scan_interval_secs": v,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct CeoTenantEnginesBody {
    engine_id: String,
    enabled: bool,
}

/// PUT/PATCH body: `{ "engine_id": "asm", "enabled": true }` — updates `system_configs.active_engines` for **`tenants.slug = default`** (orchestrator policy).
async fn api_ceo_tenant_engines_put(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
    Json(body): Json<CeoTenantEnginesBody>,
) -> Response {
    let policy_tid = match crate::ceo::default_tenant_id(state.auth_pool.as_ref()).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "detail": "no active tenant with slug 'default'; cannot update orchestrator active_engines"
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "detail": format!("resolve default tenant: {e}") })),
            )
                .into_response();
        }
    };
    match crate::ceo::patch_tenant_active_engine(
        state.app_pool.as_ref(),
        policy_tid,
        body.engine_id.trim(),
        body.enabled,
    )
    .await
    {
        Ok(engines) => (
            StatusCode::OK,
            Json(crate::ceo::tenant_engines::active_engines_json_value(&engines)),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}
