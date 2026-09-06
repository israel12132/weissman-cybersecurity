// CEO classified platform-key cockpit — live keyring, never returns secrets on GET.

#[derive(Deserialize)]
struct PlatformKeyPutBody {
    env_name: String,
    value: String,
}

fn platform_key_actor(auth: &AuthContext) -> String {
    if auth.is_superadmin {
        format!("user:{}:superadmin", auth.user_id)
    } else {
        format!("user:{}:{}", auth.user_id, auth.role)
    }
}

async fn api_ceo_platform_keys_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let v = crate::ceo::platform_keys::list_platform_keys(&state.app_pool, auth.tenant_id).await;
    (StatusCode::OK, Json(v)).into_response()
}

async fn api_ceo_platform_keys_put(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PlatformKeyPutBody>,
) -> Response {
    let ip = extract_client_ip(&headers, addr);
    match crate::ceo::platform_keys::put_platform_key(
        &state.app_pool,
        &state.auth_pool,
        auth.tenant_id,
        auth.user_id,
        &ip,
        &platform_key_actor(&auth),
        &body.env_name,
        &body.value,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_ceo_platform_keys_reveal(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(env_name): Path<String>,
) -> Response {
    let ip = extract_client_ip(&headers, addr);
    match crate::ceo::platform_keys::reveal_platform_key(
        &state.app_pool,
        &state.auth_pool,
        auth.tenant_id,
        auth.user_id,
        &ip,
        &env_name,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_ceo_platform_keys_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(env_name): Path<String>,
) -> Response {
    let ip = extract_client_ip(&headers, addr);
    match crate::ceo::platform_keys::delete_platform_key(
        &state.app_pool,
        &state.auth_pool,
        auth.tenant_id,
        auth.user_id,
        &ip,
        &env_name,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}
