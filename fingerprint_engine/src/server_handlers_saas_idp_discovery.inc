async fn api_client_saas_idp_discovery(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::client_lookup_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    };
    let row = match sqlx::query("SELECT id, name, domains FROM clients WHERE id = $1")
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
    {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::client_lookup_unavailable_json(
                    "database unavailable",
                )),
            )
                .into_response();
        }
    };
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "client not found"})),
        )
            .into_response();
    };
    let client_name: String = r.try_get::<String, _>("name").unwrap_or_default();
    let domains_raw: String = r.try_get::<String, _>("domains").unwrap_or_else(|_| "[]".to_string());
    let domains: Vec<String> = serde_json::from_str::<serde_json::Value>(&domains_raw)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .take(50)
        .collect();
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::client_lookup_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    };

    if persist_operator_audit(
        state.app_pool.as_ref(),
        state.auth_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        "saas_idp_discovery_ran",
        &format!("client_id={} client_name={}", client_id, client_name),
        &extract_client_ip(&headers, addr),
    )
    .await
    .is_err()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::saas_idp_unavailable_json(
                "store_down",
            )),
        )
            .into_response();
    }

    let report = crate::saas_idp_discovery::discover(&domains).await;

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "client_id": client_id,
            "client_name": client_name,
            "report": report,
        })),
    )
        .into_response()
}
