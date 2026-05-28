async fn api_client_saas_idp_discovery(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query("SELECT id, name, domains FROM clients WHERE id = $1")
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
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
    let _ = tx.commit().await;

    let report = crate::saas_idp_discovery::discover(&domains).await;

    // Audit log (best-effort).
    if let Ok(mut tx2) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let ip = extract_client_ip(&headers, addr);
        let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(
            &mut tx2,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            "saas_idp_discovery_ran",
            &format!("client_id={} client_name={}", client_id, client_name),
            &ip,
        )
        .await;
        let _ = tx2.commit().await;
    }

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
