async fn api_pdf_intelligence(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let requested = q.get("client_id").and_then(|s| s.parse::<i64>().ok());
    let client_id = match crate::client_isolation::bind_requested_client(&auth, requested) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match crate::pdf_intelligence::load_snapshot(state.app_pool.as_ref(), auth.tenant_id, client_id)
        .await
    {
        Ok(snap) => {
            let catalog = crate::pdf_intelligence::default_section_catalog();
            (
                StatusCode::OK,
                Json(json!({
                    "ok": snap.ok,
                    "live": snap.live,
                    "client_id": snap.client_id,
                    "client_name": snap.client_name,
                    "org_name": snap.org_name,
                    "corpus": snap.corpus,
                    "findings": snap.findings,
                    "frameworks": snap.frameworks,
                    "empty_reason": snap.empty_reason,
                    "section_catalog": catalog,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": e, "live": false})),
        )
            .into_response(),
    }
}

async fn api_pdf_intelligence_compose(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<crate::pdf_intelligence::ComposeRequest>,
) -> Response {
    let client_id = match crate::client_isolation::bind_requested_client(&auth, body.client_id) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let snap = match crate::pdf_intelligence::load_snapshot(
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
                Json(json!({"ok": false, "detail": e})),
            )
                .into_response();
        }
    };
    match crate::pdf_intelligence::compose_bytes(&snap, &body) {
        Ok(bytes) => {
            let filename = format!(
                "Weissman_Intelligence_Pack_{}.pdf",
                chrono::Utc::now().format("%Y%m%d")
            );
            let mut headers = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str("application/pdf") {
                headers.insert(CONTENT_TYPE, v);
            }
            if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
                headers.insert(CONTENT_DISPOSITION, v);
            }
            (StatusCode::OK, headers, bytes).into_response()
        }
        Err(e) => (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error_code": "pdf_corpus_empty",
                "detail": e,
            })),
        )
            .into_response(),
    }
}
