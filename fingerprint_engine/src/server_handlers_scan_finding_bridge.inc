/// GET /api/findings/scan-cortex-bridge — scan→finding map + live XSIAM coverage.
#[derive(serde::Deserialize, Default)]
struct ScanCortexBridgeQuery {
    #[serde(default)]
    client_id: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    compare_xdr: Option<bool>,
}

#[derive(serde::Deserialize, Default)]
struct ScanCortexBridgeFlushBody {
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    client_id: Option<i64>,
    #[serde(default)]
    ids: Option<Vec<String>>,
}

async fn api_findings_scan_cortex_bridge(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<ScanCortexBridgeQuery>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let compare = q.compare_xdr.unwrap_or(false);
    match crate::scan_finding_bridge::snapshot(
        state.read_pool(),
        auth.tenant_id,
        q.client_id,
        q.limit.unwrap_or(200),
        compare,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((code, detail)) => (
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({"ok": false, "detail": detail})),
        )
            .into_response(),
    }
}

async fn api_findings_scan_cortex_bridge_flush(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: Option<Json<ScanCortexBridgeFlushBody>>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let body = body.map(|b| b.0).unwrap_or_default();
    let ids = body.ids.unwrap_or_default();
    match crate::scan_finding_bridge::flush(
        state.app_pool.as_ref(),
        auth.tenant_id,
        body.client_id,
        &ids,
        body.dry_run.unwrap_or(false),
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((code, detail)) => (
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({"ok": false, "detail": detail})),
        )
            .into_response(),
    }
}
