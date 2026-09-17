// IOC feed store + extended UEBA (entity risk, peer outliers) HTTP handlers.
// `include!`d from serve.rs, so AppState / AuthContext / extractors / json! /
// crate:: paths all resolve in the shared module scope (see handler_fragments.rs).

// ─── IOC indicator store (global) ───────────────────────────────────────────

/// GET /api/ioc/indicators — query the normalized indicator store.
async fn api_ioc_indicators(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(200)
        .clamp(1, 2000);
    let type_filter = q.get("type").map(|s| s.trim()).filter(|s| !s.is_empty());
    let source_filter = q.get("source").map(|s| s.trim()).filter(|s| !s.is_empty());
    let search = q.get("q").map(|s| s.trim()).filter(|s| !s.is_empty());
    match crate::ioc::store::query_indicators(
        &state.app_pool,
        type_filter,
        source_filter,
        search,
        limit,
    )
    .await
    {
        Ok(list) => (
            StatusCode::OK,
            Json(json!({"ok": true, "indicators": list})),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(target: "ioc", error = %e, "indicator query failed");
            // Fail visibly (live-only doctrine): do not masquerade a backend
            // failure as an empty result set.
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "indicator store unavailable"})),
            )
                .into_response()
        }
    }
}

/// GET /api/ioc/feeds — feed-run health + store stats for the dashboard.
async fn api_ioc_feeds(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
) -> Response {
    let runs = crate::ioc::store::recent_feed_runs(&state.app_pool, 50)
        .await
        .unwrap_or_default();
    let stats = crate::ioc::store::indicator_stats(&state.app_pool)
        .await
        .unwrap_or_else(|_| json!({"total": 0, "by_type": [], "by_source": []}));
    let configured: Vec<&str> = crate::ioc::feeds::enabled_feeds()
        .iter()
        .map(|f| f.as_str())
        .collect();
    (
        StatusCode::OK,
        Json(json!({"ok": true, "runs": runs, "stats": stats, "enabled_feeds": configured})),
    )
        .into_response()
}

/// POST /api/ioc/ingest/run — enqueue a GLOBAL feed-ingestion job (admin only).
/// This writes the platform-wide shared indicator store, so it must NOT be
/// reachable by customer-portal users. `require_operator` would admit them
/// (role_rank maps OPERATOR and CLIENT to the same rank), so gate on admin.
async fn api_ioc_ingest_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "ioc_feed_sync",
        json!({}),
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "IOC feed sync queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "ioc", error = %e, "enqueue ioc_feed_sync failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "enqueue_failed"})),
            )
                .into_response()
        }
    }
}

/// POST /api/ioc/retrohunt/run — enqueue a tenant retrohunt job (admin only —
/// a resource-intensive sweep; keep it off the customer-portal role).
async fn api_ioc_retrohunt_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "ioc_retrohunt",
        json!({}),
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "IOC retrohunt queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "ioc", error = %e, "enqueue ioc_retrohunt failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "enqueue_failed"})),
            )
                .into_response()
        }
    }
}

/// POST /api/ioc/match — match a batch of observables against the live store +
/// this tenant's watchlist (operator analyst tool).
async fn api_ioc_match(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let observables = body.get("observables").and_then(Value::as_array).cloned();
    let Some(observables) = observables else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "body.observables[] required"})),
        )
            .into_response();
    };
    let mut matchset = match crate::ioc::store::load_active_matchset(&state.app_pool, 500_000).await
    {
        Ok(ms) => ms,
        Err(e) => {
            tracing::warn!(target: "ioc", error = %e, "load matchset failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "store unavailable"})),
            )
                .into_response();
        }
    };
    if let Ok(wl) =
        crate::ioc::store::load_watchlist_matchset(&state.app_pool, auth.tenant_id).await
    {
        matchset.merge(wl);
    }
    const MATCH_CAP: usize = 2000;
    let evaluated = observables.len().min(MATCH_CAP);
    let truncated = observables.len() > MATCH_CAP;
    let mut hits = Vec::new();
    for obs in observables.iter().take(MATCH_CAP) {
        let raw = obs.get("value").and_then(Value::as_str).unwrap_or("");
        if raw.is_empty() {
            continue;
        }
        let ty = obs
            .get("type")
            .and_then(Value::as_str)
            .and_then(crate::ioc::IocType::from_str_lenient)
            .or_else(|| crate::ioc::guess_type(raw));
        let Some(ty) = ty else { continue };
        if let Some(hit) = matchset.match_observable(ty, raw) {
            hits.push(json!({
                "observable": raw,
                "type": hit.ioc_type.as_str(),
                "matched": hit.value_norm,
                "source": hit.source,
                "severity": hit.severity,
                "confidence": hit.confidence,
            }));
        }
    }
    (
        StatusCode::OK,
        Json(json!({"ok": true, "submitted": observables.len(), "checked": evaluated, "truncated": truncated, "hits": hits})),
    )
        .into_response()
}

// ─── Tenant sightings + watchlist ───────────────────────────────────────────

/// GET /api/ioc/sightings — this tenant's IOC sightings.
async fn api_ioc_sightings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    match crate::ioc::store::query_sightings(&state.app_pool, auth.tenant_id, limit).await {
        Ok(list) => (StatusCode::OK, Json(json!({"ok": true, "sightings": list}))).into_response(),
        Err(e) => {
            tracing::warn!(target: "ioc", error = %e, "sightings query failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "sightings unavailable"})),
            )
                .into_response()
        }
    }
}

/// GET /api/ioc/watchlist — this tenant's custom indicators.
async fn api_ioc_watchlist(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match crate::ioc::store::list_watchlist(&state.app_pool, auth.tenant_id, 1000).await {
        Ok(list) => (StatusCode::OK, Json(json!({"ok": true, "watchlist": list}))).into_response(),
        Err(e) => {
            tracing::warn!(target: "ioc", error = %e, "watchlist query failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "watchlist unavailable"})),
            )
                .into_response()
        }
    }
}

/// POST /api/ioc/watchlist — add a custom indicator (analyst).
async fn api_ioc_watchlist_add(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let value = body
        .get("value")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if value.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "value required"})),
        )
            .into_response();
    }
    let ioc_type = body
        .get("type")
        .and_then(Value::as_str)
        .and_then(crate::ioc::IocType::from_str_lenient)
        .or_else(|| crate::ioc::guess_type(value));
    let Some(ioc_type) = ioc_type else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "could not classify indicator; pass an explicit type"})),
        )
            .into_response();
    };
    let severity = body
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("high");
    let note = body.get("note").and_then(Value::as_str).unwrap_or("");
    let created_by = format!("user:{}", auth.user_id);
    match crate::ioc::store::add_watchlist(
        &state.app_pool,
        auth.tenant_id,
        ioc_type,
        value,
        severity,
        note,
        &created_by,
    )
    .await
    {
        Ok(id) => (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response(),
        Err(e) => {
            tracing::warn!(target: "ioc", error = %e, "watchlist add failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "add failed"})),
            )
                .into_response()
        }
    }
}

/// DELETE /api/ioc/watchlist/:id — deactivate a custom indicator (analyst).
async fn api_ioc_watchlist_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    match crate::ioc::store::delete_watchlist(&state.app_pool, auth.tenant_id, id).await {
        Ok(true) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "not found"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "delete failed"})),
        )
            .into_response(),
    }
}

// ─── Extended UEBA surfaces ─────────────────────────────────────────────────

/// GET /api/ueba/entity-risk — top entities by decayed risk score.
async fn api_ueba_entity_risk(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 500);
    match crate::ueba_models::risk::top_entities(&state.app_pool, auth.tenant_id, limit).await {
        Ok(list) => (StatusCode::OK, Json(json!({"ok": true, "entities": list}))).into_response(),
        Err(e) => {
            tracing::warn!(target: "ueba", error = %e, "entity-risk query failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "entity risk unavailable"})),
            )
                .into_response()
        }
    }
}

/// GET /api/ueba/peer-anomalies — hosts deviating from their cohort baseline.
async fn api_ueba_peer_anomalies(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    match crate::ueba_models::peer_store::peer_outliers(&state.app_pool, auth.tenant_id, limit)
        .await
    {
        Ok(list) => (StatusCode::OK, Json(json!({"ok": true, "outliers": list}))).into_response(),
        Err(e) => {
            tracing::warn!(target: "ueba", error = %e, "peer-anomalies query failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "peer anomalies unavailable"})),
            )
                .into_response()
        }
    }
}

// ─── Feed credentials (admin) ───────────────────────────────────────────────

/// GET /api/ioc/credentials — masked status of every configurable feed key.
/// Admin only; NEVER returns a secret value (only configured/source + a hint).
async fn api_ioc_credentials(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let list = crate::ioc::creds::status(&state.app_pool).await;
    (
        StatusCode::OK,
        Json(json!({"ok": true, "credentials": list})),
    )
        .into_response()
}

/// PUT /api/ioc/credentials — set or clear one feed credential (admin only).
/// Body: `{ "key": "ABUSECH_AUTH_KEY", "value": "<secret>" }`. An empty value
/// clears the key (the connector then falls back to the environment variable).
async fn api_ioc_credentials_set(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let key = body.get("key").and_then(Value::as_str).unwrap_or("").trim();
    if !crate::ioc::creds::is_allowed(key) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "unknown feed credential key"})),
        )
            .into_response();
    }
    // `value` absent or null is treated as an explicit clear.
    let value = body.get("value").and_then(Value::as_str).unwrap_or("");
    let updated_by = format!("user:{}", auth.user_id);
    match crate::ioc::creds::set(&state.app_pool, key, value, &updated_by).await {
        Ok(()) => {
            let cleared = value.trim().is_empty();
            tracing::info!(target: "ioc", key = %key, cleared, by = %updated_by, "feed credential updated");
            (
                StatusCode::OK,
                Json(json!({"ok": true, "key": key, "cleared": cleared})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!(target: "ioc", error = %e, "feed credential write failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "write failed"})),
            )
                .into_response()
        }
    }
}
