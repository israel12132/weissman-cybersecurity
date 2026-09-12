#[derive(Deserialize)]
struct DiscoveryLabListQuery {
    #[serde(default)]
    client_id: Option<i64>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct DiscoveryExportQuery {
    #[serde(default)]
    format: Option<String>,
}

fn discovery_lab_limit(raw: Option<i64>) -> i64 {
    raw.unwrap_or(100).clamp(1, 500)
}

async fn api_discovery_lab_runs_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<DiscoveryLabListQuery>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    match crate::discovery_lab::list_runs(
        state.app_pool.as_ref(),
        auth.tenant_id,
        q.client_id.or(auth.assigned_client_id),
        discovery_lab_limit(q.limit),
    )
    .await
    {
        Ok(runs) => (StatusCode::OK, Json(json!({ "runs": runs }))).into_response(),
        Err(e) => {
            tracing::error!(target: "discovery_lab", error = %e, "list runs failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": "failed to list discovery lab runs"})),
            )
                .into_response()
        }
    }
}

async fn api_discovery_lab_run_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    match crate::discovery_lab::get_run(state.app_pool.as_ref(), auth.tenant_id, &id).await {
        Ok(Some(run)) => (StatusCode::OK, Json(run)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "run not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "discovery_lab", error = %e, "get run failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": "failed to load run"})),
            )
                .into_response()
        }
    }
}

async fn api_discovery_lab_run_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    body: axum::extract::Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    if let Err(detail) =
        crate::billing::gate_scan_enqueue(state.auth_pool.as_ref(), auth.tenant_id).await
    {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"ok": false, "detail": detail})),
        )
            .into_response();
    }
    let mut body = body.0;
    if let Err(r) = crate::client_isolation::force_json_client_id(&auth, &mut body) {
        return r;
    }
    let client_id = body
        .get("client_id")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .filter(|id| *id > 0);
    let Some(client_id) = client_id else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail": "client_id required — Discovery Lab only runs on authorized tenant clients"})),
        )
            .into_response();
    };
    let target_raw = body
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let target = match crate::discovery_lab::normalize_target_url(&target_raw) {
        Ok(t) => t,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"detail": e}))).into_response();
        }
    };
    let intensity = match body
        .get("intensity")
        .and_then(Value::as_str)
        .unwrap_or("normal")
        .trim()
    {
        "light" => "light",
        "aggressive" => "aggressive",
        _ => "normal",
    };
    let scope = match crate::security_hardening::validate_scan_target_in_scope(
        state.app_pool.as_ref(),
        auth.tenant_id,
        &target,
        Some(client_id),
    )
    .await
    {
        Ok(s) => s,
        Err(detail) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "detail": detail,
                    "code": "target_out_of_scope"
                })),
            )
                .into_response();
        }
    };
    let input = crate::discovery_lab::CreateRunInput {
        tenant_id: auth.tenant_id,
        client_id,
        target_url: target.clone(),
        target_host: scope.normalized_host.clone(),
        intensity: intensity.to_string(),
        created_by_user_id: Some(auth.user_id),
    };
    let run_id =
        match crate::discovery_lab::insert_queued_run(state.app_pool.as_ref(), &input).await {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(target: "discovery_lab", error = %e, "insert run failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"detail": "failed to create discovery lab run"})),
                )
                    .into_response();
            }
        };
    let payload = json!({
        "run_id": run_id,
        "target": target,
        "client_id": client_id,
        "tenant_id": auth.tenant_id,
        "intensity": intensity,
        "engine": crate::discovery_lab::ENGINE_ID,
        "validated_scope": {
            "host": scope.normalized_host,
            "resolved_ips": scope.resolved_ips,
        }
    });
    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &u,
            "discovery_lab_run",
            &format!(
                "run_id={run_id} target={}",
                target.chars().take(200).collect::<String>()
            ),
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        crate::discovery_lab::JOB_KIND,
        payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => {
            let _ = crate::discovery_lab::attach_job_id(
                state.app_pool.as_ref(),
                auth.tenant_id,
                &run_id,
                job_id,
            )
            .await;
            let run =
                crate::discovery_lab::get_run(state.app_pool.as_ref(), auth.tenant_id, &run_id)
                    .await
                    .ok()
                    .flatten();
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "ok": true,
                    "run_id": run_id,
                    "job_id": job_id.to_string(),
                    "run": run,
                    "status_url": format!("/api/discovery-lab/runs/{run_id}"),
                    "job_status_url": format!("/api/jobs/{job_id}"),
                })),
            )
                .into_response()
        }
        Err(e) => {
            let _ = crate::discovery_lab::mark_run_failed(
                state.app_pool.as_ref(),
                auth.tenant_id,
                &run_id,
                "enqueue failed",
            )
            .await;
            tracing::error!(target: "discovery_lab", error = %e, "enqueue failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": scrub_internal_error(&e)})),
            )
                .into_response()
        }
    }
}

async fn api_discovery_lab_candidates_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<DiscoveryLabListQuery>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    match crate::discovery_lab::list_candidates(
        state.app_pool.as_ref(),
        auth.tenant_id,
        q.client_id.or(auth.assigned_client_id),
        q.run_id.as_deref(),
        q.status.as_deref(),
        discovery_lab_limit(q.limit),
    )
    .await
    {
        Ok(candidates) => {
            (StatusCode::OK, Json(json!({ "candidates": candidates }))).into_response()
        }
        Err(e) => {
            tracing::error!(target: "discovery_lab", error = %e, "list candidates failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": "failed to list candidates"})),
            )
                .into_response()
        }
    }
}

async fn api_discovery_lab_candidate_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    match crate::discovery_lab::get_candidate(state.app_pool.as_ref(), auth.tenant_id, &id).await {
        Ok(Some(c)) => (StatusCode::OK, Json(c)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "candidate not found"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": "failed to load candidate"})),
        )
            .into_response(),
    }
}

async fn api_discovery_lab_candidate_action(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::extract::Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    let action_raw = body.get("action").and_then(Value::as_str).unwrap_or("");
    let Some(action) = crate::discovery_lab::CandidateAction::parse(action_raw) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail": "action must be validate, suppress, remediation, or disclosure_ready"})),
        )
            .into_response();
    };
    match crate::discovery_lab::apply_candidate_action(
        state.app_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        &id,
        action,
    )
    .await
    {
        Ok(c) => {
            let ip = extract_client_ip(&headers, addr);
            if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
                let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
                let _ = audit_log::insert_audit(
                    &mut tx,
                    auth.tenant_id,
                    Some(auth.user_id),
                    &u,
                    "discovery_lab_candidate",
                    &format!("candidate={id} action={}", action.as_str()),
                    &ip,
                )
                .await;
                let _ = tx.commit().await;
            }
            (StatusCode::OK, Json(c)).into_response()
        }
        Err(e) if e.contains("not found") => {
            (StatusCode::NOT_FOUND, Json(json!({"detail": e}))).into_response()
        }
        Err(e) if e.contains("illegal") => {
            (StatusCode::CONFLICT, Json(json!({"detail": e}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"detail": e}))).into_response(),
    }
}

fn disclosure_fields_from_json(
    body: &Value,
    fallback: Option<&Value>,
) -> crate::discovery_lab::DisclosureFields {
    let g = |k: &str| {
        body.get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                fallback
                    .and_then(|f| f.get(k))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default()
    };
    let flag = |k: &str, default: bool| {
        body.get(k)
            .and_then(Value::as_bool)
            .or_else(|| fallback.and_then(|f| f.get(k)).and_then(Value::as_bool))
            .unwrap_or(default)
    };
    crate::discovery_lab::DisclosureFields {
        title: g("title"),
        technical_summary: g("technical_summary"),
        impact: g("impact"),
        reproduction: g("reproduction"),
        recommended_fix: g("recommended_fix"),
        timeline: g("timeline"),
        recipient: g("recipient"),
        recipient_kind: g("recipient_kind"),
        redact_payloads: flag("redact_payloads", true),
        redact_internal_hosts: flag("redact_internal_hosts", true),
        redact_customer_ids: flag("redact_customer_ids", true),
    }
}

async fn api_discovery_lab_disclosure_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::extract::Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    let fields = disclosure_fields_from_json(&body.0, None);
    match crate::discovery_lab::create_disclosure_pack(
        state.app_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        &id,
        fields,
    )
    .await
    {
        Ok(pack) => {
            let ip = extract_client_ip(&headers, addr);
            if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
                let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
                let _ = audit_log::insert_audit(
                    &mut tx,
                    auth.tenant_id,
                    Some(auth.user_id),
                    &u,
                    "discovery_lab_disclosure",
                    &format!("opened pack for candidate={id}"),
                    &ip,
                )
                .await;
                let _ = tx.commit().await;
            }
            (StatusCode::CREATED, Json(pack)).into_response()
        }
        Err(e) if e.contains("not found") => {
            (StatusCode::NOT_FOUND, Json(json!({"detail": e}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"detail": e}))).into_response(),
    }
}

async fn api_discovery_lab_disclosures_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<DiscoveryLabListQuery>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    match crate::discovery_lab::list_disclosures(
        state.app_pool.as_ref(),
        auth.tenant_id,
        q.client_id.or(auth.assigned_client_id),
        discovery_lab_limit(q.limit),
    )
    .await
    {
        Ok(packs) => (StatusCode::OK, Json(json!({ "packs": packs }))).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": "failed to list disclosure packs"})),
        )
            .into_response(),
    }
}

async fn api_discovery_lab_disclosure_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    match crate::discovery_lab::get_disclosure(state.app_pool.as_ref(), auth.tenant_id, &id).await {
        Ok(Some(p)) => (StatusCode::OK, Json(p)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "disclosure pack not found"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": "failed to load disclosure pack"})),
        )
            .into_response(),
    }
}

async fn api_discovery_lab_disclosure_update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::extract::Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    let existing =
        match crate::discovery_lab::get_disclosure(state.app_pool.as_ref(), auth.tenant_id, &id)
            .await
        {
            Ok(Some(p)) => p,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"detail": "disclosure pack not found"})),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"detail": "failed to load disclosure pack"})),
                )
                    .into_response();
            }
        };
    let has_fields = body.0.as_object().is_some_and(|o| {
        o.keys().any(|k| {
            matches!(
                k.as_str(),
                "title"
                    | "technical_summary"
                    | "impact"
                    | "reproduction"
                    | "recommended_fix"
                    | "timeline"
                    | "recipient"
                    | "recipient_kind"
                    | "redact_payloads"
                    | "redact_internal_hosts"
                    | "redact_customer_ids"
            )
        })
    });
    let fields = if has_fields {
        Some(disclosure_fields_from_json(&body.0, Some(&existing)))
    } else {
        None
    };
    let new_status = body
        .0
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| body.0.get("action").and_then(Value::as_str));
    match crate::discovery_lab::update_disclosure(
        state.app_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        &id,
        fields,
        new_status,
    )
    .await
    {
        Ok(p) => {
            let ip = extract_client_ip(&headers, addr);
            if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
                let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
                let _ = audit_log::insert_audit(
                    &mut tx,
                    auth.tenant_id,
                    Some(auth.user_id),
                    &u,
                    "discovery_lab_disclosure",
                    &format!("updated pack={id}"),
                    &ip,
                )
                .await;
                let _ = tx.commit().await;
            }
            (StatusCode::OK, Json(p)).into_response()
        }
        Err(e) if e.contains("illegal") => {
            (StatusCode::CONFLICT, Json(json!({"detail": e}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"detail": e}))).into_response(),
    }
}

async fn api_discovery_lab_disclosure_events(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    match crate::discovery_lab::list_disclosure_events(state.app_pool.as_ref(), auth.tenant_id, &id)
        .await
    {
        Ok(events) => (StatusCode::OK, Json(json!({ "events": events }))).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": "failed to load disclosure audit log"})),
        )
            .into_response(),
    }
}

async fn api_discovery_lab_disclosure_export(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Query(q): Query<DiscoveryExportQuery>,
) -> Response {
    if let Err(r) = crate::rbac::require_discovery_lab_steward(&auth) {
        return r;
    }
    let format = q.format.as_deref().unwrap_or("markdown");
    match crate::discovery_lab::export_disclosure(
        state.app_pool.as_ref(),
        auth.tenant_id,
        &id,
        format,
        &[],
    )
    .await
    {
        Ok((filename, ctype, bytes)) => {
            let mut res = Response::new(Body::from(bytes));
            if let Ok(v) = HeaderValue::try_from(ctype) {
                res.headers_mut().insert(CONTENT_TYPE, v);
            }
            if let Ok(v) = HeaderValue::try_from(format!("attachment; filename=\"{filename}\"")) {
                res.headers_mut().insert(CONTENT_DISPOSITION, v);
            }
            res.headers_mut().insert(
                axum::http::HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
            res
        }
        Err(e) if e.contains("not found") => {
            (StatusCode::NOT_FOUND, Json(json!({"detail": e}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"detail": e}))).into_response(),
    }
}
