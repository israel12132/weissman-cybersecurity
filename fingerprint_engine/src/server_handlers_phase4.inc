use axum::body::Bytes;

async fn insert_heal_request_row(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    finding_id: &str,
    vuln_id: i64,
    branch_name: &str,
    pr_url: Option<&str>,
    pr_number: Option<i64>,
    diff_summary: &str,
    verification_status: &str,
    verification_job_id: &str,
) {
    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        let _ = sqlx::query(
            r#"INSERT INTO heal_requests (tenant_id, client_id, finding_id, vulnerability_id, branch_name, pr_url, pr_number, diff_summary, verification_status, verification_job_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(finding_id)
        .bind(vuln_id)
        .bind(branch_name)
        .bind(pr_url)
        .bind(pr_number.map(|n| n as i32))
        .bind(diff_summary)
        .bind(verification_status)
        .bind(verification_job_id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
}

async fn api_heal_verify_steps(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    let job_uuid = match uuid::Uuid::parse_str(job_id.trim()) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid job_id", "steps": []})),
            )
                .into_response();
        }
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "DB", "steps": []})),
        )
            .into_response();
    };
    let rows = sqlx::query(
        r#"SELECT step_label, detail, step_ts FROM heal_verification_steps
           WHERE tenant_id = $1 AND job_id = $2 ORDER BY step_index ASC"#,
    )
    .bind(auth.tenant_id)
    .bind(job_uuid)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let steps: Vec<crate::verification_sandbox::VerificationStep> = rows
        .into_iter()
        .filter_map(|r| {
            Some(crate::verification_sandbox::VerificationStep {
                step: r.try_get("step_label").ok()?,
                detail: r.try_get("detail").ok(),
                ts: r.try_get("step_ts").ok()?,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "steps": steps }))).into_response()
}

/// `GET /api/heal-verify/:job_id` — thin status view for a heal job: spec status + channel +
/// the resulting verdict / branch / PR (from `heal_requests`). Complements `/steps`.
async fn api_heal_verify_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    let job_uuid = match uuid::Uuid::parse_str(job_id.trim()) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid job_id"})),
            )
                .into_response();
        }
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let spec = sqlx::query(
        r#"SELECT status, COALESCE(channel,'github_pr') AS channel,
                  (result_artifact IS NOT NULL) AS has_artifact
           FROM auto_heal_job_specs WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(job_uuid)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let hr = sqlx::query(
        r#"SELECT branch_name, pr_url, pr_number, diff_summary, verification_status,
                  COALESCE(verdict,'') AS verdict, COALESCE(channel,'') AS channel
           FROM heal_requests
           WHERE tenant_id = $1 AND verification_job_id = $2
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(auth.tenant_id)
    .bind(&job_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let Some(spec) = spec else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "job not found"}))).into_response();
    };
    let mut out = json!({
        "job_id": job_id,
        "status": spec.try_get::<String,_>("status").unwrap_or_default(),
        "channel": spec.try_get::<String,_>("channel").unwrap_or_default(),
        "has_artifact": spec.try_get::<bool,_>("has_artifact").unwrap_or(false),
    });
    if let Some(r) = hr {
        out["verdict"] = json!(r.try_get::<String, _>("verdict").unwrap_or_default());
        out["verification_status"] =
            json!(r.try_get::<String, _>("verification_status").unwrap_or_default());
        out["branch_name"] = json!(r.try_get::<Option<String>, _>("branch_name").ok().flatten());
        out["pr_url"] = json!(r.try_get::<Option<String>, _>("pr_url").ok().flatten());
        out["pr_number"] = json!(r.try_get::<Option<i32>, _>("pr_number").ok().flatten());
        out["diff_summary"] = json!(r.try_get::<Option<String>, _>("diff_summary").ok().flatten());
    }
    (StatusCode::OK, Json(out)).into_response()
}

/// `GET /api/heal-verify/:job_id/patch` — download the verified artifact: the unified diff
/// (diff_download channel) as `text/x-patch`, or the virtual-patch snippet as `text/plain`.
async fn api_heal_verify_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    let job_uuid = match uuid::Uuid::parse_str(job_id.trim()) {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid job_id").into_response();
        }
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, "DB").into_response();
    };
    let row = sqlx::query(
        r#"SELECT result_artifact, COALESCE(patch_text,'') AS patch_text
           FROM auto_heal_job_specs WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(job_uuid)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let Some(row) = row else {
        return (StatusCode::NOT_FOUND, "job not found").into_response();
    };
    let artifact = row
        .try_get::<Option<Value>, _>("result_artifact")
        .ok()
        .flatten();
    let (content_type, filename, body): (&str, String, String) = match artifact {
        Some(a) if a.get("kind").and_then(Value::as_str) == Some("virtual_patch") => (
            "text/plain; charset=utf-8",
            format!("weissman-virtual-patch-{}.conf", job_id),
            a.get("snippet")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        Some(a) if a.get("unified_diff").and_then(Value::as_str).is_some() => (
            "text/x-patch; charset=utf-8",
            format!("weissman-heal-{}.patch", job_id),
            a.get("unified_diff")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        _ => (
            "text/x-patch; charset=utf-8",
            format!("weissman-heal-{}.patch", job_id),
            row.try_get::<String, _>("patch_text").unwrap_or_default(),
        ),
    };
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, content_type.to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        body,
    )
        .into_response()
}

/// EventBridge / custom forwarder: verify `X-Weissman-Signature: sha256=<hex>` with `WEISSMAN_DECEPTION_WEBHOOK_SECRET`.
async fn api_deception_aws_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    crate::deception_eventbridge::handle_aws_canary_eventbridge(
        state.app_pool.as_ref(),
        state.telemetry_broadcast_tx.as_ref(),
        &headers,
        &body,
        "aws_events_webhook",
    )
    .await
}

/// `POST /api/v1/alerts/aws-canary` — same verification and CRITICAL path as `/api/deception/aws-events`.
async fn api_v1_alerts_aws_canary(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    crate::deception_eventbridge::handle_aws_canary_eventbridge(
        state.app_pool.as_ref(),
        state.telemetry_broadcast_tx.as_ref(),
        &headers,
        &body,
        "aws_canary_alerts_v1",
    )
    .await
}

async fn api_deception_deploy_cloud(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Path(client_id): Path<i64>,
    Json(body): Json<DeceptionDeployCloudBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    if body.asset_ids.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "detail": "asset_ids required"}))).into_response();
    }
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    if !crate::security_hardening::destructive_action_authorized(&headers) {
        if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
            let _ = audit_log::insert_audit(
                &mut tx,
                auth.tenant_id,
                Some(auth.user_id),
                &actor,
                "destructive_confirm_denied",
                "deception_deploy_cloud",
                &ip,
            )
            .await;
            let _ = tx.commit().await;
        }
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "detail": "X-Weissman-Destructive-Confirm required for cloud deception deploy"})),
        )
            .into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query(
        "SELECT COALESCE(trim(aws_cross_account_role_arn),'') AS arn, COALESCE(trim(aws_external_id),'') AS ext FROM clients WHERE id = $1",
    )
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let (role_arn, _ext) = match row {
        Some(r) => (
            r.try_get::<String, _>("arn").unwrap_or_default(),
            r.try_get::<String, _>("ext").unwrap_or_default(),
        ),
        None => {
            let _ = tx.rollback().await;
            return (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response();
        }
    };
    let _ = tx.commit().await;
    if role_arn.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "client aws_cross_account_role_arn not configured"})),
        )
            .into_response();
    }

    let deployment_id = uuid::Uuid::new_v4();
    let request_val = match serde_json::to_value(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("serialize request: {}", e)})),
            )
                .into_response();
        }
    };

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let ins = sqlx::query(
        r#"INSERT INTO deception_cloud_deployments (id, tenant_id, client_id, status, request_json)
           VALUES ($1, $2, $3, 'pending', $4)"#,
    )
    .bind(deployment_id)
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(sqlx::types::Json(request_val))
    .execute(&mut *tx)
    .await;
    if ins.is_err() {
        let _ = tx.rollback().await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "failed to record deployment"})),
        )
            .into_response();
    }
    if let Ok(mut tx2) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let _ = audit_log::insert_audit(
            &mut tx2,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            "deception_deploy_cloud_queued",
            &format!("client_id={} deployment_id={}", client_id, deployment_id),
            &ip,
        )
        .await;
        let _ = tx2.commit().await;
    }
    let _ = tx.commit().await;

    let queue_payload = json!({ "deployment_id": deployment_id.to_string() });
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "deception_cloud_deploy",
        queue_payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "deployment_id": deployment_id,
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "Cloud deception deploy queued; poll status_url for result (deployment row tracks pending→deploying→active|failed)",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "deception_deploy", error = %e, "enqueue deception_cloud_deploy failed");
            if let Ok(mut tx3) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
                let _ = sqlx::query(
                    "DELETE FROM deception_cloud_deployments WHERE id = $1 AND tenant_id = $2",
                )
                .bind(deployment_id)
                .bind(auth.tenant_id)
                .execute(&mut *tx3)
                .await;
                let _ = tx3.commit().await;
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}
