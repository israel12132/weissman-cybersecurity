#[derive(Deserialize, Default)]
struct CloudIntegrationPatch {
    aws_cross_account_role_arn: Option<String>,
    aws_external_id: Option<String>,
    gcp_project_id: Option<String>,
}

#[derive(Deserialize)]
struct CompliancePostureQuery {
    client_id: Option<i64>,
}

#[derive(Deserialize)]
struct ExecutiveReportQuery {
    client_id: Option<i64>,
}

async fn api_client_cloud_integration_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<CloudIntegrationPatch>,
) -> Response {
    let arn = body.aws_cross_account_role_arn.as_deref().unwrap_or("").trim();
    if !arn.is_empty() {
        if let Err(msg) = crate::cloud_integration_engine::validate_cross_account_role_arn(arn) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": msg})),
            )
                .into_response();
        }
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let ext = body.aws_external_id.clone().unwrap_or_default();
    let gcp = body.gcp_project_id.clone().unwrap_or_default();
    let n = sqlx::query(
        "UPDATE clients SET aws_cross_account_role_arn = $1, aws_external_id = $2, gcp_project_id = $3, updated_at = now() WHERE id = $4",
    )
    .bind(arn)
    .bind(ext.trim())
    .bind(gcp.trim())
    .bind(id)
    .execute(&mut *tx)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);
    if n == 0 {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    }
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "cloud_integration_updated",
        &format!("client_id={} role_configured={}", id, !arn.is_empty()),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

async fn api_client_cloud_scan_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query(
        "SELECT COALESCE(trim(aws_cross_account_role_arn),'') AS role_arn, COALESCE(trim(aws_external_id),'') AS ext FROM clients WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let Some(_r) = row else {
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    };
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "cloud_scan_run",
        json!({ "client_id": id }),
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
                "message": "cloud scan queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue cloud_scan_run failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_compliance_posture(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CompliancePostureQuery>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"frameworks": []}))).into_response();
    };
    let mappings = match crate::compliance_engine::load_mappings(&mut *tx).await {
        Ok(m) => m,
        Err(_) => {
            let _ = tx.rollback().await;
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"frameworks": []}))).into_response();
        }
    };
    let cloud_rows = if let Some(cid) = q.client_id {
        sqlx::query("SELECT rule_id FROM cloud_scan_findings WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query("SELECT rule_id FROM cloud_scan_findings")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    };
    let cloud_rules: Vec<String> = cloud_rows
        .into_iter()
        .filter_map(|r| r.try_get::<String, _>("rule_id").ok())
        .collect();

    let vuln_rows = if let Some(cid) = q.client_id {
        sqlx::query("SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query("SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    };
    let vulns: Vec<(String, String, String)> = vuln_rows
        .into_iter()
        .filter_map(|r| {
            Some((
                r.try_get::<String, _>("source").ok()?,
                r.try_get::<String, _>("title").ok()?,
                r.try_get::<String, _>("severity").ok()?,
            ))
        })
        .collect();
    let _ = tx.commit().await;

    let frameworks = crate::compliance_engine::compute_posture(&mappings, &cloud_rules, &vulns);
    let body = crate::compliance_engine::CompliancePostureResponse {
        frameworks,
        violations_preview: vec![],
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn api_reports_executive(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<ExecutiveReportQuery>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB unavailable"}))).into_response();
    };
    let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(auth.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "Tenant".to_string());

    let client_name: Option<String> = if let Some(cid) = q.client_id {
        sqlx::query_scalar("SELECT name FROM clients WHERE id = $1")
            .bind(cid)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let sev_rows = if let Some(cid) = q.client_id {
        sqlx::query("SELECT COALESCE(severity,'') AS severity FROM vulnerabilities WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query("SELECT COALESCE(severity,'') AS severity FROM vulnerabilities")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    };
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;
    for r in sev_rows {
        if let Ok(s) = r.try_get::<String, _>("severity") {
            let l = s.to_lowercase();
            if l.contains("critical") {
                critical += 1;
            } else if l.contains("high") {
                high += 1;
            } else if l.contains("medium") || l.contains("med") {
                medium += 1;
            } else {
                low += 1;
            }
        }
    }

    let cloud_n: i64 = if let Some(cid) = q.client_id {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM cloud_scan_findings WHERE client_id = $1")
            .bind(cid)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0)
    } else {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM cloud_scan_findings")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0)
    };

    let mappings = match crate::compliance_engine::load_mappings(&mut *tx).await {
        Ok(m) => m,
        Err(_) => {
            let _ = tx.rollback().await;
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "compliance catalog"}))).into_response();
        }
    };
    let cloud_rules: Vec<String> = if let Some(cid) = q.client_id {
        sqlx::query_scalar::<_, String>("SELECT rule_id FROM cloud_scan_findings WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query_scalar::<_, String>("SELECT rule_id FROM cloud_scan_findings")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    };
    let vuln_tuples: Vec<(String, String, String)> = if let Some(cid) = q.client_id {
        let rows = sqlx::query("SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default();
        rows.into_iter()
            .filter_map(|r| {
                Some((
                    r.try_get::<String, _>("source").ok()?,
                    r.try_get::<String, _>("title").ok()?,
                    r.try_get::<String, _>("severity").ok()?,
                ))
            })
            .collect()
    } else {
        let rows = sqlx::query("SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default();
        rows.into_iter()
            .filter_map(|r| {
                Some((
                    r.try_get::<String, _>("source").ok()?,
                    r.try_get::<String, _>("title").ok()?,
                    r.try_get::<String, _>("severity").ok()?,
                ))
            })
            .collect()
    };
    let _ = tx.commit().await;

    let posture = crate::compliance_engine::compute_posture(&mappings, &cloud_rules, &vuln_tuples);
    let soc2 = posture.iter().find(|p| p.framework == "SOC2").map(|p| p.compliance_percent).unwrap_or(100);
    let iso = posture
        .iter()
        .find(|p| p.framework == "ISO27001")
        .map(|p| p.compliance_percent)
        .unwrap_or(100);
    let gdpr = posture
        .iter()
        .find(|p| p.framework == "GDPR")
        .map(|p| p.compliance_percent)
        .unwrap_or(100);

    let params = crate::executive_pdf::ExecutiveBoardParams {
        org_label: tenant_name.clone(),
        client_label: client_name.clone(),
        critical,
        high,
        medium,
        low,
        cloud_finding_count: cloud_n.max(0) as usize,
        soc2_pct: soc2,
        iso_pct: iso,
        gdpr_pct: gdpr,
    };
    let pdf = match crate::executive_pdf::render_executive_board_pdf(&params) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "PDF failed", "detail": e})),
            )
                .into_response();
        }
    };
    let scope = client_name.as_deref().unwrap_or("tenant");
    let safe_scope: String = scope
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    let filename = format!("Weissman_Board_Report_{}.pdf", safe_scope);
    let mut res = Response::new(Body::from(pdf));
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/pdf"));
    res.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::try_from(format!("attachment; filename=\"{}\"", filename)).unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    res.headers_mut().insert(
        axum::http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    res
}
