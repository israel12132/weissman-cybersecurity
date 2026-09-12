/// GET /api/jobs?limit=&offset=&status= — tenant-scoped list for the Jobs dashboard.
async fn api_async_jobs_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 500);
    let offset: i64 = q
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    let status_filter: Option<String> = q
        .get("status")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let scoped_client = match crate::client_isolation::bind_requested_client(&auth, None) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable", "jobs": []})),
        )
            .into_response();
    };

    let rows = sqlx::query(
        r#"SELECT id, kind, status,
                  COALESCE(payload, '{}'::jsonb) AS payload,
                  result_json,
                  last_error,
                  attempt_count,
                  worker_id,
                  heartbeat_at,
                  created_at,
                  updated_at
             FROM weissman_async_jobs
            WHERE tenant_id = $4
              AND ($3::text IS NULL OR status = $3)
              AND (
                    $5::bigint IS NULL
                    OR payload->>'client_id' = $5::text
                    OR (jsonb_typeof(payload->'client_id') = 'number' AND (payload->>'client_id')::bigint = $5)
                  )
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .bind(status_filter.as_deref())
    .bind(auth.tenant_id)
    .bind(scoped_client)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let total: i64 = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*)::bigint FROM weissman_async_jobs
            WHERE tenant_id = $2 AND ($1::text IS NULL OR status = $1)
              AND (
                    $3::bigint IS NULL
                    OR payload->>'client_id' = $3::text
                    OR (jsonb_typeof(payload->'client_id') = 'number' AND (payload->>'client_id')::bigint = $3)
                  )"#,
    )
    .bind(status_filter.as_deref())
    .bind(auth.tenant_id)
    .bind(scoped_client)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let _ = tx.commit().await;

    let tenant_id = auth.tenant_id;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let id_uuid: uuid::Uuid = r.try_get("id").unwrap_or_else(|_| uuid::Uuid::nil());
            let stored: Value = r.try_get("payload").unwrap_or(Value::Null);
            let payload = crate::job_envelope::reveal_job_payload_for_tenant(&stored, tenant_id);
            let target = payload.get("target").and_then(Value::as_str).map(|s| s.to_string());
            let engine = payload.get("engine").and_then(Value::as_str).map(|s| s.to_string());
            let client_id = payload.get("client_id").and_then(Value::as_i64);
            let status = r.try_get::<String, _>("status").unwrap_or_default();
            let updated_at = r
                .try_get::<chrono::DateTime<Utc>, _>("updated_at")
                .ok()
                .map(|d| d.to_rfc3339());
            let completed_at = if status == "completed" {
                updated_at.clone()
            } else {
                None
            };
            json!({
                "id": id_uuid.to_string(),
                "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
                "status": status,
                "engine": engine,
                "target": target,
                "client_id": client_id,
                "attempt_count": r.try_get::<i32, _>("attempt_count").unwrap_or(0),
                "last_error": r.try_get::<Option<String>, _>("last_error").ok().flatten(),
                "worker_id": r.try_get::<Option<String>, _>("worker_id").ok().flatten(),
                "heartbeat_at": r.try_get::<chrono::DateTime<Utc>, _>("heartbeat_at").ok().map(|d| d.to_rfc3339()),
                "created_at": r.try_get::<chrono::DateTime<Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
                "updated_at": updated_at,
                "completed_at": completed_at,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "jobs": out,
            "total": total,
            "limit": limit,
            "offset": offset,
        })),
    )
        .into_response()
}

/// GET /api/scan-finding-spine — live join of scan jobs + finding evidence.
async fn api_scan_finding_spine(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let client_filter: Option<i64> = q
        .get("client_id")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|id| *id > 0);
    let client_filter = match crate::client_isolation::bind_requested_client(&auth, client_filter) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let Ok(mut tx) = db::begin_tenant_tx(state.read_pool(), auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable"})),
        )
            .into_response();
    };

    let kpis_row = sqlx::query(
        r#"SELECT
              COUNT(*)::bigint AS findings_total,
              COUNT(*) FILTER (WHERE COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED'))::bigint AS open_findings,
              COUNT(*) FILTER (WHERE lower(severity) IN ('critical', 'high'))::bigint AS high_critical,
              COUNT(*) FILTER (WHERE COALESCE(poc_sealed, false))::bigint AS evidence,
              COUNT(*) FILTER (WHERE COALESCE(raw_data->'live_verification'->>'verdict', '') IN ('CONFIRMED', 'LIKELY_VALID'))::bigint AS proven,
              COUNT(*) FILTER (WHERE raw_data ? 'live_verification')::bigint AS verified,
              COUNT(*) FILTER (
                WHERE lower(severity) IN ('critical', 'high')
                  AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
                  AND NOT (raw_data ? 'live_verification')
              )::bigint AS unverified_critical,
              COUNT(*) FILTER (
                WHERE COALESCE(raw_data->>'mitre_attack', '') <> ''
              )::bigint AS mitre,
              COUNT(*) FILTER (
                WHERE COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
                  AND NOT COALESCE(poc_sealed, false)
              )::bigint AS open_without_evidence
           FROM vulnerabilities
          WHERE ($1::bigint IS NULL OR client_id = $1)"#,
    )
    .bind(client_filter)
    .fetch_optional(&mut *tx)
    .await;

    let kpis = match kpis_row {
        Ok(Some(r)) => crate::scan_finding_spine::SpineKpis {
            findings_total: r.try_get("findings_total").unwrap_or(0),
            open_findings: r.try_get("open_findings").unwrap_or(0),
            high_critical: r.try_get("high_critical").unwrap_or(0),
            evidence: r.try_get("evidence").unwrap_or(0),
            proven: r.try_get("proven").unwrap_or(0),
            verified: r.try_get("verified").unwrap_or(0),
            unverified_critical: r.try_get("unverified_critical").unwrap_or(0),
            mitre: r.try_get("mitre").unwrap_or(0),
            open_without_evidence: r.try_get("open_without_evidence").unwrap_or(0),
        },
        Ok(None) => crate::scan_finding_spine::SpineKpis::default(),
        Err(e) => {
            tracing::error!(target: "scan_finding_spine", tenant_id = auth.tenant_id, error = %e, "kpi query failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "findings query failed"})),
            )
                .into_response();
        }
    };

    let engine_rows = sqlx::query(
        r#"SELECT
              COALESCE(NULLIF(trim(source), ''), 'unknown') AS source,
              COUNT(*)::bigint AS findings,
              COUNT(*) FILTER (WHERE COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED'))::bigint AS open_findings,
              COUNT(*) FILTER (WHERE lower(severity) IN ('critical', 'high'))::bigint AS high_critical,
              COUNT(*) FILTER (WHERE COALESCE(poc_sealed, false))::bigint AS evidence,
              COUNT(*) FILTER (WHERE COALESCE(raw_data->'live_verification'->>'verdict', '') IN ('CONFIRMED', 'LIKELY_VALID'))::bigint AS proven,
              COUNT(*) FILTER (WHERE raw_data ? 'live_verification')::bigint AS verified,
              COUNT(*) FILTER (
                WHERE lower(severity) IN ('critical', 'high')
                  AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
                  AND NOT (raw_data ? 'live_verification')
              )::bigint AS unverified_critical,
              COUNT(*) FILTER (WHERE COALESCE(raw_data->>'mitre_attack', '') <> '')::bigint AS mitre
           FROM vulnerabilities
          WHERE ($1::bigint IS NULL OR client_id = $1)
          GROUP BY 1
          ORDER BY high_critical DESC, findings DESC
          LIMIT 200"#,
    )
    .bind(client_filter)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let engines: Vec<crate::scan_finding_spine::EngineRollup> = engine_rows
        .into_iter()
        .map(|r| {
            let source: String = r.try_get("source").unwrap_or_else(|_| "unknown".into());
            let reality_kind = crate::engine_capabilities::classify(&source).to_string();
            crate::scan_finding_spine::EngineRollup {
                source,
                findings: r.try_get("findings").unwrap_or(0),
                open_findings: r.try_get("open_findings").unwrap_or(0),
                high_critical: r.try_get("high_critical").unwrap_or(0),
                evidence: r.try_get("evidence").unwrap_or(0),
                proven: r.try_get("proven").unwrap_or(0),
                verified: r.try_get("verified").unwrap_or(0),
                unverified_critical: r.try_get("unverified_critical").unwrap_or(0),
                mitre: r.try_get("mitre").unwrap_or(0),
                reality_kind,
            }
        })
        .collect();

    let Ok(mut jobs_tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable"})),
        )
            .into_response();
    };

    let kinds: Vec<String> = crate::scan_finding_spine::SCAN_KINDS
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let job_rows = sqlx::query(
        r#"SELECT id, kind, status, last_error, attempt_count,
                  COALESCE(payload, '{}'::jsonb) AS payload,
                  heartbeat_at, created_at, updated_at
             FROM weissman_async_jobs
            WHERE tenant_id = $1
              AND kind = ANY($2)
              AND (
                    $3::bigint IS NULL
                    OR payload->>'client_id' = $3::text
                    OR (jsonb_typeof(payload->'client_id') = 'number' AND (payload->>'client_id')::bigint = $3)
                  )
            ORDER BY created_at DESC
            LIMIT 40"#,
    )
    .bind(auth.tenant_id)
    .bind(&kinds)
    .bind(client_filter)
    .fetch_all(&mut *jobs_tx)
    .await
    .unwrap_or_default();
    let _ = jobs_tx.commit().await;

    let tenant_id = auth.tenant_id;
    let scans: Vec<crate::scan_finding_spine::ScanJobView> = job_rows
        .into_iter()
        .map(|r| {
            let id_uuid: uuid::Uuid = r.try_get("id").unwrap_or_else(|_| uuid::Uuid::nil());
            let stored: Value = r.try_get("payload").unwrap_or(Value::Null);
            let payload = crate::job_envelope::reveal_job_payload_for_tenant(&stored, tenant_id);
            crate::scan_finding_spine::ScanJobView {
                id: id_uuid.to_string(),
                kind: r.try_get("kind").unwrap_or_default(),
                status: r.try_get("status").unwrap_or_default(),
                last_error: r.try_get::<Option<String>, _>("last_error").ok().flatten(),
                attempt_count: r.try_get("attempt_count").unwrap_or(0),
                created_at: r.try_get::<DateTime<Utc>, _>("created_at").ok(),
                updated_at: r.try_get::<DateTime<Utc>, _>("updated_at").ok(),
                heartbeat_at: r.try_get::<DateTime<Utc>, _>("heartbeat_at").ok(),
                engine: payload
                    .get("engine")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                target: payload
                    .get("target")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }
        })
        .collect();

    let body = crate::scan_finding_spine::build_spine_payload(kpis, engines, scans, Utc::now());
    (StatusCode::OK, Json(body)).into_response()
}

/// Unified async job + PoE job status (tenant-scoped).
async fn api_async_job_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<uuid::Uuid>,
) -> Response {
    match db::job_queue::get_job_for_tenant(state.app_pool.as_ref(), auth.tenant_id, job_id).await {
        Ok(Some(mut status)) => {
            status.payload = crate::scan_payload_redaction::redact_for_api(
                &crate::job_envelope::reveal_job_payload_for_tenant(
                    &status.payload,
                    auth.tenant_id,
                ),
            );
            if !crate::client_isolation::payload_visible_to(&auth, &status.payload) {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"ok": false, "detail": "Not found", "error_code": "not_found"})),
                )
                    .into_response();
            }
            return (StatusCode::OK, Json(json!(status))).into_response();
        }
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "get_job_for_tenant failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database_error", "detail": scrub_internal_error(&e)})),
            )
                .into_response();
        }
        Ok(None) => {}
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "database_unavailable"})),
        )
            .into_response();
    };
    let jid = job_id.to_string();
    let row = sqlx::query(
        r#"SELECT job_id, status, run_id, message, error, COALESCE(findings_json,'[]') AS findings_json
           FROM poe_jobs WHERE job_id = $1"#,
    )
    .bind(&jid)
    .fetch_optional(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match row {
        Ok(Some(r)) => {
            let findings_json: String = r.try_get("findings_json").unwrap_or_else(|_| "[]".into());
            let findings_count = serde_json::from_str::<Vec<Value>>(&findings_json)
                .map(|v| v.len())
                .unwrap_or(0);
            (
                StatusCode::OK,
                Json(json!({
                    "source": "poe_job",
                    "id": jid,
                    "status": r.try_get::<String,_>("status").unwrap_or_default(),
                    "run_id": r.try_get::<Option<i64>,_>("run_id").ok().flatten(),
                    "message": r.try_get::<Option<String>,_>("message").ok().flatten(),
                    "error": r.try_get::<Option<String>,_>("error").ok().flatten(),
                    "findings_count": findings_count,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "job_not_found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "poe_jobs lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database_error", "detail": scrub_internal_error(&e)})),
            )
                .into_response()
        }
    }
}

/// GET /api/jobs/:job_id/diagnostics — live lease / heartbeat / stuck_reason.
async fn api_async_job_diagnostics(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<uuid::Uuid>,
) -> Response {
    match db::job_queue::get_job_for_tenant(state.app_pool.as_ref(), auth.tenant_id, job_id).await {
        Ok(Some(status)) => {
            if !crate::client_isolation::payload_visible_to(&auth, &status.payload) {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"ok": false, "detail": "Not found", "error_code": "not_found"})),
                )
                    .into_response();
            }
            let now = chrono::Utc::now();
            let mut facts =
                vec![crate::job_operator_diagnostics::JobFacts::from_status_view(&status, now)];
            crate::job_operator_diagnostics::apply_live_orchestration(&mut facts).await;
            let diag = crate::job_operator_diagnostics::classify(&facts[0]);
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "job_id": job_id,
                    "status": status.status,
                    "diagnostics": diag,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "job_not_found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "job diagnostics failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database_error", "detail": scrub_internal_error(&e)})),
            )
                .into_response()
        }
    }
}
