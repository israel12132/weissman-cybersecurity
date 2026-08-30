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

    let rows = match sqlx::query(
        r#"SELECT id, kind, status,
                  COALESCE(payload, '{}'::jsonb) AS payload,
                  result_json,
                  last_error,
                  attempt_count,
                  worker_id,
                  heartbeat_at,
                  locked_until,
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
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "jobs list query failed");
            let _ = tx.rollback().await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "detail": "Database query failed",
                    "jobs": [],
                })),
            )
                .into_response();
        }
    };

    let total: i64 = match sqlx::query_scalar::<_, i64>(
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
    {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "jobs count query failed");
            let _ = tx.rollback().await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "detail": "Database query failed",
                    "jobs": [],
                })),
            )
                .into_response();
        }
    };
    if let Err(e) = tx.commit().await {
        tracing::error!(target: "async_jobs", error = %e, "jobs list commit failed");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable", "jobs": []})),
        )
            .into_response();
    }

    let mut out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let id_uuid: uuid::Uuid = r.try_get("id").unwrap_or_else(|_| uuid::Uuid::nil());
            let payload: Value = r.try_get("payload").unwrap_or(Value::Null);
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
                "locked_until": r.try_get::<chrono::DateTime<Utc>, _>("locked_until").ok().map(|d| d.to_rfc3339()),
                "created_at": r.try_get::<chrono::DateTime<Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
                "updated_at": updated_at,
                "completed_at": completed_at,
            })
        })
        .collect();

    let ids: Vec<uuid::Uuid> = out
        .iter()
        .filter_map(crate::job_lease_view::parse_job_uuid)
        .collect();
    let (lease_backend, leases) = crate::job_lease_view::inspect_leases(&ids).await;
    let now = Utc::now();
    for job in &mut out {
        let id = crate::job_lease_view::parse_job_uuid(job);
        let lease = id.and_then(|i| leases.get(&i));
        crate::job_lease_view::attach_diagnostics(job, now, &lease_backend, lease);
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "jobs": out,
            "total": total,
            "limit": limit,
            "offset": offset,
            "lease_backend": lease_backend.to_json(),
        })),
    )
        .into_response()
}

/// Unified async job + PoE job status (tenant-scoped).
async fn api_async_job_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<uuid::Uuid>,
) -> Response {
    match db::job_queue::get_job_for_tenant(state.app_pool.as_ref(), auth.tenant_id, job_id).await {
        Ok(Some(mut status)) => {
            status.payload = crate::scan_payload_redaction::redact_for_api(&status.payload);
            if !crate::client_isolation::payload_visible_to(&auth, &status.payload) {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"ok": false, "detail": "Not found", "error_code": "not_found"})),
                )
                    .into_response();
            }
            let mut body = serde_json::to_value(&status).unwrap_or_else(|_| json!(status));
            let (lease_backend, leases) = crate::job_lease_view::inspect_leases(&[job_id]).await;
            crate::job_lease_view::attach_diagnostics(
                &mut body,
                Utc::now(),
                &lease_backend,
                leases.get(&job_id),
            );
            if let Some(obj) = body.as_object_mut() {
                obj.insert("ok".into(), json!(true));
                obj.insert("lease_backend".into(), lease_backend.to_json());
            }
            return (StatusCode::OK, Json(body)).into_response();
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
