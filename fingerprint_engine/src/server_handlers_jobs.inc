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
                  max_attempts,
                  worker_id,
                  heartbeat_at,
                  locked_until,
                  run_after,
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
    let now = Utc::now();
    let mut facts: Vec<crate::job_operator_diagnostics::JobFacts> = Vec::with_capacity(rows.len());
    let mut out: Vec<Value> = Vec::with_capacity(rows.len());
    for r in rows {
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
        let heartbeat_at = r.try_get::<chrono::DateTime<Utc>, _>("heartbeat_at").ok();
        let locked_until = r.try_get::<chrono::DateTime<Utc>, _>("locked_until").ok();
        let run_after = r.try_get::<chrono::DateTime<Utc>, _>("run_after").ok();
        let created_at = r.try_get::<chrono::DateTime<Utc>, _>("created_at").ok();
        let result_json: Option<Value> = r
            .try_get::<Option<sqlx::types::Json<Value>>, _>("result_json")
            .ok()
            .flatten()
            .map(|j| j.0);
        let (result_message, result_agent_required, result_agent_live_dispatched, result_roe_blocked) =
            crate::job_operator_diagnostics::inspect_result_signals(result_json.as_ref());
        let attempt_count = r.try_get::<i32, _>("attempt_count").unwrap_or(0);
        let max_attempts = r.try_get::<i32, _>("max_attempts").unwrap_or(3);
        let worker_id_opt = r.try_get::<Option<String>, _>("worker_id").ok().flatten();
        let contract_stuck = crate::job_diagnostics::job_stuck_reason(
            &status,
            &payload,
            created_at,
            run_after,
            attempt_count,
            max_attempts,
            worker_id_opt.as_deref(),
        );
        facts.push(crate::job_operator_diagnostics::JobFacts {
            id: id_uuid,
            kind: r.try_get::<String, _>("kind").unwrap_or_default(),
            status: status.clone(),
            last_error: r.try_get::<Option<String>, _>("last_error").ok().flatten(),
            result_message,
            result_agent_required,
            result_agent_live_dispatched,
            result_roe_blocked,
            worker_id: worker_id_opt.clone(),
            heartbeat_stale_secs: crate::job_operator_diagnostics::stale_secs(heartbeat_at, now),
            lock_expired_secs: crate::job_operator_diagnostics::expired_secs(locked_until, now),
            run_after_secs: crate::job_operator_diagnostics::until_secs(run_after, now),
            age_secs: crate::job_operator_diagnostics::stale_secs(created_at, now),
            engine: engine.clone(),
            heartbeat_at: heartbeat_at.map(|d| d.to_rfc3339()),
            locked_until: locked_until.map(|d| d.to_rfc3339()),
            run_after: run_after.map(|d| d.to_rfc3339()),
            ..Default::default()
        });
        out.push(json!({
            "id": id_uuid.to_string(),
            "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
            "status": status,
            "engine": engine,
            "target": target,
            "client_id": client_id,
            "attempt_count": attempt_count,
            "last_error": r.try_get::<Option<String>, _>("last_error").ok().flatten(),
            "worker_id": worker_id_opt,
            "heartbeat_at": heartbeat_at.map(|d| d.to_rfc3339()),
            "created_at": created_at.map(|d| d.to_rfc3339()),
            "updated_at": updated_at,
            "completed_at": completed_at,
            "stuck_reason": contract_stuck,
        }));
    }
    crate::job_operator_diagnostics::apply_live_orchestration(&mut facts).await;
    for (job, fact) in out.iter_mut().zip(facts.iter()) {
        let diag = crate::job_operator_diagnostics::classify(fact);
        crate::job_operator_diagnostics::merge_into_job(job, &diag);
    }

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

/// GET /api/jobs/diagnostics — live Redis / worker census / unsigned pending / stuck reasons.
async fn api_jobs_diagnostics(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let scoped_client = match crate::client_isolation::bind_requested_client(&auth, None) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let census = weissman_job_bus::inspect_swarm_census().await;
    let redis = json!({
        "configured": census.redis_configured,
        "inspect_ok": census.inspect_ok,
    });
    let alive: Vec<&weissman_job_bus::WorkerLivenessView> =
        census.workers.iter().filter(|w| w.present).collect();
    let workers = json!({
        "alive": alive.len(),
        "inspected": census.workers.len(),
        "ids": alive.iter().map(|w| &w.worker_id).collect::<Vec<_>>(),
    });

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "detail": "Database unavailable",
                "redis": redis,
                "workers": workers,
                "pending_no_envelope": 0,
                "stuck_reason": [],
            })),
        )
            .into_response();
    };

    let pending_no_envelope: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM weissman_async_jobs
            WHERE tenant_id = $1
              AND status IN ('pending', 'queued')
              AND NOT (payload ? '_weissman_job_bus')
              AND (
                    $2::bigint IS NULL
                    OR payload->>'client_id' = $2::text
                    OR (jsonb_typeof(payload->'client_id') = 'number' AND (payload->>'client_id')::bigint = $2)
                  )"#,
    )
    .bind(auth.tenant_id)
    .bind(scoped_client)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let rows = sqlx::query(
        r#"SELECT id, status,
                  COALESCE(payload, '{}'::jsonb) AS payload,
                  attempt_count,
                  max_attempts,
                  worker_id,
                  created_at,
                  run_after
             FROM weissman_async_jobs
            WHERE tenant_id = $1
              AND status IN ('pending', 'queued', 'running')
              AND (
                    $2::bigint IS NULL
                    OR payload->>'client_id' = $2::text
                    OR (jsonb_typeof(payload->'client_id') = 'number' AND (payload->>'client_id')::bigint = $2)
                  )
            ORDER BY created_at DESC
            LIMIT 200"#,
    )
    .bind(auth.tenant_id)
    .bind(scoped_client)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut stuck_reason: Vec<Value> = Vec::new();
    for r in rows {
        let stored: Value = r.try_get("payload").unwrap_or(Value::Null);
        let payload = crate::job_envelope::reveal_job_payload_for_tenant(&stored, auth.tenant_id);
        let status = r.try_get::<String, _>("status").unwrap_or_default();
        let created_at = r.try_get::<chrono::DateTime<Utc>, _>("created_at").ok();
        let run_after = r.try_get::<chrono::DateTime<Utc>, _>("run_after").ok();
        let attempt_count = r.try_get::<i32, _>("attempt_count").unwrap_or(0);
        let max_attempts = r.try_get::<i32, _>("max_attempts").unwrap_or(3);
        let worker_id = r.try_get::<Option<String>, _>("worker_id").ok().flatten();
        if let Some(reason) = crate::job_diagnostics::job_stuck_reason(
            &status,
            &payload,
            created_at,
            run_after,
            attempt_count,
            max_attempts,
            worker_id.as_deref(),
        ) {
            let id: uuid::Uuid = r.try_get("id").unwrap_or_else(|_| uuid::Uuid::nil());
            stuck_reason.push(json!({
                "id": id.to_string(),
                "status": status,
                "stuck_reason": reason,
            }));
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "redis": redis,
            "workers": workers,
            "pending_no_envelope": pending_no_envelope,
            "stuck_reason": stuck_reason,
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
            let now = Utc::now();
            let mut facts = [crate::job_operator_diagnostics::JobFacts::from_status_view(&status, now)];
            crate::job_operator_diagnostics::apply_live_orchestration(&mut facts).await;
            let diag = crate::job_operator_diagnostics::classify(&facts[0]);
            let mut body = serde_json::to_value(&status).unwrap_or_else(|_| json!({}));
            crate::job_operator_diagnostics::merge_into_job(&mut body, &diag);
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
