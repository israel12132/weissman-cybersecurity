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
                  locked_until,
                  run_after,
                  created_at,
                  updated_at,
                  result_json->>'message' AS result_message,
                  COALESCE(result_json->'findings' @> '[{"agent_required": true}]'::jsonb, false) AS result_agent_required,
                  COALESCE(result_json->'findings' @> '[{"live_dispatched": true}]'::jsonb, false) AS result_agent_live
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

    let now = Utc::now();
    let mut facts: Vec<crate::job_operator_diagnostics::JobFacts> = Vec::with_capacity(rows.len());
    let mut out: Vec<Value> = Vec::with_capacity(rows.len());
    for r in rows {
        let (job, fact) = job_row_to_json_and_facts(&r, now);
        facts.push(fact);
        out.push(job);
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
            "diagnostics": true,
        })),
    )
        .into_response()
}

fn job_row_to_json_and_facts(
    r: &sqlx::postgres::PgRow,
    now: chrono::DateTime<Utc>,
) -> (Value, crate::job_operator_diagnostics::JobFacts) {
    use crate::job_operator_diagnostics::{expired_secs, inspect_result_signals, stale_secs, until_secs, JobFacts};
    let id_uuid: uuid::Uuid = r.try_get("id").unwrap_or_else(|_| uuid::Uuid::nil());
    let payload: Value = r.try_get("payload").unwrap_or(Value::Null);
    let target = payload
        .get("target")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let engine = payload
        .get("engine")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
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
    let heartbeat_at = r
        .try_get::<Option<chrono::DateTime<Utc>>, _>("heartbeat_at")
        .ok()
        .flatten();
    let locked_until = r
        .try_get::<Option<chrono::DateTime<Utc>>, _>("locked_until")
        .ok()
        .flatten();
    let run_after = r
        .try_get::<Option<chrono::DateTime<Utc>>, _>("run_after")
        .ok()
        .flatten();
    let created_at = r.try_get::<chrono::DateTime<Utc>, _>("created_at").ok();
    let last_error = r.try_get::<Option<String>, _>("last_error").ok().flatten();
    let worker_id = r.try_get::<Option<String>, _>("worker_id").ok().flatten();
    let result_json: Option<Value> = r.try_get::<Option<Value>, _>("result_json").ok().flatten();
    let (result_message, result_agent_required, result_agent_live) =
        inspect_result_signals(result_json.as_ref());
    let result_message = r
        .try_get::<Option<String>, _>("result_message")
        .ok()
        .flatten()
        .or(result_message);
    let result_agent_required = result_agent_required
        || r.try_get::<bool, _>("result_agent_required").unwrap_or(false);
    let result_agent_live = result_agent_live
        || r.try_get::<bool, _>("result_agent_live").unwrap_or(false);

    let job = json!({
        "id": id_uuid.to_string(),
        "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
        "status": status,
        "engine": engine,
        "target": target,
        "client_id": client_id,
        "attempt_count": r.try_get::<i32, _>("attempt_count").unwrap_or(0),
        "last_error": last_error,
        "worker_id": worker_id,
        "heartbeat_at": heartbeat_at.map(|d| d.to_rfc3339()),
        "locked_until": locked_until.map(|d| d.to_rfc3339()),
        "run_after": run_after.map(|d| d.to_rfc3339()),
        "created_at": created_at.map(|d| d.to_rfc3339()),
        "updated_at": updated_at,
        "completed_at": completed_at,
    });
    let fact = JobFacts {
        id: id_uuid,
        kind: r.try_get::<String, _>("kind").unwrap_or_default(),
        status: r.try_get::<String, _>("status").unwrap_or_default(),
        last_error: r.try_get::<Option<String>, _>("last_error").ok().flatten(),
        result_message,
        result_agent_required,
        result_agent_live_dispatched: result_agent_live,
        worker_id: r.try_get::<Option<String>, _>("worker_id").ok().flatten(),
        heartbeat_stale_secs: stale_secs(heartbeat_at, now),
        lock_expired_secs: expired_secs(locked_until, now),
        run_after_secs: until_secs(run_after, now),
        age_secs: stale_secs(created_at, now),
        engine: engine.clone(),
        heartbeat_at: heartbeat_at.map(|d| d.to_rfc3339()),
        locked_until: locked_until.map(|d| d.to_rfc3339()),
        run_after: run_after.map(|d| d.to_rfc3339()),
        ..Default::default()
    };
    (job, fact)
}

async fn enrich_job_status_json(mut body: Value, view: &db::job_queue::JobStatusView) -> Value {
    let now = Utc::now();
    let mut facts = [crate::job_operator_diagnostics::JobFacts::from_status_view(view, now)];
    crate::job_operator_diagnostics::apply_live_orchestration(&mut facts).await;
    let diag = crate::job_operator_diagnostics::classify(&facts[0]);
    crate::job_operator_diagnostics::merge_into_job(&mut body, &diag);
    if let Some(obj) = body.as_object_mut() {
        if let Some(ref lu) = facts[0].locked_until {
            obj.insert("locked_until".into(), json!(lu));
        }
        if let Some(ref ra) = facts[0].run_after {
            obj.insert("run_after".into(), json!(ra));
        }
        if let Some(ref wid) = view.worker_id {
            obj.insert("worker_id".into(), json!(wid));
        }
        obj.insert("diagnostics".into(), json!(true));
    }
    body
}

/// GET /api/jobs/:job_id/diagnostics — live lease / heartbeat / remap / stuck_reason.
async fn api_async_job_diagnostics(
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
            let body = enrich_job_status_json(json!(status), &status).await;
            return (StatusCode::OK, Json(body)).into_response();
        }
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "job diagnostics get_job_for_tenant failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "database_error", "detail": scrub_internal_error(&e)})),
            )
                .into_response();
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "job_not_found"})),
        )
            .into_response(),
    }
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
            let body = enrich_job_status_json(json!(status), &status).await;
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
            let status = r.try_get::<String, _>("status").unwrap_or_default();
            let error = r.try_get::<Option<String>, _>("error").ok().flatten();
            let message = r.try_get::<Option<String>, _>("message").ok().flatten();
            let mut body = json!({
                "source": "poe_job",
                "id": jid,
                "status": status,
                "run_id": r.try_get::<Option<i64>,_>("run_id").ok().flatten(),
                "message": message,
                "error": error,
                "findings_count": findings_count,
            });
            let facts = crate::job_operator_diagnostics::JobFacts {
                id: job_id,
                kind: "poe_job".into(),
                status: status.clone(),
                last_error: error.clone(),
                result_message: message.clone(),
                ..Default::default()
            };
            let diag = crate::job_operator_diagnostics::classify(&facts);
            crate::job_operator_diagnostics::merge_into_job(&mut body, &diag);
            (StatusCode::OK, Json(body)).into_response()
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
