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

    let out: Vec<Value> = rows
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
            let attempt_count = r.try_get::<i32, _>("attempt_count").unwrap_or(0);
            let max_attempts = r.try_get::<i32, _>("max_attempts").unwrap_or(3);
            let created_at = r
                .try_get::<chrono::DateTime<Utc>, _>("created_at")
                .ok();
            let run_after = r
                .try_get::<Option<chrono::DateTime<Utc>>, _>("run_after")
                .ok()
                .flatten();
            let last_error = r.try_get::<Option<String>, _>("last_error").ok().flatten();
            let worker_id = r.try_get::<Option<String>, _>("worker_id").ok().flatten();
            let stuck = crate::job_diagnostics::job_stuck_reason(
                &status,
                &payload,
                created_at,
                run_after,
                attempt_count,
                max_attempts,
                worker_id.as_deref(),
            );
            json!({
                "id": id_uuid.to_string(),
                "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
                "status": status,
                "engine": engine,
                "target": target,
                "client_id": client_id,
                "attempt_count": attempt_count,
                "max_attempts": max_attempts,
                "last_error": last_error,
                "stuck_reason": stuck,
                "worker_id": worker_id,
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


/// GET /api/jobs/diagnostics — why the queue is not moving. Live Redis swarm + Postgres.
async fn api_async_jobs_diagnostics(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let scoped_client = match crate::client_isolation::bind_requested_client(&auth, None) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable"})),
        )
            .into_response();
    };

    let counts = sqlx::query(
        r#"SELECT
              COUNT(*) FILTER (WHERE status = 'pending')::bigint AS pending,
              COUNT(*) FILTER (WHERE status = 'running')::bigint AS running,
              COUNT(*) FILTER (WHERE status = 'completed')::bigint AS completed,
              COUNT(*) FILTER (WHERE status IN ('failed','dead'))::bigint AS failed,
              COUNT(*) FILTER (WHERE status = 'pending' AND NOT (payload ? '_weissman_job_bus'))::bigint AS pending_no_envelope,
              COUNT(*) FILTER (WHERE status = 'pending' AND run_after IS NOT NULL AND run_after > now())::bigint AS pending_held,
              COUNT(*) FILTER (WHERE status = 'pending' AND created_at < now() - interval '60 seconds')::bigint AS pending_stale,
              MIN(created_at) FILTER (WHERE status = 'pending') AS oldest_pending
           FROM weissman_async_jobs
          WHERE tenant_id = $1
            AND (
                  $2::bigint IS NULL
                  OR payload->>'client_id' = $2::text
                  OR (jsonb_typeof(payload->'client_id') = 'number' AND (payload->>'client_id')::bigint = $2)
                )"#,
    )
    .bind(auth.tenant_id)
    .bind(scoped_client)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let (redis_ok, live_workers) = swarm_liveness_snapshot().await;

    let pending = counts
        .as_ref()
        .and_then(|r| r.try_get::<i64, _>("pending").ok())
        .unwrap_or(0);
    let pending_no_envelope = counts
        .as_ref()
        .and_then(|r| r.try_get::<i64, _>("pending_no_envelope").ok())
        .unwrap_or(0);
    let pending_stale = counts
        .as_ref()
        .and_then(|r| r.try_get::<i64, _>("pending_stale").ok())
        .unwrap_or(0);
    let oldest = counts
        .as_ref()
        .and_then(|r| r.try_get::<Option<chrono::DateTime<Utc>>, _>("oldest_pending").ok())
        .flatten()
        .map(|d| d.to_rfc3339());

    let mut blockers: Vec<Value> = Vec::new();
    if !redis_ok {
        blockers.push(json!({
            "code": "redis_down",
            "detail": "Redis is unreachable. Swarm liveness and some job-bus paths cannot run."
        }));
    }
    if live_workers == 0 {
        blockers.push(json!({
            "code": "no_live_worker",
            "detail": "No weissman-worker process is advertising liveness (weissman:swarm:worker:*). Pending jobs will sit until a worker claims them."
        }));
    }
    if pending_no_envelope > 0 {
        blockers.push(json!({
            "code": "missing_envelope",
            "detail": format!("{pending_no_envelope} pending job(s) were enqueued without a zero-trust envelope and cannot be claimed. Retention will retire them after the grace window.")
        }));
    }
    if pending_stale > 0 && live_workers == 0 {
        blockers.push(json!({
            "code": "stale_queue",
            "detail": format!("{pending_stale} pending job(s) older than 60s with no live worker.")
        }));
    }
    let bus_enabled = std::env::var("WEISSMAN_JOB_ORCHESTRATOR_SECRET")
        .ok()
        .filter(|s| s.len() >= 32)
        .is_some()
        && redis_ok;
    if !bus_enabled && pending > 0 {
        blockers.push(json!({
            "code": "job_bus_disabled",
            "detail": "WEISSMAN_JOB_ORCHESTRATOR_SECRET or Redis is not ready. The bus-path worker will not claim unsigned jobs; start weissman-worker and set the orchestrator secret (≥32 chars)."
        }));
    }

    let stuck_reason = blockers
        .first()
        .and_then(|b| b.get("code"))
        .and_then(Value::as_str)
        .map(str::to_string);

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "live": true,
            "tenant_id": auth.tenant_id,
            "client_id": scoped_client,
            "redis_ok": redis_ok,
            "redis": redis_ok,
            "job_bus_enabled": bus_enabled,
            "live_workers": live_workers,
            "workers": live_workers,
            "pending": pending,
            "running": counts.as_ref().and_then(|r| r.try_get::<i64,_>("running").ok()).unwrap_or(0),
            "completed": counts.as_ref().and_then(|r| r.try_get::<i64,_>("completed").ok()).unwrap_or(0),
            "failed": counts.as_ref().and_then(|r| r.try_get::<i64,_>("failed").ok()).unwrap_or(0),
            "pending_no_envelope": pending_no_envelope,
            "pending_held": counts.as_ref().and_then(|r| r.try_get::<i64,_>("pending_held").ok()).unwrap_or(0),
            "pending_stale": pending_stale,
            "oldest_pending": oldest,
            "blockers": blockers,
            "stuck_reason": stuck_reason,
        })),
    )
        .into_response()
}

async fn swarm_liveness_snapshot() -> (bool, usize) {
    let url = match std::env::var("REDIS_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => return (false, 0),
    };
    let Ok(client) = redis::Client::open(url.as_str()) else {
        return (false, 0);
    };
    let Ok(mut conn) = redis::aio::ConnectionManager::new(client).await else {
        return (false, 0);
    };
    let ping: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
    if !ping.map(|s| s.eq_ignore_ascii_case("PONG")).unwrap_or(false) {
        return (false, 0);
    }
    let keys: Result<Vec<String>, _> = redis::cmd("KEYS")
        .arg("weissman:swarm:worker:*")
        .query_async(&mut conn)
        .await;
    match keys {
        Ok(k) => (true, k.len()),
        Err(_) => (true, 0),
    }
}
