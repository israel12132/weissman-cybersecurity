// Supreme-layer APIs: tenant brand, ITDR connectors, Weissman Gate, agent isolate.

async fn api_tenant_brand_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::tenant_brand_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    };
    let raw: Option<String> = match sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'tenant_brand'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(target: "brand", tenant_id = auth.tenant_id, error = %e, "tenant brand query failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::tenant_brand_unavailable_json(
                    "tenant brand query failed",
                )),
            )
                .into_response();
        }
    };
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::tenant_brand_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    }
    let brand: Value = match raw {
        None => json!({}),
        Some(s) => match serde_json::from_str(&s) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(crate::http_unavailable::tenant_brand_unavailable_json(
                        "tenant brand JSON corrupt",
                    )),
                )
                    .into_response();
            }
        },
    };
    (StatusCode::OK, Json(json!({"ok": true, "brand": brand}))).into_response()
}

async fn api_tenant_brand_put(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let brand = body.get("brand").cloned().unwrap_or(body);
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::tenant_brand_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    };
    let res = sqlx::query(
        r#"INSERT INTO system_configs (tenant_id, key, value, description)
           VALUES ($1, 'tenant_brand', $2, 'Persisted white-label brand')
           ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value"#,
    )
    .bind(auth.tenant_id)
    .bind(brand.to_string())
    .execute(&mut *tx)
    .await;
    if res.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::tenant_brand_unavailable_json(
                "tenant brand persist failed",
            )),
        )
            .into_response();
    }
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::tenant_brand_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({"ok": true, "brand": brand}))).into_response()
}

async fn api_itdr_connectors_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match crate::itdr_connectors::load_connector_config(&state.app_pool, auth.tenant_id).await {
        Ok(cfg) => (StatusCode::OK, Json(json!({"ok": true, "connectors": cfg}))).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "unavailable": true,
                "connectors": {},
                "detail": scrub_internal_error(&e),
            })),
        )
            .into_response(),
    }
}

async fn api_itdr_connectors_put(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    match crate::itdr_connectors::save_connector_config(&state.app_pool, auth.tenant_id, &body).await
    {
        Ok(()) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
struct ItdrPullBody {
    #[serde(default)]
    provider: String,
    #[serde(default)]
    client_id: Option<i64>,
}

async fn api_itdr_connectors_pull(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<ItdrPullBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let cfg = match crate::itdr_connectors::load_connector_config(&state.app_pool, auth.tenant_id).await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "unavailable": true, "detail": scrub_internal_error(&e)})),
            )
                .into_response();
        }
    };
    let provider = body.provider.trim();
    let slice = cfg
        .get(provider)
        .cloned()
        .or_else(|| cfg.get("connectors").and_then(|c| c.get(provider)).cloned())
        .unwrap_or(cfg.clone());
    match crate::itdr_connectors::pull_provider(
        &state.app_pool,
        auth.tenant_id,
        body.client_id,
        provider,
        &slice,
    )
    .await
    {
        Ok(p) => (
            StatusCode::OK,
            Json(json!({"ok": true, "provider": p.provider, "ingested": p.ingested, "detail": p.detail})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

async fn api_vngfw_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let policy = match crate::vngfw_control::load_policy(&state.app_pool, auth.tenant_id).await {
        Ok(p) => p,
        Err(detail) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::vngfw_unavailable_json(detail)),
            )
                .into_response();
        }
    };
    let mut status = crate::vngfw_control::dataplane_status().await;
    if let Some(obj) = status.as_object_mut() {
        obj.insert("ok".into(), json!(true));
        obj.insert("policy".into(), policy.clone());
        obj.insert(
            "nft_preview".into(),
            json!(crate::vngfw_control::policy_to_nft(&policy)),
        );
    }
    (StatusCode::OK, Json(status)).into_response()
}

async fn api_vngfw_policy_put(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    match crate::vngfw_control::save_policy(&state.app_pool, auth.tenant_id, &body).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"ok": true, "nft_preview": crate::vngfw_control::policy_to_nft(&body)})),
        )
            .into_response(),
        Err(e) if e == "database unavailable" => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::vngfw_unavailable_json(e.as_str())),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

async fn api_vngfw_apply(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let policy = match crate::vngfw_control::load_policy(&state.app_pool, auth.tenant_id).await {
        Ok(p) => p,
        Err(detail) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::vngfw_unavailable_json(detail)),
            )
                .into_response();
        }
    };
    match crate::vngfw_control::apply_nft(&policy).await {
        Ok(detail) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "applied": true,
                "detail": detail,
                "nft_preview": crate::vngfw_control::policy_to_nft(&policy),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "applied": false,
                "detail": e,
                "nft_preview": crate::vngfw_control::policy_to_nft(&policy),
            })),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
struct IsolateBody {
    client_id: i64,
    #[serde(default)]
    target: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    path: String,
}

async fn api_agents_isolate(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<IsolateBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let action = if body.action.trim().is_empty() {
        "isolate"
    } else {
        body.action.trim()
    };
    let target = if body.target.trim().is_empty() {
        "localhost"
    } else {
        body.target.trim()
    };
    match crate::endpoint_agents::enqueue_and_dispatch_fleet(
        &state.app_pool,
        &state.endpoint_agents,
        auth.tenant_id,
        body.client_id,
        "host_isolation",
        Some(target),
        &json!({ "action": action, "path": body.path }),
    )
    .await
    {
        Ok((task, live)) => (
            StatusCode::OK,
            Json(json!({"ok": true, "task_id": task, "live_dispatched": live, "action": action})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "detail": e.to_string()})),
        )
            .into_response(),
    }
}

async fn api_itdr_auth_events_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200)
        .clamp(1, 2000);
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "unavailable": true, "events": [], "detail": "database unavailable"})),
        )
            .into_response();
    };
    let rows = match sqlx::query(
        r#"SELECT ts, username, ip, country, success, mfa_prompted
             FROM itdr_auth_events
            WHERE tenant_id = $1
            ORDER BY ts DESC
            LIMIT $2"#,
    )
    .bind(auth.tenant_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "unavailable": true,
                    "events": [],
                    "detail": scrub_internal_error(&e),
                })),
            )
                .into_response();
        }
    };
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "unavailable": true,
                "events": [],
                "detail": "database unavailable",
            })),
        )
            .into_response();
    };
    let events: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "ts": r.try_get::<i64, _>("ts").unwrap_or(0),
                "username": r.try_get::<String, _>("username").unwrap_or_default(),
                "ip": r.try_get::<String, _>("ip").unwrap_or_default(),
                "country": r.try_get::<String, _>("country").unwrap_or_default(),
                "success": r.try_get::<bool, _>("success").unwrap_or(false),
                "mfa_prompted": r.try_get::<bool, _>("mfa_prompted").unwrap_or(false),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({"ok": true, "events": events}))).into_response()
}

async fn api_cnapp_refresh(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::cnapp_refresh_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    };
    let rows = match sqlx::query("SELECT id, name, domains FROM clients ORDER BY id LIMIT 50")
        .fetch_all(&mut *tx)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::cnapp_refresh_unavailable_json(
                    scrub_internal_error(&e),
                )),
            )
                .into_response();
        }
    };
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::cnapp_refresh_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    }
    let mut queued = Vec::new();
    let mut eligible = 0usize;
    let mut items: Vec<(i64, String)> = Vec::new();
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        if id <= 0 {
            continue;
        }
        let domains_raw: String = r.try_get("domains").unwrap_or_else(|_| "[]".into());
        let domains: Vec<String> = serde_json::from_str(&domains_raw).unwrap_or_default();
        let name: String = r.try_get("name").unwrap_or_default();
        let target = domains
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or(name);
        if target.trim().is_empty() {
            continue;
        }
        eligible += 1;
        items.push((id, target));
    }
    use futures::stream::{self, StreamExt};
    let pool = state.app_pool.clone();
    let tenant_id = auth.tenant_id;
    let results: Vec<_> = stream::iter(items)
        .map(|(id, target)| {
            let pool = pool.clone();
            async move {
                let payload = json!({
                    "engine": "cnapp_continuous",
                    "target": target,
                    "client_id": id,
                    "trigger": "cnapp_refresh",
                });
                let result = crate::async_jobs::enqueue(
                    pool.as_ref(),
                    tenant_id,
                    "command_center_engine",
                    payload,
                    None,
                )
                .await;
                (id, target, result)
            }
        })
        .buffer_unordered(8)
        .collect()
        .await;
    for (id, target, result) in results {
        match result {
            Ok(job_id) => queued.push(json!({
                "client_id": id,
                "target": target,
                "job_id": job_id.to_string(),
            })),
            Err(e) => tracing::error!(error = %e, client_id = id, "cnapp_continuous enqueue failed"),
        }
    }
    if eligible > 0 && queued.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::cnapp_refresh_unavailable_json(
                "cnapp enqueue failed for every eligible client",
            )),
        )
            .into_response();
    }
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": true,
            "engine": "cnapp_continuous",
            "jobs_queued": queued.len(),
            "jobs": queued,
            "detail": if queued.is_empty() {
                "No clients with a domain/name to scan. Add a client, then retry."
            } else {
                "Queued cnapp_continuous command_center_engine jobs for tenant clients."
            }
        })),
    )
        .into_response()
}

async fn api_cnapp_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::cnapp_jobs_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    };
    let rows = match sqlx::query(
        r#"SELECT id, kind, status, payload, last_error, created_at, updated_at
             FROM weissman_async_jobs
            WHERE kind IN ('command_center_engine', 'cnapp_continuous')
              AND (
                    payload->>'engine' = 'cnapp_continuous'
                 OR payload->>'trigger' IN ('cnapp_refresh', 'cnapp_scheduler')
                 OR kind = 'cnapp_continuous'
              )
            ORDER BY updated_at DESC
            LIMIT 40"#,
    )
    .fetch_all(&mut *tx)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::cnapp_jobs_unavailable_json(
                    scrub_internal_error(&e),
                )),
            )
                .into_response();
        }
    };
    let running: i64 = match sqlx::query_scalar(
        r#"SELECT count(*)::bigint FROM weissman_async_jobs
            WHERE status = 'running'
              AND (payload->>'engine' = 'cnapp_continuous' OR kind = 'cnapp_continuous')"#,
    )
    .fetch_one(&mut *tx)
    .await
    {
        Ok(n) => n,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::cnapp_jobs_unavailable_json(
                    scrub_internal_error(&e),
                )),
            )
                .into_response();
        }
    };
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::cnapp_jobs_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    }
    let jobs: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<uuid::Uuid, _>("id").ok().map(|u| u.to_string()),
                "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
                "status": r.try_get::<String, _>("status").unwrap_or_default(),
                "payload": r.try_get::<serde_json::Value, _>("payload").unwrap_or(json!({})),
                "last_error": r.try_get::<Option<String>, _>("last_error").ok().flatten(),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok(),
                "updated_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").ok(),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "engine": "cnapp_continuous",
            "running": running,
            "jobs": jobs,
        })),
    )
        .into_response()
}

async fn api_heal_stats_tenant(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::heal_stats_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    };
    let agg = match sqlx::query(
        r#"SELECT
             count(*)::bigint AS total,
             count(*) FILTER (WHERE verdict = 'fixed')::bigint AS fixed,
             count(*) FILTER (WHERE verdict = 'broke_app')::bigint AS broke_app,
             count(*) FILTER (WHERE verdict = 'still_vulnerable')::bigint AS still_vulnerable,
             count(*) FILTER (WHERE verification_status LIKE 'verified_%')::bigint AS delivered,
             count(*) FILTER (WHERE verification_receipt IS NOT NULL AND verification_receipt <> '')::bigint AS attested
           FROM heal_requests"#,
    )
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::heal_stats_unavailable_json(
                    scrub_internal_error(&e),
                )),
            )
                .into_response();
        }
    };
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::heal_stats_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    }
    let Some(agg) = agg else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::heal_stats_unavailable_json(
                "heal stats aggregate missing",
            )),
        )
            .into_response();
    };
    let total = agg.try_get::<i64, _>("total").unwrap_or(0);
    let fixed = agg.try_get::<i64, _>("fixed").unwrap_or(0);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "scope": "tenant",
            "total": total,
            "fixed": fixed,
            "broke_app": agg.try_get::<i64, _>("broke_app").unwrap_or(0),
            "still_vulnerable": agg.try_get::<i64, _>("still_vulnerable").unwrap_or(0),
            "delivered": agg.try_get::<i64, _>("delivered").unwrap_or(0),
            "attested": agg.try_get::<i64, _>("attested").unwrap_or(0),
            "success_rate": if total > 0 { (fixed as f64 / total as f64 * 1000.0).round() / 1000.0 } else { 0.0 },
        })),
    )
        .into_response()
}

async fn api_soar_index(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::soar_executions_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    };
    let rows = match sqlx::query(
        r#"SELECT id, action_kind, status, target_id, provider, created_at
             FROM soar_action_executions
            ORDER BY created_at DESC
            LIMIT 50"#,
    )
    .fetch_all(&mut *tx)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::soar_executions_unavailable_json(
                    scrub_internal_error(&e),
                )),
            )
                .into_response();
        }
    };
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::soar_executions_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    }
    let executions: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<uuid::Uuid, _>("id").ok().map(|u| u.to_string()),
                "action_kind": r.try_get::<String, _>("action_kind").ok(),
                "status": r.try_get::<String, _>("status").ok(),
                "target_id": r.try_get::<String, _>("target_id").ok(),
                "provider": r.try_get::<String, _>("provider").ok(),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok(),
                "url": r.try_get::<uuid::Uuid, _>("id").ok().map(|u| format!("/api/soar/executions/{u}")),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "playbooks_url": "/api/playbooks",
            "executions": executions,
        })),
    )
        .into_response()
}

async fn api_agents_isolate_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::isolate_agents_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    };
    let rows = match sqlx::query(
        r#"SELECT agent_uuid::text AS agent_uuid, client_id, hostname, status, last_seen_at
             FROM endpoint_agents
            ORDER BY last_seen_at DESC NULLS LAST
            LIMIT 200"#,
    )
    .fetch_all(&mut *tx)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::isolate_agents_unavailable_json(
                    scrub_internal_error(&e),
                )),
            )
                .into_response();
        }
    };
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::isolate_agents_unavailable_json(
                "database unavailable",
            )),
        )
            .into_response();
    }
    let agents: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "agent_id": r.try_get::<String, _>("agent_uuid").unwrap_or_default(),
                "client_id": r.try_get::<Option<i64>, _>("client_id").ok().flatten(),
                "hostname": r.try_get::<String, _>("hostname").unwrap_or_default(),
                "status": r.try_get::<String, _>("status").unwrap_or_default(),
                "last_seen_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_seen_at").ok().flatten(),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "agents": agents,
            "apply": "POST /api/agents/isolate with {client_id, target, action}",
        })),
    )
        .into_response()
}
