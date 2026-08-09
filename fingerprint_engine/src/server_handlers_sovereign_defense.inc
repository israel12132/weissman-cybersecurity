// REST handlers for Sovereign Defense Matrix unified dashboard.

#[derive(Deserialize)]
struct SovereignConfigBody {
    rotation_step_secs: Option<i32>,
    port_pool_min: Option<i32>,
    port_pool_max: Option<i32>,
    #[allow(dead_code)] // accepted in JSON body; not yet consumed
    active: Option<bool>,
}

async fn api_sovereign_defense_dashboard(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    match crate::sovereign_defense_store::dashboard_snapshot(
        &state.app_pool,
        auth.tenant_id,
        client_id,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

async fn api_sovereign_defense_rotate(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Json(body): Json<SovereignConfigBody>,
) -> Response {
    let step = body.rotation_step_secs.unwrap_or(3).clamp(1, 60);
    if let (Some(min), Some(max)) = (body.port_pool_min, body.port_pool_max) {
        // `liquid_matrix_routing_tokens` is tenant-scoped; on a bare pool RLS silently matches no
        // rows and the operator's port pool is dropped while the endpoint reports success.
        if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
            match sqlx::query(
                r#"UPDATE liquid_matrix_routing_tokens
                      SET rotation_step_secs = $3, port_pool_min = $4, port_pool_max = $5, updated_at = now()
                    WHERE tenant_id = $1 AND client_id = $2"#,
            )
            .bind(auth.tenant_id)
            .bind(client_id)
            .bind(step)
            .bind(min)
            .bind(max)
            .execute(&mut *tx)
            .await
            {
                Ok(r) if r.rows_affected() == 0 => {
                    tracing::warn!(target: "sovereign_defense", tenant_id = auth.tenant_id, client_id, "liquid-matrix port pool update matched no existing token");
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(target: "sovereign_defense", tenant_id = auth.tenant_id, error = %e, "liquid-matrix port pool update failed");
                }
            }
            let _ = tx.commit().await;
        }
    }
    match crate::sovereign_defense_store::rotate_liquid_matrix(
        &state.app_pool,
        auth.tenant_id,
        client_id,
        step,
    )
    .await
    {
        Ok(r) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "epoch": r.epoch,
                "internal_ip": r.internal_ip,
                "internal_port": r.internal_port,
                "service_fingerprint": r.service_fingerprint,
                "routing_code": r.routing_code,
                "expires_at": r.expires_at.to_rfc3339(),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

async fn api_sovereign_defense_chronos_events(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = crate::db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!([]))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, event_type, pid, parent_pid, process_name, syscall_hint, action_taken, delta_json, created_at
             FROM chronos_events
            WHERE client_id = $1
            ORDER BY id DESC LIMIT 100"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "event_type": r.try_get::<String,_>("event_type").unwrap_or_default(),
                "pid": r.try_get::<Option<i32>,_>("pid").ok().flatten(),
                "parent_pid": r.try_get::<Option<i32>,_>("parent_pid").ok().flatten(),
                "process_name": r.try_get::<Option<String>,_>("process_name").ok().flatten(),
                "syscall_hint": r.try_get::<Option<String>,_>("syscall_hint").ok().flatten(),
                "action_taken": r.try_get::<Option<String>,_>("action_taken").ok().flatten(),
                "delta_json": r.try_get::<serde_json::Value,_>("delta_json").unwrap_or(json!({})),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}

async fn api_sovereign_defense_poison_library(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r.into_response();
    }
    match crate::sovereign_defense_store::load_poison_library(&state.app_pool, 50).await {
        Ok(v) => (StatusCode::OK, Json(Value::Array(v))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

async fn api_sovereign_defense_cognitive_sessions(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = crate::db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!([]))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, target_url, bot_score, bot_signals, poison_variant, poison_payload_id, response_status, created_at
             FROM cognitive_starvation_sessions
            WHERE client_id = $1
            ORDER BY id DESC LIMIT 100"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "target_url": r.try_get::<String,_>("target_url").unwrap_or_default(),
                "bot_score": r.try_get::<f64,_>("bot_score").unwrap_or(0.0),
                "bot_signals": r.try_get::<serde_json::Value,_>("bot_signals").unwrap_or(json!([])),
                "poison_variant": r.try_get::<Option<String>,_>("poison_variant").ok().flatten(),
                "poison_payload_id": r.try_get::<Option<String>,_>("poison_payload_id").ok().flatten(),
                "response_status": r.try_get::<Option<i32>,_>("response_status").ok().flatten(),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}
