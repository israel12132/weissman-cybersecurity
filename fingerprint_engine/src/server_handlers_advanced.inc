// Generated handlers for: attack-paths, SOAR playbooks.
// Mounted from `serve.rs` via `include!`.

// ─── Attack-path endpoints ─────────────────────────────────────────────────

async fn api_attack_paths_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let recompute = q.get("recompute").map(|v| v == "1" || v == "true").unwrap_or(false);
    let top_k = q.get("top_k").and_then(|s| s.parse::<usize>().ok());

    let snap = if recompute {
        match crate::attack_path::compute_and_store(&state.app_pool, auth.tenant_id, client_id, top_k).await {
            Ok(s) => Some(s),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "ok": false, "detail": format!("compute: {e}") })),
                ).into_response();
            }
        }
    } else {
        crate::attack_path::latest_snapshot(&state.app_pool, auth.tenant_id, client_id).await.ok().flatten()
    };

    match snap {
        Some(s) => (StatusCode::OK, Json(json!({ "ok": true, "snapshot": s }))).into_response(),
        None => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "snapshot": null,
                "detail": "no snapshot yet — call with ?recompute=1 to generate"
            })),
        ).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct RiskNodeFlagsBody {
    #[serde(default)]
    internet_exposed: Option<bool>,
    #[serde(default)]
    crown_jewel: Option<bool>,
    #[serde(default)]
    asset_value: Option<f32>,
}

async fn api_risk_node_flags_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(node_id): Path<i64>,
    Json(body): Json<RiskNodeFlagsBody>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query(
        r#"UPDATE risk_graph_nodes
              SET internet_exposed = COALESCE($1, internet_exposed),
                  crown_jewel      = COALESCE($2, crown_jewel),
                  asset_value      = COALESCE($3, asset_value)
            WHERE id = $4 AND tenant_id = $5"#,
    )
    .bind(body.internet_exposed)
    .bind(body.crown_jewel)
    .bind(body.asset_value)
    .bind(node_id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({"ok": true, "id": node_id}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "node not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": e.to_string()}))).into_response(),
    }
}

// ─── Playbook endpoints ────────────────────────────────────────────────────

async fn api_playbooks_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, name, description, enabled, trigger_dsl, actions_dsl,
                  last_run_at, last_run_status, run_count, failure_count,
                  created_at, updated_at
             FROM weissman_playbooks
            ORDER BY enabled DESC, updated_at DESC"#,
    )
    .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;

    let list: Vec<Value> = rows.into_iter().map(|r| {
        let trig: Value = r.try_get("trigger_dsl").unwrap_or(json!({}));
        let acts: Value = r.try_get("actions_dsl").unwrap_or(json!([]));
        json!({
            "id":              r.try_get::<i64, _>("id").unwrap_or(0),
            "name":            r.try_get::<String, _>("name").unwrap_or_default(),
            "description":     r.try_get::<String, _>("description").unwrap_or_default(),
            "enabled":         r.try_get::<bool, _>("enabled").unwrap_or(false),
            "trigger":         trig,
            "actions":         acts,
            "last_run_at":     r.try_get::<Option<chrono::DateTime<Utc>>, _>("last_run_at").ok().flatten().map(|d| d.to_rfc3339()),
            "last_run_status": r.try_get::<String, _>("last_run_status").unwrap_or_default(),
            "run_count":       r.try_get::<i32, _>("run_count").unwrap_or(0),
            "failure_count":   r.try_get::<i32, _>("failure_count").unwrap_or(0),
            "created_at":      r.try_get::<chrono::DateTime<Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
            "updated_at":      r.try_get::<chrono::DateTime<Utc>, _>("updated_at").ok().map(|d| d.to_rfc3339()),
        })
    }).collect();
    (StatusCode::OK, Json(json!({"ok": true, "playbooks": list}))).into_response()
}

#[derive(serde::Deserialize)]
struct PlaybookBody {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    trigger: Value,
    #[serde(default)]
    actions: Value,
}

async fn api_playbooks_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<PlaybookBody>,
) -> Response {
    let name = body.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "detail": "name required"}))).into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let trigger = if body.trigger.is_null() { json!({}) } else { body.trigger };
    let actions = if body.actions.is_null() { json!([]) } else { body.actions };
    let id_res: Result<i64, _> = sqlx::query_scalar(
        r#"INSERT INTO weissman_playbooks
               (tenant_id, name, description, enabled, trigger_dsl, actions_dsl, created_by_user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id"#,
    )
    .bind(auth.tenant_id)
    .bind(name)
    .bind(&body.description)
    .bind(body.enabled)
    .bind(&trigger)
    .bind(&actions)
    .bind(Some(auth.user_id))
    .fetch_one(&mut *tx).await;
    let _ = tx.commit().await;
    match id_res {
        Ok(id) => (StatusCode::CREATED, Json(json!({"ok": true, "id": id}))).into_response(),
        Err(e) => (StatusCode::CONFLICT, Json(json!({"ok": false, "detail": e.to_string()}))).into_response(),
    }
}

async fn api_playbooks_update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<PlaybookBody>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let trigger = if body.trigger.is_null() { json!({}) } else { body.trigger };
    let actions = if body.actions.is_null() { json!([]) } else { body.actions };
    let res = sqlx::query(
        r#"UPDATE weissman_playbooks
              SET name = $1, description = $2, enabled = $3,
                  trigger_dsl = $4, actions_dsl = $5, updated_at = now()
            WHERE id = $6 AND tenant_id = $7"#,
    )
    .bind(body.name.trim())
    .bind(&body.description)
    .bind(body.enabled)
    .bind(&trigger)
    .bind(&actions)
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&mut *tx).await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(e) => (StatusCode::CONFLICT, Json(json!({"ok": false, "detail": e.to_string()}))).into_response(),
    }
}

async fn api_playbooks_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query("DELETE FROM weissman_playbooks WHERE id = $1 AND tenant_id = $2")
        .bind(id).bind(auth.tenant_id)
        .execute(&mut *tx).await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": e.to_string()}))).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct PlaybookFireBody {
    event: crate::soar_playbook::PlaybookEvent,
    #[serde(default)]
    dry_run: bool,
}

async fn api_playbooks_fire(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<PlaybookFireBody>,
) -> Response {
    let mut event = body.event;
    // Force the caller's tenant onto the event — never trust the request body
    // for tenant identity.
    event.tenant_id = auth.tenant_id;
    let results = crate::soar_playbook::dispatch_event(
        &state.app_pool,
        event,
        body.dry_run,
    ).await;
    (StatusCode::OK, Json(json!({
        "ok": true,
        "dry_run": body.dry_run,
        "results": results,
    }))).into_response()
}

// ─── Financial blast-radius endpoints ──────────────────────────────────────

async fn api_financial_risk_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let recompute = q.get("recompute").map(|v| v == "1" || v == "true").unwrap_or(false);
    let snap = if recompute {
        match crate::financial_risk::compute_and_store(&state.app_pool, auth.tenant_id, client_id).await {
            Ok(s) => Some(s),
            Err(e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("compute: {e}")})),
            ).into_response(),
        }
    } else {
        crate::financial_risk::latest_snapshot(&state.app_pool, auth.tenant_id, client_id).await.ok().flatten()
    };
    match snap {
        Some(s) => (StatusCode::OK, Json(json!({"ok": true, "snapshot": s}))).into_response(),
        None => (StatusCode::OK, Json(json!({
            "ok": true, "snapshot": null,
            "detail": "no snapshot yet — call with ?recompute=1"
        }))).into_response(),
    }
}

async fn api_apply_asset_tag_rules(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    match crate::financial_risk::apply_tag_rules(&state.app_pool, auth.tenant_id, client_id).await {
        Ok(n) => (StatusCode::OK, Json(json!({"ok": true, "updated": n}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": e}))).into_response(),
    }
}

// ─── Ask Weissman (NL → safe SQL) ──────────────────────────────────────────

#[derive(serde::Deserialize)]
struct AskBody { question: String }

async fn api_ask(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<AskBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let ro_pool = match state.read_only_pool.as_ref() {
        Some(p) => p,
        None => {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
                "ok": false,
                "detail": "/api/ask requires a read-only Postgres role. Set WEISSMAN_READ_ONLY_DATABASE_URL."
            }))).into_response();
        }
    };
    let result = crate::nl_query::ask(
        &state.app_pool,
        ro_pool.as_ref(),
        auth.tenant_id,
        Some(auth.user_id),
        &body.question,
    ).await;
    (StatusCode::OK, Json(json!({"ok": result.error.is_none(), "result": result}))).into_response()
}

// ─── UEBA ingest (called by /ws/agent when ueba_baseline finding arrives) ──

async fn api_ueba_ingest(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(p): Json<crate::ueba_detector::UebaIngestPayload>,
) -> Response {
    match crate::ueba_detector::ingest_sample(&state.app_pool, auth.tenant_id, p).await {
        Ok(s) => (StatusCode::OK, Json(json!({"ok": true, "summary": s}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": e}))).into_response(),
    }
}

async fn api_ueba_anomalies(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(50).clamp(1, 500);
    let agent = q.get("agent_id").cloned();
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, agent_id, client_id, metric_name, observed,
                  baseline_mean, baseline_stddev, z_score, severity, detail, detected_at
             FROM agent_anomalies
            WHERE ($1::text IS NULL OR agent_id = $1)
            ORDER BY detected_at DESC
            LIMIT $2"#,
    )
    .bind(agent.as_deref())
    .bind(limit)
    .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;
    let list: Vec<Value> = rows.into_iter().map(|r| json!({
        "id":            r.try_get::<i64, _>("id").unwrap_or(0),
        "agent_id":      r.try_get::<String, _>("agent_id").unwrap_or_default(),
        "client_id":     r.try_get::<i64, _>("client_id").unwrap_or(0),
        "metric_name":   r.try_get::<String, _>("metric_name").unwrap_or_default(),
        "observed":      r.try_get::<f64, _>("observed").unwrap_or(0.0),
        "baseline_mean": r.try_get::<f64, _>("baseline_mean").unwrap_or(0.0),
        "baseline_stddev": r.try_get::<f64, _>("baseline_stddev").unwrap_or(0.0),
        "z_score":       r.try_get::<f64, _>("z_score").unwrap_or(0.0),
        "severity":      r.try_get::<String, _>("severity").unwrap_or_default(),
        "detail":        r.try_get::<String, _>("detail").unwrap_or_default(),
        "detected_at":   r.try_get::<chrono::DateTime<Utc>, _>("detected_at").ok().map(|d| d.to_rfc3339()),
    })).collect();
    (StatusCode::OK, Json(json!({"ok": true, "anomalies": list}))).into_response()
}

async fn api_playbook_runs(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(playbook_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(50).clamp(1, 500);
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, triggered_at, trigger_kind, trigger_event,
                  actions_total, actions_succeeded, actions_failed,
                  action_results, status, run_dedup_key
             FROM weissman_playbook_runs
            WHERE playbook_id = $1
            ORDER BY triggered_at DESC
            LIMIT $2"#,
    )
    .bind(playbook_id)
    .bind(limit)
    .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;
    let runs: Vec<Value> = rows.into_iter().map(|r| json!({
        "id":                r.try_get::<i64, _>("id").unwrap_or(0),
        "triggered_at":      r.try_get::<chrono::DateTime<Utc>, _>("triggered_at").ok().map(|d| d.to_rfc3339()),
        "trigger_kind":      r.try_get::<String, _>("trigger_kind").unwrap_or_default(),
        "trigger_event":     r.try_get::<Value, _>("trigger_event").unwrap_or(json!({})),
        "actions_total":     r.try_get::<i32, _>("actions_total").unwrap_or(0),
        "actions_succeeded": r.try_get::<i32, _>("actions_succeeded").unwrap_or(0),
        "actions_failed":    r.try_get::<i32, _>("actions_failed").unwrap_or(0),
        "action_results":    r.try_get::<Value, _>("action_results").unwrap_or(json!([])),
        "status":            r.try_get::<String, _>("status").unwrap_or_default(),
        "run_dedup_key":     r.try_get::<String, _>("run_dedup_key").unwrap_or_default(),
    })).collect();
    (StatusCode::OK, Json(json!({"ok": true, "runs": runs}))).into_response()
}
