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

    if recompute {
        if let Err(r) = crate::rbac::require_operator(&auth) {
            return r;
        }
    }

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

// ─── Unified threat analysis (planner + correlation + NDR + ITDR over live findings) ───
async fn api_threat_analysis_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(500)
        .clamp(1, 2000);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT COALESCE(raw_data, '{}'::jsonb)                       AS rd,
                  COALESCE(title, '')                                   AS title,
                  COALESCE(severity, '')                                AS severity,
                  COALESCE(EXTRACT(EPOCH FROM discovered_at)::bigint, 0) AS ts
             FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2
            ORDER BY discovered_at ASC
            LIMIT $3"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("query: {e}")})),
            )
                .into_response()
        }
    };

    let mut findings: Vec<Value> = Vec::with_capacity(rows.len());
    for r in &rows {
        let mut v: Value = r.try_get("rd").unwrap_or_else(|_| json!({}));
        if !v.is_object() {
            v = json!({});
        }
        if let Some(obj) = v.as_object_mut() {
            obj.entry("title")
                .or_insert_with(|| json!(r.try_get::<String, _>("title").unwrap_or_default()));
            obj.entry("severity")
                .or_insert_with(|| json!(r.try_get::<String, _>("severity").unwrap_or_default()));
            obj.insert("ts".to_string(), json!(r.try_get::<i64, _>("ts").unwrap_or(0)));
        }
        findings.push(v);
    }

    let report = crate::threat_analysis::analyze(&findings, &[], &[]);

    // Optional: persist detected multi-stage correlation incidents (operator-gated, idempotent).
    let mut persisted_incidents = 0usize;
    if q.get("persist").map(|v| v == "1" || v == "true").unwrap_or(false) {
        if let Err(r) = crate::rbac::require_operator(&auth) {
            return r;
        }
        let events = crate::correlation_rules::events_from_findings(&findings, |i, f| {
            f.get("ts")
                .and_then(|v| v.as_i64())
                .unwrap_or(1000 + (i as i64) * 60)
        });
        let hits = crate::correlation_rules::evaluate_all(
            &crate::correlation_rules::default_rules(),
            &events,
        );
        persisted_incidents = crate::correlation_rules::persist_incidents(
            &state.app_pool,
            auth.tenant_id,
            Some(client_id),
            &hits,
        )
        .await
        .unwrap_or(0);
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "client_id": client_id,
            "findings_analyzed": findings.len(),
            "persisted_incidents": persisted_incidents,
            "analysis": report,
        })),
    )
        .into_response()
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
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
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

// ─── Baseline & drift (UEBA tables → BaselineAndDrift.jsx) ───────────────────

fn baseline_range_interval(range: &str) -> &'static str {
    let r = range.trim();
    if r.eq_ignore_ascii_case("24h") {
        "24 hours"
    } else if r.eq_ignore_ascii_case("30d") {
        "30 days"
    } else {
        "7 days"
    }
}

fn baseline_range_bucket(range: &str) -> &'static str {
    if range.trim().eq_ignore_ascii_case("24h") {
        "hour"
    } else {
        "day"
    }
}

/// GET /api/baseline/summary — aggregate posture from agent_metric_baselines + recent anomalies.
async fn api_baseline_summary(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let baseline_row = sqlx::query(
        r#"SELECT COUNT(DISTINCT agent_id)::bigint AS total_assets,
                  MAX(last_updated_at) AS last_updated,
                  COALESCE(SUM(n), 0)::bigint AS sample_count,
                  COUNT(*)::bigint AS baseline_rows
             FROM agent_metric_baselines"#,
    )
    .fetch_one(&mut *tx)
    .await;

    let drift_row = sqlx::query(
        r#"SELECT COALESCE(
                  LEAST(
                      100.0,
                      COUNT(*)::double precision * 2.0
                          + COALESCE(AVG(ABS(z_score)), 0.0) * 8.0
                  ),
                  0.0
              ) AS drift_score
             FROM agent_anomalies
            WHERE detected_at >= now() - interval '7 days'"#,
    )
    .fetch_one(&mut *tx)
    .await;

    let _ = tx.commit().await;

    let (total_assets, last_updated, sample_count, baseline_rows) = match baseline_row {
        Ok(r) => (
            r.try_get::<i64, _>("total_assets").unwrap_or(0),
            r.try_get::<Option<chrono::DateTime<Utc>>, _>("last_updated")
                .ok()
                .flatten()
                .map(|d| d.to_rfc3339()),
            r.try_get::<i64, _>("sample_count").unwrap_or(0),
            r.try_get::<i64, _>("baseline_rows").unwrap_or(0),
        ),
        Err(_) => (0, None, 0, 0),
    };
    let drift_score = drift_row
        .ok()
        .and_then(|r| r.try_get::<f64, _>("drift_score").ok())
        .unwrap_or(0.0);

    (
        StatusCode::OK,
        Json(json!({
            "total_assets": total_assets,
            "drift_score": drift_score,
            "last_updated": last_updated,
            "sample_count": sample_count,
            "baseline_rows": baseline_rows,
        })),
    )
        .into_response()
}

/// GET /api/baseline/drift?range=24h|7d|30d — time-series drift from agent_anomalies.
async fn api_baseline_drift(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let range = q.get("range").map(String::as_str).unwrap_or("7d");
    let interval = baseline_range_interval(range);
    let bucket = baseline_range_bucket(range);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let sql = format!(
        r#"SELECT date_trunc('{bucket}', detected_at AT TIME ZONE 'UTC') AS bucket,
                  COUNT(*)::int AS anomaly_count,
                  COALESCE(AVG(ABS(z_score)), 0.0) AS avg_z
             FROM agent_anomalies
            WHERE detected_at >= now() - interval '{interval}'
            GROUP BY 1
            ORDER BY 1 ASC"#
    );
    let rows = sqlx::query(&sql).fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;

    let data: Vec<Value> = rows
        .into_iter()
        .filter_map(|r| {
            let bucket_ts = r
                .try_get::<chrono::DateTime<Utc>, _>("bucket")
                .ok()?;
            let anomaly_count = r.try_get::<i32, _>("anomaly_count").unwrap_or(0);
            let avg_z = r.try_get::<f64, _>("avg_z").unwrap_or(0.0);
            let drift = (anomaly_count as f64 * 2.0 + avg_z * 8.0).min(100.0);
            let time = if bucket == "hour" {
                bucket_ts.format("%H:%M").to_string()
            } else {
                bucket_ts.format("%b %d").to_string()
            };
            Some(json!({
                "time": time,
                "drift": (drift * 10.0).round() / 10.0,
                "anomalies": anomaly_count,
            }))
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({ "data": data, "range": range })),
    )
        .into_response()
}

/// GET /api/baseline/anomalies?range=24h|7d|30d — recent UEBA anomalies for the UI list.
async fn api_baseline_anomalies(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let range = q.get("range").map(String::as_str).unwrap_or("7d");
    let interval = baseline_range_interval(range);
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 500);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let sql = format!(
        r#"SELECT id, agent_id, metric_name, observed, baseline_mean,
                  z_score, severity, detail, detected_at
             FROM agent_anomalies
            WHERE detected_at >= now() - interval '{interval}'
            ORDER BY detected_at DESC
            LIMIT $1"#
    );
    let rows = sqlx::query(&sql)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;

    let anomalies: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let z = r.try_get::<f64, _>("z_score").unwrap_or(0.0);
            json!({
                "id": r.try_get::<i64, _>("id").unwrap_or(0),
                "type": r.try_get::<String, _>("metric_name").unwrap_or_default(),
                "score": ((z.abs() * 10.0).round() / 10.0),
                "description": r.try_get::<String, _>("detail").unwrap_or_default(),
                "agent_id": r.try_get::<String, _>("agent_id").unwrap_or_default(),
                "observed": r.try_get::<f64, _>("observed").unwrap_or(0.0),
                "baseline_mean": r.try_get::<f64, _>("baseline_mean").unwrap_or(0.0),
                "severity": r.try_get::<String, _>("severity").unwrap_or_default(),
                "detected_at": r
                    .try_get::<chrono::DateTime<Utc>, _>("detected_at")
                    .ok()
                    .map(|d| d.to_rfc3339()),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({ "anomalies": anomalies, "range": range })),
    )
        .into_response()
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
