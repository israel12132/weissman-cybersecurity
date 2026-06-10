#[derive(Deserialize)]
struct EngagementCreateBody {
    name: String,
    #[serde(default)]
    start_at: Option<String>,
    #[serde(default)]
    end_at: Option<String>,
    #[serde(default)]
    roe_mode: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Deserialize)]
struct EngagementPatchBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    end_at: Option<String>,
    #[serde(default)]
    roe_mode: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

fn parse_rfc3339_opt(s: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = s?.trim();
    if s.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn normalize_engagement_status(raw: &str) -> Option<&'static str> {
    match raw.trim().to_lowercase().as_str() {
        "active" => Some("active"),
        "paused" => Some("paused"),
        "closed" => Some("closed"),
        _ => None,
    }
}

fn normalize_roe_mode(raw: &str) -> Option<&'static str> {
    match raw.trim() {
        "safe_proofs" => Some("safe_proofs"),
        "weaponized_god_mode" => Some("weaponized_god_mode"),
        _ => None,
    }
}

async fn api_client_engagements_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"engagements": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, client_id, name, status, start_at, end_at, roe_mode, created_by_user_id, created_at, updated_at
           FROM engagements
           WHERE client_id = $1
           ORDER BY created_at DESC
           LIMIT 200"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let engagements: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let start_at: chrono::DateTime<chrono::Utc> =
                r.try_get("start_at").unwrap_or_else(|_| chrono::Utc::now());
            let end_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("end_at").ok();
            let created_at: chrono::DateTime<chrono::Utc> =
                r.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now());
            let updated_at: chrono::DateTime<chrono::Utc> =
                r.try_get("updated_at").unwrap_or_else(|_| chrono::Utc::now());
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "client_id": r.try_get::<i64,_>("client_id").unwrap_or(client_id),
                "name": r.try_get::<String,_>("name").unwrap_or_default(),
                "status": r.try_get::<String,_>("status").unwrap_or_else(|_| "active".to_string()),
                "start_at": start_at.to_rfc3339(),
                "end_at": end_at.map(|x| x.to_rfc3339()),
                "roe_mode": r.try_get::<String,_>("roe_mode").unwrap_or_else(|_| "safe_proofs".to_string()),
                "created_by_user_id": r.try_get::<Option<i64>,_>("created_by_user_id").unwrap_or(None),
                "created_at": created_at.to_rfc3339(),
                "updated_at": updated_at.to_rfc3339(),
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "engagements": engagements }))).into_response()
}

async fn api_client_engagements_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(client_id): Path<i64>,
    body: axum::extract::Json<EngagementCreateBody>,
) -> Response {
    let name = body.name.trim();
    if name.is_empty() || name.len() > 200 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "name must be 1..200 chars"})),
        )
            .into_response();
    }

    let roe_mode = body
        .roe_mode
        .as_deref()
        .and_then(normalize_roe_mode)
        .unwrap_or("safe_proofs");

    let start_at = parse_rfc3339_opt(body.start_at.as_deref()).unwrap_or_else(chrono::Utc::now);
    let end_at = parse_rfc3339_opt(body.end_at.as_deref());
    if let Some(end_at) = end_at {
        if end_at < start_at {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "end_at must be >= start_at"})),
            )
                .into_response();
        }
    }

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    // Ensure client exists and capture scope snapshot at creation time.
    let client_row = sqlx::query(
        "SELECT id, name, domains, ip_ranges, tech_stack, auto_detect_tech_stack FROM clients WHERE id = $1",
    )
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(client_row) = client_row else {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "client not found"})),
        )
            .into_response();
    };
    let snapshot = json!({
        "client_name": client_row.try_get::<String,_>("name").unwrap_or_default(),
        "domains": serde_json::from_str::<Value>(&client_row.try_get::<String,_>("domains").unwrap_or_else(|_| "[]".to_string())).unwrap_or_else(|_| json!([])),
        "ip_ranges": serde_json::from_str::<Value>(&client_row.try_get::<String,_>("ip_ranges").unwrap_or_else(|_| "[]".to_string())).unwrap_or_else(|_| json!([])),
        "tech_stack": serde_json::from_str::<Value>(&client_row.try_get::<String,_>("tech_stack").unwrap_or_else(|_| "[]".to_string())).unwrap_or_else(|_| json!([])),
        "auto_detect_tech_stack": client_row.try_get::<bool,_>("auto_detect_tech_stack").unwrap_or(true),
    });

    let notes = body.notes.clone().unwrap_or_default();

    let created: Option<(i64,)> = sqlx::query_as(
        r#"INSERT INTO engagements (tenant_id, client_id, name, status, start_at, end_at, roe_mode, notes, scope_snapshot, created_by_user_id)
           VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8, $9)
           RETURNING id"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(name)
    .bind(start_at)
    .bind(end_at)
    .bind(roe_mode)
    .bind(&notes)
    .bind(snapshot)
    .bind(auth.user_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let Some((engagement_id,)) = created else {
        let _ = tx.rollback().await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false}))).into_response();
    };

    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "engagement_created",
        &format!("client_id={} engagement_id={} roe_mode={}", client_id, engagement_id, roe_mode),
        &ip,
    )
    .await;
    let _ = tx.commit().await;

    (
        StatusCode::CREATED,
        Json(json!({"ok": true, "engagement_id": engagement_id})),
    )
        .into_response()
}

async fn api_engagement_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(engagement_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(Value::Null)).into_response();
    };
    let row = sqlx::query(
        r#"SELECT id, client_id, name, status, start_at, end_at, roe_mode, notes, scope_snapshot, created_by_user_id, created_at, updated_at
           FROM engagements WHERE id = $1"#,
    )
    .bind(engagement_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let Some(r) = row else {
        return (StatusCode::NOT_FOUND, Json(Value::Null)).into_response();
    };
    let start_at: chrono::DateTime<chrono::Utc> =
        r.try_get("start_at").unwrap_or_else(|_| chrono::Utc::now());
    let end_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("end_at").ok();
    let created_at: chrono::DateTime<chrono::Utc> =
        r.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now());
    let updated_at: chrono::DateTime<chrono::Utc> =
        r.try_get("updated_at").unwrap_or_else(|_| chrono::Utc::now());

    let payload = json!({
        "id": r.try_get::<i64,_>("id").unwrap_or(engagement_id),
        "client_id": r.try_get::<i64,_>("client_id").unwrap_or(0),
        "name": r.try_get::<String,_>("name").unwrap_or_default(),
        "status": r.try_get::<String,_>("status").unwrap_or_else(|_| "active".to_string()),
        "start_at": start_at.to_rfc3339(),
        "end_at": end_at.map(|x| x.to_rfc3339()),
        "roe_mode": r.try_get::<String,_>("roe_mode").unwrap_or_else(|_| "safe_proofs".to_string()),
        "notes": r.try_get::<String,_>("notes").unwrap_or_default(),
        "scope_snapshot": r.try_get::<Value,_>("scope_snapshot").unwrap_or_else(|_| json!({})),
        "created_by_user_id": r.try_get::<Option<i64>,_>("created_by_user_id").unwrap_or(None),
        "created_at": created_at.to_rfc3339(),
        "updated_at": updated_at.to_rfc3339(),
    });
    (StatusCode::OK, Json(payload)).into_response()
}

async fn api_engagement_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(engagement_id): Path<i64>,
    body: axum::extract::Json<EngagementPatchBody>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    // Load row (for client_id + old values).
    let row = sqlx::query(
        "SELECT id, client_id, roe_mode, status FROM engagements WHERE id = $1",
    )
    .bind(engagement_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "engagement not found"})),
        )
            .into_response();
    };
    let client_id: i64 = r.try_get("client_id").unwrap_or(0);
    let old_status: String = r.try_get("status").unwrap_or_else(|_| "active".to_string());
    let old_roe: String = r.try_get("roe_mode").unwrap_or_else(|_| "safe_proofs".to_string());

    let mut has_changes = false;
    let mut qb = sqlx::QueryBuilder::new("UPDATE engagements SET ");
    let mut separated = qb.separated(", ");
    let mut changed_keys: Vec<&'static str> = Vec::new();

    if let Some(name) = body.name.as_deref() {
        let n = name.trim();
        if n.is_empty() || n.len() > 200 {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "name must be 1..200 chars"})),
            )
            .into_response();
        }
        separated.push("name = ").push_bind(n.to_string());
        has_changes = true;
        changed_keys.push("name");
    }

    if let Some(status) = body.status.as_deref() {
        let Some(s) = normalize_engagement_status(status) else {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "status must be active|paused|closed"})),
            )
            .into_response();
        };
        separated.push("status = ").push_bind(s.to_string());
        has_changes = true;
        changed_keys.push("status");
    }

    if let Some(roe) = body.roe_mode.as_deref() {
        let Some(m) = normalize_roe_mode(roe) else {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "roe_mode must be safe_proofs|weaponized_god_mode"})),
            )
            .into_response();
        };
        separated.push("roe_mode = ").push_bind(m.to_string());
        has_changes = true;
        changed_keys.push("roe_mode");
    }

    if let Some(notes) = body.notes.as_deref() {
        separated.push("notes = ").push_bind(notes.to_string());
        has_changes = true;
        changed_keys.push("notes");
    }

    if let Some(end_at) = parse_rfc3339_opt(body.end_at.as_deref()) {
        separated.push("end_at = ").push_bind(end_at);
        has_changes = true;
        changed_keys.push("end_at");
    }

    if !has_changes {
        let _ = tx.rollback().await;
        return (StatusCode::OK, Json(json!({"ok": true}))).into_response();
    }

    separated.push("updated_at = now()");
    qb.push(" WHERE id = ").push_bind(engagement_id);
    let updated = qb.build().execute(&mut *tx).await.is_ok();
    if !updated {
        let _ = tx.rollback().await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false}))).into_response();
    }

    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "engagement_updated",
        &format!("client_id={} engagement_id={} keys={} old_status={} old_roe={}", client_id, engagement_id, changed_keys.join(","), old_status, old_roe),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}
