#[derive(Deserialize)]
struct RoeOverrideListQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
}

fn normalize_roe_request_status(raw: &str) -> Option<&'static str> {
    match raw.trim().to_lowercase().as_str() {
        "pending" => Some("pending"),
        "approved" => Some("approved"),
        "rejected" => Some("rejected"),
        "expired" => Some("expired"),
        "applied" => Some("applied"),
        _ => None,
    }
}

async fn api_roe_override_requests_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<RoeOverrideListQuery>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"requests": []}))).into_response();
    };
    // Expire old pending requests opportunistically.
    let _ = sqlx::query(
        "UPDATE roe_override_requests SET status = 'expired', updated_at = now() WHERE status = 'pending' AND expires_at <= now()",
    )
    .execute(&mut *tx)
    .await;

    let status = q.status.as_deref().and_then(normalize_roe_request_status);
    let client_id = q.client_id;

    let mut qb = sqlx::QueryBuilder::new(
        r#"SELECT r.id, r.client_id, c.name AS client_name, r.desired_roe_mode, r.status,
                  r.justification, r.requested_by_user_id, r.requested_at, r.expires_at,
                  r.first_approved_by_user_id, r.first_approved_at,
                  r.second_approved_by_user_id, r.second_approved_at,
                  r.rejected_by_user_id, r.rejected_at,
                  r.applied_by_user_id, r.applied_at
           FROM roe_override_requests r
           LEFT JOIN clients c ON c.id = r.client_id
           WHERE 1=1"#,
    );
    if let Some(s) = status {
        qb.push(" AND r.status = ").push_bind(s);
    }
    if let Some(cid) = client_id {
        qb.push(" AND r.client_id = ").push_bind(cid);
    }
    qb.push(" ORDER BY r.requested_at DESC LIMIT 200");
    let rows = qb.build().fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;

    let requests: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let requested_at: chrono::DateTime<chrono::Utc> =
                r.try_get("requested_at").unwrap_or_else(|_| chrono::Utc::now());
            let expires_at: chrono::DateTime<chrono::Utc> =
                r.try_get("expires_at").unwrap_or_else(|_| chrono::Utc::now());
            let first_approved_at: Option<chrono::DateTime<chrono::Utc>> =
                r.try_get("first_approved_at").ok();
            let second_approved_at: Option<chrono::DateTime<chrono::Utc>> =
                r.try_get("second_approved_at").ok();
            let rejected_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("rejected_at").ok();
            let applied_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("applied_at").ok();
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "client_id": r.try_get::<i64,_>("client_id").unwrap_or(0),
                "client_name": r.try_get::<Option<String>,_>("client_name").unwrap_or(None),
                "desired_roe_mode": r.try_get::<String,_>("desired_roe_mode").unwrap_or_else(|_| "weaponized_god_mode".to_string()),
                "status": r.try_get::<String,_>("status").unwrap_or_else(|_| "pending".to_string()),
                "justification": r.try_get::<String,_>("justification").unwrap_or_default(),
                "requested_by_user_id": r.try_get::<Option<i64>,_>("requested_by_user_id").unwrap_or(None),
                "requested_at": requested_at.to_rfc3339(),
                "expires_at": expires_at.to_rfc3339(),
                "first_approved_by_user_id": r.try_get::<Option<i64>,_>("first_approved_by_user_id").unwrap_or(None),
                "first_approved_at": first_approved_at.map(|x| x.to_rfc3339()),
                "second_approved_by_user_id": r.try_get::<Option<i64>,_>("second_approved_by_user_id").unwrap_or(None),
                "second_approved_at": second_approved_at.map(|x| x.to_rfc3339()),
                "rejected_by_user_id": r.try_get::<Option<i64>,_>("rejected_by_user_id").unwrap_or(None),
                "rejected_at": rejected_at.map(|x| x.to_rfc3339()),
                "applied_by_user_id": r.try_get::<Option<i64>,_>("applied_by_user_id").unwrap_or(None),
                "applied_at": applied_at.map(|x| x.to_rfc3339()),
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "requests": requests }))).into_response()
}

async fn api_roe_override_request_approve(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let row = sqlx::query(
        r#"SELECT id, client_id, desired_roe_mode, status, expires_at,
                  first_approved_by_user_id, second_approved_by_user_id
           FROM roe_override_requests
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "request not found"}))).into_response();
    };
    let status: String = r.try_get("status").unwrap_or_else(|_| "pending".to_string());
    let expires_at: chrono::DateTime<chrono::Utc> =
        r.try_get("expires_at").unwrap_or_else(|_| chrono::Utc::now());
    if status != "pending" {
        let _ = tx.rollback().await;
        return (StatusCode::CONFLICT, Json(json!({"ok": false, "detail": "request is not pending", "status": status}))).into_response();
    }
    if expires_at <= chrono::Utc::now() {
        let _ = sqlx::query("UPDATE roe_override_requests SET status = 'expired', updated_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await;
        let _ = tx.commit().await;
        return (StatusCode::CONFLICT, Json(json!({"ok": false, "detail": "request expired"}))).into_response();
    }

    let client_id: i64 = r.try_get("client_id").unwrap_or(0);
    let desired: String = r
        .try_get("desired_roe_mode")
        .unwrap_or_else(|_| "weaponized_god_mode".to_string());
    let first: Option<i64> = r.try_get("first_approved_by_user_id").ok().flatten();
    let second: Option<i64> = r.try_get("second_approved_by_user_id").ok().flatten();

    if first == Some(auth.user_id) || second == Some(auth.user_id) {
        let _ = tx.rollback().await;
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "detail": "same approver cannot approve twice"}))).into_response();
    }

    if first.is_none() {
        let _ = sqlx::query(
            "UPDATE roe_override_requests SET first_approved_by_user_id = $1, first_approved_at = now(), updated_at = now() WHERE id = $2",
        )
        .bind(auth.user_id)
        .bind(id)
        .execute(&mut *tx)
        .await;
    } else if second.is_none() {
        let _ = sqlx::query(
            "UPDATE roe_override_requests SET second_approved_by_user_id = $1, second_approved_at = now(), updated_at = now() WHERE id = $2",
        )
        .bind(auth.user_id)
        .bind(id)
        .execute(&mut *tx)
        .await;
    } else {
        let _ = tx.rollback().await;
        return (StatusCode::CONFLICT, Json(json!({"ok": false, "detail": "already fully approved"}))).into_response();
    }

    // Re-check approval completeness and auto-apply when we have two distinct approvals.
    let fresh = sqlx::query(
        r#"SELECT first_approved_by_user_id, second_approved_by_user_id
           FROM roe_override_requests WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let (mut first_now, mut second_now) = (None::<i64>, None::<i64>);
    if let Some(fr) = fresh {
        first_now = fr.try_get("first_approved_by_user_id").ok().flatten();
        second_now = fr.try_get("second_approved_by_user_id").ok().flatten();
    }

    let fully_approved = first_now.is_some() && second_now.is_some();
    if fully_approved {
        let _ = sqlx::query("UPDATE roe_override_requests SET status = 'approved', updated_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await;

        // Apply ROE change immediately (end-to-end).
        let current: Option<String> = sqlx::query_scalar(
            "SELECT COALESCE(NULLIF(trim(client_configs), ''), $1) FROM clients WHERE id = $2",
        )
        .bind(DEFAULT_CLIENT_CONFIGS_JSON)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        let current = current.unwrap_or_else(|| DEFAULT_CLIENT_CONFIGS_JSON.to_string());
        let mut config: serde_json::Map<String, Value> = match serde_json::from_str(&current) {
            Ok(Value::Object(m)) => m,
            _ => serde_json::Map::new(),
        };
        config.insert("roe_mode".to_string(), Value::String(desired.clone()));
        let new_json = Value::Object(config);
        let new_str = serde_json::to_string(&new_json).unwrap_or_else(|_| current.clone());
        let _ = sqlx::query("UPDATE clients SET client_configs = $1, updated_at = now() WHERE id = $2")
            .bind(&new_str)
            .bind(client_id)
            .execute(&mut *tx)
            .await;

        let _ = sqlx::query(
            "UPDATE roe_override_requests SET status = 'applied', applied_by_user_id = $1, applied_at = now(), updated_at = now() WHERE id = $2",
        )
        .bind(auth.user_id)
        .bind(id)
        .execute(&mut *tx)
        .await;
    }

    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "roe_override_request_approved",
        &format!("client_id={} request_id={} desired_roe_mode={} fully_approved={}", client_id, id, desired, fully_approved),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true, "request_id": id, "fully_approved": fully_approved}))).into_response()
}

#[derive(Deserialize)]
struct RoeRejectBody {
    #[serde(default)]
    reason: Option<String>,
}

async fn api_roe_override_request_reject(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    body: axum::extract::Json<RoeRejectBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query("SELECT client_id, status FROM roe_override_requests WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "request not found"}))).into_response();
    };
    let status: String = r.try_get("status").unwrap_or_else(|_| "pending".to_string());
    if status != "pending" {
        let _ = tx.rollback().await;
        return (StatusCode::CONFLICT, Json(json!({"ok": false, "detail": "request is not pending", "status": status}))).into_response();
    }
    let client_id: i64 = r.try_get("client_id").unwrap_or(0);
    let reason = body.reason.clone().unwrap_or_default();
    let _ = sqlx::query(
        "UPDATE roe_override_requests SET status = 'rejected', justification = COALESCE(NULLIF($1, ''), justification), rejected_by_user_id = $2, rejected_at = now(), updated_at = now() WHERE id = $3",
    )
    .bind(&reason)
    .bind(auth.user_id)
    .bind(id)
    .execute(&mut *tx)
    .await;

    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "roe_override_request_rejected",
        &format!("client_id={} request_id={} reason={}", client_id, id, reason),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true, "request_id": id}))).into_response()
}

