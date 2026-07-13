// Alert rules CRUD — `/api/alerts/rules` (AlertRulesEngine.jsx).

fn alert_rule_from_row(
    id: i64,
    name: &str,
    condition: &Value,
    actions: &Value,
    enabled: bool,
    triggered_count: i64,
) -> Value {
    let description = condition
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let priority = condition
        .get("priority")
        .and_then(|v| v.as_i64())
        .unwrap_or(5) as i32;
    let mut conditions = condition.clone();
    if let Some(obj) = conditions.as_object_mut() {
        obj.remove("description");
        obj.remove("priority");
    }
    let channels: Vec<String> = actions
        .get("channels")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "id": id,
        "name": name,
        "description": description,
        "enabled": enabled,
        "priority": priority,
        "conditions": conditions,
        "channels": channels,
        "triggered_count": triggered_count,
    })
}

fn alert_rule_body_to_stored(body: &AlertRuleBody) -> (Value, Value) {
    let mut condition = body.conditions.clone();
    if condition.is_null() {
        condition = json!({});
    }
    if let Some(obj) = condition.as_object_mut() {
        if !body.description.is_empty() {
            obj.insert("description".into(), json!(body.description));
        }
        obj.insert("priority".into(), json!(body.priority));
    }
    let actions = json!({ "channels": body.channels });
    (condition, actions)
}

async fn api_alert_rules_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false, "rules": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT r.id, r.name, r.condition, r.actions, r.enabled,
                  COALESCE(f.cnt, 0)::bigint AS triggered_count
             FROM weissman_alert_rules r
             LEFT JOIN (
               SELECT rule_id, COUNT(*)::bigint AS cnt
                 FROM weissman_alert_rule_fires
                GROUP BY rule_id
             ) f ON f.rule_id = r.id
            ORDER BY r.enabled DESC, r.updated_at DESC"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let rules: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let id = r.try_get::<i64, _>("id").unwrap_or(0);
            let name = r.try_get::<String, _>("name").unwrap_or_default();
            let condition: Value = r.try_get("condition").unwrap_or(json!({}));
            let actions: Value = r.try_get("actions").unwrap_or(json!({}));
            let enabled = r.try_get::<bool, _>("enabled").unwrap_or(false);
            let triggered_count = r.try_get::<i64, _>("triggered_count").unwrap_or(0);
            alert_rule_from_row(id, &name, &condition, &actions, enabled, triggered_count)
        })
        .collect();
    (StatusCode::OK, Json(json!({"ok": true, "rules": rules}))).into_response()
}

#[derive(serde::Deserialize)]
struct AlertRuleBody {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_priority")]
    priority: i32,
    #[serde(default)]
    conditions: Value,
    #[serde(default)]
    channels: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_priority() -> i32 {
    5
}

#[derive(serde::Deserialize)]
struct AlertRulePatchBody {
    #[serde(default)]
    enabled: Option<bool>,
}

async fn api_alert_rules_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<AlertRuleBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let name = body.name.trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "name required"})),
        )
            .into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let (condition, actions) = alert_rule_body_to_stored(&body);
    let id_res: Result<i64, _> = sqlx::query_scalar(
        r#"INSERT INTO weissman_alert_rules (tenant_id, name, condition, actions, enabled)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id"#,
    )
    .bind(auth.tenant_id)
    .bind(name)
    .bind(&condition)
    .bind(&actions)
    .bind(body.enabled)
    .fetch_one(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match id_res {
        Ok(id) => (StatusCode::CREATED, Json(json!({"ok": true, "id": id}))).into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "detail": e.to_string()})),
        )
            .into_response(),
    }
}

async fn api_alert_rules_put(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<AlertRuleBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let name = body.name.trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "name required"})),
        )
            .into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let (condition, actions) = alert_rule_body_to_stored(&body);
    let res = sqlx::query(
        r#"UPDATE weissman_alert_rules
              SET name = $1, condition = $2, actions = $3, enabled = $4, updated_at = now()
            WHERE id = $5 AND tenant_id = $6"#,
    )
    .bind(name)
    .bind(&condition)
    .bind(&actions)
    .bind(body.enabled)
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "detail": e.to_string()})),
        )
            .into_response(),
    }
}

async fn api_alert_rules_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<AlertRulePatchBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let Some(enabled) = body.enabled else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "enabled required"})),
        )
            .into_response();
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query(
        r#"UPDATE weissman_alert_rules
              SET enabled = $1, updated_at = now()
            WHERE id = $2 AND tenant_id = $3"#,
    )
    .bind(enabled)
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, Json(json!({"ok": true, "id": id, "enabled": enabled}))).into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
        )
            .into_response(),
    }
}

async fn api_alert_rules_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query("DELETE FROM weissman_alert_rules WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .execute(&mut *tx)
        .await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
        )
            .into_response(),
    }
}

fn cve_pattern_to_like(pattern: &str) -> String {
    pattern.replace('*', "%")
}

async fn count_findings_matching_condition(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    condition: &Value,
) -> Result<i64, sqlx::Error> {
    let severities: Vec<String> = condition
        .get("severity")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(|x| x.to_ascii_lowercase()))
                .collect()
        })
        .unwrap_or_default();
    let cve_like: Option<String> = condition
        .get("cve_pattern")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(cve_pattern_to_like);
    let engines: Vec<String> = condition
        .get("engines")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(|x| x.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint
             FROM vulnerabilities
            WHERE ($1::text[] IS NULL OR cardinality($1::text[]) = 0 OR lower(severity) = ANY($1))
              AND (
                    $2::text IS NULL
                    OR title ILIKE $2
                    OR description ILIKE $2
                    OR COALESCE(raw_data, '{}'::jsonb)::text ILIKE $2
                  )
              AND ($3::text[] IS NULL OR cardinality($3::text[]) = 0 OR source = ANY($3))"#,
    )
    .bind(if severities.is_empty() {
        None::<Vec<String>>
    } else {
        Some(severities)
    })
    .bind(cve_like.as_deref())
    .bind(if engines.is_empty() {
        None::<Vec<String>>
    } else {
        Some(engines)
    })
    .fetch_one(&mut **tx)
    .await?;

    if let Some(threshold) = condition.get("threshold").and_then(|v| v.as_i64()) {
        Ok(if count >= threshold { count } else { 0 })
    } else {
        Ok(count)
    }
}

async fn api_alert_rules_test(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query(
        r#"SELECT condition FROM weissman_alert_rules WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await;
    match row {
        Ok(Some(r)) => {
            let condition: Value = r.try_get("condition").unwrap_or(json!({}));
            let mut eval_condition = condition.clone();
            if let Some(obj) = eval_condition.as_object_mut() {
                obj.remove("description");
                obj.remove("priority");
            }
            match count_findings_matching_condition(&mut tx, &eval_condition).await {
                Ok(matched) => {
                    let _ = tx.commit().await;
                    (
                        StatusCode::OK,
                        Json(json!({"ok": true, "success": true, "matched": matched})),
                    )
                        .into_response()
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"ok": false, "success": false, "detail": scrub_internal_error(&e)})),
                    )
                        .into_response()
                }
            }
        }
        Ok(None) => {
            let _ = tx.commit().await;
            (StatusCode::NOT_FOUND, Json(json!({"ok": false, "success": false}))).into_response()
        }
        Err(e) => {
            let _ = tx.rollback().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "success": false, "detail": scrub_internal_error(&e)})),
            )
                .into_response()
        }
    }
}
