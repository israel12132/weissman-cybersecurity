

// ========== Attack surface + semantic (simplified live reads) ==========
async fn api_client_attack_surface_graph(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"DB"}))).into_response();
    };
    let run_id: Option<i64> = sqlx::query_scalar("SELECT run_id FROM asm_graph_nodes WHERE client_id = $1 ORDER BY run_id DESC LIMIT 1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let Some(run_id) = run_id else {
        let _ = tx.commit().await;
        return (StatusCode::OK, Json(json!({ "nodes": [], "edges": [], "run_id": null, "message": "No ASM graph yet." }))).into_response();
    };
    // A read failure here (RLS mismatch, lock/statement timeout) must not masquerade as an empty
    // attack surface — the genuinely-empty case already returned above with an explicit message.
    let nodes_rows = match sqlx::query("SELECT node_id, label, node_type, status, cname_target, raw_finding FROM asm_graph_nodes WHERE run_id = $1 AND client_id = $2 ORDER BY id")
        .bind(run_id)
        .bind(id)
        .fetch_all(&mut *tx)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(target: "asm_graph", client_id = id, error = %e, "asm graph nodes read failed");
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"nodes": [], "edges": [], "run_id": run_id, "partial": true, "message": "graph data temporarily unavailable"}))).into_response();
        }
    };
    let edges_rows = match sqlx::query("SELECT from_id, to_id, edge_type FROM asm_graph_edges WHERE run_id = $1 AND client_id = $2 ORDER BY id")
        .bind(run_id)
        .bind(id)
        .fetch_all(&mut *tx)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(target: "asm_graph", client_id = id, error = %e, "asm graph edges read failed");
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"nodes": [], "edges": [], "run_id": run_id, "partial": true, "message": "graph data temporarily unavailable"}))).into_response();
        }
    };
    let vuln_rows = sqlx::query("SELECT finding_id, title, severity FROM vulnerabilities WHERE client_id = $1 AND source = 'semantic_ai_fuzz' ORDER BY id DESC LIMIT 50")
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;
    let mut nodes: Vec<Value> = Vec::new();
    for r in nodes_rows {
        let raw_finding: Option<String> = r.try_get("raw_finding").ok();
        let raw_json: Option<Value> = raw_finding.as_ref().and_then(|s| serde_json::from_str(s).ok());
        nodes.push(json!({
            "id": r.try_get::<String,_>("node_id").unwrap_or_default(),
            "label": r.try_get::<String,_>("label").unwrap_or_default(),
            "node_type": r.try_get::<String,_>("node_type").unwrap_or_default(),
            "status": r.try_get::<String,_>("status").unwrap_or_default(),
            "cname_target": r.try_get::<Option<String>,_>("cname_target").ok().flatten(),
            "raw_finding": raw_json,
        }));
    }
    let edges: Vec<Value> = edges_rows
        .into_iter()
        .map(|r| {
            json!({
                "source": r.try_get::<String,_>("from_id").unwrap_or_default(),
                "target": r.try_get::<String,_>("to_id").unwrap_or_default(),
                "edge_type": r.try_get::<String,_>("edge_type").unwrap_or_default(),
            })
        })
        .collect();
    let vuln_findings: Vec<Value> = vuln_rows
        .into_iter()
        .map(|r| {
            json!({
                "finding_id": r.try_get::<String,_>("finding_id").unwrap_or_default(),
                "title": r.try_get::<String,_>("title").unwrap_or_default(),
                "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "nodes": nodes, "edges": edges, "run_id": run_id, "vuln_findings": vuln_findings }))).into_response()
}

async fn api_client_semantic_state_machine(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"DB"}))).into_response();
    };
    let rows = sqlx::query("SELECT id, log_text, created_at FROM semantic_fuzz_log WHERE client_id = $1 ORDER BY id DESC LIMIT 200")
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;
    let logs: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "log_text": r.try_get::<String,_>("log_text").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "client_id": id, "logs": logs }))).into_response()
}

async fn api_client_semantic_reasoning(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"DB"}))).into_response();
    };
    let rows = sqlx::query("SELECT log_text FROM semantic_fuzz_log WHERE client_id = $1 ORDER BY id DESC LIMIT 30")
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;
    let joined: String = rows
        .into_iter()
        .filter_map(|r| r.try_get::<String,_>("log_text").ok())
        .collect::<Vec<_>>()
        .join("\n---\n");
    // char-safe truncation — byte slicing at 8000 panics if a multibyte UTF-8 char straddles the boundary
    let summary = if joined.len() > 8000 { format!("{}…", joined.chars().take(8000).collect::<String>()) } else { joined };
    (StatusCode::OK, Json(json!({ "client_id": id, "reasoning_text": summary }))).into_response()
}

async fn api_system_configs_get(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    // system_configs holds integration credentials; the write path is admin-gated, so the read
    // must be too (a plain GET otherwise bypasses mutation_rbac_middleware).
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    // Denylist-by-default so a newly-added secret key (e.g. slack_webhook_url) is masked without a
    // code change — the previous fixed list omitted the webhook URLs entirely.
    fn mask_config_value(key: &str, value: &str) -> String {
        let k = key.to_ascii_lowercase();
        let is_secret = k.contains("token")
            || k.contains("secret")
            || k.contains("password")
            || k.contains("webhook")
            || k.contains("routing_key")
            || k.contains("api_key")
            || k.ends_with("_key");
        if is_secret && !value.trim().is_empty() {
            return "••••••••".to_string();
        }
        value.to_string()
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!([]))).into_response();
    };
    let rows = sqlx::query("SELECT key, value, description FROM system_configs ORDER BY key")
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let key = r.try_get::<String,_>("key").unwrap_or_default();
            let raw = r.try_get::<String,_>("value").unwrap_or_default();
            json!({
                "key": key,
                "value": mask_config_value(&key, &raw),
                "description": r.try_get::<String,_>("description").unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}

async fn api_system_configs_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(arr) = body.as_array() {
        for v in arr {
            if let (Some(k), Some(val)) = (
                v.get("key").and_then(|x| x.as_str()),
                v.get("value").and_then(|x| x.as_str()),
            ) {
                pairs.push((k.to_string(), val.to_string()));
            }
        }
    } else if let Some(map) = body.get("configs").and_then(|c| c.as_object()) {
        for (k, v) in map {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                _ => v.as_str().unwrap_or("").to_string(),
            };
            pairs.push((k.clone(), s));
        }
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"updated":0}))).into_response();
    };
    let mut updated = 0u32;
    for (key, value) in pairs {
        if value.trim() == "••••••••" {
            continue;
        }
        if sqlx::query(
            "INSERT INTO system_configs (tenant_id, key, value, description) VALUES ($1, $2, $3, '') ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(auth.tenant_id)
        .bind(&key)
        .bind(&value)
        .execute(&mut *tx)
        .await
        .is_ok()
        {
            updated += 1;
        }
    }
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({ "updated": updated }))).into_response()
}

