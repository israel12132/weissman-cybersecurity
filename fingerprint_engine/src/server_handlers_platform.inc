// Platform APIs: onboarding, global search, SOC views, and UI-expected endpoints
// that were missing from the Rust server (integrations, OT/ICS rollup, mobile apps).

#[derive(Debug, Deserialize)]
struct OnboardingTargetBody {
    name: String,
    #[serde(default)]
    domains: Option<Vec<String>>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    ip_ranges: Option<Vec<String>>,
    #[serde(default)]
    contact_email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OnboardingLaunchScanBody {
    client_id: i64,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    engines: Option<Vec<String>>,
}

/// POST /api/onboarding/target — create a client with authorized scan scope.
async fn api_onboarding_target(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<OnboardingTargetBody>,
) -> Response {
    let mut domain_list: Vec<String> = body.domains.unwrap_or_default();
    if let Some(d) = body.domain {
        let t = d.trim().to_string();
        if !t.is_empty() && !domain_list.iter().any(|x| x == &t) {
            domain_list.push(t);
        }
    }
    let ip_ranges = body.ip_ranges.unwrap_or_default();
    let client_body = ClientBody {
        name: Some(body.name),
        domains: Some(serde_json::to_string(&domain_list).unwrap_or_else(|_| "[]".into())),
        tech_stack: Some("[]".into()),
        ip_ranges: Some(serde_json::to_string(&ip_ranges).unwrap_or_else(|_| "[]".into())),
        contact_email: body.contact_email,
        auto_detect_tech_stack: Some(true),
        aws_cross_account_role_arn: None,
        aws_external_id: None,
        gcp_project_id: None,
    };
    let create_resp = api_clients_create(
        State(state),
        Extension(auth),
        ConnectInfo(addr),
        headers,
        axum::extract::Json(client_body),
    )
    .await;
    if create_resp.status() != StatusCode::OK {
        return create_resp;
    }
    let bytes = axum::body::to_bytes(create_resp.into_body(), 1_048_576)
        .await
        .unwrap_or_default();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    let client_id = v.get("id").cloned().unwrap_or(Value::Null);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "id": client_id,
            "client_id": client_id,
            "domains": domain_list,
            "detail": "Scan target registered. Call POST /api/onboarding/launch-scan to start baseline engines."
        })),
    )
        .into_response()
}

/// POST /api/onboarding/launch-scan — queue baseline engines for a newly onboarded client.
async fn api_onboarding_launch_scan(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(body): Json<OnboardingLaunchScanBody>,
) -> Response {
    if body.client_id <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "client_id required"})),
        )
            .into_response();
    }
    if let Some(engines) = body.engines.as_ref() {
        if !engines.is_empty() {
            let target = body.target.clone().unwrap_or_default();
            let mut job_ids = Vec::new();
            for engine in engines {
                let scan_body = json!({
                    "engine": engine,
                    "client_id": body.client_id,
                    "target": target,
                });
                let resp = api_scan(
                    State(state.clone()),
                    Extension(auth.clone()),
                    ConnectInfo(addr),
                    headers.clone(),
                    trace_ext.clone(),
                    axum::extract::Json(scan_body),
                )
                .await;
                if resp.status() == StatusCode::ACCEPTED {
                    if let Ok(bytes) = axum::body::to_bytes(resp.into_body(), 1_048_576).await {
                        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                            if let Some(jid) = v.get("job_id").and_then(Value::as_str) {
                                job_ids.push(jid.to_string());
                            }
                        }
                    }
                }
            }
            return (
                StatusCode::ACCEPTED,
                Json(json!({
                    "ok": true,
                    "client_id": body.client_id,
                    "job_ids": job_ids,
                    "engines": engines,
                    "status_url": "/jobs",
                })),
            )
                .into_response();
        }
    }
    api_clients_scan_run_all(
        State(state),
        Extension(auth),
        Path(body.client_id),
        ConnectInfo(addr),
        headers,
        trace_ext,
    )
    .await
}

/// GET /api/search?q= — global search across clients, findings, and engines.
async fn api_global_search(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let query = q.get("q").map(|s| s.trim().to_lowercase()).unwrap_or_default();
    if query.len() < 2 {
        return (StatusCode::OK, Json(json!({ "ok": true, "results": [] }))).into_response();
    }
    let like = format!("%{}%", query.replace('%', ""));
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "results": []})),
        )
            .into_response();
    };

    let mut results: Vec<Value> = Vec::new();

    let clients = sqlx::query("SELECT id, name FROM clients WHERE lower(name) LIKE $1 ORDER BY name LIMIT 8")
        .bind(&like)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    for r in clients {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let name: String = r.try_get("name").unwrap_or_default();
        results.push(json!({
            "type": "client",
            "id": id.to_string(),
            "title": name,
            "path": format!("/clients/{}", id),
            "icon": "🏢",
        }));
    }

    let findings = sqlx::query(
        "SELECT id, title, severity, client_id::text AS client_id FROM vulnerabilities \
         WHERE lower(title) LIKE $1 OR lower(COALESCE(source,'')) LIKE $1 \
         ORDER BY discovered_at DESC LIMIT 12",
    )
    .bind(&like)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    for r in findings {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let title: String = r.try_get("title").unwrap_or_default();
        let severity: String = r.try_get("severity").unwrap_or_else(|_| "info".into());
        results.push(json!({
            "type": "finding",
            "id": id.to_string(),
            "title": title,
            "severity": severity,
            "path": "/findings",
            "icon": "🔍",
        }));
    }
    let _ = tx.commit().await;

    for engine_id in weissman_core::models::engine::production_engine_ids() {
        if engine_id.contains(&query)
            || (query.len() >= 3 && engine_id.replace('_', " ").contains(&query))
        {
            results.push(json!({
                "type": "engine",
                "id": engine_id,
                "title": engine_id.replace('_', " "),
                "path": format!("/engines/{}", engine_id),
                "icon": "⚡",
            }));
            if results.len() >= 24 {
                break;
            }
        }
    }

    const STATIC_PAGES: &[(&str, &str, &str, &str)] = &[
        ("nexus", "Nexus Sovereign Swarm", "/nexus-swarm", "🌐"),
        ("swarm", "Nexus Sovereign Swarm", "/nexus-swarm", "🌐"),
        ("sovereign", "Nexus Sovereign Swarm", "/nexus-swarm", "🌐"),
        ("agent", "Endpoint Agents", "/agents", "🖥️"),
        ("agents", "Endpoint Agents", "/agents", "🖥️"),
        ("findings", "Findings Command Center", "/findings", "🔍"),
        ("jobs", "Jobs Dashboard", "/jobs", "⏱️"),
        ("engines", "Engine Matrix", "/engines", "⚙️"),
    ];
    for (key, title, path, icon) in STATIC_PAGES {
        if key.contains(&query) || title.to_lowercase().contains(&query) {
            if !results.iter().any(|r| r.get("path").and_then(Value::as_str) == Some(*path)) {
                results.push(json!({
                    "type": "page",
                    "title": title,
                    "path": path,
                    "icon": icon,
                }));
            }
        }
    }

    (StatusCode::OK, Json(json!({ "ok": true, "results": results }))).into_response()
}

/// GET /api/integrations — configured third-party integrations (stored in system_configs).
async fn api_integrations_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"integrations": []})),
        )
            .into_response();
    };
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'integrations_registry'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let webhook: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'alert_webhook_url'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let mut integrations: Vec<Value> = raw
        .and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
        .unwrap_or_default();

    if integrations.is_empty() {
        if let Some(url) = webhook.filter(|u| !u.trim().is_empty()) {
            integrations.push(json!({
                "id": "alert_webhook",
                "name": "Alert Webhook",
                "category": "Communication",
                "status": "connected",
                "config": { "url": url },
                "last_test": null,
            }));
        }
    }

    (StatusCode::OK, Json(json!({ "ok": true, "integrations": integrations }))).into_response()
}

#[derive(Debug, Deserialize)]
struct IntegrationUpsertBody {
    id: String,
    name: String,
    category: String,
    #[serde(default)]
    config: Value,
}

async fn integrations_save(
    pool: &PgPool,
    tenant_id: i64,
    integrations: &[Value],
) -> Result<(), String> {
    let payload = serde_json::to_string(integrations).map_err(|e| e.to_string())?;
    let mut tx = db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"INSERT INTO system_configs (tenant_id, key, value, description)
           VALUES ($1, 'integrations_registry', $2, 'Third-party integration registry')
           ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value"#,
    )
    .bind(tenant_id)
    .bind(payload)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn api_integrations_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<IntegrationUpsertBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_role(&auth, crate::rbac::roles::OPERATOR) {
        return r;
    }
    let list_resp = api_integrations_list(
        State(state.clone()),
        Extension(auth.clone()),
    )
    .await;
    let mut list: Vec<Value> = vec![];
    if let Ok(bytes) = axum::body::to_bytes(list_resp.into_body(), 1_048_576).await {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            list = v
                .get("integrations")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
        }
    }
    let entry = json!({
        "id": body.id,
        "name": body.name,
        "category": body.category,
        "status": "configured",
        "config": body.config,
        "last_test": null,
    });
    list.retain(|i| i.get("id").and_then(Value::as_str) != Some(body.id.as_str()));
    list.push(entry);
    match integrations_save(&state.app_pool, auth.tenant_id, &list).await {
        Ok(()) => (StatusCode::OK, Json(json!({"ok": true, "integrations": list}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

async fn api_integrations_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = crate::rbac::require_role(&auth, crate::rbac::roles::OPERATOR) {
        return r;
    }
    let list_resp = api_integrations_list(
        State(state.clone()),
        Extension(auth.clone()),
    )
    .await;
    let mut list: Vec<Value> = vec![];
    if let Ok(bytes) = axum::body::to_bytes(list_resp.into_body(), 1_048_576).await {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            list = v
                .get("integrations")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
        }
    }
    list.retain(|i| i.get("id").and_then(Value::as_str) != Some(id.as_str()));
    match integrations_save(&state.app_pool, auth.tenant_id, &list).await {
        Ok(()) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

async fn api_integrations_test(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    let list_resp = api_integrations_list(
        State(state.clone()),
        Extension(auth),
    )
    .await;
    if let Ok(bytes) = axum::body::to_bytes(list_resp.into_body(), 1_048_576).await {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            let integrations = v.get("integrations").and_then(Value::as_array);
            if let Some(list) = integrations {
                if let Some(item) = list.iter().find(|i| i.get("id").and_then(Value::as_str) == Some(id.as_str())) {
                    if id == "alert_webhook" || item.get("category").and_then(Value::as_str) == Some("Communication") {
                        if let Some(url) = item
                            .get("config")
                            .and_then(|c| c.get("url"))
                            .and_then(Value::as_str)
                            .or_else(|| {
                                item.get("config")
                                    .and_then(|c| c.get("webhook_url"))
                                    .and_then(Value::as_str)
                            })
                        {
                            let client = reqwest::Client::builder()
                                .timeout(Duration::from_secs(8))
                                .build()
                                .unwrap_or_default();
                            let probe = json!({"event": "integration_test", "integration_id": id});
                            let ok = client
                                .post(url)
                                .json(&probe)
                                .send()
                                .await
                                .map(|r| r.status().is_success())
                                .unwrap_or(false);
                            return (
                                StatusCode::OK,
                                Json(json!({"ok": true, "success": ok, "status": if ok { "connected" } else { "error" }})),
                            )
                                .into_response();
                        }
                    }
                    return (
                        StatusCode::OK,
                        Json(json!({"ok": true, "success": true, "status": "configured"})),
                    )
                        .into_response();
                }
            }
        }
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({"ok": false, "success": false, "detail": "Integration not found"})),
    )
        .into_response()
}

/// GET /api/ot-ics/devices — tenant-wide OT/ICS fingerprint rollup.
async fn api_ot_ics_devices(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"devices": [], "protocols": []})),
        )
            .into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, client_id, host, port, protocol, vendor_hint, confidence, metadata
           FROM ot_ics_fingerprints WHERE tenant_id = $1 ORDER BY id DESC LIMIT 500"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut protocol_counts: HashMap<String, (i64, String)> = HashMap::new();
    let mut devices: Vec<Value> = Vec::new();
    for r in rows {
        let protocol: String = r.try_get("protocol").unwrap_or_else(|_| "unknown".into());
        let host: String = r.try_get("host").unwrap_or_default();
        let port: i32 = r.try_get("port").unwrap_or(0);
        let vendor: String = r.try_get("vendor_hint").unwrap_or_default();
        let confidence: f64 = r.try_get("confidence").unwrap_or(0.0);
        let device_type = if vendor.to_lowercase().contains("plc") {
            "plc"
        } else if vendor.to_lowercase().contains("scada") {
            "scada"
        } else if protocol.eq_ignore_ascii_case("modbus") {
            "plc"
        } else {
            "hmi"
        };
        devices.push(json!({
            "id": r.try_get::<i64,_>("id").unwrap_or(0),
            "client_id": r.try_get::<i64,_>("client_id").unwrap_or(0),
            "host": host,
            "port": port,
            "protocol": protocol,
            "vendor": vendor,
            "type": device_type,
            "confidence": confidence,
            "status": if confidence >= 0.7 { "verified" } else { "suspected" },
        }));
        let entry = protocol_counts.entry(protocol.clone()).or_insert((0, "info".into()));
        entry.0 += 1;
        if confidence >= 0.8 {
            entry.1 = "critical".into();
        } else if confidence >= 0.5 && entry.1 != "critical" {
            entry.1 = "warning".into();
        }
    }
    let protocols: Vec<Value> = protocol_counts
        .into_iter()
        .map(|(name, (count, status))| json!({ "name": name, "count": count, "status": status }))
        .collect();

    (StatusCode::OK, Json(json!({ "ok": true, "devices": devices, "protocols": protocols }))).into_response()
}

/// GET /api/mobile-security/apps — mobile-related findings grouped as apps.
async fn api_mobile_security_apps(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"apps": [], "findings": []})),
        )
            .into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, title, severity, source, status, client_id::text, description, discovered_at
           FROM vulnerabilities
           WHERE lower(COALESCE(source,'')) LIKE '%mobile%'
              OR lower(COALESCE(source,'')) LIKE '%android%'
              OR lower(COALESCE(source,'')) LIKE '%ios%'
              OR lower(COALESCE(title,'')) LIKE '%mobile%'
              OR lower(COALESCE(title,'')) LIKE '%android%'
              OR lower(COALESCE(title,'')) LIKE '%ios%'
           ORDER BY discovered_at DESC LIMIT 200"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut apps_map: HashMap<String, Value> = HashMap::new();
    let mut findings: Vec<Value> = Vec::new();
    for r in rows {
        let title: String = r.try_get("title").unwrap_or_default();
        let source: String = r.try_get("source").unwrap_or_default();
        let severity: String = r.try_get("severity").unwrap_or_else(|_| "info".into());
        let id: i64 = r.try_get("id").unwrap_or(0);
        let platform = if title.to_lowercase().contains("ios") || source.to_lowercase().contains("ios") {
            "ios"
        } else if title.to_lowercase().contains("android") || source.to_lowercase().contains("android") {
            "android"
        } else {
            "unknown"
        };
        let app_key = format!("{}:{}", platform, source);
        let entry = apps_map.entry(app_key.clone()).or_insert_with(|| {
            json!({
                "id": app_key,
                "name": if source.is_empty() { title.clone() } else { source.clone() },
                "package_id": source,
                "platform": platform,
                "findings_count": 0,
                "max_severity": "info",
            })
        });
        if let Some(obj) = entry.as_object_mut() {
            let count = obj.get("findings_count").and_then(Value::as_i64).unwrap_or(0) + 1;
            obj.insert("findings_count".into(), json!(count));
            let cur = obj.get("max_severity").and_then(Value::as_str).unwrap_or("info");
            if severity_rank(&severity) > severity_rank(cur) {
                obj.insert("max_severity".into(), json!(severity));
            }
        }
        findings.push(json!({
            "id": id,
            "title": title,
            "severity": severity,
            "source": source,
            "platform": platform,
            "status": r.try_get::<String,_>("status").unwrap_or_default(),
        }));
    }
    let apps: Vec<Value> = apps_map.into_values().collect();
    (StatusCode::OK, Json(json!({ "ok": true, "apps": apps, "findings": findings }))).into_response()
}

fn severity_rank(s: &str) -> i32 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn finding_status_to_incident_status(status: &str) -> &'static str {
    match status.to_ascii_lowercase().as_str() {
        "open" | "new" | "triaged" => "active",
        "in_progress" | "investigating" => "containment",
        "mitigated" | "remediated" => "eradication",
        "closed" | "resolved" | "false_positive" => "resolved",
        _ => "active",
    }
}

/// GET /api/soc/incidents — derive IR cases from critical/high findings + audit trail.
async fn api_soc_incidents(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::OK, Json(json!({"incidents": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, title, severity, source, status, client_id::text, description,
                  discovered_at, updated_at
           FROM vulnerabilities
           WHERE lower(severity) IN ('critical', 'high')
           ORDER BY discovered_at DESC LIMIT 50"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let audits = sqlx::query(
        r#"SELECT action_type, details, created_at, user_label
           FROM audit_logs WHERE tenant_id = $1
           ORDER BY created_at DESC LIMIT 30"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut incidents: Vec<Value> = Vec::new();
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let title: String = r.try_get("title").unwrap_or_default();
        let severity: String = r.try_get("severity").unwrap_or_else(|_| "high".into());
        let source: String = r.try_get("source").unwrap_or_else(|_| "Weissman Engine".into());
        let status: String = r.try_get("status").unwrap_or_else(|_| "open".into());
        let client_id: String = r.try_get("client_id").unwrap_or_else(|_| "—".into());
        let description: String = r.try_get("description").unwrap_or_default();
        let created: DateTime<Utc> = r.try_get("discovered_at").unwrap_or_else(|_| Utc::now());
        let updated: DateTime<Utc> = r
            .try_get("updated_at")
            .unwrap_or(created);

        let mut timeline = vec![json!({
            "t": created.format("%H:%M").to_string(),
            "actor": source,
            "msg": title,
        })];
        for a in audits.iter().take(5) {
            let detail: String = a.try_get("details").unwrap_or_default();
            let title_snip = title.to_lowercase();
            let title_prefix = title_snip.chars().take(12).collect::<String>();
            if detail.contains(&id.to_string())
                || (!title_prefix.is_empty() && detail.to_lowercase().contains(&title_prefix))
            {
                let ts: DateTime<Utc> = a.try_get("created_at").unwrap_or_else(|_| Utc::now());
                timeline.push(json!({
                    "t": ts.format("%H:%M").to_string(),
                    "actor": a.try_get::<String,_>("user_label").unwrap_or_else(|_| "SOC".into()),
                    "msg": a.try_get::<String,_>("action_type").unwrap_or_default(),
                }));
            }
        }

        incidents.push(json!({
            "id": format!("INC-{:04}", id),
            "finding_id": id,
            "title": title,
            "severity": severity,
            "status": finding_status_to_incident_status(&status),
            "assignee": "SOC Analyst",
            "created": created.to_rfc3339(),
            "updated": updated.to_rfc3339(),
            "source": source,
            "affectedAssets": [client_id],
            "mitre": null,
            "description": description,
            "playbook": if severity == "critical" { "zero_day" } else { "credential_stuffing" },
            "timeline": timeline,
        }));
    }
    (StatusCode::OK, Json(json!({ "ok": true, "incidents": incidents }))).into_response()
}

/// GET /api/soc/hunts — hypothesis-style hunts from finding clusters / high-signal sources.
async fn api_soc_hunts(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::OK, Json(json!({"campaigns": [], "iocs": [], "queries": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT source, COUNT(*)::bigint AS cnt,
                  MAX(severity) AS max_sev,
                  MAX(discovered_at) AS last_seen
           FROM vulnerabilities
           WHERE source IS NOT NULL AND source <> ''
           GROUP BY source
           HAVING COUNT(*) >= 2
           ORDER BY cnt DESC LIMIT 20"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let ioc_rows = sqlx::query(
        r#"SELECT title, severity, source, discovered_at
           FROM vulnerabilities
           WHERE kev_listed = true OR lower(severity) = 'critical'
           ORDER BY discovered_at DESC LIMIT 40"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let campaigns: Vec<Value> = rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let source: String = r.try_get("source").unwrap_or_default();
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let max_sev: String = r.try_get("max_sev").unwrap_or_else(|_| "medium".into());
            let last: DateTime<Utc> = r.try_get("last_seen").unwrap_or_else(|_| Utc::now());
            json!({
                "id": format!("hunt-{:03}", i + 1),
                "title": format!("Correlated activity: {}", source),
                "hypothesis": format!("Multiple findings ({cnt}) from {source} may indicate coordinated attack activity."),
                "status": if cnt >= 5 { "active" } else { "completed" },
                "analyst": "Weissman Hunt Engine",
                "started": last.format("%Y-%m-%d").to_string(),
                "mitre": [],
                "hitsFound": cnt,
                "dataSources": [source],
                "priority": max_sev,
                "color": if max_sev == "critical" { "#ef4444" } else { "#22d3ee" },
            })
        })
        .collect();

    let iocs: Vec<Value> = ioc_rows
        .into_iter()
        .map(|r| {
            json!({
                "indicator": r.try_get::<String,_>("title").unwrap_or_default(),
                "type": "finding",
                "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "last_seen": r.try_get::<DateTime<Utc>,_>("discovered_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();

    let queries: Vec<Value> = campaigns
        .iter()
        .take(8)
        .map(|c| {
            json!({
                "name": c.get("title").cloned().unwrap_or(Value::Null),
                "query": format!("source:{}", c.get("dataSources").and_then(|d| d.get(0)).unwrap_or(&Value::Null)),
                "hits": c.get("hitsFound").cloned().unwrap_or(json!(0)),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "campaigns": campaigns, "iocs": iocs, "queries": queries })),
    )
        .into_response()
}

/// GET /api/soc/kill-chains — MITRE-aligned chains from privilege escalation events.
async fn api_soc_kill_chains(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::OK, Json(json!({"chains": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT client_id, method, url, severity, kill_chain_step_order, created_at
           FROM privilege_escalation_events
           WHERE tenant_id = $1
           ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut by_client: HashMap<i64, Vec<Value>> = HashMap::new();
    for r in rows {
        let cid: i64 = r.try_get("client_id").unwrap_or(0);
        by_client.entry(cid).or_default().push(json!({
            "step": r.try_get::<i32,_>("kill_chain_step_order").unwrap_or(0),
            "method": r.try_get::<String,_>("method").unwrap_or_default(),
            "url": r.try_get::<String,_>("url").unwrap_or_default(),
            "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
            "at": r.try_get::<DateTime<Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
        }));
    }

    let chains: Vec<Value> = by_client
        .into_iter()
        .enumerate()
        .map(|(i, (client_id, steps))| {
            let max_sev = steps
                .iter()
                .filter_map(|s| s.get("severity").and_then(Value::as_str))
                .max_by(|a, b| severity_rank(a).cmp(&severity_rank(b)))
                .unwrap_or("medium");
            json!({
                "id": format!("chain-{:03}", i + 1),
                "name": format!("Client {} privilege chain", client_id),
                "severity": max_sev,
                "client_id": client_id,
                "steps": steps,
                "phase_progress": (steps.len() as f64 / 7.0 * 100.0).min(100.0),
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "ok": true, "chains": chains }))).into_response()
}

/// GET /api/soc/exploit-lab — findings with PoC / exploit synthesis output.
async fn api_soc_exploit_lab(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::OK, Json(json!({"modules": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, title, severity, source, poc_sealed, poc_commitment_sha256, discovered_at
           FROM vulnerabilities
           WHERE poc_sealed = true
              OR lower(COALESCE(source,'')) LIKE '%poe%'
              OR lower(COALESCE(source,'')) LIKE '%exploit%'
              OR lower(COALESCE(title,'')) LIKE '%rce%'
           ORDER BY discovered_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let modules: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let id: i64 = r.try_get("id").unwrap_or(0);
            let title: String = r.try_get("title").unwrap_or_default();
            let severity: String = r.try_get("severity").unwrap_or_else(|_| "medium".into());
            let sealed: bool = r.try_get("poc_sealed").unwrap_or(false);
            json!({
                "id": format!("mod-{}", id),
                "name": title,
                "engine": r.try_get::<String,_>("source").unwrap_or_else(|_| "poe_synthesis".into()),
                "severity": severity,
                "status": if sealed { "verified" } else { "detected" },
                "findings": [json!({
                    "id": id,
                    "title": title,
                    "severity": severity,
                    "poc_sealed": sealed,
                })],
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "ok": true, "modules": modules }))).into_response()
}

/// GET /api/soc/ai-patterns — attack pattern rollup from clustered findings.
async fn api_soc_ai_patterns(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::OK, Json(json!({"patterns": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT cluster_id, COUNT(*)::bigint AS cnt,
                  MAX(title) AS sample_title,
                  MAX(severity) AS max_sev,
                  MAX(source) AS source
           FROM vulnerabilities
           WHERE cluster_id IS NOT NULL
           GROUP BY cluster_id
           ORDER BY cnt DESC LIMIT 24"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let patterns: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            json!({
                "id": r.try_get::<i64,_>("cluster_id").unwrap_or(0),
                "name": r.try_get::<String,_>("sample_title").unwrap_or_default(),
                "confidence": (cnt as f64 * 0.08).min(0.98),
                "severity": r.try_get::<String,_>("max_sev").unwrap_or_else(|_| "medium".into()),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "occurrences": cnt,
                "techniques": [],
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "ok": true, "patterns": patterns }))).into_response()
}

/// GET /api/soc/social-engineering — social-engineering findings as campaigns.
async fn api_soc_social_engineering(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::OK, Json(json!({"campaigns": [], "stats": {}}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, title, severity, source, status, description, discovered_at
           FROM vulnerabilities
           WHERE lower(COALESCE(source,'')) LIKE '%phish%'
              OR lower(COALESCE(source,'')) LIKE '%social%'
              OR lower(COALESCE(title,'')) LIKE '%phish%'
              OR lower(COALESCE(title,'')) LIKE '%social%'
           ORDER BY discovered_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let campaigns: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let id: i64 = r.try_get("id").unwrap_or(0);
            json!({
                "id": format!("camp-{}", id),
                "name": r.try_get::<String,_>("title").unwrap_or_default(),
                "type": "phishing_assessment",
                "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
                "status": r.try_get::<String,_>("status").unwrap_or_default(),
                "description": r.try_get::<String,_>("description").unwrap_or_default(),
                "started_at": r.try_get::<DateTime<Utc>,_>("discovered_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();

    let stats = json!({
        "total_campaigns": campaigns.len(),
        "active": campaigns.iter().filter(|c| c.get("status").and_then(Value::as_str) == Some("open")).count(),
        "critical_findings": campaigns.iter().filter(|c| c.get("severity").and_then(Value::as_str) == Some("critical")).count(),
    });

    (StatusCode::OK, Json(json!({ "ok": true, "campaigns": campaigns, "stats": stats }))).into_response()
}

/// GET /api/soc/network-protocols — protocol exposure rollup from findings + OT fingerprints.
async fn api_soc_network_protocols(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let ot_resp = api_ot_ics_devices(State(state.clone()), Extension(auth.clone())).await;
    let mut protocols: Vec<Value> = vec![];
    if let Ok(bytes) = axum::body::to_bytes(ot_resp.into_body(), 1_048_576).await {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            if let Some(list) = v.get("protocols").and_then(Value::as_array) {
                for p in list {
                    let name = p.get("name").and_then(Value::as_str).unwrap_or("unknown");
                    let count = p.get("count").and_then(Value::as_i64).unwrap_or(0);
                    let status = p.get("status").and_then(Value::as_str).unwrap_or("info");
                    protocols.push(json!({
                        "name": name,
                        "status": if status == "critical" { "critical" } else if status == "warning" { "warning" } else if count == 0 { "secure" } else { "warning" },
                        "findings": count,
                    }));
                }
            }
        }
    }

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::OK, Json(json!({"protocols": protocols}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT
             CASE
               WHEN lower(title) LIKE '%smb%' OR lower(description) LIKE '%smb%' THEN 'SMB'
               WHEN lower(title) LIKE '%ftp%' THEN 'FTP'
               WHEN lower(title) LIKE '%smtp%' THEN 'SMTP'
               WHEN lower(title) LIKE '%ssh%' THEN 'SSH'
               WHEN lower(title) LIKE '%dns%' THEN 'DNS'
               WHEN lower(title) LIKE '%tls%' OR lower(title) LIKE '%ssl%' THEN 'TLS/SSL'
               ELSE 'HTTP/HTTPS'
             END AS proto,
             COUNT(*)::bigint AS cnt,
             MAX(severity) AS max_sev
           FROM vulnerabilities
           GROUP BY 1
           ORDER BY cnt DESC"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    for r in rows {
        let name: String = r.try_get("proto").unwrap_or_default();
        let cnt: i64 = r.try_get("cnt").unwrap_or(0);
        let max_sev: String = r.try_get("max_sev").unwrap_or_else(|_| "info".into());
        let status = if max_sev == "critical" || max_sev == "high" {
            "critical"
        } else if cnt > 3 {
            "warning"
        } else {
            "secure"
        };
        if let Some(existing) = protocols.iter_mut().find(|p| p.get("name").and_then(Value::as_str) == Some(name.as_str())) {
            if let Some(obj) = existing.as_object_mut() {
                let cur = obj.get("findings").and_then(Value::as_i64).unwrap_or(0);
                obj.insert("findings".into(), json!(cur + cnt));
            }
        } else {
            protocols.push(json!({ "name": name, "status": status, "findings": cnt }));
        }
    }

    (StatusCode::OK, Json(json!({ "ok": true, "protocols": protocols }))).into_response()
}

// --- Scan schedules (weissman_scan_schedules) ---

const SCAN_SCHEDULE_DEFAULT_ENGINES: &[&str] = &[
    "osint",
    "asm",
    "leak_hunter",
    "discovery_engine",
    "supply_chain",
    "bola_idor",
    "pki_tls",
    "waf_bypass",
    "liminal_boundary",
];

#[derive(Debug, Deserialize)]
struct ScanScheduleUpsertBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default, rename = "type")]
    schedule_type: Option<String>,
    #[serde(default)]
    cron: Option<String>,
    #[serde(default)]
    target_client: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
    #[serde(default)]
    engines: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ScanSchedulePatchBody {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "type")]
    schedule_type: Option<String>,
    #[serde(default)]
    cron: Option<String>,
    #[serde(default)]
    target_client: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
    #[serde(default)]
    engines: Option<Vec<String>>,
}

fn schedule_type_to_cron(schedule_type: &str, custom_cron: &str) -> Option<String> {
    match schedule_type.trim().to_ascii_lowercase().as_str() {
        "hourly" => Some("0 * * * *".into()),
        "daily" => Some("0 2 * * *".into()),
        "weekly" => Some("0 2 * * 0".into()),
        "monthly" => Some("0 2 1 * *".into()),
        "custom" => {
            let c = custom_cron.trim();
            if c.is_empty() {
                None
            } else {
                Some(c.to_string())
            }
        }
        _ => Some("0 2 * * *".into()),
    }
}

fn normalize_schedule_engines(engines: Option<Vec<String>>) -> Vec<String> {
    let mut out: Vec<String> = engines
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect();
    if out.is_empty() {
        out = SCAN_SCHEDULE_DEFAULT_ENGINES
            .iter()
            .map(|s| s.to_string())
            .collect();
    }
    out.sort();
    out.dedup();
    out
}

async fn resolve_schedule_client_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    _tenant_id: i64,
    client_id: Option<i64>,
    target_client: Option<&str>,
) -> Result<Option<i64>, String> {
    if let Some(cid) = client_id {
        if cid <= 0 {
            return Ok(None);
        }
        let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM clients WHERE id = $1")
            .bind(cid)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| e.to_string())?;
        return if exists.is_some() {
            Ok(Some(cid))
        } else {
            Err("client not found".into())
        };
    }
    let target = target_client.map(str::trim).unwrap_or("");
    if target.is_empty() {
        return Ok(None);
    }
    if let Ok(cid) = target.parse::<i64>() {
        if cid > 0 {
            let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM clients WHERE id = $1")
                .bind(cid)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| e.to_string())?;
            return if exists.is_some() {
                Ok(Some(cid))
            } else {
                Err("client not found".into())
            };
        }
    }
    let by_name: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM clients WHERE lower(name) = lower($1) ORDER BY id LIMIT 1",
    )
    .bind(target)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| e.to_string())?;
    by_name.ok_or_else(|| format!("client not found: {target}"))
        .map(Some)
}

fn scan_schedule_row_to_json(r: &sqlx::postgres::PgRow) -> Value {
    let schedule_type: String = r
        .try_get("schedule_type")
        .unwrap_or_else(|_| "daily".into());
    let cron: String = r.try_get("cron").unwrap_or_default();
    let client_id: Option<i64> = r.try_get("client_id").ok();
    let client_name: Option<String> = r.try_get("client_name").ok();
    let engines_raw: Value = r
        .try_get::<Value, _>("engines")
        .unwrap_or_else(|_| json!([]));
    let engines: Vec<Value> = engines_raw
        .as_array()
        .cloned()
        .unwrap_or_default();
    let last_run: Option<DateTime<Utc>> = r.try_get("last_run_at").ok();
    let next_run: Option<DateTime<Utc>> = r.try_get("next_run_at").ok();
    json!({
        "id": r.try_get::<i64, _>("id").unwrap_or(0),
        "name": r.try_get::<String, _>("name").unwrap_or_default(),
        "description": r.try_get::<String, _>("description").unwrap_or_default(),
        "enabled": r.try_get::<bool, _>("enabled").unwrap_or(true),
        "type": schedule_type,
        "cron": cron,
        "frequency": schedule_type,
        "client_id": client_id,
        "target_client": client_name.unwrap_or_default(),
        "engines": engines,
        "last_run": last_run.map(|t| t.to_rfc3339()),
        "next_run": next_run.map(|t| t.to_rfc3339()),
        "run_count": r.try_get::<i64, _>("run_count").unwrap_or(0),
        "created_at": r.try_get::<DateTime<Utc>, _>("created_at")
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
        "updated_at": r.try_get::<DateTime<Utc>, _>("updated_at")
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
    })
}

async fn fetch_scan_schedule_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    schedule_id: i64,
) -> Option<sqlx::postgres::PgRow> {
    sqlx::query(
        r#"SELECT s.id, s.tenant_id, s.client_id, s.name, s.description, s.schedule_type,
                  s.cron, s.engines, s.enabled, s.last_run_at, s.next_run_at, s.run_count,
                  s.created_at, s.updated_at, c.name AS client_name
           FROM weissman_scan_schedules s
           LEFT JOIN clients c ON c.id = s.client_id
           WHERE s.id = $1"#,
    )
    .bind(schedule_id)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten()
}

/// GET /api/scans/schedules
async fn api_scan_schedules_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"schedules": []})),
        )
            .into_response();
    };
    let rows = sqlx::query(
        r#"SELECT s.id, s.tenant_id, s.client_id, s.name, s.description, s.schedule_type,
                  s.cron, s.engines, s.enabled, s.last_run_at, s.next_run_at, s.run_count,
                  s.created_at, s.updated_at, c.name AS client_name
           FROM weissman_scan_schedules s
           LEFT JOIN clients c ON c.id = s.client_id
           ORDER BY s.created_at DESC
           LIMIT 500"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let schedules: Vec<Value> = rows.iter().map(scan_schedule_row_to_json).collect();
    (StatusCode::OK, Json(json!({ "ok": true, "schedules": schedules }))).into_response()
}

/// POST /api/scans/schedules
async fn api_scan_schedules_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<ScanScheduleUpsertBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 200 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "name must be 1..200 chars"})),
        )
            .into_response();
    }
    let schedule_type = body
        .schedule_type
        .as_deref()
        .unwrap_or("daily")
        .trim()
        .to_string();
    let Some(cron) = schedule_type_to_cron(&schedule_type, body.cron.as_deref().unwrap_or("")) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "cron expression required for custom schedules"})),
        )
            .into_response();
    };
    let engines = normalize_schedule_engines(body.engines.clone());
    let engines_json = json!(engines);
    let enabled = body.enabled.unwrap_or(true);
    let description = body.description.clone().unwrap_or_default();

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let client_id = match resolve_schedule_client_id(
        &mut tx,
        auth.tenant_id,
        body.client_id,
        body.target_client.as_deref(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": e})),
            )
                .into_response();
        }
    };

    let created: Option<(i64,)> = sqlx::query_as(
        r#"INSERT INTO weissman_scan_schedules
           (tenant_id, client_id, name, description, schedule_type, cron, engines, enabled)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(name)
    .bind(description)
    .bind(&schedule_type)
    .bind(&cron)
    .bind(engines_json)
    .bind(enabled)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let Some((schedule_id,)) = created else {
        let _ = tx.rollback().await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false}))).into_response();
    };
    let row = fetch_scan_schedule_row(&mut tx, schedule_id).await;
    let _ = tx.commit().await;
    let schedule = row
        .as_ref()
        .map(scan_schedule_row_to_json)
        .unwrap_or(json!({ "id": schedule_id }));
    (StatusCode::CREATED, Json(json!({ "ok": true, "schedule": schedule }))).into_response()
}

/// PUT /api/scans/schedules/:id
async fn api_scan_schedules_update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(schedule_id): Path<i64>,
    Json(body): Json<ScanScheduleUpsertBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 200 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "name must be 1..200 chars"})),
        )
            .into_response();
    }
    let schedule_type = body
        .schedule_type
        .as_deref()
        .unwrap_or("daily")
        .trim()
        .to_string();
    let Some(cron) = schedule_type_to_cron(&schedule_type, body.cron.as_deref().unwrap_or("")) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "cron expression required for custom schedules"})),
        )
            .into_response();
    };
    let engines = normalize_schedule_engines(body.engines.clone());
    let engines_json = json!(engines);
    let enabled = body.enabled.unwrap_or(true);
    let description = body.description.clone().unwrap_or_default();

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let client_id = match resolve_schedule_client_id(
        &mut tx,
        auth.tenant_id,
        body.client_id,
        body.target_client.as_deref(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": e})),
            )
                .into_response();
        }
    };

    let updated = sqlx::query(
        r#"UPDATE weissman_scan_schedules
           SET client_id = $1, name = $2, description = $3, schedule_type = $4, cron = $5,
               engines = $6, enabled = $7, updated_at = now()
           WHERE id = $8"#,
    )
    .bind(client_id)
    .bind(name)
    .bind(description)
    .bind(&schedule_type)
    .bind(&cron)
    .bind(engines_json)
    .bind(enabled)
    .bind(schedule_id)
    .execute(&mut *tx)
    .await;

    match updated {
        Ok(r) if r.rows_affected() == 0 => {
            let _ = tx.rollback().await;
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "detail": "schedule not found"})),
            )
                .into_response();
        }
        Err(e) => {
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response();
        }
        _ => {}
    }

    let row = fetch_scan_schedule_row(&mut tx, schedule_id).await;
    let _ = tx.commit().await;
    let schedule = row
        .as_ref()
        .map(scan_schedule_row_to_json)
        .unwrap_or(json!({ "id": schedule_id }));
    (StatusCode::OK, Json(json!({ "ok": true, "schedule": schedule }))).into_response()
}

/// PATCH /api/scans/schedules/:id
async fn api_scan_schedules_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(schedule_id): Path<i64>,
    Json(body): Json<ScanSchedulePatchBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let existing = fetch_scan_schedule_row(&mut tx, schedule_id).await;
    let Some(existing) = existing else {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "schedule not found"})),
        )
            .into_response();
    };

    let mut name = existing.try_get::<String, _>("name").unwrap_or_default();
    if let Some(n) = body.name.as_deref() {
        let t = n.trim();
        if t.is_empty() || t.len() > 200 {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "name must be 1..200 chars"})),
            )
                .into_response();
        }
        name = t.to_string();
    }
    let mut description = existing.try_get::<String, _>("description").unwrap_or_default();
    if let Some(d) = body.description.as_ref() {
        description = d.clone();
    }
    let mut schedule_type = existing
        .try_get::<String, _>("schedule_type")
        .unwrap_or_else(|_| "daily".into());
    if let Some(t) = body.schedule_type.as_deref() {
        schedule_type = t.trim().to_string();
    }
    let mut cron = existing.try_get::<String, _>("cron").unwrap_or_default();
    if body.schedule_type.is_some() || body.cron.is_some() {
        let custom = body.cron.as_deref().unwrap_or(&cron);
        if let Some(c) = schedule_type_to_cron(&schedule_type, custom) {
            cron = c;
        }
    }
    let mut enabled = existing.try_get::<bool, _>("enabled").unwrap_or(true);
    if let Some(e) = body.enabled {
        enabled = e;
    }
    let mut client_id: Option<i64> = existing.try_get("client_id").ok();
    if body.client_id.is_some() || body.target_client.is_some() {
        client_id = match resolve_schedule_client_id(
            &mut tx,
            auth.tenant_id,
            body.client_id,
            body.target_client.as_deref(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"ok": false, "detail": e})),
                )
                    .into_response();
            }
        };
    }
    let mut engines_json = existing
        .try_get::<Value, _>("engines")
        .unwrap_or_else(|_| json!([]));
    if let Some(engines) = body.engines.clone() {
        engines_json = json!(normalize_schedule_engines(Some(engines)));
    }

    let updated = sqlx::query(
        r#"UPDATE weissman_scan_schedules
           SET client_id = $1, name = $2, description = $3, schedule_type = $4, cron = $5,
               engines = $6, enabled = $7, updated_at = now()
           WHERE id = $8"#,
    )
    .bind(client_id)
    .bind(&name)
    .bind(&description)
    .bind(&schedule_type)
    .bind(&cron)
    .bind(engines_json)
    .bind(enabled)
    .bind(schedule_id)
    .execute(&mut *tx)
    .await;

    if updated.is_err() {
        let _ = tx.rollback().await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false}))).into_response();
    }

    let row = fetch_scan_schedule_row(&mut tx, schedule_id).await;
    let _ = tx.commit().await;
    let schedule = row
        .as_ref()
        .map(scan_schedule_row_to_json)
        .unwrap_or(json!({ "id": schedule_id }));
    (StatusCode::OK, Json(json!({ "ok": true, "schedule": schedule }))).into_response()
}

/// DELETE /api/scans/schedules/:id
async fn api_scan_schedules_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(schedule_id): Path<i64>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query("DELETE FROM weissman_scan_schedules WHERE id = $1")
        .bind(schedule_id)
        .execute(&mut *tx)
        .await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() == 0 => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "schedule not found"})),
        )
            .into_response(),
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": e.to_string()})),
        )
            .into_response(),
    }
}

/// POST /api/scans/schedules/:id/run — enqueue scheduled engines immediately.
async fn api_scan_schedules_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(schedule_id): Path<i64>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = fetch_scan_schedule_row(&mut tx, schedule_id).await;
    let Some(row) = row else {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "schedule not found"})),
        )
            .into_response();
    };
    if !row.try_get::<bool, _>("enabled").unwrap_or(false) {
        let _ = tx.rollback().await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "schedule is paused"})),
        )
            .into_response();
    }
    let client_id: Option<i64> = row.try_get("client_id").ok();
    let Some(client_id) = client_id else {
        let _ = tx.rollback().await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "schedule has no target client"})),
        )
            .into_response();
    };
    let engines: Vec<String> = row
        .try_get::<Value, _>("engines")
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_else(|| normalize_schedule_engines(None));
    let domains_raw: Option<String> = sqlx::query_scalar("SELECT domains FROM clients WHERE id = $1")
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let domains: Vec<String> = domains_raw
        .as_deref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if domains.is_empty() {
        let _ = tx.rollback().await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "detail": "Target client has no authorized domains configured",
            })),
        )
            .into_response();
    }

    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let schedule_name = row.try_get::<String, _>("name").unwrap_or_default();
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "scan_schedule_run",
        &format!("schedule_id={schedule_id} name={schedule_name} client_id={client_id}"),
        &ip,
    )
    .await;

    let _ = sqlx::query(
        r#"UPDATE weissman_scan_schedules
           SET last_run_at = now(), run_count = run_count + 1, updated_at = now()
           WHERE id = $1"#,
    )
    .bind(schedule_id)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;

    let mut queued: Vec<Value> = Vec::new();
    for domain in &domains {
        let target = if domain.starts_with("http://") || domain.starts_with("https://") {
            domain.clone()
        } else {
            format!("http://{domain}")
        };
        for engine in &engines {
            let payload = json!({
                "engine": engine,
                "target": target,
                "client_id": client_id,
                "schedule_id": schedule_id,
            });
            match crate::async_jobs::enqueue(
                state.app_pool.as_ref(),
                auth.tenant_id,
                "command_center_engine",
                payload,
                trace_ext.as_ref().map(|Extension(t)| t.0.clone()),
            )
            .await
            {
                Ok(job_id) => {
                    queued.push(json!({
                        "engine": engine,
                        "target": target,
                        "job_id": job_id.to_string(),
                        "status_url": format!("/api/jobs/{}", job_id),
                    }));
                }
                Err(e) => {
                    tracing::error!(
                        target: "scan_schedules",
                        schedule_id = schedule_id,
                        engine = %engine,
                        error = %e,
                        "enqueue scheduled scan job failed"
                    );
                }
            }
        }
    }

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": true,
            "schedule_id": schedule_id,
            "client_id": client_id,
            "jobs_queued": queued.len(),
            "jobs": queued,
        })),
    )
        .into_response()
}

// ── Frontend API aliases (React pages expect paths that differ from client-scoped routes) ──

#[derive(Debug, Deserialize, Default)]
struct ClientIdAliasQuery {
    #[serde(default)]
    client_id: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
struct SbomExportAliasQuery {
    #[serde(default)]
    client_id: Option<i64>,
    #[serde(default = "default_sbom_export_format")]
    format: String,
}

fn default_sbom_export_format() -> String {
    "cyclonedx".to_string()
}

/// Resolve `client_id` from query param, else first tenant client (ORDER BY id).
async fn resolve_alias_client_id(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<i64, Response> {
    if let Some(cid) = client_id.filter(|&id| id > 0) {
        return Ok(cid);
    }
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable"})),
        )
            .into_response());
    };
    let cid: Option<i64> = sqlx::query_scalar("SELECT id FROM clients ORDER BY id ASC LIMIT 1")
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let _ = tx.commit().await;
    cid.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "detail": "No clients in tenant; pass ?client_id=<id>"
            })),
        )
            .into_response()
    })
}

fn risk_score_to_severity(score: i32) -> &'static str {
    if score >= 80 {
        "critical"
    } else if score >= 60 {
        "high"
    } else if score >= 40 {
        "medium"
    } else {
        "low"
    }
}

/// Reshape `/api/clients/:id/risk-graph` payload for RiskGraphVisualization (`name`, `severity`, edge `source`/`target`).
fn reshape_risk_graph_for_ui(v: Value) -> Value {
    let nodes_in = v.get("nodes").and_then(Value::as_array).cloned().unwrap_or_default();
    let edges_in = v.get("edges").and_then(Value::as_array).cloned().unwrap_or_default();
    let choke_ids: std::collections::HashSet<i64> = nodes_in
        .iter()
        .filter(|n| n.get("is_choke_point").and_then(Value::as_bool).unwrap_or(false))
        .filter_map(|n| n.get("id").and_then(Value::as_i64))
        .collect();
    let nodes: Vec<Value> = nodes_in
        .into_iter()
        .map(|n| {
            let id = n.get("id").cloned().unwrap_or(Value::Null);
            let label = n
                .get("label")
                .and_then(Value::as_str)
                .or_else(|| n.get("graph_key").and_then(Value::as_str))
                .unwrap_or("asset");
            let risk_score = n.get("risk_score").and_then(Value::as_i64).unwrap_or(0) as i32;
            json!({
                "id": id,
                "name": label,
                "label": label,
                "node_type": n.get("node_type").cloned().unwrap_or(Value::Null),
                "risk_score": risk_score,
                "severity": risk_score_to_severity(risk_score),
                "is_choke_point": n.get("is_choke_point").cloned().unwrap_or(Value::Bool(false)),
                "metadata": n.get("metadata").cloned().unwrap_or(json!({})),
            })
        })
        .collect();
    let edges: Vec<Value> = edges_in
        .into_iter()
        .map(|e| {
            let from = e.get("from_node_id").cloned().unwrap_or(Value::Null);
            let to = e.get("to_node_id").cloned().unwrap_or(Value::Null);
            let to_id = e.get("to_node_id").and_then(Value::as_i64);
            json!({
                "id": e.get("id").cloned().unwrap_or(Value::Null),
                "source": from,
                "target": to,
                "from_node_id": from,
                "to_node_id": to,
                "edge_type": e.get("edge_type").cloned().unwrap_or(Value::Null),
                "critical": to_id.map(|id| choke_ids.contains(&id)).unwrap_or(false),
                "metadata": e.get("metadata").cloned().unwrap_or(json!({})),
            })
        })
        .collect();
    json!({ "nodes": nodes, "edges": edges })
}

/// GET /api/risk/graph — alias for `/api/clients/:id/risk-graph` (optional `?client_id=`).
async fn api_risk_graph_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<ClientIdAliasQuery>,
) -> Response {
    let client_id = match resolve_alias_client_id(&state.app_pool, auth.tenant_id, q.client_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let resp = api_risk_graph_get(
        State(state),
        Extension(auth),
        Path(client_id),
    )
    .await;
    let status = resp.status();
    let bytes = match axum::body::to_bytes(resp.into_body(), 4_194_304).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"nodes": [], "edges": []})),
            )
                .into_response();
        }
    };
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(json!({"nodes": [], "edges": []}));
    (status, Json(reshape_risk_graph_for_ui(v))).into_response()
}

/// GET /api/sbom/components — alias for `/api/clients/:id/sbom/components`.
async fn api_sbom_components_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<ClientIdAliasQuery>,
) -> Response {
    let client_id = match resolve_alias_client_id(&state.app_pool, auth.tenant_id, q.client_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    api_client_sbom_list(State(state), Extension(auth), Path(client_id)).await
}

/// Build SPDX or CycloneDX export from live `client_sbom_components` rows.
async fn sbom_export_for_client(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    format: &str,
) -> Result<(HeaderMap, String), Response> {
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable"})),
        )
            .into_response());
    };
    let rows = sqlx::query(
        "SELECT package_name, ecosystem, version_spec, source, created_at FROM client_sbom_components WHERE client_id = $1 ORDER BY id",
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": e.to_string()})),
        )
            .into_response()
    })?;
    let _ = tx.commit().await;

    let fmt = format.trim().to_ascii_lowercase();
    let (content_type, filename, body) = if fmt == "spdx" {
        let mut lines = vec![
            "SPDXVersion: SPDX-2.3".to_string(),
            "DataLicense: CC0-1.0".to_string(),
            format!("SPDXID: SPDXRef-DOCUMENT-{}", client_id),
            "DocumentName: Weissman-SBOM".to_string(),
            format!(
                "Created: {}",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
            ),
        ];
        for (i, r) in rows.iter().enumerate() {
            let name: String = r.try_get("package_name").unwrap_or_default();
            let ver: String = r.try_get("version_spec").unwrap_or_else(|_| "*".into());
            let eco: String = r.try_get("ecosystem").unwrap_or_default();
            lines.push(format!("PackageName: {name}"));
            lines.push(format!("PackageVersion: {ver}"));
            lines.push(format!("PackageDownloadLocation: NOASSERTION"));
            lines.push(format!("SPDXID: SPDXRef-Package-{i}"));
            if !eco.is_empty() {
                lines.push(format!("ExternalRef: PACKAGE-MANAGER {eco}"));
            }
            lines.push(String::new());
        }
        (
            "text/spdx; charset=utf-8",
            "sbom.spdx",
            lines.join("\n"),
        )
    } else {
        let components: Vec<Value> = rows
            .iter()
            .map(|r| {
                let name: String = r.try_get("package_name").unwrap_or_default();
                let ver: String = r.try_get("version_spec").unwrap_or_else(|_| "*".into());
                let eco: String = r.try_get("ecosystem").unwrap_or_default();
                let source: String = r.try_get("source").unwrap_or_default();
                let mut comp = json!({
                    "type": "library",
                    "name": name,
                    "version": ver,
                });
                if !eco.is_empty() {
                    comp["purl"] = json!(format!("pkg:{}/{}@{}", eco, name, ver));
                }
                if !source.is_empty() {
                    comp["properties"] = json!([{ "name": "weissman:source", "value": source }]);
                }
                comp
            })
            .collect();
        let doc = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": format!("urn:uuid:weissman-sbom-{}-{}", tenant_id, client_id),
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": format!("weissman-client-{client_id}"),
                }
            },
            "components": components,
        });
        (
            "application/vnd.cyclonedx+json",
            "sbom.cyclonedx.json",
            serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()),
        )
    };

    let mut headers = HeaderMap::new();
    let _ = headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap_or_else(|_| HeaderValue::from_static("application/json")));
    let _ = headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    Ok((headers, body))
}

/// GET /api/clients/:id/sbom/export — live SBOM export (SPDX tag-value or CycloneDX JSON).
async fn api_client_sbom_export(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<SbomExportAliasQuery>,
) -> Response {
    match sbom_export_for_client(
        &state.app_pool,
        auth.tenant_id,
        client_id,
        &q.format,
    )
    .await
    {
        Ok((headers, body)) => (headers, body).into_response(),
        Err(resp) => resp,
    }
}

/// GET /api/sbom/export — alias for `/api/clients/:id/sbom/export` (`?client_id=&format=spdx|cyclonedx`).
async fn api_sbom_export_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<SbomExportAliasQuery>,
) -> Response {
    let client_id = match resolve_alias_client_id(&state.app_pool, auth.tenant_id, q.client_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match sbom_export_for_client(
        &state.app_pool,
        auth.tenant_id,
        client_id,
        &q.format,
    )
    .await
    {
        Ok((headers, body)) => (headers, body).into_response(),
        Err(resp) => resp,
    }
}

/// GET /api/containment/rules — alias for `/api/clients/:id/containment-rules`.
async fn api_containment_rules_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<ClientIdAliasQuery>,
) -> Response {
    let client_id = match resolve_alias_client_id(&state.app_pool, auth.tenant_id, q.client_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    api_containment_rules_list(State(state), Extension(auth), Path(client_id)).await
}

/// GET /api/identity/contexts — alias for `/api/clients/:id/identity-contexts` with UI field names.
async fn api_identity_contexts_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<ClientIdAliasQuery>,
) -> Response {
    let client_id = match resolve_alias_client_id(&state.app_pool, auth.tenant_id, q.client_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"identities": []})),
        )
            .into_response();
    };
    let rows = sqlx::query(
        "SELECT id, role_name, privilege_order, token_type, created_at FROM identity_contexts WHERE client_id = $1 ORDER BY privilege_order DESC, id",
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let esc_rows = sqlx::query(
        r#"SELECT from_context, to_context FROM privilege_escalation_events WHERE client_id = $1"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut anomaly_by_role: std::collections::HashMap<String, i64> =
        std::collections::HashMap::new();
    for r in esc_rows {
        for col in ["from_context", "to_context"] {
            if let Ok(ctx) = r.try_get::<String, _>(col) {
                if !ctx.is_empty() {
                    *anomaly_by_role.entry(ctx).or_insert(0) += 1;
                }
            }
        }
    }

    let identities: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let id: i64 = r.try_get("id").unwrap_or(0);
            let role: String = r.try_get("role_name").unwrap_or_default();
            let priv_order: i32 = r.try_get("privilege_order").unwrap_or(0);
            let token_type: String = r.try_get("token_type").unwrap_or_default();
            let created: String = r
                .try_get::<DateTime<Utc>, _>("created_at")
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            let risk_score = (priv_order.saturating_mul(10)).clamp(0, 100);
            let anomaly_count = anomaly_by_role.get(&role).copied().unwrap_or(0);
            json!({
                "id": id,
                "username": role,
                "email": format!("{role}@client-{client_id}.local"),
                "role_name": role,
                "token_type": token_type,
                "privilege_order": priv_order,
                "is_privileged": priv_order >= 50,
                "risk_score": risk_score,
                "anomaly_count": anomaly_count,
                "last_login": created,
                "created_at": created,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "identities": identities }))).into_response()
}

fn vault_row_to_secret(row: &Value) -> Value {
    let id = row.get("id").cloned().unwrap_or(Value::Null);
    let tech = row
        .get("tech_fingerprint")
        .and_then(Value::as_str)
        .unwrap_or("");
    let component = row
        .get("component_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let remediation = row
        .get("remediation_patch")
        .and_then(Value::as_str)
        .unwrap_or("");
    let detection = row
        .get("detection_signature")
        .and_then(Value::as_str)
        .unwrap_or("");
    let severity = row
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info");
    let name = if !component.is_empty() {
        component.to_string()
    } else if !tech.is_empty() {
        tech.to_string()
    } else {
        format!("vault-{}", id.as_i64().unwrap_or(0))
    };
    let secret_type = if detection.to_ascii_lowercase().contains("cert")
        || tech.to_ascii_lowercase().contains("cert")
    {
        "certificate"
    } else if remediation.to_ascii_lowercase().contains("password")
        || token_type_password_hint(tech)
    {
        "password"
    } else {
        "api_key"
    };
    let value = if !detection.is_empty() {
        detection.to_string()
    } else {
        remediation.to_string()
    };
    json!({
        "id": id,
        "name": name,
        "description": if remediation.is_empty() { tech } else { remediation },
        "type": secret_type,
        "value": value,
        "severity": severity,
        "tech_fingerprint": tech,
        "component_ref": component,
        "created_at": row.get("created_at").cloned().unwrap_or(Value::Null),
        "expires_at": Value::Null,
        "last_accessed": Value::Null,
    })
}

fn token_type_password_hint(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("password") || l.contains("credential") || l.contains("secret")
}

/// GET /api/ceo/vault/secrets — alias for `/api/ceo/vault` with `{ secrets: [...] }` envelope.
async fn api_ceo_vault_secrets_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match crate::ceo::vault::list_vault_rows(state.app_pool.as_ref(), auth.tenant_id, 500, 0).await {
        Ok(rows) => {
            let secrets: Vec<Value> = rows
                .iter()
                .map(|row| {
                    vault_row_to_secret(&json!({
                        "id": row.id,
                        "tech_fingerprint": row.tech_fingerprint,
                        "component_ref": row.component_ref,
                        "remediation_patch": row.remediation_patch,
                        "detection_signature": row.detection_signature,
                        "severity": row.severity,
                        "created_at": row.created_at,
                    }))
                })
                .collect();
            (StatusCode::OK, Json(json!({ "secrets": secrets }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string(), "secrets": [] })),
        )
            .into_response(),
    }
}

/// POST /api/containment/rules — alias for `/api/clients/:id/containment-rules`.
async fn api_containment_rules_post_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<ClientIdAliasQuery>,
    Json(body): Json<ContainmentRuleBody>,
) -> Response {
    let client_id = match resolve_alias_client_id(&state.app_pool, auth.tenant_id, q.client_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    api_containment_rules_post(State(state), Extension(auth), Path(client_id), Json(body)).await
}

/// PATCH/PUT /api/containment/rules/:id — update rule by id (tenant-scoped).
async fn api_containment_rules_patch_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<i64>,
    Json(body): Json<ContainmentRulePatchBody>,
) -> Response {
    api_containment_rules_patch(State(state), Extension(auth), Path(rule_id), Json(body)).await
}

/// DELETE /api/containment/rules/:id — delete rule by id (tenant-scoped).
async fn api_containment_rules_delete_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<i64>,
) -> Response {
    api_containment_rules_delete(State(state), Extension(auth), Path(rule_id)).await
}

/// POST /api/ceo/vault/secrets — map CeoVault form to genesis_vaccine_vault insert.
async fn api_ceo_vault_secrets_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<crate::ceo::vault::VaultSecretBody>,
) -> Response {
    if body.name.trim().is_empty() || body.value.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": "name and value required" })),
        )
            .into_response();
    }
    let insert = crate::ceo::vault::secret_body_to_vault_insert(&body);
    match crate::ceo::vault::post_vault_row(state.app_pool.as_ref(), auth.tenant_id, &insert).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "ok": true, "id": id }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

/// PUT /api/ceo/vault/secrets/:id — update vault secret mapped from CeoVault form.
async fn api_ceo_vault_secrets_put(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<crate::ceo::vault::VaultSecretBody>,
) -> Response {
    if body.name.trim().is_empty() || body.value.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": "name and value required" })),
        )
            .into_response();
    }
    match crate::ceo::vault::update_vault_row(state.app_pool.as_ref(), auth.tenant_id, id, &body)
        .await
    {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true, "id": id }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": "not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

/// DELETE /api/ceo/vault/secrets/:id
async fn api_ceo_vault_secrets_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    match crate::ceo::vault::delete_vault_row(state.app_pool.as_ref(), auth.tenant_id, id).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "ok": true, "id": id }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": "not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_ceo_vault_secrets_audit(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    action: &'static str,
) -> Response {
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            action,
            &format!("ceo_vault_secret_id={id}"),
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }
    (StatusCode::OK, Json(json!({ "ok": true, "id": id }))).into_response()
}

/// POST /api/ceo/vault/secrets/:id/access — audit log secret reveal.
async fn api_ceo_vault_secrets_access(
    state: State<Arc<AppState>>,
    auth: Extension<AuthContext>,
    addr: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    api_ceo_vault_secrets_audit(state, auth, addr, headers, Path(id), "ceo_vault_secret_access")
        .await
}

/// POST /api/ceo/vault/secrets/:id/copy — audit log secret copy.
async fn api_ceo_vault_secrets_copy(
    state: State<Arc<AppState>>,
    auth: Extension<AuthContext>,
    addr: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    api_ceo_vault_secrets_audit(state, auth, addr, headers, Path(id), "ceo_vault_secret_copy")
        .await
}
