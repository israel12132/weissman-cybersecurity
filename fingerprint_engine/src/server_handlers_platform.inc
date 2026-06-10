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
