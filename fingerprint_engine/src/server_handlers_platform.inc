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
        engagement_modules: None,
        onboarding: None,
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
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
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

/// Load the raw (UNREDACTED) integrations registry for a tenant. Write paths MUST use this rather
/// than round-tripping through `api_integrations_list`, whose redaction replaces every secret with
/// a "••••••••" placeholder that would then be persisted over the real encrypted credential.
async fn load_integrations_raw(state: &Arc<AppState>, tenant_id: i64) -> Vec<Value> {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, tenant_id).await else {
        return vec![];
    };
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'integrations_registry'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    raw.and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
        .unwrap_or_default()
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
        .unwrap_or_default()
        .into_iter()
        .map(|mut item| {
            if let Some(config) = item.get("config") {
                item["config"] = crate::soar::integrations_vault::redact_config(config);
            }
            item
        })
        .collect();

    if integrations.is_empty() {
        if let Some(url) = webhook.filter(|u| !u.trim().is_empty()) {
            let _ = url; // the URL is a bearer credential — expose only that it is configured.
            integrations.push(json!({
                "id": "alert_webhook",
                "name": "Alert Webhook",
                "category": "Communication",
                "status": "connected",
                "config": { "url": "••••••••", "configured": true },
                "last_test": null,
            }));
        }
    }

    (StatusCode::OK, Json(json!({
        "ok": true,
        "integrations": integrations,
        "soar_adapters": crate::soar::adapters::REGISTERED_ADAPTER_IDS,
        "adapter_count": crate::soar::adapters::registered_adapter_count(),
        "vault_enabled": std::env::var("WEISSMAN_INTEGRATIONS_VAULT_KEY")
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
            || std::env::var("WEISSMAN_VAULT_KEY").map(|s| !s.trim().is_empty()).unwrap_or(false),
    }))).into_response()
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
    // Load the UNREDACTED registry so other integrations' encrypted credentials survive this write.
    let mut list: Vec<Value> = load_integrations_raw(&state, auth.tenant_id).await;
    let entry = json!({
        "id": body.id,
        "name": body.name,
        "category": body.category,
        "type": body.id,
        "status": "configured",
        "config": crate::soar::integrations_vault::encrypt_config(&body.config),
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
    // Load the UNREDACTED registry so the surviving integrations keep their real credentials.
    let mut list: Vec<Value> = load_integrations_raw(&state, auth.tenant_id).await;
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
    body: Option<Json<Value>>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let dry_run = body
        .as_ref()
        .and_then(|b| b.get("dry_run"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let list_resp = api_integrations_list(
        State(state.clone()),
        Extension(auth.clone()),
    )
    .await;
    if let Ok(bytes) = axum::body::to_bytes(list_resp.into_body(), 1_048_576).await {
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            if let Some(list) = v.get("integrations").and_then(Value::as_array) {
                if let Some(item) = list.iter().find(|i| i.get("id").and_then(Value::as_str) == Some(id.as_str())) {
                    return integration_live_test(&state.app_pool, auth.tenant_id, id.as_str(), item, dry_run).await;
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

async fn integration_live_test(
    pool: &PgPool,
    tenant_id: i64,
    id: &str,
    item: &Value,
    dry_run: bool,
) -> Response {
    let provider = item
        .get("type")
        .or_else(|| item.get("id"))
        .and_then(Value::as_str)
        .unwrap_or(id)
        .to_ascii_lowercase();
    let config_raw = item.get("config").cloned().unwrap_or(json!({}));
    let integrations = crate::soar::integrations::load_integrations(pool, tenant_id).await;
    let record = integrations
        .into_iter()
        .find(|i| i.id == id || i.provider_type == provider)
        .unwrap_or_else(|| crate::soar::integrations::IntegrationRecord {
            id: id.to_string(),
            provider_type: provider.clone(),
            config: crate::soar::integrations_vault::decrypt_config(&config_raw),
        });

    let evidence = crate::soar::types::ThreatEvidence {
        finding_id: None,
        title: "Integration connectivity test".into(),
        severity: "info".into(),
        source: "integration_test".into(),
        target: "weissman-test".into(),
        cve: None,
        signature_hash: None,
        cvss: None,
        epss: None,
        kev: false,
        internet_exposed: false,
        trigger_kind: "integration_test".into(),
    };
    let cmd = crate::soar::engine::build_command(
        match provider.as_str() {
            "slack" => "slack_notify",
            "servicenow" => "create_incident",
            "github" => "open_pr",
            "aws_ec2" | "aws" => "isolate_host",
            "azure_vm" | "azure" => "isolate_host",
            "crowdstrike_falcon" | "crowdstrike" => "isolate_host",
            "opsgenie" | "pagerduty" => "page_oncall",
            _ => "page_oncall",
        },
        tenant_id,
        None,
        None,
        "weissman-integration-test".into(),
        json!({ "template": "Weissman integration test for {{title}}" }),
        evidence,
        dry_run,
    );

    if provider == "alert_webhook" || item.get("category").and_then(Value::as_str) == Some("Communication") {
        if let Some(url) = record.config.get("url").and_then(Value::as_str) {
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
                Json(json!({"ok": true, "success": ok, "status": if ok { "connected" } else { "error" }, "provider": provider})),
            )
                .into_response();
        }
    }

    match crate::soar::adapters::dispatch(&cmd, pool, &record).await {
        Ok(outcome) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "success": true,
                "status": "connected",
                "provider": provider,
                "detail": outcome.detail,
                "dry_run": dry_run,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "success": false,
                "status": "error",
                "provider": provider,
                "detail": e.to_string(),
            })),
        )
            .into_response(),
    }
}

fn ot_ics_infer_device_type(protocol: &str, vendor: &str) -> &'static str {
    let p = protocol.to_ascii_lowercase();
    let v = vendor.to_ascii_lowercase();
    if v.contains("plc") || p.contains("modbus") || p.contains("s7") || p.contains("profinet") {
        "plc"
    } else if v.contains("scada") || p.contains("scada") {
        "scada"
    } else if p.contains("dnp3") || p.contains("rtu") {
        "rtu"
    } else {
        "hmi"
    }
}

fn ot_ics_protocol_from_text(text: &str, source: &str) -> String {
    let blob = format!("{} {}", text, source).to_ascii_lowercase();
    if blob.contains("modbus") {
        "Modbus".into()
    } else if blob.contains("bacnet") {
        "BACnet".into()
    } else if blob.contains("opc-ua") || blob.contains("opcua") {
        "OPC-UA".into()
    } else if blob.contains("dnp3") {
        "DNP3".into()
    } else if blob.contains("s7") || blob.contains("siemens") {
        "S7".into()
    } else if blob.contains("ethernet/ip") || blob.contains("enip") {
        "EtherNet/IP".into()
    } else if blob.contains("iec 61850") || blob.contains("iec61850") || blob.contains("mms") {
        "IEC 61850".into()
    } else if blob.contains("mqtt") {
        "MQTT".into()
    } else if blob.contains("scada") || blob.contains("ics") || blob.contains("ot/") {
        "SCADA/ICS".into()
    } else {
        "unknown".into()
    }
}

fn ot_ics_parse_host_port(text: &str) -> (String, i32) {
    let mut host = String::new();
    let mut port: i32 = 0;
    for token in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != ':') {
        if token.contains(':') {
            let parts: Vec<&str> = token.split(':').collect();
            if parts.len() == 2 {
                let h = parts[0].trim();
                if h.contains('.') || h.chars().any(|c| c.is_ascii_alphabetic()) {
                    host = h.to_string();
                    port = parts[1].parse().unwrap_or(0);
                }
            }
        } else if token.contains('.')
            && token.split('.').count() == 4
            && token.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            host = token.to_string();
        }
    }
    (host, port)
}

fn ot_ics_device_key(host: &str, port: i32, protocol: &str) -> String {
    format!("{}:{}:{}", host.to_ascii_lowercase(), port, protocol.to_ascii_lowercase())
}

fn ot_ics_severity_to_confidence(severity: &str) -> f64 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 0.92,
        "high" => 0.78,
        "medium" => 0.55,
        "low" => 0.35,
        _ => 0.25,
    }
}

fn ot_ics_push_device(
    devices: &mut Vec<Value>,
    seen: &mut HashMap<String, ()>,
    protocol_counts: &mut HashMap<String, (i64, String)>,
    id: i64,
    client_id: i64,
    host: &str,
    port: i32,
    protocol: &str,
    vendor: &str,
    confidence: f64,
    source: &str,
) {
    let host = if host.is_empty() { "unknown".into() } else { host.to_string() };
    let protocol = if protocol.is_empty() || protocol == "unknown" {
        ot_ics_protocol_from_text("", source)
    } else {
        protocol.to_string()
    };
    let key = ot_ics_device_key(&host, port, &protocol);
    if seen.contains_key(&key) {
        return;
    }
    seen.insert(key, ());
    let device_type = ot_ics_infer_device_type(&protocol, vendor);
    let status = if confidence >= 0.7 { "verified" } else { "suspected" };
    devices.push(json!({
        "id": id,
        "client_id": client_id,
        "host": host,
        "ip": host,
        "name": if vendor.is_empty() { format!("{}:{}", host, port.max(0)) } else { format!("{} ({})", vendor, host) },
        "port": port,
        "protocol": protocol,
        "vendor": vendor,
        "type": device_type,
        "confidence": confidence,
        "status": status,
        "source": source,
    }));
    let entry = protocol_counts
        .entry(protocol.clone())
        .or_insert((0, "info".into()));
    entry.0 += 1;
    if confidence >= 0.8 {
        entry.1 = "critical".into();
    } else if confidence >= 0.5 && entry.1 != "critical" {
        entry.1 = "warning".into();
    }
}

/// GET /api/ot-ics/devices — tenant-wide OT/ICS fingerprint rollup.
async fn api_ot_ics_devices(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"devices": [], "protocols": [], "findings": []})),
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

    let finding_rows = sqlx::query(
        r#"SELECT id, client_id, title, severity, source, status, description, discovered_at
           FROM vulnerabilities
           WHERE lower(COALESCE(source,'')) LIKE '%scada%'
              OR lower(COALESCE(source,'')) LIKE '%modbus%'
              OR lower(COALESCE(source,'')) LIKE '%bacnet%'
              OR lower(COALESCE(source,'')) LIKE '%opcua%'
              OR lower(COALESCE(source,'')) LIKE '%opc-ua%'
              OR lower(COALESCE(source,'')) LIKE '%ot_ics%'
              OR lower(COALESCE(source,'')) LIKE '%dnp3%'
              OR lower(COALESCE(source,'')) LIKE '%iec61850%'
              OR lower(COALESCE(source,'')) LIKE '%profinet%'
              OR lower(COALESCE(source,'')) LIKE '%mqtt%'
              OR lower(COALESCE(title,'')) LIKE '%modbus%'
              OR lower(COALESCE(title,'')) LIKE '%bacnet%'
              OR lower(COALESCE(title,'')) LIKE '%opc-ua%'
              OR lower(COALESCE(title,'')) LIKE '%opc ua%'
              OR lower(COALESCE(title,'')) LIKE '%scada%'
              OR lower(COALESCE(title,'')) LIKE '%dnp3%'
              OR lower(COALESCE(title,'')) LIKE '%ot/ics%'
              OR lower(COALESCE(description,'')) LIKE '%modbus%'
              OR lower(COALESCE(description,'')) LIKE '%bacnet%'
              OR lower(COALESCE(description,'')) LIKE '%opc-ua%'
           ORDER BY discovered_at DESC LIMIT 300"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut protocol_counts: HashMap<String, (i64, String)> = HashMap::new();
    let mut devices: Vec<Value> = Vec::new();
    let mut seen: HashMap<String, ()> = HashMap::new();
    let mut findings: Vec<Value> = Vec::new();

    for r in rows {
        let protocol: String = r.try_get("protocol").unwrap_or_else(|_| "unknown".into());
        let host: String = r.try_get("host").unwrap_or_default();
        let port: i32 = r.try_get("port").unwrap_or(0);
        let vendor: String = r.try_get("vendor_hint").unwrap_or_default();
        let confidence: f64 = r.try_get("confidence").unwrap_or(0.0);
        ot_ics_push_device(
            &mut devices,
            &mut seen,
            &mut protocol_counts,
            r.try_get::<i64, _>("id").unwrap_or(0),
            r.try_get::<i64, _>("client_id").unwrap_or(0),
            &host,
            port,
            &protocol,
            &vendor,
            confidence,
            "ot_ics_fingerprints",
        );
    }

    for r in finding_rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let client_id: i64 = r.try_get("client_id").unwrap_or(0);
        let title: String = r.try_get("title").unwrap_or_default();
        let source: String = r.try_get("source").unwrap_or_default();
        let severity: String = r.try_get("severity").unwrap_or_else(|_| "info".into());
        let description: String = r.try_get("description").unwrap_or_default();
        let status: String = r.try_get("status").unwrap_or_else(|_| "open".into());
        let discovered_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("discovered_at").ok();

        findings.push(json!({
            "id": id,
            "client_id": client_id,
            "title": title,
            "severity": severity,
            "source": source,
            "status": status,
            "description": description,
            "discovered_at": discovered_at.map(|t| t.to_rfc3339()),
        }));

        let blob = format!("{} {}", title, description);
        let protocol = ot_ics_protocol_from_text(&blob, &source);
        let (mut host, mut port) = ot_ics_parse_host_port(&blob);
        if host.is_empty() {
            host = ot_ics_parse_host_port(&description).0;
            if port == 0 {
                port = ot_ics_parse_host_port(&description).1;
            }
        }
        if port == 0 {
            port = match protocol.as_str() {
                "Modbus" => 502,
                "BACnet" => 47808,
                "OPC-UA" => 4840,
                "DNP3" => 20000,
                "S7" | "IEC 61850" => 102,
                _ => 0,
            };
        }
        let vendor = if description.contains("Vendor:") {
            description
                .split("Vendor:")
                .nth(1)
                .unwrap_or("")
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        } else {
            String::new()
        };
        let confidence = ot_ics_severity_to_confidence(&severity);
        ot_ics_push_device(
            &mut devices,
            &mut seen,
            &mut protocol_counts,
            id,
            client_id,
            &host,
            port,
            &protocol,
            &vendor,
            confidence,
            &source,
        );
    }

    let protocols: Vec<Value> = protocol_counts
        .into_iter()
        .map(|(name, (count, status))| json!({ "name": name, "count": count, "status": status }))
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "devices": devices,
            "protocols": protocols,
            "findings": findings,
        })),
    )
        .into_response()
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

/// Parse `INC-0042` → underlying vulnerability id.
fn parse_incident_finding_id(incident_id: &str) -> Option<i64> {
    let s = incident_id.trim();
    let num = s.strip_prefix("INC-").or_else(|| s.strip_prefix("inc-"))?;
    num.parse::<i64>().ok().filter(|&id| id > 0)
}

#[derive(Debug, Deserialize)]
struct IncidentPlaybookStepPatchBody {
    step_id: i32,
    #[serde(default)]
    done: Option<bool>,
}

/// Load completed playbook step ids keyed by finding_id.
async fn fetch_playbook_steps_map(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    finding_ids: &[i64],
) -> std::collections::HashMap<i64, Vec<i32>> {
    if finding_ids.is_empty() {
        return std::collections::HashMap::new();
    }
    let rows = sqlx::query(
        r#"SELECT finding_id, step_id
           FROM soc_incident_playbook_steps
           WHERE finding_id = ANY($1) AND done = TRUE
           ORDER BY step_id"#,
    )
    .bind(finding_ids)
    .fetch_all(&mut **tx)
    .await
    .unwrap_or_default();
    let mut out: std::collections::HashMap<i64, Vec<i32>> = std::collections::HashMap::new();
    for r in rows {
        let fid: i64 = r.try_get("finding_id").unwrap_or(0);
        let sid: i32 = r.try_get("step_id").unwrap_or(0);
        if fid > 0 && sid > 0 {
            out.entry(fid).or_default().push(sid);
        }
    }
    out
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

    let finding_ids: Vec<i64> = rows
        .iter()
        .filter_map(|r| r.try_get::<i64, _>("id").ok())
        .collect();
    let steps_map = fetch_playbook_steps_map(&mut tx, &finding_ids).await;

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

        let done_steps = steps_map.get(&id).cloned().unwrap_or_default();
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
            "playbookStepsDone": done_steps,
            "timeline": timeline,
        }));
    }
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({ "ok": true, "incidents": incidents }))).into_response()
}

/// PATCH /api/soc/incidents/:id/playbook-steps — persist IR playbook step completion.
async fn api_soc_incident_playbook_steps_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(incident_id): Path<String>,
    Json(body): Json<IncidentPlaybookStepPatchBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let finding_id = match parse_incident_finding_id(&incident_id) {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "invalid incident id; expected INC-####"})),
            )
                .into_response();
        }
    };
    if body.step_id <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "step_id must be positive"})),
        )
            .into_response();
    }
    let done = body.done.unwrap_or(true);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let exists = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*)::bigint FROM vulnerabilities WHERE id = $1"#,
    )
    .bind(finding_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    if exists == 0 {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "incident not found"})),
        )
            .into_response();
    }

    if done {
        let _ = sqlx::query(
            r#"INSERT INTO soc_incident_playbook_steps (tenant_id, finding_id, step_id, done, updated_at)
               VALUES ($1, $2, $3, TRUE, now())
               ON CONFLICT (tenant_id, finding_id, step_id)
               DO UPDATE SET done = TRUE, updated_at = now()"#,
        )
        .bind(auth.tenant_id)
        .bind(finding_id)
        .bind(body.step_id)
        .execute(&mut *tx)
        .await;
    } else {
        let _ = sqlx::query(
            r#"DELETE FROM soc_incident_playbook_steps
               WHERE tenant_id = $1 AND finding_id = $2 AND step_id = $3"#,
        )
        .bind(auth.tenant_id)
        .bind(finding_id)
        .bind(body.step_id)
        .execute(&mut *tx)
        .await;
    }

    let steps_map = fetch_playbook_steps_map(&mut tx, &[finding_id]).await;
    let _ = tx.commit().await;
    let done_steps = steps_map.get(&finding_id).cloned().unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "incident_id": incident_id,
            "finding_id": finding_id,
            "step_id": body.step_id,
            "done": done,
            "playbookStepsDone": done_steps,
        })),
    )
        .into_response()
}

/// Extract unique IP/domain indicators from finding text fields.
fn extract_network_iocs(text: &str) -> Vec<(String, &'static str)> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();

    for token in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != ':') {
        let t = token.trim_matches(|c| c == '.' || c == '[' || c == ']' || c == '(' || c == ')');
        if t.is_empty() {
            continue;
        }
        if t.chars().filter(|&c| c == '.').count() == 3
            && t.chars().all(|c| c.is_ascii_digit() || c == '.')
            && t.len() >= 7
            && t.len() <= 15
            && seen.insert(format!("ip:{t}"))
        {
            out.push((t.to_string(), "ip"));
            continue;
        }
        if t.contains('.')
            && !t.starts_with("http")
            && t.len() >= 4
            && t.len() <= 253
            && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && t.contains('.')
            && !t.ends_with(".local")
            && seen.insert(format!("domain:{t}"))
        {
            out.push((t.to_string(), "domain"));
        }
    }
    out
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
        r#"SELECT id, title, severity, source, description, discovered_at,
                  COALESCE(raw_data, '{}'::jsonb) AS raw_data
           FROM vulnerabilities
           WHERE kev_listed = true OR lower(severity) IN ('critical', 'high')
           ORDER BY discovered_at DESC LIMIT 80"#,
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

    let mut iocs: Vec<Value> = Vec::new();
    let mut ioc_seen = std::collections::HashSet::new();
    for r in ioc_rows {
        let raw_id: i64 = r.try_get("id").unwrap_or(0);
        let title: String = r.try_get("title").unwrap_or_default();
        let severity: String = r.try_get("severity").unwrap_or_else(|_| "medium".into());
        let source: String = r.try_get("source").unwrap_or_default();
        let description: String = r.try_get("description").unwrap_or_default();
        let raw_data: Value = r.try_get("raw_data").unwrap_or(json!({}));
        let discovered: DateTime<Utc> = r.try_get("discovered_at").unwrap_or_else(|_| Utc::now());
        let added = discovered.format("%Y-%m-%d").to_string();
        let target = raw_data
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let url = raw_data
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut blob = format!("{title} {description} {target} {url}");
        if let Some(mitre) = raw_data.get("mitre_attack").and_then(Value::as_str) {
            blob.push(' ');
            blob.push_str(mitre);
        }
        for (value, ioc_type) in extract_network_iocs(&blob) {
            let key = format!("{ioc_type}:{value}");
            if !ioc_seen.insert(key) {
                continue;
            }
            iocs.push(json!({
                "id": format!("ioc-{}-{}", ioc_type, iocs.len() + 1),
                "type": ioc_type,
                "value": value,
                "source": if source.is_empty() { "Findings" } else { source.as_str() },
                "severity": severity,
                "tags": [source.clone()],
                "added": added,
                "finding_id": raw_id,
            }));
        }
        if iocs.len() >= 60 {
            break;
        }
    }

    let queries: Vec<Value> = campaigns
        .iter()
        .take(8)
        .enumerate()
        .map(|(i, c)| {
            let ds = c
                .get("dataSources")
                .and_then(|d| d.get(0))
                .and_then(Value::as_str)
                .unwrap_or("findings");
            json!({
                "id": format!("q-{}", i + 1),
                "name": c.get("title").cloned().unwrap_or(Value::Null),
                "datasource": ds,
                "language": "KQL",
                "query": format!("findings | where source == \"{ds}\" | summarize count() by severity, title"),
                "mitre": c.get("mitre").and_then(|m| m.get(0)).cloned().unwrap_or(Value::Null),
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

/// GET /api/soc/iocs — IOC library extracted from recent findings (IPs/domains).
async fn api_soc_iocs(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let resp = api_soc_hunts(State(state), Extension(auth)).await;
    let status = resp.status();
    let bytes = match axum::body::to_bytes(resp.into_body(), 4_194_304).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "iocs": []})),
            )
                .into_response();
        }
    };
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(json!({"iocs": []}));
    let iocs = v.get("iocs").cloned().unwrap_or(json!([]));
    (status, Json(json!({"ok": true, "iocs": iocs}))).into_response()
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
           WHERE lower(COALESCE(source,'')) = 'social_engineering_phishing'
              OR lower(COALESCE(source,'')) LIKE '%phish%'
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
            let source = r.try_get::<String, _>("source").unwrap_or_default();
            let status = r
                .try_get::<String, _>("status")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let campaign_type = if source.eq_ignore_ascii_case("social_engineering_phishing") {
                "email_phishing"
            } else {
                "phishing_assessment"
            };
            json!({
                "id": format!("camp-{}", id),
                "name": r.try_get::<String,_>("title").unwrap_or_default(),
                "type": campaign_type,
                "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
                "status": status,
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

#[derive(serde::Deserialize)]
struct SocialCampaignCreate {
    name: String,
    template: Option<String>,
    client_id: Option<i64>,
    description: Option<String>,
    campaign_type: Option<String>,
}

/// POST /api/soc/social-engineering/campaigns — register a phishing assessment campaign.
async fn api_soc_social_engineering_campaigns_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<SocialCampaignCreate>,
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
    let client_id = match body.client_id {
        Some(id) if id > 0 => id,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "client_id required"})),
            )
                .into_response();
        }
    };

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable"})),
        )
            .into_response();
    };

    let client_ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(client_id)
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(false);
    if !client_ok {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "client not found"})),
        )
            .into_response();
    }

    let scan_target: String = sqlx::query_scalar::<_, Option<String>>(
        "SELECT domains FROM clients WHERE id = $1 AND tenant_id = $2",
    )
    .bind(client_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .flatten()
    .and_then(|d| {
        serde_json::from_str::<Vec<String>>(&d)
            .ok()
            .and_then(|arr| arr.first().cloned())
    })
    .map(|d| {
        let t = d.trim();
        if t.starts_with("http://") || t.starts_with("https://") {
            t.to_string()
        } else {
            format!("https://{}", t.trim_start_matches('/'))
        }
    })
    .unwrap_or_else(|| name.to_string());

    let template = body.template.unwrap_or_else(|| "Password Reset".into());
    let campaign_type = body
        .campaign_type
        .unwrap_or_else(|| "email_phishing".into());
    let description = body.description.unwrap_or_default();
    let full_description = if description.is_empty() {
        format!("Phishing simulation campaign using the \"{}\" template.", template)
    } else {
        format!(
            "{} (template: {})",
            description.trim(),
            template
        )
    };

    let _ = tx.commit().await;

    let campaign_finding = json!({
        "title": name,
        "severity": "medium",
        "description": full_description,
        "type": "social_engineering_phishing",
        "evidence": {
            "proof": format!(
                "Phishing simulation campaign | template={} | type={} | campaign={}",
                template, campaign_type, name
            ),
            "engine_id": "social_engineering_phishing",
        }
    });
    let persist_result = crate::findings_persist::persist_engine_findings(
        &state.app_pool,
        auth.tenant_id,
        Some(client_id),
        "social_engineering_phishing",
        &scan_target,
        std::slice::from_ref(&campaign_finding),
    )
    .await;
    let row_id: i64 = match persist_result {
        Ok(n) if n > 0 => {
            let fid = crate::findings_persist::build_finding_id(
                "social_engineering_phishing",
                &scan_target,
                &campaign_finding,
            );
            sqlx::query_scalar(
                "SELECT id FROM vulnerabilities WHERE tenant_id = $1 AND client_id = $2 AND finding_id = $3",
            )
            .bind(auth.tenant_id)
            .bind(client_id)
            .bind(&fid)
            .fetch_optional(state.app_pool.as_ref())
            .await
            .ok()
            .flatten()
            .unwrap_or(0)
        }
        Ok(_) => 0,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
            )
                .into_response();
        }
    };
    if row_id == 0 {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "campaign finding not persisted (evidence gate)"})),
        )
            .into_response();
    }

    let campaign = json!({
        "id": format!("camp-{}", row_id),
        "name": name,
        "type": campaign_type,
        "severity": "medium",
        "status": "open",
        "description": full_description,
        "started_at": chrono::Utc::now().to_rfc3339(),
        "client_id": client_id,
        "template": template,
    });

    (
        StatusCode::CREATED,
        Json(json!({"ok": true, "campaign": campaign})),
    )
        .into_response()
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
    if let Err(r) = crate::rbac::require_operator(&auth) {
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

    let next_run = crate::scan_schedule_worker::compute_next_run_at(&schedule_type, Utc::now());
    let created: Option<(i64,)> = sqlx::query_as(
        r#"INSERT INTO weissman_scan_schedules
           (tenant_id, client_id, name, description, schedule_type, cron, engines, enabled, next_run_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
    .bind(next_run)
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
    if let Err(r) = crate::rbac::require_operator(&auth) {
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

    let next_run = crate::scan_schedule_worker::compute_next_run_at(&schedule_type, Utc::now());
    let updated = sqlx::query(
        r#"UPDATE weissman_scan_schedules
           SET client_id = $1, name = $2, description = $3, schedule_type = $4, cron = $5,
               engines = $6, enabled = $7, next_run_at = $8, updated_at = now()
           WHERE id = $9"#,
    )
    .bind(client_id)
    .bind(name)
    .bind(description)
    .bind(&schedule_type)
    .bind(&cron)
    .bind(engines_json)
    .bind(enabled)
    .bind(next_run)
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
                Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
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
    if let Err(r) = crate::rbac::require_operator(&auth) {
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
    if let Err(r) = crate::rbac::require_operator(&auth) {
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
            Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
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
    if let Err(r) = crate::rbac::require_operator(&auth) {
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

    let job_count = (domains.len() * engines.len()) as u64;
    if let Err(detail) = crate::billing::gate_scan_enqueue_n(
        state.auth_pool.as_ref(),
        auth.tenant_id,
        job_count,
    )
    .await
    {
        let _ = tx.rollback().await;
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"ok": false, "detail": detail})),
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

    let schedule_type_for_next: String = row
        .try_get("schedule_type")
        .unwrap_or_else(|_| "daily".into());
    let next_run = crate::scan_schedule_worker::compute_next_run_at(&schedule_type_for_next, Utc::now());
    let _ = sqlx::query(
        r#"UPDATE weissman_scan_schedules
           SET last_run_at = now(), next_run_at = $2, run_count = run_count + 1, updated_at = now()
           WHERE id = $1"#,
    )
    .bind(schedule_id)
    .bind(next_run)
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
            let meta_raw = n.get("metadata").cloned().unwrap_or(Value::Null);
            let meta_parsed: Value = match &meta_raw {
                Value::String(s) => serde_json::from_str(s).unwrap_or(json!({})),
                Value::Object(_) => meta_raw.clone(),
                _ => json!({}),
            };
            json!({
                "id": id,
                "name": label,
                "label": label,
                "node_type": n.get("node_type").cloned().unwrap_or(Value::Null),
                "risk_score": risk_score,
                "severity": risk_score_to_severity(risk_score),
                "is_choke_point": n.get("is_choke_point").cloned().unwrap_or(Value::Bool(false)),
                "metadata": meta_parsed,
                "description": meta_parsed.get("description").cloned()
                    .or_else(|| meta_parsed.get("summary").cloned())
                    .unwrap_or(Value::Null),
                "finding_id": meta_parsed.get("finding_id").cloned()
                    .or_else(|| meta_parsed.get("vulnerability_id").cloned())
                    .unwrap_or(Value::Null),
                "attack_paths": meta_parsed.get("attack_paths").cloned().unwrap_or(json!(0)),
                "mitigations": meta_parsed.get("mitigations").cloned().unwrap_or(json!(0)),
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

fn sbom_component_type(source: &str) -> &'static str {
    let s = source.to_ascii_lowercase();
    if s.contains("transitive") || s.contains("indirect") {
        "transitive"
    } else {
        "direct"
    }
}

/// Map DB SBOM row + matched vulns to SBOMBrowser field names.
fn reshape_sbom_component_for_ui(
    id: i64,
    package_name: &str,
    ecosystem: &str,
    version_spec: &str,
    source: &str,
    created_at: &str,
    vulns: &[Value],
) -> Value {
    let version = if version_spec.is_empty() || version_spec == "*" {
        "unknown".to_string()
    } else {
        version_spec.to_string()
    };
    let vulnerabilities: Vec<Value> = vulns
        .iter()
        .map(|v| {
            json!({
                "id": v.get("id").cloned().unwrap_or(Value::Null),
                "cve": v.get("cve").cloned()
                    .or_else(|| v.get("title").cloned())
                    .unwrap_or(Value::Null),
                "severity": v.get("severity").cloned().unwrap_or(json!("medium")),
                "title": v.get("title").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let max_sev = vulnerabilities
        .iter()
        .filter_map(|v| v.get("severity").and_then(Value::as_str))
        .max_by_key(|s| severity_rank(s))
        .unwrap_or("info");
    json!({
        "id": id,
        "name": package_name,
        "package_name": package_name,
        "version": version,
        "version_spec": version_spec,
        "ecosystem": ecosystem,
        "source": source,
        "type": sbom_component_type(source),
        "license": if ecosystem.is_empty() { Value::Null } else { json!(format!("{ecosystem}-registry")) },
        "vulnerabilities": vulnerabilities,
        "outdated": max_sev == "critical" || max_sev == "high",
        "latest_version": Value::Null,
        "created_at": created_at,
    })
}

/// Load SBOM components enriched with tenant-scoped vulnerability matches.
async fn sbom_components_for_ui(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Vec<Value>, Response> {
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "components": []})),
        )
            .into_response());
    };
    let rows = sqlx::query(
        "SELECT id, package_name, ecosystem, version_spec, source, created_at FROM client_sbom_components WHERE client_id = $1 ORDER BY id DESC",
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": scrub_internal_error(&e), "components": []})),
        )
            .into_response()
    })?;
    let vuln_rows = sqlx::query(
        r#"SELECT id, title, severity, description, source
           FROM vulnerabilities
           WHERE client_id = $1
             AND (
               lower(COALESCE(source,'')) LIKE '%sbom%'
               OR lower(COALESCE(source,'')) LIKE '%supply%'
               OR lower(COALESCE(title,'')) LIKE '%cve-%'
               OR lower(COALESCE(description,'')) LIKE '%cve-%'
             )
           ORDER BY id DESC LIMIT 500"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut vulns_by_pkg: HashMap<String, Vec<Value>> = HashMap::new();
    for r in vuln_rows {
        let title: String = r.try_get("title").unwrap_or_default();
        let description: String = r.try_get("description").unwrap_or_default();
        let blob = format!("{} {}", title, description).to_ascii_lowercase();
        for row in &rows {
            let pkg: String = row.try_get("package_name").unwrap_or_default();
            if pkg.is_empty() {
                continue;
            }
            if blob.contains(&pkg.to_ascii_lowercase()) {
                let cve = title
                    .split_whitespace()
                    .find(|t| t.to_ascii_uppercase().starts_with("CVE-"))
                    .unwrap_or("")
                    .to_string();
                vulns_by_pkg.entry(pkg).or_default().push(json!({
                    "id": r.try_get::<i64,_>("id").unwrap_or(0),
                    "title": title,
                    "severity": r.try_get::<String,_>("severity").unwrap_or_else(|_| "medium".into()),
                    "cve": if cve.is_empty() { Value::Null } else { json!(cve) },
                }));
            }
        }
    }

    let components: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let id: i64 = r.try_get("id").unwrap_or(0);
            let package_name: String = r.try_get("package_name").unwrap_or_default();
            let ecosystem: String = r.try_get("ecosystem").unwrap_or_default();
            let version_spec: String = r.try_get("version_spec").unwrap_or_default();
            let source: String = r.try_get("source").unwrap_or_default();
            let created_at = r
                .try_get::<DateTime<Utc>, _>("created_at")
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            let vulns = vulns_by_pkg.get(&package_name).map(|v| v.as_slice()).unwrap_or(&[]);
            reshape_sbom_component_for_ui(
                id,
                &package_name,
                &ecosystem,
                &version_spec,
                &source,
                &created_at,
                vulns,
            )
        })
        .collect();
    Ok(components)
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
    match sbom_components_for_ui(&state.app_pool, auth.tenant_id, client_id).await {
        Ok(components) => (StatusCode::OK, Json(json!({ "ok": true, "components": components }))).into_response(),
        Err(resp) => resp,
    }
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
            Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
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

fn infer_containment_action(
    k8s_api_server: &str,
    aws_region: &str,
    forensic_ports_csv: &str,
) -> &'static str {
    if !k8s_api_server.trim().is_empty() {
        "quarantine"
    } else if !aws_region.trim().is_empty() {
        "isolate"
    } else if forensic_ports_csv.contains(',') && forensic_ports_csv != "22,443" {
        "block"
    } else {
        "alert"
    }
}

/// Reshape DB containment row for ContainmentRulesBuilder UI fields.
fn reshape_containment_rule_for_ui(row: Value) -> Value {
    let name = row.get("name").and_then(Value::as_str).unwrap_or("");
    let enabled = row.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    let pre_approved = row.get("pre_approved").and_then(Value::as_bool).unwrap_or(false);
    let aws_region = row.get("aws_region").and_then(Value::as_str).unwrap_or("");
    let forensic_source_cidr = row
        .get("forensic_source_cidr")
        .and_then(Value::as_str)
        .unwrap_or("");
    let forensic_ports_csv = row
        .get("forensic_ports_csv")
        .and_then(Value::as_str)
        .unwrap_or("");
    let k8s_api_server = row.get("k8s_api_server").and_then(Value::as_str).unwrap_or("");
    let k8s_namespace = row.get("k8s_namespace").and_then(Value::as_str).unwrap_or("");
    let k8s_pod_label_key = row.get("k8s_pod_label_key").and_then(Value::as_str).unwrap_or("");
    let k8s_pod_label_value = row
        .get("k8s_pod_label_value")
        .and_then(Value::as_str)
        .unwrap_or("");
    let action = infer_containment_action(k8s_api_server, aws_region, forensic_ports_csv);
    let mut description_parts = Vec::new();
    if !aws_region.is_empty() {
        description_parts.push(format!("AWS region {aws_region}"));
    }
    if !forensic_source_cidr.is_empty() && forensic_source_cidr != "0.0.0.0/0" {
        description_parts.push(format!("CIDR {forensic_source_cidr}"));
    }
    if !forensic_ports_csv.is_empty() {
        description_parts.push(format!("Ports {forensic_ports_csv}"));
    }
    if !k8s_api_server.is_empty() {
        description_parts.push(format!("K8s namespace {k8s_namespace}"));
    }
    if !k8s_pod_label_key.is_empty() {
        description_parts.push(format!("Label {k8s_pod_label_key}={k8s_pod_label_value}"));
    }
    let description = if description_parts.is_empty() {
        format!("Containment rule \"{name}\"")
    } else {
        description_parts.join(" · ")
    };
    let target = if !k8s_pod_label_value.is_empty() {
        format!("{k8s_namespace}/{k8s_pod_label_value}")
    } else if !aws_region.is_empty() {
        aws_region.to_string()
    } else {
        forensic_source_cidr.to_string()
    };
    json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "name": name,
        "enabled": enabled,
        "pre_approved": pre_approved,
        "action": action,
        "auto_trigger": pre_approved,
        "description": description,
        "target": target,
        "triggered_count": 0,
        "trigger_on": json!({
            "severity": if enabled && pre_approved { json!("critical") } else { Value::Null },
        }),
        "aws_region": aws_region,
        "forensic_source_cidr": forensic_source_cidr,
        "forensic_ports_csv": forensic_ports_csv,
        "k8s_api_server": k8s_api_server,
        "k8s_token_env_var": row.get("k8s_token_env_var").cloned().unwrap_or(Value::Null),
        "k8s_namespace": k8s_namespace,
        "k8s_pod_label_key": k8s_pod_label_key,
        "k8s_pod_label_value": k8s_pod_label_value,
        "allow_dns_egress": row.get("allow_dns_egress").cloned().unwrap_or(json!(true)),
        "created_at": row.get("created_at").cloned().unwrap_or(Value::Null),
    })
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)] // JSON request-body shape; some fields accepted but not yet consumed
struct UiContainmentRuleBody {
    name: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    auto_trigger: Option<bool>,
    #[serde(default)]
    trigger_on: Option<Value>,
    #[serde(default)]
    pre_approved: Option<bool>,
    #[serde(default)]
    aws_region: Option<String>,
    #[serde(default)]
    forensic_source_cidr: Option<String>,
    #[serde(default)]
    forensic_ports_csv: Option<String>,
    #[serde(default)]
    k8s_api_server: Option<String>,
    #[serde(default)]
    k8s_token_env_var: Option<String>,
    #[serde(default)]
    k8s_namespace: Option<String>,
    #[serde(default)]
    k8s_pod_label_key: Option<String>,
    #[serde(default)]
    k8s_pod_label_value: Option<String>,
    #[serde(default)]
    allow_dns_egress: Option<bool>,
}

fn ui_containment_to_db(body: &UiContainmentRuleBody) -> ContainmentRuleBody {
    let action = body
        .action
        .as_deref()
        .unwrap_or("isolate")
        .to_ascii_lowercase();
    let auto = body
        .auto_trigger
        .or(body.pre_approved)
        .unwrap_or(false);
    let (aws_region, k8s_api_server, forensic_ports) = match action.as_str() {
        "block" => (
            body.aws_region.clone().unwrap_or_default(),
            String::new(),
            body.forensic_ports_csv
                .clone()
                .unwrap_or_else(|| "22,443,8080".into()),
        ),
        "quarantine" => (
            body.aws_region.clone().unwrap_or_default(),
            body.k8s_api_server
                .clone()
                .unwrap_or_else(|| "https://kubernetes.default.svc".into()),
            body.forensic_ports_csv
                .clone()
                .unwrap_or_else(|| "22,443".into()),
        ),
        "isolate" => (
            body.aws_region
                .clone()
                .unwrap_or_else(|| "us-east-1".into()),
            String::new(),
            body.forensic_ports_csv
                .clone()
                .unwrap_or_else(|| "22,443".into()),
        ),
        _ => (
            String::new(),
            String::new(),
            body.forensic_ports_csv
                .clone()
                .unwrap_or_else(|| "22,443".into()),
        ),
    };
    ContainmentRuleBody {
        name: body.name.clone(),
        enabled: body.enabled.or(Some(true)),
        pre_approved: Some(auto),
        aws_region: Some(aws_region),
        forensic_source_cidr: body
            .forensic_source_cidr
            .clone()
            .or(Some("0.0.0.0/0".into())),
        forensic_ports_csv: Some(forensic_ports),
        k8s_api_server: Some(k8s_api_server),
        k8s_token_env_var: body.k8s_token_env_var.clone(),
        k8s_namespace: body.k8s_namespace.clone().or(Some("default".into())),
        k8s_pod_label_key: body.k8s_pod_label_key.clone(),
        k8s_pod_label_value: body.k8s_pod_label_value.clone(),
        allow_dns_egress: body.allow_dns_egress.or(Some(true)),
    }
}

#[derive(Debug, Deserialize, Default)]
struct UiContainmentRulePatchBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    auto_trigger: Option<bool>,
    #[serde(default)]
    trigger_on: Option<Value>,
    #[serde(default)]
    pre_approved: Option<bool>,
    #[serde(default)]
    aws_region: Option<String>,
    #[serde(default)]
    forensic_source_cidr: Option<String>,
    #[serde(default)]
    forensic_ports_csv: Option<String>,
    #[serde(default)]
    k8s_api_server: Option<String>,
    #[serde(default)]
    k8s_token_env_var: Option<String>,
    #[serde(default)]
    k8s_namespace: Option<String>,
    #[serde(default)]
    k8s_pod_label_key: Option<String>,
    #[serde(default)]
    k8s_pod_label_value: Option<String>,
    #[serde(default)]
    allow_dns_egress: Option<bool>,
}

fn ui_containment_patch_to_db(body: &UiContainmentRulePatchBody) -> ContainmentRulePatchBody {
    let mut patch = ContainmentRulePatchBody::default();
    if let Some(name) = &body.name {
        patch.name = Some(name.clone());
    }
    if let Some(enabled) = body.enabled {
        patch.enabled = Some(enabled);
    }
    if let Some(auto) = body.auto_trigger.or(body.pre_approved) {
        patch.pre_approved = Some(auto);
    }
    if let Some(v) = &body.aws_region {
        patch.aws_region = Some(v.clone());
    }
    if let Some(v) = &body.forensic_source_cidr {
        patch.forensic_source_cidr = Some(v.clone());
    }
    if let Some(v) = &body.forensic_ports_csv {
        patch.forensic_ports_csv = Some(v.clone());
    }
    if let Some(v) = &body.k8s_api_server {
        patch.k8s_api_server = Some(v.clone());
    }
    if let Some(v) = &body.k8s_token_env_var {
        patch.k8s_token_env_var = Some(v.clone());
    }
    if let Some(v) = &body.k8s_namespace {
        patch.k8s_namespace = Some(v.clone());
    }
    if let Some(v) = &body.k8s_pod_label_key {
        patch.k8s_pod_label_key = Some(v.clone());
    }
    if let Some(v) = &body.k8s_pod_label_value {
        patch.k8s_pod_label_value = Some(v.clone());
    }
    if let Some(v) = body.allow_dns_egress {
        patch.allow_dns_egress = Some(v);
    }
    if let Some(action) = body.action.as_deref() {
        let mapped = ui_containment_to_db(&UiContainmentRuleBody {
            name: body.name.clone().unwrap_or_default(),
            action: Some(action.to_string()),
            auto_trigger: body.auto_trigger,
            pre_approved: body.pre_approved,
            aws_region: body.aws_region.clone(),
            forensic_source_cidr: body.forensic_source_cidr.clone(),
            forensic_ports_csv: body.forensic_ports_csv.clone(),
            k8s_api_server: body.k8s_api_server.clone(),
            k8s_token_env_var: body.k8s_token_env_var.clone(),
            k8s_namespace: body.k8s_namespace.clone(),
            k8s_pod_label_key: body.k8s_pod_label_key.clone(),
            k8s_pod_label_value: body.k8s_pod_label_value.clone(),
            allow_dns_egress: body.allow_dns_egress,
            ..Default::default()
        });
        if patch.aws_region.is_none() {
            patch.aws_region = mapped.aws_region;
        }
        if patch.forensic_ports_csv.is_none() {
            patch.forensic_ports_csv = mapped.forensic_ports_csv;
        }
        if patch.k8s_api_server.is_none() {
            patch.k8s_api_server = mapped.k8s_api_server;
        }
    }
    let _ = body.description.as_ref();
    let _ = body.trigger_on.as_ref();
    patch
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
    let resp = api_containment_rules_list(State(state), Extension(auth), Path(client_id)).await;
    let status = resp.status();
    let bytes = match axum::body::to_bytes(resp.into_body(), 2_097_152).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"rules": []})),
            )
                .into_response();
        }
    };
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(json!({"rules": []}));
    let rules: Vec<Value> = v
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(reshape_containment_rule_for_ui)
        .collect();
    (status, Json(json!({ "rules": rules }))).into_response()
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
            Json(json!({ "ok": false, "detail": scrub_internal_error(&e), "secrets": [] })),
        )
            .into_response(),
    }
}

/// POST /api/containment/rules — alias for `/api/clients/:id/containment-rules`.
async fn api_containment_rules_post_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<ClientIdAliasQuery>,
    Json(body): Json<UiContainmentRuleBody>,
) -> Response {
    let client_id = match resolve_alias_client_id(&state.app_pool, auth.tenant_id, q.client_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let db_body = ui_containment_to_db(&body);
    api_containment_rules_post(State(state), Extension(auth), Path(client_id), Json(db_body)).await
}

/// PATCH/PUT /api/containment/rules/:id — update rule by id (tenant-scoped).
async fn api_containment_rules_patch_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<i64>,
    Json(body): Json<UiContainmentRulePatchBody>,
) -> Response {
    let db_body = ui_containment_patch_to_db(&body);
    api_containment_rules_patch(State(state), Extension(auth), Path(rule_id), Json(db_body)).await
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
            Json(json!({ "ok": false, "detail": scrub_internal_error(&e) })),
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
            Json(json!({ "ok": false, "detail": scrub_internal_error(&e) })),
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
            Json(json!({ "ok": false, "detail": scrub_internal_error(&e) })),
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

/// GET /api/security/posture-score — platform self-security posture (not tenant client score).
async fn api_security_posture_score(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
) -> Response {
    let posture = crate::security_posture::compute_platform_posture(state.app_pool.as_ref()).await;
    (
        StatusCode::OK,
        Json(crate::security_posture::posture_to_json(&posture)),
    )
        .into_response()
}

/// GET /api/engines/:engine_id/contract — engine contract metadata for UI drawers / SOAR.
async fn api_engine_contract(Path(engine_id): Path<String>) -> Response {
    if !weissman_core::models::engine::is_production_engine_id(&engine_id) {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown engine" }))).into_response();
    }
    let meta = crate::engine_contract::contract_meta_for_engine(&engine_id);
    (StatusCode::OK, Json(serde_json::to_value(meta).unwrap_or(json!({})))).into_response()
}

/// GET /api/compliance/control-mappings — live framework control → evidence mappings.
async fn api_compliance_control_mappings(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let framework = q.get("framework").map(|s| s.trim().to_string());
    match crate::compliance_engine::load_control_mappings(
        state.app_pool.as_ref(),
        framework.as_deref(),
    )
    .await
    {
        Ok(rows) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "mappings": rows,
                "total": rows.len(),
                "source": "compliance_control_mappings",
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": scrub_internal_error(&e) })),
        )
            .into_response(),
    }
}

/// GET /api/compliance/control-mappings/coverage — per-framework coverage rollup plus a live
/// integrity check that every mapped `engine_id` still resolves to a known platform engine.
/// This is what keeps the "live" mapping honest: if the engine fleet changes underneath the
/// catalog, orphaned bindings surface here instead of silently degrading a compliance report.
async fn api_compliance_control_mappings_coverage(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let framework = q.get("framework").map(|s| s.trim().to_string());
    let rows = match crate::compliance_engine::load_control_mappings(
        state.app_pool.as_ref(),
        framework.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": scrub_internal_error(&e) })),
            )
                .into_response();
        }
    };

    let is_known = weissman_core::models::engine::is_known_engine_id;
    let coverage = crate::compliance_engine::summarize_control_coverage(&rows, is_known);
    // Non-blocking data-quality diagnostic: mapping rows pointing at engines the registry no
    // longer knows. Stale references never void an artifact — see the enforcement gate below.
    let stale_engine_refs = crate::compliance_engine::find_stale_engine_references(&rows, is_known);

    // The real consistency verdict must be byte-identical to the enforcement gate that voids
    // artifacts — otherwise `?framework=CIS` (or an unknown value) could report `consistent: true`
    // while every other framework is broken. Use the shared cross-listed gate; the `coverage`
    // payload above still reflects the caller's `?framework=` filter.
    let orphaned_controls: Vec<Value> = match compliance_orphaned_controls_across_listed(&state).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "coverage": coverage,
            "integrity": {
                // Consistency is a control-side verdict only.
                "consistent": orphaned_controls.is_empty(),
                "orphaned_controls": orphaned_controls,
                "orphaned_control_count": orphaned_controls.len(),
            },
            "diagnostics": {
                // Engine-side signal, explicitly non-blocking.
                "stale_engine_references": stale_engine_refs,
                "stale_engine_reference_count": stale_engine_refs.len(),
            },
            "total_mappings": rows.len(),
            "source": "compliance_control_mappings",
        })),
    )
        .into_response()
}

/// GET /api/compliance/evidence-pack/:client_id — live findings → auditor evidence pack.
async fn api_compliance_evidence_pack(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let tid = auth.tenant_id;
    let framework_filter = q.get("framework").map(|s| s.trim().to_string());

    // --- Unified control-mapping enforcement gate ---
    // The pack is cross-framework, so its validity depends on the whole enabled compliance surface
    // being consistent: any listed framework with orphaned controls (coverage gap, listed-but-
    // unmapped, or dead-predicate rot) voids the pack.
    let orphaned_controls = match compliance_orphaned_controls_across_listed(&state).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    let orphaned_control_count = orphaned_controls.len();
    let consistent = orphaned_control_count == 0;
    let acknowledged = q
        .get("acknowledge_inconsistent")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if !consistent && !acknowledged {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "reason": "inconsistent_control_mappings",
                "detail": "Evidence pack blocked: compliance requirements have no live control mapping.",
                "orphaned_controls": orphaned_controls,
                "orphaned_control_count": orphaned_control_count,
                "hint": "Re-request with acknowledge_inconsistent=true for a VOID-marked pack for internal triage.",
            })),
        )
            .into_response();
    }

    // `vulnerabilities` is FORCE RLS — a bare-pool read matches zero rows (DB default GUC = '0'),
    // which silently produced a "certified consistent" evidence pack containing no findings. Run
    // the read inside a tenant tx like the audit-chain and SOAR sections below already do.
    let mut vtx = match db::begin_tenant_tx(&state.app_pool, tid).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": scrub_internal_error(&e) })),
            )
                .into_response();
        }
    };
    let rows: Vec<(String, String, String, Value)> = match sqlx::query_as(
        r#"SELECT COALESCE(title,''), COALESCE(severity,'info'), COALESCE(source,''),
                  COALESCE(raw_data, '{}'::jsonb)
           FROM vulnerabilities
           WHERE tenant_id = $1 AND client_id = $2 AND status NOT IN ('FALSE_POSITIVE','FIXED')
           ORDER BY discovered_at DESC
           LIMIT 500"#,
    )
    .bind(tid)
    .bind(client_id)
    .fetch_all(&mut *vtx)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": scrub_internal_error(&e) })),
            )
                .into_response();
        }
    };
    let _ = vtx.commit().await;

    let mut by_framework: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    for (title, severity, source, raw) in &rows {
        let frameworks = raw
            .get("compliance")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let entry = json!({
            "title": title,
            "severity": severity,
            "source": source,
            "mitre": raw.get("mitre_attack"),
            "remediation": raw.get("remediation"),
            "evidence": raw.get("evidence"),
        });
        if frameworks.is_empty() {
            by_framework
                .entry("UNMAPPED".to_string())
                .or_default()
                .push(entry);
        } else {
            for fw in frameworks {
                let key = fw.as_str().unwrap_or("OTHER").to_string();
                by_framework.entry(key).or_default().push(entry.clone());
            }
        }
    }

    let control_mappings = match crate::compliance_engine::load_control_mappings(
        state.app_pool.as_ref(),
        framework_filter.as_deref(),
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": scrub_internal_error(&e) })),
            )
                .into_response();
        }
    };

    // Verify the ENTIRE audit chain, not just the oldest 1000 rows. Page in id-order with a 1-row
    // overlap between pages so a break spanning a page boundary is still caught. (The fully correct
    // form is a single streaming verify carrying prev_hash across pages — that belongs in
    // audit_log.rs; this handler-side paging is the in-scope equivalent.)
    let audit_chain_intact = match db::begin_tenant_tx(&state.app_pool, tid).await {
        Ok(mut tx) => {
            const PAGE: i64 = 5000;
            let mut offset: i64 = 0;
            let mut intact = true;
            loop {
                match crate::audit_log::export_for_tenant(&mut tx, tid, PAGE, offset).await {
                    Ok((entries, _total, page_intact)) => {
                        let n = entries.len() as i64;
                        if n == 0 {
                            break;
                        }
                        if !page_intact {
                            intact = false;
                            break;
                        }
                        if n < PAGE {
                            break;
                        }
                        // Overlap the last verified row into the next page to bridge the boundary.
                        offset += PAGE - 1;
                    }
                    Err(_) => {
                        intact = false;
                        break;
                    }
                }
            }
            let _ = tx.commit().await;
            intact
        }
        Err(_) => false,
    };

    let soar_executions: Vec<Value> = match db::begin_tenant_tx(&state.app_pool, tid).await {
        Ok(mut tx) => {
            let rows = sqlx::query(
                r#"SELECT id::text, action_kind, status, COALESCE(target_id,'') AS target_id,
                          COALESCE(result_detail,'') AS detail, updated_at
                   FROM soar_action_executions
                   WHERE tenant_id = $1
                   ORDER BY updated_at DESC
                   LIMIT 50"#,
            )
            .bind(tid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default();
            let _ = tx.commit().await;
            rows.into_iter()
                .map(|r| {
                    json!({
                        "id": r.try_get::<String, _>("id").unwrap_or_default(),
                        "action_kind": r.try_get::<String, _>("action_kind").unwrap_or_default(),
                        "status": r.try_get::<String, _>("status").unwrap_or_default(),
                        "target_id": r.try_get::<String, _>("target_id").unwrap_or_default(),
                        "detail": r.try_get::<String, _>("detail").unwrap_or_default(),
                        "updated_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                            .map(|d| d.to_rfc3339())
                            .unwrap_or_default(),
                    })
                })
                .collect()
        }
        Err(_) => Vec::new(),
    };

    let pack = json!({
        "packet_type": "weissman-compliance-evidence-pack-v2",
        "client_id": client_id,
        "tenant_id": tid,
        "framework_filter": framework_filter,
        "findings_total": rows.len(),
        "frameworks": by_framework,
        "control_mappings": control_mappings,
        "soar_executions": soar_executions,
        "live_evidence": {
            "audit_log_chain_intact": audit_chain_intact,
            "distributed_redis_required": crate::security_startup::production_distributed_state_required(),
            "zero_trust_job_bus": crate::http::rate_limit_redis::is_enabled()
                && std::env::var("WEISSMAN_JOB_ORCHESTRATOR_SECRET")
                    .map(|s| s.trim().len() >= 32)
                    .unwrap_or(false),
        },
        "integrity": {
            // Control-mapping consistency is part of the signed, persisted pack: a VOID pack keeps
            // its mark through the sha256 and the snapshot row.
            "consistent": consistent,
            "voided": !consistent,
            "watermark": if consistent { Value::Null } else { json!("INVALID - INCONSISTENT CONTROL-MAPPING STATE") },
            "orphaned_controls": orphaned_controls,
            "orphaned_control_count": orphaned_control_count,
        },
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "audit_ready": consistent
            && !rows.is_empty()
            && rows.iter().all(|(_, sev, _, _)| sev != "critical")
            && audit_chain_intact,
    });

    let pack_canonical = serde_json::to_string(&pack).unwrap_or_default();
    let pack_sha256 = crate::audit_log::digest_hex(&pack_canonical);
    let snapshot_id: Option<i64> = match db::begin_tenant_tx(&state.app_pool, tid).await {
        Ok(mut tx) => {
            let sid = sqlx::query_scalar::<_, i64>(
                r#"INSERT INTO compliance_evidence_pack_snapshots
                   (tenant_id, client_id, framework_filter, pack_json, pack_sha256)
                   VALUES ($1, $2, $3, $4, $5)
                   RETURNING id"#,
            )
            .bind(tid)
            .bind(client_id)
            .bind(framework_filter.as_deref())
            .bind(&pack)
            .bind(&pack_sha256)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
            let _ = tx.commit().await;
            sid
        }
        Err(_) => None,
    };

    let mut response = pack.as_object().cloned().unwrap_or_default();
    response.insert("pack_sha256".into(), json!(pack_sha256));
    if let Some(sid) = snapshot_id {
        response.insert("snapshot_id".into(), json!(sid));
    }
    (StatusCode::OK, Json(Value::Object(response))).into_response()
}
