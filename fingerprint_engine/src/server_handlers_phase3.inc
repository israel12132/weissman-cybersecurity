#[derive(Deserialize, Default)]
struct CloudIntegrationPatch {
    aws_cross_account_role_arn: Option<String>,
    aws_external_id: Option<String>,
    gcp_project_id: Option<String>,
}

#[derive(Deserialize)]
struct CompliancePostureQuery {
    client_id: Option<i64>,
}

#[derive(Deserialize)]
struct ExecutiveReportQuery {
    client_id: Option<i64>,
    lang: Option<String>,
}

async fn api_client_cloud_integration_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<CloudIntegrationPatch>,
) -> Response {
    let arn = body.aws_cross_account_role_arn.as_deref().unwrap_or("").trim();
    if !arn.is_empty() {
        if let Err(msg) = crate::cloud_integration_engine::validate_cross_account_role_arn(arn) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": msg})),
            )
                .into_response();
        }
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let ext = body.aws_external_id.clone().unwrap_or_default();
    let gcp = body.gcp_project_id.clone().unwrap_or_default();
    let n = sqlx::query(
        "UPDATE clients SET aws_cross_account_role_arn = $1, aws_external_id = $2, gcp_project_id = $3, updated_at = now() WHERE id = $4",
    )
    .bind(arn)
    .bind(ext.trim())
    .bind(gcp.trim())
    .bind(id)
    .execute(&mut *tx)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);
    if n == 0 {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    }
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "cloud_integration_updated",
        &format!("client_id={} role_configured={}", id, !arn.is_empty()),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

fn mask_secret_field(value: &str) -> Value {
    if value.trim().is_empty() {
        return json!({ "configured": false, "masked": "" });
    }
    let tail: String = value.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    json!({ "configured": true, "masked": format!("••••••••{tail}") })
}

#[derive(Deserialize, Default)]
struct LlmEndpointPatch {
    url: String,
    model: Option<String>,
    authorization: Option<String>,
}

#[derive(Deserialize, Default)]
struct ClientIntegrationsPatch {
    aws_cross_account_role_arn: Option<String>,
    aws_external_id: Option<String>,
    gcp_project_id: Option<String>,
    azure_subscription_id: Option<String>,
    azure_tenant_id: Option<String>,
    ad_domain: Option<String>,
    repo_urls: Option<Vec<String>>,
    agent_platforms: Option<Vec<String>>,
    industrial_ot_enabled: Option<bool>,
    ip_ranges: Option<Vec<String>>,
    llm_secops_endpoints: Option<Vec<LlmEndpointPatch>>,
}

/// GET /api/clients/:id/integrations — live integration config with masked secrets.
async fn api_client_integrations_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query(
        r#"SELECT id, name, domains, ip_ranges,
            COALESCE(aws_cross_account_role_arn,'') AS aws_cross_account_role_arn,
            COALESCE(aws_external_id,'') AS aws_external_id,
            COALESCE(gcp_project_id,'') AS gcp_project_id,
            COALESCE(NULLIF(trim(client_configs), ''), $2) AS client_configs
           FROM clients WHERE id = $1"#,
    )
    .bind(id)
    .bind(DEFAULT_CLIENT_CONFIGS_JSON)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let Some(r) = row else {
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    };
    let config_str: String = r.try_get("client_configs").unwrap_or_default();
    let config_val: Value = serde_json::from_str(&config_str).unwrap_or(json!({}));
    let onboarding = config_val.get("onboarding").cloned().unwrap_or(json!({}));
    let ext_id: String = r.try_get("aws_external_id").unwrap_or_default();
    let llm_eps = onboarding
        .get("llm_secops")
        .and_then(|v| v.get("endpoints"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let masked_llm: Vec<Value> = llm_eps
        .iter()
        .map(|ep| {
            let auth_masked = ep
                .get("authorization")
                .and_then(Value::as_str)
                .map(mask_secret_field)
                .unwrap_or(json!({ "configured": false, "masked": "" }));
            json!({
                "url": ep.get("url").and_then(Value::as_str).unwrap_or(""),
                "model": ep.get("model").and_then(Value::as_str).unwrap_or(""),
                "authorization": auth_masked,
            })
        })
        .collect();
    let domains_raw: String = r.try_get("domains").unwrap_or_else(|_| "[]".to_string());
    let domains_json: Value = serde_json::from_str(&domains_raw).unwrap_or(json!([]));
    let ebpf_ssh_host = onboarding
        .get("ebpf_ssh_host")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let ebpf_ssh_user = onboarding
        .get("ebpf_ssh_user")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mut github_token = String::new();
    let mut oast_domain = String::new();
    let mut oast_api_key = String::new();
    if let Ok(mut ttx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        async fn cfg_val(
            tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
            tenant_id: i64,
            key: &str,
        ) -> Option<String> {
            sqlx::query_scalar::<_, String>(
                "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = $2",
            )
            .bind(tenant_id)
            .bind(key)
            .fetch_optional(&mut **tx)
            .await
            .ok()
            .flatten()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        }
        github_token = cfg_val(&mut ttx, auth.tenant_id, "github_token")
            .await
            .unwrap_or_default();
        oast_domain = cfg_val(&mut ttx, auth.tenant_id, "oast_domain")
            .await
            .unwrap_or_default();
        oast_api_key = cfg_val(&mut ttx, auth.tenant_id, "oast_api_key")
            .await
            .unwrap_or_default();
        let _ = ttx.commit().await;
    }
    if oast_domain.is_empty() {
        oast_domain = std::env::var("WEISSMAN_OAST_DOMAIN")
            .or_else(|_| std::env::var("WEISSMAN_OAST_BASE_DOMAIN"))
            .unwrap_or_default()
            .trim()
            .to_string();
    }
    (
        StatusCode::OK,
        Json(json!({
            "client_id": id,
            "name": r.try_get::<String,_>("name").ok(),
            "domains": domains_json,
            "ip_ranges": r.try_get::<String,_>("ip_ranges").ok(),
            "aws_cross_account_role_arn": r.try_get::<String,_>("aws_cross_account_role_arn").ok(),
            "aws_external_id": mask_secret_field(&ext_id),
            "gcp_project_id": r.try_get::<String,_>("gcp_project_id").ok(),
            "azure_subscription_id": onboarding.get("azure_subscription_id").and_then(Value::as_str).unwrap_or(""),
            "azure_tenant_id": onboarding.get("azure_tenant_id").and_then(Value::as_str).unwrap_or(""),
            "ad_domain": onboarding.get("ad_domain").and_then(Value::as_str).unwrap_or(""),
            "repo_urls": onboarding.get("repo_urls").cloned().unwrap_or(json!([])),
            "agent_platforms": onboarding.get("agent_platforms").cloned().unwrap_or(json!([])),
            "industrial_ot_enabled": config_val.get("industrial_ot_enabled").and_then(Value::as_bool).unwrap_or(false),
            "llm_secops_endpoints": masked_llm,
            "engagement_modules": config_val.get("engagement_modules").cloned().unwrap_or(json!([])),
            "github_token": mask_secret_field(&github_token),
            "oast_domain": oast_domain,
            "oast_api_key": mask_secret_field(&oast_api_key),
            "ebpf_ssh_host": ebpf_ssh_host,
            "ebpf_ssh_user": ebpf_ssh_user,
        })),
    )
        .into_response()
}

/// PATCH /api/clients/:id/integrations — update cloud, identity, IaC, OT, LLM client endpoints.
async fn api_client_integrations_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<ClientIntegrationsPatch>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;

    let row = sqlx::query(
        r#"SELECT COALESCE(aws_cross_account_role_arn,'') AS arn,
            COALESCE(aws_external_id,'') AS ext,
            COALESCE(gcp_project_id,'') AS gcp,
            COALESCE(NULLIF(trim(client_configs), ''), $2) AS client_configs,
            COALESCE(domains,'[]') AS domains,
            COALESCE(ip_ranges,'[]') AS ip_ranges
           FROM clients WHERE id = $1"#,
    )
    .bind(id)
    .bind(DEFAULT_CLIENT_CONFIGS_JSON)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let Some(r) = row else {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    };

    let cur_arn: String = r.try_get("arn").unwrap_or_default();
    let cur_ext: String = r.try_get("ext").unwrap_or_default();
    let cur_gcp: String = r.try_get("gcp").unwrap_or_default();

    let arn = body
        .aws_cross_account_role_arn
        .as_deref()
        .unwrap_or(cur_arn.as_str())
        .trim()
        .to_string();
    if !arn.is_empty() {
        if let Err(msg) = crate::cloud_integration_engine::validate_cross_account_role_arn(&arn) {
            let _ = tx.rollback().await;
            return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "detail": msg}))).into_response();
        }
    }
    let ext = match body.aws_external_id.as_deref().map(str::trim) {
        Some(v) if !v.starts_with('•') => v.to_string(),
        _ => cur_ext.trim().to_string(),
    };
    let gcp = body
        .gcp_project_id
        .as_deref()
        .unwrap_or(cur_gcp.as_str())
        .trim()
        .to_string();

    let config_str: String = r.try_get("client_configs").unwrap_or_default();
    let mut config: serde_json::Map<String, Value> = serde_json::from_str::<Value>(&config_str)
        .ok()
        .and_then(|v: Value| v.as_object().cloned())
        .unwrap_or_default();
    let mut onboarding = config
        .get("onboarding")
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();

    if let Some(v) = body.azure_subscription_id {
        onboarding.insert("azure_subscription_id".into(), json!(v.trim()));
    }
    if let Some(v) = body.azure_tenant_id {
        onboarding.insert("azure_tenant_id".into(), json!(v.trim()));
    }
    if let Some(v) = body.ad_domain {
        onboarding.insert("ad_domain".into(), json!(v.trim()));
    }
    if let Some(urls) = body.repo_urls {
        let cleaned: Vec<Value> = urls
            .into_iter()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .map(|u| Value::String(u))
            .collect();
        onboarding.insert("repo_urls".into(), Value::Array(cleaned));
    }
    if let Some(platforms) = body.agent_platforms {
        onboarding.insert(
            "agent_platforms".into(),
            Value::Array(platforms.into_iter().map(|p| Value::String(p.trim().to_lowercase())).filter(|v| v.as_str().is_some_and(|s| !s.is_empty())).collect()),
        );
    }
    if let Some(endpoints) = body.llm_secops_endpoints {
        let existing: Vec<Value> = onboarding
            .get("llm_secops")
            .and_then(|v| v.get("endpoints"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let merged: Vec<Value> = endpoints
            .into_iter()
            .filter(|e| !e.url.trim().is_empty())
            .map(|e| {
                let prior_auth = existing
                    .iter()
                    .find(|x| x.get("url").and_then(Value::as_str) == Some(e.url.trim()))
                    .and_then(|x| x.get("authorization").and_then(Value::as_str))
                    .map(str::to_string);
                let auth = e
                    .authorization
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && *s != "••••••••")
                    .map(str::to_string)
                    .or(prior_auth);
                let mut obj = serde_json::Map::new();
                obj.insert("url".into(), json!(e.url.trim()));
                if let Some(m) = e.model.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    obj.insert("model".into(), json!(m));
                }
                if let Some(a) = auth {
                    obj.insert("authorization".into(), json!(a));
                }
                Value::Object(obj)
            })
            .collect();
        onboarding.insert("llm_secops".into(), json!({ "endpoints": merged }));
    }

    config.insert("onboarding".into(), Value::Object(onboarding));
    if let Some(b) = body.industrial_ot_enabled {
        config.insert("industrial_ot_enabled".into(), json!(b));
    }

    let domains_json = body.ip_ranges.as_ref().map(|ips| {
        serde_json::to_string(ips).unwrap_or_else(|_| "[]".to_string())
    });
    let ip_update = domains_json.as_deref();

    let new_config = serde_json::to_string(&Value::Object(config)).unwrap_or_else(|_| "{}".to_string());

    if let Some(ips) = ip_update {
        let _ = sqlx::query(
            "UPDATE clients SET aws_cross_account_role_arn = $1, aws_external_id = $2, gcp_project_id = $3, client_configs = $4, ip_ranges = $5, updated_at = now() WHERE id = $6",
        )
        .bind(&arn)
        .bind(&ext)
        .bind(&gcp)
        .bind(&new_config)
        .bind(ips)
        .bind(id)
        .execute(&mut *tx)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE clients SET aws_cross_account_role_arn = $1, aws_external_id = $2, gcp_project_id = $3, client_configs = $4, updated_at = now() WHERE id = $5",
        )
        .bind(&arn)
        .bind(&ext)
        .bind(&gcp)
        .bind(&new_config)
        .bind(id)
        .execute(&mut *tx)
        .await;
    }

    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "client_integrations_updated",
        &format!("client_id={}", id),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

#[derive(Deserialize, Default)]
struct OastTestBody {
    listener_url: Option<String>,
    api_key: Option<String>,
}

/// POST /api/onboarding/oast-test — verify OAST listener reachability (live HTTP probe).
async fn api_onboarding_oast_test(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<OastTestBody>,
) -> Response {
    let _ = state;
    let _ = auth;
    let listener = body
        .listener_url
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("WEISSMAN_OAST_LISTENER_URL").ok().and_then(|s| {
                let t = s.trim().to_string();
                if t.is_empty() { None } else { Some(t) }
            })
        });
    let Some(base) = listener else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "oast_listener_url required"})),
        )
            .into_response();
    };
    let url = format!("{}/api/oast/health", base.trim_end_matches('/'));
    // SSRF guard: reject non-http(s), cloud-metadata, *.internal and loopback listener URLs before
    // issuing any outbound request — a tenant user controls `listener_url`.
    if let Err(e) = crate::security_hardening::validate_poe_target_url(&url) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": format!("listener_url rejected: {}", e)})),
        )
            .into_response();
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();
    let mut req = client.get(&url);
    if let Some(k) = body
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "••••••••")
    {
        // caller-supplied key — safe to forward to the caller's own URL
        req = req.header("Authorization", format!("Bearer {}", k));
    } else if let Ok(k) = std::env::var("WEISSMAN_OAST_API_KEY") {
        let k = k.trim();
        // NEVER leak the server's OAST key to an arbitrary user-supplied host — forward it only when
        // the target host matches the configured WEISSMAN_OAST_LISTENER_URL host.
        let env_host = std::env::var("WEISSMAN_OAST_LISTENER_URL")
            .ok()
            .and_then(|u| url::Url::parse(u.trim()).ok())
            .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()));
        let target_host = url::Url::parse(&url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()));
        if !k.is_empty() && env_host.is_some() && env_host == target_host {
            req = req.header("Authorization", format!("Bearer {}", k));
        }
    }
    match req.send().await {
        Ok(resp) if resp.status().is_success() => (
            StatusCode::OK,
            Json(json!({"ok": true, "status": resp.status().as_u16(), "url": url})),
        )
            .into_response(),
        Ok(resp) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "ok": false,
                "detail": format!("OAST listener returned HTTP {}", resp.status()),
                "url": url,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "detail": format!("OAST listener unreachable: {}", e), "url": url})),
        )
            .into_response(),
    }
}

async fn api_client_cloud_scan_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    if let Err(detail) =
        crate::billing::gate_scan_enqueue(state.auth_pool.as_ref(), auth.tenant_id).await
    {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"ok": false, "detail": detail})),
        )
            .into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query(
        "SELECT COALESCE(trim(aws_cross_account_role_arn),'') AS role_arn, COALESCE(trim(aws_external_id),'') AS ext FROM clients WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let Some(_r) = row else {
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    };
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "cloud_scan_run",
        json!({ "client_id": id }),
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "cloud scan queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue cloud_scan_run failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
            )
                .into_response()
        }
    }
}

async fn api_compliance_posture(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<CompliancePostureQuery>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"frameworks": []}))).into_response();
    };
    let mappings = match crate::compliance_engine::load_mappings(&mut *tx).await {
        Ok(m) => m,
        Err(_) => {
            let _ = tx.rollback().await;
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"frameworks": []}))).into_response();
        }
    };
    let cloud_rows = if let Some(cid) = q.client_id {
        sqlx::query("SELECT rule_id FROM cloud_scan_findings WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query("SELECT rule_id FROM cloud_scan_findings")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    };
    let cloud_rules: Vec<String> = cloud_rows
        .into_iter()
        .filter_map(|r| r.try_get::<String, _>("rule_id").ok())
        .collect();

    let vuln_rows = if let Some(cid) = q.client_id {
        sqlx::query("SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query("SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    };
    let vulns: Vec<(String, String, String)> = vuln_rows
        .into_iter()
        .filter_map(|r| {
            Some((
                r.try_get::<String, _>("source").ok()?,
                r.try_get::<String, _>("title").ok()?,
                r.try_get::<String, _>("severity").ok()?,
            ))
        })
        .collect();
    let _ = tx.commit().await;

    let frameworks = crate::compliance_engine::compute_posture(&mappings, &cloud_rules, &vulns);
    let body = crate::compliance_engine::CompliancePostureResponse {
        frameworks,
        violations_preview: vec![],
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn api_reports_executive(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<ExecutiveReportQuery>,
    headers: HeaderMap,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB unavailable"}))).into_response();
    };
    let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(auth.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "Tenant".to_string());

    let client_name: Option<String> = if let Some(cid) = q.client_id {
        sqlx::query_scalar("SELECT name FROM clients WHERE id = $1")
            .bind(cid)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    // Aggregate severity counts in SQL instead of loading the entire (fastest-growing) table
    // into Rust and counting row-by-row. The FILTER ladder mirrors the previous
    // critical > high > medium > low precedence exactly.
    const SEV_AGG: &str = "COUNT(*) FILTER (WHERE lower(severity) LIKE '%critical%') AS critical, \
         COUNT(*) FILTER (WHERE lower(severity) NOT LIKE '%critical%' AND lower(severity) LIKE '%high%') AS high, \
         COUNT(*) FILTER (WHERE lower(severity) NOT LIKE '%critical%' AND lower(severity) NOT LIKE '%high%' AND lower(severity) LIKE '%med%') AS medium, \
         COUNT(*) FILTER (WHERE lower(severity) NOT LIKE '%critical%' AND lower(severity) NOT LIKE '%high%' AND lower(severity) NOT LIKE '%med%') AS low";
    let sev_row = if let Some(cid) = q.client_id {
        sqlx::query(&format!(
            "SELECT {SEV_AGG} FROM vulnerabilities WHERE client_id = $1"
        ))
        .bind(cid)
        .fetch_one(&mut *tx)
        .await
    } else {
        sqlx::query(&format!("SELECT {SEV_AGG} FROM vulnerabilities"))
            .fetch_one(&mut *tx)
            .await
    };
    let (mut critical, mut high, mut medium, mut low) = (0u32, 0u32, 0u32, 0u32);
    if let Ok(r) = sev_row {
        critical = r.try_get::<i64, _>("critical").unwrap_or(0).max(0) as u32;
        high = r.try_get::<i64, _>("high").unwrap_or(0).max(0) as u32;
        medium = r.try_get::<i64, _>("medium").unwrap_or(0).max(0) as u32;
        low = r.try_get::<i64, _>("low").unwrap_or(0).max(0) as u32;
    }

    let cloud_n: i64 = if let Some(cid) = q.client_id {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM cloud_scan_findings WHERE client_id = $1")
            .bind(cid)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0)
    } else {
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM cloud_scan_findings")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0)
    };

    let mappings = match crate::compliance_engine::load_mappings(&mut *tx).await {
        Ok(m) => m,
        Err(_) => {
            let _ = tx.rollback().await;
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "compliance catalog"}))).into_response();
        }
    };
    let cloud_rules: Vec<String> = if let Some(cid) = q.client_id {
        sqlx::query_scalar::<_, String>("SELECT rule_id FROM cloud_scan_findings WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query_scalar::<_, String>("SELECT rule_id FROM cloud_scan_findings")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    };
    let vuln_tuples: Vec<(String, String, String)> = if let Some(cid) = q.client_id {
        let rows = sqlx::query("SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default();
        rows.into_iter()
            .filter_map(|r| {
                Some((
                    r.try_get::<String, _>("source").ok()?,
                    r.try_get::<String, _>("title").ok()?,
                    r.try_get::<String, _>("severity").ok()?,
                ))
            })
            .collect()
    } else {
        let rows = sqlx::query("SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default();
        rows.into_iter()
            .filter_map(|r| {
                Some((
                    r.try_get::<String, _>("source").ok()?,
                    r.try_get::<String, _>("title").ok()?,
                    r.try_get::<String, _>("severity").ok()?,
                ))
            })
            .collect()
    };
    let _ = tx.commit().await;

    let posture = crate::compliance_engine::compute_posture(&mappings, &cloud_rules, &vuln_tuples);
    let soc2 = posture.iter().find(|p| p.framework == "SOC2").map(|p| p.compliance_percent).unwrap_or(100);
    let iso = posture
        .iter()
        .find(|p| p.framework == "ISO27001")
        .map(|p| p.compliance_percent)
        .unwrap_or(100);
    let gdpr = posture
        .iter()
        .find(|p| p.framework == "GDPR")
        .map(|p| p.compliance_percent)
        .unwrap_or(100);

    let lang = report_lang(
        &LangQuery {
            lang: q.lang.clone(),
        },
        &headers,
    );
    let pdf = match crate::pdf_report::build_executive_board_pdf_lang(
        &tenant_name,
        client_name.as_deref(),
        critical,
        high,
        medium,
        low,
        cloud_n.max(0) as usize,
        soc2,
        iso,
        gdpr,
        lang,
    ) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "PDF failed", "detail": e})),
            )
                .into_response();
        }
    };
    let scope = client_name.as_deref().unwrap_or("tenant");
    let safe_scope: String = scope
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    let filename = format!("Weissman_Board_Report_{}.pdf", safe_scope);
    let mut res = Response::new(Body::from(pdf));
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/pdf"));
    res.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::try_from(format!("attachment; filename=\"{}\"", filename)).unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    res.headers_mut().insert(
        axum::http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    res
}
