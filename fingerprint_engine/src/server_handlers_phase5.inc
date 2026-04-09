async fn ws_swarm(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> Response {
    let mut rx = state.swarm_broadcast_tx.subscribe();
    ws.on_upgrade(move |mut socket| async move {
        while let Ok(msg) = rx.recv().await {
            if socket.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    })
}

async fn api_swarm_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(client_id)
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(false);
    let _ = tx.commit().await;
    if !ok {
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    }
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "swarm_run",
        json!({ "client_id": client_id }),
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
                "message": "swarm run queued; poll status_url and /ws/swarm for live events",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue swarm_run failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_threat_ingest_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let llm_base = sqlx::query_scalar::<_, String>(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .filter(|s| !s.trim().is_empty())
    .unwrap_or_else(|| {
        std::env::var("WEISSMAN_LLM_BASE_URL")
            .or_else(|_| std::env::var("LLM_BASE_URL"))
            .unwrap_or_else(|_| "http://127.0.0.1:8000/v1".into())
    });
    let llm_model = sqlx::query_scalar::<_, String>(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    let _ = tx.commit().await;
    let payload = json!({
        "llm_base": llm_base,
        "llm_model": llm_model,
    });
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "threat_ingest_run",
        payload,
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
                "message": "Threat ingestion queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue threat_ingest_run failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct SbomComponentBody {
    package_name: String,
    ecosystem: Option<String>,
    version_spec: Option<String>,
}

async fn api_client_sbom_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Value::Object(serde_json::Map::from_iter([(
                "components".to_string(),
                Value::Array(vec![]),
            )]))),
        )
            .into_response();
    };
    let rows = sqlx::query(
        "SELECT id, package_name, ecosystem, version_spec, source, created_at FROM client_sbom_components WHERE client_id = $1 ORDER BY id DESC",
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "package_name": r.try_get::<String,_>("package_name").unwrap_or_default(),
                "ecosystem": r.try_get::<String,_>("ecosystem").unwrap_or_default(),
                "version_spec": r.try_get::<String,_>("version_spec").unwrap_or_default(),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "components": out }))).into_response()
}

async fn api_client_sbom_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Json(body): Json<SbomComponentBody>,
) -> Response {
    let pkg = body.package_name.trim();
    if pkg.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false}))).into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let eco = body.ecosystem.as_deref().unwrap_or("").to_string();
    let ver = body.version_spec.as_deref().unwrap_or("*").to_string();
    let res = sqlx::query(
        r#"INSERT INTO client_sbom_components (tenant_id, client_id, package_name, ecosystem, version_spec, source)
           VALUES ($1, $2, $3, $4, $5, 'manual')"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(pkg)
    .bind(&eco)
    .bind(&ver)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct ContainmentRuleBody {
    name: String,
    enabled: Option<bool>,
    pre_approved: Option<bool>,
    aws_region: Option<String>,
    forensic_source_cidr: Option<String>,
    forensic_ports_csv: Option<String>,
    k8s_api_server: Option<String>,
    k8s_token_env_var: Option<String>,
    k8s_namespace: Option<String>,
    k8s_pod_label_key: Option<String>,
    k8s_pod_label_value: Option<String>,
    allow_dns_egress: Option<bool>,
}

async fn api_containment_rules_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Value::Object(serde_json::Map::from_iter([(
                "rules".to_string(),
                Value::Array(vec![]),
            )]))),
        )
            .into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, name, enabled, pre_approved, aws_region, forensic_source_cidr, forensic_ports_csv,
                  k8s_api_server, k8s_token_env_var, k8s_namespace, k8s_pod_label_key, k8s_pod_label_value, allow_dns_egress, created_at
           FROM containment_rules WHERE client_id = $1 ORDER BY id DESC"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "name": r.try_get::<String,_>("name").unwrap_or_default(),
                "enabled": r.try_get::<bool,_>("enabled").unwrap_or(false),
                "pre_approved": r.try_get::<bool,_>("pre_approved").unwrap_or(false),
                "aws_region": r.try_get::<String,_>("aws_region").unwrap_or_default(),
                "forensic_source_cidr": r.try_get::<String,_>("forensic_source_cidr").unwrap_or_default(),
                "forensic_ports_csv": r.try_get::<String,_>("forensic_ports_csv").unwrap_or_default(),
                "k8s_api_server": r.try_get::<String,_>("k8s_api_server").unwrap_or_default(),
                "k8s_token_env_var": r.try_get::<String,_>("k8s_token_env_var").unwrap_or_default(),
                "k8s_namespace": r.try_get::<String,_>("k8s_namespace").unwrap_or_default(),
                "k8s_pod_label_key": r.try_get::<String,_>("k8s_pod_label_key").unwrap_or_default(),
                "k8s_pod_label_value": r.try_get::<String,_>("k8s_pod_label_value").unwrap_or_default(),
                "allow_dns_egress": r.try_get::<bool,_>("allow_dns_egress").unwrap_or(true),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "rules": out }))).into_response()
}

async fn api_containment_rules_post(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Json(body): Json<ContainmentRuleBody>,
) -> Response {
    let name = body.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false}))).into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query(
        r#"INSERT INTO containment_rules (tenant_id, client_id, name, enabled, pre_approved, aws_region, forensic_source_cidr, forensic_ports_csv,
               k8s_api_server, k8s_token_env_var, k8s_namespace, k8s_pod_label_key, k8s_pod_label_value, allow_dns_egress)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(name)
    .bind(body.enabled.unwrap_or(false))
    .bind(body.pre_approved.unwrap_or(false))
    .bind(body.aws_region.as_deref().unwrap_or(""))
    .bind(body.forensic_source_cidr.as_deref().unwrap_or("0.0.0.0/0"))
    .bind(body.forensic_ports_csv.as_deref().unwrap_or("22,443"))
    .bind(body.k8s_api_server.as_deref().unwrap_or(""))
    .bind(body.k8s_token_env_var.as_deref().unwrap_or(""))
    .bind(body.k8s_namespace.as_deref().unwrap_or("default"))
    .bind(body.k8s_pod_label_key.as_deref().unwrap_or(""))
    .bind(body.k8s_pod_label_value.as_deref().unwrap_or(""))
    .bind(body.allow_dns_egress.unwrap_or(true))
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct ContainmentExecuteBody {
    rule_id: i64,
    mode: String,
    aws_instance_id: Option<String>,
    confirm: bool,
}

async fn api_containment_execute(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(client_id): Path<i64>,
    Json(body): Json<ContainmentExecuteBody>,
) -> Response {
    if !body.confirm {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "confirm must be true"})),
        )
            .into_response();
    }
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    if !crate::security_hardening::destructive_action_authorized(&headers) {
        if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
            let _ = audit_log::insert_audit(
                &mut tx,
                auth.tenant_id,
                Some(auth.user_id),
                &actor,
                "destructive_confirm_denied",
                "containment_execute",
                &ip,
            )
            .await;
            let _ = tx.commit().await;
        }
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "detail": "X-Weissman-Destructive-Confirm required for containment execute"})),
        )
            .into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query(
        r#"SELECT id, enabled, pre_approved, aws_region, forensic_source_cidr, forensic_ports_csv, allow_dns_egress,
                  k8s_api_server, k8s_token_env_var, k8s_namespace, k8s_pod_label_key, k8s_pod_label_value
           FROM containment_rules WHERE id = $1 AND client_id = $2 AND tenant_id = $3"#,
    )
    .bind(body.rule_id)
    .bind(client_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response();
    };
    let enabled: bool = r.try_get("enabled").unwrap_or(false);
    let pre: bool = r.try_get("pre_approved").unwrap_or(false);
    if !enabled || !pre {
        let _ = tx.rollback().await;
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "detail": "rule must be enabled and pre_approved"})),
        )
            .into_response();
    }
    let aws_region: String = r.try_get("aws_region").unwrap_or_default();
    let forensic_cidr: String = r.try_get("forensic_source_cidr").unwrap_or_default();
    let ports_csv: String = r.try_get("forensic_ports_csv").unwrap_or_default();
    let allow_dns: bool = r.try_get("allow_dns_egress").unwrap_or(true);
    let k8s_api: String = r.try_get("k8s_api_server").unwrap_or_default();
    let k8s_env: String = r.try_get("k8s_token_env_var").unwrap_or_default();
    let k8s_ns: String = r.try_get("k8s_namespace").unwrap_or_default();
    let k8s_lk: String = r.try_get("k8s_pod_label_key").unwrap_or_default();
    let k8s_lv: String = r.try_get("k8s_pod_label_value").unwrap_or_default();
    let role_row = sqlx::query(
        "SELECT COALESCE(trim(aws_cross_account_role_arn),'') AS arn, COALESCE(trim(aws_external_id),'') AS ext FROM clients WHERE id = $1",
    )
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let (role_arn, ext) = match role_row {
        Some(x) => (
            x.try_get::<String, _>("arn").unwrap_or_default(),
            x.try_get::<String, _>("ext").unwrap_or_default(),
        ),
        None => (String::new(), String::new()),
    };

    let mode = body.mode.to_lowercase();
    if mode == "aws_sg" {
        let iid = body.aws_instance_id.as_deref().unwrap_or("").trim();
        if iid.is_empty() || !iid.starts_with("i-") {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "aws_instance_id required"})),
            )
                .into_response();
        }
        if role_arn.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "client aws_cross_account_role_arn required"})),
            )
                .into_response();
        }
        let aws_cfg = crate::cloud_integration_engine::CrossAccountAwsConfig {
            role_arn,
            external_id: ext,
            session_name: "weissman-containment".into(),
        };
        let vpc_dns = std::env::var("WEISSMAN_QUARANTINE_VPC_DNS_CIDR").unwrap_or_else(|_| "10.0.0.2/32".into());
        match crate::cloud_containment_engine::execute_aws_containment(
            &aws_cfg,
            &aws_region,
            iid,
            &forensic_cidr,
            &ports_csv,
            allow_dns,
            &vpc_dns,
        )
        .await
        {
            Ok(msg) => {
                let _ = state.telemetry_broadcast_tx.send(
                    json!({
                        "event": "containment_executed",
                        "severity": "critical",
                        "client_id": client_id.to_string(),
                        "message": msg,
                    })
                    .to_string(),
                );
                (StatusCode::OK, Json(json!({"ok": true, "detail": msg}))).into_response()
            }
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "detail": e})),
            )
                .into_response(),
        }
    } else if mode == "k8s_netpol" {
        let api = k8s_api.trim();
        if api.is_empty() || k8s_env.trim().is_empty() || k8s_lk.is_empty() || k8s_lv.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "k8s_api_server, k8s_token_env_var, pod labels required on rule"})),
            )
                .into_response();
        }
        let token = std::env::var(k8s_env.trim()).unwrap_or_default();
        if token.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": format!("environment variable {} empty", k8s_env.trim())})),
            )
                .into_response();
        }
        let ports: Vec<i32> = ports_csv
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        if ports.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "forensic_ports_csv must list numeric ports"})),
            )
                .into_response();
        }
        let insecure = std::env::var("WEISSMAN_K8S_INSECURE_TLS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let pname = format!("weissman-qtn-{}", body.rule_id);
        match crate::cloud_containment_engine::apply_k8s_quarantine_network_policy(
            api,
            &token,
            &k8s_ns,
            &pname,
            &k8s_lk,
            &k8s_lv,
            forensic_cidr.trim(),
            &ports,
            insecure,
        )
        .await
        {
            Ok(msg) => {
                let _ = state.telemetry_broadcast_tx.send(
                    json!({
                        "event": "containment_k8s_applied",
                        "severity": "critical",
                        "client_id": client_id.to_string(),
                        "message": msg,
                    })
                    .to_string(),
                );
                (StatusCode::OK, Json(json!({"ok": true, "detail": msg}))).into_response()
            }
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "detail": e})),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "mode must be aws_sg or k8s_netpol"})),
        )
            .into_response()
    }
}
