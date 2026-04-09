// Remaining REST handlers: engines, PoE, pipeline, risk graph, traces, heal, deception, payload sync.
// cfg_string_tx for jobs lives in async_job_executor.rs (this include had an unused duplicate).

async fn api_deep_fuzz(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(body): Json<DeepFuzzBody>,
) -> Response {
    let target = body.target.as_deref().unwrap_or("").trim();
    if target.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "target required"}))).into_response();
    }
    let mut map = serde_json::Map::new();
    map.insert("target".into(), json!(target));
    if let Some(cid) = body.client_id {
        map.insert("client_id".into(), json!(cid));
    }
    if let Some(paths) = body.discovered_paths.clone() {
        if !paths.is_empty() {
            map.insert("discovered_paths".into(), json!(paths));
        }
    }
    let mut payload = Value::Object(map);
    crate::fuzz_oob::enrich_job_payload_with_oast_scan_binding(&mut payload);
    crate::edge_swarm_intel::enrich_scan_payload_with_edge_node(
        state.app_pool.as_ref(),
        auth.tenant_id,
        target,
        &mut payload,
    )
    .await;
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "deep_fuzz",
        payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "deep fuzz queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue deep_fuzz failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "enqueue_failed", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_general_mission(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(body): Json<GeneralMissionBody>,
) -> Response {
    let domain = body.domain.as_deref().unwrap_or("").trim();
    if domain.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "domain required"}))).into_response();
    }
    let mut map = serde_json::Map::new();
    map.insert("domain".into(), json!(domain));
    if let Some(cid) = body.client_id {
        map.insert("client_id".into(), json!(cid));
    }
    let mut payload = Value::Object(map);
    crate::fuzz_oob::enrich_job_payload_with_oast_scan_binding(&mut payload);
    let edge_target = if domain.starts_with("http://") || domain.starts_with("https://") {
        domain.to_string()
    } else {
        format!("https://{}", domain.trim_start_matches('/'))
    };
    crate::edge_swarm_intel::enrich_scan_payload_with_edge_node(
        state.app_pool.as_ref(),
        auth.tenant_id,
        edge_target.as_str(),
        &mut payload,
    )
    .await;
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "general_mission",
        payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "General mission (vLLM plan → ASM → refine → semantic) queued",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue general_mission failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "enqueue_failed", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_council_debate(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(body): Json<CouncilDebateBody>,
) -> Response {
    let brief = body.target_brief.as_deref().unwrap_or("").trim();
    if brief.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "target_brief required"})),
        )
            .into_response();
    }
    let mut map = serde_json::Map::new();
    map.insert("target_brief".into(), json!(brief));
    if let Some(cid) = body.client_id {
        map.insert("client_id".into(), json!(cid));
    }
    if let Some(fl) = body.failure_log.as_deref().filter(|s| !s.trim().is_empty()) {
        map.insert("failure_log".into(), json!(fl));
    }
    if body.verify_oob == Some(true) {
        map.insert("verify_oob".into(), json!(true));
    }
    if body.supreme == Some(true) {
        map.insert("supreme".into(), json!(true));
    }
    if body.supreme_command_protocol == Some(true) {
        map.insert("supreme_command_protocol".into(), json!(true));
        map.insert("actor_user_id".into(), json!(auth.user_id));
    }
    if let Some(n) = body.max_council_rounds {
        map.insert("max_council_rounds".into(), json!(n.clamp(1, 20)));
    }
    if let Some(tok) = body
        .fallback_oast_token
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        map.insert("fallback_oast_token".into(), json!(tok));
    }
    let mut payload = Value::Object(map);
    if body.verify_oob == Some(true) {
        crate::fuzz_oob::enrich_job_payload_with_oast_scan_binding(&mut payload);
    }
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "council_debate",
        payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "Council debate (MoA Alpha→Beta→Gamma) queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue council_debate failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "enqueue_failed", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_general_ascension(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
) -> Response {
    let payload = json!({});
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "ascension_wave",
        payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "Ascension wave (mission map → risk-ranked jobs) queued",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue ascension_wave failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "enqueue_failed", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_general_self_audit(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = crate::http::extract_client_ip(&headers, addr);
    let actor = crate::audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    match crate::strategy_engine::run_self_defense_audit(
        state.app_pool.as_ref(),
        auth.tenant_id,
        Some(auth.user_id),
        actor.as_str(),
        ip.as_str(),
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response(),
    }
}

async fn api_timing_scan_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(body): Json<TimingScanRunBody>,
) -> Response {
    let target = body.target.as_deref().unwrap_or("").trim();
    if target.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "target required"}))).into_response();
    }
    let client_id_resp = body.client_id.clone();
    let mut map = serde_json::Map::new();
    map.insert("target".into(), json!(target));
    if let Some(ref cid) = body.client_id {
        if !cid.is_empty() {
            map.insert("client_id".into(), json!(cid));
        }
    }
    let payload = Value::Object(map);
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "timing_scan",
        payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "client_id": client_id_resp,
                "message": "timing scan queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue timing_scan failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "enqueue_failed", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_ai_redteam_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(body): Json<AiRedteamRunBody>,
) -> Response {
    let target = body.target.as_deref().unwrap_or("").trim();
    if target.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "target required"}))).into_response();
    }
    let client_id_resp = body.client_id.clone();
    let mut map = serde_json::Map::new();
    map.insert("target".into(), json!(target));
    if let Some(ref cid) = body.client_id {
        if !cid.is_empty() {
            map.insert("client_id".into(), json!(cid));
        }
    }
    if let Some(ref ep) = body.ai_endpoint {
        if !ep.trim().is_empty() {
            map.insert("ai_endpoint".into(), json!(ep));
        }
    }
    let payload = Value::Object(map);
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "ai_redteam",
        payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "client_id": client_id_resp,
                "message": "AI redteam queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue ai_redteam failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "enqueue_failed", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_threat_intel_feed() -> Response {
    let items = threat_intel_engine::fetch_nvd_recent(7).await;
    (StatusCode::OK, Json(json!({ "items": items }))).into_response()
}

async fn api_threat_intel_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
) -> Response {
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "threat_intel_run",
        json!({}),
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "threat intel radar queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue threat_intel_run failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "enqueue_failed", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_pipeline_scan_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Json(body): Json<PipelineScanRunBody>,
) -> Response {
    let repo = body.repo_url.trim();
    if repo.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "repo_url required"}))).into_response();
    }
    let client_id_resp = body.client_id.clone();
    let mut map = serde_json::Map::new();
    map.insert("repo_url".into(), json!(repo));
    let cid_trim = body.client_id.trim();
    if !cid_trim.is_empty() {
        if let Ok(cid) = cid_trim.parse::<i64>() {
            map.insert("client_id".into(), json!(cid));
        }
    }
    let payload = Value::Object(map);
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "pipeline_scan",
        payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "client_id": client_id_resp,
                "message": "pipeline scan queued; poll GET /api/jobs/:job_id",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue pipeline_scan failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "enqueue_failed", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_client_cicd_findings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"findings": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, finding_id, title, severity, source, COALESCE(description,''), COALESCE(poc_exploit,'')
           FROM vulnerabilities WHERE client_id = $1
           AND (lower(source) LIKE '%cicd%' OR lower(source) LIKE '%pipeline%')
           ORDER BY discovered_at DESC"#,
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let findings: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "finding_id": r.try_get::<String,_>("finding_id").unwrap_or_default(),
                "title": r.try_get::<String,_>("title").unwrap_or_default(),
                "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "description": r.try_get::<String,_>("description").unwrap_or_default(),
                "poc_exploit": r.try_get::<String,_>("poc_exploit").unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "findings": findings }))).into_response()
}

fn poe_spawn_job(
    state: Arc<AppState>,
    auth: AuthContext,
    client_id: i64,
    target: String,
    job_id: String,
) {
    let app = state.app_pool.clone();
    let intel = state.intel_pool.clone();
    let poe_tx = state.poe_job_updates_tx.clone();
    let reg = state.poe_job_registry.clone();
    let tenant_id = auth.tenant_id;
    tokio::spawn(async move {
        let run_id: i64 = {
            let Ok(mut tx) = db::begin_tenant_tx(app.as_ref(), tenant_id).await else {
                return;
            };
            let rid: Result<i64, sqlx::Error> = sqlx::query_scalar(
                "INSERT INTO report_runs (tenant_id, summary) VALUES ($1, $2) RETURNING id",
            )
            .bind(tenant_id)
            .bind(r#"{"source":"poe_api"}"#)
            .fetch_one(&mut *tx)
            .await;
            let Ok(rid) = rid else {
                let _ = tx.rollback().await;
                return;
            };
            let _ = sqlx::query("UPDATE poe_jobs SET run_id = $1 WHERE job_id = $2")
                .bind(rid)
                .bind(&job_id)
                .execute(&mut *tx)
                .await;
            let _ = tx.commit().await;
            rid
        };
        let (prog_tx, prog_rx) = flume::bounded::<(String, String)>(128);
        let reg_fwd = reg.clone();
        let job_key = job_id.clone();
        let poe_fwd = poe_tx.clone();
        tokio::spawn(async move {
            while let Ok((k, v)) = prog_rx.recv_async().await {
                let payload = serde_json::json!({ k: v }).to_string();
                let _ = poe_fwd
                    .send_async((job_key.clone(), payload.clone()))
                    .await;
                if let Some(mut subs) = reg_fwd.get_mut(&job_key) {
                    subs.retain(|s| match s.try_send(payload.clone()) {
                        Ok(()) => true,
                        Err(flume::TrySendError::Full(_)) => true,
                        Err(flume::TrySendError::Disconnected(_)) => false,
                    });
                }
            }
        });
        let cfg = match crate::orchestrator::load_poe_config_http(app.as_ref(), tenant_id, intel.clone()).await {
            Ok(c) => c,
            Err(e) => {
                if let Ok(mut tx) = db::begin_tenant_tx(app.as_ref(), tenant_id).await {
                    let _ = sqlx::query(
                        "UPDATE poe_jobs SET status = $1, error = $2, updated_at = now() WHERE job_id = $3",
                    )
                    .bind("failed")
                    .bind(e.to_string())
                    .bind(&job_id)
                    .execute(&mut *tx)
                    .await;
                    let _ = tx.commit().await;
                }
                return;
            }
        };
        let result = exploit_synthesis_engine::run_exploit_synthesis_async(
            &target,
            &cfg,
            Some((job_id.clone(), prog_tx)),
            None,
            Some(tenant_id),
        )
        .await;
        let findings_json = serde_json::to_string(&result.findings).unwrap_or_else(|_| "[]".to_string());
        let status = if result.status == "ok" {
            "completed"
        } else {
            "failed"
        };
        let Ok(mut tx) = db::begin_tenant_tx(app.as_ref(), tenant_id).await else {
            return;
        };
        let _ = sqlx::query(
            "UPDATE poe_jobs SET status = $1, findings_json = $2, message = $3, error = $4, updated_at = now() WHERE job_id = $5",
        )
        .bind(status)
        .bind(&findings_json)
        .bind(&result.message)
        .bind(if result.status == "ok" {
            None::<String>
        } else {
            Some(result.message.clone())
        })
        .bind(&job_id)
        .execute(&mut *tx)
        .await;
        if result.status == "ok" {
            for (i, f) in result.findings.iter().enumerate() {
                if let Some(obj) = f.as_object() {
                    let title = obj
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or("PoE finding")
                        .to_string();
                    let severity = obj
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or("high")
                        .to_string();
                    let fid = format!("poe_synthesis-{}-{}", run_id, i);
                    let remediation_snippet = obj
                        .get("remediation_snippet")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let generated_patch = obj
                        .get("generated_patch")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let desc_json = serde_json::json!({
                        "footprint": obj.get("footprint").and_then(Value::as_str).unwrap_or(""),
                        "verified": obj.get("verified").and_then(Value::as_bool).unwrap_or(false),
                        "expected_verification": obj.get("expected_verification").and_then(Value::as_str).unwrap_or(""),
                        "weaponization_status": "SAFE (Proof of Exploitability Only)",
                        "remediation_snippet": remediation_snippet,
                        "generated_patch": generated_patch,
                    });
                    let desc = serde_json::to_string(&desc_json).unwrap_or_default();
                    let poc_exploit = obj.get("poc_exploit").and_then(Value::as_str).unwrap_or("");
                    if sqlx::query(
                        r#"INSERT INTO vulnerabilities (run_id, tenant_id, client_id, finding_id, title, severity, source, description, status, poc_exploit, generated_patch, discovered_at)
                           VALUES ($1, $2, $3, $4, $5, $6, 'poe_synthesis', $7, 'OPEN', $8, $9, now())"#,
                    )
                    .bind(run_id)
                    .bind(tenant_id)
                    .bind(client_id)
                    .bind(&fid)
                    .bind(&title)
                    .bind(&severity)
                    .bind(&desc)
                    .bind(poc_exploit)
                    .bind(generated_patch)
                    .execute(&mut *tx)
                    .await
                    .is_ok()
                    {
                        let cid_str = client_id.to_string();
                        crate::notifications::spawn_critical_poe_alert(
                            Arc::clone(&app),
                            tenant_id,
                            &cid_str,
                            &fid,
                            &title,
                            &severity,
                            poc_exploit,
                        );
                    }
                }
            }
        }
        let _ = tx.commit().await;
    });
}

async fn api_poe_scan_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<PoEScanRunBody>,
) -> Response {
    let target = body.target_url.trim().to_string();
    let client_id: i64 = body.client_id.trim().parse().unwrap_or(0);
    if target.is_empty() || client_id == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "target_url and client_id required"})),
        )
            .into_response();
    }
    if let Err(e) = crate::security_hardening::validate_poe_target_url(&target) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid target_url", "detail": e})),
        )
            .into_response();
    }
    let job_id = uuid::Uuid::new_v4().to_string();
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1)")
        .bind(client_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(false);
    if !exists {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"error": "client not found"}))).into_response();
    }
    if sqlx::query(
        "INSERT INTO poe_jobs (job_id, tenant_id, client_id, target, status) VALUES ($1, $2, $3, $4, 'running')",
    )
    .bind(&job_id)
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(&target)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "insert job failed"}))).into_response();
    }
    let _ = tx.commit().await;
    poe_spawn_job(state, auth, client_id, target, job_id.clone());
    (StatusCode::ACCEPTED, Json(json!({ "job_id": job_id }))).into_response()
}

async fn api_poe_scan_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    match poe_job_from_db(state.app_pool.as_ref(), auth.tenant_id, &job_id).await {
        Some(s) => (StatusCode::OK, Json(json!(s))).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "job not found"}))).into_response(),
    }
}

async fn api_poe_scan_stream(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    let initial = poe_job_json_from_db(state.app_pool.as_ref(), auth.tenant_id, &job_id)
        .await
        .unwrap_or_else(|| "{}".to_string());
    let (tx, rx) = flume::bounded::<String>(128);
    state
        .poe_job_registry
        .entry(job_id.clone())
        .or_default()
        .push(tx);
    let stream = stream! {
        yield Ok::<Event, Infallible>(Event::default().data(initial));
        while let Ok(msg) = rx.recv_async().await {
            yield Ok(Event::default().data(msg));
        }
    };
    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(25)))
        .into_response()
}

async fn api_client_poe_findings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"findings": []}))).into_response();
    };
    let rows = sqlx::query(
        "SELECT id, finding_id, title, severity, description, poc_exploit, discovered_at FROM vulnerabilities WHERE client_id = $1 AND source = 'poe_synthesis' ORDER BY discovered_at DESC",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let findings: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "finding_id": r.try_get::<String,_>("finding_id").unwrap_or_default(),
                "title": r.try_get::<String,_>("title").unwrap_or_default(),
                "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
                "description": r.try_get::<String,_>("description").unwrap_or_default(),
                "poc_exploit": r.try_get::<String,_>("poc_exploit").unwrap_or_default(),
                "discovered_at": r.try_get::<chrono::DateTime<Utc>,_>("discovered_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "findings": findings }))).into_response()
}

async fn api_client_attack_chain(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"steps": []}))).into_response();
    };
    let max_run: Option<i64> = sqlx::query_scalar("SELECT MAX(run_id) FROM attack_chain WHERE client_id = $1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let steps: Vec<Value> = if let Some(rid) = max_run {
        let rows = sqlx::query(
            "SELECT step_order, step_label, finding_ref, payload_or_action FROM attack_chain WHERE client_id = $1 AND run_id = $2 ORDER BY step_order",
        )
        .bind(id)
        .bind(rid)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .map(|r| {
                json!({
                    "step_order": r.try_get::<i32,_>("step_order").unwrap_or(0),
                    "step_label": r.try_get::<String,_>("step_label").unwrap_or_default(),
                    "finding_ref": r.try_get::<Option<String>,_>("finding_ref").ok().flatten(),
                    "payload_or_action": r.try_get::<Option<String>,_>("payload_or_action").ok().flatten(),
                })
            })
            .collect()
    } else {
        vec![]
    };
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({ "steps": steps }))).into_response()
}

async fn api_identity_contexts_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!([]))).into_response();
    };
    let rows = sqlx::query(
        "SELECT id, role_name, privilege_order, token_type, created_at FROM identity_contexts WHERE client_id = $1 ORDER BY privilege_order, id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "role_name": r.try_get::<String,_>("role_name").unwrap_or_default(),
                "privilege_order": r.try_get::<i32,_>("privilege_order").unwrap_or(0),
                "token_type": r.try_get::<String,_>("token_type").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}

async fn api_identity_contexts_add(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<IdentityContextBody>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query(
        r#"INSERT INTO identity_contexts (tenant_id, client_id, role_name, privilege_order, token_type, token_value)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (tenant_id, client_id, role_name) DO UPDATE SET
             privilege_order = EXCLUDED.privilege_order,
             token_type = EXCLUDED.token_type,
             token_value = EXCLUDED.token_value"#,
    )
    .bind(auth.tenant_id)
    .bind(id)
    .bind(&body.role_name)
    .bind(body.privilege_order)
    .bind(&body.token_type)
    .bind(&body.token_value)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(r) => (
            StatusCode::OK,
            Json(json!({"ok": true, "rows": r.rows_affected()})),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": e.to_string()}))).into_response(),
    }
}

async fn api_identity_contexts_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((cid, ctx_id)): Path<(i64, i64)>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query("DELETE FROM identity_contexts WHERE id = $1 AND client_id = $2")
        .bind(ctx_id)
        .bind(cid)
        .execute(&mut *tx)
        .await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_privilege_escalation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"events": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, from_context, to_context, method, url, response_status, severity, kill_chain_step_order, created_at
           FROM privilege_escalation_events WHERE client_id = $1 ORDER BY id DESC LIMIT 100"#,
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let events: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "from_context": r.try_get::<String,_>("from_context").unwrap_or_default(),
                "to_context": r.try_get::<String,_>("to_context").unwrap_or_default(),
                "method": r.try_get::<String,_>("method").unwrap_or_default(),
                "url": r.try_get::<String,_>("url").unwrap_or_default(),
                "response_status": r.try_get::<Option<i32>,_>("response_status").ok().flatten(),
                "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
                "kill_chain_step_order": r.try_get::<i32,_>("kill_chain_step_order").unwrap_or(0),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "events": events }))).into_response()
}

async fn api_pipeline_state_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<PipelineStateQuery>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!(null))).into_response();
    };
    let row = sqlx::query(
        r#"SELECT run_id, client_id, current_stage, paused, skip_to_stage, updated_at
           FROM pipeline_run_state WHERE tenant_id = $1 AND run_id = $2 AND client_id = $3"#,
    )
    .bind(auth.tenant_id)
    .bind(q.run_id)
    .bind(&q.client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    match row {
        Some(r) => {
            let skip: Option<i32> = r.try_get("skip_to_stage").ok();
            (
                StatusCode::OK,
                Json(json!({
                    "run_id": r.try_get::<i64,_>("run_id").unwrap_or(0),
                    "client_id": r.try_get::<String,_>("client_id").unwrap_or_default(),
                    "current_stage": r.try_get::<i32,_>("current_stage").unwrap_or(0),
                    "paused": r.try_get::<bool,_>("paused").unwrap_or(false),
                    "skip_to_stage": skip,
                    "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
                })),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!(null))).into_response(),
    }
}

async fn api_pipeline_state_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<PipelineStatePatchBody>,
) -> Response {
    let run_id = body.run_id.unwrap_or(0);
    if run_id == 0 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "run_id required"}))).into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query(
        r#"UPDATE pipeline_run_state SET
             paused = COALESCE($4, paused),
             skip_to_stage = COALESCE($5, skip_to_stage),
             updated_at = now()
           WHERE tenant_id = $1 AND run_id = $2 AND client_id = $3"#,
    )
    .bind(auth.tenant_id)
    .bind(run_id)
    .bind(&body.client_id)
    .bind(body.paused)
    .bind(body.skip_to_stage)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_risk_graph_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"nodes":[],"edges":[]}))).into_response();
    };
    let nodes = sqlx::query(
        r#"SELECT id, graph_key, node_type, label, external_id, metadata, risk_score, is_choke_point
           FROM risk_graph_nodes WHERE client_id = $1 ORDER BY id"#,
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let edges = sqlx::query(
        "SELECT id, from_node_id, to_node_id, edge_type, metadata FROM risk_graph_edges WHERE client_id = $1 ORDER BY id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let nodes_j: Vec<Value> = nodes
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "graph_key": r.try_get::<String,_>("graph_key").unwrap_or_default(),
                "node_type": r.try_get::<String,_>("node_type").unwrap_or_default(),
                "label": r.try_get::<String,_>("label").unwrap_or_default(),
                "external_id": r.try_get::<Option<String>,_>("external_id").ok().flatten(),
                "metadata": r.try_get::<String,_>("metadata").unwrap_or_else(|_| "{}".into()),
                "risk_score": r.try_get::<i32,_>("risk_score").unwrap_or(0),
                "is_choke_point": r.try_get::<bool,_>("is_choke_point").unwrap_or(false),
            })
        })
        .collect();
    let edges_j: Vec<Value> = edges
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "from_node_id": r.try_get::<i64,_>("from_node_id").unwrap_or(0),
                "to_node_id": r.try_get::<i64,_>("to_node_id").unwrap_or(0),
                "edge_type": r.try_get::<String,_>("edge_type").unwrap_or_default(),
                "metadata": r.try_get::<String,_>("metadata").unwrap_or_else(|_| "{}".into()),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "nodes": nodes_j, "edges": edges_j }))).into_response()
}

async fn api_risk_graph_export(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    match risk_graph::export_risk_graph_json(&state.app_pool, auth.tenant_id, id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn api_risk_graph_build(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let llm_base: String = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "http://127.0.0.1:8000/v1".into());
    let llm_model: String = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    match risk_graph::build_risk_graph_for_client(&mut tx, auth.tenant_id, id).await {
        Ok((n, e)) => {
            let _ = tx.commit().await;
            let fusion = risk_graph::fusion_ot_it_graph_edges_llm(
                state.app_pool.as_ref(),
                auth.tenant_id,
                id,
                llm_base.as_str(),
                llm_model.as_str(),
            )
            .await
            .unwrap_or(0);
            (
                StatusCode::OK,
                Json(json!({"nodes": n, "edges": e, "fusion_ot_it_edges": fusion})),
            )
                .into_response()
        }
        Err(err) => {
            let _ = tx.rollback().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": err.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_runtime_traces_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!([]))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, run_id, finding_id, trace_id, source_file, line_number, function_name, payload_hash, metadata, created_at
           FROM runtime_traces WHERE client_id = $1 ORDER BY id DESC LIMIT 200"#,
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "run_id": r.try_get::<Option<i64>,_>("run_id").ok().flatten(),
                "finding_id": r.try_get::<Option<String>,_>("finding_id").ok().flatten(),
                "trace_id": r.try_get::<Option<String>,_>("trace_id").ok().flatten(),
                "source_file": r.try_get::<Option<String>,_>("source_file").ok().flatten(),
                "line_number": r.try_get::<Option<i32>,_>("line_number").ok().flatten(),
                "function_name": r.try_get::<Option<String>,_>("function_name").ok().flatten(),
                "payload_hash": r.try_get::<Option<String>,_>("payload_hash").ok().flatten(),
                "metadata": r.try_get::<String,_>("metadata").unwrap_or_else(|_| "{}".into()),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}

async fn api_runtime_traces_ingest(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<RuntimeTraceBody>,
) -> Response {
    let meta = serde_json::to_string(&body.metadata.clone().unwrap_or(json!({})))
        .unwrap_or_else(|_| "{}".to_string());
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query(
        r#"INSERT INTO runtime_traces (tenant_id, client_id, run_id, finding_id, trace_id, source_file, line_number, function_name, payload_hash, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(auth.tenant_id)
    .bind(id)
    .bind(body.run_id)
    .bind(body.finding_id.as_deref())
    .bind(body.trace_id.as_deref())
    .bind(body.source_file.as_deref())
    .bind(body.line_number)
    .bind(body.function_name.as_deref())
    .bind(body.payload_hash.as_deref())
    .bind(&meta)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": e.to_string()}))).into_response(),
    }
}

async fn api_auto_heal(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<AutoHealBody>,
) -> Response {
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
                "auto_heal: missing or invalid X-Weissman-Destructive-Confirm",
                &ip,
            )
            .await;
            let _ = tx.commit().await;
        }
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "destructive_confirm_required",
                "detail": "Set WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET on the server and send matching X-Weissman-Destructive-Confirm header."
            })),
        )
            .into_response();
    }
    if let Err(detail) = crate::security_hardening::validate_finding_id_token(&body.finding_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid finding_id", "detail": detail})),
        )
            .into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let row = sqlx::query(
        "SELECT id, COALESCE(generated_patch,'') AS generated_patch, COALESCE(poc_exploit,'') AS poc_exploit FROM vulnerabilities WHERE client_id = $1 AND finding_id = $2 LIMIT 1",
    )
    .bind(id)
    .bind(&body.finding_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"error": "finding not found"}))).into_response();
    };
    let vuln_id: i64 = r.try_get("id").unwrap_or(0);
    let patch: String = r.try_get::<String, _>("generated_patch").unwrap_or_default();
    let poc_default: String = r.try_get::<String, _>("poc_exploit").unwrap_or_default();
    let _ = tx.commit().await;
    let token = body.git_token.as_deref().unwrap_or("").trim();
    let repo = body.repo_slug.as_deref().unwrap_or("").trim();
    if token.is_empty() || repo.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "git_token and repo_slug required"})),
        )
            .into_response();
    }
    if let Err(detail) = crate::security_hardening::validate_github_repo_slug(repo) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid repo_slug", "detail": detail})),
        )
            .into_response();
    }
    let base = body.base_branch.as_deref().unwrap_or("main");
    if let Err(detail) = crate::security_hardening::validate_git_branch_name(base) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid base_branch", "detail": detail})),
        )
            .into_response();
    }
    let patch_use = if !patch.is_empty() {
        patch.as_str()
    } else {
        body.poc_exploit.as_deref().unwrap_or(&poc_default)
    };
    let poc_curl = body
        .poc_exploit
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(poc_default.as_str());
    if let Err(detail) = crate::security_hardening::validate_remediation_patch(patch_use) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "remediation payload rejected", "detail": detail})),
        )
            .into_response();
    }
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let details = format!(
            "auto_heal client_id={} finding_id={} repo={} branch={}",
            id, body.finding_id, repo, base
        );
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            "destructive_auto_heal_initiated",
            &details,
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }

    let skip = std::env::var("WEISSMAN_AUTOHEAL_SKIP_SANDBOX")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if skip {
        let heal = auto_heal::create_branch_and_pr(token, repo, base, &body.finding_id, patch_use, None, None).await;
        let verif = heal
            .error
            .clone()
            .unwrap_or_else(|| "opened_skip_sandbox".to_string());
        insert_heal_request_row(
            state.app_pool.as_ref(),
            auth.tenant_id,
            id,
            &body.finding_id,
            vuln_id,
            &heal.branch_name,
            heal.pr_url.as_deref(),
            heal.pr_number,
            &heal.diff_summary,
            &verif,
            "",
        )
        .await;
        return (
            StatusCode::OK,
            Json(json!({
                "branch_name": heal.branch_name,
                "pr_url": heal.pr_url,
                "pr_number": heal.pr_number,
                "diff_summary": heal.diff_summary,
                "error": heal.error,
                "skip_sandbox": true,
            })),
        )
            .into_response();
    }

    let spec_id = uuid::Uuid::new_v4();
    let docker_socket = body
        .docker_socket
        .clone()
        .unwrap_or_else(|| "/var/run/docker.sock".to_string());
    let image = body
        .image
        .clone()
        .unwrap_or_else(|| "node:20-bookworm".to_string());
    let container_port = body.container_port.unwrap_or(3000);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let ins = sqlx::query(
        r#"INSERT INTO auto_heal_job_specs (
            id, tenant_id, user_id, client_id, vuln_id, finding_id,
            git_token, repo_slug, base_branch, patch_text, poc_curl,
            docker_socket, image, container_port, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'pending')"#,
    )
    .bind(spec_id)
    .bind(auth.tenant_id)
    .bind(auth.user_id)
    .bind(id)
    .bind(vuln_id)
    .bind(&body.finding_id)
    .bind(token)
    .bind(repo)
    .bind(base)
    .bind(patch_use)
    .bind(poc_curl)
    .bind(&docker_socket)
    .bind(&image)
    .bind(container_port as i32)
    .execute(&mut *tx)
    .await;
    if ins.is_err() {
        let _ = tx.rollback().await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to persist auto_heal spec"})),
        )
            .into_response();
    }
    let _ = tx.commit().await;

    let queue_payload = json!({ "spec_id": spec_id.to_string() });
    match db::job_queue::enqueue_with_max_attempts(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "auto_heal",
        queue_payload,
        None,
        5,
    )
    .await
    {
        Ok(async_job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "job_id": spec_id.to_string(),
                "async_job_id": async_job_id,
                "message": "200% verification queued for worker; poll GET /api/heal-verify/:job_id/steps",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "auto_heal", error = %e, "enqueue auto_heal job failed");
            if let Ok(mut tx2) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
                let _ = sqlx::query("DELETE FROM auto_heal_job_specs WHERE id = $1 AND tenant_id = $2")
                    .bind(spec_id)
                    .bind(auth.tenant_id)
                    .execute(&mut *tx2)
                    .await;
                let _ = tx2.commit().await;
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "enqueue_failed", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_heal_requests_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!([]))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, finding_id, branch_name, pr_url, pr_number, diff_summary, verification_status, verification_job_id, created_at FROM heal_requests WHERE client_id = $1 ORDER BY id DESC"#,
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "finding_id": r.try_get::<String,_>("finding_id").unwrap_or_default(),
                "branch_name": r.try_get::<Option<String>,_>("branch_name").ok().flatten(),
                "pr_url": r.try_get::<Option<String>,_>("pr_url").ok().flatten(),
                "pr_number": r.try_get::<Option<i32>,_>("pr_number").ok().flatten(),
                "diff_summary": r.try_get::<Option<String>,_>("diff_summary").ok().flatten(),
                "verification_status": r.try_get::<String,_>("verification_status").unwrap_or_default(),
                "verification_job_id": r.try_get::<String,_>("verification_job_id").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "requests": out }))).into_response()
}

async fn api_deception_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!([]))).into_response();
    };
    let rows = sqlx::query(
        "SELECT id, asset_type, token_value, deployment_location, cloud_injection_uri, COALESCE(canary_access_key_id,'') AS canary_access_key_id, COALESCE(oast_canary_hook,'') AS oast_canary_hook, status, created_at FROM deception_assets WHERE client_id = $1 ORDER BY id DESC",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "asset_type": r.try_get::<String,_>("asset_type").unwrap_or_default(),
                "token_value": r.try_get::<String,_>("token_value").unwrap_or_default(),
                "deployment_location": r.try_get::<Option<String>,_>("deployment_location").ok().flatten(),
                "cloud_injection_uri": r.try_get::<Option<String>,_>("cloud_injection_uri").ok().flatten(),
                "canary_access_key_id": r.try_get::<String,_>("canary_access_key_id").unwrap_or_default(),
                "oast_canary_hook": r.try_get::<String,_>("oast_canary_hook").unwrap_or_default(),
                "status": r.try_get::<String,_>("status").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
                "token_value_masked": mask_token_preview(r.try_get::<String,_>("token_value").unwrap_or_default().as_str()),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "assets": out }))).into_response()
}

fn mask_token_preview(raw: &str) -> String {
    let t = raw.trim();
    let chs: Vec<char> = t.chars().collect();
    if chs.len() <= 8 {
        return "••••".to_string();
    }
    let head: String = chs.iter().take(4).collect();
    let tail: String = chs.iter().skip(chs.len().saturating_sub(3)).collect();
    format!("{}…{}", head, tail)
}

async fn api_deception_generate(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<DeceptionGenerateBody>,
) -> Response {
    let tech = body.tech_hint.as_deref().unwrap_or("");
    let use_real_aws = body.real_aws_canary.unwrap_or_else(|| {
        matches!(
            std::env::var("WEISSMAN_REAL_AWS_CANARY").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    });
    let use_llm_decoy = body.use_llm_decoy.unwrap_or(true);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"inserted": 0}))).into_response();
    };
    let llm_base: String = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    let llm_model: String = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    if tx.commit().await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"inserted": 0}))).into_response();
    }

    let records: Vec<deception_engine::DeceptionAssetRecord> =
        if let Some(types) = body.types.as_ref().filter(|t| !t.is_empty()) {
            deception_engine::generate_deception_assets(&id.to_string(), types, tech)
        } else {
            deception_engine::generate_deception_assets_simple(&id.to_string(), tech)
        };

    struct RowInsert {
        atype: String,
        token: String,
        loc: String,
        canary: String,
        oast: String,
        iam_user: Option<String>,
    }

    let mut to_insert: Vec<RowInsert> = Vec::new();
    for (_c, atype, token, loc) in records {
        if atype == deception_engine::TYPE_AWS_KEY && use_real_aws {
            let pair = match crate::deception_aws_canary::create_real_canary_pair(auth.tenant_id, id).await
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(target: "deception_aws_canary", error = %e, "create_real_canary_pair failed");
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(
                            json!({"inserted": 0, "error": "aws_iam_canary", "detail": e}),
                        ),
                    )
                        .into_response();
                }
            };
            let mon = uuid::Uuid::new_v4();
            let oast_url =
                crate::deception_aws_canary::aws_oast_monitor_url_with_path(&mon);
            let decoy = crate::deception_aws_canary::build_live_aws_decoy_content(
                &llm_base,
                &llm_model,
                auth.tenant_id,
                tech,
                &pair,
                &oast_url,
                use_llm_decoy,
            )
            .await;
            let loc2 =
                crate::deception_aws_canary::pick_asm_virtual_deployment_location(id, &mon);
            to_insert.push(RowInsert {
                atype,
                token: decoy,
                loc: loc2,
                canary: pair.access_key_id.clone(),
                oast: oast_url,
                iam_user: Some(pair.iam_user_name),
            });
        } else {
            let canary = crate::deception_deployment_engine::extract_canary_access_key_id(&token)
                .unwrap_or_default();
            to_insert.push(RowInsert {
                atype,
                token,
                loc,
                canary,
                oast: String::new(),
                iam_user: None,
            });
        }
    }

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"inserted": 0}))).into_response();
    };
    let mut inserted = 0u32;
    for row in to_insert {
        let cleanup_iam = row.iam_user.clone();
        let q = sqlx::query(
            r#"INSERT INTO deception_assets (tenant_id, client_id, asset_type, token_value, deployment_location, status, canary_access_key_id, oast_canary_hook)
               VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)"#,
        )
        .bind(auth.tenant_id)
        .bind(id)
        .bind(&row.atype)
        .bind(&row.token)
        .bind(&row.loc)
        .bind(&row.canary)
        .bind(&row.oast)
        .execute(&mut *tx)
        .await;
        match q {
            Ok(_) => inserted += 1,
            Err(e) => {
                tracing::error!(target: "deception_aws_canary", error = %e, "deception_assets insert failed");
                if let Some(u) = cleanup_iam {
                    crate::deception_aws_canary::delete_canary_iam_user(&u).await;
                }
            }
        }
    }
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({ "inserted": inserted }))).into_response()
}

async fn api_deception_triggered(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<DeceptionTriggeredBody>,
) -> Response {
    let aid = body.asset_id.unwrap_or(0);
    if aid == 0 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "asset_id required"}))).into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let cid: Option<i64> = sqlx::query_scalar("SELECT client_id FROM deception_assets WHERE id = $1 AND tenant_id = $2")
        .bind(aid)
        .bind(auth.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let Some(client_id) = cid else {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"error": "asset not found"}))).into_response();
    };
    let fp = body.fingerprint.as_deref().unwrap_or("");
    let meta = serde_json::to_string(&body.request_meta.clone().unwrap_or(json!({})))
        .unwrap_or_else(|_| "{}".to_string());
    let res = sqlx::query(
        r#"INSERT INTO deception_triggers (tenant_id, asset_id, client_id, fingerprint, request_meta)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(auth.tenant_id)
    .bind(aid)
    .bind(client_id)
    .bind(fp)
    .bind(&meta)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(_) => {
            let meta_ip = body.request_meta.as_ref().and_then(|v| {
                crate::deception_cf_blackhole::sniff_ipv4_from_json(v, 0).map(std::net::IpAddr::V4)
            });
            let peer_ip = crate::http::extract_client_ip(&headers, addr)
                .parse::<std::net::IpAddr>()
                .ok();
            let source = meta_ip.or(peer_ip);
            let pay = body.request_meta.clone().unwrap_or(json!({}));
            tokio::spawn(async move {
                crate::deception_cf_blackhole::maybe_blackhole_from_canary_payload(&pay, source).await;
            });
            (StatusCode::OK, Json(json!({"ok": true}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_sovereign_phantom_trap(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<SovereignPhantomBody>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "DB unavailable"})),
        )
            .into_response();
    };
    let llm_base: String = sqlx::query_scalar(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    let llm_model: String = sqlx::query_scalar(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'",
    )
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    if tx.commit().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "DB commit"})),
        )
            .into_response();
    }
    match crate::sovereign_phantom_factory::build_phantom_bundle(
        &llm_base,
        &llm_model,
        auth.tenant_id,
        &body.fingerprint,
    )
    .await
    {
        Ok(b) => match serde_json::to_value(&b) {
            Ok(v) => (StatusCode::OK, Json(v)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": "phantom_factory", "detail": e })),
        )
            .into_response(),
    }
}

async fn api_payload_sync_status(State(state): State<Arc<AppState>>) -> Response {
    match sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM dynamic_payloads WHERE added_at >= now() - interval '60 days'",
    )
    .fetch_one(state.intel_pool.as_ref())
    .await
    {
        Ok(n) => (StatusCode::OK, Json(json!({ "dynamic_payloads_60d": n }))).into_response(),
        Err(e) => {
            tracing::error!(target: "payload_sync", error = %e, "dynamic_payloads count failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "intel_db", "detail": e.to_string() })),
            )
                .into_response()
        }
    }
}

async fn api_payload_sync_payloads(State(state): State<Arc<AppState>>) -> Response {
    match sqlx::query(
        "SELECT target_library, source, source_url, added_at FROM dynamic_payloads ORDER BY added_at DESC LIMIT 200",
    )
    .fetch_all(state.intel_pool.as_ref())
    .await
    {
        Ok(rows) => {
            let out: Vec<Value> = rows
                .into_iter()
                .filter_map(|r| {
                    let tl = r.try_get::<String, _>("target_library");
                    let src = r.try_get::<String, _>("source");
                    let url = r.try_get::<String, _>("source_url");
                    let at = r.try_get::<chrono::DateTime<Utc>, _>("added_at");
                    match (tl, src, url, at) {
                        (Ok(tl), Ok(src), Ok(url), Ok(at)) => Some(json!({
                            "target_library": tl,
                            "source": src,
                            "source_url": url,
                            "added_at": at.to_rfc3339(),
                        })),
                        _ => {
                            tracing::warn!(target: "payload_sync", "dynamic_payloads row decode skipped");
                            None
                        }
                    }
                })
                .collect();
            (StatusCode::OK, Json(Value::Array(out))).into_response()
        }
        Err(e) => {
            tracing::error!(target: "payload_sync", error = %e, "dynamic_payloads list failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "intel_db", "detail": e.to_string() })),
            )
                .into_response()
        }
    }
}

async fn api_payload_sync_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
) -> Response {
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "payload_sync",
        json!({}),
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "started": true,
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue payload_sync failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"started": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}
