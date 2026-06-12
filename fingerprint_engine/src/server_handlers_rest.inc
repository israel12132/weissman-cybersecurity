async fn api_health(State(state): State<Arc<AppState>>) -> Response {
    let uptime_secs = state.started_at.elapsed().as_secs();
    let postgres_ok = match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(state.app_pool.as_ref())
        .await
    {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(target: "api_health", error = %e, "app_pool SELECT 1 failed");
            false
        }
    };
    let scanning_enabled = crate::orchestrator::is_scanning_active();
    let scan_in_progress = crate::orchestrator::scan_in_progress();
    let active_tenant_cycles = crate::orchestrator::active_tenant_scan_count();
    let mut engines: Vec<String> = vec![];
    let mut safe_mode = false;
    if postgres_ok {
        if let Some(tid) = sqlx::query_scalar::<_, i64>("SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1")
            .fetch_optional(state.auth_pool.as_ref())
            .await
            .ok()
            .flatten()
        {
            if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, tid).await {
                if let Ok(Some(s)) = sqlx::query_scalar::<_, String>("SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'active_engines'")
                    .bind(tid)
                    .fetch_optional(&mut *tx)
                    .await
                {
                    engines = serde_json::from_str(&s).unwrap_or_default();
                }
                if let Ok(Some(s)) = sqlx::query_scalar::<_, String>("SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'global_safe_mode'")
                    .bind(tid)
                    .fetch_optional(&mut *tx)
                    .await
                {
                    safe_mode = s == "true" || s == "1";
                }
                let _ = tx.commit().await;
            }
        }
    }
    let rss_kb = resident_set_kb();
    (StatusCode::OK, Json(json!({
        "ok": true,
        "uptime_secs": uptime_secs,
        "postgres_ok": postgres_ok,
        // Kept for back-compat with older clients that only check `scanning_active`.
        "scanning_active": scanning_enabled,
        // Source of truth: operator toggle vs. actual concurrent work.
        "scanning_enabled": scanning_enabled,
        "scan_in_progress": scan_in_progress,
        "active_tenant_cycles": active_tenant_cycles,
        "active_engines": engines,
        "global_safe_mode": safe_mode,
        "process_rss_kb": rss_kb,
        "telemetry_broadcast_capacity": 128,
        "ws_note": "Clients should reconnect with exponential backoff; server uses bounded broadcast channels.",
    }))).into_response()
}

#[cfg(target_os = "linux")]
fn resident_set_kb() -> Option<u64> {
    // Cache the last sampled value for 5 seconds. /proc/self/statm is tiny, but /api/health
    // is hammered by Docker / k8s probes (every 5–15s) plus uptime monitors. A blocking
    // sync read on every request adds avoidable jitter to the async runtime's poll loop
    // and shows up as latency on the rest of the request handlers sharing that worker.
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Instant, Duration};
    use std::sync::OnceLock;

    static CACHE_VAL: AtomicU64 = AtomicU64::new(0);
    static CACHE_AT:  OnceLock<std::sync::Mutex<Option<Instant>>> = OnceLock::new();
    let lock = CACHE_AT.get_or_init(|| std::sync::Mutex::new(None));

    if let Ok(guard) = lock.lock() {
        if let Some(when) = *guard {
            if when.elapsed() < Duration::from_secs(5) {
                let v = CACHE_VAL.load(Ordering::Relaxed);
                if v > 0 { return Some(v); }
            }
        }
    }
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let mut it = s.split_whitespace();
    let _vsize = it.next()?;
    let resident_pages: u64 = it.next()?.parse().ok()?;
    let kb = resident_pages.saturating_mul(4096) / 1024;
    CACHE_VAL.store(kb, Ordering::Relaxed);
    if let Ok(mut guard) = lock.lock() {
        *guard = Some(Instant::now());
    }
    Some(kb)
}

#[cfg(not(target_os = "linux"))]
fn resident_set_kb() -> Option<u64> {
    None
}

async fn api_audit_logs(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Server-side pagination + optional action / actor filter so the UI doesn't pull 500 rows.
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let offset: i64 = q
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    let action_filter: Option<String> = q
        .get("action")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let actor_filter: Option<String> = q
        .get("actor")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable", "entries": [], "total": 0})),
        )
            .into_response();
    };

    let rows = sqlx::query(
        r#"SELECT id,
                  actor_user_id,
                  COALESCE(user_label, '')  AS user_label,
                  COALESCE(action_type, '') AS action_type,
                  COALESCE(details, '')     AS details,
                  COALESCE(ip_address, '')  AS ip_address,
                  created_at
             FROM audit_logs
            WHERE tenant_id = $5
              AND ($3::text IS NULL OR action_type ILIKE '%' || $3::text || '%')
              AND ($4::text IS NULL OR user_label  ILIKE '%' || $4::text || '%')
            ORDER BY id DESC
            LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .bind(action_filter.as_deref())
    .bind(actor_filter.as_deref())
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let total: i64 = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*)::bigint FROM audit_logs
           WHERE tenant_id = $3
             AND ($1::text IS NULL OR action_type ILIKE '%' || $1::text || '%')
             AND ($2::text IS NULL OR user_label  ILIKE '%' || $2::text || '%')"#,
    )
    .bind(action_filter.as_deref())
    .bind(actor_filter.as_deref())
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let _ = tx.commit().await;

    let entries: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64, _>("id").unwrap_or(0),
                "user_id": r.try_get::<Option<i64>, _>("actor_user_id").ok().flatten(),
                "actor_email": r.try_get::<String, _>("user_label").unwrap_or_default(),
                "action": r.try_get::<String, _>("action_type").unwrap_or_default(),
                "details": r.try_get::<String, _>("details").unwrap_or_default(),
                "client_ip": r.try_get::<String, _>("ip_address").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "entries": entries,
            "total": total,
            "limit": limit,
            "offset": offset,
        })),
    )
        .into_response()
}

async fn api_enterprise_settings_get(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"global_safe_mode": false, "alert_webhook_url": ""}))).into_response();
    };
    let safe = sqlx::query_scalar::<_, String>("SELECT COALESCE(value,'false') FROM system_configs WHERE tenant_id = $1 AND key = 'global_safe_mode'")
        .bind(auth.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "false".to_string());
    let webhook = sqlx::query_scalar::<_, String>("SELECT COALESCE(value,'') FROM system_configs WHERE tenant_id = $1 AND key = 'alert_webhook_url'")
        .bind(auth.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let _ = tx.commit().await;
    let safe_b = safe == "true" || safe == "1";
    (StatusCode::OK, Json(json!({"global_safe_mode": safe_b, "alert_webhook_url": webhook}))).into_response()
}

async fn api_enterprise_settings_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<EnterpriseSettingsPatch>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    if let Some(v) = body.global_safe_mode {
        let s = if v { "true" } else { "false" };
        let _ = sqlx::query(
            "INSERT INTO system_configs (tenant_id, key, value, description) VALUES ($1, 'global_safe_mode', $2, 'Production-safe scan throttling') ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(auth.tenant_id)
        .bind(s)
        .execute(&mut *tx)
        .await;
        let _ = audit_log::insert_audit(&mut tx, auth.tenant_id, Some(auth.user_id), &actor, "safe_mode_toggled", &format!("global_safe_mode={}", s), &ip).await;
    }
    if let Some(url) = body.alert_webhook_url {
        let trimmed = url.trim();
        let _ = sqlx::query(
            "INSERT INTO system_configs (tenant_id, key, value, description) VALUES ($1, 'alert_webhook_url', $2, 'Slack/Discord webhook') ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(auth.tenant_id)
        .bind(trimmed)
        .execute(&mut *tx)
        .await;
        let _ = audit_log::insert_audit(&mut tx, auth.tenant_id, Some(auth.user_id), &actor, "alerts_settings_updated", "alert_webhook_url updated", &ip).await;
    }
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true, "message": "enterprise settings updated"}))).into_response()
}

async fn api_system_backup(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let backups_dir = std::env::var("WEISSMAN_PG_BACKUP_DIR")
        .ok()
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("backups"));
    let ip = extract_client_ip(&headers, addr);
    match crate::db_backup::backup_postgres_to_dir(&backups_dir) {
        Ok(p) => {
            if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
                let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
                let _ = audit_log::insert_audit(&mut tx, auth.tenant_id, Some(auth.user_id), &u, "backup_triggered", &format!("path={}", p.display()), &ip).await;
                let _ = tx.commit().await;
            }
            (StatusCode::OK, Json(json!({"ok": true, "path": p.to_string_lossy()}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": e}))).into_response(),
    }
}

async fn api_clients_list(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "detail": "Database unavailable. Retry shortly.",
                "code": "db_unavailable",
            })),
        )
            .into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, name, domains, tech_stack, ip_ranges,
            COALESCE(contact_email,'') AS contact_email,
            COALESCE(auto_detect_tech_stack, true) AS auto_detect_tech_stack,
            COALESCE(aws_cross_account_role_arn,'') AS aws_cross_account_role_arn,
            COALESCE(aws_external_id,'') AS aws_external_id,
            COALESCE(gcp_project_id,'') AS gcp_project_id
           FROM clients ORDER BY id"#,
    )
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").ok(),
                "name": r.try_get::<String,_>("name").ok(),
                "domains": r.try_get::<String,_>("domains").ok(),
                "tech_stack": r.try_get::<String,_>("tech_stack").ok(),
                "ip_ranges": r.try_get::<String,_>("ip_ranges").ok(),
                "contact_email": r.try_get::<String,_>("contact_email").ok(),
                "auto_detect_tech_stack": r.try_get::<bool,_>("auto_detect_tech_stack").ok(),
                "aws_cross_account_role_arn": r.try_get::<String,_>("aws_cross_account_role_arn").ok(),
                "aws_external_id": r.try_get::<String,_>("aws_external_id").ok(),
                "gcp_project_id": r.try_get::<String,_>("gcp_project_id").ok(),
            })
        })
        .collect();
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}

/// POST /api/clients/:id/scan/run-all — queue the curated baseline engine bundle against the
/// client's domains. Uses `command_center_engine` jobs so the new `findings_persist` path
/// surfaces results in the Findings Command Center end-to-end. Returns the list of queued
/// job ids so the UI can link the customer to the Jobs Dashboard.
async fn api_clients_scan_run_all(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
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

    // Resolve the client's authorized domains.
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable", "code": "db_unavailable"})),
        )
            .into_response();
    };
    let row = sqlx::query(
        "SELECT domains FROM clients WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let domains_raw: String = match row {
        Some(r) => r.try_get::<String, _>("domains").unwrap_or_default(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "detail": "Client not found"})),
            )
                .into_response();
        }
    };
    let domains: Vec<String> = serde_json::from_str::<Vec<String>>(&domains_raw)
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if domains.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "code": "no_domains",
                "detail": "Add at least one authorized domain to this client before running scans.",
            })),
        )
            .into_response();
    }

    // Curated baseline bundle that produces customer-actionable findings without burning
    // the AI-heavy quota. Engines are gated by `is_production_engine_id` in the worker.
    let baseline_engines: &[&str] = &[
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

    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &u,
            "scan_run_all_initiated",
            &format!("client_id={id} engines={baseline:?}", id = id, baseline = baseline_engines),
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }

    let mut queued: Vec<Value> = Vec::new();
    for domain in &domains {
        let target = if domain.starts_with("http://") || domain.starts_with("https://") {
            domain.clone()
        } else {
            format!("http://{}", domain)
        };
        for engine in baseline_engines {
            let payload = json!({
                "engine": engine,
                "target": target,
                "client_id": id,
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
                        target: "async_jobs",
                        engine = %engine,
                        target = %target,
                        error = %e,
                        "enqueue baseline scan job failed"
                    );
                }
            }
        }
    }

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": true,
            "client_id": id,
            "domains_count": domains.len(),
            "jobs_queued": queued.len(),
            "engines": baseline_engines,
            "jobs": queued,
            "message": format!(
                "Queued {n} baseline scan jobs across {d} domain(s). Track progress at /api/jobs/<id> or in the Jobs Dashboard.",
                n = queued.len(),
                d = domains.len()
            ),
        })),
    )
        .into_response()
}

/// GET /api/clients/:id — single-client lookup. The frontend `ClientDetail` page calls this
/// directly; before this handler existed the route only had POST/DELETE, returning 405 and
/// rendering "Failed to load client:" for every customer.
async fn api_clients_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable. Retry shortly.", "code": "db_unavailable"})),
        )
            .into_response();
    };
    let row = sqlx::query(
        r#"SELECT id, name, domains, tech_stack, ip_ranges,
            COALESCE(contact_email,'') AS contact_email,
            COALESCE(auto_detect_tech_stack, true) AS auto_detect_tech_stack,
            COALESCE(aws_cross_account_role_arn,'') AS aws_cross_account_role_arn,
            COALESCE(aws_external_id,'') AS aws_external_id,
            COALESCE(gcp_project_id,'') AS gcp_project_id
           FROM clients WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let Some(r) = row else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "Client not found", "code": "not_found"})),
        )
            .into_response();
    };

    (
        StatusCode::OK,
        Json(json!({
            "id": r.try_get::<i64,_>("id").ok(),
            "name": r.try_get::<String,_>("name").ok(),
            "domains": r.try_get::<String,_>("domains").ok(),
            "tech_stack": r.try_get::<String,_>("tech_stack").ok(),
            "ip_ranges": r.try_get::<String,_>("ip_ranges").ok(),
            "contact_email": r.try_get::<String,_>("contact_email").ok(),
            "auto_detect_tech_stack": r.try_get::<bool,_>("auto_detect_tech_stack").ok(),
            "aws_cross_account_role_arn": r.try_get::<String,_>("aws_cross_account_role_arn").ok(),
            "aws_external_id": r.try_get::<String,_>("aws_external_id").ok(),
            "gcp_project_id": r.try_get::<String,_>("gcp_project_id").ok(),
        })),
    )
        .into_response()
}

async fn api_clients_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::extract::Json<ClientBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_role(&auth, crate::rbac::roles::OPERATOR) {
        return r;
    }
    let name = body.name.as_deref().unwrap_or("").trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "detail": "name required"}))).into_response();
    }
    if let Err(detail) =
        crate::billing::enforce_client_create(state.auth_pool.as_ref(), auth.tenant_id).await
    {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"ok": false, "detail": detail})),
        )
            .into_response();
    }
    let domains = body.domains.as_deref().unwrap_or("[]");
    let tech_stack = body.tech_stack.as_deref().unwrap_or("[]");
    let ip_ranges = body.ip_ranges.as_deref().unwrap_or("[]");
    let contact_email = body.contact_email.as_deref().unwrap_or("").trim();
    let auto_detect = body.auto_detect_tech_stack.unwrap_or(true);
    let aws_arn = body
        .aws_cross_account_role_arn
        .as_deref()
        .unwrap_or("")
        .trim();
    let aws_ext = body.aws_external_id.as_deref().unwrap_or("").trim();
    let gcp = body.gcp_project_id.as_deref().unwrap_or("").trim();
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let id: i64 = match sqlx::query_scalar::<_, i64>(
        r#"INSERT INTO clients (
            tenant_id, name, domains, tech_stack, ip_ranges,
            contact_email, auto_detect_tech_stack,
            aws_cross_account_role_arn, aws_external_id, gcp_project_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id"#,
    )
    .bind(auth.tenant_id)
    .bind(name)
    .bind(domains)
    .bind(tech_stack)
    .bind(ip_ranges)
    .bind(contact_email)
    .bind(auto_detect)
    .bind(aws_arn)
    .bind(aws_ext)
    .bind(gcp)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(target: "api_clients", error = %e, name = %name, "client create failed");
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "ok": false,
                    "detail": format!("Database error while creating client: {e}"),
                })),
            )
                .into_response();
        }
    };
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "client_created",
        &format!("client_id={} name={}", id, name.chars().take(200).collect::<String>()),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    eprintln!("[Weissman][API] Client created: id={} name={}", id, name);
    (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response()
}

async fn api_clients_update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<i64>,
    body: axum::extract::Json<ClientBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_role(&auth, crate::rbac::roles::OPERATOR) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable. Retry shortly."})),
        )
            .into_response();
    };
    let row = sqlx::query(
        r#"SELECT name,
            COALESCE(domains,'[]') AS domains,
            COALESCE(tech_stack,'[]') AS tech_stack,
            COALESCE(ip_ranges,'[]') AS ip_ranges,
            COALESCE(contact_email,'') AS contact_email,
            COALESCE(auto_detect_tech_stack, true) AS auto_detect_tech_stack,
            COALESCE(aws_cross_account_role_arn,'') AS aws_cross_account_role_arn,
            COALESCE(aws_external_id,'') AS aws_external_id,
            COALESCE(gcp_project_id,'') AS gcp_project_id
           FROM clients WHERE id = $1"#,
    )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let (
        cur_name,
        cur_domains,
        cur_tech,
        cur_ip,
        cur_contact,
        cur_auto_detect,
        cur_aws_arn,
        cur_aws_ext,
        cur_gcp,
    ) = match row {
        Some(r) => (
            r.try_get::<String, _>("name").unwrap_or_default(),
            r.try_get::<String, _>("domains").unwrap_or_else(|_| "[]".to_string()),
            r.try_get::<String, _>("tech_stack").unwrap_or_else(|_| "[]".to_string()),
            r.try_get::<String, _>("ip_ranges").unwrap_or_else(|_| "[]".to_string()),
            r.try_get::<String, _>("contact_email").unwrap_or_default(),
            r.try_get::<bool, _>("auto_detect_tech_stack").unwrap_or(true),
            r.try_get::<String, _>("aws_cross_account_role_arn").unwrap_or_default(),
            r.try_get::<String, _>("aws_external_id").unwrap_or_default(),
            r.try_get::<String, _>("gcp_project_id").unwrap_or_default(),
        ),
        None => {
            let _ = tx.rollback().await;
            return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
        }
    };
    let name = body.name.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or(&cur_name);
    let domains = body.domains.as_deref().unwrap_or(&cur_domains);
    let tech_stack = body.tech_stack.as_deref().unwrap_or(&cur_tech);
    let ip_ranges = body.ip_ranges.as_deref().unwrap_or(&cur_ip);
    let contact_email = body
        .contact_email
        .as_deref()
        .unwrap_or(cur_contact.as_str())
        .trim();
    let auto_detect = body.auto_detect_tech_stack.unwrap_or(cur_auto_detect);
    let aws_arn = body
        .aws_cross_account_role_arn
        .as_deref()
        .unwrap_or(cur_aws_arn.as_str())
        .trim();
    let aws_ext = body
        .aws_external_id
        .as_deref()
        .unwrap_or(cur_aws_ext.as_str())
        .trim();
    let gcp = body
        .gcp_project_id
        .as_deref()
        .unwrap_or(cur_gcp.as_str())
        .trim();
    if sqlx::query(
        r#"UPDATE clients SET name = $1, domains = $2, tech_stack = $3, ip_ranges = $4,
            contact_email = $5, auto_detect_tech_stack = $6,
            aws_cross_account_role_arn = $7, aws_external_id = $8, gcp_project_id = $9,
            updated_at = now() WHERE id = $10"#,
    )
        .bind(name)
        .bind(domains)
        .bind(tech_stack)
        .bind(ip_ranges)
        .bind(contact_email)
        .bind(auto_detect)
        .bind(aws_arn)
        .bind(aws_ext)
        .bind(gcp)
        .bind(id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
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
        "client_updated",
        &format!("client_id={}", id),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

async fn api_clients_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = crate::rbac::require_role(&auth, crate::rbac::roles::ADMIN) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable. Retry shortly."})),
        )
            .into_response();
    };
    let row = sqlx::query("SELECT name FROM clients WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let Some(nr) = row else {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    };
    let cname: String = nr.try_get::<String, _>("name").unwrap_or_default();
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "client_deleted",
        &format!("client_id={} name={}", id, cname.chars().take(200).collect::<String>()),
        &ip,
    )
    .await;
    let n = sqlx::query("DELETE FROM clients WHERE id = $1").bind(id).execute(&mut *tx).await.map(|r| r.rows_affected()).unwrap_or(0);
    if n == 0 {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    }
    let _ = sqlx::query("DELETE FROM vulnerabilities WHERE client_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await;
    let _ = tx.commit().await;
    (StatusCode::NO_CONTENT, ()).into_response()
}

async fn api_client_config_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(Value::Null)).into_response();
    };
    let s: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(trim(client_configs), ''), $1) FROM clients WHERE id = $2",
    )
    .bind(DEFAULT_CLIENT_CONFIGS_JSON)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let config_str = match s {
        Some(x) => x,
        None => return (StatusCode::NOT_FOUND, Json(Value::Null)).into_response(),
    };
    let value: Value = serde_json::from_str(&config_str).unwrap_or_else(|_| json!({}));
    (StatusCode::OK, Json(value)).into_response()
}

async fn api_client_config_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    body: axum::extract::Json<ClientConfigBody>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let current: String = match sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(trim(client_configs), ''), $1) FROM clients WHERE id = $2",
    )
    .bind(DEFAULT_CLIENT_CONFIGS_JSON)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    {
        Some(x) => x,
        None => {
            let _ = tx.rollback().await;
            return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
        }
    };
    let mut config: serde_json::Map<String, Value> = match serde_json::from_str(&current) {
        Ok(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    let old_roe = config
        .get("roe_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("safe_proofs")
        .to_string();
    if let Some(engines) = &body.enabled_engines {
        config.insert(
            "enabled_engines".to_string(),
            Value::Array(engines.iter().map(|s| Value::String(s.clone())).collect()),
        );
    }
    if let Some(ref roe_raw) = body.roe_mode {
        let roe = roe_raw.trim();
        if roe == "safe_proofs" {
            config.insert("roe_mode".to_string(), Value::String("safe_proofs".to_string()));
        } else if roe == "weaponized_god_mode" {
            // Governance: weaponized ROE requires explicit approval trail, unless the server
            // is configured with a confirm secret and caller provides a matching header.
            let confirm_secret =
                std::env::var("WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET").unwrap_or_default();
            let header_bypass = !confirm_secret.trim().is_empty()
                && crate::security_hardening::destructive_action_authorized(&headers);

            if old_roe == "weaponized_god_mode" || header_bypass {
                config.insert(
                    "roe_mode".to_string(),
                    Value::String("weaponized_god_mode".to_string()),
                );
            } else {
                // Check for an existing approved request (2 distinct approvals) or create a pending one.
                let row = sqlx::query(
                    r#"SELECT id, status, expires_at, first_approved_by_user_id, second_approved_by_user_id
                       FROM roe_override_requests
                       WHERE client_id = $1
                         AND status IN ('pending','approved')
                         AND expires_at > now()
                       ORDER BY requested_at DESC
                       LIMIT 1
                       FOR UPDATE"#,
                )
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .ok()
                .flatten();

                if let Some(r) = row {
                    let req_id: i64 = r.try_get("id").unwrap_or(0);
                    let status: String =
                        r.try_get("status").unwrap_or_else(|_| "pending".to_string());
                    let first: Option<i64> = r.try_get("first_approved_by_user_id").ok().flatten();
                    let second: Option<i64> =
                        r.try_get("second_approved_by_user_id").ok().flatten();
                    if status == "approved" && first.is_some() && second.is_some() {
                        let _ = sqlx::query(
                            "UPDATE roe_override_requests SET status = 'applied', applied_by_user_id = $1, applied_at = now(), updated_at = now() WHERE id = $2",
                        )
                        .bind(auth.user_id)
                        .bind(req_id)
                        .execute(&mut *tx)
                        .await;
                        config.insert(
                            "roe_mode".to_string(),
                            Value::String("weaponized_god_mode".to_string()),
                        );
                    } else {
                        let _ = tx.commit().await;
                        return (
                            StatusCode::CONFLICT,
                            Json(json!({
                                "ok": false,
                                "error_code": "roe_approval_required",
                                "request_id": req_id,
                                "detail": "Weaponized ROE requires 2 distinct admin approvals. Request is pending.",
                                "approvals_needed": 2,
                                "approvals_have": (first.is_some() as i32) + (second.is_some() as i32),
                                "admin_url": "/roe-approvals"
                            })),
                        )
                            .into_response();
                    }
                } else {
                    let created: Option<(i64,)> = sqlx::query_as(
                        r#"INSERT INTO roe_override_requests (tenant_id, client_id, desired_roe_mode, status, requested_by_user_id)
                           VALUES ($1, $2, 'weaponized_god_mode', 'pending', $3)
                           RETURNING id"#,
                    )
                    .bind(auth.tenant_id)
                    .bind(id)
                    .bind(auth.user_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .ok()
                    .flatten();
                    let req_id = created.map(|(x,)| x).unwrap_or(0);
                    let _ = audit_log::insert_audit(
                        &mut tx,
                        auth.tenant_id,
                        Some(auth.user_id),
                        &actor,
                        "roe_override_request_created",
                        &format!("client_id={} request_id={}", id, req_id),
                        &ip,
                    )
                    .await;
                    let _ = tx.commit().await;
                    return (
                        StatusCode::CONFLICT,
                        Json(json!({
                            "ok": false,
                            "error_code": "roe_approval_required",
                            "request_id": req_id,
                            "detail": "Weaponized ROE requires 2 distinct admin approvals. A request was created.",
                            "approvals_needed": 2,
                            "approvals_have": 0,
                            "admin_url": "/roe-approvals"
                        })),
                    )
                        .into_response();
                }
            }
        }
    }
    if let Some(level) = body.stealth_level {
        config.insert("stealth_level".to_string(), Value::Number(serde_json::Number::from(level.min(100))));
    }
    if let Some(b) = body.auto_harvest {
        config.insert("auto_harvest".to_string(), Value::Bool(b));
    }
    if let Some(b) = body.industrial_ot_enabled {
        config.insert("industrial_ot_enabled".to_string(), Value::Bool(b));
    }
    let new_json = Value::Object(config);
    let new_str = match serde_json::to_string(&new_json) {
        Ok(s) => s,
        Err(_) => {
            let _ = tx.rollback().await;
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false}))).into_response();
        }
    };
    if sqlx::query("UPDATE clients SET client_configs = $1, updated_at = now() WHERE id = $2")
        .bind(&new_str)
        .bind(id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        let _ = tx.rollback().await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false}))).into_response();
    }
    let new_roe = new_json
        .get("roe_mode")
        .and_then(|v| v.as_str())
        .unwrap_or(&old_roe);
    if new_roe == "weaponized_god_mode" && old_roe != "weaponized_god_mode" {
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            "roe_overridden",
            &format!("client_id={} roe_mode=weaponized_god_mode", id),
            &ip,
        )
        .await;
    }
    let mut changed: Vec<&'static str> = Vec::new();
    if body.enabled_engines.is_some() {
        changed.push("enabled_engines");
    }
    if body.roe_mode.is_some() {
        changed.push("roe_mode");
    }
    if body.stealth_level.is_some() {
        changed.push("stealth_level");
    }
    if body.auto_harvest.is_some() {
        changed.push("auto_harvest");
    }
    if body.industrial_ot_enabled.is_some() {
        changed.push("industrial_ot_enabled");
    }
    if !changed.is_empty() {
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            "client_target_config_updated",
            &format!("client_id={} keys={}", id, changed.join(",")),
            &ip,
        )
        .await;
    }
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true, "config": new_json}))).into_response()
}

#[allow(dead_code)]
async fn api_scan_start(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(&mut tx, auth.tenant_id, Some(auth.user_id), &u, "scan_initiated", "continuous scanning started", &ip).await;
        let _ = tx.commit().await;
    }
    crate::orchestrator::set_scanning_active(true);
    (StatusCode::OK, Json(json!({"ok": true, "message": "Continuous scanning started"}))).into_response()
}

#[allow(dead_code)]
async fn api_scan_stop(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(&mut tx, auth.tenant_id, Some(auth.user_id), &u, "scan_stopped", "continuous scanning stopped", &ip).await;
        let _ = tx.commit().await;
    }
    crate::orchestrator::set_scanning_active(false);
    (StatusCode::OK, Json(json!({"ok": true, "message": "Scanning stopped"}))).into_response()
}

#[allow(dead_code)]
async fn api_scan_status() -> Response {
    let active = crate::orchestrator::is_scanning_active();
    (StatusCode::OK, Json(json!({ "scanning_active": active }))).into_response()
}

#[allow(dead_code)]
async fn api_scan_run_all(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
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
    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(&mut tx, auth.tenant_id, Some(auth.user_id), &u, "scan_initiated", "full scan cycle run-all (single-tenant)", &ip).await;
        let _ = tx.commit().await;
    }
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "tenant_full_scan",
        json!({}),
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
                "message": "Full tenant scan queued; poll status_url for progress",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue tenant_full_scan failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}


async fn api_scan(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    body: axum::extract::Json<Value>,
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
    let engine = body.get("engine").and_then(Value::as_str).unwrap_or("").to_string();
    let target = body.get("target").and_then(Value::as_str).unwrap_or("").to_string();
    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(&mut tx, auth.tenant_id, Some(auth.user_id), &u, "scan_initiated", &format!("command_center engine={} target={}", engine, target.chars().take(200).collect::<String>()), &ip).await;
        let _ = tx.commit().await;
    }
    let (job_kind, mut payload) =
        match crate::scan_routing::route_scan_job(&body.0, auth.tenant_id, state.app_pool.as_ref())
            .await
        {
            Ok(x) => x,
            Err(e) => {
                let mut body_json = json!({"detail": e.detail(), "code": e.error_code()});
                let mut response_headers = axum::http::HeaderMap::new();
                if let Some((reset_at, limit, used)) = e.quota_metadata() {
                    let retry_after = (reset_at - chrono::Utc::now().timestamp()).max(1);
                    if let Some(obj) = body_json.as_object_mut() {
                        obj.insert("reset_at_unix".into(), json!(reset_at));
                        obj.insert("limit".into(), json!(limit));
                        obj.insert("used".into(), json!(used));
                        obj.insert("retry_after_seconds".into(), json!(retry_after));
                    }
                    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
                        response_headers.insert("Retry-After", v);
                    }
                }
                let mut resp = (e.status_code(), Json(body_json)).into_response();
                resp.headers_mut().extend(response_headers);
                return resp;
            }
        };
    if let Some(t) = body
        .get("target")
        .and_then(Value::as_str)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        crate::edge_swarm_intel::enrich_scan_payload_with_edge_node(
            state.app_pool.as_ref(),
            auth.tenant_id,
            t,
            &mut payload,
        )
        .await;
        crate::fuzz_oob::enrich_job_payload_with_oast_scan_binding(&mut payload);
    }
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        job_kind.as_str(),
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
                "engine": engine,
                "job_kind": job_kind,
                "message": "queued; poll GET /api/jobs/:job_id for status and result",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, job_kind = %job_kind, "enqueue scan job failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": format!("enqueue failed: {}", e)})),
            )
                .into_response()
        }
    }
}

async fn ws_timing(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> Response {
    let mut rx = state.timing_broadcast_tx.subscribe();
    ws.on_upgrade(move |mut socket| async move {
        while let Ok(msg) = rx.recv().await {
            if socket.send(Message::Text(msg)).await.is_err() { break; }
        }
    })
}

async fn ws_ai_redteam(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> Response {
    let mut rx = state.redteam_broadcast_tx.subscribe();
    ws.on_upgrade(move |mut socket| async move {
        while let Ok(msg) = rx.recv().await {
            if socket.send(Message::Text(msg)).await.is_err() { break; }
        }
    })
}

async fn ws_threat_intel(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> Response {
    let mut rx = state.radar_broadcast_tx.subscribe();
    ws.on_upgrade(move |mut socket| async move {
        while let Ok(msg) = rx.recv().await {
            if socket.send(Message::Text(msg)).await.is_err() { break; }
        }
    })
}

async fn api_telemetry_stream(
    State(state): State<Arc<AppState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Optional `job_id` query param scopes the stream so each client only sees its own job.
    // Without a filter the SSE was leaking every tenant's telemetry to every connection.
    let want_job: Option<String> = q
        .get("job_id")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut rx = state.telemetry_broadcast_tx.subscribe();
    let event_stream = stream! {
        while let Ok(payload) = rx.recv().await {
            if let Some(want) = want_job.as_deref() {
                let matches = serde_json::from_str::<serde_json::Value>(&payload)
                    .ok()
                    .and_then(|v| v.get("job_id").and_then(|x| x.as_str()).map(|s| s.to_string()))
                    .map(|jid| jid == want)
                    .unwrap_or_else(|| payload.contains(want));
                if !matches {
                    continue;
                }
            }
            yield Ok::<Event, Infallible>(Event::default().data(payload));
        }
    };
    Sse::new(event_stream)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(20)))
        .into_response()
}

async fn latency_tcp_connect_ms(host: &str, port: u16) -> Option<u64> {
    if host.is_empty() {
        return None;
    }
    let addr = format!("{}:{}", host, port);
    let start = std::time::Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(6),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_)) => Some(start.elapsed().as_millis() as u64),
        _ => None,
    }
}

async fn api_latency_probe(axum::extract::Json(body): axum::extract::Json<LatencyProbeBody>) -> Response {
    let url_raw = body.url.trim();
    if url_raw.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "latency_ms": null, "error": "url required" }))).into_response();
    }
    let parsed = match url::Url::parse(url_raw) {
        Ok(u) => u,
        Err(_) => match url::Url::parse(&format!("https://{}", url_raw)) {
            Ok(u) => u,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "latency_ms": null, "error": format!("invalid url: {e}") })),
                )
                    .into_response();
            }
        },
    };
    let url = parsed.as_str();
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent("Weissman-CommandCenter/1.0 (latency-probe)")
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => reqwest::Client::new(),
    };
    let start = std::time::Instant::now();
    match client.get(url).send().await {
        Ok(resp) => {
            let _ = resp.bytes().await;
            (
                StatusCode::OK,
                Json(json!({
                    "latency_ms": start.elapsed().as_millis() as u64,
                    "probe": "http",
                })),
            )
                .into_response()
        }
        Err(e) => {
            let http_err = e.to_string();
            let host = parsed.host_str().unwrap_or("");
            let port = parsed
                .port_or_known_default()
                .unwrap_or(if parsed.scheme() == "http" { 80 } else { 443 });
            if let Some(ms) = latency_tcp_connect_ms(host, port).await {
                (
                    StatusCode::OK,
                    Json(json!({
                        "latency_ms": ms,
                        "probe": "tcp",
                        "http_error": http_err,
                    })),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(json!({ "latency_ms": null, "error": http_err })),
                )
                    .into_response()
            }
        }
    }
}

async fn api_dag_get() -> Response {
    let g = dag_engine::build_engine_dag();
    let (nodes, edges) = dag_engine::dag_for_ui(&g);
    let nodes_json: Vec<Value> = nodes.iter().map(|(id, label)| json!({ "id": id, "label": label })).collect();
    let edges_json: Vec<Value> = edges.iter().map(|(s, t)| json!({ "source": s, "target": t })).collect();
    let mut stage_to_nodes: std::collections::HashMap<u8, Vec<String>> = std::collections::HashMap::new();
    for stage in 0..=4u8 {
        let engines = dag_pipeline::engines_for_stage(stage);
        stage_to_nodes.insert(stage, engines.iter().map(|s| s.to_string()).collect());
    }
    stage_to_nodes.insert(4, vec!["compliance".to_string()]);
    (StatusCode::OK, Json(json!({ "nodes": nodes_json, "edges": edges_json, "stage_to_nodes": stage_to_nodes }))).into_response()
}

// ── Auto Domain Discovery ─────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct DomainDiscoveryRequest {
    target: String,
    #[serde(default)]
    company_name: Option<String>,
}

#[allow(dead_code)]
async fn api_discovery_domains(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::extract::Json<DomainDiscoveryRequest>,
) -> Response {
    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &u,
            "discovery_initiated",
            &format!("auto_domain_discovery target={}", body.target.chars().take(200).collect::<String>()),
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }

    let target = body.target.trim().to_string();
    if target.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "target required"})),
        )
            .into_response();
    }

    let result = crate::auto_domain_discovery_engine::run_auto_discovery(
        &target,
        body.company_name.as_deref(),
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "primary_domain": result.primary_domain,
            "company_name": result.company_name,
            "total_discovered": result.total_discovered,
            "live_domains": result.live_domains,
            "stages_completed": result.stages_completed.iter().map(|s| format!("{}", s)).collect::<Vec<_>>(),
            "domains": result.domains,
        })),
    )
        .into_response()
}

// ── Scan All Engines for Client ───────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct ScanAllEnginesRequest {
    client_id: i64,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    engines: Option<Vec<String>>,
}

#[allow(dead_code)]
async fn api_scan_all_engines(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    body: axum::extract::Json<ScanAllEnginesRequest>,
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

    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &u,
            "scan_all_engines_initiated",
            &format!("client_id={} engines={:?}", body.client_id, body.engines),
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }

    // Get enabled engines for client, or use provided list
    let engines: Vec<String> = if let Some(ref custom_engines) = body.engines {
        custom_engines.clone()
    } else {
        // Fetch from client config
        let config_result: Option<Value> = sqlx::query_scalar(
            "SELECT config FROM clients WHERE id = $1 AND tenant_id = $2"
        )
        .bind(body.client_id)
        .bind(auth.tenant_id)
        .fetch_optional(state.app_pool.as_ref())
        .await
        .ok()
        .flatten();
        
        config_result
            .and_then(|c| c.get("enabled_engines").cloned())
            .and_then(|e| e.as_array().cloned())
            .map(|arr| arr.into_iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| weissman_core::models::engine::KNOWN_ENGINE_IDS.iter().map(|s| s.to_string()).collect())
    };

    if engines.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "No engines configured for this client"})),
        )
            .into_response();
    }

    // Get target from client if not provided
    let target = if let Some(ref t) = body.target {
        t.clone()
    } else {
        let domains_result: Option<String> = sqlx::query_scalar(
            "SELECT domains FROM clients WHERE id = $1 AND tenant_id = $2"
        )
        .bind(body.client_id)
        .bind(auth.tenant_id)
        .fetch_optional(state.app_pool.as_ref())
        .await
        .ok()
        .flatten();

        domains_result
            .and_then(|d| {
                serde_json::from_str::<Vec<String>>(&d)
                    .ok()
                    .and_then(|arr| arr.first().cloned())
            })
            .unwrap_or_default()
    };

    // Queue scan-all-engines job
    let payload = json!({
        "client_id": body.client_id,
        "target": target,
        "engines": engines,
    });

    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "scan_all_engines",
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
                "engines_queued": engines.len(),
                "message": "All engines scan queued; poll status_url for progress",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue scan_all_engines failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

// ── Scan All Discovered Domains ───────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct ScanDomainsRequest {
    client_id: i64,
    domains: Vec<String>,
    #[serde(default)]
    engines: Option<Vec<String>>,
}

#[allow(dead_code)]
async fn api_scan_discovered_domains(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    body: axum::extract::Json<ScanDomainsRequest>,
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

    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &u,
            "scan_domains_initiated",
            &format!("client_id={} domains_count={}", body.client_id, body.domains.len()),
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }

    if body.domains.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "domains list required"})),
        )
            .into_response();
    }

    // Default engines for domain scanning (recon-focused)
    let engines = body.engines.clone().unwrap_or_else(|| {
        vec![
            "osint".to_string(),
            "asm".to_string(),
            "discovery_engine".to_string(),
            "recon".to_string(),
            "leak_hunter".to_string(),
        ]
    });

    let payload = json!({
        "client_id": body.client_id,
        "domains": body.domains,
        "engines": engines,
    });

    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "scan_discovered_domains",
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
                "domains_count": body.domains.len(),
                "engines": engines,
                "message": "Domain scan queued for all discovered domains",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue scan_discovered_domains failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}
