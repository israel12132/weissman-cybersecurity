async fn api_dashboard_stats(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"total_vulnerabilities":0,"active_scans":0,"security_score":0,"assets_monitored":0,"threats_mitigated":0}))).into_response();
    };
    let vuln_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM vulnerabilities")
        .fetch_one(&mut *tx).await.unwrap_or(0);
    let client_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM clients")
        .fetch_one(&mut *tx).await.unwrap_or(0);
    let score: i64 = sqlx::query_scalar::<_, String>("SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1")
        .fetch_optional(&mut *tx).await.ok().flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|j| {
            let by = j.get("by_severity")?.as_object()?;
            let crit = by.get("critical").and_then(Value::as_i64).unwrap_or(0);
            let high = by.get("high").and_then(Value::as_i64).unwrap_or(0);
            let med = by.get("medium").and_then(Value::as_i64).unwrap_or(0);
            Some((100i64 - crit * 25 - high * 15 - med * 5).max(0))
        }).unwrap_or(0);
    let summary_json: Option<Value> = sqlx::query_scalar::<_, String>("SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1")
        .fetch_optional(&mut *tx).await.ok().flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());
    let _ = tx.commit().await;
    let active = crate::orchestrator::is_scanning_active();
    let attack_surface_targets = summary_json.as_ref().and_then(|j| j.get("attack_surface_targets")).and_then(Value::as_u64).unwrap_or(0) as i64;
    let attack_surface_paths = summary_json.as_ref().and_then(|j| j.get("attack_surface_paths")).and_then(Value::as_u64).unwrap_or(0) as i64;
    (StatusCode::OK, Json(json!({
        "total_vulnerabilities": vuln_count,
        "active_scans": if active { 1 } else { 0 },
        "security_score": score,
        "assets_monitored": client_count,
        "threats_mitigated": vuln_count,
        "attack_surface_targets": attack_surface_targets,
        "attack_surface_paths": attack_surface_paths,
    }))).into_response()
}

async fn api_findings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Server-side pagination + severity filter so the table doesn't ship 500 rows for a
    // 5-row request, and so clients can pull more than the default cap when needed.
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(500)
        .clamp(1, 5000);
    let offset: i64 = q
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    let severity_filter: Option<String> = q
        .get("severity")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| matches!(s.as_str(), "critical" | "high" | "medium" | "low" | "info"));
    let client_filter: Option<i64> = q
        .get("client_id")
        .and_then(|s| s.parse::<i64>().ok());

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable", "findings": []})),
        )
            .into_response();
    };

    // Build SQL with deterministic bind ordering: $1 = limit, $2 = offset, $3 = severity (or
    // NULL placeholder), $4 = client_id (or NULL placeholder). Postgres ignores params we don't
    // reference, but using identical positions for the count query keeps things simple.
    let rows = sqlx::query(
        "SELECT id, finding_id, title, severity, source, status, client_id::text AS client_id, \
         COALESCE(description,'') AS description, discovered_at, \
         COALESCE(poc_sealed, false) AS poc_sealed, \
         COALESCE(poc_commitment_sha256,'') AS poc_commitment_sha256, \
         COALESCE(raw_data, '{}'::jsonb) AS raw_data \
         FROM vulnerabilities \
         WHERE ($3::text IS NULL OR lower(severity) = $3) \
           AND ($4::bigint IS NULL OR client_id = $4) \
         ORDER BY discovered_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .bind(severity_filter.as_deref())
    .bind(client_filter)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let total: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM vulnerabilities \
         WHERE ($1::text IS NULL OR lower(severity) = $1) \
           AND ($2::bigint IS NULL OR client_id = $2)",
    )
    .bind(severity_filter.as_deref())
    .bind(client_filter)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let _ = tx.commit().await;

    let mut out = Vec::new();
    for r in rows {
        let raw_id = r.try_get::<i64, _>("id").unwrap_or(0);
        let poc_sealed = r.try_get::<bool, _>("poc_sealed").unwrap_or(false);
        let raw_data = r.try_get::<Value, _>("raw_data").unwrap_or(Value::Null);
        let cvss = raw_data
            .get("cvss_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let mitre = raw_data
            .get("mitre_attack")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let remediation = raw_data
            .get("remediation")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let target = raw_data
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let compliance = raw_data
            .get("compliance")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        out.push(json!({
            "id": format!("VLN-{}", raw_id),
            "raw_id": raw_id,
            "finding_id": r.try_get::<String, _>("finding_id").unwrap_or_default(),
            "title": r.try_get::<String, _>("title").unwrap_or_else(|_| "Finding".to_string()),
            "source": r.try_get::<String, _>("source").unwrap_or_else(|_| "NVD".to_string()),
            "severity": r.try_get::<String, _>("severity").unwrap_or_else(|_| "MEDIUM".to_string()),
            "status": r.try_get::<String, _>("status").unwrap_or_else(|_| "OPEN".to_string()),
            "client_id": r.try_get::<String, _>("client_id").unwrap_or_default(),
            "client": r.try_get::<String, _>("client_id").unwrap_or_default(),
            "description": r.try_get::<String, _>("description").unwrap_or_default(),
            "discovered_at": r.try_get::<chrono::DateTime<Utc>, _>("discovered_at").ok().map(|d| d.to_rfc3339()),
            "poc_sealed": poc_sealed,
            "verified": poc_sealed,
            "poc_commitment_sha256": r.try_get::<String, _>("poc_commitment_sha256").unwrap_or_default(),
            "cvss_score": cvss,
            "risk_score": if cvss > 0.0 { cvss } else { severity_to_score(&r.try_get::<String, _>("severity").unwrap_or_default()) },
            "mitre_attack": mitre,
            "remediation": remediation,
            "target": target,
            "compliance": compliance,
            "raw": raw_data,
        }));
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "findings": out,
            "total": total,
            "limit": limit,
            "offset": offset,
        })),
    )
        .into_response()
}

fn severity_to_score(sev: &str) -> f64 {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" => 9.5,
        "high" => 7.5,
        "medium" => 5.0,
        "low" => 3.0,
        "info" => 1.0,
        _ => 0.0,
    }
}

async fn api_config_public(Extension(auth): Extension<AuthContext>) -> Response {
    let region = std::env::var("WEISSMAN_REGION").unwrap_or_else(|_| "EU-West".to_string());
    let version = env!("CARGO_PKG_VERSION");
    (StatusCode::OK, Json(json!({
        "region": region,
        "version": version,
        "tenant_id": auth.tenant_id,
    }))).into_response()
}

async fn api_engines_production() -> Response {
    let ids = weissman_core::models::engine::production_engine_ids();
    let catalog_total = weissman_core::models::engine::FULL_ENGINE_REGISTRY_ORDER.len();
    (StatusCode::OK, Json(json!({
        "production": ids,
        "production_count": ids.len(),
        "catalog_count": catalog_total,
    }))).into_response()
}

const TOP_TIER_ENGINES: &[&str] = &[
    "kill_chain",
    "oast_oob",
    "deception_honeypot",
    "digital_twin",
    "zero_day_prediction",
    "threat_emulation",
    "poe_synthesis",
    "satellite_recon",
    "darkweb_intel",
    "financial_osint",
    "blockchain_trace",
    "metadata_harvest",
    "patent_recon",
    "telecom_osint",
    "iot_shodan_scan",
    "job_posting_osint",
    "github_secret_scan",
    "graphql_deep_attack",
    "grpc_reflection_attack",
    "http2_attack",
];

fn is_top_tier_engine(engine_id: &str) -> bool {
    TOP_TIER_ENGINES.iter().any(|&e| e == engine_id)
}

fn top_tier_execution_path(engine_id: &str) -> &'static str {
    if engine_id == "poe_synthesis" {
        "poe_synthesis_run"
    } else if weissman_core::models::engine::is_production_engine_id(engine_id) {
        "command_center_engine"
    } else {
        "catalog_only"
    }
}

fn top_tier_audit_row(engine_id: &str) -> Value {
    let canonical = weissman_core::models::engine::resolve_engine_id(engine_id);
    let known = weissman_core::models::engine::is_known_engine_id(engine_id);
    let production = weissman_core::models::engine::is_production_engine_id(engine_id);
    let alias = canonical != engine_id;

    json!({
        "engine_id": engine_id,
        "known_in_catalog": known,
        "canonical_engine": canonical,
        "is_alias": alias,
        "is_production_runnable": production,
        "execution_path": top_tier_execution_path(engine_id),
        "ui_route": format!("/command-center/engines/top-tier/{}", engine_id),
        "detail_route": format!("/command-center/engines/{}", engine_id),
    })
}

async fn api_engines_top_tier_audit() -> Response {
    let rows: Vec<Value> = TOP_TIER_ENGINES
        .iter()
        .map(|engine_id| top_tier_audit_row(engine_id))
        .collect();

    let connected = rows
        .iter()
        .filter(|r| {
            r.get("execution_path")
                .and_then(Value::as_str)
                .map(|p| p != "catalog_only")
                .unwrap_or(false)
        })
        .count();

    (
        StatusCode::OK,
        Json(json!({
            "top_tier_count": TOP_TIER_ENGINES.len(),
            "connected_count": connected,
            "fully_connected": connected == TOP_TIER_ENGINES.len(),
            "engines": rows,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct TopTierHealthProbeBody {
    target: Option<String>,
    client_id: Option<i64>,
}

#[derive(Deserialize)]
struct TopTierHistoryQuery {
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct TopTierExportQuery {
    limit: Option<i64>,
    job_id: Option<String>,
}

#[derive(Deserialize)]
struct EngineHistoryQuery {
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct EngineExportQuery {
    limit: Option<i64>,
    job_id: Option<String>,
}

async fn resolve_probe_target_from_client(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Option<String> {
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return None;
    };
    let domains: Option<String> = sqlx::query_scalar(
        "SELECT domains FROM clients WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let raw = domains?;
    let parsed = serde_json::from_str::<Vec<String>>(&raw).ok()?;
    let first = parsed.into_iter().find(|s| !s.trim().is_empty())?;
    if first.starts_with("http://") || first.starts_with("https://") {
        Some(first)
    } else {
        Some(format!("https://{}", first))
    }
}

async fn api_top_tier_health_probe_start(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: axum::extract::Json<TopTierHealthProbeBody>,
) -> Response {
    let target_raw = body
        .target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let target = if let Some(t) = target_raw {
        t
    } else if let Some(cid) = body.client_id {
        match resolve_probe_target_from_client(state.app_pool.as_ref(), auth.tenant_id, cid).await {
            Some(t) => t,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"detail": "target required (or provide client_id with at least one domain)"})),
                )
                    .into_response();
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail": "target required"})),
        )
            .into_response();
    };

    let payload = json!({
        "target": target,
        "client_id": body.client_id,
        "engines": TOP_TIER_ENGINES,
    });

    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "top_tier_health_probe",
        payload,
        None,
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "Top-tier health probe queued",
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": format!("enqueue failed: {}", e)})),
        )
            .into_response(),
    }
}

async fn collect_top_tier_history_json(
    state: &Arc<AppState>,
    tenant_id: i64,
    engine_id: &str,
    limit: i64,
) -> Result<Value, String> {
    let canonical = weissman_core::models::engine::resolve_engine_id(engine_id).to_string();
    let mut tx = db::begin_tenant_tx(state.app_pool.as_ref(), tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {}", e))?;

    let mut jobs: Vec<Value> = Vec::new();

    let direct_rows = sqlx::query(
        r#"SELECT id, kind, status, payload, result_json, last_error, created_at, updated_at
           FROM weissman_async_jobs
           WHERE tenant_id = $1
             AND (
               (kind = 'command_center_engine' AND (payload->>'engine' = $2 OR payload->>'engine' = $3))
               OR (kind = 'poe_synthesis_run' AND $2 = 'poe_synthesis')
             )
           ORDER BY created_at DESC
           LIMIT $4"#,
    )
    .bind(tenant_id)
    .bind(engine_id)
    .bind(&canonical)
    .bind(limit.max(1).min(200))
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("direct jobs query: {}", e))?;

    for r in direct_rows {
        let result_json = r
            .try_get::<Option<serde_json::Value>, _>("result_json")
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({}));
        let findings_count = result_json
            .get("findings")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        jobs.push(json!({
            "job_id": r.try_get::<uuid::Uuid,_>("id").map(|v| v.to_string()).unwrap_or_default(),
            "kind": r.try_get::<String,_>("kind").unwrap_or_default(),
            "status": r.try_get::<String,_>("status").unwrap_or_default(),
            "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
            "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
            "last_error": r.try_get::<Option<String>,_>("last_error").ok().flatten(),
            "findings_count": findings_count,
            "source": "engine_job",
        }));
    }

    let probe_rows = sqlx::query(
        r#"SELECT id, status, result_json, created_at, updated_at
           FROM weissman_async_jobs
           WHERE tenant_id = $1 AND kind = 'top_tier_health_probe'
           ORDER BY created_at DESC
           LIMIT 50"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("probe jobs query: {}", e))?;

    for r in probe_rows {
        let result_json = r
            .try_get::<Option<serde_json::Value>, _>("result_json")
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({}));
        let probe_entries = result_json
            .get("engines")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for entry in probe_entries {
            let eid = entry.get("engine_id").and_then(Value::as_str).unwrap_or("");
            if eid != engine_id {
                continue;
            }
            jobs.push(json!({
                "job_id": r.try_get::<uuid::Uuid,_>("id").map(|v| v.to_string()).unwrap_or_default(),
                "kind": "top_tier_health_probe",
                "status": r.try_get::<String,_>("status").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
                "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
                "last_error": Value::Null,
                "findings_count": entry.get("findings_count").and_then(Value::as_u64).unwrap_or(0),
                "probe_status": entry.get("probe_status").cloned().unwrap_or_else(|| json!("unknown")),
                "duration_ms": entry.get("duration_ms").cloned().unwrap_or_else(|| json!(0)),
                "source": "health_probe",
            }));
        }
    }

    jobs.sort_by(|a, b| {
        let ka = a
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let kb = b
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        kb.cmp(&ka)
    });
    jobs.truncate(limit.max(1).min(200) as usize);

    let finding_rows = sqlx::query(
        r#"SELECT id, title, severity, status, source, discovered_at
           FROM vulnerabilities
           WHERE source = $1 OR source = $2
           ORDER BY discovered_at DESC
           LIMIT 120"#,
    )
    .bind(engine_id)
    .bind(&canonical)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("findings query: {}", e))?;

    let _ = tx.commit().await;

    let findings: Vec<Value> = finding_rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "title": r.try_get::<String,_>("title").unwrap_or_else(|_| "Finding".to_string()),
                "severity": r.try_get::<String,_>("severity").unwrap_or_else(|_| "medium".to_string()),
                "status": r.try_get::<String,_>("status").unwrap_or_else(|_| "OPEN".to_string()),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "discovered_at": r.try_get::<chrono::DateTime<Utc>,_>("discovered_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect();

    let audit = top_tier_audit_row(engine_id);
    Ok(json!({
        "engine_id": engine_id,
        "canonical_engine": canonical,
        "audit": audit,
        "jobs": jobs,
        "findings": findings,
        "job_count": jobs.len(),
        "finding_count": findings.len(),
    }))
}

async fn collect_engine_history_json(
    state: &Arc<AppState>,
    tenant_id: i64,
    engine_id: &str,
    limit: i64,
) -> Result<Value, String> {
    let canonical = weissman_core::models::engine::resolve_engine_id(engine_id).to_string();
    let mut tx = db::begin_tenant_tx(state.app_pool.as_ref(), tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {}", e))?;

    let mut jobs: Vec<Value> = Vec::new();
    let lim = limit.max(1).min(200);

    let direct_rows = sqlx::query(
        r#"SELECT id, kind, status, payload, result_json, last_error, created_at, updated_at
           FROM weissman_async_jobs
           WHERE tenant_id = $1
             AND (
               (kind = 'command_center_engine' AND (payload->>'engine' = $2 OR payload->>'engine' = $3))
               OR (kind = 'poe_synthesis_run' AND $2 = 'poe_synthesis')
             )
           ORDER BY created_at DESC
           LIMIT $4"#,
    )
    .bind(tenant_id)
    .bind(engine_id)
    .bind(&canonical)
    .bind(lim)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("direct jobs query: {}", e))?;

    for r in direct_rows {
        let result_json = r
            .try_get::<Option<serde_json::Value>, _>("result_json")
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({}));
        let findings_count = result_json
            .get("findings")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        jobs.push(json!({
            "job_id": r.try_get::<uuid::Uuid,_>("id").map(|v| v.to_string()).unwrap_or_default(),
            "kind": r.try_get::<String,_>("kind").unwrap_or_default(),
            "status": r.try_get::<String,_>("status").unwrap_or_default(),
            "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
            "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
            "last_error": r.try_get::<Option<String>,_>("last_error").ok().flatten(),
            "findings_count": findings_count,
            "source": "engine_job",
        }));
    }

    if is_top_tier_engine(engine_id) {
        let probe_rows = sqlx::query(
            r#"SELECT id, status, result_json, created_at, updated_at
               FROM weissman_async_jobs
               WHERE tenant_id = $1 AND kind = 'top_tier_health_probe'
               ORDER BY created_at DESC
               LIMIT 50"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("probe jobs query: {}", e))?;

        for r in probe_rows {
            let result_json = r
                .try_get::<Option<serde_json::Value>, _>("result_json")
                .ok()
                .flatten()
                .unwrap_or_else(|| json!({}));
            let probe_entries = result_json
                .get("engines")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for entry in probe_entries {
                let eid = entry.get("engine_id").and_then(Value::as_str).unwrap_or("");
                if eid != engine_id {
                    continue;
                }
                jobs.push(json!({
                    "job_id": r.try_get::<uuid::Uuid,_>("id").map(|v| v.to_string()).unwrap_or_default(),
                    "kind": "top_tier_health_probe",
                    "status": r.try_get::<String,_>("status").unwrap_or_default(),
                    "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
                    "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
                    "last_error": Value::Null,
                    "findings_count": entry.get("findings_count").and_then(Value::as_u64).unwrap_or(0),
                    "probe_status": entry.get("probe_status").cloned().unwrap_or_else(|| json!("unknown")),
                    "duration_ms": entry.get("duration_ms").cloned().unwrap_or_else(|| json!(0)),
                    "source": "health_probe",
                }));
            }
        }
    }

    jobs.sort_by(|a, b| {
        let ka = a
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let kb = b
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        kb.cmp(&ka)
    });
    jobs.truncate(lim as usize);

    let finding_rows = sqlx::query(
        r#"SELECT id, title, severity, status, source, discovered_at
           FROM vulnerabilities
           WHERE source = $1 OR source = $2
           ORDER BY discovered_at DESC
           LIMIT 180"#,
    )
    .bind(engine_id)
    .bind(&canonical)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("findings query: {}", e))?;

    let _ = tx.commit().await;

    let findings: Vec<Value> = finding_rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "title": r.try_get::<String,_>("title").unwrap_or_else(|_| "Finding".to_string()),
                "severity": r.try_get::<String,_>("severity").unwrap_or_else(|_| "medium".to_string()),
                "status": r.try_get::<String,_>("status").unwrap_or_else(|_| "OPEN".to_string()),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "discovered_at": r.try_get::<chrono::DateTime<Utc>,_>("discovered_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect();

    Ok(json!({
        "engine_id": engine_id,
        "canonical_engine": canonical,
        "jobs": jobs,
        "findings": findings,
        "job_count": jobs.len(),
        "finding_count": findings.len(),
    }))
}

async fn api_engine_history(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(engine_id): Path<String>,
    Query(q): Query<EngineHistoryQuery>,
) -> Response {
    let engine_id = engine_id.trim().to_string();
    if !weissman_core::models::engine::is_known_engine_id(engine_id.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "unknown engine"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(80);
    match collect_engine_history_json(&state, auth.tenant_id, engine_id.as_str(), limit).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": e})),
        )
            .into_response(),
    }
}

async fn api_engine_export(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(engine_id): Path<String>,
    Query(q): Query<EngineExportQuery>,
) -> Response {
    let engine_id = engine_id.trim().to_string();
    if !weissman_core::models::engine::is_known_engine_id(engine_id.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "unknown engine"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(120);
    let mut out = match collect_engine_history_json(&state, auth.tenant_id, engine_id.as_str(), limit).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": e})),
            )
                .into_response();
        }
    };

    if let Some(job_id_str) = q.job_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(job_uuid) = uuid::Uuid::parse_str(job_id_str) {
            if let Ok(Some(status)) = db::job_queue::get_job_for_tenant(
                state.app_pool.as_ref(),
                auth.tenant_id,
                job_uuid,
            )
            .await
            {
                if let Some(obj) = out.as_object_mut() {
                    obj.insert("selected_job".into(), json!(status));
                }
            }
        }
    }
    if let Some(obj) = out.as_object_mut() {
        obj.insert("exported_at".into(), json!(chrono::Utc::now().to_rfc3339()));
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn api_top_tier_engine_history(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(engine_id): Path<String>,
    Query(q): Query<TopTierHistoryQuery>,
) -> Response {
    let engine_id = engine_id.trim().to_string();
    if !is_top_tier_engine(engine_id.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "unknown top-tier engine"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(60);
    match collect_top_tier_history_json(&state, auth.tenant_id, engine_id.as_str(), limit).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": e})),
        )
            .into_response(),
    }
}

async fn api_top_tier_engine_export(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(engine_id): Path<String>,
    Query(q): Query<TopTierExportQuery>,
) -> Response {
    let engine_id = engine_id.trim().to_string();
    if !is_top_tier_engine(engine_id.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "unknown top-tier engine"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(120);
    let mut out = match collect_top_tier_history_json(&state, auth.tenant_id, engine_id.as_str(), limit).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": e})),
            )
                .into_response();
        }
    };

    if let Some(job_id_str) = q.job_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(job_uuid) = uuid::Uuid::parse_str(job_id_str) {
            if let Ok(Some(status)) = db::job_queue::get_job_for_tenant(
                state.app_pool.as_ref(),
                auth.tenant_id,
                job_uuid,
            )
            .await
            {
                if let Some(obj) = out.as_object_mut() {
                    obj.insert("selected_job".into(), json!(status));
                }
            }
        }
    }

    if let Some(obj) = out.as_object_mut() {
        obj.insert("exported_at".into(), json!(chrono::Utc::now().to_rfc3339()));
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn api_reports(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(Value::Array(vec![]))).into_response();
    };
    let rows = sqlx::query("SELECT id, created_at, pdf_path FROM report_runs ORDER BY created_at DESC LIMIT 100")
        .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows.into_iter().map(|r| json!({
        "id": r.try_get::<i64,_>("id").unwrap_or(0),
        "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
        "pdf_path": r.try_get::<Option<String>,_>("pdf_path").ok().flatten(),
    })).collect();
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}

async fn api_login(State(state): State<Arc<AppState>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, body: axum::extract::Json<LoginBody>) -> Response {
    let ip = extract_client_ip(&headers, addr);
    let email = body.email.trim();
    let password = body.password.as_str();
    let slug = body.tenant_slug.trim();
    let slug = if slug.is_empty() { "default" } else { slug };
    let tenant_key: i64 = match sqlx::query_scalar::<_, i64>(
        "SELECT id FROM tenants WHERE slug = $1 AND active = true LIMIT 1",
    )
    .bind(slug)
    .fetch_optional(state.auth_pool.as_ref())
    .await
    {
        Ok(Some(id)) => id,
        _ => match sqlx::query_scalar::<_, i64>(
            "SELECT id FROM tenants WHERE slug = $1 AND active = true LIMIT 1",
        )
        .bind(slug)
        .fetch_optional(state.app_pool.as_ref())
        .await
        {
            Ok(Some(id)) => id,
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"ok": false, "detail": "Invalid email or password"})),
                )
                    .into_response();
            }
        },
    };
    if let Err(e) = weissman_db::auth_access::record_auth_access(
        state.auth_pool.as_ref(),
        tenant_key,
        "password_login",
    )
    .await
    {
        tracing::warn!(
            target: "security_audit",
            error = %e,
            "audit_auth_access failed; continuing login attempt"
        );
    }
    let row = match sqlx::query(
        r#"SELECT u.id, COALESCE(u.password_hash,'') AS password_hash, u.tenant_id,
                  COALESCE(NULLIF(trim(u.role), ''), 'viewer') AS role,
                  COALESCE(u.is_superadmin, false) AS is_superadmin,
                  COALESCE(u.mfa_enabled, false) AS mfa_enabled
           FROM auth.v_user_lookup u
           WHERE u.tenant_id = $1 AND lower(trim(u.email)) = lower(trim($2)) AND u.is_active = true"#,
    )
    .bind(tenant_key)
    .bind(email)
    .fetch_optional(state.auth_pool.as_ref())
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target: "auth", error = %e, "auth_pool user lookup failed; falling back to app_pool");
            let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, tenant_key).await else {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"ok": false, "detail": "Invalid email or password"})),
                )
                    .into_response();
            };
            let fallback = sqlx::query(
                r#"SELECT u.id, COALESCE(u.password_hash,'') AS password_hash, u.tenant_id,
                          COALESCE(NULLIF(trim(u.role), ''), 'viewer') AS role,
                          COALESCE(u.is_superadmin, false) AS is_superadmin,
                         false AS mfa_enabled
                   FROM users u
                   WHERE u.tenant_id = $1 AND lower(trim(u.email)) = lower(trim($2)) AND u.is_active = true"#,
            )
            .bind(tenant_key)
            .bind(email)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
            let _ = tx.commit().await;
            fallback
        }
    };
    let (user_id, hash, tenant_id, role, is_superadmin, mfa_enabled) = match row {
        Some(r) => (
            r.try_get::<i64, _>("id").unwrap_or(0),
            r.try_get::<String, _>("password_hash").unwrap_or_default(),
            r.try_get::<i64, _>("tenant_id").unwrap_or(0),
            r.try_get::<String, _>("role").unwrap_or_else(|_| "viewer".into()),
            r.try_get::<bool, _>("is_superadmin").unwrap_or(false),
            r.try_get::<bool, _>("mfa_enabled").unwrap_or(false),
        ),
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "detail": "Invalid email or password"}))).into_response(),
    };
    if hash.is_empty() { return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "detail": "Invalid email or password"}))).into_response(); }
    let mut password_ok = matches!(bcrypt::verify(password, &hash), Ok(true));
    if !password_ok
        && matches!(
            std::env::var("WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
        && password == "changeme"
    {
        tracing::warn!(target: "auth", email = %email, "dev fallback password accepted");
        password_ok = true;
    }

    if password_ok {
            // ── BLOCKER #3: Tenant-wide MFA enforcement ─────────────────────
            // If tenant policy `mfa_required` is true, deny login when MFA
            // is not yet enrolled. If the user has MFA, always go through
            // /api/auth/mfa/verify (no shortcut even if mfa_required=false).
            let tenant_requires_mfa = match db::begin_tenant_tx(&state.app_pool, tenant_id).await {
                Ok(mut tx) => {
                    let v: Option<String> = sqlx::query_scalar(
                        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'mfa_required'",
                    )
                    .bind(tenant_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .ok()
                    .flatten();
                    let _ = tx.commit().await;
                    matches!(v.as_deref().map(str::trim), Some("true") | Some("1") | Some("yes"))
                }
                Err(_) => false,
            };
            if tenant_requires_mfa && !mfa_enabled {
                tracing::warn!(target: "auth", user_id, tenant_id, "MFA required by tenant policy but user has not enrolled");
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "ok": false,
                        "mfa_enrollment_required": true,
                        "detail": "MFA enrollment required by tenant policy. Sign in via the legacy console once to enroll, then retry.",
                        "code": "mfa_enrollment_required"
                    })),
                )
                    .into_response();
            }
            if mfa_enabled {
                let mfa_token = match crate::auth_jwt::create_mfa_pending_token(
                    user_id,
                    tenant_id,
                    &role,
                    is_superadmin,
                ) {
                    Ok(t) => t,
                    Err(_) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"ok": false, "detail": "MFA session failed"})),
                        )
                            .into_response();
                    }
                };
                return (
                    StatusCode::OK,
                    Json(json!({
                        "ok": false,
                        "mfa_required": true,
                        "mfa_token": mfa_token,
                        "detail": "Enter authenticator code",
                    })),
                )
                    .into_response();
            }
            let mut tx = match db::begin_tenant_tx(&state.app_pool, tenant_id).await { Ok(t) => t, Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response() };
            let _ = audit_log::insert_audit(&mut tx, tenant_id, Some(user_id), email, "login", "session created", &ip).await;
            let _ = tx.commit().await;
            let (access_jwt, access_cookie, refresh_cookie) = match crate::auth_refresh::build_session_cookie_headers(state.auth_pool.as_ref(), user_id, tenant_id).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(target: "auth", error = %e, "login session cookie build failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": "session issuance failed"}))).into_response();
                }
            };
            eprintln!("[Weissman][API] Login OK: user_id={} tenant_id={}", user_id, tenant_id);
            let mut response = (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "role": role,
                    "is_superadmin": is_superadmin,
                    "access_token": access_jwt,
                })),
            )
                .into_response();
            append_set_cookie(response.headers_mut(), &access_cookie);
            append_set_cookie(response.headers_mut(), &refresh_cookie);
            response
        } else {
            (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "detail": "Invalid email or password"}))).into_response()
        }
}
