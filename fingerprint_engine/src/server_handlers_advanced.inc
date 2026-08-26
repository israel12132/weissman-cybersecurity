// Generated handlers for: attack-paths, SOAR playbooks.
// Mounted from `serve.rs` via `include!`.

// ─── Attack-path endpoints ─────────────────────────────────────────────────

async fn api_attack_paths_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let recompute = q.get("recompute").map(|v| v == "1" || v == "true").unwrap_or(false);
    let top_k = q.get("top_k").and_then(|s| s.parse::<usize>().ok());

    if recompute {
        if let Err(r) = crate::rbac::require_operator(&auth) {
            return r;
        }
    }

    let snap = if recompute {
        match crate::attack_path::compute_and_store(&state.app_pool, auth.tenant_id, client_id, top_k).await {
            Ok(s) => Some(s),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "ok": false, "detail": scrub_internal_error(&e) })),
                ).into_response();
            }
        }
    } else {
        crate::attack_path::latest_snapshot(&state.app_pool, auth.tenant_id, client_id).await.ok().flatten()
    };

    match snap {
        Some(s) => (StatusCode::OK, Json(json!({ "ok": true, "snapshot": s }))).into_response(),
        None => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "snapshot": null,
                "detail": "no snapshot yet — call with ?recompute=1 to generate"
            })),
        ).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct RiskNodeFlagsBody {
    #[serde(default)]
    internet_exposed: Option<bool>,
    #[serde(default)]
    crown_jewel: Option<bool>,
    #[serde(default)]
    asset_value: Option<f32>,
}

async fn api_risk_node_flags_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(node_id): Path<i64>,
    Json(body): Json<RiskNodeFlagsBody>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query(
        r#"UPDATE risk_graph_nodes
              SET internet_exposed = COALESCE($1, internet_exposed),
                  crown_jewel      = COALESCE($2, crown_jewel),
                  asset_value      = COALESCE($3, asset_value)
            WHERE id = $4 AND tenant_id = $5"#,
    )
    .bind(body.internet_exposed)
    .bind(body.crown_jewel)
    .bind(body.asset_value)
    .bind(node_id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({"ok": true, "id": node_id}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "node not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": scrub_internal_error(&e)}))).into_response(),
    }
}

// ─── Battlespace topology (force-directed C2) ───────────────────────────────

async fn api_battlespace_topology(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    match crate::battlespace_topology::topology_bundle(
        &state.app_pool,
        auth.tenant_id,
        client_id,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

async fn api_battlespace_techniques(
    Extension(_auth): Extension<AuthContext>,
) -> Response {
    (
        StatusCode::OK,
        Json(crate::battlespace_topology::techniques_json()),
    )
        .into_response()
}

async fn api_battlespace_shadow_preview(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<crate::battlespace_topology::ShadowPreviewBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    match crate::battlespace_topology::shadow_preview(
        &state.app_pool,
        auth.tenant_id,
        &body,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Global remediation priority ("fix-first" program over all live findings) ───
async fn api_remediation_priority_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::remediation_priority::load_and_rank(
        &state.app_pool,
        auth.tenant_id,
        client_id,
        limit,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Portfolio (fleet-wide) posture across all clients in the tenant ───
async fn api_portfolio_posture(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let max_clients: i64 = q
        .get("max_clients")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(200)
        .clamp(1, 500);
    let per_client_limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::portfolio_posture::load_portfolio(
        &state.app_pool,
        auth.tenant_id,
        max_clients,
        per_client_limit,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Portfolio (fleet-wide) ATT&CK exposure across all clients in the tenant ───
async fn api_portfolio_attack_exposure(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let max_clients: i64 = q
        .get("max_clients")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(200)
        .clamp(1, 500);
    let per_client_limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::attack_exposure::load_portfolio_exposure(
        &state.app_pool,
        auth.tenant_id,
        max_clients,
        per_client_limit,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Complete arsenal inventory (every production engine + authoritative metadata) ───
async fn api_arsenal_catalog() -> Response {
    (StatusCode::OK, Json(crate::arsenal_catalog::summary())).into_response()
}

// ─── Arsenal integrity / de-duplication audit (distinct engines vs duplicate aliases) ───
async fn api_arsenal_integrity() -> Response {
    (StatusCode::OK, Json(crate::arsenal_integrity::audit_json())).into_response()
}

// ─── Stealth batch deploy ("run all" → backend drips the batch like a human red-team) ───
async fn api_arsenal_deploy(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let client_id = body.get("client_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let target = body
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let mut engines: Vec<String> = body
        .get("engines")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    engines.dedup();
    if client_id <= 0 || target.is_empty() || engines.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": "client_id, target and engines are required" })),
        )
            .into_response();
    }
    // Hard cap on a single batch (the drip, not a burst, is what keeps us under the WAF radar).
    engines.truncate(500);

    let st = body.get("stealth").cloned().unwrap_or_else(|| json!({}));
    let num = |k: &str, d: u64| st.get(k).and_then(|v| v.as_u64()).unwrap_or(d);
    let plan = crate::stealth_scheduler::StealthPlan {
        max_concurrent: num("max_concurrent", 10) as usize,
        jitter_min_ms: num("jitter_min_ms", 250),
        jitter_max_ms: num("jitter_max_ms", 1500),
        base_gap_ms: num("base_gap_ms", 300),
    }
    .sanitized();

    // Deterministic-per-batch seed from the target + size (no wall-clock dependency needed).
    let seed = target
        .bytes()
        .fold(0u64, |a, b| a.wrapping_mul(131).wrapping_add(b as u64))
        .wrapping_add(engines.len() as u64);
    let batch_id = format!("arsenal-{}-{}-{}", auth.tenant_id, client_id, seed);
    let mut sched = crate::stealth_scheduler::schedule(engines.len(), &plan, seed);
    // Fire in true global time order (lanes interleave), so the drip is smooth.
    sched.sort_by_key(|d| d.delay_ms);
    let engines_queued = engines.len();
    let summary = crate::stealth_scheduler::plan_summary(engines_queued, &plan, seed);

    // Detach the drip: sleep to each dispatch's offset, then enqueue that engine's scan job with its
    // rotated identity. Returns immediately; the operation unfolds server-side under cover.
    let pool = state.app_pool.clone();
    let tenant_id = auth.tenant_id;
    let batch_id_task = batch_id.clone();
    tokio::spawn(async move {
        let mut elapsed = 0u64;
        for d in &sched {
            let wait = d.delay_ms.saturating_sub(elapsed);
            if wait > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                elapsed = d.delay_ms;
            }
            let payload = crate::stealth_scheduler::job_payload(
                &engines[d.index],
                &target,
                client_id,
                &batch_id_task,
                d,
            );
            let _ = crate::async_jobs::enqueue(&pool, tenant_id, "command_center_engine", payload, None)
                .await;
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": true,
            "batch_id": batch_id,
            "engines_queued": engines_queued,
            "plan": summary,
        })),
    )
        .into_response()
}

// ─── Stealth dispatch plan preview (how a batch drips out under concurrency/jitter) ───
async fn api_arsenal_deploy_plan(
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    fn num(q: &std::collections::HashMap<String, String>, k: &str, d: u64) -> u64 {
        q.get(k).and_then(|s| s.parse::<u64>().ok()).unwrap_or(d)
    }
    let count = num(&q, "count", 50).clamp(1, 2000) as usize;
    let plan = crate::stealth_scheduler::StealthPlan {
        max_concurrent: num(&q, "max_concurrent", 10) as usize,
        jitter_min_ms: num(&q, "jitter_min_ms", 250),
        jitter_max_ms: num(&q, "jitter_max_ms", 1500),
        base_gap_ms: num(&q, "base_gap_ms", 300),
    };
    // Deterministic preview seed derived from the request shape.
    let seed = (count as u64).wrapping_mul(0x9E37_79B9).wrapping_add(plan.max_concurrent as u64);
    let summary = crate::stealth_scheduler::plan_summary(count, &plan, seed);
    (StatusCode::OK, Json(summary)).into_response()
}

// ─── Arsenal recommendation (client exposure crossed against the engine arsenal) ───
async fn api_arsenal_recommendation_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::arsenal_intel::load_and_analyze(&state.app_pool, auth.tenant_id, client_id, limit)
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Backlog-aging analytics (open findings bucketed by age x severity) ───
async fn api_finding_aging_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::finding_aging::load_and_aggregate(&state.app_pool, auth.tenant_id, client_id, limit)
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Unified executive summary (posture + projection + forecast + top actions, one query) ───
async fn api_executive_summary_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::executive_summary::load_summary(&state.app_pool, auth.tenant_id, client_id, limit)
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Proactive SLA breach forecast (cumulative breaches by horizon) ───
async fn api_sla_forecast_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::sla_forecast::load_and_forecast(&state.app_pool, auth.tenant_id, client_id, limit)
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Per-client compliance-framework posture (crosswalk rolled up over findings) ───
async fn api_compliance_posture_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::compliance_posture::load_and_aggregate(
        &state.app_pool,
        auth.tenant_id,
        client_id,
        limit,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Board-level security posture score (distilled from the fix-first program) ───
async fn api_posture_score_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::posture_score::load_and_score(&state.app_pool, auth.tenant_id, client_id, limit)
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Live per-client MITRE ATT&CK exposure (technique ranking + tactic rollup) ───
async fn api_attack_exposure_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);
    match crate::attack_exposure::load_and_aggregate(
        &state.app_pool,
        auth.tenant_id,
        client_id,
        limit,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

// ─── Unified threat analysis (planner + correlation + NDR + ITDR over live findings) ───
async fn api_threat_analysis_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(500)
        .clamp(1, 2000);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT COALESCE(raw_data, '{}'::jsonb)                       AS rd,
                  COALESCE(title, '')                                   AS title,
                  COALESCE(severity, '')                                AS severity,
                  COALESCE(EXTRACT(EPOCH FROM discovered_at)::bigint, 0) AS ts
             FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2
            ORDER BY discovered_at ASC
            LIMIT $3"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
            )
                .into_response()
        }
    };

    let mut findings: Vec<Value> = Vec::with_capacity(rows.len());
    for r in &rows {
        let mut v: Value = r.try_get("rd").unwrap_or_else(|_| json!({}));
        if !v.is_object() {
            v = json!({});
        }
        if let Some(obj) = v.as_object_mut() {
            obj.entry("title")
                .or_insert_with(|| json!(r.try_get::<String, _>("title").unwrap_or_default()));
            obj.entry("severity")
                .or_insert_with(|| json!(r.try_get::<String, _>("severity").unwrap_or_default()));
            obj.insert("ts".to_string(), json!(r.try_get::<i64, _>("ts").unwrap_or(0)));
        }
        findings.push(v);
    }

    // Live NDR / ITDR signals (when ingested) feed the network/identity detectors.
    let (flows, auth_events) =
        load_ndr_itdr(&state.app_pool, auth.tenant_id, client_id, limit).await;
    let report = crate::threat_analysis::analyze(&findings, &flows, &auth_events);

    // Optional: persist detected multi-stage correlation incidents (operator-gated, idempotent).
    let mut persisted_incidents = 0usize;
    if q.get("persist").map(|v| v == "1" || v == "true").unwrap_or(false) {
        if let Err(r) = crate::rbac::require_operator(&auth) {
            return r;
        }
        let events = crate::correlation_rules::events_from_findings(&findings, |i, f| {
            f.get("ts")
                .and_then(|v| v.as_i64())
                .unwrap_or(1000 + (i as i64) * 60)
        });
        let hits = crate::correlation_rules::evaluate_all(
            &crate::correlation_rules::default_rules(),
            &events,
        );
        persisted_incidents = crate::correlation_rules::persist_incidents(
            &state.app_pool,
            auth.tenant_id,
            Some(client_id),
            &hits,
        )
        .await
        .unwrap_or(0);
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "client_id": client_id,
            "findings_analyzed": findings.len(),
            "persisted_incidents": persisted_incidents,
            "analysis": report,
        })),
    )
        .into_response()
}

/// `GET /api/analytics/attack-vectors[?client_id=]` — cross-domain attack-vector synthesis.
///
/// Loads the tenant's findings and fuses them into composite, multi-stage attack vectors (see
/// `attack_vector_synthesis`). Evidence-gated: every returned vector is backed by real findings, so
/// an empty finding set yields an empty vector list rather than fabricated chains.
async fn api_analytics_attack_vectors(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let client_filter: Option<i64> = q.get("client_id").and_then(|s| s.parse::<i64>().ok());
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(2000)
        .clamp(1, 5000);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable", "vectors": []})),
        )
            .into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id,
                  COALESCE(source, '')      AS source,
                  COALESCE(severity, '')    AS severity,
                  COALESCE(title, '')       AS title,
                  COALESCE(description, '') AS description,
                  client_id
             FROM vulnerabilities
            WHERE tenant_id = $1
              AND ($2::bigint IS NULL OR client_id = $2)
            ORDER BY discovered_at DESC
            LIMIT $3"#,
    )
    .bind(auth.tenant_id)
    .bind(client_filter)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(target: "analytics", tenant_id = auth.tenant_id, error = %e, "attack-vector findings query failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "attack-vector query failed", "vectors": []})),
            )
                .into_response();
        }
    };

    let findings: Vec<crate::attack_vector_synthesis::FindingLite> = rows
        .iter()
        .map(|r| crate::attack_vector_synthesis::FindingLite {
            id: r
                .try_get::<i64, _>("id")
                .map(|v| v.to_string())
                .unwrap_or_default(),
            engine: r.try_get::<String, _>("source").unwrap_or_default(),
            severity: r.try_get::<String, _>("severity").unwrap_or_default(),
            title: r.try_get::<String, _>("title").unwrap_or_default(),
            description: r.try_get::<String, _>("description").unwrap_or_default(),
            client_id: r.try_get::<Option<i64>, _>("client_id").ok().flatten(),
        })
        .collect();

    let mut body = crate::attack_vector_synthesis::synthesize_json(&findings);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("client_id".to_string(), json!(client_filter));
        obj.insert(
            "generated_at".to_string(),
            json!(chrono::Utc::now().to_rfc3339()),
        );
    }
    (StatusCode::OK, Json(body)).into_response()
}
async fn load_ndr_itdr(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> (
    Vec<crate::ndr_beacon::FlowSample>,
    Vec<crate::itdr::AuthEvent>,
) {
    let mut flows = Vec::new();
    let mut auth = Vec::new();
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return (flows, auth);
    };
    let frows = sqlx::query(
        r#"SELECT ts, dst, bytes_out
             FROM ndr_flow_samples
            WHERE tenant_id = $1 AND (client_id = $2 OR client_id IS NULL)
            ORDER BY ts ASC
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    for r in &frows {
        let ts: i64 = r.try_get("ts").unwrap_or(0);
        let dst: String = r.try_get("dst").unwrap_or_default();
        let b: i64 = r.try_get("bytes_out").unwrap_or(0);
        flows.push(crate::ndr_beacon::FlowSample::new(ts, &dst, b.max(0) as u64));
    }
    let arows = sqlx::query(
        r#"SELECT ts, username, ip, country, success, mfa_prompted
             FROM itdr_auth_events
            WHERE tenant_id = $1 AND (client_id = $2 OR client_id IS NULL)
            ORDER BY ts ASC
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    for r in &arows {
        let ts: i64 = r.try_get("ts").unwrap_or(0);
        let user: String = r.try_get("username").unwrap_or_default();
        let ip: String = r.try_get("ip").unwrap_or_default();
        let country: String = r.try_get("country").unwrap_or_default();
        let success: bool = r.try_get("success").unwrap_or(false);
        let mfa: bool = r.try_get("mfa_prompted").unwrap_or(false);
        auth.push(crate::itdr::AuthEvent::new(
            ts, &user, &ip, &country, success, mfa,
        ));
    }
    let _ = tx.commit().await;
    (flows, auth)
}

// ─── NDR / ITDR ingest (live data sources for the network/identity detectors) ───

#[derive(serde::Deserialize)]
struct NdrFlowIn {
    ts: i64,
    dst: String,
    #[serde(default)]
    bytes_out: i64,
}

#[derive(serde::Deserialize)]
struct NdrFlowsBody {
    #[serde(default)]
    client_id: Option<i64>,
    #[serde(default)]
    samples: Vec<NdrFlowIn>,
}

async fn api_ndr_flows_ingest(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<NdrFlowsBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    if body.samples.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "samples required"})),
        )
            .into_response();
    }
    if body.samples.len() > 5000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "max 5000 samples per request"})),
        )
            .into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let mut ingested = 0usize;
    for s in &body.samples {
        let dst = s.dst.trim();
        if dst.is_empty() || dst.len() > 255 {
            continue;
        }
        let res = sqlx::query(
            r#"INSERT INTO ndr_flow_samples (tenant_id, client_id, ts, dst, bytes_out)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(auth.tenant_id)
        .bind(body.client_id)
        .bind(s.ts)
        .bind(dst)
        .bind(s.bytes_out.max(0))
        .execute(&mut *tx)
        .await;
        if res.is_ok() {
            ingested += 1;
        }
    }
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true, "ingested": ingested}))).into_response()
}

#[derive(serde::Deserialize)]
struct ItdrAuthIn {
    ts: i64,
    #[serde(default)]
    user: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    success: bool,
    #[serde(default)]
    mfa_prompted: bool,
}

#[derive(serde::Deserialize)]
struct ItdrAuthBody {
    #[serde(default)]
    client_id: Option<i64>,
    #[serde(default)]
    events: Vec<ItdrAuthIn>,
}

async fn api_itdr_auth_ingest(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<ItdrAuthBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    if body.events.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "events required"})),
        )
            .into_response();
    }
    if body.events.len() > 5000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "max 5000 events per request"})),
        )
            .into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let mut ingested = 0usize;
    for e in &body.events {
        let user = e.user.trim();
        let ip = e.ip.trim();
        if user.is_empty() || ip.is_empty() || user.len() > 320 || ip.len() > 64 {
            continue;
        }
        let res = sqlx::query(
            r#"INSERT INTO itdr_auth_events
                 (tenant_id, client_id, ts, username, ip, country, success, mfa_prompted)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(auth.tenant_id)
        .bind(body.client_id)
        .bind(e.ts)
        .bind(user)
        .bind(ip)
        .bind(e.country.trim())
        .bind(e.success)
        .bind(e.mfa_prompted)
        .execute(&mut *tx)
        .await;
        if res.is_ok() {
            ingested += 1;
        }
    }
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true, "ingested": ingested}))).into_response()
}

// ─── Playbook endpoints ────────────────────────────────────────────────────

async fn api_playbooks_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, name, description, enabled, trigger_dsl, actions_dsl,
                  last_run_at, last_run_status, run_count, failure_count,
                  created_at, updated_at
             FROM weissman_playbooks
            ORDER BY enabled DESC, updated_at DESC"#,
    )
    .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;

    let list: Vec<Value> = rows.into_iter().map(|r| {
        let trig: Value = r.try_get("trigger_dsl").unwrap_or(json!({}));
        let acts: Value = r.try_get("actions_dsl").unwrap_or(json!([]));
        json!({
            "id":              r.try_get::<i64, _>("id").unwrap_or(0),
            "name":            r.try_get::<String, _>("name").unwrap_or_default(),
            "description":     r.try_get::<String, _>("description").unwrap_or_default(),
            "enabled":         r.try_get::<bool, _>("enabled").unwrap_or(false),
            "trigger":         trig,
            "actions":         acts,
            "last_run_at":     r.try_get::<Option<chrono::DateTime<Utc>>, _>("last_run_at").ok().flatten().map(|d| d.to_rfc3339()),
            "last_run_status": r.try_get::<String, _>("last_run_status").unwrap_or_default(),
            "run_count":       r.try_get::<i32, _>("run_count").unwrap_or(0),
            "failure_count":   r.try_get::<i32, _>("failure_count").unwrap_or(0),
            "created_at":      r.try_get::<chrono::DateTime<Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
            "updated_at":      r.try_get::<chrono::DateTime<Utc>, _>("updated_at").ok().map(|d| d.to_rfc3339()),
        })
    }).collect();
    (StatusCode::OK, Json(json!({"ok": true, "playbooks": list}))).into_response()
}

#[derive(serde::Deserialize)]
struct PlaybookBody {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    trigger: Value,
    #[serde(default)]
    actions: Value,
}

async fn api_playbooks_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<PlaybookBody>,
) -> Response {
    let name = body.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "detail": "name required"}))).into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let trigger = if body.trigger.is_null() { json!({}) } else { body.trigger };
    let actions = if body.actions.is_null() { json!([]) } else { body.actions };
    let id_res: Result<i64, _> = sqlx::query_scalar(
        r#"INSERT INTO weissman_playbooks
               (tenant_id, name, description, enabled, trigger_dsl, actions_dsl, created_by_user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id"#,
    )
    .bind(auth.tenant_id)
    .bind(name)
    .bind(&body.description)
    .bind(body.enabled)
    .bind(&trigger)
    .bind(&actions)
    .bind(Some(auth.user_id))
    .fetch_one(&mut *tx).await;
    let _ = tx.commit().await;
    match id_res {
        Ok(id) => (StatusCode::CREATED, Json(json!({"ok": true, "id": id}))).into_response(),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => (StatusCode::CONFLICT, Json(json!({"ok": false, "detail": "a playbook with this name already exists"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": scrub_internal_error(&e)}))).into_response(),
    }
}

async fn api_playbooks_update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<PlaybookBody>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let trigger = if body.trigger.is_null() { json!({}) } else { body.trigger };
    let actions = if body.actions.is_null() { json!([]) } else { body.actions };
    let res = sqlx::query(
        r#"UPDATE weissman_playbooks
              SET name = $1, description = $2, enabled = $3,
                  trigger_dsl = $4, actions_dsl = $5, updated_at = now()
            WHERE id = $6 AND tenant_id = $7"#,
    )
    .bind(body.name.trim())
    .bind(&body.description)
    .bind(body.enabled)
    .bind(&trigger)
    .bind(&actions)
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&mut *tx).await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => (StatusCode::CONFLICT, Json(json!({"ok": false, "detail": "a playbook with this name already exists"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": scrub_internal_error(&e)}))).into_response(),
    }
}

async fn api_playbooks_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query("DELETE FROM weissman_playbooks WHERE id = $1 AND tenant_id = $2")
        .bind(id).bind(auth.tenant_id)
        .execute(&mut *tx).await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": scrub_internal_error(&e)}))).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct PlaybookFireBody {
    event: crate::soar_playbook::PlaybookEvent,
    #[serde(default)]
    dry_run: bool,
}

async fn api_playbooks_fire(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: axum::http::HeaderMap,
    Json(body): Json<PlaybookFireBody>,
) -> Response {
    if !body.dry_run {
        if let Err(r) = crate::security_hardening::destructive_admin_dual_authorized(&headers, &auth) {
            return r;
        }
    } else if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let mut event = body.event;
    // Force the caller's tenant onto the event — never trust the request body
    // for tenant identity.
    event.tenant_id = auth.tenant_id;
    let results = crate::soar_playbook::dispatch_event(
        &state.app_pool,
        event,
        body.dry_run,
    ).await;
    (StatusCode::OK, Json(json!({
        "ok": true,
        "dry_run": body.dry_run,
        "results": results,
    }))).into_response()
}

async fn api_soar_execution_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query(
        r#"SELECT e.id, e.action_kind, e.status, e.target_id, e.provider, e.result_detail,
                  e.external_ref, e.blast_radius, e.evidence, e.execution_payload,
                  e.created_at, e.resolved_at,
                  r.id AS revert_id, r.status AS revert_status, r.steps AS revert_steps
           FROM soar_action_executions e
           LEFT JOIN soar_revert_runbooks r ON r.execution_id = e.id
           WHERE e.id = $1 AND e.tenant_id = $2"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match row {
        Ok(Some(r)) => {
            let execution = json!({
                "id": r.try_get::<uuid::Uuid,_>("id").ok(),
                "action_kind": r.try_get::<String,_>("action_kind").ok(),
                "status": r.try_get::<String,_>("status").ok(),
                "target_id": r.try_get::<String,_>("target_id").ok(),
                "provider": r.try_get::<String,_>("provider").ok(),
                "result_detail": r.try_get::<String,_>("result_detail").ok(),
                "external_ref": r.try_get::<Option<String>,_>("external_ref").ok().flatten(),
                "blast_radius": r.try_get::<serde_json::Value,_>("blast_radius").unwrap_or(json!({})),
                "evidence": r.try_get::<serde_json::Value,_>("evidence").unwrap_or(json!({})),
                "execution_payload": r.try_get::<serde_json::Value,_>("execution_payload").unwrap_or(json!({})),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").ok(),
                "resolved_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("resolved_at").ok().flatten(),
                "revert_runbook": {
                    "id": r.try_get::<Option<uuid::Uuid>,_>("revert_id").ok().flatten(),
                    "status": r.try_get::<Option<String>,_>("revert_status").ok().flatten(),
                    "steps": r.try_get::<serde_json::Value,_>("revert_steps").unwrap_or(json!([])),
                },
            });
            (StatusCode::OK, Json(json!({"ok": true, "execution": execution}))).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": scrub_internal_error(&e)}))).into_response(),
    }
}

async fn api_soar_execution_revert(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if let Err(r) = crate::security_hardening::destructive_admin_dual_authorized(&headers, &auth) {
        return r;
    }
    match crate::soar::revert_execution(&state.app_pool, auth.tenant_id, id).await {
        Ok(detail) => (StatusCode::OK, Json(json!({"ok": true, "detail": detail}))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "detail": e}))).into_response(),
    }
}

// ─── Financial blast-radius endpoints ──────────────────────────────────────

async fn api_financial_risk_for_client(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let recompute = q.get("recompute").map(|v| v == "1" || v == "true").unwrap_or(false);
    let snap = if recompute {
        match crate::financial_risk::compute_and_store(&state.app_pool, auth.tenant_id, client_id).await {
            Ok(s) => Some(s),
            Err(e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": scrub_internal_error(&e)})),
            ).into_response(),
        }
    } else {
        crate::financial_risk::latest_snapshot(&state.app_pool, auth.tenant_id, client_id).await.ok().flatten()
    };
    match snap {
        Some(s) => (StatusCode::OK, Json(json!({"ok": true, "snapshot": s}))).into_response(),
        None => (StatusCode::OK, Json(json!({
            "ok": true, "snapshot": null,
            "detail": "no snapshot yet — call with ?recompute=1"
        }))).into_response(),
    }
}

async fn api_apply_asset_tag_rules(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    match crate::financial_risk::apply_tag_rules(&state.app_pool, auth.tenant_id, client_id).await {
        Ok(n) => (StatusCode::OK, Json(json!({"ok": true, "updated": n}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": e}))).into_response(),
    }
}

// ─── Ask Weissman (NL → safe SQL) ──────────────────────────────────────────

#[derive(serde::Deserialize)]
struct AskBody { question: String }

async fn api_ask(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<AskBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let ro_pool = match state.read_only_pool.as_ref() {
        Some(p) => p,
        None => {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
                "ok": false,
                "detail": "/api/ask requires a read-only Postgres role. Set WEISSMAN_READ_ONLY_DATABASE_URL."
            }))).into_response();
        }
    };
    let result = crate::nl_query::ask(
        &state.app_pool,
        ro_pool.as_ref(),
        auth.tenant_id,
        Some(auth.user_id),
        &body.question,
    ).await;
    (StatusCode::OK, Json(json!({"ok": result.error.is_none(), "result": result}))).into_response()
}

// ─── UEBA ingest (called by /ws/agent when ueba_baseline finding arrives) ──

async fn api_ueba_ingest(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(p): Json<crate::ueba_detector::UebaIngestPayload>,
) -> Response {
    // The real ingest path is the in-process /ws/agent handler; agent JWTs can never reach this
    // HTTP route (verify_token_for_request requires a user access context). Any human caller here
    // is supplying an arbitrary agent_id/client_id, which forges behavioural baselines/anomalies.
    // Restrict it to admins and range-check hour_of_week so it cannot be used to poison detection.
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    if !(0..=167).contains(&p.hour_of_week) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "hour_of_week must be in 0..=167"})),
        )
            .into_response();
    }
    match crate::ueba_detector::ingest_sample(&state.app_pool, auth.tenant_id, p).await {
        Ok(s) => (StatusCode::OK, Json(json!({"ok": true, "summary": s}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": e}))).into_response(),
    }
}

async fn api_ueba_anomalies(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(50).clamp(1, 500);
    let agent = q.get("agent_id").cloned();
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, agent_id, client_id, metric_name, observed,
                  baseline_mean, baseline_stddev, z_score, severity, detail, detected_at
             FROM agent_anomalies
            WHERE ($1::text IS NULL OR agent_id = $1)
            ORDER BY detected_at DESC
            LIMIT $2"#,
    )
    .bind(agent.as_deref())
    .bind(limit)
    .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;
    let list: Vec<Value> = rows.into_iter().map(|r| json!({
        "id":            r.try_get::<i64, _>("id").unwrap_or(0),
        "agent_id":      r.try_get::<String, _>("agent_id").unwrap_or_default(),
        "client_id":     r.try_get::<i64, _>("client_id").unwrap_or(0),
        "metric_name":   r.try_get::<String, _>("metric_name").unwrap_or_default(),
        "observed":      r.try_get::<f64, _>("observed").unwrap_or(0.0),
        "baseline_mean": r.try_get::<f64, _>("baseline_mean").unwrap_or(0.0),
        "baseline_stddev": r.try_get::<f64, _>("baseline_stddev").unwrap_or(0.0),
        "z_score":       r.try_get::<f64, _>("z_score").unwrap_or(0.0),
        "severity":      r.try_get::<String, _>("severity").unwrap_or_default(),
        "detail":        r.try_get::<String, _>("detail").unwrap_or_default(),
        "detected_at":   r.try_get::<chrono::DateTime<Utc>, _>("detected_at").ok().map(|d| d.to_rfc3339()),
    })).collect();
    (StatusCode::OK, Json(json!({"ok": true, "anomalies": list}))).into_response()
}

// ─── Baseline & drift (UEBA tables → BaselineAndDrift.jsx) ───────────────────

fn baseline_range_interval(range: &str) -> &'static str {
    let r = range.trim();
    if r.eq_ignore_ascii_case("24h") {
        "24 hours"
    } else if r.eq_ignore_ascii_case("30d") {
        "30 days"
    } else {
        "7 days"
    }
}

fn baseline_range_bucket(range: &str) -> &'static str {
    if range.trim().eq_ignore_ascii_case("24h") {
        "hour"
    } else {
        "day"
    }
}

/// GET /api/baseline/summary — aggregate posture from agent_metric_baselines + recent anomalies.
async fn api_baseline_summary(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let baseline_row = sqlx::query(
        r#"SELECT COUNT(DISTINCT agent_id)::bigint AS total_assets,
                  MAX(last_updated_at) AS last_updated,
                  COALESCE(SUM(n), 0)::bigint AS sample_count,
                  COUNT(*)::bigint AS baseline_rows
             FROM agent_metric_baselines"#,
    )
    .fetch_one(&mut *tx)
    .await;

    let drift_row = sqlx::query(
        r#"SELECT COALESCE(
                  LEAST(
                      100.0,
                      COUNT(*)::double precision * 2.0
                          + COALESCE(AVG(ABS(z_score)), 0.0) * 8.0
                  ),
                  0.0
              ) AS drift_score
             FROM agent_anomalies
            WHERE detected_at >= now() - interval '7 days'"#,
    )
    .fetch_one(&mut *tx)
    .await;

    let _ = tx.commit().await;

    let (total_assets, last_updated, sample_count, baseline_rows) = match baseline_row {
        Ok(r) => (
            r.try_get::<i64, _>("total_assets").unwrap_or(0),
            r.try_get::<Option<chrono::DateTime<Utc>>, _>("last_updated")
                .ok()
                .flatten()
                .map(|d| d.to_rfc3339()),
            r.try_get::<i64, _>("sample_count").unwrap_or(0),
            r.try_get::<i64, _>("baseline_rows").unwrap_or(0),
        ),
        Err(_) => (0, None, 0, 0),
    };
    let drift_score = drift_row
        .ok()
        .and_then(|r| r.try_get::<f64, _>("drift_score").ok())
        .unwrap_or(0.0);

    (
        StatusCode::OK,
        Json(json!({
            "total_assets": total_assets,
            "drift_score": drift_score,
            "last_updated": last_updated,
            "sample_count": sample_count,
            "baseline_rows": baseline_rows,
        })),
    )
        .into_response()
}

/// GET /api/baseline/drift?range=24h|7d|30d — time-series drift from agent_anomalies.
async fn api_baseline_drift(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let range = q.get("range").map(String::as_str).unwrap_or("7d");
    let interval = baseline_range_interval(range);
    let bucket = baseline_range_bucket(range);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let sql = format!(
        r#"SELECT date_trunc('{bucket}', detected_at AT TIME ZONE 'UTC') AS bucket,
                  COUNT(*)::int AS anomaly_count,
                  COALESCE(AVG(ABS(z_score)), 0.0) AS avg_z
             FROM agent_anomalies
            WHERE detected_at >= now() - interval '{interval}'
            GROUP BY 1
            ORDER BY 1 ASC"#
    );
    let rows = sqlx::query(&sql).fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;

    let data: Vec<Value> = rows
        .into_iter()
        .filter_map(|r| {
            let bucket_ts = r
                .try_get::<chrono::DateTime<Utc>, _>("bucket")
                .ok()?;
            let anomaly_count = r.try_get::<i32, _>("anomaly_count").unwrap_or(0);
            let avg_z = r.try_get::<f64, _>("avg_z").unwrap_or(0.0);
            let drift = (anomaly_count as f64 * 2.0 + avg_z * 8.0).min(100.0);
            let time = if bucket == "hour" {
                bucket_ts.format("%H:%M").to_string()
            } else {
                bucket_ts.format("%b %d").to_string()
            };
            Some(json!({
                "time": time,
                "drift": (drift * 10.0).round() / 10.0,
                "anomalies": anomaly_count,
            }))
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({ "data": data, "range": range })),
    )
        .into_response()
}

/// GET /api/baseline/anomalies?range=24h|7d|30d — recent UEBA anomalies for the UI list.
async fn api_baseline_anomalies(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let range = q.get("range").map(String::as_str).unwrap_or("7d");
    let interval = baseline_range_interval(range);
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 500);

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let sql = format!(
        r#"SELECT id, agent_id, metric_name, observed, baseline_mean,
                  z_score, severity, detail, detected_at
             FROM agent_anomalies
            WHERE detected_at >= now() - interval '{interval}'
            ORDER BY detected_at DESC
            LIMIT $1"#
    );
    let rows = sqlx::query(&sql)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;

    let anomalies: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let z = r.try_get::<f64, _>("z_score").unwrap_or(0.0);
            json!({
                "id": r.try_get::<i64, _>("id").unwrap_or(0),
                "type": r.try_get::<String, _>("metric_name").unwrap_or_default(),
                "score": ((z.abs() * 10.0).round() / 10.0),
                "description": r.try_get::<String, _>("detail").unwrap_or_default(),
                "agent_id": r.try_get::<String, _>("agent_id").unwrap_or_default(),
                "observed": r.try_get::<f64, _>("observed").unwrap_or(0.0),
                "baseline_mean": r.try_get::<f64, _>("baseline_mean").unwrap_or(0.0),
                "severity": r.try_get::<String, _>("severity").unwrap_or_default(),
                "detected_at": r
                    .try_get::<chrono::DateTime<Utc>, _>("detected_at")
                    .ok()
                    .map(|d| d.to_rfc3339()),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({ "anomalies": anomalies, "range": range })),
    )
        .into_response()
}

async fn api_playbook_runs(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(playbook_id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(50).clamp(1, 500);
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, triggered_at, trigger_kind, trigger_event,
                  actions_total, actions_succeeded, actions_failed,
                  action_results, status, run_dedup_key
             FROM weissman_playbook_runs
            WHERE playbook_id = $1
            ORDER BY triggered_at DESC
            LIMIT $2"#,
    )
    .bind(playbook_id)
    .bind(limit)
    .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;
    let runs: Vec<Value> = rows.into_iter().map(|r| json!({
        "id":                r.try_get::<i64, _>("id").unwrap_or(0),
        "triggered_at":      r.try_get::<chrono::DateTime<Utc>, _>("triggered_at").ok().map(|d| d.to_rfc3339()),
        "trigger_kind":      r.try_get::<String, _>("trigger_kind").unwrap_or_default(),
        "trigger_event":     r.try_get::<Value, _>("trigger_event").unwrap_or(json!({})),
        "actions_total":     r.try_get::<i32, _>("actions_total").unwrap_or(0),
        "actions_succeeded": r.try_get::<i32, _>("actions_succeeded").unwrap_or(0),
        "actions_failed":    r.try_get::<i32, _>("actions_failed").unwrap_or(0),
        "action_results":    r.try_get::<Value, _>("action_results").unwrap_or(json!([])),
        "status":            r.try_get::<String, _>("status").unwrap_or_default(),
        "run_dedup_key":     r.try_get::<String, _>("run_dedup_key").unwrap_or_default(),
    })).collect();
    (StatusCode::OK, Json(json!({"ok": true, "runs": runs}))).into_response()
}
