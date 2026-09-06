// CEM-DAGO Command Center API — live blackboard + manifests (no fabricated findings).

async fn api_cem_dago_status() -> Response {
    (StatusCode::OK, Json(crate::cem_dago::status_json())).into_response()
}

async fn api_cem_dago_manifests(
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or_else(|| weissman_core::models::engine::PRODUCTION_ENGINE_IDS.len());
    (StatusCode::OK, Json(crate::cem_dago::manifests_json(limit))).into_response()
}

async fn api_cem_dago_waves(
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let engines: Vec<String> = q
        .get("engines")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_else(|| {
            weissman_core::models::engine::DEFAULT_ORCHESTRATOR_ENGINES
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        });
    let mut present = std::collections::HashSet::new();
    present.insert("internet_exposed".to_string());
    if let Some(extra) = q.get("signals") {
        for s in extra.split(',') {
            let t = s.trim();
            if !t.is_empty() {
                present.insert(t.to_string());
            }
        }
    }
    let waves = crate::cem_dago::schedule_waves(&engines, &present);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "engines": engines,
            "present_signals": present.into_iter().collect::<Vec<_>>(),
            "waves": waves,
        })),
    )
        .into_response()
}

async fn api_cem_dago_blackboard(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(client_id) = q.get("client_id").and_then(|s| s.parse::<i64>().ok()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": "client_id required" })),
        )
            .into_response();
    };

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ok": false, "detail": "database unavailable" })),
        )
            .into_response();
    };
    let owned: Option<i64> = sqlx::query_scalar("SELECT id FROM clients WHERE id = $1")
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let _ = tx.rollback().await;
    if owned.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": "client not found" })),
        )
            .into_response();
    }

    let scan_id = q.get("scan_id").cloned();
    let bb = if let Some(sid) = scan_id {
        match crate::cem_dago::blackboard::open_scan(auth.tenant_id, client_id, &sid).await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "ok": false, "detail": scrub_internal_error(&e) })),
                )
                    .into_response();
            }
        }
    } else {
        match crate::cem_dago::blackboard::open_latest(auth.tenant_id, client_id).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "ok": true,
                        "scan_id": Value::Null,
                        "redis_backed": crate::http::rate_limit_redis::is_enabled(),
                        "evidence": {},
                        "failures": [],
                        "detail": "no CEM-DAGO scan recorded for this client yet"
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "ok": false, "detail": scrub_internal_error(&e) })),
                )
                    .into_response();
            }
        }
    };

    let dump = bb.dump_all().await.unwrap_or_default();
    let failures = bb.list_failures().await.unwrap_or_default();
    let flushed = bb.persist_and_take_quarantine(&state.app_pool).await;
    let quarantine = if flushed.is_empty() {
        crate::cem_dago::telemetry_quarantine::load_quarantine_for_scan(
            &state.app_pool,
            auth.tenant_id,
            client_id,
            bb.scan_id(),
        )
        .await
    } else {
        flushed
    };
    let mut evidence = serde_json::Map::new();
    for (k, ev) in dump {
        evidence.insert(
            k,
            json!({
                "source_engine": ev.source_engine,
                "timestamp": ev.timestamp,
                "value": ev.value,
            }),
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "tenant_id": bb.tenant_id(),
            "client_id": bb.client_id(),
            "scan_id": bb.scan_id(),
            "redis_backed": bb.redis_backed(),
            "evidence": evidence,
            "failures": failures,
            "evidence_count": evidence.len(),
            "quarantine": quarantine,
            "telemetry_integrity_violations": quarantine.len(),
        })),
    )
        .into_response()
}
