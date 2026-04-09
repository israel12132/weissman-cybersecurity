// Phase 7: OT/ICS API, edge swarm registry, crypto capabilities, WASM deploy manifest.

#[derive(Deserialize)]
struct EdgeSwarmHeartbeatBody {
    region_code: String,
    pop_label: String,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    wasm_revision: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    active_jobs: i32,
}

async fn api_edge_swarm_nodes(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"nodes": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, region_code, pop_label, latitude, longitude, wasm_revision, provider,
                  last_heartbeat, active_jobs, metadata
           FROM edge_swarm_nodes WHERE tenant_id = $1 ORDER BY region_code, pop_label"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let mut nodes = Vec::new();
    for r in rows {
        nodes.push(json!({
            "id": r.try_get::<i64, _>("id").unwrap_or(0),
            "region_code": r.try_get::<String, _>("region_code").unwrap_or_default(),
            "pop_label": r.try_get::<String, _>("pop_label").unwrap_or_default(),
            "latitude": r.try_get::<Option<f64>, _>("latitude").ok().flatten(),
            "longitude": r.try_get::<Option<f64>, _>("longitude").ok().flatten(),
            "wasm_revision": r.try_get::<String, _>("wasm_revision").unwrap_or_default(),
            "provider": r.try_get::<String, _>("provider").unwrap_or_default(),
            "last_heartbeat": r.try_get::<Option<chrono::DateTime<Utc>>, _>("last_heartbeat").ok().flatten(),
            "active_jobs": r.try_get::<i32, _>("active_jobs").unwrap_or(0),
            "metadata": r.try_get::<Option<Value>, _>("metadata").ok().flatten().unwrap_or(json!({})),
        }));
    }
    (StatusCode::OK, Json(json!({ "nodes": nodes }))).into_response()
}

async fn api_edge_swarm_heartbeat(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: axum::extract::Json<EdgeSwarmHeartbeatBody>,
) -> Response {
    let region = body.region_code.trim();
    let pop = body.pop_label.trim();
    if region.is_empty() || pop.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "region_code and pop_label required"})),
        )
            .into_response();
    }
    state.edge_heartbeat_batcher.enqueue(crate::edge_heartbeat_batch::PendingHeartbeat {
        tenant_id: auth.tenant_id,
        region_code: body.region_code.clone(),
        pop_label: body.pop_label.clone(),
        latitude: body.latitude,
        longitude: body.longitude,
        wasm_revision: body.wasm_revision.clone(),
        provider: body.provider.clone(),
        active_jobs: body.active_jobs,
    });
    (
        StatusCode::OK,
        Json(json!({"ok": true, "batched": true, "flush_window_secs": 30})),
    )
        .into_response()
}

async fn api_edge_fuzz_manifest() -> Response {
    (
        StatusCode::OK,
        Json(crate::edge_fuzz_bridge::edge_worker_deploy_manifest()),
    )
        .into_response()
}

async fn api_crypto_capabilities() -> Response {
    let pq_ok = crate::pqc_kem::ml_kem768_selftest()
        .ok()
        .map(|r| r.round_trip_ok);
    let cap = crate::crypto_policy::crypto_capabilities_json(pq_ok);
    (StatusCode::OK, Json(cap)).into_response()
}

async fn api_crypto_pqc_selftest() -> Response {
    (StatusCode::OK, Json(crate::pqc_kem::selftest_json())).into_response()
}

async fn api_client_ot_ics_fingerprints(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"fingerprints": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, host, port, protocol, vendor_hint, confidence, raw_excerpt_hex, metadata, created_at
           FROM ot_ics_fingerprints WHERE tenant_id = $1 AND client_id = $2 ORDER BY id"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let mut fingerprints = Vec::new();
    for r in rows {
        fingerprints.push(json!({
            "id": r.try_get::<i64, _>("id").unwrap_or(0),
            "host": r.try_get::<String, _>("host").unwrap_or_default(),
            "port": r.try_get::<i32, _>("port").unwrap_or(0),
            "protocol": r.try_get::<String, _>("protocol").unwrap_or_default(),
            "vendor_hint": r.try_get::<String, _>("vendor_hint").unwrap_or_default(),
            "confidence": r.try_get::<f32, _>("confidence").unwrap_or(0.0),
            "raw_excerpt_hex": r.try_get::<String, _>("raw_excerpt_hex").unwrap_or_default(),
            "metadata": r.try_get::<Option<Value>, _>("metadata").ok().flatten().unwrap_or(json!({})),
            "created_at": r.try_get::<Option<chrono::DateTime<Utc>>, _>("created_at").ok().flatten(),
        }));
    }
    (StatusCode::OK, Json(json!({ "fingerprints": fingerprints }))).into_response()
}
