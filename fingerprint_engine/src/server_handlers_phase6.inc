// Phase 6: CI/CD webhooks (no JWT), LLM fuzz APIs, sealed PoC decrypt + audit.

async fn hook_cicd_github(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    crate::cicd_interceptor::github_push_hook(Some(state.app_pool.clone()), headers, body).await
}

async fn hook_cicd_gitlab(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    crate::cicd_interceptor::gitlab_push_hook(Some(state.app_pool.clone()), headers, body).await
}

async fn hook_cicd_bitbucket(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    crate::cicd_interceptor::bitbucket_push_hook(Some(state.app_pool.clone()), headers, body).await
}

async fn hook_cicd_generic(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    crate::cicd_interceptor::generic_cicd_scan(Some(state.app_pool.clone()), headers, body).await
}

async fn api_llm_fuzz_run(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(client_id)
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(false);
    let _ = tx.commit().await;
    if !exists {
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "client not found"}))).into_response();
    }
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "llm_fuzz_run",
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
                "message": "LLM fuzz queued; poll GET /api/jobs/:job_id for summary",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue llm_fuzz_run failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_llm_fuzz_events(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"events": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, endpoint_url, attack_vector, request_preview, response_excerpt, leakage_score, hallucination_score, blocked, created_at
           FROM llm_fuzz_events WHERE client_id = $1 ORDER BY id DESC LIMIT 300"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let events: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "endpoint_url": r.try_get::<String,_>("endpoint_url").unwrap_or_default(),
                "attack_vector": r.try_get::<String,_>("attack_vector").unwrap_or_default(),
                "request_preview": r.try_get::<String,_>("request_preview").unwrap_or_default(),
                "response_excerpt": r.try_get::<String,_>("response_excerpt").unwrap_or_default(),
                "leakage_score": r.try_get::<f64,_>("leakage_score").unwrap_or(0.0),
                "hallucination_score": r.try_get::<f64,_>("hallucination_score").unwrap_or(0.0),
                "blocked": r.try_get::<bool,_>("blocked").unwrap_or(false),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "events": events }))).into_response()
}

async fn api_llm_fuzz_summary(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"vectors": []}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT attack_vector,
                  COALESCE(AVG(leakage_score), 0)::double precision AS avg_leakage,
                  COALESCE(AVG(hallucination_score), 0)::double precision AS avg_hallucination,
                  COUNT(*)::bigint AS n
           FROM llm_fuzz_events WHERE client_id = $1
           GROUP BY attack_vector ORDER BY attack_vector"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let vectors: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "attack_vector": r.try_get::<String,_>("attack_vector").unwrap_or_default(),
                "avg_leakage": r.try_get::<f64,_>("avg_leakage").unwrap_or(0.0),
                "avg_hallucination_under_duress": r.try_get::<f64,_>("avg_hallucination").unwrap_or(0.0),
                "sample_count": r.try_get::<i64,_>("n").unwrap_or(0),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "vectors": vectors }))).into_response()
}

async fn api_decrypt_sealed_poc(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((client_id, vuln_id)): Path<(i64, i64)>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = extract_client_ip(&headers, peer);
    let Some(key) = crate::exploit_crypto::master_key_bytes() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "WEISSMAN_EXPLOIT_MASTER_KEY not configured"})),
        )
            .into_response();
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query(
        r#"SELECT finding_id, poc_sealed, poc_ciphertext_b64, poc_nonce_b64, poc_commitment_sha256, poc_zkp_hmac
           FROM vulnerabilities WHERE id = $1 AND client_id = $2 AND tenant_id = $3"#,
    )
    .bind(vuln_id)
    .bind(client_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "finding not found"}))).into_response();
    };
    let finding_id: String = r.try_get("finding_id").unwrap_or_default();
    let sealed: bool = r.try_get("poc_sealed").unwrap_or(false);
    if !sealed {
        let _ = tx.rollback().await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "finding is not sealed"})),
        )
            .into_response();
    }
    let seal = crate::exploit_crypto::PocSeal {
        ciphertext_b64: r.try_get::<String, _>("poc_ciphertext_b64").unwrap_or_default(),
        nonce_b64: r.try_get::<String, _>("poc_nonce_b64").unwrap_or_default(),
        commitment_sha256_hex: r.try_get::<String, _>("poc_commitment_sha256").unwrap_or_default(),
        zkp_hmac_hex: r.try_get::<String, _>("poc_zkp_hmac").unwrap_or_default(),
    };
    let plain = match crate::exploit_crypto::open_poc(&seal, &key, &finding_id) {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": e})),
            )
                .into_response();
        }
    };
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    if audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "sealed_poc_decrypt",
        &format!("vulnerability_id={} finding_id={} client_id={}", vuln_id, finding_id, client_id),
        &ip,
    )
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "audit log failed"})),
        )
            .into_response();
    }
    let _ = tx.commit().await;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "poc_exploit": plain,
            "finding_id": finding_id,
            "commitment_sha256": seal.commitment_sha256_hex,
        })),
    )
        .into_response()
}
