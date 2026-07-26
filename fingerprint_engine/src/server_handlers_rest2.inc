async fn api_client_findings_all(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let cid = id;
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "findings": [] }))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, finding_id, title, severity, source, COALESCE(description,''), COALESCE(poc_exploit,''),
                  COALESCE(poc_sealed, false), COALESCE(poc_commitment_sha256,''),
                  COALESCE(raw_data, '{}'::jsonb) AS raw_data
             FROM vulnerabilities WHERE client_id = $1 ORDER BY discovered_at DESC"#,
    )
    .bind(cid)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let findings: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let row_id = r.try_get::<i64, _>("id").unwrap_or(0);
            let raw_data: Value = r
                .try_get::<Value, _>("raw_data")
                .unwrap_or_else(|_| json!({}));
            let target = raw_data
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let live_verification = raw_data.get("live_verification").cloned().unwrap_or(Value::Null);
            let live_verdict = raw_data
                .get("live_verification")
                .and_then(|v| v.get("verdict"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            json!({
                "id": row_id,
                "raw_id": row_id,
                "finding_id": r.try_get::<String,_>("finding_id").unwrap_or_default(),
                "title": r.try_get::<String,_>("title").unwrap_or_default(),
                "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "description": r.try_get::<String,_>("description").unwrap_or_default(),
                "poc_exploit": r.try_get::<String,_>("poc_exploit").unwrap_or_default(),
                "poc_sealed": r.try_get::<bool,_>("poc_sealed").unwrap_or(false),
                "poc_commitment_sha256": r.try_get::<String,_>("poc_commitment_sha256").unwrap_or_default(),
                "target": target,
                "live_verification": live_verification,
                "live_verdict": live_verdict,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "findings": findings }))).into_response()
}

async fn api_client_export_csv(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB unavailable"}))).into_response();
    };
    let rows = sqlx::query(
        "SELECT id, title, severity, source, status, discovered_at FROM vulnerabilities WHERE client_id = $1 ORDER BY discovered_at DESC",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let mut csv = String::from("ID,Title,Severity,Source,Status,Discovered\n");
    for r in rows {
        let idv = r.try_get::<i64, _>("id").unwrap_or(0);
        let title = r.try_get::<String, _>("title").unwrap_or_default().replace('"', "\"\"");
        let sev = r.try_get::<String, _>("severity").unwrap_or_default().replace('"', "\"\"");
        let src = r.try_get::<String, _>("source").unwrap_or_default().replace('"', "\"\"");
        let st = r.try_get::<String, _>("status").unwrap_or_default().replace('"', "\"\"");
        let disc = r
            .try_get::<chrono::DateTime<Utc>, _>("discovered_at")
            .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default()
            .replace('"', "\"\"");
        csv.push_str(&format!("VLN-{},{},{},{},{},{}\n", idv, title, sev, src, st, disc));
    }
    let filename = format!("Weissman_findings_client_{}.csv", id);
    let mut res = Response::new(Body::from(csv));
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
    res.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::try_from(format!("attachment; filename=\"{}\"", filename)).unwrap_or(HeaderValue::from_static("attachment")),
    );
    res
}

async fn get_crypto_proof_for_client_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    client_id: i64,
) -> Result<Option<crate::pdf_report::CryptoProof>, String> {
    let enabled: String = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'enable_rfc3161_signing'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "true".to_string());
    if enabled.to_lowercase() != "true" && enabled != "1" {
        return Ok(None);
    }
    let audit_root_hash: Option<String> = sqlx::query_scalar(
        "SELECT r.audit_root_hash FROM report_runs r INNER JOIN vulnerabilities v ON v.run_id = r.id WHERE v.client_id = $1 AND r.audit_root_hash IS NOT NULL AND trim(r.audit_root_hash) <> '' ORDER BY r.id DESC LIMIT 1",
    )
    .bind(client_id)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten();
    let hash = match audit_root_hash {
        Some(h) => h,
        None => return Ok(None),
    };
    let base_url = std::env::var("WEISSMAN_BASE_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());
    let qr_data_url = crate::crypto_engine::qr_code_for_audit(&base_url, &hash)?;
    let verification_url = crate::crypto_engine::verification_url_for_hash(&base_url, &hash);
    Ok(Some((hash, qr_data_url, verification_url)))
}

async fn api_client_report_pdf(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB unavailable"}))).into_response();
    };
    let client_name: String = match sqlx::query_scalar::<_, String>("SELECT name FROM clients WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
    {
        Some(n) => n,
        None => {
            let _ = tx.rollback().await;
            return (StatusCode::NOT_FOUND, Json(json!({"error": "client not found"}))).into_response();
        }
    };
    let rows = sqlx::query(
        "SELECT id, title, severity, source, COALESCE(description,''), COALESCE(poc_exploit,'') FROM vulnerabilities WHERE client_id = $1 ORDER BY discovered_at DESC",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let proof = match get_crypto_proof_for_client_tx(&mut tx, auth.tenant_id, id).await {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.rollback().await;
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
        }
    };
    let _ = tx.commit().await;
    let findings: Vec<(i64, String, String, String, String, String)> = rows
        .into_iter()
        .map(|r| {
            (
                r.try_get::<i64, _>("id").unwrap_or(0),
                r.try_get::<String, _>("title").unwrap_or_default(),
                r.try_get::<String, _>("severity").unwrap_or_default(),
                r.try_get::<String, _>("source").unwrap_or_default(),
                r.try_get::<String, _>("description").unwrap_or_default(),
                r.try_get::<String, _>("poc_exploit").unwrap_or_default(),
            )
        })
        .collect();
    let pdf_bytes: Vec<u8> = match crate::pdf_report::build_client_report_pdf(&client_name, &findings, proof.as_ref()) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "PDF generation failed", "detail": scrub_internal_error(&e)})),
            )
                .into_response();
        }
    };
    let safe_name = client_name.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect::<String>();
    let filename = format!("Weissman_Report_{}.pdf", safe_name);
    let mut res = Response::new(Body::from(pdf_bytes));
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

async fn api_client_report_crypto_proof(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB unavailable"}))).into_response();
    };
    match get_crypto_proof_for_client_tx(&mut tx, auth.tenant_id, id).await {
        Ok(Some((audit_root_hash, qr_data_url, verification_url))) => {
            let _ = tx.commit().await;
            (
                StatusCode::OK,
                Json(json!({
                    "audit_root_hash": audit_root_hash,
                    "qr_data_url": qr_data_url,
                    "verification_url": verification_url,
                })),
            )
                .into_response()
        }
        Ok(None) => {
            let _ = tx.commit().await;
            (
                StatusCode::OK,
                Json(json!({
                    "audit_root_hash": null,
                    "qr_data_url": null,
                    "verification_url": null,
                    "message": "No sealed run for this client yet."
                })),
            )
                .into_response()
        }
        Err(e) => {
            let _ = tx.rollback().await;
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response()
        }
    }
}

async fn api_verify_audit(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(hash): Path<String>,
) -> Response {
    let hash = hash.trim();
    if hash.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"verified": false, "error": "hash required"}))).into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"verified": false, "error": "DB"}))).into_response();
    };
    let row = sqlx::query("SELECT id, created_at, summary FROM report_runs WHERE audit_root_hash = $1 LIMIT 1")
        .bind(hash)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let _ = tx.commit().await;
    match row {
        Some(r) => {
            let run_id: i64 = r.try_get("id").unwrap_or(0);
            let created_at = r
                .try_get::<chrono::DateTime<Utc>, _>("created_at")
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            let summary: String = r.try_get("summary").unwrap_or_else(|_| "{}".to_string());
            (
                StatusCode::OK,
                Json(json!({
                    "verified": true,
                    "run_id": run_id,
                    "audit_root_hash": hash,
                    "created_at": created_at,
                    "summary": serde_json::from_str::<Value>(&summary).unwrap_or(json!({})),
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"verified": false, "error": "Hash not found"})),
        )
            .into_response(),
    }
}

/// Allowed status values for finding workflow.
const FINDING_STATUSES: &[&str] = &[
    "OPEN",
    "ACKNOWLEDGED",
    "IN_PROGRESS",
    "FIXED",
    "FALSE_POSITIVE",
];

#[derive(Deserialize)]
struct FindingStatusBody {
    status: String,
}

/// PATCH /api/findings/:id/status — update finding workflow status.
async fn api_findings_update_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<FindingStatusBody>,
) -> Response {
    let new_status = body.status.trim().to_uppercase();
    if !FINDING_STATUSES.contains(&new_status.as_str()) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "ok": false,
                "detail": format!("Invalid status '{}'. Allowed: {}", new_status, FINDING_STATUSES.join(", "))
            })),
        ).into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false, "detail": "DB unavailable"}))).into_response();
    };

    // Capture engine + signature_hash BEFORE the update so the FP/TP feedback loop
    // can record the right (tenant, engine, signature) tuple. We also need them to
    // cascade the status change down into the finding cluster (if any).
    let pre = sqlx::query(
        "SELECT source, signature_hash, cluster_id, raw_data->>'target' AS target, finding_id, client_id
           FROM vulnerabilities
          WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let (engine, sig_hash, cluster_id, target_url, finding_id, client_id) = match pre {
        Some(r) => (
            r.try_get::<String, _>("source").unwrap_or_default(),
            r.try_get::<Option<String>, _>("signature_hash").ok().flatten().unwrap_or_default(),
            r.try_get::<Option<i64>, _>("cluster_id").ok().flatten(),
            r.try_get::<Option<String>, _>("target").ok().flatten().unwrap_or_default(),
            r.try_get::<String, _>("finding_id").unwrap_or_default(),
            r.try_get::<Option<i64>, _>("client_id").ok().flatten(),
        ),
        None => {
            let _ = tx.rollback().await;
            return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "Finding not found"}))).into_response();
        }
    };

    // Explicitly scope update to current tenant to defend against any RLS gap.
    let affected = sqlx::query(
        "UPDATE vulnerabilities SET status = $1, updated_at = now(), status_changed_at = now() \
         WHERE id = $2 AND tenant_id = $3",
    )
    .bind(&new_status)
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await;

    // ── False-positive / true-positive feedback ────────────────────────────
    // FALSE_POSITIVE = engine got it wrong → record FP, possibly auto-suppress.
    // FIXED / ACKNOWLEDGED / IN_PROGRESS = analyst validated → record TP.
    let mut suppression_added = false;
    if matches!(affected, Ok(ref r) if r.rows_affected() > 0) {
        match new_status.as_str() {
            "FALSE_POSITIVE" => {
                match crate::fp_feedback::record_fp(
                    &mut tx,
                    auth.tenant_id,
                    &engine,
                    &sig_hash,
                    if target_url.is_empty() { None } else { Some(target_url.as_str()) },
                    Some(auth.user_id),
                ).await {
                    Ok(added) => suppression_added = added,
                    Err(e) => tracing::warn!(target: "fp_feedback", error = %e, "record_fp failed"),
                }
            }
            "FIXED" | "ACKNOWLEDGED" | "IN_PROGRESS" => {
                if let Err(e) = crate::fp_feedback::record_tp(
                    &mut tx, auth.tenant_id, &engine, &sig_hash,
                ).await {
                    tracing::warn!(target: "fp_feedback", error = %e, "record_tp failed");
                }
            }
            _ => {}
        }

        // The FP/TP vote above only writes engine_confidence_adjustments. The
        // findings read prefers each row's persisted confidence_multiplier /
        // effective_risk snapshot, so without invalidation the analyst's verdict
        // would never surface in the API (the snapshot is written at persist time
        // and is not refreshed on feedback). NULL the cached snapshot for this
        // (tenant, engine, signature_hash) — the multiplier's own key — so the next
        // read recomputes both the multiplier and the derived risk live from the
        // updated votes. Every finding sharing this signature is invalidated, which
        // is correct: they all resolve to the one shared multiplier.
        if matches!(
            new_status.as_str(),
            "FALSE_POSITIVE" | "FIXED" | "ACKNOWLEDGED" | "IN_PROGRESS"
        ) && !engine.is_empty()
            && !sig_hash.is_empty()
        {
            let _ = sqlx::query(
                "UPDATE vulnerabilities SET confidence_multiplier = NULL, effective_risk = NULL \
                 WHERE tenant_id = $1 AND source = $2 AND signature_hash = $3",
            )
            .bind(auth.tenant_id)
            .bind(&engine)
            .bind(&sig_hash)
            .execute(&mut *tx)
            .await;
        }

        // Propagate status to all siblings in the cluster — single click, one
        // status across every engine's view of the same vulnerability.
        if let Some(cid) = cluster_id {
            if let Err(e) = crate::findings_correlator::cascade_cluster_status(
                &mut tx, auth.tenant_id, cid, &new_status,
            ).await {
                tracing::warn!(target: "findings_correlator", error = %e, "cluster cascade failed");
            }
            let _ = sqlx::query(
                "UPDATE weissman_finding_clusters
                    SET status = $1, updated_at = now()
                  WHERE id = $2 AND tenant_id = $3",
            )
            .bind(&new_status)
            .bind(cid)
            .bind(auth.tenant_id)
            .execute(&mut *tx)
            .await;
        }
    }

    let _ = tx.commit().await;

    // Closed-loop remediation verification: when an analyst marks a finding FIXED,
    // re-run the same engine against the same target to prove the vector is actually
    // closed (→ VERIFIED_FIXED) or detect a regression (→ REOPENED).
    if new_status == "FIXED"
        && !target_url.is_empty()
        && weissman_core::models::engine::is_production_engine_id(&engine)
    {
        let body = json!({
            "engine": engine.clone(),
            "target": target_url,
            "finding_id": finding_id,
            "client_id": client_id,
        });
        if let Err(e) = weissman_db::job_queue::enqueue(
            state.app_pool.as_ref(),
            auth.tenant_id,
            "remediation_verify",
            body,
            None,
        )
        .await
        {
            tracing::warn!(target: "remediation_verify", error = %e, "enqueue verify job failed");
        }
    }

    match affected {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, Json(json!({
                "ok": true,
                "id": id,
                "status": new_status,
                "suppression_added": suppression_added,
                "engine": engine,
                "cluster_id": cluster_id,
            }))).into_response()
        }
        Ok(_) => {
            (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "Finding not found"}))).into_response()
        }
        Err(e) => {
            tracing::error!(target: "findings", error = %e, "Failed to update finding status");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": "DB error"}))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct FindingLiveVerifyBody {
    deep: Option<bool>,
}

/// POST /api/findings/:id/verify — multi-tier live validity check (attestation, scope, evidence, HTTP replay, optional re-scan).
async fn api_findings_verify_live(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Json(body): Json<FindingLiveVerifyBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let deep = body.deep.unwrap_or(false);
    match crate::finding_live_verify::verify_finding_live(
        state.app_pool.as_ref(),
        auth.tenant_id,
        id,
        deep,
    )
    .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "id": id,
                "verdict": result.verdict,
                "confidence": result.confidence,
                "reproducible": result.reproducible,
                "checks": result.checks,
                "verified_at": result.verified_at,
                "recommended_status": result.recommended_status,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

/// GET /api/findings/export/csv — export all findings for the current tenant as CSV.
async fn api_findings_export_csv(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB unavailable"}))).into_response();
    };
    let rows = sqlx::query(
        "SELECT id, finding_id, title, severity, source, status, client_id::text, \
         COALESCE(description,'') AS description, discovered_at, \
         COALESCE(poc_sealed, false) AS poc_sealed \
         FROM vulnerabilities ORDER BY discovered_at DESC",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let mut csv = String::from("ID,Finding ID,Title,Severity,Source,Status,Client,Verified,Discovered,Description\n");
    for r in rows {
        let raw_id = r.try_get::<i64, _>("id").unwrap_or(0);
        let finding_id = r.try_get::<String, _>("finding_id").unwrap_or_default().replace('"', "\"\"");
        let title = r.try_get::<String, _>("title").unwrap_or_default().replace('"', "\"\"");
        let sev = r.try_get::<String, _>("severity").unwrap_or_default().replace('"', "\"\"");
        let src = r.try_get::<String, _>("source").unwrap_or_default().replace('"', "\"\"");
        let st = r.try_get::<String, _>("status").unwrap_or_default().replace('"', "\"\"");
        let client = r.try_get::<String, _>("client_id").unwrap_or_default().replace('"', "\"\"");
        let verified = if r.try_get::<bool, _>("poc_sealed").unwrap_or(false) { "VERIFIED" } else { "POTENTIAL" };
        let disc = r
            .try_get::<chrono::DateTime<Utc>, _>("discovered_at")
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_default()
            .replace('"', "\"\"");
        let desc = r.try_get::<String, _>("description").unwrap_or_default().replace('"', "\"\"");
        // All fields quoted to handle commas and special characters safely
        csv.push_str(&format!(
            "\"VLN-{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            raw_id, finding_id, title, sev, src, st, client, verified, disc, desc
        ));
    }
    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let filename = format!("Weissman_findings_{}.csv", now);
    let mut res = Response::new(Body::from(csv));
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
    res.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::try_from(format!("attachment; filename=\"{}\"", filename))
            .unwrap_or(HeaderValue::from_static("attachment; filename=\"Weissman_findings.csv\"")),
    );
    res
}

/// GET /api/openapi.json — OpenAPI 3.1 spec documenting the public Weissman API.
async fn api_openapi_spec() -> Response {
    let spec = serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Weissman Cybersecurity API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Offensive Intelligence Platform — Attack Surface Management, Dark Web Intel, Exploit Validation, and Executive Reporting.",
            "contact": {
                "name": "Weissman Security",
                "url": "https://weissman.security"
            }
        },
        "servers": [
            { "url": "/api", "description": "API server" }
        ],
        "security": [
            { "BearerAuth": [] },
            { "CookieAuth": [] }
        ],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "JWT issued by POST /api/login. Pass as Authorization: Bearer <token>."
                },
                "CookieAuth": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "weissman_token"
                }
            },
            "schemas": {
                "Finding": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string", "example": "VLN-42" },
                        "raw_id": { "type": "integer", "example": 42 },
                        "finding_id": { "type": "string", "example": "CVE-2024-12345" },
                        "title": { "type": "string" },
                        "severity": { "type": "string", "enum": ["critical","high","medium","low","info"] },
                        "source": { "type": "string", "example": "nvd" },
                        "status": { "type": "string", "enum": ["OPEN","ACKNOWLEDGED","IN_PROGRESS","FIXED","FALSE_POSITIVE"] },
                        "verified": { "type": "boolean", "description": "True when PoC has been validated" },
                        "poc_sealed": { "type": "boolean" },
                        "description": { "type": "string" },
                        "discovered_at": { "type": "string", "format": "date-time" },
                        "client_id": { "type": "string" },
                        "risk_score": { "type": "number" }
                    }
                },
                "StatusUpdate": {
                    "type": "object",
                    "required": ["status"],
                    "properties": {
                        "status": { "type": "string", "enum": ["OPEN","ACKNOWLEDGED","IN_PROGRESS","FIXED","FALSE_POSITIVE"] }
                    }
                }
            }
        },
        "paths": {
            "/api/login": {
                "post": {
                    "summary": "Authenticate and obtain JWT",
                    "tags": ["Auth"],
                    "security": [],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email","password"],
                                    "properties": {
                                        "email": { "type": "string", "format": "email" },
                                        "password": { "type": "string" },
                                        "tenant_slug": { "type": "string", "default": "default" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Login successful; JWT in response body and HttpOnly cookie." },
                        "401": { "description": "Invalid credentials" },
                        "429": { "description": "Rate limited (5 req/min per IP)" }
                    }
                }
            },
            "/api/findings": {
                "get": {
                    "summary": "List all findings for the current tenant",
                    "tags": ["Findings"],
                    "parameters": [
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "default": 500 } }
                    ],
                    "responses": {
                        "200": {
                            "description": "Array of findings",
                            "content": {
                                "application/json": {
                                    "schema": { "type": "array", "items": { "$ref": "#/components/schemas/Finding" } }
                                }
                            }
                        }
                    }
                }
            },
            "/api/findings/export/csv": {
                "get": {
                    "summary": "Export all findings as CSV",
                    "tags": ["Findings"],
                    "responses": {
                        "200": {
                            "description": "CSV file download",
                            "content": { "text/csv": {} }
                        }
                    }
                }
            },
            "/api/findings/{id}/status": {
                "patch": {
                    "summary": "Update finding workflow status",
                    "tags": ["Findings"],
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/StatusUpdate" }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Status updated" },
                        "404": { "description": "Finding not found" },
                        "422": { "description": "Invalid status value" }
                    }
                }
            },
            "/api/clients": {
                "get": {
                    "summary": "List all clients for the current tenant",
                    "tags": ["Clients"],
                    "responses": {
                        "200": { "description": "Array of clients" }
                    }
                },
                "post": {
                    "summary": "Create a new client",
                    "tags": ["Clients"],
                    "responses": {
                        "200": { "description": "Client created" }
                    }
                }
            },
            "/api/clients/{id}/findings": {
                "get": {
                    "summary": "Get all findings for a specific client",
                    "tags": ["Clients","Findings"],
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }
                    ],
                    "responses": {
                        "200": { "description": "Findings for the client" }
                    }
                }
            },
            "/api/clients/{id}/export/csv": {
                "get": {
                    "summary": "Export findings for a specific client as CSV",
                    "tags": ["Clients","Findings"],
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }
                    ],
                    "responses": {
                        "200": { "description": "CSV file download", "content": { "text/csv": {} } }
                    }
                }
            },
            "/api/clients/{id}/report/pdf": {
                "get": {
                    "summary": "Generate Executive PDF report for a client",
                    "description": "Returns a signed PDF with severity heatmap, CVSS scoring, APT attribution, benchmarking, and SHA-256 audit trail.",
                    "tags": ["Clients","Reports"],
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }
                    ],
                    "responses": {
                        "200": { "description": "PDF file", "content": { "application/pdf": {} } }
                    }
                }
            },
            "/api/command-center/scan": {
                "post": {
                    "summary": "Trigger a full platform scan",
                    "tags": ["Scan"],
                    "responses": {
                        "200": { "description": "Scan started" }
                    }
                }
            },
            "/api/config/public": {
                "get": {
                    "summary": "Get public server configuration (region, version)",
                    "tags": ["System"],
                    "responses": {
                        "200": { "description": "Config info" }
                    }
                }
            },
            "/api/health": {
                "get": {
                    "summary": "Health check (uptime, scan state, active engines, RSS)",
                    "tags": ["System"],
                    "security": [],
                    "responses": { "200": { "description": "Server is healthy" } }
                }
            },

            "/api/dashboard/exec-kpis": {
                "get": {
                    "summary": "Executive KPI roll-up for the cockpit hero strip",
                    "description": "One-shot aggregate: severity counts (+24h deltas), open vs resolved, asset / agent / job totals, scan velocity, MTTR, 24-hour trend buckets, top engines / clients / CVEs / MITRE techniques, plus a weighted security score 0–100. The cockpit refreshes every 15 s.",
                    "tags": ["Dashboard"],
                    "responses": { "200": { "description": "Aggregated KPIs" } }
                }
            },

            "/api/findings/clusters": {
                "get": {
                    "summary": "Collapsed findings — one row per (target, signature, cwe) cluster",
                    "description": "Sorted by KEV→EPSS→severity. Supports `severity`, `status=OPEN`, `kev=true` filters; default `limit=100`, max 1000. Each cluster aggregates `engines[]`, `sources[]`, `cves[]`, `max_severity`, `max_cvss`, `max_epss`, `kev_listed`.",
                    "tags": ["Findings"],
                    "parameters": [
                        { "name": "limit",    "in": "query", "schema": { "type": "integer", "default": 100, "maximum": 1000 } },
                        { "name": "offset",   "in": "query", "schema": { "type": "integer", "default": 0 } },
                        { "name": "severity", "in": "query", "schema": { "type": "string", "enum": ["critical","high","medium","low","info"] } },
                        { "name": "status",   "in": "query", "schema": { "type": "string", "enum": ["OPEN"] } },
                        { "name": "kev",      "in": "query", "schema": { "type": "boolean" } }
                    ],
                    "responses": { "200": { "description": "Cluster list" } }
                }
            },

            "/api/intel/status": {
                "get": {
                    "summary": "Threat-intel mirror status (KEV + EPSS row counts + last refresh)",
                    "tags": ["Intel"],
                    "responses": { "200": { "description": "Mirror health" } }
                }
            },
            "/api/intel/target-profile": {
                "get": {
                    "summary": "Deterministic target classification + taxonomy-backed engine selection",
                    "description": "Classifies a target string (URL / host / IP / host:port) into what it is (asset class, facets), where it lives (registrable domain, public suffix, hosting/network class, IDN/homograph), and why it matters (sensitivity, confidence, evidence), then returns the ranked, explainable engine set the platform would prioritise for it. Pure string+catalog classification — no network traffic, no tenant data.",
                    "tags": ["Intel"],
                    "parameters": [
                        { "name": "target", "in": "query", "required": true, "schema": { "type": "string" }, "description": "URL, hostname, IP, or host:port to profile" },
                        { "name": "enrich", "in": "query", "required": false, "schema": { "type": "boolean" }, "description": "Opt-in: perform one bounded A/AAAA lookup to network-verify the seed (resolved IPs, private-space detection, CDN/hosting attribution). Off by default." }
                    ],
                    "responses": {
                        "200": { "description": "{ target, resolved, profile, selection } — profile carries asset_class/sensitivity/confidence/provenance/facets; selection carries focus[] + ranked[] with per-engine score/group/reason. `resolved` is true when active DNS enrichment succeeded" },
                        "400": { "description": "target query parameter required" }
                    }
                }
            },
            "/api/stealth/status": {
                "get": {
                    "summary": "Smart Stealth Queue live telemetry (caps + real-time load)",
                    "description": "Read-only snapshot of the outbound-traffic admission gateway: effective per-target/global concurrency caps, jitter and pacing, plus live load — global in-flight, queue depth, cumulative admissions, per-host load, and rotating-identity pool sizes. Concurrency caps + the disable flag are env-only (the protection floor); pacing is runtime-tunable via POST /api/stealth/config.",
                    "tags": ["Intel"],
                    "responses": { "200": { "description": "{ disabled, config{…,env_keys}, live{global_in_flight,waiting,admitted_total,active_hosts[]}, identity{…} }" } }
                }
            },
            "/api/stealth/config": {
                "post": {
                    "summary": "Tune Smart Stealth Queue live pacing (operator+)",
                    "description": "Adjust the cadence params — jitter_min_ms, jitter_max_ms, min_interval_ms — at runtime. Server-clamped to a sane ceiling with jitter_min ≤ jitter_max enforced; omitted fields keep their current value. Only cadence is tunable: concurrency caps and the disable kill-switch are env-only, so this can never lower the DoS/WAF protection floor. RBAC: operator+. Changes are audit-logged. Returns fresh status.",
                    "tags": ["Intel"],
                    "requestBody": {
                        "required": false,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "properties": {
                                "jitter_min_ms":   { "type": "integer", "minimum": 0, "maximum": 60000 },
                                "jitter_max_ms":   { "type": "integer", "minimum": 0, "maximum": 60000 },
                                "min_interval_ms": { "type": "integer", "minimum": 0, "maximum": 60000 }
                            }
                        } } }
                    },
                    "responses": {
                        "200": { "description": "Applied — fresh status snapshot" },
                        "403": { "description": "RBAC: operator role required" }
                    }
                }
            },
            "/api/intel/suppressions": {
                "get": {
                    "summary": "List active auto-suppression rules (3-FP threshold)",
                    "tags": ["Intel"],
                    "responses": { "200": { "description": "Suppressions" } }
                }
            },
            "/api/intel/suppressions/{id}": {
                "delete": {
                    "summary": "Remove a suppression rule (analyst override)",
                    "tags": ["Intel"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }],
                    "responses": {
                        "200": { "description": "Deleted" },
                        "404": { "description": "Not found" }
                    }
                }
            },

            "/api/attack-paths/{client_id}": {
                "get": {
                    "summary": "BFS-derived attack paths internet_exposed → crown_jewel",
                    "description": "Dijkstra over risk_graph_nodes/edges weighted by associated finding's CVSS+EPSS+KEV. Returns top-K paths + choke-point analysis. `?recompute=1` rebuilds the snapshot live; otherwise returns the latest cached snapshot from `attack_path_snapshots`.",
                    "tags": ["AttackPath"],
                    "parameters": [
                        { "name": "client_id", "in": "path",  "required": true, "schema": { "type": "integer" } },
                        { "name": "recompute", "in": "query", "schema": { "type": "boolean" } },
                        { "name": "top_k",     "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 200 } }
                    ],
                    "responses": { "200": { "description": "Snapshot or null" } }
                }
            },
            "/api/risk-graph/nodes/{node_id}/flags": {
                "patch": {
                    "summary": "Toggle internet_exposed / crown_jewel / asset_value on a node",
                    "tags": ["AttackPath"],
                    "parameters": [{ "name": "node_id", "in": "path", "required": true, "schema": { "type": "integer" } }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "properties": {
                                "internet_exposed": { "type": "boolean" },
                                "crown_jewel":      { "type": "boolean" },
                                "asset_value":      { "type": "number" }
                            }
                        } } }
                    },
                    "responses": { "200": { "description": "Updated" }, "404": { "description": "Node not found" } }
                }
            },

            "/api/playbooks": {
                "get": {
                    "summary": "List SOAR playbooks for the tenant",
                    "tags": ["SOAR"],
                    "responses": { "200": { "description": "Playbook list" } }
                },
                "post": {
                    "summary": "Create a SOAR playbook",
                    "description": "Body: `{ name, description, enabled, trigger: {...}, actions: [...] }`. Trigger DSL keys: `severity[]`, `kev`, `epss_min`, `exposed`, `engines[]`, `cve_prefixes[]`, `cooldown_seconds`. Action kinds: `set_status | slack_notify | webhook | http_post | open_pr | isolate_host | page_oncall`.",
                    "tags": ["SOAR"],
                    "responses": { "201": { "description": "Created" }, "409": { "description": "Name already exists" } }
                }
            },
            "/api/playbooks/{id}": {
                "patch":  { "summary": "Update playbook", "tags": ["SOAR"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }],
                    "responses": { "200": { "description": "Updated" }, "404": { "description": "Not found" } }
                },
                "delete": { "summary": "Delete playbook", "tags": ["SOAR"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }],
                    "responses": { "200": { "description": "Deleted" }, "404": { "description": "Not found" } }
                }
            },
            "/api/playbooks/fire": {
                "post": {
                    "summary": "Fire a synthetic PlaybookEvent against all enabled playbooks (supports dry_run)",
                    "tags": ["SOAR"],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["event"],
                            "properties": {
                                "event":   { "type": "object" },
                                "dry_run": { "type": "boolean", "default": false }
                            }
                        } } }
                    },
                    "responses": { "200": { "description": "Per-playbook dispatch results" } }
                }
            },
            "/api/playbooks/{id}/runs": {
                "get": {
                    "summary": "Audit history of dispatches for a playbook",
                    "tags": ["SOAR"],
                    "parameters": [
                        { "name": "id",    "in": "path",  "required": true, "schema": { "type": "integer" } },
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "default": 50, "maximum": 500 } }
                    ],
                    "responses": { "200": { "description": "Run history" } }
                }
            },

            "/api/financial-risk/{client_id}": {
                "get": {
                    "summary": "FAIR-aligned $-at-risk snapshot for a client",
                    "description": "Returns SLE_worst (single biggest loss possible today), ALE_annualised (expected $/yr loss), crown-jewel value, total asset value, and top contributors. `?recompute=1` runs fresh.",
                    "tags": ["FinancialRisk"],
                    "parameters": [
                        { "name": "client_id", "in": "path",  "required": true, "schema": { "type": "integer" } },
                        { "name": "recompute", "in": "query", "schema": { "type": "boolean" } }
                    ],
                    "responses": { "200": { "description": "Snapshot or null" } }
                }
            },
            "/api/financial-risk/{client_id}/apply-tags": {
                "post": {
                    "summary": "Re-apply client_asset_value_rules to all of a client's risk_graph_nodes",
                    "tags": ["FinancialRisk"],
                    "parameters": [{ "name": "client_id", "in": "path", "required": true, "schema": { "type": "integer" } }],
                    "responses": { "200": { "description": "Number of nodes updated" } }
                }
            },

            "/api/ueba/anomalies": {
                "get": {
                    "summary": "Recent UEBA anomalies detected on endpoint agents",
                    "tags": ["UEBA"],
                    "parameters": [
                        { "name": "limit",    "in": "query", "schema": { "type": "integer", "default": 50, "maximum": 500 } },
                        { "name": "agent_id", "in": "query", "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "Anomaly list" } }
                }
            },
            "/api/ueba/ingest": {
                "post": {
                    "summary": "Ingest a UEBA baseline sample from a weissman-agent",
                    "description": "Server side: writes the sample, recomputes mean/stddev from the last 7 days for `(agent, metric, hour_of_week)`, fires medium-severity anomaly when `|z| > 3` (high when > 6). Also detects new-port / new-process categorical anomalies.",
                    "tags": ["UEBA"],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["agent_id","client_id","hour_of_week","metrics"],
                            "properties": {
                                "agent_id":     { "type": "string" },
                                "client_id":    { "type": "integer" },
                                "hour_of_week": { "type": "integer", "minimum": 0, "maximum": 167 },
                                "metrics":      { "type": "object" }
                            }
                        } } }
                    },
                    "responses": { "200": { "description": "Ingest summary + any anomalies fired" } }
                }
            },

            "/api/ask": {
                "post": {
                    "summary": "Ask Weissman — natural-language query compiled to safe parameterised SQL",
                    "description": "LLM emits a strict JSON QueryPlan (never raw SQL). Server validates against an allow-list of 6 tables × N columns × 10 operators, compiles to parameterised SQL with `tenant_id=$1` enforced, and executes against the dedicated read-only role `weissman_ro` (SELECT-only, 15 s statement timeout). Returns the compiled SQL alongside the rows for full transparency. Audited to `nl_query_audit`. Returns **503** if no read-only pool is configured (set `WEISSMAN_READ_ONLY_DATABASE_URL`).",
                    "tags": ["Ask"],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["question"],
                            "properties": {
                                "question": { "type": "string", "maxLength": 2000 }
                            }
                        } } }
                    },
                    "responses": {
                        "200": { "description": "QueryPlan + compiled SQL + result rows" },
                        "503": { "description": "Read-only pool not configured" }
                    }
                }
            },

            "/api/auth/signup": {
                "post": {
                    "summary": "Self-serve signup (rate-limited; sends verification email)",
                    "tags": ["Auth"],
                    "security": [],
                    "responses": {
                        "202": { "description": "Verification email sent (or shown in dev mode)" },
                        "503": { "description": "Self-serve signup disabled (set WEISSMAN_SELF_SERVE_SIGNUP=true)" }
                    }
                }
            },
            "/api/auth/verify": {
                "get": {
                    "summary": "Verify email + create the tenant/admin user",
                    "tags": ["Auth"],
                    "security": [],
                    "parameters": [{ "name": "token", "in": "query", "required": true, "schema": { "type": "string" } }],
                    "responses": {
                        "303": { "description": "Redirect to /command-center/login?verified=1" },
                        "410": { "description": "Token invalid / consumed / expired" }
                    }
                }
            },

            "/api/audit-logs": {
                "get": {
                    "summary": "Tenant audit log (paginated + filterable)",
                    "tags": ["Audit"],
                    "parameters": [
                        { "name": "limit",  "in": "query", "schema": { "type": "integer", "default": 100, "maximum": 1000 } },
                        { "name": "offset", "in": "query", "schema": { "type": "integer", "default": 0 } },
                        { "name": "action", "in": "query", "schema": { "type": "string" } },
                        { "name": "actor",  "in": "query", "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "Audit entries" } }
                }
            }
        }
    });
    (StatusCode::OK, Json(spec)).into_response()
}
