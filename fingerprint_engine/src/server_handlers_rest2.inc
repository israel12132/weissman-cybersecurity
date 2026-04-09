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
                  COALESCE(poc_sealed, false), COALESCE(poc_commitment_sha256,'') FROM vulnerabilities WHERE client_id = $1 ORDER BY discovered_at DESC"#,
    )
    .bind(cid)
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
                "poc_sealed": r.try_get::<bool,_>("poc_sealed").unwrap_or(false),
                "poc_commitment_sha256": r.try_get::<String,_>("poc_commitment_sha256").unwrap_or_default(),
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
                Json(json!({"error": "PDF generation failed", "detail": e.to_string()})),
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
    // Explicitly scope update to current tenant to defend against any RLS gap
    let affected = sqlx::query(
        "UPDATE vulnerabilities SET status = $1, updated_at = now(), status_changed_at = now() \
         WHERE id = $2 AND tenant_id = $3",
    )
    .bind(&new_status)
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match affected {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, Json(json!({"ok": true, "id": id, "status": new_status}))).into_response()
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
                    "summary": "Health check",
                    "tags": ["System"],
                    "security": [],
                    "responses": {
                        "200": { "description": "Server is healthy" }
                    }
                }
            }
        }
    });
    (StatusCode::OK, Json(spec)).into_response()
}
