// Board-grade document / workbook export + AI key readiness.
//
// Included from `handler_fragments.rs` so handlers share `AppState` / auth scope.

#[derive(Deserialize, Default)]
struct LangQuery {
    lang: Option<String>,
}

fn accept_language(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
}

fn report_lang(q: &LangQuery, headers: &HeaderMap) -> crate::pdf::Lang {
    crate::pdf::lang_from_parts(q.lang.as_deref(), accept_language(headers))
}

fn attachment_response(bytes: Vec<u8>, content_type: &'static str, filename: &str) -> Response {
    let mut res = Response::new(Body::from(bytes));
    res.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    res.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::try_from(format!("attachment; filename=\"{filename}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    res.headers_mut().insert(
        axum::http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    res
}

fn csv_response(body: String, filename: &str) -> Response {
    attachment_response(
        body.into_bytes(),
        crate::csv_safe::content_type(),
        filename,
    )
}

const XLSX_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

fn xlsx_response(bytes: Vec<u8>, filename: &str) -> Response {
    attachment_response(bytes, XLSX_CONTENT_TYPE, filename)
}

fn pdf_response(bytes: Vec<u8>, filename: &str) -> Response {
    attachment_response(bytes, "application/pdf", filename)
}

fn col(title: &str, weight: f64, style: &str) -> crate::pdf::spec::ColumnSpec {
    crate::pdf::spec::ColumnSpec {
        title: title.to_string(),
        weight,
        style: style.to_string(),
    }
}

/// POST /api/export/document — render a [`DocumentSpec`] JSON body to PDF.
async fn api_export_document(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(spec): Json<crate::pdf::spec::DocumentSpec>,
) -> Response {
    let bytes = match spec.render_pdf() {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": e})),
            )
                .into_response();
        }
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return pdf_response(bytes, "weissman-export.pdf");
    };
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "export_document",
        &format!("title={} bytes={}", spec.title, bytes.len()),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    let safe: String = spec
        .title
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .take(48)
        .collect();
    let name = if safe.trim_matches('_').is_empty() {
        "weissman-export.pdf".into()
    } else {
        format!("{safe}.pdf")
    };
    pdf_response(bytes, &name)
}

/// POST /api/export/workbook — render a [`WorkbookSpec`] JSON body to XLSX.
async fn api_export_workbook(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(spec): Json<crate::pdf::spec::WorkbookSpec>,
) -> Response {
    let bytes = match crate::xlsx_report::render_workbook(&spec) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": e})),
            )
                .into_response();
        }
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return xlsx_response(bytes, "weissman-export.xlsx");
    };
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "export_workbook",
        &format!("title={} bytes={}", spec.title, bytes.len()),
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    xlsx_response(bytes, "weissman-export.xlsx")
}

async fn findings_export_rows(
    state: &AppState,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<Vec<Vec<String>>, StatusCode> {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, tenant_id).await else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    let rows = if let Some(cid) = client_id {
        sqlx::query(
            "SELECT id, COALESCE(finding_id,'') AS finding_id, title, severity, source, status, \
             client_id::text, COALESCE(description,'') AS description, discovered_at, \
             COALESCE(poc_sealed, false) AS poc_sealed \
             FROM vulnerabilities WHERE client_id = $1 ORDER BY discovered_at DESC LIMIT 50000",
        )
        .bind(cid)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query(
            "SELECT id, COALESCE(finding_id,'') AS finding_id, title, severity, source, status, \
             client_id::text, COALESCE(description,'') AS description, discovered_at, \
             COALESCE(poc_sealed, false) AS poc_sealed \
             FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 50000",
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default()
    };
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            let raw_id = r.try_get::<i64, _>("id").unwrap_or(0);
            let disc = r
                .try_get::<chrono::DateTime<Utc>, _>("discovered_at")
                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_default();
            let verified = if r.try_get::<bool, _>("poc_sealed").unwrap_or(false) {
                "VERIFIED"
            } else {
                "POTENTIAL"
            };
            vec![
                format!("VLN-{raw_id}"),
                r.try_get::<String, _>("finding_id").unwrap_or_default(),
                r.try_get::<String, _>("title").unwrap_or_default(),
                r.try_get::<String, _>("severity").unwrap_or_default(),
                r.try_get::<String, _>("source").unwrap_or_default(),
                r.try_get::<String, _>("status").unwrap_or_default(),
                r.try_get::<String, _>("client_id").unwrap_or_default(),
                verified.to_string(),
                disc,
                r.try_get::<String, _>("description").unwrap_or_default(),
            ]
        })
        .collect())
}

fn findings_columns() -> Vec<crate::pdf::spec::ColumnSpec> {
    vec![
        col("ID", 1.0, "mono"),
        col("Finding ID", 1.2, "mono"),
        col("Title", 3.0, "strong"),
        col("Severity", 1.0, "severity"),
        col("Source", 1.2, ""),
        col("Status", 1.0, ""),
        col("Client", 1.0, ""),
        col("Verified", 1.0, ""),
        col("Discovered", 1.4, ""),
        col("Description", 3.0, ""),
    ]
}

/// GET /api/findings/export/xlsx
async fn api_findings_export_xlsx(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let rows = match findings_export_rows(&state, auth.tenant_id, None).await {
        Ok(r) => r,
        Err(st) => {
            return (st, Json(json!({"error": "DB unavailable"}))).into_response();
        }
    };
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let lang = report_lang(&q, &headers);
    match crate::xlsx_report::table_workbook(
        "Weissman findings export",
        "tenant",
        &actor,
        lang,
        findings_columns(),
        rows,
    ) {
        Ok(bytes) => {
            let now = chrono::Utc::now().format("%Y-%m-%d");
            xlsx_response(bytes, &format!("Weissman_findings_{now}.xlsx"))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "xlsx failed", "detail": e})),
        )
            .into_response(),
    }
}

/// GET /api/clients/:id/export/xlsx
async fn api_client_export_xlsx(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Query(q): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    let rows = match findings_export_rows(&state, auth.tenant_id, Some(id)).await {
        Ok(r) => r,
        Err(st) => {
            return (st, Json(json!({"error": "DB unavailable"}))).into_response();
        }
    };
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let lang = report_lang(&q, &headers);
    match crate::xlsx_report::table_workbook(
        "Weissman client findings",
        &format!("client-{id}"),
        &actor,
        lang,
        findings_columns(),
        rows,
    ) {
        Ok(bytes) => xlsx_response(bytes, &format!("Weissman_findings_client_{id}.xlsx")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "xlsx failed", "detail": e})),
        )
            .into_response(),
    }
}

/// GET /api/ceo/vault/export/criticals.xlsx
async fn api_ceo_vault_export_criticals_xlsx(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<LangQuery>,
    headers: HeaderMap,
) -> Response {
    match crate::ceo::vault::export_vault_criticals_xlsx(
        state.app_pool.as_ref(),
        auth.tenant_id,
        report_lang(&q, &headers),
    )
    .await
    {
        Ok(bytes) => xlsx_response(bytes, "genesis_vault_criticals.xlsx"),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": scrub_internal_error(&e) })),
        )
            .into_response(),
    }
}

/// GET /api/ai/readiness — catalog of LLM + enrichment keys (fingerprints only).
async fn api_ai_readiness(Extension(_auth): Extension<AuthContext>) -> Response {
    let catalog = weissman_engines::llm_providers::catalog();
    let endpoints: Vec<_> = weissman_engines::llm_providers::discover_endpoints()
        .into_iter()
        .map(|e| e.public())
        .collect();
    let enrichment = [
        (
            "shodan",
            weissman_engines::llm_providers::env_first(&[
                "WEISSMAN_SHODAN_API_KEY",
                "SHODAN_API_KEY",
            ]),
            "WEISSMAN_SHODAN_API_KEY",
        ),
        (
            "censys_id",
            weissman_engines::llm_providers::env_nonempty("CENSYS_API_ID"),
            "CENSYS_API_ID",
        ),
        (
            "censys_secret",
            weissman_engines::llm_providers::env_nonempty("CENSYS_API_SECRET"),
            "CENSYS_API_SECRET",
        ),
        (
            "nvd",
            weissman_engines::llm_providers::env_first(&["NVD_API_KEY", "WEISSMAN_NVD_API_KEY"]),
            "NVD_API_KEY",
        ),
        (
            "github",
            weissman_engines::llm_providers::env_first(&[
                "GITHUB_TOKEN",
                "WEISSMAN_GITHUB_TOKEN",
            ]),
            "GITHUB_TOKEN",
        ),
    ];
    let enrichment_json: Vec<_> = enrichment
        .into_iter()
        .map(|(id, val, env)| {
            json!({
                "id": id,
                "key_env": env,
                "configured": val.is_some(),
                "key_fingerprint": val.as_deref().map(weissman_engines::llm_providers::fingerprint),
            })
        })
        .collect();
    let ready = catalog.iter().any(|p| p.configured) || !endpoints.is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "ready": ready,
            "providers": catalog,
            "active_endpoints": endpoints,
            "enrichment": enrichment_json,
            "note": "Secrets are never returned. Set the listed env vars and restart weissman-server.",
        })),
    )
        .into_response()
}

/// POST /api/ai/readiness/probe — reachability check against the primary endpoint.
async fn api_ai_readiness_probe(Extension(_auth): Extension<AuthContext>) -> Response {
    let endpoints = weissman_engines::llm_providers::discover_endpoints();
    let Some(ep) = endpoints.first() else {
        return (
            StatusCode::OK,
            Json(json!({
                "ok": false,
                "detail": "no LLM endpoints configured",
            })),
        )
            .into_response();
    };
    let client = match crate::outbound_http::external_json_client() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response();
        }
    };
    let url = weissman_engines::openai_chat::chat_completions_endpoint(&ep.base_url)
        .replace("/chat/completions", "/models");
    let t0 = std::time::Instant::now();
    let mut req = client.get(&url).timeout(std::time::Duration::from_secs(4));
    req = weissman_engines::llm_providers::apply_auth(req, ep.auth, ep.api_key.as_deref());
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            (
                StatusCode::OK,
                Json(json!({
                    "ok": status < 400,
                    "provider": ep.provider,
                    "label": ep.label,
                    "base_url": ep.base_url,
                    "http_status": status,
                    "latency_ms": t0.elapsed().as_millis() as u64,
                    "key_fingerprint": ep.api_key.as_deref().map(weissman_engines::llm_providers::fingerprint),
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::OK,
            Json(json!({
                "ok": false,
                "provider": ep.provider,
                "label": ep.label,
                "base_url": ep.base_url,
                "detail": e.to_string(),
                "latency_ms": t0.elapsed().as_millis() as u64,
            })),
        )
            .into_response(),
    }
}
