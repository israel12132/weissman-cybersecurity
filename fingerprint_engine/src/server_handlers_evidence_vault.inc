use base64::Engine;
use sha2::{Digest, Sha256};

const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024; // 8MB

#[derive(Deserialize)]
struct EvidenceUploadBody {
    filename: String,
    #[serde(default)]
    content_type: Option<String>,
    data_base64: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    engagement_id: Option<i64>,
    #[serde(default)]
    vulnerability_id: Option<i64>,
}

fn sanitize_filename(raw: &str) -> String {
    let raw = raw.trim();
    let last = raw
        .split('/')
        .last()
        .unwrap_or(raw)
        .split('\\')
        .last()
        .unwrap_or(raw)
        .trim();
    let mut out = String::new();
    for c in last.chars().take(200) {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' ' | '(' | ')') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    let out = out.trim().to_string();
    if out.is_empty() {
        "evidence.bin".to_string()
    } else {
        out
    }
}

fn normalize_content_type(raw: Option<&str>) -> String {
    let ct = raw.unwrap_or("application/octet-stream").trim();
    if ct.is_empty() || ct.len() > 200 {
        return "application/octet-stream".to_string();
    }
    ct.to_string()
}

async fn api_client_evidence_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"evidence": []}))).into_response();
    };
    // Ensure client exists (better error than silent empty list).
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM clients WHERE id = $1")
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    if exists.is_none() {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "client not found"})),
        )
            .into_response();
    }

    let rows = sqlx::query(
        r#"SELECT id, client_id, engagement_id, vulnerability_id, filename, content_type,
                  size_bytes, sha256_hex, label, notes, created_by_user_id, created_at
           FROM evidence_items
           WHERE client_id = $1
           ORDER BY created_at DESC
           LIMIT 200"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let evidence: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let created_at: chrono::DateTime<chrono::Utc> =
                r.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now());
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "client_id": r.try_get::<i64,_>("client_id").unwrap_or(client_id),
                "engagement_id": r.try_get::<Option<i64>,_>("engagement_id").unwrap_or(None),
                "vulnerability_id": r.try_get::<Option<i64>,_>("vulnerability_id").unwrap_or(None),
                "filename": r.try_get::<String,_>("filename").unwrap_or_default(),
                "content_type": r.try_get::<String,_>("content_type").unwrap_or_else(|_| "application/octet-stream".to_string()),
                "size_bytes": r.try_get::<i64,_>("size_bytes").unwrap_or(0),
                "sha256_hex": r.try_get::<String,_>("sha256_hex").unwrap_or_default(),
                "label": r.try_get::<String,_>("label").unwrap_or_default(),
                "notes": r.try_get::<String,_>("notes").unwrap_or_default(),
                "created_by_user_id": r.try_get::<Option<i64>,_>("created_by_user_id").unwrap_or(None),
                "created_at": created_at.to_rfc3339(),
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "evidence": evidence }))).into_response()
}

async fn api_client_evidence_upload(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(client_id): Path<i64>,
    Json(body): Json<EvidenceUploadBody>,
) -> Response {
    let filename = sanitize_filename(&body.filename);
    let content_type = normalize_content_type(body.content_type.as_deref());
    let label = body.label.unwrap_or_default().trim().chars().take(200).collect::<String>();
    let notes = body.notes.unwrap_or_default().trim().chars().take(4000).collect::<String>();

    let decoded = match base64::engine::general_purpose::STANDARD.decode(body.data_base64.trim()) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "data_base64 must be valid base64"})),
            )
                .into_response();
        }
    };
    if decoded.is_empty() || decoded.len() > MAX_EVIDENCE_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "evidence size must be 1..8MB"})),
        )
            .into_response();
    }

    let sha256_hex = {
        let mut h = Sha256::new();
        h.update(&decoded);
        let d = h.finalize();
        hex::encode(d)
    };

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let client_exists: Option<i64> = sqlx::query_scalar("SELECT id FROM clients WHERE id = $1")
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    if client_exists.is_none() {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "client not found"})),
        )
            .into_response();
    }

    // If engagement_id provided, validate it belongs to this client.
    if let Some(eid) = body.engagement_id {
        let ok: Option<i64> = sqlx::query_scalar("SELECT id FROM engagements WHERE id = $1 AND client_id = $2")
            .bind(eid)
            .bind(client_id)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
        if ok.is_none() {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "engagement_id not found for client"})),
            )
                .into_response();
        }
    }
    // If vulnerability_id provided, validate it belongs to this client.
    if let Some(vid) = body.vulnerability_id {
        let ok: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM vulnerabilities WHERE id = $1 AND client_id = $2",
        )
        .bind(vid)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        if ok.is_none() {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "vulnerability_id not found for client"})),
            )
                .into_response();
        }
    }

    let created: Option<(i64,)> = sqlx::query_as(
        r#"INSERT INTO evidence_items
              (tenant_id, client_id, engagement_id, vulnerability_id, filename, content_type,
               size_bytes, sha256_hex, label, notes, blob, created_by_user_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
           RETURNING id"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(body.engagement_id)
    .bind(body.vulnerability_id)
    .bind(&filename)
    .bind(&content_type)
    .bind(decoded.len() as i64)
    .bind(&sha256_hex)
    .bind(&label)
    .bind(&notes)
    .bind(decoded)
    .bind(auth.user_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let Some((evidence_id,)) = created else {
        let _ = tx.rollback().await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false}))).into_response();
    };

    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "evidence_uploaded",
        &format!(
            "client_id={} evidence_id={} engagement_id={:?} vulnerability_id={:?} sha256={}",
            client_id, evidence_id, body.engagement_id, body.vulnerability_id, sha256_hex
        ),
        &ip,
    )
    .await;
    let _ = tx.commit().await;

    (
        StatusCode::CREATED,
        Json(json!({"ok": true, "evidence_id": evidence_id, "sha256_hex": sha256_hex})),
    )
        .into_response()
}

async fn api_evidence_download(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(evidence_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB unavailable"}))).into_response();
    };
    let row = sqlx::query(
        r#"SELECT id, client_id, filename, content_type, blob
           FROM evidence_items
           WHERE id = $1"#,
    )
    .bind(evidence_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let Some(r) = row else {
        let _ = tx.commit().await;
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    };

    let client_id = r.try_get::<i64, _>("client_id").unwrap_or(0);
    let filename = sanitize_filename(&r.try_get::<String, _>("filename").unwrap_or_else(|_| "evidence.bin".to_string()));
    let content_type = normalize_content_type(r.try_get::<String, _>("content_type").ok().as_deref());
    let blob: Vec<u8> = r.try_get::<Vec<u8>, _>("blob").unwrap_or_default();

    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let _ = audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "evidence_downloaded",
        &format!("client_id={} evidence_id={}", client_id, evidence_id),
        &ip,
    )
    .await;
    let _ = tx.commit().await;

    let mut res = Response::new(Body::from(blob));
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::try_from(content_type).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    res.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::try_from(format!("attachment; filename=\"{}\"", filename))
            .unwrap_or(HeaderValue::from_static("attachment")),
    );
    res.headers_mut().insert(
        axum::http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    res
}

async fn api_evidence_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(evidence_id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };

    let row = sqlx::query("SELECT client_id FROM evidence_items WHERE id = $1")
        .bind(evidence_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let Some(r) = row else {
        let _ = tx.commit().await;
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "detail": "not found"}))).into_response();
    };
    let client_id = r.try_get::<i64, _>("client_id").unwrap_or(0);

    let deleted = sqlx::query("DELETE FROM evidence_items WHERE id = $1")
        .bind(evidence_id)
        .execute(&mut *tx)
        .await
        .ok()
        .map(|r| r.rows_affected())
        .unwrap_or(0);
    if deleted == 0 {
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
        "evidence_deleted",
        &format!("client_id={} evidence_id={}", client_id, evidence_id),
        &ip,
    )
    .await;
    let _ = tx.commit().await;

    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

