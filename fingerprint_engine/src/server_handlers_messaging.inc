// ===== Per-client messaging + help board, and per-user / per-client images =====
//
// All handlers here are client-scoped by the same machinery as the rest of the
// platform: the client_scope middleware auto-aims a scoped session at its own
// client (injecting client_id into query/body) and Postgres RLS on
// client_messages walls every other client's rows off. Staff/owner pick a client
// explicitly. Messaging + the avatar/profile endpoints are self-service so every
// employee (including a read-only viewer) can post and set their own picture.

const MSG_MAX_IMAGE_REF_LEN: usize = 900_000; // ~650 KB image as a data: URL
const MSG_MAX_BODY_LEN: usize = 8_000;
const MSG_DEFAULT_LIMIT: i64 = 100;
const MSG_MAX_LIMIT: i64 = 500;

/// An image reference is an https URL or an inline `data:image/...` URL under the
/// size cap. An empty string is allowed and clears the image.
fn msg_valid_image_ref(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return true;
    }
    if s.len() > MSG_MAX_IMAGE_REF_LEN {
        return false;
    }
    s.starts_with("https://") || s.starts_with("data:image/")
}

fn msg_bad_request(detail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "detail": detail })),
    )
        .into_response()
}

fn msg_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "ok": false, "detail": "messaging store unavailable" })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct MsgImageBody {
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    logo_url: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize)]
struct MsgCreateBody {
    #[serde(default)]
    body: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
}

/// Resolve which client a message read/write targets. Scoped users are bound to
/// their own client (a mismatched id was already 404'd by the middleware); staff
/// must name one.
fn msg_resolve_client(auth: &AuthContext, requested: Option<i64>) -> Result<i64, Response> {
    match crate::client_isolation::bind_requested_client(auth, requested) {
        Ok(Some(cid)) => Ok(cid),
        Ok(None) => Err(msg_bad_request(
            "client_id is required — pick a client whose board to open",
        )),
        Err(resp) => Err(resp),
    }
}

/// GET /api/account/profile — the caller's own display fields + avatar.
async fn api_account_profile(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return msg_unavailable();
    };
    let row = sqlx::query(
        "SELECT email, COALESCE(avatar_url, '') AS avatar_url FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match row {
        Ok(Some(r)) => {
            let email: String = r.try_get("email").unwrap_or_default();
            let avatar_url: String = r.try_get("avatar_url").unwrap_or_default();
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "user_id": auth.user_id,
                    "email": email,
                    "role": auth.role,
                    "avatar_url": avatar_url,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": "user not found" })),
        )
            .into_response(),
        Err(_) => msg_unavailable(),
    }
}

/// POST /api/account/avatar — set the caller's own avatar (self-service).
async fn api_account_avatar_set(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<MsgImageBody>,
) -> Response {
    let url = body
        .avatar_url
        .or(body.url)
        .unwrap_or_default()
        .trim()
        .to_string();
    if !msg_valid_image_ref(&url) {
        return msg_bad_request("avatar must be an https:// or data:image/ URL under the size limit");
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return msg_unavailable();
    };
    let res = sqlx::query("UPDATE users SET avatar_url = $1 WHERE id = $2 AND tenant_id = $3")
        .bind(&url)
        .bind(auth.user_id)
        .bind(auth.tenant_id)
        .execute(&mut *tx)
        .await;
    match res {
        Ok(_) if tx.commit().await.is_ok() => (
            StatusCode::OK,
            Json(json!({ "ok": true, "avatar_url": url })),
        )
            .into_response(),
        _ => msg_unavailable(),
    }
}

/// POST /api/clients/:id/logo — set a client's logo (operator+ / in-scope).
async fn api_client_logo_set(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Json(body): Json<MsgImageBody>,
) -> Response {
    let url = body
        .logo_url
        .or(body.url)
        .unwrap_or_default()
        .trim()
        .to_string();
    if !msg_valid_image_ref(&url) {
        return msg_bad_request("logo must be an https:// or data:image/ URL under the size limit");
    }
    // A scoped session had this path id validated against its assignment by the
    // client_scope middleware already; RLS is the backstop on the UPDATE.
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return msg_unavailable();
    };
    let res = sqlx::query(
        "UPDATE clients SET logo_url = $1, updated_at = now() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(&url)
    .bind(client_id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 && tx.commit().await.is_ok() => (
            StatusCode::OK,
            Json(json!({ "ok": true, "logo_url": url })),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": "client not found" })),
        )
            .into_response(),
        Err(_) => msg_unavailable(),
    }
}

fn msg_row_to_json(r: &sqlx::postgres::PgRow) -> Value {
    let id: i64 = r.try_get("id").unwrap_or(0);
    let client_id: i64 = r.try_get("client_id").unwrap_or(0);
    let sender_user_id: Option<i64> = r.try_get("sender_user_id").ok().flatten();
    let sender_email: String = r.try_get("sender_email").unwrap_or_default();
    let kind: String = r.try_get("kind").unwrap_or_else(|_| "message".to_string());
    let body: String = r.try_get("body").unwrap_or_default();
    let created_at = r
        .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
        .ok()
        .map(|d| d.to_rfc3339());
    json!({
        "id": id,
        "client_id": client_id,
        "sender_user_id": sender_user_id,
        "sender_email": sender_email,
        "kind": kind,
        "body": body,
        "created_at": created_at,
    })
}

/// GET /api/messages?client_id=&limit= — the client's board, newest first.
async fn api_messages_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let requested = q
        .get("client_id")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|v| *v > 0);
    let cid = match msg_resolve_client(&auth, requested) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let limit = q
        .get("limit")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(MSG_DEFAULT_LIMIT)
        .clamp(1, MSG_MAX_LIMIT);
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return msg_unavailable();
    };
    let rows = sqlx::query(
        r#"SELECT id, client_id, sender_user_id, sender_email, kind, body, created_at
           FROM client_messages
           WHERE client_id = $1
           ORDER BY created_at DESC, id DESC
           LIMIT $2"#,
    )
    .bind(cid)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match rows {
        Ok(rows) => {
            let messages: Vec<Value> = rows.iter().map(msg_row_to_json).collect();
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "client_id": cid, "messages": messages })),
            )
                .into_response()
        }
        Err(_) => msg_unavailable(),
    }
}

/// POST /api/messages — post to a client's board (kind = message | help).
async fn api_messages_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<MsgCreateBody>,
) -> Response {
    let text = body.body.trim().to_string();
    if text.is_empty() {
        return msg_bad_request("message body is required");
    }
    if text.len() > MSG_MAX_BODY_LEN {
        return msg_bad_request("message is too long");
    }
    let kind_raw = body
        .kind
        .as_deref()
        .unwrap_or("message")
        .trim()
        .to_ascii_lowercase();
    let kind = match kind_raw.as_str() {
        "" | "message" => "message",
        "help" => "help",
        _ => return msg_bad_request("kind must be 'message' or 'help'"),
    };
    let cid = match msg_resolve_client(&auth, body.client_id.filter(|v| *v > 0)) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return msg_unavailable();
    };
    let sender_email: String = sqlx::query_scalar::<_, String>(
        "SELECT email FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    let inserted = sqlx::query(
        r#"INSERT INTO client_messages (tenant_id, client_id, sender_user_id, sender_email, kind, body)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, client_id, sender_user_id, sender_email, kind, body, created_at"#,
    )
    .bind(auth.tenant_id)
    .bind(cid)
    .bind(auth.user_id)
    .bind(&sender_email)
    .bind(kind)
    .bind(&text)
    .fetch_one(&mut *tx)
    .await;
    match inserted {
        Ok(row) if tx.commit().await.is_ok() => (
            StatusCode::CREATED,
            Json(json!({ "ok": true, "message": msg_row_to_json(&row) })),
        )
            .into_response(),
        _ => msg_unavailable(),
    }
}
