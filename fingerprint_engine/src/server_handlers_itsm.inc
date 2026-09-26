// ===== ITSM connectors: ServiceNow + Jira (open tickets from findings) =====
//
// Admin-gated, tenant-scoped, audited. The connector credential is encrypted at rest
// (crate::ceo::vault, wzv1: AES-256-GCM) before storage and is NEVER returned by the API.
// Outbound calls are SSRF-validated (crate::security_hardening::validate_outbound_url).
//
//   POST   /api/integrations/itsm            create a connector (creds encrypted, never echoed)
//   GET    /api/integrations/itsm            list connectors (metadata only, no creds)
//   DELETE /api/integrations/itsm/:id        delete a connector
//   POST   /api/findings/:id/itsm-ticket     open a ticket for a finding
//
// This fragment is include!d into http::serve, so it shares that module's scope
// (State/Extension/Path/Json/StatusCode/Response/HeaderMap, `json!`, `Value`, `db`,
// `AuthContext`, `sqlx::Row`, `Arc`, `chrono`).

fn itsm_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "ok": false, "detail": "itsm store unavailable" })),
    )
        .into_response()
}

fn itsm_bad_request(detail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "detail": detail })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct ItsmCredentialBody {
    /// "basic" or "bearer".
    scheme: String,
    #[serde(default)]
    username: String,
    secret: String,
}

#[derive(Deserialize)]
struct ItsmConnectorCreateBody {
    kind: String,
    #[serde(default)]
    name: String,
    base_url: String,
    #[serde(default)]
    project_or_table: String,
    #[serde(default)]
    default_fields: Value,
    auth: ItsmCredentialBody,
}

/// POST /api/integrations/itsm — create a connector. Admin only. Encrypts the credential
/// with the vault before insert; the plaintext secret never touches the DB or the response.
async fn api_itsm_connector_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<ItsmConnectorCreateBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let kind = body.kind.trim().to_ascii_lowercase();
    if kind != crate::itsm::KIND_SERVICENOW && kind != crate::itsm::KIND_JIRA {
        return itsm_bad_request("kind must be 'servicenow' or 'jira'");
    }
    let scheme = body.auth.scheme.trim().to_ascii_lowercase();
    if scheme != "basic" && scheme != "bearer" {
        return itsm_bad_request("auth.scheme must be 'basic' or 'bearer'");
    }
    if body.auth.secret.trim().is_empty() {
        return itsm_bad_request("auth.secret is required");
    }
    if scheme == "basic" && body.auth.username.trim().is_empty() {
        return itsm_bad_request("auth.username is required for basic auth");
    }
    // SSRF-validate the base_url at configuration time (resolve + reject private/reserved).
    if let Err(e) = crate::security_hardening::validate_outbound_url(body.base_url.trim()).await {
        return itsm_bad_request(&format!("base_url rejected: {e}"));
    }
    let default_fields = if body.default_fields.is_null() {
        json!({})
    } else {
        body.default_fields.clone()
    };

    // Serialize + encrypt the credential; only the wzv1: blob is stored in auth_ref.
    let cred_json = json!({
        "scheme": scheme,
        "username": body.auth.username.trim(),
        "secret": body.auth.secret.trim(),
    })
    .to_string();
    let auth_ref = crate::ceo::vault::encrypt_secret(&cred_json);

    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return itsm_unavailable(),
    };
    let inserted = sqlx::query(
        r#"INSERT INTO itsm_connectors
               (tenant_id, kind, name, base_url, auth_ref, project_or_table, default_fields, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id, created_at"#,
    )
    .bind(auth.tenant_id)
    .bind(&kind)
    .bind(body.name.trim())
    .bind(body.base_url.trim())
    .bind(&auth_ref)
    .bind(body.project_or_table.trim())
    .bind(&default_fields)
    .bind(auth.user_id)
    .fetch_one(&mut *tx)
    .await;
    let (id, created_at) = match inserted {
        Ok(row) => (
            row.try_get::<i64, _>("id").unwrap_or(0),
            row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok(),
        ),
        Err(_) => {
            let _ = tx.rollback().await;
            return itsm_unavailable();
        }
    };
    if crate::audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &auth.role,
        "itsm_connector_created",
        &format!("id={} kind={} base_url={}", id, kind, body.base_url.trim()),
        "-",
    )
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return itsm_unavailable();
    }
    if tx.commit().await.is_err() {
        return itsm_unavailable();
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "id": id,
            "kind": kind,
            "name": body.name.trim(),
            "base_url": body.base_url.trim(),
            "project_or_table": body.project_or_table.trim(),
            "active": true,
            "created_at": created_at,
        })),
    )
        .into_response()
}

/// GET /api/integrations/itsm — list connectors (metadata only; never the credential). Admin only.
async fn api_itsm_connector_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return itsm_unavailable(),
    };
    let rows = sqlx::query(
        r#"SELECT id, kind, name, base_url, project_or_table, default_fields, active, created_at
           FROM itsm_connectors WHERE tenant_id = $1
           ORDER BY created_at DESC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match rows {
        Ok(rows) => {
            let items: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "id": r.try_get::<i64, _>("id").unwrap_or(0),
                        "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
                        "name": r.try_get::<String, _>("name").unwrap_or_default(),
                        "base_url": r.try_get::<String, _>("base_url").unwrap_or_default(),
                        "project_or_table": r.try_get::<String, _>("project_or_table").unwrap_or_default(),
                        "default_fields": r.try_get::<Value, _>("default_fields").unwrap_or_else(|_| json!({})),
                        "active": r.try_get::<bool, _>("active").unwrap_or(false),
                        "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok(),
                        // auth_ref is intentionally omitted — credentials are never returned.
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "ok": true, "connectors": items }))).into_response()
        }
        Err(_) => itsm_unavailable(),
    }
}

/// DELETE /api/integrations/itsm/:id — delete a connector. Admin only.
async fn api_itsm_connector_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return itsm_unavailable(),
    };
    let res = sqlx::query("DELETE FROM itsm_connectors WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .execute(&mut *tx)
        .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            let _ = crate::audit_log::insert_audit(
                &mut tx,
                auth.tenant_id,
                Some(auth.user_id),
                &auth.role,
                "itsm_connector_deleted",
                &format!("id={}", id),
                "-",
            )
            .await;
            if tx.commit().await.is_err() {
                return itsm_unavailable();
            }
            (StatusCode::OK, Json(json!({ "ok": true, "id": id }))).into_response()
        }
        Ok(_) => {
            let _ = tx.rollback().await;
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "ok": false, "detail": "connector not found" })),
            )
                .into_response()
        }
        Err(_) => {
            let _ = tx.rollback().await;
            itsm_unavailable()
        }
    }
}

#[derive(Deserialize)]
struct ItsmTicketBody {
    connector_id: i64,
}

/// POST /api/findings/:id/itsm-ticket — open a ServiceNow incident / Jira issue for a finding.
/// Admin only, step-up gated (no-op unless WEISSMAN_REQUIRE_STEPUP=1). The tenant tx is
/// committed BEFORE the outbound network round-trip; the created ticket is written to the
/// itsm_tickets ledger + audit in a second tx.
async fn api_finding_itsm_ticket_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<ItsmTicketBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    if let Err(r) = crate::auth_stepup::require_step_up(&headers, &auth) {
        return r;
    }

    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return itsm_unavailable(),
    };
    let finding_row = sqlx::query(
        "SELECT finding_id, title, severity, description FROM vulnerabilities \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await;
    let finding_row = match finding_row {
        Ok(Some(r)) => r,
        Ok(None) => {
            let _ = tx.rollback().await;
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "ok": false, "detail": "finding not found" })),
            )
                .into_response();
        }
        Err(_) => {
            let _ = tx.rollback().await;
            return itsm_unavailable();
        }
    };
    let connector_row = sqlx::query(
        "SELECT kind, base_url, auth_ref, project_or_table, default_fields, active \
         FROM itsm_connectors WHERE id = $1 AND tenant_id = $2",
    )
    .bind(body.connector_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await;
    let connector_row = match connector_row {
        Ok(Some(r)) => r,
        Ok(None) => {
            let _ = tx.rollback().await;
            return itsm_bad_request("connector not found");
        }
        Err(_) => {
            let _ = tx.rollback().await;
            return itsm_unavailable();
        }
    };

    let finding_input = crate::itsm::FindingTicketInput {
        finding_ref: finding_row
            .try_get::<String, _>("finding_id")
            .unwrap_or_default(),
        summary: finding_row.try_get::<String, _>("title").unwrap_or_default(),
        severity: finding_row
            .try_get::<String, _>("severity")
            .unwrap_or_default(),
        details: {
            let d: String = finding_row.try_get("description").unwrap_or_default();
            crate::itsm::truncate(&d, 4000)
        },
    };
    let kind: String = connector_row.try_get("kind").unwrap_or_default();
    let base_url: String = connector_row.try_get("base_url").unwrap_or_default();
    let auth_ref: String = connector_row.try_get("auth_ref").unwrap_or_default();
    let project_or_table: String = connector_row.try_get("project_or_table").unwrap_or_default();
    let default_fields: Value = connector_row
        .try_get("default_fields")
        .unwrap_or_else(|_| json!({}));
    let active: bool = connector_row.try_get("active").unwrap_or(false);
    // Release the tenant tx before the (slow) outbound call.
    let _ = tx.commit().await;

    if !active {
        return itsm_bad_request("connector is disabled");
    }
    // Decrypt the credential in-process (never logged, never echoed).
    let cred_plain = crate::ceo::vault::decrypt_secret(&auth_ref);
    let credential: crate::itsm::ItsmCredential = match serde_json::from_str(&cred_plain) {
        Ok(c) => c,
        Err(_) => return itsm_unavailable(),
    };
    let connector = crate::itsm::ItsmConnector {
        id: body.connector_id,
        kind,
        base_url,
        project_or_table,
        default_fields,
        credential,
    };

    let created = match crate::itsm::create_ticket(&connector, &finding_input).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "ok": false, "detail": format!("ticket creation failed: {e}") })),
            )
                .into_response();
        }
    };

    // Persist the ledger row + audit in one tenant tx.
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return itsm_unavailable(),
    };
    let ticket_id: Result<i64, sqlx::Error> = sqlx::query_scalar(
        r#"INSERT INTO itsm_tickets
               (tenant_id, connector_id, finding_id, kind, external_id, external_key, external_url, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id"#,
    )
    .bind(auth.tenant_id)
    .bind(body.connector_id)
    .bind(id)
    .bind(&connector.kind)
    .bind(&created.external_id)
    .bind(&created.external_key)
    .bind(&created.external_url)
    .bind(auth.user_id)
    .fetch_one(&mut *tx)
    .await;
    let ticket_id = match ticket_id {
        Ok(v) => v,
        Err(_) => {
            let _ = tx.rollback().await;
            return itsm_unavailable();
        }
    };
    let _ = crate::audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &auth.role,
        "itsm_ticket_created",
        &format!(
            "finding_id={} connector_id={} kind={} external_key={} external_url={}",
            id, body.connector_id, connector.kind, created.external_key, created.external_url
        ),
        "-",
    )
    .await;
    if tx.commit().await.is_err() {
        return itsm_unavailable();
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "ticket_id": ticket_id,
            "kind": connector.kind,
            "external_id": created.external_id,
            "external_key": created.external_key,
            "external_url": created.external_url,
        })),
    )
        .into_response()
}
