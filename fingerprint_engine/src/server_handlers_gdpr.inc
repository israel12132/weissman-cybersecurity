// ===== GDPR / data-subject rights (DSR): export + right-to-erasure =====
//
// Admin-gated, tenant-scoped, audited. Two POST endpoints:
//   * POST /api/gdpr/export {subject_email?}  -> JSON bundle of personal data.
//   * POST /api/gdpr/erase  {subject_email}   -> anonymize/purge the subject.
//
// Tenant isolation: every query filters `tenant_id = auth.tenant_id` and runs
// inside crate::db::begin_tenant_tx, so Postgres RLS is the backstop — a DSR
// request can never read or mutate another tenant's rows. require_admin (below)
// plus the /api/gdpr rule in rbac::required_min_role keep it admin-and-above.
//
// Append-only tables (audit_logs, nl_query_audit) are RETAINED, never mutated:
// audit_logs is guarded by BEFORE UPDATE/DELETE triggers (`audit_logs is
// append-only`) and weissman_app holds no UPDATE/DELETE on nl_query_audit.
// Retaining the tamper-evident security/audit trail is the GDPR Art. 17(3)(b)/(e)
// exemption (legal obligation + establishment/defense of legal claims); the
// erasure itself is recorded as a NEW audit row rather than by rewriting history.

const GDPR_EXPORT_MAX_ROWS: i64 = 10_000;

#[derive(Deserialize, Default)]
struct GdprSubjectBody {
    #[serde(default)]
    subject_email: Option<String>,
}

fn gdpr_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "ok": false, "detail": "gdpr store unavailable" })),
    )
        .into_response()
}

fn gdpr_bad_request(detail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "detail": detail })),
    )
        .into_response()
}

fn gdpr_user_row_to_json(r: &sqlx::postgres::PgRow) -> Value {
    let id: i64 = r.try_get("id").unwrap_or(0);
    let email: String = r.try_get("email").unwrap_or_default();
    let role: String = r.try_get("role").unwrap_or_default();
    let mfa_enabled: bool = r.try_get("mfa_enabled").unwrap_or(false);
    let sso_provider: Option<String> = r.try_get("sso_provider").ok().flatten();
    let is_active: bool = r.try_get("is_active").unwrap_or(true);
    let assigned_client_id: Option<i64> = r.try_get("assigned_client_id").ok().flatten();
    let avatar_url: String = r.try_get("avatar_url").unwrap_or_default();
    let created_at = r
        .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
        .ok()
        .map(|d| d.to_rfc3339());
    let updated_at = r
        .try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
        .ok()
        .map(|d| d.to_rfc3339());
    json!({
        "id": id,
        "email": email,
        "role": role,
        "mfa_enabled": mfa_enabled,
        "sso_provider": sso_provider,
        "is_active": is_active,
        "assigned_client_id": assigned_client_id,
        "avatar_url": avatar_url,
        "created_at": created_at,
        "updated_at": updated_at,
    })
}

fn gdpr_audit_row_to_json(r: &sqlx::postgres::PgRow) -> Value {
    let id: i64 = r.try_get("id").unwrap_or(0);
    let actor_user_id: Option<i64> = r.try_get("actor_user_id").ok().flatten();
    let user_label: String = r.try_get("user_label").unwrap_or_default();
    let action_type: String = r.try_get("action_type").unwrap_or_default();
    let details: String = r.try_get("details").unwrap_or_default();
    let ip_address: String = r.try_get("ip_address").unwrap_or_default();
    let created_at = r
        .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
        .ok()
        .map(|d| d.to_rfc3339());
    json!({
        "id": id,
        "actor_user_id": actor_user_id,
        "user_label": user_label,
        "action_type": action_type,
        "details": details,
        "ip_address": ip_address,
        "created_at": created_at,
    })
}

fn gdpr_nlqa_row_to_json(r: &sqlx::postgres::PgRow) -> Value {
    let id: i64 = r.try_get("id").unwrap_or(0);
    let user_id: Option<i64> = r.try_get("user_id").ok().flatten();
    let question: String = r.try_get("question").unwrap_or_default();
    let rows_returned: i32 = r.try_get("rows_returned").unwrap_or(0);
    let elapsed_ms: i32 = r.try_get("elapsed_ms").unwrap_or(0);
    let error: String = r.try_get("error").unwrap_or_default();
    let asked_at = r
        .try_get::<chrono::DateTime<chrono::Utc>, _>("asked_at")
        .ok()
        .map(|d| d.to_rfc3339());
    json!({
        "id": id,
        "user_id": user_id,
        "question": question,
        "rows_returned": rows_returned,
        "elapsed_ms": elapsed_ms,
        "error": error,
        "asked_at": asked_at,
    })
}

/// POST /api/gdpr/export — assemble the personal-data bundle held for a subject
/// (or the whole tenant when `subject_email` is omitted). Admin-only; the read of
/// personal data is itself recorded in the audit chain. Send `{}` for a
/// tenant-wide export.
async fn api_gdpr_export(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<GdprSubjectBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let subject_raw = body
        .subject_email
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let subject: Option<String> = if subject_raw.is_empty() {
        None
    } else if crate::gdpr_dsr::looks_like_email(&subject_raw) {
        Some(subject_raw)
    } else {
        return gdpr_bad_request("subject_email must be a valid email address");
    };

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return gdpr_unavailable();
    };

    // Resolve the subject's user row (may be absent: a former user can still have
    // audit/message rows keyed by their email/label).
    let subject_user_id: Option<i64> = if subject.is_some() {
        match sqlx::query_scalar::<_, i64>(
            "SELECT id FROM users WHERE lower(email) = lower($1) AND tenant_id = $2 ORDER BY id LIMIT 1",
        )
        .bind(subject.as_deref())
        .bind(auth.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(v) => v,
            Err(_) => {
                let _ = tx.rollback().await;
                return gdpr_unavailable();
            }
        }
    } else {
        None
    };

    let mut truncated = false;

    // -- users --------------------------------------------------------------
    let users_rows = match sqlx::query(
        r#"SELECT id, email, role, mfa_enabled, sso_provider, is_active,
                  assigned_client_id, created_at, updated_at, avatar_url
           FROM users
           WHERE tenant_id = $1 AND ($2::text IS NULL OR lower(email) = lower($2))
           ORDER BY id
           LIMIT $3"#,
    )
    .bind(auth.tenant_id)
    .bind(subject.as_deref())
    .bind(GDPR_EXPORT_MAX_ROWS)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(_) => {
            let _ = tx.rollback().await;
            return gdpr_unavailable();
        }
    };
    truncated |= users_rows.len() as i64 >= GDPR_EXPORT_MAX_ROWS;
    let users_json: Vec<Value> = users_rows.iter().map(gdpr_user_row_to_json).collect();

    // -- audit_logs (by user_label OR actor_user_id) ------------------------
    let audit_rows = match sqlx::query(
        r#"SELECT id, actor_user_id, user_label, action_type, details, ip_address, created_at
           FROM audit_logs
           WHERE tenant_id = $1
             AND ($2::text IS NULL OR lower(user_label) = lower($2) OR actor_user_id = $3)
           ORDER BY id DESC
           LIMIT $4"#,
    )
    .bind(auth.tenant_id)
    .bind(subject.as_deref())
    .bind(subject_user_id)
    .bind(GDPR_EXPORT_MAX_ROWS)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(_) => {
            let _ = tx.rollback().await;
            return gdpr_unavailable();
        }
    };
    truncated |= audit_rows.len() as i64 >= GDPR_EXPORT_MAX_ROWS;
    let audit_json: Vec<Value> = audit_rows.iter().map(gdpr_audit_row_to_json).collect();

    // -- client_messages (by sender_email OR sender_user_id) ----------------
    let message_rows = match sqlx::query(
        r#"SELECT id, client_id, sender_user_id, sender_email, kind, body, created_at
           FROM client_messages
           WHERE tenant_id = $1
             AND ($2::text IS NULL OR lower(sender_email) = lower($2) OR sender_user_id = $3)
           ORDER BY id DESC
           LIMIT $4"#,
    )
    .bind(auth.tenant_id)
    .bind(subject.as_deref())
    .bind(subject_user_id)
    .bind(GDPR_EXPORT_MAX_ROWS)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(_) => {
            let _ = tx.rollback().await;
            return gdpr_unavailable();
        }
    };
    truncated |= message_rows.len() as i64 >= GDPR_EXPORT_MAX_ROWS;
    // Reuse msg_row_to_json (defined by server_handlers_messaging.inc, same module).
    let messages_json: Vec<Value> = message_rows.iter().map(msg_row_to_json).collect();

    // -- nl_query_audit (by user_id) ----------------------------------------
    let nlqa_rows = match sqlx::query(
        r#"SELECT id, user_id, question, rows_returned, elapsed_ms, error, asked_at
           FROM nl_query_audit
           WHERE tenant_id = $1 AND ($2::text IS NULL OR user_id = $3)
           ORDER BY id DESC
           LIMIT $4"#,
    )
    .bind(auth.tenant_id)
    .bind(subject.as_deref())
    .bind(subject_user_id)
    .bind(GDPR_EXPORT_MAX_ROWS)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(_) => {
            let _ = tx.rollback().await;
            return gdpr_unavailable();
        }
    };
    truncated |= nlqa_rows.len() as i64 >= GDPR_EXPORT_MAX_ROWS;
    let nlqa_json: Vec<Value> = nlqa_rows.iter().map(gdpr_nlqa_row_to_json).collect();

    // Mandatory access audit: reading personal data is itself an audited event.
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let details = format!(
        "gdpr_export subject={} users={} audit_logs={} client_messages={} nl_query_audit={}",
        subject.as_deref().unwrap_or("<entire-tenant>"),
        users_json.len(),
        audit_json.len(),
        messages_json.len(),
        nlqa_json.len(),
    );
    if audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "gdpr_export",
        &details,
        &ip,
    )
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return gdpr_unavailable();
    }
    if tx.commit().await.is_err() {
        return gdpr_unavailable();
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "kind": "gdpr_export",
            "subject_email": subject,
            "tenant_id": auth.tenant_id,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "row_cap_per_table": GDPR_EXPORT_MAX_ROWS,
            "truncated": truncated,
            "data": {
                "users": users_json,
                "audit_logs": audit_json,
                "client_messages": messages_json,
                "nl_query_audit": nlqa_json,
                "vulnerabilities": {
                    "included": false,
                    "reason": "finding/vulnerability rows are asset-scoped and carry no data-subject identifier (no user_id/email column)"
                }
            }
        })),
    )
        .into_response()
}

/// POST /api/gdpr/erase — right-to-erasure. Anonymizes the subject's user row and
/// authored messages, revokes their sessions, retains the append-only audit
/// trails, and records a mandatory audit entry. Admin-only, tenant-scoped, atomic.
async fn api_gdpr_erase(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<GdprSubjectBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let subject = body
        .subject_email
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    if subject.is_empty() {
        return gdpr_bad_request("subject_email is required for erasure");
    }
    if !crate::gdpr_dsr::looks_like_email(&subject) {
        return gdpr_bad_request("subject_email must be a valid email address");
    }

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return gdpr_unavailable();
    };

    // Resolve the subject user row (id, is_superadmin). May be absent.
    let subject_user: Option<(i64, bool)> = match sqlx::query_as::<_, (i64, bool)>(
        "SELECT id, is_superadmin FROM users WHERE lower(email) = lower($1) AND tenant_id = $2 ORDER BY id LIMIT 1",
    )
    .bind(&subject)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(v) => v,
        Err(_) => {
            let _ = tx.rollback().await;
            return gdpr_unavailable();
        }
    };

    // Guards: never let DSR erase a break-glass account or the caller themselves.
    if let Some((id, is_superadmin)) = subject_user {
        if is_superadmin {
            let _ = tx.rollback().await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "detail": "refusing to erase a superadmin account via DSR"
                })),
            )
                .into_response();
        }
        if id == auth.user_id {
            let _ = tx.rollback().await;
            return gdpr_bad_request("cannot erase your own account");
        }
    }

    let subject_user_id: Option<i64> = subject_user.map(|(id, _)| id);
    let tombstone = subject_user_id
        .map(crate::gdpr_dsr::tombstone_email)
        .unwrap_or_else(|| "erased@erased.invalid".to_string());

    // 1) Anonymize messages authored by the subject: strip identity and content.
    //    `sender_user_id = $3` is NULL-safe: when $3 is NULL it matches nothing, so
    //    only the email clause applies (subject with no surviving user row).
    let messages_anonymized = match sqlx::query(
        r#"UPDATE client_messages
           SET sender_email = $1, sender_user_id = NULL, body = '[erased]'
           WHERE tenant_id = $2
             AND (sender_user_id = $3 OR lower(sender_email) = lower($4))"#,
    )
    .bind(&tombstone)
    .bind(auth.tenant_id)
    .bind(subject_user_id)
    .bind(&subject)
    .execute(&mut *tx)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(_) => {
            let _ = tx.rollback().await;
            return gdpr_unavailable();
        }
    };

    // Nothing matched at all -> subject unknown in this tenant.
    if subject_user_id.is_none() && messages_anonymized == 0 {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": "no data found for subject in this tenant" })),
        )
            .into_response();
    }

    // 2) Revoke all refresh sessions for the subject.
    let sessions_revoked = if let Some(uid) = subject_user_id {
        match sqlx::query("DELETE FROM user_refresh_tokens WHERE user_id = $1 AND tenant_id = $2")
            .bind(uid)
            .bind(auth.tenant_id)
            .execute(&mut *tx)
            .await
        {
            Ok(r) => r.rows_affected(),
            Err(_) => {
                let _ = tx.rollback().await;
                return gdpr_unavailable();
            }
        }
    } else {
        0
    };

    // 3) Anonymize the user row in place (keeps FK + audit-chain linkage intact).
    //    role / assigned_client_id / is_superadmin are untouched so the
    //    users_client_scope_consistency CHECK stays satisfied.
    let user_anonymized = if let Some(uid) = subject_user_id {
        match sqlx::query(
            r#"UPDATE users
               SET email = $1, password_hash = NULL, mfa_secret = '', mfa_enabled = false,
                   sso_provider = NULL, sso_id = NULL, avatar_url = '', is_active = false,
                   updated_at = now()
               WHERE id = $2 AND tenant_id = $3"#,
        )
        .bind(&tombstone)
        .bind(uid)
        .bind(auth.tenant_id)
        .execute(&mut *tx)
        .await
        {
            Ok(r) => r.rows_affected(),
            Err(_) => {
                let _ = tx.rollback().await;
                return gdpr_unavailable();
            }
        }
    } else {
        0
    };

    // Append-only trails are retained (Art. 17(3) exemption); count for the summary.
    let audit_logs_retained: i64 = match sqlx::query_scalar::<_, i64>(
        r#"SELECT count(*) FROM audit_logs
           WHERE tenant_id = $1 AND (lower(user_label) = lower($2) OR actor_user_id = $3)"#,
    )
    .bind(auth.tenant_id)
    .bind(&subject)
    .bind(subject_user_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(n) => n,
        Err(_) => {
            // A store failure must not be reported as "0 records retained" — the erasure
            // summary is a compliance artefact and has to be honest or not exist at all.
            let _ = tx.rollback().await;
            return gdpr_unavailable();
        }
    };

    let nl_query_audit_retained: i64 = if let Some(uid) = subject_user_id {
        match sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM nl_query_audit WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(auth.tenant_id)
        .bind(uid)
        .fetch_one(&mut *tx)
        .await
        {
            Ok(n) => n,
            Err(_) => {
                let _ = tx.rollback().await;
                return gdpr_unavailable();
            }
        }
    } else {
        0
    };

    // Mandatory: record the erasure itself in the append-only audit chain.
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    let details = format!(
        "gdpr_erase subject={} user_anonymized={} messages_anonymized={} sessions_revoked={} audit_logs_retained={} nl_query_audit_retained={}",
        subject,
        user_anonymized,
        messages_anonymized,
        sessions_revoked,
        audit_logs_retained,
        nl_query_audit_retained,
    );
    if audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &actor,
        "gdpr_erase",
        &details,
        &ip,
    )
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return gdpr_unavailable();
    }
    if tx.commit().await.is_err() {
        return gdpr_unavailable();
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "kind": "gdpr_erase",
            "subject_email": subject,
            "tenant_id": auth.tenant_id,
            "erased_at": chrono::Utc::now().to_rfc3339(),
            "summary": {
                "user_anonymized": user_anonymized,
                "client_messages_anonymized": messages_anonymized,
                "refresh_sessions_revoked": sessions_revoked,
                "audit_logs_retained": audit_logs_retained,
                "nl_query_audit_retained": nl_query_audit_retained
            },
            "notes": [
                "audit_logs and nl_query_audit are append-only tamper-evident trails; retained under GDPR Art. 17(3) (legal obligation / defense of legal claims).",
                "the user row is anonymized in place (email tombstoned, credentials + PII cleared, account deactivated) to preserve referential and audit-chain integrity."
            ]
        })),
    )
        .into_response()
}
