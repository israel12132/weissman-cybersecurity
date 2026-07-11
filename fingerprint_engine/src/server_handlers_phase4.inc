use axum::body::Bytes;

async fn insert_heal_request_row(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    finding_id: &str,
    vuln_id: i64,
    branch_name: &str,
    pr_url: Option<&str>,
    pr_number: Option<i64>,
    diff_summary: &str,
    verification_status: &str,
    verification_job_id: &str,
) {
    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        let _ = sqlx::query(
            r#"INSERT INTO heal_requests (tenant_id, client_id, finding_id, vulnerability_id, branch_name, pr_url, pr_number, diff_summary, verification_status, verification_job_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(finding_id)
        .bind(vuln_id)
        .bind(branch_name)
        .bind(pr_url)
        .bind(pr_number.map(|n| n as i32))
        .bind(diff_summary)
        .bind(verification_status)
        .bind(verification_job_id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
}

async fn api_heal_verify_steps(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    let job_uuid = match uuid::Uuid::parse_str(job_id.trim()) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid job_id", "steps": []})),
            )
                .into_response();
        }
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "DB", "steps": []})),
        )
            .into_response();
    };
    let rows = sqlx::query(
        r#"SELECT step_label, detail, step_ts FROM heal_verification_steps
           WHERE tenant_id = $1 AND job_id = $2 ORDER BY step_index ASC"#,
    )
    .bind(auth.tenant_id)
    .bind(job_uuid)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let steps: Vec<crate::verification_sandbox::VerificationStep> = rows
        .into_iter()
        .filter_map(|r| {
            Some(crate::verification_sandbox::VerificationStep {
                step: r.try_get("step_label").ok()?,
                detail: r.try_get("detail").ok(),
                ts: r.try_get("step_ts").ok()?,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "steps": steps }))).into_response()
}

/// `GET /api/heal-verify/:job_id` — thin status view for a heal job: spec status + channel +
/// the resulting verdict / branch / PR (from `heal_requests`). Complements `/steps`.
async fn api_heal_verify_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    let job_uuid = match uuid::Uuid::parse_str(job_id.trim()) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid job_id"})),
            )
                .into_response();
        }
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let spec = sqlx::query(
        r#"SELECT status, COALESCE(channel,'github_pr') AS channel,
                  (result_artifact IS NOT NULL) AS has_artifact
           FROM auto_heal_job_specs WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(job_uuid)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let hr = sqlx::query(
        r#"SELECT branch_name, pr_url, pr_number, diff_summary, verification_status,
                  COALESCE(verdict,'') AS verdict, COALESCE(channel,'') AS channel,
                  COALESCE(attempts, 1) AS attempts,
                  (COALESCE(verification_receipt,'') <> '') AS attested
           FROM heal_requests
           WHERE tenant_id = $1 AND verification_job_id = $2
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(auth.tenant_id)
    .bind(&job_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let Some(spec) = spec else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "job not found"}))).into_response();
    };
    let mut out = json!({
        "job_id": job_id,
        "status": spec.try_get::<String,_>("status").unwrap_or_default(),
        "channel": spec.try_get::<String,_>("channel").unwrap_or_default(),
        "has_artifact": spec.try_get::<bool,_>("has_artifact").unwrap_or(false),
    });
    if let Some(r) = hr {
        out["verdict"] = json!(r.try_get::<String, _>("verdict").unwrap_or_default());
        out["verification_status"] =
            json!(r.try_get::<String, _>("verification_status").unwrap_or_default());
        out["branch_name"] = json!(r.try_get::<Option<String>, _>("branch_name").ok().flatten());
        out["pr_url"] = json!(r.try_get::<Option<String>, _>("pr_url").ok().flatten());
        out["pr_number"] = json!(r.try_get::<Option<i32>, _>("pr_number").ok().flatten());
        out["diff_summary"] = json!(r.try_get::<Option<String>, _>("diff_summary").ok().flatten());
        out["attempts"] = json!(r.try_get::<i32, _>("attempts").unwrap_or(1));
        out["attested"] = json!(r.try_get::<bool, _>("attested").unwrap_or(false));
    }
    (StatusCode::OK, Json(out)).into_response()
}

/// `GET /api/heal-verify/:job_id/patch` — download the verified artifact: the unified diff
/// (diff_download channel) as `text/x-patch`, or the virtual-patch snippet as `text/plain`.
async fn api_heal_verify_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    let job_uuid = match uuid::Uuid::parse_str(job_id.trim()) {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid job_id").into_response();
        }
    };
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, "DB").into_response();
    };
    let row = sqlx::query(
        r#"SELECT result_artifact, COALESCE(patch_text,'') AS patch_text
           FROM auto_heal_job_specs WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(job_uuid)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let Some(row) = row else {
        return (StatusCode::NOT_FOUND, "job not found").into_response();
    };
    let artifact = row
        .try_get::<Option<Value>, _>("result_artifact")
        .ok()
        .flatten();
    let (content_type, filename, body): (&str, String, String) = match artifact {
        Some(a) if a.get("kind").and_then(Value::as_str) == Some("virtual_patch") => (
            "text/plain; charset=utf-8",
            format!("weissman-virtual-patch-{}.conf", job_id),
            a.get("snippet")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        Some(a) if a.get("unified_diff").and_then(Value::as_str).is_some() => (
            "text/x-patch; charset=utf-8",
            format!("weissman-heal-{}.patch", job_id),
            a.get("unified_diff")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        _ => (
            "text/x-patch; charset=utf-8",
            format!("weissman-heal-{}.patch", job_id),
            row.try_get::<String, _>("patch_text").unwrap_or_default(),
        ),
    };
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, content_type.to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        body,
    )
        .into_response()
}

/// `GET /api/heal-verify/:job_id/attestation` — verify the signed heal receipt (HMAC-SHA256)
/// stored for this job: confirms the receipt is a genuine, untampered Weissman attestation of
/// the verification digest.
async fn api_heal_verify_attestation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    if uuid::Uuid::parse_str(job_id.trim()).is_err() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid job_id"}))).into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let row = sqlx::query(
        r#"SELECT COALESCE(verification_receipt,'') AS receipt, COALESCE(verification_digest,'') AS digest,
                  COALESCE(verdict,'') AS verdict, verification_status
           FROM heal_requests
           WHERE tenant_id = $1 AND verification_job_id = $2
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(auth.tenant_id)
    .bind(&job_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let Some(r) = row else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "heal not found"}))).into_response();
    };
    let receipt: String = r.try_get("receipt").unwrap_or_default();
    let digest: String = r.try_get("digest").unwrap_or_default();
    let verdict: String = r.try_get("verdict").unwrap_or_default();
    let status: String = r.try_get("verification_status").unwrap_or_default();

    if receipt.is_empty() || digest.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({
                "attested": false,
                "reason": if crate::finding_attestation::is_enabled() {
                    "no receipt on this heal (not a verified outcome)"
                } else {
                    "attestation disabled on this deployment (no WEISSMAN_ATTESTATION_KEY)"
                },
                "alg": crate::finding_attestation::ATTEST_ALG,
                "enabled": crate::finding_attestation::is_enabled(),
                "verdict": verdict,
                "verification_status": status,
            })),
        )
            .into_response();
    }
    let ok = crate::finding_attestation::verify(&digest, &receipt);
    (
        StatusCode::OK,
        Json(json!({
            "attested": ok,
            "digest": digest,
            "alg": crate::finding_attestation::ATTEST_ALG,
            "enabled": crate::finding_attestation::is_enabled(),
            "verdict": verdict,
            "verification_status": status,
        })),
    )
        .into_response()
}

/// Load everything a completed heal's report needs in one query pass (spec + heal_requests + brief),
/// so the HTML report, `report.json`, and the SARIF export can all be served from the same data.
/// Errs with the response status a handler should return (400 bad id / 404 not found / 503 DB).
async fn load_heal_report_data(
    state: &Arc<AppState>,
    tenant_id: i64,
    job_id: &str,
) -> Result<crate::remediation_report::HealReportData, (StatusCode, &'static str)> {
    let job_uuid = uuid::Uuid::parse_str(job_id.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid job_id"))?;
    let mut tx = db::begin_tenant_tx(&state.app_pool, tenant_id)
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "DB"))?;

    // Job spec (keyed by UUID).
    let spec = sqlx::query(
        r#"SELECT COALESCE(status,'') AS status, COALESCE(channel,'github_pr') AS channel,
                  result_artifact, COALESCE(patch_text,'') AS patch_text,
                  COALESCE(finding_id,'') AS finding_id, client_id::bigint AS client_id
           FROM auto_heal_job_specs WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(job_uuid)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(spec) = spec else {
        let _ = tx.commit().await;
        return Err((StatusCode::NOT_FOUND, "job not found"));
    };
    let status: String = spec.try_get("status").unwrap_or_default();
    let channel: String = spec.try_get("channel").unwrap_or_default();
    let patch_text: String = spec.try_get("patch_text").unwrap_or_default();
    let finding_id: String = spec.try_get("finding_id").unwrap_or_default();
    let client_id: i64 = spec.try_get("client_id").unwrap_or_default();
    let artifact = spec
        .try_get::<Option<Value>, _>("result_artifact")
        .ok()
        .flatten();

    // Heal request row (keyed by the canonical string verification_job_id).
    let hr = sqlx::query(
        r#"SELECT COALESCE(verdict,'') AS verdict, COALESCE(verification_status,'') AS verification_status,
                  pr_url, branch_name, COALESCE(attempts,1)::bigint AS attempts,
                  COALESCE(verification_receipt,'') AS receipt, COALESCE(verification_digest,'') AS digest
           FROM heal_requests
           WHERE tenant_id = $1 AND verification_job_id = $2
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    // Canonical UUID text so a non-canonical path segment (which still matches the uuid spec lookup)
    // cannot miss the heal_requests row and produce a misleading "unverified" report.
    .bind(job_uuid.to_string())
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    // Finding title/severity + cached bilingual brief (tenant-scoped as defense-in-depth alongside RLS).
    let vuln = sqlx::query(
        r#"SELECT COALESCE(title,'') AS title, COALESCE(severity,'') AS severity, remediation_brief
           FROM vulnerabilities WHERE tenant_id = $1 AND client_id = $2 AND finding_id = $3 LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&finding_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    let (verdict, verification_status, pr_url, branch_name, attempts, receipt, digest) = match &hr {
        Some(r) => (
            r.try_get::<String, _>("verdict").unwrap_or_default(),
            r.try_get::<String, _>("verification_status").unwrap_or_default(),
            r.try_get::<Option<String>, _>("pr_url").ok().flatten(),
            r.try_get::<Option<String>, _>("branch_name").ok().flatten(),
            r.try_get::<i64, _>("attempts").unwrap_or(1),
            r.try_get::<String, _>("receipt").unwrap_or_default(),
            r.try_get::<String, _>("digest").unwrap_or_default(),
        ),
        None => (String::new(), String::new(), None, None, 1, String::new(), String::new()),
    };

    let (mut title, mut severity, brief_val) = match &vuln {
        Some(r) => (
            r.try_get::<String, _>("title").unwrap_or_default(),
            r.try_get::<String, _>("severity").unwrap_or_default(),
            r.try_get::<Option<Value>, _>("remediation_brief").ok().flatten(),
        ),
        None => (String::new(), String::new(), None),
    };
    let brief: Option<crate::remediation_brief::RemediationBrief> = brief_val.and_then(|v| {
        match serde_json::from_value(v) {
            Ok(b) => Some(b),
            Err(e) => {
                // Fail soft (still serve the finding + verified diff), but surface the parse problem.
                tracing::warn!(target: "heal_report", job_id = %job_id, error = %e,
                    "cached remediation_brief failed to parse; serving report without it");
                None
            }
        }
    });
    if title.trim().is_empty() {
        title = finding_id.clone();
    }
    if severity.trim().is_empty() {
        if let Some(b) = &brief {
            severity = b.severity.clone();
        }
    }
    let cwe = brief.as_ref().map(|b| b.cwe.clone()).unwrap_or_default();

    // Verified change: prefer the applied artifact, fall back to the stored patch_text.
    let (unified_diff, changed_files, deleted_paths): (String, Vec<String>, Vec<String>) =
        match &artifact {
            Some(a) => {
                let diff = a
                    .get("unified_diff")
                    .and_then(Value::as_str)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| patch_text.clone());
                let cf = a
                    .get("changed_files")
                    .and_then(Value::as_array)
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let dp = a
                    .get("deleted_paths")
                    .and_then(Value::as_array)
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                (diff, cf, dp)
            }
            None => (patch_text.clone(), Vec::new(), Vec::new()),
        };

    let attestation_enabled = crate::finding_attestation::is_enabled();
    let receipt_verified = !receipt.is_empty()
        && !digest.is_empty()
        && crate::finding_attestation::verify(&digest, &receipt);

    // Advisory governance disposition under the tenant's heal policy (safe defaults).
    let policy = crate::heal_policy::HealPolicy::load(&state.app_pool, tenant_id).await;
    let governance = Some(policy.decide(&verdict, &severity, receipt_verified, attempts));

    Ok(crate::remediation_report::HealReportData {
        job_id: job_id.to_string(),
        finding_id,
        title,
        severity,
        cwe,
        status,
        verdict,
        verification_status,
        channel,
        pr_url,
        branch_name,
        attempts,
        receipt,
        digest,
        attestation_enabled,
        receipt_verified,
        unified_diff,
        changed_files,
        deleted_paths,
        brief,
        generated_at: chrono::Utc::now().to_rfc3339(),
        governance,
    })
}

/// `GET /api/heal-verify/:job_id/report` — self-contained, printable, bilingual (he/en) HTML report
/// for a completed auto-heal (finding, bilingual problem/root-cause/impact/fix, verified diff +
/// changed files, per-channel how-to-apply, and the honestly-labelled signed receipt).
async fn api_heal_verify_report(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    let data = match load_heal_report_data(&state, auth.tenant_id, &job_id).await {
        Ok(d) => d,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    let html = crate::remediation_report::render_heal_report_html(&data.as_input());
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/html; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("inline; filename=\"weissman-remediation-report-{}.html\"", job_id),
            ),
        ],
        html,
    )
        .into_response()
}

/// `GET /api/heal-verify/:job_id/report.json` — the same completed-heal data as a stable, structured
/// JSON document (schema `weissman-heal-report/v1`) for programmatic / CI consumption.
async fn api_heal_verify_report_json(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    match load_heal_report_data(&state, auth.tenant_id, &job_id).await {
        Ok(d) => Json(crate::heal_export::to_report_json(&d)).into_response(),
        Err((code, msg)) => (code, msg).into_response(),
    }
}

/// `GET /api/heal-verify/:job_id/sarif` — a SARIF 2.1.0 document describing the finding and its
/// verified auto-heal, so the proof plugs into GitHub code scanning / SAST dashboards.
async fn api_heal_verify_sarif(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Response {
    match load_heal_report_data(&state, auth.tenant_id, &job_id).await {
        Ok(d) => {
            let body = crate::heal_export::to_sarif(&d).to_string();
            (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/sarif+json; charset=utf-8".to_string(),
                )],
                body,
            )
                .into_response()
        }
        Err((code, msg)) => (code, msg).into_response(),
    }
}

/// `GET /api/heal-readiness` — bilingual (he/en) self-diagnostics of the auto-heal pipeline: per
/// capability (LLM, sandbox/Docker, signed receipts, autonomous GitHub PRs, Slack approvals, LLM auth)
/// whether it is connected and, if not, exactly how to connect it. Returns only presence booleans +
/// guidance — never any secret value.
async fn api_heal_readiness(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    use std::collections::HashMap;
    let mut cfg: HashMap<String, String> = HashMap::new();
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let keys: Vec<String> = vec![
            "llm_base_url".to_string(),
            "llm_model".to_string(),
            "auto_heal_repo_slug".to_string(),
        ];
        if let Ok(rows) = sqlx::query(
            "SELECT key, COALESCE(value,'') AS value FROM system_configs WHERE tenant_id = $1 AND key = ANY($2)",
        )
        .bind(auth.tenant_id)
        .bind(&keys)
        .fetch_all(&mut *tx)
        .await
        {
            for r in rows {
                let k: String = r.try_get("key").unwrap_or_default();
                let v: String = r.try_get("value").unwrap_or_default();
                if !v.trim().is_empty() {
                    cfg.insert(k, v);
                }
            }
        }
        let _ = tx.commit().await;
    }

    let env_nonempty =
        |k: &str| std::env::var(k).map(|v| !v.trim().is_empty()).unwrap_or(false);

    let signals = crate::heal_readiness::ReadinessSignals {
        llm_configured: cfg.contains_key("llm_base_url") || cfg.contains_key("llm_model"),
        llm_auth_present: weissman_engines::openai_chat::llm_api_key_from_env().is_some(),
        docker_socket: std::path::Path::new("/var/run/docker.sock").exists()
            || env_nonempty("DOCKER_HOST"),
        attestation: crate::finding_attestation::is_enabled(),
        slack_approvals: env_nonempty("WEISSMAN_SLACK_SIGNING_SECRET"),
        configless_github: env_nonempty("WEISSMAN_GITHUB_TOKEN")
            && (cfg.contains_key("auto_heal_repo_slug") || env_nonempty("WEISSMAN_AUTOHEAL_REPO")),
    };
    let report = crate::heal_readiness::evaluate_readiness(&signals);
    (StatusCode::OK, Json(report)).into_response()
}

/// `GET /api/clients/:id/heal-trends?days=30` — daily auto-heal trend/SLA analytics for a client:
/// per-day totals, success rate and average attempts, plus an attempts histogram and rollups.
async fn api_heal_trends(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let days: i32 = params
        .get("days")
        .and_then(|d| d.parse::<i32>().ok())
        .unwrap_or(30)
        .clamp(1, 365);
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT to_char(created_at, 'YYYY-MM-DD') AS day,
                  COALESCE(verdict,'') AS verdict,
                  COALESCE(attempts,1)::bigint AS attempts
           FROM heal_requests
           WHERE tenant_id = $1 AND client_id = $2
             AND created_at >= now() - make_interval(days => $3)
           ORDER BY created_at ASC"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(days)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let parsed: Vec<(String, String, i64)> = rows
        .iter()
        .map(|r| {
            (
                r.try_get::<String, _>("day").unwrap_or_default(),
                r.try_get::<String, _>("verdict").unwrap_or_default(),
                r.try_get::<i64, _>("attempts").unwrap_or(1),
            )
        })
        .collect();
    let report = crate::heal_trends::compute_trends(&parsed);
    (
        StatusCode::OK,
        Json(json!({ "client_id": client_id, "days": days, "trend": report })),
    )
        .into_response()
}

/// `GET /api/clients/:id/heal-priorities?limit=50` — ranks the client's OPEN findings by auto-heal
/// priority (0–100 + P0–P3 tier + bilingual reason), so the most dangerous, most reachable issues
/// surface first. Exposure / impact class are inferred from the finding text.
async fn api_heal_priorities(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(client_id): Path<i64>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: usize = params
        .get("limit")
        .and_then(|d| d.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 500);
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT finding_id, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity,
                  COALESCE(description,'') AS description, COALESCE(source,'') AS source,
                  (COALESCE(poc_exploit,'') <> '') AS has_poc,
                  GREATEST(0, EXTRACT(EPOCH FROM (now() - discovered_at)) / 86400)::bigint AS age_days
           FROM vulnerabilities
           WHERE tenant_id = $1 AND client_id = $2 AND status = 'OPEN'
           ORDER BY CASE lower(severity)
                      WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                      WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
                    discovered_at DESC
           LIMIT 2000"#,
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut scored: Vec<Value> = rows
        .iter()
        .map(|r| {
            let title: String = r.try_get("title").unwrap_or_default();
            let desc: String = r.try_get("description").unwrap_or_default();
            let source: String = r.try_get("source").unwrap_or_default();
            let text = format!("{title} {desc} {source}");
            let inputs = crate::heal_priority::PriorityInputs {
                severity: r.try_get::<String, _>("severity").unwrap_or_default(),
                has_poc: r.try_get::<bool, _>("has_poc").unwrap_or(false),
                internet_facing: crate::heal_priority::classify_internet_facing(&text),
                high_impact_category: crate::heal_priority::classify_high_impact(&text),
                age_days: r.try_get::<i64, _>("age_days").unwrap_or(0),
            };
            let p = crate::heal_priority::score_priority(&inputs);
            json!({
                "finding_id": r.try_get::<String, _>("finding_id").unwrap_or_default(),
                "title": title,
                "severity": inputs.severity,
                "score": p.score,
                "tier": p.tier,
                "reason_en": p.reason_en,
                "reason_he": p.reason_he,
                "factors": p.factors,
            })
        })
        .collect();
    scored.sort_by(|a, b| b["score"].as_u64().cmp(&a["score"].as_u64()));
    scored.truncate(limit);
    (
        StatusCode::OK,
        Json(json!({ "client_id": client_id, "count": scored.len(), "priorities": scored })),
    )
        .into_response()
}

/// `GET /api/clients/:id/findings/:finding_id/channel-suggestion?host=&repo_write=1` — advises the
/// best delivery channel for a finding (code-level PR/MR on the matching SCM when the repo is
/// writable; a WAF virtual patch or downloadable diff otherwise), with a bilingual rationale.
async fn api_channel_suggestion(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((client_id, finding_id)): Path<(i64, String)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let host = params
        .get("host")
        .cloned()
        .unwrap_or_else(|| "github.com".to_string());
    let repo_write = params
        .get("repo_write")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "DB"}))).into_response();
    };
    let row = sqlx::query(
        "SELECT COALESCE(title,'') AS title, COALESCE(description,'') AS description
           FROM vulnerabilities WHERE tenant_id = $1 AND client_id = $2 AND finding_id = $3 LIMIT 1",
    )
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(&finding_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let (title, desc) = match row {
        Some(r) => (
            r.try_get::<String, _>("title").unwrap_or_default(),
            r.try_get::<String, _>("description").unwrap_or_default(),
        ),
        None => (String::new(), String::new()),
    };
    let text = format!("{title} {desc}");
    let scm = crate::heal_channel_select::scm_from_host(&host);
    let sel = crate::heal_channel_select::select_channel(&text, scm, repo_write);
    (
        StatusCode::OK,
        Json(json!({
            "finding_id": finding_id,
            "channel": sel.channel,
            "reason_en": sel.reason_en,
            "reason_he": sel.reason_he,
        })),
    )
        .into_response()
}

/// Enqueue an auto-heal approved from a Slack button, using env GitHub token + configured repo.
async fn enqueue_heal_from_slack(
    state: &Arc<AppState>,
    tenant_id: i64,
    client_id: i64,
    finding_id: &str,
) -> Result<String, String> {
    let token = std::env::var("WEISSMAN_GITHUB_TOKEN").unwrap_or_default();
    if token.trim().is_empty() {
        return Err("no WEISSMAN_GITHUB_TOKEN configured".into());
    }
    let mut tx = db::begin_tenant_tx(&state.app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let repo_cfg: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'auto_heal_repo_slug'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let repo = repo_cfg
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("WEISSMAN_AUTOHEAL_REPO").ok())
        .unwrap_or_default();
    if repo.trim().is_empty() {
        let _ = tx.rollback().await;
        return Err("no repo configured (system_configs.auto_heal_repo_slug or WEISSMAN_AUTOHEAL_REPO)".into());
    }
    let row = sqlx::query(
        "SELECT id, COALESCE(generated_patch,'') AS gp, COALESCE(poc_exploit,'') AS pe FROM vulnerabilities WHERE client_id = $1 AND finding_id = $2 LIMIT 1",
    )
    .bind(client_id)
    .bind(finding_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return Err("finding not found".into());
    };
    let vuln_id: i64 = r.try_get("id").unwrap_or(0);
    let patch: String = r.try_get("gp").unwrap_or_default();
    let poc: String = r.try_get("pe").unwrap_or_default();
    if patch.trim().is_empty() {
        let _ = tx.rollback().await;
        return Err("finding has no generated patch".into());
    }
    let spec_id = uuid::Uuid::new_v4();
    let ins = sqlx::query(
        r#"INSERT INTO auto_heal_job_specs (id, tenant_id, client_id, vuln_id, finding_id, git_token, repo_slug, base_branch, patch_text, poc_curl, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'main', $8, $9, 'pending')"#,
    )
    .bind(spec_id)
    .bind(tenant_id)
    .bind(client_id)
    .bind(vuln_id)
    .bind(finding_id)
    .bind(&token)
    .bind(&repo)
    .bind(&patch)
    .bind(&poc)
    .execute(&mut *tx)
    .await;
    if ins.is_err() {
        let _ = tx.rollback().await;
        return Err("failed to persist heal spec".into());
    }
    let _ = tx.commit().await;
    db::job_queue::enqueue_with_max_attempts(
        state.app_pool.as_ref(),
        tenant_id,
        "auto_heal",
        json!({ "spec_id": spec_id.to_string() }),
        None,
        5,
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(spec_id.to_string())
}

/// `POST /api/integrations/slack/interactivity` — Slack interactive-message callback (signature
/// verified, not JWT). Handles Approve / Dismiss buttons on a heal proposal.
async fn api_slack_interactivity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let secret = std::env::var("WEISSMAN_SLACK_SIGNING_SECRET").unwrap_or_default();
    if secret.trim().is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, "slack interactivity not configured").into_response();
    }
    let ts = headers
        .get("x-slack-request-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sig = headers
        .get("x-slack-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let ts_num: i64 = ts.parse().unwrap_or(0);
    if ts_num == 0 || (now - ts_num).abs() > 300 {
        return (StatusCode::UNAUTHORIZED, "stale request").into_response();
    }
    if !crate::slack_interactivity::verify_slack_signature(&secret, ts, &body, sig) {
        return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
    }

    let body_str = String::from_utf8_lossy(&body);
    let payload_raw = url::form_urlencoded::parse(body_str.as_bytes())
        .find(|(k, _)| k == "payload")
        .map(|(_, v)| v.to_string());
    let Some(payload_raw) = payload_raw else {
        return (StatusCode::OK, Json(json!({ "text": "no payload" }))).into_response();
    };
    let payload: Value = serde_json::from_str(&payload_raw).unwrap_or(Value::Null);
    let Some((action_id, value)) = crate::slack_interactivity::parse_interaction(&payload) else {
        return (StatusCode::OK, Json(json!({ "text": "no action" }))).into_response();
    };

    match crate::slack_interactivity::SlackHealAction::from_action_id(&action_id) {
        crate::slack_interactivity::SlackHealAction::Approve => {
            let Some((tenant_id, client_id, finding_id)) =
                crate::slack_interactivity::verify_action_value(&value)
            else {
                return (
                    StatusCode::OK,
                    Json(json!({ "replace_original": false, "text": "⚠️ Invalid or tampered action." })),
                )
                    .into_response();
            };
            match enqueue_heal_from_slack(&state, tenant_id, client_id, &finding_id).await {
                Ok(job) => (
                    StatusCode::OK,
                    Json(json!({
                        "replace_original": true,
                        "text": format!("✅ Auto-heal approved and queued for `{}` (job {}).", finding_id, job)
                    })),
                )
                    .into_response(),
                Err(e) => (
                    StatusCode::OK,
                    Json(json!({ "replace_original": false, "text": format!("⚠️ Could not start heal: {}", e) })),
                )
                    .into_response(),
            }
        }
        crate::slack_interactivity::SlackHealAction::Dismiss => (
            StatusCode::OK,
            Json(json!({ "replace_original": true, "text": "Auto-heal dismissed." })),
        )
            .into_response(),
        crate::slack_interactivity::SlackHealAction::Unknown => {
            (StatusCode::OK, Json(json!({ "text": "ok" }))).into_response()
        }
    }
}

/// EventBridge / custom forwarder: verify `X-Weissman-Signature: sha256=<hex>` with `WEISSMAN_DECEPTION_WEBHOOK_SECRET`.
async fn api_deception_aws_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    crate::deception_eventbridge::handle_aws_canary_eventbridge(
        state.app_pool.as_ref(),
        state.telemetry_broadcast_tx.as_ref(),
        &headers,
        &body,
        "aws_events_webhook",
    )
    .await
}

/// `POST /api/v1/alerts/aws-canary` — same verification and CRITICAL path as `/api/deception/aws-events`.
async fn api_v1_alerts_aws_canary(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    crate::deception_eventbridge::handle_aws_canary_eventbridge(
        state.app_pool.as_ref(),
        state.telemetry_broadcast_tx.as_ref(),
        &headers,
        &body,
        "aws_canary_alerts_v1",
    )
    .await
}

async fn api_deception_deploy_cloud(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
    Path(client_id): Path<i64>,
    Json(body): Json<DeceptionDeployCloudBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    if body.asset_ids.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "detail": "asset_ids required"}))).into_response();
    }
    let ip = extract_client_ip(&headers, addr);
    let actor = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
    if !crate::security_hardening::destructive_action_authorized(&headers) {
        if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
            let _ = audit_log::insert_audit(
                &mut tx,
                auth.tenant_id,
                Some(auth.user_id),
                &actor,
                "destructive_confirm_denied",
                "deception_deploy_cloud",
                &ip,
            )
            .await;
            let _ = tx.commit().await;
        }
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "detail": "X-Weissman-Destructive-Confirm required for cloud deception deploy"})),
        )
            .into_response();
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let row = sqlx::query(
        "SELECT COALESCE(trim(aws_cross_account_role_arn),'') AS arn, COALESCE(trim(aws_external_id),'') AS ext FROM clients WHERE id = $1",
    )
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let (role_arn, _ext) = match row {
        Some(r) => (
            r.try_get::<String, _>("arn").unwrap_or_default(),
            r.try_get::<String, _>("ext").unwrap_or_default(),
        ),
        None => {
            let _ = tx.rollback().await;
            return (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response();
        }
    };
    let _ = tx.commit().await;
    if role_arn.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "client aws_cross_account_role_arn not configured"})),
        )
            .into_response();
    }

    let deployment_id = uuid::Uuid::new_v4();
    let request_val = match serde_json::to_value(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("serialize request: {}", e)})),
            )
                .into_response();
        }
    };

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let ins = sqlx::query(
        r#"INSERT INTO deception_cloud_deployments (id, tenant_id, client_id, status, request_json)
           VALUES ($1, $2, $3, 'pending', $4)"#,
    )
    .bind(deployment_id)
    .bind(auth.tenant_id)
    .bind(client_id)
    .bind(sqlx::types::Json(request_val))
    .execute(&mut *tx)
    .await;
    if ins.is_err() {
        let _ = tx.rollback().await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "failed to record deployment"})),
        )
            .into_response();
    }
    if let Ok(mut tx2) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let _ = audit_log::insert_audit(
            &mut tx2,
            auth.tenant_id,
            Some(auth.user_id),
            &actor,
            "deception_deploy_cloud_queued",
            &format!("client_id={} deployment_id={}", client_id, deployment_id),
            &ip,
        )
        .await;
        let _ = tx2.commit().await;
    }
    let _ = tx.commit().await;

    let queue_payload = json!({ "deployment_id": deployment_id.to_string() });
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "deception_cloud_deploy",
        queue_payload,
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "deployment_id": deployment_id,
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "Cloud deception deploy queued; poll status_url for result (deployment row tracks pending→deploying→active|failed)",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "deception_deploy", error = %e, "enqueue deception_cloud_deploy failed");
            if let Ok(mut tx3) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
                let _ = sqlx::query(
                    "DELETE FROM deception_cloud_deployments WHERE id = $1 AND tenant_id = $2",
                )
                .bind(deployment_id)
                .bind(auth.tenant_id)
                .execute(&mut *tx3)
                .await;
                let _ = tx3.commit().await;
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}
