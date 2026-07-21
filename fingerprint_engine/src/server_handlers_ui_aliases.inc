// Aliases for endpoints the React UI expects but that exist under different names today.
// Returning thin pass-throughs keeps both URLs working without duplicating logic.

/// GET /api/system/config — singular alias the SystemConfiguration page calls.
/// Reshapes the `[{key,value,description}]` rows into a flat `{key: value, ...}` object so the
/// frontend can read `config.org_name` style fields directly.
async fn api_system_config_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = crate::db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable"})),
        )
            .into_response();
    };
    let rows = sqlx::query("SELECT key, value FROM system_configs")
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;
    // Bucket each system_configs row into one of the seven tabs the UI renders
    // (general / security / scanning / integrations / retention / performance / compliance).
    // Anything we don't have a default place for goes under `extra`.
    fn bucket_for(key: &str) -> &'static str {
        match key {
            "org_name" | "region" | "support_email" | "logo_url" | "tenant_slug" => "general",
            "mfa_required" | "enforce_scope_strict" | "session_timeout_minutes"
            | "password_min_length" | "allowed_login_ips" => "security",
            "default_timeout" | "max_concurrency" | "active_engines"
            | "asm_ports" | "asm_port_timeout_ms" | "auto_retry"
            | "ai_daily_scan_quota" | "ai_heavy_entitled" => "scanning",
            "slack_webhook_url" | "alert_webhook_url" | "pagerduty_routing_key"
            | "github_token" | "shodan_api_key" | "censys_api_id" | "censys_api_secret"
            | "smtp_host" | "smtp_user" | "smtp_password" => "integrations",
            "findings_retention_days" | "audit_retention_days" | "scan_logs_retention_days" => "retention",
            "worker_pool" | "scan_concurrency" | "fuzz_qps" | "ws_keepalive_secs" => "performance",
            "ai_redteam_endpoint" | "adversarial_strategy" => "scanning",
            _ if key.starts_with("compliance_") => "compliance",
            _ => "extra",
        }
    }

    let mut buckets: std::collections::HashMap<&'static str, serde_json::Map<String, Value>> =
        std::collections::HashMap::new();
    for label in [
        "general",
        "security",
        "scanning",
        "integrations",
        "retention",
        "performance",
        "compliance",
        "extra",
    ] {
        buckets.insert(label, serde_json::Map::new());
    }

    for r in rows {
        let key: String = r.try_get("key").unwrap_or_default();
        let raw: String = r.try_get("value").unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let v = if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
            parsed
        } else if raw.eq_ignore_ascii_case("true") || raw.eq_ignore_ascii_case("false") {
            Value::Bool(raw.eq_ignore_ascii_case("true"))
        } else if let Ok(n) = raw.parse::<i64>() {
            Value::Number(n.into())
        } else {
            Value::String(raw)
        };
        let bucket = bucket_for(&key);
        if let Some(b) = buckets.get_mut(bucket) {
            b.insert(key, v);
        }
    }

    // Seed sensible defaults so the first-paint inputs are not `undefined`.
    let general = buckets.get_mut("general").unwrap();
    for (k, v) in [
        ("org_name", Value::String(String::new())),
        ("region", Value::String("EU-West".to_string())),
        ("support_email", Value::String(String::new())),
        ("logo_url", Value::String(String::new())),
    ] {
        general.entry(k.to_string()).or_insert(v);
    }
    let scanning = buckets.get_mut("scanning").unwrap();
    for (k, v) in [
        ("default_timeout", json!(300)),
        ("max_concurrency", json!(10)),
        ("auto_retry", Value::Bool(false)),
    ] {
        scanning.entry(k.to_string()).or_insert(v);
    }
    let security = buckets.get_mut("security").unwrap();
    for (k, v) in [
        ("mfa_required", Value::Bool(false)),
        ("enforce_scope_strict", Value::Bool(true)),
        ("session_timeout_minutes", json!(15)),
    ] {
        security.entry(k.to_string()).or_insert(v);
    }

    let mut out = serde_json::Map::new();
    for (label, bucket) in buckets {
        out.insert(label.to_string(), Value::Object(bucket));
    }
    (StatusCode::OK, Json(Value::Object(out))).into_response()
}

/// PUT /api/system/config — accepts either:
///   * the nested-by-tab shape returned by GET, OR
///   * a flat `{key:value}` object, OR
///   * an array of `[{key,value}]` rows
/// and forwards the flattened set to the legacy POST handler.
async fn api_system_config_put_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<Value>,
) -> Response {
    let mut flat: Vec<Value> = Vec::new();

    let stringify = |v: &Value| -> String {
        match v {
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::Null => String::new(),
            other => other.to_string(),
        }
    };

    if let Some(arr) = body.as_array() {
        flat = arr.clone();
    } else if let Some(map) = body.as_object() {
        let nested_keys = [
            "general",
            "security",
            "scanning",
            "integrations",
            "retention",
            "performance",
            "compliance",
            "extra",
        ];
        let looks_nested = map
            .keys()
            .all(|k| nested_keys.iter().any(|nk| nk == k));
        if looks_nested {
            for (_bucket, inner) in map {
                if let Some(obj) = inner.as_object() {
                    for (k, v) in obj {
                        flat.push(json!({ "key": k, "value": stringify(v) }));
                    }
                }
            }
        } else {
            for (k, v) in map {
                flat.push(json!({ "key": k, "value": stringify(v) }));
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "Expected JSON object or array of {key,value}"})),
        )
            .into_response();
    }

    api_system_configs_post(State(state), Extension(auth), Json(Value::Array(flat))).await
}

/// Static control catalog for frameworks not yet fully mapped in compliance_mappings.
fn static_framework_controls(framework_id: &str) -> Vec<(&'static str, &'static str)> {
    match framework_id {
        "iso27001" => vec![
            ("A.5", "Organizational controls"),
            ("A.8", "Asset management"),
            ("A.9", "Access control"),
            ("A.10", "Cryptography"),
            ("A.12", "Operations security"),
            ("A.13", "Communications security"),
        ],
        "soc2" => vec![
            ("CC6.1", "Logical and physical access controls"),
            ("CC6.6", "Cloud network security"),
            ("CC6.7", "Cryptographic controls"),
            ("CC7.1", "Detection and monitoring"),
        ],
        "nis2" => vec![
            ("Art.21(2)(d)", "Supply-chain security"),
            ("Art.21(2)(h)", "Use of cryptography"),
            ("Art.21(2)(i)", "Access control"),
        ],
        "gdpr" => vec![("Art.32", "Security of processing")],
        "iec62443" => vec![
            ("FR-1", "Identification and authentication"),
            ("FR-3", "System integrity"),
        ],
        "pci" | "pci-dss" => vec![("4.1", "Strong cryptography on public networks")],
        "csa-ccm" => vec![("DCS-04", "Data classification")],
        "cis" => vec![
            ("CIS 1", "Inventory and control of enterprise assets"),
            ("CIS 3", "Data protection"),
            ("CIS 6", "Access control management"),
        ],
        "nist" | "nist-csf" => vec![
            ("ID.AM", "Asset management"),
            ("PR.AC", "Identity management and access control"),
            ("DE.CM", "Security continuous monitoring"),
        ],
        "hipaa" => vec![
            ("164.312(a)", "Access control"),
            ("164.312(e)", "Transmission security"),
        ],
        "fedramp" => vec![
            ("AC-2", "Account management"),
            ("SC-13", "Cryptographic protection"),
        ],
        _ => vec![],
    }
}

fn framework_slug_known(framework_id: &str) -> bool {
    crate::compliance_engine::normalize_framework_slug(framework_id).is_some()
        || !static_framework_controls(framework_id).is_empty()
}

async fn load_compliance_evidence(
    state: &Arc<AppState>,
    tenant_id: i64,
) -> Result<
    (
        String,
        Vec<crate::compliance_engine::ComplianceMappingRow>,
        Vec<String>,
        Vec<(String, String, String)>,
    ),
    (),
> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(&state.app_pool, tenant_id).await else {
        return Err(());
    };
    let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "Tenant".to_string());
    let mappings = crate::compliance_engine::load_mappings(&mut *tx)
        .await
        .map_err(|_| ())?;
    let cloud_rules: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT rule_id FROM cloud_scan_findings",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let vuln_rows = sqlx::query(
        "SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let vulns: Vec<(String, String, String)> = vuln_rows
        .into_iter()
        .filter_map(|r| {
            Some((
                r.try_get::<String, _>("source").ok()?,
                r.try_get::<String, _>("title").ok()?,
                r.try_get::<String, _>("severity").ok()?,
            ))
        })
        .collect();
    Ok((tenant_name, mappings, cloud_rules, vulns))
}

fn merge_control_statuses(
    framework_id: &str,
    mappings: &[crate::compliance_engine::ComplianceMappingRow],
    cloud_rules: &[String],
    vulns: &[(String, String, String)],
) -> Vec<crate::compliance_engine::ControlStatusRow> {
    let fw_db = crate::compliance_engine::normalize_framework_slug(framework_id)
        .unwrap_or_else(|| framework_id.to_uppercase());
    let live =
        crate::compliance_engine::compute_control_statuses(mappings, &fw_db, cloud_rules, vulns);
    let live_map: std::collections::HashMap<String, crate::compliance_engine::ControlStatusRow> =
        live
            .into_iter()
            .map(|r| (r.control_id.clone(), r))
            .collect();

    let static_rows = static_framework_controls(framework_id);
    if static_rows.is_empty() && live_map.is_empty() {
        return vec![];
    }
    if static_rows.is_empty() {
        let mut only_live: Vec<_> = live_map.into_values().collect();
        only_live.sort_by(|a, b| a.control_id.cmp(&b.control_id));
        return only_live;
    }

    static_rows
        .into_iter()
        .map(|(id, title)| {
            if let Some(row) = live_map.get(id) {
                row.clone()
            } else {
                crate::compliance_engine::ControlStatusRow {
                    control_id: id.to_string(),
                    control_title: title.to_string(),
                    status: "compliant".into(),
                }
            }
        })
        .collect()
}

/// UI framework slugs that carry a canonical control set (see `static_framework_controls`). These
/// are the frameworks a compliance artifact can be reconciled against for orphaned controls.
const COMPLIANCE_UI_SLUGS: &[&str] = &[
    "iso27001", "soc2", "nis2", "gdpr", "iec62443", "pci", "csa-ccm", "cis", "nist", "hipaa",
    "fedramp",
];

/// Orphaned controls for one framework slug: canonical requirements with no covering row in the
/// live control-mapping catalog. Returns a 503 `Response` if the catalog cannot be loaded (fail
/// closed on the artifact rather than assert an unverifiable clean state). An unsupported or
/// not-yet-onboarded framework yields an empty list.
async fn compliance_orphaned_controls(
    state: &Arc<AppState>,
    framework_slug: &str,
) -> Result<Vec<crate::compliance_engine::OrphanedControl>, Response> {
    let expected: Vec<(String, String)> = static_framework_controls(framework_slug)
        .into_iter()
        .map(|(id, title)| (id.to_string(), title.to_string()))
        .collect();
    if expected.is_empty() {
        return Ok(Vec::new());
    }
    let db_fw = crate::compliance_engine::normalize_framework_slug(framework_slug)
        .unwrap_or_else(|| framework_slug.to_uppercase());
    let mapping_ids: Vec<String> = match crate::compliance_engine::load_control_mappings(
        state.app_pool.as_ref(),
        Some(&db_fw),
    )
    .await
    {
        Ok(m) => m.into_iter().map(|r| r.control_id).collect(),
        Err(_) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "ok": false, "detail": "Control-mapping catalog unavailable" })),
            )
                .into_response());
        }
    };
    Ok(crate::compliance_engine::find_orphaned_controls(
        &expected,
        &mapping_ids,
    ))
}

/// Aggregate orphaned controls across several framework slugs, tagged with the owning framework.
/// Used to gate the cross-framework evidence pack: its validity depends on the whole live-mapping
/// catalog being consistent, so any onboarded framework with gaps voids the pack.
async fn compliance_orphaned_controls_across(
    state: &Arc<AppState>,
    slugs: &[&str],
) -> Result<Vec<Value>, Response> {
    let mut out: Vec<Value> = Vec::new();
    for slug in slugs {
        for o in compliance_orphaned_controls(state, slug).await? {
            out.push(json!({
                "framework": slug,
                "control_id": o.control_id,
                "control_title": o.control_title,
            }));
        }
    }
    Ok(out)
}

/// GET /api/compliance/frameworks — UI expects a list of supported frameworks. Map from posture.
async fn api_compliance_frameworks_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    // Until the dedicated frameworks table ships, derive the list from finding compliance tags
    // and the well-known tag taxonomy used by engine_probes::default_compliance().
    let _ = state;
    let _ = auth;
    let frameworks = vec![
        ("iso27001", "ISO/IEC 27001:2022", "Information Security Management"),
        ("soc2",      "SOC 2 Type II",       "Trust Services Criteria"),
        ("nis2",      "NIS 2 Directive",     "EU Network and Information Security"),
        ("gdpr",      "GDPR",                "EU General Data Protection Regulation"),
        ("iec62443",  "IEC 62443",           "OT / Industrial Cybersecurity"),
        ("pci",       "PCI DSS 4.0",         "Payment Card Industry"),
        ("csa-ccm",   "CSA CCM",             "Cloud Controls Matrix"),
    ];
    let out: Vec<Value> = frameworks
        .into_iter()
        .map(|(id, name, scope)| {
            json!({
                "id": id,
                "name": name,
                "scope": scope,
                "controls_url": format!("/api/compliance/frameworks/{}/controls", id),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "ok": true, "frameworks": out }))).into_response()
}

/// GET /api/compliance/frameworks/:framework_id/controls — live status from mapped findings.
async fn api_compliance_frameworks_controls(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(framework_id): Path<String>,
) -> Response {
    if !framework_slug_known(&framework_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": format!("Unknown framework '{framework_id}'") })),
        )
            .into_response();
    }
    let Ok((_tenant, mappings, cloud_rules, vulns)) =
        load_compliance_evidence(&state, auth.tenant_id).await
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ok": false, "detail": "Database unavailable" })),
        )
            .into_response();
    };
    let rows = merge_control_statuses(&framework_id, &mappings, &cloud_rules, &vulns);
    if rows.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": format!("Unknown framework '{framework_id}'") })),
        )
            .into_response();
    }
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.control_id,
                "title": r.control_title,
                "status": r.status,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "ok": true, "controls": out }))).into_response()
}

/// GET /api/compliance/frameworks/:framework_id/report — PDF audit report (application/pdf).
///
/// Enforcement: a report is refused (409) when the framework has orphaned controls — compliance
/// requirements with no live control mapping. `?acknowledge_inconsistent=true` downgrades the
/// refusal to a watermarked (VOID) copy for internal triage.
async fn api_compliance_frameworks_report(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(framework_id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if !framework_slug_known(&framework_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": format!("Unknown framework '{framework_id}'") })),
        )
            .into_response();
    }
    let Ok((tenant_name, mappings, cloud_rules, vulns)) =
        load_compliance_evidence(&state, auth.tenant_id).await
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ok": false, "detail": "Database unavailable" })),
        )
            .into_response();
    };
    let rows = merge_control_statuses(&framework_id, &mappings, &cloud_rules, &vulns);
    if rows.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": format!("Unknown framework '{framework_id}'") })),
        )
            .into_response();
    }

    // --- Live control-mapping enforcement gate (orphaned controls only) ---
    let orphaned = match compliance_orphaned_controls(&state, &framework_id).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    let acknowledged = q
        .get("acknowledge_inconsistent")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let invalid_orphans: Option<Vec<(String, String)>> =
        match crate::compliance_engine::report_gate(&orphaned, acknowledged) {
            crate::compliance_engine::ReportGate::Allow => None,
            crate::compliance_engine::ReportGate::Block => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "ok": false,
                        "reason": "inconsistent_control_mappings",
                        "detail": "Report generation blocked: compliance requirements have no live control mapping.",
                        "orphaned_controls": orphaned,
                        "orphaned_control_count": orphaned.len(),
                        "hint": "Re-request with acknowledge_inconsistent=true for a watermarked (VOID) copy for internal triage.",
                    })),
                )
                    .into_response();
            }
            crate::compliance_engine::ReportGate::Watermark => Some(
                orphaned
                    .iter()
                    .map(|o| (o.control_id.clone(), o.control_title.clone()))
                    .collect(),
            ),
        };

    let compliant = rows.iter().filter(|r| r.status == "compliant").count();
    let compliance_pct = if rows.is_empty() {
        100u8
    } else {
        ((compliant as f64 / rows.len() as f64) * 100.0).round().clamp(0.0, 100.0) as u8
    };
    let pdf_controls: Vec<(String, String, bool)> = rows
        .iter()
        .map(|r| {
            (
                r.control_id.clone(),
                r.control_title.clone(),
                r.status == "compliant",
            )
        })
        .collect();
    let framework_label = crate::compliance_engine::framework_display_name(&framework_id);
    let pdf = match crate::pdf_report::build_compliance_framework_pdf(
        &tenant_name,
        framework_label,
        compliance_pct,
        &pdf_controls,
        invalid_orphans.as_deref(),
    ) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "detail": scrub_internal_error(&e) })),
            )
                .into_response();
        }
    };
    let safe_id: String = framework_id
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    let filename = if invalid_orphans.is_some() {
        format!("{safe_id}-compliance-report-VOID.pdf")
    } else {
        format!("{safe_id}-compliance-report.pdf")
    };
    let mut res = Response::new(Body::from(pdf));
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
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
