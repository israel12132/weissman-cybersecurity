// Aliases for endpoints the React UI expects but that exist under different names today.
// Returning thin pass-throughs keeps both URLs working without duplicating logic.

/// GET /api/system/config — singular alias the SystemConfiguration page calls.
/// Reshapes the `[{key,value,description}]` rows into a flat `{key: value, ...}` object so the
/// frontend can read `config.org_name` style fields directly.
async fn api_system_config_alias(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    // This alias is a GET, so mutation_rbac_middleware never runs. It reads system_configs,
    // which holds integration credentials — gate it to admins, matching the PUT arm.
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
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
            "org_name" | "region" | "support_email" | "logo_url" | "tenant_slug"
            | "timezone" | "language" | "date_format" => "general",
            "mfa_required" | "enforce_scope_strict" | "session_timeout_minutes"
            | "password_min_length" | "allowed_login_ips"
            | "password_max_age" | "password_require_uppercase" | "password_require_numbers"
            | "password_require_special" | "session_timeout" | "max_concurrent_sessions" => "security",
            "default_timeout" | "max_concurrency" | "active_engines"
            | "asm_ports" | "asm_port_timeout_ms" | "auto_retry"
            | "ai_daily_scan_quota" | "ai_heavy_entitled" | "max_retries" => "scanning",
            "slack_webhook_url" | "alert_webhook_url" | "pagerduty_routing_key"
            | "github_token" | "shodan_api_key" | "censys_api_id" | "censys_api_secret"
            | "smtp_host" | "smtp_user" | "smtp_password"
            | "webhook_url" | "siem_type" | "siem_endpoint" | "smtp_server" | "smtp_port" => "integrations",
            "findings_retention_days" | "audit_retention_days" | "scan_logs_retention_days"
            | "scan_results_retention" | "audit_logs_retention" | "findings_retention"
            | "metrics_retention" => "retention",
            "worker_pool" | "scan_concurrency" | "fuzz_qps" | "ws_keepalive_secs"
            | "worker_threads" | "cache_ttl" | "max_memory" | "db_pool_size" => "performance",
            "ai_redteam_endpoint" | "adversarial_strategy" => "scanning",
            _ if key.starts_with("compliance_") => "compliance",
            _ if key.starts_with("framework_") => "compliance",
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

    // Denylist-by-default: any config key that looks like a credential is masked before it
    // leaves the server, so a newly-added secret key is protected without a code change.
    fn is_secret_config_key(key: &str) -> bool {
        let k = key.to_ascii_lowercase();
        k.contains("token")
            || k.contains("secret")
            || k.contains("password")
            || k.contains("webhook")
            || k.contains("routing_key")
            || k.contains("api_key")
            || k.ends_with("_key")
    }

    for r in rows {
        let key: String = r.try_get("key").unwrap_or_default();
        let raw: String = r.try_get("value").unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let v = if is_secret_config_key(&key) && !raw.trim().is_empty() {
            // The SPA treats this sentinel as "unchanged" on write-back, so a masked
            // round-trip does not clobber the stored secret.
            Value::String("••••••••".to_string())
        } else if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
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
        "SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity \
         FROM vulnerabilities \
         WHERE COALESCE(status, 'OPEN') NOT IN ('FALSE_POSITIVE', 'FIXED', 'VERIFIED_FIXED') \
         LIMIT 5000",
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

    // Family-containment roll-up. The canonical control ids (e.g. ISO `A.8`) are parents of the
    // live mapping ids (e.g. `A.8.5`), so an EXACT `live_map.get(id)` never matched and every
    // canonical control silently defaulted to "compliant" — findings could not move the report.
    // Match the same parent/child predicate the gate uses, and default to "not_assessed" (not
    // "compliant") when no live evidence maps to a control, so a lack of evidence never inflates
    // the compliance percentage.
    fn control_ids_related(a: &str, b: &str) -> bool {
        fn is_child(child: &str, parent: &str) -> bool {
            child.len() > parent.len()
                && child.starts_with(parent)
                && matches!(child.as_bytes()[parent.len()], b'.' | b' ' | b'(')
        }
        a == b || is_child(a, b) || is_child(b, a)
    }

    static_rows
        .into_iter()
        .map(|(id, title)| {
            let related: Vec<&crate::compliance_engine::ControlStatusRow> = live_map
                .values()
                .filter(|r| control_ids_related(&r.control_id, id))
                .collect();
            let status = if related.is_empty() {
                "not_assessed".to_string()
            } else if let Some(bad) = related.iter().find(|r| r.status != "compliant") {
                bad.status.clone()
            } else {
                "compliant".to_string()
            };
            crate::compliance_engine::ControlStatusRow {
                control_id: id.to_string(),
                control_title: title.to_string(),
                status,
            }
        })
        .collect()
}

/// Fallback framework catalog, used only when the dynamic `compliance_frameworks` table is
/// unavailable (e.g. before its migration is applied). Mirrors the historical hardcoded list plus
/// CIS (now fully mapped). The authoritative list lives in the database.
///
/// NIST / HIPAA / FedRAMP are intentionally absent: they carry a canonical control set in
/// `static_framework_controls` but no live evidence mapping, so listing them as in-scope would
/// (correctly) void every official artifact through the listed-but-unmapped signal.
const FALLBACK_FRAMEWORKS: &[(&str, &str, &str)] = &[
    (
        "iso27001",
        "ISO/IEC 27001:2022",
        "Information Security Management",
    ),
    ("soc2", "SOC 2 Type II", "Trust Services Criteria"),
    (
        "nis2",
        "NIS 2 Directive",
        "EU Network and Information Security",
    ),
    ("gdpr", "GDPR", "EU General Data Protection Regulation"),
    ("iec62443", "IEC 62443", "OT / Industrial Cybersecurity"),
    ("pci", "PCI DSS 4.0", "Payment Card Industry"),
    ("csa-ccm", "CSA CCM", "Cloud Controls Matrix"),
    (
        "cis",
        "CIS Benchmarks",
        "Center for Internet Security Controls",
    ),
];

/// One enabled row from the dynamic `compliance_frameworks` catalog.
#[derive(Debug, Clone)]
struct ListedFramework {
    slug: String,
    name: String,
    scope: String,
}

/// Load the enabled compliance frameworks from the dynamic catalog, ordered for display.
/// Returns `Err` only on a genuine DB failure (e.g. before the migration lands) so callers can
/// fall back to `FALLBACK_FRAMEWORKS`; `Ok(vec![])` is a legitimately empty catalog (every
/// framework taken out of scope) and MUST NOT resurrect the hardcoded list.
async fn load_listed_frameworks(
    state: &Arc<AppState>,
) -> Result<Vec<ListedFramework>, sqlx::Error> {
    match sqlx::query(
        "SELECT slug, name, scope FROM compliance_frameworks WHERE enabled ORDER BY display_order, slug",
    )
    .fetch_all(state.app_pool.as_ref())
    .await
    {
        Ok(rows) => Ok(rows
            .into_iter()
            .filter_map(|r| {
                Some(ListedFramework {
                    slug: r.try_get::<String, _>("slug").ok()?,
                    name: r.try_get::<String, _>("name").ok()?,
                    scope: r.try_get::<String, _>("scope").ok().unwrap_or_default(),
                })
            })
            .collect()),
        Err(e) => {
            tracing::warn!(target: "compliance", error = %e, "compliance_frameworks catalog load failed; using fallback list");
            Err(e)
        }
    }
}

/// Enabled framework slugs from the dynamic catalog. Falls back to `FALLBACK_FRAMEWORKS` only on a
/// DB error — an empty-but-successful catalog means "no frameworks in scope".
async fn listed_framework_slugs(state: &Arc<AppState>) -> Vec<String> {
    match load_listed_frameworks(state).await {
        Ok(listed) => listed.into_iter().map(|f| f.slug).collect(),
        Err(_) => FALLBACK_FRAMEWORKS
            .iter()
            .map(|(s, _, _)| s.to_string())
            .collect(),
    }
}

fn catalog_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "ok": false, "detail": "Control-mapping catalog unavailable" })),
    )
        .into_response()
}

/// Unified orphaned-control verdict for one framework — the single gate every official compliance
/// artifact passes through. It folds together every signal that voids such an artifact:
///   1. **coverage gap** — a canonical requirement with no covering row in
///      `compliance_control_mappings` (`find_orphaned_controls`);
///   2. **listed-but-unmapped** — a framework the platform lists as in-scope that carries no live
///      control mapping at all (an entire framework of silent rot);
///   3. **dead predicate** — a control in `compliance_mappings` whose every row is structurally
///      dead (`find_dead_predicate_controls`, ported from the parallel integrity work — one gate,
///      not two).
///
/// Fails closed (503) if a catalog cannot be loaded, rather than asserting an unverifiable clean
/// state. `listed` marks whether the framework appears in the enabled dynamic catalog.
async fn compliance_framework_orphans(
    state: &Arc<AppState>,
    framework_slug: &str,
    listed: bool,
) -> Result<Vec<crate::compliance_engine::OrphanedControl>, Response> {
    use crate::compliance_engine::OrphanedControl;
    let expected: Vec<(String, String)> = static_framework_controls(framework_slug)
        .into_iter()
        .map(|(id, title)| (id.to_string(), title.to_string()))
        .collect();
    // An unlisted framework with no canonical control set is out of scope for the gate entirely.
    if expected.is_empty() && !listed {
        return Ok(Vec::new());
    }
    let db_fw = crate::compliance_engine::normalize_framework_slug(framework_slug)
        .unwrap_or_else(|| framework_slug.to_uppercase());

    let control_map_ids: Vec<String> = match crate::compliance_engine::load_control_mappings(
        state.app_pool.as_ref(),
        Some(&db_fw),
    )
    .await
    {
        Ok(m) => m.into_iter().map(|r| r.control_id).collect(),
        Err(_) => return Err(catalog_unavailable()),
    };

    // (1) coverage gap
    let mut orphans = crate::compliance_engine::find_orphaned_controls(&expected, &control_map_ids);

    // (2) carrying no live control mapping at all. This must fire regardless of `listed`:
    // an UNLISTED framework that nonetheless has a canonical control set (nist/hipaa/fedramp
    // via normalize_framework_slug) previously slipped through here — `find_orphaned_controls`
    // returns empty when there are zero mapping ids — and produced a clean "100% compliant"
    // PDF. Treat every canonical control as orphaned so the gate blocks/voids the artifact.
    if control_map_ids.is_empty() {
        if expected.is_empty() {
            orphans.push(OrphanedControl {
                control_id: "*".into(),
                control_title: "Framework is listed but has no live control mapping".into(),
            });
        } else {
            orphans = expected
                .iter()
                .map(|(id, title)| OrphanedControl {
                    control_id: id.clone(),
                    control_title: title.clone(),
                })
                .collect();
        }
    }

    // (3) dead-predicate rot in the finding->control catalog
    let mappings = match crate::compliance_engine::load_mappings(state.app_pool.as_ref()).await {
        Ok(m) => m,
        Err(_) => return Err(catalog_unavailable()),
    };
    let dead = crate::compliance_engine::find_dead_predicate_controls(&mappings, &db_fw);

    Ok(crate::compliance_engine::merge_orphaned_controls(
        orphans, dead,
    ))
}

/// Aggregate orphaned controls across the whole enabled compliance surface, tagged with framework.
/// Gates the cross-framework evidence pack: any listed framework with rot voids the pack.
async fn compliance_orphaned_controls_across_listed(
    state: &Arc<AppState>,
) -> Result<Vec<Value>, Response> {
    let slugs = listed_framework_slugs(state).await;
    let mut out: Vec<Value> = Vec::new();
    for slug in &slugs {
        for o in compliance_framework_orphans(state, slug, true).await? {
            out.push(json!({
                "framework": slug,
                "control_id": o.control_id,
                "control_title": o.control_title,
            }));
        }
    }
    Ok(out)
}

/// GET /api/compliance/frameworks — the supported frameworks, from the dynamic
/// `compliance_frameworks` catalog (falls back to the historical list only if the table is
/// unavailable). `dynamic` reports which source served the list.
async fn api_compliance_frameworks_list(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
) -> Response {
    // Only a DB error falls back to the hardcoded list; an empty catalog is served as-is so an
    // operator who has taken every framework out of scope sees exactly that.
    let (rows, dynamic): (Vec<(String, String, String)>, bool) =
        match load_listed_frameworks(&state).await {
            Ok(listed) => (
                listed
                    .into_iter()
                    .map(|f| (f.slug, f.name, f.scope))
                    .collect(),
                true,
            ),
            Err(_) => (
                FALLBACK_FRAMEWORKS
                    .iter()
                    .map(|(id, name, scope)| (id.to_string(), name.to_string(), scope.to_string()))
                    .collect(),
                false,
            ),
        };
    let out: Vec<Value> = rows
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
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "dynamic": dynamic, "frameworks": out })),
    )
        .into_response()
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
    headers: HeaderMap,
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

    // --- Unified control-mapping enforcement gate ---
    // Coverage gap + listed-but-unmapped + dead-predicate rot, all through one gate/watermark.
    let is_listed = listed_framework_slugs(&state)
        .await
        .iter()
        .any(|s| s == &framework_id);
    let orphaned = match compliance_framework_orphans(&state, &framework_id, is_listed).await {
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
    let lang = report_lang(
        &LangQuery {
            lang: q.get("lang").cloned(),
        },
        &headers,
    );
    let pdf = match crate::pdf_report::build_compliance_framework_pdf_lang(
        &tenant_name,
        framework_label,
        compliance_pct,
        &pdf_controls,
        invalid_orphans.as_deref(),
        lang,
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
