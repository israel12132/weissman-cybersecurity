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

/// GET /api/compliance/frameworks/:framework_id/controls — Minimal placeholder mapping framework
/// → top engine groups so the UI can render a per-framework rollup until the full controls table
/// ships.
async fn api_compliance_frameworks_controls(
    Extension(auth): Extension<AuthContext>,
    Path(framework_id): Path<String>,
) -> Response {
    let _ = auth;
    let controls = match framework_id.as_str() {
        "iso27001" => vec![
            ("A.5",   "Organizational controls"),
            ("A.8",   "Asset management"),
            ("A.9",   "Access control",),
            ("A.10",  "Cryptography"),
            ("A.12",  "Operations security"),
            ("A.13",  "Communications security"),
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
        "gdpr"     => vec![("Art.32", "Security of processing")],
        "iec62443" => vec![("FR-1", "Identification and authentication"), ("FR-3", "System integrity")],
        "pci"      => vec![("4.1", "Strong cryptography on public networks")],
        "csa-ccm"  => vec![("DCS-04", "Data classification")],
        _ => vec![],
    };
    if controls.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "detail": format!("Unknown framework '{framework_id}'") })),
        )
            .into_response();
    }
    let out: Vec<Value> = controls
        .into_iter()
        .map(|(id, title)| json!({ "id": id, "title": title }))
        .collect();
    (StatusCode::OK, Json(json!({ "ok": true, "controls": out }))).into_response()
}
