fn dedupe_findings(findings: Vec<Value>) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(findings.len());
    for f in findings {
        let key = format!(
            "{}|{}|{}",
            f.get("category").and_then(Value::as_str).unwrap_or(""),
            f.get("title").and_then(Value::as_str).unwrap_or(""),
            f.get("evidence")
                .and_then(|e| e.get("url"))
                .and_then(Value::as_str)
                .unwrap_or("")
        );
        if seen.insert(key) {
            out.push(f);
        }
    }
    out
}

fn build_coverage_manifest(probe_flags: &[(&str, bool)], findings_count: usize) -> Value {
    let enabled: usize = probe_flags.iter().filter(|(_, on)| *on).count();
    let total = probe_flags.len();
    let dimensions = [
        "unkeyed_input_poisoning",
        "cache_key_oracles",
        "normalization_fractures",
        "method_range_primitives",
        "protocol_schism",
        "client_hint_fractures",
        "session_auth_isolation",
        "redirect_poisoning",
        "cache_deception",
        "cdn_hardening_intel",
        "conditional_validators",
        "edge_directive_schisms",
        "duplicate_header_oracles",
    ];
    let sealed = enabled >= total;
    json!({
        "engine_version": "cache_posture_v11_sealed",
        "probe_categories_total": total,
        "probes_enabled": enabled,
        "findings_observed": findings_count,
        "competitive_dimensions": dimensions,
        "coverage_complete": sealed,
        "sealed_complete": sealed,
        "competitive_parity": if sealed { "world_class_complete" } else { "partial" },
        "enabled_probes": probe_flags.iter().filter(|(_, on)| *on).map(|(n, _)| *n).collect::<Vec<_>>(),
    })
}

fn build_competitive_parity_index(probe_flags: &[(&str, bool)], beyond_score: u32) -> u32 {
    let enabled = probe_flags.iter().filter(|(_, on)| *on).count() as u32;
    let total = probe_flags.len().max(1) as u32;
    let breadth = (enabled * 100 / total).min(100);
    breadth.min(beyond_score).min(100)
}

fn compute_poison_window_seconds(findings: &[Value]) -> u64 {
    findings
        .iter()
        .filter_map(|f| {
            f.get("evidence")
                .and_then(|e| e.get("cache_ttl_seconds"))
                .and_then(Value::as_u64)
        })
        .max()
        .unwrap_or(0)
}

fn build_top_primitives(findings: &[Value]) -> Vec<Value> {
    let mut ranked: Vec<(u8, f64, Value)> = Vec::new();
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        let exp = f.get("exposure").and_then(Value::as_str).unwrap_or("");
        if !matches!(exp, "confirmed" | "suspected" | "reflected")
            && !matches!(sev, "critical" | "high")
        {
            continue;
        }
        let conf = f.get("confidence").and_then(Value::as_f64).unwrap_or(0.5);
        let score = severity_rank(sev) as f64 * 10.0
            + if exp == "confirmed" { 20.0 } else { 0.0 }
            + conf * 5.0;
        ranked.push((
            severity_rank(sev),
            score,
            json!({
                "title": f.get("title").and_then(Value::as_str).unwrap_or(""),
                "severity": sev,
                "exposure": exp,
                "category": f.get("category").and_then(Value::as_str).unwrap_or(""),
                "confidence": conf,
                "url": f.get("evidence").and_then(|e| e.get("url")).and_then(Value::as_str).unwrap_or(""),
            }),
        ));
    }
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked.into_iter().take(8).map(|(_, _, v)| v).collect()
}

fn build_compliance_map(findings: &[Value]) -> Value {
    let mut cwe: BTreeSet<String> = BTreeSet::new();
    let mut owasp: BTreeSet<String> = BTreeSet::new();
    cwe.insert("CWE-444".to_string()); // HTTP Request Smuggling adjacent / cache poisoning class
    owasp.insert("A05:2021 Security Misconfiguration".to_string());
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        let exp = f.get("exposure").and_then(Value::as_str).unwrap_or("");
        match cat {
            "cache_poisoning" | "redirect_cache" if exp == "confirmed" => {
                cwe.insert("CWE-349".to_string());
                owasp.insert("Web Cache Poisoning".to_string());
            }
            "cache_deception" => {
                cwe.insert("CWE-525".to_string());
                owasp.insert("Web Cache Deception".to_string());
            }
            "auth_cache" | "cookie_cache" => {
                cwe.insert("CWE-613".to_string());
            }
            _ => {}
        }
    }
    json!({
        "cwe": cwe.iter().collect::<Vec<_>>(),
        "owasp": owasp.iter().collect::<Vec<_>>(),
        "mitre_attack": ["T1557"],
    })
}

fn build_defense_controls(findings: &[Value]) -> Value {
    let mut controls: BTreeSet<String> = BTreeSet::new();
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        if !matches!(sev, "critical" | "high" | "medium") {
            continue;
        }
        match cat {
            "cache_poisoning" | "redirect_cache" => {
                controls.insert("strip_x_forwarded_and_forwarded_at_edge".to_string());
                controls.insert("include_unkeyed_headers_in_cache_key".to_string());
                controls.insert("never_reflect_untrusted_host_into_body".to_string());
            }
            "cache_key_oracle" | "cache_normalization" => {
                controls.insert("normalize_cache_key_canonical_form".to_string());
                controls.insert("include_all_query_params_in_cache_key".to_string());
            }
            "cache_method" => {
                controls.insert("key_http_method_in_cache".to_string());
            }
            "auth_cache" | "cookie_cache" => {
                controls.insert("vary_authorization_and_cookie".to_string());
                controls.insert("no_store_on_session_responses".to_string());
            }
            "cache_hardening" => {
                controls.insert("complete_vary_header".to_string());
                controls.insert("respect_origin_no_store_at_cdn".to_string());
            }
            "cache_deception" => {
                controls.insert("cache_by_content_type_not_url_suffix".to_string());
            }
            "cache_protocol" => {
                controls.insert("key_protocol_in_cache_or_disable_h2_cache".to_string());
            }
            _ => {}
        }
    }
    json!({
        "controls_required": controls.iter().collect::<Vec<_>>(),
        "control_count": controls.len(),
    })
}

fn build_risk_matrix(findings: &[Value]) -> Value {
    let mut map = serde_json::Map::new();
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let cat = f
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("other")
            .to_string();
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("info");
        let entry = map
            .entry(cat)
            .or_insert_with(|| json!({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}));
        if let Some(obj) = entry.as_object_mut() {
            if let Some(n) = obj.get_mut(sev) {
                if let Some(v) = n.as_u64() {
                    *n = json!(v + 1);
                }
            }
        }
    }
    Value::Object(map)
}

fn build_cdn_playbook(vendor: Option<&str>, findings: &[Value]) -> Value {
    let has_confirmed = findings.iter().any(|f| {
        f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });
    let mut steps: Vec<String> = Vec::new();
    match vendor.unwrap_or("generic") {
        "Cloudflare" => {
            steps.push("Cloudflare: enable 'Cache Key' customization — include all query params; add X-Forwarded-Host to cache key or strip via Transform Rules.".to_string());
            steps.push("Cloudflare: use Cache Rules to bypass cache on Set-Cookie / Authorization responses.".to_string());
        }
        "AWS CloudFront" => {
            steps.push("CloudFront: configure Origin Request / Cache Policies to whitelist only required headers/query strings in the cache key.".to_string());
            steps.push("CloudFront: enable CachingDisabled policy on dynamic behaviors; never forward X-Forwarded-Host to origin.".to_string());
        }
        "Fastly" => {
            steps.push("Fastly: define VCL recv to strip X-Forwarded-* before hash; use req.http.Fastly-FF checks.".to_string());
            steps.push("Fastly: set beresp.cacheable = false when Set-Cookie present.".to_string());
        }
        "Akamai" => {
            steps.push("Akamai: use Cache ID Modification to include all query parameters; enable SureRoute only on static assets.".to_string());
        }
        _ => {
            steps.push("Generic CDN: treat cache key as trust boundary — key every input that affects the response.".to_string());
        }
    }
    if has_confirmed {
        steps.insert(
            0,
            "URGENT: confirmed cache poisoning primitive — purge affected cache namespace and deploy header-stripping at edge before next scan.".to_string(),
        );
    }
    json!({
        "vendor": vendor.unwrap_or("generic"),
        "steps": steps,
    })
}

fn compute_exploitability_index(findings: &[Value]) -> u32 {
    let mut score = 0u32;
    for f in findings {
        if f.get("summary").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let exp = f.get("exposure").and_then(Value::as_str).unwrap_or("");
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        score += match (exp, sev) {
            ("confirmed", "critical") => 28,
            ("confirmed", "high") => 20,
            ("confirmed", _) => 14,
            ("suspected", "critical") | ("suspected", "high") => 12,
            ("reflected", "high") | ("reflected", "critical") => 10,
            ("variant", "high") | ("variant", "critical") => 8,
            (_, "critical") => 15,
            (_, "high") => 8,
            (_, "medium") => 4,
            _ => 1,
        };
    }
    score.min(100)
}

fn count_confirmed_primitives(findings: &[Value]) -> u32 {
    findings
        .iter()
        .filter(|f| {
            f.get("summary").and_then(Value::as_bool) != Some(true)
                && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
        })
        .count() as u32
}

fn build_attack_chains(findings: &[Value], any_cache: bool) -> Vec<Value> {
    let mut chains = Vec::new();
    let has_confirmed_poison = findings.iter().any(|f| {
        f.get("category").and_then(Value::as_str) == Some("cache_poisoning")
            && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });
    let has_redirect = findings.iter().any(|f| {
        f.get("category").and_then(Value::as_str) == Some("redirect_cache")
            && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });
    let has_auth_bleed = findings.iter().any(|f| {
        f.get("category").and_then(Value::as_str) == Some("auth_cache")
            && matches!(
                f.get("exposure").and_then(Value::as_str),
                Some("confirmed" | "suspected")
            )
    });
    let has_deception = findings.iter().any(|f| {
        f.get("category").and_then(Value::as_str) == Some("cache_deception")
            && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });

    if any_cache && has_confirmed_poison {
        chains.push(json!({
            "id": "mass_cache_poison",
            "title": "Mass user cache poisoning",
            "severity": "critical",
            "description": "Confirmed unkeyed-input poisoning on a shared cache — any visitor receives the attacker-primed response.",
            "mitre": "T1557"
        }));
    }
    if has_redirect {
        chains.push(json!({
            "id": "redirect_hijack",
            "title": "Sitewide redirect hijack",
            "severity": "critical",
            "description": "Cached 3xx with attacker-controlled Location — victims are redirected to a malicious host on every cache HIT.",
            "mitre": "T1557"
        }));
    }
    if has_auth_bleed && any_cache {
        chains.push(json!({
            "id": "auth_session_bleed",
            "title": "Authenticated session bleed via CDN",
            "severity": "critical",
            "description": "Authorization-dependent responses are cacheable without Vary — API/session data may be served to anonymous users.",
            "mitre": "T1557"
        }));
    }
    if has_deception {
        chains.push(json!({
            "id": "cache_deception_harvest",
            "title": "Web cache deception data harvest",
            "severity": "high",
            "description": "Dynamic authenticated pages cached under static suffixes — attacker reads victim session from shared cache.",
            "mitre": "T1557"
        }));
    }
    let has_host_poison = findings.iter().any(|f| {
        f.get("title")
            .and_then(Value::as_str)
            .map(|t| t.contains("Host header override"))
            .unwrap_or(false)
            && f.get("exposure").and_then(Value::as_str) == Some("confirmed")
    });
    if any_cache && has_host_poison {
        chains.push(json!({
            "id": "host_header_mass_poison",
            "title": "Host-header cache slot hijack",
            "severity": "critical",
            "description": "Confirmed Host header override poisoning — CDN cache key ignores Host, attacker poisons the shared slot for the URL path.",
            "mitre": "T1557"
        }));
    }
    chains
}

fn build_probe_manifest(enabled: &[(&str, bool)]) -> Value {
    let enabled_list: Vec<&str> = enabled.iter().filter(|(_, on)| *on).map(|(n, _)| *n).collect();
    json!({
        "probes_enabled": enabled_list.len(),
        "probes": enabled_list,
        "engine_version": "cache_posture_v11_sealed",
    })
}

#[derive(Clone, Copy)]
struct ProbeToggles {
    fingerprint: bool,
    unkeyed: bool,
    query_unkeyed: bool,
    cookie_cache: bool,
    hardening: bool,
    fat_get: bool,
    method_confusion: bool,
    range_poisoning: bool,
    normalization: bool,
    cache_key_oracle: bool,
    h2_schism: bool,
    encoding_vary: bool,
    method_override: bool,
    authorization_cache: bool,
    redirect_poisoning: bool,
    query_order: bool,
    cdn_schism: bool,
    user_agent_vary: bool,
    tracking_oracle: bool,
    vary_incomplete: bool,
    stale_revalidate: bool,
    accept_vary: bool,
    post_cache: bool,
    immutable_dynamic: bool,
    etag_injection: bool,
    case_header: bool,
    sec_fetch: bool,
    save_data: bool,
    options_cache: bool,
    pragma_oracle: bool,
    forwarded_rfc7239: bool,
    host_header: bool,
    edge_no_store: bool,
    vary_star: bool,
    link_header: bool,
    duplicate_query: bool,
    accept_lang_order: bool,
    if_none_match: bool,
    if_modified_since: bool,
    duplicate_header: bool,
    only_if_cached: bool,
    x_requested_with: bool,
    prefer_vary: bool,
    alt_svc_h3: bool,
    s_maxage_schism: bool,
    brotli_vary: bool,
    sec_ch_ua: bool,
    forwarded_prefix: bool,
    set_cookie_cache_bleed: bool,
    stale_if_error: bool,
    sec_ch_viewport: bool,
    trailing_dot_host: bool,
    protocol_relative_redirect: bool,
    deception: bool,
}

struct PathScanResult {
    findings: Vec<Value>,
    cacheable: bool,
    vendor: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn scan_one_path(
    client: reqwest::Client,
    url: String,
    target: String,
    env: PathEnv,
    toggles: ProbeToggles,
    max_tier: u8,
    header_fanout: usize,
    include_info: bool,
    timeout_ms: u64,
    query_param: String,
    header_set: Vec<(String, HeaderKind)>,
    exts: Vec<String>,
) -> PathScanResult {
    let mut findings = Vec::new();
    let mut cacheable = false;
    let mut vendor = None;
    let mut sig = CacheSignal::default();

    if toggles.fingerprint {
        let (fps, s) = probe_fingerprint(&client, &url, &target).await;
        sig = s;
        if sig.cacheable {
            cacheable = true;
            if sig.vendor.is_some() {
                vendor = sig.vendor.clone();
            }
        }
        for f in fps {
            let sev = f.get("severity").and_then(Value::as_str).unwrap_or("info");
            if include_info || sev != "info" {
                findings.push(f);
            }
        }
    }
    if toggles.unkeyed {
        findings.extend(
            probe_unkeyed_headers(&client, &url, &target, &env, &header_set, &sig, header_fanout).await,
        );
    }
    if toggles.query_unkeyed {
        findings.extend(probe_query_unkeyed(&client, &url, &target, &sig, &query_param).await);
    }
    if toggles.cookie_cache {
        findings.extend(probe_cookie_cache(&client, &url, &target, &sig).await);
    }
    if toggles.hardening {
        findings.extend(probe_cache_hardening(&client, &url, &target, &sig).await);
    }
    if toggles.fat_get && max_tier >= 2 {
        findings.extend(probe_fat_get(&client, &url, &target, &sig).await);
    }
    if toggles.method_confusion && max_tier >= 2 {
        findings.extend(probe_method_confusion(&client, &url, &target, &env, &sig).await);
    }
    if toggles.range_poisoning && max_tier >= 2 {
        findings.extend(probe_range_poisoning(&client, &url, &target, &env, &sig).await);
    }
    if toggles.normalization && max_tier >= 3 {
        findings.extend(probe_normalization(&client, &url, &target, &env, &sig).await);
    }
    if toggles.cache_key_oracle && max_tier >= 3 {
        findings.extend(probe_cache_key_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.h2_schism && max_tier >= 2 {
        findings.extend(probe_h2_cache_schism(timeout_ms, &url, &target, &sig).await);
    }
    if toggles.encoding_vary && max_tier >= 2 {
        findings.extend(probe_encoding_vary(&client, &url, &target, &sig).await);
    }
    if toggles.method_override && max_tier >= 2 {
        findings.extend(probe_method_override(&client, &url, &target, &sig).await);
    }
    if toggles.authorization_cache && max_tier >= 2 {
        findings.extend(probe_authorization_cache(&client, &url, &target, &sig).await);
    }
    if toggles.redirect_poisoning && max_tier >= 2 {
        findings.extend(probe_redirect_poisoning(&client, &url, &target, &env, &sig).await);
    }
    if toggles.query_order && max_tier >= 3 {
        findings.extend(probe_query_order_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.cdn_schism {
        findings.extend(probe_cdn_origin_cache_schism(&client, &url, &target, &sig).await);
    }
    if toggles.user_agent_vary && max_tier >= 2 {
        findings.extend(probe_user_agent_vary(&client, &url, &target, &sig).await);
    }
    if toggles.tracking_oracle && max_tier >= 2 {
        findings.extend(probe_tracking_param_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.vary_incomplete && max_tier >= 2 {
        findings.extend(probe_vary_incomplete(&client, &url, &target, &sig).await);
    }
    if toggles.stale_revalidate {
        findings.extend(probe_stale_revalidate_risk(&client, &url, &target, &sig).await);
    }
    if toggles.accept_vary && max_tier >= 2 {
        findings.extend(probe_accept_vary(&client, &url, &target, &sig).await);
    }
    if toggles.post_cache && max_tier >= 3 {
        findings.extend(probe_post_cache_oracle(&client, &url, &target, &sig).await);
    }
    if toggles.immutable_dynamic {
        findings.extend(probe_immutable_dynamic(&client, &url, &target, &sig).await);
    }
    if toggles.etag_injection && max_tier >= 2 {
        findings.extend(probe_etag_injection(&client, &url, &target, &env, &sig).await);
    }
    if toggles.case_header && max_tier >= 2 {
        findings.extend(probe_case_header_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.sec_fetch && max_tier >= 2 {
        findings.extend(probe_sec_fetch_vary(&client, &url, &target, &sig).await);
    }
    if toggles.save_data && max_tier >= 2 {
        findings.extend(probe_save_data_vary(&client, &url, &target, &sig).await);
    }
    if toggles.options_cache && max_tier >= 2 {
        findings.extend(probe_options_cache_oracle(&client, &url, &target, &sig).await);
    }
    if toggles.pragma_oracle {
        findings.extend(probe_pragma_no_cache_oracle(&client, &url, &target, &sig).await);
    }
    if toggles.forwarded_rfc7239 && max_tier >= 2 {
        findings.extend(probe_forwarded_rfc7239(&client, &url, &target, &env, &sig).await);
    }
    if toggles.host_header && max_tier >= 2 {
        findings.extend(probe_host_header_poison(&client, &url, &target, &env, &sig).await);
    }
    if toggles.edge_no_store {
        findings.extend(probe_edge_no_store_bypass(&client, &url, &target, &sig).await);
    }
    if toggles.vary_star {
        findings.extend(probe_vary_star_misconfig(&client, &url, &target, &sig).await);
    }
    if toggles.link_header && max_tier >= 2 {
        findings.extend(probe_link_header_poison(&client, &url, &target, &env, &sig).await);
    }
    if toggles.duplicate_query && max_tier >= 3 {
        findings.extend(probe_duplicate_query_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.accept_lang_order && max_tier >= 2 {
        findings.extend(probe_accept_language_order(&client, &url, &target, &sig).await);
    }
    if toggles.if_none_match && max_tier >= 2 {
        findings.extend(probe_if_none_match_cache(&client, &url, &target, &env, &sig).await);
    }
    if toggles.if_modified_since && max_tier >= 2 {
        findings.extend(probe_if_modified_since_cache(&client, &url, &target, &env, &sig).await);
    }
    if toggles.duplicate_header && max_tier >= 2 {
        findings.extend(probe_duplicate_header_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.only_if_cached && max_tier >= 2 {
        findings.extend(probe_only_if_cached_oracle(&client, &url, &target, &env, &sig).await);
    }
    if toggles.x_requested_with && max_tier >= 2 {
        findings.extend(probe_x_requested_with_vary(&client, &url, &target, &sig).await);
    }
    if toggles.prefer_vary && max_tier >= 2 {
        findings.extend(probe_prefer_vary(&client, &url, &target, &sig).await);
    }
    if toggles.alt_svc_h3 && max_tier >= 2 {
        findings.extend(probe_alt_svc_h3_surface(&client, &url, &target, &sig).await);
    }
    if toggles.s_maxage_schism {
        findings.extend(probe_s_maxage_schism(&client, &url, &target, &sig).await);
    }
    if toggles.brotli_vary && max_tier >= 2 {
        findings.extend(probe_brotli_encoding_vary(&client, &url, &target, &sig).await);
    }
    if toggles.sec_ch_ua && max_tier >= 2 {
        findings.extend(probe_sec_ch_ua_vary(&client, &url, &target, &sig).await);
    }
    if toggles.forwarded_prefix && max_tier >= 2 {
        findings.extend(probe_x_forwarded_prefix_poison(&client, &url, &target, &sig).await);
    }
    if toggles.set_cookie_cache_bleed {
        findings.extend(probe_set_cookie_cache_bleed(&client, &url, &target, &sig).await);
    }
    if toggles.stale_if_error {
        findings.extend(probe_stale_if_error_risk(&client, &url, &target, &sig).await);
    }
    if toggles.sec_ch_viewport && max_tier >= 2 {
        findings.extend(probe_sec_ch_viewport_vary(&client, &url, &target, &sig).await);
    }
    if toggles.trailing_dot_host && max_tier >= 2 {
        findings.extend(probe_trailing_dot_host(&client, &url, &target, &env, &sig).await);
    }
    if toggles.protocol_relative_redirect && max_tier >= 2 {
        findings.extend(probe_protocol_relative_redirect(&client, &url, &target, &env, &sig).await);
    }
    if toggles.deception {
        findings.extend(probe_deception(&client, &url, &target, &exts).await);
    }

    PathScanResult {
        findings,
        cacheable,
        vendor,
    }
}

