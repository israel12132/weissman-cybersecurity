// ── Orchestration + posture summary ─────────────────────────────────────────

/// Backward-compatible entry (CLI + alias callers). Uses default parameters.
pub async fn run_cache_poisoning_result(target: &str) -> EngineResult {
    run_cache_poisoning_result_ctx(target, &EngineRunContext::default()).await
}

/// Parameterised entry used by the dispatch layer (reads `ctx.job_params`).
pub async fn run_cache_poisoning_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let timeout_ms = cfg.timeout_ms(8000);
    let intensity = cfg.intensity();
    let include_info = cfg.bool_or("include_info_findings", true);
    let concurrency = cfg.concurrency().clamp(1, 16);
    let client = build_client(timeout_ms).await;

    let check_fingerprint = cfg.bool_or("check_fingerprint", true);
    let check_unkeyed = cfg.bool_or("check_unkeyed", true);
    let check_deception = cfg.bool_or("check_deception", true);
    let check_query_unkeyed = cfg.bool_or("check_query_unkeyed", true);
    let check_cookie_cache = cfg.bool_or("check_cookie_cache", true);
    let check_hardening = cfg.bool_or("check_hardening", true);
    let check_fat_get = cfg.bool_or("check_fat_get", true);
    let check_method_confusion = cfg.bool_or("check_method_confusion", true);
    let check_range_poisoning = cfg.bool_or("check_range_poisoning", true);
    let check_normalization = cfg.bool_or("check_normalization", true);
    let check_cache_key_oracle = cfg.bool_or("check_cache_key_oracle", true);
    let check_h2_schism = cfg.bool_or("check_h2_schism", true);
    let check_encoding_vary = cfg.bool_or("check_encoding_vary", true);
    let check_method_override = cfg.bool_or("check_method_override", true);
    let check_authorization_cache = cfg.bool_or("check_authorization_cache", true);
    let check_redirect_poisoning = cfg.bool_or("check_redirect_poisoning", true);
    let check_query_order = cfg.bool_or("check_query_order", true);
    let check_cdn_schism = cfg.bool_or("check_cdn_schism", true);
    let check_user_agent_vary = cfg.bool_or("check_user_agent_vary", true);
    let check_tracking_oracle = cfg.bool_or("check_tracking_oracle", true);
    let check_vary_incomplete = cfg.bool_or("check_vary_incomplete", true);
    let check_stale_revalidate = cfg.bool_or("check_stale_revalidate", true);
    let check_accept_vary = cfg.bool_or("check_accept_vary", true);
    let check_post_cache = cfg.bool_or("check_post_cache", true);
    let check_immutable_dynamic = cfg.bool_or("check_immutable_dynamic", true);
    let check_etag_injection = cfg.bool_or("check_etag_injection", true);
    let check_case_header = cfg.bool_or("check_case_header", true);
    let check_path_discover = cfg.bool_or("check_path_discover", true);
    let check_sec_fetch = cfg.bool_or("check_sec_fetch", true);
    let check_save_data = cfg.bool_or("check_save_data", true);
    let check_options_cache = cfg.bool_or("check_options_cache", true);
    let check_pragma_oracle = cfg.bool_or("check_pragma_oracle", true);
    let check_forwarded_rfc7239 = cfg.bool_or("check_forwarded_rfc7239", true);
    let check_host_header = cfg.bool_or("check_host_header", true);
    let check_edge_no_store = cfg.bool_or("check_edge_no_store", true);
    let check_vary_star = cfg.bool_or("check_vary_star", true);
    let check_link_header = cfg.bool_or("check_link_header", true);
    let check_duplicate_query = cfg.bool_or("check_duplicate_query", true);
    let check_accept_lang_order = cfg.bool_or("check_accept_lang_order", true);
    let check_if_none_match = cfg.bool_or("check_if_none_match", true);
    let check_if_modified_since = cfg.bool_or("check_if_modified_since", true);
    let check_duplicate_header = cfg.bool_or("check_duplicate_header", true);
    let check_only_if_cached = cfg.bool_or("check_only_if_cached", true);
    let check_x_requested_with = cfg.bool_or("check_x_requested_with", true);
    let check_prefer_vary = cfg.bool_or("check_prefer_vary", true);
    let check_alt_svc_h3 = cfg.bool_or("check_alt_svc_h3", true);
    let check_s_maxage_schism = cfg.bool_or("check_s_maxage_schism", true);
    let check_brotli_vary = cfg.bool_or("check_brotli_vary", true);
    let check_sec_ch_ua = cfg.bool_or("check_sec_ch_ua", true);
    let check_forwarded_prefix = cfg.bool_or("check_forwarded_prefix", true);
    let check_set_cookie_cache_bleed = cfg.bool_or("check_set_cookie_cache_bleed", true);
    let check_stale_if_error = cfg.bool_or("check_stale_if_error", true);
    let check_sec_ch_viewport = cfg.bool_or("check_sec_ch_viewport", true);
    let check_trailing_dot_host = cfg.bool_or("check_trailing_dot_host", true);
    let check_protocol_relative_redirect = cfg.bool_or("check_protocol_relative_redirect", true);
    let query_param = cfg.string_or("query_param", "wzqp");
    let path_concurrency = cfg.usize_or("path_concurrency", 2).clamp(1, 4);
    let max_paths = cfg.usize_or("max_paths", 0);

    let probe_flags: &[(&str, bool)] = &[
        ("fingerprint", check_fingerprint),
        ("unkeyed_headers", check_unkeyed),
        ("query_unkeyed", check_query_unkeyed),
        ("cookie_cache", check_cookie_cache),
        ("hardening", check_hardening),
        ("fat_get", check_fat_get),
        ("method_confusion", check_method_confusion),
        ("range_poisoning", check_range_poisoning),
        ("normalization", check_normalization),
        ("cache_key_oracle", check_cache_key_oracle),
        ("h2_schism", check_h2_schism),
        ("encoding_vary", check_encoding_vary),
        ("method_override", check_method_override),
        ("authorization_cache", check_authorization_cache),
        ("redirect_poisoning", check_redirect_poisoning),
        ("query_order", check_query_order),
        ("cdn_schism", check_cdn_schism),
        ("user_agent_vary", check_user_agent_vary),
        ("tracking_oracle", check_tracking_oracle),
        ("vary_incomplete", check_vary_incomplete),
        ("stale_revalidate", check_stale_revalidate),
        ("accept_vary", check_accept_vary),
        ("post_cache", check_post_cache),
        ("immutable_dynamic", check_immutable_dynamic),
        ("etag_injection", check_etag_injection),
        ("case_header", check_case_header),
        ("path_discover", check_path_discover),
        ("sec_fetch", check_sec_fetch),
        ("save_data", check_save_data),
        ("options_cache", check_options_cache),
        ("pragma_oracle", check_pragma_oracle),
        ("forwarded_rfc7239", check_forwarded_rfc7239),
        ("host_header", check_host_header),
        ("edge_no_store", check_edge_no_store),
        ("vary_star", check_vary_star),
        ("link_header", check_link_header),
        ("duplicate_query", check_duplicate_query),
        ("accept_lang_order", check_accept_lang_order),
        ("if_none_match", check_if_none_match),
        ("if_modified_since", check_if_modified_since),
        ("duplicate_header", check_duplicate_header),
        ("only_if_cached", check_only_if_cached),
        ("x_requested_with", check_x_requested_with),
        ("prefer_vary", check_prefer_vary),
        ("alt_svc_h3", check_alt_svc_h3),
        ("s_maxage_schism", check_s_maxage_schism),
        ("brotli_vary", check_brotli_vary),
        ("sec_ch_ua", check_sec_ch_ua),
        ("forwarded_prefix", check_forwarded_prefix),
        ("set_cookie_cache_bleed", check_set_cookie_cache_bleed),
        ("stale_if_error", check_stale_if_error),
        ("sec_ch_viewport", check_sec_ch_viewport),
        ("trailing_dot_host", check_trailing_dot_host),
        ("protocol_relative_redirect", check_protocol_relative_redirect),
        ("deception", check_deception),
    ];

    HTTP_REQUESTS.store(0, Ordering::Relaxed);
    let scan_started = Instant::now();
    let env = PathEnv::from_cfg(&cfg);
    let canary_domain = env.poison_domain.to_string();

    let default_path_limit = if matches!(intensity, Intensity::Aggressive) {
        10
    } else {
        4
    };
    let path_limit = if max_paths > 0 {
        max_paths.clamp(1, 16)
    } else {
        default_path_limit
    };

    let base = base_url(target);
    let mut paths = cfg.string_list("paths");
    if paths.is_empty() {
        paths.push("/".to_string());
    }
    if check_path_discover {
        let pd_cb = token("pd");
        let discover_url = with_buster(&base, &pd_cb);
        if let Some(home) = tracked_get(&client, &discover_url, &[]).await {
            for dp in discover_paths_from_html(&home.body) {
                if paths.len() >= path_limit {
                    break;
                }
                if !paths.iter().any(|p| p == &dp) {
                    paths.push(dp);
                }
            }
        }
    }
    let max_tier = match intensity {
        Intensity::Light => 1,
        Intensity::Normal => 2,
        Intensity::Aggressive => 3,
    };
    let mut header_set: Vec<(String, HeaderKind)> = UNKEYED_HEADERS
        .iter()
        .filter(|h| h.tier <= max_tier)
        .map(|h| (h.name.to_string(), h.kind))
        .collect();
    // Operator-supplied extra headers (treated as Host-type reflections).
    for name in cfg.string_list("headers") {
        header_set.push((name, HeaderKind::Host));
    }
    let exts = cfg.string_list_or("deception_extensions", DEFAULT_DECEPTION_EXTS);

    let toggles = ProbeToggles {
        fingerprint: check_fingerprint,
        unkeyed: check_unkeyed,
        query_unkeyed: check_query_unkeyed,
        cookie_cache: check_cookie_cache,
        hardening: check_hardening,
        fat_get: check_fat_get,
        method_confusion: check_method_confusion,
        range_poisoning: check_range_poisoning,
        normalization: check_normalization,
        cache_key_oracle: check_cache_key_oracle,
        h2_schism: check_h2_schism,
        encoding_vary: check_encoding_vary,
        method_override: check_method_override,
        authorization_cache: check_authorization_cache,
        redirect_poisoning: check_redirect_poisoning,
        query_order: check_query_order,
        cdn_schism: check_cdn_schism,
        user_agent_vary: check_user_agent_vary,
        tracking_oracle: check_tracking_oracle,
        vary_incomplete: check_vary_incomplete,
        stale_revalidate: check_stale_revalidate,
        accept_vary: check_accept_vary,
        post_cache: check_post_cache,
        immutable_dynamic: check_immutable_dynamic,
        etag_injection: check_etag_injection,
        case_header: check_case_header,
        sec_fetch: check_sec_fetch,
        save_data: check_save_data,
        options_cache: check_options_cache,
        pragma_oracle: check_pragma_oracle,
        forwarded_rfc7239: check_forwarded_rfc7239,
        host_header: check_host_header,
        edge_no_store: check_edge_no_store,
        vary_star: check_vary_star,
        link_header: check_link_header,
        duplicate_query: check_duplicate_query,
        accept_lang_order: check_accept_lang_order,
        if_none_match: check_if_none_match,
        if_modified_since: check_if_modified_since,
        duplicate_header: check_duplicate_header,
        only_if_cached: check_only_if_cached,
        x_requested_with: check_x_requested_with,
        prefer_vary: check_prefer_vary,
        alt_svc_h3: check_alt_svc_h3,
        s_maxage_schism: check_s_maxage_schism,
        brotli_vary: check_brotli_vary,
        sec_ch_ua: check_sec_ch_ua,
        forwarded_prefix: check_forwarded_prefix,
        set_cookie_cache_bleed: check_set_cookie_cache_bleed,
        stale_if_error: check_stale_if_error,
        sec_ch_viewport: check_sec_ch_viewport,
        trailing_dot_host: check_trailing_dot_host,
        protocol_relative_redirect: check_protocol_relative_redirect,
        deception: check_deception,
    };

    let scan_urls: Vec<String> = paths
        .iter()
        .take(path_limit)
        .map(|path| {
            if path == "/" || path.is_empty() {
                base.clone()
            } else {
                format!(
                    "{}/{}",
                    base.trim_end_matches('/'),
                    path.trim_start_matches('/')
                )
            }
        })
        .collect();

    let target_owned = target.to_string();
    let query_param_owned = query_param.clone();
    let mut findings: Vec<Value> = Vec::new();
    let mut any_cache = false;
    let mut detected_vendor: Option<String> = None;

    for chunk in scan_urls.chunks(path_concurrency) {
        let futs: Vec<_> = chunk
            .iter()
            .map(|url| {
                scan_one_path(
                    client.clone(),
                    url.clone(),
                    target_owned.clone(),
                    env.clone(),
                    toggles,
                    max_tier,
                    concurrency,
                    include_info,
                    timeout_ms,
                    query_param_owned.clone(),
                    header_set.clone(),
                    exts.clone(),
                )
            })
            .collect();
        for res in join_all(futs).await {
            findings.extend(res.findings);
            if res.cacheable {
                any_cache = true;
            }
            if res.vendor.is_some() {
                detected_vendor = res.vendor;
            }
        }
    }

    findings = dedupe_findings(findings);

    let summary = build_summary(
        target,
        &base,
        &findings,
        any_cache,
        detected_vendor.as_deref(),
        intensity,
        probe_flags,
        concurrency,
        scan_started.elapsed().as_millis(),
        scan_urls.len(),
        path_concurrency,
        &canary_domain,
        path_limit,
        max_paths,
    );
    let score = summary.get("posture_score").and_then(Value::as_u64).unwrap_or(100);
    let real = findings.len();
    findings.insert(0, summary);

    EngineResult::ok(
        findings,
        format!("Web cache posture {}/100 — {} finding(s) for {}", score, real, base),
    )
}

fn build_summary(
    target: &str,
    base: &str,
    findings: &[Value],
    any_cache: bool,
    detected_vendor: Option<&str>,
    intensity: Intensity,
    probe_flags: &[(&str, bool)],
    concurrency: usize,
    scan_duration_ms: u128,
    paths_tested: usize,
    path_concurrency: usize,
    canary_domain: &str,
    path_limit_applied: usize,
    max_paths: usize,
) -> Value {
    let mut crit = 0u32;
    let mut high = 0u32;
    let mut med = 0u32;
    let mut low = 0u32;
    let mut categories: BTreeSet<String> = BTreeSet::new();
    let mut worst = "info";
    for f in findings {
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        match sev {
            "critical" => crit += 1,
            "high" => high += 1,
            "medium" => med += 1,
            "low" => low += 1,
            _ => {}
        }
        if severity_rank(sev) > severity_rank(worst) {
            worst = sev;
        }
        let exposure = f.get("exposure").and_then(Value::as_str).unwrap_or("");
        if !matches!(exposure, "present" | "clean") {
            if let Some(c) = f.get("category").and_then(Value::as_str) {
                categories.insert(c.to_string());
            }
        }
    }
    let penalty = crit * 30 + high * 14 + med * 6 + low * 2;
    let score = 100u32.saturating_sub(penalty).max(if crit > 0 { 0 } else { 5 });
    let grade = match score {
        92..=100 => "A",
        80..=91 => "B",
        65..=79 => "C",
        45..=64 => "D",
        _ => "F",
    };
    let cats: Vec<String> = categories.iter().cloned().collect();
    let posture_dimensions = compute_posture_dimensions(findings);
    let roadmap = build_hardening_roadmap(findings);
    let attack_chains = build_attack_chains(findings, any_cache);
    let probe_manifest = build_probe_manifest(probe_flags);
    let exploitability_index = compute_exploitability_index(findings);
    let confirmed_primitives = count_confirmed_primitives(findings);
    let beyond_score = compute_beyond_score(score, exploitability_index, &posture_dimensions);
    let risk_matrix = build_risk_matrix(findings);
    let cdn_playbook = build_cdn_playbook(detected_vendor, findings);
    let defense_controls = build_defense_controls(findings);
    let poison_window_seconds = compute_poison_window_seconds(findings);
    let top_primitives = build_top_primitives(findings);
    let compliance_map = build_compliance_map(findings);
    let coverage_manifest = build_coverage_manifest(probe_flags, findings.len());
    let competitive_parity_index = build_competitive_parity_index(probe_flags, beyond_score);
    let http_requests = HTTP_REQUESTS.load(Ordering::Relaxed);
    let scan_telemetry = json!({
        "http_requests": http_requests,
        "paths_tested": paths_tested,
        "scan_duration_ms": scan_duration_ms,
        "concurrency": concurrency,
        "path_concurrency": path_concurrency,
        "canary_domain": canary_domain,
        "max_paths": max_paths,
        "path_limit_applied": path_limit_applied,
        "probe_categories_total": probe_flags.len(),
    });

    let description = if !any_cache && crit == 0 && high == 0 {
        format!(
            "No shared cache / CDN layer was observed in front of {}, and no reflection/deception primitive was found. Web-cache-poisoning exposure is minimal. Score {}/100 (grade {}).",
            base, score, grade
        )
    } else {
        format!(
            "Web cache poisoning & deception posture for {}: score {}/100 (grade {}). {} critical / {} high / {} medium / {} low across: {}.",
            base, score, grade, crit, high, med, low, if cats.is_empty() { "—".to_string() } else { cats.join(", ") }
        )
    };

    let ev = Evidence::new()
        .with("base_url", base.to_string())
        .with("posture_score", json!(score))
        .with("grade", grade)
        .with("shared_cache_detected", json!(any_cache))
        .with("intensity", intensity.as_str())
        .with("severity_breakdown", json!({ "critical": crit, "high": high, "medium": med, "low": low }))
        .with("weak_categories", json!(cats.clone()))
        .with("posture_dimensions", posture_dimensions.clone())
        .with("probe_manifest", probe_manifest.clone())
        .with("attack_chains", json!(attack_chains.len()))
        .with("exploitability_index", json!(exploitability_index))
        .with("confirmed_primitives", json!(confirmed_primitives))
        .with("beyond_score", json!(beyond_score))
        .with("scan_telemetry", scan_telemetry.clone())
        .with("concurrency", json!(concurrency))
        .with("detected_cdn_vendor", json!(detected_vendor))
        .with("risk_matrix", risk_matrix.clone())
        .with("cdn_playbook", cdn_playbook.clone())
        .with("defense_controls", defense_controls.clone())
        .with("poison_window_seconds", json!(poison_window_seconds))
        .with("top_primitives", json!(top_primitives.clone()))
        .with("compliance_map", compliance_map.clone())
        .with("coverage_manifest", coverage_manifest.clone())
        .with("competitive_parity_index", json!(competitive_parity_index));

    let mut summary = finding_rich(
        ENGINE_ID,
        &format!("Web cache posture score {}/100 (grade {})", score, grade),
        "info",
        "T1557",
        &description,
        target,
        0.99,
        ev,
    );
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("category".to_string(), json!("posture_summary"));
        obj.insert("summary".to_string(), json!(true));
        obj.insert("posture_score".to_string(), json!(score));
        obj.insert("grade".to_string(), json!(grade));
        obj.insert("worst_severity".to_string(), json!(worst));
        obj.insert("weak_categories".to_string(), json!(cats));
        obj.insert("shared_cache_detected".to_string(), json!(any_cache));
        obj.insert("posture_dimensions".to_string(), posture_dimensions);
        obj.insert("hardening_roadmap".to_string(), json!(roadmap));
        obj.insert("attack_chains".to_string(), json!(attack_chains));
        obj.insert("probe_manifest".to_string(), probe_manifest);
        obj.insert("exploitability_index".to_string(), json!(exploitability_index));
        obj.insert("confirmed_primitives".to_string(), json!(confirmed_primitives));
        obj.insert("beyond_score".to_string(), json!(beyond_score));
        obj.insert("scan_telemetry".to_string(), scan_telemetry);
        obj.insert("detected_cdn_vendor".to_string(), json!(detected_vendor));
        obj.insert("risk_matrix".to_string(), risk_matrix);
        obj.insert("cdn_playbook".to_string(), cdn_playbook);
        obj.insert("defense_controls".to_string(), defense_controls);
        obj.insert("poison_window_seconds".to_string(), json!(poison_window_seconds));
        obj.insert("top_primitives".to_string(), json!(top_primitives));
        obj.insert("compliance_map".to_string(), compliance_map);
        obj.insert("coverage_manifest".to_string(), coverage_manifest.clone());
        obj.insert("competitive_parity_index".to_string(), json!(competitive_parity_index));
        obj.insert(
            "sealed_complete".to_string(),
            json!(coverage_manifest.get("sealed_complete").and_then(Value::as_bool).unwrap_or(false)),
        );
        obj.insert("canary_domain".to_string(), json!(canary_domain));
        obj.insert(
            "remediation".to_string(),
            json!("Treat the cache key as a security boundary: key on every request input that affects the response, strip untrusted X-Forwarded-*/Forwarded headers at the edge, set Cache-Control: no-store on authenticated/dynamic responses, and match caching on real Content-Type rather than URL suffix."),
        );
    }
    summary
}

pub async fn run_cache_poisoning(target: &str) {
    print_result(run_cache_poisoning_result(target).await);
}

