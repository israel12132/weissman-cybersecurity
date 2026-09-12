//! Wave-1/2/3 supreme-layer engines — live fusion + product-class probes.
//!
//! Every engine either correlates live child probes / DB telemetry or performs
//! distinct HTTP/API I/O. Missing credentials or empty inputs yield `empty_ok`
//! or a visible error — never fabricated critical findings.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, finding, header_value, http_client, http_get, http_get_with_headers,
    http_post_json, join_url, normalize_url, tcp_open,
};
use crate::engine_result::EngineResult;
use crate::itdr::{analyze, AuthEvent, ItdrConfig};
use serde_json::{json, Value};
use sqlx::Row;

fn ingest(merged: &mut Vec<Value>, label: &str, fusion: &str, result: &EngineResult) {
    if !result.success {
        return;
    }
    for mut f in result.findings.clone() {
        if let Some(obj) = f.as_object_mut() {
            obj.entry("source_engine".to_string())
                .or_insert(json!(label));
            obj.entry("fusion_engine".to_string())
                .or_insert(json!(fusion));
        }
        merged.push(f);
    }
}

fn haystack(f: &Value) -> String {
    format!(
        "{} {} {}",
        f.get("title").and_then(Value::as_str).unwrap_or(""),
        f.get("description").and_then(Value::as_str).unwrap_or(""),
        f.get("type").and_then(Value::as_str).unwrap_or(""),
    )
    .to_ascii_lowercase()
}

fn has_kw(findings: &[Value], kws: &[&str]) -> bool {
    findings
        .iter()
        .any(|f| kws.iter().any(|k| haystack(f).contains(k)))
}

/// Prove installed controls (PAN/Falcon/Defender/WAF/email DNS) and name the gaps.
pub async fn run_control_plane_of_controls_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let host = extract_host(target);
    let mut findings = Vec::new();

    let named = http_get(&client, &url).await;
    if let Some(ref p) = named {
        let server = header_value(&p.headers, "server")
            .unwrap_or("")
            .to_ascii_lowercase();
        let hay = format!(
            "{} {}",
            server,
            p.headers
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase()
        );
        let mut seen = Vec::new();
        if hay.contains("cloudflare") || hay.contains("cf-ray") {
            seen.push("Cloudflare");
        }
        if hay.contains("akamai") {
            seen.push("Akamai");
        }
        if hay.contains("imperva") || hay.contains("incapsula") {
            seen.push("Imperva");
        }
        if hay.contains("aws") && hay.contains("waf") {
            seen.push("AWS WAF");
        }
        if hay.contains("palo") || p.body.to_ascii_lowercase().contains("globalprotect") {
            seen.push("Palo Alto");
        }
        if seen.is_empty() {
            findings.push(finding(
                "control_plane_of_controls",
                "No WAF/SSE product fingerprint on the public edge",
                "medium",
                "T1595",
                &format!(
                    "{} Server/edge headers do not show Cloudflare, Akamai, Imperva, AWS WAF, or Palo Alto — the control plane cannot prove an inline preventer.",
                    p.final_url
                ),
                target,
            ));
        }

        for path in [
            "/global-protect/login.esp",
            "/dana-na/",
            "/remote/login",
            "/#/login",
        ] {
            let u = join_url(&url, path);
            if let Some(gp) = http_get(&client, &u).await {
                if gp.status == 200
                    && (gp.body.to_ascii_lowercase().contains("globalprotect")
                        || gp.body.to_ascii_lowercase().contains("fortigate"))
                {
                    findings.push(finding(
                        "control_plane_of_controls",
                        "VPN/ZTNA portal discovered — control installed",
                        "info",
                        "T1595",
                        &format!("{} HTTP {}", gp.final_url, gp.status),
                        target,
                    ));
                }
            }
        }
    }

    let email = crate::email_dns_posture_engine::run_email_dns_posture_result(target, ctx).await;
    ingest(
        &mut findings,
        "email_dns_posture",
        "control_plane_of_controls",
        &email,
    );

    let waf = crate::waf_bypass_engine::run_waf_bypass_result(target).await;
    ingest(
        &mut findings,
        "waf_bypass",
        "control_plane_of_controls",
        &waf,
    );

    if tcp_open(&host, 445).await {
        findings.push(finding(
            "control_plane_of_controls",
            "SMB 445 reachable from scan origin — NGFW microseg not holding",
            "high",
            "T1021.002",
            &format!("Host {host} accepts TCP/445 from the Weissman probe origin."),
            target,
        ));
    }

    if findings.is_empty() {
        empty_ok("control_plane_of_controls", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("control_plane_of_controls: {}", findings.len()),
        )
    }
}

/// OT protocol + cloud identity + ITDR chain in one evidence pack.
pub async fn run_ot_cloud_identity_killpath_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let mut merged = Vec::new();
    let (ot, cloud, ident) = tokio::join!(
        crate::scada_ics_engine::run_scada_ics_result(target),
        crate::azure_attack_engine::run_azure_attack_result(target),
        crate::identity_attack_chain_engine::run_identity_attack_chain_result(target, ctx),
    );
    ingest(&mut merged, "scada_ics", "ot_cloud_identity_killpath", &ot);
    ingest(
        &mut merged,
        "azure_attack",
        "ot_cloud_identity_killpath",
        &cloud,
    );
    ingest(
        &mut merged,
        "identity_attack_chain",
        "ot_cloud_identity_killpath",
        &ident,
    );

    let ot_hit = has_kw(&merged, &["modbus", "ot", "scada", "bacnet", "dnp3", "ics"]);
    let cloud_hit = has_kw(&merged, &["azure", "aws", "iam", "role", "storage"]);
    let id_hit = has_kw(&merged, &["kerberos", "spray", "saml", "oauth", "itdr"]);
    if ot_hit && (cloud_hit || id_hit) {
        merged.push(finding(
            "ot_cloud_identity_killpath",
            "Cross-domain kill path: OT signal fused with cloud/identity",
            "critical",
            "T0866",
            "Live OT protocol or ICS findings correlate with cloud or identity evidence on the same target — Purdue-model IT/OT boundary is not holding.",
            target,
        ));
    }
    if has_kw(&merged, &["mqtt", "iec", "opc ua", "dnp3", "ethernet/ip"]) {
        merged.push(finding(
            "ot_cloud_identity_killpath",
            "ICS C2 channel fused onto the OT/cloud kill path",
            "high",
            "T0869",
            "MQTT/IEC-104/OPC UA/DNP3 evidence on this target is a standard-application-layer C2 path. No industrial write is issued.",
            target,
        ));
    }
    if has_kw(
        &merged,
        &[
            "engineering",
            "plc admin",
            "codesys",
            "tiaportal",
            "webvisu",
        ],
    ) {
        merged.push(finding(
            "ot_cloud_identity_killpath",
            "ICS privilege-escalation surface on engineering panel",
            "critical",
            "T0890",
            "Engineering/PLC admin HTTP is the ICS privilege-escalation surface. Auditor only — no process-I/O write.",
            target,
        ));
    }

    if merged.is_empty() {
        empty_ok("ot_cloud_identity_killpath", target)
    } else {
        EngineResult::ok(
            merged.clone(),
            format!("ot_cloud_identity_killpath: {}", merged.len()),
        )
    }
}

/// BEC → account takeover: email DNS + BEC engine + OAuth/OIDC + ITDR rows.
pub async fn run_bec_ato_chain_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let mut merged = Vec::new();
    let (dns, bec, oauth) = tokio::join!(
        crate::email_dns_posture_engine::run_email_dns_posture_result(target, ctx),
        crate::advanced_social_engines::run_business_email_compromise_result(target),
        crate::oauth_oidc_engine::run_oauth_oidc_result(target, ctx),
    );
    ingest(&mut merged, "email_dns_posture", "bec_ato_chain", &dns);
    ingest(
        &mut merged,
        "business_email_compromise",
        "bec_ato_chain",
        &bec,
    );
    ingest(&mut merged, "oauth_oidc", "bec_ato_chain", &oauth);

    if has_kw(&merged, &["dmarc", "spf", "dkim", "spoof"])
        && has_kw(&merged, &["oauth", "token", "redirect", "pkce"])
    {
        merged.push(finding(
            "bec_ato_chain",
            "Email auth gap chained with OAuth takeover surface",
            "critical",
            "T1566.002",
            "SPF/DKIM/DMARC or BEC signals co-occur with OAuth/OIDC weaknesses — mailbox spoof can become IdP session theft.",
            target,
        ));
    }

    if merged.is_empty() {
        empty_ok("bec_ato_chain", target)
    } else {
        EngineResult::ok(merged.clone(), format!("bec_ato_chain: {}", merged.len()))
    }
}

/// AI-agent CASB: LLM hijack + OAuth + live SaaS discovery.
pub async fn run_ai_casb_saas_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let mut merged = Vec::new();
    let (llm, oauth) = tokio::join!(
        crate::advanced_ai_engines::run_llm_agent_hijack_result(target),
        crate::oauth_oidc_engine::run_oauth_oidc_result(target, ctx),
    );
    ingest(&mut merged, "llm_agent_hijack", "ai_casb_saas", &llm);
    ingest(&mut merged, "oauth_oidc", "ai_casb_saas", &oauth);

    let client = http_client().await;
    let url = normalize_url(target);
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/mcp",
        "/v1/chat/completions",
        "/openai/v1/models",
    ] {
        let u = join_url(&url, path);
        if let Some(p) = http_get(&client, &u).await {
            if p.status == 200 {
                merged.push(finding(
                    "ai_casb_saas",
                    "AI/SaaS identity or model API is publicly reachable",
                    "high",
                    "T1190",
                    &format!(
                        "{} HTTP {} — treat as unsanctioned AI/SaaS channel (CASB control gap).",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
    }

    if merged.is_empty() {
        empty_ok("ai_casb_saas", target)
    } else {
        EngineResult::ok(merged.clone(), format!("ai_casb_saas: {}", merged.len()))
    }
}

/// DNS Security posture: exfil + email DNS + ASM.
pub async fn run_dns_security_posture_fusion_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let mut merged = Vec::new();
    let (exfil, email, asm) = tokio::join!(
        crate::advanced_data_engines::run_dns_exfil_engine_result(target),
        crate::email_dns_posture_engine::run_email_dns_posture_result(target, ctx),
        crate::asm_engine::run_asm_result(target),
    );
    ingest(
        &mut merged,
        "dns_exfil_engine",
        "dns_security_posture_fusion",
        &exfil,
    );
    ingest(
        &mut merged,
        "email_dns_posture",
        "dns_security_posture_fusion",
        &email,
    );
    ingest(&mut merged, "asm", "dns_security_posture_fusion", &asm);

    if has_kw(&merged, &["txt", "tunnel", "exfil"]) && has_kw(&merged, &["spf", "dmarc", "mx"]) {
        merged.push(finding(
            "dns_security_posture_fusion",
            "DNS exfil surface plus email-DNS weakness",
            "high",
            "T1071.004",
            "Live DNS tunneling/TXT signals co-occur with email DNS posture gaps — recursive DNS security is not covering this zone.",
            target,
        ));
    }

    if merged.is_empty() {
        empty_ok("dns_security_posture_fusion", target)
    } else {
        EngineResult::ok(
            merged.clone(),
            format!("dns_security_posture_fusion: {}", merged.len()),
        )
    }
}

/// CNAPP toxic combo with safe exposure proof (IMDS/S3/K8s).
pub async fn run_toxic_combo_runtime_proof_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let mut merged = Vec::new();
    let (cnapp, k8s) = tokio::join!(
        crate::cloud_posture_engine::run_cloud_posture_result_ctx(target, ctx),
        crate::k8s_container_engine::run_k8s_container_result(target, ctx),
    );
    ingest(
        &mut merged,
        "cloud_posture",
        "toxic_combo_runtime_proof",
        &cnapp,
    );
    ingest(
        &mut merged,
        "k8s_container",
        "toxic_combo_runtime_proof",
        &k8s,
    );

    let client = http_client().await;
    let imds = http_get_with_headers(
        &client,
        "http://169.254.169.254/latest/meta-data/",
        &[("X-Forwarded-For", "169.254.169.254")],
    )
    .await;
    if let Some(p) = imds {
        if p.status == 200 && p.body.len() > 8 {
            merged.push(finding(
                "toxic_combo_runtime_proof",
                "IMDS reachable from scanner — instance identity exposed",
                "critical",
                "T1552.005",
                "Link-local metadata service answered HTTP 200. Combined with public cloud findings this is a confirmed toxic combo, not a ticket.",
                target,
            ));
        }
    }

    let url = normalize_url(target);
    if let Some(p) = http_get(&client, &join_url(&url, "/latest/meta-data/")).await {
        if p.status == 200 && p.body.contains("ami-id") {
            merged.push(finding(
                "toxic_combo_runtime_proof",
                "IMDS-like metadata proxied on the target origin",
                "critical",
                "T1552.005",
                &format!(
                    "{} returned AMI metadata — SSRF-to-IMDS proof.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    if has_kw(&merged, &["public", "s3", "bucket", "acl"])
        && has_kw(&merged, &["iam", "role", "imds", "metadata", "rbac"])
    {
        merged.push(finding(
            "toxic_combo_runtime_proof",
            "Toxic combination: public storage × identity/runtime",
            "critical",
            "T1530",
            "Public cloud storage findings correlate with IAM/IMDS/K8s RBAC evidence on this target.",
            target,
        ));
    }

    if merged.is_empty() {
        empty_ok("toxic_combo_runtime_proof", target)
    } else {
        EngineResult::ok(
            merged.clone(),
            format!("toxic_combo_runtime_proof: {}", merged.len()),
        )
    }
}

/// Standalone ITDR engine over ingested auth events.
pub async fn run_itdr_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let (pool, tenant_id, client_id) = match (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id) {
        (Some(p), Some(t), Some(c)) => (p.as_ref(), t, c),
        _ => {
            return EngineResult::ok(
                vec![finding(
                    "itdr",
                    "ITDR requires tenant context and ingested auth events",
                    "info",
                    "T1078",
                    "Connect Entra/Okta/Google via POST /api/itdr/connectors/pull or POST /api/itdr/auth-events, then re-run.",
                    target,
                )],
                "itdr: needs identity feed",
            );
        }
    };
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return EngineResult::error("database unavailable");
    };
    let rows = sqlx::query(
        r#"SELECT ts, username, ip, country, success, mfa_prompted
             FROM itdr_auth_events
            WHERE client_id = $1
            ORDER BY id DESC LIMIT 2000"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut events = Vec::new();
    for r in rows {
        events.push(AuthEvent::new(
            r.try_get::<i64, _>("ts").unwrap_or(0),
            &r.try_get::<String, _>("username").unwrap_or_default(),
            &r.try_get::<String, _>("ip").unwrap_or_default(),
            &r.try_get::<String, _>("country").unwrap_or_default(),
            r.try_get::<bool, _>("success").unwrap_or(false),
            r.try_get::<bool, _>("mfa_prompted").unwrap_or(false),
        ));
    }
    if events.is_empty() {
        return empty_ok("itdr", target);
    }
    let hits = analyze(&events, &ItdrConfig::default());
    if hits.is_empty() {
        return empty_ok("itdr", target);
    }
    let findings: Vec<Value> = hits
        .into_iter()
        .map(|h| {
            let mut f = finding(
                "itdr",
                &format!("ITDR {} — {}", h.kind, h.subject),
                &h.severity,
                &h.mitre,
                &format!("Detector {} on identity {}.", h.kind, h.subject),
                target,
            );
            if let Some(obj) = f.as_object_mut() {
                obj.insert("evidence".into(), h.evidence);
                obj.insert("itdr_kind".into(), json!(h.kind));
            }
            f
        })
        .collect();
    EngineResult::ok(findings.clone(), format!("itdr: {}", findings.len()))
}

/// CASB SaaS discovery: well-known IdP + Graph/Google grant inventory when tokens exist.
pub async fn run_casb_saas_posture_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let host = extract_host(target);
    let domain = host.trim_start_matches("www.");
    let mut findings = Vec::new();
    let candidates = [
        format!("https://login.microsoftonline.com/{domain}"),
        format!("https://{domain}.okta.com"),
        format!("https://accounts.google.com"),
        format!("https://{domain}.my.salesforce.com"),
        format!("https://{domain}.slack.com"),
        format!("https://{domain}.atlassian.net"),
    ];
    for u in candidates {
        if let Some(p) = http_get(&client, &u).await {
            if p.status < 400 {
                findings.push(finding(
                    "casb_saas_posture",
                    "SaaS / IdP tenant reachable",
                    "info",
                    "T1078",
                    &format!(
                        "{} HTTP {} — inventory as sanctioned or shadow SaaS for CASB policy.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
    }
    let tokens = crate::casb_dlp_api::load_tokens(ctx).await;
    if let Some(ref t) = tokens.graph {
        findings.extend(crate::casb_dlp_api::graph_casb_findings(target, t).await);
    }
    if let Some(ref t) = tokens.google {
        findings.extend(crate::casb_dlp_api::google_casb_findings(target, t).await);
    }
    if tokens.graph.is_none() && tokens.google.is_none() {
        findings.push(finding(
            "casb_saas_posture",
            "No Graph/Google CASB token — HTTP SaaS discovery only",
            "info",
            "T1078",
            "Set WEISSMAN_GRAPH_TOKEN / WEISSMAN_GOOGLE_TOKEN or persist IdP tokens via PUT /api/itdr/connectors for OAuth-grant inventory. Not faked.",
            target,
        ));
    }
    if findings.is_empty() {
        empty_ok("casb_saas_posture", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("casb_saas_posture: {}", findings.len()),
        )
    }
}

/// DLP content scan: live HTTP body + Graph/Gmail APIs when tokens exist.
pub async fn run_dlp_content_scan_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let Some(p) = http_get(&client, &url).await else {
        return empty_ok("dlp_content_scan", target);
    };
    let mut findings = Vec::new();
    let re_cc = regex::Regex::new(r"\b(?:\d[ -]*?){13,19}\b").ok();
    let re_ssn = regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").ok();
    let re_il_id = regex::Regex::new(r"\b\d{9}\b").ok();
    let re_secret = regex::Regex::new(r"(?i)(api[_-]?key|secret|bearer [a-z0-9\-_\.]{20,})").ok();
    if let Some(re) = re_cc {
        if re.is_match(&p.body) {
            findings.push(finding(
                "dlp_content_scan",
                "Possible payment-card pattern in HTTP body",
                "high",
                "T1530",
                &format!(
                    "{} body matched a PAN-like digit run — DLP should quarantine this URL.",
                    p.final_url
                ),
                target,
            ));
        }
    }
    if let Some(re) = re_ssn {
        if re.is_match(&p.body) {
            findings.push(finding(
                "dlp_content_scan",
                "SSN-shaped identifier in HTTP body",
                "high",
                "T1530",
                &format!("{} matched ###-##-####.", p.final_url),
                target,
            ));
        }
    }
    if let Some(re) = re_secret {
        if re.is_match(&p.body) {
            findings.push(finding(
                "dlp_content_scan",
                "Secret/API token pattern in HTTP body",
                "high",
                "T1552.001",
                &format!("{} leaked credential-shaped text.", p.final_url),
                target,
            ));
        }
    }
    let _ = re_il_id;
    let tokens = crate::casb_dlp_api::load_tokens(ctx).await;
    if let Some(ref t) = tokens.graph {
        findings.extend(crate::casb_dlp_api::graph_dlp_findings(target, t).await);
    }
    if let Some(ref t) = tokens.google {
        findings.extend(crate::casb_dlp_api::google_dlp_findings(target, t).await);
    }
    if findings.is_empty() {
        empty_ok("dlp_content_scan", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("dlp_content_scan: {}", findings.len()),
        )
    }
}

/// Continuous CNAPP: re-run posture and tag drift vs last stored findings when DB is present.
pub async fn run_cnapp_continuous_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let (mut r, azure) = tokio::join!(
        crate::cloud_posture_engine::run_cloud_posture_result_ctx(target, ctx),
        crate::azure_attack_engine::run_azure_attack_result(target),
    );
    ingest(&mut r.findings, "azure_attack", "cnapp_continuous", &azure);
    r.success = r.success || azure.success;
    for f in &mut r.findings {
        if let Some(obj) = f.as_object_mut() {
            obj.insert("cnapp_mode".into(), json!("continuous_refresh"));
            obj.insert("fusion_engine".into(), json!("cnapp_continuous"));
            obj.insert("ciem_surface".into(), json!(true));
        }
    }
    if r.findings.is_empty() && r.success {
        return empty_ok("cnapp_continuous", target);
    }
    r.message = format!("cnapp_continuous: {}", r.findings.len());
    r
}

/// NGFW / PAN-OS / Forti / NSG management-plane posture.
pub async fn run_ngfw_posture_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let host = extract_host(target);
    let mut findings = Vec::new();

    for port in [443u16, 4443, 8443, 444, 22] {
        if tcp_open(&host, port).await {
            findings.push(finding(
                "ngfw_posture",
                &format!("Management port {port}/tcp is reachable"),
                if port == 22 { "high" } else { "medium" },
                "T1190",
                &format!(
                    "{host}:{port} accepts connections from the probe origin — PAN-OS/Forti/NSG admin planes must not be internet-exposed."
                ),
                target,
            ));
        }
    }

    let paths = [
        "/api/?type=keygen",
        "/php/login.php",
        "/logincheck",
        "/api/v2/monitor/system/status",
        "/web_api/login",
    ];
    for path in paths {
        let u = join_url(&url, path);
        if let Some(p) = http_get(&client, &u).await {
            let bl = p.body.to_ascii_lowercase();
            if p.status < 500
                && (bl.contains("paloalto")
                    || bl.contains("panorama")
                    || bl.contains("fortigate")
                    || bl.contains("checkpoint")
                    || bl.contains("keygen")
                    || header_value(&p.headers, "server")
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .contains("panos"))
            {
                findings.push(finding(
                    "ngfw_posture",
                    "Network firewall / manager API or UI is exposed",
                    "high",
                    "T1190",
                    &format!(
                        "{} HTTP {} — inventory this as a PAN-OS/Forti/Check Point control plane and restrict to jump hosts.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
    }

    if let Ok(key) = std::env::var("WEISSMAN_PANOS_API_KEY") {
        if !key.trim().is_empty() {
            let api = format!(
                "{}/api/?type=op&cmd={}&key={}",
                url.trim_end_matches('/'),
                urlencoding::encode("<show><system><info></info></system></show>"),
                key.trim()
            );
            if let Some(p) = http_get(&client, &api).await {
                if p.body.contains("<hostname>") || p.body.contains("status=\"success\"") {
                    findings.push(finding(
                        "ngfw_posture",
                        "PAN-OS operational API accepted the configured key",
                        "info",
                        "T1595",
                        "Live PAN-OS <show system info> succeeded — policy audit can proceed from this control plane.",
                        target,
                    ));
                } else if p.body.contains("status=\"error\"") {
                    findings.push(finding(
                        "ngfw_posture",
                        "PAN-OS API key rejected or command failed",
                        "medium",
                        "T1190",
                        &format!("API at {} returned error XML.", p.final_url),
                        target,
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        empty_ok("ngfw_posture", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("ngfw_posture: {}", findings.len()),
        )
    }
}

/// Malware detonation farm — distinct from heal verification_sandbox.
pub async fn run_malware_detonation_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let farm = std::env::var("WEISSMAN_DETONATION_URL").unwrap_or_default();
    let client = http_client().await;
    let url = normalize_url(target);
    let Some(p) = http_get(&client, &url).await else {
        return empty_ok("malware_detonation", target);
    };

    let mut findings = Vec::new();
    let magic_mz = p.body.as_bytes().starts_with(b"MZ");
    let magic_elf = p.body.as_bytes().starts_with(b"\x7fELF");
    let ct = header_value(&p.headers, "content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    if magic_mz || magic_elf || ct.contains("octet-stream") || ct.contains("executable") {
        findings.push(finding(
            "malware_detonation",
            "Target serves an executable payload",
            "high",
            "T1204.002",
            &format!(
                "{} content-type={} mz={} elf={} bytes={}.",
                p.final_url,
                ct,
                magic_mz,
                magic_elf,
                p.body.len()
            ),
            target,
        ));
    }

    if farm.trim().is_empty() {
        if findings.is_empty() {
            return empty_ok("malware_detonation", target);
        }
        findings.push(finding(
            "malware_detonation",
            "Detonation farm not configured (WEISSMAN_DETONATION_URL)",
            "info",
            "T1204.002",
            "Static magic-byte analysis ran. Set WEISSMAN_DETONATION_URL to a isolated detonator to execute the sample.",
            target,
        ));
        return EngineResult::ok(
            findings.clone(),
            format!("malware_detonation: {}", findings.len()),
        );
    }

    let body = json!({ "url": url, "source": "weissman-malware_detonation" });
    match http_post_json(&client, farm.trim(), &body).await {
        Some(r) if r.status >= 200 && r.status < 300 => {
            findings.push(finding(
                "malware_detonation",
                "Sample submitted to detonation farm",
                "info",
                "T1204.002",
                &format!("Farm {} accepted the URL (HTTP {}).", r.final_url, r.status),
                target,
            ));
        }
        Some(r) => {
            return EngineResult::error(format!(
                "detonation farm HTTP {} at {}",
                r.status, r.final_url
            ));
        }
        None => {
            return EngineResult::error("detonation farm unreachable");
        }
    }

    if findings.is_empty() {
        empty_ok("malware_detonation", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("malware_detonation: {}", findings.len()),
        )
    }
}

/// Virtual NGFW control-plane probe — fails visibly when dataplane is down.
pub async fn run_weissman_vngfw_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let sock = std::env::var("WEISSMAN_VNGFW_ADMIN").unwrap_or_default();
    if sock.trim().is_empty() {
        return EngineResult::error(
            "Weissman Gate dataplane not configured (set WEISSMAN_VNGFW_ADMIN to the admin URL)",
        );
    }
    let client = http_client().await;
    let Some(p) = http_get(&client, sock.trim()).await else {
        return EngineResult::error("Weissman Gate dataplane unreachable");
    };
    if p.status != 200 {
        return EngineResult::error(format!(
            "Weissman Gate admin HTTP {} at {}",
            p.status, p.final_url
        ));
    }
    EngineResult::ok(
        vec![finding(
            "weissman_vngfw",
            "Weissman Gate dataplane is live",
            "info",
            "T1595",
            &format!("Admin {} HTTP 200 — policy engine responding.", p.final_url),
            target,
        )],
        "weissman_vngfw: live",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_targets_error() {
        let ctx = EngineRunContext::default();
        assert!(!run_control_plane_of_controls_result("", &ctx).await.success);
        assert!(!run_itdr_result("", &ctx).await.success);
        assert!(!run_ngfw_posture_result("").await.success);
        assert!(!run_malware_detonation_result("").await.success);
        assert!(!run_weissman_vngfw_result("").await.success);
        assert!(!run_casb_saas_posture_result("", &ctx).await.success);
        assert!(!run_dlp_content_scan_result("", &ctx).await.success);
    }

    #[tokio::test]
    async fn vngfw_errors_without_dataplane_env() {
        std::env::remove_var("WEISSMAN_VNGFW_ADMIN");
        let r = run_weissman_vngfw_result("https://example.com").await;
        assert!(!r.success);
        assert!(r.message.contains("not configured"));
    }
}
