//! Advanced Social-engineering engines — DNS/HTTP probes for phishing surface and OAuth misconfig hints.
//! No phishing payloads are sent; we audit email auth, login pages, and OIDC discovery.

use crate::engine_probes::{
    dns_mx, dns_txt, empty_ok, extract_host, finding_with_probe_depth, header_value, http_client,
    http_get, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

const SOCIAL_PROBE_DEPTH: &str = "phishing_oauth_surface";

fn social_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> Value {
    finding_with_probe_depth(
        engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        SOCIAL_PROBE_DEPTH,
    )
}

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

async fn oauth_misconfig_hints(t: &str, engine_id: &str, mitre: &str) -> Vec<Value> {
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings = Vec::new();
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/default",
    ] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status != 200 {
                continue;
            }
            let Ok(doc) = serde_json::from_str::<Value>(&p.body) else {
                continue;
            };
            findings.push(social_finding(
                engine_id,
                "OAuth/OIDC discovery document public",
                "info",
                mitre,
                &format!(
                    "Discovery doc at {} — review redirect_uri allow-list and token endpoint exposure.",
                    p.final_url
                ),
                t,
            ));
            if let Some(response_types) = doc.get("response_types_supported").and_then(|v| v.as_array())
            {
                let has_implicit = response_types.iter().filter_map(|v| v.as_str()).any(|rt| {
                    rt == "token" || (rt.contains("token") && rt != "code token")
                });
                if has_implicit {
                    findings.push(social_finding(
                        engine_id,
                        "Implicit OAuth flow supported",
                        "high",
                        mitre,
                        &format!(
                            "response_types_supported at {} includes token-in-URL flows — phishing can steal bearer tokens via redirect.",
                            p.final_url
                        ),
                        t,
                    ));
                }
            }
            let pkce_advertised = doc.get("code_challenge_methods_supported").is_some()
                || doc
                    .get("require_pkce")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            if !pkce_advertised {
                findings.push(social_finding(
                    engine_id,
                    "PKCE not advertised on OAuth server",
                    "medium",
                    mitre,
                    &format!(
                        "Discovery doc at {} does not require PKCE — authorization-code interception is easier.",
                        p.final_url
                    ),
                    t,
                ));
            }
        }
    }
    for path in ["/oauth/authorize", "/oauth2/authorize", "/connect/authorize"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status != 404 && (p.body.contains("redirect_uri") || p.body.contains("client_id")) {
                findings.push(social_finding(
                    engine_id,
                    "OAuth authorize endpoint reachable",
                    "info",
                    mitre,
                    &format!(
                        "{} (HTTP {}) exposes an OAuth authorize surface — test redirect_uri validation.",
                        p.final_url, p.status
                    ),
                    t,
                ));
            }
        }
    }
    findings
}

async fn email_auth_audit(t: &str, engine_id: &str, mitre: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let txt = dns_txt(&host).await;
    let dmarc_host = format!("_dmarc.{}", host);
    let dmarc_txt = dns_txt(&dmarc_host).await;
    let mx = dns_mx(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    let has_spf = txt.iter().any(|r| r.starts_with("v=spf1"));
    let has_dmarc = dmarc_txt.iter().any(|r| r.contains("v=DMARC1"));
    let has_dkim = txt.iter().any(|r| r.contains("v=DKIM1") || r.contains("k=rsa"));
    let dmarc_reject = dmarc_txt.iter().any(|r| {
        let r = r.to_ascii_lowercase();
        r.contains("p=reject") || r.contains("p=quarantine")
    });
    if !mx.is_empty() && !has_spf {
        findings.push(social_finding(
            engine_id,
            "Domain accepts mail but lacks SPF",
            "medium",
            mitre,
            &format!("MX={:?} for {} but no v=spf1 TXT — domain spoofing-friendly.", mx, host),
            t,
        ));
    }
    if !mx.is_empty() && !has_dmarc {
        findings.push(social_finding(
            engine_id,
            "No DMARC policy",
            "medium",
            mitre,
            &format!("_dmarc.{} has no DMARC1 record.", host),
            t,
        ));
    } else if !mx.is_empty() && has_dmarc && !dmarc_reject {
        findings.push(social_finding(
            engine_id,
            "Weak DMARC policy (p=none)",
            "low",
            mitre,
            &format!("_dmarc.{} publishes DMARC but not p=reject/quarantine.", host),
            t,
        ));
    }
    if !mx.is_empty() && !has_dkim {
        findings.push(social_finding(
            engine_id,
            "No DKIM selector in apex TXT",
            "low",
            mitre,
            &format!("{} accepts mail but apex TXT lacks DKIM hints — verify selector records.", host),
            t,
        ));
    }
    findings.extend(oauth_misconfig_hints(t, engine_id, mitre).await);
    if findings.is_empty() {
        empty_ok(engine_id, t)
    } else {
        EngineResult::ok(findings.clone(), format!("{}: {}", engine_id, findings.len()))
    }
}

async fn phishing_login_surface(t: &str, engine_id: &str, mitre: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    for path in ["/login", "/signin", "/auth/login", "/account/login", "/sso/login"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            let body = p.body.to_ascii_lowercase();
            let login_form = body.contains("type=\"password\"")
                || body.contains("type='password'")
                || body.contains("name=\"password\"");
            if p.status == 200 && login_form {
                let offsite_action = body.contains("action=\"http://")
                    || body.contains("action='http://")
                    || (body.contains("action=\"https://")
                        && !body.contains(&format!("action=\"https://{}", extract_host(t).to_ascii_lowercase())));
                findings.push(social_finding(
                    engine_id,
                    "Public login form detected",
                    if offsite_action { "high" } else { "medium" },
                    mitre,
                    &format!(
                        "{} exposes a password login form{}.",
                        p.final_url,
                        if offsite_action {
                            " with off-domain form action — review for credential phishing"
                        } else {
                            " — harden against credential harvesting clones"
                        }
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok(engine_id, t)
    } else {
        EngineResult::ok(findings.clone(), format!("{}: {}", engine_id, findings.len()))
    }
}

pub async fn run_spear_phishing_engine_result(t: &str) -> EngineResult {
    email_auth_audit(t, "spear_phishing_engine", "T1566.001").await
}
cli_wrapper!(run_spear_phishing_engine, run_spear_phishing_engine_result);

pub async fn run_vishing_engine_result(t: &str) -> EngineResult {
    email_auth_audit(t, "vishing_engine", "T1566.004").await
}
cli_wrapper!(run_vishing_engine, run_vishing_engine_result);

pub async fn run_smishing_engine_result(t: &str) -> EngineResult {
    email_auth_audit(t, "smishing_engine", "T1566.004").await
}
cli_wrapper!(run_smishing_engine, run_smishing_engine_result);

pub async fn run_qr_phishing_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let body = p.body.to_ascii_lowercase();
        if body.contains("qrcode") || body.contains("qr-code") || body.contains("data:image/svg+xml") {
            findings.push(social_finding(
                "qr_phishing",
                "Inline QR-code generator detected",
                "low",
                "T1204",
                &format!(
                    "{} embeds QR rendering — verify destination URLs stay on first-party domains.",
                    p.final_url
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("qr_phishing", t)
    } else {
        EngineResult::ok(findings.clone(), format!("qr_phishing: {}", findings.len()))
    }
}
cli_wrapper!(run_qr_phishing, run_qr_phishing_result);

pub async fn run_deepfake_voice_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "deepfake_voice_engine",
        t,
        "Deepfake voice detection requires call-flow audio agent",
        "Synthetic-voice features are inside the audio stream; deploy the SIP/Voice agent on the PBX.",
    )
}
cli_wrapper!(run_deepfake_voice_engine, run_deepfake_voice_engine_result);

pub async fn run_business_email_compromise_result(t: &str) -> EngineResult {
    email_auth_audit(t, "business_email_compromise", "T1566.001").await
}
cli_wrapper!(run_business_email_compromise, run_business_email_compromise_result);

pub async fn run_watering_hole_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let csp = header_value(&p.headers, "content-security-policy").unwrap_or("");
        if !csp.contains("script-src") && p.body.contains("<script") {
            findings.push(social_finding(
                "watering_hole_attack",
                "Site loads scripts without CSP",
                "medium",
                "T1189",
                &format!(
                    "{} ships inline/external scripts without CSP — attractive watering-hole target.",
                    p.final_url
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("watering_hole_attack", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("watering_hole_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_watering_hole_attack, run_watering_hole_attack_result);

pub async fn run_pretexting_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "pretexting_engine",
        t,
        "Pretexting detection requires email gateway + helpdesk telemetry",
        "Pretext campaigns are content-based; we surface them via MX-gateway integration and ticketing logs.",
    )
}
cli_wrapper!(run_pretexting_engine, run_pretexting_engine_result);

pub async fn run_insider_threat_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "insider_threat_engine",
        t,
        "Insider-threat detection requires UEBA telemetry",
        "Identity-anomaly scoring needs authn, file-server, and IAM-event feeds — connect them in Integrations.",
    )
}
cli_wrapper!(run_insider_threat_engine, run_insider_threat_engine_result);

pub async fn run_brand_impersonation_result(t: &str) -> EngineResult {
    crate::typosquatting_monitor_engine::run_typosquatting_monitor_result(t).await
}
cli_wrapper!(run_brand_impersonation, run_brand_impersonation_result);

pub async fn run_fake_update_engine_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let body = p.body.to_ascii_lowercase();
        if body.contains("chrome update") || body.contains("update.exe") || body.contains("urgent security patch")
        {
            findings.push(social_finding(
                "fake_update_engine",
                "Fake-update landing-page indicator",
                "medium",
                "T1189",
                &format!(
                    "{} contains lure copy commonly used by fake-update campaigns.",
                    p.final_url
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("fake_update_engine", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("fake_update_engine: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_fake_update_engine, run_fake_update_engine_result);

pub async fn run_linkedin_phishing_result(t: &str) -> EngineResult {
    phishing_login_surface(t, "linkedin_phishing", "T1566.002").await
}
cli_wrapper!(run_linkedin_phishing, run_linkedin_phishing_result);

pub async fn run_callback_phishing_result(t: &str) -> EngineResult {
    email_auth_audit(t, "callback_phishing", "T1566.001").await
}
cli_wrapper!(run_callback_phishing, run_callback_phishing_result);

pub async fn run_physical_social_eng_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "physical_social_eng",
        t,
        "Physical / badge social-engineering test requires an on-site assessor",
        "Tailgating, badge cloning and reception bypass are physical engagements; schedule via Services → Red Team.",
    )
}
cli_wrapper!(run_physical_social_eng, run_physical_social_eng_result);

pub async fn run_typosquatting_phishing_result(t: &str) -> EngineResult {
    crate::typosquatting_monitor_engine::run_typosquatting_monitor_result(t).await
}
cli_wrapper!(run_typosquatting_phishing, run_typosquatting_phishing_result);
