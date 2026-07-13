//! Advanced Social-engineering engines — DNS/HTTP probes for phishing surface and OAuth misconfig hints.
//! No phishing payloads are sent; we audit email auth, login pages, and OIDC discovery.

use crate::engine_probes::{
    dns_a, dns_mx, dns_txt, empty_ok, extract_host, finding_with_probe_depth, header_value,
    http_client, http_get, normalize_url, tcp_open, tcp_probe_response, udp_probe_response,
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
            if let Some(response_types) = doc
                .get("response_types_supported")
                .and_then(|v| v.as_array())
            {
                let has_implicit = response_types
                    .iter()
                    .filter_map(|v| v.as_str())
                    .any(|rt| rt == "token" || (rt.contains("token") && rt != "code token"));
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
    for path in [
        "/oauth/authorize",
        "/oauth2/authorize",
        "/connect/authorize",
    ] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status != 404 && (p.body.contains("redirect_uri") || p.body.contains("client_id"))
            {
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

/// Email-authentication posture (SPF / DMARC / DKIM) + OAuth/OIDC misconfig
/// hints. Returns findings for composition into channel-specific engines.
async fn email_auth_findings(t: &str, engine_id: &str, mitre: &str) -> Vec<Value> {
    let host = extract_host(t);
    let txt = dns_txt(&host).await;
    let dmarc_host = format!("_dmarc.{}", host);
    let dmarc_txt = dns_txt(&dmarc_host).await;
    let mx = dns_mx(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    let has_spf = txt.iter().any(|r| r.starts_with("v=spf1"));
    let has_dmarc = dmarc_txt.iter().any(|r| r.contains("v=DMARC1"));
    let has_dkim = txt
        .iter()
        .any(|r| r.contains("v=DKIM1") || r.contains("k=rsa"));
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
            &format!(
                "MX={:?} for {} but no v=spf1 TXT — domain spoofing-friendly.",
                mx, host
            ),
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
            &format!(
                "_dmarc.{} publishes DMARC but not p=reject/quarantine.",
                host
            ),
            t,
        ));
    }
    if !mx.is_empty() && !has_dkim {
        findings.push(social_finding(
            engine_id,
            "No DKIM selector in apex TXT",
            "low",
            mitre,
            &format!(
                "{} accepts mail but apex TXT lacks DKIM hints — verify selector records.",
                host
            ),
            t,
        ));
    }
    findings.extend(oauth_misconfig_hints(t, engine_id, mitre).await);
    findings
}

// ── VoIP / SIP surface (vishing infrastructure) ─────────────────────────────

/// A minimal, read-only SIP OPTIONS ping (the SIP equivalent of an ICMP echo).
fn sip_options_probe(host: &str) -> Vec<u8> {
    format!(
        "OPTIONS sip:{h} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {h}:5060;branch=z9hG4bK-weissman\r\n\
         Max-Forwards: 70\r\n\
         To: <sip:{h}>\r\n\
         From: <sip:probe@{h}>;tag=weissman\r\n\
         Call-ID: weissman-probe@{h}\r\n\
         CSeq: 1 OPTIONS\r\n\
         Contact: <sip:probe@{h}>\r\n\
         Content-Length: 0\r\n\r\n",
        h = host
    )
    .into_bytes()
}

/// True if a raw response looks like a SIP endpoint answering.
fn is_sip_response(resp: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&resp[..resp.len().min(256)]).to_ascii_lowercase();
    head.contains("sip/2.0")
}

/// Probe for an exposed VoIP/PBX (SIP) — the infrastructure that makes caller-ID
/// spoofing / vishing possible. UDP 5060, then TCP 5060, then TLS 5061.
async fn voip_sip_surface(host: &str, engine_id: &str, mitre: &str, target: &str) -> Vec<Value> {
    let mut findings = Vec::new();
    let probe = sip_options_probe(host);
    let mut confirmed = false;
    if let Some(resp) = udp_probe_response(host, 5060, &probe).await {
        if is_sip_response(&resp) {
            confirmed = true;
            findings.push(social_finding(
                engine_id,
                "Exposed SIP/VoIP service (UDP 5060)",
                "high",
                mitre,
                &format!("{host}:5060/udp answered a SIP OPTIONS probe — an exposed PBX/SIP trunk enables caller-ID spoofing and vishing / toll-fraud abuse."),
                target,
            ));
        }
    }
    if !confirmed {
        if let Some(resp) = tcp_probe_response(host, 5060, &probe).await {
            if is_sip_response(&resp) {
                confirmed = true;
                findings.push(social_finding(
                    engine_id,
                    "Exposed SIP/VoIP service (TCP 5060)",
                    "high",
                    mitre,
                    &format!("{host}:5060/tcp answered a SIP OPTIONS probe — exposed VoIP signalling reachable for vishing infrastructure abuse."),
                    target,
                ));
            }
        }
    }
    if !confirmed && tcp_open(host, 5061).await {
        findings.push(social_finding(
            engine_id,
            "SIP-TLS port open (5061)",
            "medium",
            mitre,
            &format!("{host}:5061/tcp is open (SIP-TLS candidate) — confirm VoIP exposure and vishing / toll-fraud risk."),
            target,
        ));
    }
    findings
}

// ── SMS gateway surface (smishing infrastructure) ───────────────────────────

/// True if an HTTP body/path looks like a third-party SMS-send API surface.
fn is_sms_api_surface(path: &str, body_lower: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("sms")
        || p.contains("message")
        || body_lower.contains("twilio")
        || body_lower.contains("messagebird")
        || body_lower.contains("vonage")
        || body_lower.contains("nexmo")
}

/// Probe for an exposed SMS gateway (SMPP 2775) or SMS-send HTTP API — the
/// infrastructure abused to blast spoofed smishing messages.
async fn sms_gateway_surface(
    host: &str,
    base: &str,
    engine_id: &str,
    mitre: &str,
    target: &str,
) -> Vec<Value> {
    let mut findings = Vec::new();
    // SMPP (Short Message Peer-to-Peer) default port.
    if tcp_open(host, 2775).await {
        findings.push(social_finding(
            engine_id,
            "SMPP SMS-gateway port open (2775)",
            "high",
            mitre,
            &format!("{host}:2775/tcp (SMPP) is reachable — an exposed SMS gateway can be abused to send spoofed smishing messages at scale."),
            target,
        ));
    }
    let client = http_client().await;
    for path in [
        "/api/sms",
        "/api/sms/send",
        "/sms/send",
        "/api/messages",
        "/webhook/sms",
    ] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            // A POST-only send endpoint typically answers 405/401/400 (not 404)
            // to a GET; that plus the sms-named path is a real surface signal.
            if p.status != 0
                && p.status != 404
                && (matches!(p.status, 400 | 401 | 403 | 405)
                    || is_sms_api_surface(path, &p.body.to_ascii_lowercase()))
            {
                findings.push(social_finding(
                    engine_id,
                    "SMS-send API surface reachable",
                    "medium",
                    mitre,
                    &format!("{} (HTTP {}) exposes an SMS-send API surface — verify authentication and rate-limits to prevent smishing abuse.", p.final_url, p.status),
                    target,
                ));
                break;
            }
        }
    }
    findings
}

// ── Look-alike domain surface (BEC / impersonation infrastructure) ──────────

/// Generate common look-alike variants of a registrable domain (character
/// doubling, deletion, hyphen insertion, and digit/letter homoglyph swaps).
/// Pure + bounded so it is unit-testable and cheap.
fn lookalike_variants(domain: &str) -> Vec<String> {
    let Some((label, tld)) = domain.split_once('.') else {
        return Vec::new();
    };
    if label.len() < 3 {
        return Vec::new();
    }
    let chars: Vec<char> = label.chars().collect();
    let mid = chars.len() / 2;
    let mut candidates: Vec<String> = Vec::new();
    // Doubled first character.
    candidates.push(format!("{}{}", chars[0], label));
    // Single-character deletion at the middle.
    candidates.push(
        chars
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != mid)
            .map(|(_, c)| *c)
            .collect(),
    );
    // Hyphen inserted in the middle (common BEC trick: "my-company"). Split on a
    // char boundary, not a byte index.
    let a: String = chars[..mid].iter().collect();
    let b: String = chars[mid..].iter().collect();
    candidates.push(format!("{a}-{b}"));
    // Homoglyph swaps (o↔0, l↔1, i↔1, e↔3).
    for (from, to) in [('o', '0'), ('l', '1'), ('i', '1'), ('e', '3')] {
        if label.contains(from) {
            candidates.push(label.replacen(from, &to.to_string(), 1));
        }
    }
    // De-duplicate and drop the identity, then attach the TLD.
    let mut out: Vec<String> = Vec::new();
    for c in candidates {
        if c != label && !out.contains(&c) {
            out.push(c);
        }
    }
    out.into_iter()
        .map(|l| format!("{l}.{tld}"))
        .take(6)
        .collect()
}

/// Resolve a few look-alike variants; registered/live ones are candidate BEC
/// (business-email-compromise) impersonation infrastructure.
async fn lookalike_domain_surface(
    domain: &str,
    engine_id: &str,
    mitre: &str,
    target: &str,
) -> Vec<Value> {
    let mut findings = Vec::new();
    for variant in lookalike_variants(domain) {
        if !dns_a(&variant).await.is_empty() {
            findings.push(social_finding(
                engine_id,
                "Registered look-alike domain resolves",
                "high",
                mitre,
                &format!("Look-alike of {domain} → {variant} resolves to a live host — candidate BEC / exec-impersonation infrastructure. Confirm ownership and monitor for spoofed-sender abuse."),
                target,
            ));
        }
    }
    findings
}

fn build_social_result(
    engine_id: &str,
    target: &str,
    findings: Vec<Value>,
    label: &str,
) -> EngineResult {
    if findings.is_empty() {
        empty_ok(engine_id, target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("{engine_id}: {n} {label}"))
    }
}

/// Public login / credential-harvest surface (the spear-phishing payload target).
async fn phishing_login_findings(t: &str, engine_id: &str, mitre: &str) -> Vec<Value> {
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    for path in [
        "/login",
        "/signin",
        "/auth/login",
        "/account/login",
        "/sso/login",
    ] {
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
                        && !body.contains(&format!(
                            "action=\"https://{}",
                            extract_host(t).to_ascii_lowercase()
                        )));
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
    findings
}

/// Thin wrapper kept for callers that want the login surface as a standalone
/// engine result (e.g. `linkedin_phishing`).
async fn phishing_login_surface(t: &str, engine_id: &str, mitre: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let findings = phishing_login_findings(t, engine_id, mitre).await;
    build_social_result(engine_id, t, findings, "login surface signal(s)")
}

pub async fn run_spear_phishing_engine_result(t: &str) -> EngineResult {
    // Spear phishing arrives by email; the payload target is a credential-harvest
    // login page. Assess both the email-auth posture and the public login surface.
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let mut findings = email_auth_findings(t, "spear_phishing_engine", "T1566.001").await;
    findings.extend(phishing_login_findings(t, "spear_phishing_engine", "T1566.001").await);
    build_social_result(
        "spear_phishing_engine",
        t,
        findings,
        "spear-phishing surface signal(s)",
    )
}
cli_wrapper!(run_spear_phishing_engine, run_spear_phishing_engine_result);

pub async fn run_vishing_engine_result(t: &str) -> EngineResult {
    // Voice phishing rides on VoIP/PBX infrastructure — probe SIP, not email.
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let findings = voip_sip_surface(&host, "vishing_engine", "T1566.004", t).await;
    build_social_result("vishing_engine", t, findings, "VoIP/SIP exposure signal(s)")
}
cli_wrapper!(run_vishing_engine, run_vishing_engine_result);

pub async fn run_smishing_engine_result(t: &str) -> EngineResult {
    // SMS phishing rides on SMS gateways (SMPP) / SMS-send APIs — probe those.
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let base = normalize_url(t);
    let findings = sms_gateway_surface(&host, &base, "smishing_engine", "T1566.004", t).await;
    build_social_result(
        "smishing_engine",
        t,
        findings,
        "SMS-gateway exposure signal(s)",
    )
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
        if body.contains("qrcode")
            || body.contains("qr-code")
            || body.contains("data:image/svg+xml")
        {
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
    // BEC impersonates trusted senders via registered look-alike domains and
    // exploits unenforced DMARC. Assess email-auth posture + live look-alikes.
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings = email_auth_findings(t, "business_email_compromise", "T1566.001").await;
    findings
        .extend(lookalike_domain_surface(&host, "business_email_compromise", "T1566.001", t).await);
    build_social_result(
        "business_email_compromise",
        t,
        findings,
        "BEC exposure signal(s)",
    )
}
cli_wrapper!(
    run_business_email_compromise,
    run_business_email_compromise_result
);

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
        if body.contains("chrome update")
            || body.contains("update.exe")
            || body.contains("urgent security patch")
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
    // Callback / TOAD (telephone-oriented attack delivery) pairs an email lure
    // with a phone callback number — assess the email posture AND the VoIP surface.
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings = email_auth_findings(t, "callback_phishing", "T1566.001").await;
    findings.extend(voip_sip_surface(&host, "callback_phishing", "T1566.001", t).await);
    build_social_result(
        "callback_phishing",
        t,
        findings,
        "callback-phishing surface signal(s)",
    )
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
cli_wrapper!(
    run_typosquatting_phishing,
    run_typosquatting_phishing_result
);

#[cfg(test)]
mod social_channel_tests {
    use super::{is_sip_response, is_sms_api_surface, lookalike_variants};

    #[test]
    fn sip_response_detected() {
        assert!(is_sip_response(b"SIP/2.0 200 OK\r\nVia: ..."));
        assert!(is_sip_response(b"sip/2.0 486 Busy Here"));
        assert!(!is_sip_response(b"HTTP/1.1 200 OK"));
        assert!(!is_sip_response(b""));
    }

    #[test]
    fn sms_api_surface_detected() {
        assert!(is_sms_api_surface("/api/sms/send", ""));
        assert!(is_sms_api_surface("/api/messages", ""));
        assert!(is_sms_api_surface("/webhook/x", "powered by twilio"));
        assert!(!is_sms_api_surface("/login", "welcome"));
    }

    #[test]
    fn lookalike_variants_are_plausible_and_bounded() {
        let v = lookalike_variants("example.com");
        assert!(!v.is_empty() && v.len() <= 6);
        // Every variant keeps the TLD and differs from the original label.
        assert!(v.iter().all(|d| d.ends_with(".com") && d != "example.com"));
        // A homoglyph swap fires for letters present in the label (example has
        // 'e' and 'l', so expect a '3' or '1' variant).
        assert!(v.iter().any(|d| d.contains('3') || d.contains('1')));
        // The o->0 homoglyph fires only when the label contains an 'o'.
        let vo = lookalike_variants("proton.com");
        assert!(
            vo.iter().any(|d| d.contains('0')),
            "o->0 homoglyph expected"
        );
        // Too-short labels produce nothing (avoids noise).
        assert!(lookalike_variants("ab.com").is_empty());
    }
}
