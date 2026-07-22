//! Supreme-tier password spray / credential-stuffing synthesis — toxic combos, security graph,
//! agent guidance, transport hardening probes. Called from the main password_spray engine module.

use super::{with_fields, SprayPosture, ENGINE_ID, MITRE_SPRAY, MITRE_STUFF, MITRE_VALID};
use crate::arsenal_config::{finding_rich, Evidence};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use crate::engine_probes::{http_get, join_url};
use reqwest::Client;
use serde_json::{json, Value};

const WEBAUTHN_MARKERS: &[&str] = &[
    "webauthn",
    "passkey",
    "fido2",
    "publickeycredential",
    "navigator.credentials",
    "authenticatorselection",
    "passwordless",
    "windows hello",
];

// ─── Transport / hardening probes (real HTTP observations) ───────────────────────

pub async fn probe_hsts_auth_surface(client: &Client, url: &str, target: &str) -> Option<Value> {
    let resp = http_get(client, url).await?;
    let hsts = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("strict-transport-security"))
        .map(|(_, v)| v.clone());
    if hsts.is_some() {
        return None;
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Auth surface missing HSTS: {url}"),
            "medium",
            MITRE_SPRAY,
            "Login/SSO endpoint responds without Strict-Transport-Security — credential submission vulnerable to SSL-stripping and on-path downgrade before MFA step-up.",
            target,
            0.84,
            Evidence::new()
                .with("url", url)
                .with("hsts_present", false)
                .check("hsts_probe", true, "live GET observed"),
        ),
        &[("category", json!("transport_hardening"))],
    ))
}

pub async fn probe_webauthn_surface(client: &Client, url: &str, target: &str) -> Option<Value> {
    let resp = http_get(client, url).await?;
    let bl = resp.body.to_ascii_lowercase();
    let hits: Vec<&str> = WEBAUTHN_MARKERS
        .iter()
        .copied()
        .filter(|m| bl.contains(m))
        .collect();
    if hits.is_empty() {
        return None;
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Passwordless/WebAuthn surface detected: {url}"),
            "info",
            MITRE_VALID,
            &format!(
                "Login page references passwordless/FIDO markers ({}) — phishing-resistant path available; ensure spray-viable password forms are disabled or MFA-gated.",
                hits.join(", ")
            ),
            target,
            0.9,
            Evidence::new()
                .with("url", url)
                .with("markers", json!(hits)),
        ),
        &[("category", json!("webauthn_surface"))],
    ))
}

pub async fn probe_oidc_pkce_posture(client: &Client, base: &str, target: &str) -> Option<Value> {
    let well_known = join_url(base, "/.well-known/openid-configuration");
    let resp = http_get(client, &well_known).await?;
    if resp.status != 200 {
        return None;
    }
    let parsed: Value = serde_json::from_str(&resp.body).ok()?;
    let methods = parsed
        .get("code_challenge_methods_supported")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if methods.iter().any(|m| m == "s256" || m == "plain") {
        return Some(with_fields(
            finding_rich(
                ENGINE_ID,
                "OIDC PKCE supported — authorize flow hardening present",
                "info",
                MITRE_VALID,
                &format!(
                    "OpenID configuration at {well_known} advertises code_challenge_methods_supported: {:?}. PKCE reduces authorization-code interception during federated login.",
                    methods
                ),
                target,
                0.88,
                Evidence::new()
                    .with("url", well_known)
                    .with("code_challenge_methods", json!(methods)),
            ),
            &[("category", json!("oidc_pkce"))],
        ));
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            "OIDC authorize flow without PKCE advertisement",
            "medium",
            MITRE_SPRAY,
            &format!(
                "OpenID configuration at {well_known} does not advertise code_challenge_methods_supported — federated login may accept authorize requests without PKCE binding."
            ),
            target,
            0.82,
            Evidence::new()
                .with("url", well_known)
                .with("code_challenge_methods", json!(methods)),
        ),
        &[("category", json!("oidc_pkce"))],
    ))
}

pub async fn probe_login_cookie_security(
    client: &Client,
    url: &str,
    target: &str,
) -> Option<Value> {
    let resp = http_get(client, url).await?;
    let cookies: Vec<String> = resp
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.clone())
        .collect();
    if cookies.is_empty() {
        return None;
    }
    let mut gaps = Vec::new();
    for c in &cookies {
        let cl = c.to_ascii_lowercase();
        if !cl.contains("secure") {
            gaps.push("missing Secure");
        }
        if !cl.contains("httponly") {
            gaps.push("missing HttpOnly");
        }
        if !cl.contains("samesite") {
            gaps.push("missing SameSite");
        }
    }
    if gaps.is_empty() {
        return None;
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Auth Set-Cookie hardening gaps: {url}"),
            "medium",
            MITRE_SPRAY,
            &format!(
                "Login response Set-Cookie headers lack hardening attributes ({}) — session fixation / XSS token theft amplifies spray success.",
                gaps.join("; ")
            ),
            target,
            0.83,
            Evidence::new()
                .with("url", url)
                .with("set_cookie_count", cookies.len())
                .with("gaps", json!(gaps)),
        ),
        &[("category", json!("cookie_security"))],
    ))
}

pub async fn run_transport_probes(
    client: &Client,
    base: &str,
    posture: &mut SprayPosture,
    findings: &mut Vec<Value>,
    target: &str,
    check_hsts: bool,
    check_webauthn: bool,
    check_pkce: bool,
    check_cookies: bool,
) {
    let probe_urls: Vec<String> = {
        let mut u: Vec<String> = posture
            .login_surfaces
            .iter()
            .map(|s| s.url.clone())
            .take(6)
            .collect();
        if u.is_empty() {
            u.push(base.to_string());
        }
        u
    };

    if check_pkce {
        if let Some(f) = probe_oidc_pkce_posture(client, base, target).await {
            findings.push(f);
        }
    }
    for url in probe_urls {
        if check_hsts {
            if let Some(f) = probe_hsts_auth_surface(client, &url, target).await {
                posture.transport_gaps.push(url.clone());
                findings.push(f);
            }
        }
        if check_webauthn {
            if let Some(f) = probe_webauthn_surface(client, &url, target).await {
                posture.webauthn_surfaces.push(url.clone());
                findings.push(f);
            }
        }
        if check_cookies {
            if let Some(f) = probe_login_cookie_security(client, &url, target).await {
                posture.cookie_gaps.push(url.clone());
                findings.push(f);
            }
        }
    }
}

// ─── 8-domain category scores ────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct SprayCategoryScores {
    pub rate_limiting: f64,
    pub lockout_policy: f64,
    pub mfa_captcha: f64,
    pub enumeration_resistance: f64,
    pub federation_hygiene: f64,
    pub oidc_token_hygiene: f64,
    pub automation_resistance: f64,
    pub transport_session: f64,
}

impl SprayCategoryScores {
    fn from_posture(p: &SprayPosture) -> Self {
        let penalize =
            |gaps: usize, w: f64| -> f64 { (100.0 - (gaps.min(4) as f64) * w).clamp(0.0, 100.0) };
        Self {
            rate_limiting: penalize(p.no_rate_limit.len(), 22.0),
            lockout_policy: penalize(p.no_lockout.len() + p.short_lockout_decay.len(), 18.0),
            mfa_captcha: penalize(p.mfa_absent.len() + p.captcha_absent.len(), 15.0),
            enumeration_resistance: penalize(
                p.user_enum.len()
                    + p.timing_enum_surfaces.len()
                    + p.breach_oracles.len()
                    + p.verbose_errors.len(),
                12.0,
            ),
            federation_hygiene: penalize(
                p.federated_exposed.len()
                    + p.saml_exposed.len()
                    + if p.m365_federated { 1 } else { 0 },
                14.0,
            ),
            oidc_token_hygiene: penalize(p.ropc_enabled.len() + p.device_code_enabled.len(), 25.0),
            automation_resistance: penalize(
                p.browser_waf_gaps.len() + p.xff_bypassable.len() + p.cors_permissive.len(),
                16.0,
            ),
            transport_session: penalize(p.transport_gaps.len() + p.cookie_gaps.len(), 20.0),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "rate_limiting": self.rate_limiting.round() as u32,
            "lockout_policy": self.lockout_policy.round() as u32,
            "mfa_captcha": self.mfa_captcha.round() as u32,
            "enumeration_resistance": self.enumeration_resistance.round() as u32,
            "federation_hygiene": self.federation_hygiene.round() as u32,
            "oidc_token_hygiene": self.oidc_token_hygiene.round() as u32,
            "automation_resistance": self.automation_resistance.round() as u32,
            "transport_session": self.transport_session.round() as u32,
        })
    }
}

pub fn finalize_category_scores(posture: &SprayPosture) -> SprayCategoryScores {
    SprayCategoryScores::from_posture(posture)
}

// ─── Extended attack paths ─────────────────────────────────────────────────────

pub fn extend_attack_paths(
    target: &str,
    posture: &SprayPosture,
    host: &str,
    findings: &mut Vec<Value>,
) {
    if !posture.timing_enum_surfaces.is_empty() && !posture.no_rate_limit.is_empty() {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: timing enumeration → unthrottled spray",
                "critical",
                MITRE_STUFF,
                &format!(
                    "Timing oracle on {:?} combined with absent rate-limiting enables high-precision account harvesting followed by distributed spray on {host}.",
                    posture.timing_enum_surfaces.first()
                ),
                target,
                0.93,
                Evidence::new()
                    .with("stage_1", "timing_user_enum")
                    .with("stage_2", "password_spray")
                    .with("stage_3", "valid_account"),
            ),
            &[("category", json!("attack_path"))],
        ));
    }
    if !posture.breach_oracles.is_empty() && !posture.no_lockout.is_empty() {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: breach-password oracle → stuffing without lockout",
                "critical",
                MITRE_STUFF,
                &format!(
                    "Distinct error handling for known-breach passwords on {:?} with no lockout policy — credential stuffing at scale.",
                    posture.breach_oracles.first()
                ),
                target,
                0.91,
                Evidence::new()
                    .with("stage_1", "breach_password_probe")
                    .with("stage_2", "credential_stuffing"),
            ),
            &[("category", json!("attack_path"))],
        ));
    }
    if !posture.device_code_enabled.is_empty() && !posture.mfa_absent.is_empty() {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: device-code phish → token without MFA gate",
                "high",
                MITRE_VALID,
                &format!(
                    "OIDC device-code grant on {:?} with absent MFA on password surfaces — attacker phishes device code, obtains refresh token.",
                    posture.device_code_enabled.first()
                ),
                target,
                0.87,
                Evidence::new()
                    .with("stage_1", "device_code_phish")
                    .with("stage_2", "token_acquisition"),
            ),
            &[("category", json!("attack_path"))],
        ));
    }
    if !posture.cors_permissive.is_empty() && !posture.user_enum.is_empty() {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: CORS + enumeration → browser-origin spray",
                "high",
                MITRE_SPRAY,
                &format!(
                    "Permissive CORS on {:?} with user-enumeration oracle — malicious site can spray from victim browser origin.",
                    posture.cors_permissive.first()
                ),
                target,
                0.86,
                Evidence::new()
                    .with("stage_1", "cors_abuse")
                    .with("stage_2", "browser_origin_spray"),
            ),
            &[("category", json!("attack_path"))],
        ));
    }
    if !posture.short_lockout_decay.is_empty() && posture.captcha_absent.len() > 0 {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: short lockout decay → perpetual low-and-slow spray",
                "high",
                MITRE_SPRAY,
                &format!(
                    "Lockout window decays quickly on {:?} without CAPTCHA — attacker cycles IP/username sets indefinitely.",
                    posture.short_lockout_decay.first()
                ),
                target,
                0.88,
                Evidence::new()
                    .with("stage_1", "lockout_decay_probe")
                    .with("stage_2", "infinite_spray_cycle"),
            ),
            &[("category", json!("attack_path"))],
        ));
    }
    if posture.m365_federated && !posture.no_rate_limit.is_empty() {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: Entra federated tenant → IdP password spray",
                "high",
                MITRE_SPRAY,
                &format!(
                    "Managed/Federated M365 tenant for {host} with unthrottled login surface — spray targets upstream IdP (ADFS/Okta) not Entra lockout counters alone."
                ),
                target,
                0.84,
                Evidence::new()
                    .with("stage_1", "m365_realm_intel")
                    .with("stage_2", "idp_password_spray"),
            ),
            &[("category", json!("attack_path"))],
        ));
    }
}

// ─── Toxic combination headline (Wiz-style) ────────────────────────────────────

pub fn emit_toxic_headline(target: &str, posture: &SprayPosture, findings: &mut Vec<Value>) {
    let mut combos = Vec::new();
    if !posture.no_rate_limit.is_empty()
        && !posture.user_enum.is_empty()
        && !posture.mfa_absent.is_empty()
    {
        combos.push(
            "no rate-limit + user enumeration + no MFA ⇒ targeted spray → valid account in hours",
        );
    }
    if !posture.ropc_enabled.is_empty() && !posture.no_lockout.is_empty() {
        combos.push(
            "OIDC ROPC grant + no lockout ⇒ direct bearer token from spray (bypasses browser MFA)",
        );
    }
    if !posture.xff_bypassable.is_empty() && !posture.no_rate_limit.is_empty() {
        combos.push(
            "X-Forwarded-For IP rotation + no rate-limit ⇒ distributed spray behind single egress",
        );
    }
    if !posture.browser_waf_gaps.is_empty() && !posture.no_lockout.is_empty() {
        combos.push("script UA bypasses WAF + no lockout ⇒ automated stuffing at API scale");
    }
    if !posture.timing_enum_surfaces.is_empty() && !posture.federated_exposed.is_empty() {
        combos.push("timing enumeration + federated SSO ⇒ precision spray against upstream IdP");
    }
    if !posture.device_code_enabled.is_empty() && !posture.captcha_absent.is_empty() {
        combos.push(
            "device-code grant + no CAPTCHA ⇒ token phishing chain parallel to password spray",
        );
    }
    if posture.m365_federated
        && !posture.no_rate_limit.is_empty()
        && !posture.saml_exposed.is_empty()
    {
        combos.push(
            "M365 federated + SAML metadata + unthrottled login ⇒ IdP spray with federation intel",
        );
    }
    if combos.is_empty() {
        return;
    }
    let headline = combos.join(" ⊕ ");
    findings.insert(
        0,
        with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("TOXIC COMBINATION: {headline}"),
                "critical",
                MITRE_SPRAY,
                "Correlated credential-attack exposures form a breach chain beyond individual findings — execute P0 controls within 24h.",
                target,
                0.97,
                Evidence::new()
                    .with("combinations", json!(combos))
                    .with("toxic_count", combos.len())
                    .with("stuffing_friction", posture.stuffing_friction()),
            ),
            &[("category", json!("toxic_combination"))],
        ),
    );
}

// ─── Prioritized remediation roadmap ─────────────────────────────────────────────

pub fn emit_remediation_roadmap(target: &str, posture: &SprayPosture, findings: &mut Vec<Value>) {
    let mut steps: Vec<Value> = Vec::new();
    let mut priority = 1u8;
    let mut push = |tier: &str, action: &str, detail: &str, effort: &str| {
        steps.push(json!({
            "priority": priority,
            "tier": tier,
            "action": action,
            "detail": detail,
            "effort": effort,
        }));
        priority += 1;
    };

    if !posture.ropc_enabled.is_empty() {
        push(
            "P0",
            "Disable OIDC ROPC grant",
            "Block password grant on all app registrations; migrate to auth-code + PKCE",
            "hours",
        );
    }
    if !posture.no_rate_limit.is_empty() {
        push(
            "P0",
            "Enforce per-username rate limiting",
            "HTTP 429 on login/token endpoints; align CDN/WAF with origin counters",
            "hours",
        );
    }
    if !posture.user_enum.is_empty() || !posture.timing_enum_surfaces.is_empty() {
        push("P0", "Normalize auth failure responses", "Identical status/body/timing for valid vs invalid users; strip AADSTS distinctions at edge", "days");
    }
    if !posture.xff_bypassable.is_empty() {
        push(
            "P0",
            "Rate-limit on account identity not IP alone",
            "Ignore X-Forwarded-For for auth throttling unless from trusted proxy list",
            "hours",
        );
    }
    if !posture.mfa_absent.is_empty() {
        push(
            "P1",
            "Phishing-resistant MFA everywhere",
            "FIDO2/WHfB on all spray-viable surfaces including federated IdP",
            "days",
        );
    }
    if !posture.device_code_enabled.is_empty() {
        push(
            "P1",
            "Restrict device-code flow",
            "Limit to native clients; require admin consent; monitor device-code grants",
            "days",
        );
    }
    if !posture.short_lockout_decay.is_empty() {
        push(
            "P1",
            "Extend lockout duration + progressive backoff",
            "Smart lockout ≥15min; CAPTCHA after N failures",
            "days",
        );
    }
    if !posture.cors_permissive.is_empty() {
        push(
            "P1",
            "Tighten CORS on auth APIs",
            "Reject wildcard origins on login/token endpoints",
            "hours",
        );
    }
    if !posture.browser_waf_gaps.is_empty() {
        push(
            "P1",
            "Block unregistered script clients",
            "Require registered OAuth clients; block curl/python UA on auth unless API",
            "days",
        );
    }
    push(
        "P2",
        "Deploy Entra Password Protection + banned-password list",
        "Block spray wordlists at directory level",
        "days",
    );
    push(
        "P2",
        "Honeypot accounts + spray detection analytics",
        "Alert on weissman_probe-style synthetic username patterns",
        "days",
    );

    if steps.is_empty() {
        return;
    }
    findings.push(with_fields(
        finding_rich(
            ENGINE_ID,
            "Prioritized credential-attack remediation roadmap",
            "info",
            MITRE_SPRAY,
            "Ordered remediation plan derived from observed spray/stuffing gaps — P0 items reduce breach blast radius within 24h.",
            target,
            0.99,
            Evidence::new()
                .with("roadmap", Value::Array(steps))
                .with("category_scores", finalize_category_scores(posture).to_json()),
        ),
        &[("category", json!("remediation_roadmap"))],
    ));
}

// ─── Honest agent-guidance ───────────────────────────────────────────────────────

pub fn emit_agent_guidance(target: &str, findings: &mut Vec<Value>) {
    let capabilities = [
        (
            "entra_signin_risk_logs",
            "Entra ID Sign-in risk logs + impossible-travel correlation for spray campaigns",
        ),
        (
            "defender_identity_lockout",
            "Microsoft Defender for Identity lockout source IP attribution on-DC",
        ),
        (
            "okta_threatinsight_feed",
            "Okta ThreatInsight / behavior analytics with live session revocation",
        ),
        (
            "password_spray_honeypots",
            "AD honeypot accounts with instant SOC alert on TGS/SAML auth",
        ),
        (
            "kerberos_preauth_audit",
            "Kerberos pre-auth failure volume per source IP (internal vantage)",
        ),
        (
            "conditional_access_eval",
            "Full Conditional Access policy simulation per sprayed account",
        ),
    ];
    for (cap, desc) in capabilities {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Agent-required: {desc}"),
                "info",
                MITRE_SPRAY,
                &format!(
                    "Capability `{cap}` requires Weissman host agent or internal IdP vantage — \
                     not fully observable via external agentless scan."
                ),
                target,
                1.0,
                Evidence::new()
                    .with("capability", cap)
                    .with("requires_agent", true),
            ),
            &[("category", json!("agent_guidance"))],
        ));
    }
}

// ─── Security graph ──────────────────────────────────────────────────────────────

pub fn build_security_graph(
    target: &str,
    posture: &SprayPosture,
    host: &str,
) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let score = posture.score();
    let mut nodes = vec![GraphNode {
        id: "root".to_string(),
        label: host.to_string(),
        node_type: "root".to_string(),
        status: if score >= 80 {
            "secure".to_string()
        } else if score >= 50 {
            "degraded".to_string()
        } else {
            "exposed".to_string()
        },
        cname_target: None,
        raw_finding: None,
    }];
    let mut edges = Vec::new();
    let mut add = |id: &str, label: &str, kind: &str, exposed: bool| {
        nodes.push(GraphNode {
            id: id.to_string(),
            label: label.to_string(),
            node_type: "identity_surface".to_string(),
            status: if exposed {
                "exposed".to_string()
            } else {
                "secure".to_string()
            },
            cname_target: None,
            raw_finding: None,
        });
        edges.push(GraphEdge {
            id: format!("e_root_{id}"),
            from_id: "root".to_string(),
            to_id: id.to_string(),
            edge_type: kind.to_string(),
        });
    };

    add(
        "login_surfaces",
        &format!("{} login surface(s)", posture.login_surfaces.len()),
        "LOGIN_DISCOVERY",
        !posture.login_surfaces.is_empty(),
    );
    if !posture.no_rate_limit.is_empty() {
        add("no_ratelimit", "No rate-limiting", "RATE_LIMIT_GAP", true);
    }
    if !posture.user_enum.is_empty() {
        add("user_enum", "User enumeration oracle", "ENUM_ORACLE", true);
    }
    if !posture.ropc_enabled.is_empty() {
        add("ropc", "OIDC ROPC grant", "ROPC_EXPOSED", true);
    }
    if !posture.mfa_absent.is_empty() {
        add("no_mfa", "MFA absent on spray surface", "MFA_GAP", true);
    }
    if posture.m365_federated {
        add("m365_fed", "M365 federated tenant", "M365_FEDERATED", true);
    }
    if !posture.xff_bypassable.is_empty() {
        add("xff_bypass", "XFF rate-limit bypass", "XFF_BYPASS", true);
    }

    if !posture.no_rate_limit.is_empty() && !posture.user_enum.is_empty() {
        edges.push(GraphEdge {
            id: "ap_spray".to_string(),
            from_id: "user_enum".to_string(),
            to_id: "no_ratelimit".to_string(),
            edge_type: "ENUM_TO_SPRAY".to_string(),
        });
    }
    if !posture.ropc_enabled.is_empty() && !posture.no_lockout.is_empty() {
        edges.push(GraphEdge {
            id: "ap_ropc".to_string(),
            from_id: "ropc".to_string(),
            to_id: "no_ratelimit".to_string(),
            edge_type: "ROPC_TOKEN_CHAIN".to_string(),
        });
    }
    if !posture.mfa_absent.is_empty() && !posture.no_rate_limit.is_empty() {
        edges.push(GraphEdge {
            id: "ap_valid".to_string(),
            from_id: "no_ratelimit".to_string(),
            to_id: "no_mfa".to_string(),
            edge_type: "VALID_ACCOUNT_PIVOT".to_string(),
        });
    }

    let _ = target;
    (nodes, edges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password_spray_engine::LoginSurface;

    fn strv(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("s{i}")).collect()
    }

    #[test]
    fn category_scores_penalize_per_axis() {
        let posture = SprayPosture {
            no_rate_limit: strv(1),
            no_lockout: strv(1),
            short_lockout_decay: strv(1),
            mfa_absent: strv(1),
            captcha_absent: strv(1),
            user_enum: strv(1),
            timing_enum_surfaces: strv(1),
            breach_oracles: strv(1),
            verbose_errors: strv(1),
            federated_exposed: strv(1),
            saml_exposed: strv(1),
            m365_federated: true,
            ropc_enabled: strv(1),
            device_code_enabled: strv(1),
            browser_waf_gaps: strv(1),
            xff_bypassable: strv(1),
            cors_permissive: strv(1),
            transport_gaps: strv(1),
            cookie_gaps: strv(1),
            ..Default::default()
        };
        let s = finalize_category_scores(&posture);
        assert_eq!(s.rate_limiting, 78.0); // 100 - 1*22
        assert_eq!(s.lockout_policy, 64.0); // 100 - 2*18
        assert_eq!(s.mfa_captcha, 70.0); // 100 - 2*15
        assert_eq!(s.enumeration_resistance, 52.0); // 100 - min(4,4)*12
        assert_eq!(s.federation_hygiene, 58.0); // 100 - 3*14
        assert_eq!(s.oidc_token_hygiene, 50.0); // 100 - 2*25
        assert_eq!(s.automation_resistance, 52.0); // 100 - 3*16
        assert_eq!(s.transport_session, 60.0); // 100 - 2*20

        let j = s.to_json();
        assert_eq!(j["rate_limiting"], 78);
        assert_eq!(j["oidc_token_hygiene"], 50);
        assert_eq!(j["transport_session"], 60);
    }

    #[test]
    fn category_scores_default_posture_is_perfect() {
        let s = finalize_category_scores(&SprayPosture::default());
        assert_eq!(s.rate_limiting, 100.0);
        assert_eq!(s.transport_session, 100.0);
        assert_eq!(s.to_json()["mfa_captcha"], 100);
    }

    #[test]
    fn category_scores_clamp_to_zero_and_cap_gap_count() {
        // 4 device-code gaps: min(4)*25 == 100 -> clamps to 0.
        let posture = SprayPosture {
            device_code_enabled: strv(4),
            // 10 enumeration gaps still capped at min(4): 100 - 48 == 52.
            user_enum: strv(10),
            ..Default::default()
        };
        let s = finalize_category_scores(&posture);
        assert_eq!(s.oidc_token_hygiene, 0.0);
        assert_eq!(s.enumeration_resistance, 52.0);
    }

    #[test]
    fn extend_attack_paths_emits_nothing_without_combos() {
        let mut findings = Vec::new();
        extend_attack_paths("tgt", &SprayPosture::default(), "host", &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn extend_attack_paths_emits_timing_plus_spray_chain() {
        let posture = SprayPosture {
            timing_enum_surfaces: strv(1),
            no_rate_limit: strv(1),
            ..Default::default()
        };
        let mut findings = Vec::new();
        extend_attack_paths("tgt", &posture, "host", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "critical");
        assert_eq!(findings[0]["category"], "attack_path");
        assert_eq!(
            findings[0]["title"],
            "Attack path: timing enumeration → unthrottled spray"
        );
    }

    #[test]
    fn toxic_headline_inserts_only_when_combo_present() {
        let mut findings = Vec::new();
        emit_toxic_headline("tgt", &SprayPosture::default(), &mut findings);
        assert!(findings.is_empty());

        let posture = SprayPosture {
            no_rate_limit: strv(1),
            user_enum: strv(1),
            mfa_absent: strv(1),
            ..Default::default()
        };
        emit_toxic_headline("tgt", &posture, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "critical");
        assert_eq!(findings[0]["category"], "toxic_combination");
        assert!(findings[0]["title"]
            .as_str()
            .unwrap()
            .starts_with("TOXIC COMBINATION:"));
    }

    #[test]
    fn agent_guidance_emits_six_info_findings() {
        let mut findings = Vec::new();
        emit_agent_guidance("tgt", &mut findings);
        assert_eq!(findings.len(), 6);
        assert!(findings
            .iter()
            .all(|f| f["severity"] == "info" && f["category"] == "agent_guidance"));
    }

    #[test]
    fn remediation_roadmap_always_emits_p2_baseline() {
        let mut findings = Vec::new();
        emit_remediation_roadmap("tgt", &SprayPosture::default(), &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "info");
        assert_eq!(findings[0]["category"], "remediation_roadmap");
        // Only the two unconditional P2 steps for an empty posture.
        let roadmap = findings[0]["evidence"]["roadmap"].as_array().unwrap();
        assert_eq!(roadmap.len(), 2);
        assert_eq!(roadmap[0]["priority"], 1);
        assert_eq!(roadmap[1]["priority"], 2);
        assert_eq!(roadmap[0]["tier"], "P2");
    }

    #[test]
    fn remediation_roadmap_prepends_p0_when_ropc_present() {
        let posture = SprayPosture {
            ropc_enabled: strv(1),
            ..Default::default()
        };
        let mut findings = Vec::new();
        emit_remediation_roadmap("tgt", &posture, &mut findings);
        let roadmap = findings[0]["evidence"]["roadmap"].as_array().unwrap();
        // ROPC P0 step + two P2 baseline steps.
        assert_eq!(roadmap.len(), 3);
        assert_eq!(roadmap[0]["tier"], "P0");
        assert_eq!(roadmap[0]["action"], "Disable OIDC ROPC grant");
    }

    #[test]
    fn security_graph_default_posture_secure_root_login_node() {
        let (nodes, edges) = build_security_graph("tgt", &SprayPosture::default(), "host.io");
        // root + login_surfaces node only.
        assert_eq!(nodes.len(), 2);
        assert_eq!(edges.len(), 1);
        assert_eq!(nodes[0].id, "root");
        assert_eq!(nodes[0].label, "host.io");
        assert_eq!(nodes[0].status, "secure"); // score 100
        assert_eq!(edges[0].from_id, "root");
        assert_eq!(edges[0].to_id, "login_surfaces");
    }

    #[test]
    fn security_graph_adds_exposure_nodes_and_chain_edge() {
        let mut posture = SprayPosture {
            no_rate_limit: strv(1),
            user_enum: strv(1),
            ..Default::default()
        };
        posture.login_surfaces.push(LoginSurface::default());
        let (nodes, edges) = build_security_graph("tgt", &posture, "host.io");
        // root, login_surfaces, no_ratelimit, user_enum.
        assert_eq!(nodes.len(), 4);
        // 3 root edges + 1 ENUM_TO_SPRAY chain edge.
        assert_eq!(edges.len(), 4);
        assert_eq!(nodes[0].status, "degraded"); // 100-22-12 == 66
        assert!(edges.iter().any(|e| e.edge_type == "ENUM_TO_SPRAY"
            && e.from_id == "user_enum"
            && e.to_id == "no_ratelimit"));
    }
}
