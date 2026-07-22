//! Supreme-tier OAuth/OIDC identity synthesis — toxic combos, security graph, agent guidance.

use super::{attack_path_finding, IdentitySignals, T_APP_TOKEN, T_FORGE_OIDC, T_STEAL_TOKEN};
use crate::arsenal_config::{finding_rich, Evidence};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use serde_json::{json, Value};

const ENGINE_ID: &str = "oauth_oidc";

pub struct OidcCategoryScores {
    pub flow_hygiene: f64,
    pub token_crypto: f64,
    pub redirect_validation: f64,
    pub client_authentication: f64,
    pub modern_hardening: f64,
    pub endpoint_exposure: f64,
    pub federation_bridge: f64,
    pub token_endpoint_hygiene: f64,
}

impl OidcCategoryScores {
    fn from_signals(sig: &IdentitySignals) -> Self {
        let bad = |b: bool, w: f64| -> f64 {
            if b {
                100.0 - w
            } else {
                100.0
            }
        };
        let count_penalty =
            |n: usize, w: f64| -> f64 { (100.0 - (n.min(3) as f64) * w).clamp(0.0, 100.0) };
        Self {
            flow_hygiene: bad(
                sig.implicit_flow
                    || sig.ropc_grant
                    || sig.ropc_live_accepts
                    || (sig.device_flow_advertised && sig.device_flow_reachable),
                35.0,
            ),
            token_crypto: bad(
                sig.alg_none || sig.symmetric_alg || sig.weak_jwks_key || sig.jwks_http,
                40.0,
            ),
            redirect_validation: bad(sig.open_redirect_uri, 45.0),
            client_authentication: bad(
                sig.public_clients_allowed && (sig.pkce_not_advertised || sig.pkce_plain_only)
                    || sig.token_issued_without_auth,
                35.0,
            ),
            modern_hardening: bad(
                sig.pkce_not_advertised
                    || sig.pkce_plain_only
                    || sig.pkce_not_enforced_live
                    || sig.par_missing
                    || sig.dpop_missing
                    || sig.backchannel_logout_missing,
                25.0,
            ),
            endpoint_exposure: bad(
                sig.userinfo_anonymous
                    || sig.dcr_open
                    || sig.cors_permissive_metadata
                    || sig.request_uri_unregistered,
                20.0,
            )
            .min(count_penalty(sig.subdomain_takeover_hits, 22.0)),
            federation_bridge: bad(
                sig.saml_metadata_exposed || sig.insecure_issuer_transport,
                30.0,
            ),
            token_endpoint_hygiene: bad(
                sig.introspection_reachable && sig.token_issued_without_auth
                    || sig.ropc_live_accepts,
                35.0,
            ),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "flow_hygiene": self.flow_hygiene.round() as u32,
            "token_crypto": self.token_crypto.round() as u32,
            "redirect_validation": self.redirect_validation.round() as u32,
            "client_authentication": self.client_authentication.round() as u32,
            "modern_hardening": self.modern_hardening.round() as u32,
            "endpoint_exposure": self.endpoint_exposure.round() as u32,
            "federation_bridge": self.federation_bridge.round() as u32,
            "token_endpoint_hygiene": self.token_endpoint_hygiene.round() as u32,
        })
    }
}

pub fn finalize_category_scores(sig: &IdentitySignals) -> OidcCategoryScores {
    OidcCategoryScores::from_signals(sig)
}

pub fn extend_attack_paths(target: &str, sig: &IdentitySignals, findings: &mut Vec<Value>) {
    if sig.device_flow_reachable && sig.pkce_not_enforced_live {
        findings.push(attack_path_finding(
            "Attack path: device-code phish → refresh token without PKCE gate",
            "high",
            T_STEAL_TOKEN,
            "Device authorization endpoint is reachable while PKCE is not enforced on code redemption — parallel phishing path to password-spray campaigns.",
            target,
            0.84,
            &[
                "Phish user with device-code link",
                "User completes auth on legitimate IdP UI",
                "Attacker polls token endpoint for refresh/access token",
                "Replay token against APIs and SSO apps",
            ],
            Evidence::new()
                .check("device_flow", true, "device endpoint reachable")
                .check("pkce_gap", true, "PKCE not enforced live"),
        ));
    }
    if sig.subdomain_takeover_hits > 0 && sig.subdomain_oauth_surfaces > 0 {
        findings.push(attack_path_finding(
            "Attack path: identity subdomain takeover → OAuth redirect hijack",
            "critical",
            T_STEAL_TOKEN,
            "Dangling identity subdomain with OAuth surface lets attacker claim host and receive authorization codes/tokens for registered redirect URIs.",
            target,
            0.9,
            &[
                "Claim abandoned subdomain (GitHub Pages/S3/Heroku signature)",
                "Host OAuth callback matching registered redirect_uri",
                "Phish authorization link to victim",
                "Capture code/token at attacker-controlled subdomain",
            ],
            Evidence::new()
                .with("takeover_hits", sig.subdomain_takeover_hits)
                .with("oauth_surfaces", sig.subdomain_oauth_surfaces),
        ));
    }
    if sig.dcr_open && sig.public_clients_allowed {
        findings.push(attack_path_finding(
            "Attack path: dynamic client registration → rogue public client",
            "high",
            T_APP_TOKEN,
            "Open dynamic client registration combined with public (none) auth enables attacker-registered clients that receive valid authorization codes.",
            target,
            0.82,
            &[
                "Register attacker client via registration_endpoint",
                "Set redirect_uri to attacker host",
                "Run authorization code flow as public client",
                "Maintain persistent SSO access",
            ],
            Evidence::new()
                .check("dcr_open", true, "registration endpoint open")
                .check("public_clients", true, "none auth allowed"),
        ));
    }
    if sig.cors_permissive_metadata && sig.open_redirect_uri {
        findings.push(attack_path_finding(
            "Attack path: CORS metadata abuse + redirect_uri → browser-origin token theft",
            "high",
            T_STEAL_TOKEN,
            "Permissive CORS on discovery/JWKS combined with lax redirect_uri enables malicious-site driven token acquisition from victim browsers.",
            target,
            0.8,
            &[
                "Malicious origin reads OIDC metadata/JWKS via CORS",
                "Craft authorize URL with attacker redirect_uri",
                "Victim browser completes flow",
                "Token/code delivered cross-origin to attacker",
            ],
            Evidence::new()
                .check("cors_metadata", true, "permissive CORS")
                .check("open_redirect", true, "redirect_uri accepted"),
        ));
    }
}

pub fn emit_toxic_headline(target: &str, sig: &IdentitySignals, findings: &mut Vec<Value>) {
    let mut combos = Vec::new();
    if sig.open_redirect_uri && sig.implicit_flow {
        combos.push("lax redirect_uri + implicit flow ⇒ access token exfiltration in URL fragment");
    }
    if sig.alg_none {
        combos.push("alg:none advertised ⇒ trivial unsigned ID-token forgery");
    }
    if sig.open_redirect_uri && sig.pkce_not_enforced_live && sig.public_clients_allowed {
        combos.push(
            "open redirect + public client + no PKCE ⇒ authorization-code interception chain",
        );
    }
    if sig.ropc_live_accepts {
        combos.push("live ROPC acceptance ⇒ direct bearer token from password spray");
    }
    if sig.weak_jwks_key && sig.symmetric_alg {
        combos.push("weak JWKS RSA + HS* advertised ⇒ algorithm-confusion forgery surface");
    }
    if sig.subdomain_takeover_hits > 0 && sig.open_redirect_uri {
        combos.push("identity subdomain takeover + redirect abuse ⇒ SSO hijack at scale");
    }
    if sig.device_flow_reachable && sig.cors_permissive_metadata {
        combos.push("device-code reachable + permissive CORS ⇒ parallel token phishing");
    }
    if combos.is_empty() {
        return;
    }
    let headline = combos.join(" ⊕ ");
    let mut f = finding_rich(
        ENGINE_ID,
        &format!("TOXIC COMBINATION: {headline}"),
        "critical",
        T_FORGE_OIDC,
        "Correlated OAuth/OIDC weaknesses form complete account-takeover chains — execute RFC9700 P0 controls within 24h.",
        target,
        0.97,
        Evidence::new()
            .with("combinations", json!(combos))
            .with("toxic_count", combos.len())
            .with("provider", sig.provider.clone().unwrap_or_default()),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("toxic_combination"));
    }
    findings.insert(0, f);
}

pub fn emit_remediation_roadmap(target: &str, sig: &IdentitySignals, findings: &mut Vec<Value>) {
    let mut steps: Vec<Value> = Vec::new();
    let mut n = 1u8;
    let mut push = |tier: &str, action: &str, detail: &str, effort: &str| {
        steps.push(json!({
            "priority": n,
            "tier": tier,
            "action": action,
            "detail": detail,
            "effort": effort,
        }));
        n += 1;
    };

    if sig.alg_none || sig.symmetric_alg {
        push(
            "P0",
            "Reject alg:none and symmetric ID-token algs",
            "RS256/ES256 only; rotate JWKS; pin kid",
            "hours",
        );
    }
    if sig.open_redirect_uri {
        push(
            "P0",
            "Exact redirect_uri allow-list",
            "Reject partial/wildcard matches; register every callback",
            "hours",
        );
    }
    if sig.implicit_flow {
        push(
            "P0",
            "Disable implicit/hybrid flows",
            "Authorization code + PKCE only per RFC9700",
            "days",
        );
    }
    if sig.ropc_grant || sig.ropc_live_accepts {
        push(
            "P0",
            "Disable resource-owner password grant",
            "Block password grant at tenant policy",
            "hours",
        );
    }
    if sig.pkce_not_advertised || sig.pkce_not_enforced_live {
        push(
            "P0",
            "Enforce PKCE S256",
            "Reject authorize without code_challenge; plain disallowed",
            "days",
        );
    }
    if sig.weak_jwks_key || sig.jwks_http {
        push(
            "P1",
            "Harden JWKS transport and key size",
            "HTTPS-only jwks_uri; RSA ≥2048 or P-384",
            "days",
        );
    }
    if sig.dcr_open {
        push(
            "P1",
            "Lock dynamic client registration",
            "Admin approval + mTLS for DCR",
            "days",
        );
    }
    if sig.subdomain_takeover_hits > 0 {
        push(
            "P0",
            "Remediate dangling identity subdomains",
            "Delete CNAME or claim host; audit redirect URIs",
            "hours",
        );
    }
    if sig.cors_permissive_metadata {
        push(
            "P1",
            "Restrict CORS on metadata/JWKS",
            "No wildcard origins on discovery documents",
            "hours",
        );
    }
    push(
        "P2",
        "Enable PAR + DPoP + back-channel logout",
        "RFC9126 PAR, RFC9449 DPoP, OIDC back-channel logout",
        "days",
    );
    push(
        "P2",
        "Continuous token abuse detection",
        "Deploy Weissman agent for refresh-token reuse analytics",
        "days",
    );

    if steps.is_empty() {
        return;
    }
    let mut f = finding_rich(
        ENGINE_ID,
        "Prioritized OAuth/OIDC remediation roadmap",
        "info",
        T_APP_TOKEN,
        "Ordered identity hardening plan derived from observed OAuth/OIDC gaps.",
        target,
        0.99,
        Evidence::new()
            .with("roadmap", Value::Array(steps))
            .with("category_scores", finalize_category_scores(sig).to_json()),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("remediation_roadmap"));
    }
    findings.push(f);
}

pub fn emit_agent_guidance(target: &str, findings: &mut Vec<Value>) {
    let caps = [
        (
            "refresh_token_reuse",
            "Refresh-token family reuse detection and impossible-travel correlation",
        ),
        (
            "auth_code_replay_lab",
            "Authorized authorization-code replay against token endpoint",
        ),
        (
            "client_secret_spray",
            "Client-credential brute-force against token endpoint (rate-limited lab)",
        ),
        (
            "session_cookie_theft",
            "Post-login session cookie capture on SP (host agent vantage)",
        ),
        (
            "entra_ca_simulation",
            "Conditional Access policy simulation per forged token claim set",
        ),
        (
            "federation_token_audit",
            "Cross-protocol SAML→OIDC token exchange audit on-DC",
        ),
    ];
    for (cap, desc) in caps {
        let mut f = finding_rich(
            ENGINE_ID,
            &format!("Agent-required: {desc}"),
            "info",
            T_APP_TOKEN,
            &format!(
                "Capability `{cap}` requires Weissman host agent or internal IdP vantage — not fully observable via external agentless scan."
            ),
            target,
            1.0,
            Evidence::new().with("capability", cap).with("requires_agent", true),
        );
        if let Some(o) = f.as_object_mut() {
            o.insert("category".to_string(), json!("agent_guidance"));
        }
        findings.push(f);
    }
}

pub fn build_security_graph(
    target: &str,
    sig: &IdentitySignals,
    host: &str,
) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let radar = sig.radar();
    let score = radar
        .as_object()
        .map(|o| {
            let vals: Vec<u64> = o.values().filter_map(Value::as_u64).collect();
            if vals.is_empty() {
                50
            } else {
                vals.iter().sum::<u64>() / vals.len() as u64
            }
        })
        .unwrap_or(50);

    let mut nodes = vec![GraphNode {
        id: "root".to_string(),
        label: if host.is_empty() {
            target.to_string()
        } else {
            host.to_string()
        },
        node_type: "root".to_string(),
        status: if score >= 80 {
            "secure".to_string()
        } else if score >= 55 {
            "degraded".to_string()
        } else {
            "exposed".to_string()
        },
        cname_target: None,
        raw_finding: None,
    }];
    let mut edges = Vec::new();
    let mut add = |id: &str, label: &str, kind: &str| {
        nodes.push(GraphNode {
            id: id.to_string(),
            label: label.to_string(),
            node_type: "identity_surface".to_string(),
            status: "exposed".to_string(),
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

    if sig.discovered {
        add("discovery", "OIDC discovery analyzed", "METADATA");
    }
    if sig.open_redirect_uri {
        add("redirect", "Open redirect_uri", "REDIRECT_GAP");
    }
    if sig.implicit_flow || sig.ropc_live_accepts {
        add("flow", "Risky grant/flow", "FLOW_GAP");
    }
    if sig.alg_none || sig.weak_jwks_key {
        add("crypto", "Weak token crypto", "CRYPTO_GAP");
    }
    if sig.pkce_not_enforced_live {
        add("pkce", "PKCE not enforced", "PKCE_GAP");
    }

    if sig.open_redirect_uri && (sig.implicit_flow || sig.pkce_not_enforced_live) {
        edges.push(GraphEdge {
            id: "ap_token".to_string(),
            from_id: "redirect".to_string(),
            to_id: "flow".to_string(),
            edge_type: "TOKEN_EXFIL".to_string(),
        });
    }
    if sig.alg_none || sig.weak_jwks_key {
        edges.push(GraphEdge {
            id: "ap_forge".to_string(),
            from_id: "crypto".to_string(),
            to_id: "discovery".to_string(),
            edge_type: "ID_TOKEN_FORGE".to_string(),
        });
    }

    let _ = target;
    (nodes, edges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn category_scores_all_clean_are_100() {
        let sig = IdentitySignals::default();
        let j = finalize_category_scores(&sig).to_json();
        for k in [
            "flow_hygiene",
            "token_crypto",
            "redirect_validation",
            "client_authentication",
            "modern_hardening",
            "endpoint_exposure",
            "federation_bridge",
            "token_endpoint_hygiene",
        ] {
            assert_eq!(j[k].as_u64().unwrap(), 100, "axis {k}");
        }
    }

    #[test]
    fn category_scores_specific_penalties() {
        let mut sig = IdentitySignals::default();
        sig.alg_none = true; // token_crypto 100-40
        sig.open_redirect_uri = true; // redirect_validation 100-45
        sig.implicit_flow = true; // flow_hygiene 100-35
        sig.subdomain_takeover_hits = 3; // endpoint_exposure via count_penalty 100-66
        let j = finalize_category_scores(&sig).to_json();
        assert_eq!(j["flow_hygiene"].as_u64().unwrap(), 65);
        assert_eq!(j["token_crypto"].as_u64().unwrap(), 60);
        assert_eq!(j["redirect_validation"].as_u64().unwrap(), 55);
        assert_eq!(j["endpoint_exposure"].as_u64().unwrap(), 34);
        // Untouched axes stay clean.
        assert_eq!(j["client_authentication"].as_u64().unwrap(), 100);
        assert_eq!(j["federation_bridge"].as_u64().unwrap(), 100);
    }

    #[test]
    fn category_scores_client_auth_requires_public_and_pkce_gap() {
        // public_clients_allowed alone does not fail client_authentication.
        let mut a = IdentitySignals::default();
        a.public_clients_allowed = true;
        assert_eq!(
            finalize_category_scores(&a).to_json()["client_authentication"]
                .as_u64()
                .unwrap(),
            100
        );
        // public + pkce-not-advertised does.
        let mut b = IdentitySignals::default();
        b.public_clients_allowed = true;
        b.pkce_not_advertised = true;
        assert_eq!(
            finalize_category_scores(&b).to_json()["client_authentication"]
                .as_u64()
                .unwrap(),
            65
        );
    }

    #[test]
    fn extend_attack_paths_device_phish() {
        let mut sig = IdentitySignals::default();
        sig.device_flow_reachable = true;
        sig.pkce_not_enforced_live = true;
        let mut f = Vec::new();
        extend_attack_paths("t", &sig, &mut f);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0]["severity"], "high");
    }

    #[test]
    fn extend_attack_paths_subdomain_takeover_is_critical() {
        let mut sig = IdentitySignals::default();
        sig.subdomain_takeover_hits = 1;
        sig.subdomain_oauth_surfaces = 1;
        let mut f = Vec::new();
        extend_attack_paths("t", &sig, &mut f);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0]["severity"], "critical");
    }

    #[test]
    fn extend_attack_paths_none_when_clean() {
        let sig = IdentitySignals::default();
        let mut f = Vec::new();
        extend_attack_paths("t", &sig, &mut f);
        assert!(f.is_empty());
    }

    #[test]
    fn toxic_headline_empty_when_no_combos() {
        let sig = IdentitySignals::default();
        let mut f = Vec::new();
        emit_toxic_headline("t", &sig, &mut f);
        assert!(f.is_empty());
    }

    #[test]
    fn toxic_headline_alg_none_inserts_front() {
        let mut sig = IdentitySignals::default();
        sig.alg_none = true;
        let mut f = vec![json!({"title": "existing"})];
        emit_toxic_headline("t", &sig, &mut f);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0]["severity"], "critical");
        assert_eq!(f[0]["category"], "toxic_combination");
        assert!(f[0]["title"]
            .as_str()
            .unwrap()
            .starts_with("TOXIC COMBINATION:"));
    }

    #[test]
    fn remediation_roadmap_always_emits() {
        let sig = IdentitySignals::default();
        let mut f = Vec::new();
        emit_remediation_roadmap("t", &sig, &mut f);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0]["category"], "remediation_roadmap");
        assert!(f[0]["evidence"]["roadmap"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn agent_guidance_emits_six() {
        let mut f = Vec::new();
        emit_agent_guidance("t", &mut f);
        assert_eq!(f.len(), 6);
        for finding in &f {
            assert_eq!(finding["category"], "agent_guidance");
        }
    }

    #[test]
    fn security_graph_clean_root_only() {
        let sig = IdentitySignals::default();
        let (nodes, edges) = build_security_graph("t", &sig, "host.example.com");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "root");
        assert_eq!(nodes[0].label, "host.example.com");
        assert_eq!(nodes[0].status, "secure"); // radar avg 100
        assert!(edges.is_empty());
    }

    #[test]
    fn security_graph_root_label_falls_back_to_target() {
        let sig = IdentitySignals::default();
        let (nodes, _) = build_security_graph("target-id", &sig, "");
        assert_eq!(nodes[0].label, "target-id");
    }

    #[test]
    fn security_graph_redirect_and_flow_chain() {
        let mut sig = IdentitySignals::default();
        sig.open_redirect_uri = true;
        sig.implicit_flow = true;
        let (nodes, edges) = build_security_graph("t", &sig, "h");
        // root + redirect + flow
        assert_eq!(nodes.len(), 3);
        // e_root_redirect, e_root_flow, ap_token
        assert_eq!(edges.len(), 3);
        assert!(edges.iter().any(|e| e.edge_type == "TOKEN_EXFIL"));
    }

    #[test]
    fn security_graph_crypto_forge_edge() {
        let mut sig = IdentitySignals::default();
        sig.discovered = true;
        sig.alg_none = true;
        let (nodes, edges) = build_security_graph("t", &sig, "h");
        // root + discovery + crypto
        assert_eq!(nodes.len(), 3);
        assert!(edges.iter().any(|e| e.edge_type == "ID_TOKEN_FORGE"));
    }
}
