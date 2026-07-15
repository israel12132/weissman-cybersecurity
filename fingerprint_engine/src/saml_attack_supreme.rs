//! Supreme-tier SAML/SSO federation synthesis — toxic combos, security graph, agent guidance,
//! extended probes. Called from the main saml_attack engine module.

use super::{
    saml_attack_path, MetadataFacts, Signals, ENGINE_ID, T_APP_TOKEN, T_FORGE_SAML, T_MODIFY_AUTH,
    T_TRUST,
};
use crate::arsenal_config::{finding_rich, Evidence};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use crate::engine_probes::http_get;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::{json, Value};

const WS_FED_PATHS: &[&str] = &[
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/adfs/services/trust/mex",
    "/adfs/services/trust/2005/windowstransport",
];

// ─── Metadata-derived probe findings (from parsed facts — not simulated) ─────────

pub fn emit_metadata_depth_findings(
    target: &str,
    metadata_url: &str,
    facts: &MetadataFacts,
    sig: &mut Signals,
    findings: &mut Vec<Value>,
    check_xsw: bool,
    check_slo: bool,
    check_bindings: bool,
    check_expiry: bool,
) {
    if check_expiry {
        if let Some(vu) = &facts.valid_until {
            if let Ok(dt) = DateTime::parse_from_rfc3339(vu) {
                if dt < Utc::now() {
                    sig.metadata_expired = true;
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "SAML metadata validUntil expired",
                        "high",
                        T_MODIFY_AUTH,
                        &format!(
                            "EntityDescriptor at {metadata_url} has validUntil={vu} in the past — federation metadata may be stale; SPs trusting this document operate on expired trust anchors."
                        ),
                        target,
                        0.9,
                        Evidence::new()
                            .with("metadata_url", metadata_url)
                            .with("valid_until", vu.clone())
                            .check("metadata_expired", true, vu.clone()),
                    ));
                }
            }
        }
    }

    if facts.authn_requests_signed == Some(false) {
        sig.authn_requests_unsigned = true;
        findings.push(finding_rich(
            ENGINE_ID,
            "IdP accepts unsigned AuthnRequests (AuthnRequestsSigned=false)",
            "medium",
            T_MODIFY_AUTH,
            &format!(
                "Metadata at {metadata_url} advertises AuthnRequestsSigned=false — SP-initiated flows may accept unsigned SAML requests, easing request tampering at the edge."
            ),
            target,
            0.84,
            Evidence::new()
                .with("metadata_url", metadata_url)
                .check("authn_requests_signed", true, false),
        ));
    }

    if check_slo && !facts.slo_urls.is_empty() {
        sig.slo_exposed = true;
        sig.slo_urls.extend(facts.slo_urls.clone());
        findings.push(finding_rich(
            ENGINE_ID,
            &format!("SAML Single Logout endpoint(s) exposed ({} URL(s))", facts.slo_urls.len()),
            "info",
            T_APP_TOKEN,
            &format!(
                "Metadata lists SingleLogoutService at {:?} — SLO surface enables session-termination abuse research and must be TLS-only with strict signature validation.",
                facts.slo_urls.iter().take(3).collect::<Vec<_>>()
            ),
            target,
            0.82,
            Evidence::new()
                .with("metadata_url", metadata_url)
                .with("slo_urls", json!(facts.slo_urls)),
        ));
    }

    if check_bindings && facts.bindings.iter().any(|b| b == "HTTP-Redirect") {
        sig.http_redirect_binding = true;
        findings.push(finding_rich(
            ENGINE_ID,
            "SAML HTTP-Redirect binding advertised",
            "medium",
            T_MODIFY_AUTH,
            &format!(
                "Metadata at {metadata_url} exposes HTTP-Redirect binding — SAML requests/responses in URL query strings increase tampering and open-redirect coupling risk vs POST-only profiles."
            ),
            target,
            0.8,
            Evidence::new()
                .with("metadata_url", metadata_url)
                .with("bindings", json!(facts.bindings)),
        ));
    }

    if !facts.http_acs_urls.is_empty() {
        sig.http_acs_urls.extend(facts.http_acs_urls.clone());
        findings.push(finding_rich(
            ENGINE_ID,
            &format!("Cleartext HTTP AssertionConsumerService URL(s) ({})", facts.http_acs_urls.len()),
            "high",
            T_MODIFY_AUTH,
            &format!(
                "Metadata advertises ACS endpoints over http://: {:?} — assertions and session cookies may traverse cleartext; enforce HTTPS-only ACS.",
                facts.http_acs_urls.iter().take(3).collect::<Vec<_>>()
            ),
            target,
            0.91,
            Evidence::new()
                .with("http_acs_urls", json!(facts.http_acs_urls)),
        ));
    }

    if check_xsw && facts.acs_urls.len() > 1 && facts.certs.len() > 1 {
        sig.xsw_preconditions = facts.acs_urls.len().saturating_add(facts.certs.len());
        findings.push(finding_rich(
            ENGINE_ID,
            &format!(
                "XML Signature Wrapping preconditions: {} ACS + {} signing cert(s)",
                facts.acs_urls.len(),
                facts.certs.len()
            ),
            "medium",
            T_FORGE_SAML,
            &format!(
                "Multiple AssertionConsumerService endpoints ({}) and multiple signing certificates ({}) in metadata at {metadata_url} — classic XSW attack surface (multi-ACS + cert confusion). Validate signature placement and strict ACS allow-listing.",
                facts.acs_urls.len(),
                facts.certs.len()
            ),
            target,
            0.86,
            Evidence::new()
                .with("acs_count", facts.acs_urls.len())
                .with("cert_count", facts.certs.len())
                .with("acs_urls", json!(facts.acs_urls.iter().take(6).collect::<Vec<_>>())),
        ));
    }
}

pub async fn probe_ws_federation(
    client: &Client,
    base: &str,
    target: &str,
    sig: &mut Signals,
    findings: &mut Vec<Value>,
) {
    for path in WS_FED_PATHS {
        let url = format!(
            "{}/{}",
            base.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        if let Some(p) = http_get(client, &url).await {
            let bl = p.body.to_ascii_lowercase();
            if bl.contains("federationmetadata")
                || bl.contains("ws-federation")
                || bl.contains("securitytokenservice")
                || bl.contains("entitydescriptor")
            {
                sig.ws_fed_exposed = true;
                findings.push(finding_rich(
                    ENGINE_ID,
                    &format!("WS-Federation metadata exposed: {url}"),
                    "info",
                    T_TRUST,
                    "Live WS-Federation / ADFS trust metadata observed — extends SAML assessment to legacy Microsoft federation plane (Golden SAML / token-signing cert risk model).",
                    target,
                    0.88,
                    Evidence::new()
                        .with("url", url)
                        .with("http_status", p.status)
                        .check("ws_federation", true, "live response"),
                ));
                break;
            }
        }
    }
}

// ─── 8-domain category scores ────────────────────────────────────────────────────

pub struct SamlCategoryScores {
    pub signing_trust: f64,
    pub assertion_policy: f64,
    pub metadata_hygiene: f64,
    pub transport_binding: f64,
    pub redirect_relay: f64,
    pub parser_disclosure: f64,
    pub slo_surface: f64,
    pub xsw_surface: f64,
}

impl SamlCategoryScores {
    fn from_signals(sig: &Signals) -> Self {
        let penalize =
            |gaps: usize, w: f64| -> f64 { (100.0 - (gaps.min(4) as f64) * w).clamp(0.0, 100.0) };
        Self {
            signing_trust: penalize(
                (sig.weak_sha1 as usize)
                    + (sig.weak_key_cert as usize)
                    + (sig.expired_cert as usize),
                20.0,
            ),
            assertion_policy: if sig.unsigned_assertions {
                20.0
            } else if sig.missing_encryption {
                70.0
            } else {
                100.0
            },
            metadata_hygiene: penalize(
                (sig.metadata_expired as usize) + (sig.error_disclosure as usize),
                25.0,
            ),
            transport_binding: penalize(
                (sig.http_redirect_binding as usize) + sig.http_acs_urls.len().min(2),
                22.0,
            ),
            redirect_relay: if sig.open_redirect.is_some() {
                30.0
            } else {
                100.0
            },
            parser_disclosure: if sig.error_disclosure { 40.0 } else { 100.0 },
            slo_surface: if sig.slo_exposed { 75.0 } else { 100.0 },
            xsw_surface: if sig.xsw_preconditions > 2 {
                (100.0 - sig.xsw_preconditions.min(8) as f64 * 8.0).clamp(20.0, 100.0)
            } else {
                100.0
            },
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "signing_trust": self.signing_trust.round() as u32,
            "assertion_policy": self.assertion_policy.round() as u32,
            "metadata_hygiene": self.metadata_hygiene.round() as u32,
            "transport_binding": self.transport_binding.round() as u32,
            "redirect_relay": self.redirect_relay.round() as u32,
            "parser_disclosure": self.parser_disclosure.round() as u32,
            "slo_surface": self.slo_surface.round() as u32,
            "xsw_surface": self.xsw_surface.round() as u32,
        })
    }
}

pub fn finalize_category_scores(sig: &Signals) -> SamlCategoryScores {
    SamlCategoryScores::from_signals(sig)
}

// ─── Extended attack paths ─────────────────────────────────────────────────────

pub fn extend_attack_paths(target: &str, sig: &Signals, findings: &mut Vec<Value>) {
    if sig.unsigned_assertions && sig.open_redirect.is_some() {
        findings.push(saml_attack_path(
            "Attack path: unsigned assertion + RelayState phishing → admin session",
            "critical",
            T_FORGE_SAML,
            target,
            "Unsigned assertions combined with RelayState open redirect enables forged admin login followed by session relay to attacker infrastructure.",
            &[
                "Forge unsigned SAMLResponse as privileged user",
                "Wrap in phishing SSO link with malicious RelayState",
                "Victim authenticates via legitimate IdP flow",
                "RelayState bounces session to attacker",
            ],
        ));
    }
    if sig.weak_sha1 && sig.idp_metadata && sig.ws_fed_exposed {
        findings.push(saml_attack_path(
            "Attack path: Golden SAML — WS-Fed + weak SHA-1 signing trust",
            "critical",
            T_FORGE_SAML,
            target,
            "ADFS WS-Federation metadata with SHA-1 signing trust is the UNC2452/Golden SAML precondition chain — token-signing key forgery bypasses MFA for all federated apps.",
            &[
                "Compromise or extract ADFS token-signing certificate",
                "Forge WS-Fed / SAML tokens with SHA-1 trust anchor",
                "Replay to all trusting SPs",
                "Operate as any identity with MFA bypass",
            ],
        ));
    }
    if sig.xsw_preconditions > 3 && !sig.unsigned_assertions {
        findings.push(saml_attack_path(
            "Attack path: XML Signature Wrapping via multi-ACS confusion",
            "high",
            T_FORGE_SAML,
            target,
            "Multiple ACS endpoints and signing certificates create signature-placement ambiguity — XSW variants may smuggle assertions past validators that do not pin ACS + cert pairs.",
            &[
                "Map all ACS endpoints and signing cert roles from metadata",
                "Craft wrapped assertion targeting alternate ACS",
                "Exploit validator that checks signature on wrong element",
                "Obtain SP session as victim identity",
            ],
        ));
    }
    if sig.http_acs_urls.len() > 0 && sig.slo_exposed {
        findings.push(saml_attack_path(
            "Attack path: cleartext ACS + SLO → assertion/session interception",
            "high",
            T_APP_TOKEN,
            target,
            "HTTP ACS and exposed SLO endpoints allow on-path assertion capture and forced global logout manipulation on untrusted networks.",
            &[
                "Position on network path to HTTP ACS",
                "Capture SAMLResponse in cleartext",
                "Replay assertion before NotOnOrAfter expiry",
                "Optionally abuse SLO to deny service",
            ],
        ));
    }
}

// ─── Toxic combination headline ──────────────────────────────────────────────────

pub fn emit_toxic_headline(target: &str, sig: &Signals, findings: &mut Vec<Value>) {
    let mut combos = Vec::new();
    if sig.unsigned_assertions {
        combos.push("WantAssertionsSigned=false ⇒ forge any identity without credentials");
    }
    if sig.unsigned_assertions && sig.open_redirect.is_some() {
        combos.push("unsigned assertions + RelayState open redirect ⇒ phishing-grade SSO bypass");
    }
    if sig.idp_metadata && (sig.weak_key_cert || sig.weak_sha1) && sig.ws_fed_exposed {
        combos.push("WS-Fed + weak signing (SHA-1/short key) ⇒ Golden SAML MFA bypass");
    }
    if sig.expired_cert && sig.idp_metadata {
        combos.push("expired IdP signing cert in metadata ⇒ trust rotation gap / silent downgrade");
    }
    if sig.xsw_preconditions > 3 && sig.http_redirect_binding {
        combos.push("multi-ACS XSW surface + HTTP-Redirect binding ⇒ assertion smuggling chain");
    }
    if sig.authn_requests_unsigned && sig.unsigned_assertions {
        combos.push(
            "unsigned AuthnRequests + unsigned assertions ⇒ bidirectional SAML trust collapse",
        );
    }
    if combos.is_empty() {
        return;
    }
    let headline = combos.join(" ⊕ ");
    findings.insert(
        0,
        {
            let mut f = finding_rich(
                ENGINE_ID,
                &format!("TOXIC COMBINATION: {headline}"),
                "critical",
                T_FORGE_SAML,
                "Correlated SAML/SSO exposures form a domain-wide identity compromise chain — execute P0 federation hardening within 24h.",
                target,
                0.97,
                Evidence::new()
                    .with("combinations", json!(combos))
                    .with("toxic_count", combos.len())
                    .with("vendor", sig.idp_vendor.clone().unwrap_or_default()),
            );
            if let Some(o) = f.as_object_mut() {
                o.insert("category".to_string(), json!("toxic_combination"));
            }
            f
        },
    );
}

// ─── Remediation roadmap ─────────────────────────────────────────────────────────

pub fn emit_remediation_roadmap(target: &str, sig: &Signals, findings: &mut Vec<Value>) {
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

    if sig.unsigned_assertions {
        push(
            "P0",
            "Require signed assertions",
            "Set WantAssertionsSigned=true on all SPs; reject unsigned SAMLResponse at ACS",
            "hours",
        );
    }
    if sig.weak_sha1 {
        push(
            "P0",
            "Migrate off SHA-1",
            "Reissue metadata + signing certs with rsa-sha256; disable SHA-1 at XMLSec/ADFS",
            "days",
        );
    }
    if sig.expired_cert || sig.weak_key_cert {
        push(
            "P0",
            "Rotate SAML signing certificates",
            "Deploy 4096-bit RSA or P-384 ECDSA keys; automate metadata refresh",
            "days",
        );
    }
    if sig.open_redirect.is_some() {
        push(
            "P0",
            "Validate RelayState allow-list",
            "Reject RelayState not matching registered SP redirect URIs",
            "hours",
        );
    }
    if !sig.http_acs_urls.is_empty() {
        push(
            "P0",
            "HTTPS-only ACS",
            "Remove http:// ACS URLs from metadata; enforce TLS 1.2+ at load balancer",
            "hours",
        );
    }
    if sig.xsw_preconditions > 2 {
        push(
            "P1",
            "Pin ACS + signature placement",
            "Single ACS per SP; validate signature covers Assertion element only",
            "days",
        );
    }
    if sig.authn_requests_unsigned {
        push(
            "P1",
            "Require signed AuthnRequests",
            "AuthnRequestsSigned=true on IdP metadata",
            "days",
        );
    }
    if sig.error_disclosure {
        push(
            "P1",
            "Suppress SAML parser errors",
            "Return generic auth failure; log details server-side only",
            "hours",
        );
    }
    push(
        "P2",
        "Monitor Event 4769 / SAML audit logs",
        "Alert on anomalous assertion issuers and SLO volume",
        "days",
    );
    push(
        "P2",
        "Deploy honeypot SAML SP",
        "Detect forged assertion attempts against canary ACS",
        "days",
    );

    if steps.is_empty() {
        return;
    }
    let mut f = finding_rich(
        ENGINE_ID,
        "Prioritized SAML/SSO remediation roadmap",
        "info",
        T_FORGE_SAML,
        "Ordered federation hardening plan derived from observed SAML weaknesses.",
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

// ─── Agent guidance ──────────────────────────────────────────────────────────────

pub fn emit_agent_guidance(target: &str, findings: &mut Vec<Value>) {
    let caps = [
        (
            "saml_response_replay",
            "Live SAMLResponse replay against ACS with signed assertion capture",
        ),
        (
            "xsw_variant_testing",
            "Authorized XML Signature Wrapping variant lab (XSW #1–#8)",
        ),
        (
            "adfs_token_signing_audit",
            "On-DC ADFS token-signing + decryption cert DPAPI audit",
        ),
        (
            "bloodhound_federation_acl",
            "Federation trust ACL graph (SP ↔ IdP) from internal AD",
        ),
        (
            "saml_assertion_decrypt",
            "Decrypt encrypted assertions with SP private key (host agent)",
        ),
        (
            "golden_saml_hunt",
            "KRBTGT-adjacent DCSync + ADFS farm persistence indicators",
        ),
    ];
    for (cap, desc) in caps {
        let mut f = finding_rich(
            ENGINE_ID,
            &format!("Agent-required: {desc}"),
            "info",
            T_FORGE_SAML,
            &format!(
                "Capability `{cap}` requires Weissman host agent or authorized intrusive SAML lab — not observable via external agentless scan alone."
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

// ─── Security graph ──────────────────────────────────────────────────────────────

pub fn build_security_graph(
    target: &str,
    sig: &Signals,
    host: &str,
) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let score = sig.score();
    let mut nodes = vec![GraphNode {
        id: "root".to_string(),
        label: host.to_string(),
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
            node_type: "federation_surface".to_string(),
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

    if sig.idp_metadata {
        add("idp_meta", "IdP metadata exposed", "IDP_METADATA");
    }
    if sig.unsigned_assertions {
        add(
            "unsigned",
            "Unsigned assertions accepted",
            "UNSIGNED_ASSERTION",
        );
    }
    if sig.weak_sha1 || sig.weak_key_cert {
        add("weak_sign", "Weak signing trust", "WEAK_SIGNING");
    }
    if sig.open_redirect.is_some() {
        add("relaystate", "RelayState open redirect", "RELAYSTATE");
    }
    if sig.ws_fed_exposed {
        add("wsfed", "WS-Federation metadata", "WS_FED");
    }

    if sig.unsigned_assertions && sig.open_redirect.is_some() {
        edges.push(GraphEdge {
            id: "ap_phish".to_string(),
            from_id: "unsigned".to_string(),
            to_id: "relaystate".to_string(),
            edge_type: "FORGE_TO_PHISH".to_string(),
        });
    }
    if sig.weak_sha1 && sig.ws_fed_exposed {
        edges.push(GraphEdge {
            id: "ap_golden".to_string(),
            from_id: "weak_sign".to_string(),
            to_id: "wsfed".to_string(),
            edge_type: "GOLDEN_SAML".to_string(),
        });
    }

    let _ = target;
    (nodes, edges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cert() -> super::super::CertFacts {
        super::super::CertFacts {
            subject: "CN=idp".to_string(),
            issuer: "CN=idp".to_string(),
            key_bits: 2048,
            sig_alg: "sha256WithRSAEncryption".to_string(),
            days_until_expiry: 100,
            expired: false,
            self_signed: true,
        }
    }

    #[test]
    fn category_scores_all_clean_are_100() {
        let sig = Signals::default();
        let j = finalize_category_scores(&sig).to_json();
        for k in [
            "signing_trust",
            "assertion_policy",
            "metadata_hygiene",
            "transport_binding",
            "redirect_relay",
            "parser_disclosure",
            "slo_surface",
            "xsw_surface",
        ] {
            assert_eq!(j[k].as_u64().unwrap(), 100, "axis {k}");
        }
    }

    #[test]
    fn category_scores_penalize_signing_trust() {
        let mut sig = Signals::default();
        sig.weak_sha1 = true;
        sig.weak_key_cert = true;
        sig.expired_cert = true;
        // 3 gaps * 20 = 60 penalty -> 40
        let j = finalize_category_scores(&sig).to_json();
        assert_eq!(j["signing_trust"].as_u64().unwrap(), 40);
    }

    #[test]
    fn category_scores_assertion_policy_ladder() {
        let mut a = Signals::default();
        a.unsigned_assertions = true;
        assert_eq!(
            finalize_category_scores(&a).to_json()["assertion_policy"]
                .as_u64()
                .unwrap(),
            20
        );
        let mut b = Signals::default();
        b.missing_encryption = true;
        assert_eq!(
            finalize_category_scores(&b).to_json()["assertion_policy"]
                .as_u64()
                .unwrap(),
            70
        );
    }

    #[test]
    fn category_scores_transport_and_xsw() {
        let mut sig = Signals::default();
        sig.http_redirect_binding = true;
        sig.http_acs_urls = vec!["http://a".into(), "http://b".into(), "http://c".into()];
        // gaps = 1 + min(3,2)=2 => 3 gaps * 22 = 66 -> 34
        assert_eq!(
            finalize_category_scores(&sig).to_json()["transport_binding"]
                .as_u64()
                .unwrap(),
            34
        );

        let mut x = Signals::default();
        x.xsw_preconditions = 5; // (100 - 5*8)=60 clamped [20,100]
        assert_eq!(
            finalize_category_scores(&x).to_json()["xsw_surface"]
                .as_u64()
                .unwrap(),
            60
        );
        let mut x2 = Signals::default();
        x2.xsw_preconditions = 2; // not > 2 -> 100
        assert_eq!(
            finalize_category_scores(&x2).to_json()["xsw_surface"]
                .as_u64()
                .unwrap(),
            100
        );
    }

    #[test]
    fn metadata_depth_expired_flags_signal_and_high_finding() {
        let mut sig = Signals::default();
        let mut findings = Vec::new();
        let mut facts = MetadataFacts::default();
        facts.valid_until = Some("2000-01-01T00:00:00Z".to_string());
        emit_metadata_depth_findings(
            "t", "https://idp/meta", &facts, &mut sig, &mut findings, true, true, true, true,
        );
        assert!(sig.metadata_expired);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "high");
        assert!(findings[0]["title"]
            .as_str()
            .unwrap()
            .contains("validUntil expired"));
    }

    #[test]
    fn metadata_depth_future_expiry_no_finding() {
        let mut sig = Signals::default();
        let mut findings = Vec::new();
        let mut facts = MetadataFacts::default();
        facts.valid_until = Some("2999-01-01T00:00:00Z".to_string());
        emit_metadata_depth_findings(
            "t", "https://idp/meta", &facts, &mut sig, &mut findings, true, true, true, true,
        );
        assert!(!sig.metadata_expired);
        assert!(findings.is_empty());
    }

    #[test]
    fn metadata_depth_unsigned_authn_requests() {
        let mut sig = Signals::default();
        let mut findings = Vec::new();
        let mut facts = MetadataFacts::default();
        facts.authn_requests_signed = Some(false);
        emit_metadata_depth_findings(
            "t", "https://idp/meta", &facts, &mut sig, &mut findings, false, false, false, false,
        );
        assert!(sig.authn_requests_unsigned);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "medium");
    }

    #[test]
    fn metadata_depth_slo_and_redirect_binding_respect_toggles() {
        let mut facts = MetadataFacts::default();
        facts.slo_urls = vec!["https://idp/slo".into()];
        facts.bindings = vec!["HTTP-Redirect".into()];

        // Toggles off -> no findings, no signals.
        let mut sig = Signals::default();
        let mut findings = Vec::new();
        emit_metadata_depth_findings(
            "t", "u", &facts, &mut sig, &mut findings, false, false, false, false,
        );
        assert!(!sig.slo_exposed);
        assert!(!sig.http_redirect_binding);
        assert!(findings.is_empty());

        // Toggles on -> both fire.
        let mut sig2 = Signals::default();
        let mut findings2 = Vec::new();
        emit_metadata_depth_findings(
            "t", "u", &facts, &mut sig2, &mut findings2, false, true, true, false,
        );
        assert!(sig2.slo_exposed);
        assert!(sig2.http_redirect_binding);
        assert_eq!(findings2.len(), 2);
    }

    #[test]
    fn metadata_depth_http_acs_always_fires() {
        let mut sig = Signals::default();
        let mut findings = Vec::new();
        let mut facts = MetadataFacts::default();
        facts.http_acs_urls = vec!["http://sp/acs".into()];
        emit_metadata_depth_findings(
            "t", "u", &facts, &mut sig, &mut findings, false, false, false, false,
        );
        assert_eq!(sig.http_acs_urls.len(), 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "high");
    }

    #[test]
    fn metadata_depth_xsw_preconditions() {
        let mut sig = Signals::default();
        let mut findings = Vec::new();
        let mut facts = MetadataFacts::default();
        facts.acs_urls = vec!["https://a".into(), "https://b".into()];
        facts.certs = vec![cert(), cert()];
        emit_metadata_depth_findings(
            "t", "u", &facts, &mut sig, &mut findings, true, false, false, false,
        );
        // 2 ACS + 2 certs = 4
        assert_eq!(sig.xsw_preconditions, 4);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "medium");
    }

    #[test]
    fn extend_attack_paths_phishing_combo() {
        let mut sig = Signals::default();
        sig.unsigned_assertions = true;
        sig.open_redirect = Some("https://evil".into());
        let mut findings = Vec::new();
        extend_attack_paths("t", &sig, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "critical");
        assert_eq!(findings[0]["category"], "attack_path");
    }

    #[test]
    fn extend_attack_paths_none_when_clean() {
        let sig = Signals::default();
        let mut findings = Vec::new();
        extend_attack_paths("t", &sig, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn extend_attack_paths_golden_saml() {
        let mut sig = Signals::default();
        sig.weak_sha1 = true;
        sig.idp_metadata = true;
        sig.ws_fed_exposed = true;
        let mut findings = Vec::new();
        extend_attack_paths("t", &sig, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]["title"].as_str().unwrap().contains("Golden SAML"));
    }

    #[test]
    fn toxic_headline_empty_when_no_combos() {
        let sig = Signals::default();
        let mut findings = Vec::new();
        emit_toxic_headline("t", &sig, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn toxic_headline_inserts_at_front() {
        let mut sig = Signals::default();
        sig.unsigned_assertions = true;
        let mut findings = vec![json!({"title": "pre-existing"})];
        emit_toxic_headline("t", &sig, &mut findings);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0]["severity"], "critical");
        assert_eq!(findings[0]["category"], "toxic_combination");
        assert!(findings[0]["title"]
            .as_str()
            .unwrap()
            .starts_with("TOXIC COMBINATION:"));
    }

    #[test]
    fn remediation_roadmap_always_emits_one_finding() {
        // Even with a clean signal set, P2 monitoring steps are always appended.
        let sig = Signals::default();
        let mut findings = Vec::new();
        emit_remediation_roadmap("t", &sig, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["category"], "remediation_roadmap");
        let roadmap = findings[0]["evidence"]["roadmap"].as_array().unwrap();
        assert!(roadmap.len() >= 2);
        assert_eq!(roadmap[0]["priority"], 1);
    }

    #[test]
    fn agent_guidance_emits_six() {
        let mut findings = Vec::new();
        emit_agent_guidance("t", &mut findings);
        assert_eq!(findings.len(), 6);
        for f in &findings {
            assert_eq!(f["category"], "agent_guidance");
            assert_eq!(f["severity"], "info");
        }
    }

    #[test]
    fn security_graph_clean_is_root_only_and_secure() {
        let sig = Signals::default();
        let (nodes, edges) = build_security_graph("t", &sig, "idp.example.com");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "root");
        assert_eq!(nodes[0].label, "idp.example.com");
        assert_eq!(nodes[0].status, "secure"); // score 100
        assert!(edges.is_empty());
    }

    #[test]
    fn security_graph_phishing_chain_adds_nodes_and_edge() {
        let mut sig = Signals::default();
        sig.unsigned_assertions = true;
        sig.open_redirect = Some("https://evil".into());
        let (nodes, edges) = build_security_graph("t", &sig, "h");
        // root + unsigned + relaystate
        assert_eq!(nodes.len(), 3);
        // e_root_unsigned, e_root_relaystate, ap_phish
        assert_eq!(edges.len(), 3);
        assert!(edges.iter().any(|e| e.edge_type == "FORGE_TO_PHISH"));
        // score = 100 - 22 - 14 = 64 -> degraded
        assert_eq!(nodes[0].status, "degraded");
    }

    #[test]
    fn security_graph_golden_edge() {
        let mut sig = Signals::default();
        sig.weak_sha1 = true;
        sig.ws_fed_exposed = true;
        let (nodes, edges) = build_security_graph("t", &sig, "h");
        assert_eq!(nodes.len(), 3); // root + weak_sign + wsfed
        assert!(edges.iter().any(|e| e.edge_type == "GOLDEN_SAML"));
    }
}
