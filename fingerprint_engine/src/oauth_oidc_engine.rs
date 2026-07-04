//! OAuth 2.0 / OIDC / SSO Identity Security engine — world-class, agentless identity-provider
//! posture assessment.
//!
//! Identity is the modern perimeter: nearly every breach now rides a federation/SSO weakness
//! (token theft, ID-token forgery, redirect-URI abuse, implicit-flow leakage, missing PKCE). This
//! engine performs the deepest *agentless, evidence-only* assessment of an OAuth 2.0 Authorization
//! Server / OpenID Provider that is possible without credentials — every finding is backed by a
//! real HTTP/DNS/crypto observation against the operator-supplied target; nothing is fabricated.
//!
//! Assessment layers (all read-only):
//!   1. **Discovery & provider fingerprint** — RFC 8414 / OIDC discovery documents, issuer/host
//!      heuristics (Okta, Auth0, Microsoft Entra, Google, Keycloak, Ping, AWS Cognito, OneLogin…).
//!   2. **Metadata posture** — response/grant types (implicit, ROPC), PKCE advertisement
//!      (`code_challenge_methods_supported`), ID-token signing algs (`none`, symmetric HS*),
//!      token-endpoint auth methods, request_uri / JAR exposure, PAR / DPoP / back-channel-logout
//!      hardening, issuer transport.
//!   3. **JWKS cryptographic analysis** — fetch `jwks_uri`, estimate RSA modulus bits, flag
//!      sub-2048-bit keys, missing `kid`, and dangerous advertised algorithms.
//!   4. **Live authorization-endpoint behavior** — benign, unauthenticated probes that observe how
//!      the server handles an attacker-shaped `redirect_uri`, the implicit `response_type=token`,
//!      and a code request with no PKCE — real server redirects/errors are the only signal.
//!   5. **Attack-path synthesis (identity security graph)** — correlates weaknesses into prioritized
//!      account-takeover paths (e.g. *lax redirect_uri + implicit flow → access-token exfiltration*,
//!      *`alg:none` / weak JWKS → ID-token forgery → impersonation*).
//!   6. **Supreme synthesis** — toxic-combination headline, 8-domain category scores, remediation
//!      roadmap, security graph (`ok_with_graph`), extended attack paths, honest agent guidance.
//!
//! It closes with a single 0–100 **identity posture score**. Every operational knob is driven from
//! the live scan request body (`POST /api/command-center/scan` → `EngineRunContext::job_params`),
//! so an operator tunes issuer/discovery URL, client_id, probe redirect_uri, probe scope, intensity
//! and per-check toggles with zero code change. MITRE: T1550.001 (Application Access Token),
//! T1606.002 (Forge Web Credentials: SAML/OIDC tokens), T1528 (Steal Application Access Token),
//! T1539 (Steal Web Session Cookie).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_result::{print_result, EngineResult};

#[path = "oauth_oidc_supreme.rs"]
mod supreme;
use base64::Engine as _;
use serde_json::{json, Value};
use std::time::Duration;

const ENGINE_ID: &str = "oauth_oidc";

// MITRE ATT&CK technique IDs reused across findings.
const T_APP_TOKEN: &str = "T1550.001"; // Use Alternate Auth Material: Application Access Token
const T_FORGE_OIDC: &str = "T1606.002"; // Forge Web Credentials: SAML/OIDC Tokens
const T_STEAL_TOKEN: &str = "T1528"; // Steal Application Access Token
const T_STEAL_COOKIE: &str = "T1539"; // Steal Web Session Cookie

const DEFAULT_DISCOVERY_PATHS: &[&str] = &[
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/default",
    "/.well-known/openid-configuration/default",
];

const COMMON_AUTH_PATHS: &[&str] = &[
    "/oauth/authorize",
    "/oauth2/authorize",
    "/oauth2/v1/authorize",
    "/connect/authorize",
    "/authorize",
    "/as/authorization.oauth2",
    "/protocol/openid-connect/auth",
];

const COMMON_SAML_PATHS: &[&str] = &[
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/saml/metadata",
    "/saml2/metadata",
    "/auth/saml/metadata",
    "/.well-known/saml-configuration",
    "/saml/descriptor",
];

/// SaaS fingerprints that indicate a dangling identity subdomain (takeover / mis-claim surface).
const SUBDOMAIN_TAKEOVER_SIGS: &[(&str, &str)] = &[
    ("there isn't a github pages site here", "GitHub Pages"),
    ("nosuchbucket", "AWS S3"),
    ("the specified bucket does not exist", "AWS S3"),
    ("heroku | no such app", "Heroku"),
    ("no such app", "Heroku"),
    ("project not found", "Vercel"),
    ("fastly error: unknown domain", "Fastly"),
    ("the request could not be satisfied", "CloudFront"),
    ("unknown host", "Generic CDN"),
];

// ─────────────────────────────────────────────────────────────────────────────────
// Helpers: URL handling + finding construction.
// ─────────────────────────────────────────────────────────────────────────────────

fn base_url(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{t}")
    }
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase))
}

/// Redirect-following client for discovery / JWKS retrieval.
fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-IdentityProbe/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Non-redirecting client so authorization-endpoint behavior (302 Location) is observable raw.
fn make_no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Weissman-IdentityProbe/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[allow(clippy::too_many_arguments)]
fn id_finding(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    confidence: f64,
    evidence: Evidence,
    category: &str,
    standards: &[&str],
) -> Value {
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        evidence,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("identity_domain".to_string(), json!("oauth_oidc"));
        obj.insert("category".to_string(), json!(category));
        if !standards.is_empty() {
            obj.insert("standards".to_string(), json!(standards));
        }
    }
    f
}

fn attack_path_finding(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    confidence: f64,
    steps: &[&str],
    evidence: Evidence,
) -> Value {
    let mut f = id_finding(
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        evidence,
        "attack_path",
        &[],
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("attack_path".to_string(), json!(steps));
        obj.insert("graph_kind".to_string(), json!("toxic_combination"));
    }
    f
}

// ─────────────────────────────────────────────────────────────────────────────────
// Pure analyzers (unit-tested).
// ─────────────────────────────────────────────────────────────────────────────────

/// Estimate an RSA modulus size in bits from the base64url `n` parameter of a JWK.
fn estimate_rsa_bits(n_b64url: &str) -> Option<usize> {
    let cleaned = n_b64url.trim().trim_end_matches('=');
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cleaned)
        .ok()?;
    // Drop a leading zero byte (ASN.1 sign padding) if present before counting.
    let len = bytes
        .iter()
        .position(|&b| b != 0)
        .map_or(0, |p| bytes.len() - p);
    if len == 0 {
        None
    } else {
        Some(len * 8)
    }
}

/// Classify an advertised signing algorithm. Returns `Some((severity, reason))` when risky.
fn classify_signing_alg(alg: &str) -> Option<(&'static str, String)> {
    let a = alg.trim().to_ascii_uppercase();
    match a.as_str() {
        "NONE" => Some((
            "critical",
            "`alg:none` is advertised — unsigned tokens may be accepted, enabling trivial ID-token forgery and full impersonation.".to_string(),
        )),
        "HS256" | "HS384" | "HS512" => Some((
            "high",
            format!("Symmetric signing ({a}) is advertised. If any client can learn the shared secret, or an RS256↔HS256 algorithm-confusion is possible, attackers can forge valid tokens."),
        )),
        "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512"
        | "EDDSA" => None,
        other if !other.is_empty() => Some((
            "low",
            format!("Unrecognized signing algorithm `{a}` advertised — review whether it meets current cryptographic guidance."),
        )),
        _ => None,
    }
}

/// Best-effort identity-provider fingerprint from issuer + host.
fn fingerprint_provider(issuer: &str, host: &str) -> Option<&'static str> {
    let i = issuer.to_ascii_lowercase();
    let h = host.to_ascii_lowercase();
    let hay = format!("{i} {h}");
    let table: &[(&str, &str)] = &[
        ("okta.com", "Okta"),
        ("oktapreview.com", "Okta (preview)"),
        ("auth0.com", "Auth0"),
        ("login.microsoftonline.com", "Microsoft Entra ID (Azure AD)"),
        ("sts.windows.net", "Microsoft Entra ID (Azure AD)"),
        ("ciamlogin.com", "Microsoft Entra External ID"),
        ("accounts.google.com", "Google Identity"),
        ("cognito-idp.", "AWS Cognito"),
        ("amazoncognito.com", "AWS Cognito"),
        ("/realms/", "Keycloak"),
        ("pingone.com", "Ping Identity (PingOne)"),
        ("pingidentity.com", "Ping Identity"),
        ("onelogin.com", "OneLogin"),
        ("duosecurity.com", "Cisco Duo"),
        ("fusionauth.io", "FusionAuth"),
        ("frontegg.com", "Frontegg"),
        ("workos.com", "WorkOS"),
        ("gitlab", "GitLab OIDC"),
        ("salesforce.com", "Salesforce Identity"),
    ];
    for (needle, name) in table {
        if hay.contains(needle) {
            return Some(name);
        }
    }
    None
}

fn str_array(doc: &Value, key: &str) -> Vec<String> {
    doc.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────────
// Signal accumulator for attack-path synthesis + scoring.
// ─────────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct IdentitySignals {
    issuer: Option<String>,
    provider: Option<String>,
    discovered: bool,
    implicit_flow: bool,
    ropc_grant: bool,
    pkce_not_advertised: bool,
    pkce_plain_only: bool,
    alg_none: bool,
    symmetric_alg: bool,
    weak_jwks_key: bool,
    public_clients_allowed: bool,
    request_uri_unregistered: bool,
    insecure_issuer_transport: bool,
    open_redirect_uri: bool,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    par_endpoint: Option<String>,
    device_auth_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    registration_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    jwks_uri: Option<String>,
    device_flow_advertised: bool,
    token_issued_without_auth: bool,
    jwks_http: bool,
    userinfo_anonymous: bool,
    dcr_open: bool,
    introspection_reachable: bool,
    ropc_live_accepts: bool,
    pkce_not_enforced_live: bool,
    device_flow_reachable: bool,
    cors_permissive_metadata: bool,
    saml_metadata_exposed: bool,
    subdomain_takeover_hits: usize,
    subdomain_oauth_surfaces: usize,
    backchannel_logout_missing: bool,
    par_missing: bool,
    dpop_missing: bool,
    risky_scopes_advertised: bool,
}

impl IdentitySignals {
    fn has_gaps(&self) -> bool {
        self.implicit_flow
            || self.ropc_grant
            || self.ropc_live_accepts
            || self.pkce_not_advertised
            || self.pkce_plain_only
            || self.pkce_not_enforced_live
            || self.alg_none
            || self.symmetric_alg
            || self.weak_jwks_key
            || self.open_redirect_uri
            || self.token_issued_without_auth
            || self.request_uri_unregistered
            || self.insecure_issuer_transport
            || self.jwks_http
            || self.userinfo_anonymous
            || self.dcr_open
            || self.cors_permissive_metadata
            || self.saml_metadata_exposed
            || self.subdomain_takeover_hits > 0
            || self.par_missing
            || self.dpop_missing
            || self.backchannel_logout_missing
            || self.risky_scopes_advertised
    }

    /// Six-axis identity posture radar (0–100 per axis; higher = stronger).
    fn radar(&self) -> Value {
        let axis = |bad: bool, weight: u32| -> u32 {
            if bad {
                100u32.saturating_sub(weight)
            } else {
                100
            }
        };
        let flow_bad = self.implicit_flow
            || self.ropc_grant
            || self.ropc_live_accepts
            || self.device_flow_advertised && self.device_flow_reachable;
        let crypto_bad =
            self.alg_none || self.symmetric_alg || self.weak_jwks_key || self.jwks_http;
        let redirect_bad = self.open_redirect_uri;
        let client_auth_bad = self.public_clients_allowed
            && (self.pkce_not_advertised || self.pkce_plain_only)
            || self.token_issued_without_auth;
        let hardening_bad = self.pkce_not_advertised
            || self.pkce_plain_only
            || self.pkce_not_enforced_live
            || self.par_missing
            || self.dpop_missing
            || self.backchannel_logout_missing;
        let exposure_bad = self.userinfo_anonymous
            || self.dcr_open
            || self.introspection_reachable
            || self.cors_permissive_metadata
            || self.saml_metadata_exposed
            || self.subdomain_takeover_hits > 0
            || self.request_uri_unregistered;
        json!({
            "flow_hygiene": axis(flow_bad, 35),
            "token_crypto": axis(crypto_bad, 40),
            "redirect_validation": axis(redirect_bad, 45),
            "client_authentication": axis(client_auth_bad, 35),
            "modern_hardening": axis(hardening_bad, 30),
            "endpoint_exposure": axis(exposure_bad, 25),
        })
    }

    fn rfc9700_matrix(&self) -> Value {
        let row = |id: &str, title: &str, pass: bool, detail: &str| {
            json!({
                "control_id": id,
                "title": title,
                "status": if pass { "pass" } else { "fail" },
                "detail": detail,
            })
        };
        json!([
            row(
                "RFC9700-2.1",
                "Exact redirect_uri matching",
                !self.open_redirect_uri,
                if self.open_redirect_uri {
                    "Arbitrary redirect_uri accepted in live probe"
                } else {
                    "Attacker redirect_uri rejected or not honored"
                }
            ),
            row(
                "RFC9700-2.1.1",
                "PKCE (S256) for public clients",
                !self.pkce_not_advertised && !self.pkce_plain_only && !self.pkce_not_enforced_live,
                if self.pkce_not_advertised {
                    "PKCE not advertised"
                } else if self.pkce_plain_only {
                    "Only plain PKCE"
                } else if self.pkce_not_enforced_live {
                    "Authorization code issued without code_challenge"
                } else {
                    "PKCE posture acceptable"
                }
            ),
            row(
                "RFC9700-2.1.2",
                "No implicit flow",
                !self.implicit_flow,
                if self.implicit_flow {
                    "Implicit flow advertised or accepted live"
                } else {
                    "Implicit flow not observed"
                }
            ),
            row(
                "RFC9700-2.4",
                "No ROPC grant",
                !self.ropc_grant && !self.ropc_live_accepts,
                if self.ropc_live_accepts {
                    "ROPC grant accepted at token endpoint"
                } else if self.ropc_grant {
                    "ROPC advertised in metadata"
                } else {
                    "ROPC not advertised"
                }
            ),
            row(
                "RFC9700-2.5",
                "Token-endpoint client authentication",
                !self.token_issued_without_auth,
                if self.token_issued_without_auth {
                    "client_credentials without secret returned access_token"
                } else {
                    "No unauthenticated token minting observed"
                }
            ),
            row(
                "RFC9700-4",
                "Strong asymmetric token signing",
                !self.alg_none && !self.symmetric_alg && !self.weak_jwks_key,
                if self.alg_none {
                    "alg:none advertised"
                } else if self.symmetric_alg {
                    "HS* symmetric signing advertised"
                } else if self.weak_jwks_key {
                    "Undersized JWKS RSA key"
                } else {
                    "Signing algorithms and JWKS acceptable"
                }
            ),
            row(
                "RFC9700-4.5",
                "request_uri registration",
                !self.request_uri_unregistered,
                if self.request_uri_unregistered {
                    "request_uri without registration"
                } else {
                    "request_uri posture acceptable"
                }
            ),
            row(
                "RFC9126",
                "Pushed Authorization Requests (PAR)",
                !self.par_missing,
                if self.par_missing {
                    "PAR endpoint not advertised"
                } else {
                    "PAR advertised"
                }
            ),
            row(
                "RFC9449",
                "DPoP sender-constrained tokens",
                !self.dpop_missing,
                if self.dpop_missing {
                    "DPoP not advertised"
                } else {
                    "DPoP signing algs advertised"
                }
            ),
            row(
                "RFC9700-2.1",
                "TLS for issuer and JWKS",
                !self.insecure_issuer_transport && !self.jwks_http,
                if self.insecure_issuer_transport {
                    "Issuer uses http://"
                } else if self.jwks_http {
                    "jwks_uri uses http://"
                } else {
                    "HTTPS for issuer/JWKS"
                }
            ),
        ])
    }
}

// ─────────────────────────────────────────────────────────────────────────────────
// Layer 1+2 — Discovery + metadata posture.
// ─────────────────────────────────────────────────────────────────────────────────

async fn discover_metadata(
    client: &reqwest::Client,
    base: &str,
    cfg: &ArsenalConfig,
) -> Option<(String, Value)> {
    let mut candidates: Vec<String> = Vec::new();
    // Operator override: explicit discovery URL or issuer.
    if let Some(durl) = cfg.string("discovery_url") {
        candidates.push(durl);
    }
    if let Some(issuer) = cfg.string("issuer") {
        let iss = issuer.trim_end_matches('/').to_string();
        candidates.push(format!("{iss}/.well-known/openid-configuration"));
        candidates.push(format!("{iss}/.well-known/oauth-authorization-server"));
    }
    for p in DEFAULT_DISCOVERY_PATHS {
        candidates.push(format!("{base}{p}"));
    }
    for extra in cfg.string_list("extra_discovery_paths") {
        let e = extra.trim();
        if e.starts_with("http") {
            candidates.push(e.to_string());
        } else {
            candidates.push(format!("{base}{e}"));
        }
    }

    for url in candidates {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().as_u16() == 200 {
                let body = resp.text().await.unwrap_or_default();
                if let Ok(doc) = serde_json::from_str::<Value>(&body) {
                    if doc.get("issuer").is_some()
                        || doc.get("authorization_endpoint").is_some()
                        || doc.get("token_endpoint").is_some()
                    {
                        return Some((url, doc));
                    }
                }
            }
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
fn analyze_metadata(
    doc: &Value,
    discovery_url: &str,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let issuer = doc
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    sig.issuer = Some(if issuer.is_empty() {
        discovery_url.to_string()
    } else {
        issuer.clone()
    });
    sig.authorization_endpoint = doc
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .map(str::to_string);
    sig.token_endpoint = doc
        .get("token_endpoint")
        .and_then(Value::as_str)
        .map(str::to_string);
    sig.par_endpoint = doc
        .get("pushed_authorization_request_endpoint")
        .and_then(Value::as_str)
        .map(str::to_string);
    sig.device_auth_endpoint = doc
        .get("device_authorization_endpoint")
        .and_then(Value::as_str)
        .map(str::to_string);
    sig.userinfo_endpoint = doc
        .get("userinfo_endpoint")
        .and_then(Value::as_str)
        .map(str::to_string);
    sig.introspection_endpoint = doc
        .get("introspection_endpoint")
        .and_then(Value::as_str)
        .map(str::to_string);
    sig.revocation_endpoint = doc
        .get("revocation_endpoint")
        .and_then(Value::as_str)
        .map(str::to_string);
    sig.registration_endpoint = doc
        .get("registration_endpoint")
        .and_then(Value::as_str)
        .map(str::to_string);
    sig.end_session_endpoint = doc
        .get("end_session_endpoint")
        .and_then(Value::as_str)
        .map(str::to_string);
    sig.jwks_uri = doc
        .get("jwks_uri")
        .and_then(Value::as_str)
        .map(str::to_string);

    if let Some(jwks) = sig.jwks_uri.as_deref() {
        if jwks.starts_with("http://") {
            sig.jwks_http = true;
            findings.push(id_finding(
                "JWKS URI served over plaintext HTTP",
                "high",
                T_FORGE_OIDC,
                &format!("`jwks_uri` is `{jwks}` (http://). Signing keys and token verification material can be intercepted or substituted on the wire. Publish JWKS exclusively over HTTPS."),
                target,
                0.85,
                Evidence::new().with("jwks_uri", jwks).check("jwks_https", false, "jwks_uri scheme is http"),
                "transport_security",
                &["RFC7517", "RFC9700-2.1"],
            ));
        }
    }

    let host = host_of(&issuer)
        .or_else(|| host_of(discovery_url))
        .unwrap_or_default();
    let provider = fingerprint_provider(&issuer, &host);
    sig.provider = provider.map(str::to_string);

    // Discovery exposure (informational asset-inventory context).
    {
        let mut ev = Evidence::new()
            .with("discovery_url", discovery_url)
            .with("issuer", issuer.clone())
            .check(
                "discovery_document",
                true,
                "RFC 8414 / OIDC metadata served",
            );
        if let Some(p) = provider {
            ev = ev.with("provider", p);
        }
        findings.push(id_finding(
            &format!(
                "Identity provider discovery document exposed{}",
                provider.map(|p| format!(" ({p})")).unwrap_or_default()
            ),
            "info",
            T_APP_TOKEN,
            &format!("OAuth/OIDC metadata is published at {discovery_url}. Catalogued for posture analysis and attack-path correlation."),
            target,
            0.9,
            ev,
            "asset_inventory",
            &["RFC8414", "OIDC-Discovery"],
        ));
    }

    // Issuer transport.
    if issuer.starts_with("http://") {
        sig.insecure_issuer_transport = true;
        findings.push(id_finding(
            "OAuth issuer served over plaintext HTTP",
            "critical",
            T_STEAL_TOKEN,
            &format!("The advertised issuer `{issuer}` uses http://. Tokens and authorization codes can be intercepted; OAuth mandates TLS for all endpoints."),
            target,
            0.9,
            Evidence::new().with("issuer", issuer.clone()).check("https_issuer", false, "Issuer scheme is http"),
            "transport_security",
            &["RFC9700-2.1"],
        ));
    }

    // Response types — implicit flow.
    let response_types = str_array(doc, "response_types_supported");
    let implicit = response_types.iter().any(|t| {
        let parts: Vec<&str> = t.split_whitespace().collect();
        parts.contains(&"token") || (parts.contains(&"id_token") && !parts.contains(&"code"))
    });
    if implicit {
        sig.implicit_flow = true;
        findings.push(id_finding(
            "Implicit flow supported (tokens returned in URL fragment)",
            "high",
            T_STEAL_COOKIE,
            &format!("`response_types_supported` advertises implicit flow ({}). Access/ID tokens are returned in the URL fragment where they leak via browser history, Referer, and logs. OAuth 2.1 / RFC 9700 forbid implicit flow — use authorization code + PKCE.", response_types.join(", ")),
            target,
            0.85,
            Evidence::new().with("response_types_supported", json!(response_types)).check("implicit_response_type", true, "token / id_token-only response type advertised"),
            "insecure_flow",
            &["RFC9700-2.1.2", "OAuth2.1"],
        ));
    }

    // Grant types — ROPC / implicit.
    let grant_types = str_array(doc, "grant_types_supported");
    if grant_types.iter().any(|t| t == "implicit") {
        sig.implicit_flow = true;
        findings.push(id_finding(
            "Implicit grant type advertised",
            "high",
            T_STEAL_COOKIE,
            "`grant_types_supported` includes `implicit`, deprecated for its token-leakage exposure. Disable it and require authorization code + PKCE.",
            target,
            0.8,
            Evidence::new().with("grant_types_supported", json!(grant_types)).check("implicit_grant", true, "implicit grant advertised"),
            "insecure_flow",
            &["RFC9700-2.1.2"],
        ));
    }
    if grant_types.iter().any(|t| t == "password") {
        sig.ropc_grant = true;
        findings.push(id_finding(
            "Resource Owner Password Credentials (ROPC) grant advertised",
            "medium",
            T_APP_TOKEN,
            "`grant_types_supported` includes `password` (ROPC). It hands user passwords directly to the client, defeats MFA/passwordless, and is removed in OAuth 2.1. Migrate to authorization code + PKCE.",
            target,
            0.8,
            Evidence::new().with("grant_types_supported", json!(grant_types)).check("ropc_grant", true, "password grant advertised"),
            "insecure_flow",
            &["RFC9700-2.4", "OAuth2.1"],
        ));
    }
    let device_grant = grant_types.iter().any(|t| {
        t.contains("device_code") || t.contains("urn:ietf:params:oauth:grant-type:device_code")
    }) || sig.device_auth_endpoint.is_some();
    if device_grant {
        sig.device_flow_advertised = true;
        findings.push(id_finding(
            "OAuth device authorization grant advertised (device flow)",
            "medium",
            T_STEAL_TOKEN,
            "The provider advertises the device authorization grant (RFC 8628). Device flow is vulnerable to social-engineering of user codes and slow-polling abuse if rate limits and user-code entropy are weak. Restrict to trusted device clients, enforce strict polling limits, and prefer authorization code + PKCE for user-facing apps.",
            target,
            0.65,
            Evidence::new()
                .with("device_authorization_endpoint", sig.device_auth_endpoint.clone().unwrap_or_default())
                .check("device_flow_advertised", true, "device_code grant or device_authorization_endpoint present"),
            "insecure_flow",
            &["RFC8628", "RFC9700-2.8"],
        ));
    }

    // PKCE advertisement.
    let pkce_methods = str_array(doc, "code_challenge_methods_supported");
    let has_authorization_code = grant_types.is_empty()
        || grant_types.iter().any(|t| t == "authorization_code")
        || response_types
            .iter()
            .any(|t| t.split_whitespace().any(|p| p == "code"));
    if has_authorization_code {
        if pkce_methods.is_empty() {
            sig.pkce_not_advertised = true;
            findings.push(id_finding(
                "PKCE not advertised (code_challenge_methods_supported missing)",
                "medium",
                T_STEAL_TOKEN,
                "The metadata does not advertise PKCE support for the authorization code flow. Without enforced PKCE, intercepted authorization codes can be exchanged for tokens. Require PKCE with S256 for all clients.",
                target,
                0.7,
                Evidence::new().check("code_challenge_methods_supported", false, "PKCE methods absent from metadata"),
                "missing_pkce",
                &["RFC9700-2.1.1", "RFC7636"],
            ));
        } else if pkce_methods.iter().all(|m| m.eq_ignore_ascii_case("plain")) {
            sig.pkce_plain_only = true;
            findings.push(id_finding(
                "PKCE supports only the `plain` method (no S256)",
                "medium",
                T_STEAL_TOKEN,
                "Only the `plain` PKCE method is advertised. `plain` offers no protection if the verifier is observed in transit. Support and require `S256`.",
                target,
                0.7,
                Evidence::new().with("code_challenge_methods_supported", json!(pkce_methods)).check("s256_supported", false, "Only plain advertised"),
                "missing_pkce",
                &["RFC7636"],
            ));
        }
    }

    // ID-token signing algorithms.
    let id_algs = str_array(doc, "id_token_signing_alg_values_supported");
    for alg in &id_algs {
        if let Some((sev, reason)) = classify_signing_alg(alg) {
            if alg.eq_ignore_ascii_case("none") {
                sig.alg_none = true;
            } else if alg.to_ascii_uppercase().starts_with("HS") {
                sig.symmetric_alg = true;
            }
            findings.push(id_finding(
                &format!("Risky ID-token signing algorithm advertised: {alg}"),
                sev,
                T_FORGE_OIDC,
                &reason,
                target,
                if sev == "critical" { 0.85 } else { 0.7 },
                Evidence::new()
                    .with("algorithm", alg.clone())
                    .with("id_token_signing_alg_values_supported", json!(id_algs))
                    .check("risky_signing_alg", true, reason.clone()),
                "weak_token_signing",
                &["RFC9700-4", "JWT-BCP"],
            ));
        }
    }

    // Token-endpoint authentication methods.
    let auth_methods = str_array(doc, "token_endpoint_auth_methods_supported");
    if auth_methods.iter().any(|m| m.eq_ignore_ascii_case("none")) {
        sig.public_clients_allowed = true;
        findings.push(id_finding(
            "Public clients allowed at the token endpoint (auth method `none`)",
            "low",
            T_APP_TOKEN,
            "`token_endpoint_auth_methods_supported` includes `none`, allowing public (secret-less) clients. This is acceptable only when PKCE is strictly enforced; combined with missing PKCE it enables code interception.",
            target,
            0.65,
            Evidence::new().with("token_endpoint_auth_methods_supported", json!(auth_methods)).check("public_client_allowed", true, "auth method none advertised"),
            "client_authentication",
            &["RFC9700-2.1.1"],
        ));
    }

    // request_uri / JAR without registration → SSRF / request-object injection surface.
    let request_uri_param = doc
        .get("request_uri_parameter_supported")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let require_request_uri_registration = doc
        .get("require_request_uri_registration")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if request_uri_param && !require_request_uri_registration {
        sig.request_uri_unregistered = true;
        findings.push(id_finding(
            "request_uri accepted without registration (SSRF / JAR injection surface)",
            "medium",
            T_APP_TOKEN,
            "The server accepts `request_uri` without requiring pre-registration. An attacker can point it at an arbitrary URL, creating an SSRF channel and enabling request-object injection. Set `require_request_uri_registration=true` or disable `request_uri`.",
            target,
            0.7,
            Evidence::new().check("request_uri_parameter_supported", true, "request_uri accepted").check("require_request_uri_registration", false, "registration not required"),
            "request_object_abuse",
            &["RFC9700-4.5", "OIDC-Core-6.2"],
        ));
    }

    // Hardening posture (informational gaps — positive controls absent).
    let par = doc.get("pushed_authorization_request_endpoint").is_some()
        || doc
            .get("require_pushed_authorization_requests")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let dpop = !str_array(doc, "dpop_signing_alg_values_supported").is_empty();
    sig.par_missing = !par;
    sig.dpop_missing = !dpop;
    let backchannel = doc
        .get("backchannel_logout_supported")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || doc
            .get("backchannel_logout_session_supported")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    sig.backchannel_logout_missing = !backchannel;
    if !par || !dpop {
        let mut missing = Vec::new();
        if !par {
            missing.push("Pushed Authorization Requests (PAR, RFC 9126)");
        }
        if !dpop {
            missing.push("DPoP sender-constrained tokens (RFC 9449)");
        }
        findings.push(id_finding(
            "Modern OAuth hardening features not advertised",
            "info",
            T_APP_TOKEN,
            &format!("The provider does not advertise: {}. These materially reduce token-theft and authorization-request-tampering risk; adopt them where the platform supports it.", missing.join("; ")),
            target,
            0.6,
            Evidence::new().with("missing_hardening", json!(missing)),
            "hardening_gap",
            &["RFC9126", "RFC9449", "RFC9700"],
        ));
    }
    if !backchannel {
        findings.push(id_finding(
            "Back-channel logout not advertised (session persistence after IdP sign-out)",
            "low",
            T_STEAL_COOKIE,
            "The metadata does not advertise `backchannel_logout_supported`. Without back-channel (or front-channel) logout, relying parties may keep sessions alive after the user signs out at the IdP — increasing stolen-token window. Enable OIDC back-channel logout where supported.",
            target,
            0.55,
            Evidence::new().check("backchannel_logout_supported", false, "Not advertised in metadata"),
            "session_management",
            &["OIDC-Back-Channel-Logout", "RFC9700-2.7"],
        ));
    }
    if sig.end_session_endpoint.is_none() {
        findings.push(id_finding(
            "End-session (RP-initiated logout) endpoint not advertised",
            "info",
            T_STEAL_COOKIE,
            "No `end_session_endpoint` in metadata. RP-initiated logout may be unavailable or vendor-specific, complicating consistent session termination across federated apps.",
            target,
            0.5,
            Evidence::new().check("end_session_endpoint", false, "Absent from metadata"),
            "session_management",
            &["OIDC-Session", "RFC9700-2.7"],
        ));
    }

    // Scope hygiene — flag over-broad advertised scopes (inventory + abuse surface).
    let scopes = str_array(doc, "scopes_supported");
    let risky_scope_needles = [
        "admin",
        "management",
        "write",
        "delete",
        "full",
        "offline_access",
        "user_impersonation",
        ".default",
    ];
    let risky: Vec<&str> = scopes
        .iter()
        .filter(|s| {
            let sl = s.to_ascii_lowercase();
            risky_scope_needles
                .iter()
                .any(|n| sl.contains(n) || sl.ends_with("all"))
        })
        .map(|s| s.as_str())
        .collect();
    if !risky.is_empty() {
        sig.risky_scopes_advertised = true;
        findings.push(id_finding(
            "Broad or high-privilege OAuth scopes advertised",
            "low",
            T_APP_TOKEN,
            &format!(
                "`scopes_supported` includes potentially high-impact scope(s): {}. Review least-privilege defaults, consent prompts, and admin-consent requirements for these scopes.",
                risky.join(", ")
            ),
            target,
            0.6,
            Evidence::new()
                .with("scopes_supported", json!(scopes))
                .with("risky_scopes", json!(risky)),
            "scope_hygiene",
            &["RFC9700-2.6", "OAuth2-Scope"],
        ));
    }

    // Federation bridge hints from metadata.
    if doc.get("claims_supported").is_some() {
        let claims = str_array(doc, "claims_supported");
        if claims.iter().any(|c| c.eq_ignore_ascii_case("groups"))
            && claims.iter().any(|c| c.eq_ignore_ascii_case("email"))
        {
            findings.push(id_finding(
                "OIDC claims bridge group + email (federation abuse surface)",
                "info",
                T_APP_TOKEN,
                "Metadata advertises both `groups` and `email` claims. Misconfigured group-to-role mapping or unverified email claims can yield privilege escalation in downstream SaaS. Enforce verified email, group filtering, and least-privilege role assignment.",
                target,
                0.55,
                Evidence::new().with("claims_supported", json!(claims)),
                "federation_hygiene",
                &["RFC9700-2.6"],
            ));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────
// Layer 3 — JWKS cryptographic analysis.
// ─────────────────────────────────────────────────────────────────────────────────

async fn analyze_jwks(
    client: &reqwest::Client,
    doc: &Value,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let Some(jwks_uri) = doc.get("jwks_uri").and_then(Value::as_str) else {
        return;
    };
    let Ok(resp) = client.get(jwks_uri).send().await else {
        return;
    };
    if resp.status().as_u16() != 200 {
        return;
    }
    let body = resp.text().await.unwrap_or_default();
    let Ok(jwks) = serde_json::from_str::<Value>(&body) else {
        return;
    };
    let Some(keys) = jwks.get("keys").and_then(Value::as_array) else {
        return;
    };

    let mut min_rsa_bits: Option<usize> = None;
    let mut missing_kid = 0usize;
    for key in keys {
        let kty = key.get("kty").and_then(Value::as_str).unwrap_or("");
        if key
            .get("kid")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        {
            missing_kid += 1;
        }
        if kty.eq_ignore_ascii_case("RSA") {
            if let Some(n) = key.get("n").and_then(Value::as_str) {
                if let Some(bits) = estimate_rsa_bits(n) {
                    min_rsa_bits = Some(min_rsa_bits.map_or(bits, |m| m.min(bits)));
                }
            }
        }
        if let Some(alg) = key.get("alg").and_then(Value::as_str) {
            if alg.eq_ignore_ascii_case("none") {
                sig.alg_none = true;
            }
        }
    }

    if let Some(bits) = min_rsa_bits {
        if bits < 2048 {
            sig.weak_jwks_key = true;
            findings.push(id_finding(
                &format!("JWKS contains an undersized RSA signing key (~{bits}-bit)"),
                "high",
                T_FORGE_OIDC,
                &format!("A signing key in {jwks_uri} is approximately {bits}-bit RSA (< 2048). Undersized keys weaken token-signature integrity and may be factorable; rotate to ≥ 2048-bit RSA or an EC/EdDSA key."),
                target,
                0.8,
                Evidence::new().with("jwks_uri", jwks_uri).with("rsa_bits_estimate", bits).check("rsa_key_lt_2048", true, "Estimated modulus below 2048 bits"),
                "weak_token_signing",
                &["NIST-SP-800-57", "JWT-BCP"],
            ));
        }
    }
    if missing_kid > 0 {
        findings.push(id_finding(
            "JWKS keys missing `kid` (key id)",
            "low",
            T_FORGE_OIDC,
            &format!("{missing_kid} key(s) in {jwks_uri} have no `kid`. Missing key identifiers complicate safe key rotation and can enable key-confusion during verification."),
            target,
            0.6,
            Evidence::new().with("jwks_uri", jwks_uri).with("keys_without_kid", missing_kid).check("missing_kid", true, "At least one JWK has no kid"),
            "key_management",
            &["JWT-BCP"],
        ));
    }

    findings.push(id_finding(
        "JWKS published",
        "info",
        T_APP_TOKEN,
        &format!(
            "{} signing key(s) published at {jwks_uri}. Analyzed for size and algorithm posture.",
            keys.len()
        ),
        target,
        0.9,
        Evidence::new()
            .with("jwks_uri", jwks_uri)
            .with("key_count", keys.len()),
        "asset_inventory",
        &["RFC7517"],
    ));
}

// ─────────────────────────────────────────────────────────────────────────────────
// Layer 3b — Token endpoint + PAR live probing (unauthenticated, evidence-only).
// ─────────────────────────────────────────────────────────────────────────────────

async fn probe_token_and_par_endpoints(
    cfg: &ArsenalConfig,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let client = make_client();
    let client_id = cfg.string_or("client_id", "weissman-probe-client");
    let probe_redirect = cfg.string_or(
        "probe_redirect_uri",
        "https://oauth-validate.weissman.invalid/callback",
    );

    if let Some(token_ep) = sig.token_endpoint.clone() {
        let invalid_code_body = format!(
            "grant_type=authorization_code&code=weissman-invalid-probe&redirect_uri={ru}&client_id={cid}",
            ru = urlencoding::encode(&probe_redirect),
            cid = urlencoding::encode(&client_id),
        );
        if let Ok(resp) = client
            .post(&token_ep)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(invalid_code_body)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let rejects_invalid_code = status == 400
                || status == 401
                || body.contains("invalid_grant")
                || body.contains("invalid_client")
                || body.contains("unsupported_grant_type");
            findings.push(id_finding(
                "Token endpoint reachable (live probe)",
                if rejects_invalid_code { "info" } else { "low" },
                T_APP_TOKEN,
                &format!(
                    "The token endpoint at {token_ep} responded to a benign invalid-code exchange probe (HTTP {status}). {}",
                    if rejects_invalid_code {
                        "The server rejected the forged authorization code — expected validation behavior."
                    } else {
                        "Response did not clearly reject the invalid code; review token-endpoint error handling and logging."
                    }
                ),
                target,
                0.7,
                Evidence::new()
                    .with("token_endpoint", token_ep.clone())
                    .with("http_status", status)
                    .check("rejects_invalid_code", rejects_invalid_code, "Invalid authorization code rejected"),
                "asset_inventory",
                &["RFC6749-3.2"],
            ));

            if sig.public_clients_allowed {
                let cc_body = format!(
                    "grant_type=client_credentials&client_id={cid}",
                    cid = urlencoding::encode(&client_id),
                );
                if let Ok(cc_resp) = client
                    .post(&token_ep)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(cc_body)
                    .send()
                    .await
                {
                    let cc_status = cc_resp.status().as_u16();
                    let cc_body_text = cc_resp.text().await.unwrap_or_default();
                    if cc_status == 200 && cc_body_text.contains("access_token") {
                        sig.token_issued_without_auth = true;
                        findings.push(id_finding(
                            "Token endpoint issued access token without client authentication",
                            "critical",
                            T_STEAL_TOKEN,
                            &format!(
                                "A `client_credentials` request with only `client_id={client_id}` (no secret, no mTLS) returned HTTP 200 with an access_token from {token_ep}. Any party who learns or guesses a public client_id can obtain tokens. Require confidential clients or bind tokens with mTLS/DPoP.",
                            ),
                            target,
                            0.88,
                            Evidence::new()
                                .with("token_endpoint", token_ep)
                                .with("http_status", cc_status)
                                .check("client_credentials_without_auth", true, "access_token returned without client secret"),
                            "token_endpoint_auth",
                            &["RFC6749-2.3", "RFC9700-2.5"],
                        ));
                    }
                }
            }
        }
    }

    if let Some(par_ep) = sig.par_endpoint.clone() {
        if let Ok(resp) = client
            .post(&par_ep)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("client_id=weissman-par-probe")
            .send()
            .await
        {
            let status = resp.status().as_u16();
            if status != 404 && status != 0 {
                findings.push(id_finding(
                    "Pushed Authorization Request (PAR) endpoint reachable",
                    "info",
                    T_APP_TOKEN,
                    &format!(
                        "The PAR endpoint at {par_ep} responded to a minimal probe (HTTP {status}). PAR reduces authorization-request tampering when enforced — ensure clients use PAR for sensitive flows.",
                    ),
                    target,
                    0.75,
                    Evidence::new()
                        .with("pushed_authorization_request_endpoint", par_ep)
                        .with("http_status", status)
                        .check("par_endpoint_reachable", true, "PAR endpoint responded"),
                    "hardening_signal",
                    &["RFC9126"],
                ));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────
// Layer 3c — OIDC extension endpoints (userinfo, introspection, revocation, DCR).
// ─────────────────────────────────────────────────────────────────────────────────

/// Replay WebSocket-captured tokens (Intelligence Bus) against OIDC userinfo / API surfaces.
async fn probe_ws_intelligence_cross_protocol(
    job_params: &serde_json::Value,
    target: &str,
    sig: &IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let Some(arr) = job_params
        .get("intelligence_artifacts")
        .and_then(|v| v.as_array())
    else {
        return;
    };
    let client = make_client();
    let mut probe_urls: Vec<String> = Vec::new();
    if let Some(ui) = sig.userinfo_endpoint.clone() {
        probe_urls.push(ui);
    }
    if let Some(issuer) = sig.issuer.as_deref() {
        let base = issuer.trim_end_matches('/');
        for p in ["/api/me", "/api/user", "/api/v1/me", "/api/profile"] {
            probe_urls.push(format!("{base}{p}"));
        }
    }
    probe_urls.sort();
    probe_urls.dedup();

    for art in arr {
        let kind = art.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let value = art.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let proof = art.get("proof").and_then(|v| v.as_str()).unwrap_or("");
        if value.is_empty() {
            continue;
        }
        let probe = crate::ws_intelligence_bus::IntelArtifact {
            kind: kind.to_string(),
            value: value.to_string(),
            source_url: art
                .get("source_url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            source_engine: "websocket_attack".to_string(),
            proof: proof.to_string(),
            captured_unix_ms: 0,
        };
        if !crate::ws_intelligence_bus::is_cross_protocol_eligible(&probe) {
            continue;
        }
        let bearer = if value.starts_with("Bearer ") {
            value.to_string()
        } else {
            format!("Bearer {value}")
        };
        for url in &probe_urls {
            let Ok(unauth) = client.get(url).send().await else {
                continue;
            };
            let unauth_status = unauth.status().as_u16();
            let unauth_body = unauth.text().await.unwrap_or_default();
            let Ok(auth_resp) = client
                .get(url)
                .header("Authorization", &bearer)
                .send()
                .await
            else {
                continue;
            };
            let auth_status = auth_resp.status().as_u16();
            let auth_body = auth_resp.text().await.unwrap_or_default();
            let u = unauth_body.to_ascii_lowercase();
            let a = auth_body.to_ascii_lowercase();
            let unauth_denied = unauth_status == 401
                || unauth_status == 403
                || u.contains("unauthorized")
                || u.contains("forbidden");
            let auth_granted = auth_status < 400
                && !a.contains("unauthorized")
                && !a.contains("forbidden")
                && auth_body.len() > unauth_body.len().saturating_add(20);
            if unauth_denied && auth_granted {
                findings.push(id_finding(
                    "Cross-protocol escalation — WebSocket token grants OIDC/API access",
                    "critical",
                    T_STEAL_TOKEN,
                    &format!(
                        "A token harvested from a WebSocket server frame (kind={kind}, proof={proof}) was replayed against {url} and returned privileged data (HTTP {auth_status}) that unauthenticated requests could not access.",
                    ),
                    target,
                    0.95,
                    Evidence::new()
                        .with("artifact_kind", kind)
                        .with("artifact_proof", proof)
                        .with("http_url", url.clone())
                        .with("unauth_status", unauth_status)
                        .with("auth_status", auth_status)
                        .with("auth_body_preview", auth_body.chars().take(200).collect::<String>())
                        .check("ws_to_oidc_escalation", true, "WS artifact replay returned privileged OIDC/API response"),
                    "cross_protocol_escalation",
                    &["RFC9700-2.6", "T1185"],
                ));
                return;
            }
        }
    }
}

async fn probe_oidc_extension_endpoints(
    cfg: &ArsenalConfig,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let client = make_client();
    let client_id = cfg.string_or("client_id", "weissman-probe-client");

    if let Some(ui) = sig.userinfo_endpoint.clone() {
        if let Ok(resp) = client.get(&ui).send().await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let looks_like_profile = body.contains("\"sub\"")
                || body.contains("\"email\"")
                || body.contains("\"preferred_username\"");
            if status == 200 && looks_like_profile {
                sig.userinfo_anonymous = true;
                findings.push(id_finding(
                    "UserInfo endpoint returns profile data without authentication",
                    "critical",
                    T_STEAL_TOKEN,
                    &format!("GET {ui} returned HTTP 200 with OIDC profile-shaped JSON without a Bearer token. Any anonymous caller can harvest user identifiers. Require a valid access token with the `openid` scope."),
                    target,
                    0.88,
                    Evidence::new()
                        .with("userinfo_endpoint", ui.clone())
                        .with("http_status", status)
                        .check("anonymous_userinfo", true, "Profile JSON without Bearer token"),
                    "endpoint_exposure",
                    &["OIDC-Core-5.3", "RFC9700-2.6"],
                ));
            } else {
                findings.push(id_finding(
                    "UserInfo endpoint reachable",
                    "info",
                    T_APP_TOKEN,
                    &format!(
                        "UserInfo endpoint at {ui} responded (HTTP {status}). {}",
                        if status == 401 || status == 403 {
                            "Authentication required — expected."
                        } else {
                            "Review access-token requirements."
                        }
                    ),
                    target,
                    0.65,
                    Evidence::new()
                        .with("userinfo_endpoint", ui)
                        .with("http_status", status),
                    "asset_inventory",
                    &["OIDC-Core-5.3"],
                ));
            }
        }
    }

    if let Some(introspect) = sig.introspection_endpoint.clone() {
        let body = format!(
            "token=weissman-invalid-introspect&client_id={cid}",
            cid = urlencoding::encode(&client_id),
        );
        if let Ok(resp) = client
            .post(&introspect)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            if status != 404 && status != 0 {
                sig.introspection_reachable = true;
                findings.push(id_finding(
                    "Token introspection endpoint reachable",
                    "info",
                    T_APP_TOKEN,
                    &format!("Introspection endpoint at {introspect} responded (HTTP {status}). Ensure only confidential resource servers can introspect tokens and rate-limit the endpoint."),
                    target,
                    0.7,
                    Evidence::new()
                        .with("introspection_endpoint", introspect)
                        .with("http_status", status)
                        .check("introspection_reachable", true, "Endpoint responded to probe"),
                    "asset_inventory",
                    &["RFC7662"],
                ));
            }
        }
    }

    if let Some(revoke) = sig.revocation_endpoint.clone() {
        if let Ok(resp) = client
            .post(&revoke)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("token=weissman-invalid-revoke")
            .send()
            .await
        {
            let status = resp.status().as_u16();
            if status != 404 && status != 0 {
                findings.push(id_finding(
                    "Token revocation endpoint reachable",
                    "info",
                    T_APP_TOKEN,
                    &format!("Revocation endpoint at {revoke} responded (HTTP {status}). Confirm client authentication is required for revocation requests."),
                    target,
                    0.65,
                    Evidence::new().with("revocation_endpoint", revoke).with("http_status", status),
                    "asset_inventory",
                    &["RFC7009"],
                ));
            }
        }
    }

    if let Some(reg) = sig.registration_endpoint.clone() {
        if let Ok(resp) = client
            .post(&reg)
            .header("Content-Type", "application/json")
            .body(r#"{"client_name":"weissman-dcr-probe","redirect_uris":["https://oauth-validate.weissman.invalid/callback"],"token_endpoint_auth_method":"none"}"#)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let registered = (status == 200 || status == 201)
                && (body.contains("client_id") || body.contains("registration_access_token"));
            if registered {
                sig.dcr_open = true;
                findings.push(id_finding(
                    "Dynamic Client Registration (DCR) accepts unauthenticated client creation",
                    "critical",
                    T_APP_TOKEN,
                    &format!("POST to {reg} returned HTTP {status} with client registration material without operator credentials. Attackers can register rogue OAuth clients (including public clients) and phish users through legitimate-looking consent screens. Disable open DCR or require initial access tokens / mTLS."),
                    target,
                    0.9,
                    Evidence::new()
                        .with("registration_endpoint", reg)
                        .with("http_status", status)
                        .check("open_dcr", true, "Client registered without auth"),
                    "endpoint_exposure",
                    &["RFC7591", "RFC9700-2.3"],
                ));
            } else if status == 401 || status == 403 {
                findings.push(id_finding(
                    "Dynamic Client Registration endpoint present (authentication required)",
                    "info",
                    T_APP_TOKEN,
                    &format!("Registration endpoint at {reg} rejected unauthenticated registration (HTTP {status}) — expected for enterprise IdPs."),
                    target,
                    0.7,
                    Evidence::new().with("registration_endpoint", reg).with("http_status", status),
                    "asset_inventory",
                    &["RFC7591"],
                ));
            }
        }
    }
}

async fn probe_device_authorization_flow(
    cfg: &ArsenalConfig,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let Some(device_ep) = sig.device_auth_endpoint.clone() else {
        return;
    };
    let client = make_client();
    let client_id = cfg.string_or("client_id", "weissman-probe-client");
    let body = format!(
        "client_id={cid}&scope=openid",
        cid = urlencoding::encode(&client_id),
    );
    if let Ok(resp) = client
        .post(&device_ep)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
    {
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status == 200 && text.contains("device_code") && text.contains("user_code") {
            sig.device_flow_reachable = true;
            findings.push(id_finding(
                "Device authorization flow issues device_code (live probe)",
                "medium",
                T_STEAL_TOKEN,
                &format!("POST to {device_ep} returned a device_code/user_code pair for client_id `{client_id}`. Device flow is reachable — enforce user-code entropy, rate limits, and restrict to trusted device clients to reduce social-engineering risk."),
                target,
                0.72,
                Evidence::new()
                    .with("device_authorization_endpoint", device_ep)
                    .with("http_status", status)
                    .check("device_code_issued", true, "device_code returned"),
                "insecure_flow",
                &["RFC8628", "RFC9700-2.8"],
            ));
        }
    }
}

async fn probe_ropc_oracle(
    cfg: &ArsenalConfig,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let Some(token_ep) = sig.token_endpoint.clone() else {
        return;
    };
    if !sig.ropc_grant && !cfg.bool_or("probe_ropc", true) {
        return;
    }
    let client = make_client();
    let client_id = cfg.string_or("client_id", "weissman-probe-client");
    let body = format!(
        "grant_type=password&username=weissman-probe%40invalid.local&password=WeissmanProbe%211&client_id={cid}&scope=openid",
        cid = urlencoding::encode(&client_id),
    );
    if let Ok(resp) = client
        .post(&token_ep)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
    {
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let ropc_enabled = text.contains("invalid_grant")
            || text.contains("invalid_user")
            || text.contains("invalid_credentials")
            || (status == 400 && !text.contains("unsupported_grant_type"));
        let ropc_disabled = text.contains("unsupported_grant_type")
            || text.contains("unauthorized_client")
            || status == 501;
        if status == 200 && text.contains("access_token") {
            sig.ropc_live_accepts = true;
            findings.push(id_finding(
                "ROPC grant accepted invalid credentials probe (grant enabled)",
                "high",
                T_APP_TOKEN,
                &format!("Token endpoint at {token_ep} returned HTTP 200 with an access_token for a ROPC probe using synthetic credentials — ROPC appears fully enabled. Disable password grant; migrate to authorization code + PKCE with phishing-resistant MFA."),
                target,
                0.82,
                Evidence::new().with("token_endpoint", token_ep).check("ropc_token_issued", true, "access_token on ROPC probe"),
                "insecure_flow",
                &["RFC9700-2.4", "OAuth2.1"],
            ));
        } else if ropc_enabled && !ropc_disabled {
            sig.ropc_live_accepts = true;
            findings.push(id_finding(
                "ROPC grant enabled at token endpoint (error-oracle probe)",
                "high",
                T_APP_TOKEN,
                &format!("Token endpoint at {token_ep} processed `grant_type=password` and returned an auth error consistent with an enabled ROPC grant (HTTP {status}). ROPC bypasses browser MFA and enables credential-stuffing directly against the token endpoint."),
                target,
                0.78,
                Evidence::new()
                    .with("token_endpoint", token_ep)
                    .with("http_status", status)
                    .check("ropc_error_oracle", true, "Password grant processed"),
                "insecure_flow",
                &["RFC9700-2.4"],
            ));
        }
    }
}

async fn probe_metadata_cors(
    discovery_url: &str,
    jwks_uri: Option<&str>,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let client = make_client();
    let probe_origin = "https://evil.weissman.invalid";
    for url in std::iter::once(discovery_url).chain(jwks_uri) {
        if let Ok(resp) = client.get(url).header("Origin", probe_origin).send().await {
            let acao = resp
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if acao == "*" || acao.eq_ignore_ascii_case(probe_origin) {
                sig.cors_permissive_metadata = true;
                findings.push(id_finding(
                    "Permissive CORS on OAuth/OIDC metadata or JWKS",
                    "medium",
                    T_APP_TOKEN,
                    &format!("{url} reflects `Access-Control-Allow-Origin: {acao}`. Browser-origin attackers can read discovery/JWKS cross-origin, aiding token-forgery reconnaissance. Restrict CORS on metadata endpoints."),
                    target,
                    0.7,
                    Evidence::new()
                        .with("url", url)
                        .with("access_control_allow_origin", acao)
                        .check("permissive_cors", true, "Wildcard or attacker origin allowed"),
                    "transport_security",
                    &["RFC9700-4"],
                ));
                break;
            }
        }
    }
}

async fn probe_saml_federation_surface(
    base: &str,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let client = make_client();
    for path in COMMON_SAML_PATHS {
        let url = format!("{base}{path}");
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status != 200 {
                continue;
            }
            let body = resp.text().await.unwrap_or_default();
            let bl = body.to_ascii_lowercase();
            if bl.contains("entitydescriptor")
                || bl.contains("md:entitydescriptor")
                || bl.contains("samlp:")
                || bl.contains("federationmetadata")
            {
                sig.saml_metadata_exposed = true;
                findings.push(id_finding(
                    "SAML federation metadata exposed (OAuth/SAML hybrid surface)",
                    "info",
                    T_FORGE_OIDC,
                    &format!("SAML metadata document reachable at {url}. Hybrid OAuth+SAML estates must keep signing certificates, ACS URLs, and NameID formats aligned — stale SAML certs or lax ACS validation can bypass OIDC hardening."),
                    target,
                    0.75,
                    Evidence::new().with("saml_metadata_url", url).check("saml_metadata", true, "EntityDescriptor XML"),
                    "federation_hygiene",
                    &["SAML2-Meta", "RFC9700"],
                ));
                break;
            }
        }
    }
}

fn apex_domain(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        Some(format!(
            "{}.{}",
            parts[parts.len() - 2],
            parts[parts.len() - 1]
        ))
    } else {
        None
    }
}

async fn probe_subdomain_identity_surface(
    cfg: &ArsenalConfig,
    host: &str,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let subs = cfg.string_list("takeover_subdomains");
    if subs.is_empty() {
        return;
    };
    let Some(apex) = apex_domain(host) else {
        return;
    };
    let client = make_client();
    for sub in subs {
        let sub = sub.trim().trim_end_matches('.');
        if sub.is_empty() {
            continue;
        }
        let fqdn = format!("{sub}.{apex}");
        let base = format!("https://{fqdn}");
        if let Ok(resp) = client
            .get(format!("{base}/.well-known/openid-configuration"))
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let bl = body.to_ascii_lowercase();
            for (sig_str, vendor) in SUBDOMAIN_TAKEOVER_SIGS {
                if bl.contains(sig_str) {
                    sig.subdomain_takeover_hits += 1;
                    findings.push(id_finding(
                        &format!("Identity subdomain dangling reference ({vendor}) — {fqdn}"),
                        "critical",
                        T_STEAL_TOKEN,
                        &format!("HTTPS GET to {base}/.well-known/openid-configuration returned a takeover signature for {vendor} (`{sig_str}`). An attacker can claim this subdomain and serve OAuth metadata under your brand — full federated identity compromise."),
                        target,
                        0.88,
                        Evidence::new()
                            .with("subdomain", fqdn.clone())
                            .with("vendor", vendor)
                            .with("signature", sig_str),
                        "subdomain_takeover",
                        &["RFC9700-2.2"],
                    ));
                    break;
                }
            }
            if status == 200 && body.contains("\"issuer\"") {
                sig.subdomain_oauth_surfaces += 1;
                findings.push(id_finding(
                    &format!("OAuth/OIDC discovery on identity subdomain `{fqdn}`"),
                    "info",
                    T_APP_TOKEN,
                    &format!("A discovery document is served at https://{fqdn}/.well-known/openid-configuration. Catalog secondary IdP surfaces for redirect_uri, certificate, and subdomain lifecycle governance."),
                    target,
                    0.7,
                    Evidence::new().with("subdomain", fqdn).with("http_status", status),
                    "asset_inventory",
                    &["RFC8414"],
                ));
            }
        }
    }
}

fn build_rfc9700_matrix_finding(target: &str, sig: &IdentitySignals) -> Value {
    let matrix = sig.rfc9700_matrix();
    let fails = matrix
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|r| r.get("status") == Some(&json!("fail")))
                .count()
        })
        .unwrap_or(0);
    let passes = matrix
        .as_array()
        .map(|a| a.len().saturating_sub(fails))
        .unwrap_or(0);
    let mut f = id_finding(
        &format!("RFC 9700 OAuth security control matrix ({passes}/{} pass)", passes + fails),
        if fails >= 4 {
            "high"
        } else if fails >= 2 {
            "medium"
        } else {
            "info"
        },
        T_APP_TOKEN,
        &format!(
            "Mapped {passes} passing and {fails} failing controls against RFC 9700 (OAuth 2.0 Security Best Current Practice) from live metadata and probe evidence.",
            passes = passes,
            fails = fails,
        ),
        target,
        0.95,
        Evidence::new().with("controls", matrix.clone()),
        "control_matrix",
        &["RFC9700"],
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("rfc9700_matrix".to_string(), matrix);
    }
    f
}

fn build_remediation_playbook(target: &str, sig: &IdentitySignals) -> Value {
    let mut actions: Vec<Value> = Vec::new();
    if sig.open_redirect_uri {
        actions.push(json!({
            "priority": "P0",
            "control": "redirect_uri validation",
            "action": "Enforce exact, pre-registered redirect_uri matching on every client; block open redirects and wildcard hosts.",
            "standards": "RFC9700-2.1",
        }));
    }
    if sig.implicit_flow {
        actions.push(json!({
            "priority": "P0",
            "control": "Authorization flows",
            "action": "Disable implicit flow and response_type=token; require authorization code + PKCE (S256) for all user-facing clients.",
            "standards": "RFC9700-2.1.2 / OAuth 2.1",
        }));
    }
    if sig.alg_none || sig.symmetric_alg || sig.weak_jwks_key {
        actions.push(json!({
            "priority": "P0",
            "control": "Token signing",
            "action": "Reject alg:none; use RS256/ES256+ with ≥2048-bit RSA keys; rotate JWKS with kid; disable HS* for OIDC ID tokens.",
            "standards": "RFC9700-4 / JWT-BCP",
        }));
    }
    if sig.ropc_grant || sig.ropc_live_accepts {
        actions.push(json!({
            "priority": "P0",
            "control": "ROPC removal",
            "action": "Disable resource-owner password credentials grant; block grant_type=password at the token endpoint.",
            "standards": "RFC9700-2.4",
        }));
    }
    if sig.token_issued_without_auth {
        actions.push(json!({
            "priority": "P0",
            "control": "Client authentication",
            "action": "Require client_secret, private_key_jwt, or mTLS for confidential flows; never mint bearer tokens from client_id alone.",
            "standards": "RFC9700-2.5",
        }));
    }
    if sig.pkce_not_advertised || sig.pkce_plain_only || sig.pkce_not_enforced_live {
        actions.push(json!({
            "priority": "P1",
            "control": "PKCE",
            "action": "Advertise and enforce PKCE with S256 for all authorization-code clients (including public/mobile).",
            "standards": "RFC7636 / RFC9700-2.1.1",
        }));
    }
    if sig.dcr_open {
        actions.push(json!({
            "priority": "P0",
            "control": "Dynamic Client Registration",
            "action": "Disable open DCR or require initial access tokens / admin approval for every new OAuth client.",
            "standards": "RFC7591 / RFC9700-2.3",
        }));
    }
    if sig.userinfo_anonymous {
        actions.push(json!({
            "priority": "P0",
            "control": "UserInfo",
            "action": "Require valid Bearer access tokens on UserInfo; return 401 for unauthenticated requests.",
            "standards": "OIDC-Core-5.3",
        }));
    }
    if sig.par_missing || sig.dpop_missing {
        actions.push(json!({
            "priority": "P1",
            "control": "Modern hardening",
            "action": "Enable PAR (RFC 9126) for sensitive clients and adopt DPoP (RFC 9449) for sender-constrained tokens.",
            "standards": "RFC9126 / RFC9449",
        }));
    }
    if sig.subdomain_takeover_hits > 0 {
        actions.push(json!({
            "priority": "P0",
            "control": "Subdomain lifecycle",
            "action": "Remove dangling DNS CNAMEs for auth/login/sso hosts; monitor identity subdomains for takeover signatures.",
            "standards": "RFC9700-2.2",
        }));
    }
    id_finding(
        &format!("Identity remediation playbook ({} prioritized actions)", actions.len()),
        "info",
        T_APP_TOKEN,
        "Ordered remediation sequence synthesized from observed OAuth/OIDC posture gaps — execute P0 items before lower tiers to collapse account-takeover blast radius.",
        target,
        1.0,
        Evidence::new()
            .with("actions", json!(actions))
            .with("posture_radar", sig.radar()),
        "remediation_playbook",
        &["RFC9700", "OWASP-OAuth"],
    )
}

// ─────────────────────────────────────────────────────────────────────────────────
// Layer 4 — Live authorization-endpoint behavior probing.
// ─────────────────────────────────────────────────────────────────────────────────

fn nonce_token() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("wzm{n:x}")
}

async fn probe_authorization_endpoint(
    cfg: &ArsenalConfig,
    base: &str,
    target: &str,
    sig: &mut IdentitySignals,
    findings: &mut Vec<Value>,
) {
    let client = make_no_redirect_client();

    // Resolve the authorization endpoint (discovery → operator override → common-path probe).
    let mut endpoint = sig.authorization_endpoint.clone();
    if endpoint.is_none() {
        if let Some(e) = cfg.string("authorization_endpoint") {
            endpoint = Some(e);
        }
    }
    if endpoint.is_none() {
        for p in COMMON_AUTH_PATHS {
            let url = format!("{base}{p}");
            if let Ok(resp) = client.get(&url).send().await {
                let s = resp.status().as_u16();
                if s != 404 && s != 0 {
                    endpoint = Some(url);
                    break;
                }
            }
        }
    }
    let Some(endpoint) = endpoint else {
        return;
    };
    sig.authorization_endpoint = Some(endpoint.clone());

    let client_id = cfg.string_or("client_id", "weissman-probe-client");
    let probe_redirect = cfg.string_or(
        "probe_redirect_uri",
        "https://oauth-validate.weissman.invalid/callback",
    );
    let probe_host = host_of(&probe_redirect).unwrap_or_default();
    let scope = cfg.string_or("probe_scope", "openid");
    let client_id_is_real = cfg.string("client_id").is_some();

    let sep = if endpoint.contains('?') { '&' } else { '?' };

    // Probe 1 — redirect_uri validation: does the server bounce to an arbitrary external URI?
    {
        let state = nonce_token();
        let nonce = nonce_token();
        let url = format!(
            "{endpoint}{sep}client_id={cid}&redirect_uri={ru}&response_type=code&scope={sc}&state={st}&nonce={no}",
            cid = urlencoding::encode(&client_id),
            ru = urlencoding::encode(&probe_redirect),
            sc = urlencoding::encode(&scope),
            st = state,
            no = nonce,
        );
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let redirected_to_attacker = (301..=308).contains(&status)
                && !probe_host.is_empty()
                && host_of(&location).as_deref() == Some(probe_host.as_str());
            if redirected_to_attacker {
                sig.open_redirect_uri = true;
                // Confidence is higher when a real client_id was provided (rules out generic accept).
                let conf = if client_id_is_real { 0.9 } else { 0.6 };
                findings.push(id_finding(
                    "Authorization endpoint accepts arbitrary redirect_uri (open redirect)",
                    "critical",
                    T_STEAL_TOKEN,
                    &format!("The authorization endpoint redirected to the attacker-controlled `redirect_uri` ({probe_redirect}) with HTTP {status}. Combined with the code/implicit flow this enables authorization-code / token exfiltration and account takeover. Enforce exact, pre-registered redirect_uri matching.{}", if client_id_is_real { "" } else { " (Probed with a placeholder client_id — confirm with a valid client_id.)" }),
                    target,
                    conf,
                    Evidence::new().with("authorization_endpoint", endpoint.clone()).with("probe_redirect_uri", probe_redirect.clone()).with("location", location.clone()).with("http_status", status).check("redirected_to_external_uri", true, "Location host matches attacker redirect_uri"),
                    "redirect_uri_validation",
                    &["RFC9700-2.1", "RFC6749-3.1.2"],
                ));
            } else if (301..=308).contains(&status) && !location.is_empty() {
                // Server bounced somewhere else (likely login/consent or an error) — validated behavior.
                findings.push(id_finding(
                    "Authorization endpoint reachable and validating redirect_uri",
                    "info",
                    T_APP_TOKEN,
                    &format!("The authorization endpoint at {endpoint} responded ({status}) without honoring the attacker redirect_uri — redirect validation appears active. Verified live."),
                    target,
                    0.55,
                    Evidence::new().with("authorization_endpoint", endpoint.clone()).with("http_status", status).check("honored_attacker_redirect", false, "Did not redirect to external URI"),
                    "redirect_uri_validation",
                    &[],
                ));
            }
        }
    }

    // Probe 2 — implicit flow live confirmation (response_type=token).
    if cfg.bool_or("probe_implicit", true) {
        let url = format!(
            "{endpoint}{sep}client_id={cid}&redirect_uri={ru}&response_type=token&scope={sc}&state={st}",
            cid = urlencoding::encode(&client_id),
            ru = urlencoding::encode(&probe_redirect),
            sc = urlencoding::encode(&scope),
            st = nonce_token(),
        );
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            // An error explicitly naming unsupported_response_type means implicit is blocked (good).
            let blocked = location.contains("unsupported_response_type")
                || location.contains("error=invalid_request");
            if (301..=308).contains(&status)
                && !blocked
                && !location.is_empty()
                && !sig.implicit_flow
            {
                sig.implicit_flow = true;
                findings.push(id_finding(
                    "Implicit flow accepted live (response_type=token)",
                    "high",
                    T_STEAL_COOKIE,
                    &format!("The authorization endpoint processed `response_type=token` (HTTP {status}) rather than rejecting it. Implicit flow returns tokens in the URL fragment and must be disabled."),
                    target,
                    0.7,
                    Evidence::new().with("authorization_endpoint", endpoint.clone()).with("http_status", status).check("implicit_accepted_live", true, "response_type=token not rejected"),
                    "insecure_flow",
                    &["RFC9700-2.1.2"],
                ));
            }
        }
    }

    // Probe 3 — PKCE enforcement: authorization code request without code_challenge.
    if cfg.bool_or("probe_pkce", true) {
        let url = format!(
            "{endpoint}{sep}client_id={cid}&redirect_uri={ru}&response_type=code&scope={sc}&state={st}",
            cid = urlencoding::encode(&client_id),
            ru = urlencoding::encode(&probe_redirect),
            sc = urlencoding::encode(&scope),
            st = nonce_token(),
        );
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let pkce_required_error = location.contains("code_challenge")
                || location.contains("invalid_request")
                || location.contains("PKCE");
            let code_leaked = (301..=308).contains(&status)
                && location.contains("code=")
                && !location.contains("error=");
            if code_leaked {
                sig.pkce_not_enforced_live = true;
                findings.push(id_finding(
                    "Authorization code issued without PKCE (live probe)",
                    "high",
                    T_STEAL_TOKEN,
                    &format!("The authorization endpoint returned a redirect containing `code=` (HTTP {status}) for a request with no `code_challenge`. Intercepted codes can be redeemed without proof-of-possession. Enforce PKCE S256 for all clients."),
                    target,
                    0.75,
                    Evidence::new()
                        .with("authorization_endpoint", endpoint.clone())
                        .with("location", location.clone())
                        .check("code_without_pkce", true, "Authorization code in redirect without code_challenge"),
                    "missing_pkce",
                    &["RFC7636", "RFC9700-2.1.1"],
                ));
            } else if !pkce_required_error && (301..=308).contains(&status) && !location.is_empty()
            {
                findings.push(id_finding(
                    "Authorization endpoint processed code flow without explicit PKCE error",
                    "low",
                    T_STEAL_TOKEN,
                    &format!("Authorization request without `code_challenge` was not rejected with an explicit PKCE error (HTTP {status}). Confirm PKCE is enforced server-side for public clients."),
                    target,
                    0.55,
                    Evidence::new().with("authorization_endpoint", endpoint).with("http_status", status),
                    "missing_pkce",
                    &["RFC7636"],
                ));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────
// Layer 5 — Attack-path synthesis + posture score.
// ─────────────────────────────────────────────────────────────────────────────────

fn synthesize_attack_paths(target: &str, sig: &IdentitySignals, findings: &mut Vec<Value>) {
    // Path 1 — token exfiltration via redirect abuse + token-bearing flow.
    if sig.open_redirect_uri && (sig.implicit_flow || sig.pkce_not_advertised) {
        let steps = [
            "Authorization endpoint accepts an attacker-controlled redirect_uri",
            "Victim is sent a crafted authorization link (phishing / watering hole)",
            if sig.implicit_flow {
                "Implicit flow returns the access/ID token in the URL fragment to the attacker host"
            } else {
                "Authorization code is delivered to the attacker host and exchanged (no PKCE binding)"
            },
            "Attacker replays the token/code → full account takeover",
        ];
        findings.push(attack_path_finding(
            "Attack path: redirect_uri abuse → token/code exfiltration → account takeover",
            "critical",
            T_STEAL_TOKEN,
            "Lax redirect_uri validation combined with a token-bearing or unprotected flow forms a complete account-takeover path. Enforce exact redirect_uri matching and authorization code + PKCE.",
            target,
            0.85,
            &steps,
            Evidence::new()
                .check("open_redirect_uri", sig.open_redirect_uri, "Arbitrary redirect_uri accepted")
                .check("token_bearing_or_no_pkce", true, "Implicit flow and/or missing PKCE"),
        ));
    }

    // Path 2 — ID-token forgery via weak/none signing.
    if sig.alg_none || sig.symmetric_alg || sig.weak_jwks_key {
        let steps = [
            "Provider advertises a forgeable token-signing posture (alg:none / symmetric / weak key)",
            "Attacker mints or alters an ID/access token offline",
            "Relying parties accept the forged token as a valid identity assertion",
            "Attacker impersonates any user, including administrators",
        ];
        let sev = if sig.alg_none { "critical" } else { "high" };
        findings.push(attack_path_finding(
            "Attack path: weak token signing → ID-token forgery → impersonation",
            sev,
            T_FORGE_OIDC,
            "A weak or absent signature posture lets an attacker forge identity tokens that downstream applications trust, yielding arbitrary user impersonation. Require asymmetric signing (RS256/ES256+) with ≥ 2048-bit keys and reject `none`.",
            target,
            if sig.alg_none { 0.85 } else { 0.72 },
            &steps,
            Evidence::new()
                .check("alg_none", sig.alg_none, "alg:none advertised")
                .check("symmetric_alg", sig.symmetric_alg, "HS* signing advertised")
                .check("weak_jwks_key", sig.weak_jwks_key, "Undersized RSA key in JWKS"),
        ));
    }

    // Path 3 — public client + no PKCE → authorization-code interception.
    if sig.public_clients_allowed && (sig.pkce_not_advertised || sig.pkce_plain_only) {
        let steps = [
            "Public (secret-less) clients are permitted at the token endpoint",
            "PKCE is not enforced (or only `plain`)",
            "Attacker intercepts the authorization code (malicious app, network, logs)",
            "Code is redeemed for tokens without proof-of-possession",
        ];
        findings.push(attack_path_finding(
            "Attack path: public client without PKCE → authorization-code interception",
            "high",
            T_STEAL_TOKEN,
            "Allowing public clients while not enforcing PKCE (S256) exposes the authorization code to interception and redemption by an attacker. Require S256 PKCE for every client.",
            target,
            0.7,
            &steps,
            Evidence::new()
                .check("public_clients_allowed", sig.public_clients_allowed, "auth method none advertised")
                .check("pkce_weak_or_absent", true, "PKCE missing or plain-only"),
        ));
    }

    // Path 4 — unauthenticated client_credentials token minting.
    if sig.token_issued_without_auth {
        let steps = [
            "Token endpoint accepts client_credentials with only a public client_id",
            "Attacker registers or discovers a public client_id",
            "Attacker obtains access tokens without a client secret or mTLS binding",
            "Tokens are replayed against resource servers → unauthorized API access",
        ];
        findings.push(attack_path_finding(
            "Attack path: unauthenticated client_credentials → token minting → API abuse",
            "critical",
            T_STEAL_TOKEN,
            "When the token endpoint mints bearer tokens without client authentication, any attacker with a valid public client_id can obtain API access. Require confidential clients, mTLS, or DPoP-bound tokens.",
            target,
            0.82,
            &steps,
            Evidence::new().check("token_issued_without_auth", true, "client_credentials returned access_token without secret"),
        ));
    }

    // Path 5 — open DCR → rogue client → phishing consent.
    if sig.dcr_open {
        let steps = [
            "Attacker registers a malicious OAuth client via open Dynamic Client Registration",
            "Rogue client uses attacker-controlled redirect_uri and branding",
            "Victim completes legitimate-looking consent/login at the real IdP",
            "Authorization code/token delivered to attacker → account takeover",
        ];
        findings.push(attack_path_finding(
            "Attack path: open DCR → rogue OAuth client → federated phishing",
            "critical",
            T_STEAL_TOKEN,
            "Unauthenticated Dynamic Client Registration lets attackers mint OAuth clients that inherit user trust in the IdP consent UI. Disable open DCR or gate it with admin approval.",
            target,
            0.86,
            &steps,
            Evidence::new().check("open_dcr", true, "Client registered without credentials"),
        ));
    }

    // Path 6 — ROPC → credential stuffing on token endpoint.
    if sig.ropc_live_accepts || sig.ropc_grant {
        let steps = [
            "Resource-owner password credentials grant is enabled",
            "Attacker runs credential-stuffing/spray directly against the token endpoint (no browser MFA)",
            "Valid username/password pairs yield access/refresh tokens",
            "Tokens replayed to cloud APIs and SaaS integrations",
        ];
        findings.push(attack_path_finding(
            "Attack path: ROPC grant → token-endpoint credential stuffing → API takeover",
            "high",
            T_APP_TOKEN,
            "ROPC removes browser-based MFA and ships passwords to clients. Disable password grant and enforce authorization code + PKCE with phishing-resistant MFA.",
            target,
            0.78,
            &steps,
            Evidence::new()
                .check("ropc_advertised", sig.ropc_grant, "password grant in metadata")
                .check("ropc_live", sig.ropc_live_accepts, "ROPC processed at token endpoint"),
        ));
    }

    // Path 7 — anonymous UserInfo → user enumeration / profiling.
    if sig.userinfo_anonymous {
        let steps = [
            "UserInfo endpoint returns OIDC claims without a Bearer token",
            "Attacker harvests sub/email/preferred_username at scale",
            "Identifiers fuel targeted phishing and cross-app correlation",
            "Combined with weak session hygiene → impersonation and fraud",
        ];
        findings.push(attack_path_finding(
            "Attack path: anonymous UserInfo → identity harvesting → targeted takeover",
            "high",
            T_STEAL_TOKEN,
            "Unauthenticated UserInfo leaks stable user identifiers. Require access tokens and rate-limit per client.",
            target,
            0.8,
            &steps,
            Evidence::new().check("anonymous_userinfo", true, "Profile JSON without auth"),
        ));
    }

    // Path 8 — identity subdomain takeover → forged OAuth metadata.
    if sig.subdomain_takeover_hits > 0 {
        let steps = [
            "Dangling DNS/CNAME on auth/login/sso subdomain",
            "Attacker claims the orphaned SaaS bucket/app and serves OAuth/OIDC metadata",
            "Corporate apps or users trust the subdomain as an IdP surface",
            "Attacker intercepts codes/tokens or phishes via legitimate-looking hostnames",
        ];
        findings.push(attack_path_finding(
            "Attack path: identity subdomain takeover → forged IdP → federated compromise",
            "critical",
            T_STEAL_TOKEN,
            "Dangling identity subdomains let attackers publish OAuth metadata under your brand. Remove orphaned DNS and monitor auth subdomains continuously.",
            target,
            0.9,
            &steps,
            Evidence::new().with("takeover_hits", sig.subdomain_takeover_hits),
        ));
    }
}

fn severity_weight(sev: &str) -> u32 {
    match sev {
        "critical" => 20,
        "high" => 10,
        "medium" => 4,
        "low" => 1,
        _ => 0,
    }
}

fn posture_summary(target: &str, findings: &[Value], sig: &IdentitySignals) -> Value {
    let mut counts = std::collections::BTreeMap::<String, u32>::new();
    let mut penalty: u32 = 0;
    for f in findings {
        let sev = f
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_string();
        *counts.entry(sev.clone()).or_insert(0) += 1;
        penalty = penalty.saturating_add(severity_weight(&sev));
    }
    let score = 100i32.saturating_sub(i32::try_from(penalty.min(100)).unwrap_or(100));
    let grade = match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    };
    let sev = if score < 60 {
        "high"
    } else if score < 85 {
        "medium"
    } else {
        "info"
    };
    let ev = Evidence::new()
        .with("score", score)
        .with("grade", grade)
        .with("issuer", sig.issuer.clone().unwrap_or_default())
        .with(
            "provider",
            sig.provider.clone().unwrap_or_else(|| "unknown".into()),
        )
        .with("counts", json!(counts))
        .with("posture_radar", sig.radar())
        .check(
            "discovery_succeeded",
            sig.discovered,
            if sig.discovered {
                "OIDC/OAuth metadata analyzed"
            } else {
                "No discovery document — endpoint probing only"
            },
        );
    let mut f = id_finding(
        &format!("OAuth/OIDC identity posture: {score}/100 (grade {grade})"),
        sev,
        T_APP_TOKEN,
        &format!(
            "Identity provider{}: {} critical / {} high / {} medium / {} low findings. Six-axis posture radar emitted. Score is a weighted identity-security posture index (100 = no observed weakness).",
            sig.provider.as_ref().map(|p| format!(" [{p}]")).unwrap_or_default(),
            counts.get("critical").copied().unwrap_or(0),
            counts.get("high").copied().unwrap_or(0),
            counts.get("medium").copied().unwrap_or(0),
            counts.get("low").copied().unwrap_or(0),
        ),
        target,
        0.99,
        ev,
        "posture_summary",
        &["RFC9700"],
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("posture_radar".to_string(), sig.radar());
    }
    f
}

// ─────────────────────────────────────────────────────────────────────────────────
// Entry points.
// ─────────────────────────────────────────────────────────────────────────────────

/// Run the OAuth 2.0 / OIDC / SSO Identity Security engine.
pub async fn run_oauth_oidc_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("oauth_oidc: target required (identity provider host/issuer)");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let base = base_url(target);
    let client = make_client();
    let mut findings: Vec<Value> = Vec::new();
    let mut sig = IdentitySignals::default();

    // Layer 1+2 — discovery + metadata posture.
    if cfg.bool_or("check_discovery", true) {
        if let Some((discovery_url, doc)) = discover_metadata(&client, &base, &cfg).await {
            sig.discovered = true;
            analyze_metadata(&doc, &discovery_url, target, &mut sig, &mut findings);
            // Layer 3 — JWKS crypto analysis.
            if cfg.bool_or("check_jwks", true) {
                analyze_jwks(&client, &doc, target, &mut sig, &mut findings).await;
            }
            if cfg.bool_or("probe_token_endpoint", true) {
                probe_token_and_par_endpoints(&cfg, target, &mut sig, &mut findings).await;
            }
            if cfg.bool_or("probe_extensions", true) {
                probe_oidc_extension_endpoints(&cfg, target, &mut sig, &mut findings).await;
                probe_device_authorization_flow(&cfg, target, &mut sig, &mut findings).await;
                probe_ropc_oracle(&cfg, target, &mut sig, &mut findings).await;
            }
            if cfg.bool_or("probe_cors", true) {
                let jwks_uri = sig.jwks_uri.clone();
                probe_metadata_cors(
                    &discovery_url,
                    jwks_uri.as_deref(),
                    target,
                    &mut sig,
                    &mut findings,
                )
                .await;
            }
        }
    }

    if cfg.bool_or("probe_federation", true) {
        probe_saml_federation_surface(&base, target, &mut sig, &mut findings).await;
    }

    let host = sig
        .issuer
        .as_deref()
        .and_then(host_of)
        .or_else(|| host_of(&base))
        .unwrap_or_default();
    if cfg.bool_or("probe_subdomains", true) && !host.is_empty() {
        probe_subdomain_identity_surface(&cfg, &host, target, &mut sig, &mut findings).await;
    }

    // Layer 4 — live authorization-endpoint behavior.
    if cfg.bool_or("probe_authorization", true) {
        probe_authorization_endpoint(&cfg, &base, target, &mut sig, &mut findings).await;
    }

    if cfg.bool_or("probe_cross_protocol_chain", true) {
        probe_ws_intelligence_cross_protocol(&ctx.job_params, target, &sig, &mut findings).await;
    }

    // Fallback: surface raw OAuth endpoints when nothing else matched, so an operator still
    // gets an asset-inventory signal (deeper analysis needs an issuer/discovery doc).
    if findings.is_empty() {
        let probe = make_no_redirect_client();
        for p in COMMON_AUTH_PATHS {
            let url = format!("{base}{p}");
            if let Ok(resp) = probe.get(&url).send().await {
                let status = resp.status().as_u16();
                if status != 404 && status != 0 {
                    findings.push(id_finding(
                        "OAuth endpoint detected",
                        "info",
                        T_APP_TOKEN,
                        &format!("An OAuth endpoint responded at {url} (HTTP {status}). No discovery document was found; supply an `issuer` or `client_id` for deep posture analysis."),
                        target,
                        0.6,
                        Evidence::new().with("url", url.clone()).with("http_status", status).check("endpoint_reachable", true, "Non-404 response"),
                        "asset_inventory",
                        &[],
                    ));
                    break;
                }
            }
        }
    }

    // Layer 5 — attack-path synthesis.
    if cfg.bool_or("attack_paths", true) {
        synthesize_attack_paths(target, &sig, &mut findings);
        supreme::extend_attack_paths(target, &sig, &mut findings);
    }

    supreme::emit_toxic_headline(target, &sig, &mut findings);
    supreme::emit_remediation_roadmap(target, &sig, &mut findings);
    if cfg.bool_or("emit_agent_guidance", true) {
        supreme::emit_agent_guidance(target, &mut findings);
    }

    let category_scores = supreme::finalize_category_scores(&sig);
    let (graph_nodes, graph_edges) = supreme::build_security_graph(target, &sig, &host);

    if sig.discovered && cfg.bool_or("check_control_matrix", true) {
        findings.push(build_rfc9700_matrix_finding(target, &sig));
    }

    if cfg.bool_or("check_remediation_playbook", true) && sig.has_gaps() {
        findings.push(build_remediation_playbook(target, &sig));
    }

    // Always close with the posture summary so the GUI can render the identity risk gauge.
    if sig.discovered || !findings.is_empty() {
        let mut summary = posture_summary(target, &findings, &sig);
        if let Some(obj) = summary.as_object_mut() {
            if let Some(ev) = obj.get_mut("evidence").and_then(Value::as_object_mut) {
                ev.insert("category_scores".to_string(), category_scores.to_json());
            }
        }
        findings.push(summary);
    }

    let crit = findings
        .iter()
        .filter(|f| f.get("severity").and_then(Value::as_str) == Some("critical"))
        .count();
    let toxic = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) == Some("toxic_combination"))
        .count();
    let path_count = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) == Some("attack_path"))
        .count();
    let message = if findings.is_empty() {
        "oauth_oidc: no OAuth/OIDC surface observed".to_string()
    } else {
        format!(
            "oauth_oidc: {} finding(s){}{}{}{} ({} critical)",
            findings.len(),
            sig.provider
                .as_ref()
                .map(|p| format!(", provider {p}"))
                .unwrap_or_default(),
            if sig.discovered {
                ", metadata analyzed"
            } else {
                ""
            },
            if toxic > 0 {
                format!(", {toxic} toxic combo(s)")
            } else {
                String::new()
            },
            if path_count > 0 {
                format!(", {path_count} attack path(s)")
            } else {
                String::new()
            },
            crit,
        )
    };
    EngineResult::ok_with_graph(findings, message, graph_nodes, graph_edges)
}

/// CLI wrapper.
pub async fn run_oauth_oidc(target: &str) {
    print_result(run_oauth_oidc_result(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_bits_estimate_2048() {
        // 256 bytes → 2048 bits. Build a base64url string of 256 0x01 bytes.
        let raw = vec![1u8; 256];
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
        assert_eq!(estimate_rsa_bits(&b64), Some(2048));
    }

    #[test]
    fn rsa_bits_estimate_strips_leading_zero() {
        let mut raw = vec![0u8; 1];
        raw.extend(vec![1u8; 128]); // 0x00 + 128 bytes → 1024 bits
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
        assert_eq!(estimate_rsa_bits(&b64), Some(1024));
    }

    #[test]
    fn signing_alg_classification() {
        assert_eq!(classify_signing_alg("none").unwrap().0, "critical");
        assert_eq!(classify_signing_alg("HS256").unwrap().0, "high");
        assert!(classify_signing_alg("RS256").is_none());
        assert!(classify_signing_alg("ES256").is_none());
    }

    #[test]
    fn provider_fingerprint_detects_majors() {
        assert_eq!(
            fingerprint_provider("https://example.okta.com", "example.okta.com"),
            Some("Okta")
        );
        assert_eq!(
            fingerprint_provider(
                "https://login.microsoftonline.com/tenant/v2.0",
                "login.microsoftonline.com"
            ),
            Some("Microsoft Entra ID (Azure AD)")
        );
        assert!(fingerprint_provider("https://idp.acme.com", "idp.acme.com").is_none());
    }

    #[test]
    fn host_extraction() {
        assert_eq!(
            host_of("https://Login.Example.com/cb").as_deref(),
            Some("login.example.com")
        );
        assert_eq!(host_of("not a url"), None);
    }

    #[test]
    fn posture_summary_scores_and_grades() {
        let sig = IdentitySignals::default();
        let findings = vec![id_finding(
            "x",
            "critical",
            T_STEAL_TOKEN,
            "d",
            "t",
            0.9,
            Evidence::new(),
            "insecure_flow",
            &[],
        )];
        let s = posture_summary("t", &findings, &sig);
        let score = s["evidence"]["score"].as_i64().unwrap();
        assert!(score <= 80);
        assert_eq!(s["category"], json!("posture_summary"));
    }
}
