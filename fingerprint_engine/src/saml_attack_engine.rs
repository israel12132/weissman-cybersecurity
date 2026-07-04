//! SAML & Enterprise-SSO Federation Security Engine — agentless, evidence-first.
//!
//! Identity is the modern perimeter, and SAML/WS-Fed is the protocol that still underpins the
//! single-sign-on trust of most enterprises (ADFS, Azure AD/Entra, Okta, Ping, OneLogin, Shibboleth,
//! SimpleSAMLphp, Keycloak). This engine assesses that federation surface the way the best identity-
//! security platforms do — comprehensively and from the outside — and goes a step further by
//! correlating the observed weaknesses into the named, real-world attack chains that have breached
//! Fortune-500s and governments (Golden SAML / UNC2452, XML Signature Wrapping, SAML replay).
//!
//! Honesty contract (shared with the rest of the arsenal): **every finding is backed by a real
//! observation** — a live HTTP response, a parsed metadata document, or an X.509 certificate decoded
//! from that metadata. Nothing is simulated. The engine performs only read-only, non-destructive
//! operations:
//!   * SAML/WS-Fed endpoint discovery (metadata, SSO, ACS, SLO, ADFS, Shibboleth, …);
//!   * IdP/SP product fingerprinting (ADFS, Entra, Okta, Ping, OneLogin, Shibboleth, SimpleSAMLphp,
//!     Keycloak, Auth0);
//!   * deep `EntityDescriptor` metadata analysis — X.509 signing-certificate hygiene (expiry, key
//!     size, signature algorithm), signing/encryption requirement flags (`WantAssertionsSigned`,
//!     `AuthnRequestsSigned`, `WantAssertionsEncrypted`), SHA-1 usage, and binding inventory;
//!   * RelayState open-redirect probing (benign canary) and verbose-parser-error disclosure;
//!   * Wiz-style attack-path synthesis + a quantified 0–100 federation-hardening posture score.
//!   * **Supreme synthesis** — toxic combinations, 8-domain category scores, remediation roadmap,
//!     security graph (`ok_with_graph`), XSW/SLO/WS-Fed probes, honest agent guidance.
//!
//! Actually *forging* or *replaying* assertions is an intrusive, authorized action that needs a valid
//! signed SAMLResponse / session — it is surfaced as honest guidance, never faked.
//!
//! Every knob (endpoint paths, explicit metadata URL, per-check toggles, RelayState canary, cert
//! thresholds, intensity, caps, timeout, concurrency) is GUI-driven via [`ArsenalConfig`]
//! (`POST /api/command-center/scan` → `EngineRunContext::job_params`).
//!
//! MITRE ATT&CK: T1606.002 (Forge Web Credentials: SAML Tokens / Golden SAML), T1556 (Modify
//! Authentication Process), T1550.001 (Application Access Token), T1199 (Trusted Relationship).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, header_value, http_get, HttpProbe};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::Duration;

const ENGINE_ID: &str = "saml_attack";

const T_FORGE_SAML: &str = "T1606.002"; // Forge Web Credentials: SAML Tokens (Golden SAML)
const T_MODIFY_AUTH: &str = "T1556"; // Modify Authentication Process
const T_APP_TOKEN: &str = "T1550.001"; // Application Access Token
const T_TRUST: &str = "T1199"; // Trusted Relationship

#[path = "saml_attack_supreme.rs"]
mod supreme;

const DEFAULT_METADATA_PATHS: &[&str] = &[
    "/saml/metadata",
    "/saml2/metadata",
    "/saml2/idp/metadata",
    "/saml/idp/metadata",
    "/sso/saml/metadata",
    "/auth/saml/metadata",
    "/saml/sp/metadata",
    "/metadata.xml",
    "/sp/metadata",
    "/simplesaml/saml2/idp/metadata.php",
    "/federationmetadata/2007-06/federationmetadata.xml",
    "/adfs/ls/idpinitiatedsignon.aspx",
    "/Shibboleth.sso/Metadata",
    "/realms/master/protocol/saml/descriptor",
];

const DEFAULT_SSO_PATHS: &[&str] = &[
    "/saml/login",
    "/saml2/login",
    "/saml/sso",
    "/saml2/sso",
    "/sso/saml",
    "/auth/saml",
    "/saml/acs",
    "/saml2/acs",
    "/saml/consume",
    "/sso/acs",
    "/login/saml",
    "/sso",
    "/adfs/ls/",
    "/Shibboleth.sso/SAML2/POST",
    "/simplesaml/saml2/sp/AssertionConsumerService.php",
];

// ── Product fingerprints (token, product, version-hint-key) ──────────────────────
const IDP_FINGERPRINTS: &[(&str, &str)] = &[
    ("microsoft.identityserver", "Microsoft ADFS"),
    ("/adfs/ls", "Microsoft ADFS"),
    ("login.microsoftonline.com", "Microsoft Entra ID (Azure AD)"),
    ("sts.windows.net", "Microsoft Entra ID (Azure AD)"),
    ("shibboleth", "Shibboleth IdP"),
    ("simplesamlphp", "SimpleSAMLphp"),
    ("okta.com", "Okta"),
    ("onelogin.com", "OneLogin"),
    ("pingfederate", "Ping Identity (PingFederate)"),
    ("pingone", "Ping Identity (PingOne)"),
    ("keycloak", "Keycloak"),
    ("auth0.com", "Auth0"),
    ("gluu", "Gluu"),
    ("wso2", "WSO2 Identity Server"),
];

// ── Accumulated, observed signals (drive attack-path synthesis + score) ──────────
#[derive(Default, Debug)]
struct Signals {
    endpoints: Vec<String>,
    idp_vendor: Option<String>,
    idp_metadata: bool,
    sp_metadata: bool,
    signing_certs: usize,
    weak_sha1: bool,
    unsigned_assertions: bool,
    missing_encryption: bool,
    expired_cert: bool,
    weak_key_cert: bool,
    open_redirect: Option<String>,
    error_disclosure: bool,
    entity_ids: Vec<String>,
    metadata_expired: bool,
    authn_requests_unsigned: bool,
    slo_exposed: bool,
    slo_urls: Vec<String>,
    http_redirect_binding: bool,
    http_acs_urls: Vec<String>,
    ws_fed_exposed: bool,
    xsw_preconditions: usize,
}

impl Signals {
    fn score(&self) -> u32 {
        let mut s: i32 = 100;
        if self.idp_metadata && self.signing_certs > 0 {
            s -= 14; // Golden-SAML precondition exposed
        }
        if self.unsigned_assertions {
            s -= 22;
        }
        if self.weak_sha1 {
            s -= 16;
        }
        if self.expired_cert {
            s -= 10;
        }
        if self.weak_key_cert {
            s -= 12;
        }
        if self.open_redirect.is_some() {
            s -= 14;
        }
        if self.missing_encryption {
            s -= 6;
        }
        if self.error_disclosure {
            s -= 6;
        }
        s.clamp(0, 100) as u32
    }

    fn grade(&self) -> &'static str {
        match self.score() {
            90..=100 => "A",
            75..=89 => "B",
            55..=74 => "C",
            35..=54 => "D",
            _ => "F",
        }
    }

    fn has_federation(&self) -> bool {
        !self.endpoints.is_empty() || self.idp_metadata || self.sp_metadata
    }
}

// ── X.509 facts decoded from metadata (real openssl parse) ───────────────────────
#[derive(Debug, Clone)]
struct CertFacts {
    subject: String,
    issuer: String,
    key_bits: u32,
    sig_alg: String,
    days_until_expiry: i64,
    expired: bool,
    self_signed: bool,
}

#[derive(Debug, Default)]
struct MetadataFacts {
    is_idp: bool,
    is_sp: bool,
    entity_id: Option<String>,
    valid_until: Option<String>,
    want_assertions_signed: Option<bool>,
    authn_requests_signed: Option<bool>,
    want_assertions_encrypted: Option<bool>,
    sha1: bool,
    bindings: Vec<String>,
    acs_urls: Vec<String>,
    slo_urls: Vec<String>,
    http_acs_urls: Vec<String>,
    certs: Vec<CertFacts>,
}

fn pem_wrap(b64: &str) -> String {
    let cleaned: String = b64.split_whitespace().collect();
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + 64).min(bytes.len());
        out.push_str(&cleaned[i..end]);
        out.push('\n');
        i = end;
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Decode a base64 `X509Certificate` from metadata into real, openssl-parsed facts.
fn parse_metadata_cert(b64: &str) -> Option<CertFacts> {
    use openssl::x509::{X509NameEntryRef, X509};
    let pem = pem_wrap(b64);
    let cert = X509::from_pem(pem.as_bytes()).ok()?;
    let fmt = |e: &X509NameEntryRef| -> String {
        let key = e.object().nid().short_name().unwrap_or("?");
        let val = e
            .data()
            .as_utf8()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| "?".into());
        format!("{key}={val}")
    };
    let issuer = cert
        .issuer_name()
        .entries()
        .map(fmt)
        .collect::<Vec<_>>()
        .join(", ");
    let subject = cert
        .subject_name()
        .entries()
        .map(fmt)
        .collect::<Vec<_>>()
        .join(", ");
    let self_signed = issuer == subject;
    let not_after = cert.not_after().to_owned();
    let now = openssl::asn1::Asn1Time::days_from_now(0).ok();
    let expired = now.as_ref().is_some_and(|n| not_after <= *n);
    let days_until_expiry = now
        .as_ref()
        .and_then(|n| not_after.diff(n.as_ref()).ok())
        .map(|d| i64::from(d.days))
        .unwrap_or(0);
    let key_bits = cert.public_key().map(|k| k.bits()).unwrap_or(0);
    let sig_alg = cert
        .signature_algorithm()
        .object()
        .nid()
        .short_name()
        .unwrap_or("unknown")
        .to_string();
    Some(CertFacts {
        subject,
        issuer,
        key_bits,
        sig_alg,
        days_until_expiry,
        expired,
        self_signed,
    })
}

fn attr_bool(lx: &str, attr: &str) -> Option<bool> {
    let a = attr.to_ascii_lowercase();
    for q in ['"', '\''] {
        if lx.contains(&format!("{a}={q}true{q}")) {
            return Some(true);
        }
        if lx.contains(&format!("{a}={q}false{q}")) {
            return Some(false);
        }
    }
    None
}

/// Parse a SAML `EntityDescriptor` into structured facts. Pure (string + openssl); unit-tested.
fn analyze_metadata(xml: &str) -> MetadataFacts {
    static CERT_RE: OnceLock<Regex> = OnceLock::new();
    static ENTITY_RE: OnceLock<Regex> = OnceLock::new();
    static ACS_RE: OnceLock<Regex> = OnceLock::new();
    static SLO_RE: OnceLock<Regex> = OnceLock::new();
    static VALID_RE: OnceLock<Regex> = OnceLock::new();
    let cert_re = CERT_RE.get_or_init(|| {
        Regex::new(
            r"(?s)<(?:[A-Za-z0-9]+:)?X509Certificate>(.*?)</(?:[A-Za-z0-9]+:)?X509Certificate>",
        )
        .expect("valid regex")
    });
    let entity_re =
        ENTITY_RE.get_or_init(|| Regex::new(r#"entityID\s*=\s*["']([^"']+)["']"#).expect("re"));
    let acs_re = ACS_RE.get_or_init(|| {
        Regex::new(r#"(?i)AssertionConsumerService[^>]*Location\s*=\s*["']([^"']+)["']"#)
            .expect("re")
    });
    let slo_re = SLO_RE.get_or_init(|| {
        Regex::new(r#"(?i)SingleLogoutService[^>]*Location\s*=\s*["']([^"']+)["']"#).expect("re")
    });
    let valid_re =
        VALID_RE.get_or_init(|| Regex::new(r#"validUntil\s*=\s*["']([^"']+)["']"#).expect("re"));

    let lx = xml.to_ascii_lowercase();
    let mut facts = MetadataFacts {
        is_idp: lx.contains("idpssodescriptor"),
        is_sp: lx.contains("spssodescriptor"),
        sha1: lx.contains("rsa-sha1") || lx.contains("#sha1") || lx.contains("dsa-sha1"),
        want_assertions_signed: attr_bool(&lx, "WantAssertionsSigned"),
        authn_requests_signed: attr_bool(&lx, "AuthnRequestsSigned"),
        want_assertions_encrypted: attr_bool(&lx, "WantAssertionsEncrypted"),
        ..MetadataFacts::default()
    };
    facts.entity_id = entity_re
        .captures(xml)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());
    facts.valid_until = valid_re
        .captures(xml)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());
    for m in acs_re.captures_iter(xml).filter_map(|c| c.get(1)) {
        let u = m.as_str().to_string();
        if u.to_ascii_lowercase().starts_with("http://") && !facts.http_acs_urls.contains(&u) {
            facts.http_acs_urls.push(u.clone());
        }
        if !facts.acs_urls.contains(&u) {
            facts.acs_urls.push(u);
        }
    }
    for m in slo_re.captures_iter(xml).filter_map(|c| c.get(1)) {
        let u = m.as_str().to_string();
        if !facts.slo_urls.contains(&u) {
            facts.slo_urls.push(u);
        }
    }
    for (urn, label) in [
        ("http-post", "HTTP-POST"),
        ("http-redirect", "HTTP-Redirect"),
        ("http-artifact", "HTTP-Artifact"),
        ("paos", "PAOS"),
    ] {
        if lx.contains(&format!("bindings:{urn}")) || lx.contains(&format!("binding-{urn}")) {
            facts.bindings.push(label.to_string());
        }
    }
    for cap in cert_re.captures_iter(xml).filter_map(|c| c.get(1)) {
        if let Some(cf) = parse_metadata_cert(cap.as_str()) {
            facts.certs.push(cf);
        }
    }
    facts
}

fn fingerprint_idp(probe: &HttpProbe) -> Option<&'static str> {
    let mut hay = probe.body.to_ascii_lowercase();
    for (k, v) in &probe.headers {
        hay.push('\n');
        hay.push_str(&k.to_ascii_lowercase());
        hay.push(':');
        hay.push_str(&v.to_ascii_lowercase());
    }
    hay.push('\n');
    hay.push_str(&probe.final_url.to_ascii_lowercase());
    IDP_FINGERPRINTS
        .iter()
        .find(|(tok, _)| hay.contains(tok))
        .map(|(_, label)| *label)
}

fn looks_like_saml(body: &str) -> bool {
    body.contains("EntityDescriptor")
        || body.contains("SAMLRequest")
        || body.contains("SAMLResponse")
        || body.contains("urn:oasis:names:tc:SAML")
        || body.contains("<md:")
}

fn saml_client(timeout_ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.clamp(800, 30_000)))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Weissman-SAML/2.0 (+sso-federation-posture)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn get_many(
    client: &reqwest::Client,
    urls: Vec<String>,
    concurrency: usize,
) -> Vec<(String, HttpProbe)> {
    stream::iter(urls)
        .map(|u| {
            let c = client.clone();
            async move { http_get(&c, &u).await.map(|p| (u, p)) }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await
}

// ── Configuration (GUI-driven via ArsenalConfig / job_params) ────────────────────
struct SamlConfig {
    metadata_url: Option<String>,
    metadata_paths: Vec<String>,
    sso_paths: Vec<String>,
    check_metadata: bool,
    check_relaystate: bool,
    check_error_disclosure: bool,
    check_attack_paths: bool,
    check_xsw_preconditions: bool,
    check_slo_exposure: bool,
    check_ws_federation: bool,
    check_metadata_expiry: bool,
    check_binding_posture: bool,
    emit_agent_guidance: bool,
    relaystate_canary: String,
    cert_expiry_warn_days: i64,
    min_cert_bits: u32,
    timeout_ms: u64,
    concurrency: usize,
    max_paths: usize,
}

impl SamlConfig {
    fn from_arsenal(c: &ArsenalConfig) -> Self {
        let default_max = match c.intensity() {
            Intensity::Light => 12,
            Intensity::Normal => 28,
            Intensity::Aggressive => 64,
        };
        Self {
            metadata_url: c.string("metadata_url"),
            metadata_paths: c.string_list_or("metadata_paths", DEFAULT_METADATA_PATHS),
            sso_paths: c.string_list_or("sso_paths", DEFAULT_SSO_PATHS),
            check_metadata: c.bool_or("check_metadata", true),
            check_relaystate: c.bool_or("check_relaystate", true),
            check_error_disclosure: c.bool_or("check_error_disclosure", true),
            check_attack_paths: c.bool_or("check_attack_paths", true),
            check_xsw_preconditions: c.bool_or("check_xsw_preconditions", true),
            check_slo_exposure: c.bool_or("check_slo_exposure", true),
            check_ws_federation: c.bool_or("check_ws_federation", true),
            check_metadata_expiry: c.bool_or("check_metadata_expiry", true),
            check_binding_posture: c.bool_or("check_binding_posture", true),
            emit_agent_guidance: c.bool_or("emit_agent_guidance", true),
            relaystate_canary: c.string_or(
                "relaystate_canary",
                "https://weissman-canary.example.net/probe",
            ),
            cert_expiry_warn_days: i64::try_from(c.u64_or("cert_expiry_warn_days", 30))
                .unwrap_or(30),
            min_cert_bits: u32::try_from(c.u64_or("min_cert_bits", 2048)).unwrap_or(2048),
            timeout_ms: c.timeout_ms(8000),
            concurrency: c.concurrency(),
            max_paths: c.usize_or("max_paths", default_max).clamp(1, 200),
        }
    }
}

/// Build a SAML/SSO attack-path (toxic-combination) finding from observed federation weaknesses.
fn saml_attack_path(
    title: &str,
    severity: &str,
    mitre: &str,
    target: &str,
    description: &str,
    steps: &[&str],
) -> Value {
    let ev = Evidence::new()
        .with("kind", "attack_path")
        .with("steps", json!(steps))
        .check("correlation", true, format!("{}-step chain", steps.len()));
    let mut v = finding_rich(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        0.82,
        ev,
    );
    if let Some(o) = v.as_object_mut() {
        o.insert("category".to_string(), json!("attack_path"));
        o.insert("attack_path".to_string(), json!(true));
        o.insert("steps".to_string(), json!(steps));
    }
    v
}

/// Back-compat entry (dispatch / advanced_crypto / CLI): runs with default parameters.
pub async fn run_saml_attack_result(target: &str) -> EngineResult {
    run_saml_attack_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_saml_attack(target: &str) {
    print_result(run_saml_attack_result(target).await);
}

/// Parameterised entry — reads every knob from `ctx.job_params` (GUI-driven).
pub async fn run_saml_attack_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = SamlConfig::from_arsenal(&ArsenalConfig::from_ctx(ctx));
    let client = saml_client(cfg.timeout_ms);
    let host = extract_host(target);
    let scheme = if target.trim().starts_with("http://") {
        "http"
    } else {
        "https"
    };
    let base = format!("{scheme}://{host}");

    let mut findings: Vec<Value> = Vec::new();
    let mut sig = Signals::default();

    // ── 1) Endpoint discovery (explicit metadata URL + metadata/SSO path probing) ──
    let mut url_set: BTreeSet<String> = BTreeSet::new();
    if let Some(u) = &cfg.metadata_url {
        url_set.insert(u.clone());
    }
    if cfg.check_metadata {
        for p in cfg.metadata_paths.iter().take(cfg.max_paths) {
            url_set.insert(format!(
                "{}/{}",
                base.trim_end_matches('/'),
                p.trim_start_matches('/')
            ));
        }
    }
    for p in cfg.sso_paths.iter().take(cfg.max_paths) {
        url_set.insert(format!(
            "{}/{}",
            base.trim_end_matches('/'),
            p.trim_start_matches('/')
        ));
    }
    let responses = get_many(&client, url_set.into_iter().collect(), cfg.concurrency).await;

    // ── 2) Vendor fingerprint + metadata analysis ──
    for (url, probe) in &responses {
        if sig.idp_vendor.is_none() {
            if let Some(v) = fingerprint_idp(probe) {
                sig.idp_vendor = Some(v.to_string());
            }
        }
        if !looks_like_saml(&probe.body) || probe.status >= 500 {
            continue;
        }
        if !sig.endpoints.contains(url) {
            sig.endpoints.push(url.clone());
        }

        if probe.body.contains("EntityDescriptor") {
            let facts = analyze_metadata(&probe.body);
            if facts.is_idp {
                sig.idp_metadata = true;
            }
            if facts.is_sp {
                sig.sp_metadata = true;
            }
            if let Some(eid) = &facts.entity_id {
                if !sig.entity_ids.contains(eid) {
                    sig.entity_ids.push(eid.clone());
                }
            }
            sig.signing_certs += facts.certs.len();

            findings.push(finding_rich(
                ENGINE_ID,
                "SAML federation metadata exposed",
                "info",
                T_TRUST,
                &format!(
                    "Parsed a SAML EntityDescriptor at {url} (role: {}). entityID={}, {} signing cert(s), bindings: {}.",
                    if facts.is_idp { "IdP" } else if facts.is_sp { "SP" } else { "unknown" },
                    facts.entity_id.clone().unwrap_or_else(|| "?".into()),
                    facts.certs.len(),
                    if facts.bindings.is_empty() { "n/a".to_string() } else { facts.bindings.join(", ") },
                ),
                target,
                0.95,
                Evidence::new()
                    .with("metadata_url", url.clone())
                    .with("entity_id", facts.entity_id.clone().unwrap_or_default())
                    .with("bindings", json!(facts.bindings))
                    .with("acs_urls", json!(facts.acs_urls))
                    .with("authn_requests_signed", json!(facts.authn_requests_signed))
                    .check("entity_descriptor", true, "parsed"),
            ));

            // X.509 signing-certificate hygiene.
            for cert in &facts.certs {
                if cert.expired {
                    sig.expired_cert = true;
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Expired SAML signing certificate",
                        "high",
                        T_MODIFY_AUTH,
                        &format!("A SAML signing certificate in the metadata has expired ({} days past validity; subject {}). Federation trust can break or be silently weakened during rotation gaps.", -cert.days_until_expiry, cert.subject),
                        target,
                        0.9,
                        Evidence::new()
                            .with("subject", cert.subject.clone())
                            .with("issuer", cert.issuer.clone())
                            .with("self_signed", cert.self_signed)
                            .with("days_until_expiry", cert.days_until_expiry)
                            .check("cert_expired", true, "not_after in past"),
                    ));
                } else if cert.days_until_expiry < cfg.cert_expiry_warn_days {
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "SAML signing certificate expiring soon",
                        "medium",
                        T_MODIFY_AUTH,
                        &format!("A SAML signing certificate expires in {} days (subject {}). Plan a controlled rotation to avoid an SSO outage.", cert.days_until_expiry, cert.subject),
                        target,
                        0.85,
                        Evidence::new()
                            .with("subject", cert.subject.clone())
                            .with("days_until_expiry", cert.days_until_expiry)
                            .check("cert_expiring", true, cert.days_until_expiry),
                    ));
                }
                if cert.key_bits > 0 && cert.key_bits < cfg.min_cert_bits {
                    sig.weak_key_cert = true;
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Weak SAML signing key",
                        "high",
                        T_FORGE_SAML,
                        &format!("A SAML signing certificate uses a {}-bit key (below the {}-bit minimum). Weak keys lower the cost of forging signed assertions (Golden-SAML-class).", cert.key_bits, cfg.min_cert_bits),
                        target,
                        0.88,
                        Evidence::new()
                            .with("subject", cert.subject.clone())
                            .with("key_bits", cert.key_bits)
                            .check("weak_key", true, cert.key_bits),
                    ));
                }
                if cert.sig_alg.to_ascii_lowercase().contains("sha1") {
                    sig.weak_sha1 = true;
                }
            }

            if facts.sha1 {
                sig.weak_sha1 = true;
            }
            // SP that does not require signed assertions = forgeable login.
            if facts.want_assertions_signed == Some(false) {
                sig.unsigned_assertions = true;
                findings.push(finding_rich(
                    ENGINE_ID,
                    "SAML accepts unsigned assertions (WantAssertionsSigned=false)",
                    "critical",
                    T_FORGE_SAML,
                    &format!("The SAML metadata at {url} advertises WantAssertionsSigned=false, so the relying party accepts unsigned assertions. An attacker can forge an assertion and authenticate as any user (authentication bypass)."),
                    target,
                    0.9,
                    Evidence::new()
                        .with("metadata_url", url.clone())
                        .check("want_assertions_signed", true, false),
                ));
            }
            if facts.want_assertions_encrypted == Some(false) {
                sig.missing_encryption = true;
                findings.push(finding_rich(
                    ENGINE_ID,
                    "SAML assertions not encrypted (WantAssertionsEncrypted=false)",
                    "low",
                    T_APP_TOKEN,
                    "The relying party does not require encrypted assertions; assertion attributes (including identity claims) traverse in cleartext within the signed envelope.",
                    target,
                    0.7,
                    Evidence::new().check("want_assertions_encrypted", true, false),
                ));
            }

            supreme::emit_metadata_depth_findings(
                target,
                url,
                &facts,
                &mut sig,
                &mut findings,
                cfg.check_xsw_preconditions,
                cfg.check_slo_exposure,
                cfg.check_binding_posture,
                cfg.check_metadata_expiry,
            );
        }
    }

    if sig.weak_sha1 {
        findings.push(finding_rich(
            ENGINE_ID,
            "SHA-1 signature algorithm in SAML federation",
            "high",
            T_MODIFY_AUTH,
            "The SAML federation references SHA-1 (rsa-sha1 / #sha1). SHA-1 is collision-broken and must not anchor signature trust; migrate signing + digest to SHA-256.",
            target,
            0.85,
            Evidence::new().check("sha1_in_metadata", true, "rsa-sha1/#sha1"),
        ));
    }

    if let Some(vendor) = &sig.idp_vendor {
        findings.push(finding_rich(
            ENGINE_ID,
            &format!("SSO identity provider fingerprinted: {vendor}"),
            "info",
            T_TRUST,
            &format!("The federation surface identifies as {vendor}. Vendor context tunes the relevant CVE/hardening guidance and Golden-SAML risk model."),
            target,
            0.75,
            Evidence::new().with("vendor", vendor.clone()).check("fingerprint", true, vendor.clone()),
        ));
    }

    // ── 3) RelayState open-redirect canary (benign) ──
    if cfg.check_relaystate && !sig.endpoints.is_empty() {
        let canary_host = extract_host(&cfg.relaystate_canary);
        for ep in sig.endpoints.clone().iter().take(8) {
            let sep = if ep.contains('?') { '&' } else { '?' };
            let url = format!(
                "{ep}{sep}RelayState={}",
                urlencoding::encode(&cfg.relaystate_canary)
            );
            if let Some(p) = http_get(&client, &url).await {
                if (300..400).contains(&p.status) {
                    if let Some(loc) = header_value(&p.headers, "location") {
                        if !canary_host.is_empty()
                            && (loc.contains(&canary_host) || loc.contains(&cfg.relaystate_canary))
                        {
                            sig.open_redirect = Some(ep.clone());
                            findings.push(finding_rich(
                                ENGINE_ID,
                                "SAML RelayState open redirect",
                                "high",
                                T_MODIFY_AUTH,
                                &format!("The SSO endpoint {ep} reflects RelayState into a redirect toward an attacker-controlled host ({loc}). RelayState open redirects enable convincing SSO phishing and post-auth token relay."),
                                target,
                                0.7,
                                Evidence::new()
                                    .with("endpoint", ep.clone())
                                    .with("location", loc.to_string())
                                    .check("relaystate_redirect", true, "canary reflected"),
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }

    // ── 4) Verbose parser-error disclosure (from observed responses) ──
    if cfg.check_error_disclosure {
        const MARKERS: &[&str] = &[
            "stacktrace",
            "stack trace",
            "exception in",
            "nullpointerexception",
            "java.lang.",
            "org.opensaml",
            "traceback (most recent",
            "system.web",
            "fatal error",
        ];
        for (url, probe) in &responses {
            if probe.status >= 400 {
                let bl = probe.body.to_ascii_lowercase();
                if MARKERS.iter().any(|m| bl.contains(m)) {
                    sig.error_disclosure = true;
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Verbose SAML parser error disclosure",
                        "low",
                        T_MODIFY_AUTH,
                        &format!("The endpoint {url} returned a verbose error/stack trace (HTTP {}), leaking the SAML stack/version and aiding targeted exploitation.", probe.status),
                        target,
                        0.6,
                        Evidence::new()
                            .with("endpoint", url.clone())
                            .with("http_status", probe.status)
                            .check("error_disclosure", true, "stack trace"),
                    ));
                    break;
                }
            }
        }
    }

    // No federation observed → honest empty result (nothing fabricated).
    if !sig.has_federation() {
        return empty_ok(ENGINE_ID, target);
    }

    if cfg.check_ws_federation {
        supreme::probe_ws_federation(&client, &base, target, &mut sig, &mut findings).await;
    }

    // ── 5) Attack-path synthesis (named, real-world SSO breach chains) ──
    if cfg.check_attack_paths {
        if sig.unsigned_assertions {
            findings.push(saml_attack_path(
                "Attack path: forge unsigned SAML assertion → authentication bypass",
                "critical",
                T_FORGE_SAML,
                target,
                "Because the relying party accepts unsigned assertions, an attacker can craft a SAMLResponse asserting any identity and log in as an arbitrary (admin) user without credentials.",
                &[
                    "Capture the ACS endpoint + expected attributes from metadata",
                    "Craft a SAMLResponse asserting a privileged NameID",
                    "POST the unsigned assertion to the ACS",
                    "Obtain an authenticated session as the victim",
                ],
            ));
        }
        if sig.idp_metadata && (sig.weak_key_cert || sig.weak_sha1) {
            findings.push(saml_attack_path(
                "Attack path: Golden SAML preconditions (weak IdP signing trust)",
                "high",
                T_FORGE_SAML,
                target,
                "The IdP federation trust relies on a weak key / SHA-1. If the token-signing private key is recovered or coerced, an attacker forges arbitrary, validly-signed assertions (Golden SAML / UNC2452-class) and bypasses MFA across every SP.",
                &[
                    "Recover/abuse the IdP token-signing key (weak key/algorithm lowers cost)",
                    "Forge a signed SAMLResponse for any user + attributes",
                    "Replay to each trusting SP",
                    "Persist as any identity, bypassing MFA",
                ],
            ));
        }
        if sig.open_redirect.is_some() {
            findings.push(saml_attack_path(
                "Attack path: RelayState phishing → session relay",
                "high",
                T_APP_TOKEN,
                target,
                "The RelayState open redirect lets an attacker craft a trusted-looking SSO link that, after a legitimate login, bounces the user (and post-auth state) to attacker infrastructure for credential/token capture.",
                &[
                    "Craft an SSO URL with a malicious RelayState",
                    "Phish a legitimate user to authenticate",
                    "Redirect the post-auth flow to attacker host",
                    "Capture tokens / relay the session",
                ],
            ));
        }
    }

    if cfg.check_attack_paths {
        supreme::extend_attack_paths(target, &sig, &mut findings);
    }

    supreme::emit_toxic_headline(target, &sig, &mut findings);
    supreme::emit_remediation_roadmap(target, &sig, &mut findings);
    if cfg.emit_agent_guidance {
        supreme::emit_agent_guidance(target, &mut findings);
    }

    let category_scores = supreme::finalize_category_scores(&sig);
    let (graph_nodes, graph_edges) = supreme::build_security_graph(target, &sig, &host);

    // ── 6) Posture summary (graded headline, emitted first) ──
    let score = sig.score();
    let grade = sig.grade();
    let vendor = sig
        .idp_vendor
        .clone()
        .unwrap_or_else(|| "unidentified".to_string());
    let summary_sev = if score < 55 {
        "high"
    } else if score < 75 {
        "medium"
    } else {
        "info"
    };
    let mut summary = finding_rich(
        ENGINE_ID,
        &format!("SAML/SSO Federation Posture: Grade {grade} ({score}/100)"),
        summary_sev,
        T_FORGE_SAML,
        &format!(
            "Federation surface for {host} (vendor: {vendor}) scored {score}/100 across {} endpoint(s) and {} signing certificate(s).",
            sig.endpoints.len(),
            sig.signing_certs
        ),
        target,
        1.0,
        Evidence::new()
            .with("score", score)
            .with("grade", grade)
            .with("vendor", vendor.clone())
            .with("category_scores", category_scores.to_json())
            .with("endpoints", json!(sig.endpoints))
            .with("entity_ids", json!(sig.entity_ids))
            .with("signing_certs", sig.signing_certs)
            .check("unsigned_assertions", sig.unsigned_assertions, sig.unsigned_assertions)
            .check("weak_sha1", sig.weak_sha1, sig.weak_sha1)
            .check("expired_cert", sig.expired_cert, sig.expired_cert)
            .check("open_redirect", sig.open_redirect.is_some(), sig.open_redirect.clone().unwrap_or_default()),
    );
    if let Some(o) = summary.as_object_mut() {
        o.insert("category".to_string(), json!("posture"));
        o.insert("grade".to_string(), json!(grade));
        o.insert("posture_score".to_string(), json!(score));
        o.insert("vendor".to_string(), json!(vendor));
    }
    findings.insert(0, summary);

    let actionable = findings
        .iter()
        .filter(|f| {
            f.get("category").and_then(Value::as_str) != Some("posture")
                && f.get("severity").and_then(Value::as_str) != Some("info")
        })
        .count();
    let toxic = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) == Some("toxic_combination"))
        .count();
    let path_count = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) == Some("attack_path"))
        .count();
    EngineResult::ok_with_graph(
        findings,
        format!(
            "SAML/SSO Federation Posture: grade {grade} ({score}/100), {actionable} actionable finding(s) on {host}{}{}",
            if toxic > 0 { format!(", {toxic} toxic combo(s)") } else { String::new() },
            if path_count > 0 { format!(", {path_count} attack path(s)") } else { String::new() },
        ),
        graph_nodes,
        graph_edges,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_parse_detects_idp_and_flags() {
        let xml = r#"<EntityDescriptor entityID="https://idp.example.com/meta">
            <IDPSSODescriptor WantAuthnRequestsSigned="false">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
            </IDPSSODescriptor></EntityDescriptor>"#;
        let f = analyze_metadata(xml);
        assert!(f.is_idp);
        assert_eq!(f.entity_id.as_deref(), Some("https://idp.example.com/meta"));
    }

    #[test]
    fn looks_like_saml_matches() {
        assert!(looks_like_saml("<EntityDescriptor>"));
        assert!(looks_like_saml("urn:oasis:names:tc:SAML:2.0"));
        assert!(!looks_like_saml("<html>nope</html>"));
    }

    #[test]
    fn signals_score_penalises_unsigned() {
        let mut s = Signals::default();
        s.endpoints.push("x".into());
        let base = s.score();
        s.unsigned_assertions = true;
        assert!(s.score() < base);
    }
}
