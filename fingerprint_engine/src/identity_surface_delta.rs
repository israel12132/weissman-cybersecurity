//! **Identity Surface Delta** — a new host is an IdP problem the same hour it appears.
//!
//! Runs live `first_mover_surface_delta`, then OIDC/SAML discovery only on *added*
//! FQDNs that look like login/SSO/IdP (plus in-scope login/sso/auth/idp prefixes).
//! Findings require a live HTTP body (issuer JSON or EntityDescriptor). Missing MFA
//! claims in metadata are **not** invented as a bypass.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding, http_client, http_get, join_url};
use crate::engine_result::EngineResult;
use crate::first_mover_surface_delta::{self, in_authorized_scope};
use serde_json::{json, Value};

pub const ENGINE_ID: &str = "identity_surface_delta";
const MITRE: &str = "T1078";
const MAX_HOSTS: usize = 6;
const IDP_PREFIXES: &[&str] = &[
    "login", "sso", "auth", "idp", "accounts", "adfs", "sts", "okta",
];

const IDP_TOKENS: &[&str] = &[
    "login",
    "sso",
    "auth",
    "idp",
    "identity",
    "accounts",
    "adfs",
    "okta",
    "oauth",
    "oidc",
    "saml",
    "sts",
    "ping",
    "onelogin",
    "auth0",
    "keycloak",
    "cognito",
    "entra",
    "b2clogin",
    "federation",
    "authentication",
];

fn label_hits_idp_token(label: &str, tok: &str) -> bool {
    if label == tok {
        return true;
    }
    // login-sso / sso-prod / sts-01 — not "author" or "authorized"
    if let Some(rest) = label.strip_prefix(tok) {
        return rest.starts_with('-') || rest.starts_with('_');
    }
    if let Some(head) = label.strip_suffix(tok) {
        return head.ends_with('-') || head.ends_with('_');
    }
    false
}

#[must_use]
pub fn looks_like_idp_host(fqdn: &str) -> bool {
    let h = fqdn.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    h.split('.').any(|label| {
        IDP_TOKENS
            .iter()
            .any(|tok| label_hits_idp_token(label, tok))
    })
}

fn normalize_fqdn(raw: &str) -> Option<String> {
    let h = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.contains('.') {
        Some(h)
    } else {
        None
    }
}

fn added_fqdns(findings: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for f in findings {
        if f.get("category").and_then(Value::as_str) != Some("added") {
            continue;
        }
        if let Some(t) = f
            .get("target")
            .or_else(|| f.get("value"))
            .and_then(Value::as_str)
        {
            if let Some(h) = normalize_fqdn(t) {
                if !out.iter().any(|x| x == &h) {
                    out.push(h);
                }
            }
        }
        if out.len() >= MAX_HOSTS * 4 {
            break;
        }
    }
    out
}

fn tag_parent(mut f: Value, host: &str) -> Value {
    if let Some(obj) = f.as_object_mut() {
        obj.insert("parent_fqdn".into(), json!(host));
        obj.insert("fusion".into(), json!(ENGINE_ID));
        obj.entry("asset")
            .or_insert_with(|| json!("identity_delta"));
    }
    f
}

/// Pick IdP-looking added hosts, then fill with in-scope login/sso prefixes.
#[must_use]
pub fn select_idp_hosts(apex: &str, added: &[String], extra: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let push = |out: &mut Vec<String>, h: String| {
        if out.len() >= MAX_HOSTS {
            return;
        }
        if !in_authorized_scope(apex, &h) {
            return;
        }
        if !out.iter().any(|x| x == &h) {
            out.push(h);
        }
    };
    for h in added.iter().chain(extra.iter()) {
        if looks_like_idp_host(h) {
            push(&mut out, h.clone());
        }
    }
    if out.len() < MAX_HOSTS {
        let apex_n = extract_host(apex);
        for p in IDP_PREFIXES {
            push(&mut out, format!("{p}.{apex_n}"));
        }
    }
    out
}

fn oidc_issuer(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    v.get("issuer")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with("http"))
}

fn saml_entity(body: &str) -> bool {
    let low = body.to_ascii_lowercase();
    low.contains("entitydescriptor") || low.contains("entityid=")
}

async fn probe_idp_host(host: &str, from_delta: bool) -> Vec<Value> {
    let client = http_client().await;
    let base = format!("https://{host}");
    let mut out = Vec::new();
    let paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/webfinger?resource=acct:probe",
        "/FederationMetadata/2007-06/FederationMetadata.xml",
        "/adfs/ls/",
        "/oauth2/v2.0/authorize",
    ];
    for path in paths {
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            join_url(&base, path)
        };
        let Some(p) = http_get(&client, &url).await else {
            continue;
        };
        if p.status >= 400 {
            continue;
        }
        if let Some(issuer) = oidc_issuer(&p.body) {
            let sev = if from_delta { "high" } else { "medium" };
            out.push(tag_parent(
                finding(
                    ENGINE_ID,
                    &format!("Live OIDC IdP on {host}"),
                    sev,
                    MITRE,
                    &format!(
                        "{} HTTP {} issuer={} — identity protocol on this FQDN. {}",
                        p.final_url,
                        p.status,
                        issuer,
                        if from_delta {
                            "Host appeared in this first-mover snapshot (not a weekly later hunt)."
                        } else {
                            "In-scope IdP prefix responded with OpenID Provider metadata."
                        }
                    ),
                    host,
                ),
                host,
            ));
            break;
        }
        if saml_entity(&p.body) {
            let sev = if from_delta { "high" } else { "medium" };
            out.push(tag_parent(
                finding(
                    ENGINE_ID,
                    &format!("SAML metadata exposed on {host}"),
                    sev,
                    "T1550.001",
                    &format!(
                        "{} HTTP {} returned EntityDescriptor/entityID — federation surface is live.",
                        p.final_url, p.status
                    ),
                    host,
                ),
                host,
            ));
            break;
        }
    }
    out
}

pub async fn run_identity_surface_delta_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let mut inner = ctx.clone();
    let mut params = ctx.job_params.clone();
    if !params.is_object() {
        params = json!({});
    }
    if let Some(o) = params.as_object_mut() {
        o.insert("chain_web_engines".into(), json!(false));
        o.insert("fusion_inline".into(), json!(true));
    }
    inner.job_params = params;

    let mut delta =
        first_mover_surface_delta::run_first_mover_surface_delta_result(target, &inner).await;
    if !delta.success {
        return delta;
    }

    let added = added_fqdns(&delta.findings);
    let extra: Vec<String> = first_mover_surface_delta::extra_hosts_from_params(&ctx.job_params)
        .into_iter()
        .filter_map(|h| normalize_fqdn(&h))
        .collect();
    let hosts = select_idp_hosts(target, &added, &extra);
    if hosts.is_empty() {
        delta.findings.push(finding(
            ENGINE_ID,
            "Identity surface delta: no IdP-looking hosts in this snapshot",
            "info",
            MITRE,
            "First-mover ran live. OIDC/SAML fire only on added login/SSO/IdP FQDNs or in-scope prefixes — not fabricated IdP findings.",
            target,
        ));
        delta.message = format!("{} + identity delta idle", delta.message);
        return delta;
    }

    let added_set: std::collections::BTreeSet<&str> = added.iter().map(|s| s.as_str()).collect();
    let mut fused = 0usize;
    for host in &hosts {
        let from_delta = added_set.contains(host.as_str());
        let batch = probe_idp_host(host, from_delta).await;
        fused += batch.len();
        delta.findings.extend(batch);
    }

    delta.findings.insert(
        0,
        finding(
            ENGINE_ID,
            &format!(
                "Identity surface delta on {} host(s) — OIDC/SAML same job as first-mover",
                hosts.len()
            ),
            if fused > 0 { "high" } else { "info" },
            MITRE,
            &format!(
                "Live first-mover added [{}]. IdP candidates [{}]. {} protocol finding(s). Competitors inventory hosts; this engine proves identity protocol on the new FQDN now.",
                added.join(", "),
                hosts.join(", "),
                fused
            ),
            target,
        ),
    );
    if delta.findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    delta.message = format!(
        "{ENGINE_ID}: idp_hosts={} protocol_findings={fused}",
        hosts.len()
    );
    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idp_host_classifier_hits_login_sso_okta() {
        assert!(looks_like_idp_host("login.acme.test"));
        assert!(looks_like_idp_host("sso.corp.example.com"));
        assert!(looks_like_idp_host("acme.okta.com"));
        assert!(looks_like_idp_host("auth.example.com"));
        assert!(looks_like_idp_host("login-prod.acme.test"));
        assert!(!looks_like_idp_host("www.example.com"));
        assert!(!looks_like_idp_host("shop.example.com"));
        assert!(
            !looks_like_idp_host("author.example.com"),
            "short token 'auth' must not match author.*"
        );
        assert!(!looks_like_idp_host("authorized.example.com"));
    }

    #[test]
    fn select_prefers_added_idp_then_prefixes() {
        let added = vec!["shop.acme.test".into(), "login.acme.test".into()];
        let h = select_idp_hosts("acme.test", &added, &[]);
        assert!(h.contains(&"login.acme.test".into()));
        assert!(!h.contains(&"shop.acme.test".into()));
        assert!(h.iter().any(|x| x.starts_with("sso.")));
    }

    #[test]
    fn oidc_issuer_requires_http_issuer_field() {
        assert_eq!(
            oidc_issuer(r#"{"issuer":"https://login.acme.test"}"#).as_deref(),
            Some("https://login.acme.test")
        );
        assert!(oidc_issuer(r#"{"issuer":"not-a-url"}"#).is_none());
        assert!(oidc_issuer("not-json").is_none());
    }

    #[test]
    fn saml_entity_detects_descriptor() {
        assert!(saml_entity("<EntityDescriptor entityID=\"https://idp\">"));
        assert!(!saml_entity("<html>login</html>"));
    }
}
