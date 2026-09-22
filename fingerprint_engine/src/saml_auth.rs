//! SAML 2.0 HTTP-POST ACS: verify signature, parse the *single* signed assertion, resolve subject
//! to email, JIT user, session JWT.
//!
//! **Default (production):** responses must be verified with `xmlsec1` (`WEISSMAN_XMLSEC1_BINARY`)
//! using the tenant IdP PEM in `tenant_idps.saml_idp_cert_pem`. The signature is bound to the SAML
//! assertion/response `ID` attribute (`--id-attr:ID`), and identity is extracted with a namespaced
//! quick-xml parse that enforces EXACTLY ONE `<Assertion>` (kills XML Signature Wrapping), validates
//! Conditions/AudienceRestriction/SubjectConfirmationData, binds `InResponseTo` to the AuthnRequest
//! we issued, and rejects replayed assertion IDs (`saml_seen_assertions`).
//!
//! **Lab only:** set `WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1` (non-production hosts only) to parse
//! NameID/email from the single assertion without cryptographic verification or profile checks.

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use flate2::read::DeflateDecoder;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use serde::Deserialize;
use serde_json::json;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::NamedTempFile;

use crate::audit_log;
use crate::db;
use crate::http::AppState;

/// Clock skew (seconds) tolerated on SAML Conditions / SubjectConfirmationData time bounds.
const CLOCK_SKEW_SECS: i64 = 120;

fn auth_store_down() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(crate::http_unavailable::auth_degraded_unavailable_json(
            "database unavailable",
        )),
    )
}

fn unauthorized(detail: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"ok": false, "detail": detail})),
    )
}

#[derive(Deserialize)]
pub struct SamlBeginQuery {
    pub tenant_slug: String,
    pub idp_name: String,
}

#[derive(Deserialize)]
pub struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    // SAML 2.0 HTTP-POST binding delivers this as `RelayState` (exactly what `saml_begin` emits);
    // without the rename serde_urlencoded drops the unknown key and relay_state is always None,
    // so SP-initiated SSO can never complete.
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

fn public_base_url() -> String {
    std::env::var("WEISSMAN_PUBLIC_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string())
}

/// SP AssertionConsumerService URL — must equal the SubjectConfirmationData Recipient.
fn sp_acs_url() -> String {
    let base = public_base_url().trim_end_matches('/').to_string();
    format!("{}/api/auth/saml/acs", base)
}

/// SP Issuer / EntityID — must equal the assertion AudienceRestriction Audience. Identical to the
/// `<saml:Issuer>` we send in `saml_begin`, so the IdP echoes exactly this value.
fn sp_issuer() -> String {
    let base = public_base_url().trim_end_matches('/').to_string();
    std::env::var("WEISSMAN_SAML_SP_ISSUER").unwrap_or_else(|_| format!("{}/saml/metadata", base))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SamlRelay {
    idp_id: i64,
    tenant_id: i64,
    exp: i64,
    /// AuthnRequest ID we issued in `saml_begin`; the assertion's `InResponseTo` must equal it.
    /// `#[serde(default)]` so relay tokens minted by a previous build (≤ 10 min TTL) still decode
    /// during a rolling deploy — they carry an empty `request_id`, which fails the InResponseTo
    /// binding (secure-by-default: the user simply re-initiates login).
    #[serde(default)]
    request_id: String,
}

fn decode_saml_xml(b64: &str) -> Result<String, String> {
    let raw = B64.decode(b64.trim()).map_err(|e| e.to_string())?;
    let xml = if raw.len() > 2 && raw[0] == 0x78 {
        let mut dec = DeflateDecoder::new(&raw[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).map_err(|e| e.to_string())?;
        String::from_utf8(out).map_err(|e| e.to_string())?
    } else {
        String::from_utf8(raw).map_err(|e| e.to_string())?
    };
    Ok(xml)
}

// ---------------------------------------------------------------------------
// XML parsing (quick-xml 0.41) — namespaced, single-assertion, anti-XSW.
// ---------------------------------------------------------------------------

/// Local (prefix-stripped) part of a possibly-prefixed XML name, e.g. `saml:Assertion` -> `Assertion`.
fn local_name_bytes(qname: &[u8]) -> &[u8] {
    match qname.iter().rposition(|&b| b == b':') {
        Some(i) => &qname[i + 1..],
        None => qname,
    }
}

fn start_local(e: &BytesStart) -> String {
    let qn = e.name();
    let full: &[u8] = qn.as_ref();
    String::from_utf8_lossy(local_name_bytes(full)).into_owned()
}

fn end_local(e: &BytesEnd) -> String {
    let qn = e.name();
    let full: &[u8] = qn.as_ref();
    String::from_utf8_lossy(local_name_bytes(full)).into_owned()
}

/// Value of the attribute whose *local* name equals `want`, XML-unescaped and trimmed.
fn get_attr(e: &BytesStart, want: &str) -> Option<String> {
    for a in e.attributes() {
        let a = match a {
            Ok(a) => a,
            Err(_) => continue,
        };
        let kq = a.key; // QName is Copy
        let kb: &[u8] = kq.as_ref();
        let matches = std::str::from_utf8(local_name_bytes(kb))
            .map(|s| s == want)
            .unwrap_or(false);
        if matches {
            if let Ok(s) = std::str::from_utf8(&a.value) {
                return Some(xml_unescape(s.trim()));
            }
        }
    }
    None
}

fn xml_unescape(s: &str) -> String {
    // Replace `&amp;` last so a literal `&lt;` does not get double-decoded.
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn ancestor(stack: &[String], name: &str) -> bool {
    stack.iter().any(|s| s.as_str() == name)
}

#[derive(Default, Debug)]
struct ParsedSaml {
    assertion_count: usize,
    signature_present: bool,
    top_status: Option<String>,
    response_in_response_to: Option<String>,
    assertion_id: Option<String>,
    name_id: Option<String>,
    email_attr: Option<String>,
    /// Group/role claim AttributeValues collected ONLY from inside the single verified
    /// `<Assertion>` (same anti-XSW scoping as `email_attr`). Sorted + deduped so the value
    /// mirrors `scim::groups_from_saml_xml` for the legitimate signed case.
    assertion_groups: Vec<String>,
    cond_not_before: Option<String>,
    cond_not_on_or_after: Option<String>,
    audiences: Vec<String>,
    scd_recipient: Option<String>,
    scd_not_on_or_after: Option<String>,
    scd_in_response_to: Option<String>,
}

/// Handle a Start/Empty element: read the attributes we care about, scoped to the *single* assertion
/// where required. `stack` holds the element's ancestors (self not yet pushed).
fn on_open(
    e: &BytesStart,
    stack: &[String],
    p: &mut ParsedSaml,
    is_start: bool,
    attr_email: &mut bool,
    attr_group: &mut bool,
) {
    let name = start_local(e);
    match name.as_str() {
        "Assertion" => {
            p.assertion_count += 1;
            // Only trust the FIRST assertion's ID; if there is more than one the whole document
            // is rejected downstream (assertion_count > 1).
            if p.assertion_count == 1 {
                if let Some(id) = get_attr(e, "ID") {
                    p.assertion_id = Some(id);
                }
            }
        }
        "Signature" => {
            p.signature_present = true;
        }
        "Response" => {
            if p.response_in_response_to.is_none() {
                if let Some(v) = get_attr(e, "InResponseTo") {
                    p.response_in_response_to = Some(v);
                }
            }
        }
        "StatusCode" => {
            // Top-level protocol status only (never a StatusCode nested inside an assertion).
            if p.top_status.is_none() && !ancestor(stack, "Assertion") {
                if let Some(v) = get_attr(e, "Value") {
                    p.top_status = Some(v);
                }
            }
        }
        "Conditions" if ancestor(stack, "Assertion") => {
            if let Some(v) = get_attr(e, "NotBefore") {
                p.cond_not_before = Some(v);
            }
            if let Some(v) = get_attr(e, "NotOnOrAfter") {
                p.cond_not_on_or_after = Some(v);
            }
        }
        "SubjectConfirmationData" if ancestor(stack, "Assertion") => {
            if let Some(v) = get_attr(e, "Recipient") {
                p.scd_recipient = Some(v);
            }
            if let Some(v) = get_attr(e, "NotOnOrAfter") {
                p.scd_not_on_or_after = Some(v);
            }
            if let Some(v) = get_attr(e, "InResponseTo") {
                p.scd_in_response_to = Some(v);
            }
        }
        "Attribute" if is_start && ancestor(stack, "Assertion") => {
            if let Some(nm) = get_attr(e, "Name") {
                let low = nm.to_ascii_lowercase();
                if low.contains("email") || low.contains("mail") {
                    *attr_email = true;
                }
                // Same group-ish Name set as `scim::groups_from_saml_xml`
                // (case-insensitive substring `groups?`/`Group`/`memberOf`).
                if low.contains("group") || low.contains("memberof") {
                    *attr_group = true;
                }
            }
        }
        _ => {}
    }
}

/// Single-pass namespaced parse. Extracts identity ONLY from inside the (single) assertion.
fn parse_saml_response(xml: &str) -> Result<ParsedSaml, String> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut p = ParsedSaml::default();
    let mut stack: Vec<String> = Vec::new();
    let mut current_attr_is_email = false;
    let mut current_attr_is_group = false;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                on_open(
                    &e,
                    &stack,
                    &mut p,
                    true,
                    &mut current_attr_is_email,
                    &mut current_attr_is_group,
                );
                stack.push(start_local(&e));
            }
            Ok(Event::Empty(e)) => {
                on_open(
                    &e,
                    &stack,
                    &mut p,
                    false,
                    &mut current_attr_is_email,
                    &mut current_attr_is_group,
                );
            }
            Ok(Event::Text(t)) => {
                // quick-xml 0.41: BytesText has `decode()` (charset), not `unescape()`; resolve XML
                // entities with the same manual helper used by get_attr.
                let txt = match t.decode() {
                    Ok(c) => xml_unescape(c.as_ref()),
                    Err(_) => String::new(),
                };
                let txt = txt.trim().to_string();
                if !txt.is_empty() {
                    match stack.last().map(|s| s.as_str()) {
                        Some("NameID")
                            if ancestor(&stack, "Subject") && ancestor(&stack, "Assertion") =>
                        {
                            if p.name_id.is_none() {
                                p.name_id = Some(txt);
                            }
                        }
                        Some("Audience")
                            if ancestor(&stack, "AudienceRestriction")
                                && ancestor(&stack, "Assertion") =>
                        {
                            p.audiences.push(txt);
                        }
                        Some("AttributeValue")
                            if current_attr_is_email && ancestor(&stack, "Assertion") =>
                        {
                            if p.email_attr.is_none() {
                                p.email_attr = Some(txt);
                            }
                        }
                        Some("AttributeValue")
                            if current_attr_is_group && ancestor(&stack, "Assertion") =>
                        {
                            p.assertion_groups.push(txt);
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                if end_local(&e) == "Attribute" {
                    current_attr_is_email = false;
                    current_attr_is_group = false;
                }
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(format!("xml parse error: {e}")),
        }
        buf.clear();
    }

    // Normalize to match `scim::groups_from_saml_xml` output (sorted + deduped) for the
    // legitimate signed case.
    p.assertion_groups.sort();
    p.assertion_groups.dedup();

    Ok(p)
}

// ---------------------------------------------------------------------------
// Assertion profile validation (pure — fully unit-testable, no I/O).
// ---------------------------------------------------------------------------

struct ValidationContext {
    acs_url: String,
    sp_issuer: String,
    request_id: String,
    allow_unsolicited: bool,
    now: chrono::DateTime<chrono::Utc>,
    skew: chrono::Duration,
}

fn parse_saml_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

fn assertion_email(p: &ParsedSaml) -> Option<String> {
    if let Some(n) = p.name_id.as_deref() {
        let t = n.trim();
        if t.contains('@') && !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(e) = p.email_attr.as_deref() {
        let t = e.trim();
        if t.contains('@') && !t.is_empty() {
            return Some(t.to_string());
        }
    }
    None
}

/// Enforce the SAML Web-Browser-SSO assertion profile on an already-signature-verified document.
/// Returns the resolved email on success, or a human-readable rejection reason.
fn validate_assertion(p: &ParsedSaml, ctx: &ValidationContext) -> Result<String, String> {
    // XML Signature Wrapping defense: there must be exactly one Assertion, and all identity was
    // extracted only from within it.
    if p.assertion_count == 0 {
        return Err("no SAML assertion present".to_string());
    }
    if p.assertion_count > 1 {
        return Err("multiple SAML assertions (possible signature wrapping)".to_string());
    }

    // Top-level protocol status.
    if let Some(st) = p.top_status.as_deref() {
        if !st.ends_with(":Success") {
            return Err(format!("SAML status not Success: {st}"));
        }
    }

    // Conditions: NotOnOrAfter is required; NotBefore optional. Both with clock skew.
    match p.cond_not_on_or_after.as_deref().and_then(parse_saml_time) {
        Some(noa) => {
            if ctx.now - ctx.skew >= noa {
                return Err("assertion expired (Conditions NotOnOrAfter)".to_string());
            }
        }
        None => return Err("assertion missing/invalid Conditions NotOnOrAfter".to_string()),
    }
    if let Some(nb) = p.cond_not_before.as_deref().and_then(parse_saml_time) {
        if ctx.now + ctx.skew < nb {
            return Err("assertion not yet valid (Conditions NotBefore)".to_string());
        }
    }

    // AudienceRestriction: some Audience must equal our SP issuer.
    if !p.audiences.iter().any(|a| a == &ctx.sp_issuer) {
        return Err("SAML AudienceRestriction does not match SP issuer".to_string());
    }

    // SubjectConfirmationData: Recipient must equal our ACS URL; NotOnOrAfter required + skew.
    match p.scd_recipient.as_deref() {
        Some(rcpt) if rcpt == ctx.acs_url => {}
        Some(_) => {
            return Err("SubjectConfirmationData Recipient does not match ACS URL".to_string())
        }
        None => return Err("SubjectConfirmationData Recipient missing".to_string()),
    }
    match p.scd_not_on_or_after.as_deref().and_then(parse_saml_time) {
        Some(noa) => {
            if ctx.now - ctx.skew >= noa {
                return Err("SubjectConfirmationData expired (NotOnOrAfter)".to_string());
            }
        }
        None => return Err("SubjectConfirmationData missing/invalid NotOnOrAfter".to_string()),
    }

    // InResponseTo binding — prefer the value inside the signed assertion (SCD), fall back to the
    // Response element. Empty => unsolicited (IdP-initiated): rejected unless the IdP opts in.
    let in_response_to = p
        .scd_in_response_to
        .clone()
        .or_else(|| p.response_in_response_to.clone())
        .unwrap_or_default();
    if in_response_to.is_empty() {
        if !ctx.allow_unsolicited {
            return Err("unsolicited SAML response (no InResponseTo) not allowed".to_string());
        }
    } else if in_response_to != ctx.request_id {
        return Err("InResponseTo does not match issued AuthnRequest ID".to_string());
    }

    assertion_email(p).ok_or_else(|| "could not extract email from assertion".to_string())
}

/// Lab-only (INSECURE_SKIP_VERIFY): keep the anti-XSW single-assertion hygiene, skip crypto/profile.
fn extract_email_lab(p: &ParsedSaml) -> Option<String> {
    if p.assertion_count != 1 {
        return None;
    }
    assertion_email(p)
}

/// Replay-cache TTL: the assertion's own validity horizon plus one skew window.
fn validity_expiry(p: &ParsedSaml, ctx: &ValidationContext) -> chrono::DateTime<chrono::Utc> {
    let base = p
        .cond_not_on_or_after
        .as_deref()
        .and_then(parse_saml_time)
        .or_else(|| p.scd_not_on_or_after.as_deref().and_then(parse_saml_time))
        .unwrap_or_else(|| ctx.now + chrono::Duration::minutes(10));
    base + ctx.skew
}

// ---------------------------------------------------------------------------
// Anti-replay: one-shot assertion IDs (auth pool, BYPASSRLS `weissman_auth`).
// AppState carries no Redis handle (app_pool/intel_pool/auth_pool/read_only_pool only), so the
// durable Postgres table `saml_seen_assertions` is authoritative.
// ---------------------------------------------------------------------------

/// Returns `Ok(true)` when the assertion ID is seen for the FIRST time (login may proceed),
/// `Ok(false)` when it is a replay within its validity window, or a DB error.
async fn assertion_replay_guard(
    auth: &sqlx::PgPool,
    tenant_id: i64,
    assertion_id: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, sqlx::Error> {
    // Opportunistic GC of already-expired IDs (bounded, index-driven).
    let _ = sqlx::query("DELETE FROM saml_seen_assertions WHERE expires_at < now()")
        .execute(auth)
        .await;
    let res = sqlx::query(
        "INSERT INTO saml_seen_assertions (assertion_id, tenant_id, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (assertion_id) DO NOTHING",
    )
    .bind(assertion_id)
    .bind(tenant_id)
    .bind(expires_at)
    .execute(auth)
    .await?;
    Ok(res.rows_affected() == 1)
}

async fn verify_xmlsec(
    xmlsec_bin: &str,
    xml_path: &std::path::Path,
    pem_path: &std::path::Path,
) -> Result<(), String> {
    let pem = pem_path.to_str().ok_or("pem path")?.to_string();
    let xml = xml_path.to_str().ok_or("xml path")?.to_string();
    // The ACS route is unauthenticated: run xmlsec1 off the runtime with `kill_on_drop` and a
    // hard timeout so an attacker-supplied assertion that makes it hang cannot pin a tokio
    // worker thread (a handful of such requests would stall the whole API otherwise).
    //
    // `--id-attr:ID <ns>:<name>` registers the SAML ID attribute on both the assertion and the
    // protocol Response so a `Reference URI="#<id>"` resolves to the signed element (xmlsec splits
    // on the LAST ':' — everything before it is the namespace href). `--enabled-reference-uris
    // empty,same-doc` permits whole-document and same-document fragment references while forbidding
    // `local`/`remote` (no file:// or http(s):// reference fetch — SSRF/file-read guard).
    let mut cmd = tokio::process::Command::new(xmlsec_bin);
    cmd.args([
        "--verify",
        "--pubkey-pem",
        &pem,
        "--id-attr:ID",
        "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
        "--id-attr:ID",
        "urn:oasis:names:tc:SAML:2.0:protocol:Response",
        "--enabled-reference-uris",
        "empty,same-doc",
        &xml,
    ])
    .kill_on_drop(true);
    let out = match tokio::time::timeout(std::time::Duration::from_secs(5), cmd.output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("xmlsec verification timed out".to_string()),
    };
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct SamlIdpRow {
    id: i64,
    tenant_id: i64,
    saml_idp_sso_url: Option<String>,
}

/// GET /api/auth/saml/begin — auto-posting form to IdP SSO (SP-initiated).
pub async fn saml_begin(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SamlBeginQuery>,
) -> Result<Html<String>, (StatusCode, Json<serde_json::Value>)> {
    let auth = state.auth_pool.as_ref();
    let slug = q.tenant_slug.trim();
    let name = q.idp_name.trim();
    if slug.is_empty() || name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "tenant_slug and idp_name required"})),
        ));
    }
    let row = sqlx::query_as::<_, SamlIdpRow>(
        r#"SELECT i.id, i.tenant_id, i.saml_idp_sso_url FROM tenant_idps i
           INNER JOIN tenants t ON t.id = i.tenant_id
           WHERE t.slug = $1 AND i.name = $2 AND i.provider = 'saml' AND i.active = true AND t.active = true"#,
    )
    .bind(slug)
    .bind(name)
    .fetch_optional(auth)
    .await
    .map_err(|_| auth_store_down())?;
    let Some(r) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "SAML IdP not found"})),
        ));
    };
    let sso = r.saml_idp_sso_url.as_deref().unwrap_or("").trim();
    if sso.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "saml_idp_sso_url not configured"})),
        ));
    }
    let acs = sp_acs_url();
    let issuer = sp_issuer();
    let instant = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let req_id = format!("_{}", uuid::Uuid::new_v4());
    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}"><saml:Issuer>{}</saml:Issuer></samlp:AuthnRequest>"#,
        req_id, instant, sso, acs, issuer
    );
    // HTTP-POST binding: base64-encoded XML (no DEFLATE; Redirect binding would use DEFLATE).
    let saml_req_b64 = B64.encode(xml.as_bytes());
    let exp = chrono::Utc::now().timestamp() + 600;
    let relay = SamlRelay {
        idp_id: r.id,
        tenant_id: r.tenant_id,
        exp,
        request_id: req_id.clone(),
    };
    let relay_jwt = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &relay,
        &jsonwebtoken::EncodingKey::from_secret(crate::auth_jwt::jwt_secret()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "relay jwt"})),
        )
    })?;
    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Redirecting to SSO…</title></head><body>
<form id="f" method="post" action="{}">
<input type="hidden" name="SAMLRequest" value="{}"/>
<input type="hidden" name="RelayState" value="{}"/>
<noscript><button type="submit">Continue to SSO</button></noscript>
</form><script>document.getElementById('f').submit();</script></body></html>"#,
        html_escape_attr(sso),
        html_escape_attr(&saml_req_b64),
        html_escape_attr(&relay_jwt),
    );
    Ok(Html(html))
}

fn html_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// POST /api/auth/saml/acs
pub async fn saml_acs(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<SamlAcsForm>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let relay = form.relay_state.as_deref().unwrap_or("");
    if relay.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "relay_state required"})),
        ));
    }
    let mut validation = jsonwebtoken::Validation::default();
    validation.validate_exp = true;
    let r = jsonwebtoken::decode::<SamlRelay>(
        relay,
        &jsonwebtoken::DecodingKey::from_secret(crate::auth_jwt::jwt_secret()),
        &validation,
    )
    .map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "invalid relay_state"})),
        )
    })?
    .claims;
    if r.exp < chrono::Utc::now().timestamp() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "relay_state expired"})),
        ));
    }
    let auth = state.auth_pool.as_ref();
    let row = sqlx::query_as::<_, (String, Option<String>, bool)>(
        "SELECT COALESCE(saml_idp_cert_pem,''), saml_idp_sso_url, COALESCE(saml_allow_unsolicited, false) \
         FROM tenant_idps WHERE id = $1 AND tenant_id = $2 AND provider = 'saml' AND active = true",
    )
    .bind(r.idp_id)
    .bind(r.tenant_id)
    .fetch_optional(auth)
    .await
    .map_err(|_| auth_store_down())?;
    let Some((cert_pem, _sso, allow_unsolicited)) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "SAML IdP not found"})),
        ));
    };
    let xml = decode_saml_xml(&form.saml_response).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "SAML response decode failed"})),
        )
    })?;
    let parsed = parse_saml_response(&xml).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "SAML response parse failed"})),
        )
    })?;

    let insecure = !weissman_core::tls_policy::is_production_environment()
        && matches!(
            std::env::var("WEISSMAN_SAML_INSECURE_SKIP_VERIFY")
                .ok()
                .as_deref(),
            Some("1") | Some("true") | Some("yes")
        );
    let xmlsec_bin = std::env::var("WEISSMAN_XMLSEC1_BINARY").unwrap_or_default();

    let email: String = if !insecure {
        if xmlsec_bin.trim().is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(
                    json!({"ok": false, "detail": "SAML verification required: set WEISSMAN_XMLSEC1_BINARY to xmlsec1 path, or WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1 for lab only"}),
                ),
            ));
        }
        if cert_pem.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "saml_idp_cert_pem missing for IdP"})),
            ));
        }
        // Require a signature to exist (xmlsec1 also fails when absent — belt and suspenders).
        if !parsed.signature_present {
            return Err(unauthorized("SAML response is not signed"));
        }
        let xml_file = NamedTempFile::new().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "temporary file unavailable"})),
            )
        })?;
        tokio::fs::write(xml_file.path(), xml.as_bytes())
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "detail": "temporary file unavailable"})),
                )
            })?;
        let pem_file = NamedTempFile::new().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "temporary file unavailable"})),
            )
        })?;
        tokio::fs::write(pem_file.path(), cert_pem.as_bytes())
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "detail": "temporary file unavailable"})),
                )
            })?;
        verify_xmlsec(&xmlsec_bin, xml_file.path(), pem_file.path())
            .await
            .map_err(|_| unauthorized("SAML xmlsec verify failed"))?;

        let ctx = ValidationContext {
            acs_url: sp_acs_url(),
            sp_issuer: sp_issuer(),
            request_id: r.request_id.clone(),
            allow_unsolicited,
            now: chrono::Utc::now(),
            skew: chrono::Duration::seconds(CLOCK_SKEW_SECS),
        };
        let email = validate_assertion(&parsed, &ctx).map_err(|reason| unauthorized(&reason))?;

        // Anti-replay: reject a re-used assertion ID within its validity window.
        let assertion_id = parsed
            .assertion_id
            .clone()
            .ok_or_else(|| unauthorized("assertion missing ID attribute"))?;
        let expires_at = validity_expiry(&parsed, &ctx);
        match assertion_replay_guard(auth, r.tenant_id, &assertion_id, expires_at).await {
            Ok(true) => {}
            Ok(false) => return Err(unauthorized("SAML assertion replay detected")),
            Err(_) => return Err(auth_store_down()),
        }
        email
    } else {
        extract_email_lab(&parsed)
            .ok_or_else(|| unauthorized("could not extract email from SAML assertion"))?
    };

    weissman_db::auth_access::record_auth_access(auth, r.tenant_id, "saml_acs")
        .await
        .map_err(|_| auth_store_down())?;
    // Group/role claims drive authorization (resolve_sso_user -> role_from_claim_groups ->
    // apply_groups_to_user UPDATEs users.role), so they MUST come only from inside the single
    // signature-verified <Assertion> -- the same anti-XSW scoping already used for NameID/email.
    // Scanning the raw document (the previous `groups_from_saml_xml(&xml)`) let an IdP that signs
    // only the assertion splice an unsigned Response-scope <AttributeStatement> to escalate the
    // role. `parsed` is the single-assertion parse shared by both the verified and lab branches,
    // so the scoping is identical regardless of branch.
    let claim_groups: &[String] = &parsed.assertion_groups;
    let user_id = crate::scim::resolve_sso_user(
        auth,
        state.app_pool.as_ref(),
        r.tenant_id,
        &email,
        claim_groups,
    )
    .await?;
    let ip = crate::http::extract_client_ip(&headers, addr);
    let mut tx = db::begin_tenant_tx(&state.app_pool, r.tenant_id)
        .await
        .map_err(|_| auth_store_down())?;
    audit_log::insert_audit(
        &mut tx,
        r.tenant_id,
        Some(user_id),
        email.as_str(),
        "login",
        "SAML session created",
        &ip,
    )
    .await
    .map_err(|_| auth_store_down())?;
    tx.commit().await.map_err(|_| auth_store_down())?;
    let binding = crate::auth_jwt::StreamBinding::from_http(&headers, addr);
    let (_access_jwt, access_line, refresh_line) =
        crate::auth_refresh::build_session_cookie_headers(auth, user_id, r.tenant_id, &binding)
            .await
            .map_err(|_| auth_store_down())?;
    let mut res = Redirect::to("/command-center/").into_response();
    if let Ok(v) = HeaderValue::from_str(&access_line) {
        res.headers_mut().append(SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&refresh_line) {
        res.headers_mut().append(SET_COOKIE, v);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn decode_saml_xml_plain_base64() {
        let xml = "<Response>hello</Response>";
        let b64 = STANDARD.encode(xml.as_bytes());
        assert_eq!(decode_saml_xml(&b64).unwrap(), xml);
    }

    #[test]
    fn decode_saml_xml_trims_whitespace() {
        let xml = "<Root/>";
        let b64 = STANDARD.encode(xml.as_bytes());
        let padded = format!("  {}\n", b64);
        assert_eq!(decode_saml_xml(&padded).unwrap(), xml);
    }

    #[test]
    fn decode_saml_xml_rejects_invalid_base64() {
        assert!(decode_saml_xml("!!!not-base64!!!").is_err());
    }

    #[test]
    fn html_escape_attr_escapes_all_specials() {
        assert_eq!(html_escape_attr(r#"a&b"c<d>e"#), "a&amp;b&quot;c&lt;d&gt;e");
        assert_eq!(html_escape_attr("&lt;"), "&amp;lt;");
        assert_eq!(html_escape_attr("plain"), "plain");
    }

    #[test]
    fn saml_relay_serde_round_trip() {
        let relay = SamlRelay {
            idp_id: 7,
            tenant_id: 42,
            exp: 1234567890,
            request_id: "_req-abc".to_string(),
        };
        let v = serde_json::to_value(&relay).unwrap();
        assert_eq!(v["idp_id"], 7);
        assert_eq!(v["tenant_id"], 42);
        assert_eq!(v["exp"], 1234567890);
        assert_eq!(v["request_id"], "_req-abc");
        let back: SamlRelay = serde_json::from_value(v).unwrap();
        assert_eq!(back.request_id, "_req-abc");
    }

    #[test]
    fn saml_relay_legacy_token_without_request_id_decodes() {
        // A relay minted by a previous build has no `request_id`; serde(default) => empty string.
        let v = json!({"idp_id": 1, "tenant_id": 2, "exp": 99});
        let back: SamlRelay = serde_json::from_value(v).unwrap();
        assert_eq!(back.request_id, "");
    }

    // ---- SAML parsing / profile validation ----

    const ACS: &str = "https://sp.example.com/api/auth/saml/acs";
    const ISS: &str = "https://sp.example.com/saml/metadata";

    fn ctx(request_id: &str) -> ValidationContext {
        ValidationContext {
            acs_url: ACS.to_string(),
            sp_issuer: ISS.to_string(),
            request_id: request_id.to_string(),
            allow_unsolicited: false,
            now: chrono::Utc::now(),
            skew: chrono::Duration::seconds(CLOCK_SKEW_SECS),
        }
    }

    fn rfc3339_offset(hours: i64) -> String {
        (chrono::Utc::now() + chrono::Duration::hours(hours)).to_rfc3339()
    }

    #[allow(clippy::too_many_arguments)]
    fn assertion(
        id: &str,
        email: &str,
        audience: &str,
        recipient: &str,
        cond_noa: &str,
        scd_noa: &str,
        scd_irt: &str,
    ) -> String {
        format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}">
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData Recipient="{recipient}" NotOnOrAfter="{scd_noa}" InResponseTo="{scd_irt}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="{cond_noa}">
    <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
  </saml:Conditions>
</saml:Assertion>"#
        )
    }

    fn response(inner: &str, status_success: bool, resp_irt: &str) -> String {
        let status = if status_success {
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        } else {
            "urn:oasis:names:tc:SAML:2.0:status:Requester"
        };
        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" InResponseTo="{resp_irt}">
  <samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>
  <ds:Signature><ds:SignedInfo/></ds:Signature>
  {inner}
</samlp:Response>"#
        )
    }

    fn valid_doc(req_id: &str) -> String {
        let a = assertion(
            "_assert-1",
            "alice@corp.example",
            ISS,
            ACS,
            &rfc3339_offset(1),
            &rfc3339_offset(1),
            req_id,
        );
        response(&a, true, req_id)
    }

    #[test]
    fn valid_single_assertion_ok() {
        let p = parse_saml_response(&valid_doc("_req-1")).unwrap();
        assert_eq!(p.assertion_count, 1);
        assert!(p.signature_present);
        assert_eq!(p.assertion_id.as_deref(), Some("_assert-1"));
        let email = validate_assertion(&p, &ctx("_req-1")).unwrap();
        assert_eq!(email, "alice@corp.example");
    }

    #[test]
    fn wrapped_second_assertion_rejected() {
        // Legit assertion + attacker-wrapped second (unsigned) assertion carrying attacker identity.
        let good = assertion(
            "_assert-1",
            "alice@corp.example",
            ISS,
            ACS,
            &rfc3339_offset(1),
            &rfc3339_offset(1),
            "_req-1",
        );
        let evil = assertion(
            "_assert-evil",
            "mallory@evil.example",
            ISS,
            ACS,
            &rfc3339_offset(1),
            &rfc3339_offset(1),
            "_req-1",
        );
        let doc = response(&format!("{good}{evil}"), true, "_req-1");
        let p = parse_saml_response(&doc).unwrap();
        assert_eq!(p.assertion_count, 2);
        let err = validate_assertion(&p, &ctx("_req-1")).unwrap_err();
        assert!(err.contains("multiple SAML assertions"), "{err}");
    }

    #[test]
    fn unsigned_nameid_outside_assertion_ignored() {
        // Attacker adds an unsigned NameID at the Response level; identity must still be alice.
        let a = assertion(
            "_assert-1",
            "alice@corp.example",
            ISS,
            ACS,
            &rfc3339_offset(1),
            &rfc3339_offset(1),
            "_req-1",
        );
        let doc = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" InResponseTo="_req-1">
  <saml:NameID>mallory@evil.example</saml:NameID>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <ds:Signature><ds:SignedInfo/></ds:Signature>
  {a}
</samlp:Response>"#
        );
        let p = parse_saml_response(&doc).unwrap();
        assert_eq!(p.assertion_count, 1);
        assert_eq!(p.name_id.as_deref(), Some("alice@corp.example"));
        assert_eq!(
            validate_assertion(&p, &ctx("_req-1")).unwrap(),
            "alice@corp.example"
        );
    }

    #[test]
    fn expired_conditions_rejected() {
        let a = assertion(
            "_assert-1",
            "alice@corp.example",
            ISS,
            ACS,
            &rfc3339_offset(-1), // Conditions NotOnOrAfter in the past
            &rfc3339_offset(1),
            "_req-1",
        );
        let p = parse_saml_response(&response(&a, true, "_req-1")).unwrap();
        let err = validate_assertion(&p, &ctx("_req-1")).unwrap_err();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn wrong_audience_rejected() {
        let a = assertion(
            "_assert-1",
            "alice@corp.example",
            "https://attacker.example/sp",
            ACS,
            &rfc3339_offset(1),
            &rfc3339_offset(1),
            "_req-1",
        );
        let p = parse_saml_response(&response(&a, true, "_req-1")).unwrap();
        let err = validate_assertion(&p, &ctx("_req-1")).unwrap_err();
        assert!(err.contains("AudienceRestriction"), "{err}");
    }

    #[test]
    fn wrong_recipient_rejected() {
        let a = assertion(
            "_assert-1",
            "alice@corp.example",
            ISS,
            "https://attacker.example/acs",
            &rfc3339_offset(1),
            &rfc3339_offset(1),
            "_req-1",
        );
        let p = parse_saml_response(&response(&a, true, "_req-1")).unwrap();
        let err = validate_assertion(&p, &ctx("_req-1")).unwrap_err();
        assert!(err.contains("Recipient"), "{err}");
    }

    #[test]
    fn in_response_to_mismatch_rejected() {
        // Assertion says it answers a different AuthnRequest than the one we issued.
        let p = parse_saml_response(&valid_doc("_attacker-req")).unwrap();
        let err = validate_assertion(&p, &ctx("_req-1")).unwrap_err();
        assert!(err.contains("InResponseTo"), "{err}");
    }

    #[test]
    fn unsolicited_rejected_without_flag_but_allowed_with_flag() {
        let a = assertion(
            "_assert-1",
            "alice@corp.example",
            ISS,
            ACS,
            &rfc3339_offset(1),
            &rfc3339_offset(1),
            "", // empty SCD InResponseTo
        );
        let doc = response(&a, true, ""); // empty Response InResponseTo
        let p = parse_saml_response(&doc).unwrap();
        let err = validate_assertion(&p, &ctx("_req-1")).unwrap_err();
        assert!(err.contains("unsolicited"), "{err}");

        let mut c = ctx("_req-1");
        c.allow_unsolicited = true;
        assert_eq!(validate_assertion(&p, &c).unwrap(), "alice@corp.example");
    }

    #[test]
    fn non_success_status_rejected() {
        let a = assertion(
            "_assert-1",
            "alice@corp.example",
            ISS,
            ACS,
            &rfc3339_offset(1),
            &rfc3339_offset(1),
            "_req-1",
        );
        let p = parse_saml_response(&response(&a, false, "_req-1")).unwrap();
        let err = validate_assertion(&p, &ctx("_req-1")).unwrap_err();
        assert!(err.contains("status not Success"), "{err}");
    }

    #[test]
    fn email_from_attribute_when_nameid_not_email() {
        let doc = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" InResponseTo="_req-1">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <ds:Signature><ds:SignedInfo/></ds:Signature>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assert-1">
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">user-123-opaque</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="{ACS}" NotOnOrAfter="{noa}" InResponseTo="_req-1"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="{noa}">
      <saml:AudienceRestriction><saml:Audience>{ISS}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>alice@corp.example</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
            ACS = ACS,
            ISS = ISS,
            noa = rfc3339_offset(1),
        );
        let p = parse_saml_response(&doc).unwrap();
        assert_eq!(p.name_id.as_deref(), Some("user-123-opaque"));
        assert_eq!(p.email_attr.as_deref(), Some("alice@corp.example"));
        assert_eq!(
            validate_assertion(&p, &ctx("_req-1")).unwrap(),
            "alice@corp.example"
        );
    }

    #[test]
    fn injected_response_scope_groups_ignored() {
        // XSW on GROUP claims: the IdP signs ONLY the assertion, which carries NO group
        // attributes. The attacker splices an unsigned <AttributeStatement> with
        // groups=admins at RESPONSE scope (outside the assertion). xmlsec still verifies the
        // intact assertion and the single-assertion check still passes, but the group claim must
        // be scoped to the verified assertion, so the injected group is ignored (empty) and the
        // role cannot be escalated.
        let a = assertion(
            "_assert-1",
            "alice@corp.example",
            ISS,
            ACS,
            &rfc3339_offset(1),
            &rfc3339_offset(1),
            "_req-1",
        );
        let doc = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" InResponseTo="_req-1">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <ds:Signature><ds:SignedInfo/></ds:Signature>
  <saml:AttributeStatement>
    <saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
  {a}
</samlp:Response>"#
        );
        let p = parse_saml_response(&doc).unwrap();
        assert_eq!(p.assertion_count, 1);
        // The injected Response-scope group is outside the assertion -> not collected.
        assert!(
            p.assertion_groups.is_empty(),
            "injected Response-scope groups must be ignored, got {:?}",
            p.assertion_groups
        );
        // Identity still resolves correctly from the verified assertion.
        assert_eq!(
            validate_assertion(&p, &ctx("_req-1")).unwrap(),
            "alice@corp.example"
        );
    }

    #[test]
    fn groups_inside_assertion_collected() {
        // Legitimate case: group AttributeValues INSIDE the signed assertion are collected
        // (sorted + deduped), so authorization mapping is unchanged for honest IdPs.
        let doc = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" InResponseTo="_req-1">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <ds:Signature><ds:SignedInfo/></ds:Signature>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assert-1">
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@corp.example</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="{ACS}" NotOnOrAfter="{noa}" InResponseTo="_req-1"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="{noa}">
      <saml:AudienceRestriction><saml:Audience>{ISS}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="groups">
        <saml:AttributeValue>analysts</saml:AttributeValue>
        <saml:AttributeValue>admins</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
            ACS = ACS,
            ISS = ISS,
            noa = rfc3339_offset(1),
        );
        let p = parse_saml_response(&doc).unwrap();
        assert_eq!(p.assertion_count, 1);
        assert_eq!(
            p.assertion_groups,
            vec!["admins".to_string(), "analysts".to_string()]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL) with migrations applied"]
    async fn replayed_assertion_id_rejected() {
        let url = match std::env::var("TEST_DATABASE_URL")
            .ok()
            .or_else(|| std::env::var("DATABASE_URL").ok())
        {
            Some(u) if !u.trim().is_empty() => u,
            _ => return,
        };
        crate::db::run_migrations(url.trim())
            .await
            .expect("migrations");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(url.trim())
            .await
            .expect("connect");
        // saml_seen_assertions.tenant_id references tenants(id); use a real tenant or skip.
        let tenant_id: i64 =
            match sqlx::query_scalar::<_, i64>("SELECT id FROM tenants ORDER BY id LIMIT 1")
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten()
            {
                Some(id) => id,
                None => return,
            };
        let aid = format!("_replay-{}", uuid::Uuid::new_v4());
        let exp = chrono::Utc::now() + chrono::Duration::minutes(5);
        assert!(
            assertion_replay_guard(&pool, tenant_id, &aid, exp)
                .await
                .unwrap(),
            "first use must insert"
        );
        assert!(
            !assertion_replay_guard(&pool, tenant_id, &aid, exp)
                .await
                .unwrap(),
            "replay must be detected"
        );
        let _ = sqlx::query("DELETE FROM saml_seen_assertions WHERE assertion_id = $1")
            .bind(&aid)
            .execute(&pool)
            .await;
    }
}
