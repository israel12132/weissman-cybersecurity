//! SAML 2.0 HTTP-POST ACS: decode assertion, resolve subject to email, JIT user, session JWT.
//!
//! **Default (production):** responses must be verified with `xmlsec1` (`WEISSMAN_XMLSEC1_BINARY`)
//! using the tenant IdP PEM in `tenant_idps.saml_idp_cert_pem`.
//!
//! **Lab only:** set `WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1` to parse NameID/email from XML without
//! cryptographic verification (never use in production).

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use flate2::read::DeflateDecoder;
use serde::Deserialize;
use serde_json::json;
use std::io::Read;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use tempfile::NamedTempFile;

use crate::audit_log;
use crate::db;
use crate::http::AppState;

#[derive(Deserialize)]
pub struct SamlBeginQuery {
    pub tenant_slug: String,
    pub idp_name: String,
}

#[derive(Deserialize)]
pub struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    pub relay_state: Option<String>,
}

fn public_base_url() -> String {
    std::env::var("WEISSMAN_PUBLIC_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SamlRelay {
    idp_id: i64,
    tenant_id: i64,
    exp: i64,
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

fn extract_email_from_saml_xml(xml: &str) -> Option<String> {
    let re_name =
        regex::Regex::new(r"(?i)<[^:>]*:?NameID[^>]*>([^<@]+@[^<]+)</[^:>]*:?NameID>").ok()?;
    for cap in re_name.captures_iter(xml) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str().trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    // AttributeStatement / mail
    if let Ok(re) = regex::Regex::new(r#"(?i)Name\s*=\s*"[^"]*[Ee]mail[^"]*"[^>]*>([^<@]+@[^<]+)<"#)
    {
        if let Some(cap) = re.captures(xml) {
            if let Some(m) = cap.get(1) {
                let s = m.as_str().trim();
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

fn verify_xmlsec(
    xmlsec_bin: &str,
    xml_path: &std::path::Path,
    pem_path: &std::path::Path,
) -> Result<(), String> {
    let out = Command::new(xmlsec_bin)
        .args([
            "--verify",
            "--pubkey-pem",
            pem_path.to_str().ok_or("pem path")?,
            "--enabled-reference-uris",
            "empty",
            xml_path.to_str().ok_or("xml path")?,
        ])
        .output()
        .map_err(|e| e.to_string())?;
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": format!("{}", e)})),
        )
    })?;
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
    let base = public_base_url().trim_end_matches('/').to_string();
    let acs = format!("{}/api/auth/saml/acs", base);
    let issuer = std::env::var("WEISSMAN_SAML_SP_ISSUER")
        .unwrap_or_else(|_| format!("{}/saml/metadata", base));
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
    let row = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT COALESCE(saml_idp_cert_pem,''), saml_idp_sso_url FROM tenant_idps WHERE id = $1 AND tenant_id = $2 AND provider = 'saml' AND active = true",
    )
    .bind(r.idp_id)
    .bind(r.tenant_id)
    .fetch_optional(auth)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": format!("{}", e)})),
        )
    })?;
    let Some((cert_pem, _sso)) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "SAML IdP not found"})),
        ));
    };
    let xml = decode_saml_xml(&form.saml_response).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": format!("decode: {}", e)})),
        )
    })?;
    let insecure = matches!(
        std::env::var("WEISSMAN_SAML_INSECURE_SKIP_VERIFY")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    let xmlsec_bin = std::env::var("WEISSMAN_XMLSEC1_BINARY").unwrap_or_default();
    if !insecure {
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
        let xml_file = NamedTempFile::new().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("temp: {}", e)})),
            )
        })?;
        std::fs::write(xml_file.path(), xml.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("{}", e)})),
            )
        })?;
        let pem_file = NamedTempFile::new().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("temp: {}", e)})),
            )
        })?;
        std::fs::write(pem_file.path(), cert_pem.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("{}", e)})),
            )
        })?;
        verify_xmlsec(&xmlsec_bin, xml_file.path(), pem_file.path()).map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "detail": format!("SAML xmlsec verify failed: {}", e)})),
            )
        })?;
    }
    let email = extract_email_from_saml_xml(&xml).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "detail": "could not extract email from SAML assertion"})),
        )
    })?;
    weissman_db::auth_access::record_auth_access(auth, r.tenant_id, "saml_acs")
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("auth audit: {}", e)})),
            )
        })?;
    let user_id: i64 = if let Some(uid) = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM auth.v_user_lookup WHERE tenant_id = $1 AND lower(trim(email)) = lower(trim($2)) AND is_active = true",
    )
    .bind(r.tenant_id)
    .bind(&email)
    .fetch_optional(auth)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": format!("{}", e)})),
        )
    })? {
        uid
    } else {
        weissman_db::auth_access::insert_user_auth(auth, r.tenant_id, &email, None, "viewer")
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "detail": format!("provision: {}", e)})),
                )
            })?
    };
    let ip = crate::http::extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, r.tenant_id).await {
        let _ = audit_log::insert_audit(
            &mut tx,
            r.tenant_id,
            Some(user_id),
            email.as_str(),
            "login",
            "SAML session created",
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }
    let (_access_jwt, access_line, refresh_line) =
        crate::auth_refresh::build_session_cookie_headers(auth, user_id, r.tenant_id)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "detail": format!("session: {}", e)})),
                )
            })?;
    let mut res = Redirect::to("/command-center/").into_response();
    if let Ok(v) = HeaderValue::from_str(&access_line) {
        res.headers_mut().append(SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&refresh_line) {
        res.headers_mut().append(SET_COOKIE, v);
    }
    Ok(res)
}
