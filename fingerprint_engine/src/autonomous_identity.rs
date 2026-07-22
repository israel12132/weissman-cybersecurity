//! Zero-config synthetic accounts for BOLA shadow replay: discover auth endpoints, register/login,
//! extract tokens, refresh on 401/403. No pre-seeded `identity_contexts` rows required.

use crate::identity_engine::{extract_jwts_from_text, extract_token_from_response, AuthContext};
use crate::stealth_engine;
use reqwest::header::HeaderMap;
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

const AUTH_TIMEOUT_SECS: u64 = 12;

#[must_use]
pub fn autonomous_identity_enabled() -> bool {
    !matches!(
        std::env::var("WEISSMAN_BOLA_AUTONOMOUS_IDENTITY").as_deref(),
        Ok("0") | Ok("false") | Ok("off")
    )
}

/// Pre-loaded DB contexts (≥2) or live synthetic sessions with self-healing refresh.
#[derive(Clone)]
pub enum IdentityBundle {
    Static(Vec<AuthContext>),
    Live(Arc<IdentityMatrix>),
}

impl IdentityBundle {
    /// Sort static contexts by privilege (desc) for shadow baseline ordering.
    #[must_use]
    pub fn from_db_contexts(mut v: Vec<AuthContext>) -> Self {
        v.sort_by(|a, b| b.privilege_order.cmp(&a.privilege_order));
        Self::Static(v)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            IdentityBundle::Static(v) => v.len(),
            IdentityBundle::Live(m) => m.len(),
        }
    }

    #[must_use]
    pub fn is_shadow_ready(&self) -> bool {
        self.len() >= 2
    }

    #[must_use]
    pub fn context_count(&self) -> usize {
        self.len()
    }
}

/// In-memory session with mutex-protected token (refresh without reallocating matrix).
pub struct IdentityMatrix {
    sessions: Vec<Arc<AutonomousSession>>,
}

impl IdentityMatrix {
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Build [`AuthContext`] for shadow index `idx` (0 = highest `privilege_order`).
    pub async fn auth_context(
        &self,
        idx: usize,
        client: &Client,
        stealth: Option<&stealth_engine::StealthConfig>,
    ) -> Option<AuthContext> {
        let s = self.sessions.get(idx)?;
        s.materialize_auth_context(client, stealth).await
    }

    /// Re-run login for this synthetic user after 401/403.
    pub async fn refresh_session(
        &self,
        idx: usize,
        client: &Client,
        stealth: Option<&stealth_engine::StealthConfig>,
    ) -> bool {
        let Some(s) = self.sessions.get(idx) else {
            return false;
        };
        s.login_and_store(client, stealth).await
    }
}

pub struct AutonomousSession {
    role_name: String,
    privilege_order: i32,
    login_url: String,
    email: String,
    password: String,
    email_field: String,
    password_field: String,
    state: Mutex<SessionMaterial>,
}

#[derive(Clone)]
struct SessionMaterial {
    token_type: String,
    token_value: String,
}

impl AutonomousSession {
    async fn materialize_auth_context(
        &self,
        client: &Client,
        stealth: Option<&stealth_engine::StealthConfig>,
    ) -> Option<AuthContext> {
        {
            let g = self.state.lock().await;
            if !g.token_value.is_empty() {
                return Some(AuthContext {
                    role_name: self.role_name.clone(),
                    privilege_order: self.privilege_order,
                    token_type: g.token_type.clone(),
                    token_value: g.token_value.clone(),
                });
            }
        }
        if self.login_and_store(client, stealth).await {
            let g = self.state.lock().await;
            if !g.token_value.is_empty() {
                return Some(AuthContext {
                    role_name: self.role_name.clone(),
                    privilege_order: self.privilege_order,
                    token_type: g.token_type.clone(),
                    token_value: g.token_value.clone(),
                });
            }
        }
        None
    }

    async fn login_and_store(
        &self,
        client: &Client,
        stealth: Option<&stealth_engine::StealthConfig>,
    ) -> bool {
        if let Some(sleep_ms) = std::env::var("WEISSMAN_AUTO_IDENTITY_LOGIN_GAP_MS")
            .ok()
            .and_then(|x| x.parse::<u64>().ok())
        {
            tokio::time::sleep(std::time::Duration::from_millis(sleep_ms.min(5000))).await;
        }
        if let Some(s) = stealth {
            stealth_engine::apply_jitter(s).await;
        }
        let body = build_creds_json(
            &self.email_field,
            &self.password_field,
            &self.email,
            &self.password,
        );
        let rb = client
            .post(&self.login_url)
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(AUTH_TIMEOUT_SECS))
            .json(&body);
        let rb = apply_stealth_to_req(rb, stealth);
        let Ok(resp) = rb.send().await else {
            return false;
        };
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return false;
        }
        let Some((tt, tv)) = extract_auth_material(&headers, &text) else {
            return false;
        };
        let mut g = self.state.lock().await;
        g.token_type = tt;
        g.token_value = tv;
        true
    }
}

// Forward stealth header application without circular dependency: use local helper.
// bola_idor_engine exposes `bola_apply_stealth` — we use stealth inline here instead to avoid cycle.

impl AutonomousSession {
    fn new(
        role_name: String,
        privilege_order: i32,
        login_url: String,
        email: String,
        password: String,
        email_field: String,
        password_field: String,
    ) -> Self {
        Self {
            role_name,
            privilege_order,
            login_url,
            email,
            password,
            email_field,
            password_field,
            state: Mutex::new(SessionMaterial {
                token_type: "bearer".into(),
                token_value: String::new(),
            }),
        }
    }
}

fn apply_stealth_to_req(
    rb: reqwest::RequestBuilder,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> reqwest::RequestBuilder {
    match stealth {
        Some(s) => rb.headers(stealth_engine::random_morph_headers(s)),
        None => rb,
    }
}

/// Try register (optional) + login for two synthetic users. Returns matrix if both sessions hold tokens.
pub async fn try_provision_identity_matrix(
    client: &Client,
    base_url: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
    spec: Option<&Value>,
) -> Option<Arc<IdentityMatrix>> {
    let base = base_url.trim().trim_end_matches('/');
    let candidates = discover_auth_candidates(spec);
    for (pair_idx, (reg_rel, login_rel, email_k, pass_k)) in candidates.into_iter().enumerate() {
        let login_url = join_url(base, &login_rel);
        let reg_url = reg_rel.as_ref().map(|r| join_url(base, r));
        let mut sessions: Vec<Arc<AutonomousSession>> = Vec::new();
        for user_n in 0..2u32 {
            let email = synthetic_email(pair_idx as u32 * 8 + user_n);
            let password = synthetic_password();
            if let Some(ref ru) = reg_url {
                post_auth_json(
                    client,
                    ru,
                    &build_creds_json(&email_k, &pass_k, &email, &password),
                    stealth,
                )
                .await;
            }
            let session = Arc::new(AutonomousSession::new(
                format!("synthetic_user_{}", sessions.len() + 1),
                if sessions.is_empty() { 2 } else { 1 },
                login_url.clone(),
                email,
                password,
                email_k.clone(),
                pass_k.clone(),
            ));
            if session.login_and_store(client, stealth).await {
                sessions.push(session);
            }
        }
        if sessions.len() >= 2 {
            return Some(Arc::new(IdentityMatrix { sessions }));
        }
    }
    None
}

fn join_url(base: &str, path: &str) -> String {
    let p = path.trim();
    let p = if p.starts_with('/') {
        p
    } else {
        return format!("{base}/{p}");
    };
    format!("{}{}", base.trim_end_matches('/'), p)
}

fn synthetic_email(salt: u32) -> String {
    format!(
        "ws{:x}{:x}@auto.weissman.local",
        salt,
        rand::random::<u32>()
    )
}

fn synthetic_password() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrst23456789!@#$%";
    (0..22)
        .map(|_| {
            let i = rng.random_range(0..CHARSET.len());
            CHARSET[i] as char
        })
        .collect()
}

fn build_creds_json(email_k: &str, pass_k: &str, email: &str, password: &str) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(email_k.to_string(), Value::String(email.to_string()));
    m.insert(pass_k.to_string(), Value::String(password.to_string()));
    Value::Object(m)
}

async fn post_auth_json(
    client: &Client,
    url: &str,
    body: &Value,
    stealth: Option<&stealth_engine::StealthConfig>,
) {
    if let Some(s) = stealth {
        stealth_engine::apply_jitter(s).await;
    }
    let rb = client
        .post(url)
        .header("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(AUTH_TIMEOUT_SECS))
        .json(body);
    let rb = apply_stealth_to_req(rb, stealth);
    let _ = rb.send().await;
}

/// (register_path_opt, login_path, email_field, password_field)
type AuthCandidate = (Option<String>, String, String, String);

fn discover_auth_candidates(spec: Option<&Value>) -> Vec<AuthCandidate> {
    let mut out: Vec<AuthCandidate> = Vec::new();
    if let Some(spec) = spec {
        if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
            let mut reg: Option<(String, String, String)> = None;
            let mut login: Option<(String, String, String)> = None;
            for (path, item) in paths {
                let Some(obj) = item.as_object() else {
                    continue;
                };
                for (method, opv) in obj {
                    if !matches!(method.as_str(), "post" | "put") {
                        continue;
                    }
                    let Some(op) = opv.as_object() else {
                        continue;
                    };
                    let mut hint = path.to_lowercase();
                    hint.push(' ');
                    hint.push_str(
                        &op.get("summary")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_lowercase(),
                    );
                    hint.push(' ');
                    hint.push_str(
                        &op.get("operationId")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_lowercase(),
                    );
                    let (ek, pk) = infer_credential_keys(op);
                    if reg.is_none()
                        && (hint.contains("register")
                            || hint.contains("signup")
                            || hint.contains("sign-up")
                            || hint.contains("sign_up"))
                    {
                        reg = Some((path.clone(), ek.clone(), pk.clone()));
                    }
                    if login.is_none()
                        && (hint.contains("login")
                            || hint.contains("signin")
                            || hint.contains("sign-in")
                            || hint.contains("session")
                            || (hint.contains("token") && hint.contains("auth")))
                    {
                        login = Some((path.clone(), ek, pk));
                    }
                }
            }
            if let Some((lp, ek, pk)) = login {
                let rr = reg.map(|(p, _, _)| p);
                out.push((rr, lp, ek, pk));
            }
        }
    }
    // Heuristic fallbacks (Juice Shop, common SPA APIs)
    out.extend([
        (
            Some("/rest/user/registration".into()),
            "/rest/user/login".into(),
            "email".into(),
            "password".into(),
        ),
        (
            None,
            "/api/auth/login".into(),
            "email".into(),
            "password".into(),
        ),
        (
            Some("/api/auth/register".into()),
            "/api/auth/login".into(),
            "email".into(),
            "password".into(),
        ),
        (
            None,
            "/api/v1/auth/login".into(),
            "email".into(),
            "password".into(),
        ),
        (
            Some("/api/v1/auth/register".into()),
            "/api/v1/auth/login".into(),
            "email".into(),
            "password".into(),
        ),
        (
            None,
            "/auth/login".into(),
            "email".into(),
            "password".into(),
        ),
        (
            Some("/auth/register".into()),
            "/auth/login".into(),
            "email".into(),
            "password".into(),
        ),
        (
            None,
            "/api/users/login".into(),
            "username".into(),
            "password".into(),
        ),
    ]);
    out
}

fn infer_credential_keys(op: &serde_json::Map<String, Value>) -> (String, String) {
    let mut email_k = "email".to_string();
    let mut pass_k = "password".to_string();
    let Some(rb) = op
        .get("requestBody")
        .and_then(|b| b.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|j| j.get("schema"))
    else {
        return (email_k, pass_k);
    };
    let props = rb
        .get("properties")
        .and_then(|p| p.as_object())
        .cloned()
        .unwrap_or_default();
    for k in props.keys() {
        let kl = k.to_lowercase();
        if kl.contains("mail") || kl == "username" || kl == "user" {
            email_k = k.clone();
        }
        if kl.contains("pass") || kl == "pwd" {
            pass_k = k.clone();
        }
    }
    (email_k, pass_k)
}

fn extract_auth_material(headers: &HeaderMap, body: &str) -> Option<(String, String)> {
    if let Some((t, is_cookie)) = extract_token_from_response(headers, body) {
        let tt = if is_cookie { "cookie" } else { "bearer" };
        return Some((tt.to_string(), t));
    }
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        for keys in [
            &["authentication", "token"][..],
            &["data", "token"][..],
            &["data", "access_token"][..],
        ] {
            let mut cur = &v;
            for key in keys {
                cur = cur.get(*key)?;
            }
            if let Some(s) = cur.as_str() {
                if !s.is_empty() {
                    if extract_jwts_from_text(s).first().is_some() || s.len() > 40 {
                        return Some(("bearer".into(), s.to_string()));
                    }
                }
            }
        }
        for key in [
            "access_token",
            "accessToken",
            "token",
            "id_token",
            "idToken",
            "jwt",
        ] {
            if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    return Some(("bearer".into(), s.to_string()));
                }
            }
        }
    }
    cookie_header_from_set_cookie(headers)
}

fn cookie_header_from_set_cookie(headers: &HeaderMap) -> Option<(String, String)> {
    let mut parts: Vec<String> = Vec::new();
    for v in headers.get_all(reqwest::header::SET_COOKIE) {
        if let Ok(s) = v.to_str() {
            if let Some(first) = s.split(';').next() {
                let t = first.trim();
                if t.contains('=') && t.len() > 5 {
                    parts.push(t.to_string());
                }
            }
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(("cookie".into(), parts.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderValue, SET_COOKIE};
    use serde_json::json;

    fn ctx(privilege_order: i32) -> AuthContext {
        AuthContext {
            role_name: format!("role_{privilege_order}"),
            privilege_order,
            token_type: "bearer".into(),
            token_value: "tok".into(),
        }
    }

    #[test]
    fn from_db_contexts_sorts_by_privilege_desc() {
        let b = IdentityBundle::from_db_contexts(vec![ctx(1), ctx(3), ctx(2)]);
        match &b {
            IdentityBundle::Static(v) => {
                assert_eq!(v[0].privilege_order, 3);
                assert_eq!(v[1].privilege_order, 2);
                assert_eq!(v[2].privilege_order, 1);
            }
            _ => panic!("expected Static variant"),
        }
        assert_eq!(b.len(), 3);
        assert_eq!(b.context_count(), 3);
        assert!(b.is_shadow_ready());
    }

    #[test]
    fn shadow_ready_needs_two() {
        let one = IdentityBundle::from_db_contexts(vec![ctx(5)]);
        assert_eq!(one.len(), 1);
        assert!(!one.is_shadow_ready());
        let empty = IdentityBundle::from_db_contexts(vec![]);
        assert!(!empty.is_shadow_ready());
    }

    #[test]
    fn join_url_absolute_path() {
        assert_eq!(join_url("http://h", "/a"), "http://h/a");
        assert_eq!(join_url("http://h/", "/a"), "http://h/a");
    }

    #[test]
    fn join_url_relative_path() {
        assert_eq!(join_url("http://h", "rel"), "http://h/rel");
    }

    #[test]
    fn join_url_trims_whitespace() {
        assert_eq!(join_url("http://h", " /x "), "http://h/x");
    }

    #[test]
    fn build_creds_json_uses_supplied_keys() {
        assert_eq!(
            build_creds_json("email", "password", "a@b.com", "pw"),
            json!({"email": "a@b.com", "password": "pw"})
        );
        assert_eq!(
            build_creds_json("username", "pwd", "bob", "secret"),
            json!({"username": "bob", "pwd": "secret"})
        );
    }

    #[test]
    fn discover_candidates_fallbacks_when_no_spec() {
        let out = discover_auth_candidates(None);
        assert_eq!(out.len(), 8);
        assert_eq!(
            out[0],
            (
                Some("/rest/user/registration".to_string()),
                "/rest/user/login".to_string(),
                "email".to_string(),
                "password".to_string()
            )
        );
        assert_eq!(
            out[7],
            (
                None,
                "/api/users/login".to_string(),
                "username".to_string(),
                "password".to_string()
            )
        );
    }

    #[test]
    fn discover_candidates_login_only_from_spec() {
        let spec = json!({"paths": {"/signin": {"post": {"summary": "User Login"}}}});
        let out = discover_auth_candidates(Some(&spec));
        assert_eq!(out.len(), 9); // 1 derived + 8 fallbacks
        assert_eq!(
            out[0],
            (
                None,
                "/signin".to_string(),
                "email".to_string(),
                "password".to_string()
            )
        );
    }

    #[test]
    fn discover_candidates_register_and_login_from_spec() {
        let spec = json!({"paths": {
            "/register": {"post": {"operationId": "registerUser"}},
            "/login": {"post": {"summary": "login"}}
        }});
        let out = discover_auth_candidates(Some(&spec));
        assert_eq!(out.len(), 9);
        assert_eq!(
            out[0],
            (
                Some("/register".to_string()),
                "/login".to_string(),
                "email".to_string(),
                "password".to_string()
            )
        );
    }

    #[test]
    fn infer_credential_keys_defaults() {
        let op = json!({});
        let (e, p) = infer_credential_keys(op.as_object().unwrap());
        assert_eq!(e, "email");
        assert_eq!(p, "password");
    }

    #[test]
    fn infer_credential_keys_from_schema_props() {
        let op = json!({
            "requestBody": {"content": {"application/json": {"schema": {"properties": {
                "userEmail": {"type": "string"},
                "pwd": {"type": "string"}
            }}}}}
        });
        let (e, p) = infer_credential_keys(op.as_object().unwrap());
        assert_eq!(e, "userEmail");
        assert_eq!(p, "pwd");
    }

    #[test]
    fn infer_credential_keys_username_password() {
        let op = json!({
            "requestBody": {"content": {"application/json": {"schema": {"properties": {
                "username": {"type": "string"},
                "password": {"type": "string"}
            }}}}}
        });
        let (e, p) = infer_credential_keys(op.as_object().unwrap());
        assert_eq!(e, "username");
        assert_eq!(p, "password");
    }

    #[test]
    fn cookie_header_joins_first_parts() {
        let mut h = HeaderMap::new();
        h.append(
            SET_COOKIE,
            HeaderValue::from_static("session=abcdef; Path=/; HttpOnly"),
        );
        h.append(
            SET_COOKIE,
            HeaderValue::from_static("token=xyz12345; Secure"),
        );
        assert_eq!(
            cookie_header_from_set_cookie(&h),
            Some((
                "cookie".to_string(),
                "session=abcdef; token=xyz12345".to_string()
            ))
        );
    }

    #[test]
    fn cookie_header_none_when_empty() {
        let h = HeaderMap::new();
        assert_eq!(cookie_header_from_set_cookie(&h), None);
    }

    #[test]
    fn cookie_header_skips_short_values() {
        let mut h = HeaderMap::new();
        // "a=b" trims to len 3 (<= 5) so it is skipped, leaving nothing.
        h.append(SET_COOKIE, HeaderValue::from_static("a=b; Path=/"));
        assert_eq!(cookie_header_from_set_cookie(&h), None);
    }

    #[test]
    fn synthetic_email_encodes_salt_hex() {
        let e0 = synthetic_email(0);
        assert!(e0.starts_with("ws0"), "got {e0}");
        assert!(e0.ends_with("@auto.weissman.local"), "got {e0}");
        let e255 = synthetic_email(255);
        assert!(e255.starts_with("wsff"), "got {e255}");
    }

    #[test]
    fn synthetic_password_length_and_charset() {
        const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrst23456789!@#$%";
        let p = synthetic_password();
        assert_eq!(p.chars().count(), 22);
        assert!(
            p.bytes().all(|b| CHARSET.contains(&b)),
            "unexpected char in {p}"
        );
    }
}
