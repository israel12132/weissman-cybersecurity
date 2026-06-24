//! Cross-protocol Memory Intelligence Bus — real artifact sharing between WebSocket and HTTP engines.
//!
//! Only **WS-captured** artifacts (tokens/IDs observed in server frames, SignalR negotiate, etc.)
//! are eligible for cross-protocol replay. Operator-supplied scan credentials are never published.

use crate::engine_probes::{http_get, http_get_with_headers, HttpProbe};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// A captured credential or session handle suitable for cross-protocol replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntelArtifact {
    pub kind: String,
    pub value: String,
    pub source_url: String,
    pub source_engine: String,
    pub proof: String,
    pub captured_unix_ms: u64,
}

#[derive(Default)]
pub struct IntelligenceBus {
    inner: Mutex<Vec<IntelArtifact>>,
}

impl IntelligenceBus {
    #[must_use]
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn publish(&self, artifact: IntelArtifact) {
        if !is_cross_protocol_eligible(&artifact) {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.iter().any(|a| a.kind == artifact.kind && a.value == artifact.value) {
            return;
        }
        g.push(artifact);
    }

    pub fn publish_token(&self, kind: &str, value: &str, source_url: &str, proof: &str) {
        if value.trim().is_empty() {
            return;
        }
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.publish(IntelArtifact {
            kind: kind.to_string(),
            value: value.to_string(),
            source_url: source_url.to_string(),
            source_engine: "websocket_attack".to_string(),
            proof: proof.to_string(),
            captured_unix_ms: ts,
        });
    }

    pub fn snapshot(&self) -> Vec<IntelArtifact> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn snapshot_for_cross_protocol(&self) -> Vec<IntelArtifact> {
        self.snapshot()
            .into_iter()
            .filter(|a| is_cross_protocol_eligible(a))
            .collect()
    }

    pub fn export_json(&self) -> Value {
        json!(self.snapshot_for_cross_protocol())
    }
}

/// Proofs that indicate the artifact was observed from the target — not operator-supplied creds.
#[must_use]
pub fn is_cross_protocol_eligible(artifact: &IntelArtifact) -> bool {
    let proof = artifact.proof.to_ascii_lowercase();
    if proof.contains("operator")
        || proof.contains("supplied")
        || proof.contains("cswsh_handshake")
        || proof.contains("message_session")
        || proof.contains("stateful_fuzz_session")
    {
        return false;
    }
    proof.starts_with("jwt_pattern")
        || proof.starts_with("json_key_")
        || proof.contains("signalr")
        || proof.contains("negotiate")
        || proof.contains("socketio")
        || proof.contains("ws_frame")
        || proof.contains("binary_frame")
}

/// Reorder batch engines so WebSocket runs before HTTP consumers of the Intelligence Bus.
#[must_use]
pub fn prioritize_ws_intelligence_chain(mut engines: Vec<String>) -> Vec<String> {
    let ws_pos = engines.iter().position(|e| e == "websocket_attack");
    let gql_pos = engines.iter().position(|e| e == "graphql_attack");
    if let (Some(ws), Some(gql)) = (ws_pos, gql_pos) {
        if ws > gql {
            let ws_id = engines.remove(ws);
            let insert_at = engines.iter().position(|e| e == "graphql_attack").unwrap_or(gql);
            engines.insert(insert_at, ws_id);
        }
    }
    engines
}

/// Apply WS-captured artifacts into scan `job_params` for downstream HTTP/API engines.
pub fn merge_params_artifacts(params: &mut Value, bus: &IntelligenceBus) {
    let arts = bus.export_json();
    if arts.as_array().is_some_and(|a| a.is_empty()) {
        return;
    }
    if let Some(obj) = params.as_object_mut() {
        obj.insert("intelligence_artifacts".into(), arts);
    }
}

/// Inject cross-protocol artifacts into HTTP header list when explicit auth is absent.
pub fn apply_intelligence_artifacts_to_headers(
    params: &Value,
    extra_headers: &mut Vec<(String, String)>,
) {
    let has_auth = extra_headers.iter().any(|(k, _)| {
        let kl = k.to_ascii_lowercase();
        kl == "authorization" || kl == "cookie"
    });
    if has_auth {
        return;
    }
    let Some(arr) = params.get("intelligence_artifacts").and_then(Value::as_array) else {
        return;
    };
    for art in arr {
        let kind = art.get("kind").and_then(Value::as_str).unwrap_or("");
        let value = art.get("value").and_then(Value::as_str).unwrap_or("");
        let proof = art.get("proof").and_then(Value::as_str).unwrap_or("");
        if value.is_empty() {
            continue;
        }
        let probe = IntelArtifact {
            kind: kind.to_string(),
            value: value.to_string(),
            source_url: String::new(),
            source_engine: String::new(),
            proof: proof.to_string(),
            captured_unix_ms: 0,
        };
        if !is_cross_protocol_eligible(&probe) {
            continue;
        }
        match kind {
            "cookie" | "session_cookie" => {
                if !extra_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
                    extra_headers.push(("Cookie".to_string(), value.to_string()));
                }
            }
            "bearer" | "jwt" | "access_token" | "token" | "connectionToken" | "connectionId" => {
                if !extra_headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                {
                    let bearer = if value.starts_with("Bearer ") {
                        value.to_string()
                    } else {
                        format!("Bearer {value}")
                    };
                    extra_headers.push(("Authorization".to_string(), bearer));
                }
            }
            "api_key" => {
                if !extra_headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("x-api-key"))
                {
                    extra_headers.push(("X-Api-Key".to_string(), value.to_string()));
                }
            }
            _ => {}
        }
    }
}

/// Deterministic HTTP replay: unauthenticated baseline vs artifact-authenticated request.
pub async fn verify_http_privilege_escalation(
    client: &Client,
    http_base: &str,
    artifact: &IntelArtifact,
    probe_paths: &[&str],
) -> Option<HttpEscalationProof> {
    if !is_cross_protocol_eligible(artifact) {
        return None;
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    match artifact.kind.as_str() {
        "cookie" | "session_cookie" => headers.push(("Cookie".to_string(), artifact.value.clone())),
        "bearer" | "jwt" | "access_token" => {
            headers.push((
                "Authorization".to_string(),
                if artifact.value.starts_with("Bearer ") {
                    artifact.value.clone()
                } else {
                    format!("Bearer {}", artifact.value)
                },
            ));
        }
        "api_key" => headers.push(("X-Api-Key".to_string(), artifact.value.clone())),
        "connectionToken" | "connectionId" | "token" | "sid" | "sessionId" | "session_id" => {
            headers.push(("Authorization".to_string(), format!("Bearer {}", artifact.value)));
        }
        _ => headers.push(("Authorization".to_string(), artifact.value.clone())),
    }

    for path in probe_paths {
        let url = format!(
            "{}/{}",
            http_base.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let unauth = http_get(client, &url).await?;
        let auth = http_get_with_headers(
            client,
            &url,
            &headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>(),
        )
        .await?;
        if proof_escalation(&unauth, &auth) {
            return Some(HttpEscalationProof {
                url,
                artifact_kind: artifact.kind.clone(),
                unauth_status: unauth.status,
                auth_status: auth.status,
                unauth_len: unauth.body.len(),
                auth_len: auth.body.len(),
                auth_body_preview: auth.body.chars().take(240).collect(),
            });
        }
    }
    None
}

#[derive(Clone, Debug)]
pub struct HttpEscalationProof {
    pub url: String,
    pub artifact_kind: String,
    pub unauth_status: u16,
    pub auth_status: u16,
    pub unauth_len: usize,
    pub auth_len: usize,
    pub auth_body_preview: String,
}

fn proof_escalation(unauth: &HttpProbe, auth: &HttpProbe) -> bool {
    if auth.status >= 400 {
        return false;
    }
    if unauth.status == auth.status && unauth.body.len().abs_diff(auth.body.len()) < 16 {
        return false;
    }
    let u = unauth.body.to_ascii_lowercase();
    let a = auth.body.to_ascii_lowercase();
    let unauth_denied = u.contains("unauthorized")
        || u.contains("forbidden")
        || u.contains("login")
        || unauth.status == 401
        || unauth.status == 403;
    let auth_granted = auth.status == 200
        || auth.status == 201
        || (auth.status < 400 && !a.contains("unauthorized") && !a.contains("forbidden"));
    if unauth_denied && auth_granted && auth.body.len() > unauth.body.len().saturating_add(20) {
        return true;
    }
    if unauth.status >= 400 && auth.status == 200 && auth.body.len() > 32 {
        return true;
    }
    false
}

/// Extract publishable artifacts from a WebSocket server frame (JWT, session ids).
pub fn artifacts_from_ws_frame(text: &str, source_url: &str) -> Vec<IntelArtifact> {
    let mut out = Vec::new();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    for token in text.split(|c: char| c.is_whitespace() || c == '"' || c == ',') {
        if token.starts_with("eyJ") && token.matches('.').count() >= 2 && token.len() > 40 {
            out.push(IntelArtifact {
                kind: "jwt".into(),
                value: token.to_string(),
                source_url: source_url.to_string(),
                source_engine: "websocket_attack".into(),
                proof: "jwt_pattern_in_ws_frame".into(),
                captured_unix_ms: ts,
            });
        }
    }
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        for key in [
            "sid",
            "sessionId",
            "session_id",
            "connectionId",
            "connectionToken",
            "token",
            "access_token",
        ] {
            if let Some(s) = v.get(key).and_then(Value::as_str) {
                if !s.is_empty() {
                    out.push(IntelArtifact {
                        kind: key.to_string(),
                        value: s.to_string(),
                        source_url: source_url.to_string(),
                        source_engine: "websocket_attack".into(),
                        proof: format!("json_key_{key}_in_ws_frame"),
                        captured_unix_ms: ts,
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_detects_auth_differential() {
        let unauth = HttpProbe {
            status: 401,
            headers: vec![],
            body: "unauthorized".into(),
            final_url: "https://x/api/me".into(),
        };
        let auth = HttpProbe {
            status: 200,
            headers: vec![],
            body: r#"{"user":"admin","role":"administrator"}"#.into(),
            final_url: "https://x/api/me".into(),
        };
        assert!(proof_escalation(&unauth, &auth));
    }

    #[test]
    fn extracts_jwt_from_frame() {
        let arts = artifacts_from_ws_frame(
            r#"{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"}"#,
            "wss://x/ws",
        );
        assert!(arts.iter().any(|a| a.kind == "jwt" || a.kind == "token"));
    }

    #[test]
    fn rejects_operator_supplied_artifacts() {
        let op = IntelArtifact {
            kind: "cookie".into(),
            value: "session=abc".into(),
            source_url: "wss://x/ws".into(),
            source_engine: "websocket_attack".into(),
            proof: "authenticated_cswsh_handshake".into(),
            captured_unix_ms: 0,
        };
        assert!(!is_cross_protocol_eligible(&op));
        let bus = IntelligenceBus::default();
        bus.publish(op);
        assert!(bus.snapshot().is_empty());
    }

    #[test]
    fn merge_params_injects_artifacts() {
        let bus = IntelligenceBus::default();
        bus.publish_token("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x", "wss://x/ws", "jwt_pattern_in_ws_frame");
        let mut params = json!({});
        merge_params_artifacts(&mut params, &bus);
        assert!(params.get("intelligence_artifacts").is_some());
    }

    #[test]
    fn ws_runs_before_graphql_in_chain() {
        let ordered = prioritize_ws_intelligence_chain(vec![
            "graphql_attack".into(),
            "websocket_attack".into(),
            "jwt_attack".into(),
        ]);
        assert_eq!(ordered[0], "websocket_attack");
        assert_eq!(ordered[1], "graphql_attack");
    }
}
