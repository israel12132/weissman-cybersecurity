//! Stateful conversational WebSocket fuzzing — async state machine on one persistent session.

use crate::ws_session::{exchange_phases, WsConnectOpts};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Clone, Debug, Default)]
pub struct SessionVars {
    pub vars: HashMap<String, String>,
    pub depth: u8,
}

#[derive(Clone, Debug, Default)]
pub struct ConvFuzzResult {
    pub states_visited: Vec<String>,
    pub frames_sent: Vec<String>,
    pub frames_received: Vec<String>,
    pub frames_received_binary: Vec<Vec<u8>>,
    pub mutation_accepted: bool,
    pub idor_surface: bool,
    pub auth_bypass_hint: bool,
}

fn key_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)"(sid|session_?id|connection_?id|connection_?token|token|auth|id|user_?id|channel|subscription_?id)"\s*:\s*"([^"]+)""#)
            .expect("session key regex")
    })
}

/// Ingest a server text frame — extract constraints for the state machine.
pub fn ingest_server_frame(text: &str, session: &mut SessionVars) {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        extract_json_vars(&v, session, "");
    }
    for cap in key_regex().captures_iter(text) {
        if let (Some(k), Some(val)) = (cap.get(1), cap.get(2)) {
            session.vars.insert(k.as_str().to_ascii_lowercase(), val.as_str().to_string());
        }
    }
}

fn extract_json_vars(v: &Value, session: &mut SessionVars, prefix: &str) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let key = if prefix.is_empty() {
                    k.to_ascii_lowercase()
                } else {
                    format!("{prefix}.{k}").to_ascii_lowercase()
                };
                if let Some(s) = val.as_str() {
                    if !s.is_empty() && s.len() < 512 {
                        session.vars.insert(key, s.to_string());
                    }
                } else if val.is_number() {
                    session.vars.insert(key, val.to_string());
                } else {
                    extract_json_vars(val, session, &key);
                }
            }
        }
        Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                extract_json_vars(item, session, &format!("{prefix}[{i}]"));
            }
        }
        _ => {}
    }
}

/// Build mutation payloads using live session variables (IDOR / role / type confusion).
pub fn mutation_frames(session: &SessionVars) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in &session.vars {
        let kl = k.to_ascii_lowercase();
        if kl.contains("id") || kl.contains("token") || kl.contains("sid") {
            out.push(json!({"type":"subscribe","id":"weissman-mut","payload":{k: "1"}}).to_string());
            out.push(json!({"type":"subscribe","id":"weissman-mut2","payload":{k: v}}).to_string());
            out.push(
                json!({"type":"message","payload":{k: "00000000-0000-0000-0000-000000000001"}})
                    .to_string(),
            );
        }
        if kl.contains("role") || kl.contains("admin") {
            out.push(json!({"type":"auth","payload":{k: "administrator"}}).to_string());
            out.push(json!({"type":"auth","payload":{k: "superuser"}}).to_string());
        }
    }
    if out.is_empty() {
        out.push(json!({"type":"subscribe","id":"weissman-fallback","payload":{"id":1}}).to_string());
    }
    out.sort();
    out.dedup();
    out.truncate(8);
    out
}

fn initial_handshake_frames(framework: Option<&str>, subproto: Option<&str>) -> Vec<String> {
    let mut frames = vec![json!({"type":"connection_init","payload":{}}).to_string()];
    let fw = framework.unwrap_or("");
    let sp = subproto.unwrap_or("").to_ascii_lowercase();
    if fw.contains("GraphQL") || sp.contains("graphql") {
        frames.push(r#"{"type":"subscribe","id":"conv-1","payload":{"query":"{ __typename }"}}"#.to_string());
    }
    if fw.contains("Socket.IO") {
        frames.push("40".to_string());
    }
    if fw.contains("SignalR") {
        frames.push(r#"{"protocol":"json","version":1}"#.to_string());
    }
    frames
}

fn analyze_mutations(recv: &[String], sent: &[String]) -> (bool, bool, bool) {
    let joined = recv.join("\n").to_ascii_lowercase();
    let mutation_accepted = recv.len() > 1
        && (joined.contains("\"type\":\"next\"")
            || joined.contains("connection_ack")
            || joined.contains("\"success\":true")
            || joined.contains("subscribed"));
    let idor_surface = sent.iter().any(|s| s.contains("\"id\":1") || s.contains("00000000-0000"))
        && mutation_accepted
        && !joined.contains("unauthorized")
        && !joined.contains("forbidden");
    let auth_bypass_hint = mutation_accepted
        && !joined.contains("authentication")
        && !joined.contains("unauthorized")
        && recv.iter().any(|r| r.len() > 40);
    (mutation_accepted, idor_surface, auth_bypass_hint)
}

/// Run conversational fuzzing on **one** WebSocket connection (persistent session).
pub async fn run_conversational_fuzz(
    http_url: &str,
    opts: &WsConnectOpts,
    framework: Option<&str>,
    subproto: Option<&str>,
    max_rounds: u8,
) -> Option<ConvFuzzResult> {
    let mut session = SessionVars::default();
    let visited = vec!["Init".into(), "AwaitChallenge".into(), "InjectMutations".into()];

    let handshake = initial_handshake_frames(framework, subproto);
    let phase1 = handshake;
    let phase2 = mutation_frames(&session);

    let ex = exchange_phases(http_url, opts, &[phase1, phase2]).await?;

    let mut all_recv = ex.received.clone();
    let mut all_sent = ex.sent.clone();
    for frame in &ex.received {
        ingest_server_frame(frame, &mut session);
    }

    // Second mutation round with live-extracted constraints (if rounds > 1).
    if max_rounds > 1 && !session.vars.is_empty() {
        let phase3 = mutation_frames(&session);
        if let Some(ex2) = crate::ws_session::exchange_frames(http_url, opts, &phase3, &[]).await {
            all_sent.extend(ex2.sent);
            for frame in &ex2.received {
                ingest_server_frame(frame, &mut session);
                all_recv.push(frame.clone());
            }
        }
    }

    session.depth = session.depth.saturating_add(1);
    let (mutation_accepted, idor_surface, auth_bypass_hint) =
        analyze_mutations(&all_recv, &all_sent);

    Some(ConvFuzzResult {
        states_visited: visited,
        frames_sent: all_sent,
        frames_received: all_recv,
        frames_received_binary: ex.received_binary,
        mutation_accepted,
        idor_surface,
        auth_bypass_hint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingests_json_session_id() {
        let mut s = SessionVars::default();
        ingest_server_frame(r#"{"sid":"abc123","type":"welcome"}"#, &mut s);
        assert!(s.vars.contains_key("sid"));
    }

    #[test]
    fn mutations_from_session_vars() {
        let mut s = SessionVars::default();
        s.vars.insert("session_id".into(), "live-sid".into());
        let m = mutation_frames(&s);
        assert!(!m.is_empty());
    }

    #[test]
    fn analyze_detects_idor_surface() {
        let recv = vec![
            "welcome".into(),
            r#"{"type":"next","payload":{"id":1}}"#.into(),
        ];
        let sent = vec![r#"{"payload":{"id":1}}"#.into()];
        let (ok, idor, _) = analyze_mutations(&recv, &sent);
        assert!(ok);
        assert!(idor);
    }
}
