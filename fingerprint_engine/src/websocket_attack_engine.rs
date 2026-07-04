//! WebSocket Security Engine — world-class, agentless WebSocket attack-surface assessment.
//!
//! Modelled on the WebSocket testing that defines modern API-security tooling (PortSwigger, Salt
//! Security, Akamai/Cloudflare). Every finding is backed by a real RFC 6455 handshake — nothing is
//! simulated, and the engine does not over-claim:
//!
//!   * **Confirmed WebSocket endpoints** — a real upgrade handshake whose `Sec-WebSocket-Accept`
//!     header is *cryptographically verified* (`base64(sha1(key + GUID))`). This distinguishes a
//!     genuine RFC 6455 server from a coincidental 101, eliminating false positives.
//!   * **Cross-Site WebSocket Hijacking (CSWSH) — differential, not a guess** — performs the
//!     handshake from a legitimate same-origin and from a foreign origin and compares: only when the
//!     foreign origin is *also* accepted is Origin validation reported as missing. When an operator
//!     session cookie is supplied and the foreign-origin + cookie handshake still succeeds, an
//!     *authenticated* CSWSH (session-riding) is confirmed (critical).
//!   * **Cleartext WebSocket (`ws://`)** — unencrypted transport (token/data interception).
//!   * **Unauthenticated endpoints**, **permessage-deflate** compression, and framework
//!     fingerprinting (Socket.IO / SignalR / Action Cable / graphql-ws).
//!   * **Null-Origin & missing-Origin CSWSH** — real bypass classes (`Origin: null` from
//!     sandboxed iframes; handshake with no Origin header) that many WAFs miss.
//!   * **Subprotocol smuggling** — offers privileged subprotocol names and reports when the server
//!     echoes one without authentication (graphql-ws, STOMP, OCPP, etc.).
//!   * **Real-time stack chains** — SignalR `/negotiate` token discovery and Socket.IO polling
//!     `sid` extraction (HTTP probes that precede the WebSocket upgrade in production stacks).
//!   * **TLS downgrade** — when the origin is HTTPS, probes cleartext `http://` on the same paths
//!     and reports verified handshakes (native clients / mixed-content bypass class).
//!   * **X-Forwarded-* proxy CSWSH** — foreign Origin combined with X-Forwarded-Host/Proto to
//!     detect reverse-proxy Origin reconstruction bypasses.
//!   * **Post-handshake message probing** — after a verified upgrade, opens a real WebSocket
//!     session (native TLS, same cert policy as HTTP probes) and exchanges live frames: GraphQL
//!     `connection_init` / `subscribe`, STOMP `CONNECT`, Socket.IO `40`, Action Cable subscribe,
//!     plus operator-supplied custom messages. Nothing is simulated — every finding cites frames
//!     actually sent and received.
//!   * **Real-time sensitive-data flow analysis** — server frames are scanned for JWTs, cloud
//!     access keys, bearer tokens, private-key material, and high-entropy secret-like strings
//!     before subscription auth completes (message-level exfil class).
//!   * **Message reflection / DOM XSS via WS** — injects a unique marker through the socket and
//!     reports when the server echoes it unsanitized (client-side XSS when the app renders WS data).
//!   * **JavaScript WebSocket URL harvest** — regex-mines page source for `ws://` / `wss://` URLs
//!     and `new WebSocket("…")` literals, auto-expanding the path list beyond defaults.
//!   * **Auth-differential message probing** — when session credentials are supplied, runs identical
//!     probe frames with and without auth and compares server responses; flags when unauthenticated
//!     peers receive the same sensitive or subscription data as authenticated sessions.
//!   * **Foreign-origin live session abuse** — opens a real WebSocket from a foreign Origin and
//!     verifies whether application frames (not just the handshake) flow cross-site.
//!   * **Host-header smuggling on upgrade** — `Host` / `X-Forwarded-Host` mismatch vs `Origin` to
//!     catch reverse-proxy routing bugs beyond CSWSH alone.
//!   * **WebSocket protocol-version downgrade** — probes legacy `Sec-WebSocket-Version` values (8/7)
//!     and reports verified upgrades (hybi downgrade class).
//!   * **GraphQL introspection over live graphql-ws** — sends a real introspection subscribe frame
//!     on an open socket and reports schema leakage.
//!   * **Rate-limit absence burst** — rapid ping/message burst on an open session; flags endpoints
//!     that accept unbounded frames (DoS / credential-stuffing surface).
//!   * **Binary frame acceptance** — sends RFC6455 binary frames and reports servers that process
//!     attacker-controlled binary payloads without auth.
//!   * **Stateful conversational fuzzing (Weissman Standard)** — async state machine reads live
//!     server frames, extracts session constraints (IDs, tokens, roles), mutates them, and injects
//!     malicious payloads into subsequent frames in real time.
//!   * **Binary protobuf deep inspection** — wire-walks protobuf frames without a schema, surgically
//!     mutates role/amount fields, re-encodes, and verifies the server processes manipulated binary.
//!   * **Blind race-condition execution** — Tokio barrier-synchronized parallel WebSocket connections
//!     dispatch transactional frames with microsecond timing analysis for atomicity gaps.
//!   * **Cross-protocol attack chaining (Memory Intelligence Bus)** — hijacked WS session artifacts
//!     (JWT, cookie, connectionToken) are published to a shared bus and immediately replayed over
//!     HTTP/API surfaces with deterministic status/body differential proof.
//!
//! ### Wiz-style differentiators
//!   * **Attack-path synthesis** — CSWSH + cookie auth → cross-site session-riding kill chain.
//!   * **Posture score** — a quantified 0–100 grade from observed, verified exposures only.
//!
//! Every knob (paths, origins, auth/cookie, per-check toggles, intensity, caps, timeout,
//! concurrency) is GUI-driven via [`ArsenalConfig`] (`POST /api/command-center/scan` →
//! `EngineRunContext::job_params`).
//!
//! MITRE ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols), T1185 (Browser Session
//! Hijacking), T1040 (Network Sniffing — for cleartext ws://).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, http_get, http_get_with_headers, http_post_json_with_headers,
};
use crate::engine_result::{print_result, EngineResult};
use crate::ws_binary_protocol::{binary_mutation_probe, synthetic_protobuf_seed};
use crate::ws_intelligence_bus::{
    artifacts_from_ws_frame, verify_http_privilege_escalation, IntelligenceBus,
};
use crate::ws_race_executor::{execute_race_burst, RaceConfig};
use crate::ws_session::WsConnectOpts;
use crate::ws_state_machine::run_conversational_fuzz;
use futures::{stream, StreamExt};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ENGINE_ID: &str = "websocket_attack";

const T_WEB_PROTO: &str = "T1071.001"; // Application Layer Protocol: Web Protocols
const T_SESSION_HIJACK: &str = "T1185"; // Browser Session Hijacking (CSWSH)
const T_SNIFF: &str = "T1040"; // Network Sniffing (cleartext ws://)

/// RFC 6455 GUID appended to the client key before SHA-1 to derive `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const DEFAULT_WS_PATHS: &[&str] = &[
    "/ws",
    "/wss",
    "/websocket",
    "/socket",
    "/socket.io/?EIO=4&transport=websocket",
    "/signalr",
    "/cable",
    "/chat",
    "/live",
    "/realtime",
    "/api/ws",
    "/api/websocket",
    "/events",
    "/stream",
    "/graphql",
    "/subscriptions",
    "/notifications",
    "/v1/ws",
];

const DEFAULT_FOREIGN_ORIGIN: &str = "https://attacker.example.com";

/// Literal `Origin: null` — sent by sandboxed documents, `file://`, and redirected contexts.
const ORIGIN_NULL: &str = "null";

const DEFAULT_FOREIGN_ORIGINS: &[&str] = &[
    "https://attacker.example.com",
    "https://evil.example.org",
    "http://127.0.0.1",
];

const DEFAULT_PRIVILEGED_SUBPROTOCOLS: &[&str] = &[
    "graphql-transport-ws",
    "graphql-ws",
    "v11.stomp",
    "v10.stomp",
    "ocpp2.0.1",
    "ocpp1.6",
    "mqtt",
    "json.webpubsub.azure.v1",
    "wamp.2.json",
];

const DEFAULT_SIGNALR_NEGOTIATE_PATHS: &[&str] = &[
    "/negotiate",
    "/signalr/negotiate",
    "/hubs/chat/negotiate",
    "/hubs/notifications/negotiate",
    "/api/hubs/chat/negotiate",
    "/chat/negotiate",
];

const SOCKETIO_POLLING_SUFFIX: &str = "/socket.io/?EIO=4&transport=polling";

// ── Crypto: Sec-WebSocket-Accept verification ───────────────────────────────────

fn ws_accept(key: &str) -> String {
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(WS_GUID.as_bytes());
    let digest = openssl::sha::sha1(&input);
    openssl::base64::encode_block(&digest)
}

fn random_ws_key() -> String {
    let mut buf = [0u8; 16];
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        ^ (buf.as_ptr() as u64);
    let mut x = seed | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xff) as u8;
    }
    openssl::base64::encode_block(&buf)
}

// ── Handshake ───────────────────────────────────────────────────────────────────

#[derive(Default, Clone, Debug)]
struct Handshake {
    status: u16,
    /// True when status==101 and the server returned the cryptographically-correct accept value.
    verified: bool,
    accept: Option<String>,
    protocol: Option<String>,
    extensions: Option<String>,
    server: Option<String>,
}

/// How to set (or omit) the `Origin` header on an upgrade request.
#[derive(Clone, Debug)]
enum OriginMode {
    Omit,
    Set(String),
}

#[derive(Clone, Debug, Default)]
struct HandshakeOpts {
    origin: Option<OriginMode>,
    auth: Vec<(String, String)>,
    subprotocols: Option<String>,
    extra_headers: Vec<(String, String)>,
    /// RFC6455 = 13; legacy hybi 8/7 probed for downgrade detection.
    ws_version: Option<u8>,
}

fn build_client(timeout_ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.clamp(500, 30_000)))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-WS/2.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Perform a real RFC 6455 upgrade handshake. Reads only status + headers (never the body, so a
/// hijacked/upgraded connection cannot hang the worker).
async fn ws_handshake_opts(
    client: &reqwest::Client,
    url: &str,
    opts: &HandshakeOpts,
) -> Option<Handshake> {
    let key = random_ws_key();
    let version = opts.ws_version.unwrap_or(13);
    let mut req = client
        .get(url)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Key", key.clone())
        .header("Sec-WebSocket-Version", version.to_string())
        .header("Sec-WebSocket-Extensions", "permessage-deflate");
    if let Some(OriginMode::Set(o)) = opts.origin.as_ref() {
        req = req.header("Origin", o.as_str());
    }
    if let Some(sp) = opts.subprotocols.as_deref() {
        req = req.header("Sec-WebSocket-Protocol", sp);
    }
    for (k, v) in &opts.auth {
        req = req.header(k.as_str(), v.as_str());
    }
    for (k, v) in &opts.extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let h = resp.headers();
    let geth = |name: &str| {
        h.get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let accept = geth("sec-websocket-accept");
    let verified = status == 101 && accept.as_deref() == Some(ws_accept(&key).as_str());
    Some(Handshake {
        status,
        verified,
        accept,
        protocol: geth("sec-websocket-protocol"),
        extensions: geth("sec-websocket-extensions"),
        server: geth("server"),
    })
}

async fn ws_handshake(
    client: &reqwest::Client,
    url: &str,
    origin: Option<&str>,
    auth: &[(String, String)],
) -> Option<Handshake> {
    let origin_mode = origin.map(|o| OriginMode::Set(o.to_string()));
    ws_handshake_opts(
        client,
        url,
        &HandshakeOpts {
            origin: origin_mode,
            auth: auth.to_vec(),
            ..Default::default()
        },
    )
    .await
}

// ── Posture accumulation ────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct WsPosture {
    endpoints: Vec<String>,
    cswsh: Vec<String>, // origin not validated (foreign)
    null_origin_cswsh: Vec<String>,
    missing_origin_cswsh: Vec<String>,
    authenticated_cswsh: Vec<String>, // confirmed with session cookie
    subprotocol_abuse: Vec<String>,
    cleartext: bool,
    tls_downgrade: Vec<String>,
    forwarded_bypass: Vec<String>,
    unauthenticated: Vec<String>,
    cookie_provided: bool,
    signalr_tokens: Vec<String>,
    socketio_sessions: Vec<String>,
    sensitive_leaks: Vec<String>,
    graphql_unauth: Vec<String>,
    stomp_unauth: Vec<String>,
    ws_reflection: Vec<String>,
    verbose_errors: Vec<String>,
    js_discovered: Vec<String>,
    auth_differential: Vec<String>,
    foreign_origin_data: Vec<String>,
    host_injection: Vec<String>,
    version_downgrade: Vec<String>,
    graphql_introspection: Vec<String>,
    no_rate_limit: Vec<String>,
    binary_accepted: Vec<String>,
    stateful_fuzz: Vec<String>,
    binary_mutation: Vec<String>,
    race_condition: Vec<String>,
    cross_protocol_escalation: Vec<String>,
    checks: u32,
}

impl WsPosture {
    fn score(&self) -> u32 {
        let mut s: i32 = 100;
        if !self.authenticated_cswsh.is_empty() {
            s -= 55;
        }
        s -= (self.cswsh.len() as i32).min(4) * 18;
        s -= (self.null_origin_cswsh.len() as i32).min(3) * 15;
        s -= (self.missing_origin_cswsh.len() as i32).min(3) * 12;
        s -= (self.subprotocol_abuse.len() as i32).min(3) * 10;
        if self.cleartext {
            s -= 20;
        }
        s -= (self.tls_downgrade.len() as i32).min(2) * 22;
        s -= (self.forwarded_bypass.len() as i32).min(2) * 14;
        s -= (self.signalr_tokens.len() as i32).min(2) * 8;
        s -= (self.socketio_sessions.len() as i32).min(2) * 6;
        s -= (self.sensitive_leaks.len() as i32).min(3) * 20;
        s -= (self.graphql_unauth.len() as i32).min(2) * 16;
        s -= (self.stomp_unauth.len() as i32).min(2) * 14;
        s -= (self.ws_reflection.len() as i32).min(2) * 8;
        s -= (self.verbose_errors.len() as i32).min(2) * 3;
        s -= (self.auth_differential.len() as i32).min(2) * 22;
        s -= (self.foreign_origin_data.len() as i32).min(2) * 18;
        s -= (self.host_injection.len() as i32).min(2) * 12;
        s -= (self.version_downgrade.len() as i32).min(2) * 10;
        s -= (self.graphql_introspection.len() as i32).min(2) * 15;
        s -= (self.no_rate_limit.len() as i32).min(2) * 6;
        s -= (self.binary_accepted.len() as i32).min(2) * 8;
        s -= (self.missing_origin_cswsh.len() as i32).min(2) * 10;
        s -= (self.version_downgrade.len() as i32).min(2) * 8;
        s -= (self.stateful_fuzz.len() as i32).min(2) * 18;
        s -= (self.binary_mutation.len() as i32).min(2) * 14;
        s -= (self.race_condition.len() as i32).min(2) * 16;
        s -= (self.cross_protocol_escalation.len() as i32).min(2) * 22;
        s -= (self.unauthenticated.len() as i32).min(4) * 4;
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
    fn has_any(&self) -> bool {
        !self.cswsh.is_empty()
            || !self.null_origin_cswsh.is_empty()
            || !self.missing_origin_cswsh.is_empty()
            || !self.authenticated_cswsh.is_empty()
            || !self.subprotocol_abuse.is_empty()
            || self.cleartext
            || !self.tls_downgrade.is_empty()
            || !self.forwarded_bypass.is_empty()
            || !self.signalr_tokens.is_empty()
            || !self.socketio_sessions.is_empty()
            || !self.sensitive_leaks.is_empty()
            || !self.graphql_unauth.is_empty()
            || !self.stomp_unauth.is_empty()
            || !self.ws_reflection.is_empty()
            || !self.auth_differential.is_empty()
            || !self.foreign_origin_data.is_empty()
            || !self.host_injection.is_empty()
            || !self.graphql_introspection.is_empty()
            || !self.stateful_fuzz.is_empty()
            || !self.binary_mutation.is_empty()
            || !self.race_condition.is_empty()
            || !self.cross_protocol_escalation.is_empty()
    }

    fn weak_categories(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let push = |v: &mut Vec<&'static str>, cat: &'static str, hit: bool| {
            if hit {
                v.push(cat);
            }
        };
        push(
            &mut out,
            "authenticated_cswsh",
            !self.authenticated_cswsh.is_empty(),
        );
        push(
            &mut out,
            "auth_differential",
            !self.auth_differential.is_empty(),
        );
        push(&mut out, "cswsh", !self.cswsh.is_empty());
        push(
            &mut out,
            "null_origin_cswsh",
            !self.null_origin_cswsh.is_empty(),
        );
        push(
            &mut out,
            "foreign_origin_data",
            !self.foreign_origin_data.is_empty(),
        );
        push(&mut out, "sensitive_leak", !self.sensitive_leaks.is_empty());
        push(&mut out, "graphql_unauth", !self.graphql_unauth.is_empty());
        push(
            &mut out,
            "graphql_introspection",
            !self.graphql_introspection.is_empty(),
        );
        push(&mut out, "host_injection", !self.host_injection.is_empty());
        push(
            &mut out,
            "forwarded_bypass",
            !self.forwarded_bypass.is_empty(),
        );
        push(&mut out, "tls_downgrade", !self.tls_downgrade.is_empty());
        push(&mut out, "stomp_unauth", !self.stomp_unauth.is_empty());
        push(
            &mut out,
            "subprotocol_abuse",
            !self.subprotocol_abuse.is_empty(),
        );
        push(&mut out, "no_rate_limit", !self.no_rate_limit.is_empty());
        push(
            &mut out,
            "missing_origin_cswsh",
            !self.missing_origin_cswsh.is_empty(),
        );
        push(
            &mut out,
            "version_downgrade",
            !self.version_downgrade.is_empty(),
        );
        push(&mut out, "ws_reflection", !self.ws_reflection.is_empty());
        push(
            &mut out,
            "binary_accepted",
            !self.binary_accepted.is_empty(),
        );
        push(&mut out, "stateful_fuzz", !self.stateful_fuzz.is_empty());
        push(
            &mut out,
            "binary_mutation",
            !self.binary_mutation.is_empty(),
        );
        push(&mut out, "race_condition", !self.race_condition.is_empty());
        push(
            &mut out,
            "cross_protocol_escalation",
            !self.cross_protocol_escalation.is_empty(),
        );
        out
    }

    fn worst_severity(&self) -> &'static str {
        if !self.authenticated_cswsh.is_empty()
            || !self.auth_differential.is_empty()
            || !self.sensitive_leaks.is_empty()
            || !self.cross_protocol_escalation.is_empty()
        {
            "critical"
        } else if !self.cswsh.is_empty()
            || !self.null_origin_cswsh.is_empty()
            || !self.foreign_origin_data.is_empty()
            || !self.graphql_unauth.is_empty()
            || !self.graphql_introspection.is_empty()
            || !self.host_injection.is_empty()
            || !self.forwarded_bypass.is_empty()
            || !self.tls_downgrade.is_empty()
            || !self.stomp_unauth.is_empty()
            || !self.stateful_fuzz.is_empty()
            || !self.race_condition.is_empty()
        {
            "high"
        } else if !self.missing_origin_cswsh.is_empty()
            || !self.subprotocol_abuse.is_empty()
            || !self.ws_reflection.is_empty()
            || self.cleartext
            || !self.no_rate_limit.is_empty()
            || !self.binary_mutation.is_empty()
        {
            "medium"
        } else if !self.unauthenticated.is_empty()
            || !self.verbose_errors.is_empty()
            || !self.socketio_sessions.is_empty()
        {
            "low"
        } else {
            "info"
        }
    }
}

fn with_fields(mut f: Value, extra: &[(&str, Value)]) -> Value {
    if let Some(obj) = f.as_object_mut() {
        for (k, v) in extra {
            obj.insert((*k).to_string(), v.clone());
        }
    }
    f
}

fn framework_of(path: &str, proto: Option<&str>) -> Option<&'static str> {
    let p = path.to_ascii_lowercase();
    if p.contains("socket.io") {
        return Some("Socket.IO");
    }
    if p.contains("signalr") {
        return Some("ASP.NET SignalR");
    }
    if p.contains("cable") {
        return Some("Rails Action Cable");
    }
    if let Some(pr) = proto {
        let pr = pr.to_ascii_lowercase();
        if pr.contains("graphql") {
            return Some("graphql-ws (GraphQL subscriptions)");
        }
        if pr.contains("actioncable") {
            return Some("Rails Action Cable");
        }
    }
    if p.contains("graphql") || p.contains("subscription") {
        return Some("GraphQL subscriptions");
    }
    None
}

/// Extract Socket.IO session id from a polling transport body (`0{"sid":"…",…}`).
fn socketio_sid_from_body(body: &str) -> Option<String> {
    let trimmed = body.trim();
    let json_part = trimmed.strip_prefix('0')?;
    let v: Value = serde_json::from_str(json_part).ok()?;
    v.get("sid").and_then(Value::as_str).map(str::to_string)
}

fn preview(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

// ── JavaScript WebSocket URL harvest ────────────────────────────────────────────

fn ws_url_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(wss?://[^\s"'<>\\]+)|new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]"#)
            .expect("ws url regex")
    })
}

fn resolve_ws_path(raw: &str, base: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with("ws://") || t.starts_with("wss://") {
        return Some(t.replace("wss://", "https://").replace("ws://", "http://"));
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        return Some(t.to_string());
    }
    if t.starts_with('/') {
        return Some(format!("{}{}", base.trim_end_matches('/'), t));
    }
    Some(format!(
        "{}/{}",
        base.trim_end_matches('/'),
        t.trim_start_matches('/')
    ))
}

/// Mine HTML/JS for WebSocket endpoints referenced by the target application.
fn harvest_ws_urls_from_html(html: &str, base: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in ws_url_regex().captures_iter(html) {
        let raw = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        if raw.is_empty() || raw.contains("new WebSocket") {
            continue;
        }
        if let Some(resolved) = resolve_ws_path(raw, base) {
            out.push(resolved);
        }
    }
    out.sort();
    out.dedup();
    out
}

// ── Sensitive-data flow analysis ────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct SensitiveHit {
    kind: &'static str,
    preview: String,
}

fn looks_like_jwt(s: &str) -> bool {
    s.starts_with("eyJ") && s.matches('.').count() >= 2 && s.len() > 40
}

fn scan_sensitive(text: &str) -> Vec<SensitiveHit> {
    let mut hits = Vec::new();
    let lower = text.to_ascii_lowercase();
    for token in text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',') {
        if looks_like_jwt(token) {
            hits.push(SensitiveHit {
                kind: "jwt",
                preview: preview(token, 48),
            });
        }
    }
    if lower.contains("akia") {
        for token in text.split(|c: char| !c.is_ascii_alphanumeric()) {
            if token.starts_with("AKIA") && token.len() >= 20 {
                hits.push(SensitiveHit {
                    kind: "aws_access_key",
                    preview: preview(token, 24),
                });
            }
        }
    }
    if lower.contains("begin rsa private key") || lower.contains("begin private key") {
        hits.push(SensitiveHit {
            kind: "private_key_pem",
            preview: "-----BEGIN … PRIVATE KEY-----".to_string(),
        });
    }
    for marker in [
        ("bearer_token", "bearer "),
        ("api_key_field", "\"api_key\""),
        ("api_key_field", "'api_key'"),
        ("password_field", "\"password\""),
        ("secret_field", "\"secret\""),
        ("refresh_token", "refresh_token"),
        ("access_token", "access_token"),
    ] {
        if lower.contains(marker.1) {
            hits.push(SensitiveHit {
                kind: marker.0,
                preview: preview(&lower[lower.find(marker.1).unwrap_or(0)..], 64),
            });
        }
    }
    hits.sort_by(|a, b| a.kind.cmp(b.kind));
    hits.dedup_by(|a, b| a.kind == b.kind && a.preview == b.preview);
    hits
}

fn verbose_ws_error(text: &str) -> bool {
    let l = text.to_ascii_lowercase();
    l.contains("stacktrace")
        || l.contains("stack trace")
        || l.contains("traceback")
        || l.contains("syntaxerror")
        || l.contains("internal server error")
        || l.contains("sqlexception")
        || l.contains("panic at")
        || l.contains(".rs:")
        || l.contains(".java:")
        || l.contains("node:internal")
}

// ── Framework-specific post-handshake probes ────────────────────────────────────

fn framework_message_probes(
    framework: Option<&str>,
    subproto: Option<&str>,
    check_graphql: bool,
    check_graphql_introspection: bool,
    check_stomp: bool,
    reflection_marker: &str,
) -> Vec<String> {
    let mut probes = Vec::new();
    let fw = framework.unwrap_or("");
    let sp = subproto.unwrap_or("").to_ascii_lowercase();

    let graphql = check_graphql
        && (fw.contains("GraphQL")
            || sp.contains("graphql")
            || sp.contains("graphql-transport-ws")
            || sp.contains("graphql-ws"));
    if graphql {
        probes.push(r#"{"type":"connection_init","payload":{}}"#.to_string());
        probes.push(r#"{"type":"subscribe","id":"weissman-1","payload":{"query":"subscription { __typename }"}}"#.to_string());
        if check_graphql_introspection {
            probes.push(
                r#"{"type":"subscribe","id":"weissman-intro","payload":{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}}"#
                    .to_string(),
            );
        } else {
            probes.push(r#"{"type":"subscribe","id":"weissman-2","payload":{"query":"{ __schema { types { name } } }"}}"#.to_string());
        }
    }

    if check_stomp && (sp.contains("stomp") || fw.contains("STOMP")) {
        probes.push("CONNECT\naccept-version:1.2\nhost:weissman.probe\n\n\u{0}".to_string());
    }

    if fw.contains("Socket.IO") {
        probes.push("40".to_string());
        probes.push("42[\"weissman_probe\",{}]".to_string());
    }
    if fw.contains("Action Cable") {
        probes.push(
            r#"{"command":"subscribe","identifier":"{\"channel\":\"NotificationsChannel\"}"}"#
                .to_string(),
        );
    }
    if fw.contains("SignalR") {
        probes.push(r#"{"protocol":"json","version":1}"#.to_string());
        probes.push(r#"{"type":6}"#.to_string()); // ping
    }

    // Generic JSON-RPC / echo probes (safe, read-only intent).
    probes.push(json!({"jsonrpc":"2.0","method":"ping","id":1}).to_string());
    probes.push(json!({"type":"ping","payload":reflection_marker}).to_string());
    probes.push(format!(
        r#"{{"type":"echo","payload":"{}"}}"#,
        reflection_marker
    ));
    probes
}

// ── Live WebSocket session exchange ─────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
struct WsSessionOpts {
    origin: Option<String>,
    auth: Vec<(String, String)>,
    subprotocol: Option<String>,
    read_ms: u64,
    max_messages: usize,
}

#[derive(Clone, Debug, Default)]
struct WsSessionResult {
    sent: Vec<String>,
    received: Vec<String>,
    connected: bool,
    close_reason: Option<String>,
}

async fn ws_session_exchange(
    http_url: &str,
    opts: &WsSessionOpts,
    outbound: &[String],
) -> Option<WsSessionResult> {
    let connect_opts = WsConnectOpts {
        origin: opts.origin.clone(),
        auth: opts.auth.clone(),
        subprotocol: opts.subprotocol.clone(),
        read_ms: opts.read_ms,
        max_messages: opts.max_messages,
    };
    let ex = crate::ws_session::exchange_frames(http_url, &connect_opts, outbound, &[]).await?;
    let mut received = ex.received;
    for b in &ex.received_binary {
        let hex_preview: String = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
        received.push(format!("[binary {}B] {hex_preview}", b.len()));
    }
    Some(WsSessionResult {
        sent: ex.sent,
        received,
        connected: ex.connected,
        close_reason: ex.close_reason,
    })
}

struct MessageProbeCfg {
    read_ms: u64,
    max_messages: usize,
    check_sensitive: bool,
    check_graphql: bool,
    check_graphql_introspection: bool,
    check_stomp: bool,
    check_reflection: bool,
    check_auth_differential: bool,
    check_foreign_origin_messages: bool,
    check_rate_limit: bool,
    check_binary_frames: bool,
    burst_count: usize,
    foreign_origin: String,
    custom_messages: Vec<String>,
    reflection_marker: String,
}

fn meaningful_ws_data(frames: &[String]) -> bool {
    if frames.is_empty() {
        return false;
    }
    let joined = frames.join("\n");
    if scan_sensitive(&joined).is_empty() {
        return frames.iter().any(|f| {
            let l = f.to_ascii_lowercase();
            f.len() > 24
                && !l.contains("ping")
                && !l.contains("pong")
                && !l.contains("unauthorized")
                && !l.contains("forbidden")
        });
    }
    true
}

fn graphql_introspection_leak(frames: &[String]) -> bool {
    frames.iter().any(|r| {
        let l = r.to_ascii_lowercase();
        (l.contains("__schema") || l.contains("\"types\""))
            && (l.contains("\"querytype\"") || l.contains("\"mutationtype\""))
            && !l.contains("unauthorized")
    })
}

/// Minimal probes for differential auth / foreign-origin sessions (fast, comparable).
fn minimal_compare_probes(framework: Option<&str>, subproto: Option<&str>) -> Vec<String> {
    let mut p = vec![json!({"type":"ping","id":1}).to_string()];
    let fw = framework.unwrap_or("");
    let sp = subproto.unwrap_or("").to_ascii_lowercase();
    if fw.contains("GraphQL") || sp.contains("graphql") {
        p.push(r#"{"type":"connection_init","payload":{}}"#.to_string());
        p.push(
            r#"{"type":"subscribe","id":"diff-1","payload":{"query":"{ __typename }"}}"#
                .to_string(),
        );
    }
    if fw.contains("Socket.IO") {
        p.push("40".to_string());
    }
    p
}

async fn probe_auth_differential(
    http_url: &str,
    target: &str,
    same_origin: &str,
    auth: &[(String, String)],
    framework: Option<&str>,
    subproto: Option<&str>,
    read_ms: u64,
) -> Vec<Value> {
    if auth.is_empty() {
        return Vec::new();
    }
    let probes = minimal_compare_probes(framework, subproto);
    let base_opts = |with_auth: bool| WsSessionOpts {
        origin: Some(same_origin.to_string()),
        auth: if with_auth { auth.to_vec() } else { Vec::new() },
        subprotocol: subproto.map(str::to_string),
        read_ms,
        max_messages: 8,
    };
    let Some(unauth) = ws_session_exchange(http_url, &base_opts(false), &probes).await else {
        return Vec::new();
    };
    let Some(with_auth) = ws_session_exchange(http_url, &base_opts(true), &probes).await else {
        return Vec::new();
    };
    let unauth_meaningful = meaningful_ws_data(&unauth.received);
    let unauth_secrets = !scan_sensitive(&unauth.received.join("\n")).is_empty();
    let auth_meaningful = meaningful_ws_data(&with_auth.received);
    if !unauth_meaningful && !unauth_secrets {
        return Vec::new();
    }
    if unauth_secrets
        || (unauth_meaningful
            && auth_meaningful
            && unauth.received.len() >= with_auth.received.len())
    {
        return vec![with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Auth-differential bypass — unauthenticated WS peer receives session data: {}", http_url),
                "critical",
                T_WEB_PROTO,
                "Identical probe frames were sent on two live sessions (with and without supplied credentials). The unauthenticated session received comparable or sensitive server data — message-level authorization is missing or broken.",
                target,
                0.9,
                Evidence::new()
                    .with("url", http_url)
                    .with("unauth_frames", unauth.received.len())
                    .with("auth_frames", with_auth.received.len())
                    .with("unauth_preview", preview(&unauth.received.join("\n"), 300))
                    .with("auth_preview", preview(&with_auth.received.join("\n"), 300))
                    .check("unauth_received_data", unauth_meaningful || unauth_secrets, "unauthenticated session returned app/sensitive data")
                    .check("auth_received_data", auth_meaningful, "authenticated session returned data"),
            ),
            &[("category", json!("auth_differential")), ("url", json!(http_url))],
        )];
    }
    Vec::new()
}

async fn probe_foreign_origin_session(
    http_url: &str,
    target: &str,
    foreign_origin: &str,
    framework: Option<&str>,
    subproto: Option<&str>,
    read_ms: u64,
) -> Vec<Value> {
    let probes = minimal_compare_probes(framework, subproto);
    let opts = WsSessionOpts {
        origin: Some(foreign_origin.to_string()),
        auth: Vec::new(),
        subprotocol: subproto.map(str::to_string),
        read_ms,
        max_messages: 8,
    };
    let Some(session) = ws_session_exchange(http_url, &opts, &probes).await else {
        return Vec::new();
    };
    if !meaningful_ws_data(&session.received) {
        return Vec::new();
    }
    vec![with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Foreign-origin WebSocket session received application data: {}", http_url),
            "high",
            T_SESSION_HIJACK,
            &format!(
                "A live WebSocket was opened from foreign Origin `{}` and the server returned application frames (not just protocol acks). Cross-site pages can read real-time data from this endpoint — CSWSH at the message layer.",
                foreign_origin
            ),
            target,
            0.86,
            Evidence::new()
                .with("url", http_url)
                .with("foreign_origin", foreign_origin)
                .with("received_preview", preview(&session.received.join("\n"), 400))
                .check("foreign_origin_app_data", true, "foreign-origin session returned meaningful frames"),
        ),
        &[("category", json!("foreign_origin_data")), ("url", json!(http_url))],
    )]
}

async fn probe_ws_rate_limit_burst(
    http_url: &str,
    target: &str,
    same_origin: &str,
    burst_count: usize,
    read_ms: u64,
) -> Vec<Value> {
    let opts = WsSessionOpts {
        origin: Some(same_origin.to_string()),
        auth: Vec::new(),
        subprotocol: None,
        read_ms: read_ms.min(2000),
        max_messages: burst_count + 4,
    };
    let bursts: Vec<String> = (0..burst_count.clamp(4, 24))
        .map(|i| json!({"type":"ping","seq":i,"probe":"weissman_burst"}).to_string())
        .collect();
    let Some(session) = ws_session_exchange(http_url, &opts, &bursts).await else {
        return Vec::new();
    };
    if session.sent.len() >= burst_count.saturating_sub(2) && session.close_reason.is_none() {
        return vec![with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("WebSocket rate-limit absence ({}-frame burst accepted): {}", burst_count, http_url),
                "medium",
                T_WEB_PROTO,
                &format!(
                    "The server accepted {} rapid probe frames without closing the session or signaling backpressure. Unbounded WebSocket message rates enable DoS, credential stuffing over WS transports, and subscription flooding.",
                    session.sent.len()
                ),
                target,
                0.62,
                Evidence::new()
                    .with("url", http_url)
                    .with("frames_sent", session.sent.len())
                    .with("frames_received", session.received.len())
                    .check("burst_accepted", true, "session survived rapid message burst"),
            ),
            &[("category", json!("ws_no_rate_limit")), ("url", json!(http_url))],
        )];
    }
    Vec::new()
}

async fn probe_binary_ws_frames(
    http_url: &str,
    target: &str,
    same_origin: &str,
    read_ms: u64,
) -> Vec<Value> {
    let opts = ws_connect_opts(same_origin, &[], None, read_ms, 6);
    let payload = b"\x00weissman_binary_probe\x7b\x22type\x22:\x22ping\x22\x7d".to_vec();
    let Some(ex) =
        crate::ws_session::exchange_frames(http_url, &opts, &[], std::slice::from_ref(&payload))
            .await
    else {
        return Vec::new();
    };
    let got_binary = !ex.received_binary.is_empty();
    let got_app_reply = got_binary
        || ex
            .received
            .iter()
            .any(|t| !t.is_empty() && !t.to_ascii_lowercase().contains("error"));
    if !got_app_reply {
        return Vec::new();
    }
    vec![with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Binary WebSocket frame processed by server: {}", http_url),
            "low",
            T_WEB_PROTO,
            "The server responded to an attacker-supplied binary WebSocket frame. Binary gateways (protobuf, MessagePack, CBOR) must authenticate and schema-validate every frame — not only text JSON.",
            target,
            0.55,
            Evidence::new()
                .with("url", http_url)
                .with("binary_reply", got_binary)
                .check("binary_frame_processed", true, "server replied after binary probe frame"),
        ),
        &[("category", json!("ws_binary_accepted")), ("url", json!(http_url))],
    )]
}

const DEFAULT_HTTP_ESCALATION_PATHS: &[&str] = &[
    "api/me",
    "api/user",
    "api/v1/me",
    "api/v1/user",
    "api/profile",
    "graphql",
    "admin",
    "api/admin",
];

fn ws_connect_opts(
    same_origin: &str,
    auth: &[(String, String)],
    subproto: Option<&str>,
    read_ms: u64,
    max_messages: usize,
) -> WsConnectOpts {
    WsConnectOpts {
        origin: Some(same_origin.to_string()),
        auth: auth.to_vec(),
        subprotocol: subproto.map(str::to_string),
        read_ms,
        max_messages,
    }
}

fn publish_frame_artifacts(bus: &IntelligenceBus, url: &str, frames: &[String]) {
    for frame in frames {
        for art in artifacts_from_ws_frame(frame, url) {
            bus.publish(art);
        }
    }
}

async fn probe_stateful_conversational_fuzz(
    http_url: &str,
    target: &str,
    same_origin: &str,
    auth: &[(String, String)],
    subproto: Option<&str>,
    framework: Option<&str>,
    read_ms: u64,
    max_rounds: u8,
    bus: &IntelligenceBus,
) -> Vec<Value> {
    let opts = ws_connect_opts(same_origin, auth, subproto, read_ms, 16);
    let Some(result) =
        run_conversational_fuzz(http_url, &opts, framework, subproto, max_rounds).await
    else {
        return Vec::new();
    };

    publish_frame_artifacts(bus, http_url, &result.frames_received);

    if !result.mutation_accepted && !result.idor_surface && !result.auth_bypass_hint {
        return Vec::new();
    }

    let sev = if result.idor_surface || result.auth_bypass_hint {
        "high"
    } else {
        "medium"
    };
    vec![with_fields(
        finding_rich(
            ENGINE_ID,
            &format!(
                "Stateful conversational fuzzing accepted mutated session frames: {}",
                http_url
            ),
            sev,
            T_WEB_PROTO,
            "The async state machine extracted live session constraints from server frames, mutated identifiers/roles, and the server accepted subsequent malicious frames — confirming stateful IDOR or auth-bypass surface on the WebSocket conversation.",
            target,
            if result.idor_surface { 0.88 } else { 0.72 },
            Evidence::new()
                .with("url", http_url)
                .with("states_visited", json!(result.states_visited))
                .with("frames_sent", json!(result.frames_sent))
                .with("frames_received", json!(result.frames_received))
                .with("mutation_accepted", result.mutation_accepted)
                .with("idor_surface", result.idor_surface)
                .with("auth_bypass_hint", result.auth_bypass_hint)
                .check(
                    "stateful_fuzz_confirmed",
                    true,
                    "live response-driven mutation accepted by server",
                ),
        ),
        &[("category", json!("ws_stateful_fuzz")), ("url", json!(http_url))],
    )]
}

async fn probe_binary_frame_mutation(
    http_url: &str,
    target: &str,
    same_origin: &str,
    auth: &[(String, String)],
    subproto: Option<&str>,
    read_ms: u64,
    bus: &IntelligenceBus,
) -> Vec<Value> {
    let opts = ws_connect_opts(same_origin, auth, subproto, read_ms, 8);
    let live_seed = crate::ws_session::exchange_frames(
        http_url,
        &opts,
        &[json!({"type":"ping","id":"bin-probe"}).to_string()],
        &[],
    )
    .await
    .and_then(|ex| ex.received_binary.into_iter().find(|b| b.len() >= 4));
    let from_live = live_seed.is_some();
    let seed = live_seed.unwrap_or_else(|| synthetic_protobuf_seed("user", 100));
    let Some(result) = binary_mutation_probe(http_url, &opts, &seed).await else {
        return Vec::new();
    };
    if !result.server_processed_binary {
        return Vec::new();
    }
    for frame in &result.reply_text {
        publish_frame_artifacts(bus, http_url, std::slice::from_ref(frame));
    }
    let sev = if result.mutation_transmitted && result.protobuf_parsed {
        "high"
    } else {
        "medium"
    };
    vec![with_fields(
        finding_rich(
            ENGINE_ID,
            &format!(
                "Binary protobuf frame surgically mutated and processed: {}",
                http_url
            ),
            sev,
            T_WEB_PROTO,
            "The engine decoded protobuf wire fields from a binary WebSocket frame, surgically mutated role/amount fields, re-encoded, and the server processed the manipulated frame — binary protocol validation bypass confirmed.",
            target,
            if result.mutation_transmitted { 0.85 } else { 0.65 },
            Evidence::new()
                .with("url", http_url)
                .with("seed_len", seed.len())
                .with("seed_from_live_capture", from_live)
                .with("protobuf_parsed", result.protobuf_parsed)
                .with("mutation_transmitted", result.mutation_transmitted)
                .with("reply_text", json!(result.reply_text))
                .with("reply_binary_count", result.reply_binary.len())
                .check(
                    "binary_mutation_processed",
                    true,
                    "server responded after mutated binary frame",
                ),
        ),
        &[("category", json!("ws_binary_mutation")), ("url", json!(http_url))],
    )]
}

async fn probe_ws_race_condition(
    http_url: &str,
    target: &str,
    same_origin: &str,
    auth: &[(String, String)],
    subproto: Option<&str>,
    read_ms: u64,
    connections: usize,
    sync_us: u64,
    payload: &str,
) -> Vec<Value> {
    let opts = ws_connect_opts(same_origin, auth, subproto, read_ms, 4);
    let cfg = RaceConfig {
        connections,
        sync_window_us: sync_us,
        payload: payload.to_string(),
        read_ms,
    };
    let Some(outcome) = execute_race_burst(http_url, &opts, &cfg).await else {
        return Vec::new();
    };
    if !outcome.duplicate_success && !outcome.timing_anomaly {
        return Vec::new();
    }
    let sev = if outcome.duplicate_success {
        "high"
    } else {
        "medium"
    };
    vec![with_fields(
        finding_rich(
            ENGINE_ID,
            &format!(
                "Blind race condition — {} parallel WS connections, {}µs spread: {}",
                outcome.connections, outcome.spread_us, http_url
            ),
            sev,
            T_WEB_PROTO,
            "Synchronized multi-connection WebSocket dispatch detected duplicate transactional success or sub-millisecond timing anomalies — indicative of missing server-side atomicity / race window on stateful frames.",
            target,
            if outcome.duplicate_success { 0.9 } else { 0.7 },
            Evidence::new()
                .with("url", http_url)
                .with("connections", outcome.connections)
                .with("success_responses", outcome.success_responses)
                .with("spread_us", outcome.spread_us)
                .with("duplicate_success", outcome.duplicate_success)
                .with("timing_anomaly", outcome.timing_anomaly)
                .with("responses", json!(outcome.responses))
                .check(
                    "race_condition_signal",
                    true,
                    "parallel synchronized frames produced anomalous success pattern",
                ),
        ),
        &[("category", json!("ws_race_condition")), ("url", json!(http_url))],
    )]
}

async fn verify_cross_protocol_escalation(
    client: &reqwest::Client,
    http_base: &str,
    target: &str,
    bus: &IntelligenceBus,
    probe_paths: &[&str],
) -> Vec<Value> {
    let mut findings = Vec::new();
    for artifact in bus.snapshot_for_cross_protocol() {
        if let Some(proof) =
            verify_http_privilege_escalation(client, http_base, &artifact, probe_paths).await
        {
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!(
                        "Cross-protocol privilege escalation via {} artifact: {}",
                        artifact.kind, proof.url
                    ),
                    "critical",
                    T_SESSION_HIJACK,
                    "A WebSocket-captured session artifact was replayed over HTTP and returned privileged data that unauthenticated requests could not access — cross-protocol session hijacking confirmed with deterministic status/body differential.",
                    target,
                    0.95,
                    Evidence::new()
                        .with("artifact_kind", artifact.kind.clone())
                        .with("artifact_proof", artifact.proof.clone())
                        .with("ws_source", artifact.source_url.clone())
                        .with("http_url", proof.url.clone())
                        .with("unauth_status", proof.unauth_status)
                        .with("auth_status", proof.auth_status)
                        .with("unauth_len", proof.unauth_len)
                        .with("auth_len", proof.auth_len)
                        .with("auth_body_preview", proof.auth_body_preview.clone())
                        .check(
                            "cross_protocol_escalation",
                            true,
                            "HTTP replay of WS artifact returned privileged response",
                        ),
                ),
                &[
                    ("category", json!("cross_protocol_escalation")),
                    ("url", json!(proof.url)),
                ],
            ));
        }
    }
    findings
}

async fn probe_ws_messages(
    http_url: &str,
    target: &str,
    same_origin: &str,
    auth: &[(String, String)],
    subproto: Option<&str>,
    framework: Option<&str>,
    cfg: &MessageProbeCfg,
    bus: Option<&IntelligenceBus>,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let probes = framework_message_probes(
        framework,
        subproto,
        cfg.check_graphql,
        cfg.check_graphql_introspection,
        cfg.check_stomp,
        &cfg.reflection_marker,
    );
    let mut outbound: Vec<String> = probes;
    outbound.extend(cfg.custom_messages.clone());
    outbound.sort();
    outbound.dedup();

    let opts = WsSessionOpts {
        origin: Some(same_origin.to_string()),
        auth: auth.to_vec(),
        subprotocol: subproto.map(str::to_string),
        read_ms: cfg.read_ms,
        max_messages: cfg.max_messages,
    };

    let Some(session) = ws_session_exchange(http_url, &opts, &outbound).await else {
        return findings;
    };
    if !session.connected {
        return findings;
    }

    if let Some(b) = bus {
        publish_frame_artifacts(b, http_url, &session.received);
    }

    let combined_recv = session.received.join("\n");
    let combined_sent = session.sent.join("\n");

    if session.received.is_empty() {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("WebSocket accepts messages but returns silence: {}", http_url),
                "info",
                T_WEB_PROTO,
                "A live WebSocket session was opened and probe frames were sent, but the server returned no application data within the read window. This may indicate strict message auth (good) or a binary/custom protocol — supply `custom_messages` to probe further.",
                target,
                0.35,
                Evidence::new()
                    .with("url", http_url)
                    .with("frames_sent", session.sent.len())
                    .with("sent_preview", combined_sent)
                    .check("session_open_no_data", true, "connected and sent probes, zero app frames"),
            ),
            &[("category", json!("ws_message_silent")), ("url", json!(http_url))],
        ));
    }

    // GraphQL subscription accepted without credentials.
    if cfg.check_graphql
        && (framework.unwrap_or("").contains("GraphQL")
            || subproto.unwrap_or("").contains("graphql"))
    {
        let gql_ok = session.received.iter().any(|r| {
            let l = r.to_ascii_lowercase();
            (l.contains("connection_ack")
                || l.contains("\"type\":\"next\"")
                || l.contains("\"type\": \"next\""))
                && !l.contains("unauthorized")
                && !l.contains("authentication")
        });
        if gql_ok {
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("GraphQL subscription data without message-level auth: {}", http_url),
                    "high",
                    T_WEB_PROTO,
                    "After `connection_init` / `subscribe`, the server returned `connection_ack` or subscription `next` payloads without rejecting unauthenticated clients. Message-level authorization is missing on live GraphQL subscription transport.",
                    target,
                    0.82,
                    Evidence::new()
                        .with("url", http_url)
                        .with("received_preview", preview(&combined_recv, 400))
                        .check("graphql_subscription_data", true, "connection_ack/next observed without auth error"),
                ),
                &[("category", json!("graphql_ws_unauth")), ("url", json!(http_url))],
            ));
        }
    }

    // STOMP CONNECT accepted.
    if cfg.check_stomp {
        let stomp_ok = session.received.iter().any(|r| {
            let u = r.to_ascii_uppercase();
            u.contains("CONNECTED") || u.starts_with("CONNECTED")
        });
        if stomp_ok {
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("STOMP CONNECT accepted without credentials: {}", http_url),
                    "high",
                    T_WEB_PROTO,
                    "The server responded with STOMP `CONNECTED` to an unauthenticated CONNECT frame. Attackers can subscribe to message queues and exfiltrate broker traffic.",
                    target,
                    0.8,
                    Evidence::new()
                        .with("url", http_url)
                        .with("received_preview", preview(&combined_recv, 200))
                        .check("stomp_connected", true, "STOMP CONNECTED frame observed"),
                ),
                &[("category", json!("stomp_unauth")), ("url", json!(http_url))],
            ));
        }
    }

    if cfg.check_sensitive {
        for hit in scan_sensitive(&combined_recv) {
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("Sensitive data in WebSocket server frame ({}) — {}", hit.kind, http_url),
                    if hit.kind == "private_key_pem" || hit.kind == "jwt" {
                        "critical"
                    } else {
                        "high"
                    },
                    T_WEB_PROTO,
                    &format!(
                        "A server WebSocket frame contained `{}`-class material before the client completed authentication. Real-time channels must never push secrets, tokens, or key material to unauthenticated peers.",
                        hit.kind
                    ),
                    target,
                    0.88,
                    Evidence::new()
                        .with("url", http_url)
                        .with("leak_kind", hit.kind)
                        .with("preview", hit.preview)
                        .check("sensitive_in_server_frame", true, "pattern matched in received frame"),
                ),
                &[("category", json!("ws_sensitive_leak")), ("url", json!(http_url))],
            ));
        }
    }

    if cfg.check_reflection && combined_recv.contains(&cfg.reflection_marker) {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("WebSocket message reflection (DOM XSS surface): {}", http_url),
                "medium",
                T_WEB_PROTO,
                &format!(
                    "The server echoed probe marker `{}` inside a WebSocket frame. If the client application renders WS message bodies into the DOM without sanitization, this enables DOM-based XSS via malicious server or MITM content.",
                    cfg.reflection_marker
                ),
                target,
                0.72,
                Evidence::new()
                    .with("url", http_url)
                    .with("marker", cfg.reflection_marker.clone())
                    .check("message_reflected", true, "unique marker echoed in server frame"),
            ),
            &[("category", json!("ws_reflection")), ("url", json!(http_url))],
        ));
    }

    if cfg.check_graphql_introspection && graphql_introspection_leak(&session.received) {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("GraphQL introspection over live WebSocket transport: {}", http_url),
                "high",
                T_WEB_PROTO,
                "An introspection query sent over graphql-ws returned schema metadata (`__schema`, types, fields) on a live subscription socket. Disable introspection on production WebSocket GraphQL endpoints and enforce auth on `connection_init`.",
                target,
                0.84,
                Evidence::new()
                    .with("url", http_url)
                    .with("received_preview", preview(&combined_recv, 400))
                    .check("graphql_introspection_over_ws", true, "__schema/types metadata in WS frame"),
            ),
            &[("category", json!("graphql_ws_introspection")), ("url", json!(http_url))],
        ));
    }

    for recv in &session.received {
        if verbose_ws_error(recv) {
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("Verbose WebSocket error disclosure: {}", http_url),
                    "low",
                    T_WEB_PROTO,
                    "The server returned a verbose error/stack trace over the WebSocket channel. Disable debug errors on production real-time endpoints.",
                    target,
                    0.45,
                    Evidence::new()
                        .with("url", http_url)
                        .with("error_preview", preview(recv, 300))
                        .check("verbose_ws_error", true, "stack trace / internal error in WS frame"),
                ),
                &[("category", json!("ws_verbose_error")), ("url", json!(http_url))],
            ));
            break;
        }
    }

    findings
}

/// Probe SignalR negotiate endpoints — returns (path, connectionToken or connectionId).
async fn probe_signalr_negotiate(
    client: &reqwest::Client,
    base: &str,
    paths: &[String],
    same_origin: &str,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for path in paths {
        let url = if path.starts_with("http") {
            path.clone()
        } else {
            format!(
                "{}/{}",
                base.trim_end_matches('/'),
                path.trim_start_matches('/')
            )
        };
        let payload = json!({});
        let extra = [
            ("Origin", same_origin),
            ("X-Requested-With", "XMLHttpRequest"),
        ];
        let Some(resp) = http_post_json_with_headers(client, &url, &payload, &extra).await else {
            continue;
        };
        if resp.status != 200 {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(&resp.body) else {
            continue;
        };
        let token = v
            .get("connectionToken")
            .or_else(|| v.get("connectionId"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(t) = token {
            if !t.is_empty() {
                out.push((url, t));
            }
        }
    }
    out
}

/// Probe Socket.IO long-polling transport for a live `sid`.
async fn probe_socketio_polling(
    client: &reqwest::Client,
    base: &str,
    same_origin: &str,
) -> Option<(String, String)> {
    let url = format!("{}{}", base.trim_end_matches('/'), SOCKETIO_POLLING_SUFFIX);
    let extra = [("Origin", same_origin)];
    let resp = http_get_with_headers(client, &url, &extra).await?;
    if resp.status != 200 {
        return None;
    }
    let sid = socketio_sid_from_body(&resp.body)?;
    Some((url, sid))
}

// ── Per-endpoint probe ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct EndpointProbeCfg {
    host: String,
    same_origin: String,
    foreign_origins: Vec<String>,
    auth: Vec<(String, String)>,
    check_cswsh: bool,
    check_null_origin: bool,
    check_missing_origin: bool,
    check_compression: bool,
    check_subprotocols: bool,
    check_forwarded_bypass: bool,
    check_host_injection: bool,
    check_ws_version_downgrade: bool,
    subprotocols: Vec<String>,
}

#[derive(Clone)]
struct EndpointResult {
    url: String,
    findings: Vec<Value>,
    is_endpoint: bool,
    verified: bool,
    subprotocol: Option<String>,
    framework: Option<String>,
    cswsh: bool,
    null_origin_cswsh: bool,
    missing_origin_cswsh: bool,
    auth_cswsh: bool,
    subprotocol_abuse: bool,
    forwarded_bypass: bool,
    host_injection: bool,
    version_downgrade: bool,
    tls_downgrade: bool,
    unauth: bool,
}

async fn probe_endpoint(
    client: &reqwest::Client,
    url: String,
    target: &str,
    cfg: &EndpointProbeCfg,
) -> Option<EndpointResult> {
    // 1) Same-origin, no-credential handshake — confirms a real WS endpoint.
    let same = ws_handshake(client, &url, Some(&cfg.same_origin), &[]).await?;
    let detected = same.verified || matches!(same.status, 101 | 426);
    if !detected {
        return None;
    }
    let fw = framework_of(&url, same.protocol.as_deref());
    let mut findings = Vec::new();
    let mut out = EndpointResult {
        url: url.clone(),
        findings: Vec::new(),
        is_endpoint: true,
        verified: same.verified,
        subprotocol: same.protocol.clone(),
        framework: fw.map(str::to_string),
        cswsh: false,
        null_origin_cswsh: false,
        missing_origin_cswsh: false,
        auth_cswsh: false,
        subprotocol_abuse: false,
        forwarded_bypass: false,
        host_injection: false,
        version_downgrade: false,
        tls_downgrade: false,
        unauth: false,
    };

    let ev = Evidence::new()
        .with("url", url.clone())
        .with("http_status", same.status)
        .with("accept_verified", same.verified)
        .with(
            "sec_websocket_accept",
            same.accept.clone().unwrap_or_default(),
        )
        .with("subprotocol", same.protocol.clone().unwrap_or_default())
        .with("extensions", same.extensions.clone().unwrap_or_default())
        .with("server", same.server.clone().unwrap_or_default())
        .with("framework", fw.unwrap_or("generic"))
        .check(
            "rfc6455_handshake",
            same.verified,
            "Sec-WebSocket-Accept cryptographically verified",
        );
    findings.push(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!(
                "WebSocket endpoint confirmed{}: {}",
                fw.map(|f| format!(" ({f})")).unwrap_or_default(),
                url
            ),
            "info",
            T_WEB_PROTO,
            &format!(
                "A live WebSocket endpoint was confirmed at {} via a real RFC 6455 handshake{}. Ensure it enforces authentication, strict Origin validation and message-level authorization.",
                url,
                if same.verified { " (Sec-WebSocket-Accept verified)" } else { " (upgrade-required response)" }
            ),
            target,
            if same.verified { 0.95 } else { 0.6 },
            ev,
        ),
        &[("category", json!("ws_endpoint")), ("url", json!(url))],
    ));

    // Unauthenticated: a credential-free handshake fully succeeded.
    if same.verified && cfg.auth.is_empty() {
        out.unauth = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Unauthenticated WebSocket handshake accepted: {}", url),
                "low",
                T_WEB_PROTO,
                "The WebSocket upgrade completed without any credentials. If the channel exposes sensitive data or actions, require authentication at (or before) the handshake and authorize every message.",
                target,
                0.5,
                Evidence::new().with("url", url.clone()).check("no_credentials_required", true, "101 handshake with no auth headers/cookies"),
            ),
            &[("category", json!("ws_unauthenticated")), ("url", json!(url))],
        ));
    }

    // permessage-deflate compression (context-takeover side-channel surface).
    if cfg.check_compression {
        if let Some(ext) = same.extensions.as_deref() {
            if ext.to_ascii_lowercase().contains("permessage-deflate") {
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        "WebSocket permessage-deflate compression enabled",
                        "low",
                        T_WEB_PROTO,
                        "The server negotiated permessage-deflate. Compressing attacker-influenced + secret data in the same context can leak secrets via a CRIME/BREACH-style side channel. Disable context takeover or compression on sensitive channels.",
                        target,
                        0.4,
                        Evidence::new().with("url", url.clone()).with("extensions", ext.to_string()).check("permessage_deflate", true, "compression negotiated"),
                    ),
                    &[("category", json!("ws_compression")), ("url", json!(url))],
                ));
            }
        }
    }

    if !same.verified {
        out.findings = findings;
        return Some(out);
    }

    // Cleartext downgrade: http:// endpoint confirmed while the assessed origin is TLS-only.
    if url.starts_with("http://") && cfg.same_origin.starts_with("https://") {
        out.tls_downgrade = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("TLS downgrade — cleartext WebSocket accepts handshake: {}", url),
                "high",
                T_SNIFF,
                "A live WebSocket handshake succeeded over unencrypted http:// while the target origin is HTTPS. Browsers may block mixed content, but native clients, mobile SDKs, and misconfigured SPAs can still connect — exposing tokens and messages to network MITM. Disable cleartext at the load balancer and enforce wss:// only.",
                target,
                0.82,
                Evidence::new()
                    .with("url", url.clone())
                    .with("scheme", "http")
                    .check("cleartext_ws_on_tls_origin", true, "verified 101 on http:// while origin is https"),
            ),
            &[("category", json!("tls_downgrade")), ("url", json!(url))],
        ));
    }

    // 2) CSWSH — foreign origins (multi-origin sweep).
    if cfg.check_cswsh {
        for foreign_origin in &cfg.foreign_origins {
            if let Some(foreign) =
                ws_handshake(client, &url, Some(foreign_origin.as_str()), &[]).await
            {
                if foreign.verified {
                    out.cswsh = true;
                    findings.push(with_fields(
                        finding_rich(
                            ENGINE_ID,
                            &format!("Cross-Site WebSocket Hijacking (foreign Origin accepted): {}", url),
                            "high",
                            T_SESSION_HIJACK,
                            &format!(
                                "The handshake at {} succeeded from foreign Origin ({}) exactly as from the legitimate origin — the server does not validate Origin. Any web page can open a cross-site WebSocket to this endpoint. If the channel authenticates via cookies, this is full session-riding (CSWSH).",
                                url, foreign_origin
                            ),
                            target,
                            0.8,
                            Evidence::new()
                                .with("url", url.clone())
                                .with("foreign_origin", foreign_origin.clone())
                                .with("foreign_status", foreign.status)
                                .check("foreign_origin_accepted", true, "verified handshake from attacker origin")
                                .check("same_origin_accepted", true, "verified handshake from legitimate origin"),
                        ),
                        &[("category", json!("cswsh")), ("url", json!(url))],
                    ));

                    // Authenticated CSWSH — foreign origin + supplied session cookie still succeeds.
                    if !cfg.auth.is_empty() {
                        if let Some(fa) =
                            ws_handshake(client, &url, Some(foreign_origin.as_str()), &cfg.auth)
                                .await
                        {
                            if fa.verified {
                                out.auth_cswsh = true;
                                findings.push(with_fields(
                                    finding_rich(
                                        ENGINE_ID,
                                        &format!("Authenticated CSWSH confirmed (session-riding): {}", url),
                                        "critical",
                                        T_SESSION_HIJACK,
                                        &format!(
                                            "With the provided session credentials, the foreign-origin handshake at {} still completed — confirming an attacker page can ride the victim's authenticated WebSocket session.",
                                            url
                                        ),
                                        target,
                                        0.92,
                                        Evidence::new()
                                            .with("url", url.clone())
                                            .with("foreign_origin", foreign_origin.clone())
                                            .check("authenticated_foreign_handshake", true, "foreign origin + session cookie → verified 101"),
                                    ),
                                    &[("category", json!("authenticated_cswsh")), ("url", json!(url))],
                                ));
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    // Reverse-proxy Origin bypass: foreign Origin + X-Forwarded-* claiming the victim host.
    if cfg.check_forwarded_bypass && !out.cswsh && !out.forwarded_bypass {
        for foreign_origin in &cfg.foreign_origins {
            let fwd = ws_handshake_opts(
                client,
                &url,
                &HandshakeOpts {
                    origin: Some(OriginMode::Set(foreign_origin.clone())),
                    extra_headers: vec![
                        ("X-Forwarded-Host".to_string(), cfg.host.clone()),
                        ("X-Forwarded-Proto".to_string(), "https".to_string()),
                        ("X-Forwarded-For".to_string(), "127.0.0.1".to_string()),
                    ],
                    ..Default::default()
                },
            )
            .await;
            if let Some(f) = fwd {
                if f.verified {
                    out.forwarded_bypass = true;
                    findings.push(with_fields(
                        finding_rich(
                            ENGINE_ID,
                            &format!("CSWSH via X-Forwarded-* proxy trust: {}", url),
                            "high",
                            T_SESSION_HIJACK,
                            &format!(
                                "The handshake at {} accepted foreign Origin ({}) when X-Forwarded-Host/Proto were set to the victim host. Reverse proxies that trust these headers for Origin reconstruction can be bypassed — an attacker origin passes while the backend believes the request is same-site.",
                                url, foreign_origin
                            ),
                            target,
                            0.78,
                            Evidence::new()
                                .with("url", url.clone())
                                .with("foreign_origin", foreign_origin.clone())
                                .with("x_forwarded_host", cfg.host.clone())
                                .check("forwarded_header_origin_bypass", true, "foreign origin + X-Forwarded-Host → verified 101"),
                        ),
                        &[("category", json!("forwarded_bypass")), ("url", json!(url))],
                    ));
                    break;
                }
            }
        }
    }

    // 3) Null-Origin CSWSH — sandboxed iframe / data: URL bypass class.
    if cfg.check_null_origin {
        let null_hs = ws_handshake_opts(
            client,
            &url,
            &HandshakeOpts {
                origin: Some(OriginMode::Set(ORIGIN_NULL.to_string())),
                ..Default::default()
            },
        )
        .await;
        if let Some(null) = null_hs {
            if null.verified {
                out.null_origin_cswsh = true;
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Null-Origin WebSocket hijacking: {}", url),
                        "high",
                        T_SESSION_HIJACK,
                        &format!(
                            "The handshake at {} accepts `Origin: null` — a value sent by sandboxed iframes, redirected contexts, and file/data URLs. Attackers embed a sandboxed document that opens a null-origin WebSocket while cookies still attach. Reject `Origin: null` unless explicitly required.",
                            url
                        ),
                        target,
                        0.85,
                        Evidence::new()
                            .with("url", url.clone())
                            .with("origin", ORIGIN_NULL)
                            .check("null_origin_accepted", true, "verified handshake with Origin: null"),
                    ),
                    &[("category", json!("null_origin_cswsh")), ("url", json!(url))],
                ));

                if !cfg.auth.is_empty() {
                    if let Some(na) = ws_handshake_opts(
                        client,
                        &url,
                        &HandshakeOpts {
                            origin: Some(OriginMode::Set(ORIGIN_NULL.to_string())),
                            auth: cfg.auth.clone(),
                            ..Default::default()
                        },
                    )
                    .await
                    {
                        if na.verified {
                            out.auth_cswsh = true;
                            findings.push(with_fields(
                                finding_rich(
                                    ENGINE_ID,
                                    &format!("Authenticated null-Origin CSWSH (sandboxed iframe session-riding): {}", url),
                                    "critical",
                                    T_SESSION_HIJACK,
                                    "With supplied session credentials, `Origin: null` still completes the handshake — confirming sandboxed iframe / data-URL CSWSH with cookie session-riding.",
                                    target,
                                    0.9,
                                    Evidence::new()
                                        .with("url", url.clone())
                                        .with("origin", ORIGIN_NULL)
                                        .check("authenticated_null_origin", true, "null origin + session → verified 101"),
                                ),
                                &[("category", json!("authenticated_null_origin_cswsh")), ("url", json!(url))],
                            ));
                        }
                    }
                }
            }
        }
    }

    // 4) Missing-Origin handshake — some stacks skip Origin validation entirely.
    if cfg.check_missing_origin {
        let no_origin = ws_handshake_opts(
            client,
            &url,
            &HandshakeOpts {
                origin: Some(OriginMode::Omit),
                ..Default::default()
            },
        )
        .await;
        if let Some(missing) = no_origin {
            if missing.verified {
                out.missing_origin_cswsh = true;
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Missing-Origin WebSocket upgrade accepted: {}", url),
                        "medium",
                        T_SESSION_HIJACK,
                        &format!(
                            "The handshake at {} completed with no Origin header at all. Non-browser clients and CSWSH tooling can connect without presenting an Origin. Require and validate Origin for browser-facing endpoints.",
                            url
                        ),
                        target,
                        0.7,
                        Evidence::new()
                            .with("url", url.clone())
                            .check("origin_header_absent", true, "verified 101 with Origin omitted"),
                    ),
                    &[("category", json!("missing_origin_cswsh")), ("url", json!(url))],
                ));
            }
        }
    }

    // 5) Subprotocol smuggling — server echoes a privileged subprotocol without auth.
    if cfg.check_subprotocols && !cfg.subprotocols.is_empty() {
        let offered = cfg.subprotocols.join(", ");
        let sp_hs = ws_handshake_opts(
            client,
            &url,
            &HandshakeOpts {
                origin: Some(OriginMode::Set(cfg.same_origin.clone())),
                subprotocols: Some(offered.clone()),
                ..Default::default()
            },
        )
        .await;
        if let Some(sp) = sp_hs {
            if sp.verified {
                if let Some(negotiated) = sp.protocol.as_deref() {
                    let neg = negotiated.to_ascii_lowercase();
                    let privileged = cfg.subprotocols.iter().find(|p| {
                        neg == p.to_ascii_lowercase() || neg.contains(&p.to_ascii_lowercase())
                    });
                    if privileged.is_some() {
                        out.subprotocol_abuse = true;
                        findings.push(with_fields(
                            finding_rich(
                                ENGINE_ID,
                                &format!("Privileged subprotocol negotiated without auth: {} → {}", url, negotiated),
                                "medium",
                                T_WEB_PROTO,
                                &format!(
                                    "The server negotiated subprotocol `{}` after we offered privileged names ({}) without credentials. Subprotocol choice can gate access to GraphQL subscriptions, STOMP brokers, OCPP, etc. Bind subprotocol + auth at the handshake.",
                                    negotiated, offered
                                ),
                                target,
                                0.65,
                                Evidence::new()
                                    .with("url", url.clone())
                                    .with("offered", offered)
                                    .with("negotiated", negotiated)
                                    .check("privileged_subprotocol_echoed", true, "server selected attacker-offered subprotocol"),
                            ),
                            &[("category", json!("subprotocol_abuse")), ("url", json!(url))],
                        ));
                    }
                }
            }
        }
    }

    // Host-header smuggling: same Origin but attacker Host / localhost routing.
    if cfg.check_host_injection {
        for evil_host in ["127.0.0.1", "localhost", "evil.internal"] {
            let hij = ws_handshake_opts(
                client,
                &url,
                &HandshakeOpts {
                    origin: Some(OriginMode::Set(cfg.same_origin.clone())),
                    extra_headers: vec![("Host".to_string(), evil_host.to_string())],
                    ..Default::default()
                },
            )
            .await;
            if let Some(h) = hij {
                if h.verified {
                    out.host_injection = true;
                    findings.push(with_fields(
                        finding_rich(
                            ENGINE_ID,
                            &format!("WebSocket Host-header smuggling accepted (Host: {}): {}", evil_host, url),
                            "high",
                            T_SESSION_HIJACK,
                            &format!(
                                "The handshake at {} accepted `Host: {}` while presenting the legitimate Origin. Reverse proxies and virtual-host routers that key routing off Host can be tricked into attaching the wrong backend or skipping tenant isolation.",
                                url, evil_host
                            ),
                            target,
                            0.76,
                            Evidence::new()
                                .with("url", url.clone())
                                .with("injected_host", evil_host)
                                .check("host_header_smuggling", true, "verified 101 with attacker Host header"),
                        ),
                        &[("category", json!("host_injection")), ("url", json!(url))],
                    ));
                    break;
                }
            }
        }
    }

    // Legacy Sec-WebSocket-Version downgrade (hybi 8 / 7).
    if cfg.check_ws_version_downgrade {
        for ver in [8_u8, 7] {
            let down = ws_handshake_opts(
                client,
                &url,
                &HandshakeOpts {
                    origin: Some(OriginMode::Set(cfg.same_origin.clone())),
                    ws_version: Some(ver),
                    ..Default::default()
                },
            )
            .await;
            if let Some(d) = down {
                if d.verified {
                    out.version_downgrade = true;
                    findings.push(with_fields(
                        finding_rich(
                            ENGINE_ID,
                            &format!("WebSocket protocol version downgrade (v{}): {}", ver, url),
                            "medium",
                            T_WEB_PROTO,
                            &format!(
                                "The server completed a verified RFC6455-style upgrade using legacy Sec-WebSocket-Version `{}`. Old hybi stacks lack modern security controls — disable legacy versions and accept only version 13.",
                                ver
                            ),
                            target,
                            0.68,
                            Evidence::new()
                                .with("url", url.clone())
                                .with("ws_version", ver)
                                .check("legacy_ws_version_accepted", true, "verified 101 on Sec-WebSocket-Version < 13"),
                        ),
                        &[("category", json!("ws_version_downgrade")), ("url", json!(url))],
                    ));
                    break;
                }
            }
        }
    }

    out.findings = findings;
    Some(out)
}

// ── Attack-path synthesis ───────────────────────────────────────────────────────

fn synthesize_attack_paths(target: &str, p: &WsPosture) -> Vec<Value> {
    let mut out = Vec::new();
    let mut emit = |title: &str, steps: Vec<&str>, sev: &str, mitre: &str, impact: &str| {
        let ev = Evidence::new()
            .with("kind", "attack_path")
            .with("steps", json!(steps))
            .with("step_count", steps.len());
        out.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Attack path: {}", title),
                sev,
                mitre,
                &format!("{} Chain: {}", impact, steps.join("  →  ")),
                target,
                0.9,
                ev,
            ),
            &[
                ("category", json!("attack_path")),
                ("kill_chain", json!(steps)),
            ],
        ));
    };
    if !p.authenticated_cswsh.is_empty() {
        emit(
            "CSWSH → authenticated session-riding → account takeover",
            vec![
                "victim is logged in and visits an attacker page",
                "the page opens a cross-site WebSocket (cookies auto-sent)",
                "the server accepts the foreign Origin and authenticates via cookie",
                "attacker reads/sends messages as the victim (data theft / account actions)",
            ],
            "critical",
            T_SESSION_HIJACK,
            "Missing Origin validation on a cookie-authenticated WebSocket is full session-riding.",
        );
    } else if !p.cswsh.is_empty() {
        emit(
            "CSWSH → cross-site WebSocket access",
            vec![
                "attacker page opens a cross-site WebSocket to the endpoint",
                "the server accepts the foreign Origin",
                "attacker interacts with the channel from any site",
            ],
            "high",
            T_SESSION_HIJACK,
            "An endpoint that ignores Origin can be driven from any web page.",
        );
    }
    if p.cleartext || !p.tls_downgrade.is_empty() {
        emit(
            "Cleartext ws:// → message interception",
            vec![
                "WebSocket runs over unencrypted ws:// (or TLS origin exposes ws:// downgrade)",
                "a network MITM reads/modifies frames",
                "session tokens and message contents are captured",
            ],
            "high",
            T_SNIFF,
            "Unencrypted WebSocket transport exposes all traffic to a network attacker.",
        );
    }
    if !p.null_origin_cswsh.is_empty() {
        emit(
            "Null-Origin CSWSH → sandboxed iframe session-riding",
            vec![
                "attacker embeds a sandboxed iframe (Origin: null)",
                "victim cookies still attach to the WebSocket upgrade",
                "server accepts null Origin — attacker reads/sends as victim",
            ],
            "high",
            T_SESSION_HIJACK,
            "Origin: null bypasses naive same-origin checks used by many real-time stacks.",
        );
    }
    if !p.subprotocol_abuse.is_empty() {
        emit(
            "Subprotocol smuggling → privileged channel access",
            vec![
                "attacker offers privileged subprotocol names at handshake",
                "server echoes graphql-ws / STOMP / OCPP without auth",
                "attacker subscribes to sensitive real-time feeds",
            ],
            "medium",
            T_WEB_PROTO,
            "Subprotocol negotiation gates access in GraphQL subscriptions, STOMP brokers, and IoT OCPP channels.",
        );
    }
    if !p.signalr_tokens.is_empty() {
        emit(
            "SignalR negotiate token → unauthenticated hub connection",
            vec![
                "attacker POSTs to /negotiate without auth",
                "server returns connectionToken / connectionId",
                "attacker opens WebSocket to hub with stolen token",
            ],
            "high",
            T_WEB_PROTO,
            "Exposed SignalR negotiate tokens enable hub impersonation before WebSocket upgrade.",
        );
    }
    if !p.socketio_sessions.is_empty() {
        emit(
            "Socket.IO polling sid → session hijack → WebSocket upgrade",
            vec![
                "attacker GETs Socket.IO polling transport",
                "server returns live session id (sid)",
                "attacker upgrades to WebSocket with hijacked sid",
            ],
            "medium",
            T_WEB_PROTO,
            "Socket.IO polling sid leakage precedes the WebSocket transport in production deployments.",
        );
    }
    if !p.forwarded_bypass.is_empty() {
        emit(
            "X-Forwarded-* trust → CSWSH through reverse proxy",
            vec![
                "attacker sends foreign Origin with X-Forwarded-Host set to victim",
                "reverse proxy / app trusts forwarded headers for origin reconstruction",
                "handshake succeeds — CSWSH through the proxy layer",
            ],
            "high",
            T_SESSION_HIJACK,
            "Misconfigured proxy Origin handling is a common real-time API bypass class.",
        );
    }
    if !p.sensitive_leaks.is_empty() {
        emit(
            "Unauthenticated WS session → sensitive frame exfiltration",
            vec![
                "attacker opens WebSocket without credentials",
                "server pushes JWT / API key / secret material in a frame",
                "attacker harvests live secrets from the real-time channel",
            ],
            "critical",
            T_WEB_PROTO,
            "Message-level leaks over WebSocket bypass HTTP WAFs and REST log pipelines.",
        );
    }
    if !p.graphql_unauth.is_empty() {
        emit(
            "GraphQL subscription without message auth → live data stream abuse",
            vec![
                "attacker sends connection_init + subscribe over graphql-ws",
                "server returns connection_ack / next payloads",
                "attacker receives live subscription events (PII, trades, alerts)",
            ],
            "high",
            T_WEB_PROTO,
            "GraphQL subscriptions over WebSocket require per-message authorization, not just handshake auth.",
        );
    }
    if !p.stomp_unauth.is_empty() {
        emit(
            "STOMP CONNECT without auth → message broker access",
            vec![
                "attacker sends STOMP CONNECT frame",
                "broker responds CONNECTED",
                "attacker SUBSCRIBEs to queues and exfiltrates messages",
            ],
            "high",
            T_WEB_PROTO,
            "STOMP over WebSocket is common in Java messaging backends — CONNECT must require credentials.",
        );
    }
    if !p.ws_reflection.is_empty() {
        emit(
            "WebSocket reflection → DOM XSS when client renders WS data",
            vec![
                "attacker or MITM sends crafted WS payload",
                "server echoes unsanitized content",
                "victim SPA renders the frame into innerHTML → XSS",
            ],
            "medium",
            T_WEB_PROTO,
            "Real-time UIs that bind WebSocket messages to the DOM are vulnerable to reflected content.",
        );
    }
    if !p.auth_differential.is_empty() {
        emit(
            "Auth-differential bypass → unauthenticated peer reads session data",
            vec![
                "attacker opens WebSocket without credentials",
                "sends identical probes as an authenticated client",
                "server returns the same subscription / sensitive frames",
            ],
            "critical",
            T_WEB_PROTO,
            "Message-level auth must gate every frame — not only the HTTP upgrade.",
        );
    }
    if !p.foreign_origin_data.is_empty() {
        emit(
            "CSWSH message-layer → cross-site real-time data theft",
            vec![
                "attacker page opens WebSocket with foreign Origin",
                "server returns live application frames",
                "attacker JavaScript reads streaming data cross-site",
            ],
            "high",
            T_SESSION_HIJACK,
            "Origin validation must block both handshake and ongoing message exchange.",
        );
    }
    if !p.graphql_introspection.is_empty() {
        emit(
            "GraphQL introspection over graphql-ws → schema exfiltration",
            vec![
                "attacker sends introspection subscribe on live socket",
                "server returns __schema/types/fields metadata",
                "attacker maps the API for targeted queries",
            ],
            "high",
            T_WEB_PROTO,
            "Production graphql-ws endpoints must disable introspection and require connection_init auth.",
        );
    }
    if !p.host_injection.is_empty() {
        emit(
            "Host-header smuggling → wrong backend / tenant routing",
            vec![
                "attacker sends WebSocket upgrade with attacker Host header",
                "proxy routes to unintended vhost/backend",
                "cross-tenant data or admin socket attached",
            ],
            "high",
            T_SESSION_HIJACK,
            "Validate Host against the TLS SNI and configured tenant routing on every upgrade.",
        );
    }
    if !p.stateful_fuzz.is_empty() {
        emit(
            "Stateful WS fuzz → live IDOR / auth-bypass on conversation state",
            vec![
                "attacker opens WebSocket and receives challenge/session frame",
                "state machine extracts session IDs and mutates identifiers/roles",
                "server accepts malicious follow-up frames on the same conversation",
            ],
            "high",
            T_WEB_PROTO,
            "Real-time APIs must validate every frame against server-side session state — not trust client-supplied IDs.",
        );
    }
    if !p.binary_mutation.is_empty() {
        emit(
            "Binary protobuf mutation → role/amount tampering on wire",
            vec![
                "attacker captures or crafts binary WebSocket frame",
                "engine decodes protobuf wire, mutates privileged fields, re-encodes",
                "server processes manipulated binary without schema/auth validation",
            ],
            "high",
            T_WEB_PROTO,
            "Binary gateways must authenticate and schema-validate every frame at the protocol layer.",
        );
    }
    if !p.race_condition.is_empty() {
        emit(
            "Parallel WS race → double-spend / duplicate transaction window",
            vec![
                "attacker opens N simultaneous WebSocket connections",
                "barrier-synchronized transactional frames hit the backend concurrently",
                "duplicate success or sub-ms timing anomaly indicates missing atomicity",
            ],
            "high",
            T_WEB_PROTO,
            "Stateful real-time backends need idempotency keys and server-side serialization for financial/state frames.",
        );
    }
    if !p.cross_protocol_escalation.is_empty() {
        emit(
            "WS token → HTTP/API privilege escalation (cross-protocol chain)",
            vec![
                "attacker harvests JWT/session token from WebSocket server frame",
                "token published to Intelligence Bus and replayed over HTTP REST/GraphQL",
                "privileged HTTP response confirms cross-protocol session riding",
            ],
            "critical",
            T_SESSION_HIJACK,
            "Tokens observed on WebSocket channels must not grant broader HTTP privileges than intended.",
        );
    }
    if !p.missing_origin_cswsh.is_empty() {
        emit(
            "Missing-Origin CSWSH → non-browser client impersonation",
            vec![
                "attacker omits Origin header on WebSocket upgrade",
                "server accepts handshake without Origin validation",
                "automated tooling rides sessions without browser context",
            ],
            "high",
            T_SESSION_HIJACK,
            "Require and validate Origin on every WebSocket upgrade — reject missing Origin.",
        );
    }
    if !p.version_downgrade.is_empty() {
        emit(
            "WebSocket protocol downgrade → legacy parser bugs",
            vec![
                "attacker offers Sec-WebSocket-Version 8 or 7",
                "server completes verified upgrade on legacy hybi draft",
                "legacy parser differential may enable smuggling or auth bypass",
            ],
            "medium",
            T_WEB_PROTO,
            "Accept only Sec-WebSocket-Version 13 (RFC6455) in production.",
        );
    }
    if !p.no_rate_limit.is_empty() {
        emit(
            "Unbounded WS frame rate → DoS / credential stuffing amplifier",
            vec![
                "attacker floods rapid frames on open session",
                "server accepts burst without throttling or close",
                "backend queues saturate — DoS or brute-force amplification",
            ],
            "medium",
            T_WEB_PROTO,
            "Apply per-connection and per-IP rate limits on WebSocket message handlers.",
        );
    }
    if !p.binary_accepted.is_empty() {
        emit(
            "Unauthenticated binary frame processing → protocol injection",
            vec![
                "attacker sends binary WebSocket frame without auth",
                "server parses and responds to attacker-controlled binary payload",
                "gateway treats binary as trusted application input",
            ],
            "medium",
            T_WEB_PROTO,
            "Binary WebSocket endpoints require the same auth and validation as text JSON frames.",
        );
    }
    out
}

// ── Entry points ────────────────────────────────────────────────────────────────

/// Full, GUI-parameterised WebSocket security assessment.
pub async fn run_websocket_attack_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("could not parse host from target");
    }
    let intensity = cfg.intensity();
    let timeout_ms = cfg.timeout_ms(8000);
    let concurrency = cfg.concurrency().clamp(1, 32);

    let is_https = !target.trim().starts_with("http://");
    let scheme = if is_https { "https" } else { "http" };
    let base = format!("{}://{}", scheme, host);
    let same_origin = base.clone();

    let check_cswsh = cfg.bool_or("check_cswsh", true);
    let check_null_origin = cfg.bool_or("check_null_origin", true);
    let check_missing_origin = cfg.bool_or("check_missing_origin", true);
    let check_subprotocols = cfg.bool_or("check_subprotocols", true);
    let check_forwarded_bypass = cfg.bool_or("check_forwarded_bypass", true);
    let check_compression = cfg.bool_or("check_compression", true);
    let check_tls = cfg.bool_or("check_cleartext", true);
    let check_tls_downgrade = cfg.bool_or("check_tls_downgrade", true);
    let check_signalr = cfg.bool_or("check_signalr_negotiate", true);
    let check_socketio = cfg.bool_or("check_socketio_polling", true);
    let check_message_probe = cfg.bool_or("check_message_probe", true);
    let check_sensitive_leak = cfg.bool_or("check_sensitive_leak", true);
    let check_graphql_subscribe = cfg.bool_or("check_graphql_subscribe", true);
    let check_stomp_connect = cfg.bool_or("check_stomp_connect", true);
    let check_message_reflection = cfg.bool_or("check_message_reflection", true);
    let check_js_harvest = cfg.bool_or("check_js_harvest", true);
    let check_host_injection = cfg.bool_or("check_host_injection", true);
    let check_ws_version_downgrade = cfg.bool_or("check_ws_version_downgrade", true);
    let check_auth_differential = cfg.bool_or("check_auth_differential", true);
    let check_foreign_origin_messages = cfg.bool_or("check_foreign_origin_messages", true);
    let check_graphql_introspection = cfg.bool_or("check_graphql_introspection", true);
    let check_ws_rate_limit = cfg.bool_or("check_ws_rate_limit", true);
    let check_binary_frames = cfg.bool_or("check_binary_frames", true);
    let check_stateful_fuzz = cfg.bool_or("check_stateful_fuzz", true);
    let check_binary_mutation = cfg.bool_or("check_binary_mutation", true);
    let check_race_conditions = cfg.bool_or("check_race_conditions", true);
    let check_cross_protocol_chain = cfg.bool_or("check_cross_protocol_chain", true);
    let stateful_fuzz_rounds = cfg.usize_or("stateful_fuzz_rounds", 4).clamp(1, 6) as u8;
    let race_connections = cfg.usize_or("race_connections", 4).clamp(2, 16);
    let race_sync_us = cfg.usize_or("race_sync_us", 0).clamp(0, 50_000) as u64;
    let race_payload = cfg.string_or(
        "race_payload",
        r#"{"type":"subscribe","id":"race-1","payload":{"action":"transfer","amount":1}}"#,
    );
    let http_escalation_paths =
        cfg.string_list_or("http_escalation_paths", DEFAULT_HTTP_ESCALATION_PATHS);
    let ws_burst_count = cfg.usize_or(
        "ws_burst_count",
        match intensity {
            Intensity::Light => 8,
            Intensity::Normal => 12,
            Intensity::Aggressive => 20,
        },
    );
    let message_read_ms = cfg.usize_or("message_read_ms", 3000).clamp(500, 15_000) as u64;
    let max_message_endpoints = cfg.usize_or(
        "max_message_endpoints",
        match intensity {
            Intensity::Light => 2,
            Intensity::Normal => 5,
            Intensity::Aggressive => 12,
        },
    );
    let do_paths = cfg.bool_or("attack_path_synthesis", true);
    let do_score = cfg.bool_or("posture_scoring", true);

    let mut foreign_origins = cfg.string_list_or("foreign_origins", DEFAULT_FOREIGN_ORIGINS);
    let primary_foreign = cfg.string_or("foreign_origin", DEFAULT_FOREIGN_ORIGIN);
    let foreign_origin_probe = primary_foreign.clone();
    if !foreign_origins.iter().any(|o| o == &primary_foreign) {
        foreign_origins.insert(0, primary_foreign);
    }
    foreign_origins.sort();
    foreign_origins.dedup();

    let subprotocols = cfg.string_list_or("subprotocols", DEFAULT_PRIVILEGED_SUBPROTOCOLS);
    let signalr_paths = cfg.string_list_or("signalr_paths", DEFAULT_SIGNALR_NEGOTIATE_PATHS);
    let custom_messages = cfg.string_list_or("custom_messages", &[] as &[&str]);
    let reflection_marker = cfg.string_or(
        "reflection_marker",
        "weissman_ws_xss_probe_<script>alert(1)</script>",
    );

    // JavaScript harvest — expand path list from live page source before probing.
    let mut paths = cfg.string_list_or("paths", DEFAULT_WS_PATHS);
    let mut js_discovered: Vec<String> = Vec::new();
    if check_js_harvest {
        if let Some(page) = http_get(&build_client(timeout_ms), &base).await {
            for discovered in harvest_ws_urls_from_html(&page.body, &base) {
                js_discovered.push(discovered.clone());
                paths.push(discovered);
            }
        }
    }
    for p in ctx.discovered_paths.iter() {
        paths.push(p.clone());
    }
    paths.sort();
    paths.dedup();
    let cap = cfg.usize_or(
        "max_paths",
        match intensity {
            Intensity::Light => 8,
            Intensity::Normal => 18,
            Intensity::Aggressive => 40,
        },
    );
    paths.truncate(cap.max(1));

    // Optional auth (cookie / bearer / header) to test *authenticated* CSWSH.
    let mut auth: Vec<(String, String)> = Vec::new();
    if let Some(c) = cfg.string("cookies").or_else(|| cfg.string("cookie")) {
        auth.push(("Cookie".to_string(), c));
    }
    if let Some(b) = cfg.string("bearer_token") {
        auth.push(("Authorization".to_string(), format!("Bearer {}", b)));
    }
    if let Some(h) = cfg.string("auth_header") {
        if let Some((k, v)) = h.split_once(':') {
            auth.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let client = build_client(timeout_ms);
    let intelligence_bus = ctx
        .intelligence_bus
        .clone()
        .unwrap_or_else(IntelligenceBus::new_shared);
    let mut posture = WsPosture::default();
    posture.checks += 1;
    posture.cookie_provided = !auth.is_empty();
    posture.js_discovered = js_discovered;

    let probe_cfg = EndpointProbeCfg {
        host: host.clone(),
        same_origin: same_origin.clone(),
        foreign_origins,
        auth: auth.clone(),
        check_cswsh,
        check_null_origin,
        check_missing_origin,
        check_compression,
        check_subprotocols,
        check_forwarded_bypass,
        check_host_injection,
        check_ws_version_downgrade,
        subprotocols,
    };

    let mut urls: Vec<String> = paths
        .iter()
        .map(|p| {
            if p.starts_with("http://") || p.starts_with("https://") {
                p.clone()
            } else if p.starts_with("ws://") || p.starts_with("wss://") {
                p.replace("wss://", "https://").replace("ws://", "http://")
            } else {
                format!(
                    "{}/{}",
                    base.trim_end_matches('/'),
                    p.trim_start_matches('/')
                )
            }
        })
        .collect();

    // TLS downgrade sweep: when the origin is HTTPS, also probe cleartext http:// on the same paths.
    if check_tls_downgrade && is_https {
        for p in &paths {
            let u = if p.starts_with("https://") {
                p.replace("https://", "http://")
            } else if p.starts_with("wss://") {
                p.replace("wss://", "http://")
            } else if p.starts_with("http://") || p.starts_with("ws://") {
                continue;
            } else {
                format!("http://{}/{}", host, p.trim_start_matches('/'))
            };
            urls.push(u);
        }
    }
    urls.sort();
    urls.dedup();
    urls.truncate(cap.max(1));

    let results: Vec<EndpointResult> = stream::iter(urls)
        .map(|u| {
            let c = client.clone();
            let pc = probe_cfg.clone();
            async move { probe_endpoint(&c, u, target, &pc).await }
        })
        .buffer_unordered(concurrency)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let mut verified_endpoints: Vec<EndpointResult> = Vec::new();
    let mut findings: Vec<Value> = Vec::new();
    for mut r in results {
        if r.is_endpoint {
            let u = r.url.clone();
            posture.endpoints.push(u.clone());
            if r.verified {
                verified_endpoints.push(EndpointResult {
                    findings: Vec::new(),
                    ..r.clone()
                });
            }
            if r.cswsh {
                posture.cswsh.push(u.clone());
            }
            if r.null_origin_cswsh {
                posture.null_origin_cswsh.push(u.clone());
            }
            if r.missing_origin_cswsh {
                posture.missing_origin_cswsh.push(u.clone());
            }
            if r.auth_cswsh {
                posture.authenticated_cswsh.push(u.clone());
            }
            if r.subprotocol_abuse {
                posture.subprotocol_abuse.push(u.clone());
            }
            if r.forwarded_bypass {
                posture.forwarded_bypass.push(u.clone());
            }
            if r.host_injection {
                posture.host_injection.push(u.clone());
            }
            if r.version_downgrade {
                posture.version_downgrade.push(u.clone());
            }
            if r.tls_downgrade {
                posture.tls_downgrade.push(u.clone());
            }
            if r.unauth {
                posture.unauthenticated.push(u.clone());
            }
        }
        findings.append(&mut r.findings);
    }

    if !posture.js_discovered.is_empty() {
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!(
                    "JavaScript WebSocket URLs harvested from page source ({} path(s))",
                    posture.js_discovered.len()
                ),
                "info",
                T_WEB_PROTO,
                "Live page source references WebSocket endpoints not in the default path list. These were auto-added to the assessment scope.",
                target,
                0.5,
                Evidence::new()
                    .with("discovered", json!(posture.js_discovered))
                    .check("js_harvest", true, "ws/wss URLs mined from HTML/JS"),
            ),
            &[("category", json!("js_ws_harvest"))],
        ));
    }

    // Post-handshake message probing on verified endpoints (real WebSocket sessions).
    let mut enterprise_endpoints = verified_endpoints.clone();
    if check_message_probe && !verified_endpoints.is_empty() {
        let msg_cfg = MessageProbeCfg {
            read_ms: message_read_ms,
            max_messages: cfg.usize_or("max_ws_messages", 12).clamp(1, 40),
            check_sensitive: check_sensitive_leak,
            check_graphql: check_graphql_subscribe,
            check_graphql_introspection,
            check_stomp: check_stomp_connect,
            check_reflection: check_message_reflection,
            check_auth_differential,
            check_foreign_origin_messages,
            check_rate_limit: check_ws_rate_limit,
            check_binary_frames,
            burst_count: ws_burst_count,
            foreign_origin: foreign_origin_probe.clone(),
            custom_messages,
            reflection_marker,
        };
        enterprise_endpoints.truncate(max_message_endpoints.max(1));
        for ep in enterprise_endpoints.iter() {
            let fw = ep.framework.as_deref();
            let sp = ep.subprotocol.as_deref();
            let mut msg_findings = probe_ws_messages(
                &ep.url,
                target,
                &same_origin,
                &auth,
                sp,
                fw,
                &msg_cfg,
                Some(&intelligence_bus),
            )
            .await;
            if check_auth_differential && !auth.is_empty() {
                msg_findings.extend(
                    probe_auth_differential(
                        &ep.url,
                        target,
                        &same_origin,
                        &auth,
                        fw,
                        sp,
                        message_read_ms,
                    )
                    .await,
                );
            }
            if check_foreign_origin_messages {
                msg_findings.extend(
                    probe_foreign_origin_session(
                        &ep.url,
                        target,
                        &foreign_origin_probe,
                        fw,
                        sp,
                        message_read_ms,
                    )
                    .await,
                );
            }
            if check_ws_rate_limit {
                msg_findings.extend(
                    probe_ws_rate_limit_burst(
                        &ep.url,
                        target,
                        &same_origin,
                        ws_burst_count,
                        message_read_ms,
                    )
                    .await,
                );
            }
            if check_binary_frames {
                msg_findings.extend(
                    probe_binary_ws_frames(&ep.url, target, &same_origin, message_read_ms).await,
                );
            }
            for f in &msg_findings {
                let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
                let url = f
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or(&ep.url)
                    .to_string();
                match cat {
                    "ws_sensitive_leak" => posture.sensitive_leaks.push(url),
                    "graphql_ws_unauth" => posture.graphql_unauth.push(url),
                    "graphql_ws_introspection" => posture.graphql_introspection.push(url),
                    "stomp_unauth" => posture.stomp_unauth.push(url),
                    "ws_reflection" => posture.ws_reflection.push(url),
                    "ws_verbose_error" => posture.verbose_errors.push(url),
                    "auth_differential" => posture.auth_differential.push(url),
                    "foreign_origin_data" => posture.foreign_origin_data.push(url),
                    "ws_no_rate_limit" => posture.no_rate_limit.push(url),
                    "ws_binary_accepted" => posture.binary_accepted.push(url),
                    "ws_stateful_fuzz" => posture.stateful_fuzz.push(url),
                    "ws_binary_mutation" => posture.binary_mutation.push(url),
                    "ws_race_condition" => posture.race_condition.push(url),
                    "cross_protocol_escalation" => posture.cross_protocol_escalation.push(url),
                    _ => {}
                }
            }
            findings.extend(msg_findings);
        }
    }

    // Weissman Standard — stateful fuzz, binary mutation, race execution, cross-protocol chain.
    let enterprise_tier = check_stateful_fuzz
        || check_binary_mutation
        || check_race_conditions
        || check_cross_protocol_chain;
    if enterprise_tier && !enterprise_endpoints.is_empty() {
        enterprise_endpoints.truncate(max_message_endpoints.max(1));
        let escalation_paths: Vec<&str> =
            http_escalation_paths.iter().map(|s| s.as_str()).collect();
        for ep in &enterprise_endpoints {
            let fw = ep.framework.as_deref();
            let sp = ep.subprotocol.as_deref();
            if check_stateful_fuzz {
                let tier_findings = probe_stateful_conversational_fuzz(
                    &ep.url,
                    target,
                    &same_origin,
                    &auth,
                    sp,
                    fw,
                    message_read_ms,
                    stateful_fuzz_rounds,
                    &intelligence_bus,
                )
                .await;
                for f in &tier_findings {
                    posture.stateful_fuzz.push(
                        f.get("url")
                            .and_then(Value::as_str)
                            .unwrap_or(&ep.url)
                            .to_string(),
                    );
                }
                findings.extend(tier_findings);
            }
            if check_binary_mutation {
                let tier_findings = probe_binary_frame_mutation(
                    &ep.url,
                    target,
                    &same_origin,
                    &auth,
                    sp,
                    message_read_ms,
                    &intelligence_bus,
                )
                .await;
                for f in &tier_findings {
                    posture.binary_mutation.push(
                        f.get("url")
                            .and_then(Value::as_str)
                            .unwrap_or(&ep.url)
                            .to_string(),
                    );
                }
                findings.extend(tier_findings);
            }
            if check_race_conditions {
                let tier_findings = probe_ws_race_condition(
                    &ep.url,
                    target,
                    &same_origin,
                    &auth,
                    sp,
                    message_read_ms,
                    race_connections,
                    race_sync_us,
                    &race_payload,
                )
                .await;
                for f in &tier_findings {
                    posture.race_condition.push(
                        f.get("url")
                            .and_then(Value::as_str)
                            .unwrap_or(&ep.url)
                            .to_string(),
                    );
                }
                findings.extend(tier_findings);
            }
        }
        if check_cross_protocol_chain && !intelligence_bus.snapshot_for_cross_protocol().is_empty()
        {
            let chain_findings = verify_cross_protocol_escalation(
                &client,
                &base,
                target,
                &intelligence_bus,
                &escalation_paths,
            )
            .await;
            for f in &chain_findings {
                posture.cross_protocol_escalation.push(
                    f.get("url")
                        .and_then(Value::as_str)
                        .unwrap_or(&base)
                        .to_string(),
                );
            }
            findings.extend(chain_findings);
        }
    }

    // SignalR negotiate — real HTTP probe that precedes the WebSocket upgrade in ASP.NET stacks.
    if check_signalr {
        for (path, token) in
            probe_signalr_negotiate(&client, &base, &signalr_paths, &same_origin).await
        {
            posture.signalr_tokens.push(path.clone());
            intelligence_bus.publish_token("connectionToken", &token, &path, "signalr_negotiate");
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("SignalR negotiate token exposed: {}", path),
                    "medium",
                    T_WEB_PROTO,
                    "The SignalR /negotiate endpoint returned a connectionToken or connectionId without authentication. An attacker can use this token to open a WebSocket to the hub and impersonate a client. Require auth on negotiate and bind tokens to the authenticated session.",
                    target,
                    0.75,
                    Evidence::new()
                        .with("url", path.clone())
                        .with("token_prefix", token.chars().take(12).collect::<String>())
                        .check("negotiate_token_returned", true, "connectionToken/connectionId in 200 response"),
                ),
                &[("category", json!("signalr_negotiate")), ("url", json!(path))],
            ));
        }
    }

    // Socket.IO polling sid — real transport probe before WebSocket upgrade.
    if check_socketio {
        if let Some((poll_url, sid)) = probe_socketio_polling(&client, &base, &same_origin).await {
            posture.socketio_sessions.push(poll_url.clone());
            findings.push(with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("Socket.IO polling session id (sid) exposed: {}", poll_url),
                    "low",
                    T_WEB_PROTO,
                    "The Socket.IO long-polling transport returned a live session id without credentials. Combined with weak Origin validation, an attacker can hijack the polling session and upgrade to WebSocket. Require auth on the Engine.IO handshake and rotate sids aggressively.",
                    target,
                    0.6,
                    Evidence::new()
                        .with("url", poll_url.clone())
                        .with("sid_prefix", sid.chars().take(10).collect::<String>())
                        .check("socketio_sid_returned", true, "sid in polling transport body"),
                ),
                &[("category", json!("socketio_polling")), ("url", json!(poll_url))],
            ));
        }
    }

    // Cleartext transport (target served over http:// → ws://).
    if check_tls && !is_https && !posture.endpoints.is_empty() {
        posture.cleartext = true;
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Cleartext WebSocket (ws://) in use",
                "medium",
                T_SNIFF,
                "WebSocket endpoints are served over unencrypted ws:// (the target is plain HTTP). A network attacker can read and tamper with all frames, including auth tokens. Serve WebSockets over wss:// (TLS) only and enable HSTS.",
                target,
                0.7,
                Evidence::new().with("scheme", scheme).check("cleartext_transport", true, "no TLS on the WebSocket origin"),
            ),
            &[("category", json!("ws_cleartext"))],
        ));
    }

    // Page-source hint when no endpoint resolved from the path list.
    if posture.endpoints.is_empty() {
        if let Some(p) = http_get(&client, &base).await {
            let b = p.body.to_ascii_lowercase();
            if b.contains("new websocket(")
                || b.contains("io.connect(")
                || b.contains("socket.io")
                || b.contains("websocket")
            {
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        "WebSocket client code detected (endpoint not resolved)",
                        "info",
                        T_WEB_PROTO,
                        "The page references WebSocket client code but no endpoint resolved from the default path list. Supply the exact WebSocket path via the `paths` parameter and re-run to assess Origin validation and authentication.",
                        target,
                        0.4,
                        Evidence::new().with("url", base.clone()).check("client_code_reference", true, "WebSocket usage referenced in page source"),
                    ),
                    &[("category", json!("ws_hint"))],
                ));
            }
        }
    }

    if do_paths {
        findings.extend(synthesize_attack_paths(target, &posture));
    }

    if do_score && (posture.has_any() || !posture.endpoints.is_empty()) {
        let score = posture.score();
        let grade = posture.grade();
        let weak = posture.weak_categories();
        let worst = posture.worst_severity();
        let ev = Evidence::new()
            .with("score", score)
            .with("grade", grade)
            .with("posture_score", score)
            .with("worst_severity", worst)
            .with("weak_categories", json!(weak))
            .with("endpoints", json!(posture.endpoints))
            .with("cswsh", json!(posture.cswsh))
            .with("null_origin_cswsh", json!(posture.null_origin_cswsh))
            .with("missing_origin_cswsh", json!(posture.missing_origin_cswsh))
            .with("authenticated_cswsh", json!(posture.authenticated_cswsh))
            .with("subprotocol_abuse", json!(posture.subprotocol_abuse))
            .with("forwarded_bypass", json!(posture.forwarded_bypass))
            .with("tls_downgrade", json!(posture.tls_downgrade))
            .with("signalr_tokens", json!(posture.signalr_tokens))
            .with("socketio_sessions", json!(posture.socketio_sessions))
            .with("sensitive_leaks", json!(posture.sensitive_leaks))
            .with("graphql_unauth", json!(posture.graphql_unauth))
            .with("stomp_unauth", json!(posture.stomp_unauth))
            .with("ws_reflection", json!(posture.ws_reflection))
            .with("auth_differential", json!(posture.auth_differential))
            .with("foreign_origin_data", json!(posture.foreign_origin_data))
            .with("host_injection", json!(posture.host_injection))
            .with("version_downgrade", json!(posture.version_downgrade))
            .with(
                "graphql_introspection",
                json!(posture.graphql_introspection),
            )
            .with("no_rate_limit", json!(posture.no_rate_limit))
            .with("stateful_fuzz", json!(posture.stateful_fuzz))
            .with("binary_mutation", json!(posture.binary_mutation))
            .with("race_condition", json!(posture.race_condition))
            .with(
                "cross_protocol_escalation",
                json!(posture.cross_protocol_escalation),
            )
            .with("intelligence_artifacts", intelligence_bus.export_json())
            .with("js_discovered", json!(posture.js_discovered))
            .with("cleartext", posture.cleartext)
            .with("unauthenticated", json!(posture.unauthenticated))
            .with("session_cookie_supplied", posture.cookie_provided);
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("WebSocket Posture: {}/100 (Grade {})", score, grade),
                "info",
                T_WEB_PROTO,
                &format!(
                    "Quantified WebSocket security posture for {} from {} verified endpoint(s).",
                    host,
                    posture.endpoints.len()
                ),
                target,
                1.0,
                ev,
            ),
            &[
                ("category", json!("posture_summary")),
                ("score", json!(score)),
                ("grade", json!(grade)),
                ("posture_score", json!(score)),
                ("worst_severity", json!(worst)),
                ("weak_categories", json!(weak)),
                ("summary", json!(true)),
            ],
        ));
    }

    if findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    let summary = format!(
        "websocket_attack: {} finding(s) on {} · {} endpoint(s) · {} CSWSH ({} auth-riding) · {} null-origin · {} subprotocol · {} sensitive-leak · posture {}/100 ({})",
        findings.len(),
        host,
        posture.endpoints.len(),
        posture.cswsh.len(),
        posture.authenticated_cswsh.len(),
        posture.null_origin_cswsh.len(),
        posture.subprotocol_abuse.len(),
        posture.sensitive_leaks.len(),
        posture.score(),
        posture.grade()
    );
    EngineResult::ok(findings, summary)
}

/// Backward-compatible entry (default parameters) — used by alias engines + the CLI wrapper.
pub async fn run_websocket_attack_result(target: &str) -> EngineResult {
    run_websocket_attack_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_websocket_attack(target: &str) {
    print_result(run_websocket_attack_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_accept_matches_rfc6455_vector() {
        // The canonical RFC 6455 §1.3 example.
        assert_eq!(
            ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn random_key_is_valid_base64_16_bytes() {
        let k = random_ws_key();
        let decoded = openssl::base64::decode_block(&k).unwrap_or_default();
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn framework_fingerprint() {
        assert_eq!(framework_of("/socket.io/?EIO=4", None), Some("Socket.IO"));
        assert_eq!(framework_of("/cable", None), Some("Rails Action Cable"));
        assert_eq!(
            framework_of("/ws", Some("graphql-transport-ws")),
            Some("graphql-ws (GraphQL subscriptions)")
        );
        assert!(framework_of("/ws", None).is_none());
    }

    #[test]
    fn posture_reacts_to_authenticated_cswsh() {
        let mut p = WsPosture::default();
        assert_eq!(p.score(), 100);
        assert_eq!(p.grade(), "A");
        p.endpoints.push("wss://x/ws".into());
        p.cswsh.push("wss://x/ws".into());
        p.authenticated_cswsh.push("wss://x/ws".into());
        assert!(p.score() < 50);
        assert!(p.has_any());
    }

    fn attack_paths_cover_weissman_standard() {
        let mut p = WsPosture::default();
        p.stateful_fuzz.push("wss://x/ws".into());
        p.binary_mutation.push("wss://x/ws".into());
        p.race_condition.push("wss://x/ws".into());
        p.cross_protocol_escalation.push("https://x/api/me".into());
        let paths = synthesize_attack_paths("https://x", &p);
        assert!(paths.len() >= 4);
        assert!(paths.iter().all(|f| f["category"] == json!("attack_path")));
    }

    #[test]
    fn attack_paths_scale_with_severity() {
        assert!(synthesize_attack_paths("https://x", &WsPosture::default()).is_empty());
        let mut p = WsPosture::default();
        p.authenticated_cswsh.push("wss://x/ws".into());
        let paths = synthesize_attack_paths("https://x", &p);
        assert!(paths.iter().any(|f| f["severity"] == "critical"));
        assert!(paths.iter().all(|f| f["category"] == json!("attack_path")));
    }

    #[test]
    fn socketio_sid_parsing() {
        assert_eq!(
            socketio_sid_from_body(r#"0{"sid":"abc123","upgrades":["websocket"]}"#),
            Some("abc123".into())
        );
        assert!(socketio_sid_from_body("invalid").is_none());
    }

    #[test]
    fn posture_penalizes_tls_downgrade() {
        let mut p = WsPosture::default();
        p.endpoints.push("http://x/ws".into());
        p.tls_downgrade.push("http://x/ws".into());
        assert!(p.score() < 80);
    }

    #[test]
    fn harvest_ws_urls_from_js() {
        let html = r#"
            const s = new WebSocket("wss://app.example.com/live/chat");
            connect("ws://internal.example/ws");
        "#;
        let urls = harvest_ws_urls_from_html(html, "https://app.example.com");
        assert!(urls.iter().any(|u| u.contains("/live/chat")));
        assert!(urls.iter().any(|u| u.contains("internal.example")));
    }

    #[test]
    fn scan_sensitive_detects_jwt() {
        let hits = scan_sensitive("token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig");
        assert!(hits.iter().any(|h| h.kind == "jwt"));
    }

    #[test]
    fn framework_message_probes_graphql() {
        let probes = framework_message_probes(
            Some("GraphQL subscriptions"),
            Some("graphql-transport-ws"),
            true,
            true,
            false,
            "marker",
        );
        assert!(probes.iter().any(|p| p.contains("connection_init")));
        assert!(probes.iter().any(|p| p.contains("subscribe")));
        assert!(probes.iter().any(|p| p.contains("__schema")));
    }

    #[test]
    fn graphql_introspection_detector() {
        assert!(graphql_introspection_leak(&[
            r#"{"type":"next","payload":{"data":{"__schema":{"queryType":{"name":"Query"}}}}}"#
                .into()
        ]));
    }

    #[test]
    fn auth_differential_posture() {
        let mut p = WsPosture::default();
        p.auth_differential.push("wss://x/ws".into());
        assert!(p.score() < 80);
        assert_eq!(p.worst_severity(), "critical");
        assert!(p.weak_categories().contains(&"auth_differential"));
    }

    #[test]
    fn posture_penalizes_sensitive_leak() {
        let mut p = WsPosture::default();
        p.sensitive_leaks.push("wss://x/ws".into());
        assert!(p.score() < 85);
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_websocket_attack_result_ctx("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }
}
