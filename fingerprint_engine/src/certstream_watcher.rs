//! Live Certificate Transparency squirt — push when a cert is issued, not crt.sh polling.
//!
//! Connects to a Certstream-compatible WebSocket (default `wss://certstream.calidog.io/`),
//! matches SANs against authorized client apexes, and enqueues `first_mover_delta_fusion`
//! with `extra_hosts` so the new FQDN is probed AND exploit-proofed immediately (RoE-gated).
//!
//! Empty scope or a down feed is honest: no hunts, visible nerve-center status. Never
//! fabricates findings from CT.

use crate::first_mover_surface_delta::in_authorized_scope;
use futures::StreamExt;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

const DEFAULT_URL: &str = "wss://certstream.calidog.io/";
const SCOPE_REFRESH: Duration = Duration::from_secs(45);
const DEDUP_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_ENQUEUE_PER_MIN: u64 = 12;
const BACKOFF_MIN: u64 = 1;
const BACKOFF_MAX: u64 = 60;

#[derive(Clone, Debug)]
struct ScopeRow {
    tenant_id: i64,
    client_id: i64,
    apex: String,
}

struct Nerve {
    connected: AtomicBool,
    enabled: AtomicBool,
    certs_seen: AtomicU64,
    matches: AtomicU64,
    hunts: AtomicU64,
    last_cert_unix: AtomicU64,
    last_error: Mutex<String>,
    url: Mutex<String>,
}

impl Nerve {
    fn new() -> Self {
        Self {
            connected: AtomicBool::new(false),
            enabled: AtomicBool::new(false),
            certs_seen: AtomicU64::new(0),
            matches: AtomicU64::new(0),
            hunts: AtomicU64::new(0),
            last_cert_unix: AtomicU64::new(0),
            last_error: Mutex::new(String::new()),
            url: Mutex::new(DEFAULT_URL.to_string()),
        }
    }
}

fn nerve() -> &'static Nerve {
    static N: OnceLock<Nerve> = OnceLock::new();
    N.get_or_init(Nerve::new)
}

fn certstream_enabled() -> bool {
    match std::env::var("WEISSMAN_CERTSTREAM_ENABLED") {
        Ok(v) => matches!(v.trim(), "1" | "true" | "yes" | "on"),
        Err(_) => true,
    }
}

fn certstream_url() -> String {
    let u = std::env::var("WEISSMAN_CERTSTREAM_URL").unwrap_or_default();
    let u = u.trim();
    if u.is_empty() {
        DEFAULT_URL.to_string()
    } else {
        u.to_string()
    }
}

/// Operator nerve-center JSON (live counters, no secrets).
#[must_use]
pub fn watcher_status_json() -> Value {
    let n = nerve();
    json!({
        "enabled": n.enabled.load(Ordering::Relaxed),
        "connected": n.connected.load(Ordering::Relaxed),
        "url": n.url.lock().map(|s| s.clone()).unwrap_or_default(),
        "certs_seen": n.certs_seen.load(Ordering::Relaxed),
        "in_scope_matches": n.matches.load(Ordering::Relaxed),
        "hunts_enqueued": n.hunts.load(Ordering::Relaxed),
        "last_cert_unix": n.last_cert_unix.load(Ordering::Relaxed),
        "last_error": n.last_error.lock().map(|s| s.clone()).unwrap_or_default(),
    })
}

fn set_error(msg: impl Into<String>) {
    if let Ok(mut g) = nerve().last_error.lock() {
        *g = msg.into();
    }
}

/// Normalize a client domain / URL into an apex hostname.
#[must_use]
pub fn apex_from_domain(raw: &str) -> Option<String> {
    let t = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("*.")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if t.len() < 4 || !t.contains('.') || t.starts_with('.') {
        return None;
    }
    if t.chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return None;
    }
    Some(t)
}

/// SANs / CN list from a Certstream `certificate_update` frame.
#[must_use]
pub fn sans_from_certstream(v: &Value) -> Vec<String> {
    let mut out: HashSet<String> = HashSet::new();
    let push = |raw: &str, out: &mut HashSet<String>| {
        let n = raw
            .trim()
            .trim_start_matches("DNS:")
            .trim_start_matches("dns:")
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if let Some(a) = apex_from_domain(&n) {
            out.insert(a);
        }
    };
    if let Some(arr) = v
        .pointer("/data/leaf_cert/all_domains")
        .and_then(Value::as_array)
    {
        for d in arr {
            if let Some(s) = d.as_str() {
                push(s, &mut out);
            }
        }
    }
    if let Some(cn) = v
        .pointer("/data/leaf_cert/subject/CN")
        .and_then(Value::as_str)
    {
        push(cn, &mut out);
    }
    if let Some(san) = v
        .pointer("/data/leaf_cert/extensions/subjectAltName")
        .and_then(Value::as_str)
    {
        for part in san.split([',', ';']) {
            push(part, &mut out);
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v
}

#[must_use]
fn match_sans_to_scope(sans: &[String], scope: &[ScopeRow]) -> Vec<(ScopeRow, String)> {
    let mut hits = Vec::new();
    let mut seen: HashSet<(i64, i64, String)> = HashSet::new();
    for san in sans {
        for row in scope {
            if in_authorized_scope(&row.apex, san)
                && seen.insert((row.tenant_id, row.client_id, san.clone()))
            {
                hits.push((row.clone(), san.clone()));
            }
        }
    }
    hits
}

async fn load_scope(app_pool: &PgPool, auth_pool: &PgPool) -> Vec<ScopeRow> {
    let tenants: Vec<i64> = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true")
        .fetch_all(auth_pool)
        .await
        .unwrap_or_default();
    let mut out = Vec::new();
    for tenant_id in tenants {
        let Ok(mut tx) = crate::db::begin_tenant_tx(app_pool, tenant_id).await else {
            continue;
        };
        let rows =
            sqlx::query("SELECT id, COALESCE(domains, '[]') AS domains FROM clients ORDER BY id")
                .fetch_all(&mut *tx)
                .await
                .unwrap_or_default();
        let _ = tx.commit().await;
        for r in rows {
            let client_id: i64 = r.try_get("id").unwrap_or(0);
            if client_id <= 0 {
                continue;
            }
            let raw: String = r.try_get("domains").unwrap_or_else(|_| "[]".into());
            let domains: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
            for d in domains {
                if let Some(apex) = apex_from_domain(&d) {
                    out.push(ScopeRow {
                        tenant_id,
                        client_id,
                        apex,
                    });
                }
            }
        }
    }
    out
}

struct Dedup {
    seen: HashMap<String, Instant>,
    window_start: Instant,
    window_count: u64,
}

impl Dedup {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
            window_start: Instant::now(),
            window_count: 0,
        }
    }

    fn allow(&mut self, tenant_id: i64, client_id: i64, fqdn: &str) -> bool {
        let now = Instant::now();
        self.seen.retain(|_, t| now.duration_since(*t) < DEDUP_TTL);
        if now.duration_since(self.window_start) >= Duration::from_secs(60) {
            self.window_start = now;
            self.window_count = 0;
        }
        if self.window_count >= MAX_ENQUEUE_PER_MIN {
            return false;
        }
        let key = format!("{tenant_id}:{client_id}:{fqdn}");
        if self.seen.contains_key(&key) {
            return false;
        }
        self.seen.insert(key, now);
        self.window_count += 1;
        true
    }
}

const CT_SQUIRT_ENGINE: &str = "first_mover_delta_fusion";

/// Job payload for a Certstream SAN that matched an authorized apex.
#[must_use]
pub fn ct_squirt_payload(client_id: i64, apex: &str, fqdn: &str) -> Value {
    json!({
        "engine": CT_SQUIRT_ENGINE,
        "target": apex,
        "client_id": client_id,
        "extra_hosts": [fqdn],
        "include_ct": false,
        "include_http": true,
        "chain_web_engines": false,
        "fusion_inline": true,
        "trigger": "certstream",
    })
}

async fn enqueue_hunt(pool: &PgPool, tenant_id: i64, client_id: i64, apex: &str, fqdn: &str) {
    let payload = ct_squirt_payload(client_id, apex, fqdn);
    match crate::async_jobs::enqueue(pool, tenant_id, "command_center_engine", payload, None).await
    {
        Ok(_) => {
            nerve().hunts.fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                target: "certstream",
                tenant_id,
                client_id,
                apex,
                fqdn,
                "CT squirt → delta fusion hunt"
            );
        }
        Err(e) => {
            tracing::warn!(target: "certstream", tenant_id, client_id, error = %e, "enqueue failed");
            set_error(format!("enqueue: {e}"));
        }
    }
}

async fn handle_frame(v: &Value, scope: &[ScopeRow], pool: &PgPool, dedup: &mut Dedup) {
    let msg = v.get("message_type").and_then(Value::as_str).unwrap_or("");
    if msg == "heartbeat" {
        return;
    }
    if msg != "certificate_update" && v.pointer("/data/leaf_cert").is_none() {
        return;
    }
    nerve().certs_seen.fetch_add(1, Ordering::Relaxed);
    nerve().last_cert_unix.store(
        chrono::Utc::now().timestamp().max(0) as u64,
        Ordering::Relaxed,
    );
    let sans = sans_from_certstream(v);
    if sans.is_empty() || scope.is_empty() {
        return;
    }
    let hits = match_sans_to_scope(&sans, scope);
    if hits.is_empty() {
        return;
    }
    nerve()
        .matches
        .fetch_add(hits.len() as u64, Ordering::Relaxed);
    for (row, fqdn) in hits {
        if !dedup.allow(row.tenant_id, row.client_id, &fqdn) {
            continue;
        }
        enqueue_hunt(pool, row.tenant_id, row.client_id, &row.apex, &fqdn).await;
    }
}

async fn connect_and_read(url: &str, app_pool: &PgPool, auth_pool: &PgPool) -> Result<(), String> {
    let connector = crate::ws_session::build_ws_connector();
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(url, None, false, connector)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    nerve().connected.store(true, Ordering::Relaxed);
    set_error("");
    tracing::info!(target: "certstream", url, "CT squirt connected");

    let (_write, mut read) = ws.split();
    let mut scope = load_scope(app_pool, auth_pool).await;
    let mut last_scope = Instant::now();
    let mut dedup = Dedup::new();

    while let Some(msg) = read.next().await {
        if last_scope.elapsed() >= SCOPE_REFRESH {
            scope = load_scope(app_pool, auth_pool).await;
            last_scope = Instant::now();
        }
        match msg {
            Ok(Message::Text(t)) => {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    handle_frame(&v, &scope, app_pool, &mut dedup).await;
                }
            }
            Ok(Message::Binary(b)) => {
                if let Ok(v) = serde_json::from_slice::<Value>(&b) {
                    handle_frame(&v, &scope, app_pool, &mut dedup).await;
                }
            }
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
            Ok(Message::Close(_)) => {
                return Err("server closed".into());
            }
            Err(e) => return Err(format!("ws: {e}")),
        }
    }
    Err("stream ended".into())
}

async fn run_loop(app_pool: Arc<PgPool>, auth_pool: Arc<PgPool>) {
    let url = certstream_url();
    if let Ok(mut g) = nerve().url.lock() {
        *g = url.clone();
    }
    let mut backoff = BACKOFF_MIN;
    loop {
        if !certstream_enabled() {
            nerve().enabled.store(false, Ordering::Relaxed);
            nerve().connected.store(false, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        }
        nerve().enabled.store(true, Ordering::Relaxed);
        match connect_and_read(&url, app_pool.as_ref(), auth_pool.as_ref()).await {
            Ok(()) => backoff = BACKOFF_MIN,
            Err(e) => {
                nerve().connected.store(false, Ordering::Relaxed);
                set_error(&e);
                tracing::warn!(target: "certstream", error = %e, backoff_s = backoff, "CT squirt reconnect");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// Leader-only: live CT websocket → in-scope first-mover hunts.
pub fn spawn_certstream_watcher(app_pool: Arc<PgPool>, auth_pool: Arc<PgPool>) {
    static SPAWNED: OnceLock<()> = OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    if !certstream_enabled() {
        nerve().enabled.store(false, Ordering::Relaxed);
        tracing::info!(target: "certstream", "CT squirt disabled (WEISSMAN_CERTSTREAM_ENABLED)");
        return;
    }
    nerve().enabled.store(true, Ordering::Relaxed);
    tokio::spawn(async move {
        run_loop(app_pool, auth_pool).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apex_strips_scheme_and_wildcard() {
        assert_eq!(
            apex_from_domain("https://api.example.com/path"),
            Some("api.example.com".into())
        );
        assert_eq!(
            apex_from_domain("*.shop.example.com"),
            Some("shop.example.com".into())
        );
        assert!(apex_from_domain("localhost").is_none());
        assert!(apex_from_domain("").is_none());
    }

    #[test]
    fn sans_parse_certstream_all_domains() {
        let v = json!({
            "message_type": "certificate_update",
            "data": {
                "leaf_cert": {
                    "all_domains": ["www.acme.test", "*.cdn.acme.test", "acme.test"],
                    "subject": {"CN": "acme.test"}
                }
            }
        });
        let s = sans_from_certstream(&v);
        assert!(s.contains(&"www.acme.test".into()));
        assert!(s.contains(&"cdn.acme.test".into()));
        assert!(s.contains(&"acme.test".into()));
    }

    #[test]
    fn scope_match_is_roe_gated() {
        let scope = vec![ScopeRow {
            tenant_id: 1,
            client_id: 9,
            apex: "acme.test".into(),
        }];
        let hits = match_sans_to_scope(
            &["api.acme.test".into(), "acme.test.evil.example".into()],
            &scope,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "api.acme.test");
    }

    #[test]
    fn dedup_blocks_same_host_within_ttl() {
        let mut d = Dedup::new();
        assert!(d.allow(1, 2, "a.acme.test"));
        assert!(!d.allow(1, 2, "a.acme.test"));
        assert!(d.allow(1, 2, "b.acme.test"));
    }

    #[test]
    fn ct_squirt_payload_is_inline_fusion_not_async_chain() {
        let p = ct_squirt_payload(9, "acme.test", "shop.acme.test");
        assert_eq!(p["engine"], CT_SQUIRT_ENGINE);
        assert_eq!(p["target"], "acme.test");
        assert_eq!(p["client_id"], 9);
        assert_eq!(p["extra_hosts"][0], "shop.acme.test");
        assert_eq!(p["trigger"], "certstream");
        assert_eq!(p["fusion_inline"], true);
        assert_eq!(p["chain_web_engines"], false);
    }
}
