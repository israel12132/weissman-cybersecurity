//! Endpoint agent state: enrollment, session, task dispatch, finding ingestion.
//!
//! Concurrent design:
//!   * `AgentRegistry` is a process-local map from `agent_uuid` to an `mpsc::Sender<ServerToAgent>`
//!     for the currently-active WebSocket session.
//!   * A new WS connection replaces any prior sender for that agent (latest-connection-wins).
//!   * Task dispatch reads the registry; if no live agent for the client, the task is queued in
//!     `endpoint_agent_tasks` with `status='pending'` and an `expires_at` (15min).
//!   * When an agent comes online, the server replays any non-expired pending tasks for that
//!     client.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Remote presence entries older than this are treated as offline (replica crash / network loss).
pub const REMOTE_PRESENCE_STALE_AFTER: Duration = Duration::from_secs(120);

/// Maximum endpoint agents dispatched per fleet operation (NSSI bridge, round-robin).
pub const FLEET_MAX_AGENTS: i32 = 30;
/// Pending tasks replayed when an agent reconnects.
pub const PENDING_TASK_REPLAY_LIMIT: i32 = 500;
/// Agent status listing cap (dashboard).
pub const AGENT_STATUS_LIMIT: i32 = 10_000;

static GLOBAL_REGISTRY: OnceLock<Arc<AgentRegistry>> = OnceLock::new();

/// Engines dispatched to real endpoint agents during NSSI `endpoint_bridge`.
pub const NSSI_BRIDGE_ENGINES: &[&str] = &[
    "process_inventory",
    "arp_spoofing_engine",
    "usb_enumeration",
    "log_tampering_engine",
    "persistence_mechanism",
    "av_bypass_engine",
    "ueba_baseline",
    "process_hollowing",
    "clipboard_hijack",
    "dns_tunneling_c2",
];

fn parse_ueba_ingest(
    finding: &Value,
    client_id: i64,
) -> Option<crate::ueba_detector::UebaIngestPayload> {
    let agent_id = finding
        .get("agent_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();
    let hour_of_week = finding
        .get("hour_of_week")
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .clamp(0, 167) as i16;
    let metrics = finding
        .get("metrics")
        .cloned()
        .or_else(|| finding.get("raw_metrics").cloned())
        .filter(|v| !v.is_null())?;
    Some(crate::ueba_detector::UebaIngestPayload {
        agent_id,
        client_id: finding
            .get("client_id")
            .and_then(Value::as_i64)
            .unwrap_or(client_id),
        hour_of_week,
        metrics,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerToAgent {
    Welcome {
        scan_concurrency: Option<u32>,
        heartbeat_secs: Option<u64>,
    },
    Task {
        task_id: String,
        engine: String,
        target: Option<String>,
        params: Value,
    },
    Ack {
        task_id: String,
    },
    Shutdown {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub tenant_id: i64,
    pub client_id: i64,
    pub session_jwt: String,
    pub ws_path: String,
    pub server_message: Option<String>,
}

#[derive(Clone, Debug)]
struct RemotePresence {
    replica_id: String,
    #[allow(dead_code)]
    tenant_id: i64,
    status: String,
    updated_at: Instant,
}

pub struct AgentRegistry {
    inner: RwLock<HashMap<String, Sender<ServerToAgent>>>,
    remote: RwLock<HashMap<String, RemotePresence>>,
    dispatch_cursor: AtomicUsize,
    sync: OnceLock<Arc<crate::agent_registry_sync::AgentRegistrySync>>,
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            remote: RwLock::new(HashMap::new()),
            dispatch_cursor: AtomicUsize::new(0),
            sync: OnceLock::new(),
        }
    }
}

impl AgentRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Process-wide registry shared by HTTP handlers and async job executor.
    pub fn global() -> Arc<Self> {
        GLOBAL_REGISTRY
            .get_or_init(|| Self::new())
            .clone()
    }

    /// Wire Redis pub-sub (call once at HTTP startup when `REDIS_URL` is set).
    pub fn set_sync(&self, sync: Arc<crate::agent_registry_sync::AgentRegistrySync>) {
        let _ = self.sync.set(sync);
    }

    fn sync(&self) -> Option<&Arc<crate::agent_registry_sync::AgentRegistrySync>> {
        self.sync.get()
    }

    fn remote_is_live(presence: &RemotePresence) -> bool {
        presence.status != "offline"
            && presence.updated_at.elapsed() < REMOTE_PRESENCE_STALE_AFTER
    }

    pub async fn apply_remote_event(
        &self,
        sync: &crate::agent_registry_sync::AgentRegistrySync,
        raw: &str,
    ) {
        let Ok(event) = serde_json::from_str::<crate::agent_registry_sync::AgentSyncEvent>(raw)
        else {
            return;
        };
        match event {
            crate::agent_registry_sync::AgentSyncEvent::Attach {
                replica_id,
                agent_uuid,
                tenant_id,
                ..
            } => {
                if replica_id == sync.replica_id {
                    return;
                }
                if self.inner.read().await.contains_key(&agent_uuid) {
                    return;
                }
                let mut remote = self.remote.write().await;
                remote.insert(
                    agent_uuid,
                    RemotePresence {
                        replica_id,
                        tenant_id,
                        status: "online".into(),
                        updated_at: Instant::now(),
                    },
                );
            }
            crate::agent_registry_sync::AgentSyncEvent::Detach {
                replica_id,
                agent_uuid,
                ..
            } => {
                if replica_id == sync.replica_id {
                    return;
                }
                let mut remote = self.remote.write().await;
                if remote
                    .get(&agent_uuid)
                    .is_some_and(|p| p.replica_id == replica_id)
                {
                    remote.remove(&agent_uuid);
                }
            }
            crate::agent_registry_sync::AgentSyncEvent::Status {
                replica_id,
                agent_uuid,
                tenant_id,
                status,
                ..
            } => {
                if replica_id == sync.replica_id {
                    return;
                }
                if self.inner.read().await.contains_key(&agent_uuid) {
                    return;
                }
                let mut remote = self.remote.write().await;
                if status == "offline" {
                    if remote
                        .get(&agent_uuid)
                        .is_some_and(|p| p.replica_id == replica_id)
                    {
                        remote.remove(&agent_uuid);
                    }
                } else {
                    remote.insert(
                        agent_uuid,
                        RemotePresence {
                            replica_id,
                            tenant_id,
                            status,
                            updated_at: Instant::now(),
                        },
                    );
                }
            }
        }
    }

    pub fn spawn_remote_presence_pruner(self: &Arc<Self>) {
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let mut remote = registry.remote.write().await;
                remote.retain(|_, p| Self::remote_is_live(p));
            }
        });
    }

    pub async fn attach(&self, agent_uuid: &str, tenant_id: i64, tx: Sender<ServerToAgent>) {
        {
            let mut g = self.inner.write().await;
            g.insert(agent_uuid.to_string(), tx);
        }
        {
            let mut remote = self.remote.write().await;
            remote.remove(agent_uuid);
        }
        if let Some(sync) = self.sync() {
            let event = crate::agent_registry_sync::AgentSyncEvent::attach(
                &sync.replica_id,
                agent_uuid,
                tenant_id,
            );
            sync.publish(&event).await;
        }
    }

    pub async fn detach(&self, agent_uuid: &str) {
        let removed = {
            let mut g = self.inner.write().await;
            g.remove(agent_uuid).is_some()
        };
        if removed {
            if let Some(sync) = self.sync() {
                let event = crate::agent_registry_sync::AgentSyncEvent::detach(
                    &sync.replica_id,
                    agent_uuid,
                );
                sync.publish(&event).await;
            }
        }
    }

    /// Propagate agent status to peer replicas (heartbeats, explicit offline).
    pub async fn notify_status(&self, agent_uuid: &str, tenant_id: i64, status: &str) {
        if let Some(sync) = self.sync() {
            let event = crate::agent_registry_sync::AgentSyncEvent::status(
                &sync.replica_id,
                agent_uuid,
                tenant_id,
                status,
            );
            sync.publish(&event).await;
        }
    }

    pub async fn send(
        &self,
        agent_uuid: &str,
        msg: ServerToAgent,
    ) -> Result<(), String> {
        let g = self.inner.read().await;
        let Some(tx) = g.get(agent_uuid) else {
            return Err("agent not connected".into());
        };
        tx.send(msg).await.map_err(|e| e.to_string())
    }

    pub async fn is_online(&self, agent_uuid: &str) -> bool {
        if self.inner.read().await.contains_key(agent_uuid) {
            return true;
        }
        self.remote
            .read()
            .await
            .get(agent_uuid)
            .is_some_and(Self::remote_is_live)
    }

    pub async fn online_agents(&self) -> Vec<String> {
        let local = self.inner.read().await;
        let remote = self.remote.read().await;
        let mut out: std::collections::HashSet<String> = local.keys().cloned().collect();
        for (uuid, presence) in remote.iter() {
            if Self::remote_is_live(presence) {
                out.insert(uuid.clone());
            }
        }
        out.into_iter().collect()
    }

    pub async fn is_agent_online(&self, agent_uuid: &str) -> bool {
        self.is_online(agent_uuid).await
    }
}

/// Live + recently-enrolled agents for a client, ordered for fleet dispatch.
pub async fn agent_uuids_for_client(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i32,
) -> Result<Vec<String>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query_scalar::<_, String>(
        r#"SELECT agent_uuid::text FROM endpoint_agents
            WHERE tenant_id = $1 AND client_id = $2
              AND status IN ('online', 'enrolled')
            ORDER BY
              CASE WHEN status = 'online' THEN 0 ELSE 1 END,
              last_seen_at DESC NULLS LAST
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows)
}

/// Round-robin live dispatch across the fleet; returns count of agents that received the message.
pub async fn dispatch_to_fleet(
    pool: &PgPool,
    registry: &Arc<AgentRegistry>,
    tenant_id: i64,
    client_id: i64,
    msg: ServerToAgent,
    max_agents: i32,
) -> u32 {
    let Ok(agents) = agent_uuids_for_client(pool, tenant_id, client_id, max_agents).await else {
        return 0;
    };
    if agents.is_empty() {
        return 0;
    }
    let start = registry.dispatch_cursor.fetch_add(1, Ordering::Relaxed) % agents.len();
    let mut dispatched = 0u32;
    for i in 0..agents.len() {
        let uuid = &agents[(start + i) % agents.len()];
        if registry.is_agent_online(uuid).await {
            if registry.send(uuid, msg.clone()).await.is_ok() {
                dispatched += 1;
            }
        }
    }
    dispatched
}

/// Enqueue + live-push a task to the next agent in the fleet (round-robin).
pub async fn enqueue_and_dispatch_fleet(
    pool: &PgPool,
    registry: &Arc<AgentRegistry>,
    tenant_id: i64,
    client_id: i64,
    engine: &str,
    target: Option<&str>,
    params: &Value,
) -> Result<(Uuid, bool), sqlx::Error> {
    let task_uuid = enqueue_task(pool, tenant_id, client_id, engine, target, params).await?;
    let agents = agent_uuids_for_client(pool, tenant_id, client_id, FLEET_MAX_AGENTS).await?;
    let start = registry.dispatch_cursor.fetch_add(1, Ordering::Relaxed);
    let mut live = false;
    for (offset, _uuid) in agents.iter().enumerate() {
        let idx = (start + offset) % agents.len();
        let pick = &agents[idx];
        if registry.is_agent_online(pick).await {
            live = registry
                .send(
                    pick,
                    ServerToAgent::Task {
                        task_id: task_uuid.to_string(),
                        engine: engine.to_string(),
                        target: target.map(str::to_string),
                        params: params.clone(),
                    },
                )
                .await
                .is_ok();
            if live {
                break;
            }
        }
    }
    Ok((task_uuid, live))
}

/// Bridge NSSI virtual swarm to real endpoint agents — one detection per agent (up to 30).
pub async fn bridge_nssi_fleet(
    pool: &PgPool,
    registry: &Arc<AgentRegistry>,
    tenant_id: i64,
    client_id: i64,
    targets: &[String],
) -> u32 {
    let Ok(agents) = agent_uuids_for_client(pool, tenant_id, client_id, FLEET_MAX_AGENTS).await
    else {
        return 0;
    };
    if agents.is_empty() {
        return 0;
    }
    let mut bridged = 0u32;
    let mod_targets = targets.len().max(1);
    for (i, _) in agents.iter().enumerate() {
        let engine = NSSI_BRIDGE_ENGINES[i % NSSI_BRIDGE_ENGINES.len()];
        let target = targets
            .get(i % mod_targets)
            .map(|s| s.as_str());
        let params = json!({
            "nssi_bridge": true,
            "priority": "high",
            "fleet_slot": i + 1,
            "fleet_size": agents.len(),
        });
        if enqueue_and_dispatch_fleet(pool, registry, tenant_id, client_id, engine, target, &params)
            .await
            .is_ok()
        {
            bridged += 1;
        }
    }
    bridged
}

/// Compute storage hash for an enrollment token. The plaintext is sent once over HTTPS.
pub fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.trim().as_bytes());
    hex::encode(h.finalize())
}

/// Generate a 256-bit URL-safe token. Caller stores the hash, returns the plaintext exactly once.
pub fn generate_enrollment_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(48);
    for b in buf {
        out.push(alphabet[(b as usize) % alphabet.len()] as char);
    }
    out
}

/// Create + insert a one-time token. Returns plaintext (display once).
pub async fn create_enrollment_token(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    created_by_user_id: Option<i64>,
    valid_for_minutes: i64,
) -> Result<String, sqlx::Error> {
    let plaintext = generate_enrollment_token();
    let hash = hash_token(&plaintext);
    // Token table has RLS that reads `app.current_tenant_id` — must run inside begin_tenant_tx
    // so the GUC is set, otherwise the policy cast `current_setting(...)::bigint` panics on ''.
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    sqlx::query(
        r#"INSERT INTO endpoint_agent_enrollment_tokens
            (token_hash, tenant_id, client_id, created_by_user_id, expires_at)
           VALUES ($1, $2, $3, $4, now() + ($5 || ' minutes')::interval)"#,
    )
    .bind(&hash)
    .bind(tenant_id)
    .bind(client_id)
    .bind(created_by_user_id)
    .bind(valid_for_minutes.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(plaintext)
}

#[derive(Debug)]
pub struct ConsumedToken {
    pub tenant_id: i64,
    pub client_id: i64,
}

/// Atomically consume an enrollment token. Returns the bound tenant+client on success.
pub async fn consume_enrollment_token(
    pool: &PgPool,
    plaintext: &str,
) -> Result<ConsumedToken, String> {
    let hash = hash_token(plaintext);
    let row = sqlx::query_as::<_, (i64, i64)>(
        r#"SELECT out_tenant_id, out_client_id
             FROM consume_endpoint_agent_enrollment_token($1)"#,
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "invalid, consumed, revoked or expired enrollment token".to_string())?;
    Ok(ConsumedToken {
        tenant_id: row.0,
        client_id: row.1,
    })
}

#[allow(clippy::too_many_arguments)]
/// Resolve the DB-registered client_id for an agent (authoritative over hello JSON).
pub async fn registered_client_id(
    pool: &PgPool,
    tenant_id: i64,
    agent_uuid: &Uuid,
) -> Result<Option<i64>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let cid = sqlx::query_scalar::<_, i64>(
        "SELECT client_id FROM endpoint_agents WHERE agent_uuid = $1 AND tenant_id = $2",
    )
    .bind(agent_uuid)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(cid)
}

pub async fn client_exists(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<bool, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let ok = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(client_id)
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(ok)
}

/// All enrolled/online agents for a tenant.
pub async fn all_agent_uuids_for_tenant(
    pool: &PgPool,
    tenant_id: i64,
    limit: i32,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query_as::<_, (String, i64)>(
        r#"SELECT agent_uuid::text, client_id FROM endpoint_agents
            WHERE tenant_id = $1
            ORDER BY last_seen_at DESC NULLS LAST
            LIMIT $2"#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows)
}

/// Push pending tasks to all online agents (API process — worker only queues).
pub async fn push_pending_tasks_to_online(
    pool: &PgPool,
    registry: &Arc<AgentRegistry>,
    tenant_id: i64,
) -> u32 {
    let Ok(agents) = all_agent_uuids_for_tenant(pool, tenant_id, AGENT_STATUS_LIMIT).await else {
        return 0;
    };
    let mut pushed = 0u32;
    for (uuid, client_id) in agents {
        if !registry.is_agent_online(&uuid).await {
            continue;
        }
        if let Ok(pending) = pending_tasks_for_client(pool, tenant_id, client_id).await {
            for task in pending {
                if registry.send(&uuid, task).await.is_ok() {
                    pushed += 1;
                }
            }
        }
    }
    pushed
}

pub fn spawn_pending_task_pusher(pool: Arc<PgPool>, registry: Arc<AgentRegistry>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Ok(rows) = sqlx::query_scalar::<_, i64>(
                "SELECT DISTINCT tenant_id FROM endpoint_agent_tasks WHERE status = 'pending' AND expires_at > now() LIMIT 200",
            )
            .fetch_all(pool.as_ref())
            .await
            else {
                continue;
            };
            for tid in rows {
                let _ = push_pending_tasks_to_online(pool.as_ref(), &registry, tid).await;
            }
        }
    });
}

pub async fn register_agent(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    hostname: &str,
    device_name: &str,
    os: &str,
    arch: &str,
    agent_version: &str,
    capabilities: &[String],
) -> Result<Uuid, sqlx::Error> {
    let agent_uuid = Uuid::new_v4();
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    sqlx::query(
        r#"INSERT INTO endpoint_agents
            (agent_uuid, tenant_id, client_id, hostname, device_name, os, arch, agent_version, capabilities, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'enrolled')"#,
    )
    .bind(agent_uuid)
    .bind(tenant_id)
    .bind(client_id)
    .bind(hostname)
    .bind(device_name)
    .bind(os)
    .bind(arch)
    .bind(agent_version)
    .bind(serde_json::to_value(capabilities).unwrap_or(serde_json::Value::Array(vec![])))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(agent_uuid)
}

/// Update last-seen for an agent. We don't know the tenant from the agent_uuid alone, but the
/// table is keyed on agent_uuid which is itself the secret, so we run the update via a SECURITY
/// DEFINER helper-free path: bypass RLS by setting app.current_tenant_id to the row's tenant
/// after a privileged lookup. Since we cannot create new roles at runtime, this function uses
/// `SET LOCAL row_security = off` which any role that owns the table can use (the backend's
/// `weissman_app` role does not own it, so we instead look up tenant first using the trick that
/// `current_setting('app.current_tenant_id', true)` returns NULL when unset and the policy
/// `tenant_id = NULL` is never true; therefore we set tenant=0 to skip the policy on no rows,
/// then re-set to the row's actual tenant_id).
pub async fn mark_seen(
    pool: &PgPool,
    tenant_id: i64,
    agent_uuid: &Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    crate::db::set_tenant_conn(&mut *conn, tenant_id).await?;
    sqlx::query(
        "UPDATE endpoint_agents SET last_seen_at = now(), status = $2 WHERE agent_uuid = $1 AND tenant_id = $3",
    )
    .bind(agent_uuid)
    .bind(status)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn store_finding(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    engine: &str,
    finding: &Value,
) -> Result<(), sqlx::Error> {
    if engine == "ueba_baseline" {
        if let Some(payload) = parse_ueba_ingest(finding, client_id) {
            let _ = crate::ueba_detector::ingest_sample(pool, tenant_id, payload).await;
        }
        return Ok(());
    }
    let target = finding
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("endpoint");
    let source = format!("agent.{engine}");
    if let Err(e) = crate::findings_persist::persist_engine_findings(
        pool,
        tenant_id,
        Some(client_id),
        &source,
        target,
        std::slice::from_ref(finding),
    )
    .await
    {
        tracing::error!(
            target: "endpoint_agents",
            tenant_id,
            client_id,
            engine = %engine,
            error = %e,
            "findings_persist failed for agent finding"
        );
    }
    Ok(())
}

/// Find any pending tasks for the given client and convert them into ServerToAgent::Task messages.
pub async fn pending_tasks_for_client(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Vec<ServerToAgent>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, Value)>(
        r#"SELECT task_uuid, engine, target, params
             FROM endpoint_agent_tasks
            WHERE tenant_id = $1
              AND client_id = $2
              AND status = 'pending'
              AND expires_at > now()
            ORDER BY created_at
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(PENDING_TASK_REPLAY_LIMIT)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|(uuid, engine, target, params)| ServerToAgent::Task {
            task_id: uuid.to_string(),
            engine,
            target,
            params,
        })
        .collect())
}

pub async fn enqueue_task(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    engine: &str,
    target: Option<&str>,
    params: &Value,
) -> Result<Uuid, sqlx::Error> {
    let task_uuid = Uuid::new_v4();
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    sqlx::query(
        r#"INSERT INTO endpoint_agent_tasks
            (task_uuid, tenant_id, client_id, engine, target, params)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(task_uuid)
    .bind(tenant_id)
    .bind(client_id)
    .bind(engine)
    .bind(target)
    .bind(params)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(task_uuid)
}

/// mark_task_status — like mark_seen, doesn't know tenant from task_uuid. Set GUC to 0 so
/// the policy compares against 0 (never matches a real tenant) — but task tables also have
/// `tenant_id = current_setting...` so this update only affects the right row when the agent
/// session already set the GUC. In practice callers run inside the WS session loop where the
/// agent's tenant GUC was set on hello.
pub async fn mark_task_status(
    pool: &PgPool,
    tenant_id: i64,
    task_uuid: &Uuid,
    status: &str,
    findings_count: i32,
    error: Option<&str>,
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    crate::db::set_tenant_conn(&mut *conn, tenant_id).await?;
    sqlx::query(
        r#"UPDATE endpoint_agent_tasks
              SET status = $2,
                  findings_count = $3,
                  error = $4,
                  completed_at = CASE WHEN $2 IN ('done','failed','expired') THEN now() ELSE completed_at END
            WHERE task_uuid = $1 AND tenant_id = $5"#,
    )
    .bind(task_uuid)
    .bind(status)
    .bind(findings_count)
    .bind(error)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}
