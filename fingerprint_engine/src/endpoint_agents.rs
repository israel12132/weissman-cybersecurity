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
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use uuid::Uuid;

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

#[derive(Default)]
pub struct AgentRegistry {
    inner: RwLock<HashMap<String, Sender<ServerToAgent>>>,
}

impl AgentRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(HashMap::new()),
        })
    }

    pub async fn attach(&self, agent_uuid: &str, tx: Sender<ServerToAgent>) {
        let mut g = self.inner.write().await;
        g.insert(agent_uuid.to_string(), tx);
    }

    pub async fn detach(&self, agent_uuid: &str) {
        let mut g = self.inner.write().await;
        g.remove(agent_uuid);
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
        let g = self.inner.read().await;
        g.contains_key(agent_uuid)
    }

    pub async fn online_agents(&self) -> Vec<String> {
        let g = self.inner.read().await;
        g.keys().cloned().collect()
    }
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
    .execute(pool)
    .await?;
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
        r#"UPDATE endpoint_agent_enrollment_tokens
              SET consumed_at = now()
            WHERE token_hash = $1
              AND consumed_at IS NULL
              AND revoked_at IS NULL
              AND expires_at > now()
        RETURNING tenant_id, client_id"#,
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
    .execute(pool)
    .await?;
    Ok(agent_uuid)
}

pub async fn mark_seen(
    pool: &PgPool,
    agent_uuid: &Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE endpoint_agents SET last_seen_at = now(), status = $2 WHERE agent_uuid = $1",
    )
    .bind(agent_uuid)
    .bind(status)
    .execute(pool)
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
    let title = finding
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let severity = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info")
        .to_string();
    let description = finding
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let finding_id = format!(
        "agent-{}-{}",
        engine,
        Uuid::new_v4().simple()
    );
    sqlx::query(
        r#"INSERT INTO vulnerabilities
            (tenant_id, client_id, finding_id, title, severity, source, description, status, discovered_at, raw_data)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'OPEN', now(), $8)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&finding_id)
    .bind(&title)
    .bind(&severity)
    .bind(format!("agent.{}", engine))
    .bind(&description)
    .bind(finding)
    .execute(pool)
    .await?;
    Ok(())
}

/// Find any pending tasks for the given client and convert them into ServerToAgent::Task messages.
pub async fn pending_tasks_for_client(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Vec<ServerToAgent>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, Value)>(
        r#"SELECT task_uuid, engine, target, params
             FROM endpoint_agent_tasks
            WHERE tenant_id = $1
              AND client_id = $2
              AND status = 'pending'
              AND expires_at > now()
            ORDER BY created_at
            LIMIT 50"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(pool)
    .await?;
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
    .execute(pool)
    .await?;
    Ok(task_uuid)
}

pub async fn mark_task_status(
    pool: &PgPool,
    task_uuid: &Uuid,
    status: &str,
    findings_count: i32,
    error: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"UPDATE endpoint_agent_tasks
              SET status = $2,
                  findings_count = $3,
                  error = $4,
                  completed_at = CASE WHEN $2 IN ('done','failed','expired') THEN now() ELSE completed_at END
            WHERE task_uuid = $1"#,
    )
    .bind(task_uuid)
    .bind(status)
    .bind(findings_count)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}
