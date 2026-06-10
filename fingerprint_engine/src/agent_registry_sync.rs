//! Redis pub-sub for multi-replica [`crate::endpoint_agents::AgentRegistry`] presence sync.
//!
//! When `REDIS_URL` is set, attach/detach/status events are published so every API replica
//! maintains a consistent view of which agents are online (locally or on a peer). Without Redis,
//! the registry behaves as a single-replica in-process map.

use futures::StreamExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

pub const CHANNEL: &str = "weissman:agent_registry:sync";

const EVENT_VERSION: u8 = 1;
const SUBSCRIBER_RETRY_SECS: u64 = 5;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentSyncEvent {
    Attach {
        v: u8,
        replica_id: String,
        agent_uuid: String,
        tenant_id: i64,
    },
    Detach {
        v: u8,
        replica_id: String,
        agent_uuid: String,
    },
    Status {
        v: u8,
        replica_id: String,
        agent_uuid: String,
        tenant_id: i64,
        status: String,
    },
}

impl AgentSyncEvent {
    pub fn attach(replica_id: &str, agent_uuid: &str, tenant_id: i64) -> Self {
        Self::Attach {
            v: EVENT_VERSION,
            replica_id: replica_id.to_string(),
            agent_uuid: agent_uuid.to_string(),
            tenant_id,
        }
    }

    pub fn detach(replica_id: &str, agent_uuid: &str) -> Self {
        Self::Detach {
            v: EVENT_VERSION,
            replica_id: replica_id.to_string(),
            agent_uuid: agent_uuid.to_string(),
        }
    }

    pub fn status(replica_id: &str, agent_uuid: &str, tenant_id: i64, status: &str) -> Self {
        Self::Status {
            v: EVENT_VERSION,
            replica_id: replica_id.to_string(),
            agent_uuid: agent_uuid.to_string(),
            tenant_id,
            status: status.to_string(),
        }
    }
}

pub struct AgentRegistrySync {
    pub replica_id: String,
    client: redis::Client,
}

impl AgentRegistrySync {
    /// Build a sync handle from `REDIS_URL` (and optional `WEISSMAN_REPLICA_ID`).
    pub fn from_env() -> Option<Arc<Self>> {
        let url = std::env::var("REDIS_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let client = redis::Client::open(url.as_str()).ok()?;
        let replica_id = std::env::var("WEISSMAN_REPLICA_ID")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        Some(Arc::new(Self { replica_id, client }))
    }

    pub async fn publish(&self, event: &AgentSyncEvent) {
        let Ok(payload) = serde_json::to_string(event) else {
            return;
        };
        let Ok(mut conn) = self.client.get_multiplexed_async_connection().await else {
            tracing::debug!(
                target: "agent_registry_sync",
                "redis publish connection unavailable"
            );
            return;
        };
        if let Err(e) = conn.publish::<_, _, ()>(CHANNEL, payload).await {
            tracing::debug!(
                target: "agent_registry_sync",
                error = %e,
                "redis publish failed"
            );
        }
    }
}

async fn run_subscriber(
    registry: Arc<crate::endpoint_agents::AgentRegistry>,
    sync: Arc<AgentRegistrySync>,
) -> Result<(), String> {
    let mut pubsub = sync
        .client
        .get_async_pubsub()
        .await
        .map_err(|e| e.to_string())?;
    pubsub
        .subscribe(CHANNEL)
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!(
        target: "agent_registry_sync",
        replica_id = %sync.replica_id,
        channel = CHANNEL,
        "redis pub-sub subscriber active"
    );
    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = msg.get_payload().unwrap_or_default();
        registry.apply_remote_event(&sync, &payload).await;
    }
    Ok(())
}

/// Start Redis pub-sub for the process-wide agent registry (no-op without `REDIS_URL`).
pub fn spawn_agent_registry_redis_sync(registry: Arc<crate::endpoint_agents::AgentRegistry>) {
    let Some(sync) = AgentRegistrySync::from_env() else {
        tracing::info!(
            target: "agent_registry_sync",
            "REDIS_URL not set; agent registry single-replica mode"
        );
        return;
    };
    registry.set_sync(sync.clone());
    let reg = registry.clone();
    let sync_sub = sync.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_subscriber(reg.clone(), sync_sub.clone()).await {
                tracing::warn!(
                    target: "agent_registry_sync",
                    error = %e,
                    "subscriber disconnected; retrying"
                );
            }
            tokio::time::sleep(Duration::from_secs(SUBSCRIBER_RETRY_SECS)).await;
        }
    });
    registry.spawn_remote_presence_pruner();
    tracing::info!(
        target: "agent_registry_sync",
        replica_id = %sync.replica_id,
        "agent registry redis sync enabled"
    );
}
