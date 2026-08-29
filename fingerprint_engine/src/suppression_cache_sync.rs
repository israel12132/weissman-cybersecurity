//! Redis pub/sub so every API / worker replica drops its in-memory suppression
//! cache the moment an analyst marks FP or deletes a rule.
//!
//! Without this, a 30s DashMap TTL on node B keeps serving a stale empty/old
//! rule set and will still dispatch SOAR after node A already busted locally.
//!
//! Pub/Sub is at-most-once. A reconnect gap is handled with stale-while-revalidate
//! plus 0..=5000 ms jitter — never a fleet-wide DashMap `.clear()`.

use futures::StreamExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

pub const CHANNEL: &str = "weissman:suppression_cache:bust";
const EVENT_VERSION: u8 = 1;
const SUBSCRIBER_RETRY_SECS: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheBustEvent {
    pub v: u8,
    pub replica_id: String,
    pub tenant_id: i64,
    /// `None` = drop every engine for the tenant.
    pub engine: Option<String>,
}

impl CacheBustEvent {
    #[must_use]
    pub fn new(tenant_id: i64, engine: Option<&str>) -> Self {
        Self {
            v: EVENT_VERSION,
            replica_id: replica_id(),
            tenant_id,
            engine: engine.map(|e| e.to_ascii_lowercase()),
        }
    }
}

fn replica_id() -> String {
    std::env::var("WEISSMAN_REPLICA_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("pid:{}", std::process::id()))
}

fn redis_client() -> Option<redis::Client> {
    let url = std::env::var("REDIS_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    redis::Client::open(url).ok()
}

/// Fire-and-forget publish. No-op without `REDIS_URL` or outside a Tokio runtime.
pub fn publish_bust(tenant_id: i64, engine: Option<&str>) {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    let event = CacheBustEvent::new(tenant_id, engine);
    tokio::spawn(async move {
        let Some(client) = redis_client() else {
            return;
        };
        let Ok(payload) = serde_json::to_string(&event) else {
            return;
        };
        let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
            tracing::debug!(
                target: "suppression_cache_sync",
                "redis publish connection unavailable"
            );
            return;
        };
        if let Err(e) = conn.publish::<_, _, ()>(CHANNEL, payload).await {
            tracing::debug!(
                target: "suppression_cache_sync",
                error = %e,
                "CACHE_BUST_SUPPRESSION publish failed"
            );
        }
    });
}

fn apply_remote(event: &CacheBustEvent) {
    if event.replica_id == replica_id() {
        return;
    }
    match event.engine.as_deref() {
        Some(engine) => {
            crate::fp_feedback::invalidate_suppression_cache_local(event.tenant_id, engine)
        }
        None => crate::fp_feedback::invalidate_suppression_cache_tenant_local(event.tenant_id),
    }
}

fn on_pubsub_gap(pool: &Arc<PgPool>) {
    crate::fp_feedback::mark_suppression_cache_stale_for_swr();
    crate::fp_feedback::schedule_suppression_cache_swr_refresh(pool.clone());
}

async fn run_subscriber(pool: Arc<PgPool>) -> Result<(), String> {
    let client = redis_client().ok_or("REDIS_URL unset")?;
    let mut pubsub = client.get_async_pubsub().await.map_err(|e| e.to_string())?;
    pubsub.subscribe(CHANNEL).await.map_err(|e| e.to_string())?;
    // At-most-once: busts published while we were down are gone. Keep serving
    // stale rules and refresh from Postgres after a random jitter so every
    // replica does not stampede the suppression table at once.
    on_pubsub_gap(&pool);
    tracing::info!(
        target: "suppression_cache_sync",
        channel = CHANNEL,
        "CACHE_BUST_SUPPRESSION subscriber active (SWR refresh scheduled)"
    );
    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = msg.get_payload().unwrap_or_default();
        if let Ok(event) = serde_json::from_str::<CacheBustEvent>(&payload) {
            apply_remote(&event);
        }
    }
    Ok(())
}

/// Subscribe for the life of this process (server + worker). No-op without Redis.
pub fn spawn_suppression_cache_redis_sync(pool: Arc<PgPool>) {
    if redis_client().is_none() {
        tracing::info!(
            target: "suppression_cache_sync",
            "REDIS_URL not set; suppression cache is single-replica"
        );
        return;
    }
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_subscriber(pool.clone()).await {
                tracing::warn!(
                    target: "suppression_cache_sync",
                    error = %e,
                    "subscriber disconnected; retrying with SWR"
                );
            }
            on_pubsub_gap(&pool);
            tokio::time::sleep(Duration::from_secs(SUBSCRIBER_RETRY_SECS)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bust_event_round_trips() {
        let e = CacheBustEvent::new(7, Some("ASM"));
        assert_eq!(e.v, 1);
        assert_eq!(e.tenant_id, 7);
        assert_eq!(e.engine.as_deref(), Some("asm"));
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("tenant_id"));
        let back: CacheBustEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tenant_id, 7);
        assert_eq!(back.engine, e.engine);
    }

    #[test]
    fn subscriber_uses_swr_not_violent_clear_on_reconnect() {
        let src = include_str!("suppression_cache_sync.rs");
        assert!(
            !src.contains(concat!("invalidate_suppression_cache_all", "_local()")),
            "reconnect must not empty the DashMap (thundering herd)"
        );
        assert!(
            src.contains("mark_suppression_cache_stale_for_swr"),
            "reconnect must mark the cache stale"
        );
        assert!(
            src.contains("schedule_suppression_cache_swr_refresh"),
            "reconnect must schedule a jittered Postgres refresh"
        );
    }
}
