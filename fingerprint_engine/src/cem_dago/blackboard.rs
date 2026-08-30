//! Redis-backed transient scan blackboard (`weissman:blackboard:{tenant}:{client}:{scan}`).
//!
//! Engines never message each other. They read/write this hash only. Local cache
//! avoids duplicate Redis round-trips within a process. TTL is 24 hours.
//!
//! When `REDIS_URL` is unset the store is in-process memory (honest: the API on
//! another process cannot see it). Production multi-replica deployments already
//! require Redis (`rate_limit_redis::distributed_state_required`).

use super::BLACKBOARD_TTL_SECS;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

const REDIS_OP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum BlackboardError {
    #[error("redis: {0}")]
    Redis(String),
    #[error("serialize: {0}")]
    Serialize(String),
    #[error("deserialize: {0}")]
    Deserialize(String),
}

impl From<redis::RedisError> for BlackboardError {
    fn from(e: redis::RedisError) -> Self {
        Self::Redis(e.to_string())
    }
}

/// Hot-path Redis codec: MessagePack. JSON is accepted on read for mixed-version
/// workers; Command Center APIs re-serialize Evidence to JSON at the HTTP edge.
pub(crate) fn encode_evidence(ev: &Evidence) -> Result<Vec<u8>, BlackboardError> {
    rmp_serde::to_vec_named(ev).map_err(|e| BlackboardError::Serialize(e.to_string()))
}

pub(crate) fn decode_evidence(raw: &[u8]) -> Result<Evidence, BlackboardError> {
    if let Ok(ev) = rmp_serde::from_slice::<Evidence>(raw) {
        return Ok(ev);
    }
    let s = std::str::from_utf8(raw).map_err(|e| BlackboardError::Deserialize(e.to_string()))?;
    serde_json::from_str(s).map_err(|e| BlackboardError::Deserialize(e.to_string()))
}

pub(crate) fn encode_failure(f: &FailureLog) -> Result<Vec<u8>, BlackboardError> {
    rmp_serde::to_vec_named(f).map_err(|e| BlackboardError::Serialize(e.to_string()))
}

pub(crate) fn decode_failure(raw: &[u8]) -> Result<FailureLog, BlackboardError> {
    if let Ok(f) = rmp_serde::from_slice::<FailureLog>(raw) {
        return Ok(f);
    }
    let s = std::str::from_utf8(raw).map_err(|e| BlackboardError::Deserialize(e.to_string()))?;
    serde_json::from_str(s).map_err(|e| BlackboardError::Deserialize(e.to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source_engine: String,
    pub timestamp: i64,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureLog {
    pub engine_id: String,
    pub target: String,
    pub error_message: String,
    pub timestamp: i64,
}

/// Shared scan memory. Cheap to clone (`Arc` internals).
pub struct ScanBlackboard {
    tenant_id: i64,
    client_id: i64,
    scan_id: String,
    redis_client: Option<Arc<redis::Client>>,
    local_cache: RwLock<HashMap<String, Evidence>>,
}

impl std::fmt::Debug for ScanBlackboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanBlackboard")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("scan_id", &self.scan_id)
            .field("redis_backed", &self.redis_client.is_some())
            .finish()
    }
}

impl ScanBlackboard {
    pub fn new(tenant_id: i64, client_id: i64, scan_id: String, redis: Arc<redis::Client>) -> Self {
        Self {
            tenant_id,
            client_id,
            scan_id,
            redis_client: Some(redis),
            local_cache: RwLock::new(HashMap::new()),
        }
    }

    /// In-process store — tests and Redis-less single-node workers.
    #[must_use]
    pub fn memory(tenant_id: i64, client_id: i64, scan_id: impl Into<String>) -> Self {
        Self {
            tenant_id,
            client_id,
            scan_id: scan_id.into(),
            redis_client: None,
            local_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Redis when `REDIS_URL` is set, otherwise memory.
    #[must_use]
    pub fn from_env(tenant_id: i64, client_id: i64, scan_id: impl Into<String>) -> Self {
        let scan_id = scan_id.into();
        match redis_client_from_env() {
            Some(c) => Self::new(tenant_id, client_id, scan_id, c),
            None => Self::memory(tenant_id, client_id, scan_id),
        }
    }

    #[must_use]
    pub fn tenant_id(&self) -> i64 {
        self.tenant_id
    }

    #[must_use]
    pub fn client_id(&self) -> i64 {
        self.client_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub fn redis_backed(&self) -> bool {
        self.redis_client.is_some()
    }

    #[must_use]
    pub fn redis_key(&self) -> String {
        format!(
            "weissman:blackboard:{}:{}:{}",
            self.tenant_id, self.client_id, self.scan_id
        )
    }

    #[must_use]
    pub fn failures_key(&self) -> String {
        format!(
            "weissman:failures:{}:{}:{}",
            self.tenant_id, self.client_id, self.scan_id
        )
    }

    #[must_use]
    pub fn latest_index_key(tenant_id: i64, client_id: i64) -> String {
        format!("weissman:blackboard:latest:{tenant_id}:{client_id}")
    }

    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection, BlackboardError> {
        let client = self
            .redis_client
            .as_ref()
            .ok_or_else(|| BlackboardError::Redis("redis not configured".into()))?;
        let mut conn =
            tokio::time::timeout(REDIS_OP_TIMEOUT, client.get_multiplexed_async_connection())
                .await
                .map_err(|_| BlackboardError::Redis("redis connect timeout".into()))?
                .map_err(|e| BlackboardError::Redis(e.to_string()))?;
        conn.set_response_timeout(REDIS_OP_TIMEOUT);
        Ok(conn)
    }

    /// Write a finding or hot evidence field.
    pub async fn write_evidence(
        &self,
        key: &str,
        engine: &str,
        val: Value,
    ) -> Result<(), BlackboardError> {
        let timestamp = chrono::Utc::now().timestamp_millis();
        let evidence = Evidence {
            source_engine: engine.to_string(),
            timestamp,
            value: val,
        };
        let serialized = encode_evidence(&evidence)?;
        {
            let mut cache = self.local_cache.write().await;
            cache.insert(key.to_string(), evidence);
        }
        if self.redis_client.is_none() {
            return Ok(());
        }
        let mut conn = self.conn().await?;
        let hash_key = self.redis_key();
        let _: () = conn.hset(&hash_key, key, serialized.as_slice()).await?;
        let _: () = conn.expire(&hash_key, BLACKBOARD_TTL_SECS).await?;
        Ok(())
    }

    pub async fn read_evidence(&self, key: &str) -> Result<Option<Evidence>, BlackboardError> {
        {
            let cache = self.local_cache.read().await;
            if let Some(evidence) = cache.get(key) {
                return Ok(Some(evidence.clone()));
            }
        }
        if self.redis_client.is_none() {
            return Ok(None);
        }
        let mut conn = self.conn().await?;
        let result: Option<Vec<u8>> = conn.hget(self.redis_key(), key).await?;
        match result {
            Some(data) => {
                let evidence = decode_evidence(&data)?;
                let mut cache = self.local_cache.write().await;
                cache.insert(key.to_string(), evidence.clone());
                Ok(Some(evidence))
            }
            None => Ok(None),
        }
    }

    pub async fn has_signal(&self, key: &str) -> bool {
        self.read_evidence(key).await.ok().flatten().is_some()
    }

    /// Keys currently known (local cache ∪ Redis hash).
    pub async fn present_signals(&self) -> Result<Vec<String>, BlackboardError> {
        let mut keys: std::collections::BTreeSet<String> = {
            let cache = self.local_cache.read().await;
            cache.keys().cloned().collect()
        };
        if self.redis_client.is_some() {
            let mut conn = self.conn().await?;
            let map: HashMap<String, Vec<u8>> = conn.hgetall(self.redis_key()).await?;
            for (k, raw) in map {
                if let Ok(ev) = decode_evidence(&raw) {
                    let mut cache = self.local_cache.write().await;
                    cache.insert(k.clone(), ev);
                }
                keys.insert(k);
            }
        }
        Ok(keys.into_iter().collect())
    }

    pub async fn dump_all(&self) -> Result<HashMap<String, Evidence>, BlackboardError> {
        let _ = self.present_signals().await?;
        Ok(self.local_cache.read().await.clone())
    }

    pub async fn log_engine_failure(
        &self,
        engine_id: &str,
        target: &str,
        err: &str,
    ) -> Result<(), BlackboardError> {
        let failure = FailureLog {
            engine_id: engine_id.to_string(),
            target: target.to_string(),
            error_message: err.to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
        };
        if self.redis_client.is_none() {
            // Keep failures on a reserved evidence key so tests / single-node still work.
            let mut list = self
                .read_evidence("_failures")
                .await?
                .map(|e| e.value)
                .unwrap_or_else(|| Value::Array(vec![]));
            if let Some(arr) = list.as_array_mut() {
                arr.push(serde_json::to_value(&failure).unwrap_or(Value::Null));
            }
            return self.write_evidence("_failures", "dago", list).await;
        }
        let serialized = encode_failure(&failure)?;
        let mut conn = self.conn().await?;
        let log_key = self.failures_key();
        let _: () = conn.rpush(&log_key, serialized.as_slice()).await?;
        let _: () = conn.expire(&log_key, BLACKBOARD_TTL_SECS).await?;
        Ok(())
    }

    pub async fn list_failures(&self) -> Result<Vec<FailureLog>, BlackboardError> {
        if self.redis_client.is_none() {
            let ev = self.read_evidence("_failures").await?;
            let Some(v) = ev.map(|e| e.value) else {
                return Ok(Vec::new());
            };
            let parsed: Vec<FailureLog> = serde_json::from_value(v).unwrap_or_default();
            return Ok(parsed);
        }
        let mut conn = self.conn().await?;
        let raw: Vec<Vec<u8>> = conn.lrange(self.failures_key(), 0, -1).await?;
        let mut out = Vec::with_capacity(raw.len());
        for row in raw {
            match decode_failure(&row) {
                Ok(f) => out.push(f),
                Err(e) => {
                    tracing::warn!(target: "cem_dago", error = %e, "skip malformed failure log");
                }
            }
        }
        Ok(out)
    }

    /// Point `weissman:blackboard:latest:{tenant}:{client}` at this scan (24h TTL).
    pub async fn mark_latest(&self) -> Result<(), BlackboardError> {
        if self.redis_client.is_none() {
            return Ok(());
        }
        let mut conn = self.conn().await?;
        let idx = Self::latest_index_key(self.tenant_id, self.client_id);
        let _: () = conn.set(&idx, self.scan_id.as_str()).await?;
        let _: () = conn.expire(&idx, BLACKBOARD_TTL_SECS).await?;
        Ok(())
    }
}

/// Open the latest scan blackboard for a client (Redis index). `None` when no scan recorded.
pub async fn open_latest(
    tenant_id: i64,
    client_id: i64,
) -> Result<Option<ScanBlackboard>, BlackboardError> {
    let Some(client) = redis_client_from_env() else {
        return Ok(None);
    };
    let idx = ScanBlackboard::latest_index_key(tenant_id, client_id);
    let mut conn =
        tokio::time::timeout(REDIS_OP_TIMEOUT, client.get_multiplexed_async_connection())
            .await
            .map_err(|_| BlackboardError::Redis("redis connect timeout".into()))?
            .map_err(|e| BlackboardError::Redis(e.to_string()))?;
    conn.set_response_timeout(REDIS_OP_TIMEOUT);
    let scan_id: Option<String> = conn.get(&idx).await?;
    Ok(scan_id.map(|id| ScanBlackboard::new(tenant_id, client_id, id, client)))
}

pub async fn open_scan(
    tenant_id: i64,
    client_id: i64,
    scan_id: &str,
) -> Result<ScanBlackboard, BlackboardError> {
    match redis_client_from_env() {
        Some(c) => Ok(ScanBlackboard::new(
            tenant_id,
            client_id,
            scan_id.to_string(),
            c,
        )),
        None => Ok(ScanBlackboard::memory(tenant_id, client_id, scan_id)),
    }
}

fn redis_client_from_env() -> Option<Arc<redis::Client>> {
    static CLIENT: std::sync::OnceLock<Option<Arc<redis::Client>>> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let url = std::env::var("REDIS_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())?;
            redis::Client::open(url.as_str()).ok().map(Arc::new)
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::AsyncCommands;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn memory_round_trip() {
        let bb = ScanBlackboard::memory(9, 8, "s1");
        bb.write_evidence("k", "eng", serde_json::json!({"n": 1}))
            .await
            .unwrap();
        let ev = bb.read_evidence("k").await.unwrap().unwrap();
        assert_eq!(ev.source_engine, "eng");
        assert_eq!(ev.value["n"], 1);
        assert!(bb.has_signal("k").await);
        assert!(!bb.has_signal("missing").await);
    }

    #[tokio::test]
    async fn memory_failure_log() {
        let bb = ScanBlackboard::memory(1, 2, "s2");
        bb.log_engine_failure("modbus_tcp", "10.0.0.5", "register read timeout")
            .await
            .unwrap();
        let fails = bb.list_failures().await.unwrap();
        assert_eq!(fails.len(), 1);
        assert_eq!(fails[0].engine_id, "modbus_tcp");
    }

    #[test]
    fn msgpack_roundtrip_and_json_compat() {
        let ev = Evidence {
            source_engine: "asm".into(),
            timestamp: 42,
            value: serde_json::json!({"open": true}),
        };
        let packed = encode_evidence(&ev).unwrap();
        assert_ne!(packed.first().copied(), Some(b'{'), "must not be JSON");
        let back = decode_evidence(&packed).unwrap();
        assert_eq!(back.source_engine, "asm");
        assert_eq!(back.value["open"], true);
        let json = serde_json::to_vec(&ev).unwrap();
        let from_json = decode_evidence(&json).unwrap();
        assert_eq!(from_json.source_engine, "asm");
    }

    #[tokio::test]
    async fn redis_msgpack_when_available() {
        let url = std::env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379/0".into());
        let Ok(client) = redis::Client::open(url.as_str()) else {
            return;
        };
        let client = Arc::new(client);
        let ping = tokio::time::timeout(
            Duration::from_secs(2),
            client.get_multiplexed_async_connection(),
        )
        .await;
        let Ok(Ok(mut conn)) = ping else {
            return;
        };
        conn.set_response_timeout(Duration::from_secs(2));
        let pong: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
        if pong.as_deref() != Ok("PONG") {
            return;
        }
        let bb = ScanBlackboard::new(99, 88, "cem-dago-live-proof".into(), client);
        bb.write_evidence(
            "web_port_active",
            "live_proof",
            serde_json::json!({"live": true}),
        )
        .await
        .expect("redis write");
        let ev = bb
            .read_evidence("web_port_active")
            .await
            .expect("redis read")
            .expect("evidence present");
        assert_eq!(ev.source_engine, "live_proof");
        assert_eq!(ev.value["live"], true);
        let raw: Option<Vec<u8>> = conn.hget(bb.redis_key(), "web_port_active").await.unwrap();
        let bytes = raw.expect("hash field");
        assert_ne!(bytes.first().copied(), Some(b'{'));
        let decoded = decode_evidence(&bytes).unwrap();
        assert_eq!(decoded.source_engine, "live_proof");
    }
}
