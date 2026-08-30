//! Redis-backed transient scan blackboard (`weissman:blackboard:{tenant}:{client}:{scan}`).
//!
//! Engines never message each other. They read/write this hash only. Local cache
//! avoids duplicate Redis round-trips within a process. TTL is 24 hours.
//!
//! Redis I/O uses a **cgroup-sized shard of** [`redis::aio::ConnectionManager`]
//! sockets ([`super::redis_pool`]). Wave `join_all` tasks pick a shard by field
//! key so large MessagePack writes do not Head-of-Line block a single TCP
//! socket, without opening a connection per engine.
//!
//! When `REDIS_URL` is unset the store is in-process memory (honest: the API on
//! another process cannot see it). Production multi-replica deployments already
//! require Redis (`rate_limit_redis::distributed_state_required`).

use super::redis_pool::{acquire_redis_connection_with_timeout, REDIS_ACQUIRE_TIMEOUT};
use super::telemetry_quarantine::{blob_from_raw, persist_quarantine, QuarantineBlob};
use super::BLACKBOARD_TTL_SECS;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

/// Every blackboard Redis command is bounded so a hung ConnectionManager
/// reconnect cannot starve the Tokio runtime under scan load.
pub(crate) const REDIS_OP_TIMEOUT: Duration = Duration::from_millis(50);

/// MessagePack "never used" opcode. A valid map/array/str never starts with this,
/// so mixed-version readers can distinguish a version envelope from legacy bodies.
pub const CODEC_MAGIC: u8 = 0xC1;
/// Current Evidence / FailureLog named-map layout.
pub const CODEC_VERSION: u8 = 1;

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

fn wrap_versioned(body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(CODEC_MAGIC);
    out.push(CODEC_VERSION);
    out.extend_from_slice(&body);
    out
}

fn named_msgpack<T: Serialize>(v: &T) -> Result<Vec<u8>, BlackboardError> {
    rmp_serde::to_vec_named(v).map_err(|e| BlackboardError::Serialize(e.to_string()))
}

/// Hot-path Redis codec: `0xC1` + `u8` version + named MessagePack.
/// JSON is accepted on read for mixed-version workers; Command Center APIs
/// re-serialize Evidence to JSON at the HTTP edge.
pub(crate) fn encode_evidence(ev: &Evidence) -> Result<Vec<u8>, BlackboardError> {
    Ok(wrap_versioned(named_msgpack(ev)?))
}

pub(crate) fn encode_failure(f: &FailureLog) -> Result<Vec<u8>, BlackboardError> {
    Ok(wrap_versioned(named_msgpack(f)?))
}

fn strip_version_prefix(raw: &[u8]) -> (Option<u8>, &[u8]) {
    if raw.len() >= 2 && raw[0] == CODEC_MAGIC {
        (Some(raw[1]), &raw[2..])
    } else {
        (None, raw)
    }
}

fn json_from_utf8(raw: &[u8]) -> Result<Value, BlackboardError> {
    let s = std::str::from_utf8(raw).map_err(|e| BlackboardError::Deserialize(e.to_string()))?;
    serde_json::from_str(s).map_err(|e| BlackboardError::Deserialize(e.to_string()))
}

/// Decode a named map, skipping unknown keys. Used when a newer writer added
/// fields the local struct does not know — serde already ignores extras on the
/// typed path; this recovers when types drifted (e.g. timestamp as string).
fn evidence_from_dynamic(v: &Value) -> Result<Evidence, BlackboardError> {
    let obj = v
        .as_object()
        .ok_or_else(|| BlackboardError::Deserialize("evidence is not a map".into()))?;
    let source_engine = obj
        .get("source_engine")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let timestamp = obj
        .get("timestamp")
        .and_then(|t| t.as_i64().or_else(|| t.as_u64().map(|n| n as i64)))
        .unwrap_or(0);
    let value = obj.get("value").cloned().unwrap_or(Value::Null);
    Ok(Evidence {
        source_engine,
        timestamp,
        value,
    })
}

fn failure_from_dynamic(v: &Value) -> Result<FailureLog, BlackboardError> {
    let obj = v
        .as_object()
        .ok_or_else(|| BlackboardError::Deserialize("failure is not a map".into()))?;
    Ok(FailureLog {
        engine_id: obj
            .get("engine_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        target: obj
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        error_message: obj
            .get("error_message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        timestamp: obj
            .get("timestamp")
            .and_then(|t| t.as_i64().or_else(|| t.as_u64().map(|n| n as i64)))
            .unwrap_or(0),
    })
}

fn decode_named_or_json<T, F>(raw: &[u8], from_dynamic: F) -> Result<T, BlackboardError>
where
    T: for<'de> Deserialize<'de>,
    F: Fn(&Value) -> Result<T, BlackboardError>,
{
    let (ver, body) = strip_version_prefix(raw);
    if let Some(v) = ver {
        if v > CODEC_VERSION {
            tracing::debug!(
                target: "cem_dago",
                version = v,
                local = CODEC_VERSION,
                "newer blackboard codec; decoding known fields only"
            );
        }
        if let Ok(typed) = rmp_serde::from_slice::<T>(body) {
            return Ok(typed);
        }
        if let Ok(dynv) = rmp_serde::from_slice::<Value>(body) {
            return from_dynamic(&dynv);
        }
        if let Ok(dynv) = json_from_utf8(body) {
            return from_dynamic(&dynv);
        }
        return Err(BlackboardError::Deserialize(format!(
            "versioned codec v{v} body is neither MessagePack nor JSON"
        )));
    }
    // Legacy unversioned MessagePack (maps typically start 0x80–0x8f / 0xde).
    if let Ok(typed) = rmp_serde::from_slice::<T>(raw) {
        return Ok(typed);
    }
    if let Ok(dynv) = rmp_serde::from_slice::<Value>(raw) {
        if dynv.is_object() {
            return from_dynamic(&dynv);
        }
    }
    let dynv = json_from_utf8(raw)?;
    from_dynamic(&dynv)
}

pub(crate) fn decode_evidence(raw: &[u8]) -> Result<Evidence, BlackboardError> {
    decode_named_or_json(raw, evidence_from_dynamic)
}

pub(crate) fn decode_failure(raw: &[u8]) -> Result<FailureLog, BlackboardError> {
    decode_named_or_json(raw, failure_from_dynamic)
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

/// Shared scan memory. Cheap to clone a shard manager (`ConnectionManager` is
/// `Clone`); the local cache stays behind `RwLock`.
pub struct ScanBlackboard {
    tenant_id: i64,
    client_id: i64,
    scan_id: String,
    /// When true, I/O goes through the sharded ConnectionManager pool (or a test-injected manager).
    redis_enabled: bool,
    /// Test override. `None` means pick a shard from the process-wide pool.
    redis_dedicated: Option<redis::aio::ConnectionManager>,
    local_cache: RwLock<HashMap<String, Evidence>>,
    quarantine: RwLock<Vec<QuarantineBlob>>,
}

impl std::fmt::Debug for ScanBlackboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanBlackboard")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("scan_id", &self.scan_id)
            .field("redis_backed", &self.redis_enabled)
            .field("redis_sharded", &self.redis_enabled)
            .finish()
    }
}

impl ScanBlackboard {
    /// Redis-backed blackboard using the process-wide connection manager.
    pub fn new(tenant_id: i64, client_id: i64, scan_id: String) -> Self {
        Self {
            tenant_id,
            client_id,
            scan_id,
            redis_enabled: true,
            redis_dedicated: None,
            local_cache: RwLock::new(HashMap::new()),
            quarantine: RwLock::new(Vec::new()),
        }
    }

    /// Inject a manager (live tests). Production paths use the sharded pool.
    pub fn with_manager(
        tenant_id: i64,
        client_id: i64,
        scan_id: String,
        redis: redis::aio::ConnectionManager,
    ) -> Self {
        Self {
            tenant_id,
            client_id,
            scan_id,
            redis_enabled: true,
            redis_dedicated: Some(redis),
            local_cache: RwLock::new(HashMap::new()),
            quarantine: RwLock::new(Vec::new()),
        }
    }

    /// In-process store — tests and Redis-less single-node workers.
    #[must_use]
    pub fn memory(tenant_id: i64, client_id: i64, scan_id: impl Into<String>) -> Self {
        Self {
            tenant_id,
            client_id,
            scan_id: scan_id.into(),
            redis_enabled: false,
            redis_dedicated: None,
            local_cache: RwLock::new(HashMap::new()),
            quarantine: RwLock::new(Vec::new()),
        }
    }

    /// Redis when `REDIS_URL` is set, otherwise memory.
    #[must_use]
    pub fn from_env(tenant_id: i64, client_id: i64, scan_id: impl Into<String>) -> Self {
        let scan_id = scan_id.into();
        if redis_url_configured() {
            Self::new(tenant_id, client_id, scan_id)
        } else {
            Self::memory(tenant_id, client_id, scan_id)
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
        self.redis_enabled
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

    #[must_use]
    pub fn quarantine_key(&self) -> String {
        format!(
            "weissman:quarantine:{}:{}:{}",
            self.tenant_id, self.client_id, self.scan_id
        )
    }

    async fn conn_for(
        &self,
        shard_key: &str,
    ) -> Result<redis::aio::ConnectionManager, BlackboardError> {
        if let Some(m) = &self.redis_dedicated {
            return tokio::time::timeout(REDIS_ACQUIRE_TIMEOUT, async { m.clone() })
                .await
                .map_err(|_| {
                    BlackboardError::Redis("Redis connection acquisition timed out!".into())
                });
        }
        if !self.redis_enabled {
            return Err(BlackboardError::Redis("redis not configured".into()));
        }
        acquire_redis_connection_with_timeout(shard_key)
            .await
            .map_err(BlackboardError::Redis)
    }

    /// Decode failure → hex quarantine blob + critical log. Never a silent skip.
    /// Corrupt fields are **not** treated as present DAG signals.
    pub(crate) async fn quarantine_decode_failure(
        &self,
        kind: &str,
        field_key: &str,
        raw: &[u8],
        err: &BlackboardError,
    ) {
        metrics::counter!("weissman_cem_dago_telemetry_integrity_violations_total").increment(1);
        tracing::error!(
            target: "cem_dago",
            kind,
            field_key,
            error = %err,
            bytes = raw.len(),
            "TELEMETRY INTEGRITY VIOLATION — MessagePack body quarantined (DAG continues)"
        );
        let blob = blob_from_raw(kind, field_key, raw, &err.to_string());
        {
            let mut q = self.quarantine.write().await;
            q.push(blob.clone());
        }
        if !self.redis_enabled {
            return;
        }
        let Ok(mut conn) = self.conn_for(&self.quarantine_key()).await else {
            return;
        };
        let payload = serde_json::to_vec(&blob).unwrap_or_default();
        let key = self.quarantine_key();
        let _ = tokio::time::timeout(REDIS_OP_TIMEOUT, async {
            let _: () = conn.rpush(&key, payload.as_slice()).await?;
            let _: () = conn.expire(&key, BLACKBOARD_TTL_SECS).await?;
            Ok::<(), redis::RedisError>(())
        })
        .await;
    }

    /// Drain in-memory + Redis quarantine lists.
    pub async fn take_quarantine(&self) -> Vec<QuarantineBlob> {
        let mut out = {
            let mut q = self.quarantine.write().await;
            std::mem::take(&mut *q)
        };
        if self.redis_enabled {
            if let Ok(mut conn) = self.conn_for(&self.quarantine_key()).await {
                let key = self.quarantine_key();
                let raw: Result<Vec<Vec<u8>>, _> =
                    tokio::time::timeout(REDIS_OP_TIMEOUT, conn.lrange(&key, 0, -1))
                        .await
                        .map_err(|_| BlackboardError::Redis("timeout".into()))
                        .and_then(|r| r.map_err(Into::into));
                if let Ok(rows) = raw {
                    let _: Result<(), _> = tokio::time::timeout(REDIS_OP_TIMEOUT, conn.del(&key))
                        .await
                        .map_err(|_| ())
                        .and_then(|r: Result<u64, _>| r.map(|_| ()).map_err(|_| ()));
                    for row in rows {
                        if let Ok(b) = serde_json::from_slice::<QuarantineBlob>(&row) {
                            out.push(b);
                        }
                    }
                }
            }
        }
        out
    }

    /// Persist drained quarantine blobs under RLS and emit SOC events.
    pub async fn persist_and_take_quarantine(&self, pool: &PgPool) -> Vec<QuarantineBlob> {
        let blobs = self.take_quarantine().await;
        let _ =
            persist_quarantine(pool, self.tenant_id, self.client_id, &self.scan_id, &blobs).await;
        blobs
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
        if !self.redis_enabled {
            return Ok(());
        }
        let mut conn = self.conn_for(key).await?;
        let hash_key = self.redis_key();
        tokio::time::timeout(REDIS_OP_TIMEOUT, async {
            let _: () = conn.hset(&hash_key, key, serialized.as_slice()).await?;
            let _: () = conn.expire(&hash_key, BLACKBOARD_TTL_SECS).await?;
            Ok::<(), redis::RedisError>(())
        })
        .await
        .map_err(|_| BlackboardError::Redis("redis write timeout".into()))??;
        Ok(())
    }

    pub async fn read_evidence(&self, key: &str) -> Result<Option<Evidence>, BlackboardError> {
        {
            let cache = self.local_cache.read().await;
            if let Some(evidence) = cache.get(key) {
                return Ok(Some(evidence.clone()));
            }
        }
        if !self.redis_enabled {
            return Ok(None);
        }
        let mut conn = self.conn_for(key).await?;
        let result: Option<Vec<u8>> =
            tokio::time::timeout(REDIS_OP_TIMEOUT, conn.hget(self.redis_key(), key))
                .await
                .map_err(|_| BlackboardError::Redis("redis read timeout".into()))??;
        match result {
            Some(data) => match decode_evidence(&data) {
                Ok(evidence) => {
                    let mut cache = self.local_cache.write().await;
                    cache.insert(key.to_string(), evidence.clone());
                    Ok(Some(evidence))
                }
                Err(e) => {
                    self.quarantine_decode_failure("evidence", key, &data, &e)
                        .await;
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    pub async fn has_signal(&self, key: &str) -> bool {
        self.read_evidence(key).await.ok().flatten().is_some()
    }

    /// Keys currently known (local cache ∪ Redis hash). Corrupt fields are quarantined
    /// and **omitted** so the DAG does not treat garbage as a present signal.
    pub async fn present_signals(&self) -> Result<Vec<String>, BlackboardError> {
        let mut keys: std::collections::BTreeSet<String> = {
            let cache = self.local_cache.read().await;
            cache.keys().cloned().collect()
        };
        if self.redis_enabled {
            let hash_key = self.redis_key();
            let mut conn = self.conn_for(&hash_key).await?;
            let map: HashMap<String, Vec<u8>> =
                tokio::time::timeout(REDIS_OP_TIMEOUT, conn.hgetall(&hash_key))
                    .await
                    .map_err(|_| BlackboardError::Redis("redis hgetall timeout".into()))??;
            for (k, raw) in map {
                match decode_evidence(&raw) {
                    Ok(ev) => {
                        let mut cache = self.local_cache.write().await;
                        cache.insert(k.clone(), ev);
                        keys.insert(k);
                    }
                    Err(e) => {
                        self.quarantine_decode_failure("evidence", &k, &raw, &e)
                            .await;
                    }
                }
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
        if !self.redis_enabled {
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
        let log_key = self.failures_key();
        let mut conn = self.conn_for(&log_key).await?;
        tokio::time::timeout(REDIS_OP_TIMEOUT, async {
            let _: () = conn.rpush(&log_key, serialized.as_slice()).await?;
            let _: () = conn.expire(&log_key, BLACKBOARD_TTL_SECS).await?;
            Ok::<(), redis::RedisError>(())
        })
        .await
        .map_err(|_| BlackboardError::Redis("redis failure-log timeout".into()))??;
        Ok(())
    }

    pub async fn list_failures(&self) -> Result<Vec<FailureLog>, BlackboardError> {
        if !self.redis_enabled {
            let ev = self.read_evidence("_failures").await?;
            let Some(v) = ev.map(|e| e.value) else {
                return Ok(Vec::new());
            };
            let parsed: Vec<FailureLog> = serde_json::from_value(v).unwrap_or_default();
            return Ok(parsed);
        }
        let log_key = self.failures_key();
        let mut conn = self.conn_for(&log_key).await?;
        let raw: Vec<Vec<u8>> =
            tokio::time::timeout(REDIS_OP_TIMEOUT, conn.lrange(&log_key, 0, -1))
                .await
                .map_err(|_| BlackboardError::Redis("redis lrange timeout".into()))??;
        let mut out = Vec::with_capacity(raw.len());
        for (i, row) in raw.into_iter().enumerate() {
            match decode_failure(&row) {
                Ok(f) => out.push(f),
                Err(e) => {
                    self.quarantine_decode_failure("failure", &format!("failures[{i}]"), &row, &e)
                        .await;
                }
            }
        }
        Ok(out)
    }

    /// Point `weissman:blackboard:latest:{tenant}:{client}` at this scan (24h TTL).
    pub async fn mark_latest(&self) -> Result<(), BlackboardError> {
        if !self.redis_enabled {
            return Ok(());
        }
        let idx = Self::latest_index_key(self.tenant_id, self.client_id);
        let mut conn = self.conn_for(&idx).await?;
        let scan = self.scan_id.clone();
        tokio::time::timeout(REDIS_OP_TIMEOUT, async {
            let _: () = conn.set(&idx, scan.as_str()).await?;
            let _: () = conn.expire(&idx, BLACKBOARD_TTL_SECS).await?;
            Ok::<(), redis::RedisError>(())
        })
        .await
        .map_err(|_| BlackboardError::Redis("redis mark_latest timeout".into()))??;
        Ok(())
    }
}

/// Default shard from the process-wide pool (compat for callers that want one manager).
pub async fn shared_redis_manager() -> Option<redis::aio::ConnectionManager> {
    acquire_redis_connection_with_timeout("weissman:blackboard")
        .await
        .ok()
}

/// Open the latest scan blackboard for a client (Redis index). `None` when no scan recorded.
pub async fn open_latest(
    tenant_id: i64,
    client_id: i64,
) -> Result<Option<ScanBlackboard>, BlackboardError> {
    let idx = ScanBlackboard::latest_index_key(tenant_id, client_id);
    let mut conn = match acquire_redis_connection_with_timeout(&idx).await {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let scan_id: Option<String> = tokio::time::timeout(REDIS_OP_TIMEOUT, conn.get(&idx))
        .await
        .map_err(|_| BlackboardError::Redis("redis connect timeout".into()))??;
    Ok(scan_id.map(|id| ScanBlackboard::new(tenant_id, client_id, id)))
}

pub async fn open_scan(
    tenant_id: i64,
    client_id: i64,
    scan_id: &str,
) -> Result<ScanBlackboard, BlackboardError> {
    if redis_url_configured() {
        Ok(ScanBlackboard::new(
            tenant_id,
            client_id,
            scan_id.to_string(),
        ))
    } else {
        Ok(ScanBlackboard::memory(tenant_id, client_id, scan_id))
    }
}

fn redis_url_configured() -> bool {
    std::env::var("REDIS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::AsyncCommands;
    use std::time::Duration;

    #[test]
    fn redis_timeouts_are_fifty_ms() {
        assert_eq!(REDIS_OP_TIMEOUT, Duration::from_millis(50));
        assert_eq!(REDIS_ACQUIRE_TIMEOUT, Duration::from_millis(50));
    }

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
    fn msgpack_v1_prefix_and_json_compat() {
        let ev = Evidence {
            source_engine: "asm".into(),
            timestamp: 42,
            value: serde_json::json!({"open": true}),
        };
        let packed = encode_evidence(&ev).unwrap();
        assert_eq!(packed.first().copied(), Some(CODEC_MAGIC));
        assert_eq!(packed.get(1).copied(), Some(CODEC_VERSION));
        assert_ne!(packed.first().copied(), Some(b'{'), "must not be JSON");
        let back = decode_evidence(&packed).unwrap();
        assert_eq!(back.source_engine, "asm");
        assert_eq!(back.value["open"], true);
        let json = serde_json::to_vec(&ev).unwrap();
        let from_json = decode_evidence(&json).unwrap();
        assert_eq!(from_json.source_engine, "asm");
    }

    #[test]
    fn decode_legacy_unversioned_msgpack() {
        let ev = Evidence {
            source_engine: "web_port_active".into(),
            timestamp: 7,
            value: serde_json::json!(true),
        };
        let legacy = rmp_serde::to_vec_named(&ev).unwrap();
        assert_ne!(legacy.first().copied(), Some(CODEC_MAGIC));
        let back = decode_evidence(&legacy).unwrap();
        assert_eq!(back.source_engine, "web_port_active");
        assert_eq!(back.timestamp, 7);
    }

    #[test]
    fn decode_future_version_skips_unknown_fields() {
        #[derive(Serialize)]
        struct FutureEvidence {
            source_engine: String,
            timestamp: i64,
            value: Value,
            extra_future_field: String,
            another_new_key: i64,
        }
        let body = rmp_serde::to_vec_named(&FutureEvidence {
            source_engine: "ot_ics".into(),
            timestamp: 99,
            value: serde_json::json!({"plc": "s7"}),
            extra_future_field: "schema-v99".into(),
            another_new_key: 123,
        })
        .unwrap();
        let mut buf = vec![CODEC_MAGIC, 99];
        buf.extend_from_slice(&body);
        let back = decode_evidence(&buf).expect("lenient skip of unknown fields");
        assert_eq!(back.source_engine, "ot_ics");
        assert_eq!(back.value["plc"], "s7");
    }

    #[test]
    fn decode_garbage_does_not_panic() {
        assert!(decode_evidence(&[]).is_err());
        assert!(decode_evidence(&[CODEC_MAGIC]).is_err());
        assert!(decode_evidence(&[0xff, 0xff, 0xff]).is_err());
        assert!(decode_failure(b"not-a-failure").is_err());
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
        let ping = tokio::time::timeout(
            Duration::from_secs(2),
            redis::aio::ConnectionManager::new(client),
        )
        .await;
        let Ok(Ok(mgr)) = ping else {
            return;
        };
        let mut conn = mgr.clone();
        let pong: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
        if pong.as_deref() != Ok("PONG") {
            return;
        }
        let bb = ScanBlackboard::with_manager(99, 88, "cem-dago-live-proof".into(), mgr);
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
        assert_eq!(bytes.first().copied(), Some(CODEC_MAGIC));
        assert_eq!(bytes.get(1).copied(), Some(CODEC_VERSION));
        let decoded = decode_evidence(&bytes).unwrap();
        assert_eq!(decoded.source_engine, "live_proof");
    }

    #[tokio::test]
    async fn decode_failure_quarantines_and_is_not_a_signal() {
        let bb = ScanBlackboard::memory(1, 2, "q-scan");
        bb.quarantine_decode_failure(
            "evidence",
            "web_port_active",
            &[0xff, 0x00, 0xc1],
            &BlackboardError::Deserialize("corrupt msgpack".into()),
        )
        .await;
        let q = bb.take_quarantine().await;
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].kind, "evidence");
        assert_eq!(q[0].field_key, "web_port_active");
        assert_eq!(q[0].raw_hex, "ff00c1");
        assert!(bb.read_evidence("web_port_active").await.unwrap().is_none());
        assert!(!bb.has_signal("web_port_active").await);
        assert!(bb.present_signals().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn redis_corrupt_field_quarantined_when_available() {
        let url = std::env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379/0".into());
        let Ok(client) = redis::Client::open(url.as_str()) else {
            return;
        };
        let ping = tokio::time::timeout(
            Duration::from_secs(2),
            redis::aio::ConnectionManager::new(client),
        )
        .await;
        let Ok(Ok(mgr)) = ping else {
            return;
        };
        let mut conn = mgr.clone();
        let pong: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
        if pong.as_deref() != Ok("PONG") {
            return;
        }
        let bb = ScanBlackboard::with_manager(77, 66, "cem-dago-quarantine-proof".into(), mgr);
        let hash = bb.redis_key();
        let garbage = b"%%%not-a-codec%%%";
        let _: () = conn
            .hset(&hash, "web_port_active", &garbage[..])
            .await
            .unwrap();
        assert!(bb.read_evidence("web_port_active").await.unwrap().is_none());
        let signals = bb.present_signals().await.unwrap();
        assert!(
            !signals.iter().any(|s| s == "web_port_active"),
            "corrupt field must not be a DAG signal"
        );
        let q = bb.take_quarantine().await;
        assert!(!q.is_empty(), "decode failure must quarantine, got {q:?}");
        let expected_hex = crate::cem_dago::telemetry_quarantine::encode_raw_hex(garbage);
        assert!(
            q.iter().any(|b| b.raw_hex.contains(&expected_hex)),
            "quarantine hex missing {expected_hex}: {q:?}"
        );
    }
}
