//! Distributed job lease (Redlock-style single-Redis with cryptographic claim token).
//!
//! Every write path MUST set a TTL. A `SET NX` without `EX` leaves the key immortal: after a
//! worker crash the row can be reclaimed in Postgres while Redis still denies `SET NX`, so
//! `tenant_full_scan` (and every other long job) sits `pending` forever. Acquire, extend, and
//! reclaim all go through Lua that refuses to persist a key without `EX`.

use crate::error::JobBusError;
use rand::Rng;
use std::collections::HashMap;
use uuid::Uuid;

const LEASE_PREFIX: &str = "weissman:job:lease:";

pub fn new_claim_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[must_use]
pub fn lease_key(job_id: Uuid) -> String {
    format!("{}{}", LEASE_PREFIX, job_id)
}

#[must_use]
pub fn lease_key_pattern() -> &'static str {
    "weissman:job:lease:*"
}

fn lease_value(worker_id: &str, claim_token: &str) -> String {
    format!("{}:{}", worker_id, claim_token)
}

/// Split `worker_id:claim_token`. `worker_id` itself contains a colon (`host:pid`).
#[must_use]
pub fn holder_worker_id(value: &str) -> Option<&str> {
    value
        .rsplit_once(':')
        .map(|(w, _)| w)
        .filter(|w| !w.is_empty())
}

/// Live Redis lease as observed by the jobs API / reclaim sweeper. `ttl_secs` uses Redis
/// conventions: `-2` missing, `-1` no expiry (immortal — a production incident), `>=0` remaining.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseInspection {
    pub exists: bool,
    pub ttl_secs: i64,
    pub holder_worker_id: Option<String>,
}

impl LeaseInspection {
    #[must_use]
    pub fn missing() -> Self {
        Self {
            exists: false,
            ttl_secs: -2,
            holder_worker_id: None,
        }
    }

    #[must_use]
    pub fn is_immortal(&self) -> bool {
        self.exists && self.ttl_secs == -1
    }
}

/// Result of inspecting many leases, including whether Redis itself answered.
#[derive(Debug, Clone)]
pub struct LeaseInspectBatch {
    pub redis_configured: bool,
    pub error: Option<String>,
    pub leases: HashMap<Uuid, LeaseInspection>,
}

/// Active distributed lease — only the holder with the claim token may extend/release.
pub struct LeaseHandle {
    redis: redis::aio::ConnectionManager,
    job_id: Uuid,
    worker_id: String,
    claim_token: String,
}

impl LeaseHandle {
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    pub fn claim_token(&self) -> &str {
        &self.claim_token
    }

    pub fn job_id(&self) -> Uuid {
        self.job_id
    }

    /// Refresh TTL atomically, still bound to the claim token.
    ///
    /// Uses `SET XX EX` (not bare `EXPIRE`) so a key that somehow lost its TTL is healed on the
    /// next living heartbeat instead of remaining immortal.
    pub async fn extend(&self, lock_secs: i64) -> Result<(), JobBusError> {
        let key = lease_key(self.job_id);
        let expected = lease_value(&self.worker_id, &self.claim_token);
        let ttl = lock_secs.max(1).to_string();
        let script = r#"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                redis.call('SET', KEYS[1], ARGV[1], 'XX', 'EX', ARGV[2])
                return 1
            else
                return 0
            end
        "#;
        let mut conn = self.redis.clone();
        let result: i32 = redis::Script::new(script)
            .key(&key)
            .arg(&expected)
            .arg(&ttl)
            .invoke_async(&mut conn)
            .await?;
        if result == 0 {
            return Err(JobBusError::LeaseDenied(
                "lease extension denied — token mismatch or expired".into(),
            ));
        }
        Ok(())
    }

    pub async fn release(self) -> Result<(), JobBusError> {
        let key = lease_key(self.job_id);
        let expected = lease_value(&self.worker_id, &self.claim_token);
        let script = r#"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('DEL', KEYS[1])
            else
                return 0
            end
        "#;
        let mut conn = self.redis.clone();
        let _: i32 = redis::Script::new(script)
            .key(&key)
            .arg(&expected)
            .invoke_async(&mut conn)
            .await?;
        Ok(())
    }
}

pub struct DistributedLease;

impl DistributedLease {
    /// Acquire exclusive lease — `SET NX EX`, stealing only immortal keys (TTL `-1`).
    ///
    /// A living worker refreshes TTL every heartbeat, so a key with a real TTL is never stolen
    /// here. A key with no TTL cannot belong to a living worker (extend would have written `EX`)
    /// and is the exact shape that wedged `tenant_full_scan` after a crash.
    pub async fn acquire(
        redis: redis::aio::ConnectionManager,
        job_id: Uuid,
        worker_id: &str,
        claim_token: &str,
        lock_secs: i64,
    ) -> Result<LeaseHandle, JobBusError> {
        let key = lease_key(job_id);
        let value = lease_value(worker_id, claim_token);
        let ttl = lock_secs.max(1).to_string();
        let mut conn = redis.clone();
        // Atomic: missing → SET EX; immortal (TTL -1) or TTL 0 → overwrite with SET EX;
        // live TTL > 0 → deny. Never SET without EX.
        let script = r#"
            local ttl = redis.call('TTL', KEYS[1])
            if ttl == -2 or ttl == -1 or ttl == 0 then
                redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
                return 1
            end
            return 0
        "#;
        let acquired: i32 = redis::Script::new(script)
            .key(&key)
            .arg(&value)
            .arg(&ttl)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        if acquired == 0 {
            return Err(JobBusError::LeaseDenied(format!(
                "job {job_id} already leased"
            )));
        }
        Ok(LeaseHandle {
            redis,
            job_id,
            worker_id: worker_id.to_string(),
            claim_token: claim_token.to_string(),
        })
    }

    pub async fn inspect(
        redis: &redis::aio::ConnectionManager,
        job_id: Uuid,
    ) -> Result<LeaseInspection, JobBusError> {
        let mut conn = redis.clone();
        let key = lease_key(job_id);
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        let ttl_secs: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        Ok(LeaseInspection {
            exists: value.is_some(),
            ttl_secs,
            holder_worker_id: value
                .as_deref()
                .and_then(holder_worker_id)
                .map(str::to_string),
        })
    }

    pub async fn inspect_many(
        redis: &redis::aio::ConnectionManager,
        job_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, LeaseInspection>, JobBusError> {
        let mut out = HashMap::with_capacity(job_ids.len());
        if job_ids.is_empty() {
            return Ok(out);
        }
        let mut pipe = redis::pipe();
        for id in job_ids {
            let key = lease_key(*id);
            pipe.cmd("GET").arg(&key).cmd("TTL").arg(&key);
        }
        let mut conn = redis.clone();
        let rows: Vec<redis::Value> = pipe
            .query_async(&mut conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        // Each job contributes GET then TTL.
        for (i, id) in job_ids.iter().enumerate() {
            let get_idx = i * 2;
            let ttl_idx = get_idx + 1;
            let value = rows.get(get_idx).and_then(redis_value_to_string);
            let ttl_secs = rows.get(ttl_idx).and_then(redis_value_to_i64).unwrap_or(-2);
            out.insert(
                *id,
                LeaseInspection {
                    exists: value.is_some(),
                    ttl_secs,
                    holder_worker_id: value
                        .as_deref()
                        .and_then(holder_worker_id)
                        .map(str::to_string),
                },
            );
        }
        Ok(out)
    }

    /// Force-release the lease of a worker the coordinator has declared dead.
    ///
    /// Compare-and-delete against the worker the coordinator actually observed, NOT a bare `DEL`.
    /// The unconditional delete raced the liveness check it followed: a worker whose 2s Redis
    /// liveness key lapsed during a runtime stall or a Redis blip (its refresh result is
    /// discarded, so it never learns) would have its still-valid lease destroyed while it was
    /// mid-scan. The next worker then acquired the freed key and ran the same red-team scan
    /// against the same customer target, concurrently.
    ///
    /// Deleting only when the value still names the dead worker means a lease re-acquired in the
    /// meantime — by that worker recovering, or by another worker legitimately taking over — is
    /// left alone. Returns whether a lease was actually removed.
    pub async fn force_release_owned(
        redis: &redis::aio::ConnectionManager,
        job_id: Uuid,
        worker_id: &str,
    ) -> Result<bool, JobBusError> {
        if worker_id.is_empty() {
            return Ok(false);
        }
        let mut conn = redis.clone();
        // The claim token is not known to the coordinator, so match on the `worker_id:` prefix.
        let script = r#"
            local v = redis.call('GET', KEYS[1])
            if v and string.sub(v, 1, string.len(ARGV[1])) == ARGV[1] then
                return redis.call('DEL', KEYS[1])
            else
                return 0
            end
        "#;
        let removed: i64 = redis::Script::new(script)
            .key(lease_key(job_id))
            .arg(format!("{worker_id}:"))
            .invoke_async(&mut conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        Ok(removed > 0)
    }

    /// After a Postgres stale-lock reclaim: drop this job's Redis lease if it still names the
    /// dead worker, or if it is immortal (TTL -1). A live TTL held by another worker is left
    /// alone so resume cannot double-execute.
    pub async fn release_for_reclaim(
        redis: &redis::aio::ConnectionManager,
        job_id: Uuid,
        worker_id: Option<&str>,
    ) -> Result<bool, JobBusError> {
        let mut removed = false;
        if let Some(w) = worker_id.filter(|s| !s.is_empty()) {
            removed = Self::force_release_owned(redis, job_id, w).await?;
        }
        let inspect = Self::inspect(redis, job_id).await?;
        if inspect.is_immortal() {
            let mut conn = redis.clone();
            let n: i64 = redis::cmd("DEL")
                .arg(lease_key(job_id))
                .query_async(&mut conn)
                .await
                .map_err(|e| JobBusError::Redis(e.to_string()))?;
            removed = removed || n > 0;
        }
        Ok(removed)
    }

    /// Delete every `weissman:job:lease:*` key that has no TTL. Living workers write `EX` on
    /// every extend, so a persist-forever key is a crash leftover and must not block resume.
    pub async fn heal_immortal_leases(
        redis: &redis::aio::ConnectionManager,
    ) -> Result<u64, JobBusError> {
        let mut conn = redis.clone();
        let mut cursor: u64 = 0;
        let mut healed = 0u64;
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(lease_key_pattern())
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .map_err(|e| JobBusError::Redis(e.to_string()))?;
            for key in keys {
                let ttl: i64 = redis::cmd("TTL")
                    .arg(&key)
                    .query_async(&mut conn)
                    .await
                    .map_err(|e| JobBusError::Redis(e.to_string()))?;
                if ttl == -1 {
                    let n: i64 = redis::cmd("DEL")
                        .arg(&key)
                        .query_async(&mut conn)
                        .await
                        .map_err(|e| JobBusError::Redis(e.to_string()))?;
                    if n > 0 {
                        healed += 1;
                        tracing::error!(
                            target: "job_bus_lease",
                            key = %key,
                            "deleted immortal job lease (no TTL) — this is the stuck-forever Redis lock"
                        );
                    }
                }
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(healed)
    }
}

fn redis_value_to_string(v: &redis::Value) -> Option<String> {
    match v {
        redis::Value::Nil => None,
        redis::Value::BulkString(bytes) => String::from_utf8(bytes.clone()).ok(),
        redis::Value::SimpleString(s) => Some(s.clone()),
        redis::Value::Okay => Some("OK".into()),
        _ => None,
    }
}

fn redis_value_to_i64(v: &redis::Value) -> Option<i64> {
    match v {
        redis::Value::Int(n) => Some(*n),
        redis::Value::BulkString(bytes) => std::str::from_utf8(bytes).ok()?.parse().ok(),
        redis::Value::SimpleString(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod holder_parse_tests {
    use super::holder_worker_id;

    #[test]
    fn splits_host_pid_from_claim_token() {
        assert_eq!(
            holder_worker_id(
                "scan-host:4127:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            Some("scan-host:4127")
        );
    }

    #[test]
    fn empty_and_token_only_are_none() {
        assert_eq!(holder_worker_id(""), None);
        assert_eq!(holder_worker_id(":token"), None);
    }
}
