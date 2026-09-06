//! Distributed job lease (Redlock-style single-Redis with cryptographic claim token).

use crate::error::JobBusError;
use rand::Rng;
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

fn lease_value(worker_id: &str, claim_token: &str) -> String {
    format!("{}:{}", worker_id, claim_token)
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

    pub async fn extend(&self, lock_secs: i64) -> Result<(), JobBusError> {
        let key = lease_key(self.job_id);
        let expected = lease_value(&self.worker_id, &self.claim_token);
        let script = r#"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('EXPIRE', KEYS[1], ARGV[2])
            else
                return 0
            end
        "#;
        let mut conn = self.redis.clone();
        let result: i32 = redis::Script::new(script)
            .key(&key)
            .arg(&expected)
            .arg(lock_secs.max(1))
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

/// Read-only snapshot of one Redis job lease (GET + TTL). Never mutates.
#[derive(Debug, Clone, Default)]
pub struct LeaseInspect {
    pub exists: bool,
    /// Redis TTL: `-2` missing, `-1` immortal (no EXPIRE), `>= 0` remaining seconds.
    pub ttl_secs: i64,
    pub holder_worker_id: Option<String>,
}

impl LeaseInspect {
    #[must_use]
    pub fn is_immortal(&self) -> bool {
        self.exists && self.ttl_secs == -1
    }
}

pub struct DistributedLease;

impl DistributedLease {
    /// Acquire exclusive lease — SET NX with worker_id:claim_token binding.
    ///
    /// An existing key with **no TTL** (the historical SET-without-EX crash window) is
    /// stolen once so a tenant scan can resume. A healthy TTL'd lease is never stolen.
    pub async fn acquire(
        redis: redis::aio::ConnectionManager,
        job_id: Uuid,
        worker_id: &str,
        claim_token: &str,
        lock_secs: i64,
    ) -> Result<LeaseHandle, JobBusError> {
        let key = lease_key(job_id);
        let value = lease_value(worker_id, claim_token);
        let ttl = lock_secs.max(1);
        let mut conn = redis.clone();
        for attempt in 0..2 {
            let acquired: Option<String> = redis::cmd("SET")
                .arg(&key)
                .arg(&value)
                .arg("NX")
                .arg("EX")
                .arg(ttl)
                .query_async(&mut conn)
                .await
                .map_err(|e| JobBusError::Redis(e.to_string()))?;
            if acquired.is_some() {
                return Ok(LeaseHandle {
                    redis,
                    job_id,
                    worker_id: worker_id.to_string(),
                    claim_token: claim_token.to_string(),
                });
            }
            let inspect = Self::inspect(&redis, job_id).await?;
            if inspect.is_immortal() {
                tracing::warn!(
                    target: "job_bus_lease",
                    %job_id,
                    previous_worker = ?inspect.holder_worker_id,
                    "stealing immortal lease (no TTL) so the job can resume"
                );
                let _: i64 = redis::cmd("DEL")
                    .arg(&key)
                    .query_async(&mut conn)
                    .await
                    .map_err(|e| JobBusError::Redis(e.to_string()))?;
                if attempt == 0 {
                    continue;
                }
            }
            break;
        }
        Err(JobBusError::LeaseDenied(format!(
            "job {job_id} already leased"
        )))
    }

    /// GET + TTL for one job. `ttl_secs == -1` means the key has no expire.
    pub async fn inspect(
        redis: &redis::aio::ConnectionManager,
        job_id: Uuid,
    ) -> Result<LeaseInspect, JobBusError> {
        let mut conn = redis.clone();
        let key = lease_key(job_id);
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        Ok(LeaseInspect {
            exists: value.is_some(),
            ttl_secs: ttl,
            holder_worker_id: value
                .as_ref()
                .and_then(|v| v.split(':').next())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        })
    }

    pub async fn inspect_many(
        redis: &redis::aio::ConnectionManager,
        job_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, LeaseInspect>, JobBusError> {
        let mut out = std::collections::HashMap::with_capacity(job_ids.len());
        for id in job_ids {
            out.insert(*id, Self::inspect(redis, *id).await?);
        }
        Ok(out)
    }

    /// Delete lease keys that have no TTL (TTL -1). A process crash between SET NX and
    /// EXPIRE used to leave keys that no worker could ever steal. Returns how many were removed.
    pub async fn heal_immortal_leases(
        redis: &redis::aio::ConnectionManager,
    ) -> Result<u64, JobBusError> {
        let mut conn = redis.clone();
        let mut cursor: u64 = 0;
        let mut keys: Vec<String> = Vec::new();
        loop {
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{LEASE_PREFIX}*"))
                .arg("COUNT")
                .arg(100i64)
                .query_async(&mut conn)
                .await
                .map_err(|e| JobBusError::Redis(e.to_string()))?;
            keys.extend(batch);
            cursor = next;
            if cursor == 0 || keys.len() >= 4096 {
                break;
            }
        }
        let mut healed = 0u64;
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
                }
            }
        }
        Ok(healed)
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
}
