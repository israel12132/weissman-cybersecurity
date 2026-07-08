//! Distributed job lease (Redlock-style single-Redis with cryptographic claim token).

use crate::error::JobBusError;
use rand::RngCore;
use redis::AsyncCommands;
use uuid::Uuid;

const LEASE_PREFIX: &str = "weissman:job:lease:";

pub fn new_claim_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn lease_key(job_id: Uuid) -> String {
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

pub struct DistributedLease;

impl DistributedLease {
    /// Acquire exclusive lease — SET NX with worker_id:claim_token binding.
    pub async fn acquire(
        redis: redis::aio::ConnectionManager,
        job_id: Uuid,
        worker_id: &str,
        claim_token: &str,
        lock_secs: i64,
    ) -> Result<LeaseHandle, JobBusError> {
        let key = lease_key(job_id);
        let value = lease_value(worker_id, claim_token);
        let mut conn = redis.clone();
        // Atomic `SET key value NX EX secs`. A separate `EXPIRE` after `SET NX` leaves the
        // lease with no TTL — wedged forever — if the process dies between the two calls.
        let acquired: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(&value)
            .arg("NX")
            .arg("EX")
            .arg(lock_secs.max(1))
            .query_async(&mut conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        if acquired.is_none() {
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

    /// Force-release a stale lease (swarm coordinator only).
    pub async fn force_release(
        redis: &redis::aio::ConnectionManager,
        job_id: Uuid,
    ) -> Result<(), JobBusError> {
        let mut conn = redis.clone();
        let _: () = conn.del(lease_key(job_id)).await?;
        Ok(())
    }
}
