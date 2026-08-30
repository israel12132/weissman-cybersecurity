//! Distributed job lease (Redlock-style single-Redis with cryptographic claim token).

use crate::error::JobBusError;
use rand::Rng;
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

const LEASE_PREFIX: &str = "weissman:job:lease:";

pub fn new_claim_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn lease_key(job_id: Uuid) -> String {
    format!("{}{}", LEASE_PREFIX, job_id)
}

fn lease_value(worker_id: &str, claim_token: &str) -> String {
    format!("{}:{}", worker_id, claim_token)
}

/// Live Redis lease as seen by operators. Never includes the claim token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaseView {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_worker_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<i64>,
    /// Key exists but has no EXPIRE — this is the wedge the acquire path was written to prevent.
    pub no_ttl: bool,
}

/// Extract the owning worker from a lease value (`{worker_id}:{64-hex-token}`).
///
/// Worker ids themselves contain colons (`hostname:pid`), so this splits from the right
/// on the claim token rather than on the first colon.
#[must_use]
pub fn parse_lease_owner(value: &str) -> Option<String> {
    let (worker, token) = value.rsplit_once(':')?;
    if worker.is_empty() {
        return None;
    }
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(worker.to_string())
    } else {
        None
    }
}

fn lease_view_from_get_ttl(value: Option<&str>, ttl: i64) -> LeaseView {
    // TTL -2: key does not exist (expired between GET and TTL, or never written).
    if ttl == -2 || value.map(str::trim).unwrap_or("").is_empty() {
        return LeaseView {
            present: false,
            owner_worker_id: None,
            ttl_secs: None,
            no_ttl: false,
        };
    }
    LeaseView {
        present: true,
        owner_worker_id: value.and_then(parse_lease_owner),
        ttl_secs: if ttl >= 0 { Some(ttl) } else { None },
        no_ttl: ttl == -1,
    }
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

    /// Read-only snapshot of the live Redis lease. Does not acquire, extend, or release.
    pub async fn inspect<C: redis::aio::ConnectionLike>(
        conn: &mut C,
        job_id: Uuid,
    ) -> Result<LeaseView, JobBusError> {
        let key = lease_key(job_id);
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        Ok(lease_view_from_get_ttl(value.as_deref(), ttl))
    }

    /// Batch read-only inspect. Order-independent map keyed by job id.
    pub async fn inspect_many<C: redis::aio::ConnectionLike>(
        conn: &mut C,
        job_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, LeaseView>, JobBusError> {
        let mut out = HashMap::with_capacity(job_ids.len());
        if job_ids.is_empty() {
            return Ok(out);
        }
        let keys: Vec<String> = job_ids.iter().copied().map(lease_key).collect();
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&keys)
            .query_async(conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        let mut pipe = redis::pipe();
        for k in &keys {
            pipe.cmd("TTL").arg(k);
        }
        let ttls: Vec<i64> = pipe
            .query_async(conn)
            .await
            .map_err(|e| JobBusError::Redis(e.to_string()))?;
        for (i, id) in job_ids.iter().enumerate() {
            let value = values.get(i).and_then(|v| v.as_deref());
            let ttl = ttls.get(i).copied().unwrap_or(-2);
            out.insert(*id, lease_view_from_get_ttl(value, ttl));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn parse_owner_keeps_colons_inside_worker_id() {
        let v = format!("worker-host:4242:{}", hex64());
        assert_eq!(parse_lease_owner(&v).as_deref(), Some("worker-host:4242"));
    }

    #[test]
    fn parse_owner_rejects_short_or_non_hex_token() {
        assert!(parse_lease_owner("host:1:abcd").is_none());
        assert!(parse_lease_owner(
            "host:1:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_none());
        assert!(parse_lease_owner("").is_none());
        assert!(parse_lease_owner(&hex64()).is_none());
    }

    #[test]
    fn view_from_missing_key_is_absent() {
        let v = lease_view_from_get_ttl(None, -2);
        assert!(!v.present);
        assert!(v.owner_worker_id.is_none());
        assert!(!v.no_ttl);
    }

    #[test]
    fn view_from_live_lease_exposes_owner_and_ttl() {
        let raw = format!("box:99:{}", hex64());
        let v = lease_view_from_get_ttl(Some(&raw), 42);
        assert!(v.present);
        assert_eq!(v.owner_worker_id.as_deref(), Some("box:99"));
        assert_eq!(v.ttl_secs, Some(42));
        assert!(!v.no_ttl);
    }

    #[test]
    fn view_flags_lease_without_ttl() {
        let raw = format!("box:1:{}", hex64());
        let v = lease_view_from_get_ttl(Some(&raw), -1);
        assert!(v.present);
        assert!(v.no_ttl);
        assert!(v.ttl_secs.is_none());
    }

    #[tokio::test]
    async fn inspect_reads_acquired_lease_when_redis_live() {
        let Ok(url) = std::env::var("REDIS_URL") else {
            return;
        };
        if url.trim().is_empty() {
            return;
        }
        let client = match redis::Client::open(url.as_str()) {
            Ok(c) => c,
            Err(_) => return,
        };
        let redis = match redis::aio::ConnectionManager::new(client).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let job_id = Uuid::new_v4();
        let worker = "inspect-host:7";
        let token = new_claim_token();
        let handle = DistributedLease::acquire(redis.clone(), job_id, worker, &token, 30)
            .await
            .expect("acquire live lease");
        let mut conn = redis.clone();
        let view = DistributedLease::inspect(&mut conn, job_id)
            .await
            .expect("inspect live lease");
        assert!(
            view.present,
            "inspect must see the lease acquire just wrote"
        );
        assert_eq!(view.owner_worker_id.as_deref(), Some(worker));
        assert!(view.ttl_secs.unwrap_or(0) > 0);
        handle.release().await.expect("release live lease");
        let after = DistributedLease::inspect(&mut conn, job_id)
            .await
            .expect("inspect after release");
        assert!(!after.present);
    }
}
