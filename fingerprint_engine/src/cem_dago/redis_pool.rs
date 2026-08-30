//! Sharded Redis `ConnectionManager` pool sized to the cgroup CPU quota.
//!
//! A single multiplexed TCP socket head-of-line blocks when many `join_all`
//! tasks write large MessagePack payloads. We keep **one multiplexed manager
//! per physical/cgroup core** (clamped 2..=8) and pick the shard by key hash.
//! That splits client-side write buffers without opening a socket per engine.

use redis::aio::ConnectionManager;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::sync::OnceCell;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const SHARD_LO: usize = 2;
const SHARD_HI: usize = 8;

static POOL: OnceCell<Option<ShardedRedis>> = OnceCell::const_new();

#[derive(Clone)]
pub struct ShardedRedis {
    shards: Vec<ConnectionManager>,
}

impl ShardedRedis {
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.len()
    }

    #[must_use]
    pub fn shard(&self, key: &str) -> ConnectionManager {
        let i = shard_index(key, self.shards.len());
        self.shards[i].clone()
    }
}

#[must_use]
pub fn shard_index(key: &str, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() as usize) % n
}

/// cgroup v2 `cpu.max` quota, else `available_parallelism`. Clamped 2..=8.
#[must_use]
pub fn redis_shard_count() -> usize {
    cgroup_cpu_count().clamp(SHARD_LO, SHARD_HI)
}

fn cgroup_cpu_count() -> usize {
    let fallback = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let Ok(raw) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") else {
        return fallback;
    };
    let mut parts = raw.split_whitespace();
    let quota = parts.next().unwrap_or("max");
    let period = parts
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(100_000);
    if quota.eq_ignore_ascii_case("max") {
        return fallback;
    }
    let Ok(q) = quota.parse::<u64>() else {
        return fallback;
    };
    let n = q.saturating_add(period.saturating_sub(1)) / period.max(1);
    (n as usize).max(1)
}

pub async fn shared_redis_pool() -> Option<ShardedRedis> {
    POOL.get_or_init(|| async { build_pool().await })
        .await
        .clone()
}

async fn build_pool() -> Option<ShardedRedis> {
    let url = std::env::var("REDIS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let n = redis_shard_count();
    let mut shards = Vec::with_capacity(n);
    for _ in 0..n {
        let client = redis::Client::open(url.as_str()).ok()?;
        let mgr = tokio::time::timeout(CONNECT_TIMEOUT, ConnectionManager::new(client))
            .await
            .ok()?
            .ok()?;
        shards.push(mgr);
    }
    tracing::info!(
        target: "cem_dago",
        shards = shards.len(),
        "blackboard Redis sharded ConnectionManager pool online"
    );
    Some(ShardedRedis { shards })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_index_stable_and_in_range() {
        let n = 4;
        let a = shard_index("web_port_active", n);
        let b = shard_index("web_port_active", n);
        assert_eq!(a, b);
        assert!(a < n);
        let other = shard_index("ot_protocol", n);
        assert!(other < n);
    }

    #[test]
    fn shard_count_clamped() {
        let n = redis_shard_count();
        assert!((2..=8).contains(&n));
    }
}
