//! Distributed idempotency — Redis SET NX lock + SHA-256 action fingerprint.

use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const LOCK_PREFIX: &str = "weissman:soar:lock:";
const DONE_PREFIX: &str = "weissman:soar:done:";
const DEFAULT_LOCK_SECS: u64 = 3600;

struct RedisSoar {
    client: redis::Client,
}

fn shared() -> Option<Arc<RedisSoar>> {
    static S: OnceLock<Option<Arc<RedisSoar>>> = OnceLock::new();
    S.get_or_init(|| {
        let url = std::env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let client = redis::Client::open(url).ok()?;
        tracing::info!(target: "soar_idempotency", "SOAR distributed locks enabled");
        Some(Arc::new(RedisSoar { client }))
    })
    .clone()
}

/// `SHA-256(action_kind | target_id | vulnerability_signature)` — stable across retries.
#[must_use]
pub fn idempotency_key(action_kind: &str, target_id: &str, vuln_signature: &str) -> String {
    let mut h = Sha256::new();
    h.update(action_kind.trim().to_ascii_lowercase().as_bytes());
    h.update(b"|");
    h.update(target_id.trim().as_bytes());
    h.update(b"|");
    h.update(vuln_signature.trim().as_bytes());
    hex::encode(h.finalize())
}

/// Guard releasing the Redis lock on drop (best-effort Lua compare-and-del).
pub enum SoarLockGuard {
    Redis {
        key: String,
        token: String,
        client: redis::Client,
    },
    /// Single-node fallback when REDIS_URL is unset.
    Local,
}

impl Drop for SoarLockGuard {
    fn drop(&mut self) {
        let SoarLockGuard::Redis { key, token, client } = self else {
            return;
        };
        let key = key.clone();
        let token = token.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
                return;
            };
            let script = r#"
                if redis.call('GET', KEYS[1]) == ARGV[1] then
                    return redis.call('DEL', KEYS[1])
                else
                    return 0
                end
            "#;
            let _: Result<i32, _> = redis::Script::new(script)
                .key(&key)
                .arg(&token)
                .invoke_async(&mut conn)
                .await;
        });
    }
}

/// Acquire exclusive lock for this idempotency key. `None` = already in-flight or done marker.
pub async fn try_acquire_lock(idempotency_key: &str) -> Option<SoarLockGuard> {
    let Some(rl) = shared() else {
        return Some(SoarLockGuard::Local);
    };
    let lock_key = format!("{LOCK_PREFIX}{idempotency_key}");
    let done_key = format!("{DONE_PREFIX}{idempotency_key}");
    let Ok(mut conn) = rl.client.get_multiplexed_async_connection().await else {
        return Some(SoarLockGuard::Local);
    };
    if conn.exists(&done_key).await.ok().unwrap_or(false) {
        return None;
    }
    let token = uuid::Uuid::new_v4().to_string();
    let acquired: bool = conn.set_nx(&lock_key, &token).await.ok().unwrap_or(false);
    if !acquired {
        return None;
    }
    let _: Result<(), _> = conn.expire(&lock_key, DEFAULT_LOCK_SECS as i64).await;
    Some(SoarLockGuard::Redis {
        key: lock_key,
        token,
        client: rl.client.clone(),
    })
}

/// Mark idempotency key completed — survives lock release for cooldown window.
pub async fn mark_completed(idempotency_key: &str, ttl: Duration) {
    let Some(rl) = shared() else {
        return;
    };
    let done_key = format!("{DONE_PREFIX}{idempotency_key}");
    if let Ok(mut conn) = rl.client.get_multiplexed_async_connection().await {
        let _: Result<(), _> = conn.set_ex(&done_key, 1i64, ttl.as_secs().max(60)).await;
    }
}

#[must_use]
pub fn redis_enabled() -> bool {
    shared().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_key_stable() {
        let a = idempotency_key("isolate_host", "i-abc123", "CVE-2021-44228");
        let b = idempotency_key("isolate_host", "i-abc123", "CVE-2021-44228");
        assert_eq!(a, b);
        assert_ne!(
            a,
            idempotency_key("isolate_host", "i-xyz", "CVE-2021-44228")
        );
    }
}
