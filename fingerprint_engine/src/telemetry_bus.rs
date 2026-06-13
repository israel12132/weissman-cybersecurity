//! Cross-replica real-time fan-out for SSE/WS broadcast channels via Redis pub/sub.
//!
//! Each replica keeps its in-process `tokio::sync::broadcast` channel (which is what the
//! SSE/WS handlers subscribe to). This module bridges that channel to a Redis pub/sub
//! topic so an event produced on replica A is also delivered to clients connected to
//! replica B. No-op when `REDIS_URL` is unset (single-replica → unchanged behaviour).
//!
//! ## Echo / amplification prevention (no publish-site changes required)
//! - Every replica has a random `instance_id`.
//! - **Egress**: subscribes the local broadcast and re-publishes each message to Redis,
//!   tagged with `instance_id` — UNLESS that exact message was just injected by our own
//!   ingress (tracked in a bounded "injected" set), which would otherwise loop forever.
//! - **Ingress**: subscribes Redis; for messages NOT from our own `instance_id`, records
//!   the message hash as "injected" and forwards it into the local broadcast so local
//!   clients see it. Messages we published ourselves (origin == our id) are ignored.
//!
//! Net effect: producers keep calling `tx.send(..)` (clients on the producing replica see
//! the event directly); every other replica's clients see it exactly once; no echo storm.

use futures::StreamExt;
use redis::AsyncCommands;
use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::broadcast;

/// Max recently-injected message hashes retained for echo suppression.
const INJECTED_CAP: usize = 8192;

/// Fixed-capacity set with FIFO eviction: O(1) membership for the most recent
/// `INJECTED_CAP` hashes. Unlike a periodic full `clear()`, evicting only the oldest
/// entry keeps the dedup window continuous — there is never a moment where a just-
/// injected message is forgotten and re-published into an echo loop.
struct BoundedHashSet {
    set: HashSet<u64>,
    order: VecDeque<u64>,
}

impl BoundedHashSet {
    fn new() -> Self {
        Self {
            set: HashSet::with_capacity(INJECTED_CAP + 1),
            order: VecDeque::with_capacity(INJECTED_CAP + 1),
        }
    }

    fn insert(&mut self, h: u64) {
        if !self.set.insert(h) {
            return; // already present — don't duplicate in the eviction queue
        }
        self.order.push_back(h);
        if self.order.len() > INJECTED_CAP {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
    }

    fn contains(&self, h: u64) -> bool {
        self.set.contains(&h)
    }
}

fn instance_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        use rand_core::{OsRng, RngCore};
        let mut b = [0u8; 8];
        OsRng.fill_bytes(&mut b);
        hex::encode(b)
    })
}

fn injected_set() -> &'static Mutex<BoundedHashSet> {
    static S: OnceLock<Mutex<BoundedHashSet>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(BoundedHashSet::new()))
}

fn hash_msg(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn mark_injected(h: u64) {
    if let Ok(mut set) = injected_set().lock() {
        set.insert(h);
    }
}

fn was_injected(h: u64) -> bool {
    injected_set()
        .lock()
        .map(|s| s.contains(h))
        .unwrap_or(false)
}

fn redis_url() -> Option<String> {
    std::env::var("REDIS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// Bridge a local broadcast channel to a Redis pub/sub topic. Spawns an egress and an
/// ingress task. No-op when `REDIS_URL` is unset. Call once per channel, per replica.
pub fn spawn_bridge(channel: &'static str, tx: broadcast::Sender<String>) {
    let Some(url) = redis_url() else {
        return;
    };
    let client = match redis::Client::open(url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[Weissman][telemetry_bus] redis open failed for '{channel}': {e}");
            return;
        }
    };
    let topic = format!("weissman:bus:{channel}");

    // Egress: local broadcast → Redis (skip messages our ingress just injected).
    {
        let client = client.clone();
        let topic = topic.clone();
        let mut rx = tx.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(msg) => {
                        if was_injected(hash_msg(&msg)) {
                            continue;
                        }
                        if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                            let env =
                                serde_json::json!({ "i": instance_id(), "m": msg }).to_string();
                            let _: Result<(), _> = conn.publish(&topic, env).await;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    // Ingress: Redis → local broadcast (skip our own messages; mark injected).
    tokio::spawn(async move {
        loop {
            match client.get_async_pubsub().await {
                Ok(mut pubsub) => {
                    if pubsub.subscribe(&topic).await.is_err() {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                    let mut stream = pubsub.on_message();
                    while let Some(m) = stream.next().await {
                        let Ok(payload) = m.get_payload::<String>() else {
                            continue;
                        };
                        let Ok(env) = serde_json::from_str::<serde_json::Value>(&payload) else {
                            continue;
                        };
                        let origin = env.get("i").and_then(|v| v.as_str()).unwrap_or("");
                        if origin == instance_id() {
                            continue;
                        }
                        if let Some(msg) = env.get("m").and_then(|v| v.as_str()) {
                            mark_injected(hash_msg(msg));
                            let _ = tx.send(msg.to_string());
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    });
    eprintln!("[Weissman][telemetry_bus] cross-replica bridge active for '{channel}'");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_dedup_roundtrips_and_bounds() {
        let h = hash_msg("{\"event\":\"x\",\"ts\":1}");
        assert!(!was_injected(h.wrapping_add(1)));
        mark_injected(h);
        assert!(was_injected(h));
    }

    #[test]
    fn bounded_set_evicts_oldest_first_without_full_wipe() {
        let mut s = BoundedHashSet::new();
        // Fill exactly to capacity with a disjoint hash space (offset by a constant
        // so these never collide with the roundtrip test's hashes).
        let base: u64 = 1_000_000;
        for i in 0..INJECTED_CAP as u64 {
            s.insert(base + i);
        }
        assert!(s.contains(base)); // oldest still present at capacity
        assert!(s.contains(base + INJECTED_CAP as u64 - 1)); // newest present

        // One more insert evicts ONLY the oldest, not the whole set (no clear()).
        s.insert(base + INJECTED_CAP as u64);
        assert!(!s.contains(base), "oldest must be evicted");
        assert!(
            s.contains(base + 1),
            "second-oldest must survive (no full wipe)"
        );
        assert!(
            s.contains(base + INJECTED_CAP as u64),
            "newest must be present"
        );
        assert_eq!(s.set.len(), INJECTED_CAP);
        assert_eq!(s.order.len(), INJECTED_CAP);
    }

    #[test]
    fn bounded_set_ignores_duplicate_inserts() {
        let mut s = BoundedHashSet::new();
        s.insert(42);
        s.insert(42);
        assert_eq!(
            s.order.len(),
            1,
            "duplicate must not grow the eviction queue"
        );
        assert!(s.contains(42));
    }

    #[test]
    fn instance_id_is_stable_and_hex() {
        let a = instance_id();
        let b = instance_id();
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
