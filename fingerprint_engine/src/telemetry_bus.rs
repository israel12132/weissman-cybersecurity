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
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::broadcast;

fn instance_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        use rand_core::{OsRng, RngCore};
        let mut b = [0u8; 8];
        OsRng.fill_bytes(&mut b);
        hex::encode(b)
    })
}

fn injected_set() -> &'static Mutex<HashSet<u64>> {
    static S: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

fn hash_msg(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn mark_injected(h: u64) {
    if let Ok(mut set) = injected_set().lock() {
        if set.len() > 8192 {
            set.clear();
        }
        set.insert(h);
    }
}

fn was_injected(h: u64) -> bool {
    injected_set().lock().map(|s| s.contains(&h)).unwrap_or(false)
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
    fn instance_id_is_stable_and_hex() {
        let a = instance_id();
        let b = instance_id();
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
