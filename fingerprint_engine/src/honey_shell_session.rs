//! Debug-shell session state: Redis TTL 10 minutes + in-process LRU cap 1_000.
//!
//! Never stores attacker input as a process. Cwd is a fictional path only.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::honey_deception_node::ShellState;
use crate::http::rate_limit_redis;

/// Hard ceiling on simultaneous decoy shell sessions in this process (OOM guard).
pub const MAX_ACTIVE_DECOY_SESSIONS: usize = 1000;
pub const SESSION_TTL: Duration = Duration::from_secs(600);

const REDIS_PREFIX: &str = "weissman:honey:shell:";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredShell {
    cwd: String,
}

struct LruSlot {
    state: ShellState,
    at: Instant,
}

struct Lru {
    map: HashMap<String, LruSlot>,
    order: VecDeque<String>,
}

impl Lru {
    fn get(&mut self, fp: &str) -> Option<ShellState> {
        self.evict_expired();
        let slot = self.map.get(fp)?;
        if slot.at.elapsed() > SESSION_TTL {
            self.remove(fp);
            return None;
        }
        let st = slot.state.clone();
        if let Some(pos) = self.order.iter().position(|k| k == fp) {
            self.order.remove(pos);
            self.order.push_back(fp.to_string());
        }
        Some(st)
    }

    fn insert(&mut self, fp: String, state: ShellState) {
        self.evict_expired();
        if self.map.contains_key(&fp) {
            if let Some(pos) = self.order.iter().position(|k| k == &fp) {
                self.order.remove(pos);
            }
        } else {
            while self.map.len() >= MAX_ACTIVE_DECOY_SESSIONS {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                } else {
                    break;
                }
            }
        }
        self.order.push_back(fp.clone());
        self.map.insert(
            fp,
            LruSlot {
                state,
                at: Instant::now(),
            },
        );
    }

    fn remove(&mut self, fp: &str) {
        self.map.remove(fp);
        if let Some(pos) = self.order.iter().position(|k| k == fp) {
            self.order.remove(pos);
        }
    }

    fn evict_expired(&mut self) {
        let stale: Vec<String> = self
            .map
            .iter()
            .filter(|(_, s)| s.at.elapsed() > SESSION_TTL)
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            self.remove(&k);
        }
    }

    #[must_use]
    fn len(&self) -> usize {
        self.map.len()
    }
}

fn lru() -> &'static Mutex<Lru> {
    static LRU: OnceLock<Mutex<Lru>> = OnceLock::new();
    LRU.get_or_init(|| {
        Mutex::new(Lru {
            map: HashMap::new(),
            order: VecDeque::new(),
        })
    })
}

fn redis_key(fp: &str) -> String {
    format!("{REDIS_PREFIX}{fp}")
}

pub fn sanitize_cwd(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() || t.len() > 256 || t.contains('\0') || !t.starts_with('/') {
        return crate::honey_deception_node::HOME.to_string();
    }
    if t.chars().any(|c| c.is_control()) {
        return crate::honey_deception_node::HOME.to_string();
    }
    t.to_string()
}

#[must_use]
#[allow(dead_code)]
pub fn lru_len() -> usize {
    lru().lock().map(|g| g.len()).unwrap_or(0)
}

/// Load cwd for this attacker fingerprint. Redis first, then LRU, else default home.
pub async fn load_state(session_fp: &str) -> ShellState {
    if session_fp.is_empty() {
        return ShellState::default();
    }
    if let Some(raw) = rate_limit_redis::kv_get(&redis_key(session_fp)).await {
        if let Ok(stored) = serde_json::from_str::<StoredShell>(&raw) {
            let st = ShellState {
                cwd: sanitize_cwd(&stored.cwd),
            };
            if let Ok(mut g) = lru().lock() {
                g.insert(session_fp.to_string(), st.clone());
            }
            return st;
        }
    }
    if let Ok(mut g) = lru().lock() {
        if let Some(st) = g.get(session_fp) {
            return st;
        }
    }
    ShellState::default()
}

pub async fn save_state(session_fp: &str, state: &ShellState) {
    if session_fp.is_empty() {
        return;
    }
    let st = ShellState {
        cwd: sanitize_cwd(&state.cwd),
    };
    if let Ok(mut g) = lru().lock() {
        g.insert(session_fp.to_string(), st.clone());
    }
    let payload = serde_json::to_string(&StoredShell {
        cwd: st.cwd.clone(),
    })
    .unwrap_or_else(|_| format!("{{\"cwd\":\"{}\"}}", crate::honey_deception_node::HOME));
    let _ = rate_limit_redis::kv_set_ex(&redis_key(session_fp), &payload, SESSION_TTL).await;
}

/// Run a decoy command against persisted session state (never exec).
pub async fn exec_for_session(session_fp: &str, cmd: &str) -> serde_json::Value {
    let state = load_state(session_fp).await;
    let value = crate::honey_deception_node::shell_exec_json(cmd, &state.cwd);
    if let Some(cwd) = value.get("cwd").and_then(|v| v.as_str()) {
        save_state(
            session_fp,
            &ShellState {
                cwd: cwd.to_string(),
            },
        )
        .await;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_hard_caps_at_1000() {
        let mut cache = Lru {
            map: HashMap::new(),
            order: VecDeque::new(),
        };
        for i in 0..(MAX_ACTIVE_DECOY_SESSIONS + 50) {
            cache.insert(
                format!("cap-test-{i}"),
                ShellState {
                    cwd: format!("/tmp/{i}"),
                },
            );
        }
        assert_eq!(cache.len(), MAX_ACTIVE_DECOY_SESSIONS);
        assert!(cache.get("cap-test-0").is_none());
        assert!(cache
            .get(&format!("cap-test-{}", MAX_ACTIVE_DECOY_SESSIONS + 49))
            .is_some());
    }

    #[tokio::test]
    async fn cd_persists_across_calls() {
        let fp = format!("persist-cd-fp-{}", uuid::Uuid::new_v4());
        save_state(
            &fp,
            &ShellState {
                cwd: "/home/ops-admin".into(),
            },
        )
        .await;
        let first = exec_for_session(&fp, "cd /opt/weissman").await;
        assert_eq!(
            first.get("cwd").and_then(|v| v.as_str()),
            Some("/opt/weissman")
        );
        let second = exec_for_session(&fp, "pwd").await;
        let stdout = second.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
        assert!(stdout.contains("/opt/weissman"), "stdout={stdout}");
    }

    #[test]
    fn rejects_hostile_cwd() {
        assert_eq!(
            sanitize_cwd("not-absolute"),
            crate::honey_deception_node::HOME
        );
        assert_eq!(sanitize_cwd("/ok"), "/ok");
        assert_eq!(
            sanitize_cwd(&format!("/{}", "a".repeat(300))),
            crate::honey_deception_node::HOME
        );
    }
}
