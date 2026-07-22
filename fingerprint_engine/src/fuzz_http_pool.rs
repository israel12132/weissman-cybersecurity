//! Rotating egress proxies (`PROXIES_LIST` / `PROXIES_FILE`) and per-request User-Agent jitter for fuzz probes.

use rand::seq::IndexedRandom;
use reqwest::Proxy;
use reqwest::RequestBuilder;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 15;

// One authoritative, fresh browser User-Agent pool for the whole platform (see stealth_scheduler).
use crate::stealth_scheduler::USER_AGENTS;

#[must_use]
pub fn random_fuzz_user_agent() -> &'static str {
    USER_AGENTS
        .choose(&mut rand::rng())
        .copied()
        .unwrap_or(USER_AGENTS[0])
}

static GHOST_SEQ: AtomicU64 = AtomicU64::new(0);

/// Rotate client hints / Accept-Language rings (fuzz probes). True per-egress IP rotation uses `PROXIES_LIST` or edge proxies.
#[must_use]
pub fn ghost_swarm_fingerprint_enabled() -> bool {
    matches!(
        std::env::var("WEISSMAN_GHOST_SWARM_FINGERPRINT").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Deterministic fingerprint from global sequence (optionally XOR with edge node id from job payload).
#[must_use]
pub fn ghost_swarm_sequence(edge_node_id: Option<i64>) -> u64 {
    let n = GHOST_SEQ.fetch_add(1, Ordering::Relaxed);
    match edge_node_id {
        Some(id) if id != 0 => n ^ (id as u64).rotate_left(17),
        _ => n,
    }
}

/// Apply the full rotated stealth header set (UA + Accept*, Sec-Fetch-*, Sec-CH-UA-*, …) to a probe
/// request, drawn from the single authoritative `stealth_scheduler` source so every probe blends in
/// as a real browser rather than a scanner. Richer than a bare UA — the extra headers defeat header
/// -profile WAF rules.
pub fn apply_ghost_swarm_headers(req: RequestBuilder, seq: u64) -> RequestBuilder {
    let mut req = req;
    for (name, value) in crate::stealth_scheduler::header_set(seq as usize) {
        req = req.header(name, value);
    }
    req
}

fn load_all_proxies() -> Vec<String> {
    let mut list: Vec<String> = if let Ok(env_list) = std::env::var("PROXIES_LIST") {
        env_list
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    } else {
        vec![]
    };
    if list.is_empty() {
        if let Ok(path) = std::env::var("PROXIES_FILE") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                list = content
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
            }
        }
    }
    list
}

fn proxy_rotate_every() -> usize {
    std::env::var("WEISSMAN_FUZZ_PROXY_ROTATE_EVERY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1)
}

async fn build_client_with_proxy(
    proxy_url: Option<&str>,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs());
    if let Some(raw) = proxy_url {
        let raw = raw.trim();
        if !raw.is_empty() {
            let url = if raw.starts_with("http://") || raw.starts_with("https://") {
                raw.to_string()
            } else {
                format!("http://{raw}")
            };
            let p = Proxy::http(&url).or_else(|_| Proxy::all(&url))?;
            b = b.proxy(p);
        }
    }
    b.build()
}

/// One client per proxy (or a single direct client). Rotates egress every N probes.
pub struct FuzzHttpPool {
    clients: Vec<Arc<reqwest::Client>>,
    rotate_every: usize,
    counter: AtomicUsize,
}

impl FuzzHttpPool {
    pub async fn from_env() -> Result<Self, reqwest::Error> {
        let _ = std::env::var("WEISSMAN_REGION");
        let proxies = load_all_proxies();
        let rotate_every = proxy_rotate_every();
        let mut clients = Vec::new();
        if proxies.is_empty() {
            clients.push(Arc::new(build_client_with_proxy(None).await?));
        } else {
            for p in proxies {
                clients.push(Arc::new(build_client_with_proxy(Some(&p)).await?));
            }
        }
        Ok(Self {
            clients,
            rotate_every,
            counter: AtomicUsize::new(0),
        })
    }

    #[must_use]
    pub fn client_for_probe(&self) -> Arc<reqwest::Client> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let idx = if self.clients.len() == 1 {
            0
        } else {
            (n / self.rotate_every) % self.clients.len()
        };
        self.clients[idx].clone()
    }
}

/// Random delay between fuzz batches (anti-automation / behavioral WAF evasion).
pub async fn batch_jitter_sleep() {
    let low: u64 = std::env::var("WEISSMAN_FUZZ_BATCH_JITTER_MS_LOW")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let high: u64 = std::env::var("WEISSMAN_FUZZ_BATCH_JITTER_MS_HIGH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let low = low.min(high);
    let high = high.max(low);
    let ms = rand::random::<u64>() % (high - low + 1) + low;
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_user_agent_is_from_pool() {
        for _ in 0..20 {
            let ua = random_fuzz_user_agent();
            assert!(!ua.is_empty());
            assert!(USER_AGENTS.contains(&ua));
        }
    }

    #[test]
    fn client_for_probe_single_client_always_returns_it() {
        let c = Arc::new(reqwest::Client::new());
        let pool = FuzzHttpPool {
            clients: vec![Arc::clone(&c)],
            rotate_every: 5,
            counter: AtomicUsize::new(0),
        };
        for _ in 0..4 {
            assert!(Arc::ptr_eq(&pool.client_for_probe(), &c));
        }
    }

    #[test]
    fn client_for_probe_rotates_every_n_probes() {
        let c0 = Arc::new(reqwest::Client::new());
        let c1 = Arc::new(reqwest::Client::new());
        let pool = FuzzHttpPool {
            clients: vec![Arc::clone(&c0), Arc::clone(&c1)],
            rotate_every: 2,
            counter: AtomicUsize::new(0),
        };
        // idx = (n / rotate_every) % len : n=0,1 -> c0 ; n=2,3 -> c1 ; n=4 -> c0
        assert!(Arc::ptr_eq(&pool.client_for_probe(), &c0));
        assert!(Arc::ptr_eq(&pool.client_for_probe(), &c0));
        assert!(Arc::ptr_eq(&pool.client_for_probe(), &c1));
        assert!(Arc::ptr_eq(&pool.client_for_probe(), &c1));
        assert!(Arc::ptr_eq(&pool.client_for_probe(), &c0));
    }
}
