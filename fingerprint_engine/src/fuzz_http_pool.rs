//! Rotating egress proxies (`PROXIES_LIST` / `PROXIES_FILE`) and per-request User-Agent jitter for fuzz probes.

use rand::seq::SliceRandom;
use reqwest::Proxy;
use reqwest::RequestBuilder;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 15;

static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
];

#[must_use]
pub fn random_fuzz_user_agent() -> &'static str {
    USER_AGENTS
        .choose(&mut rand::thread_rng())
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

static GHOST_LANG: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.7",
    "fr-FR,fr;q=0.9,en;q=0.6",
    "ja-JP,ja;q=0.9,en;q=0.5",
    "es-ES,es;q=0.9,en;q=0.6",
    "pt-BR,pt;q=0.9,en;q=0.5",
    "nl-NL,nl;q=0.9,en;q=0.6",
];

static GHOST_PLATFORM: &[&str] = &["\"Windows\"", "\"macOS\"", "\"Linux\""];

/// Deterministic fingerprint from global sequence (optionally XOR with edge node id from job payload).
#[must_use]
pub fn ghost_swarm_sequence(edge_node_id: Option<i64>) -> u64 {
    let n = GHOST_SEQ.fetch_add(1, Ordering::Relaxed);
    match edge_node_id {
        Some(id) if id != 0 => n ^ (id as u64).rotate_left(17),
        _ => n,
    }
}

/// Apply rotating User-Agent, Accept-Language, Sec-CH-UA-Platform to a probe request.
pub fn apply_ghost_swarm_headers(req: RequestBuilder, seq: u64) -> RequestBuilder {
    let ua = USER_AGENTS[(seq as usize) % USER_AGENTS.len()];
    let lang = GHOST_LANG[(seq as usize) % GHOST_LANG.len()];
    let plat = GHOST_PLATFORM[((seq as usize) / 3) % GHOST_PLATFORM.len()];
    req.header("User-Agent", ua)
        .header("Accept-Language", lang)
        .header("Sec-CH-UA-Platform", plat)
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

async fn build_client_with_proxy(proxy_url: Option<&str>) -> Result<reqwest::Client, reqwest::Error> {
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
