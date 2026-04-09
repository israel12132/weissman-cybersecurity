//! Ghost network: polymorphic headers, jitter, proxy rotation (shared by all engines).

use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::time::Duration;

/// Stealth config (proxy pool, jitter, identity morphing).
#[derive(Clone, Debug, Default)]
pub struct StealthConfig {
    pub proxy_list: Vec<String>,
    pub jitter_min_ms: u64,
    pub jitter_max_ms: u64,
    pub identity_morphing: bool,
}

/// Behavioral jitter between sessions (human browsing cadence).
pub fn apply_behavioral_jitter() {
    let ms = rand::thread_rng().gen_range(200..=2000);
    std::thread::sleep(Duration::from_millis(ms));
}

fn random_spoof_ip() -> String {
    let mut rng = rand::thread_rng();
    match rng.gen_range(0..3) {
        0 => format!(
            "10.{}.{}.{}",
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(1..254)
        ),
        1 => format!(
            "172.{}.{}.{}",
            rng.gen_range(16..32),
            rng.gen_range(0..255),
            rng.gen_range(1..254)
        ),
        _ => format!(
            "192.168.{}.{}",
            rng.gen_range(0..255),
            rng.gen_range(1..254)
        ),
    }
}

impl StealthConfig {
    /// Parse proxy_swarm string (comma/newline separated URLs).
    pub fn parse_proxy_swarm(s: &str) -> Vec<String> {
        s.split([',', '\n', '\r'])
            .map(|x| x.trim().to_string())
            .filter(|x| {
                !x.is_empty()
                    && (x.starts_with("http://")
                        || x.starts_with("https://")
                        || x.starts_with("socks5://"))
            })
            .collect()
    }
}

pub fn apply_jitter(config: &StealthConfig) {
    let (min_ms, max_ms) = (
        config.jitter_min_ms,
        config.jitter_max_ms.max(config.jitter_min_ms),
    );
    if max_ms == 0 {
        return;
    }
    let ms = rand::thread_rng().gen_range(min_ms..=max_ms);
    std::thread::sleep(Duration::from_millis(ms));
}

pub fn build_client(config: &StealthConfig, timeout_secs: u64) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs());
    if !config.proxy_list.is_empty() {
        let idx = rand::thread_rng().gen_range(0..config.proxy_list.len());
        if let Some(proxy_url) = config.proxy_list.get(idx) {
            if !proxy_url.is_empty() {
                let normalized = if proxy_url.contains("://") {
                    proxy_url.clone()
                } else {
                    format!("http://{}", proxy_url)
                };
                if let Ok(proxy) = reqwest::Proxy::all(&normalized) {
                    builder = builder.proxy(proxy);
                }
            }
        }
    }
    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
];
const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "he-IL,he;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
];
const SEC_CH_UA: &[&str] = &[
    "\"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\", \"Not-A.Brand\";v=\"24\"",
    "\"Not_A Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
];
const CONNECTION: &[&str] = &["keep-alive", "Keep-Alive"];

pub fn random_morph_headers(config: &StealthConfig) -> HeaderMap {
    let mut map = HeaderMap::new();
    if !config.identity_morphing {
        return map;
    }
    let mut rng = rand::thread_rng();
    if let (Ok(name), Ok(val)) = (
        HeaderName::try_from("User-Agent"),
        HeaderValue::try_from(USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())]),
    ) {
        map.insert(name, val);
    }
    let spoof_ip = random_spoof_ip();
    if let (Ok(name), Ok(val)) = (
        HeaderName::try_from("X-Forwarded-For"),
        HeaderValue::try_from(spoof_ip.as_str()),
    ) {
        map.insert(name, val);
    }
    if let (Ok(name), Ok(val)) = (
        HeaderName::try_from("X-Real-IP"),
        HeaderValue::try_from(spoof_ip.as_str()),
    ) {
        map.insert(name, val);
    }
    if let (Ok(name), Ok(val)) = (
        HeaderName::try_from("Accept-Language"),
        HeaderValue::try_from(ACCEPT_LANGUAGES[rng.gen_range(0..ACCEPT_LANGUAGES.len())]),
    ) {
        map.insert(name, val);
    }
    if let (Ok(name), Ok(val)) = (
        HeaderName::try_from("Sec-Ch-Ua"),
        HeaderValue::try_from(SEC_CH_UA[rng.gen_range(0..SEC_CH_UA.len())]),
    ) {
        map.insert(name, val);
    }
    if let (Ok(name), Ok(val)) = (
        HeaderName::try_from("Connection"),
        HeaderValue::try_from(CONNECTION[rng.gen_range(0..CONNECTION.len())]),
    ) {
        map.insert(name, val);
    }
    map
}

pub fn is_waf_or_rate_limit(status: u16, body: &str) -> bool {
    if status == 429 {
        return true;
    }
    if status == 403 || status == 503 {
        let lower = body.to_lowercase();
        if lower.contains("rate limit")
            || lower.contains("too many requests")
            || lower.contains("blocked")
            || lower.contains("captcha")
            || lower.contains("cloudflare")
            || lower.contains("akamai")
            || (lower.contains("access denied") && lower.contains("waf"))
        {
            return true;
        }
    }
    false
}

pub fn apply_rotation_delay(config: &StealthConfig) {
    let extra = rand::thread_rng().gen_range(1000..=4000);
    let ms = (config.jitter_max_ms + extra).min(15_000);
    std::thread::sleep(Duration::from_millis(ms));
}
