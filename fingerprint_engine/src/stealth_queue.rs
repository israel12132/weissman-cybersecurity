//! Smart Stealth Queue — a global admission gateway that turns a burst of engine
//! requests against a single target into careful, human-paced Red-Team traffic.
//!
//! When an operator clicks **Run All** (up to the full engine arsenal) the
//! backend must not fan every request out at once: that trips WAFs, rate limits,
//! and can knock a fragile target over. This gateway shapes the traffic like a
//! disciplined human tester would:
//!
//! * **Per-target concurrency cap** — at most `per_target` requests are ever in
//!   flight against one host at once (default 10); the rest wait in a dynamic
//!   queue (a per-host [`Semaphore`]).
//! * **Global concurrency ceiling** — a second semaphore bounds total in-flight
//!   requests across *all* targets so one big engagement can't saturate egress.
//! * **Randomized jitter** — each admission sleeps a random interval so requests
//!   arrive with human cadence, never in a machine-gun burst.
//! * **Adaptive per-target pacing** — an optional minimum interval between
//!   request *starts* to the same host (a soft rate limit).
//! * **Rotating identity** — a pool of realistic `User-Agent` + client-hint
//!   headers so traffic blends in as ordinary browser sessions.
//!
//! Usage: an engine (or HTTP helper) calls [`acquire`] before an outbound
//! request or batch and holds the returned [`StealthPermit`] until it completes;
//! the permit frees both the per-target and global slots on drop. [`apply`]
//! stamps a request with a rotating browser identity.
//!
//! Everything is env-tunable (see [`QueueConfig::from_env`]) and can be disabled
//! wholesale with `WEISSMAN_STEALTH_DISABLED=1` (used by tests / offline CI).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dashmap::DashMap;
use rand::RngExt;
use reqwest::RequestBuilder;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Tunable limits for the stealth queue.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Max concurrent requests in flight against a single target host.
    pub per_target: usize,
    /// Max concurrent requests in flight across all targets.
    pub global: usize,
    /// Minimum jitter sleep before each admission (ms).
    pub jitter_min_ms: u64,
    /// Maximum jitter sleep before each admission (ms).
    pub jitter_max_ms: u64,
    /// Minimum interval between consecutive request *starts* to the same host
    /// (ms). 0 disables adaptive pacing (jitter + concurrency cap only).
    pub min_interval_ms: u64,
    /// Bypass everything (no caps, no sleeps). For tests / offline runs.
    pub disabled: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            per_target: 10,
            global: 64,
            // Modest per-request jitter: enough to break machine-gun cadence
            // without tanking throughput (the per-target concurrency cap and the
            // fleet-shaping rate limiter are the primary DoS/WAF protections).
            // Ghost-escalation mode raises jitter far higher once a WAF is seen.
            jitter_min_ms: 0,
            jitter_max_ms: 150,
            min_interval_ms: 0,
            disabled: false,
        }
    }
}

impl QueueConfig {
    /// Build from `WEISSMAN_STEALTH_*` env vars, falling back to defaults.
    #[must_use]
    pub fn from_env() -> Self {
        fn num(key: &str, default: u64) -> u64 {
            std::env::var(key)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default)
        }
        fn flag(key: &str) -> bool {
            matches!(
                std::env::var(key).as_deref(),
                Ok("1") | Ok("true") | Ok("yes") | Ok("on")
            )
        }
        let d = QueueConfig::default();
        let per_target = num("WEISSMAN_STEALTH_PER_TARGET", d.per_target as u64).max(1) as usize;
        let global =
            num("WEISSMAN_STEALTH_GLOBAL", d.global as u64).max(per_target as u64) as usize;
        let jitter_min_ms = num("WEISSMAN_STEALTH_JITTER_MIN_MS", d.jitter_min_ms);
        let jitter_max_ms =
            num("WEISSMAN_STEALTH_JITTER_MAX_MS", d.jitter_max_ms).max(jitter_min_ms);
        Self {
            per_target,
            global,
            jitter_min_ms,
            jitter_max_ms,
            min_interval_ms: num("WEISSMAN_STEALTH_MIN_INTERVAL_MS", d.min_interval_ms),
            disabled: flag("WEISSMAN_STEALTH_DISABLED"),
        }
    }
}

struct Inner {
    cfg: QueueConfig,
    global: Arc<Semaphore>,
    per_target: DashMap<String, Arc<Semaphore>>,
    last_start: DashMap<String, Instant>,
    /// Requests currently parked in [`acquire`] waiting for a slot (live gauge).
    waiting: AtomicU64,
    /// Cumulative admissions granted since process start (monotonic counter).
    admitted_total: AtomicU64,
    // Live-tunable *pacing* (cadence) — read on every admission, so held as
    // atomics that an operator can adjust at runtime via `reconfigure_pacing`.
    // Pacing only changes *timing*: the concurrency caps (`cfg.per_target` /
    // `cfg.global`, baked into the semaphores) and the `disabled` kill-switch
    // stay env-only, so the DoS/WAF protection floor can never be lowered from
    // the console — only the cadence within that envelope is tuned.
    jitter_min_ms: AtomicU64,
    jitter_max_ms: AtomicU64,
    min_interval_ms: AtomicU64,
}

/// Upper clamp for runtime-tunable pacing (60s) — generous for careful pacing,
/// bounded so a fat-fingered value can't wedge a scan behind an hour-long sleep.
const MAX_PACING_MS: u64 = 60_000;

/// Per-host live load: how many requests are in flight against one target.
#[derive(Debug, Clone)]
pub struct HostLoad {
    pub host: String,
    pub in_flight: usize,
    pub capacity: usize,
}

/// A point-in-time snapshot of the stealth queue for observability. Read-only:
/// the effective caps are set at deploy time via `WEISSMAN_STEALTH_*` env vars
/// (a safety-critical rate limiter is never weakened from the web console).
#[derive(Debug, Clone)]
pub struct StealthStatus {
    pub disabled: bool,
    pub per_target: usize,
    pub global_capacity: usize,
    pub jitter_min_ms: u64,
    pub jitter_max_ms: u64,
    pub min_interval_ms: u64,
    /// Requests in flight across all targets right now (global_capacity − free).
    pub global_in_flight: usize,
    /// Requests parked in the queue waiting for a slot right now.
    pub waiting: usize,
    /// Cumulative admissions granted since start.
    pub admitted_total: u64,
    /// Distinct hosts the queue has ever tracked (per-host semaphores retained).
    pub tracked_hosts: usize,
    /// Hosts with ≥1 request in flight, busiest first (capped for payload size).
    pub active_hosts: Vec<HostLoad>,
    /// Size of the rotating identity pools.
    pub user_agent_pool: usize,
    pub accept_language_pool: usize,
    pub platform_pool: usize,
    /// Total identities dispensed since start (rotation cursor).
    pub identities_dispensed: u64,
}

impl StealthStatus {
    /// Serialize to the JSON shape consumed by `GET /api/stealth/status`.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "disabled": self.disabled,
            "config": {
                "per_target": self.per_target,
                "global_capacity": self.global_capacity,
                "jitter_min_ms": self.jitter_min_ms,
                "jitter_max_ms": self.jitter_max_ms,
                "min_interval_ms": self.min_interval_ms,
                "env_keys": {
                    "per_target": "WEISSMAN_STEALTH_PER_TARGET",
                    "global": "WEISSMAN_STEALTH_GLOBAL",
                    "jitter_min_ms": "WEISSMAN_STEALTH_JITTER_MIN_MS",
                    "jitter_max_ms": "WEISSMAN_STEALTH_JITTER_MAX_MS",
                    "min_interval_ms": "WEISSMAN_STEALTH_MIN_INTERVAL_MS",
                    "disabled": "WEISSMAN_STEALTH_DISABLED"
                }
            },
            "live": {
                "global_in_flight": self.global_in_flight,
                "global_free": self.global_capacity.saturating_sub(self.global_in_flight),
                "waiting": self.waiting,
                "admitted_total": self.admitted_total,
                "tracked_hosts": self.tracked_hosts,
                "active_hosts": self.active_hosts.iter().map(|h| serde_json::json!({
                    "host": h.host,
                    "in_flight": h.in_flight,
                    "capacity": h.capacity,
                })).collect::<Vec<_>>(),
            },
            "identity": {
                "user_agent_pool": self.user_agent_pool,
                "accept_language_pool": self.accept_language_pool,
                "platform_pool": self.platform_pool,
                "identities_dispensed": self.identities_dispensed,
            }
        })
    }
}

/// A cheap, cloneable handle to the shared stealth queue.
#[derive(Clone)]
pub struct StealthQueue(Arc<Inner>);

/// RAII counter guard for the `waiting` gauge. Increments on construction and
/// decrements on drop — so the live queue-depth gauge stays accurate even when
/// an admission future is *cancelled* while parked (dropped mid-await under a
/// scan timeout / abort), which a plain increment/decrement pair would leak.
struct WaitGuard<'a>(&'a AtomicU64);

impl<'a> WaitGuard<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        WaitGuard(counter)
    }
}

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII admission ticket. Holds the per-target and global semaphore permits;
/// dropping it frees both slots for the next queued request.
#[must_use = "hold the permit for the duration of the request; dropping it early releases the slot"]
pub struct StealthPermit {
    _target: Option<OwnedSemaphorePermit>,
    _global: Option<OwnedSemaphorePermit>,
}

impl StealthQueue {
    /// Construct a queue with an explicit config (used directly by tests).
    #[must_use]
    pub fn new(cfg: QueueConfig) -> Self {
        let global = Arc::new(Semaphore::new(cfg.global.max(1)));
        let jitter_min_ms = AtomicU64::new(cfg.jitter_min_ms);
        let jitter_max_ms = AtomicU64::new(cfg.jitter_max_ms.max(cfg.jitter_min_ms));
        let min_interval_ms = AtomicU64::new(cfg.min_interval_ms);
        Self(Arc::new(Inner {
            cfg,
            global,
            per_target: DashMap::new(),
            last_start: DashMap::new(),
            waiting: AtomicU64::new(0),
            admitted_total: AtomicU64::new(0),
            jitter_min_ms,
            jitter_max_ms,
            min_interval_ms,
        }))
    }

    /// Update the live pacing (cadence) params at runtime — jitter bounds and the
    /// per-host minimum interval. Values are clamped to `[0, MAX_PACING_MS]` and
    /// `jitter_min ≤ jitter_max` is enforced. Concurrency caps and the disable
    /// kill-switch are deliberately NOT tunable here (env-only protection floor).
    /// Returns the effective values actually applied.
    pub fn reconfigure_pacing(
        &self,
        jitter_min_ms: u64,
        jitter_max_ms: u64,
        min_interval_ms: u64,
    ) -> (u64, u64, u64) {
        let lo = jitter_min_ms.min(MAX_PACING_MS);
        let hi = jitter_max_ms.min(MAX_PACING_MS).max(lo);
        let interval = min_interval_ms.min(MAX_PACING_MS);
        self.0.jitter_min_ms.store(lo, Ordering::Relaxed);
        self.0.jitter_max_ms.store(hi, Ordering::Relaxed);
        self.0.min_interval_ms.store(interval, Ordering::Relaxed);
        (lo, hi, interval)
    }

    /// Point-in-time snapshot of caps + live load for observability.
    #[must_use]
    pub fn status(&self) -> StealthStatus {
        let cap = self.0.cfg.per_target.max(1);
        let global_cap = self.0.cfg.global.max(1);
        let global_in_flight = global_cap.saturating_sub(self.0.global.available_permits());
        // Only surface hosts with live traffic; cap the list so a huge engagement
        // can't bloat the payload. Busiest hosts first.
        let mut active: Vec<HostLoad> = self
            .0
            .per_target
            .iter()
            .filter_map(|e| {
                let in_flight = cap.saturating_sub(e.value().available_permits());
                (in_flight > 0).then(|| HostLoad {
                    host: e.key().clone(),
                    in_flight,
                    capacity: cap,
                })
            })
            .collect();
        active.sort_by(|a, b| {
            b.in_flight
                .cmp(&a.in_flight)
                .then_with(|| a.host.cmp(&b.host))
        });
        active.truncate(64);
        StealthStatus {
            disabled: self.0.cfg.disabled,
            per_target: cap,
            global_capacity: global_cap,
            jitter_min_ms: self.0.jitter_min_ms.load(Ordering::Relaxed),
            jitter_max_ms: self.0.jitter_max_ms.load(Ordering::Relaxed),
            min_interval_ms: self.0.min_interval_ms.load(Ordering::Relaxed),
            global_in_flight,
            waiting: self.0.waiting.load(Ordering::Relaxed) as usize,
            admitted_total: self.0.admitted_total.load(Ordering::Relaxed),
            tracked_hosts: self.0.per_target.len(),
            active_hosts: active,
            user_agent_pool: USER_AGENTS.len(),
            accept_language_pool: ACCEPT_LANG.len(),
            platform_pool: PLATFORMS.len(),
            identities_dispensed: IDENTITY_SEQ.load(Ordering::Relaxed),
        }
    }

    /// Admit one request against `host`: wait for a free per-target slot and a
    /// free global slot, then pace + jitter, and return a permit that releases
    /// both on drop. `host` may be a bare host, `host:port`, or a full URL — it
    /// is normalized to the host key.
    pub async fn acquire(&self, host: &str) -> StealthPermit {
        if self.0.cfg.disabled {
            return StealthPermit {
                _target: None,
                _global: None,
            };
        }
        let key = normalize_host(host);

        // Clone the per-host semaphore Arc, dropping the DashMap guard *before*
        // awaiting so we never hold a shard lock across a suspension point.
        let target_sem = {
            let entry = self
                .0
                .per_target
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(self.0.cfg.per_target.max(1))));
            Arc::clone(entry.value())
        };

        // Per-target slot first, then the global ceiling. Count ourselves as
        // "waiting" across both awaits so the live gauge reflects real queue
        // depth — via an RAII guard so a cancelled (dropped) admission future
        // still decrements the gauge instead of leaking it.
        let wait = WaitGuard::new(&self.0.waiting);
        let target = target_sem.acquire_owned().await.ok();
        let global = Arc::clone(&self.0.global).acquire_owned().await.ok();
        drop(wait); // admitted — no longer queued (pace/jitter below is in-flight)

        self.0.admitted_total.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("weissman_stealth_acquire_total").increment(1);

        self.pace(&key).await;
        self.jitter().await;

        StealthPermit {
            _target: target,
            _global: global,
        }
    }

    /// Enforce the optional minimum interval between request starts to `key`.
    async fn pace(&self, key: &str) {
        let min_interval_ms = self.0.min_interval_ms.load(Ordering::Relaxed);
        if min_interval_ms == 0 {
            return;
        }
        let min = Duration::from_millis(min_interval_ms);
        let now = Instant::now();
        let wait = {
            let mut slot = self.0.last_start.entry(key.to_string()).or_insert(now);
            let since = now.saturating_duration_since(*slot);
            let w = min.saturating_sub(since);
            // Reserve the next start instant so concurrent admissions stagger.
            *slot = now + w;
            w
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    /// Sleep a random jitter interval within the configured bounds.
    async fn jitter(&self) {
        let lo = self.0.jitter_min_ms.load(Ordering::Relaxed);
        let hi = self.0.jitter_max_ms.load(Ordering::Relaxed).max(lo);
        if hi == 0 {
            return;
        }
        let ms = if hi > lo {
            rand::rng().random_range(lo..=hi)
        } else {
            lo
        };
        if ms > 0 {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
    }
}

/// The process-wide stealth queue, configured from the environment once.
#[must_use]
pub fn shared() -> StealthQueue {
    static SHARED: OnceLock<StealthQueue> = OnceLock::new();
    SHARED
        .get_or_init(|| StealthQueue::new(QueueConfig::from_env()))
        .clone()
}

/// Admit one request against `host` on the process-wide queue.
pub async fn acquire(host: &str) -> StealthPermit {
    shared().acquire(host).await
}

/// Snapshot of the process-wide queue for the observability endpoint.
#[must_use]
pub fn status() -> StealthStatus {
    shared().status()
}

/// Update the process-wide queue's live pacing params. Returns the effective
/// (clamped) `(jitter_min_ms, jitter_max_ms, min_interval_ms)`.
pub fn reconfigure_pacing(
    jitter_min_ms: u64,
    jitter_max_ms: u64,
    min_interval_ms: u64,
) -> (u64, u64, u64) {
    shared().reconfigure_pacing(jitter_min_ms, jitter_max_ms, min_interval_ms)
}

// ---------------------------------------------------------------------------
// Rotating browser identity
// ---------------------------------------------------------------------------

static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
];

static ACCEPT_LANG: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.7",
    "fr-FR,fr;q=0.9,en;q=0.6",
    "es-ES,es;q=0.9,en;q=0.6",
    "pt-BR,pt;q=0.9,en;q=0.5",
    "nl-NL,nl;q=0.9,en;q=0.6",
    "it-IT,it;q=0.9,en;q=0.6",
];

static PLATFORMS: &[&str] = &["\"Windows\"", "\"macOS\"", "\"Linux\"", "\"Android\""];

static IDENTITY_SEQ: AtomicU64 = AtomicU64::new(0);

/// Next rotating (User-Agent, Accept-Language, Sec-CH-UA-Platform) triple.
#[must_use]
pub fn rotating_identity() -> (&'static str, &'static str, &'static str) {
    let n = IDENTITY_SEQ.fetch_add(1, Ordering::Relaxed) as usize;
    (
        USER_AGENTS[n % USER_AGENTS.len()],
        ACCEPT_LANG[n % ACCEPT_LANG.len()],
        PLATFORMS[(n / 3) % PLATFORMS.len()],
    )
}

/// A random `User-Agent` from the pool (for callers that only need the UA).
#[must_use]
pub fn random_user_agent() -> &'static str {
    let n = rand::rng().random_range(0..USER_AGENTS.len());
    USER_AGENTS[n]
}

/// Stamp a request with a rotating browser identity so it blends in as ordinary
/// client traffic. Deliberately limited to the identity headers that are safe on
/// *any* request method / content type — `User-Agent`, `Accept-Language`, and
/// `Sec-CH-UA-Platform`. It does NOT set navigation-only headers (`Accept:
/// text/html`, `Sec-Fetch-*`) which would corrupt JSON/protobuf/API probes.
/// Callers that pass their own `User-Agent` in extra headers still win, because
/// engines apply their extra headers after this.
#[must_use]
pub fn apply(req: RequestBuilder) -> RequestBuilder {
    let (ua, lang, platform) = rotating_identity();
    req.header("User-Agent", ua)
        .header("Accept-Language", lang)
        .header("Sec-CH-UA-Platform", platform)
}

/// Normalize an arbitrary target string (URL / `host:port` / bare host / IPv6)
/// to its host key, so all engines pointed at the same host share one queue.
/// Deliberately lightweight — this runs on the per-request hot path, so it does
/// not invoke the full `TargetProfile::classify`.
fn normalize_host(target: &str) -> String {
    let t = target.trim();
    let rest = t.split_once("://").map_or(t, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or(authority)
    } else if authority.matches(':').count() == 1 {
        authority.split(':').next().unwrap_or(authority)
    } else {
        authority
    };
    host.to_lowercase()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn fast_cfg(per_target: usize, global: usize) -> QueueConfig {
        QueueConfig {
            per_target,
            global,
            jitter_min_ms: 0,
            jitter_max_ms: 0,
            min_interval_ms: 0,
            disabled: false,
        }
    }

    async fn measure_max_inflight(q: StealthQueue, hosts: Vec<String>) -> usize {
        let inflight = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for host in hosts {
            let q = q.clone();
            let inflight = inflight.clone();
            let max = max.clone();
            handles.push(tokio::spawn(async move {
                let _permit = q.acquire(&host).await;
                let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(cur, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(25)).await;
                inflight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        max.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn per_target_concurrency_is_capped() {
        let q = StealthQueue::new(fast_cfg(2, 100));
        let hosts = vec!["https://example.com/a".to_string(); 8];
        let max = measure_max_inflight(q, hosts).await;
        assert!(max <= 2, "per-target cap breached: {max} concurrent");
        assert!(max >= 1);
    }

    #[tokio::test]
    async fn global_concurrency_is_capped() {
        let q = StealthQueue::new(fast_cfg(10, 3));
        // Distinct hosts so the per-target cap never binds — only the global does.
        let hosts: Vec<String> = (0..12)
            .map(|i| format!("http://host{i}.example/"))
            .collect();
        let max = measure_max_inflight(q, hosts).await;
        assert!(max <= 3, "global cap breached: {max} concurrent");
    }

    #[tokio::test]
    async fn permit_released_on_drop_frees_slot() {
        let q = StealthQueue::new(fast_cfg(1, 1));
        {
            let _p = q.acquire("example.com").await;
        } // dropped here
          // Next acquire must succeed promptly now the slot is free.
        let again =
            tokio::time::timeout(Duration::from_millis(500), q.acquire("example.com")).await;
        assert!(again.is_ok(), "slot not released on drop");
    }

    #[tokio::test]
    async fn disabled_bypasses_all_caps() {
        let mut cfg = fast_cfg(1, 1);
        cfg.disabled = true;
        let q = StealthQueue::new(cfg);
        let hosts = vec!["example.com".to_string(); 6];
        let max = measure_max_inflight(q, hosts).await;
        assert!(max >= 4, "disabled queue should not serialize: max {max}");
    }

    #[tokio::test]
    async fn different_hosts_do_not_share_a_queue() {
        let q = StealthQueue::new(fast_cfg(1, 100));
        // Two distinct hosts, per-target cap 1 each → both can run at once.
        let hosts = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        let max = measure_max_inflight(q, hosts).await;
        assert_eq!(max, 2, "distinct hosts should run concurrently");
    }

    #[test]
    fn normalize_host_extracts_host() {
        assert_eq!(
            normalize_host("https://Example.com:8443/path?x=1"),
            "example.com"
        );
        assert_eq!(normalize_host("10.0.0.5:445"), "10.0.0.5");
        assert_eq!(normalize_host("HOST.example.org"), "host.example.org");
    }

    #[test]
    fn identity_rotates() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..USER_AGENTS.len() {
            seen.insert(rotating_identity().0);
        }
        assert!(seen.len() > 1, "user-agents should rotate");
    }

    #[tokio::test]
    async fn status_reports_live_load_and_caps() {
        let q = StealthQueue::new(fast_cfg(3, 10));
        // Idle: no traffic yet.
        let s0 = q.status();
        assert_eq!(s0.per_target, 3);
        assert_eq!(s0.global_capacity, 10);
        assert_eq!(s0.global_in_flight, 0);
        assert_eq!(s0.admitted_total, 0);
        assert!(s0.active_hosts.is_empty());
        assert!(s0.user_agent_pool >= 2);

        // Hold two permits against one host: in-flight must reflect them.
        let _p1 = q.acquire("https://target.example/a").await;
        let _p2 = q.acquire("https://target.example/b").await;
        let s1 = q.status();
        assert_eq!(s1.global_in_flight, 2);
        assert_eq!(s1.admitted_total, 2);
        assert_eq!(s1.active_hosts.len(), 1);
        assert_eq!(s1.active_hosts[0].host, "target.example");
        assert_eq!(s1.active_hosts[0].in_flight, 2);
        assert_eq!(s1.active_hosts[0].capacity, 3);

        // JSON snapshot is well-formed and carries the env-key hints.
        let j = s1.to_json();
        assert_eq!(j["live"]["global_in_flight"], 2);
        assert_eq!(
            j["config"]["env_keys"]["per_target"],
            "WEISSMAN_STEALTH_PER_TARGET"
        );

        drop(_p1);
        drop(_p2);
        let s2 = q.status();
        assert_eq!(s2.global_in_flight, 0, "permits freed on drop");
        assert_eq!(
            s2.admitted_total, 2,
            "cumulative counter does not decrement"
        );
    }

    #[tokio::test]
    async fn waiting_gauge_is_cancellation_safe() {
        // Single per-target slot so a second admission must queue.
        let q = StealthQueue::new(fast_cfg(1, 10));
        let _held = q.acquire("host.example").await;
        assert_eq!(q.status().waiting, 0, "no one waiting yet");

        // Second acquire parks behind the held slot; cancel it by dropping the
        // future on timeout. The WaitGuard must decrement despite cancellation.
        {
            let fut = q.acquire("host.example");
            let r = tokio::time::timeout(Duration::from_millis(50), fut).await;
            assert!(r.is_err(), "second acquire should block behind the held slot");
        }
        assert_eq!(
            q.status().waiting,
            0,
            "waiting gauge leaked after a parked admission was cancelled"
        );
        // The held permit is still valid; admitted_total counted only the one
        // real admission, not the cancelled attempt.
        assert_eq!(q.status().admitted_total, 1);
    }

    #[tokio::test]
    async fn reconfigure_pacing_clamps_and_takes_effect_live() {
        let q = StealthQueue::new(fast_cfg(4, 20));
        // Normal update: reflected immediately in status().
        let (lo, hi, iv) = q.reconfigure_pacing(20, 120, 50);
        assert_eq!((lo, hi, iv), (20, 120, 50));
        let s = q.status();
        assert_eq!(s.jitter_min_ms, 20);
        assert_eq!(s.jitter_max_ms, 120);
        assert_eq!(s.min_interval_ms, 50);

        // min > max is repaired (hi lifted to lo); everything clamped to MAX.
        let (lo, hi, iv) = q.reconfigure_pacing(500, 10, u64::MAX);
        assert_eq!(lo, 500);
        assert_eq!(hi, 500, "max lifted to min");
        assert_eq!(iv, MAX_PACING_MS, "interval clamped to ceiling");

        // Caps and disable are untouched by pacing reconfig (protection floor).
        let s = q.status();
        assert_eq!(s.per_target, 4);
        assert_eq!(s.global_capacity, 20);
        assert!(!s.disabled);
    }

    #[test]
    fn config_from_env_has_sane_defaults() {
        let d = QueueConfig::default();
        assert_eq!(d.per_target, 10);
        assert!(d.global >= d.per_target);
        assert!(d.jitter_max_ms >= d.jitter_min_ms);
    }
}
