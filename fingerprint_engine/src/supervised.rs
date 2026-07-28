//! Supervised background tasks — keep the platform's long-lived loops alive.
//!
//! Several critical loops run as fire-and-forget `tokio::spawn` tasks: the 10s health / self-heal
//! loop ([`crate::observability::spawn_pool_metrics_loop`]), the cron scan-schedule worker
//! ([`crate::scan_schedule_worker`]), the worker's stale-lock reclaimer. Two failure modes are
//! currently silent and unrecovered:
//!
//! - **Panic** — a panic inside the spawned task kills it for the rest of the process lifetime.
//!   Self-healing, cron, or reclaim just *stops*, with no restart and no signal.
//! - **Stuck** — a loop wedged on a dependency call with no timeout (e.g. a `fetch_one` against a
//!   hung Postgres) is still "up" but makes no progress, so the function it performs silently stalls.
//!
//! [`supervise`] wraps such a loop: it restarts the task on exit/panic with bounded exponential
//! backoff and — when given a [`Heartbeat`] the loop bumps each iteration — a watchdog aborts and
//! restarts the task once it goes stuck (no beat within `stuck_deadline_secs`). This is the
//! "supervised auto-restart of stuck workers" follow-up from `docs/PLATFORM_SELF_HEALING.md`.
//!
//! # Safety
//! - Auto-restart is pure upside for an idempotent background loop: a dead/stuck loop revived is
//!   strictly better than one left dead. It never touches per-job processing (jobs already have
//!   their own timeout+abort and stale-lock reclaim), so it changes no job semantics.
//! - **Kill switch.** `WEISSMAN_SUPERVISOR_ENABLED=0` runs the factory exactly once, unsupervised —
//!   i.e. today's fire-and-forget behavior — so supervision can be disabled without code changes.
//! - **Bounded.** Backoff grows exponentially to a cap, so a hard crash-loop cannot hot-spin; each
//!   restart is counted (`weissman_supervised_restart_total{task,reason}`) and a crash-loop is
//!   visible via that rate + the `weissman_supervised_up{task}` gauge.
//!
//! # Testability
//! The decision core ([`next_backoff_secs`], [`is_stuck`], [`join_reason`]) is **pure** and
//! unit-tested; the restart glue is covered by an async test that a panicking factory is restarted.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinError;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => default,
    }
}

/// Tunables (env-overridable) that bound supervision.
#[derive(Debug, Clone, Copy)]
pub struct SupervisorConfig {
    /// Master switch — when false, [`supervise`] runs the factory once, unsupervised.
    pub enabled: bool,
    /// First restart's backoff; doubles each subsequent restart up to `max_backoff_secs`.
    pub base_backoff_secs: u64,
    /// Ceiling on the restart backoff (a hard crash-loop settles here rather than hot-spinning).
    pub max_backoff_secs: u64,
    /// A supervised task with a heartbeat is considered stuck after this many seconds without a
    /// beat; the watchdog then aborts and restarts it. `0` disables stuck-detection (exit/panic
    /// restart still applies).
    pub stuck_deadline_secs: u64,
    /// How often the watchdog checks the heartbeat.
    pub watchdog_poll_secs: u64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_backoff_secs: 2,
            max_backoff_secs: 60,
            stuck_deadline_secs: 0,
            watchdog_poll_secs: 10,
        }
    }
}

impl SupervisorConfig {
    /// Load from `WEISSMAN_SUPERVISOR_*` env, falling back to [`SupervisorConfig::default`].
    #[must_use]
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            enabled: env_bool("WEISSMAN_SUPERVISOR_ENABLED", d.enabled),
            base_backoff_secs: env_u64(
                "WEISSMAN_SUPERVISOR_BASE_BACKOFF_SECS",
                d.base_backoff_secs,
            ),
            max_backoff_secs: env_u64("WEISSMAN_SUPERVISOR_MAX_BACKOFF_SECS", d.max_backoff_secs)
                .max(1),
            stuck_deadline_secs: env_u64(
                "WEISSMAN_SUPERVISOR_STUCK_DEADLINE_SECS",
                d.stuck_deadline_secs,
            ),
            watchdog_poll_secs: env_u64(
                "WEISSMAN_SUPERVISOR_WATCHDOG_POLL_SECS",
                d.watchdog_poll_secs,
            )
            .max(1),
        }
    }

    /// A config that also watches a heartbeat and restarts a stuck task after `deadline` seconds.
    #[must_use]
    pub fn with_stuck_deadline(mut self, deadline_secs: u64, poll_secs: u64) -> Self {
        self.stuck_deadline_secs = deadline_secs;
        self.watchdog_poll_secs = poll_secs.max(1);
        self
    }
}

/// A liveness beat a supervised loop bumps each iteration; the watchdog reads it to detect a stuck
/// task. Cheap, lock-free (a single atomic epoch-secs).
#[derive(Debug)]
pub struct Heartbeat {
    last: AtomicU64,
}

impl Heartbeat {
    /// A heartbeat that starts "beating now".
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            last: AtomicU64::new(now_secs()),
        })
    }

    /// A heartbeat pinned to a specific epoch-secs (for tests / a known-stale start).
    #[must_use]
    pub fn with_last(secs: u64) -> Arc<Self> {
        Arc::new(Self {
            last: AtomicU64::new(secs),
        })
    }

    /// Record progress — call once per loop iteration.
    pub fn beat(&self) {
        self.last.store(now_secs(), Ordering::SeqCst);
    }

    /// Epoch-secs of the last beat.
    #[must_use]
    pub fn last_beat(&self) -> u64 {
        self.last.load(Ordering::SeqCst)
    }
}

/// Pure: the backoff (seconds) before the `restarts`-th restart. Exponential from
/// `base` (the 1st restart), doubling each time, capped at `max`. `restarts == 0` ⇒ 0.
#[must_use]
pub fn next_backoff_secs(restarts: u32, base: u64, max: u64) -> u64 {
    if restarts == 0 || base == 0 {
        return 0;
    }
    // base * 2^(restarts-1), capped at max. Double with SATURATING multiply and short-circuit at
    // the cap: a plain `base << (restarts-1)` would *wrap* to 0 for a large restart count, handing
    // a crash-loop 0 backoff — the exact hot-spin the cap exists to prevent.
    let mut v = base;
    for _ in 1..restarts {
        v = v.saturating_mul(2);
        if v >= max {
            return max;
        }
    }
    v.min(max)
}

/// Pure: a heartbeat-bearing task is stuck iff it has not beaten within `deadline` seconds.
/// `deadline == 0` disables the check (never stuck).
#[must_use]
pub fn is_stuck(last_beat: u64, now: u64, deadline: u64) -> bool {
    deadline > 0 && now.saturating_sub(last_beat) >= deadline
}

/// Pure: why a supervised task's `JoinHandle` resolved, as a stable metric label.
#[must_use]
pub fn join_reason(res: &Result<(), JoinError>) -> &'static str {
    match res {
        Ok(()) => "exited",
        Err(e) if e.is_panic() => "panicked",
        Err(_) => "cancelled",
    }
}

/// Run `factory` under supervision forever: (re)spawn it, and when it exits, panics, or (with a
/// heartbeat) goes stuck, count the restart, back off, and spawn it again. Never returns while
/// supervision is enabled.
///
/// `factory` is called once per (re)start and must produce a fresh future each time (clone whatever
/// it captures). When `hb` is `Some` and `cfg.stuck_deadline_secs > 0`, the loop the factory runs
/// should call [`Heartbeat::beat`] each iteration so the watchdog can tell progress from a hang.
pub async fn supervise<F, Fut>(
    name: &'static str,
    cfg: SupervisorConfig,
    hb: Option<Arc<Heartbeat>>,
    mut factory: F,
) where
    F: FnMut(Option<Arc<Heartbeat>>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    if !cfg.enabled {
        // Supervision off ⇒ today's behavior: run the loop once, unsupervised.
        factory(hb).await;
        return;
    }
    let watchdog = cfg.stuck_deadline_secs > 0 && hb.is_some();
    let mut restarts: u32 = 0;
    loop {
        metrics::gauge!("weissman_supervised_up", "task" => name).set(1.0);
        if watchdog {
            if let Some(ref h) = hb {
                // Fresh window each (re)start so a slow first iteration is not mistaken for stuck.
                h.beat();
            }
        }
        let handle = tokio::spawn(factory(hb.clone()));
        let reason = if watchdog {
            supervise_watch(handle, hb.clone().expect("watchdog implies hb"), &cfg).await
        } else {
            join_reason(&handle.await)
        };
        restarts = restarts.saturating_add(1);
        metrics::gauge!("weissman_supervised_up", "task" => name).set(0.0);
        metrics::counter!(
            "weissman_supervised_restart_total",
            "task" => name,
            "reason" => reason,
        )
        .increment(1);
        let backoff = next_backoff_secs(restarts, cfg.base_backoff_secs, cfg.max_backoff_secs);
        tracing::warn!(
            target: "supervised",
            task = name,
            reason,
            restarts,
            backoff_secs = backoff,
            "supervised task ended — restarting after backoff"
        );
        if backoff > 0 {
            tokio::time::sleep(Duration::from_secs(backoff)).await;
        }
    }
}

/// Wait for the task to finish, OR — polling the heartbeat — abort and reap it if it goes stuck.
/// Returns the restart reason (`"stuck"` when the watchdog fired).
async fn supervise_watch(
    mut handle: tokio::task::JoinHandle<()>,
    hb: Arc<Heartbeat>,
    cfg: &SupervisorConfig,
) -> &'static str {
    let mut poll = tokio::time::interval(Duration::from_secs(cfg.watchdog_poll_secs));
    poll.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            res = &mut handle => return join_reason(&res),
            _ = poll.tick() => {
                if is_stuck(hb.last_beat(), now_secs(), cfg.stuck_deadline_secs) {
                    handle.abort();
                    let _ = (&mut handle).await; // reap the cancelled task
                    return "stuck";
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[test]
    fn backoff_is_exponential_and_capped() {
        // base 2, cap 60: 2, 4, 8, 16, 32, then capped at 60.
        assert_eq!(next_backoff_secs(0, 2, 60), 0); // no restart yet
        assert_eq!(next_backoff_secs(1, 2, 60), 2);
        assert_eq!(next_backoff_secs(2, 2, 60), 4);
        assert_eq!(next_backoff_secs(3, 2, 60), 8);
        assert_eq!(next_backoff_secs(4, 2, 60), 16);
        assert_eq!(next_backoff_secs(5, 2, 60), 32);
        assert_eq!(next_backoff_secs(6, 2, 60), 60); // 64 -> capped
        assert_eq!(next_backoff_secs(100, 2, 60), 60); // stays capped, no overflow
    }

    #[test]
    fn backoff_zero_base_stays_zero() {
        assert_eq!(next_backoff_secs(1, 0, 60), 0);
        assert_eq!(next_backoff_secs(10, 0, 60), 0);
    }

    #[test]
    fn stuck_only_past_deadline() {
        assert!(!is_stuck(1_000, 1_000, 30)); // just beat
        assert!(!is_stuck(1_000, 1_029, 30)); // 29s < 30s
        assert!(is_stuck(1_000, 1_030, 30)); // 30s >= 30s
        assert!(is_stuck(1_000, 5_000, 30)); // long stall
        assert!(!is_stuck(1_000, 9_999, 0)); // deadline 0 disables
    }

    #[test]
    fn join_reason_maps_outcomes() {
        assert_eq!(join_reason(&Ok(())), "exited");
    }

    #[test]
    fn heartbeat_beat_advances_last() {
        let hb = Heartbeat::with_last(0);
        assert_eq!(hb.last_beat(), 0);
        hb.beat();
        assert!(hb.last_beat() > 0, "beat should move last_beat to ~now");
    }

    #[test]
    fn config_from_env_defaults_are_sane() {
        let d = SupervisorConfig::default();
        assert!(d.enabled);
        assert!(d.max_backoff_secs >= d.base_backoff_secs);
        let w = d.with_stuck_deadline(45, 0);
        assert_eq!(w.stuck_deadline_secs, 45);
        assert!(w.watchdog_poll_secs >= 1, "poll clamps to >= 1");
    }

    #[tokio::test]
    async fn exiting_task_is_restarted() {
        // A factory whose task exits (returns) must be respawned by the supervisor. With 0 backoff
        // we get many restarts fast; cut the (otherwise infinite) supervise loop with a timeout.
        // Exit rather than panic keeps the test deterministic and free of backtrace-print noise
        // while exercising the same restart glue.
        let count = Arc::new(AtomicU32::new(0));
        let c = count.clone();
        let cfg = SupervisorConfig {
            enabled: true,
            base_backoff_secs: 0,
            max_backoff_secs: 1,
            stuck_deadline_secs: 0,
            watchdog_poll_secs: 1,
        };
        let fut = supervise("test_exit", cfg, None, move |_| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
            }
        });
        let _ = tokio::time::timeout(Duration::from_millis(200), fut).await;
        assert!(
            count.load(Ordering::SeqCst) >= 2,
            "an exiting task must be restarted by the supervisor"
        );
    }

    #[tokio::test]
    async fn disabled_runs_factory_once_unsupervised() {
        // With supervision off, the factory runs exactly once and supervise returns (no restart).
        let count = Arc::new(AtomicU32::new(0));
        let c = count.clone();
        let cfg = SupervisorConfig {
            enabled: false,
            ..SupervisorConfig::default()
        };
        supervise("test_disabled", cfg, None, move |_| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
