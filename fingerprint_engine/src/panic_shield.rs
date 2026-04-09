//! Catches unwinds from async scan/orchestrator work so panics in engines never take down the Axum runtime task tree unexpectedly.
//! Tokio already isolates per-task panics; this adds structured logging with real panic messages + backtraces, metrics,
//! and a per-label panic-rate circuit breaker (sliding window).

use dashmap::DashMap;
use futures::FutureExt;
use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Outcome of running a future that might panic during polling.
pub enum CatchOutcome<T> {
    Completed(T),
    /// Panic was caught; `message` is the best-effort payload (`&'static str` / `String`); `backtrace` is captured at catch site.
    Panicked {
        message: String,
        backtrace: String,
    },
    /// Panic rate for this `label` exceeded the threshold; future was not run (cooldown).
    CircuitOpen {
        cooldown_remaining_secs: u64,
    },
}

fn panic_window_secs() -> u64 {
    std::env::var("WEISSMAN_PANIC_CIRCUIT_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60)
        .max(1)
}

fn panic_threshold() -> u32 {
    std::env::var("WEISSMAN_PANIC_CIRCUIT_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
        .max(1)
}

fn panic_cooldown_secs() -> u64 {
    std::env::var("WEISSMAN_PANIC_CIRCUIT_COOLDOWN_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
        .max(5)
}

struct BreakerState {
    /// Panic timestamps within the sliding window.
    recent: VecDeque<Instant>,
    /// When set and `Instant::now() < tripped_until`, skip executing the wrapped future.
    tripped_until: Option<Instant>,
}

impl Default for BreakerState {
    fn default() -> Self {
        Self {
            recent: VecDeque::new(),
            tripped_until: None,
        }
    }
}

fn breakers() -> &'static DashMap<&'static str, Mutex<BreakerState>> {
    static M: OnceLock<DashMap<&'static str, Mutex<BreakerState>>> = OnceLock::new();
    M.get_or_init(DashMap::new)
}

/// True if this label is in cooldown after excessive panics (callers may skip work early).
#[must_use]
pub fn circuit_is_open(label: &'static str) -> bool {
    let Some(cell) = breakers().get(label) else {
        return false;
    };
    let Ok(g) = cell.value().lock() else {
        return false;
    };
    g.tripped_until
        .is_some_and(|until| Instant::now() < until)
}

fn cooldown_remaining(label: &'static str) -> u64 {
    let Some(cell) = breakers().get(label) else {
        return 0;
    };
    let Ok(g) = cell.value().lock() else {
        return 0;
    };
    let Some(until) = g.tripped_until else {
        return 0;
    };
    let now = Instant::now();
    if now >= until {
        return 0;
    }
    until.saturating_duration_since(now).as_secs().max(1)
}

/// On each panic: record timestamp, trip circuit if rate exceeds threshold in the window.
fn record_panic_event(label: &'static str) {
    let window = Duration::from_secs(panic_window_secs());
    let threshold = panic_threshold() as usize;
    let cooldown = Duration::from_secs(panic_cooldown_secs());
    let map = breakers();
    let cell = map
        .entry(label)
        .or_insert_with(|| Mutex::new(BreakerState::default()));
    let Ok(mut st) = cell.lock() else {
        return;
    };
    let now = Instant::now();
    st.recent.retain(|t| now.saturating_duration_since(*t) < window);
    st.recent.push_back(now);
    if st.recent.len() >= threshold {
        st.tripped_until = Some(now + cooldown);
        st.recent.clear();
        metrics::counter!("weissman_panic_circuit_open_total", "area" => label).increment(1);
        tracing::error!(
            target: "panic_shield",
            area = label,
            threshold,
            window_secs = panic_window_secs(),
            cooldown_secs = panic_cooldown_secs(),
            "CRITICAL: panic circuit breaker OPEN — too many panics in window; execution for this label paused until cooldown"
        );
    }
}

/// Extract human-readable panic message from `catch_unwind` payload.
fn format_panic_payload(p: Box<dyn std::any::Any + Send>) -> String {
    match p.downcast::<String>() {
        Ok(s) => *s,
        Err(p) => match p.downcast::<&'static str>() {
            Ok(s) => (*s).to_string(),
            Err(_) => "panic payload is not &str or String (opaque type)".to_string(),
        },
    }
}

/// Runs `f` and converts a panic while polling into [`CatchOutcome::Panicked`] with metrics, message, and backtrace.
/// If the per-label circuit is open, returns [`CatchOutcome::CircuitOpen`] without polling `f`.
pub async fn catch_unwind_future<F, T>(label: &'static str, f: F) -> CatchOutcome<T>
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    if circuit_is_open(label) {
        let secs = cooldown_remaining(label);
        metrics::counter!("weissman_panic_circuit_skip_total", "area" => label).increment(1);
        tracing::warn!(
            target: "panic_shield",
            area = label,
            cooldown_remaining_secs = secs,
            "skipping future: panic circuit breaker is open"
        );
        return CatchOutcome::CircuitOpen {
            cooldown_remaining_secs: secs,
        };
    }

    match AssertUnwindSafe(f).catch_unwind().await {
        Ok(v) => CatchOutcome::Completed(v),
        Err(p) => {
            metrics::counter!("weissman_async_task_panic_total", "area" => label).increment(1);
            let message = format_panic_payload(p);
            let backtrace = std::backtrace::Backtrace::capture();
            let bt_fmt = format!("{backtrace}");
            record_panic_event(label);
            tracing::error!(
                target: "panic_shield",
                area = label,
                %message,
                backtrace = %bt_fmt,
                "async task panicked during poll"
            );
            CatchOutcome::Panicked {
                message,
                backtrace: bt_fmt,
            }
        }
    }
}
