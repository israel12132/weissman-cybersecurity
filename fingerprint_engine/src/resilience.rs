//! P0: Retry with exponential backoff and circuit breaker for external APIs.
//! Ensures one failing service never crashes the orchestrator; alerts via callback.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Circuit state: Closed = normal, Open = failing (reject fast), HalfOpen = probing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker: tracks failures and opens after threshold; allows probe after cooldown.
pub struct CircuitBreaker {
    failures: AtomicU64,
    last_failure_ts: AtomicU64,
    threshold: u64,
    cooldown_secs: u64,
}

impl CircuitBreaker {
    pub fn new(threshold: u64, cooldown_secs: u64) -> Self {
        Self {
            failures: AtomicU64::new(0),
            last_failure_ts: AtomicU64::new(0),
            threshold,
            cooldown_secs,
        }
    }

    pub fn state(&self) -> CircuitState {
        let f = self.failures.load(Ordering::SeqCst);
        if f < self.threshold {
            return CircuitState::Closed;
        }
        let last = self.last_failure_ts.load(Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(last) >= self.cooldown_secs {
            CircuitState::HalfOpen
        } else {
            CircuitState::Open
        }
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::SeqCst);
    }

    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_failure_ts.store(now, Ordering::SeqCst);
    }

    pub fn allow_request(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => false,
        }
    }
}

/// Run an async operation with retries (exponential backoff). On circuit open, returns Err immediately.
/// max_retries: 2 = initial + 2 retries (3 attempts total). Caller should broadcast Err message to UI.
pub async fn with_retry_circuit<T, F, Fut>(
    circuit: &Arc<CircuitBreaker>,
    _engine_id: &str,
    max_retries: u32,
    mut f: F,
) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    if !circuit.allow_request() {
        return Err("Circuit open; request skipped".to_string());
    }
    let mut backoff_ms = 500u64;
    for attempt in 0..=max_retries {
        match f().await {
            Ok(v) => {
                circuit.record_success();
                return Ok(v);
            }
            Err(e) => {
                circuit.record_failure();
                if attempt == max_retries {
                    return Err(format!("All retries failed: {}", e));
                }
                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(30_000);
            }
        }
    }
    Err("Retry exhausted".to_string())
}

/// Shared circuit breakers per service (LLM, crt.sh, etc.). Created once and passed to callers.
pub struct ResilienceRegistry {
    pub llm: Arc<CircuitBreaker>,
    pub crt_sh: Arc<CircuitBreaker>,
    pub webhook: Arc<CircuitBreaker>,
}

impl Default for ResilienceRegistry {
    fn default() -> Self {
        Self {
            llm: Arc::new(CircuitBreaker::new(5, 60)),
            crt_sh: Arc::new(CircuitBreaker::new(3, 30)),
            webhook: Arc::new(CircuitBreaker::new(3, 30)),
        }
    }
}
