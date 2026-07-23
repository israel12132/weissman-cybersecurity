//! P0: Retry with exponential backoff + jitter and circuit breaker for external APIs.
//! Ensures one failing service never crashes the orchestrator; alerts via callback.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Full-jitter: sleep for a random duration in `[0, cap]` where `cap` is the exponential backoff.
/// This prevents thundering-herd on retry storms (see AWS Architecture Blog: "Exponential Backoff
/// And Jitter").
pub fn jittered_backoff_duration(base_ms: u64, attempt: u32, cap_ms: u64) -> Duration {
    let exp = base_ms
        .saturating_mul(2u64.saturating_pow(attempt))
        .min(cap_ms);
    // Use the low bits of a cheap wall-clock read as entropy — no crypto quality needed here.
    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u64;
    let jitter_ms = if exp == 0 { 0 } else { entropy % exp };
    Duration::from_millis(jitter_ms)
}

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
                // Exponential backoff with full jitter (base 500 ms, cap 30 s).
                let wait = jittered_backoff_duration(500, attempt, 30_000);
                sleep(wait).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_zero_base_or_cap_is_zero() {
        // exp = 0 -> jitter window is empty -> always zero
        assert_eq!(jittered_backoff_duration(0, 5, 1000), Duration::ZERO);
        assert_eq!(jittered_backoff_duration(500, 3, 0), Duration::ZERO);
    }

    #[test]
    fn backoff_stays_within_exponential_window() {
        // exp = 500 * 2^0 = 500, so full-jitter result is strictly < 500 ms
        for _ in 0..64 {
            let d = jittered_backoff_duration(500, 0, 30_000);
            assert!(d.as_millis() < 500, "got {:?}", d);
        }
        // exp = 500 * 2^3 = 4000
        for _ in 0..64 {
            let d = jittered_backoff_duration(500, 3, 30_000);
            assert!(d.as_millis() < 4000, "got {:?}", d);
        }
    }

    #[test]
    fn backoff_respects_cap() {
        // 1000 * 2^10 = 1_024_000 but capped to 2000 -> result < 2000 ms
        for _ in 0..64 {
            let d = jittered_backoff_duration(1000, 10, 2000);
            assert!(d.as_millis() < 2000, "got {:?}", d);
        }
    }

    #[test]
    fn circuit_starts_closed_and_allows() {
        let cb = CircuitBreaker::new(3, 3600);
        assert!(cb.state() == CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn circuit_opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(3, 3600);
        cb.record_failure();
        assert!(cb.state() == CircuitState::Closed); // still below threshold
        cb.record_failure();
        cb.record_failure();
        // failures >= threshold and cooldown not elapsed -> Open
        assert!(cb.state() == CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn circuit_success_resets_to_closed() {
        let cb = CircuitBreaker::new(1, 3600);
        cb.record_failure();
        assert!(cb.state() == CircuitState::Open);
        cb.record_success();
        assert!(cb.state() == CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn circuit_half_open_when_cooldown_elapsed() {
        // cooldown 0 -> now - last >= 0 is always true, so an over-threshold breaker
        // is immediately HalfOpen (probe allowed).
        let cb = CircuitBreaker::new(1, 0);
        cb.record_failure();
        assert!(cb.state() == CircuitState::HalfOpen);
        assert!(cb.allow_request());
    }

    #[test]
    fn resilience_registry_defaults_are_closed() {
        let reg = ResilienceRegistry::default();
        assert!(reg.llm.state() == CircuitState::Closed);
        assert!(reg.crt_sh.state() == CircuitState::Closed);
        assert!(reg.webhook.state() == CircuitState::Closed);
        assert!(reg.llm.allow_request());
    }
}
