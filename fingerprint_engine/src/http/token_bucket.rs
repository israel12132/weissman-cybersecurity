//! In-process token bucket (GCRA-style refill) used by login and API rate limiters.
//!
//! Redis-backed replicas use the same math via `rate_limit_redis` Lua so a single-node
//! process and a multi-replica fleet enforce the same burst + refill contract.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct TokenBucketConfig {
    /// Tokens added per second (e.g. 8/min → `8.0 / 60.0`).
    pub rate_per_sec: f64,
    /// Maximum tokens (burst). Must be ≥ 1.
    pub burst: u32,
}

impl TokenBucketConfig {
    #[must_use]
    pub fn per_minute(per_minute: u32, burst: u32) -> Self {
        Self {
            rate_per_sec: f64::from(per_minute.max(1)) / 60.0,
            burst: burst.max(1),
        }
    }

    #[must_use]
    pub fn per_second(per_sec: u32, burst: u32) -> Self {
        Self {
            rate_per_sec: f64::from(per_sec.max(1)),
            burst: burst.max(1),
        }
    }
}

#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    last: Instant,
    cfg: TokenBucketConfig,
}

impl TokenBucket {
    #[must_use]
    pub fn new(cfg: TokenBucketConfig) -> Self {
        Self {
            tokens: f64::from(cfg.burst),
            last: Instant::now(),
            cfg,
        }
    }

    #[must_use]
    pub fn config(&self) -> TokenBucketConfig {
        self.cfg
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.cfg.rate_per_sec)
                .min(f64::from(self.cfg.burst));
            self.last = now;
        }
    }

    #[must_use]
    pub fn available(&mut self, now: Instant) -> f64 {
        self.refill(now);
        self.tokens
    }

    /// Time until one token is available. At least 1s when empty so `Retry-After` is useful.
    #[must_use]
    pub fn retry_after(&mut self, now: Instant) -> Duration {
        self.refill(now);
        if self.tokens >= 1.0 {
            return Duration::from_secs(1);
        }
        let need = 1.0 - self.tokens;
        let secs = (need / self.cfg.rate_per_sec).ceil().max(1.0);
        Duration::from_secs(secs as u64)
    }

    pub fn try_consume(&mut self, now: Instant) -> Result<(), Duration> {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(self.retry_after(now))
        }
    }

    /// Tokens consumed from the burst (for status APIs).
    #[must_use]
    pub fn used(&mut self, now: Instant) -> u32 {
        let avail = self.available(now);
        (f64::from(self.cfg.burst) - avail).max(0.0).floor() as u32
    }
}

/// Outcome-aware pair of buckets: strict on failures, lighter on successes.
#[derive(Debug)]
pub struct OutcomeAwareGate {
    failure: TokenBucket,
    success: TokenBucket,
    in_flight: u32,
    max_in_flight: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Wrong password / unknown user (HTTP 401).
    Failure,
    /// Authenticated or password-accepted MFA/policy challenge (HTTP 200/403).
    Success,
    /// Server error, validation, or account lockout response — do not charge either bucket.
    Neutral,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitDecision {
    Allow,
    DenyFailures { retry_after_secs: u64 },
    DenySuccesses { retry_after_secs: u64 },
    DenyInFlight { retry_after_secs: u64 },
}

impl AdmitDecision {
    #[must_use]
    pub fn allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    #[must_use]
    pub fn retry_after_secs(self) -> u64 {
        match self {
            Self::Allow => 0,
            Self::DenyFailures { retry_after_secs }
            | Self::DenySuccesses { retry_after_secs }
            | Self::DenyInFlight { retry_after_secs } => retry_after_secs,
        }
    }
}

impl OutcomeAwareGate {
    #[must_use]
    pub fn new(failure: TokenBucketConfig, success: TokenBucketConfig) -> Self {
        let max_in_flight = success.burst.max(failure.burst).max(1);
        Self {
            failure: TokenBucket::new(failure),
            success: TokenBucket::new(success),
            in_flight: 0,
            max_in_flight,
        }
    }

    /// Peek both buckets and the in-flight cap. Does not consume tokens (outcome is unknown).
    pub fn admit(&mut self, now: Instant) -> AdmitDecision {
        if self.in_flight >= self.max_in_flight {
            return AdmitDecision::DenyInFlight {
                retry_after_secs: 1,
            };
        }
        if self.failure.available(now) < 1.0 {
            return AdmitDecision::DenyFailures {
                retry_after_secs: self.failure.retry_after(now).as_secs().max(1),
            };
        }
        if self.success.available(now) < 1.0 {
            return AdmitDecision::DenySuccesses {
                retry_after_secs: self.success.retry_after(now).as_secs().max(1),
            };
        }
        self.in_flight = self.in_flight.saturating_add(1);
        AdmitDecision::Allow
    }

    pub fn record(&mut self, now: Instant, outcome: AuthOutcome) {
        self.in_flight = self.in_flight.saturating_sub(1);
        match outcome {
            AuthOutcome::Failure => {
                let _ = self.failure.try_consume(now);
            }
            AuthOutcome::Success => {
                let _ = self.success.try_consume(now);
            }
            AuthOutcome::Neutral => {}
        }
    }

    #[must_use]
    pub fn failure_used(&mut self, now: Instant) -> u32 {
        self.failure.used(now)
    }

    #[must_use]
    pub fn success_used(&mut self, now: Instant) -> u32 {
        self.success.used(now)
    }
}

#[must_use]
pub fn classify_auth_status(status: axum::http::StatusCode) -> AuthOutcome {
    match status.as_u16() {
        401 => AuthOutcome::Failure,
        200 | 403 => AuthOutcome::Success,
        _ => AuthOutcome::Neutral,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn documented_api_budget_allows_burst_then_429() {
        let mut b = TokenBucket::new(TokenBucketConfig::per_second(30, 60));
        let now = t0();
        for i in 0..60 {
            assert!(
                b.try_consume(now).is_ok(),
                "documented API burst token {i} must pass"
            );
        }
        let err = b.try_consume(now).expect_err("61st poll in the same instant");
        assert!(err.as_secs() >= 1);
    }

    #[test]
    fn api_bucket_refills_at_documented_rate() {
        let mut b = TokenBucket::new(TokenBucketConfig::per_second(30, 60));
        let now = t0();
        for _ in 0..60 {
            b.try_consume(now).unwrap();
        }
        let later = now + Duration::from_secs(1);
        // 30 tokens/sec refill, still capped at burst 60 — one second yields 30.
        let mut ok = 0;
        for _ in 0..40 {
            if b.try_consume(later).is_ok() {
                ok += 1;
            }
        }
        assert_eq!(ok, 30);
    }

    #[test]
    fn serial_failures_lock_at_failure_burst() {
        let mut g = OutcomeAwareGate::new(
            TokenBucketConfig::per_minute(8, 12),
            TokenBucketConfig::per_minute(40, 48),
        );
        let now = t0();
        for i in 0..12 {
            assert!(g.admit(now).allowed(), "failure {i} must be admitted");
            g.record(now, AuthOutcome::Failure);
        }
        let denied = g.admit(now);
        assert!(!denied.allowed());
        assert!(denied.retry_after_secs() >= 1);
        assert!(matches!(denied, AdmitDecision::DenyFailures { .. }));
    }

    #[test]
    fn successful_logins_from_same_ip_do_not_hit_failure_budget() {
        let mut g = OutcomeAwareGate::new(
            TokenBucketConfig::per_minute(8, 12),
            TokenBucketConfig::per_minute(40, 48),
        );
        let now = t0();
        // More successes than the failure burst — the bug this change fixes.
        for i in 0..20 {
            assert!(
                g.admit(now).allowed(),
                "success {i} from a shared IP must pass"
            );
            g.record(now, AuthOutcome::Success);
        }
        assert!(
            g.failure.available(now) >= 11.0,
            "successes must not spend failure tokens"
        );
        // A subsequent password failure is still admitted (failure burst intact).
        assert!(g.admit(now).allowed());
        g.record(now, AuthOutcome::Failure);
    }

    #[test]
    fn success_budget_is_bounded_not_unlimited() {
        let mut g = OutcomeAwareGate::new(
            TokenBucketConfig::per_minute(8, 12),
            TokenBucketConfig::per_minute(40, 48),
        );
        let now = t0();
        for _ in 0..48 {
            assert!(g.admit(now).allowed());
            g.record(now, AuthOutcome::Success);
        }
        let denied = g.admit(now);
        assert!(!denied.allowed());
        assert!(matches!(denied, AdmitDecision::DenySuccesses { .. }));
        assert!(denied.retry_after_secs() >= 1);
    }

    #[test]
    fn classify_does_not_treat_lockout_or_5xx_as_password_failure() {
        assert_eq!(
            classify_auth_status(axum::http::StatusCode::UNAUTHORIZED),
            AuthOutcome::Failure
        );
        assert_eq!(
            classify_auth_status(axum::http::StatusCode::OK),
            AuthOutcome::Success
        );
        assert_eq!(
            classify_auth_status(axum::http::StatusCode::FORBIDDEN),
            AuthOutcome::Success
        );
        assert_eq!(
            classify_auth_status(axum::http::StatusCode::TOO_MANY_REQUESTS),
            AuthOutcome::Neutral
        );
        assert_eq!(
            classify_auth_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
            AuthOutcome::Neutral
        );
    }

    #[test]
    fn retry_after_never_zero_when_empty() {
        let mut b = TokenBucket::new(TokenBucketConfig::per_minute(8, 12));
        let now = t0();
        for _ in 0..12 {
            b.try_consume(now).unwrap();
        }
        assert!(b.retry_after(now).as_secs() >= 1);
    }
}
