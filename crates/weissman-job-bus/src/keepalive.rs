//! Keep-alive heartbeat + progress watchdog for claimed jobs.
//!
//! A long `tenant_full_scan` or fuzz job that never extends its Redis lease wedges the
//! only worker (`lease extend failed`) and starves SOAR / every other tenant. Two clocks:
//!
//! 1. **Lease keep-alive** — extend the Redis/PG lease every [`LEASE_HEARTBEAT_INTERVAL_SECS`]
//!    (default 10s) on a task *beside* the actual work.
//! 2. **Physical progress** — if the job reports no progress for
//!    [`PROGRESS_STALL_SECS`] (default 60s), **Force Abort**, return the lease, mark `failed`
//!    with a precise `stuck_reason`.
//!
//! This is not "just increase TTL". The lock window stays short; liveness is proven by
//! heartbeats, and a hung engine cannot Self-DoS the fleet.

use std::time::Duration;

/// Default Redis/PG lease extend interval (seconds). Spec: 10s.
pub const LEASE_HEARTBEAT_INTERVAL_SECS: u64 = 10;

/// Default no-physical-progress abort (seconds). Spec: 60s.
pub const PROGRESS_STALL_SECS: u64 = 60;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// How often the keep-alive thread extends the lease. Override:
/// `WEISSMAN_JOB_LEASE_HEARTBEAT_SECS` (clamped 1..=30, default 10).
#[must_use]
pub fn heartbeat_interval() -> Duration {
    Duration::from_secs(
        env_u64(
            "WEISSMAN_JOB_LEASE_HEARTBEAT_SECS",
            LEASE_HEARTBEAT_INTERVAL_SECS,
        )
        .clamp(1, 30),
    )
}

/// No-progress abort deadline. Override: `WEISSMAN_JOB_PROGRESS_STALL_SECS`
/// (clamped 1..=600, default 60). Tests may lower this; production stays at 60.
#[must_use]
pub fn progress_stall() -> Duration {
    Duration::from_secs(
        env_u64("WEISSMAN_JOB_PROGRESS_STALL_SECS", PROGRESS_STALL_SECS).clamp(1, 600),
    )
}

/// Precise `stuck_reason` written onto a Force-Aborted job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StuckReason {
    /// Redis/PG lease extend failed — the keep-alive thread lost the lock.
    LeaseHeartbeatTimeout,
    /// No physical progress (engine/probe/chunk) for the stall window.
    NoProgress60s,
}

impl StuckReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LeaseHeartbeatTimeout => "lease_heartbeat_timeout",
            Self::NoProgress60s => "no_progress_60s",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "lease_heartbeat_timeout" => Some(Self::LeaseHeartbeatTimeout),
            "no_progress_60s" => Some(Self::NoProgress60s),
            _ => None,
        }
    }
}

impl std::fmt::Display for StuckReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Decision from one keep-alive tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepAliveDecision {
    /// Lease was extended; job continues.
    Extend,
    /// Force-abort: return the lease and mark the job failed.
    Abort { stuck_reason: StuckReason },
}

/// Pure scheduler: lease extend outcome + progress age → extend or Force Abort.
///
/// `lease_extend_ok` is false when Redis `EXPIRE`/`SET XX EX` is denied or PG heartbeat
/// fails. `progress_age_secs` is time since the last **physical** progress mark (not the
/// lease heartbeat itself).
#[must_use]
pub fn evaluate_keepalive(
    lease_extend_ok: bool,
    progress_age_secs: u64,
    stall_secs: u64,
) -> KeepAliveDecision {
    if !lease_extend_ok {
        return KeepAliveDecision::Abort {
            stuck_reason: StuckReason::LeaseHeartbeatTimeout,
        };
    }
    if stall_secs > 0 && progress_age_secs >= stall_secs {
        return KeepAliveDecision::Abort {
            stuck_reason: StuckReason::NoProgress60s,
        };
    }
    KeepAliveDecision::Extend
}

/// Format `last_error` so operators and `job_stuck_reason` can parse it.
#[must_use]
pub fn stuck_error_message(reason: StuckReason, detail: &str) -> String {
    let d = detail.trim();
    if d.is_empty() {
        format!("stuck_reason={}", reason.as_str())
    } else {
        format!("stuck_reason={}: {d}", reason.as_str())
    }
}

/// Pull `stuck_reason=` out of a `last_error` string (legacy rows without the column).
#[must_use]
pub fn stuck_reason_from_error(last_error: &str) -> Option<StuckReason> {
    let s = last_error.trim();
    let rest = s.strip_prefix("stuck_reason=")?;
    let token = rest.split([':', ' ', '\n']).next().unwrap_or(rest);
    StuckReason::parse(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_when_lease_ok_and_progress_fresh() {
        assert_eq!(evaluate_keepalive(true, 9, 60), KeepAliveDecision::Extend);
        assert_eq!(evaluate_keepalive(true, 59, 60), KeepAliveDecision::Extend);
    }

    #[test]
    fn abort_when_lease_extend_fails() {
        assert_eq!(
            evaluate_keepalive(false, 0, 60),
            KeepAliveDecision::Abort {
                stuck_reason: StuckReason::LeaseHeartbeatTimeout
            }
        );
    }

    #[test]
    fn abort_when_no_progress_for_stall_window() {
        assert_eq!(
            evaluate_keepalive(true, 60, 60),
            KeepAliveDecision::Abort {
                stuck_reason: StuckReason::NoProgress60s
            }
        );
        assert_eq!(
            evaluate_keepalive(true, 61, 60),
            KeepAliveDecision::Abort {
                stuck_reason: StuckReason::NoProgress60s
            }
        );
    }

    #[test]
    fn lease_failure_wins_over_progress_stall() {
        assert_eq!(
            evaluate_keepalive(false, 90, 60),
            KeepAliveDecision::Abort {
                stuck_reason: StuckReason::LeaseHeartbeatTimeout
            }
        );
    }

    #[test]
    fn stall_zero_disables_progress_abort() {
        assert_eq!(
            evaluate_keepalive(true, 10_000, 0),
            KeepAliveDecision::Extend
        );
    }

    #[test]
    fn stuck_reason_round_trip() {
        for r in [
            StuckReason::LeaseHeartbeatTimeout,
            StuckReason::NoProgress60s,
        ] {
            assert_eq!(StuckReason::parse(r.as_str()), Some(r));
            let msg = stuck_error_message(r, "last: http_feedback_fuzz");
            assert_eq!(stuck_reason_from_error(&msg), Some(r));
        }
        assert!(stuck_reason_from_error("database unavailable").is_none());
    }

    #[test]
    fn defaults_match_architect_spec() {
        assert_eq!(LEASE_HEARTBEAT_INTERVAL_SECS, 10);
        assert_eq!(PROGRESS_STALL_SECS, 60);
        assert_eq!(StuckReason::NoProgress60s.as_str(), "no_progress_60s");
        assert_eq!(
            StuckReason::LeaseHeartbeatTimeout.as_str(),
            "lease_heartbeat_timeout"
        );
    }
}
