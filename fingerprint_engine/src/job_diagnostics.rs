//! Why a queue row is not moving. Shared by `/api/jobs` list + diagnostics.

use chrono::{DateTime, Utc};
use serde_json::Value;
use weissman_job_bus::{stuck_reason_from_error, PROGRESS_STALL_SECS};

/// Extra liveness columns for the live `stuck_reason` overlay.
#[derive(Debug, Clone, Default)]
pub struct JobLiveness<'a> {
    pub persisted_stuck: Option<&'a str>,
    pub last_error: Option<&'a str>,
    pub progress_at: Option<DateTime<Utc>>,
    pub heartbeat_at: Option<DateTime<Utc>>,
}

/// Human-readable stuck reason for a live job row, or `None` if it looks healthy.
#[must_use]
pub fn job_stuck_reason(
    status: &str,
    payload: &Value,
    created_at: Option<DateTime<Utc>>,
    run_after: Option<DateTime<Utc>>,
    attempt_count: i32,
    max_attempts: i32,
    worker_id: Option<&str>,
) -> Option<String> {
    job_stuck_reason_live(
        status,
        payload,
        created_at,
        run_after,
        attempt_count,
        max_attempts,
        worker_id,
        JobLiveness::default(),
    )
}

/// Live overlay: persisted Force-Abort class, last_error parse, 60s progress stall.
#[must_use]
pub fn job_stuck_reason_live(
    status: &str,
    payload: &Value,
    created_at: Option<DateTime<Utc>>,
    run_after: Option<DateTime<Utc>>,
    attempt_count: i32,
    max_attempts: i32,
    worker_id: Option<&str>,
    live: JobLiveness<'_>,
) -> Option<String> {
    if let Some(s) = live
        .persisted_stuck
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(s.to_string());
    }
    if let Some(err) = live.last_error {
        if let Some(r) = stuck_reason_from_error(err) {
            return Some(r.as_str().to_string());
        }
    }
    let age = created_at
        .map(|t| (Utc::now() - t).num_seconds())
        .unwrap_or(0);
    let has_envelope = payload.get("_weissman_job_bus").is_some();
    match status {
        "pending" | "queued" => {
            if let Some(ra) = run_after {
                if ra > Utc::now() {
                    return Some("held_until_run_after".into());
                }
            }
            if !has_envelope && age > 15 {
                return Some("missing_envelope".into());
            }
            if attempt_count >= max_attempts {
                return Some("attempts_exhausted".into());
            }
            if age > 30 {
                return Some("waiting_for_worker".into());
            }
            None
        }
        "running" => {
            if worker_id.is_none() && age > 60 {
                return Some("running_without_worker".into());
            }
            if let Some(pa) = live.progress_at {
                let stale = (Utc::now() - pa).num_seconds();
                if stale >= PROGRESS_STALL_SECS as i64 {
                    return Some("no_progress_60s".into());
                }
            }
            if let Some(hb) = live.heartbeat_at {
                let stale = (Utc::now() - hb).num_seconds();
                if stale >= 45 {
                    return Some("lease_heartbeat_timeout".into());
                }
            }
            None
        }
        "failed" | "dead" => live
            .last_error
            .and_then(stuck_reason_from_error)
            .map(|r| r.as_str().to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_less_pending_is_stuck() {
        let created = Utc::now() - chrono::Duration::seconds(45);
        let reason = job_stuck_reason(
            "pending",
            &json!({"engine": "asm"}),
            Some(created),
            None,
            0,
            3,
            None,
        );
        assert_eq!(reason.as_deref(), Some("missing_envelope"));
    }

    #[test]
    fn held_job_is_not_missing_envelope() {
        let created = Utc::now() - chrono::Duration::seconds(5);
        let future = Utc::now() + chrono::Duration::seconds(20);
        let reason = job_stuck_reason(
            "pending",
            &json!({}),
            Some(created),
            Some(future),
            0,
            3,
            None,
        );
        assert_eq!(reason.as_deref(), Some("held_until_run_after"));
    }

    #[test]
    fn signed_pending_waits_for_worker() {
        let created = Utc::now() - chrono::Duration::seconds(45);
        let reason = job_stuck_reason(
            "pending",
            &json!({"_weissman_job_bus": {"envelope": {}}}),
            Some(created),
            None,
            0,
            3,
            None,
        );
        assert_eq!(reason.as_deref(), Some("waiting_for_worker"));
    }

    #[test]
    fn completed_is_never_stuck() {
        assert!(job_stuck_reason(
            "completed",
            &json!({}),
            Some(Utc::now()),
            None,
            1,
            3,
            Some("w")
        )
        .is_none());
    }

    #[test]
    fn persisted_force_abort_wins() {
        let reason = job_stuck_reason_live(
            "failed",
            &json!({}),
            Some(Utc::now()),
            None,
            1,
            3,
            Some("w"),
            JobLiveness {
                persisted_stuck: Some("no_progress_60s"),
                last_error: Some("other"),
                progress_at: None,
                heartbeat_at: None,
            },
        );
        assert_eq!(reason.as_deref(), Some("no_progress_60s"));
    }

    #[test]
    fn running_stale_progress_is_no_progress_60s() {
        let stale = Utc::now() - chrono::Duration::seconds(90);
        let reason = job_stuck_reason_live(
            "running",
            &json!({"_weissman_job_bus": {"envelope": {}}}),
            Some(Utc::now()),
            None,
            1,
            5,
            Some("w"),
            JobLiveness {
                persisted_stuck: None,
                last_error: None,
                progress_at: Some(stale),
                heartbeat_at: Some(Utc::now()),
            },
        );
        assert_eq!(reason.as_deref(), Some("no_progress_60s"));
    }
}
