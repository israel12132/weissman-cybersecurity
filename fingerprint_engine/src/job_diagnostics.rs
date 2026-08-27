//! Why a queue row is not moving. Shared by `/api/jobs` list + diagnostics.

use chrono::{DateTime, Utc};
use serde_json::Value;

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
            None
        }
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
        assert!(job_stuck_reason("completed", &json!({}), Some(Utc::now()), None, 1, 3, Some("w")).is_none());
    }
}
