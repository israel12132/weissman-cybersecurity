//! Auto-heal **governance policy** — decides, for a completed heal, the recommended disposition:
//! auto-merge, open for human review, hold, or block. Enterprises must not merge an app-breaking or
//! unverified fix, nor silently auto-merge a critical change; this encodes that judgment as an
//! auditable, per-tenant policy with a bilingual (he/en) rationale.
//!
//! [`evaluate_policy`] is a **pure function** (unit-tested); [`HealPolicy::load`] reads the tenant's
//! `system_configs` overrides and falls back to safe defaults. The decision is **advisory** — it is
//! surfaced on the report/JSON/SARIF so an operator (or a future automation) can act on it — it never
//! merges anything on its own.

use serde::Serialize;
use sqlx::PgPool;

/// Recommended disposition for a completed heal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Safe to merge automatically (verified, within the auto-merge risk envelope).
    AutoMerge,
    /// Deliver as a PR/MR but require a human to merge.
    OpenForReview,
    /// Do not deliver yet — the outcome is not a verified fix.
    Hold,
    /// Never deliver — the change is unsafe (e.g. it broke the app).
    Block,
}

impl Disposition {
    pub fn code(self) -> &'static str {
        match self {
            Disposition::AutoMerge => "auto_merge",
            Disposition::OpenForReview => "open_for_review",
            Disposition::Hold => "hold",
            Disposition::Block => "block",
        }
    }
}

/// The decision plus a bilingual rationale, ready to serialize onto the proof artifacts.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDecision {
    pub disposition: String,
    pub reason_en: String,
    pub reason_he: String,
}

fn decision(d: Disposition, en: &str, he: &str) -> PolicyDecision {
    PolicyDecision {
        disposition: d.code().to_string(),
        reason_en: en.to_string(),
        reason_he: he.to_string(),
    }
}

/// Per-tenant governance policy (safe defaults).
#[derive(Debug, Clone)]
pub struct HealPolicy {
    /// Highest severity eligible for auto-merge (rank: low < medium < high < critical).
    pub auto_merge_max_severity: String,
    /// Auto-merge requires a verified signed receipt.
    pub require_attestation_for_merge: bool,
    /// Auto-merge only if the winning patch was reached within this many attempts.
    pub max_attempts_for_merge: i64,
    /// If false (default), a `broke_app` verdict is blocked from delivery.
    pub allow_broke_app_delivery: bool,
}

impl Default for HealPolicy {
    fn default() -> Self {
        HealPolicy {
            auto_merge_max_severity: "low".to_string(),
            require_attestation_for_merge: true,
            max_attempts_for_merge: 3,
            allow_broke_app_delivery: false,
        }
    }
}

/// Severity rank; unknown severities rank 0 (never auto-merge-eligible on their own).
fn sev_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

impl HealPolicy {
    /// Load tenant overrides from `system_configs`, falling back to [`HealPolicy::default`].
    pub async fn load(pool: &PgPool, tenant_id: i64) -> Self {
        let mut p = HealPolicy::default();
        let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
            return p;
        };
        let keys: Vec<String> = vec![
            "heal_auto_merge_max_severity".to_string(),
            "heal_require_attestation_for_merge".to_string(),
            "heal_max_attempts_for_merge".to_string(),
            "heal_allow_broke_app_delivery".to_string(),
        ];
        if let Ok(rows) = sqlx::query(
            "SELECT key, COALESCE(value,'') AS value FROM system_configs WHERE tenant_id = $1 AND key = ANY($2)",
        )
        .bind(tenant_id)
        .bind(&keys)
        .fetch_all(&mut *tx)
        .await
        {
            use sqlx::Row;
            for r in rows {
                let k: String = r.try_get("key").unwrap_or_default();
                let v: String = r.try_get("value").unwrap_or_default();
                let vt = v.trim();
                if vt.is_empty() {
                    continue;
                }
                match k.as_str() {
                    "heal_auto_merge_max_severity" if sev_rank(vt) > 0 => {
                        p.auto_merge_max_severity = vt.to_ascii_lowercase();
                    }
                    "heal_require_attestation_for_merge" => {
                        p.require_attestation_for_merge = parse_bool(vt, p.require_attestation_for_merge);
                    }
                    "heal_max_attempts_for_merge" => {
                        if let Ok(n) = vt.parse::<i64>() {
                            if n >= 1 {
                                p.max_attempts_for_merge = n;
                            }
                        }
                    }
                    "heal_allow_broke_app_delivery" => {
                        p.allow_broke_app_delivery = parse_bool(vt, p.allow_broke_app_delivery);
                    }
                    _ => {}
                }
            }
        }
        let _ = tx.commit().await;
        p
    }

    /// Convenience: evaluate this policy against a heal outcome.
    pub fn decide(&self, verdict: &str, severity: &str, attested: bool, attempts: i64) -> PolicyDecision {
        evaluate_policy(self, verdict, severity, attested, attempts)
    }
}

fn parse_bool(v: &str, default: bool) -> bool {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

/// Pure policy evaluation over a completed heal's outcome.
pub fn evaluate_policy(
    p: &HealPolicy,
    verdict: &str,
    severity: &str,
    attested: bool,
    attempts: i64,
) -> PolicyDecision {
    let v = verdict.trim().to_ascii_lowercase();

    // An app-breaking fix is never delivered unless explicitly allowed.
    if v == "broke_app" && !p.allow_broke_app_delivery {
        return decision(
            Disposition::Block,
            "Blocked — the candidate fix broke the application in verification.",
            "נחסם — התיקון המועמד שבר את האפליקציה באימות.",
        );
    }
    // Anything that is not a verified fix is held (do not deliver an unproven change).
    if v != "fixed" {
        return decision(
            Disposition::Hold,
            "Held — the outcome is not a verified fix; no delivery is recommended.",
            "מוחזק — התוצאה אינה תיקון מאומת; לא מומלץ למסור.",
        );
    }

    // Verified fix: decide auto-merge eligibility against the risk envelope.
    let sev_ok = sev_rank(severity) > 0 && sev_rank(severity) <= sev_rank(&p.auto_merge_max_severity);
    let attest_ok = attested || !p.require_attestation_for_merge;
    let attempts_ok = attempts <= p.max_attempts_for_merge;

    if sev_ok && attest_ok && attempts_ok {
        return decision(
            Disposition::AutoMerge,
            "Auto-merge — verified fix within the configured auto-merge risk envelope.",
            "מיזוג אוטומטי — תיקון מאומת בתוך מעטפת הסיכון שהוגדרה למיזוג אוטומטי.",
        );
    }

    // Verified but outside the envelope → open for human review, with the specific reason.
    let (en, he) = if !sev_ok {
        (
            "Open for review — severity exceeds the auto-merge threshold; a human should merge.",
            "פתוח לסקירה — החומרה גבוהה מסף המיזוג האוטומטי; נדרש אישור אנושי למיזוג.",
        )
    } else if !attest_ok {
        (
            "Open for review — auto-merge requires a verified signed receipt, which is missing.",
            "פתוח לסקירה — מיזוג אוטומטי דורש קבלה חתומה ומאומתת, שחסרה.",
        )
    } else {
        (
            "Open for review — the fix needed more attempts than the auto-merge limit.",
            "פתוח לסקירה — התיקון דרש יותר ניסיונות מהמותר למיזוג אוטומטי.",
        )
    };
    decision(Disposition::OpenForReview, en, he)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict() -> HealPolicy {
        HealPolicy::default() // low / require attestation / <=3 attempts / block broke_app
    }

    #[test]
    fn broke_app_is_blocked_by_default() {
        let d = evaluate_policy(&strict(), "broke_app", "low", true, 1);
        assert_eq!(d.disposition, "block");
        assert!(!d.reason_he.is_empty());
    }

    #[test]
    fn broke_app_allowed_when_configured_is_not_blocked() {
        let mut p = strict();
        p.allow_broke_app_delivery = true;
        // Not fixed, so it holds rather than blocks.
        let d = evaluate_policy(&p, "broke_app", "low", true, 1);
        assert_eq!(d.disposition, "hold");
    }

    #[test]
    fn non_fixed_verdicts_hold() {
        for v in ["still_vulnerable", "inconclusive", "pending", ""] {
            assert_eq!(evaluate_policy(&strict(), v, "low", true, 1).disposition, "hold");
        }
    }

    #[test]
    fn low_verified_attested_auto_merges() {
        let d = evaluate_policy(&strict(), "fixed", "low", true, 1);
        assert_eq!(d.disposition, "auto_merge");
    }

    #[test]
    fn high_severity_opens_for_review() {
        let d = evaluate_policy(&strict(), "fixed", "high", true, 1);
        assert_eq!(d.disposition, "open_for_review");
        assert!(d.reason_en.contains("severity"));
    }

    #[test]
    fn missing_attestation_opens_for_review() {
        let d = evaluate_policy(&strict(), "fixed", "low", false, 1);
        assert_eq!(d.disposition, "open_for_review");
        assert!(d.reason_en.contains("receipt"));
    }

    #[test]
    fn too_many_attempts_opens_for_review() {
        let d = evaluate_policy(&strict(), "fixed", "low", true, 4);
        assert_eq!(d.disposition, "open_for_review");
        assert!(d.reason_en.contains("attempts"));
    }

    #[test]
    fn relaxed_policy_auto_merges_high_without_attestation() {
        let p = HealPolicy {
            auto_merge_max_severity: "critical".to_string(),
            require_attestation_for_merge: false,
            max_attempts_for_merge: 10,
            allow_broke_app_delivery: false,
        };
        assert_eq!(evaluate_policy(&p, "fixed", "high", false, 5).disposition, "auto_merge");
    }

    #[test]
    fn unknown_severity_never_auto_merges() {
        // severity rank 0 must not slip under the threshold.
        let d = evaluate_policy(&strict(), "fixed", "weird", true, 1);
        assert_eq!(d.disposition, "open_for_review");
    }
}
