//! Hack-Fix-Verify — live closed loop that NodeZero / Strix cannot skip.
//!
//! Analysts and SOAR playbooks may mark a finding *remediated* (`FIXED`).
//! That mark does **not** drop FAIR ALE and does **not** become
//! `VERIFIED_FIXED`. The only path to verified-closed is a later *successful*
//! live engine scan of the same tenant/client/engine/target that does **not**
//! reproduce the finding id / corroboration key.
//!
//! A failed, timed-out, or errored scan that returns zero findings must not
//! close anything (the classic false-close that BAS and some pentest products
//! allow). If the same key reappears after a mark, the row is `REOPENED`.

use serde_json::{json, Value};

/// Kernel capability flag consumed by the moat fusion predicate.
pub const LIVE: bool = true;

pub const STATUS_OPEN: &str = "OPEN";
pub const STATUS_FIXED: &str = "FIXED";
pub const STATUS_RESCAN_PENDING: &str = "RESCAN_PENDING";
pub const STATUS_REMEDIATION_MARKED: &str = "REMEDIATION_MARKED";
pub const STATUS_VERIFIED_FIXED: &str = "VERIFIED_FIXED";
pub const STATUS_REOPENED: &str = "REOPENED";
pub const STATUS_FALSE_POSITIVE: &str = "FALSE_POSITIVE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Open,
    RemediationMarked,
    ReScanPending,
    VerifiedClosed,
    Reopened,
    FalsePositive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Apply(&'static str),
    Hold { reason: &'static str },
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Open => STATUS_OPEN,
            Phase::RemediationMarked | Phase::ReScanPending => STATUS_FIXED,
            Phase::VerifiedClosed => STATUS_VERIFIED_FIXED,
            Phase::Reopened => STATUS_REOPENED,
            Phase::FalsePositive => STATUS_FALSE_POSITIVE,
        }
    }
}

pub fn phase_of(status: &str) -> Phase {
    match status.trim().to_ascii_uppercase().as_str() {
        STATUS_VERIFIED_FIXED => Phase::VerifiedClosed,
        STATUS_REOPENED => Phase::Reopened,
        STATUS_FALSE_POSITIVE => Phase::FalsePositive,
        STATUS_RESCAN_PENDING | STATUS_REMEDIATION_MARKED | STATUS_FIXED => {
            Phase::RemediationMarked
        }
        _ => Phase::Open,
    }
}

/// Statuses that mean "analyst/SOAR claimed a fix; waiting for a live absence scan".
pub fn is_remediation_marked(status: &str) -> bool {
    matches!(
        phase_of(status),
        Phase::RemediationMarked | Phase::ReScanPending
    )
}

/// FAIR / exposure queries must keep pricing until *verified* closed.
/// `FIXED` is a claim, not proof — that is the board-level closer vs NodeZero/Strix.
pub fn fair_still_open_risk(status: &str) -> bool {
    match phase_of(status) {
        Phase::VerifiedClosed | Phase::FalsePositive => false,
        _ => true,
    }
}

/// SQL `NOT IN (...)` list for live risk joins. Keep in lockstep with
/// [`fair_still_open_risk`].
pub const FAIR_CLOSED_STATUSES_SQL: &str = "('VERIFIED_FIXED','FALSE_POSITIVE')";

/// Playbooks and PATCH /status cannot mint verified-closed. Map it back to a
/// claim so the next successful absence scan is still required.
pub fn coerce_operator_status(requested: &str) -> String {
    let u = requested.trim().to_ascii_uppercase();
    if u == STATUS_VERIFIED_FIXED {
        return STATUS_FIXED.to_string();
    }
    u
}

/// After a finding is upserted again, reopen any remediation/verified claim.
pub fn on_reappearance(current_status: &str) -> Transition {
    match phase_of(current_status) {
        Phase::RemediationMarked | Phase::ReScanPending | Phase::VerifiedClosed => {
            Transition::Apply(STATUS_REOPENED)
        }
        _ => Transition::Hold {
            reason: "not_a_remediation_claim",
        },
    }
}

/// Close only when the scan *succeeded*, the host was proven live, and the key
/// is absent, and only if the row was already marked remediated. OPEN findings
/// that a flaky engine missed stay OPEN (חוק 2 — do not empty the inbox).
/// An `ok` scan against a dead/firewalled host must not mint `VERIFIED_FIXED`.
pub fn on_successful_absence(scan_ok: bool, host_live: bool, current_status: &str) -> Transition {
    if !scan_ok {
        return Transition::Hold {
            reason: "scan_did_not_succeed",
        };
    }
    if !host_live {
        return Transition::Hold {
            reason: "host_liveness_unproven",
        };
    }
    if is_remediation_marked(current_status) {
        return Transition::Apply(STATUS_VERIFIED_FIXED);
    }
    Transition::Hold {
        reason: "not_marked_fixed",
    }
}

/// Combined rescan decision used by `remediation_verify` and persist.
/// `still_present` is itself liveness (the engine reproduced the finding).
pub fn after_rescan(
    scan_ok: bool,
    still_present: bool,
    host_live: bool,
    current_status: &str,
) -> Transition {
    if !scan_ok {
        return Transition::Hold {
            reason: "scan_did_not_succeed",
        };
    }
    if still_present {
        return on_reappearance(current_status);
    }
    on_successful_absence(true, host_live, current_status)
}

pub fn engine_scan_ok(status: &str, success_flag: bool) -> bool {
    success_flag && status.trim().eq_ignore_ascii_case("ok")
}

pub fn snapshot() -> Value {
    json!({
        "live": LIVE,
        "beats": "Horizon3 NodeZero + Strix: operator/PR 'fixed' is not verified-closed; FAIR ALE stays priced until a later successful live scan of a proven-live host does not reproduce the key. Failed/empty error scans and offline hosts cannot close.",
        "phases": [
            "OPEN",
            "FIXED (claim only — still priced in FAIR)",
            "REOPENED (key reproduced after claim or verified-close)",
            "VERIFIED_FIXED (successful absence scan + active host liveness proof)"
        ],
        "rules": {
            "analyst_cannot_set_verified_fixed": true,
            "soar_cannot_set_verified_fixed": true,
            "failed_scan_cannot_close": true,
            "open_absence_does_not_auto_close": true,
            "fair_prices_fixed_until_verified": true,
            "host_liveness_required_to_close": true,
        },
        "fair_closed_sql": FAIR_CLOSED_STATUSES_SQL,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_cannot_mint_verified_closed() {
        assert_eq!(coerce_operator_status("VERIFIED_FIXED"), STATUS_FIXED);
        assert_eq!(coerce_operator_status("fixed"), STATUS_FIXED);
        assert_eq!(coerce_operator_status("OPEN"), STATUS_OPEN);
    }

    #[test]
    fn failed_scan_never_closes() {
        assert_eq!(
            after_rescan(false, false, true, STATUS_FIXED),
            Transition::Hold {
                reason: "scan_did_not_succeed"
            }
        );
        assert_eq!(
            after_rescan(false, true, true, STATUS_FIXED),
            Transition::Hold {
                reason: "scan_did_not_succeed"
            }
        );
    }

    #[test]
    fn offline_host_never_closes_even_on_ok_empty_scan() {
        assert_eq!(
            after_rescan(true, false, false, STATUS_FIXED),
            Transition::Hold {
                reason: "host_liveness_unproven"
            }
        );
    }

    #[test]
    fn successful_absence_closes_only_marked_rows() {
        assert_eq!(
            after_rescan(true, false, true, STATUS_FIXED),
            Transition::Apply(STATUS_VERIFIED_FIXED)
        );
        assert_eq!(
            after_rescan(true, false, true, STATUS_RESCAN_PENDING),
            Transition::Apply(STATUS_VERIFIED_FIXED)
        );
        assert_eq!(
            after_rescan(true, false, true, STATUS_OPEN),
            Transition::Hold {
                reason: "not_marked_fixed"
            }
        );
    }

    #[test]
    fn reproduced_key_reopens_claim_and_verified() {
        assert_eq!(
            after_rescan(true, true, false, STATUS_FIXED),
            Transition::Apply(STATUS_REOPENED)
        );
        assert_eq!(
            after_rescan(true, true, true, STATUS_VERIFIED_FIXED),
            Transition::Apply(STATUS_REOPENED)
        );
        assert_eq!(
            after_rescan(true, true, true, STATUS_OPEN),
            Transition::Hold {
                reason: "not_a_remediation_claim"
            }
        );
        assert_eq!(
            after_rescan(true, true, true, STATUS_FALSE_POSITIVE),
            Transition::Hold {
                reason: "not_a_remediation_claim"
            }
        );
    }

    #[test]
    fn fair_keeps_pricing_fixed_claims() {
        assert!(fair_still_open_risk(STATUS_FIXED));
        assert!(fair_still_open_risk(STATUS_OPEN));
        assert!(fair_still_open_risk(STATUS_REOPENED));
        assert!(fair_still_open_risk(STATUS_ACK_PROXY));
        assert!(!fair_still_open_risk(STATUS_VERIFIED_FIXED));
        assert!(!fair_still_open_risk(STATUS_FALSE_POSITIVE));
    }

    const STATUS_ACK_PROXY: &str = "ACKNOWLEDGED";

    #[test]
    fn engine_ok_requires_both_flags() {
        assert!(engine_scan_ok("ok", true));
        assert!(!engine_scan_ok("ok", false));
        assert!(!engine_scan_ok("error", true));
        assert!(!engine_scan_ok("timeout", true));
    }

    #[test]
    fn snapshot_is_live() {
        let s = snapshot();
        assert_eq!(s["live"], true);
        assert_eq!(s["rules"]["failed_scan_cannot_close"], true);
        assert_eq!(s["rules"]["fair_prices_fixed_until_verified"], true);
        assert_eq!(s["rules"]["host_liveness_required_to_close"], true);
    }
}
