//! Coverage table for the 500-check catalog.
//!
//! Default status is `NotObserved`. Live probes promote a check to Pass / Fail / Na
//! only when they collected evidence. Never invent a Pass.

use super::catalog::{self, Check, Domain, CHECK_COUNT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    Na,
    NotObserved,
}

impl CheckStatus {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Na => "na",
            Self::NotObserved => "not_observed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CheckResult {
    pub check: Check,
    pub status: CheckStatus,
    pub evidence: String,
}

pub struct Coverage {
    pub slots: Vec<CheckResult>,
}

impl Coverage {
    pub fn new() -> Self {
        Self {
            slots: catalog::all_checks()
                .into_iter()
                .map(|c| CheckResult {
                    check: c,
                    status: CheckStatus::NotObserved,
                    evidence: String::new(),
                })
                .collect(),
        }
    }

    pub fn get_mut(&mut self, id: u16) -> Option<&mut CheckResult> {
        let idx = id.checked_sub(1)? as usize;
        self.slots.get_mut(idx)
    }

    pub fn counts(&self) -> StatusCounts {
        let mut c = StatusCounts::default();
        for s in &self.slots {
            match s.status {
                CheckStatus::Pass => c.pass += 1,
                CheckStatus::Fail => c.fail += 1,
                CheckStatus::Na => c.na += 1,
                CheckStatus::NotObserved => c.not_observed += 1,
            }
        }
        c
    }

    pub fn domain_fail(&self, d: Domain) -> u32 {
        self.slots
            .iter()
            .filter(|s| s.check.domain == d && s.status == CheckStatus::Fail)
            .count() as u32
    }
}

impl Default for Coverage {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default)]
pub struct StatusCounts {
    pub pass: u32,
    pub fail: u32,
    pub na: u32,
    pub not_observed: u32,
}

/// Force listed checks to `status`, including overwriting Fail.
/// Used when the operator disables a domain — those rows stay `na`.
pub fn force(cov: &mut Coverage, ids: &[u16], status: CheckStatus, evidence: &str) {
    for id in ids {
        if *id == 0 || *id as usize > CHECK_COUNT {
            continue;
        }
        if let Some(slot) = cov.get_mut(*id) {
            slot.status = status;
            slot.evidence = evidence.to_string();
        }
    }
}

/// Promote listed checks. Fail always wins over Pass; Na/NotObserved yield to evidence.
pub fn apply(cov: &mut Coverage, ids: &[u16], status: CheckStatus, evidence: &str) {
    for id in ids {
        if *id == 0 || *id as usize > CHECK_COUNT {
            continue;
        }
        if let Some(slot) = cov.get_mut(*id) {
            let overwrite = match (slot.status, status) {
                (CheckStatus::Fail, _) => false,
                (_, CheckStatus::Fail) => true,
                (CheckStatus::Pass, CheckStatus::Na | CheckStatus::NotObserved) => false,
                (CheckStatus::NotObserved, _) => true,
                (CheckStatus::Na, CheckStatus::Pass) => true,
                (CheckStatus::Pass, CheckStatus::Pass) => true,
                _ => false,
            };
            if overwrite {
                slot.status = status;
                slot.evidence = evidence.to_string();
            } else if slot.status == CheckStatus::Fail && status == CheckStatus::Fail {
                if !slot.evidence.contains(evidence) {
                    slot.evidence.push_str(" | ");
                    slot.evidence.push_str(evidence);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_wins_over_pass() {
        let mut c = Coverage::new();
        apply(&mut c, &[12], CheckStatus::Pass, "ok");
        apply(&mut c, &[12], CheckStatus::Fail, "rwx");
        assert_eq!(c.get_mut(12).unwrap().status, CheckStatus::Fail);
        apply(&mut c, &[12], CheckStatus::Pass, "later");
        assert_eq!(c.slots[11].status, CheckStatus::Fail);
        force(&mut c, &[12], CheckStatus::Na, "domain disabled");
        assert_eq!(c.slots[11].status, CheckStatus::Na);
    }
}
