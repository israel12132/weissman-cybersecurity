//! CloudTrail-quiet IAM collection.
//!
//! Default: skip per-user `ListUsers` / `GetLoginProfile` / `ListAccessKeys` enumeration
//! (those APIs fan out into noisy CloudTrail events that wake SOC detections).
//! Keep account-level `GetAccountSummary` / `GetAccountPasswordPolicy` and optionally
//! IAM Access Analyzer findings.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IamMode {
    Quiet,
    Enumerate,
}

impl IamMode {
    pub fn from_intensity_and_flag(quiet_flag: Option<bool>, aggressive: bool) -> Self {
        match quiet_flag {
            Some(true) => IamMode::Quiet,
            Some(false) => IamMode::Enumerate,
            None if aggressive => IamMode::Enumerate,
            None => IamMode::Quiet,
        }
    }

    pub fn allow_list_users(self) -> bool {
        matches!(self, IamMode::Enumerate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_quiet() {
        assert_eq!(
            IamMode::from_intensity_and_flag(None, false),
            IamMode::Quiet
        );
        assert!(!IamMode::Quiet.allow_list_users());
    }

    #[test]
    fn aggressive_may_enumerate() {
        assert_eq!(
            IamMode::from_intensity_and_flag(None, true),
            IamMode::Enumerate
        );
    }
}
