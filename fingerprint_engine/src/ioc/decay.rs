//! Confidence decay + expiry math for indicators.
//!
//! Raw feed confidence is a *point-in-time* assertion. An IP flagged as a C2
//! today is far less likely to still be malicious in three weeks (hosts get
//! re-provisioned, domains get sinkholed, campaigns rotate), while a malware
//! file hash is malicious forever. We model this with an exponential decay
//! whose half-life depends on the indicator class:
//!
//! ```text
//! effective = base * 2^(-age_days / half_life_days)
//! ```
//!
//! When `effective` falls below [`RETIRE_CONFIDENCE`] the indicator is retired
//! (`active = false`) so matching stays cheap and precise.

use super::IocType;

/// Below this effective confidence an indicator is retired from active matching.
pub const RETIRE_CONFIDENCE: f64 = 8.0;

/// Per-class half-life (days). Network indicators age fast; file hashes do not.
#[must_use]
pub fn half_life_days(ioc_type: IocType) -> f64 {
    match ioc_type {
        IocType::Ipv4 | IocType::Ipv6 | IocType::Cidr => 14.0,
        IocType::Domain | IocType::Url => 30.0,
        IocType::Email => 45.0,
        IocType::Ja3 | IocType::Ja3s => 60.0,
        // Content hashes and host artefacts are effectively immutable truths.
        IocType::Sha256 | IocType::Sha1 | IocType::Md5 => 365.0,
        IocType::FilePath | IocType::Mutex | IocType::RegistryKey => 180.0,
    }
}

/// Default hard-expiry horizon (days from last_seen) per class — a backstop well
/// beyond the decay floor so even a high-base indicator is eventually dropped.
#[must_use]
pub fn default_ttl_days(ioc_type: IocType) -> i64 {
    match ioc_type {
        IocType::Ipv4 | IocType::Ipv6 | IocType::Cidr => 60,
        IocType::Domain | IocType::Url => 120,
        IocType::Email => 180,
        IocType::Ja3 | IocType::Ja3s => 240,
        IocType::Sha256 | IocType::Sha1 | IocType::Md5 => 3650,
        IocType::FilePath | IocType::Mutex | IocType::RegistryKey => 730,
    }
}

/// Effective confidence after aging `base` by `age_days`. Clamped to 0..=100.
#[must_use]
pub fn effective_confidence(base: u8, age_days: f64, ioc_type: IocType) -> f64 {
    if age_days <= 0.0 {
        return f64::from(base).clamp(0.0, 100.0);
    }
    let hl = half_life_days(ioc_type).max(0.5);
    let factor = 2f64.powf(-age_days / hl);
    (f64::from(base) * factor).clamp(0.0, 100.0)
}

/// Whether an indicator has decayed below the retirement floor.
#[must_use]
pub fn is_retired(base: u8, age_days: f64, ioc_type: IocType) -> bool {
    effective_confidence(base, age_days, ioc_type) < RETIRE_CONFIDENCE
}

/// Age in days (fractional) from a timestamp given the current unix seconds.
#[must_use]
pub fn age_days_from_unix(first_seen_unix: i64, now_unix: i64) -> f64 {
    if now_unix <= first_seen_unix {
        return 0.0;
    }
    (now_unix - first_seen_unix) as f64 / 86_400.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_indicator_keeps_full_confidence() {
        assert_eq!(effective_confidence(90, 0.0, IocType::Ipv4), 90.0);
    }

    #[test]
    fn one_half_life_halves_confidence() {
        let e = effective_confidence(80, half_life_days(IocType::Ipv4), IocType::Ipv4);
        assert!((e - 40.0).abs() < 1e-6, "got {e}");
    }

    #[test]
    fn hashes_barely_decay_over_a_month() {
        let e = effective_confidence(90, 30.0, IocType::Sha256);
        // 30/365 half-lives → still ~85+.
        assert!(e > 85.0, "hash decayed too fast: {e}");
    }

    #[test]
    fn ips_decay_and_retire() {
        // 14d half-life: after ~60 days an 80-base IP is well under the floor.
        assert!(is_retired(80, 60.0, IocType::Ipv4));
        assert!(!is_retired(80, 3.0, IocType::Ipv4));
    }

    #[test]
    fn monotonic_non_increasing_in_age() {
        let mut prev = 101.0;
        for d in 0..120 {
            let e = effective_confidence(100, f64::from(d), IocType::Domain);
            assert!(e <= prev + 1e-9, "not monotonic at {d}");
            prev = e;
        }
    }

    #[test]
    fn age_days_is_non_negative() {
        assert_eq!(age_days_from_unix(1000, 500), 0.0);
        assert!((age_days_from_unix(0, 86_400) - 1.0).abs() < 1e-9);
    }
}
