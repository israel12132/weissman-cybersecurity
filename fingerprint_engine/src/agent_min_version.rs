//! Reject endpoint agents older than `WEISSMAN_AGENT_MIN_VERSION`.
//!
//! Comparison is dotted numeric (`1.2.3`); a missing or unparseable agent version
//! is treated as `0.0.0` and rejected when a minimum is configured.

/// Default floor when the env var is unset. Matches the crate version shipped
/// with this tree so current agents enroll; operators raise the floor to evict
/// a vulnerable build.
pub const DEFAULT_MIN_VERSION: &str = "0.1.0";

#[must_use]
pub fn configured_min_version() -> String {
    std::env::var("WEISSMAN_AGENT_MIN_VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_MIN_VERSION.to_string())
}

/// `Ok(())` when `agent_version` is at least the configured minimum.
pub fn require_min_version(agent_version: &str) -> Result<(), String> {
    let min = configured_min_version();
    if version_at_least(agent_version, &min) {
        Ok(())
    } else {
        Err(format!(
            "agent version '{agent_version}' is below the required minimum '{min}'"
        ))
    }
}

#[must_use]
pub fn version_at_least(have: &str, need: &str) -> bool {
    parse_semver(have) >= parse_semver(need)
}

fn parse_semver(raw: &str) -> [u64; 3] {
    let cleaned = raw.trim().trim_start_matches('v');
    let mut out = [0u64; 3];
    for (i, part) in cleaned.split('.').take(3).enumerate() {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        out[i] = digits.parse().unwrap_or(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_dotted_numeric() {
        assert!(version_at_least("0.1.0", "0.1.0"));
        assert!(version_at_least("0.2.0", "0.1.0"));
        assert!(version_at_least("1.0.0", "0.9.9"));
        assert!(!version_at_least("0.0.9", "0.1.0"));
        assert!(!version_at_least("", "0.1.0"));
        assert!(!version_at_least("old", "0.1.0"));
    }

    #[test]
    fn strips_v_prefix_and_suffix() {
        assert!(version_at_least("v0.1.0-beta", "0.1.0"));
        assert!(!version_at_least("v0.0.1", "0.1.0"));
    }
}
