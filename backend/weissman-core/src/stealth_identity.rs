//! Canonical browser identities for outbound probes.
//!
//! One list for the whole platform so Ghost Network, the stealth scheduler, and
//! individual engines rotate the same believable clients instead of a fixed
//! scanner fingerprint.

/// Realistic modern browser User-Agents. Index is a stable rotation key.
pub const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
];

pub const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "he-IL,he;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,fr;q=0.6",
];

/// Headers that must never appear on an active probe (scanner / library fingerprints).
pub const STRIP_HEADER_NAMES: &[&str] = &[
    "x-scanner",
    "x-bug-bounty",
    "x-pentest",
    "x-request-id",
    "x-weissman-engine",
    "x-nuclei",
    "x-sqlmap",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_looks_like_browsers_not_scanners() {
        assert!(USER_AGENTS.len() >= 8);
        for ua in USER_AGENTS {
            assert!(
                ua.starts_with("Mozilla/5.0"),
                "UA must look like a browser: {ua}"
            );
            let lower = ua.to_ascii_lowercase();
            assert!(!lower.contains("weissman"));
            assert!(!lower.contains("sqlmap"));
            assert!(!lower.contains("nuclei"));
            assert!(!lower.contains("python-requests"));
        }
    }
}
