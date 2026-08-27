//! OAST callback domains must be high-reputation (not freshly registered
//! throwaway names that land on SOC DNS blocklists).

pub const HIGH_REPUTATION_SUFFIXES: &[&str] = &[
    "oast.live",
    "oast.pro",
    "oast.fun",
    "oast.site",
    "oast.online",
    "interact.sh",
    "burpcollaborator.net",
    "webhook.site",
];

pub fn is_high_reputation_callback(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    HIGH_REPUTATION_SUFFIXES
        .iter()
        .any(|sfx| h == *sfx || h.ends_with(&format!(".{sfx}")))
}

/// True when the host looks like a public collaborator brand (interact.sh / oast.* / burp).
/// Operator-owned domains (e.g. weissmancyber.com) are not public brands.
pub fn looks_like_public_collaborator(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').collect();
    labels.windows(2).any(|w| w == ["interact", "sh"])
        || h.ends_with("burpcollaborator.net")
        || h.ends_with("webhook.site")
        || labels.iter().any(|p| *p == "oast")
}

pub fn assert_callback_host(host: &str) -> Result<(), String> {
    if is_high_reputation_callback(host) {
        Ok(())
    } else {
        Err(format!(
            "OAST callback host '{host}' is not on the high-reputation allow-list"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_interactsh_style() {
        assert!(is_high_reputation_callback("abc.oast.live"));
        assert!(is_high_reputation_callback("xyz.interact.sh"));
    }

    #[test]
    fn rejects_fresh_c2() {
        assert!(!is_high_reputation_callback("evil.tk"));
        assert!(!is_high_reputation_callback(""));
        assert!(assert_callback_host("not-a-real-oast.example").is_err());
    }

    #[test]
    fn public_collaborator_detection() {
        assert!(looks_like_public_collaborator("abc.oast.live"));
        assert!(looks_like_public_collaborator("xyz.interact.sh"));
        assert!(!looks_like_public_collaborator("weissmancyber.com"));
        assert!(!looks_like_public_collaborator("notinteract.sh.example"));
    }
}
