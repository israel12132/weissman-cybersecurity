//! Automatic **delivery-channel selection** — given a finding and the repo's SCM, pick the best way to
//! ship the verified fix, with a bilingual (he/en) rationale. When the repo is writable, deliver a
//! code-level fix as a pull/merge request on the matching SCM; when it isn't, fall back to a WAF
//! virtual patch for request-layer classes (a fast compensating control) or a downloadable diff.
//!
//! [`select_channel`] and the classifiers are **pure functions**, fully unit-tested.

use serde::Serialize;

use crate::heal_channels::DeliveryChannel;

/// Which source-control system hosts the repo (drives which PR/MR channel to use).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scm {
    GitHub,
    GitLab,
    Bitbucket,
    Azure,
    Unknown,
}

impl Scm {
    fn label(self) -> &'static str {
        match self {
            Scm::GitHub => "GitHub",
            Scm::GitLab => "GitLab",
            Scm::Bitbucket => "Bitbucket",
            Scm::Azure => "Azure DevOps",
            Scm::Unknown => "the repository",
        }
    }
}

/// Infer the SCM from a host or repo URL. Unknown when nothing matches.
///
/// The input may be a bare host or a full URL. We first reduce it to its bare host *authority* —
/// stripping scheme, userinfo, port, and any path/query/fragment — before matching, so a hostile
/// path segment (e.g. `https://git.evil.example/path/github`) can't be mistaken for the SCM. A
/// substring match on the authority is deliberately retained so self-managed hosts still classify
/// (e.g. `gitlab.example.com` → GitLab).
#[must_use]
pub fn scm_from_host(host: &str) -> Scm {
    let lower = host.trim().to_ascii_lowercase();
    let after_scheme = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(lower.as_str());
    // Authority is everything before the first path/query/fragment separator.
    let authority = after_scheme
        .split(|c| c == '/' || c == '?' || c == '#')
        .next()
        .unwrap_or("");
    // Drop userinfo (`user@`) and port (`:443`).
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let h = host_port.split(':').next().unwrap_or(host_port);
    if h.contains("github") {
        Scm::GitHub
    } else if h.contains("gitlab") {
        Scm::GitLab
    } else if h.contains("bitbucket") {
        Scm::Bitbucket
    } else if h.contains("azure") || h.contains("visualstudio") || h.contains("dev.azure") {
        Scm::Azure
    } else {
        Scm::Unknown
    }
}

/// True when `haystack` contains `word` as a whole alphanumeric token (so short acronyms like `sqli`
/// don't false-match a substring, e.g. inside `sqlite`).
fn contains_word(haystack: &str, word: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == word)
}

/// True when the vulnerability class is a request-layer issue a WAF rule can block in-flight.
#[must_use]
pub fn waf_mitigable(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    // Multi-word phrases (never a bare "injection", which would false-match "dependency injection").
    const PHRASES: &[&str] = &[
        "sql injection",
        "code injection",
        "ldap injection",
        "xpath injection",
        "template injection",
        "header injection",
        "cross-site scripting",
        "path traversal",
        "directory traversal",
        "command inj",
    ];
    // Short acronyms match whole-word only (avoids `sqli` in `sqlite`, `xss` in a longer token, …).
    const WORDS: &[&str] = &["sqli", "ssti", "crlf", "xss", "ssrf", "xxe", "lfi", "rfi"];
    PHRASES.iter().any(|p| t.contains(p)) || WORDS.iter().any(|w| contains_word(&t, w))
}

/// The PR/MR channel that matches an SCM.
fn pr_channel_for(scm: Scm) -> DeliveryChannel {
    match scm {
        Scm::GitHub => DeliveryChannel::GithubPr,
        Scm::GitLab => DeliveryChannel::GitlabMr,
        Scm::Bitbucket => DeliveryChannel::BitbucketPr,
        Scm::Azure => DeliveryChannel::AzureReposPr,
        Scm::Unknown => DeliveryChannel::GithubPr,
    }
}

/// The chosen channel plus a bilingual rationale.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelSelection {
    pub channel: String,
    pub reason_en: String,
    pub reason_he: String,
}

/// Choose the delivery channel for a finding.
///
/// * `has_repo_write` — a token that can push to the repo is configured.
/// * `scm` — where the repo lives (for the PR/MR channel).
/// * `finding_text` — title/description, used to detect WAF-mitigable classes.
#[must_use]
pub fn select_channel(finding_text: &str, scm: Scm, has_repo_write: bool) -> ChannelSelection {
    if has_repo_write && scm != Scm::Unknown {
        let ch = pr_channel_for(scm);
        return ChannelSelection {
            channel: ch.id().to_string(),
            reason_en: format!(
                "Deliver a code-level fix as a pull request on {}.",
                scm.label()
            ),
            reason_he: format!("מסירת תיקון ברמת הקוד כ-Pull Request ב-{}.", scm.label()),
        };
    }
    if has_repo_write {
        // Repo is writable but the SCM host is unrecognized — none of our PR/MR clients apply, so
        // fall back to a downloadable diff rather than mis-routing a non-GitHub host to a GitHub PR.
        return ChannelSelection {
            channel: DeliveryChannel::DiffDownload.id().to_string(),
            reason_en: "The repository host was not recognized as GitHub / GitLab / Bitbucket / Azure — download the verified diff to apply it manually.".to_string(),
            reason_he: "מארח המאגר לא זוהה כ-GitHub / GitLab / Bitbucket / Azure — הורד את ה-diff המאומת כדי להחילו ידנית.".to_string(),
        };
    }
    if waf_mitigable(finding_text) {
        return ChannelSelection {
            channel: DeliveryChannel::VirtualPatch.id().to_string(),
            reason_en: "No repository write access — a WAF virtual patch blocks the exploit in-flight while a code fix is arranged.".to_string(),
            reason_he: "אין הרשאת כתיבה למאגר — חוק WAF (וירטואלי) חוסם את הניצול בזמן אמת עד להסדרת תיקון בקוד.".to_string(),
        };
    }
    ChannelSelection {
        channel: DeliveryChannel::DiffDownload.id().to_string(),
        reason_en: "No repository write access — download the verified diff to apply it manually."
            .to_string(),
        reason_he: "אין הרשאת כתיבה למאגר — הורד את ה-diff המאומת כדי להחילו ידנית.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scm_detection() {
        assert_eq!(scm_from_host("github.com"), Scm::GitHub);
        assert_eq!(scm_from_host("gitlab.example.com"), Scm::GitLab);
        assert_eq!(scm_from_host("bitbucket.org"), Scm::Bitbucket);
        assert_eq!(scm_from_host("dev.azure.com/org"), Scm::Azure);
        assert_eq!(scm_from_host("git.corp.internal"), Scm::Unknown);
        // A hostile path segment must NOT be mistaken for the SCM — only the authority is matched.
        assert_eq!(
            scm_from_host("https://git.evil.example/path/github"),
            Scm::Unknown
        );
        assert_eq!(scm_from_host("git.evil.example/gitlab/x"), Scm::Unknown);
        // Scheme, userinfo, and port are stripped before matching.
        assert_eq!(scm_from_host("https://user@github.com:443"), Scm::GitHub);
    }

    #[test]
    fn waf_mitigable_classes() {
        assert!(waf_mitigable("Reflected XSS in search"));
        assert!(waf_mitigable("Blind SQL Injection"));
        assert!(waf_mitigable("Path traversal in file download"));
        assert!(waf_mitigable("LDAP injection in the directory search"));
        assert!(waf_mitigable("Server-side template injection (SSTI)"));
        assert!(!waf_mitigable("Insecure deserialization gadget chain"));
        assert!(!waf_mitigable("Weak password policy"));
        // Must not false-match benign engineering text (bare "injection" removed).
        assert!(!waf_mitigable(
            "Dependency injection container misconfiguration"
        ));
        // Short acronyms match whole-word only — "sqli" must not fire inside "sqlite".
        assert!(!waf_mitigable("SQLite database file world-readable"));
        assert!(waf_mitigable("SQLi in the search parameter"));
    }

    #[test]
    fn writable_repo_picks_matching_pr_channel() {
        assert_eq!(
            select_channel("anything", Scm::GitHub, true).channel,
            "github_pr"
        );
        assert_eq!(
            select_channel("anything", Scm::GitLab, true).channel,
            "gitlab_mr"
        );
        assert_eq!(
            select_channel("anything", Scm::Bitbucket, true).channel,
            "bitbucket_pr"
        );
        assert_eq!(
            select_channel("anything", Scm::Azure, true).channel,
            "azure_repos_pr"
        );
        // Unknown SCM but writable → safe downloadable diff (never mis-route to a GitHub PR).
        assert_eq!(
            select_channel("anything", Scm::Unknown, true).channel,
            "diff_download"
        );
    }

    #[test]
    fn no_write_waf_class_picks_virtual_patch() {
        let s = select_channel("SQL injection in login", Scm::GitHub, false);
        assert_eq!(s.channel, "virtual_patch");
        assert!(s.reason_he.contains("WAF"));
    }

    #[test]
    fn no_write_non_waf_class_picks_diff_download() {
        let s = select_channel("Insecure deserialization", Scm::GitHub, false);
        assert_eq!(s.channel, "diff_download");
    }
}
