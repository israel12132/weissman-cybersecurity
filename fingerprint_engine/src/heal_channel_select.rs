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
#[must_use]
pub fn scm_from_host(host: &str) -> Scm {
    let h = host.to_ascii_lowercase();
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

/// True when the vulnerability class is a request-layer issue a WAF rule can block in-flight.
#[must_use]
pub fn waf_mitigable(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    const NEEDLES: [&str; 12] = [
        "sql injection",
        "sqli",
        "injection",
        "xss",
        "cross-site scripting",
        "path traversal",
        "directory traversal",
        "ssrf",
        "command inj",
        "xxe",
        "lfi",
        "rfi",
    ];
    NEEDLES.iter().any(|n| t.contains(n))
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
    if has_repo_write {
        let ch = pr_channel_for(scm);
        return ChannelSelection {
            channel: ch.id().to_string(),
            reason_en: format!("Deliver a code-level fix as a pull request on {}.", scm.label()),
            reason_he: format!("מסירת תיקון ברמת הקוד כ-Pull Request ב-{}.", scm.label()),
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
        reason_en: "No repository write access — download the verified diff to apply it manually.".to_string(),
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
    }

    #[test]
    fn waf_mitigable_classes() {
        assert!(waf_mitigable("Reflected XSS in search"));
        assert!(waf_mitigable("Blind SQL Injection"));
        assert!(waf_mitigable("Path traversal in file download"));
        assert!(!waf_mitigable("Insecure deserialization gadget chain"));
        assert!(!waf_mitigable("Weak password policy"));
    }

    #[test]
    fn writable_repo_picks_matching_pr_channel() {
        assert_eq!(select_channel("anything", Scm::GitHub, true).channel, "github_pr");
        assert_eq!(select_channel("anything", Scm::GitLab, true).channel, "gitlab_mr");
        assert_eq!(select_channel("anything", Scm::Bitbucket, true).channel, "bitbucket_pr");
        assert_eq!(select_channel("anything", Scm::Azure, true).channel, "azure_repos_pr");
        // Unknown SCM but writable → safe default.
        assert_eq!(select_channel("anything", Scm::Unknown, true).channel, "github_pr");
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
