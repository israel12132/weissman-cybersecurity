//! Delivery channels for a verified auto-heal fix.
//!
//! After the sandbox proves a patch (`HealVerdict::Fixed`), the same verified artifact —
//! the set of changed files plus the unified diff — can be delivered several ways. The
//! operator picks a channel; the worker (`auto_heal_job`) branches on it. Every channel
//! reuses the one verified artifact, so adding a channel is cheap.

/// How a verified fix is delivered. `github_pr` is the default (a mergeable PR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DeliveryChannel {
    /// Applied-fix pull request (default): commit the real changed files, open a PR.
    GithubPr,
    /// Commit the applied fix straight to the heal branch, no PR.
    GithubDirectCommit,
    /// Do not touch the repo — expose the verified unified diff for download/manual apply.
    DiffDownload,
    /// Do not touch the repo — render a WAF / virtual-patch snippet from the detection signature.
    VirtualPatch,
    /// Applied-fix GitLab Merge Request (v4 API).
    GitlabMr,
}

impl DeliveryChannel {
    /// Parse a channel id; unknown/empty falls back to the safe default (`GithubPr`).
    #[must_use]
    pub fn from_id(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "github_direct_commit" | "direct_commit" | "commit" => DeliveryChannel::GithubDirectCommit,
            "diff_download" | "diff" | "patch_download" => DeliveryChannel::DiffDownload,
            "virtual_patch" | "waf" | "virtual" => DeliveryChannel::VirtualPatch,
            "gitlab_mr" | "gitlab" | "mr" => DeliveryChannel::GitlabMr,
            _ => DeliveryChannel::GithubPr,
        }
    }

    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            DeliveryChannel::GithubPr => "github_pr",
            DeliveryChannel::GithubDirectCommit => "github_direct_commit",
            DeliveryChannel::DiffDownload => "diff_download",
            DeliveryChannel::VirtualPatch => "virtual_patch",
            DeliveryChannel::GitlabMr => "gitlab_mr",
        }
    }

    /// Whether this channel mutates the customer's git repository.
    #[must_use]
    pub fn touches_repo(&self) -> bool {
        matches!(
            self,
            DeliveryChannel::GithubPr
                | DeliveryChannel::GithubDirectCommit
                | DeliveryChannel::GitlabMr
        )
    }

    /// All channel ids, for surfacing the picker to the UI.
    #[must_use]
    pub fn all_ids() -> &'static [&'static str] {
        &[
            "github_pr",
            "github_direct_commit",
            "diff_download",
            "virtual_patch",
            "gitlab_mr",
        ]
    }
}

/// Render a defense-in-depth virtual-patch (ModSecurity-style) snippet from the detection
/// signature. This is a compensating control shown when the operator can't (or won't) touch
/// the repo — it does not replace the code fix, and says so.
#[must_use]
pub fn render_virtual_patch(finding_id: &str, title: &str, detection_signature: &str) -> String {
    let sig = detection_signature.trim();
    let rule_msg = title.replace('"', "'");
    let sig_block = if sig.is_empty() {
        "# No detection signature was available for this finding — craft a rule that matches the\n\
         # exploit request captured in the PoC before deploying.".to_string()
    } else {
        format!("# Detection signature:\n# {}", sig.replace('\n', "\n# "))
    };
    format!(
        "# ── Weissman CNAPP virtual patch (compensating control) ──────────────\n\
         # Finding: {finding_id}\n\
         # This is a WAF-layer mitigation, NOT a source fix. Deploy it to block the exploit\n\
         # in-flight while the code patch is reviewed and merged.\n\
         {sig_block}\n\
         #\n\
         # Example ModSecurity rule (adapt the operator/target to your WAF):\n\
         SecRule REQUEST_URI|ARGS|REQUEST_BODY \"@rx (?i)<detection-pattern-from-signature>\" \\\n\
         \x20   \"id:900{id_suffix},phase:2,deny,status:403,log,\\\n\
         \x20    msg:'Weissman virtual patch: {rule_msg}'\"\n",
        finding_id = finding_id,
        sig_block = sig_block,
        rule_msg = rule_msg,
        id_suffix = short_id(finding_id),
    )
}

/// Derive a stable 3-digit suffix for the WAF rule id from the finding id.
fn short_id(finding_id: &str) -> u16 {
    let mut acc: u16 = 0;
    for b in finding_id.bytes() {
        acc = acc.wrapping_mul(31).wrapping_add(b as u16);
    }
    acc % 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_from_id_round_trip() {
        for id in DeliveryChannel::all_ids() {
            let ch = DeliveryChannel::from_id(id);
            assert_eq!(ch.id(), *id, "round trip for {id}");
        }
    }

    #[test]
    fn channel_from_id_aliases_and_default() {
        assert_eq!(DeliveryChannel::from_id("WAF"), DeliveryChannel::VirtualPatch);
        assert_eq!(DeliveryChannel::from_id("commit"), DeliveryChannel::GithubDirectCommit);
        assert_eq!(DeliveryChannel::from_id("diff"), DeliveryChannel::DiffDownload);
        // unknown ⇒ safe default
        assert_eq!(DeliveryChannel::from_id("nonsense"), DeliveryChannel::GithubPr);
        assert_eq!(DeliveryChannel::from_id(""), DeliveryChannel::GithubPr);
    }

    #[test]
    fn touches_repo_only_for_git_channels() {
        assert!(DeliveryChannel::GithubPr.touches_repo());
        assert!(DeliveryChannel::GithubDirectCommit.touches_repo());
        assert!(!DeliveryChannel::DiffDownload.touches_repo());
        assert!(!DeliveryChannel::VirtualPatch.touches_repo());
    }

    #[test]
    fn virtual_patch_mentions_finding_and_is_advisory() {
        let out = render_virtual_patch("F-123", "SQL Injection", "matches ' OR 1=1");
        assert!(out.contains("F-123"));
        assert!(out.contains("compensating control") || out.contains("NOT a source fix"));
        assert!(out.contains("SecRule"));
    }
}
