//! Auto-heal **readiness self-diagnostics** — a bilingual (Hebrew + English) preflight that reports,
//! per capability, whether the self-healing pipeline can actually heal, and — when it can't — exactly
//! how to connect the missing piece.
//!
//! A system that "fixes itself" should also *know whether it can*: this turns opaque
//! "why didn't it open a PR?" moments into an explicit, operator-facing checklist. Two required
//! capabilities gate a *verified* heal (the LLM that writes the fix, and the ephemeral Docker sandbox
//! that proves it); everything else is recommended/optional and only affects the score.
//!
//! [`evaluate_readiness`] is a **pure function** over [`ReadinessSignals`] (booleans gathered by the
//! handler from real config/env), so the scoring and the bilingual guidance are fully unit-tested.

use serde::Serialize;

/// Booleans the handler resolves from tenant config + process env; the pure evaluator turns them
/// into a scored, bilingual report.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadinessSignals {
    /// Tenant `llm_base_url` / `llm_model` configured — the fix synthesizer has an endpoint.
    pub llm_configured: bool,
    /// `WEISSMAN_LLM_API_KEY` present — Bearer for authenticated / hosted LLM endpoints.
    pub llm_auth_present: bool,
    /// A Docker socket is reachable (`/var/run/docker.sock` or `DOCKER_HOST`).
    pub docker_socket: bool,
    /// Attestation signing enabled (`finding_attestation::is_enabled`).
    pub attestation: bool,
    /// `WEISSMAN_SLACK_SIGNING_SECRET` present — signed Slack approval buttons work.
    pub slack_approvals: bool,
    /// `WEISSMAN_GITHUB_TOKEN` + a default repo — autonomous / Slack-approved PRs without a per-heal token.
    pub configless_github: bool,
}

/// One capability line in the readiness report.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessCheck {
    pub key: String,
    pub ok: bool,
    pub required: bool,
    pub weight: u8,
    pub label_en: String,
    pub label_he: String,
    pub detail_en: String,
    pub detail_he: String,
    /// How to connect it when `ok == false` (bilingual); empty when already connected.
    pub fix_en: String,
    pub fix_he: String,
}

/// The full readiness report.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessReport {
    /// True only when every **required** capability is connected.
    pub ready: bool,
    /// Weighted 0..=100 across all capabilities.
    pub score: u8,
    pub summary_en: String,
    pub summary_he: String,
    pub checks: Vec<ReadinessCheck>,
}

fn check(
    key: &str,
    ok: bool,
    required: bool,
    weight: u8,
    label: (&str, &str),
    detail: (&str, &str),
    fix: (&str, &str),
) -> ReadinessCheck {
    ReadinessCheck {
        key: key.to_string(),
        ok,
        required,
        weight,
        label_en: label.0.to_string(),
        label_he: label.1.to_string(),
        detail_en: detail.0.to_string(),
        detail_he: detail.1.to_string(),
        // Guidance is only meaningful when the capability is missing.
        fix_en: if ok { String::new() } else { fix.0.to_string() },
        fix_he: if ok { String::new() } else { fix.1.to_string() },
    }
}

/// Turn raw signals into a scored, bilingual readiness report.
pub fn evaluate_readiness(s: &ReadinessSignals) -> ReadinessReport {
    let checks =
        vec![
        check(
            "llm",
            s.llm_configured,
            true,
            30,
            ("AI patch synthesis (LLM)", "מנוע ייצור תיקונים (LLM)"),
            (
                "Writes the fix and iteratively corrects it until it passes verification.",
                "כותב את התיקון ומתקן אותו שוב ושוב עד שהוא עובר אימות.",
            ),
            (
                "Set the tenant llm_base_url and llm_model in system settings.",
                "הגדירו את llm_base_url ואת llm_model בהגדרות המערכת.",
            ),
        ),
        check(
            "sandbox",
            s.docker_socket,
            true,
            25,
            ("Ephemeral verification sandbox (Docker)", "ארגז חול אֶפֶמֶרִי לאימות (Docker)"),
            (
                "Proves the fix closes the exploit without breaking the application.",
                "מוכיח שהתיקון סוגר את החולשה מבלי לשבור את האפליקציה.",
            ),
            (
                "Expose a Docker socket (/var/run/docker.sock) or set DOCKER_HOST.",
                "חשפו סוקט Docker (/var/run/docker.sock) או הגדירו DOCKER_HOST.",
            ),
        ),
        check(
            "attestation",
            s.attestation,
            false,
            15,
            ("Signed heal receipts", "קבלות ריפוי חתומות"),
            (
                "Tamper-evident HMAC proof that a fix was genuinely verified.",
                "הוכחת HMAC עמידה בזיוף לכך שהתיקון אכן אומת.",
            ),
            (
                "Set WEISSMAN_ATTESTATION_KEY (or a platform JWT signing key).",
                "הגדירו WEISSMAN_ATTESTATION_KEY (או מפתח חתימת JWT של הפלטפורמה).",
            ),
        ),
        check(
            "github_autopilot",
            s.configless_github,
            false,
            12,
            ("Autonomous GitHub pull requests", "פתיחת Pull Request אוטונומית ב-GitHub"),
            (
                "Opens fix PRs for auto / Slack-approved heals without a per-heal token.",
                "פותח PR לתיקון בריפוי אוטומטי או מאושר-Slack ללא צורך באסימון לכל ריפוי.",
            ),
            (
                "Set WEISSMAN_GITHUB_TOKEN and auto_heal_repo_slug (or WEISSMAN_AUTOHEAL_REPO).",
                "הגדירו WEISSMAN_GITHUB_TOKEN ואת auto_heal_repo_slug (או WEISSMAN_AUTOHEAL_REPO).",
            ),
        ),
        check(
            "slack",
            s.slack_approvals,
            false,
            10,
            ("Slack approval buttons", "כפתורי אישור ב-Slack"),
            (
                "Approve or dismiss a verified fix directly from Slack (signed).",
                "אישור או דחייה של תיקון מאומת ישירות מ-Slack (חתום).",
            ),
            (
                "Set WEISSMAN_SLACK_SIGNING_SECRET and a Slack webhook / bot token.",
                "הגדירו WEISSMAN_SLACK_SIGNING_SECRET ואסימון webhook או בוט של Slack.",
            ),
        ),
        check(
            "llm_auth",
            s.llm_auth_present,
            false,
            8,
            ("LLM endpoint authentication", "אימות מול נקודת הקצה של ה-LLM"),
            (
                "Bearer token for authenticated or hosted LLM endpoints.",
                "אסימון Bearer לנקודות קצה מאומתות או מתארחות של LLM.",
            ),
            (
                "Set WEISSMAN_LLM_API_KEY if your LLM endpoint requires authentication.",
                "הגדירו WEISSMAN_LLM_API_KEY אם נקודת הקצה של ה-LLM דורשת אימות.",
            ),
        ),
    ];

    let score: u32 = checks
        .iter()
        .filter(|c| c.ok)
        .map(|c| c.weight as u32)
        .sum();
    let score = score.min(100) as u8;
    let ready = checks.iter().filter(|c| c.required).all(|c| c.ok);
    let all_ok = checks.iter().all(|c| c.ok);

    let (summary_en, summary_he) = if ready && all_ok {
        (
            "Fully armed — every auto-heal capability is connected.",
            "מזוין במלואו — כל יכולות הריפוי האוטומטי מחוברות.",
        )
    } else if ready {
        (
            "Ready to auto-heal — some optional capabilities are not yet connected.",
            "מוכן לריפוי אוטומטי — חלק מיכולות הרשות עדיין לא מחוברות.",
        )
    } else {
        (
            "Not ready — connect the required capabilities listed below.",
            "לא מוכן — חברו את היכולות הנדרשות המפורטות למטה.",
        )
    };

    ReadinessReport {
        ready,
        score,
        summary_en: summary_en.to_string(),
        summary_he: summary_he.to_string(),
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_on() -> ReadinessSignals {
        ReadinessSignals {
            llm_configured: true,
            llm_auth_present: true,
            docker_socket: true,
            attestation: true,
            slack_approvals: true,
            configless_github: true,
        }
    }

    #[test]
    fn everything_connected_is_ready_and_full_score() {
        let r = evaluate_readiness(&all_on());
        assert!(r.ready);
        assert_eq!(r.score, 100);
        assert!(r.summary_en.contains("Fully armed"));
        // Every check ok => no fix guidance is emitted.
        assert!(r
            .checks
            .iter()
            .all(|c| c.ok && c.fix_en.is_empty() && c.fix_he.is_empty()));
    }

    #[test]
    fn missing_required_llm_is_not_ready() {
        let mut s = all_on();
        s.llm_configured = false;
        let r = evaluate_readiness(&s);
        assert!(!r.ready);
        assert_eq!(r.score, 70); // 100 - 30
        assert!(r.summary_en.contains("Not ready"));
        let llm = r.checks.iter().find(|c| c.key == "llm").unwrap();
        assert!(!llm.ok && llm.required);
        // Missing capability carries bilingual connect guidance.
        assert!(!llm.fix_en.is_empty() && !llm.fix_he.is_empty());
    }

    #[test]
    fn missing_required_sandbox_is_not_ready() {
        let mut s = all_on();
        s.docker_socket = false;
        let r = evaluate_readiness(&s);
        assert!(!r.ready);
        assert_eq!(r.score, 75); // 100 - 25
    }

    #[test]
    fn only_required_connected_is_ready_but_not_full() {
        let s = ReadinessSignals {
            llm_configured: true,
            docker_socket: true,
            ..ReadinessSignals::default()
        };
        let r = evaluate_readiness(&s);
        assert!(r.ready);
        assert_eq!(r.score, 55); // 30 + 25
        assert!(r.summary_en.contains("Ready to auto-heal"));
        assert!(r.summary_he.contains("מוכן"));
    }

    #[test]
    fn optional_missing_does_not_block_readiness() {
        let mut s = all_on();
        s.attestation = false;
        s.slack_approvals = false;
        let r = evaluate_readiness(&s);
        assert!(r.ready); // still ready — both were optional
        assert_eq!(r.score, 100 - 15 - 10);
    }

    #[test]
    fn nothing_connected_scores_zero() {
        let r = evaluate_readiness(&ReadinessSignals::default());
        assert!(!r.ready);
        assert_eq!(r.score, 0);
        assert_eq!(r.checks.len(), 6);
        assert!(r.checks.iter().all(|c| !c.ok));
    }

    #[test]
    fn every_check_has_both_languages() {
        let r = evaluate_readiness(&ReadinessSignals::default());
        for c in &r.checks {
            assert!(
                !c.label_en.is_empty() && !c.label_he.is_empty(),
                "label {}",
                c.key
            );
            assert!(
                !c.detail_en.is_empty() && !c.detail_he.is_empty(),
                "detail {}",
                c.key
            );
            assert!(
                !c.fix_en.is_empty() && !c.fix_he.is_empty(),
                "fix {}",
                c.key
            );
        }
    }
}
