//! Bilingual (Hebrew + English) remediation brief for a finding.
//!
//! Explains — in impeccable native Hebrew AND English — WHAT the problem was, WHY it happened,
//! its IMPACT, HOW the fix works, and, per delivery channel, HOW TO CONNECT and HOW TO APPLY it.
//! Generated on-demand via the tenant's LLM (same OpenAI-compatible endpoint as council synthesis)
//! and cached in `vulnerabilities.remediation_brief`. Fails soft: an LLM error returns an error the
//! caller can surface without blocking the finding.

use serde::{Deserialize, Serialize};
use weissman_engines::deserialize_llm_json;
use weissman_engines::openai_chat::{self, LlmError};

use crate::council::CouncilConfig;
use crate::heal_channels::DeliveryChannel;

/// A single string in both languages. Rendered directly (the UI toggles he/en).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Bilingual {
    #[serde(default)]
    pub he: String,
    #[serde(default)]
    pub en: String,
}

/// Per-channel "how to connect" + "how to apply" guidance, bilingual.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelHowTo {
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub connect: Bilingual,
    #[serde(default)]
    pub apply: Bilingual,
}

/// The full remediation brief for one finding.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemediationBrief {
    #[serde(default)]
    pub problem: Bilingual,
    #[serde(default)]
    pub root_cause: Bilingual,
    #[serde(default)]
    pub impact: Bilingual,
    #[serde(default)]
    pub fix_explanation: Bilingual,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub cwe: String,
    #[serde(default)]
    pub channels: Vec<ChannelHowTo>,
    #[serde(default)]
    pub generated_at: i64,
    #[serde(default)]
    pub model: String,
}

const SYS_BRIEF: &str = "You are a principal application-security engineer writing a remediation brief. \
Output ONE minified JSON object ONLY, no prose outside JSON. Schema: {\
\"problem\":{\"he\":string,\"en\":string},\
\"root_cause\":{\"he\":string,\"en\":string},\
\"impact\":{\"he\":string,\"en\":string},\
\"fix_explanation\":{\"he\":string,\"en\":string},\
\"severity\":string,\"cwe\":string,\
\"channels\":[{\"channel\":string,\"connect\":{\"he\":string,\"en\":string},\"apply\":{\"he\":string,\"en\":string}}]}. \
EVERY text field MUST contain BOTH an impeccable, native, professional Hebrew (\"he\") AND English (\"en\") version \
of the SAME content — never leave one empty, never mix languages inside a field. Hebrew must read as written by a \
native security professional. Keep each field concise (1-4 sentences). The \"channels\" array MUST contain one entry \
for each of these channel ids: github_pr, github_direct_commit, gitlab_mr, bitbucket_pr, azure_repos_pr, diff_download, virtual_patch — each explaining how to \
connect that channel (credentials/config needed) and how to apply the fix through it. Do not include exploit payloads.";

/// Bilingual fallback how-tos so the UI always has connection guidance even if the LLM omits
/// the `channels` array. Content is factual and channel-specific.
#[must_use]
pub fn default_channel_howtos() -> Vec<ChannelHowTo> {
    let mk = |ch: DeliveryChannel, connect_he: &str, connect_en: &str, apply_he: &str, apply_en: &str| {
        ChannelHowTo {
            channel: ch.id().to_string(),
            connect: Bilingual { he: connect_he.to_string(), en: connect_en.to_string() },
            apply: Bilingual { he: apply_he.to_string(), en: apply_en.to_string() },
        }
    };
    vec![
        mk(
            DeliveryChannel::GithubPr,
            "חבר טוקן GitHub עם הרשאת repo ואת שם המאגר (owner/repo). המערכת פותחת Pull Request לאחר אימות בסנדבוקס.",
            "Connect a GitHub token with `repo` scope and the repository slug (owner/repo). The platform opens a Pull Request after sandbox verification.",
            "לחץ \"רפא\" — נוצר ענף עם התיקון המוחל ונפתח PR מוכן למיזוג לאחר סקירה.",
            "Click \"Heal\" — a branch with the applied fix is created and a PR is opened, ready to merge after review.",
        ),
        mk(
            DeliveryChannel::GithubDirectCommit,
            "כמו PR, אך התיקון נכתב ישירות לענף ריפוי ללא פתיחת PR. דורש טוקן GitHub עם הרשאת repo.",
            "Same as PR, but the fix is committed straight to a heal branch without opening a PR. Requires a GitHub token with `repo` scope.",
            "בחר בערוץ זה ולחץ \"רפא\" — הקבצים המתוקנים נדחפים לענף הריפוי.",
            "Select this channel and click \"Heal\" — the patched files are pushed to the heal branch.",
        ),
        mk(
            DeliveryChannel::DiffDownload,
            "אינו נוגע במאגר. נדרשת רק גישת קריאה לצורך האימות בסנדבוקס.",
            "Does not touch the repository. Only read access is needed for the sandbox verification.",
            "לאחר האימות, הורד את קובץ ה-diff המאומת והחל אותו ידנית עם `git apply` או `patch -p1`.",
            "After verification, download the verified diff and apply it manually with `git apply` or `patch -p1`.",
        ),
        mk(
            DeliveryChannel::VirtualPatch,
            "אינו נוגע בקוד. פועל בשכבת ה-WAF כבקרה מפצה.",
            "Does not touch the code. Operates at the WAF layer as a compensating control.",
            "הורד את חוקת ה-WAF (למשל ModSecurity) ופרוס אותה כדי לחסום את הניצול עד שהתיקון בקוד ימוזג.",
            "Download the WAF rule (e.g. ModSecurity) and deploy it to block the exploit until the code fix is merged.",
        ),
        mk(
            DeliveryChannel::GitlabMr,
            "חבר טוקן GitLab (glpat) עם הרשאת api ואת נתיב הפרויקט (owner/repo). ברירת מחדל gitlab.com, ניתן להגדיר מארח עצמי.",
            "Connect a GitLab token (glpat) with `api` scope and the project path (owner/repo). Defaults to gitlab.com; a self-managed host can be configured.",
            "בחר בערוץ זה ולחץ \"רפא\" — נפתח Merge Request עם התיקון המוחל לאחר אימות בסנדבוקס.",
            "Select this channel and click \"Heal\" — a Merge Request with the applied fix is opened after sandbox verification.",
        ),
        mk(
            DeliveryChannel::BitbucketPr,
            "חבר Access Token של Bitbucket Cloud ואת נתיב המאגר (workspace/repo). האימות מתבצע בסנדבוקס לפני פתיחת ה-PR.",
            "Connect a Bitbucket Cloud access token and the repository slug (workspace/repo). Verification runs in the sandbox before the PR is opened.",
            "בחר בערוץ זה ולחץ \"רפא\" — נוצר ענף ריפוי, הקבצים נדחפים דרך `/src`, ונפתח Pull Request.",
            "Select this channel and click \"Heal\" — a heal branch is created, the files are committed via `/src`, and a Pull Request is opened.",
        ),
        mk(
            DeliveryChannel::AzureReposPr,
            "חבר Personal Access Token של Azure DevOps (הרשאת Code: Read & Write) ואת הנתיב org/project/repo.",
            "Connect an Azure DevOps Personal Access Token (Code: Read & Write) and the org/project/repo path.",
            "בחר בערוץ זה ולחץ \"רפא\" — התיקון נדחף כ-commit יחיד לענף ריפוי חדש, ונפתח Pull Request.",
            "Select this channel and click \"Heal\" — the fix is pushed as a single commit to a new heal branch, and a Pull Request is opened.",
        ),
    ]
}

/// Generate the bilingual brief for a finding via the tenant LLM. `patch`/`detection_signature`
/// may be empty. Returns a validated `RemediationBrief` with `generated_at`/`model` stamped
/// server-side. Errors are returned as strings so the caller can fail soft.
#[allow(clippy::too_many_arguments)]
pub async fn generate_remediation_brief(
    cfg: &CouncilConfig,
    tenant_id: i64,
    title: &str,
    description: &str,
    severity: &str,
    cwe: &str,
    patch: &str,
    detection_signature: &str,
) -> Result<RemediationBrief, String> {
    let client = cfg.http_client();
    let user = format!(
        "Finding title: {title}\nSeverity: {severity}\nCWE: {cwe}\n\nDescription:\n{desc}\n\nProposed patch (may be empty):\n{patch}\n\nDetection signature (may be empty):\n{sig}",
        title = title.chars().take(600).collect::<String>(),
        severity = severity,
        cwe = cwe,
        desc = description.chars().take(4000).collect::<String>(),
        patch = patch.chars().take(6000).collect::<String>(),
        sig = detection_signature.chars().take(1500).collect::<String>(),
    );

    // sanitize_user_input=true: finding title/description/patch are attacker-influenced.
    let raw = openai_chat::chat_completion_text_json_object(
        &client,
        cfg.base_url.as_str(),
        cfg.model_synthesizer.as_str(),
        Some(SYS_BRIEF),
        &user,
        0.2,
        1800,
        Some(tenant_id),
        "remediation_brief",
        true,
    )
    .await
    .map_err(|e: LlmError| format!("remediation brief LLM error: {e}"))?;

    let mut brief: RemediationBrief =
        deserialize_llm_json(&raw).map_err(|e| format!("remediation brief parse error: {e}"))?;

    // Stamp trust-sensitive fields server-side; never trust the model for these.
    brief.model = cfg.model_synthesizer.clone();
    brief.generated_at = chrono::Utc::now().timestamp();
    if brief.severity.trim().is_empty() {
        brief.severity = severity.to_string();
    }
    if brief.cwe.trim().is_empty() {
        brief.cwe = cwe.to_string();
    }
    // Guarantee channel guidance exists even if the model omitted it.
    if brief.channels.is_empty() {
        brief.channels = default_channel_howtos();
    }
    Ok(brief)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_bilingual_brief() {
        let raw = r#"{
            "problem":{"he":"הזרקת SQL","en":"SQL injection"},
            "root_cause":{"he":"קלט לא מסונן","en":"Unsanitized input"},
            "impact":{"he":"דליפת נתונים","en":"Data exfiltration"},
            "fix_explanation":{"he":"שימוש בשאילתות פרמטריות","en":"Use parameterized queries"},
            "severity":"critical","cwe":"CWE-89",
            "channels":[{"channel":"github_pr","connect":{"he":"טוקן","en":"token"},"apply":{"he":"רפא","en":"heal"}}]
        }"#;
        let brief: RemediationBrief = deserialize_llm_json(raw).expect("parse");
        assert_eq!(brief.problem.he, "הזרקת SQL");
        assert_eq!(brief.problem.en, "SQL injection");
        assert_eq!(brief.severity, "critical");
        assert_eq!(brief.channels.len(), 1);
        assert_eq!(brief.channels[0].channel, "github_pr");
        assert_eq!(brief.channels[0].apply.he, "רפא");
    }

    #[test]
    fn default_howtos_cover_all_channels() {
        let hows = default_channel_howtos();
        let ids: Vec<&str> = hows.iter().map(|h| h.channel.as_str()).collect();
        for id in DeliveryChannel::all_ids() {
            assert!(ids.contains(id), "missing default how-to for {id}");
        }
        // every field is bilingual (both he and en present)
        for h in &hows {
            assert!(!h.connect.he.is_empty() && !h.connect.en.is_empty());
            assert!(!h.apply.he.is_empty() && !h.apply.en.is_empty());
        }
    }
}
