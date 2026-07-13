//! Auditor-grade, self-contained bilingual (Hebrew + English) remediation report.
//!
//! Renders one completed auto-heal into a single **self-contained, printable** HTML document that a
//! customer can hand to an auditor: the finding, the bilingual problem / root-cause / impact / fix
//! explanation, the *verified* unified diff, the changed/deleted files, per-channel how-to-apply
//! guidance, and — crucially — the tamper-evident signed receipt (honestly labelled: a seal is shown
//! only when the receipt actually verifies; disabled deployments and unverified outcomes say so).
//!
//! [`render_heal_report_html`] is a **pure function** (no I/O, no clock, no DB) so it is fully
//! deterministic and unit-tested. Every dynamic value is HTML-escaped, and `pr_url` is rendered as a
//! link only for `http(s)` schemes — the report never emits attacker-controlled markup or `javascript:`
//! URIs even though titles, LLM-generated brief text, and diffs all flow in from untrusted content.

use crate::remediation_brief::{Bilingual, RemediationBrief};

/// Everything the report needs. All `&str` fields are HTML-escaped at render time.
#[derive(Debug, Default)]
pub struct HealReportInput<'a> {
    pub job_id: &'a str,
    pub finding_id: &'a str,
    pub title: &'a str,
    pub severity: &'a str,
    pub cwe: &'a str,
    pub status: &'a str,
    pub verdict: &'a str,
    pub verification_status: &'a str,
    pub channel: &'a str,
    pub pr_url: Option<&'a str>,
    pub branch_name: Option<&'a str>,
    pub attempts: i64,
    pub receipt: &'a str,
    pub digest: &'a str,
    pub attestation_enabled: bool,
    pub receipt_verified: bool,
    pub unified_diff: &'a str,
    pub changed_files: &'a [String],
    pub deleted_paths: &'a [String],
    pub brief: Option<&'a RemediationBrief>,
    /// Pre-formatted timestamp string (ISO-8601 recommended); rendered verbatim (escaped).
    pub generated_at: &'a str,
    /// Advisory governance disposition (auto-merge / open-for-review / hold / block) + bilingual reason.
    pub governance: Option<&'a crate::heal_policy::PolicyDecision>,
}

/// Owned counterpart of [`HealReportInput`] — a single load of everything a completed heal's
/// report needs, so the HTML report, the machine-readable `report.json`, and the SARIF export can
/// all be served from one query pass. Borrow it as a [`HealReportInput`] via [`HealReportData::as_input`].
#[derive(Debug, Clone, Default)]
pub struct HealReportData {
    pub job_id: String,
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub cwe: String,
    pub status: String,
    pub verdict: String,
    pub verification_status: String,
    pub channel: String,
    pub pr_url: Option<String>,
    pub branch_name: Option<String>,
    pub attempts: i64,
    pub receipt: String,
    pub digest: String,
    pub attestation_enabled: bool,
    pub receipt_verified: bool,
    pub unified_diff: String,
    pub changed_files: Vec<String>,
    pub deleted_paths: Vec<String>,
    pub brief: Option<RemediationBrief>,
    pub generated_at: String,
    pub governance: Option<crate::heal_policy::PolicyDecision>,
}

impl HealReportData {
    /// Borrow this owned data as the renderer's input view.
    pub fn as_input(&self) -> HealReportInput<'_> {
        HealReportInput {
            job_id: &self.job_id,
            finding_id: &self.finding_id,
            title: &self.title,
            severity: &self.severity,
            cwe: &self.cwe,
            status: &self.status,
            verdict: &self.verdict,
            verification_status: &self.verification_status,
            channel: &self.channel,
            pr_url: self.pr_url.as_deref(),
            branch_name: self.branch_name.as_deref(),
            attempts: self.attempts,
            receipt: &self.receipt,
            digest: &self.digest,
            attestation_enabled: self.attestation_enabled,
            receipt_verified: self.receipt_verified,
            unified_diff: &self.unified_diff,
            changed_files: &self.changed_files,
            deleted_paths: &self.deleted_paths,
            brief: self.brief.as_ref(),
            generated_at: &self.generated_at,
            governance: self.governance.as_ref(),
        }
    }
}

/// HTML-escape text for element content and double-quoted attributes.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape, then turn newlines into `<br>` for paragraph-style brief text.
fn esc_multiline(s: &str) -> String {
    esc(s).replace('\n', "<br>")
}

/// Only treat `http(s)://…` as a safe, linkable URL. Everything else (e.g. `javascript:`) is text.
fn safe_http_url(u: &str) -> Option<&str> {
    let t = u.trim();
    if t.starts_with("https://") || t.starts_with("http://") {
        Some(t)
    } else {
        None
    }
}

/// Green/red/orange/grey per verdict, matching the front-end VERDICT_META palette.
fn verdict_color(verdict: &str) -> &'static str {
    match verdict {
        "fixed" => "#16a34a",
        "broke_app" => "#dc2626",
        "still_vulnerable" => "#ea580c",
        _ => "#64748b",
    }
}

/// A two-column (EN ltr / HE rtl) block. Each language column is emitted only when that language
/// is non-empty, so a one-sided brief field never renders a blank paragraph under a header; the
/// whole block is empty when both languages are blank.
fn bilingual_block(label_en: &str, label_he: &str, b: &Bilingual) -> String {
    let has_en = !b.en.trim().is_empty();
    let has_he = !b.he.trim().is_empty();
    if !has_en && !has_he {
        return String::new();
    }
    let mut cols = String::new();
    if has_en {
        cols.push_str(&format!(
            r#"<div class="col" dir="ltr" lang="en"><h3>{le}</h3><p>{en}</p></div>"#,
            le = esc(label_en),
            en = esc_multiline(&b.en),
        ));
    }
    if has_he {
        cols.push_str(&format!(
            r#"<div class="col he" dir="rtl" lang="he"><h3>{lh}</h3><p>{he}</p></div>"#,
            lh = esc(label_he),
            he = esc_multiline(&b.he),
        ));
    }
    format!("<section class=\"blk\">{cols}</section>")
}

/// Colourised, escaped unified diff.
fn render_diff(diff: &str) -> String {
    if diff.trim().is_empty() {
        return "<p class=\"muted\">—</p>".to_string();
    }
    let mut out = String::from("<pre class=\"diff\">");
    for line in diff.lines() {
        let cls = if line.starts_with("+++") || line.starts_with("---") {
            "dh"
        } else if line.starts_with("@@") {
            "dm"
        } else if line.starts_with('+') {
            "da"
        } else if line.starts_with('-') {
            "dr"
        } else {
            "dc"
        };
        out.push_str(&format!("<span class=\"{cls}\">{}</span>\n", esc(line)));
    }
    out.push_str("</pre>");
    out
}

/// The tamper-evident receipt panel — honest about what is and isn't proven.
fn render_receipt(input: &HealReportInput<'_>) -> String {
    let short = input.digest.chars().take(16).collect::<String>();
    if !input.attestation_enabled {
        return r#"<div class="seal off"><span class="ico">🔓</span>
      <div><strong>Signing disabled on this deployment</strong>
      <span class="he" dir="rtl">חתימה מושבתת בפריסה זו (ללא מפתח אטסטציה)</span></div></div>"#
            .to_string();
    }
    if input.receipt.is_empty() || input.digest.is_empty() {
        return r#"<div class="seal off"><span class="ico">•</span>
      <div><strong>No signed receipt — this outcome was not a verified fix</strong>
      <span class="he" dir="rtl">אין קבלה חתומה — התוצאה אינה תיקון מאומת</span></div></div>"#
            .to_string();
    }
    if input.receipt_verified {
        format!(
            r#"<div class="seal ok"><span class="ico">🔏</span>
      <div><strong>Verified — HMAC-SHA256 receipt {short}…</strong>
      <span class="he" dir="rtl">מאומת — קבלה חתומה HMAC-SHA256</span></div></div>"#,
            short = esc(&short),
        )
    } else {
        r#"<div class="seal bad"><span class="ico">⚠</span>
      <div><strong>Receipt FAILED verification — do not trust this artifact</strong>
      <span class="he" dir="rtl">אימות הקבלה נכשל — אין לסמוך על מסמך זה</span></div></div>"#
            .to_string()
    }
}

/// Advisory governance disposition strip (auto-merge / open-for-review / hold / block), bilingual.
fn render_governance(input: &HealReportInput<'_>) -> String {
    let Some(g) = input.governance else {
        return String::new();
    };
    let (color, label_en, label_he) = match g.disposition.as_str() {
        "auto_merge" => ("#16a34a", "Auto-merge", "מיזוג אוטומטי"),
        "open_for_review" => ("#0ea5e9", "Open for review", "פתוח לסקירה"),
        "hold" => ("#64748b", "Hold", "מוחזק"),
        "block" => ("#dc2626", "Blocked", "נחסם"),
        _ => ("#64748b", "—", "—"),
    };
    format!(
        r#"<div class="gov" style="border-color:{c}">
      <div class="gov-h" style="color:{c}">⚖ Recommended disposition: {le} · <span class="he" dir="rtl">{lh}</span></div>
      <div class="blk">
        <div class="col" dir="ltr" lang="en"><p>{en}</p></div>
        <div class="col he" dir="rtl" lang="he"><p>{he}</p></div>
      </div>
    </div>"#,
        c = color,
        le = esc(label_en),
        lh = esc(label_he),
        en = esc(&g.reason_en),
        he = esc(&g.reason_he),
    )
}

/// Per-channel connect + apply guidance. The channel actually used is shown first and highlighted.
fn render_channels(input: &HealReportInput<'_>) -> String {
    let Some(brief) = input.brief else {
        return String::new();
    };
    if brief.channels.is_empty() {
        return String::new();
    }
    let mut ordered: Vec<&crate::remediation_brief::ChannelHowTo> = brief.channels.iter().collect();
    ordered.sort_by_key(|c| if c.channel == input.channel { 0 } else { 1 });
    let mut out =
        String::from("<h2>How to apply <span class=\"he\" dir=\"rtl\">איך ליישם</span></h2>");
    for c in ordered {
        let used = c.channel == input.channel;
        out.push_str(&format!(
            "<div class=\"chan{}\"><div class=\"chan-h\"><code>{}</code>{}</div>{}{}</div>",
            if used { " used" } else { "" },
            esc(&c.channel),
            if used {
                " <span class=\"tag\">used for this heal</span>"
            } else {
                ""
            },
            bilingual_block("Connect", "חיבור", &c.connect),
            bilingual_block("Apply", "יישום", &c.apply),
        ));
    }
    out
}

/// One `<tr>` of the metadata table.
fn meta_row(k: &str, v: &str) -> String {
    if v.trim().is_empty() {
        return String::new();
    }
    format!("<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(v))
}

const STYLE: &str = r#"
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;background:#eef2f7;color:#0f172a;font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,"Noto Sans Hebrew",sans-serif}
.wrap{max-width:900px;margin:24px auto;background:#fff;border:1px solid #e2e8f0;border-radius:14px;box-shadow:0 6px 30px rgba(15,23,42,.08);overflow:hidden}
header{padding:22px 28px;background:linear-gradient(135deg,#0f172a,#1e293b);color:#fff}
header h1{margin:0 0 6px;font-size:20px}
header .fid{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:#94a3b8}
.badges{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}
.badge{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
main{padding:22px 28px}
h2{font-size:15px;margin:26px 0 10px;padding-bottom:6px;border-bottom:1px solid #e2e8f0;display:flex;justify-content:space-between;align-items:baseline}
h3{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#64748b;margin:0 0 4px}
.he{font-family:"Noto Sans Hebrew",sans-serif}
.blk{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:10px 0 4px}
.blk .col p{margin:0;white-space:normal}
.blk .col.he{border-right:3px solid #e2e8f0;padding-right:14px}
.seal{display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:10px;margin:6px 0}
.seal .ico{font-size:22px}
.seal .he{display:block;font-size:12px;color:#475569}
.seal.ok{background:#f0fdf4;border:1px solid #16a34a}
.seal.bad{background:#fef2f2;border:1px solid #dc2626}
.seal.off{background:#f8fafc;border:1px solid #cbd5e1}
.gov{border:1px solid #cbd5e1;border-left-width:4px;border-radius:10px;padding:10px 16px;margin:6px 0;background:#f8fafc}
.gov-h{font-weight:600;margin-bottom:4px}
.gov .blk{margin:4px 0 0}
.gov .col p{margin:0;font-size:13px;color:#334155}
pre.diff{background:#0b1120;color:#cbd5e1;border-radius:10px;padding:14px;overflow-x:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre}
pre.diff span{display:block}
.da{color:#4ade80}.dr{color:#f87171}.dm{color:#22d3ee}.dh{color:#a78bfa}.dc{color:#94a3b8}
.files{list-style:none;padding:0;margin:8px 0;font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
.files li{padding:2px 0}
.files .add::before{content:"+ ";color:#16a34a;font-weight:700}
.files .del{color:#94a3b8;text-decoration:line-through}
.files .del::before{content:"- ";color:#dc2626;font-weight:700;text-decoration:none;display:inline-block}
.chan{border:1px solid #e2e8f0;border-radius:10px;padding:12px 16px;margin:10px 0}
.chan.used{border-color:#0ea5e9;background:#f0f9ff}
.chan-h{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.chan-h code{background:#0f172a;color:#e2e8f0;padding:2px 8px;border-radius:6px;font-size:12px}
.tag{font-size:11px;color:#0369a1;font-weight:600}
table.meta{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
table.meta th{text-align:left;color:#64748b;font-weight:600;width:210px;vertical-align:top;padding:5px 8px;border-bottom:1px solid #f1f5f9}
table.meta td{padding:5px 8px;border-bottom:1px solid #f1f5f9;word-break:break-all}
table.meta a{color:#0369a1}
.muted{color:#94a3b8}
footer{padding:16px 28px;background:#f8fafc;border-top:1px solid #e2e8f0;font-size:11px;color:#94a3b8;text-align:center}
@media (max-width:640px){.blk{grid-template-columns:1fr}.blk .col.he{border-right:0;padding-right:0}}
@media print{body{background:#fff}.wrap{border:0;box-shadow:none;margin:0;max-width:none}pre.diff{white-space:pre-wrap}}
"#;

/// Render a complete, self-contained bilingual remediation report as HTML.
pub fn render_heal_report_html(input: &HealReportInput<'_>) -> String {
    let vcolor = verdict_color(input.verdict);
    let sev_color = match input.severity.to_ascii_lowercase().as_str() {
        "critical" => "#7f1d1d",
        "high" => "#dc2626",
        "medium" => "#ea580c",
        "low" => "#ca8a04",
        _ => "#475569",
    };

    // Prefer the brief's structured content; fall back to a bare finding if absent.
    let brief_sections = input
        .brief
        .map(|b| {
            let mut s = String::new();
            // "What was the problem" — only emit the heading if at least one block has content.
            let problem = bilingual_block("Problem", "הבעיה", &b.problem);
            let root = bilingual_block("Root cause", "שורש הבעיה", &b.root_cause);
            let impact = bilingual_block("Impact", "השפעה", &b.impact);
            if !problem.is_empty() || !root.is_empty() || !impact.is_empty() {
                s.push_str("<h2>What was the problem <span class=\"he\" dir=\"rtl\">מה הייתה הבעיה</span></h2>");
                s.push_str(&problem);
                s.push_str(&root);
                s.push_str(&impact);
            }
            // "How the fix works" — likewise gated on non-empty content.
            let fix = bilingual_block("Fix explanation", "הסבר התיקון", &b.fix_explanation);
            if !fix.is_empty() {
                s.push_str("<h2>How the fix works <span class=\"he\" dir=\"rtl\">איך התיקון עובד</span></h2>");
                s.push_str(&fix);
            }
            s
        })
        .unwrap_or_default();

    // Changed / deleted file list.
    let mut files = String::new();
    if !input.changed_files.is_empty() || !input.deleted_paths.is_empty() {
        files.push_str("<ul class=\"files\">");
        for f in input.changed_files {
            files.push_str(&format!("<li class=\"add\">{}</li>", esc(f)));
        }
        for f in input.deleted_paths {
            files.push_str(&format!("<li class=\"del\">{}</li>", esc(f)));
        }
        files.push_str("</ul>");
    }

    // Metadata table (PR shown as a link only for http(s) URLs).
    let pr_cell = match input.pr_url.and_then(safe_http_url) {
        Some(u) => format!(
            "<tr><th>Pull / Merge request</th><td><a href=\"{u}\" rel=\"noreferrer noopener\">{u}</a></td></tr>",
            u = esc(u)
        ),
        None => input
            .pr_url
            .map(|u| meta_row("Pull / Merge request", u))
            .unwrap_or_default(),
    };
    let meta = format!(
        "<table class=\"meta\">{fid}{job}{chan}{st}{vs}{vd}{att}{br}{pr}{dg}{alg}{gen}</table>",
        fid = meta_row("Finding ID", input.finding_id),
        job = meta_row("Heal job", input.job_id),
        chan = meta_row("Delivery channel", input.channel),
        st = meta_row("Job status", input.status),
        vs = meta_row("Verification status", input.verification_status),
        vd = meta_row("Verdict", input.verdict),
        att = meta_row("Attempts", &input.attempts.to_string()),
        br = input
            .branch_name
            .map(|b| meta_row("Branch", b))
            .unwrap_or_default(),
        pr = pr_cell,
        dg = meta_row("Attestation digest", input.digest),
        alg = if input.attestation_enabled {
            meta_row("Attestation alg", "HMAC-SHA256")
        } else {
            String::new()
        },
        gen = meta_row("Generated", input.generated_at),
    );

    // Only invite independent receipt verification when a receipt actually exists and verified —
    // otherwise the seal already says signing is disabled / not a verified fix, and pointing the
    // reader at an attestation endpoint for a receipt that does not exist would be incoherent.
    let footer_verify = if input.receipt_verified {
        format!(
            " — verify the receipt independently at /api/heal-verify/{}/attestation",
            esc(input.job_id)
        )
    } else {
        String::new()
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Remediation report — {title}</title>
<style>{style}</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Remediation report · דוח תיקון</h1>
  <div style="font-size:16px;font-weight:600;margin-top:2px">{title}</div>
  <div class="fid">{fid}</div>
  <div class="badges">
    <span class="badge" style="background:{sev}">{sev_label}</span>
    <span class="badge" style="background:{vc}">{vd}</span>
    {cwe}
  </div>
</header>
<main>
  {receipt}
  {governance}
  {brief}
  <h2>Verified change <span class="he" dir="rtl">השינוי שאומת</span></h2>
  {files}
  {diff}
  {channels}
  <h2>Evidence &amp; metadata <span class="he" dir="rtl">ראיות ונתונים</span></h2>
  {meta}
</main>
<footer>Weissman Cybersecurity · Auto-Heal · self-contained report{footer_verify}</footer>
</div>
</body>
</html>"#,
        title = esc(input.title),
        style = STYLE,
        fid = esc(input.finding_id),
        sev = sev_color,
        sev_label = esc(if input.severity.is_empty() {
            "UNSPECIFIED"
        } else {
            input.severity
        }),
        vc = vcolor,
        vd = esc(if input.verdict.is_empty() {
            "pending"
        } else {
            input.verdict
        }),
        cwe = if input.cwe.trim().is_empty() {
            String::new()
        } else {
            format!(
                "<span class=\"badge\" style=\"background:#334155\">{}</span>",
                esc(input.cwe)
            )
        },
        receipt = render_receipt(input),
        governance = render_governance(input),
        brief = brief_sections,
        files = files,
        diff = render_diff(input.unified_diff),
        channels = render_channels(input),
        meta = meta,
        footer_verify = footer_verify,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation_brief::ChannelHowTo;

    fn bi(en: &str, he: &str) -> Bilingual {
        Bilingual {
            en: en.to_string(),
            he: he.to_string(),
        }
    }

    fn sample_brief() -> RemediationBrief {
        RemediationBrief {
            problem: bi("SQL injection in login.", "הזרקת SQL בהתחברות."),
            root_cause: bi("Unparameterized query.", "שאילתה לא פרמטרית."),
            impact: bi("Full DB read.", "קריאת מסד נתונים מלאה."),
            fix_explanation: bi("Use bound parameters.", "שימוש בפרמטרים קשורים."),
            severity: "high".into(),
            cwe: "CWE-89".into(),
            channels: vec![ChannelHowTo {
                channel: "github_pr".into(),
                connect: bi("Add a token.", "הוסף אסימון."),
                apply: bi("Merge the PR.", "מזג את הבקשה."),
            }],
            generated_at: 0,
            model: "test".into(),
        }
    }

    fn base<'a>() -> HealReportInput<'a> {
        HealReportInput {
            job_id: "job-1",
            finding_id: "F-1",
            title: "Login SQLi",
            severity: "high",
            cwe: "CWE-89",
            status: "completed",
            verdict: "fixed",
            verification_status: "verified_fixed",
            channel: "github_pr",
            pr_url: Some("https://github.com/o/r/pull/7"),
            branch_name: Some("auto-heal/F-1"),
            attempts: 2,
            receipt: "aa",
            digest: "0123456789abcdef0123",
            attestation_enabled: true,
            receipt_verified: true,
            unified_diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-bad\n+good\n",
            changed_files: &[],
            deleted_paths: &[],
            brief: None,
            generated_at: "2026-07-10T00:00:00Z",
            governance: None,
        }
    }

    #[test]
    fn escapes_all_untrusted_fields_no_raw_markup() {
        let brief = RemediationBrief {
            problem: bi("<script>alert(1)</script>", "<img src=x onerror=alert(2)>"),
            ..sample_brief()
        };
        let mut i = base();
        i.title = "<script>steal()</script>";
        i.finding_id = "<b>F</b>";
        i.unified_diff = "+<script>evil()</script>\n-safe";
        i.brief = Some(&brief);
        let html = render_heal_report_html(&i);
        // No raw injected markup survives.
        assert!(!html.contains("<script>steal()"));
        assert!(!html.contains("<script>alert(1)"));
        assert!(!html.contains("<script>evil()"));
        assert!(!html.contains("<img src=x onerror"));
        // Escaped forms are present instead.
        assert!(html.contains("&lt;script&gt;steal()"));
        assert!(html.contains("&lt;script&gt;evil()"));
        // The document itself carries no executable script tag (we emit zero JS).
        assert!(!html.contains("<script"));
    }

    #[test]
    fn both_languages_render_with_dir() {
        let b = sample_brief();
        let mut i = base();
        i.brief = Some(&b);
        let html = render_heal_report_html(&i);
        assert!(html.contains("SQL injection in login."));
        assert!(html.contains("הזרקת SQL בהתחברות."));
        assert!(html.contains("dir=\"rtl\""));
        assert!(html.contains("dir=\"ltr\""));
    }

    #[test]
    fn verified_seal_only_when_actually_verified() {
        let i = base();
        let ok = render_heal_report_html(&i);
        assert!(ok.contains("Verified — HMAC-SHA256"));
        // Footer invites independent verification only when a receipt actually verified.
        assert!(ok.contains("verify the receipt independently"));

        let mut bad = base();
        bad.receipt_verified = false;
        assert!(render_heal_report_html(&bad).contains("FAILED verification"));

        let mut disabled = base();
        disabled.attestation_enabled = false;
        disabled.receipt_verified = false;
        let h = render_heal_report_html(&disabled);
        assert!(h.contains("Signing disabled"));
        assert!(!h.contains("Verified — HMAC-SHA256"));
        // No incoherent "verify the receipt" instruction when there is no receipt.
        assert!(!h.contains("verify the receipt independently"));

        let mut noreceipt = base();
        noreceipt.receipt = "";
        noreceipt.digest = "";
        noreceipt.receipt_verified = false;
        let h2 = render_heal_report_html(&noreceipt);
        assert!(h2.contains("not a verified fix"));
        assert!(!h2.contains("Verified — HMAC-SHA256"));
        assert!(!h2.contains("verify the receipt independently"));
    }

    #[test]
    fn partial_language_and_empty_sections_are_omitted() {
        let brief = RemediationBrief {
            problem: bi("Only English problem.", ""), // he intentionally empty
            root_cause: bi("", ""),
            impact: bi("", ""),
            fix_explanation: bi("", ""),
            channels: vec![],
            ..sample_brief()
        };
        let mut i = base();
        i.brief = Some(&brief);
        let html = render_heal_report_html(&i);
        assert!(html.contains("Only English problem."));
        // Never a blank paragraph, and the empty Hebrew half is omitted (no he column div at all —
        // the only populated field is English-only). Note the Hebrew *heading* span is unrelated.
        assert!(!html.contains("<p></p>"));
        assert!(!html.contains("<div class=\"col he\""));
        // The problem section heading shows (has content); the fix section is fully omitted.
        assert!(html.contains("What was the problem"));
        assert!(!html.contains("How the fix works"));
        assert!(!html.contains("שורש הבעיה")); // root-cause label omitted (empty)
    }

    #[test]
    fn rejects_non_http_pr_url() {
        let mut i = base();
        i.pr_url = Some("javascript:alert(1)");
        let html = render_heal_report_html(&i);
        assert!(!html.contains("href=\"javascript:"));
        assert!(!html.contains("<a href"), "no anchor for a non-http url");
        // still shown as inert text
        assert!(html.contains("javascript:alert(1)"));
    }

    #[test]
    fn diff_lines_are_classified() {
        let i = base();
        let html = render_heal_report_html(&i);
        assert!(html.contains("class=\"da\"")); // + line
        assert!(html.contains("class=\"dr\"")); // - line
        assert!(html.contains("class=\"dm\"")); // @@ hunk
    }

    #[test]
    fn renders_without_brief() {
        let i = base();
        let html = render_heal_report_html(&i);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("Login SQLi"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn self_contained_no_external_resources() {
        let b = sample_brief();
        let mut i = base();
        i.brief = Some(&b);
        let html = render_heal_report_html(&i);
        assert!(html.contains("<style>"));
        assert!(!html.contains("<link"));
        assert!(!html.contains("src=")); // no external scripts/images
        assert!(!html.contains("@import"));
    }

    #[test]
    fn governance_disposition_renders_bilingually() {
        let g = crate::heal_policy::PolicyDecision {
            disposition: "block".to_string(),
            reason_en: "Blocked — the fix broke the app.".to_string(),
            reason_he: "נחסם — התיקון שבר את האפליקציה.".to_string(),
        };
        let mut i = base();
        i.governance = Some(&g);
        let html = render_heal_report_html(&i);
        assert!(html.contains("Recommended disposition"));
        assert!(html.contains("Blocked"));
        assert!(html.contains("נחסם — התיקון שבר את האפליקציה."));
        // No governance strip when none is supplied.
        let plain = render_heal_report_html(&base());
        assert!(!plain.contains("Recommended disposition"));
    }

    #[test]
    fn used_channel_is_flagged() {
        let b = sample_brief();
        let mut i = base();
        i.brief = Some(&b);
        let html = render_heal_report_html(&i);
        assert!(html.contains("used for this heal"));
        assert!(html.contains("chan used"));
    }
}
