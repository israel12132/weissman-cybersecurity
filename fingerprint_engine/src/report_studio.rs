//! Report Studio — the platform's flagship customer deliverable renderer.
//!
//! Produces a **self-contained, printable, bilingual (Hebrew RTL / English LTR)** HTML report from
//! the *full* live finding model (CVSS + vector, CWE/CVE, OWASP, MITRE, KEV/EPSS, status, evidence,
//! remediation, affected assets, crypto audit proof) — not the six-field tuple the legacy native-PDF
//! writer consumes. The browser prints it to a pixel-clean PDF (the deliberately minimal, Chromium-free
//! production image needs no headless browser), so Hebrew renders with embedded fonts on any machine.
//!
//! Design goals, mirroring [`crate::remediation_report`]:
//! * **Pure function** — no I/O, no clock, no DB; every dynamic value is HTML-escaped; deterministic
//!   and fully unit-tested.
//! * **Self-contained** — one `<style>` block, fonts embedded as `data:` URIs, inline SVG charts;
//!   no `<link>`, no `<script>`, no external `src`, no `@import`.
//! * **Honest** — counts, scores and charts derive only from the findings passed in; it never invents
//!   threat-actor names, industry averages or benchmarks.
//! * **White-label safe** — when a tenant brand is set, the vendor mark never appears anywhere.
//!
//! Structure follows the Weissman report-design standard (PTES / OWASP WSTG / NIST SP 800-115) and the
//! Israeli regulatory mapping (Privacy Protection (Data Security) Regulations reg. 5(d); INCD).

use base64::Engine as _;

/// Report language / direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    He,
    En,
}

impl Lang {
    /// Parse a `?lang=` query value; Hebrew for `he|he-il|iw|hebrew`, English otherwise.
    #[must_use]
    pub fn parse(s: Option<&str>) -> Lang {
        match s.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("he" | "he-il" | "iw" | "hebrew" | "עברית") => Lang::He,
            _ => Lang::En,
        }
    }
    fn dir(self) -> &'static str {
        match self {
            Lang::He => "rtl",
            Lang::En => "ltr",
        }
    }
    fn code(self) -> &'static str {
        match self {
            Lang::He => "he",
            Lang::En => "en",
        }
    }
    /// Public language code (`"he"` / `"en"`), e.g. for a download filename.
    #[must_use]
    pub fn code_public(self) -> &'static str {
        self.code()
    }
    /// Pick the language-appropriate literal.
    fn t(self, en: &'static str, he: &'static str) -> &'static str {
        match self {
            Lang::He => he,
            Lang::En => en,
        }
    }
}

/// One finding, with every field a professional report can surface. Empty fields are omitted at
/// render time, so a sparse finding never produces blank rows.
#[derive(Debug, Clone, Default)]
pub struct ReportFinding {
    pub id: i64,
    /// Stable, human-facing id (signature). Falls back to `VLN-{id}` when blank.
    pub finding_id: String,
    pub title: String,
    /// critical | high | medium | low | info (case-insensitive; normalised at render).
    pub severity: String,
    pub source: String,
    pub status: String,
    pub description: String,
    /// Sanitised reproduction / proof-of-breach (e.g. a safe cURL). Rendered as evidence, escaped.
    pub poc_exploit: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: String,
    pub cwe: String,
    pub cve: String,
    pub owasp: String,
    pub mitre: String,
    /// Affected asset / host / URL.
    pub affected: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub kev: bool,
    pub epss: Option<f64>,
    pub discovered_at: String,
    /// Epistemic / proof status: observed | validated_safe_proof | proven | failed_proof | not_applicable.
    pub proof_status: String,
}

/// Cover, scope and provenance metadata for a report.
#[derive(Debug, Clone, Default)]
pub struct ReportMeta {
    pub client_name: String,
    /// White-label brand display name. `Some` ⇒ the vendor mark is fully suppressed.
    pub brand_name: Option<String>,
    pub report_id: String,
    pub version: String,
    /// Pre-formatted issue timestamp (the handler passes Israel-local time); rendered verbatim.
    pub generated_at: String,
    pub assessment_window: Option<String>,
    pub assessment_type: Option<String>,
    pub scope_assets: Vec<String>,
    pub exclusions: Vec<String>,
    pub roe_mode: Option<String>,
    pub crypto_hash: Option<String>,
    pub verify_url: Option<String>,
    pub contact_email: Option<String>,
}

impl ReportMeta {
    fn is_white_label(&self) -> bool {
        self.brand_name
            .as_deref()
            .map(|b| !b.trim().is_empty())
            .unwrap_or(false)
    }
    /// The brand shown on the report; the vendor mark only when no tenant brand is set.
    fn brand(&self) -> &str {
        match self.brand_name.as_deref() {
            Some(b) if !b.trim().is_empty() => b.trim(),
            _ => "Weissman Cybersecurity",
        }
    }
}

// ---------------------------------------------------------------------------
// escaping helpers (identical semantics to remediation_report::esc)
// ---------------------------------------------------------------------------

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

fn esc_multiline(s: &str) -> String {
    esc(s).replace('\n', "<br>")
}

fn safe_http_url(u: &str) -> Option<&str> {
    let t = u.trim();
    if t.starts_with("https://") || t.starts_with("http://") {
        Some(t)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// severity model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sev {
    Crit,
    High,
    Med,
    Low,
    Info,
}

fn sev_of(s: &str) -> Sev {
    let s = s.to_ascii_lowercase();
    if s.contains("crit") {
        Sev::Crit
    } else if s.contains("high") {
        Sev::High
    } else if s.contains("med") {
        Sev::Med
    } else if s.contains("low") {
        Sev::Low
    } else {
        Sev::Info
    }
}

impl Sev {
    fn class(self) -> &'static str {
        match self {
            Sev::Crit => "crit",
            Sev::High => "high",
            Sev::Med => "med",
            Sev::Low => "low",
            Sev::Info => "info",
        }
    }
    fn label(self, lang: Lang) -> &'static str {
        match self {
            Sev::Crit => lang.t("Critical", "קריטי"),
            Sev::High => lang.t("High", "גבוה"),
            Sev::Med => lang.t("Medium", "בינוני"),
            Sev::Low => lang.t("Low", "נמוך"),
            Sev::Info => lang.t("Informational", "מידעי"),
        }
    }
    fn rank(self) -> u8 {
        match self {
            Sev::Crit => 0,
            Sev::High => 1,
            Sev::Med => 2,
            Sev::Low => 3,
            Sev::Info => 4,
        }
    }
}

/// (critical, high, medium, low, info) counts.
fn buckets(findings: &[ReportFinding]) -> (i64, i64, i64, i64, i64) {
    let mut b = (0i64, 0i64, 0i64, 0i64, 0i64);
    for f in findings {
        match sev_of(&f.severity) {
            Sev::Crit => b.0 += 1,
            Sev::High => b.1 += 1,
            Sev::Med => b.2 += 1,
            Sev::Low => b.3 += 1,
            Sev::Info => b.4 += 1,
        }
    }
    b
}

/// 0–100 posture score (continuity with the legacy report: 100 − crit·25 − high·15 − med·5, clamped).
fn score(b: (i64, i64, i64, i64, i64)) -> i64 {
    (100 - b.0 * 25 - b.1 * 15 - b.2 * 5).clamp(0, 100)
}

/// Overall rating word from the worst present severity.
fn posture_word(b: (i64, i64, i64, i64, i64), lang: Lang) -> (&'static str, &'static str) {
    // returns (label, css-class)
    if b.0 > 0 {
        (lang.t("Critical", "קריטי"), "crit")
    } else if b.1 > 0 {
        (lang.t("High", "גבוה"), "high")
    } else if b.2 > 0 {
        (lang.t("Medium", "בינוני"), "med")
    } else if b.3 > 0 {
        (lang.t("Low", "נמוך"), "low")
    } else {
        (lang.t("Managed", "מנוהל"), "ok")
    }
}

// ---------------------------------------------------------------------------
// SVG charts (inline, honest — from real counts only)
// ---------------------------------------------------------------------------

fn donut_svg(b: (i64, i64, i64, i64, i64), lang: Lang) -> String {
    let total = (b.0 + b.1 + b.2 + b.3 + b.4).max(1) as f64;
    let r = 44.0_f64;
    let circ = 2.0 * std::f64::consts::PI * r;
    let segs = [
        (b.0 as f64, "#7A0C2E"),
        (b.1 as f64, "#D92D20"),
        (b.2 as f64, "#F79009"),
        (b.3 as f64, "#CA8A04"),
        (b.4 as f64, "#2E90FA"),
    ];
    let mut out = String::from(
        "<svg viewBox=\"0 0 120 120\" width=\"46mm\" role=\"img\"><circle cx=\"60\" cy=\"60\" r=\"44\" fill=\"none\" stroke=\"#EDF3F9\" stroke-width=\"18\"/>",
    );
    let mut offset = 0.0_f64;
    for (count, color) in segs {
        if count <= 0.0 {
            continue;
        }
        let len = count / total * circ;
        out.push_str(&format!(
            "<circle cx=\"60\" cy=\"60\" r=\"44\" fill=\"none\" stroke=\"{c}\" stroke-width=\"18\" stroke-dasharray=\"{len:.2} {rest:.2}\" stroke-dashoffset=\"{off:.2}\" transform=\"rotate(-90 60 60)\"/>",
            c = color,
            len = len,
            rest = circ - len,
            off = -offset,
        ));
        offset += len;
    }
    let total_i = (b.0 + b.1 + b.2 + b.3 + b.4).to_string();
    out.push_str(&format!(
        "<text x=\"60\" y=\"58\" text-anchor=\"middle\" font-family=\"WReportHead,sans-serif\" font-weight=\"800\" font-size=\"22\" fill=\"#0A1626\">{n}</text><text x=\"60\" y=\"72\" text-anchor=\"middle\" font-family=\"WReport,sans-serif\" font-size=\"8\" fill=\"#5A6B7B\">{lbl}</text></svg>",
        n = esc(&total_i),
        lbl = esc(lang.t("findings", "ממצאים")),
    ));
    out
}

fn bars_svg(b: (i64, i64, i64, i64, i64), lang: Lang) -> String {
    let rows = [
        (Sev::Crit, b.0, "#7A0C2E"),
        (Sev::High, b.1, "#D92D20"),
        (Sev::Med, b.2, "#F79009"),
        (Sev::Low, b.3, "#CA8A04"),
        (Sev::Info, b.4, "#2E90FA"),
    ];
    let max = rows.iter().map(|r| r.1).max().unwrap_or(0).max(1) as f64;
    let mut out = String::from("<div class=\"bars\">");
    for (sev, n, color) in rows {
        let pct = (n as f64 / max * 100.0).round() as i64;
        out.push_str(&format!(
            "<div class=\"bar\"><span>{lbl}</span><div class=\"track\"><div class=\"fill\" style=\"width:{pct}%;background:{c}\">{n}</div></div><span></span></div>",
            lbl = esc(sev.label(lang)),
            pct = pct.max(3),
            c = color,
            n = n,
        ));
    }
    out.push_str("</div>");
    out
}

// ---------------------------------------------------------------------------
// small building blocks
// ---------------------------------------------------------------------------

fn kv_row(k: &str, v: &str) -> String {
    if v.trim().is_empty() {
        return String::new();
    }
    format!("<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(v))
}

fn eyebrow(en: &'static str, _lang: Lang) -> String {
    // English eyebrow kept ASCII for stable print bookmarks; the heading carries the localised title.
    format!("<div class=\"eyebrow\">{}</div>", esc(en))
}

// ---------------------------------------------------------------------------
// embedded fonts (Assistant = body, Heebo = headings) — self-contained data URIs
// ---------------------------------------------------------------------------

fn font_face_css() -> String {
    let body = base64::engine::general_purpose::STANDARD
        .encode(include_bytes!("../assets/fonts/Assistant.ttf"));
    let head = base64::engine::general_purpose::STANDARD
        .encode(include_bytes!("../assets/fonts/Heebo.ttf"));
    format!(
        "@font-face{{font-family:'WReport';src:url(data:font/ttf;base64,{body}) format('truetype');font-weight:200 800;font-display:swap}}@font-face{{font-family:'WReportHead';src:url(data:font/ttf;base64,{head}) format('truetype');font-weight:100 900;font-display:swap}}"
    )
}

const STYLE: &str = r#"
:root{color-scheme:light;
--ink:#0A1626;--ink-soft:#16293C;--body:#23323F;--muted:#5A6B7B;--faint:#8697A6;
--line:#E4EAF1;--paper:#fff;--paper-2:#F6F9FC;--paper-3:#EDF3F9;
--brand:#0E7C86;--brand-strong:#0A5A62;--brand-deep:#073A40;--brand-bright:#16B4BF;--cyan:#22C3D2;
--crit:#7A0C2E;--high:#D92D20;--med:#F79009;--low:#CA8A04;--info:#2E90FA;--ok:#12B76A;
--crit-bg:#FBEAEF;--high-bg:#FEECEA;--med-bg:#FFF4E5;--low-bg:#FEF9E7;--info-bg:#EAF3FF;--ok-bg:#E9F9F1}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:#e9eef4;color:var(--body);font-family:'WReport','Noto Sans Hebrew',Arial,sans-serif;font-size:10.6pt;line-height:1.6}
.sheet{max-width:210mm;margin:0 auto;background:var(--paper)}
@page{size:A4;margin:16mm 0}
h1{font-family:'WReportHead',sans-serif;font-weight:800;color:var(--ink);font-size:20pt;margin:0 0 4mm;line-height:1.2}
h1 .num{color:var(--brand);font-weight:800}
[dir=ltr] h1 .num{margin-right:3mm}[dir=rtl] h1 .num{margin-left:3mm}
h2{font-family:'WReportHead',sans-serif;font-weight:700;color:var(--ink-soft);font-size:13pt;margin:7mm 0 2.5mm}
h3{font-family:'WReportHead',sans-serif;font-weight:700;color:var(--ink-soft);font-size:11pt;margin:5mm 0 2mm}
h4{font-weight:700;color:var(--brand-strong);font-size:10pt;margin:4mm 0 1.5mm}
p{margin:0 0 2.6mm}ul,ol{margin:0 0 2.6mm}[dir=ltr] ul,[dir=ltr] ol{padding-left:5.5mm}[dir=rtl] ul,[dir=rtl] ol{padding-right:5.5mm}
li{margin-bottom:1.1mm}
.lead{font-size:11pt;color:var(--ink-soft)}
.eyebrow{font-size:8pt;letter-spacing:.14em;text-transform:uppercase;color:var(--brand);font-weight:700;margin-bottom:1.5mm}
.rule{height:2px;width:22mm;background:linear-gradient(90deg,var(--brand),var(--cyan));margin:0 0 5mm}
.muted{color:var(--muted)}.small{font-size:8.8pt}.avoid{break-inside:avoid}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:5mm}
.sec{padding:10mm 18mm;break-before:page}
.sec.first{break-before:auto}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:8.6pt;background:var(--paper-3);padding:1px 4px;border-radius:3px;direction:ltr;unicode-bidi:isolate}
pre{direction:ltr;text-align:left;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:8.2pt;line-height:1.45;background:#0B1B26;color:#DCEBF2;padding:3.5mm 4mm;border-radius:5px;margin:2mm 0 3mm;white-space:pre-wrap;word-break:break-word;border-inline-start:3px solid var(--cyan)}
table{width:100%;border-collapse:collapse;margin:1.5mm 0 4mm;font-size:9.3pt}
th,td{border:1px solid var(--line);padding:1.8mm 2.4mm;vertical-align:top}
[dir=ltr] th,[dir=ltr] td{text-align:left}[dir=rtl] th,[dir=rtl] td{text-align:right}
thead th{background:var(--brand-deep);color:#fff;font-weight:700;font-size:8.8pt}
tbody tr:nth-child(even) td{background:var(--paper-2)}
tr{break-inside:avoid}
table.kv th{width:38mm;background:var(--paper-3);color:var(--ink-soft);font-weight:700}
.callout{border-inline-start:4px solid var(--brand);background:var(--paper-2);padding:3mm 4mm;border-radius:4px;margin:3mm 0}
.callout.warn{border-color:var(--high);background:var(--high-bg)}
.callout.ok{border-color:var(--ok);background:var(--ok-bg)}
.callout.note{border-color:var(--info);background:var(--info-bg)}
.sev{display:inline-block;padding:1px 9px;border-radius:999px;color:#fff;font-weight:700;font-size:8.4pt;white-space:nowrap}
.sev.crit{background:var(--crit)}.sev.high{background:var(--high)}.sev.med{background:var(--med);color:#1A1200}
.sev.low{background:var(--low)}.sev.info{background:var(--info)}.sev.ok{background:var(--ok)}
.status{display:inline-block;padding:1px 7px;border-radius:4px;font-size:8.2pt;font-weight:700;border:1px solid;text-transform:capitalize}
.status.open{color:var(--high);border-color:var(--high);background:var(--high-bg)}
.status.fixed{color:#087443;border-color:var(--ok);background:var(--ok-bg)}
.status.other{color:var(--muted);border-color:var(--faint);background:var(--paper-2)}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:3mm;margin:3mm 0 5mm}
.kpi{border:1px solid var(--line);border-radius:6px;padding:2.5mm 3mm}
.kpi b{display:block;font-family:'WReportHead',sans-serif;font-size:19pt;font-weight:800;line-height:1.1}
.kpi small{display:block;color:var(--muted);font-size:8pt;margin-top:1mm}
.kpi.crit b{color:var(--crit)}.kpi.high b{color:var(--high)}.kpi.med b{color:#B45309}.kpi.low b{color:#854D0E}.kpi.info b{color:var(--info)}.kpi.total b{color:var(--brand)}
.posture{display:flex;align-items:center;gap:5mm;border:1px solid var(--line);border-radius:8px;padding:4mm 5mm;background:linear-gradient(90deg,var(--paper-2),#fff);margin:3mm 0}
.posture__score{font-family:'WReportHead',sans-serif;font-size:30pt;font-weight:800;line-height:1}
.posture__score.crit{color:var(--crit)}.posture__score.high{color:var(--high)}.posture__score.med{color:#B45309}.posture__score.low{color:#854D0E}.posture__score.ok{color:var(--ok)}
.posture__label{font-size:8pt;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}
.posture__text{flex:1;font-size:9.6pt}
.chart{display:grid;grid-template-columns:52mm 1fr;gap:6mm;align-items:center;margin:2mm 0 4mm}
.bars{display:grid;gap:1.8mm}
.bar{display:grid;grid-template-columns:26mm 1fr;align-items:center;gap:2mm;font-size:8.8pt}
.bar .track{height:5.5mm;background:var(--paper-3);border-radius:3px;overflow:hidden}
.bar .fill{height:100%;border-radius:3px;display:flex;align-items:center;justify-content:flex-end;padding:0 2mm;color:#fff;font-size:7.5pt;font-weight:700}
.legend{font-size:8.4pt;color:var(--muted)}
.finding{border:1px solid var(--line);border-radius:8px;margin:0 0 6mm;overflow:hidden;break-inside:avoid}
.finding__head{display:grid;grid-template-columns:auto 1fr auto;gap:4mm;align-items:center;padding:3mm 4mm;border-inline-start:5px solid var(--brand)}
.finding.sev-crit .finding__head{border-color:var(--crit);background:var(--crit-bg)}
.finding.sev-high .finding__head{border-color:var(--high);background:var(--high-bg)}
.finding.sev-med .finding__head{border-color:var(--med);background:var(--med-bg)}
.finding.sev-low .finding__head{border-color:var(--low);background:var(--low-bg)}
.finding.sev-info .finding__head{border-color:var(--info);background:var(--info-bg)}
.finding__id{font-family:ui-monospace,Menlo,monospace;font-size:9pt;font-weight:700;color:var(--ink-soft);direction:ltr}
.finding__title{margin:0;font-size:11.5pt;font-family:'WReportHead',sans-serif;font-weight:700;color:var(--ink)}
.finding__body{padding:2mm 4mm 3mm}
.tags{display:flex;flex-wrap:wrap;gap:4px;margin:1mm 0 2mm}
.tag{font-size:7.8pt;font-weight:700;padding:1px 6px;border-radius:4px;background:var(--paper-3);color:var(--ink-soft);direction:ltr}
.tag.kev{background:var(--crit);color:#fff}
.evidence{border:1px dashed var(--faint);border-radius:5px;padding:2.5mm 3mm;background:var(--paper-2);margin:2mm 0 3mm}
.evidence .cap{font-size:8.2pt;color:var(--muted);margin-bottom:1mm}
.toc{list-style:none;padding:0;margin:0}
.toc li{display:flex;justify-content:space-between;padding:1.6mm 0;border-bottom:1px dotted var(--line)}
.toc a{color:var(--ink-soft);text-decoration:none}
.toc .n{color:var(--brand);font-weight:700;min-width:9mm;display:inline-block}
.phase{display:inline-block;padding:1px 7px;border-radius:4px;font-size:8.4pt;font-weight:700;color:#fff}
.phase.p0{background:var(--crit)}.phase.p1{background:var(--high)}.phase.p2{background:#B45309}.phase.p3{background:var(--brand)}
.hash{font-family:ui-monospace,Menlo,monospace;font-size:8pt;direction:ltr;unicode-bidi:isolate;word-break:break-all;color:var(--ink-soft)}
.foot-note{font-size:8.4pt;color:var(--muted);border-top:1px solid var(--line);padding-top:2mm;margin-top:4mm}
/* cover */
.cover{position:relative;height:calc(297mm - 0px);min-height:265mm;color:#EAF3F6;overflow:hidden;padding:22mm 20mm 18mm;display:flex;flex-direction:column;
background:radial-gradient(120% 80% at 82% -8%,rgba(34,195,210,.22) 0,rgba(34,195,210,0) 46%),linear-gradient(160deg,#061019,#0A1E2E 55%,#0E2B39)}
.cover__mark{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--cyan),var(--brand));box-shadow:0 0 0 4px rgba(34,195,210,.15)}
.cover__bn{font-family:'WReportHead',sans-serif;font-weight:700;letter-spacing:.14em;font-size:11pt;margin-top:8px}
.cover__band{margin-top:14mm;font-size:8.5pt;letter-spacing:.12em;color:#B7E9EE;text-transform:uppercase}
.cover__title{margin:8mm 0 0;font-family:'WReportHead',sans-serif;font-weight:800;font-size:31pt;line-height:1.15;color:#fff}
.cover__sub{margin:5mm 0 0;font-size:13.5pt;color:#B7C9D3}
.cover__rule{width:36mm;height:3px;background:linear-gradient(90deg,var(--cyan),transparent);margin:10mm 0}
.cover__client{font-size:12pt}.cover__client b{color:#fff}
.cover__meta{margin-top:auto;display:grid;grid-template-columns:repeat(3,1fr);gap:6mm 8mm;border-top:1px solid rgba(255,255,255,.14);padding-top:8mm}
.cover__meta div{font-size:9pt}.cover__meta small{display:block;color:#8AA3B1;font-size:7.5pt;letter-spacing:.08em;text-transform:uppercase;margin-bottom:2px}
.cover__foot{margin-top:9mm;display:flex;justify-content:space-between;font-size:8pt;color:#8AA3B1}
.cover__class{border:1px solid rgba(255,255,255,.35);border-radius:4px;padding:2px 10px;color:#fff;letter-spacing:.1em;font-size:8pt}
@media screen{.sheet{box-shadow:0 6px 30px rgba(15,23,42,.10);margin:18px auto}}
@media print{body{background:#fff}.sheet{box-shadow:none;margin:0;max-width:none}.cover{min-height:auto;height:265mm}}
"#;

/// Render the flagship client technical security-assessment report as self-contained bilingual HTML.
#[must_use]
pub fn render_client_report_html(
    meta: &ReportMeta,
    findings: &[ReportFinding],
    lang: Lang,
) -> String {
    let b = buckets(findings);
    let sc = score(b);
    let (posture_label, posture_class) = posture_word(b, lang);

    let mut body = String::new();
    body.push_str(&cover_section(
        meta,
        lang,
        lang.t("Security Assessment Report", "דוח מבדק אבטחה"),
        lang.t("Security Assessment Report", "דוח מבדק אבטחה"),
        lang.t(
            "Penetration test & security assessment — findings and remediation",
            "מבדק חדירות והערכת אבטחה — ממצאים והמלצות לתיקון",
        ),
    ));
    body.push_str(&doc_control_section(meta, lang));
    body.push_str(&disclaimer_section(meta, lang));
    body.push_str(&toc_section(lang));
    body.push_str(&exec_summary_section(
        meta,
        findings,
        b,
        sc,
        posture_label,
        posture_class,
        lang,
    ));
    body.push_str(&scope_section(meta, lang));
    body.push_str(&methodology_section(meta, lang));
    body.push_str(&summary_section(findings, b, lang));
    body.push_str(&detailed_findings_section(findings, lang));
    body.push_str(&roadmap_section(b, "6", lang));
    body.push_str(&appendix_section(meta, "7", lang));

    let title = format!(
        "{} — {}",
        lang.t("Security Assessment Report", "דוח מבדק אבטחה"),
        meta.client_name
    );
    wrap_document(&title, &body, lang)
}

/// Aggregate compliance posture (percent aligned per framework) for the board report.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompliancePosture {
    pub soc2: u8,
    pub iso: u8,
    pub gdpr: u8,
}

/// Render the executive / board cyber-risk report — a concise, non-technical dashboard for directors:
/// overall posture, the numbers, top risks in business terms, compliance posture and the roadmap.
#[must_use]
pub fn render_executive_report_html(
    meta: &ReportMeta,
    findings: &[ReportFinding],
    compliance: Option<&CompliancePosture>,
    lang: Lang,
) -> String {
    let b = buckets(findings);
    let sc = score(b);
    let (pl, pc) = posture_word(b, lang);
    let mut body = String::new();
    body.push_str(&cover_section(
        meta,
        lang,
        lang.t("Board Cyber Risk Report", "דוח סיכון סייבר לדירקטוריון"),
        lang.t("Cyber Risk Report", "דוח סיכון סייבר"),
        lang.t(
            "Security posture, top risks & remediation — for the board",
            "תמונת מצב אבטחה, סיכונים מרכזיים והמלצות — להנהלה ולדירקטוריון",
        ),
    ));
    body.push_str(&exec_board_section(
        meta, findings, b, sc, pl, pc, compliance, lang,
    ));
    body.push_str(&roadmap_section(b, "2", lang));
    body.push_str(&appendix_section(meta, "3", lang));
    let title = format!(
        "{} — {}",
        lang.t("Board Cyber Risk Report", "דוח סיכון סייבר לדירקטוריון"),
        meta.client_name
    );
    wrap_document(&title, &body, lang)
}

/// Shared self-contained HTML document shell (fonts + style + sheet) for every report kind.
fn wrap_document(title: &str, body: &str, lang: Lang) -> String {
    format!(
        r#"<!doctype html>
<html lang="{lc}" dir="{dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{title}</title>
<style>{fonts}{style}</style>
</head>
<body>
<div class="sheet">
{body}
</div>
</body>
</html>"#,
        lc = lang.code(),
        dir = lang.dir(),
        title = esc(title),
        fonts = font_face_css(),
        style = STYLE,
        body = body,
    )
}

// ---------------------------------------------------------------------------
// sections
// ---------------------------------------------------------------------------

fn cover_section(meta: &ReportMeta, lang: Lang, band: &str, title: &str, sub: &str) -> String {
    let brand = esc(meta.brand());
    let vendor_sub = if meta.is_white_label() {
        String::new()
    } else {
        format!(
            "<div class=\"cover__brandsub\" style=\"font-size:8.5pt;color:#9DB4C0;letter-spacing:.04em\">{}</div>",
            esc(lang.t(
                "Offensive Security · Assessment &amp; Assurance",
                "התקפי · הערכה ואבטחה"
            ))
        )
    };
    let mut meta_cells = String::new();
    let cell = |s: &mut String, label: &str, val: &str| {
        if !val.trim().is_empty() {
            s.push_str(&format!(
                "<div><small>{}</small>{}</div>",
                esc(label),
                esc(val)
            ));
        }
    };
    cell(
        &mut meta_cells,
        lang.t("Report ID", "מזהה דוח"),
        &meta.report_id,
    );
    cell(
        &mut meta_cells,
        lang.t("Version", "גרסה"),
        if meta.version.is_empty() {
            "1.0"
        } else {
            &meta.version
        },
    );
    cell(
        &mut meta_cells,
        lang.t("Issued", "תאריך הנפקה"),
        &meta.generated_at,
    );
    if let Some(w) = &meta.assessment_window {
        cell(
            &mut meta_cells,
            lang.t("Assessment window", "חלון הבדיקה"),
            w,
        );
    }
    if let Some(t) = &meta.assessment_type {
        cell(&mut meta_cells, lang.t("Assessment type", "סוג הבדיקה"), t);
    }
    cell(
        &mut meta_cells,
        lang.t("Prepared by", "הוכן על ידי"),
        meta.brand(),
    );

    format!(
        r#"<section class="cover">
  <div class="cover__mark"></div>
  <div class="cover__bn">{brand}</div>
  {vendor_sub}
  <div class="cover__band">{band}</div>
  <h1 class="cover__title" style="border:0;padding:0">{title}</h1>
  <div class="cover__sub">{sub}</div>
  <div class="cover__rule"></div>
  <div class="cover__client">{prep} <b>{client}</b></div>
  <div class="cover__meta">{cells}</div>
  <div class="cover__foot">
    <span class="cover__class">{cls}</span>
    <span>{brand}</span>
  </div>
</section>"#,
        brand = brand,
        vendor_sub = vendor_sub,
        band = esc(band),
        title = esc(title),
        sub = esc(sub),
        prep = esc(lang.t("Prepared for:", "הוכן עבור:")),
        client = esc(&meta.client_name),
        cells = meta_cells,
        cls = esc(lang.t("Confidential — Client Use Only", "סודי — לשימוש הלקוח בלבד")),
    )
}

fn doc_control_section(meta: &ReportMeta, lang: Lang) -> String {
    let rows = format!(
        "{}{}{}{}{}{}",
        kv_row(lang.t("Document ID", "מזהה מסמך"), &meta.report_id),
        kv_row(
            lang.t("Version", "גרסה"),
            if meta.version.is_empty() {
                "1.0"
            } else {
                &meta.version
            }
        ),
        kv_row(
            lang.t("Classification", "סיווג"),
            lang.t("Confidential — Client Use Only", "סודי — לשימוש הלקוח בלבד")
        ),
        kv_row(lang.t("Client", "לקוח"), &meta.client_name),
        kv_row(lang.t("Prepared by", "הוכן על ידי"), meta.brand()),
        kv_row(lang.t("Issued", "הופק"), &meta.generated_at),
    );
    format!(
        r#"<section class="sec first" dir="{dir}">
  {eyebrow}
  <h1>{h}</h1><div class="rule"></div>
  <table class="kv">{rows}</table>
  {contact}
</section>"#,
        dir = lang.dir(),
        eyebrow = eyebrow("Document Control", lang),
        h = esc(lang.t("Document control", "בקרת מסמך")),
        rows = rows,
        contact = meta
            .contact_email
            .as_deref()
            .filter(|e| !e.trim().is_empty())
            .map(|e| format!(
                "<p class=\"small muted\">{} {}</p>",
                esc(lang.t("Contact:", "איש קשר:")),
                esc(e)
            ))
            .unwrap_or_default(),
    )
}

fn disclaimer_section(meta: &ReportMeta, lang: Lang) -> String {
    let brand = esc(meta.brand());
    format!(
        r#"<section class="sec" dir="{dir}">
  {eyebrow}
  <h1>{h}</h1><div class="rule"></div>
  <h2>{c_h}</h2><p>{c_b}</p>
  <h2>{d_h}</h2><p>{d_b}</p>
</section>"#,
        dir = lang.dir(),
        eyebrow = eyebrow("Confidentiality & Disclaimer", lang),
        h = esc(lang.t("Confidentiality & disclaimer", "הצהרת סודיות והגבלת אחריות")),
        c_h = esc(lang.t("Confidentiality", "סודיות")),
        c_b = format!(
            "{} {} {}",
            esc(lang.t(
                "This document is confidential and the property of",
                "מסמך זה סודי ומהווה רכוש של"
            )),
            brand,
            esc(lang.t(
                "and the client. It contains sensitive details of security weaknesses; do not redistribute without written consent.",
                "והלקוח. הוא מכיל פרטים רגישים על חולשות אבטחה; אין להפיצו ללא אישור בכתב."
            ))
        ),
        d_h = esc(lang.t("Disclaimer", "הגבלת אחריות")),
        d_b = esc(lang.t(
            "A security assessment is a point-in-time snapshot. Findings reflect the environment during the testing window and do not account for later changes. The absence of a finding is not a guarantee that no weakness exists. Testing was performed under written authorisation.",
            "מבדק אבטחה הוא תמונת מצב נקודתית. הממצאים משקפים את הסביבה בחלון הבדיקה ואינם מתייחסים לשינויים שלאחר מכן. אי-זיהוי חולשה אינו ערובה לאי-קיומה. הבדיקה בוצעה בהתאם להרשאה בכתב."
        )),
    )
}

fn toc_section(lang: Lang) -> String {
    let items = [
        (lang.t("Executive summary", "תקציר מנהלים"), "s-exec"),
        (
            lang.t("Scope & rules of engagement", "היקף וכללי התקשרות"),
            "s-scope",
        ),
        (
            lang.t("Methodology & risk rating", "מתודולוגיה ודירוג סיכון"),
            "s-method",
        ),
        (lang.t("Findings summary", "סיכום ממצאים"), "s-summary"),
        (lang.t("Detailed findings", "ממצאים מפורטים"), "s-findings"),
        (lang.t("Remediation roadmap", "תוכנית תיקון"), "s-roadmap"),
        (
            lang.t(
                "Appendix — definitions & regulatory mapping",
                "נספח — הגדרות ומיפוי רגולטורי",
            ),
            "s-appendix",
        ),
    ];
    let mut lis = String::new();
    for (i, (label, anchor)) in items.iter().enumerate() {
        lis.push_str(&format!(
            "<li><span><span class=\"n\">{}</span>{}</span></li>",
            i + 1,
            esc(label),
        ));
        let _ = anchor;
    }
    format!(
        r#"<section class="sec" dir="{dir}">
  {eyebrow}
  <h1>{h}</h1><div class="rule"></div>
  <ul class="toc">{lis}</ul>
</section>"#,
        dir = lang.dir(),
        eyebrow = eyebrow("Table of Contents", lang),
        h = esc(lang.t("Table of contents", "תוכן עניינים")),
        lis = lis,
    )
}

#[allow(clippy::too_many_arguments)]
fn exec_summary_section(
    meta: &ReportMeta,
    findings: &[ReportFinding],
    b: (i64, i64, i64, i64, i64),
    sc: i64,
    posture_label: &str,
    posture_class: &str,
    lang: Lang,
) -> String {
    let total = b.0 + b.1 + b.2 + b.3 + b.4;
    // Top risks = the highest-severity findings, in order, up to 3.
    let mut ordered: Vec<&ReportFinding> = findings.iter().collect();
    ordered.sort_by_key(|f| sev_of(&f.severity).rank());
    let mut top_rows = String::new();
    for (i, f) in ordered.iter().take(3).enumerate() {
        let s = sev_of(&f.severity);
        top_rows.push_str(&format!(
            "<tr><td>{n}</td><td><b>{title}</b>{desc}</td><td><code>{fid}</code></td><td><span class=\"sev {cls}\">{sev}</span></td></tr>",
            n = i + 1,
            title = esc(&f.title),
            desc = if f.description.trim().is_empty() {
                String::new()
            } else {
                format!("<div class=\"small muted\">{}</div>", esc(&first_sentence(&f.description)))
            },
            fid = esc(&finding_ref(f)),
            cls = s.class(),
            sev = esc(s.label(lang)),
        ));
    }
    let top_block = if top_rows.is_empty() {
        format!(
            "<div class=\"callout ok\">{}</div>",
            esc(lang.t(
                "No exploitable findings were identified in scope during this assessment.",
                "לא זוהו ממצאים הניתנים לניצול במסגרת הבדיקה."
            ))
        )
    } else {
        format!(
            "<h2>{h}</h2><table><thead><tr><th style=\"width:8mm\">#</th><th>{risk}</th><th style=\"width:28mm\">{id}</th><th style=\"width:20mm\">{sev}</th></tr></thead><tbody>{rows}</tbody></table>",
            h = esc(lang.t("Top risks", "הסיכונים המרכזיים")),
            risk = esc(lang.t("Risk", "סיכון")),
            id = esc(lang.t("Finding", "ממצא")),
            sev = esc(lang.t("Severity", "חומרה")),
            rows = top_rows,
        )
    };

    let lead = format!(
        "{} {}. {} {} {}.",
        esc(meta.brand()),
        esc(lang.t(
            "performed a security assessment for",
            "ביצעה מבדק אבטחה עבור"
        )),
        esc(&meta.client_name),
        esc(lang.t("The assessment identified", "הבדיקה זיהתה")),
        format!("{} {}", total, esc(lang.t("findings", "ממצאים"))),
    );

    format!(
        r#"<section class="sec" id="s-exec" dir="{dir}">
  {eyebrow}
  <h1><span class="num">1</span>{h}</h1><div class="rule"></div>
  <p class="lead">{lead}</p>
  <div class="posture avoid">
    <div><div class="posture__label">{ov}</div><div class="posture__score {pc}">{pl}</div></div>
    <div class="posture__text">{postxt}</div>
    <div style="text-align:center"><div class="posture__score {pc}" style="font-size:22pt">{sc}</div><div class="posture__label">{scl}</div></div>
  </div>
  <div class="kpis avoid">
    <div class="kpi total"><b>{total}</b><small>{c_total}</small></div>
    <div class="kpi crit"><b>{c}</b><small>{c_crit}</small></div>
    <div class="kpi high"><b>{h1}</b><small>{c_high}</small></div>
    <div class="kpi med"><b>{m}</b><small>{c_med}</small></div>
    <div class="kpi low"><b>{l}</b><small>{c_low}</small></div>
  </div>
  <div class="chart avoid">{donut}<div>{bars}<div class="legend" style="margin-top:2mm">{leg}</div></div></div>
  {top_block}
</section>"#,
        dir = lang.dir(),
        eyebrow = eyebrow("Executive Summary", lang),
        h = esc(lang.t("Executive summary", "תקציר מנהלים")),
        lead = lead,
        ov = esc(lang.t("Overall risk", "דירוג סיכון כולל")),
        pc = posture_class,
        pl = esc(posture_label),
        postxt = esc(posture_sentence(b, lang)),
        sc = sc,
        scl = esc(lang.t("Security score", "ציון אבטחה")),
        total = total,
        c_total = esc(lang.t("Findings total", "סה״כ ממצאים")),
        c = b.0,
        c_crit = esc(lang.t("Critical", "קריטי")),
        h1 = b.1,
        c_high = esc(lang.t("High", "גבוה")),
        m = b.2,
        c_med = esc(lang.t("Medium", "בינוני")),
        l = b.3 + b.4,
        c_low = esc(lang.t("Low / Info", "נמוך / מידעי")),
        donut = donut_svg(b, lang),
        bars = bars_svg(b, lang),
        leg = esc(lang.t(
            "Distribution of findings by severity (live counts).",
            "התפלגות הממצאים לפי חומרה (ספירה חיה)."
        )),
        top_block = top_block,
    )
}

fn posture_sentence(b: (i64, i64, i64, i64, i64), lang: Lang) -> &'static str {
    if b.0 > 0 {
        lang.t(
            "Critical findings were identified that could lead to system compromise or exposure of sensitive data; immediate action is required.",
            "זוהו ממצאים קריטיים העלולים להוביל להשתלטות על מערכת או לחשיפת מידע רגיש; נדרשת פעולה מיידית.",
        )
    } else if b.1 > 0 {
        lang.t(
            "High-severity findings require prompt remediation to reduce meaningful risk to the business.",
            "ממצאים בחומרה גבוהה מחייבים תיקון מהיר להפחתת סיכון משמעותי לעסק.",
        )
    } else if b.2 + b.3 + b.4 > 0 {
        lang.t(
            "No critical or high-severity findings were identified; remaining items are hardening opportunities.",
            "לא זוהו ממצאים קריטיים או גבוהים; הפריטים שנותרו הם הזדמנויות להקשחה.",
        )
    } else {
        lang.t(
            "No findings were identified in scope during this assessment.",
            "לא זוהו ממצאים במסגרת הבדיקה.",
        )
    }
}

fn scope_section(meta: &ReportMeta, lang: Lang) -> String {
    let mut assets = String::new();
    for a in &meta.scope_assets {
        if !a.trim().is_empty() {
            assets.push_str(&format!("<li>{}</li>", esc(a)));
        }
    }
    let assets_block = if assets.is_empty() {
        format!(
            "<p class=\"muted\">{}</p>",
            esc(lang.t(
                "Scope assets are recorded in the engagement record.",
                "נכסי ההיקף מתועדים ברשומת ההתקשרות."
            ))
        )
    } else {
        format!("<ul>{}</ul>", assets)
    };
    let mut excl = String::new();
    for e in &meta.exclusions {
        if !e.trim().is_empty() {
            excl.push_str(&format!("<li>{}</li>", esc(e)));
        }
    }
    let excl_block = if excl.is_empty() {
        String::new()
    } else {
        format!(
            "<h2>{}</h2><ul>{}</ul>",
            esc(lang.t("Out of scope", "מחוץ להיקף")),
            excl
        )
    };
    let roe = meta
        .roe_mode
        .as_deref()
        .filter(|r| !r.trim().is_empty())
        .map(|r| kv_row(lang.t("Rules of engagement", "כללי התקשרות"), r))
        .unwrap_or_default();
    let window = meta
        .assessment_window
        .as_deref()
        .map(|w| kv_row(lang.t("Assessment window", "חלון הבדיקה"), w))
        .unwrap_or_default();
    let atype = meta
        .assessment_type
        .as_deref()
        .map(|t| kv_row(lang.t("Assessment type", "סוג הבדיקה"), t))
        .unwrap_or_default();
    format!(
        r#"<section class="sec" id="s-scope" dir="{dir}">
  {eyebrow}
  <h1><span class="num">2</span>{h}</h1><div class="rule"></div>
  <table class="kv">{window}{atype}{roe}</table>
  <h2>{in_scope}</h2>{assets}
  {excl}
</section>"#,
        dir = lang.dir(),
        eyebrow = eyebrow("Scope & Rules of Engagement", lang),
        h = esc(lang.t("Scope & rules of engagement", "היקף וכללי התקשרות")),
        window = window,
        atype = atype,
        roe = roe,
        in_scope = esc(lang.t("In-scope assets", "נכסים בהיקף")),
        assets = assets_block,
        excl = excl_block,
    )
}

fn methodology_section(meta: &ReportMeta, lang: Lang) -> String {
    let rows = [
        (
            lang.t("Critical", "קריטי"),
            "9.0–10.0",
            "crit",
            lang.t(
                "Straightforward exploitation, typically system compromise or broad exposure of sensitive data.",
                "ניצול פשוט, בדרך כלל השתלטות על מערכת או חשיפה רחבה של מידע רגיש.",
            ),
            lang.t("≤ 7 days", "עד 7 ימים"),
        ),
        (
            lang.t("High", "גבוה"),
            "7.0–8.9",
            "high",
            lang.t(
                "Exploitable under limited conditions with significant impact on confidentiality, integrity or availability.",
                "ניתן לניצול בתנאים מוגבלים עם השפעה משמעותית על סודיות, שלמות או זמינות.",
            ),
            lang.t("≤ 30 days", "עד 30 יום"),
        ),
        (
            lang.t("Medium", "בינוני"),
            "4.0–6.9",
            "med",
            lang.t(
                "Requires additional conditions or chaining; limited impact on its own.",
                "דורש תנאים נוספים או שרשור; השפעה מוגבלת בפני עצמו.",
            ),
            lang.t("≤ 90 days", "עד 90 יום"),
        ),
        (
            lang.t("Low", "נמוך"),
            "0.1–3.9",
            "low",
            lang.t(
                "Minimal impact or impractical exploitation; defence-in-depth.",
                "השפעה מזערית או ניצול לא מעשי; הגנה לעומק.",
            ),
            lang.t("Backlog", "מועד תחזוקה"),
        ),
        (
            lang.t("Informational", "מידעי"),
            "—",
            "info",
            lang.t(
                "Not a direct weakness; observations and hardening advice.",
                "אינו חולשה ישירה; תצפיות והמלצות להקשחה.",
            ),
            lang.t("Discretionary", "לפי שיקול דעת"),
        ),
    ];
    let mut trs = String::new();
    for (label, band, cls, def, sla) in rows {
        trs.push_str(&format!(
            "<tr><td><span class=\"sev {cls}\">{label}</span></td><td>{band}</td><td>{def}</td><td>{sla}</td></tr>",
            cls = cls,
            label = esc(label),
            band = esc(band),
            def = esc(def),
            sla = esc(sla),
        ));
    }
    format!(
        r#"<section class="sec" id="s-method" dir="{dir}">
  {eyebrow}
  <h1><span class="num">3</span>{h}</h1><div class="rule"></div>
  <p>{intro}</p>
  <h2>{scale}</h2>
  <table><thead><tr><th style="width:22mm">{c_sev}</th><th style="width:20mm">CVSS</th><th>{c_def}</th><th style="width:26mm">{c_sla}</th></tr></thead><tbody>{trs}</tbody></table>
  <p class="small muted">{note}</p>
</section>"#,
        dir = lang.dir(),
        eyebrow = eyebrow("Methodology & Risk Rating", lang),
        h = esc(lang.t("Methodology & risk rating", "מתודולוגיה ודירוג סיכון")),
        intro = format!(
            "{} {} {}",
            esc(lang.t("Testing followed the", "הבדיקה בוצעה על-פי מתודולוגיית")),
            esc(meta.brand()),
            esc(lang.t(
                "methodology, aligned with PTES, the OWASP Web Security Testing Guide and NIST SP 800-115. Findings are mapped to CWE, the OWASP Top 10 and, where relevant, MITRE ATT&CK, with CVSS v3.1 as the technical severity measure.",
                ", בהתאמה ל-PTES, למדריך OWASP WSTG ול-NIST SP 800-115. הממצאים ממופים ל-CWE, ל-OWASP Top 10 ובמידת הצורך ל-MITRE ATT&CK, עם CVSS v3.1 כמדד החומרה הטכני."
            )),
        ),
        scale = esc(lang.t("Severity scale & remediation SLA", "סולם חומרה ו-SLA לתיקון")),
        c_sev = esc(lang.t("Severity", "חומרה")),
        c_def = esc(lang.t("Definition", "הגדרה")),
        c_sla = esc(lang.t("Target fix", "יעד תיקון")),
        trs = trs,
        note = esc(lang.t(
            "Technical CVSS severity may be adjusted for business context; where adjusted, the rationale is stated in the finding.",
            "חומרת ה-CVSS הטכנית עשויה להיות מותאמת להקשר העסקי; במקרה של התאמה, הנימוק מצוין בגוף הממצא."
        )),
    )
}

fn summary_section(findings: &[ReportFinding], b: (i64, i64, i64, i64, i64), lang: Lang) -> String {
    let ordered = sort_findings(findings);
    let mut rows = String::new();
    for f in &ordered {
        let s = sev_of(&f.severity);
        rows.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{title}</td><td><span class=\"sev {cls}\">{sev}</span></td><td>{cvss}</td><td>{proof}</td><td>{asset}</td><td>{status}</td></tr>",
            id = esc(&finding_ref(f)),
            title = esc(&f.title),
            cls = s.class(),
            sev = esc(s.label(lang)),
            cvss = f
                .cvss_score
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "—".into()),
            proof = proof_badge_tag(&f.proof_status, lang),
            asset = esc(&truncate(&f.affected, 34)),
            status = status_badge(&f.status, lang),
        ));
    }
    let body = if rows.is_empty() {
        format!(
            "<div class=\"callout ok\">{}</div>",
            esc(lang.t(
                "No findings to list — the assessment did not identify weaknesses in scope.",
                "אין ממצאים לרשימה — הבדיקה לא זיהתה חולשות במסגרת ההיקף."
            ))
        )
    } else {
        format!(
            "<table><thead><tr><th style=\"width:22mm\">{id}</th><th>{title}</th><th style=\"width:17mm\">{sev}</th><th style=\"width:12mm\">CVSS</th><th style=\"width:16mm\">{proof}</th><th style=\"width:28mm\">{asset}</th><th style=\"width:18mm\">{status}</th></tr></thead><tbody>{rows}</tbody></table>",
            id = esc(lang.t("ID", "מזהה")),
            title = esc(lang.t("Finding", "ממצא")),
            sev = esc(lang.t("Severity", "חומרה")),
            proof = esc(lang.t("Proof", "הוכחה")),
            asset = esc(lang.t("Affected asset", "נכס מושפע")),
            status = esc(lang.t("Status", "סטטוס")),
            rows = rows,
        )
    };
    format!(
        r#"<section class="sec" id="s-summary" dir="{dir}">
  {eyebrow}
  <h1><span class="num">4</span>{h}</h1><div class="rule"></div>
  {body}
  {assurance}
  <div class="chart avoid" style="margin-top:4mm">{donut}<div>{bars}</div></div>
</section>"#,
        dir = lang.dir(),
        eyebrow = eyebrow("Findings Summary", lang),
        h = esc(lang.t("Findings summary", "סיכום ממצאים")),
        body = body,
        assurance = assurance_block(findings, lang),
        donut = donut_svg(b, lang),
        bars = bars_svg(b, lang),
    )
}

/// A compact breakdown by status and by proof/epistemic status, so the reader sees the full
/// disposition of every finding — how many are open vs fixed vs false-positive, proven vs observed.
fn assurance_block(findings: &[ReportFinding], lang: Lang) -> String {
    if findings.is_empty() {
        return String::new();
    }
    let total = findings.len();
    let mut open = 0;
    let mut fixed = 0;
    let mut fp = 0;
    let mut other = 0;
    let (mut proven, mut validated, mut observed, mut failed, mut na) = (0, 0, 0, 0, 0);
    for f in findings {
        let s = f.status.trim().to_ascii_lowercase();
        if is_fp(f) {
            fp += 1;
        } else if s.contains("fixed")
            || s.contains("remed")
            || s.contains("closed")
            || s.contains("resolved")
        {
            fixed += 1;
        } else if s.is_empty() || s == "open" {
            open += 1;
        } else {
            other += 1;
        }
        match f.proof_status.trim().to_ascii_lowercase().as_str() {
            "proven" => proven += 1,
            "validated_safe_proof" | "validated" => validated += 1,
            "failed_proof" => failed += 1,
            "not_applicable" | "na" | "n/a" => na += 1,
            _ => observed += 1,
        }
    }
    let fp_rate = (fp as f64 / total as f64 * 100.0).round() as i64;
    let chip = |label: &str, n: usize, color: &str| {
        if n == 0 {
            String::new()
        } else {
            format!(
                "<span class=\"tag\" style=\"background:{color};color:#fff\">{}: {n}</span>",
                esc(label)
            )
        }
    };
    format!(
        "<div class=\"grid2 avoid\" style=\"margin-top:3mm\"><div><h4>{sh}</h4><div class=\"tags\">{open}{fixed}{other}{fp}</div></div><div><h4>{ph}</h4><div class=\"tags\">{proven}{validated}{observed}{failed}{na}</div></div></div><p class=\"small muted\">{note}</p>",
        sh = esc(lang.t("By status", "לפי סטטוס")),
        ph = esc(lang.t("By proof / assurance", "לפי הוכחה / ודאות")),
        open = chip(lang.t("Open", "פתוח"), open, "#D92D20"),
        fixed = chip(lang.t("Fixed", "תוקן"), fixed, "#12B76A"),
        other = chip(lang.t("In progress", "בתהליך"), other, "#B45309"),
        fp = chip(lang.t("False positive", "חיובי שגוי"), fp, "#5A6B7B"),
        proven = chip(lang.t("Proven", "מוכח"), proven, "#087443"),
        validated = chip(lang.t("Validated", "אומת"), validated, "#0E7C86"),
        observed = chip(lang.t("Observed", "נצפה"), observed, "#5A6B7B"),
        failed = chip(lang.t("Proof failed", "הוכחה נכשלה"), failed, "#B45309"),
        na = chip(lang.t("N/A", "לא רלוונטי"), na, "#8697A6"),
        note = format!(
            "{} {} · {} {}%",
            esc(lang.t("Total findings recorded:", "סה״כ ממצאים שנרשמו:")),
            total,
            esc(lang.t("false-positive rate", "שיעור חיובי שגוי")),
            fp_rate,
        ),
    )
}

fn detailed_findings_section(findings: &[ReportFinding], lang: Lang) -> String {
    let ordered = sort_findings(findings);
    let mut cards = String::new();
    for f in &ordered {
        cards.push_str(&finding_card(f, lang));
    }
    if cards.is_empty() {
        cards = format!(
            "<div class=\"callout ok\">{}</div>",
            esc(lang.t(
                "No detailed findings — nothing exploitable was identified in scope.",
                "אין ממצאים מפורטים — לא זוהה דבר הניתן לניצול במסגרת ההיקף."
            ))
        );
    }
    format!(
        r#"<section class="sec" id="s-findings" dir="{dir}">
  {eyebrow}
  <h1><span class="num">5</span>{h}</h1><div class="rule"></div>
  {cards}
</section>"#,
        dir = lang.dir(),
        eyebrow = eyebrow("Detailed Findings", lang),
        h = esc(lang.t("Detailed findings", "ממצאים מפורטים")),
        cards = cards,
    )
}

fn finding_card(f: &ReportFinding, lang: Lang) -> String {
    let s = sev_of(&f.severity);
    // tags: CWE, CVE, OWASP, MITRE, KEV, EPSS
    let mut tags = String::new();
    let mut tag = |val: &str, extra: &str| {
        if !val.trim().is_empty() {
            tags.push_str(&format!("<span class=\"tag {extra}\">{}</span>", esc(val)));
        }
    };
    tag(&f.cwe, "");
    tag(&f.cve, "");
    tag(&f.owasp, "");
    tag(&f.mitre, "");
    if f.kev {
        tags.push_str("<span class=\"tag kev\">KEV</span>");
    }
    if let Some(e) = f.epss {
        tags.push_str(&format!(
            "<span class=\"tag\">EPSS {:.0}%</span>",
            (e * 100.0).round()
        ));
    }
    // Epistemic / proof status on every card — proven vs observed vs proof-failed.
    tags.push_str(&proof_badge_tag(&f.proof_status, lang));
    let tags_block = if tags.is_empty() {
        String::new()
    } else {
        format!("<div class=\"tags\">{tags}</div>")
    };

    // metadata rows
    let cvss_cell = match (&f.cvss_score, f.cvss_vector.trim()) {
        (Some(v), vec) if !vec.is_empty() => format!("{v:.1} · {}", vec),
        (Some(v), _) => format!("{v:.1}"),
        (None, vec) if !vec.is_empty() => vec.to_string(),
        _ => String::new(),
    };
    let meta = format!(
        "<table class=\"kv\">{sev}{cvss}{asset}{src}{disc}{status}</table>",
        sev = format!(
            "<tr><th>{}</th><td><span class=\"sev {cls}\">{lbl}</span></td></tr>",
            esc(lang.t("Severity", "חומרה")),
            cls = s.class(),
            lbl = esc(s.label(lang)),
        ),
        cvss = kv_row(lang.t("CVSS", "CVSS"), &cvss_cell),
        asset = kv_row(lang.t("Affected asset", "נכס מושפע"), &f.affected),
        src = kv_row(lang.t("Detected by", "זוהה על ידי"), &f.source),
        disc = kv_row(lang.t("Discovered", "התגלה"), &f.discovered_at),
        status = if f.status.trim().is_empty() {
            String::new()
        } else {
            format!(
                "<tr><th>{}</th><td>{}</td></tr>",
                esc(lang.t("Status", "סטטוס")),
                status_badge(&f.status, lang)
            )
        },
    );

    let desc = section_block(lang.t("Description", "תיאור"), &f.description);
    let remediation = section_block(lang.t("Remediation", "המלצת תיקון"), &f.remediation);
    let evidence = if f.poc_exploit.trim().is_empty() {
        String::new()
    } else {
        format!(
            "<h4>{h}</h4><div class=\"evidence\"><div class=\"cap\">{cap}</div><pre>{poc}</pre></div>",
            h = esc(lang.t("Evidence / proof", "ראיות / הוכחה")),
            cap = esc(lang.t(
                "Sanitised reproduction (secrets redacted).",
                "שחזור מבוקר (ערכים רגישים הוסתרו)."
            )),
            poc = esc(&f.poc_exploit),
        )
    };
    let refs = if f.references.is_empty() {
        String::new()
    } else {
        let mut items = String::new();
        for r in &f.references {
            match safe_http_url(r) {
                Some(u) => items.push_str(&format!(
                    "<li><a href=\"{u}\" rel=\"noreferrer noopener\">{u}</a></li>",
                    u = esc(u)
                )),
                None => items.push_str(&format!("<li>{}</li>", esc(r))),
            }
        }
        format!(
            "<h4>{}</h4><ul class=\"small\">{}</ul>",
            esc(lang.t("References", "הפניות")),
            items
        )
    };

    let fp_class = if is_fp(f) { " fp" } else { "" };
    format!(
        r#"<article class="finding sev-{cls}{fp} avoid">
  <div class="finding__head">
    <div class="finding__id">{id}</div>
    <div><h3 class="finding__title">{title}</h3></div>
    <div><span class="sev {cls}">{sev}</span></div>
  </div>
  <div class="finding__body">
    {tags}
    {meta}
    {desc}{evidence}{remediation}{refs}
  </div>
</article>"#,
        cls = s.class(),
        fp = fp_class,
        id = esc(&finding_ref(f)),
        title = esc(&f.title),
        sev = esc(s.label(lang)),
        tags = tags_block,
        meta = meta,
        desc = desc,
        evidence = evidence,
        remediation = remediation,
        refs = refs,
    )
}

fn section_block(label: &str, content: &str) -> String {
    if content.trim().is_empty() {
        return String::new();
    }
    format!("<h4>{}</h4><p>{}</p>", esc(label), esc_multiline(content))
}

fn roadmap_section(b: (i64, i64, i64, i64, i64), num: &str, lang: Lang) -> String {
    let mut rows = String::new();
    let push = |rows: &mut String,
                phase_cls: &str,
                phase: &str,
                n: i64,
                action: &str,
                sla: &str| {
        if n > 0 {
            rows.push_str(&format!(
                "<tr><td><span class=\"phase {pc}\">{ph}</span></td><td>{act}</td><td>{n}</td><td>{sla}</td></tr>",
                pc = phase_cls,
                ph = esc(phase),
                act = esc(action),
                n = n,
                sla = esc(sla),
            ));
        }
    };
    push(
        &mut rows,
        "p0",
        lang.t("Immediate", "מיידי"),
        b.0,
        lang.t(
            "Remediate all critical findings that could lead to compromise or data exposure.",
            "לתקן את כל הממצאים הקריטיים העלולים להוביל להשתלטות או לחשיפת מידע.",
        ),
        lang.t("≤ 7 days", "עד 7 ימים"),
    );
    push(
        &mut rows,
        "p1",
        lang.t("Short term", "קצר טווח"),
        b.1,
        lang.t(
            "Fix high-severity findings and re-test the affected components.",
            "לתקן ממצאים בחומרה גבוהה ולבצע בדיקה חוזרת לרכיבים המושפעים.",
        ),
        lang.t("≤ 30 days", "עד 30 יום"),
    );
    push(
        &mut rows,
        "p2",
        lang.t("Medium term", "בינוני"),
        b.2,
        lang.t(
            "Address medium findings and underlying process gaps.",
            "לטפל בממצאים בינוניים ובפערי התהליך שבבסיסם.",
        ),
        lang.t("≤ 90 days", "עד 90 יום"),
    );
    push(
        &mut rows,
        "p3",
        lang.t("Hardening", "הקשחה"),
        b.3 + b.4,
        lang.t(
            "Apply low-risk hardening and defence-in-depth improvements.",
            "ליישם הקשחה בסיכון נמוך ושיפורי הגנה-לעומק.",
        ),
        lang.t("Backlog", "מועד תחזוקה"),
    );
    let body = if rows.is_empty() {
        format!(
            "<div class=\"callout ok\">{}</div>",
            esc(lang.t(
                "No remediation is required from this assessment.",
                "לא נדרשת פעולת תיקון מבדיקה זו."
            ))
        )
    } else {
        format!(
            "<table><thead><tr><th style=\"width:24mm\">{ph}</th><th>{act}</th><th style=\"width:14mm\">{n}</th><th style=\"width:22mm\">{sla}</th></tr></thead><tbody>{rows}</tbody></table>",
            ph = esc(lang.t("Phase", "שלב")),
            act = esc(lang.t("Action", "פעולה")),
            n = esc(lang.t("Findings", "ממצאים")),
            sla = esc(lang.t("Target", "יעד")),
            rows = rows,
        )
    };
    format!(
        r#"<section class="sec" id="s-roadmap" dir="{dir}">
  {eyebrow}
  <h1><span class="num">{num}</span>{h}</h1><div class="rule"></div>
  <p>{intro}</p>
  {body}
</section>"#,
        dir = lang.dir(),
        num = num,
        eyebrow = eyebrow("Remediation Roadmap", lang),
        h = esc(lang.t("Remediation roadmap", "תוכנית תיקון")),
        intro = esc(lang.t(
            "Work is sequenced by risk: immediate actions first, then root-cause fixes to prevent recurrence.",
            "העבודה מדורגת לפי סיכון: פעולות מיידיות תחילה, ולאחריהן תיקון גורמי שורש למניעת הישנות."
        )),
        body = body,
    )
}

fn appendix_section(meta: &ReportMeta, num: &str, lang: Lang) -> String {
    let proof = match (&meta.crypto_hash, &meta.verify_url) {
        (Some(h), _) if !h.trim().is_empty() => {
            let verify = meta
                .verify_url
                .as_deref()
                .and_then(safe_http_url)
                .map(|u| {
                    format!(
                        "<div class=\"small muted\" style=\"margin-top:1mm\">{} <a href=\"{u}\" rel=\"noreferrer noopener\">{u}</a></div>",
                        esc(lang.t("Verify:", "אימות:")),
                        u = esc(u)
                    )
                })
                .unwrap_or_default();
            format!(
                "<h2>{h2}</h2><p class=\"small\">{intro}</p><div class=\"hash\">SHA-256: {hash}</div>{verify}",
                h2 = esc(lang.t("Integrity proof", "הוכחת שלמות")),
                intro = esc(lang.t(
                    "The evidence bundle is hash-chained; this value lets the reader confirm the report was not altered since issue.",
                    "חבילת הראיות חתומה בשרשרת גיבוב; ערך זה מאפשר לוודא שהדוח לא שונה מאז הנפקתו."
                )),
                hash = esc(h.trim()),
                verify = verify,
            )
        }
        _ => String::new(),
    };
    let glossary = [
        (
            "CVSS",
            lang.t(
                "Common Vulnerability Scoring System — a 0–10 technical severity scale.",
                "סולם חומרה טכני 0–10.",
            ),
        ),
        (
            "CWE",
            lang.t(
                "Common Weakness Enumeration — a classification of software weakness types.",
                "מיון סוגי חולשות בקוד.",
            ),
        ),
        (
            "KEV",
            lang.t(
                "CISA Known Exploited Vulnerabilities — actively exploited in the wild.",
                "חולשות המנוצלות באופן פעיל (CISA KEV).",
            ),
        ),
        (
            "EPSS",
            lang.t(
                "Exploit Prediction Scoring System — probability of exploitation.",
                "הסתברות לניצול (EPSS).",
            ),
        ),
        (
            "PoC",
            lang.t(
                "Proof of Concept — a controlled demonstration of a weakness.",
                "הוכחת היתכנות מבוקרת.",
            ),
        ),
    ];
    let mut gloss = String::new();
    for (t, d) in glossary {
        gloss.push_str(&format!(
            "<tr><th style=\"width:26mm\">{}</th><td>{}</td></tr>",
            esc(t),
            esc(d)
        ));
    }
    format!(
        r#"<section class="sec" id="s-appendix" dir="{dir}">
  {eyebrow}
  <h1><span class="num">{num}</span>{h}</h1><div class="rule"></div>
  {proof}
  <h2>{gl}</h2><table class="kv">{gloss}</table>
  <h2>{reg_h}</h2><p class="small">{reg_b}</p>
  <div class="foot-note">{foot}</div>
</section>"#,
        dir = lang.dir(),
        num = num,
        eyebrow = eyebrow("Appendix", lang),
        h = esc(lang.t("Appendix — definitions & regulatory mapping", "נספח — הגדרות ומיפוי רגולטורי")),
        proof = proof,
        gl = esc(lang.t("Glossary", "מונחון")),
        gloss = gloss,
        reg_h = esc(lang.t("Regulatory mapping (Israel)", "מיפוי רגולטורי (ישראל)")),
        reg_b = esc(lang.t(
            "For databases at the high security tier, the Privacy Protection (Data Security) Regulations 5777-2017, reg. 5(d), require a penetration test at least every 18 months; the owner must review the results and remediate deficiencies. This report supports that obligation and aligns with the INCD Cyber Defense Methodology.",
            "למאגרי מידע ברמת אבטחה גבוהה, תקנה 5(ד) לתקנות הגנת הפרטיות (אבטחת מידע) התשע\"ז-2017 מחייבת מבדק חדירות אחת ל-18 חודשים לפחות; בעל המאגר נדרש לדון בתוצאות ולתקן ליקויים. דוח זה תומך בדרישה זו ומתיישב עם תורת ההגנה של מערך הסייבר הלאומי."
        )),
        foot = format!(
            "{} · {} · {}",
            esc(meta.brand()),
            esc(&meta.report_id),
            esc(lang.t("Confidential — Client Use Only", "סודי — לשימוש הלקוח בלבד"))
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn exec_board_section(
    meta: &ReportMeta,
    findings: &[ReportFinding],
    b: (i64, i64, i64, i64, i64),
    sc: i64,
    posture_label: &str,
    posture_class: &str,
    compliance: Option<&CompliancePosture>,
    lang: Lang,
) -> String {
    let total = b.0 + b.1 + b.2 + b.3 + b.4;
    // Top risks in business terms — highest severity first, up to 3.
    let mut ordered: Vec<&ReportFinding> = findings.iter().collect();
    ordered.sort_by_key(|f| sev_of(&f.severity).rank());
    let mut top_rows = String::new();
    for (i, f) in ordered.iter().take(3).enumerate() {
        let s = sev_of(&f.severity);
        top_rows.push_str(&format!(
            "<tr><td>{n}</td><td><b>{title}</b>{desc}</td><td><span class=\"sev {cls}\">{sev}</span></td></tr>",
            n = i + 1,
            title = esc(&f.title),
            desc = if f.description.trim().is_empty() {
                String::new()
            } else {
                format!("<div class=\"small muted\">{}</div>", esc(&first_sentence(&f.description)))
            },
            cls = s.class(),
            sev = esc(s.label(lang)),
        ));
    }
    let top_block = if top_rows.is_empty() {
        format!(
            "<div class=\"callout ok\">{}</div>",
            esc(lang.t(
                "No exploitable findings were identified this period.",
                "לא זוהו ממצאים הניתנים לניצול בתקופה זו."
            ))
        )
    } else {
        format!(
            "<h2>{h}</h2><table><thead><tr><th style=\"width:8mm\">#</th><th>{risk}</th><th style=\"width:22mm\">{sev}</th></tr></thead><tbody>{rows}</tbody></table>",
            h = esc(lang.t("Top risks", "הסיכונים המרכזיים")),
            risk = esc(lang.t("Risk (business terms)", "סיכון (במונחים עסקיים)")),
            sev = esc(lang.t("Severity", "חומרה")),
            rows = top_rows,
        )
    };
    let lead = format!(
        "{} {} {}. {} {} {}.",
        esc(meta.brand()),
        esc(lang.t(
            "assessed the security posture of",
            "העריכה את מצב האבטחה של"
        )),
        esc(&meta.client_name),
        esc(lang.t("The assessment identified", "הבדיקה זיהתה")),
        total,
        esc(lang.t("findings", "ממצאים")),
    );
    format!(
        r#"<section class="sec first" id="s-dashboard" dir="{dir}">
  {eyebrow}
  <h1>{h}</h1><div class="rule"></div>
  <p class="lead">{lead}</p>
  <div class="posture avoid">
    <div><div class="posture__label">{ov}</div><div class="posture__score {pc}">{pl}</div></div>
    <div class="posture__text">{postxt}</div>
    <div style="text-align:center"><div class="posture__score {pc}" style="font-size:22pt">{sc}</div><div class="posture__label">{scl}</div></div>
  </div>
  <div class="kpis avoid">
    <div class="kpi total"><b>{total}</b><small>{c_total}</small></div>
    <div class="kpi crit"><b>{c}</b><small>{c_crit}</small></div>
    <div class="kpi high"><b>{h1}</b><small>{c_high}</small></div>
    <div class="kpi med"><b>{m}</b><small>{c_med}</small></div>
    <div class="kpi low"><b>{l}</b><small>{c_low}</small></div>
  </div>
  <div class="chart avoid">{donut}<div>{bars}</div></div>
  {top_block}
  {compliance}
</section>"#,
        dir = lang.dir(),
        eyebrow = eyebrow("Executive Dashboard", lang),
        h = esc(lang.t("Where we stand", "תמונת המצב")),
        lead = lead,
        ov = esc(lang.t("Overall risk", "דירוג סיכון כולל")),
        pc = posture_class,
        pl = esc(posture_label),
        postxt = esc(posture_sentence(b, lang)),
        sc = sc,
        scl = esc(lang.t("Security score", "ציון אבטחה")),
        total = total,
        c_total = esc(lang.t("Findings total", "סה״כ ממצאים")),
        c = b.0,
        c_crit = esc(lang.t("Critical", "קריטי")),
        h1 = b.1,
        c_high = esc(lang.t("High", "גבוה")),
        m = b.2,
        c_med = esc(lang.t("Medium", "בינוני")),
        l = b.3 + b.4,
        c_low = esc(lang.t("Low / Info", "נמוך / מידעי")),
        donut = donut_svg(b, lang),
        bars = bars_svg(b, lang),
        top_block = top_block,
        compliance = compliance_block(compliance, lang),
    )
}

fn compliance_block(compliance: Option<&CompliancePosture>, lang: Lang) -> String {
    let Some(c) = compliance else {
        return String::new();
    };
    let bar = |label: &str, pct: u8| {
        let color = if pct >= 80 {
            "var(--ok)"
        } else if pct >= 50 {
            "var(--med)"
        } else {
            "var(--high)"
        };
        format!(
            "<div class=\"bar\"><span>{label}</span><div class=\"track\"><div class=\"fill\" style=\"width:{pct}%;background:{color}\">{pct}%</div></div></div>",
            label = esc(label),
            pct = pct.min(100),
            color = color,
        )
    };
    format!(
        "<h2>{h}</h2><div class=\"bars\">{soc}{iso}{gdpr}</div><p class=\"small muted\">{note}</p>",
        h = esc(lang.t(
            "Compliance posture (mapped controls)",
            "מצב עמידה (בקרות ממופות)"
        )),
        soc = bar("SOC 2", c.soc2),
        iso = bar("ISO 27001", c.iso),
        gdpr = bar(lang.t("GDPR (Art. 32)", "GDPR (סעיף 32)"), c.gdpr),
        note = esc(lang.t(
            "Alignment is measured against mapped controls, not a formal certification.",
            "העמידה נמדדת מול בקרות ממופות ואינה מהווה הסמכה פורמלית."
        )),
    )
}

// ---------------------------------------------------------------------------
// misc helpers
// ---------------------------------------------------------------------------

fn finding_ref(f: &ReportFinding) -> String {
    if f.finding_id.trim().is_empty() {
        format!("VLN-{}", f.id)
    } else {
        f.finding_id.trim().to_string()
    }
}

/// A finding the client acknowledged as not a real issue (false positive / suppressed). Such items
/// are disclosed in a dedicated log and the complete register — never silently dropped.
fn is_fp(f: &ReportFinding) -> bool {
    let s = f.status.trim().to_ascii_lowercase();
    s.contains("false") || s == "fp" || s.contains("suppress")
}

/// Epistemic / proof status → (label, colour). Every finding is tagged so the reader can tell a
/// proven exploit from an observed signal or a proof that failed — nothing is presented as more
/// certain than it is.
fn proof_meta(ps: &str, lang: Lang) -> (&'static str, &'static str) {
    match ps.trim().to_ascii_lowercase().as_str() {
        "proven" => (lang.t("Proven", "מוכח"), "#087443"),
        "validated_safe_proof" | "validated" => (lang.t("Validated", "אומת"), "#0E7C86"),
        "failed_proof" => (lang.t("Proof failed", "הוכחה נכשלה"), "#B45309"),
        "not_applicable" | "na" | "n/a" => (lang.t("N/A", "לא רלוונטי"), "#8697A6"),
        _ => (lang.t("Observed", "נצפה"), "#5A6B7B"),
    }
}

fn proof_badge_tag(ps: &str, lang: Lang) -> String {
    let (label, color) = proof_meta(ps, lang);
    format!(
        "<span class=\"tag\" style=\"background:{color};color:#fff\">{}</span>",
        esc(label)
    )
}

/// Order: active findings first (by severity), suppressed / false-positive last.
fn sort_findings<'a>(findings: &'a [ReportFinding]) -> Vec<&'a ReportFinding> {
    let mut v: Vec<&ReportFinding> = findings.iter().collect();
    v.sort_by_key(|f| (is_fp(f), sev_of(&f.severity).rank()));
    v
}

fn status_badge(status: &str, lang: Lang) -> String {
    let s = status.trim().to_ascii_lowercase();
    let (cls, label) = if s.is_empty() || s == "open" {
        ("open", lang.t("Open", "פתוח"))
    } else if s.contains("remed")
        || s.contains("fixed")
        || s.contains("closed")
        || s.contains("resolved")
    {
        ("fixed", lang.t("Remediated", "תוקן"))
    } else {
        ("other", lang.t("In review", "בבדיקה"))
    };
    format!("<span class=\"status {cls}\">{}</span>", esc(label))
}

fn first_sentence(s: &str) -> String {
    let s = s.trim();
    match s.find(['.', '\n']) {
        Some(i) if i < 160 => s[..=i].trim().to_string(),
        _ => truncate(s, 140),
    }
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        format!("{}…", chars.into_iter().take(max).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: i64, title: &str, sev: &str) -> ReportFinding {
        ReportFinding {
            id,
            title: title.into(),
            severity: sev.into(),
            ..Default::default()
        }
    }

    fn meta() -> ReportMeta {
        ReportMeta {
            client_name: "NovaMed Health".into(),
            report_id: "WC-2026-0147".into(),
            version: "1.0".into(),
            generated_at: "2026-09-22 10:00 IDT".into(),
            ..Default::default()
        }
    }

    #[test]
    fn lang_parse() {
        assert_eq!(Lang::parse(Some("he")), Lang::He);
        assert_eq!(Lang::parse(Some("HE-IL")), Lang::He);
        assert_eq!(Lang::parse(Some("en")), Lang::En);
        assert_eq!(Lang::parse(None), Lang::En);
    }

    #[test]
    fn renders_self_contained_no_external_resources() {
        let html = render_client_report_html(&meta(), &[f(1, "SQLi", "critical")], Lang::En);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<style>"));
        assert!(!html.contains("<link"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("@import"));
        // fonts embedded as data URIs, not external src=
        assert!(html.contains("data:font/ttf;base64,"));
        assert!(!html.contains("src=\""));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn escapes_untrusted_fields() {
        let mut bad = f(7, "<script>steal()</script>", "high");
        bad.description = "<img src=x onerror=alert(1)>".into();
        bad.poc_exploit = "curl '<script>'".into();
        let html = render_client_report_html(&meta(), &[bad], Lang::En);
        assert!(!html.contains("<script>steal()"));
        assert!(!html.contains("<img src=x onerror"));
        assert!(html.contains("&lt;script&gt;steal()"));
    }

    #[test]
    fn both_languages_render_with_direction() {
        let he = render_client_report_html(&meta(), &[f(1, "X", "high")], Lang::He);
        assert!(he.contains("dir=\"rtl\""));
        assert!(he.contains("תקציר מנהלים"));
        let en = render_client_report_html(&meta(), &[f(1, "X", "high")], Lang::En);
        assert!(en.contains("dir=\"ltr\""));
        assert!(en.contains("Executive summary"));
    }

    #[test]
    fn severity_counts_and_score() {
        let fs = vec![
            f(1, "a", "critical"),
            f(2, "b", "high"),
            f(3, "c", "high"),
            f(4, "d", "medium"),
            f(5, "e", "low"),
            f(6, "g", "info"),
        ];
        let b = buckets(&fs);
        assert_eq!(b, (1, 2, 1, 1, 1));
        // 100 - 25 - 30 - 5 = 40
        assert_eq!(score(b), 40);
        let html = render_client_report_html(&meta(), &fs, Lang::En);
        assert!(html.contains("Critical"));
        assert!(html.contains("VLN-1"));
    }

    #[test]
    fn empty_findings_is_clean_and_positive() {
        let html = render_client_report_html(&meta(), &[], Lang::En);
        assert_eq!(score(buckets(&[])), 100);
        assert!(html.contains("No findings") || html.contains("No exploitable"));
        assert!(!html.contains("VLN-"));
    }

    #[test]
    fn white_label_suppresses_vendor_mark() {
        let mut m = meta();
        m.brand_name = Some("Northwind Security".into());
        let html = render_client_report_html(&m, &[f(1, "x", "low")], Lang::En);
        assert!(html.contains("Northwind Security"));
        assert!(!html.contains("Weissman"));
        assert!(!html.contains("WEISSMAN"));
        // without a brand, the vendor mark remains
        let plain = render_client_report_html(&meta(), &[f(1, "x", "low")], Lang::En);
        assert!(plain.contains("Weissman Cybersecurity"));
    }

    #[test]
    fn honest_no_invented_intel() {
        let html = render_client_report_html(&meta(), &[f(1, "x", "critical")], Lang::En);
        for banned in [
            "APT28",
            "FIN7",
            "Lazarus",
            "Industry Avg",
            "Industry Benchmark",
        ] {
            assert!(!html.contains(banned), "must not invent: {banned}");
        }
    }

    #[test]
    fn rich_finding_fields_render_and_omit_empties() {
        let mut rich = f(9, "IDOR in invoices", "high");
        rich.finding_id = "ACME-24-004".into();
        rich.cvss_score = Some(7.5);
        rich.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N".into();
        rich.cwe = "CWE-639".into();
        rich.owasp = "A01:2021".into();
        rich.kev = true;
        rich.epss = Some(0.42);
        rich.affected = "https://portal.example/api/v1/invoices/{id}".into();
        rich.remediation = "Enforce tenant ownership server-side.".into();
        rich.references = vec!["https://owasp.org/".into()];
        let html = render_client_report_html(&meta(), &[rich], Lang::En);
        assert!(html.contains("ACME-24-004"));
        assert!(html.contains("CWE-639"));
        assert!(html.contains("7.5"));
        assert!(html.contains("KEV"));
        assert!(html.contains("EPSS 42%"));
        assert!(html.contains("Enforce tenant ownership"));
        // a sparse finding must not leave empty labelled rows
        let sparse = render_client_report_html(&meta(), &[f(1, "bare", "low")], Lang::En);
        assert!(!sparse.contains("<p></p>"));
    }

    #[test]
    fn executive_report_renders_with_compliance() {
        let comp = CompliancePosture {
            soc2: 82,
            iso: 61,
            gdpr: 44,
        };
        let html = render_executive_report_html(
            &meta(),
            &[f(1, "a", "critical"), f(2, "b", "high")],
            Some(&comp),
            Lang::En,
        );
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("Cyber Risk Report"));
        assert!(html.contains("Where we stand"));
        assert!(html.contains("SOC 2"));
        assert!(html.contains("82%"));
        assert!(!html.contains("<script"));
        // Hebrew variant is RTL and localised.
        let he = render_executive_report_html(&meta(), &[f(1, "a", "high")], None, Lang::He);
        assert!(he.contains("dir=\"rtl\""));
        assert!(he.contains("תמונת המצב"));
        // no compliance block when none supplied
        assert!(!he.contains("SOC 2"));
    }

    #[test]
    fn executive_report_white_label() {
        let mut m = meta();
        m.brand_name = Some("Northwind Security".into());
        let html = render_executive_report_html(&m, &[f(1, "x", "low")], None, Lang::En);
        assert!(html.contains("Northwind Security"));
        assert!(!html.contains("Weissman"));
    }
}
