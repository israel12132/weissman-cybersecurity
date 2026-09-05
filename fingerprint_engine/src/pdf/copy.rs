//! Bilingual copy for product reports. English is the default; Hebrew is a first-class twin,
//! not a transliteration overlay.

use super::doc::Lang;

/// A pair of localised strings selected by [`Lang`].
#[derive(Clone, Copy)]
pub struct Copy {
    en: &'static str,
    he: &'static str,
}

impl Copy {
    #[must_use]
    pub const fn new(en: &'static str, he: &'static str) -> Self {
        Self { en, he }
    }

    #[must_use]
    pub fn get(self, lang: Lang) -> &'static str {
        match lang {
            Lang::He => self.he,
            Lang::En => self.en,
        }
    }
}

pub const ORG: Copy = Copy::new("Weissman Cybersecurity", "חבת וייסמן אבטחת מידע");
pub const CLASSIFICATION: Copy = Copy::new("Confidential", "חסוי");
pub const ASSESSMENT_TITLE: Copy = Copy::new(
    "Executive Security Assessment Report",
    "דוח הערכת אבטחה למנהלים",
);
pub const ASSESSMENT_SUB: Copy = Copy::new(
    "Live, evidence-backed findings from production engines. No simulated results.",
    "ממצאים חיים ומגובים בראיות ממנועי הייצור. ללא תוצאות מדומות.",
);
pub const BOARD_TITLE: Copy = Copy::new("Board / CISO Briefing", "תדרוך דירקטוריון / מנמ\"ר");
pub const BOARD_SUB: Copy = Copy::new(
    "Aggregate risk and compliance posture. No raw proof-of-concept payloads.",
    "תמונת סיכון וציות מצרפית. ללא מטעני הוכחת-ניצול גולמיים.",
);
pub const COMPLIANCE_TITLE: Copy = Copy::new("Compliance Audit Report", "דוח ביקורת ציות");
pub const COMPLIANCE_SUB: Copy = Copy::new(
    "Control status derived from live findings against the compliance mappings catalog.",
    "סטטוס בקרות הנגזר מממצאים חיים מול קטלוג מיפוי הציות.",
);
pub const ANOMALY_TITLE: Copy = Copy::new("Fuzzer Anomaly Report", "דוח חריגת מערער");
pub const EXEC_SUMMARY: Copy = Copy::new("Executive Summary", "תקציר מנהלים");
pub const REMEDIATION: Copy = Copy::new("Executive Remediation Roadmap", "מפת דרכים לתיקון");
pub const THREAT_INTEL: Copy = Copy::new("Threat Intelligence", "מודיעין איומים");
pub const FINDINGS: Copy = Copy::new("Technical Finding Details", "פירוט ממצאים טכני");
pub const INTEGRITY: Copy = Copy::new(
    "Cryptographic Proof of Integrity",
    "הוכחת שלמות קריפטוגרפית",
);
pub const METHODOLOGY: Copy = Copy::new("Methodology", "מתודולוגיה");
pub const CONTROL_ASSESSMENT: Copy = Copy::new("Control Assessment", "הערכת בקרות");
pub const RISK_POSTURE: Copy = Copy::new("Risk Posture", "מצב סיכון");
pub const COMPLIANCE_POSTURE: Copy = Copy::new("Continuous Compliance", "ציות רציף");
pub const GENERATED: Copy = Copy::new("Generated (Israel)", "הופק (ישראל)");
pub const SCOPE: Copy = Copy::new("Scope", "היקף");
pub const ORGANIZATION: Copy = Copy::new("Organization", "ארגון");
pub const FRAMEWORK: Copy = Copy::new("Framework", "מסגרת");
pub const SECURITY_SCORE: Copy = Copy::new("Security posture score", "ציון מצב אבטחה");
pub const SEVERITY_MIX: Copy = Copy::new("Severity mix", "פילוח חומרה");
pub const CRITICAL: Copy = Copy::new("Critical", "קריטי");
pub const HIGH: Copy = Copy::new("High", "גבוה");
pub const MEDIUM: Copy = Copy::new("Medium", "בינוני");
pub const LOW: Copy = Copy::new("Low / Info", "נמוך / מידע");
pub const VERIFIED: Copy = Copy::new("Verified", "מאומת");
pub const FINDINGS_N: Copy = Copy::new("Findings", "ממצאים");
pub const CLOUD_MISCONFIG: Copy = Copy::new("Cloud misconfigurations", "שגיאות תצורה בענן");
pub const PRIORITY: Copy = Copy::new("Priority", "עדיפות");
pub const THREAT: Copy = Copy::new("Threat", "איום");
pub const ACTION: Copy = Copy::new("Action", "פעולה");
pub const EFFICIENCY: Copy = Copy::new("Efficiency", "יעילות");
pub const COL_ID: Copy = Copy::new("ID", "מזהה");
pub const COL_FINDING: Copy = Copy::new("Finding", "ממצא");
pub const COL_SEVERITY: Copy = Copy::new("Severity", "חומרה");
pub const COL_SOURCE: Copy = Copy::new("Source", "מקור");
pub const COL_PRIORITY: Copy = Copy::new("Priority", "עדיפות");
pub const COL_PROOF: Copy = Copy::new("Proof of breach", "הוכחת פריצה");
pub const COL_REMEDIATION: Copy = Copy::new("Remediation", "תיקון");
pub const COL_CONTROL: Copy = Copy::new("Control", "בקרה");
pub const COL_TITLE: Copy = Copy::new("Title", "כותרת");
pub const COL_STATUS: Copy = Copy::new("Status", "סטטוס");
pub const COMPLIANT: Copy = Copy::new("Compliant", "עומד");
pub const NON_COMPLIANT: Copy = Copy::new("Non-compliant", "לא עומד");
pub const ALIGNMENT: Copy = Copy::new("Overall alignment", "הלימה כוללת");
pub const VOID_BANNER: Copy = Copy::new(
    "*** REPORT VOID — INCONSISTENT CONTROL-MAPPING STATE ***",
    "*** הדוח בטל — מצב מיפוי בקרות אינו עקבי ***",
);
pub const VOID_BODY: Copy = Copy::new(
    "This report is NOT valid for audit. The controls below are compliance requirements with no live evidence mapping. Complete the mapping catalog and regenerate before relying on this document.",
    "דוח זה אינו תקף לביקורת. הבקרות שלהלן הן דרישות ציות ללא מיפוי ראיות חי. יש להשלים את קטלוג המיפוי ולהפיק מחדש לפני הסתמכות על המסמך.",
);
pub const VOID_FOOTER: Copy = Copy::new(
    "VOID: generated in an inconsistent control-mapping state — not valid for audit or attestation.",
    "בטל: הופק במצב מיפוי בקרות שאינו עקבי — אינו תקף לביקורת או להצהרה.",
);
pub const UNMAPPED: Copy = Copy::new("UNMAPPED", "לא ממופה");
pub const NO_PROOF: Copy = Copy::new(
    "No proof-of-breach findings (no cURL / HIGH / CRITICAL with remediation). Data is live from the database.",
    "אין ממצאי הוכחת-פריצה (אין cURL / גבוה / קריטי עם תיקון). הנתונים חיים ממסד הנתונים.",
);
pub const NO_FINDINGS: Copy = Copy::new(
    "No findings. Data is live from the database.",
    "אין ממצאים. הנתונים חיים ממסד הנתונים.",
);
pub const DISCOVERY: Copy = Copy::new("Attack surface discovery", "גילוי משטח תקיפה");
pub const BENCHMARK: Copy = Copy::new("Client vs industry benchmark", "הלקוח מול ממוצע הענף");
pub const INDUSTRY_AVG: Copy = Copy::new("Industry average", "ממוצע ענף");
pub const CLIENT_SCORE: Copy = Copy::new("Client", "לקוח");
pub const SHA256: Copy = Copy::new("SHA-256", "SHA-256");
pub const VERIFY: Copy = Copy::new("Verify", "אימות");
pub const LIKELY_ACTORS: Copy = Copy::new(
    "Likely threat actors (contextual): APT28, FIN7, Lazarus — prioritize external exposure and authentication findings.",
    "גורמי איום סבירים (הקשרי): APT28, FIN7, Lazarus — יש לתעדף חשיפה חיצונית וממצאי אימות.",
);
pub const METHOD_BODY: Copy = Copy::new(
    "Every finding in this document was produced by a live Weissman engine against the named scope. Scores, charts and tables are computed from the same database rows the Command Center displays. Nothing here is a placeholder, a canned demo, or a static template filled with sample data.",
    "כל ממצא במסמך זה הופק על ידי מנוע וייסמן חי כנגד ההיקף הנקוב. ציונים, תרשימים וטבלאות מחושבים מאותן שורות מסד שה-Command Center מציג. אין כאן ממלא-מקום, הדגמה מוכנה או תבנית סטטית עם נתוני דוגמה.",
);
pub const PROOF_FILTER: Copy = Copy::new(
    "Proof-of-breach only: findings with a Safe Reproduce (cURL) payload or HIGH/CRITICAL severity and a remediation path.",
    "הוכחת-פריצה בלבד: ממצאים עם מטען שחזור בטוח (cURL) או חומרה גבוהה/קריטית ומסלול תיקון.",
);
pub const REMEDIATION_INTRO: Copy = Copy::new(
    "Top strategic actions derived from live findings, ranked by severity then remediation-priority score (PoE, entropy, stack/CVE correlation).",
    "פעולות אסטרטגיות המופקות מממצאים חיים, מדורגות לפי חומרה ואז לפי ציון עדיפות תיקון (PoE, אנטרופיה, מתאם מחסנית/CVE).",
);
pub const HIGH_IMPACT: Copy =
    Copy::new("High impact / critical effort", "השפעה גבוהה / מאמץ קריטי");
pub const HIGH_MODERATE: Copy =
    Copy::new("High impact / moderate effort", "השפעה גבוהה / מאמץ מתון");
pub const MODERATE_EASY: Copy = Copy::new("Moderate impact / easy fix", "השפעה מתונה / תיקון קל");
pub const OVERVIEW_SHEET: Copy = Copy::new("Overview", "סקירה");
pub const DATA_SHEET: Copy = Copy::new("Findings", "ממצאים");
pub const ACTOR: Copy = Copy::new("Requested by", "התבקש על ידי");
pub const ROW_COUNT: Copy = Copy::new("Rows", "שורות");
pub const INTEGRITY_HASH: Copy = Copy::new("Integrity hash", "גיבוב שלמות");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hebrew_and_english_are_distinct_for_customer_facing_copy() {
        assert_ne!(
            ASSESSMENT_TITLE.get(Lang::En),
            ASSESSMENT_TITLE.get(Lang::He)
        );
        assert!(ASSESSMENT_TITLE
            .get(Lang::He)
            .chars()
            .any(|c| ('\u{0590}'..='\u{05FF}').contains(&c)));
    }

    #[test]
    fn english_is_the_default_selection() {
        assert_eq!(ORG.get(Lang::En), "Weissman Cybersecurity");
    }
}
