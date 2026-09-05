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
    "Live, evidence-backed assessment from production engines against the authorized scope.",
    "הערכת אבטחה חיה ומגובה ראיות ממנועי הייצור מול ההיקף המורשה.",
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
pub const COL_FINDING_ID: Copy = Copy::new("Finding ID", "מזהה ממצא");
pub const COL_SEVERITY: Copy = Copy::new("Severity", "חומרה");
pub const COL_SOURCE: Copy = Copy::new("Source", "מקור");
pub const COL_PRIORITY: Copy = Copy::new("Priority", "עדיפות");
pub const COL_PROOF: Copy = Copy::new("Proof of breach", "הוכחת פריצה");
pub const COL_REMEDIATION: Copy = Copy::new("Remediation", "תיקון");
pub const COL_CONTROL: Copy = Copy::new("Control", "בקרה");
pub const COL_TITLE: Copy = Copy::new("Title", "כותרת");
pub const COL_STATUS: Copy = Copy::new("Status", "סטטוס");
pub const COL_CVE: Copy = Copy::new("CVE", "CVE");
pub const COL_CVSS: Copy = Copy::new("CVSS", "CVSS");
pub const COL_VECTOR: Copy = Copy::new("CVSS vector", "וקטור CVSS");
pub const COL_CWE: Copy = Copy::new("CWE", "CWE");
pub const COL_EPSS: Copy = Copy::new("EPSS", "EPSS");
pub const COL_KEV: Copy = Copy::new("CISA KEV", "CISA KEV");
pub const COL_MITRE: Copy = Copy::new("MITRE ATT&CK", "MITRE ATT&CK");
pub const COL_ASSET: Copy = Copy::new("Asset", "נכס");
pub const COL_DISCOVERED: Copy = Copy::new("First seen", "זוהה לראשונה");
pub const COL_VERIFIED: Copy = Copy::new("Verified", "מאומת");
pub const COL_METRIC: Copy = Copy::new("Metric", "מדד");
pub const COL_VALUE: Copy = Copy::new("Value", "ערך");
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
    "No findings are recorded for this client. The tables below remain so the register is complete.",
    "אין ממצאים רשומים ללקוח זה. הטבלאות נשארות כדי שהרשם יהיה שלם.",
);
pub const DISCOVERY: Copy = Copy::new("Attack surface discovery", "גילוי משטח תקיפה");
pub const CLIENT_SCORE: Copy = Copy::new("Client", "לקוח");
pub const SHA256: Copy = Copy::new("SHA-256", "SHA-256");
pub const VERIFY: Copy = Copy::new("Verify", "אימות");
pub const BLUF: Copy = Copy::new("Bottom line", "שורה תחתונה");
pub const ROE_HEADING: Copy = Copy::new("Rules of engagement", "כללי התקשרות");
pub const SCOPE_HEADING: Copy = Copy::new("Authorized scope", "היקף מורשה");
pub const METHOD_BODY: Copy = Copy::new(
    "Findings in this document were produced by live Weissman production engines against the authorized scope. Scores, charts and tables are computed from the same tenant-scoped database rows the Command Center displays.",
    "הממצאים במסמך זה הופקו על ידי מנועי ייצור חיים של וייסמן כנגד ההיקף המורשה. ציונים, תרשימים וטבלאות מחושבים מאותן שורות מסד מוגבלות-דייר שה-Command Center מציג.",
);
pub const METHOD_STANDARDS: Copy = Copy::new(
    "Practice follows OWASP WSTG, PTES, MITRE ATT&CK, and NIST SP 800-115. CVSS 3.1, CWE, CVE, FIRST EPSS and CISA KEV appear only when a live engine or intel enrichment recorded them. Empty cells mean the identifier was not recorded — they are never estimated from severity.",
    "העבודה נשענת על OWASP WSTG, PTES, MITRE ATT&CK ו-NIST SP 800-115. CVSS 3.1, CWE, CVE, FIRST EPSS ו-CISA KEV מופיעים רק כשמנוע חי או העשרת מודיעין תיעדו אותם. תאים ריקים פירושם שהמזהה לא נרשם — הם אינם מוערכים מחומרה.",
);
pub const INTEL_NONE: Copy = Copy::new(
    "No CISA KEV, FIRST EPSS or CVE identifiers are recorded on this client's live findings. Blank intel cells are intentional.",
    "אין מזהי CISA KEV, FIRST EPSS או CVE על ממצאי הלקוח החיים. תאי מודיעין ריקים הם מכוונים.",
);
pub const POSTURE_NOTE: Copy = Copy::new(
    "The posture score starts at 100 and subtracts 25 per critical, 15 per high and 5 per medium finding on this client only. It is not an industry benchmark.",
    "ציון המצב מתחיל ב-100 ומחסיר 25 לכל ממצא קריטי, 15 לכל גבוה ו-5 לכל בינוני אצל לקוח זה בלבד. זה אינו מדד ענפי.",
);
pub const REGISTER_INTRO: Copy = Copy::new(
    "Complete findings register. CVSS, CVE, CWE, KEV, EPSS and ATT&CK are live fields; a dash means the identifier was not recorded.",
    "רשם ממצאים מלא. CVSS, CVE, CWE, KEV, EPSS ו-ATT&CK הם שדות חיים; מקף פירושו שהמזהה לא נרשם.",
);
pub const PROOF_FILTER: Copy = Copy::new(
    "Proof-of-breach extract: findings with a Safe Reproduce payload or HIGH/CRITICAL severity and a remediation path.",
    "חילוץ הוכחת-פריצה: ממצאים עם מטען שחזור בטוח או חומרה גבוהה/קריטית ומסלול תיקון.",
);
pub const NARRATIVES: Copy = Copy::new("Finding narratives", "תיאורי ממצאים");
pub const NARRATIVE_INTRO: Copy = Copy::new(
    "Each card is one live finding: affected asset, recorded intel, description, evidence, and remediation. Sorted critical first.",
    "כל כרטיס הוא ממצא חי אחד: נכס מושפע, מודיעין שנרשם, תיאור, ראיות ותיקון. ממוין מקריטי תחילה.",
);
pub const EVIDENCE: Copy = Copy::new("Evidence", "ראיות");
pub const DOC_ID: Copy = Copy::new("Document ID", "מזהה מסמך");
pub const PREPARED_FOR: Copy = Copy::new("Prepared for", "הוכן עבור");
pub const DISTRIBUTION: Copy = Copy::new(
    "Limited distribution — named client only. Handle as Confidential.",
    "הפצה מוגבלת — ללקוח הנקוב בלבד. יש לטפל כחסוי.",
);
pub const INTEGRITY_NONE: Copy = Copy::new(
    "No cryptographic proof is attached to this copy. A SHA-256 is included when a sealed assessment run exists for this client.",
    "אין הוכחה קריפטוגרפית מצורפת לעותק זה. SHA-256 נכלל כאשר קיים ריצת הערכה חתומה ללקוח זה.",
);
pub const COL_DESCRIPTION: Copy = Copy::new("Description", "תיאור");
pub const REMEDIATION_INTRO: Copy = Copy::new(
    "Top strategic actions from live findings, ranked by severity then remediation-priority score (proof, entropy, stack/CVE correlation).",
    "פעולות אסטרטגיות מממצאים חיים, מדורגות לפי חומרה ואז לפי ציון עדיפות תיקון (הוכחה, אנטרופיה, מתאם מחסנית/CVE).",
);
pub const HIGH_IMPACT: Copy =
    Copy::new("High impact / critical effort", "השפעה גבוהה / מאמץ קריטי");
pub const HIGH_MODERATE: Copy =
    Copy::new("High impact / moderate effort", "השפעה גבוהה / מאמץ מתון");
pub const MODERATE_EASY: Copy = Copy::new("Moderate impact / easy fix", "השפעה מתונה / תיקון קל");
pub const OVERVIEW_SHEET: Copy = Copy::new("Overview", "סקירה");
pub const DATA_SHEET: Copy = Copy::new("Findings", "ממצאים");
pub const EXEC_SHEET: Copy = Copy::new("Executive", "מנהלים");
pub const REMEDIATION_SHEET: Copy = Copy::new("Remediation", "תיקון");
pub const INTEL_SHEET: Copy = Copy::new("Intel", "מודיעין");
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

    #[test]
    fn customer_copy_does_not_apologize_about_fakes() {
        for s in [
            POSTURE_NOTE.get(Lang::En),
            INTEL_NONE.get(Lang::En),
            METHOD_BODY.get(Lang::En),
            ASSESSMENT_SUB.get(Lang::En),
        ] {
            let lower = s.to_ascii_lowercase();
            assert!(!lower.contains("invented"), "{s}");
            assert!(!lower.contains("placeholder"), "{s}");
            assert!(!lower.contains("canned demo"), "{s}");
        }
    }
}
