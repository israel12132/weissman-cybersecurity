//! Auto-heal **risk / priority scoring** — ranks which findings deserve to be healed first, so an
//! operator (or the batch-heal queue) works the most dangerous, most reachable issues before the rest.
//!
//! [`score_priority`] is a **pure function** over signals the platform already has (severity, a working
//! PoC, exposure, impact class, age). It returns a 0–100 score, a `P0`–`P3` tier, and a bilingual
//! (he/en) rationale naming the factors that drove the score. The text classifiers
//! ([`classify_high_impact`], [`classify_internet_facing`]) are pure and unit-tested too.

use serde::Serialize;

/// Signals that drive the priority of healing a finding.
#[derive(Debug, Clone, Default)]
pub struct PriorityInputs {
    pub severity: String,
    /// A reproducible exploit exists (weaponized → urgent).
    pub has_poc: bool,
    /// The asset is reachable from the internet.
    pub internet_facing: bool,
    /// Impact class is high (RCE / injection / auth-bypass / SSRF / deser…).
    pub high_impact_category: bool,
    /// Days the finding has been open.
    pub age_days: i64,
}

/// The computed priority.
#[derive(Debug, Clone, Serialize)]
pub struct PriorityScore {
    pub score: u8,
    pub tier: String,
    pub reason_en: String,
    pub reason_he: String,
    /// Machine-readable list of the factors that contributed points.
    pub factors: Vec<String>,
}

fn severity_points(sev: &str) -> u8 {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" => 45,
        "high" => 32,
        "medium" => 18,
        "low" => 8,
        _ => 0,
    }
}

/// True when `haystack` contains `word` as a whole alphanumeric token (so short acronyms like `rce`
/// don't false-match a substring, e.g. inside `source`).
fn contains_word(haystack: &str, word: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == word)
}

/// True when the text describes a high-impact vulnerability class.
pub fn classify_high_impact(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    // Multi-word phrases match as substrings; a bare "injection" is deliberately absent (it would
    // false-match "dependency injection").
    const PHRASES: &[&str] = &[
        "sql injection",
        "code injection",
        "command inj",
        "ldap injection",
        "template injection",
        "remote code",
        "deserial",
        "auth bypass",
        "authentication bypass",
        "path traversal",
        "privilege escalation",
    ];
    // Short acronyms match only as whole words (avoids `rce` in `source`, etc.).
    const WORDS: &[&str] = &["rce", "ssrf", "xxe", "ssti"];
    PHRASES.iter().any(|p| t.contains(p)) || WORDS.iter().any(|w| contains_word(&t, w))
}

/// True when the text suggests an internet-facing / externally exposed asset.
pub fn classify_internet_facing(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    const NEEDLES: [&str; 6] = ["internet", "external", "public-facing", "publicly", "exposed", "perimeter"];
    NEEDLES.iter().any(|n| t.contains(n))
}

/// Score a finding's auto-heal priority (0–100) with a bilingual rationale.
pub fn score_priority(i: &PriorityInputs) -> PriorityScore {
    let mut score: u32 = severity_points(&i.severity) as u32;
    let mut factors: Vec<String> = Vec::new();
    let mut en: Vec<String> = Vec::new();
    let mut he: Vec<String> = Vec::new();

    let sev = i.severity.trim().to_ascii_lowercase();
    if !sev.is_empty() && sev != "unspecified" {
        factors.push(format!("severity:{sev}"));
    }

    if i.has_poc {
        score += 25;
        factors.push("reproducible_poc".into());
        en.push("a reproducible exploit exists".into());
        he.push("קיים אקספלויט הניתן לשחזור".into());
    }
    if i.internet_facing {
        score += 15;
        factors.push("internet_facing".into());
        en.push("the asset is internet-facing".into());
        he.push("הנכס חשוף לאינטרנט".into());
    }
    if i.high_impact_category {
        score += 10;
        factors.push("high_impact_class".into());
        en.push("a high-impact vulnerability class".into());
        he.push("סוג חולשה בעל השפעה גבוהה".into());
    }
    // Age nudge: up to +5, one point per week open.
    if i.age_days > 0 {
        let bump = ((i.age_days / 7).max(0)).min(5) as u32;
        if bump > 0 {
            score += bump;
            factors.push(format!("age_days:{}", i.age_days));
            en.push(format!("open for {} days", i.age_days));
            he.push(format!("פתוח כבר {} ימים", i.age_days));
        }
    }

    let score = score.min(100) as u8;
    let tier = if score >= 80 {
        "P0"
    } else if score >= 60 {
        "P1"
    } else if score >= 35 {
        "P2"
    } else {
        "P3"
    };

    let sev_en = if sev.is_empty() { "unspecified".to_string() } else { sev.clone() };
    let reason_en = if en.is_empty() {
        format!("{tier} · {sev_en} severity.")
    } else {
        format!("{tier} · {sev_en} severity — {}.", en.join(", "))
    };
    let reason_he = if he.is_empty() {
        format!("{tier} · חומרה {sev_en}.")
    } else {
        format!("{tier} · חומרה {sev_en} — {}.", he.join(", "))
    };

    PriorityScore { score, tier: tier.to_string(), reason_en, reason_he, factors }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inp(sev: &str) -> PriorityInputs {
        PriorityInputs { severity: sev.into(), ..Default::default() }
    }

    #[test]
    fn severity_sets_the_base() {
        assert_eq!(score_priority(&inp("critical")).score, 45);
        assert_eq!(score_priority(&inp("high")).score, 32);
        assert_eq!(score_priority(&inp("medium")).score, 18);
        assert_eq!(score_priority(&inp("low")).score, 8);
        assert_eq!(score_priority(&inp("weird")).score, 0);
    }

    #[test]
    fn weaponized_internet_facing_critical_is_p0() {
        let p = score_priority(&PriorityInputs {
            severity: "critical".into(),
            has_poc: true,
            internet_facing: true,
            high_impact_category: true,
            age_days: 40,
        });
        // 45 + 25 + 15 + 10 + 5 = 100
        assert_eq!(p.score, 100);
        assert_eq!(p.tier, "P0");
        assert!(p.reason_he.contains("אקספלויט"));
        assert!(p.factors.contains(&"reproducible_poc".to_string()));
    }

    #[test]
    fn score_is_capped_at_100() {
        let p = score_priority(&PriorityInputs {
            severity: "critical".into(),
            has_poc: true,
            internet_facing: true,
            high_impact_category: true,
            age_days: 9999,
        });
        assert_eq!(p.score, 100);
    }

    #[test]
    fn low_and_bare_medium_are_low_tiers() {
        assert_eq!(score_priority(&inp("low")).tier, "P3"); // 8
        assert_eq!(score_priority(&inp("medium")).tier, "P3"); // 18
    }

    #[test]
    fn tier_thresholds() {
        // medium(18)+poc(25) = 43 -> P2
        let p = PriorityInputs { severity: "medium".into(), has_poc: true, ..Default::default() };
        let s = score_priority(&p);
        assert_eq!(s.score, 43);
        assert_eq!(s.tier, "P2");
        // high(32)+poc(25)+internet(15) = 72 -> P1
        let p = PriorityInputs { severity: "high".into(), has_poc: true, internet_facing: true, ..Default::default() };
        assert_eq!(score_priority(&p).tier, "P1");
    }

    #[test]
    fn age_bump_is_capped_at_five() {
        let base = score_priority(&inp("low")).score; // 8
        let aged = score_priority(&PriorityInputs { severity: "low".into(), age_days: 90, ..Default::default() }).score;
        assert_eq!(aged - base, 5);
    }

    #[test]
    fn high_impact_classifier() {
        assert!(classify_high_impact("Blind SQL Injection in search"));
        assert!(classify_high_impact("Potential RCE via deserialization"));
        assert!(classify_high_impact("Authentication bypass on admin"));
        assert!(!classify_high_impact("Missing security header"));
        // Must not false-match benign engineering text.
        assert!(!classify_high_impact("Refactor to constructor dependency injection"));
        // Short acronyms match whole-word only — "rce" must not fire inside "source".
        assert!(!classify_high_impact("Exposed source map in production build"));
        assert!(classify_high_impact("RCE in the upload handler"));
    }

    #[test]
    fn internet_facing_classifier() {
        assert!(classify_internet_facing("External, internet-facing login portal"));
        assert!(classify_internet_facing("Publicly exposed API"));
        assert!(!classify_internet_facing("Internal admin tool"));
    }
}
