//! Board-level security posture score.
//!
//! Every other module answers a slice of the question — what to fix, by when, which controls,
//! which ATT&CK techniques. A board wants one honest number. This module distills the same live
//! "fix-first" program into a 0..100 posture score (higher = healthier) with an A–F grade, four
//! transparent sub-scores, and plain-language drivers. It is deterministic and evidence-backed:
//! it reads the exact [`crate::remediation_priority`] program the remediation view shows, so the
//! score can never disagree with the queue behind it.
//!
//! Scoring model: each sub-score starts at a perfect 100 and loses points for open risk, then the
//! overall is a fixed-weight blend. Weights and penalties are named constants so the model is
//! auditable rather than a black box.

use crate::remediation_priority::{RemediationItem, SlaState};
use serde::Serialize;
use serde_json::{json, Value};

// Sub-score weights (sum = 1.0).
const W_EXPLOITABILITY: f64 = 0.35;
const W_TIMELINESS: f64 = 0.30;
const W_BUSINESS_EXPOSURE: f64 = 0.20;
const W_SEVERITY_LOAD: f64 = 0.15;

// Exploitability penalties (per action).
const PEN_RANSOMWARE: f64 = 25.0;
const PEN_KEV: f64 = 12.0;
const PEN_CRITICAL_RISK: f64 = 6.0; // effective_risk >= 9, not KEV
const PEN_HIGH_RISK: f64 = 3.0; // effective_risk >= 7, not KEV

// Timeliness penalties (per action).
const PEN_OVERDUE_KEV: f64 = 20.0;
const PEN_OVERDUE: f64 = 8.0;
const PEN_DUE_SOON: f64 = 2.0;

// Business-exposure penalties (per action).
const PEN_CROWN_JEWEL: f64 = 15.0;
const PEN_CHOKE_POINT: f64 = 8.0;

// Severity-load penalties (per action).
const PEN_SEV_CRITICAL: f64 = 4.0;
const PEN_SEV_HIGH: f64 = 2.0;

// Hard caps encode "one truly bad thing is a bad posture, however few" — a security truth that
// per-action penalties alone would dilute across a large program.
const CAP_EXPLOIT_RANSOMWARE: f64 = 35.0; // any ransomware-associated KEV open
const CAP_EXPLOIT_KEV: f64 = 60.0; // any (non-ransomware) KEV open
const CAP_TIMELINESS_OVERDUE_KEV: f64 = 35.0; // any KEV action past SLA
const CAP_TIMELINESS_OVERDUE: f64 = 65.0; // any action past SLA

/// The four transparent sub-scores (each 0..100, higher = healthier).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SubScores {
    pub exploitability_control: f64,
    pub remediation_timeliness: f64,
    pub business_exposure: f64,
    pub severity_load: f64,
}

/// A board-ready posture verdict.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PostureScore {
    pub score: f64,
    pub grade: char,
    pub sub_scores: SubScores,
    /// The largest drivers pulling the score down, most significant first.
    pub drivers: Vec<String>,
    pub remediation_actions: usize,
    pub total_findings: usize,
}

fn clamp_score(v: f64) -> f64 {
    (v.clamp(0.0, 100.0) * 10.0).round() / 10.0
}

fn grade_for(score: f64) -> char {
    match score {
        s if s >= 90.0 => 'A',
        s if s >= 80.0 => 'B',
        s if s >= 70.0 => 'C',
        s if s >= 60.0 => 'D',
        _ => 'F',
    }
}

/// Compute the posture score from a ranked remediation program. Pure and deterministic.
///
/// `total_findings` is reported for context (a score of 100 with zero findings means "nothing
/// open", which could also mean "not yet scanned" — the caller surfaces the count so that's visible).
#[must_use]
pub fn score(items: &[RemediationItem], total_findings: usize) -> PostureScore {
    let mut exploit_pen = 0.0;
    let mut timeliness_pen = 0.0;
    let mut business_pen = 0.0;
    let mut severity_pen = 0.0;

    let mut ransomware = 0usize;
    let mut kev = 0usize;
    let mut overdue_kev = 0usize;
    let mut overdue = 0usize;
    let mut crown = 0usize;
    let mut choke = 0usize;

    for it in items {
        // Exploitability.
        if it.kev_ransomware {
            exploit_pen += PEN_RANSOMWARE;
            ransomware += 1;
        } else if it.kev {
            exploit_pen += PEN_KEV;
            kev += 1;
        } else if it.max_effective_risk >= 9.0 {
            exploit_pen += PEN_CRITICAL_RISK;
        } else if it.max_effective_risk >= 7.0 {
            exploit_pen += PEN_HIGH_RISK;
        }

        // Timeliness.
        match it.sla.state {
            SlaState::Overdue => {
                if it.kev || it.kev_ransomware {
                    timeliness_pen += PEN_OVERDUE_KEV;
                    overdue_kev += 1;
                } else {
                    timeliness_pen += PEN_OVERDUE;
                    overdue += 1;
                }
            }
            SlaState::DueSoon => timeliness_pen += PEN_DUE_SOON,
            _ => {}
        }

        // Business exposure.
        if it.crown_jewel {
            business_pen += PEN_CROWN_JEWEL;
            crown += 1;
        }
        if it.on_choke_point {
            business_pen += PEN_CHOKE_POINT;
            choke += 1;
        }

        // Severity load.
        if it.max_effective_risk >= 9.0 {
            severity_pen += PEN_SEV_CRITICAL;
        } else if it.max_effective_risk >= 7.0 {
            severity_pen += PEN_SEV_HIGH;
        }
    }

    // Apply hard caps for the presence of severe conditions.
    let mut exploit = 100.0 - exploit_pen;
    if ransomware > 0 {
        exploit = exploit.min(CAP_EXPLOIT_RANSOMWARE);
    } else if kev > 0 {
        exploit = exploit.min(CAP_EXPLOIT_KEV);
    }
    let mut timeliness = 100.0 - timeliness_pen;
    if overdue_kev > 0 {
        timeliness = timeliness.min(CAP_TIMELINESS_OVERDUE_KEV);
    } else if overdue > 0 {
        timeliness = timeliness.min(CAP_TIMELINESS_OVERDUE);
    }

    let sub = SubScores {
        exploitability_control: clamp_score(exploit),
        remediation_timeliness: clamp_score(timeliness),
        business_exposure: clamp_score(100.0 - business_pen),
        severity_load: clamp_score(100.0 - severity_pen),
    };

    let overall = clamp_score(
        W_EXPLOITABILITY * sub.exploitability_control
            + W_TIMELINESS * sub.remediation_timeliness
            + W_BUSINESS_EXPOSURE * sub.business_exposure
            + W_SEVERITY_LOAD * sub.severity_load,
    );

    // Drivers, ordered by how much they hurt.
    let mut drivers: Vec<(f64, String)> = Vec::new();
    if ransomware > 0 {
        drivers.push((
            ransomware as f64 * PEN_RANSOMWARE,
            format!("{ransomware} ransomware-associated KEV action(s) open"),
        ));
    }
    if overdue_kev > 0 {
        drivers.push((
            overdue_kev as f64 * PEN_OVERDUE_KEV,
            format!("{overdue_kev} KEV action(s) past SLA"),
        ));
    }
    if kev > 0 {
        drivers.push((kev as f64 * PEN_KEV, format!("{kev} KEV action(s) open")));
    }
    if crown > 0 {
        drivers.push((
            crown as f64 * PEN_CROWN_JEWEL,
            format!("{crown} crown-jewel asset(s) exposed"),
        ));
    }
    if overdue > 0 {
        drivers.push((
            overdue as f64 * PEN_OVERDUE,
            format!("{overdue} action(s) past SLA"),
        ));
    }
    if choke > 0 {
        drivers.push((
            choke as f64 * PEN_CHOKE_POINT,
            format!("{choke} attack-path choke point(s) open"),
        ));
    }
    drivers.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
    });
    let drivers: Vec<String> = drivers.into_iter().take(5).map(|(_, s)| s).collect();

    PostureScore {
        score: overall,
        grade: grade_for(overall),
        sub_scores: sub,
        drivers,
        remediation_actions: items.len(),
        total_findings,
    }
}

/// Load a client's live findings, rank them, and compute the posture score. Read-only; RLS-scoped.
pub async fn load_and_score(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Value, String> {
    let findings = crate::remediation_priority::load_findings(pool, tenant_id, client_id, limit)
        .await?;
    let total_findings = findings.len();
    let program = crate::remediation_priority::rank(&findings);
    let posture = score(&program, total_findings);

    Ok(json!({
        "ok": true,
        "client_id": client_id,
        "posture": posture,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation_priority::{rank, FindingInput};

    fn finding(id: &str, sev: &str, er: Option<f64>) -> FindingInput {
        FindingInput {
            finding_id: id.to_string(),
            title: format!("finding {id}"),
            severity: sev.to_string(),
            cwe: format!("CWE-{id}"), // distinct groups so each finding is its own action
            asset: format!("asset-{id}.example.com"),
            effective_risk: er,
            epss: None,
            kev: false,
            kev_ransomware: false,
            cluster_id: None,
            on_choke_point: false,
            crown_jewel: false,
            asset_value: 1.0,
            business_value_usd: None,
            first_seen_days: None,
        }
    }

    #[test]
    fn empty_program_is_a_perfect_a() {
        let p = score(&[], 0);
        assert_eq!(p.score, 100.0);
        assert_eq!(p.grade, 'A');
        assert!(p.drivers.is_empty());
        assert_eq!(p.total_findings, 0);
    }

    #[test]
    fn grade_thresholds_map_correctly() {
        assert_eq!(grade_for(90.0), 'A');
        assert_eq!(grade_for(89.9), 'B');
        assert_eq!(grade_for(80.0), 'B');
        assert_eq!(grade_for(70.0), 'C');
        assert_eq!(grade_for(60.0), 'D');
        assert_eq!(grade_for(59.9), 'F');
    }

    #[test]
    fn ransomware_kev_crushes_the_score() {
        let mut f = finding("a", "critical", Some(9.5));
        f.kev = true;
        f.kev_ransomware = true;
        f.first_seen_days = Some(90); // well past the 7-day ransomware SLA → overdue
        f.crown_jewel = true;
        f.on_choke_point = true;
        let program = rank(&[f]);
        let p = score(&program, 1);
        assert!(p.score < 60.0, "worst-case posture should be failing, got {}", p.score);
        assert_eq!(p.grade, 'F');
        // The most punishing driver is listed first.
        assert!(p.drivers[0].contains("ransomware"));
    }

    #[test]
    fn a_single_low_finding_barely_dents_posture() {
        let program = rank(&[finding("a", "low", Some(2.0))]);
        let p = score(&program, 1);
        assert!(p.score >= 90.0, "one low finding should stay an A, got {}", p.score);
        assert_eq!(p.grade, 'A');
    }

    #[test]
    fn sub_scores_are_independent() {
        // A crown-jewel medium (no KEV, on track) hits business_exposure but not exploitability.
        let mut f = finding("a", "medium", Some(5.0));
        f.crown_jewel = true;
        f.first_seen_days = Some(0); // fresh → on track
        let program = rank(&[f]);
        let p = score(&program, 1);
        assert_eq!(p.sub_scores.exploitability_control, 100.0);
        assert!(p.sub_scores.business_exposure < 100.0);
        assert!(p.drivers.iter().any(|d| d.contains("crown-jewel")));
    }

    #[test]
    fn score_is_deterministic() {
        let program = rank(&[
            finding("a", "high", Some(7.5)),
            finding("b", "critical", Some(9.2)),
        ]);
        assert_eq!(score(&program, 2), score(&program, 2));
    }
}
