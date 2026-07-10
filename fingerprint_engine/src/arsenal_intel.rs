//! Arsenal-intelligence engine — the system's self-awareness of its own capabilities.
//!
//! The platform ships a large engine fleet (the *arsenal*), and [`crate::attack_coverage`] already
//! maps every ATT&CK technique to the engines that surface it. [`crate::attack_exposure`] tells us
//! what a client is actually exposed to. This module crosses the two so the platform can answer,
//! per client, three operational questions with no human triage:
//!
//!   1. **What in our arsenal handles this?** — for the client's exposed techniques, the engines to
//!      deploy, ranked by how many exposed findings each addresses. This is the one-click plan.
//!   2. **What is covered vs. not?** — how much of the exposure our arsenal can address.
//!   3. **What arsenal do we still need?** — exposed techniques no engine covers: the capability
//!      gaps that should drive new engine development.
//!
//! Pure/deterministic; the DB loader reuses [`crate::attack_exposure`] so the recommendation can
//! never disagree with the exposure view it is built from.

use crate::attack_exposure::TechniqueStat;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// One recommended engine and what it would address for this client.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EngineRecommendation {
    pub engine_id: String,
    /// Sum of findings across the exposed techniques this engine covers.
    pub addressable_findings: usize,
    pub covered_techniques: Vec<String>,
    pub tactics: Vec<String>,
}

/// A technique the client is exposed to that no engine in the arsenal covers.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ArsenalGap {
    pub technique: String,
    pub finding_count: usize,
}

/// The full arsenal-readiness picture for a client.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ArsenalReport {
    /// Distinct engines referenced by the coverage catalog (the arsenal size).
    pub arsenal_engine_count: usize,
    /// Techniques the arsenal can detect (catalog size).
    pub arsenal_technique_count: usize,
    pub exposed_techniques: usize,
    /// Exposed techniques our arsenal has at least one engine for.
    pub covered_techniques: usize,
    /// 0..100 — share of exposed techniques the arsenal covers (100 when nothing is exposed).
    pub coverage_pct: f64,
    /// The ranked one-click deployment plan.
    pub recommended_engines: Vec<EngineRecommendation>,
    /// Exposure the arsenal cannot address — the capability roadmap.
    pub gaps: Vec<ArsenalGap>,
}

#[derive(Debug, Default)]
struct EngineAcc {
    addressable_findings: usize,
    techniques: BTreeSet<String>,
    tactics: BTreeSet<String>,
}

/// Distinct engines referenced across the whole coverage catalog (the arsenal inventory).
#[must_use]
pub fn arsenal_engine_count() -> usize {
    let mut set: BTreeSet<&'static str> = BTreeSet::new();
    for t in crate::attack_coverage::catalog() {
        for e in t.engines {
            set.insert(e);
        }
    }
    set.len()
}

/// Cross a client's exposure against the arsenal. Pure/deterministic: recommendations sorted by
/// addressable findings desc then engine id; gaps by finding count desc then technique id.
#[must_use]
pub fn analyze(exposure: &[TechniqueStat]) -> ArsenalReport {
    let mut engines: BTreeMap<String, EngineAcc> = BTreeMap::new();
    let mut gaps: Vec<ArsenalGap> = Vec::new();
    let mut covered = 0usize;

    for stat in exposure {
        match crate::attack_coverage::lookup(&stat.technique) {
            Some(tech) if !tech.engines.is_empty() => {
                covered += 1;
                for eng in tech.engines {
                    let acc = engines.entry((*eng).to_string()).or_default();
                    acc.addressable_findings += stat.count;
                    acc.techniques.insert(stat.technique.clone());
                    acc.tactics.insert(tech.tactic.to_string());
                }
            }
            _ => gaps.push(ArsenalGap {
                technique: stat.technique.clone(),
                finding_count: stat.count,
            }),
        }
    }

    let mut recommended: Vec<EngineRecommendation> = engines
        .into_iter()
        .map(|(engine_id, a)| EngineRecommendation {
            engine_id,
            addressable_findings: a.addressable_findings,
            covered_techniques: a.techniques.into_iter().collect(),
            tactics: a.tactics.into_iter().collect(),
        })
        .collect();
    recommended.sort_by(|a, b| {
        b.addressable_findings
            .cmp(&a.addressable_findings)
            .then(a.engine_id.cmp(&b.engine_id))
    });

    gaps.sort_by(|a, b| {
        b.finding_count
            .cmp(&a.finding_count)
            .then(a.technique.cmp(&b.technique))
    });

    let exposed = exposure.len();
    let coverage_pct = if exposed == 0 {
        100.0
    } else {
        ((covered as f64 / exposed as f64) * 1000.0).round() / 10.0
    };

    ArsenalReport {
        arsenal_engine_count: arsenal_engine_count(),
        arsenal_technique_count: crate::attack_coverage::catalog().len(),
        exposed_techniques: exposed,
        covered_techniques: covered,
        coverage_pct,
        recommended_engines: recommended,
        gaps,
    }
}

/// Load a client's exposure and produce the arsenal recommendation. Read-only; RLS-scoped.
pub async fn load_and_analyze(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Value, String> {
    let exposure = crate::attack_exposure::load_exposure(pool, tenant_id, client_id, limit).await?;
    let report = analyze(&exposure);
    let mut v = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("ok".to_string(), json!(true));
        obj.insert("client_id".to_string(), json!(client_id));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(tech: &str, count: usize) -> TechniqueStat {
        TechniqueStat {
            technique: tech.to_string(),
            name: None,
            tactic: String::new(),
            count,
            critical: 0,
            high: count,
            medium: 0,
            low: 0,
            info: 0,
            other: 0,
        }
    }

    #[test]
    fn arsenal_inventory_is_substantial() {
        assert!(arsenal_engine_count() >= 20, "the arsenal should reference many engines");
        assert!(crate::attack_coverage::catalog().len() >= 30);
    }

    #[test]
    fn empty_exposure_is_full_coverage_with_no_plan() {
        let r = analyze(&[]);
        assert_eq!(r.exposed_techniques, 0);
        assert_eq!(r.coverage_pct, 100.0);
        assert!(r.recommended_engines.is_empty());
        assert!(r.gaps.is_empty());
        assert!(r.arsenal_engine_count > 0);
    }

    #[test]
    fn covered_technique_yields_engine_recommendations() {
        // T1190 (Exploit Public-Facing Application) is covered by several web engines.
        let r = analyze(&[stat("T1190", 5)]);
        assert_eq!(r.covered_techniques, 1);
        assert_eq!(r.coverage_pct, 100.0);
        assert!(!r.recommended_engines.is_empty());
        assert!(r
            .recommended_engines
            .iter()
            .all(|e| e.addressable_findings == 5));
        assert!(r
            .recommended_engines
            .iter()
            .any(|e| e.engine_id == "advanced_web_engines"));
    }

    #[test]
    fn unmapped_technique_becomes_a_gap() {
        let r = analyze(&[stat("T9999", 3)]);
        assert_eq!(r.covered_techniques, 0);
        assert_eq!(r.coverage_pct, 0.0);
        assert!(r.recommended_engines.is_empty());
        assert_eq!(r.gaps.len(), 1);
        assert_eq!(r.gaps[0].technique, "T9999");
        assert_eq!(r.gaps[0].finding_count, 3);
    }

    #[test]
    fn engines_ranked_by_addressable_findings() {
        // Two covered techniques; the engine covering both (if any) or the higher-count one leads.
        let r = analyze(&[stat("T1190", 10), stat("T1059", 2)]);
        // Recommendations are sorted non-increasing by addressable_findings.
        for w in r.recommended_engines.windows(2) {
            assert!(w[0].addressable_findings >= w[1].addressable_findings);
        }
        // Mixed coverage → partial percentage.
        assert!(r.coverage_pct > 0.0 && r.coverage_pct <= 100.0);
    }

    #[test]
    fn mixed_coverage_computes_partial_pct_and_both_lists() {
        let r = analyze(&[stat("T1190", 4), stat("T9999", 1)]);
        assert_eq!(r.exposed_techniques, 2);
        assert_eq!(r.covered_techniques, 1);
        assert_eq!(r.coverage_pct, 50.0);
        assert!(!r.recommended_engines.is_empty());
        assert_eq!(r.gaps.len(), 1);
    }
}
