//! Arsenal integrity & de-duplication audit — the honest, no-marketing-fluff view of the fleet.
//!
//! An arsenal is only credible if every engine in it performs a *distinct* operation. The registry
//! also carries **aliases**: ids that [`resolve_engine_id`] maps onto another canonical engine — i.e.
//! the exact same network detection logic under a second name. Those are 100%-certain duplicates,
//! and this audit surfaces every one of them with its canonical target, so the platform can present
//! a tight, real arsenal (and prune the aliases) rather than an inflated headline count.
//!
//! Classification is authoritative (`engine_capabilities::classify`, which resolves via the canonical
//! registry): each production id is exactly one of real_probe / alias / agent_required / special.
//! Pure and deterministic.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use weissman_core::models::engine::{production_engine_ids, resolve_engine_id};

/// An alias id that is a 100%-certain duplicate of another engine's network operation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AliasDuplicate {
    pub alias: String,
    /// The canonical engine this alias resolves to (same detection logic).
    pub canonical: String,
}

/// The de-duplicated integrity picture of the arsenal.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IntegrityReport {
    pub total_engines: usize,
    /// Engines with their own live dispatch arm (a distinct remote operation).
    pub distinct_engines: usize,
    /// Remote-impossible engines answered by the endpoint agent (distinct, kept).
    pub agent_required: usize,
    /// Async-only engines without a sync dispatch arm (distinct, kept).
    pub special: usize,
    /// Pure aliases — the removable fluff. Every entry is a 100% duplicate of its canonical.
    pub pure_aliases: Vec<AliasDuplicate>,
    /// Count of pure aliases (== pure_aliases.len()).
    pub alias_count: usize,
    /// The real arsenal size once aliases are collapsed onto their canonical engines.
    pub hardened_arsenal_size: usize,
    /// For each canonical engine, the aliases inflating it (how much fluff each real engine carries).
    pub duplicates_by_canonical: BTreeMap<String, Vec<String>>,
}

/// Audit the whole production arsenal for distinct operations vs. duplicate aliases. Deterministic.
#[must_use]
pub fn audit() -> IntegrityReport {
    let mut distinct = 0usize;
    let mut agent = 0usize;
    let mut special = 0usize;
    let mut aliases: Vec<AliasDuplicate> = Vec::new();
    let mut by_canonical: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for &id in production_engine_ids() {
        match crate::engine_capabilities::classify(id) {
            "alias" => {
                let canonical = resolve_engine_id(id).to_string();
                by_canonical
                    .entry(canonical.clone())
                    .or_default()
                    .push(id.to_string());
                aliases.push(AliasDuplicate {
                    alias: id.to_string(),
                    canonical,
                });
            }
            "agent_required" => agent += 1,
            "special" => special += 1,
            _ => distinct += 1, // real_probe
        }
    }
    for v in by_canonical.values_mut() {
        v.sort();
        v.dedup();
    }

    let total = production_engine_ids().len();
    let alias_count = aliases.len();
    IntegrityReport {
        total_engines: total,
        distinct_engines: distinct,
        agent_required: agent,
        special,
        alias_count,
        hardened_arsenal_size: total - alias_count,
        pure_aliases: aliases,
        duplicates_by_canonical: by_canonical,
    }
}

/// JSON audit for `GET /api/arsenal/integrity`.
#[must_use]
pub fn audit_json() -> Value {
    let r = audit();
    // Most-inflated canonicals first (biggest fluff offenders), for the operator's attention.
    let mut inflation: Vec<Value> = r
        .duplicates_by_canonical
        .iter()
        .map(|(canonical, aliases)| json!({ "canonical": canonical, "alias_count": aliases.len(), "aliases": aliases }))
        .collect();
    inflation.sort_by(|a, b| {
        b["alias_count"]
            .as_u64()
            .cmp(&a["alias_count"].as_u64())
            .then(a["canonical"].as_str().cmp(&b["canonical"].as_str()))
    });
    json!({
        "ok": true,
        "total_engines": r.total_engines,
        "hardened_arsenal_size": r.hardened_arsenal_size,
        "distinct_engines": r.distinct_engines,
        "agent_required": r.agent_required,
        "special": r.special,
        "alias_count": r.alias_count,
        "inflation_pct": if r.total_engines > 0 {
            ((r.alias_count as f64 / r.total_engines as f64) * 1000.0).round() / 10.0
        } else { 0.0 },
        "duplicate_aliases": r.pure_aliases,
        "inflation_by_canonical": inflation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_partition_the_whole_arsenal() {
        let r = audit();
        assert_eq!(
            r.distinct_engines + r.agent_required + r.special + r.alias_count,
            r.total_engines,
            "every engine must fall into exactly one bucket"
        );
        assert_eq!(r.total_engines, production_engine_ids().len());
    }

    #[test]
    fn hardened_size_removes_exactly_the_aliases() {
        let r = audit();
        assert_eq!(r.hardened_arsenal_size, r.total_engines - r.alias_count);
        assert!(r.hardened_arsenal_size <= r.total_engines);
    }

    #[test]
    fn every_pure_alias_resolves_to_a_different_canonical() {
        let r = audit();
        for a in &r.pure_aliases {
            assert_ne!(
                a.alias, a.canonical,
                "an alias must resolve to a different engine"
            );
            assert_eq!(
                resolve_engine_id(&a.alias),
                a.canonical,
                "canonical must match the registry resolution"
            );
        }
    }

    #[test]
    fn alias_count_matches_grouping() {
        let r = audit();
        let grouped: usize = r.duplicates_by_canonical.values().map(|v| v.len()).sum();
        assert_eq!(grouped, r.alias_count);
    }

    #[test]
    fn json_reports_consistent_totals() {
        let j = audit_json();
        let total = j["total_engines"].as_u64().unwrap();
        let hardened = j["hardened_arsenal_size"].as_u64().unwrap();
        let aliases = j["alias_count"].as_u64().unwrap();
        assert_eq!(hardened + aliases, total);
        assert!(j["inflation_pct"].as_f64().unwrap() >= 0.0);
    }
}
