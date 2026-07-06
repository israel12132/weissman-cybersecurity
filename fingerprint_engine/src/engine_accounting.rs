//! Honest engine accounting.
//!
//! The platform exposes 530+ engine *IDs*, but a large share are marketing aliases that resolve to
//! a shared canonical probe, plus agent-required collectors that cannot detect from a remote probe.
//! Reporting the raw ID count overstates distinct capability. This module derives a truthful
//! breakdown directly from the canonical registry so dashboards/reports can show real numbers.

use std::collections::HashSet;
use weissman_core::models::engine::{production_engine_ids, resolve_engine_id};

/// Truthful breakdown of the production engine catalog.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EngineAccounting {
    /// Total production engine IDs advertised.
    pub total_ids: usize,
    /// Distinct canonical probe implementations behind those IDs.
    pub distinct_canonical: usize,
    /// IDs that are aliases of another canonical engine (same probe, different name).
    pub alias_ids: usize,
    /// Canonical engines that require an on-host agent (no purely-remote signal).
    pub agent_required: usize,
    /// Distinct canonical engines that can detect from a remote probe (estimate:
    /// `distinct_canonical - agent_required`).
    pub remotely_detecting: usize,
    /// `distinct_canonical / total_ids` — how much of the advertised count is distinct capability.
    pub distinct_ratio: f64,
}

/// Compute the breakdown from the canonical registry. Deterministic, no I/O.
pub fn compute() -> EngineAccounting {
    let ids = production_engine_ids();
    let mut canonical: HashSet<&str> = HashSet::new();
    let mut alias_ids = 0usize;
    for &id in ids {
        let canon = resolve_engine_id(id);
        if canon != id {
            alias_ids += 1;
        }
        canonical.insert(canon);
    }
    let total_ids = ids.len();
    let distinct_canonical = canonical.len();
    let agent_required = weissman_core::models::engine_agent::AGENT_REQUIRED_ENGINES.len();
    let remotely_detecting = distinct_canonical.saturating_sub(agent_required);
    let distinct_ratio = if total_ids == 0 {
        0.0
    } else {
        (distinct_canonical as f64 / total_ids as f64 * 10000.0).round() / 10000.0
    };
    EngineAccounting {
        total_ids,
        distinct_canonical,
        alias_ids,
        agent_required,
        remotely_detecting,
        distinct_ratio,
    }
}

/// JSON form for API/report surfaces.
pub fn to_json() -> serde_json::Value {
    let a = compute();
    serde_json::json!({
        "total_ids": a.total_ids,
        "distinct_canonical": a.distinct_canonical,
        "alias_ids": a.alias_ids,
        "agent_required": a.agent_required,
        "remotely_detecting": a.remotely_detecting,
        "distinct_ratio": a.distinct_ratio,
        "note": "total_ids counts advertised engine IDs; distinct_canonical is the real number of \
                 distinct probe implementations (aliases resolve to a shared canonical engine).",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounting_is_internally_consistent() {
        let a = compute();
        assert!(a.total_ids > 0, "must advertise some engines");
        assert!(a.distinct_canonical >= 1);
        assert!(
            a.distinct_canonical <= a.total_ids,
            "distinct ({}) cannot exceed total ids ({})",
            a.distinct_canonical,
            a.total_ids
        );
        assert!(a.alias_ids <= a.total_ids);
        assert!(a.remotely_detecting <= a.distinct_canonical);
        assert!(a.distinct_ratio > 0.0 && a.distinct_ratio <= 1.0);
    }

    #[test]
    fn aliases_exist_so_id_count_is_inflated() {
        let a = compute();
        // The catalog is known to carry marketing aliases; the honest distinct count must therefore
        // be strictly below the advertised ID count.
        assert!(
            a.alias_ids > 0,
            "expected alias IDs in the catalog, found none"
        );
        assert!(
            a.distinct_canonical < a.total_ids,
            "distinct ({}) should be below advertised ({}) due to aliases",
            a.distinct_canonical,
            a.total_ids
        );
    }

    #[test]
    fn json_contains_core_fields() {
        let v = to_json();
        println!("WEISSMAN_ENGINE_ACCOUNTING {v}");
        assert!(v["total_ids"].as_u64().is_some());
        assert!(v["distinct_canonical"].as_u64().is_some());
        assert!(v["note"].as_str().is_some());
    }
}
