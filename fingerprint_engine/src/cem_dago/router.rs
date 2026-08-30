//! Active DAG router — ready-set from blackboard signals + manifest producers.
//! Engines never form a peer mesh; the router is the only scheduler.

use super::registry::{is_pipeline_special, manifest_for};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Default)]
pub struct PartitionedEngines {
    /// Dedicated orchestrator pipeline (ASM graph, harvest, BOLA kill-chain, …).
    pub pipeline: Vec<String>,
    /// Cognitive mesh — DAG waves + pivot + council.
    pub mesh: Vec<String>,
}

/// Split enabled engines into pipeline-special vs mesh. Order inside each list
/// is preserved from the caller (already production-filtered).
#[must_use]
pub fn partition_scan_engines(enabled: &[String]) -> PartitionedEngines {
    let mut pipeline = Vec::new();
    let mut mesh = Vec::new();
    for id in enabled {
        if is_pipeline_special(id) {
            pipeline.push(id.clone());
        } else {
            mesh.push(id.clone());
        }
    }
    PartitionedEngines { pipeline, mesh }
}

/// Static wave plan from currently known signals (used by API preview + tests).
#[must_use]
pub fn schedule_waves(
    engine_ids: &[String],
    present_signals: &HashSet<String>,
) -> Vec<Vec<String>> {
    let mut remaining: HashSet<String> = engine_ids.iter().cloned().collect();
    let mut done_signals = present_signals.clone();
    let mut waves = Vec::new();
    let mut guard = 0u32;
    while !remaining.is_empty() && guard < 64 {
        guard += 1;
        let ready = next_ready_wave(&remaining, &done_signals);
        if ready.is_empty() {
            let rest: Vec<String> = remaining.iter().cloned().collect();
            waves.push(rest);
            break;
        }
        for id in &ready {
            remaining.remove(id);
            for s in manifest_for(id).output_signals {
                done_signals.insert(s);
            }
        }
        waves.push(ready);
    }
    waves
}

/// Engines whose required inputs are either already on the blackboard **or**
/// not produced by any other still-pending engine (so we never deadlock).
#[must_use]
pub fn next_ready_wave(
    remaining: &HashSet<String>,
    present_signals: &HashSet<String>,
) -> Vec<String> {
    let producers = producers_of(remaining);
    let mut ready: Vec<String> = remaining
        .iter()
        .filter(|id| engine_is_ready(id, remaining, present_signals, &producers))
        .cloned()
        .collect();
    ready.sort();
    ready
}

fn producers_of(remaining: &HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for id in remaining {
        for sig in manifest_for(id).output_signals {
            map.entry(sig).or_default().push(id.clone());
        }
    }
    map
}

fn engine_is_ready(
    id: &str,
    remaining: &HashSet<String>,
    present_signals: &HashSet<String>,
    producers: &HashMap<String, Vec<String>>,
) -> bool {
    let manifest = manifest_for(id);
    manifest.required_inputs.iter().all(|input| {
        if present_signals.contains(input) {
            return true;
        }
        let Some(prods) = producers.get(input) else {
            return true; // nobody in this scan produces it — do not starve
        };
        !prods.iter().any(|p| p != id && remaining.contains(p))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osint_and_asm_wave0_then_web() {
        let ids = vec!["osint".into(), "asm".into(), "graphql_attack".into()];
        let present = HashSet::from(["internet_exposed".into()]);
        let waves = schedule_waves(&ids, &present);
        assert!(waves.len() >= 2);
        let flat0 = &waves[0];
        assert!(flat0.contains(&"osint".to_string()) || flat0.contains(&"asm".to_string()));
        let all: HashSet<_> = waves.into_iter().flatten().collect();
        assert!(all.contains("graphql_attack"));
    }

    #[test]
    fn partition_splits_special() {
        let ids = vec!["osint".into(), "graphql_attack".into(), "asm".into()];
        let p = partition_scan_engines(&ids);
        assert_eq!(p.pipeline, vec!["osint", "asm"]);
        assert_eq!(p.mesh, vec!["graphql_attack"]);
    }

    #[test]
    fn no_deadlock_when_producer_absent() {
        // graphql wants web_port_active; nobody in the set produces it.
        let mut rem = HashSet::from(["graphql_attack".into()]);
        let present = HashSet::new();
        let ready = next_ready_wave(&rem, &present);
        assert_eq!(ready, vec!["graphql_attack"]);
        rem.remove("graphql_attack");
        assert!(remaining_empty(&rem));
    }

    fn remaining_empty(r: &HashSet<String>) -> bool {
        r.is_empty()
    }
}
