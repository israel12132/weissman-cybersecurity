//! Isolated OT / APT / web run queues inside a DAG wave.
//!
//! OT probes need bounded, careful concurrency; web fuzzing is bursty. Mixing them
//! on one semaphore lets fuzzing starve ICS. Lanes share a wave (no dependency)
//! but use separate permits. Join is always `join_all` / `tokio::join!` — never
//! `try_join!` / `try_join_all`, so one Modbus timeout cannot abort the web half.

use super::manifest::EdgeKind;
use super::registry::manifest_for;
use weissman_core::models::engine::resolve_engine_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineLane {
    Ot,
    Apt,
    Web,
}

#[must_use]
pub fn engine_lane(id: &str) -> EngineLane {
    let canonical = resolve_engine_id(id);
    match crate::engine_requirements::engine_group(canonical) {
        Some("ot") => EngineLane::Ot,
        Some("apt") => EngineLane::Apt,
        _ => {
            let m = manifest_for(id);
            if m.edge_kinds.contains(&EdgeKind::OtProtocol) {
                EngineLane::Ot
            } else {
                EngineLane::Web
            }
        }
    }
}

pub fn partition_lanes(ids: &[String]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut ot = Vec::new();
    let mut apt = Vec::new();
    let mut web = Vec::new();
    for id in ids {
        match engine_lane(id) {
            EngineLane::Ot => ot.push(id.clone()),
            EngineLane::Apt => apt.push(id.clone()),
            EngineLane::Web => web.push(id.clone()),
        }
    }
    (ot, apt, web)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scada_is_ot_graphql_is_web() {
        assert_eq!(engine_lane("scada_ics"), EngineLane::Ot);
        assert_eq!(engine_lane("graphql_attack"), EngineLane::Web);
    }

    #[test]
    fn partition_isolates_ot() {
        let ids = vec![
            "scada_ics".into(),
            "graphql_attack".into(),
            "iot_firmware".into(),
        ];
        let (ot, _apt, web) = partition_lanes(&ids);
        assert!(ot.contains(&"scada_ics".to_string()));
        assert!(ot.contains(&"iot_firmware".to_string()));
        assert_eq!(web, vec!["graphql_attack"]);
    }
}
