//! Critical-infrastructure engines — compartmentalized high-risk OT/ICS probes.
//!
//! These engines are **not** on the permissive web-scanner path. Execution requires:
//! - compile-time `high_risk_engines` feature on the binary
//! - runtime Rules of Engagement (RoE) preflight (signed contract or explicit authorization + whitelist)
//! - findings tagged `CRITICAL_RISK` with immediate Command Center telemetry

pub mod roe;
pub mod telemetry;

#[cfg(feature = "high_risk_engines")]
mod engines;

use crate::arsenal_config::{finding_rich, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_result::EngineResult;
use serde_json::{json, Value};

/// Canonical production IDs for critical-infrastructure attack engines.
pub const ENGINE_IDS: &[&str] = &[
    "avionics_adsb_attack",
    "maritime_ais_attack",
    "ev_charging_ocpp_attack",
    "smart_grid_dlms_attack",
    "rail_signaling_attack",
    "building_automation_attack",
    "robotics_ros2_attack",
    "ot_sis_triton_attack",
];

#[must_use]
pub fn is_critical_infra_engine(engine_id: &str) -> bool {
    let id = engine_id.trim();
    ENGINE_IDS.contains(&id)
        || ENGINE_IDS.contains(&weissman_core::models::engine::dispatch_engine_id(id))
}

/// What the engine would do if every RoE gate passed — live read-only probes only, never invented findings.
#[must_use]
pub fn would_run_if_authorized(engine_id: &str) -> &'static str {
    match weissman_core::models::engine::dispatch_engine_id(engine_id.trim()) {
        "avionics_adsb_attack" => {
            "Live ADS-B feeder, Beast input, SBS BaseStation, and ACARS port identification (read-only)"
        }
        "maritime_ais_attack" => {
            "AIS/NMEA TCP feed and gpsd socket identification on maritime navigation hosts (read-only)"
        }
        "ev_charging_ocpp_attack" => {
            "OCPP WebSocket upgrade and SteVe management UI fingerprinting on EV charging central systems (read-only)"
        }
        "smart_grid_dlms_attack" => {
            "IEC 60870-5-104 STARTDT handshake and DLMS/COSEM meter-port reachability (read-only)"
        }
        "rail_signaling_attack" => {
            "Rail SCADA telecontrol surface mapping — IEC-104, Modbus, DNP3, OPC-UA (read-only)"
        }
        "building_automation_attack" => {
            "KNXnet/IP SEARCH_REQUEST, Niagara Fox banner, and LonWorks/IP discovery (read-only)"
        }
        "robotics_ros2_attack" => {
            "ROS XML-RPC getSystemState and Universal Robots dashboard port reachability (read-only)"
        }
        "ot_sis_triton_attack" => {
            "Triconex TriStation safety-instrumented-system reachability mapping (read-only)"
        }
        _ => "Authorized critical-infrastructure protocol identification (read-only; no ICS findings are invented)",
    }
}

/// Tag a finding for immediate, unbatched Command Center alerting.
#[must_use]
pub fn tag_critical_risk(mut finding: Value) -> Value {
    if let Some(obj) = finding.as_object_mut() {
        obj.insert("risk_class".to_string(), json!("CRITICAL_RISK"));
        obj.insert("telemetry_priority".to_string(), json!("immediate"));
        obj.insert("roe_tier".to_string(), json!("critical_infrastructure"));
        obj.insert("bypass_batch".to_string(), json!(true));
    }
    finding
}

/// Rich finding builder with mandatory `CRITICAL_RISK` classification.
#[must_use]
pub fn critical_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    confidence: f64,
    evidence: Evidence,
) -> Value {
    tag_critical_risk(finding_rich(
        engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        evidence,
    ))
}

#[must_use]
pub fn is_critical_risk_finding(finding: &Value) -> bool {
    finding
        .get("risk_class")
        .and_then(Value::as_str)
        .is_some_and(|s| s.eq_ignore_ascii_case("CRITICAL_RISK"))
}

/// Dispatch a RoE-gated critical-infrastructure engine (canonical ID).
#[cfg(feature = "high_risk_engines")]
pub async fn dispatch(canonical: &str, target: &str, ctx: &EngineRunContext) -> EngineResult {
    use engines::{
        run_avionics_adsb_attack_result, run_building_automation_attack_result,
        run_ev_charging_ocpp_attack_result, run_maritime_ais_attack_result,
        run_ot_sis_triton_result, run_rail_signaling_attack_result,
        run_robotics_ros2_attack_result, run_smart_grid_dlms_attack_result,
    };

    match canonical {
        "avionics_adsb_attack" => run_avionics_adsb_attack_result(target, ctx).await,
        "maritime_ais_attack" => run_maritime_ais_attack_result(target, ctx).await,
        "ev_charging_ocpp_attack" => run_ev_charging_ocpp_attack_result(target, ctx).await,
        "smart_grid_dlms_attack" => run_smart_grid_dlms_attack_result(target, ctx).await,
        "rail_signaling_attack" => run_rail_signaling_attack_result(target, ctx).await,
        "building_automation_attack" => run_building_automation_attack_result(target, ctx).await,
        "robotics_ros2_attack" => run_robotics_ros2_attack_result(target, ctx).await,
        "ot_sis_triton_attack" => run_ot_sis_triton_result(target, ctx).await,
        other => EngineResult::error(format!(
            "critical infrastructure engine '{other}' is not registered"
        )),
    }
}

#[cfg(not(feature = "high_risk_engines"))]
pub async fn dispatch(canonical: &str, _target: &str, _ctx: &EngineRunContext) -> EngineResult {
    EngineResult::error(format!(
        "critical infrastructure engine '{canonical}' requires binary compiled with `high_risk_engines` feature"
    ))
}

/// Ensure every finding carries CRITICAL_RISK tags and emit immediate telemetry.
pub async fn postprocess_result(
    engine_id: &str,
    target: &str,
    ctx: &EngineRunContext,
    result: &mut EngineResult,
) {
    for f in &mut result.findings {
        *f = tag_critical_risk(f.clone());
    }
    telemetry::emit_critical_risk_execution(
        ctx,
        engine_id,
        target,
        result.findings.len(),
        &result.message,
    )
    .await;
    for f in &result.findings {
        telemetry::emit_critical_risk_finding(ctx, engine_id, target, f).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn registry_covers_all_ids() {
        assert_eq!(ENGINE_IDS.len(), 8);
        assert!(is_critical_infra_engine("smart_grid_dlms_attack"));
        assert!(!is_critical_infra_engine("osint"));
    }

    #[test]
    fn critical_finding_tagged() {
        let f = critical_finding(
            "smart_grid_dlms_attack",
            "test",
            "critical",
            "T0855",
            "desc",
            "10.0.0.1",
            0.9,
            Evidence::new(),
        );
        assert!(is_critical_risk_finding(&f));
        assert_eq!(f["telemetry_priority"], json!("immediate"));
    }
}
