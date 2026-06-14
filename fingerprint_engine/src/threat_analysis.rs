//! Unified threat-analysis composition.
//!
//! Ties the new algorithmic cores into one incident-level view over a single engagement's signals:
//!
//!   * [`crate::attack_chain_planner`] — the cheapest realizable attack chain to objective, grounded
//!     in observed findings;
//!   * [`crate::correlation_rules`] — multi-stage kill-chain correlation across findings;
//!   * [`crate::ndr_beacon`] — network beaconing / exfiltration from flow samples;
//!   * [`crate::itdr`] — identity threats from auth events.
//!
//! Produces a composite `incident_score` so a SOC sees one prioritized picture instead of four
//! disconnected signal streams. Pure and unit-tested.

use crate::{attack_chain_planner, correlation_rules, itdr, ndr_beacon};

/// Default objective the planner tries to reach.
const DEFAULT_GOAL: &str = "impact:objective";

fn finding_ts(index: usize, f: &serde_json::Value) -> i64 {
    for key in ["ts", "discovered_at", "first_seen_ts"] {
        if let Some(n) = f.get(key).and_then(serde_json::Value::as_i64) {
            return n;
        }
    }
    // Stable monotonic fallback preserves input ordering for the window logic.
    1000 + (index as i64) * 60
}

/// Compose a unified incident report from the available signals. Any slice may be empty.
pub fn analyze(
    findings: &[serde_json::Value],
    flows: &[ndr_beacon::FlowSample],
    auth: &[itdr::AuthEvent],
) -> serde_json::Value {
    // 1) Attack-chain plan (offense): grounded path to objective, if reachable from evidence.
    let chain = attack_chain_planner::plan_from_findings(findings, DEFAULT_GOAL);

    // 2) Multi-stage correlation (defense): kill-chain progression across findings.
    let events = correlation_rules::events_from_findings(findings, finding_ts);
    let corr_hits = correlation_rules::evaluate_all(&correlation_rules::default_rules(), &events);

    // 3) NDR (network): beaconing + exfiltration.
    let ndr = ndr_beacon::analyze(flows, &ndr_beacon::NdrConfig::default());

    // 4) ITDR (identity): impossible travel, spray, brute force, MFA fatigue.
    let id_findings = itdr::analyze(auth, &itdr::ItdrConfig::default());

    // Composite, bounded incident score.
    let mut score: f64 = 0.0;
    if chain.as_ref().map(|c| c.reached_goal).unwrap_or(false) {
        score += 40.0;
    }
    score += (corr_hits.len() as f64) * 20.0;
    score += ndr
        .iter()
        .map(|f| if f.severity == "critical" { 15.0 } else { 8.0 })
        .sum::<f64>();
    score += id_findings
        .iter()
        .map(|f| if f.severity == "high" { 12.0 } else { 6.0 })
        .sum::<f64>();
    let incident_score = score.min(100.0);

    serde_json::json!({
        "incident_score": (incident_score * 100.0).round() / 100.0,
        "attack_chain": chain.as_ref().map(attack_chain_planner::AttackChain::to_json),
        "correlation_hits": corr_hits.iter().map(correlation_rules::CorrelationHit::to_json).collect::<Vec<_>>(),
        "network_findings": serde_json::to_value(&ndr).unwrap_or_else(|_| serde_json::json!([])),
        "identity_findings": serde_json::to_value(&id_findings).unwrap_or_else(|_| serde_json::json!([])),
        "summary": {
            "reached_objective": chain.as_ref().map(|c| c.reached_goal).unwrap_or(false),
            "correlation_incidents": corr_hits.len(),
            "network_detections": ndr.len(),
            "identity_detections": id_findings.len(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_signals_produce_high_incident_score() {
        let findings = vec![
            serde_json::json!({"mitre_attack":"T1595","type":"recon","title":"scan","severity":"info","target":"app.example.com","ts":1000}),
            serde_json::json!({"mitre_attack":"T1190","type":"poe","title":"rce","severity":"critical","verified":true,"target":"app.example.com","ts":1100}),
            serde_json::json!({"mitre_attack":"T1068","type":"privesc","title":"sudo","severity":"high","target":"app.example.com","ts":1200}),
            serde_json::json!({"mitre_attack":"T1567","type":"exfil","title":"dump","severity":"critical","target":"app.example.com","ts":1300}),
        ];
        let report = analyze(&findings, &[], &[]);
        assert_eq!(report["summary"]["reached_objective"], true);
        assert_eq!(report["summary"]["correlation_incidents"], 1);
        assert!(report["incident_score"].as_f64().unwrap() >= 60.0);
        assert!(report["attack_chain"]["reached_goal"].as_bool().unwrap());
    }

    #[test]
    fn benign_signals_score_low() {
        let findings = vec![
            serde_json::json!({"type":"banner","title":"server header","severity":"info","verified":false,"target":"x"}),
        ];
        let report = analyze(&findings, &[], &[]);
        assert_eq!(report["summary"]["reached_objective"], false);
        assert_eq!(report["incident_score"].as_f64().unwrap(), 0.0);
    }

    #[test]
    fn integrates_network_and_identity_signals() {
        let flows: Vec<ndr_beacon::FlowSample> = (0..10)
            .map(|i| ndr_beacon::FlowSample::new(i * 60, "c2.example", 256))
            .collect();
        let auth = vec![
            itdr::AuthEvent::new(0, "alice", "1.1.1.1", "US", true, false),
            itdr::AuthEvent::new(600, "alice", "2.2.2.2", "DE", true, false),
        ];
        let report = analyze(&[], &flows, &auth);
        assert!(report["summary"]["network_detections"].as_u64().unwrap() >= 1);
        assert!(report["summary"]["identity_detections"].as_u64().unwrap() >= 1);
        assert!(report["incident_score"].as_f64().unwrap() > 0.0);
    }
}
