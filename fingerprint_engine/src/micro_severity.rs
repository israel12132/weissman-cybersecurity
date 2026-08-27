//! Micro-Severity — SOC analyst **local ranking** only.
//!
//! Linear product `severity_weight × asset_criticality × exposure`.
//! Architect rule: this formula is **never** residual financial risk, **never** a
//! USD blast-radius, and **must not** be the Command Center / PDF / Kill-Chain
//! Commander headline. Those surfaces use [`crate::financial_risk`] FAIR SLE/ALE.

use serde::Serialize;

/// Published product — SOC ranking, not money.
pub const EXPRESSION: &str = "severity_weight × asset_criticality × exposure";
pub const METHOD: &str = "micro_severity_product";
pub const LABEL: &str = "Micro-Severity (SOC analyst local ranking)";
pub const NOT_RESIDUAL: &str =
    "Not residual financial risk. Not a USD blast-radius. Executive dollars come only from FAIR SLE/ALE.";

pub const SEV_CRITICAL: f64 = 5.0;
pub const SEV_HIGH: f64 = 4.0;
pub const SEV_MEDIUM: f64 = 3.0;
pub const SEV_LOW: f64 = 2.0;
pub const SEV_INFO: f64 = 1.0;
pub const CRIT_CROWN: f64 = 2.5;
pub const EXP_INTERNET: f64 = 2.0;
pub const EXP_INTERNAL: f64 = 1.0;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MicroSeveritySpec {
    pub method: &'static str,
    pub label: &'static str,
    pub expression: &'static str,
    pub not_residual_financial_risk: bool,
    pub note: &'static str,
}

#[must_use]
pub fn spec() -> MicroSeveritySpec {
    MicroSeveritySpec {
        method: METHOD,
        label: LABEL,
        expression: EXPRESSION,
        not_residual_financial_risk: true,
        note: NOT_RESIDUAL,
    }
}

#[must_use]
pub fn severity_weight(normalized_sev: &str) -> f64 {
    match normalized_sev {
        "critical" => SEV_CRITICAL,
        "high" => SEV_HIGH,
        "medium" => SEV_MEDIUM,
        "low" => SEV_LOW,
        _ => SEV_INFO,
    }
}

/// Linear product for SOC queue ranking. Never convert this to USD.
#[must_use]
pub fn score(severity_weight: f64, asset_criticality: f64, exposure: f64) -> f64 {
    ((severity_weight * asset_criticality * exposure) * 100.0).round() / 100.0
}

/// JSON contract nested under cockpit/PDF/kill-chain payloads so the UI can
/// label SOC ranking without mistaking it for FAIR dollars.
#[must_use]
pub fn api_object(local_score: Option<f64>) -> serde_json::Value {
    serde_json::json!({
        "method": METHOD,
        "label": LABEL,
        "expression": EXPRESSION,
        "not_residual_financial_risk": true,
        "note": NOT_RESIDUAL,
        "score": local_score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_is_severity_times_criticality_times_exposure() {
        assert_eq!(score(5.0, 2.5, 2.0), 25.0);
        assert_eq!(score(3.0, 1.0, 1.0), 3.0);
    }

    #[test]
    fn contract_refuses_to_claim_financial_risk() {
        let v = api_object(Some(12.0));
        assert_eq!(v["method"], METHOD);
        assert_eq!(v["not_residual_financial_risk"], true);
        assert!(v.get("ale_annualised_usd").is_none());
        assert!(v.get("sle_worst_usd").is_none());
        assert!(v.get("priced_usd").is_none());
    }
}
