//! FAIR extensions: multi-currency, remediation cost, business interruption, data sources.

/// Convert an amount in `currency` to USD using `fx_rate` (units of USD per 1 foreign unit).
pub fn to_usd(amount: i64, fx_rate: f64) -> i64 {
    if amount == 0 {
        return 0;
    }
    let rate = if fx_rate.is_finite() && fx_rate > 0.0 {
        fx_rate
    } else {
        1.0
    };
    ((amount as f64) * rate).round() as i64
}

pub fn from_usd(amount_usd: i64, fx_rate: f64) -> i64 {
    if amount_usd == 0 {
        return 0;
    }
    let rate = if fx_rate.is_finite() && fx_rate > 0.0 {
        fx_rate
    } else {
        1.0
    };
    ((amount_usd as f64) / rate).round() as i64
}

/// Risk-reduction ratio: expected ALE drop vs remediation cost. Higher is better.
pub fn remediation_roi(ale_before: i64, ale_after: i64, cost: i64) -> f64 {
    if cost <= 0 {
        return 0.0;
    }
    (ale_before.saturating_sub(ale_after) as f64) / (cost as f64)
}

/// Business interruption adder: days_down × daily_revenue, floored at 0.
pub fn business_interruption_usd(daily_revenue_usd: i64, days_down: f64) -> i64 {
    if daily_revenue_usd <= 0 || !days_down.is_finite() || days_down <= 0.0 {
        return 0;
    }
    ((daily_revenue_usd as f64) * days_down).round() as i64
}

pub fn data_sources_json() -> serde_json::Value {
    serde_json::json!({
        "epss": "https://api.first.org/data/v1/epss",
        "kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "formula": {
            "sle": "asset_value × max(CVSS/10, 0.5)",
            "ale": "SLE × min(EPSS×12, 12) × discount",
            "kev_aro_floor": 1.0,
            "ot_process_disruption": "high OT findings × hours_to_recover × daily_process_revenue / 24, capped at 8 findings",
            "hack_fix_verify": "ALE keeps pricing FIXED until a later successful live scan does not reproduce the corroboration key (VERIFIED_FIXED)"
        }
    })
}

/// OT/ICS asset heuristic from graph node type / label / key.
pub fn is_ot_asset(node_type: &str, label: &str, graph_key: &str) -> bool {
    let blob = format!("{node_type} {label} {graph_key}").to_ascii_lowercase();
    const TOKENS: &[&str] = &["ot", "ics", "scada", "plc", "rtu", "ied", "hmi"];
    const NEEDLES: &[&str] = &[
        "modbus", "dnp3", "iec61850", "opcua", "profinet", "bacnet", "siemens", "triton",
    ];
    let toks = blob.split(|c: char| !c.is_ascii_alphanumeric());
    if toks.clone().any(|t| TOKENS.contains(&t)) {
        return true;
    }
    NEEDLES.iter().any(|n| blob.contains(n)) || blob.contains("s7comm")
}

/// Process-disruption loss used when live OT findings exist (DeNexus gap-closer,
/// priced from *our* graph, not a vendor import).
pub fn ot_process_disruption_usd(
    ot_high_findings: u32,
    daily_process_revenue_usd: i64,
    hours_to_recover: f64,
) -> i64 {
    if ot_high_findings == 0 || daily_process_revenue_usd <= 0 {
        return 0;
    }
    if !hours_to_recover.is_finite() || hours_to_recover <= 0.0 {
        return 0;
    }
    let n = ot_high_findings.min(8) as f64;
    let days = (hours_to_recover * n) / 24.0;
    business_interruption_usd(daily_process_revenue_usd, days)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fx_roundtrip_usd() {
        assert_eq!(to_usd(100, 1.0), 100);
        assert_eq!(from_usd(100, 1.0), 100);
    }

    #[test]
    fn ils_example() {
        // 1 ILS ≈ 0.27 USD
        let usd = to_usd(10_000, 0.27);
        assert!(usd > 2_000 && usd < 3_000);
    }

    #[test]
    fn roi_positive_when_ale_drops() {
        let r = remediation_roi(100_000, 20_000, 10_000);
        assert!((r - 8.0).abs() < 0.01);
    }

    #[test]
    fn bi_zero_on_bad_inputs() {
        assert_eq!(business_interruption_usd(0, 3.0), 0);
        assert_eq!(business_interruption_usd(1000, f64::NAN), 0);
    }

    #[test]
    fn ot_disruption_scales_with_findings() {
        assert_eq!(ot_process_disruption_usd(0, 24_000, 8.0), 0);
        let one = ot_process_disruption_usd(1, 24_000, 8.0);
        let two = ot_process_disruption_usd(2, 24_000, 8.0);
        assert!(one > 0 && two > one);
        assert!(is_ot_asset("plc", "Siemens S7", "site/modbus"));
        assert!(!is_ot_asset("web", "www", "app/frontend"));
    }
}
