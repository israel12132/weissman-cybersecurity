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
            "kev_aro_floor": 1.0
        }
    })
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
}
