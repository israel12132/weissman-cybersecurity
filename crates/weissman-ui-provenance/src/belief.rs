//! Risk Superposition Collapse belief fusion — must match `risk_superposition_collapse_engine.rs`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusionMode {
    NoisyOr,
    LogOdds,
    Hybrid,
}

impl FusionMode {
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "noisy_or" => Self::NoisyOr,
            "log_odds" => Self::LogOdds,
            _ => Self::Hybrid,
        }
    }
}

/// Independent corroboration (noisy-or): `1 − ∏(1 − pᵢ)`.
#[must_use]
pub fn noisy_or_belief(probs: &[f64]) -> f64 {
    if probs.is_empty() {
        return 0.0;
    }
    let product: f64 = probs.iter().map(|p| 1.0 - p.clamp(0.0, 1.0)).product();
    (1.0 - product).clamp(0.0, 1.0)
}

/// Cumulative-odds fusion — sums independent odds.
#[must_use]
pub fn log_odds_fusion(probs: &[f64]) -> f64 {
    if probs.is_empty() {
        return 0.0;
    }
    let odds_sum: f64 = probs
        .iter()
        .map(|p| {
            let p = p.clamp(0.01, 0.99);
            p / (1.0 - p)
        })
        .sum();
    (odds_sum / (1.0 + odds_sum)).clamp(0.0, 1.0)
}

#[must_use]
pub fn temporal_decay(age_hours: f64, halflife_hours: f64) -> f64 {
    if halflife_hours <= 0.0 {
        return 1.0;
    }
    0.5_f64.powf((age_hours / halflife_hours).max(0.0))
}

#[must_use]
pub fn risk_to_belief(effective_risk: f64, confidence: f64) -> f64 {
    ((effective_risk / 10.0) * confidence.clamp(0.1, 1.0)).clamp(0.0, 1.0)
}

#[must_use]
pub fn collapse_belief(probs: &[f64], mode: FusionMode) -> f64 {
    match mode {
        FusionMode::NoisyOr => noisy_or_belief(probs),
        FusionMode::LogOdds => log_odds_fusion(probs),
        FusionMode::Hybrid => noisy_or_belief(probs).max(log_odds_fusion(probs)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noisy_or_fuses_independent_beliefs() {
        let p = noisy_or_belief(&[0.2, 0.3]);
        assert!(p > 0.44 && p < 0.46);
    }

    #[test]
    fn hybrid_lifts_weak_signals() {
        let probs = vec![0.15, 0.12, 0.18];
        let h = collapse_belief(&probs, FusionMode::Hybrid);
        assert!(h > 0.35);
    }
}
