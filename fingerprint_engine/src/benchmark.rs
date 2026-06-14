//! Detection benchmark harness — measurable repro-rate (recall) and false-positive rate.
//!
//! World-class detection is a *measured* claim, not a marketing one. This harness records, per
//! benchmark case, whether a real engine produced a detection on a target whose ground truth is
//! known (a deliberately-vulnerable fixture vs. a benign one), then aggregates into the two metrics
//! that matter:
//!
//!   * **repro-rate** (recall) = `TP / (TP + FN)` — of the things we *should* catch, how many did we?
//!   * **fp-rate**            = `FP / (FP + TN)` — of the benign cases, how many did we wrongly flag?
//!
//! The harness itself does no mocking of engine internals: callers run the actual engine against an
//! actual (local) HTTP fixture and feed the observed outcome here. This module is the pure
//! aggregation/reporting layer and is fully unit-tested; the live wiring lives in
//! `tests/benchmark_repro.rs`.

use serde::Serialize;

/// Confusion-matrix classification of a single benchmark case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Classification {
    TruePositive,
    FalseNegative,
    FalsePositive,
    TrueNegative,
}

impl Classification {
    pub fn label(&self) -> &'static str {
        match self {
            Classification::TruePositive => "true_positive",
            Classification::FalseNegative => "false_negative",
            Classification::FalsePositive => "false_positive",
            Classification::TrueNegative => "true_negative",
        }
    }
}

/// Map ground truth + observed detection to a confusion-matrix cell. Pure.
pub fn classify(expected_detection: bool, detected: bool) -> Classification {
    match (expected_detection, detected) {
        (true, true) => Classification::TruePositive,
        (true, false) => Classification::FalseNegative,
        (false, true) => Classification::FalsePositive,
        (false, false) => Classification::TrueNegative,
    }
}

/// One benchmark case: a real engine run against a target with known ground truth.
#[derive(Debug, Clone, Serialize)]
pub struct BenchOutcome {
    pub name: String,
    pub engine: String,
    /// Ground truth: should this engine detect on this target?
    pub expected_detection: bool,
    /// Observed: did the engine detect?
    pub detected: bool,
    /// Number of findings the engine returned (for context).
    pub findings: usize,
    /// Free-form note (engine message, evidence hash, etc.).
    pub detail: String,
}

impl BenchOutcome {
    pub fn new(
        name: impl Into<String>,
        engine: impl Into<String>,
        expected_detection: bool,
        detected: bool,
        findings: usize,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            engine: engine.into(),
            expected_detection,
            detected,
            findings,
            detail: detail.into(),
        }
    }

    pub fn classification(&self) -> Classification {
        classify(self.expected_detection, self.detected)
    }

    pub fn correct(&self) -> bool {
        self.expected_detection == self.detected
    }
}

/// Confusion-matrix counts.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Counts {
    pub true_positive: usize,
    pub false_negative: usize,
    pub false_positive: usize,
    pub true_negative: usize,
}

/// Aggregated benchmark report.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BenchReport {
    pub outcomes: Vec<BenchOutcome>,
}

impl BenchReport {
    pub fn new() -> Self {
        Self {
            outcomes: Vec::new(),
        }
    }

    pub fn push(&mut self, o: BenchOutcome) {
        self.outcomes.push(o);
    }

    pub fn counts(&self) -> Counts {
        let mut c = Counts::default();
        for o in &self.outcomes {
            match o.classification() {
                Classification::TruePositive => c.true_positive += 1,
                Classification::FalseNegative => c.false_negative += 1,
                Classification::FalsePositive => c.false_positive += 1,
                Classification::TrueNegative => c.true_negative += 1,
            }
        }
        c
    }

    /// Recall over positive-ground-truth cases. Returns 1.0 when there are no positive cases
    /// (nothing was there to miss).
    pub fn repro_rate(&self) -> f64 {
        let c = self.counts();
        let denom = c.true_positive + c.false_negative;
        if denom == 0 {
            1.0
        } else {
            c.true_positive as f64 / denom as f64
        }
    }

    /// False-positive rate over benign cases. Returns 0.0 when there are no benign cases.
    pub fn fp_rate(&self) -> f64 {
        let c = self.counts();
        let denom = c.false_positive + c.true_negative;
        if denom == 0 {
            0.0
        } else {
            c.false_positive as f64 / denom as f64
        }
    }

    /// Fraction of cases classified correctly.
    pub fn accuracy(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 1.0;
        }
        let correct = self.outcomes.iter().filter(|o| o.correct()).count();
        correct as f64 / self.outcomes.len() as f64
    }

    pub fn to_json(&self) -> serde_json::Value {
        let c = self.counts();
        let cases: Vec<serde_json::Value> = self
            .outcomes
            .iter()
            .map(|o| {
                serde_json::json!({
                    "name": o.name,
                    "engine": o.engine,
                    "expected_detection": o.expected_detection,
                    "detected": o.detected,
                    "classification": o.classification().label(),
                    "findings": o.findings,
                    "detail": o.detail,
                })
            })
            .collect();
        serde_json::json!({
            "summary": {
                "cases": self.outcomes.len(),
                "true_positive": c.true_positive,
                "false_negative": c.false_negative,
                "false_positive": c.false_positive,
                "true_negative": c.true_negative,
                "repro_rate": (self.repro_rate() * 10000.0).round() / 10000.0,
                "fp_rate": (self.fp_rate() * 10000.0).round() / 10000.0,
                "accuracy": (self.accuracy() * 10000.0).round() / 10000.0,
            },
            "cases": cases,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_all_cells() {
        assert_eq!(classify(true, true), Classification::TruePositive);
        assert_eq!(classify(true, false), Classification::FalseNegative);
        assert_eq!(classify(false, true), Classification::FalsePositive);
        assert_eq!(classify(false, false), Classification::TrueNegative);
    }

    #[test]
    fn perfect_report_metrics() {
        let mut r = BenchReport::new();
        r.push(BenchOutcome::new("a", "e", true, true, 1, ""));
        r.push(BenchOutcome::new("b", "e", false, false, 0, ""));
        assert_eq!(r.repro_rate(), 1.0);
        assert_eq!(r.fp_rate(), 0.0);
        assert_eq!(r.accuracy(), 1.0);
    }

    #[test]
    fn mixed_report_metrics() {
        let mut r = BenchReport::new();
        r.push(BenchOutcome::new("tp", "e", true, true, 1, ""));
        r.push(BenchOutcome::new("fn", "e", true, false, 0, "")); // missed
        r.push(BenchOutcome::new("fp", "e", false, true, 1, "")); // wrongly flagged
        r.push(BenchOutcome::new("tn", "e", false, false, 0, ""));
        let c = r.counts();
        assert_eq!(c.true_positive, 1);
        assert_eq!(c.false_negative, 1);
        assert_eq!(c.false_positive, 1);
        assert_eq!(c.true_negative, 1);
        assert!((r.repro_rate() - 0.5).abs() < 1e-9);
        assert!((r.fp_rate() - 0.5).abs() < 1e-9);
        assert!((r.accuracy() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn empty_denominators_are_safe() {
        let mut r = BenchReport::new();
        r.push(BenchOutcome::new("tn", "e", false, false, 0, ""));
        // no positive cases → repro 1.0; one benign correct → fp 0.0
        assert_eq!(r.repro_rate(), 1.0);
        assert_eq!(r.fp_rate(), 0.0);
    }

    #[test]
    fn json_has_summary_and_cases() {
        let mut r = BenchReport::new();
        r.push(BenchOutcome::new("tp", "graphql", true, true, 2, "ok"));
        let v = r.to_json();
        assert_eq!(v["summary"]["true_positive"], 1);
        assert_eq!(v["cases"][0]["classification"], "true_positive");
        assert_eq!(v["cases"][0]["engine"], "graphql");
    }
}
