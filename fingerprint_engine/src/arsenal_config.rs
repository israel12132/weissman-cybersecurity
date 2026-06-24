//! Next-Gen Arsenal — shared configuration + evidence layer.
//!
//! Every engine added in the Next-Gen Arsenal batch reads its knobs from the live scan request
//! body (`POST /api/command-center/scan` → `EngineRunContext::job_params`). This module turns that
//! free-form JSON into a typed, ergonomic config surface so an operator can override **any** aspect
//! of a probe (ports, timeouts, intensity, credential/word-lists, per-check toggles, protocol
//! parameters) without a code change — that is the "infinite options" guarantee.
//!
//! It also provides [`Evidence`] + [`finding_rich`] so every finding carries the full, granular
//! trail of what the probe actually did (target host/port, protocol, raw excerpt, per-check
//! results, confidence) — the "see every smallest thing" guarantee. No value is fabricated: an
//! engine only emits a finding when a real probe observed a real signal.

use crate::engine_dispatch::EngineRunContext;
use serde::Serialize;
use serde_json::{json, Map, Value};

/// Typed, lossless view over the scan request's `job_params`.
///
/// All accessors are total (never panic) and fall back to sensible, documented defaults so an
/// engine behaves correctly even when the operator sends an empty body.
#[derive(Clone, Debug, Default)]
pub struct ArsenalConfig {
    raw: Value,
}

impl ArsenalConfig {
    #[must_use]
    pub fn from_ctx(ctx: &EngineRunContext) -> Self {
        Self {
            raw: ctx.job_params.clone(),
        }
    }

    #[must_use]
    pub fn from_value(raw: Value) -> Self {
        Self { raw }
    }

    /// Raw, untouched parameter bag (useful for engine-specific knobs not modelled here).
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    fn lookup(&self, key: &str) -> Option<&Value> {
        // Support both top-level keys and a nested `options: { ... }` object so the UI can group
        // engine knobs under one field without breaking older callers.
        if let Some(v) = self.raw.get(key) {
            return Some(v);
        }
        self.raw.get("options").and_then(|o| o.get(key))
    }

    #[must_use]
    pub fn string(&self, key: &str) -> Option<String> {
        self.lookup(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    #[must_use]
    pub fn string_or(&self, key: &str, default: &str) -> String {
        self.string(key).unwrap_or_else(|| default.to_string())
    }

    #[must_use]
    pub fn bool_or(&self, key: &str, default: bool) -> bool {
        match self.lookup(key) {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ),
            Some(Value::Number(n)) => n.as_i64().map(|x| x != 0).unwrap_or(default),
            _ => default,
        }
    }

    #[must_use]
    pub fn u64_or(&self, key: &str, default: u64) -> u64 {
        match self.lookup(key) {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(default),
            Some(Value::String(s)) => s.trim().parse().unwrap_or(default),
            _ => default,
        }
    }

    #[must_use]
    pub fn usize_or(&self, key: &str, default: usize) -> usize {
        usize::try_from(self.u64_or(key, default as u64)).unwrap_or(default)
    }

    /// Parse a port list from either a JSON array of numbers/strings or a comma/space string.
    #[must_use]
    pub fn ports(&self, key: &str) -> Vec<u16> {
        let mut out: Vec<u16> = Vec::new();
        match self.lookup(key) {
            Some(Value::Array(arr)) => {
                for v in arr {
                    if let Some(p) = v.as_u64() {
                        if p > 0 && p <= u64::from(u16::MAX) {
                            out.push(p as u16);
                        }
                    } else if let Some(s) = v.as_str() {
                        if let Ok(p) = s.trim().parse::<u16>() {
                            out.push(p);
                        }
                    }
                }
            }
            Some(Value::String(s)) => {
                for tok in s.split([',', ' ', ';']) {
                    if let Ok(p) = tok.trim().parse::<u16>() {
                        out.push(p);
                    }
                }
            }
            _ => {}
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Ports override for `key`, or `default` when the operator did not supply any.
    #[must_use]
    pub fn ports_or(&self, key: &str, default: &[u16]) -> Vec<u16> {
        let p = self.ports(key);
        if p.is_empty() {
            default.to_vec()
        } else {
            p
        }
    }

    /// Parse a string list from a JSON array or a comma/newline string.
    #[must_use]
    pub fn string_list(&self, key: &str) -> Vec<String> {
        match self.lookup(key) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            Some(Value::String(s)) => s
                .split(['\n', ','])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        }
    }

    #[must_use]
    pub fn string_list_or(&self, key: &str, default: &[&str]) -> Vec<String> {
        let l = self.string_list(key);
        if l.is_empty() {
            default.iter().map(|s| (*s).to_string()).collect()
        } else {
            l
        }
    }

    // ── Common cross-engine knobs ───────────────────────────────────────────

    /// Per-probe socket timeout (ms). Clamped to a safe window so an engine cannot hang the worker.
    #[must_use]
    pub fn timeout_ms(&self, default: u64) -> u64 {
        self.u64_or("timeout_ms", default).clamp(200, 30_000)
    }

    /// Bounded fan-out concurrency for port/path scanning.
    #[must_use]
    pub fn concurrency(&self) -> usize {
        self.usize_or("concurrency", 16).clamp(1, 256)
    }

    /// `light` | `normal` | `aggressive`. Controls how deep an engine probes by default.
    #[must_use]
    pub fn intensity(&self) -> Intensity {
        match self
            .string("intensity")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "light" | "passive" | "safe" => Intensity::Light,
            "aggressive" | "deep" | "max" => Intensity::Aggressive,
            _ => Intensity::Normal,
        }
    }

    /// Whether the engine should emit the honest `agent_required` info finding for sub-capabilities
    /// that genuinely need a host/RF collector (default on, so nothing is silently hidden).
    #[must_use]
    pub fn emit_agent_guidance(&self) -> bool {
        self.bool_or("include_agent_findings", true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intensity {
    Light,
    Normal,
    Aggressive,
}

impl Intensity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Intensity::Light => "light",
            Intensity::Normal => "normal",
            Intensity::Aggressive => "aggressive",
        }
    }
}

/// Granular, structured evidence attached to a finding so the operator can audit exactly what the
/// probe observed. Every field is optional and only populated from real observations.
#[derive(Clone, Debug, Default)]
pub struct Evidence {
    fields: Map<String, Value>,
    checks: Vec<Value>,
}

impl Evidence {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a typed observation (host, port, protocol, banner, version, …).
    #[must_use]
    pub fn with(mut self, key: &str, value: impl Serialize) -> Self {
        self.fields.insert(
            key.to_string(),
            serde_json::to_value(value).unwrap_or(Value::Null),
        );
        self
    }

    /// Record a single sub-check result (name, passed/observed, detail). Builds the granular
    /// per-check trail the UI renders under each finding.
    #[must_use]
    pub fn check(mut self, name: &str, observed: bool, detail: impl Serialize) -> Self {
        self.checks.push(json!({
            "name": name,
            "observed": observed,
            "detail": serde_json::to_value(detail).unwrap_or(Value::Null),
        }));
        self
    }

    /// Bound + hex-encode a raw protocol excerpt for forensic visibility (capped to 256 bytes).
    #[must_use]
    pub fn raw_excerpt(mut self, bytes: &[u8]) -> Self {
        let take = bytes.len().min(256);
        let hex: String = bytes[..take].iter().map(|b| format!("{:02x}", b)).collect();
        self.fields
            .insert("raw_excerpt_hex".to_string(), Value::String(hex));
        self.fields.insert(
            "raw_excerpt_len".to_string(),
            Value::Number(bytes.len().into()),
        );
        self
    }

    #[must_use]
    pub fn into_value(self) -> Value {
        let mut obj = self.fields;
        if !self.checks.is_empty() {
            obj.insert("checks".to_string(), Value::Array(self.checks));
        }
        Value::Object(obj)
    }
}

/// Build a fully-detailed finding: same core shape as [`crate::engine_probes::finding`] but with a
/// structured `evidence` object and a `confidence` score so the operator sees the complete trail.
#[must_use]
pub fn finding_rich(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    confidence: f64,
    evidence: Evidence,
) -> Value {
    let mut f =
        crate::engine_probes::finding(engine_id, title, severity, mitre, description, target);
    if let Some(obj) = f.as_object_mut() {
        obj.insert("confidence".to_string(), json!(confidence.clamp(0.0, 1.0)));
        obj.insert("evidence".to_string(), evidence.into_value());
        obj.insert("engine_id".to_string(), json!(engine_id));
    }
    f
}

/// Severity ladder helper keyed on a confidence/exposure score in `[0,1]`.
#[must_use]
pub fn severity_for_score(score: f64) -> &'static str {
    if score >= 0.85 {
        "critical"
    } else if score >= 0.6 {
        "high"
    } else if score >= 0.3 {
        "medium"
    } else {
        "low"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ports_parses_array_and_string() {
        let c = ArsenalConfig::from_value(json!({ "ports": [502, "2404", 502] }));
        assert_eq!(c.ports("ports"), vec![502, 2404]);
        let c2 = ArsenalConfig::from_value(json!({ "ports": "23, 992 ; 21" }));
        assert_eq!(c2.ports("ports"), vec![21, 23, 992]);
        assert_eq!(c2.ports_or("missing", &[80, 443]), vec![80, 443]);
    }

    #[test]
    fn nested_options_and_typed_accessors() {
        let c = ArsenalConfig::from_value(json!({
            "options": { "timeout_ms": 5000, "intensity": "aggressive", "deep": true }
        }));
        assert_eq!(c.timeout_ms(1500), 5000);
        assert_eq!(c.intensity(), Intensity::Aggressive);
        assert!(c.bool_or("deep", false));
        assert_eq!(c.timeout_ms(1500).clamp(200, 30_000), 5000);
    }

    #[test]
    fn timeout_is_clamped() {
        let c = ArsenalConfig::from_value(json!({ "timeout_ms": 9_999_999 }));
        assert_eq!(c.timeout_ms(1500), 30_000);
    }

    #[test]
    fn evidence_serializes_checks_and_excerpt() {
        let ev = Evidence::new()
            .with("host", "10.0.0.1")
            .with("port", 502)
            .check("modbus_fc03", true, "responded")
            .raw_excerpt(&[0x68, 0x04, 0x0b]);
        let v = ev.into_value();
        assert_eq!(v["host"], json!("10.0.0.1"));
        assert_eq!(v["raw_excerpt_hex"], json!("68040b"));
        assert_eq!(v["checks"][0]["name"], json!("modbus_fc03"));
    }
}
