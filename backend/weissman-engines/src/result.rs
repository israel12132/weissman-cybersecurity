//! Minimal engine output (no ASM graph attachment — that stays in the monolith `EngineResult`).

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct EngineResult {
    pub status: String,
    pub findings: Vec<Value>,
    pub message: String,
}

impl EngineResult {
    pub fn ok(findings: Vec<Value>, message: impl Into<String>) -> Self {
        Self {
            status: "ok".to_string(),
            findings,
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "error".to_string(),
            findings: vec![],
            message: message.into(),
        }
    }
}

/// Print JSON line for CLI / subprocess consumers.
pub fn print_result(r: &EngineResult) {
    if let Ok(s) = serde_json::to_string(r) {
        println!("{}", s);
    } else {
        println!("{{\"status\":\"error\",\"findings\":[],\"message\":\"serialize failed\"}}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_sets_status_and_fields() {
        let r = EngineResult::ok(vec![serde_json::json!({"a":1})], "great");
        assert_eq!(r.status, "ok");
        assert_eq!(r.message, "great");
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn error_has_empty_findings() {
        let r = EngineResult::error("boom");
        assert_eq!(r.status, "error");
        assert!(r.findings.is_empty());
        assert_eq!(r.message, "boom");
    }

    #[test]
    fn ok_serializes_to_json() {
        let r = EngineResult::ok(vec![], "m");
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"status\":\"ok\""));
    }
}
