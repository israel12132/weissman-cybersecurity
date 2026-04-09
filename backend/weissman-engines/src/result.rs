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
