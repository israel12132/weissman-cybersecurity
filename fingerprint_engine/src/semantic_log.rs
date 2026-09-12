//! Persist and recover OpenAPI state-machine graphs from `semantic_fuzz_log.log_text`.
//!
//! Job JSON already carries `state_nodes` / `state_edges`, but the GET handlers only
//! read `semantic_fuzz_log`. Encoding an envelope into `log_text` lets the live
//! Semantic Logic UI reconstruct the graph without treating an empty React Flow
//! canvas as "no OpenAPI".

use serde_json::{json, Value};
use weissman_core::models::semantic::{StateEdge, StateNode};

const MAX_LOG_CHARS: usize = 120_000;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedSemanticLog {
    pub reasoning: String,
    pub state_nodes: Vec<Value>,
    pub state_edges: Vec<Value>,
}

pub fn encode_semantic_fuzz_log(
    reasoning_log: &str,
    state_nodes: &[StateNode],
    state_edges: &[StateEdge],
) -> String {
    if reasoning_log.is_empty() && state_nodes.is_empty() && state_edges.is_empty() {
        return String::new();
    }
    let reasoning: String = reasoning_log.chars().take(100_000).collect();
    let envelope = json!({
        "weissman_semantic_graph": {
            "state_nodes": state_nodes,
            "state_edges": state_edges,
        },
        "reasoning_log": reasoning,
    });
    let encoded = envelope.to_string();
    if encoded.chars().count() <= MAX_LOG_CHARS {
        return encoded;
    }
    json!({
        "weissman_semantic_graph": {
            "state_nodes": state_nodes,
            "state_edges": state_edges,
        },
        "reasoning_log": "",
    })
    .to_string()
}

pub fn parse_semantic_fuzz_log(log_text: &str) -> ParsedSemanticLog {
    let trimmed = log_text.trim();
    if trimmed.is_empty() {
        return ParsedSemanticLog::default();
    }
    let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
        return ParsedSemanticLog {
            reasoning: log_text.to_string(),
            ..ParsedSemanticLog::default()
        };
    };
    let Some(obj) = v.as_object() else {
        return ParsedSemanticLog {
            reasoning: log_text.to_string(),
            ..ParsedSemanticLog::default()
        };
    };
    let graph = obj.get("weissman_semantic_graph").and_then(Value::as_object);
    let nodes = graph
        .and_then(|g| g.get("state_nodes"))
        .or_else(|| obj.get("state_nodes"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let edges = graph
        .and_then(|g| g.get("state_edges"))
        .or_else(|| obj.get("state_edges"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let reasoning = obj
        .get("reasoning_log")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if nodes.is_empty() && edges.is_empty() {
                log_text.to_string()
            } else {
                String::new()
            }
        });
    ParsedSemanticLog {
        reasoning,
        state_nodes: nodes,
        state_edges: edges,
    }
}

pub fn graph_from_logs(logs: &[Value]) -> (Vec<Value>, Vec<Value>) {
    let Some(latest) = logs.first() else {
        return (Vec::new(), Vec::new());
    };
    let text = latest
        .get("log_text")
        .and_then(Value::as_str)
        .unwrap_or("");
    let parsed = parse_semantic_fuzz_log(text);
    (parsed.state_nodes, parsed.state_edges)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str) -> StateNode {
        StateNode {
            id: id.into(),
            path: "/login".into(),
            method: "POST".into(),
            summary: "auth".into(),
        }
    }

    #[test]
    fn encode_round_trips_graph_and_reasoning() {
        let encoded = encode_semantic_fuzz_log("step 1", &[node("POST_login")], &[]);
        let parsed = parse_semantic_fuzz_log(&encoded);
        assert_eq!(parsed.reasoning, "step 1");
        assert_eq!(parsed.state_nodes.len(), 1);
        assert_eq!(parsed.state_nodes[0]["id"], "POST_login");
        assert!(parsed.state_edges.is_empty());
    }

    #[test]
    fn raw_text_is_legacy_reasoning_without_pretending_to_be_a_graph() {
        let parsed = parse_semantic_fuzz_log("fuzzed /admin → 403");
        assert_eq!(parsed.reasoning, "fuzzed /admin → 403");
        assert!(parsed.state_nodes.is_empty());
        assert!(parsed.state_edges.is_empty());
    }

    #[test]
    fn empty_encode_is_empty() {
        assert!(encode_semantic_fuzz_log("", &[], &[]).is_empty());
    }

    #[test]
    fn graph_from_logs_uses_the_newest_row_only() {
        let logs = vec![
            json!({"log_text": encode_semantic_fuzz_log("new", &[node("GET_health")], &[])}),
            json!({"log_text": "legacy run without graph"}),
        ];
        let (nodes, edges) = graph_from_logs(&logs);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["id"], "GET_health");
        assert!(edges.is_empty());
    }

    #[test]
    fn graph_from_logs_does_not_steal_an_older_run_when_latest_is_legacy() {
        let logs = vec![
            json!({"log_text": "latest run did not persist a graph"}),
            json!({"log_text": encode_semantic_fuzz_log("old", &[node("POST_login")], &[])}),
        ];
        let (nodes, _) = graph_from_logs(&logs);
        assert!(nodes.is_empty());
    }
}
