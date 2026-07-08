//! Shared Supreme-tier synthesis helpers — toxic combos, roadmap, agent guidance, security graph.

use crate::arsenal_config::{finding_rich, Evidence};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use serde_json::{json, Value};

pub fn emit_toxic_from_combos(
    engine_id: &str,
    mitre: &str,
    target: &str,
    combos: Vec<String>,
    extra: Value,
    findings: &mut Vec<Value>,
) {
    if combos.is_empty() {
        return;
    }
    let headline = combos.join(" ⊕ ");
    let mut f = finding_rich(
        engine_id,
        &format!("TOXIC COMBINATION: {headline}"),
        "critical",
        mitre,
        "Correlated weaknesses form a complete exploitation chain — remediate immediately.",
        target,
        0.97,
        Evidence::new()
            .with("combinations", json!(combos))
            .with("toxic_count", combos.len())
            .with("extra", extra),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("toxic_combination"));
    }
    findings.insert(0, f);
}

pub fn emit_roadmap_from_steps(
    engine_id: &str,
    mitre: &str,
    target: &str,
    steps: Vec<(u8, &str, &str, &str)>,
    category_scores: Value,
    findings: &mut Vec<Value>,
) {
    if steps.is_empty() {
        return;
    }
    let roadmap: Vec<Value> = steps
        .into_iter()
        .map(|(priority, tier, action, detail)| {
            json!({ "priority": priority, "tier": tier, "action": action, "detail": detail })
        })
        .collect();
    let mut f = finding_rich(
        engine_id,
        "Prioritized remediation roadmap",
        "info",
        mitre,
        "Ordered hardening plan from observed weaknesses.",
        target,
        0.99,
        Evidence::new()
            .with("roadmap", Value::Array(roadmap))
            .with("category_scores", category_scores),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("remediation_roadmap"));
    }
    findings.push(f);
}

pub fn emit_agent_caps(
    engine_id: &str,
    mitre: &str,
    target: &str,
    caps: &[(&str, &str)],
    findings: &mut Vec<Value>,
) {
    for (cap, desc) in caps {
        let mut f = finding_rich(
            engine_id,
            &format!("Agent-required: {desc}"),
            "info",
            mitre,
            &format!("Capability `{cap}` requires Weissman host agent — not fully observable via external probes alone."),
            target,
            1.0,
            Evidence::new().with("capability", *cap).with("requires_agent", true),
        );
        if let Some(o) = f.as_object_mut() {
            o.insert("category".to_string(), json!("agent_guidance"));
        }
        findings.push(f);
    }
}

pub fn build_simple_graph(
    target: &str,
    host: &str,
    avg_score: f64,
    nodes: &[(&str, &str, &str)],
) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let mut graph_nodes = vec![GraphNode {
        id: "root".to_string(),
        label: if host.is_empty() { target.to_string() } else { host.to_string() },
        node_type: "root".to_string(),
        status: if avg_score >= 80.0 {
            "secure".into()
        } else if avg_score >= 50.0 {
            "degraded".into()
        } else {
            "exposed".into()
        },
        cname_target: None,
        raw_finding: None,
    }];
    let mut edges = Vec::new();
    for (id, label, kind) in nodes {
        graph_nodes.push(GraphNode {
            id: (*id).into(),
            label: (*label).into(),
            node_type: "surface".into(),
            status: "exposed".into(),
            cname_target: None,
            raw_finding: None,
        });
        edges.push(GraphEdge {
            id: format!("e_root_{id}"),
            from_id: "root".into(),
            to_id: (*id).into(),
            edge_type: (*kind).into(),
        });
    }
    let _ = target;
    (graph_nodes, edges)
}

pub fn finding_has(findings: &[Value], needle: &str) -> bool {
    let n = needle.to_ascii_lowercase();
    findings.iter().any(|f| {
        let title = f.get("title").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
        let vuln = f.get("vuln_class").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
        title.contains(&n) || cat.contains(&n) || vuln.contains(&n)
    })
}

pub fn avg_score(scores: &Value) -> f64 {
    let Some(obj) = scores.as_object() else {
        return 70.0;
    };
    let vals: Vec<f64> = obj.values().filter_map(|v| v.as_u64().map(|x| x as f64)).collect();
    if vals.is_empty() {
        70.0
    } else {
        vals.iter().sum::<f64>() / vals.len() as f64
    }
}

pub fn finalize_supreme_run(
    engine_id: &str,
    mitre: &str,
    target: &str,
    host: &str,
    findings: &mut Vec<Value>,
    category_scores: Value,
    toxic_combos: Vec<String>,
    roadmap_steps: Vec<(u8, &str, &str, &str)>,
    agent_caps: &[(&str, &str)],
    graph_nodes: &[(&str, &str, &str)],
    emit_agent: bool,
) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    emit_toxic_from_combos(engine_id, mitre, target, toxic_combos, json!({}), findings);
    emit_roadmap_from_steps(engine_id, mitre, target, roadmap_steps, category_scores.clone(), findings);
    if emit_agent {
        emit_agent_caps(engine_id, mitre, target, agent_caps, findings);
    }
    build_simple_graph(target, host, avg_score(&category_scores), graph_nodes)
}
