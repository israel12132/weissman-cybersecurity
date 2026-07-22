//! Supreme-tier GraphQL API synthesis — toxic combos, security graph, agent guidance.

use crate::arsenal_config::{finding_rich, Evidence};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use serde_json::{json, Value};

const ENGINE_ID: &str = "graphql_attack";
const MITRE: &str = "T1190";

#[derive(Default)]
pub struct GraphqlSignals {
    pub endpoints_found: usize,
    pub introspection_enabled: bool,
    pub sensitive_fields: bool,
    pub bola_surface: bool,
    pub auth_differential: bool,
    pub dos_unbounded: bool,
    pub csrf_get: bool,
    pub cors_permissive: bool,
    pub ide_exposed: bool,
    pub error_verbose: bool,
    pub federation_sdl: bool,
    pub live_data_leak: bool,
}

pub fn collect_signals(findings: &[Value], endpoints_found: usize) -> GraphqlSignals {
    let mut sig = GraphqlSignals {
        endpoints_found,
        ..Default::default()
    };
    for f in findings {
        let title = f
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let vuln = f
            .get("vuln_class")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let component = f
            .get("component")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if vuln.contains("introspection") || title.contains("introspection") {
            sig.introspection_enabled = true;
        }
        if vuln.contains("sensitive") || title.contains("sensitive field") {
            sig.sensitive_fields = true;
        }
        if vuln.contains("bola") || component.contains("bola") || title.contains("bola") {
            sig.bola_surface = true;
        }
        if vuln.contains("auth_differential") || title.contains("auth differential") {
            sig.auth_differential = true;
        }
        if vuln.contains("alias")
            || vuln.contains("batch")
            || vuln.contains("depth")
            || title.contains("dos")
        {
            sig.dos_unbounded = true;
        }
        if vuln.contains("csrf") || title.contains("csrf") || title.contains("get query") {
            sig.csrf_get = true;
        }
        if vuln.contains("cors") || title.contains("cors") {
            sig.cors_permissive = true;
        }
        if vuln.contains("graphiql") || vuln.contains("playground") || title.contains("graphiql") {
            sig.ide_exposed = true;
        }
        if vuln.contains("error")
            || title.contains("stack trace")
            || title.contains("verbose error")
        {
            sig.error_verbose = true;
        }
        if vuln.contains("federation") || title.contains("federation sdl") {
            sig.federation_sdl = true;
        }
        if vuln.contains("live_data") || title.contains("live data") {
            sig.live_data_leak = true;
        }
    }
    sig
}

pub struct GraphqlCategoryScores {
    pub authorization: f64,
    pub authentication: f64,
    pub resource_limits: f64,
    pub schema_exposure: f64,
    pub transport_hygiene: f64,
    pub error_disclosure: f64,
    pub inventory_management: f64,
    pub business_flows: f64,
}

impl GraphqlCategoryScores {
    fn from_signals(sig: &GraphqlSignals) -> Self {
        let bad = |b: bool, w: f64| -> f64 {
            if b {
                100.0 - w
            } else {
                100.0
            }
        };
        Self {
            authorization: bad(sig.bola_surface || sig.auth_differential, 40.0),
            authentication: bad(sig.auth_differential && sig.live_data_leak, 35.0),
            resource_limits: bad(sig.dos_unbounded, 30.0),
            schema_exposure: bad(
                sig.introspection_enabled || sig.sensitive_fields || sig.federation_sdl,
                45.0,
            ),
            transport_hygiene: bad(sig.csrf_get || sig.cors_permissive, 25.0),
            error_disclosure: bad(sig.error_verbose, 20.0),
            inventory_management: bad(sig.ide_exposed, 15.0),
            business_flows: bad(sig.live_data_leak && !sig.auth_differential, 30.0),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "authorization": self.authorization.round() as u32,
            "authentication": self.authentication.round() as u32,
            "resource_limits": self.resource_limits.round() as u32,
            "schema_exposure": self.schema_exposure.round() as u32,
            "transport_hygiene": self.transport_hygiene.round() as u32,
            "error_disclosure": self.error_disclosure.round() as u32,
            "inventory_management": self.inventory_management.round() as u32,
            "business_flows": self.business_flows.round() as u32,
        })
    }
}

pub fn finalize_category_scores(sig: &GraphqlSignals) -> GraphqlCategoryScores {
    GraphqlCategoryScores::from_signals(sig)
}

pub fn extend_attack_paths(target: &str, sig: &GraphqlSignals, findings: &mut Vec<Value>) {
    if sig.introspection_enabled && sig.sensitive_fields && sig.bola_surface {
        push_path(
            findings,
            "Attack path: introspection → sensitive fields → BOLA ID enumeration",
            "critical",
            &[
                "Dump full schema via introspection",
                "Map password/token/PII fields",
                "Enumerate object IDs via alias-batch BOLA",
                "Exfiltrate cross-tenant records",
            ],
            target,
            0.95,
        );
    }
    if sig.auth_differential && sig.live_data_leak {
        push_path(
            findings,
            "Attack path: unauthenticated schema/data differential → mass record harvest",
            "critical",
            &[
                "Compare authenticated vs anonymous GraphQL responses",
                "Replay unauthenticated queries returning PII",
                "Automate pagination/alias batching for scale",
                "Bypass broken function-level authorization",
            ],
            target,
            0.92,
        );
    }
    if sig.cors_permissive && sig.csrf_get {
        push_path(
            findings,
            "Attack path: CORS + GET mutations → browser-driven data theft",
            "high",
            &[
                "Host malicious page with credentialed cross-origin GraphQL GET",
                "Victim browser sends session cookies",
                "Steal query results via permissive ACAO",
                "Chain to account takeover flows",
            ],
            target,
            0.88,
        );
    }
}

fn push_path(
    findings: &mut Vec<Value>,
    title: &str,
    sev: &str,
    steps: &[&str],
    target: &str,
    conf: f64,
) {
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        sev,
        MITRE,
        "Correlated GraphQL weaknesses form a complete API exploitation chain.",
        target,
        conf,
        Evidence::new().with("steps", json!(steps)),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("attack_path"));
        o.insert("attack_path".to_string(), json!(steps));
    }
    findings.push(f);
}

pub fn emit_toxic_headline(target: &str, sig: &GraphqlSignals, findings: &mut Vec<Value>) {
    let mut combos = Vec::new();
    if sig.introspection_enabled && sig.sensitive_fields {
        combos.push("introspection + sensitive schema fields ⇒ full data-map disclosure");
    }
    if sig.introspection_enabled && sig.bola_surface {
        combos.push("introspection + BOLA surface ⇒ automated cross-tenant harvest");
    }
    if sig.auth_differential && sig.live_data_leak {
        combos.push("auth differential + live PII leak ⇒ unauthenticated mass exfil");
    }
    if sig.cors_permissive && sig.csrf_get {
        combos.push("permissive CORS + GET query execution ⇒ browser token theft");
    }
    if sig.dos_unbounded && sig.endpoints_found > 0 {
        combos.push("unbounded alias/batch/depth ⇒ API availability collapse");
    }
    if sig.federation_sdl && sig.sensitive_fields {
        combos.push("federation SDL + sensitive fields ⇒ multi-service blast radius");
    }
    if combos.is_empty() {
        return;
    }
    let headline = combos.join(" ⊕ ");
    let mut f = finding_rich(
        ENGINE_ID,
        &format!("TOXIC COMBINATION: {headline}"),
        "critical",
        MITRE,
        "Correlated GraphQL API failures enable schema-guided mass exploitation — disable introspection, enforce authZ, and rate-limit immediately.",
        target,
        0.97,
        Evidence::new()
            .with("combinations", json!(combos))
            .with("toxic_count", combos.len())
            .with("endpoints", sig.endpoints_found),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("toxic_combination"));
    }
    findings.insert(0, f);
}

pub fn emit_remediation_roadmap(target: &str, sig: &GraphqlSignals, findings: &mut Vec<Value>) {
    let mut steps: Vec<Value> = Vec::new();
    let mut n = 1u8;
    let mut push = |tier: &str, action: &str, detail: &str| {
        steps.push(json!({ "priority": n, "tier": tier, "action": action, "detail": detail }));
        n += 1;
    };
    if sig.introspection_enabled {
        push(
            "P0",
            "Disable introspection in production",
            "Allow only persisted/allowlisted operations",
        );
    }
    if sig.bola_surface || sig.auth_differential {
        push(
            "P0",
            "Enforce object-level authorization",
            "Server-side ID ownership checks on every resolver",
        );
    }
    if sig.dos_unbounded {
        push(
            "P0",
            "Deploy query cost limits",
            "Alias/depth/batch caps + rate limiting per client IP",
        );
    }
    if sig.csrf_get || sig.cors_permissive {
        push(
            "P1",
            "Block GET mutations & tighten CORS",
            "POST-only + strict origin allow-list",
        );
    }
    if sig.ide_exposed {
        push(
            "P1",
            "Remove GraphiQL/Playground from prod",
            "Dev consoles only on internal networks",
        );
    }
    if sig.error_verbose {
        push(
            "P1",
            "Sanitize GraphQL errors",
            "Generic errors to clients; log details server-side only",
        );
    }
    push(
        "P2",
        "Deploy Weissman agent for resolver authZ telemetry",
        "Detect runtime BOLA across microservices",
    );
    if steps.is_empty() {
        return;
    }
    let mut f = finding_rich(
        ENGINE_ID,
        "Prioritized GraphQL remediation roadmap",
        "info",
        MITRE,
        "Ordered API hardening plan from observed GraphQL weaknesses.",
        target,
        0.99,
        Evidence::new()
            .with("roadmap", Value::Array(steps))
            .with("category_scores", finalize_category_scores(sig).to_json()),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("remediation_roadmap"));
    }
    findings.push(f);
}

pub fn emit_agent_guidance(target: &str, findings: &mut Vec<Value>) {
    for (cap, desc) in [
        (
            "resolver_authz_mesh",
            "Per-resolver authorization enforcement telemetry across services",
        ),
        (
            "query_cost_runtime",
            "Live query-cost and complexity enforcement at the gateway",
        ),
        (
            "subscription_session_audit",
            "WebSocket subscription session binding and replay detection",
        ),
        (
            "api_inventory_agent",
            "Shadow GraphQL endpoint discovery on internal meshes",
        ),
    ] {
        let mut f = finding_rich(
            ENGINE_ID,
            &format!("Agent-required: {desc}"),
            "info",
            MITRE,
            &format!("Capability `{cap}` requires Weissman host agent — not fully observable via external GraphQL probes alone."),
            target,
            1.0,
            Evidence::new().with("capability", cap).with("requires_agent", true),
        );
        if let Some(o) = f.as_object_mut() {
            o.insert("category".to_string(), json!("agent_guidance"));
        }
        findings.push(f);
    }
}

pub fn build_security_graph(
    target: &str,
    sig: &GraphqlSignals,
    host: &str,
) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let score = finalize_category_scores(sig);
    let avg = (score.authorization + score.schema_exposure + score.resource_limits) / 3.0;
    let mut nodes = vec![GraphNode {
        id: "root".to_string(),
        label: if host.is_empty() {
            target.to_string()
        } else {
            host.to_string()
        },
        node_type: "root".to_string(),
        status: if avg >= 80.0 {
            "secure".into()
        } else if avg >= 50.0 {
            "degraded".into()
        } else {
            "exposed".into()
        },
        cname_target: None,
        raw_finding: None,
    }];
    let mut edges = Vec::new();
    let mut add = |id: &str, label: &str, kind: &str| {
        nodes.push(GraphNode {
            id: id.into(),
            label: label.into(),
            node_type: "graphql_surface".into(),
            status: "exposed".into(),
            cname_target: None,
            raw_finding: None,
        });
        edges.push(GraphEdge {
            id: format!("e_root_{id}"),
            from_id: "root".into(),
            to_id: id.into(),
            edge_type: kind.into(),
        });
    };
    if sig.endpoints_found > 0 {
        add(
            "gql",
            &format!("{} GraphQL endpoint(s)", sig.endpoints_found),
            "ENDPOINT",
        );
    }
    if sig.introspection_enabled {
        add("intro", "Introspection enabled", "INTROSPECTION");
    }
    if sig.bola_surface {
        add("bola", "BOLA surface", "BOLA");
    }
    if sig.sensitive_fields {
        add("pii", "Sensitive schema fields", "SENSITIVE");
    }
    if sig.auth_differential {
        add("authz", "Auth differential", "AUTH_DIFF");
    }
    if sig.introspection_enabled && sig.bola_surface && sig.sensitive_fields {
        edges.push(GraphEdge {
            id: "ap_exfil".into(),
            from_id: "intro".into(),
            to_id: "pii".into(),
            edge_type: "MASS_EXFIL".into(),
        });
    }
    let _ = target;
    (nodes, edges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_signals_empty_defaults() {
        let sig = collect_signals(&[], 0);
        assert_eq!(sig.endpoints_found, 0);
        assert!(!sig.introspection_enabled);
        let s = finalize_category_scores(&sig);
        assert_eq!(s.authorization, 100.0);
        assert_eq!(s.business_flows, 100.0);
    }

    #[test]
    fn collect_signals_detects_various() {
        let findings = vec![
            json!({"vuln_class": "Introspection"}),
            json!({"title": "Sensitive field password exposed"}),
            json!({"vuln_class": "BOLA"}),
            json!({"vuln_class": "cors_wildcard"}),
            json!({"vuln_class": "batch_alias_dos"}),
        ];
        let sig = collect_signals(&findings, 1);
        assert!(sig.introspection_enabled);
        assert!(sig.sensitive_fields);
        assert!(sig.bola_surface);
        assert!(sig.cors_permissive);
        assert!(sig.dos_unbounded);
        assert_eq!(sig.endpoints_found, 1);
    }

    #[test]
    fn collect_signals_component_bola() {
        let findings = vec![json!({"component": "user-BOLA-resolver"})];
        let sig = collect_signals(&findings, 0);
        assert!(sig.bola_surface);
    }

    #[test]
    fn category_scores_json_shape() {
        let findings = vec![
            json!({"vuln_class": "introspection"}),
            json!({"title": "sensitive field"}),
            json!({"vuln_class": "bola"}),
            json!({"vuln_class": "cors"}),
        ];
        let sig = collect_signals(&findings, 1);
        let v = finalize_category_scores(&sig).to_json();
        assert_eq!(v["authorization"], json!(60));
        assert_eq!(v["schema_exposure"], json!(55));
        assert_eq!(v["transport_hygiene"], json!(75));
        assert_eq!(v["resource_limits"], json!(100));
        assert_eq!(v["error_disclosure"], json!(100));
    }

    #[test]
    fn business_flows_penalized_only_without_auth_diff() {
        let leak_only = GraphqlSignals {
            live_data_leak: true,
            ..Default::default()
        };
        assert_eq!(finalize_category_scores(&leak_only).business_flows, 70.0);
        let both = GraphqlSignals {
            live_data_leak: true,
            auth_differential: true,
            ..Default::default()
        };
        assert_eq!(finalize_category_scores(&both).business_flows, 100.0);
    }

    #[test]
    fn emit_toxic_headline_inserts_when_combos() {
        let sig = GraphqlSignals {
            introspection_enabled: true,
            sensitive_fields: true,
            ..Default::default()
        };
        let mut findings: Vec<Value> = Vec::new();
        emit_toxic_headline("t", &sig, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["category"], json!("toxic_combination"));
        assert!(findings[0]["title"]
            .as_str()
            .unwrap()
            .contains("TOXIC COMBINATION"));
    }

    #[test]
    fn emit_toxic_headline_noop_when_clean() {
        let sig = GraphqlSignals::default();
        let mut findings: Vec<Value> = Vec::new();
        emit_toxic_headline("t", &sig, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn extend_attack_paths_exfil_chain() {
        let sig = GraphqlSignals {
            introspection_enabled: true,
            sensitive_fields: true,
            bola_surface: true,
            ..Default::default()
        };
        let mut findings: Vec<Value> = Vec::new();
        extend_attack_paths("t", &sig, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["category"], json!("attack_path"));
    }

    #[test]
    fn remediation_roadmap_always_baseline() {
        let sig = GraphqlSignals::default();
        let mut findings: Vec<Value> = Vec::new();
        emit_remediation_roadmap("t", &sig, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["category"], json!("remediation_roadmap"));
    }

    #[test]
    fn agent_guidance_emits_four() {
        let mut findings: Vec<Value> = Vec::new();
        emit_agent_guidance("t", &mut findings);
        assert_eq!(findings.len(), 4);
        assert!(findings
            .iter()
            .all(|f| f["category"] == json!("agent_guidance")));
    }

    #[test]
    fn security_graph_secure_status() {
        let sig = GraphqlSignals {
            endpoints_found: 1,
            ..Default::default()
        };
        let (nodes, _edges) = build_security_graph("t", &sig, "host.example");
        assert_eq!(nodes[0].id, "root");
        assert_eq!(nodes[0].label, "host.example");
        assert_eq!(nodes[0].status, "secure");
        assert!(nodes
            .iter()
            .any(|n| n.id == "gql" && n.label == "1 GraphQL endpoint(s)"));
    }

    #[test]
    fn security_graph_degraded_with_exfil_edge() {
        let sig = GraphqlSignals {
            endpoints_found: 2,
            introspection_enabled: true,
            bola_surface: true,
            sensitive_fields: true,
            ..Default::default()
        };
        let (nodes, edges) = build_security_graph("t", &sig, "");
        assert_eq!(nodes[0].label, "t"); // empty host -> target
        assert_eq!(nodes[0].status, "degraded"); // avg (60+55+100)/3 ~= 71.7
        assert!(nodes.iter().any(|n| n.id == "intro"));
        assert!(nodes.iter().any(|n| n.id == "bola"));
        assert!(nodes.iter().any(|n| n.id == "pii"));
        assert!(edges.iter().any(|e| e.id == "ap_exfil"
            && e.from_id == "intro"
            && e.to_id == "pii"
            && e.edge_type == "MASS_EXFIL"));
    }
}
