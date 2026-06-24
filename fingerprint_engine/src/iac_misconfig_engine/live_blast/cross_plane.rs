//! Cross-plane trust bridges — IRSA / EKS pod identity wiring K8s ServiceAccount → AWS IAM Role.

use super::graph_model::{EdgeKind, GraphNode, InfraGraph, LiveStatus, NodeKind};
use crate::iac_misconfig_engine::model::IacFile;
use crate::iac_misconfig_engine::terraform::{parse_hcl, HclValue};
use serde_yaml::Value;

#[derive(Debug, Clone)]
pub struct CrossPlaneBridge {
    pub k8s_sa_id: String,
    pub iam_id: String,
    pub role_arn: String,
    pub evidence: String,
}

/// Wire deterministic cross-plane edges from Terraform IRSA + K8s SA annotations.
#[must_use]
pub fn wire_cross_plane(files: &[IacFile], graph: &mut InfraGraph) -> Vec<CrossPlaneBridge> {
    let mut bridges = Vec::new();

    for f in files {
        if f.name.ends_with(".tf") || f.content.contains("resource \"") {
            bridges.extend(wire_terraform_irsa(f, graph));
        }
        if f.name.ends_with(".yaml") || f.name.ends_with(".yml") {
            bridges.extend(wire_k8s_sa_annotations(f, graph));
        }
    }

    for b in &bridges {
        graph.add_edge(&b.k8s_sa_id, &b.iam_id, EdgeKind::CrossPlaneTrust, b.evidence.clone());
        if let Some(iam) = graph.nodes.get_mut(&b.iam_id) {
            iam.cloud_arn = Some(b.role_arn.clone());
        }
        if let Some(sa) = graph.nodes.get_mut(&b.k8s_sa_id) {
            sa.cloud_arn = Some(b.role_arn.clone());
        }
    }

    bridges
}

fn wire_terraform_irsa(f: &IacFile, graph: &mut InfraGraph) -> Vec<CrossPlaneBridge> {
    let mut out = Vec::new();
    for b in parse_hcl(&f.content) {
        if b.typ != "resource" {
            continue;
        }
        let rtype = b.labels.first().map(String::as_str).unwrap_or("");
        if rtype != "aws_iam_role_for_service_account" && rtype != "aws_eks_pod_identity_association" {
            continue;
        }
        let rname = b.labels.get(1).map(String::as_str).unwrap_or("?");
        let role_arn = b
            .attr_str("role_arn")
            .or_else(|| extract_role_arn_from_nested(&b));
        let Some(role_arn) = role_arn else { continue };
        let sa_name = b
            .attr_str("service_account")
            .or_else(|| b.attr_str("service_account_name"))
            .unwrap_or_else(|| rname.to_string());
        let sa_id = format!("sa:{sa_name}");
        ensure_sa_node(graph, &sa_id, &sa_name, &f.name);
        let iam_id = ensure_iam_from_arn(graph, &role_arn, &f.name);
        out.push(CrossPlaneBridge {
            k8s_sa_id: sa_id,
            iam_id,
            role_arn: role_arn.clone(),
            evidence: format!("{rtype} IRSA trust → {role_arn}"),
        });
    }
    out
}

fn wire_k8s_sa_annotations(f: &IacFile, graph: &mut InfraGraph) -> Vec<CrossPlaneBridge> {
    let mut out = Vec::new();
    for doc in f.content.split("\n---\n") {
        let Ok(v) = serde_yaml::from_str::<Value>(doc.trim()) else { continue };
        if v.get("kind").and_then(Value::as_str) != Some("ServiceAccount") {
            continue;
        }
        let name = v
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("?");
        let sa_id = format!("sa:{name}");
        ensure_sa_node(graph, &sa_id, name, &f.name);
        let role_arn = v
            .get("metadata")
            .and_then(|m| m.get("annotations"))
            .and_then(|a| a.get("eks.amazonaws.com/role-arn"))
            .and_then(Value::as_str)
            .or_else(|| {
                v.get("metadata")
                    .and_then(|m| m.get("annotations"))
                    .and_then(|a| a.get("iam.amazonaws.com/role"))
                    .and_then(Value::as_str)
            });
        let Some(role_arn) = role_arn else { continue };
        let iam_id = ensure_iam_from_arn(graph, role_arn, &f.name);
        out.push(CrossPlaneBridge {
            k8s_sa_id: sa_id,
            iam_id,
            role_arn: role_arn.to_string(),
            evidence: format!("ServiceAccount annotation → {role_arn}"),
        });
    }
    out
}

fn extract_role_arn_from_nested(b: &crate::iac_misconfig_engine::terraform::HclBlock) -> Option<String> {
    for key in ["role_arn", "target_role_arn"] {
        if let Some(HclValue::Str(s) | HclValue::Raw(s)) = b.attr(key) {
            if s.starts_with("arn:aws:iam::") {
                return Some(s.clone());
            }
        }
    }
    None
}

fn ensure_sa_node(graph: &mut InfraGraph, sa_id: &str, name: &str, file: &str) {
    if graph.nodes.contains_key(sa_id) {
        return;
    }
    graph.add_node(GraphNode {
        id: sa_id.to_string(),
        kind: NodeKind::K8sServiceAccount,
        label: name.to_string(),
        file: file.to_string(),
        provider: "kubernetes".to_string(),
        sensitive: false,
        internet_facing: false,
        live_status: LiveStatus::NotChecked,
        live_evidence: None,
        iac_address: Some(format!("default/ServiceAccount/{name}")),
        cloud_arn: None,
    });
}

fn ensure_iam_from_arn(graph: &mut InfraGraph, role_arn: &str, file: &str) -> String {
    let role_name = role_arn.split('/').next_back().unwrap_or("role");
    let iam_id = format!("iam:{role_name}");
    if !graph.nodes.contains_key(&iam_id) {
        graph.add_node(GraphNode {
            id: iam_id.clone(),
            kind: NodeKind::IamRole,
            label: role_name.to_string(),
            file: file.to_string(),
            provider: "aws".to_string(),
            sensitive: true,
            internet_facing: false,
            live_status: LiveStatus::NotChecked,
            live_evidence: None,
            iac_address: Some(format!("aws_iam_role.{role_name}")),
            cloud_arn: Some(role_arn.to_string()),
        });
    } else if let Some(n) = graph.nodes.get_mut(&iam_id) {
        n.cloud_arn = Some(role_arn.to_string());
        n.sensitive = true;
    }
    iam_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::model::IacFile;

    #[test]
    fn wires_irsa_from_terraform() {
        let tf = r#"
resource "aws_iam_role_for_service_account" "app" {
  role_arn         = "arn:aws:iam::123456789012:role/app-irsa"
  service_account  = "app-sa"
}
"#;
        let mut g = InfraGraph::default();
        let files = vec![IacFile {
            name: "irsa.tf".into(),
            content: tf.into(),
            forced: None,
            origin: "inline".into(),
        }];
        let bridges = wire_cross_plane(&files, &mut g);
        assert_eq!(bridges.len(), 1);
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::CrossPlaneTrust));
    }
}
