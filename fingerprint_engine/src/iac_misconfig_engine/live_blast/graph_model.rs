//! Deterministic infrastructure graph model — nodes, edges, and proven attack paths.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    Internet,
    SecurityGroup,
    Ec2Instance,
    RdsInstance,
    S3Bucket,
    SecretsManagerSecret,
    KmsKey,
    IamRole,
    IamPolicy,
    LoadBalancer,
    K8sIngress,
    K8sService,
    K8sPod,
    K8sServiceAccount,
    K8sSecret,
}

impl NodeKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::Internet => "internet",
            NodeKind::SecurityGroup => "security_group",
            NodeKind::Ec2Instance => "ec2_instance",
            NodeKind::RdsInstance => "rds_instance",
            NodeKind::S3Bucket => "s3_bucket",
            NodeKind::SecretsManagerSecret => "secretsmanager_secret",
            NodeKind::KmsKey => "kms_key",
            NodeKind::IamRole => "iam_role",
            NodeKind::IamPolicy => "iam_policy",
            NodeKind::LoadBalancer => "load_balancer",
            NodeKind::K8sIngress => "k8s_ingress",
            NodeKind::K8sService => "k8s_service",
            NodeKind::K8sPod => "k8s_pod",
            NodeKind::K8sServiceAccount => "k8s_service_account",
            NodeKind::K8sSecret => "k8s_secret",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    NetworkReachable,
    IamAttached,
    IamAllows,
    IamProven,
    CrossPlaneTrust,
    K8sRoutesTo,
    K8sMountsSa,
    RbacGrants,
    RbacProven,
}

impl EdgeKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::NetworkReachable => "network_reachable",
            EdgeKind::IamAttached => "iam_attached",
            EdgeKind::IamAllows => "iam_allows",
            EdgeKind::IamProven => "iam_proven",
            EdgeKind::CrossPlaneTrust => "cross_plane_trust",
            EdgeKind::K8sRoutesTo => "k8s_routes_to",
            EdgeKind::K8sMountsSa => "k8s_mounts_sa",
            EdgeKind::RbacGrants => "rbac_grants",
            EdgeKind::RbacProven => "rbac_proven",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    pub file: String,
    pub provider: String,
    pub sensitive: bool,
    pub internet_facing: bool,
    pub live_status: LiveStatus,
    pub live_evidence: Option<String>,
    pub iac_address: Option<String>,
    /// AWS ARN when known (IRSA role-arn, bucket ARN after live reconcile, etc.)
    pub cloud_arn: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LiveStatus {
    #[default]
    NotChecked,
    Skipped,
    ConfirmedLive,
    NotDeployed,
    ContradictsIac,
}

impl LiveStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LiveStatus::NotChecked => "not_checked",
            LiveStatus::Skipped => "skipped",
            LiveStatus::ConfirmedLive => "confirmed_live",
            LiveStatus::NotDeployed => "not_deployed",
            LiveStatus::ContradictsIac => "contradicts_iac",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub evidence: String,
}

#[derive(Debug, Clone, Default)]
pub struct InfraGraph {
    pub nodes: HashMap<String, GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub permission_proofs: Vec<PermissionProof>,
    pub k8s_rbac_proofs: Vec<K8sRbacProof>,
}

impl InfraGraph {
    pub fn add_node(&mut self, node: GraphNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn add_edge(&mut self, from: &str, to: &str, kind: EdgeKind, evidence: impl Into<String>) {
        if self.nodes.contains_key(from) && self.nodes.contains_key(to) {
            self.edges.push(GraphEdge {
                from: from.to_string(),
                to: to.to_string(),
                kind,
                evidence: evidence.into(),
            });
        }
    }

    #[must_use]
    pub fn neighbors(&self, id: &str) -> Vec<(&GraphEdge, &GraphNode)> {
        self.edges
            .iter()
            .filter(|e| e.from == id)
            .filter_map(|e| self.nodes.get(&e.to).map(|n| (e, n)))
            .collect()
    }

    /// BFS from Internet to every sensitive node — returns only mathematically proven paths.
    #[must_use]
    pub fn proven_paths_to_sensitive(&self) -> Vec<ProvenAttackPath> {
        let start = "internet";
        if !self.nodes.contains_key(start) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(vec![start.to_string()]);

        let mut seen_paths: HashSet<String> = HashSet::new();

        while let Some(path) = queue.pop_front() {
            let current = path.last().map(String::as_str).unwrap_or("");
            let Some(node) = self.nodes.get(current) else {
                continue;
            };

            if node.sensitive && path.len() > 1 {
                let key = path.join("->");
                if seen_paths.insert(key) {
                    out.push(ProvenAttackPath::from_path(self, &path));
                }
                continue;
            }
            if path.len() > 8 {
                continue;
            }
            for (edge, next) in self.neighbors(current) {
                if path.contains(&next.id) {
                    continue;
                }
                let mut np = path.clone();
                np.push(next.id.clone());
                queue.push_back(np);
                let _ = edge;
            }
        }
        out.sort_by(|a, b| b.severity_weight().cmp(&a.severity_weight()));
        out.truncate(25);
        out
    }

    #[must_use]
    pub fn summary_json(&self) -> Value {
        let by_kind: HashMap<String, u64> = self.nodes.values().fold(HashMap::new(), |mut m, n| {
            *m.entry(n.kind.as_str().to_string()).or_insert(0) += 1;
            m
        });
        json!({
            "node_count": self.nodes.len(),
            "edge_count": self.edges.len(),
            "nodes_by_kind": by_kind,
            "live_confirmed": self.nodes.values().filter(|n| n.live_status == LiveStatus::ConfirmedLive).count(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProvenAttackPath {
    pub id: String,
    pub title: String,
    pub hops: Vec<PathHop>,
    pub target_sensitive: bool,
    pub live_confirmed_hops: u64,
    pub permission_proven_hops: u64,
    pub toxic_class: String,
    pub narrative: String,
}

#[derive(Debug, Clone)]
pub struct PermissionProof {
    pub principal_id: String,
    pub resource_id: String,
    pub action: String,
    pub resource_arn: String,
    pub allowed: bool,
    pub method: String,
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct K8sRbacProof {
    pub subject_id: String,
    pub resource_id: String,
    pub verb: String,
    pub resource: String,
    pub namespace: String,
    pub allowed: bool,
    pub evidence: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BlastRadiusReport {
    pub entry_points: u64,
    pub sensitive_reachable: u64,
    pub max_path_depth: u64,
    pub permission_proven_paths: u64,
    pub cross_plane_paths: u64,
    pub toxic_paths: u64,
    pub blast_score: u64,
}

impl ProvenAttackPath {
    fn from_path(graph: &InfraGraph, path: &[String]) -> Self {
        let hops: Vec<PathHop> = path
            .iter()
            .enumerate()
            .filter_map(|(i, id)| {
                let node = graph.nodes.get(id)?;
                let edge = if i == 0 {
                    None
                } else {
                    graph
                        .edges
                        .iter()
                        .find(|e| e.to == *id && e.from == path[i - 1])
                };
                Some(PathHop {
                    node_id: id.clone(),
                    kind: node.kind.as_str().to_string(),
                    label: node.label.clone(),
                    edge_kind: edge.map(|e| e.kind.as_str().to_string()),
                    evidence: edge.map(|e| e.evidence.clone()),
                    live_status: node.live_status.as_str().to_string(),
                })
            })
            .collect();
        let live_confirmed = hops
            .iter()
            .filter(|h| h.live_status == "confirmed_live")
            .count() as u64;
        let permission_proven_hops = hops
            .windows(2)
            .filter(|w| {
                graph.edges.iter().any(|e| {
                    e.from == w[0].node_id
                        && e.to == w[1].node_id
                        && (e.kind == EdgeKind::IamProven || e.kind == EdgeKind::RbacProven)
                })
            })
            .count() as u64;
        let toxic_class = classify_toxic(&hops);
        let end = graph.nodes.get(path.last().unwrap_or(&String::new()));
        let title = if let Some(n) = end {
            format!(
                "Proven path [{}]: Internet → {} ({})",
                toxic_class,
                n.label,
                n.kind.as_str()
            )
        } else {
            "Proven infrastructure attack path".to_string()
        };
        let narrative = hops
            .iter()
            .map(|h| h.label.clone())
            .collect::<Vec<_>>()
            .join(" → ");
        let id = format!("WZ-PATH-{:06x}", stable_hash(&narrative));
        Self {
            id,
            title,
            hops,
            target_sensitive: end.map(|n| n.sensitive).unwrap_or(false),
            live_confirmed_hops: live_confirmed,
            permission_proven_hops,
            toxic_class,
            narrative,
        }
    }

    #[must_use]
    pub fn severity_weight(&self) -> u64 {
        let base = if self.target_sensitive { 50 } else { 20 };
        let toxic = match self.toxic_class.as_str() {
            "CROSS_PLANE_EXFIL" => 25,
            "IAM_PROVEN_EXFIL" => 20,
            "SECRET_EXPOSURE" => 18,
            "DATA_BREACH" => 15,
            _ => 0,
        };
        base + toxic
            + self.live_confirmed_hops * 15
            + self.permission_proven_hops * 20
            + self.hops.len() as u64 * 3
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "title": self.title,
            "type": "proven_attack_path",
            "toxic_class": self.toxic_class,
            "hops": self.hops,
            "hop_count": self.hops.len(),
            "live_confirmed_hops": self.live_confirmed_hops,
            "permission_proven_hops": self.permission_proven_hops,
            "target_sensitive": self.target_sensitive,
            "narrative": self.narrative,
            "deterministic": true,
            "verification_method": if self.permission_proven_hops > 0 {
                "graph_path_proof+iam_simulate"
            } else {
                "graph_path_proof"
            },
        })
    }

    #[must_use]
    pub fn mermaid(&self) -> String {
        let mut lines = vec!["graph LR".to_string()];
        for (i, hop) in self.hops.iter().enumerate() {
            let nid = format!("N{i}");
            lines.push(format!("  {nid}[\"{}\"]", hop.label.replace('"', "'")));
            if i > 0 {
                lines.push(format!("  N{} --> N{i}", i - 1));
            }
        }
        lines.join("\n")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PathHop {
    pub node_id: String,
    pub kind: String,
    pub label: String,
    pub edge_kind: Option<String>,
    pub evidence: Option<String>,
    pub live_status: String,
}

#[derive(Debug, Clone)]
pub struct LiveReconcileMatch {
    pub node_id: String,
    pub iac_address: String,
    pub live_status: LiveStatus,
    pub evidence: String,
    pub api_called: String,
}

fn classify_toxic(hops: &[PathHop]) -> String {
    let kinds: Vec<&str> = hops.iter().map(|h| h.kind.as_str()).collect();
    let has = |k: &str| kinds.iter().any(|x| *x == k);
    if has("k8s_ingress")
        && has("k8s_service_account")
        && (has("iam_role")
            || hops
                .iter()
                .any(|h| h.edge_kind.as_deref() == Some("cross_plane_trust")))
        && has("s3_bucket")
    {
        return "CROSS_PLANE_EXFIL".to_string();
    }
    if hops
        .iter()
        .any(|h| h.edge_kind.as_deref() == Some("iam_proven"))
        && has("s3_bucket")
    {
        return "IAM_PROVEN_EXFIL".to_string();
    }
    if hops
        .iter()
        .any(|h| h.edge_kind.as_deref() == Some("rbac_proven"))
        && has("k8s_secret")
    {
        return "RBAC_PROVEN_SECRET".to_string();
    }
    if has("k8s_ingress") && has("k8s_secret") {
        return "SECRET_EXPOSURE".to_string();
    }
    if has("rds_instance") || has("k8s_secret") {
        return "DATA_BREACH".to_string();
    }
    if has("security_group") && has("ec2_instance") {
        return "LATERAL_COMPUTE".to_string();
    }
    "GENERIC_REACHABILITY".to_string()
}

fn stable_hash(s: &str) -> u32 {
    s.bytes().fold(0u32, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u32::from(b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proves_internet_to_s3_path() {
        let mut g = InfraGraph::default();
        g.add_node(GraphNode {
            id: "internet".into(),
            kind: NodeKind::Internet,
            label: "Internet".into(),
            file: "graph".into(),
            provider: "generic".into(),
            sensitive: false,
            internet_facing: true,
            live_status: LiveStatus::ConfirmedLive,
            live_evidence: None,
            iac_address: None,
            cloud_arn: None,
        });
        g.add_node(GraphNode {
            id: "sg:web".into(),
            kind: NodeKind::SecurityGroup,
            label: "sg-web".into(),
            file: "main.tf".into(),
            provider: "aws".into(),
            sensitive: false,
            internet_facing: true,
            live_status: LiveStatus::NotChecked,
            live_evidence: None,
            iac_address: Some("aws_security_group.web".into()),
            cloud_arn: None,
        });
        g.add_node(GraphNode {
            id: "s3:assets".into(),
            kind: NodeKind::S3Bucket,
            label: "assets-bucket".into(),
            file: "main.tf".into(),
            provider: "aws".into(),
            sensitive: true,
            internet_facing: false,
            live_status: LiveStatus::ConfirmedLive,
            live_evidence: Some("public ACL".into()),
            iac_address: Some("aws_s3_bucket.assets".into()),
            cloud_arn: None,
        });
        g.add_edge(
            "internet",
            "sg:web",
            EdgeKind::NetworkReachable,
            "0.0.0.0/0 ingress",
        );
        g.add_edge(
            "sg:web",
            "s3:assets",
            EdgeKind::IamAllows,
            "IAM s3:* on bucket",
        );
        let paths = g.proven_paths_to_sensitive();
        assert!(!paths.is_empty());
        assert!(paths[0].hops.len() >= 3);
    }
}
