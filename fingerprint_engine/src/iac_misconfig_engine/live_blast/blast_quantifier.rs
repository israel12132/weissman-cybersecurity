//! Blast radius quantification — deterministic metrics over proven paths and permission proofs.

use super::graph_model::{BlastRadiusReport, EdgeKind, InfraGraph, NodeKind, PermissionProof, ProvenAttackPath};

#[must_use]
pub fn quantify(
    graph: &InfraGraph,
    paths: &[ProvenAttackPath],
    proofs: &[PermissionProof],
) -> BlastRadiusReport {
    let entry_points = graph
        .nodes
        .values()
        .filter(|n| n.internet_facing || n.kind == NodeKind::Internet)
        .count() as u64;
    let sensitive_reachable = paths
        .iter()
        .filter(|p| p.target_sensitive)
        .map(|p| p.hops.last().map(|h| h.node_id.clone()))
        .collect::<std::collections::HashSet<_>>()
        .len() as u64;
    let max_path_depth = paths.iter().map(|p| p.hops.len() as u64).max().unwrap_or(0);
    let permission_proven_paths = paths.iter().filter(|p| p.permission_proven_hops > 0).count() as u64;
    let cross_plane_paths = paths
        .iter()
        .filter(|p| p.toxic_class == "CROSS_PLANE_EXFIL")
        .count() as u64;
    let toxic_paths = paths
        .iter()
        .filter(|p| p.toxic_class != "GENERIC_REACHABILITY")
        .count() as u64;
    let allowed_proofs = proofs.iter().filter(|p| p.allowed).count() as u64;
    let cross_edges = graph
        .edges
        .iter()
        .filter(|e| e.kind == EdgeKind::CrossPlaneTrust)
        .count() as u64;

    let mut blast_score = sensitive_reachable.saturating_mul(8).min(40);
    blast_score += permission_proven_paths.saturating_mul(12).min(30);
    blast_score += cross_plane_paths.saturating_mul(15).min(20);
    blast_score += toxic_paths.saturating_mul(5).min(15);
    blast_score += allowed_proofs.saturating_mul(3).min(15);
    if cross_edges > 0 {
        blast_score = blast_score.saturating_add(5);
    }
    blast_score = blast_score.min(100);

    BlastRadiusReport {
        entry_points,
        sensitive_reachable,
        max_path_depth,
        permission_proven_paths,
        cross_plane_paths,
        toxic_paths,
        blast_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::live_blast::graph_model::{GraphNode, LiveStatus, PathHop};

    #[test]
    fn quantifies_toxic_cross_plane_paths() {
        let mut g = InfraGraph::default();
        g.add_node(GraphNode {
            id: "internet".into(),
            kind: NodeKind::Internet,
            label: "Internet".into(),
            file: "".into(),
            provider: "".into(),
            sensitive: false,
            internet_facing: true,
            live_status: LiveStatus::Skipped,
            live_evidence: None,
            iac_address: None,
            cloud_arn: None,
        });
        let paths = vec![ProvenAttackPath {
            id: "p1".into(),
            title: "x".into(),
            hops: vec![
                PathHop {
                    node_id: "internet".into(),
                    kind: "internet".into(),
                    label: "Internet".into(),
                    edge_kind: None,
                    evidence: None,
                    live_status: "skipped".into(),
                },
                PathHop {
                    node_id: "s3:x".into(),
                    kind: "s3_bucket".into(),
                    label: "x".into(),
                    edge_kind: Some("cross_plane_trust".into()),
                    evidence: None,
                    live_status: "not_checked".into(),
                },
            ],
            target_sensitive: true,
            live_confirmed_hops: 0,
            permission_proven_hops: 1,
            toxic_class: "CROSS_PLANE_EXFIL".into(),
            narrative: "cross".into(),
        }];
        let report = quantify(&g, &paths, &[]);
        assert!(report.blast_score >= 20);
        assert_eq!(report.cross_plane_paths, 1);
    }
}
