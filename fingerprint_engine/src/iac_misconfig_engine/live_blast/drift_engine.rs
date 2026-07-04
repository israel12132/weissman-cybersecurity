//! IaC ↔ live drift detection — NotDeployed and ContradictsIac from reconcile matches.

use super::graph_model::{InfraGraph, LiveReconcileMatch, LiveStatus, NodeKind};
use super::policies::{
    finding_from_drift, finding_from_not_deployed, DRIFT_CONTRADICTS, NOT_DEPLOYED,
};
use crate::iac_misconfig_engine::model::Finding;

/// Emit findings for drift states discovered during live reconciliation.
#[must_use]
pub fn findings_from_matches(
    graph: &mut InfraGraph,
    matches: &[LiveReconcileMatch],
) -> Vec<Finding> {
    let mut out = Vec::new();
    for m in matches {
        let file = graph
            .nodes
            .get(&m.node_id)
            .map(|n| n.file.clone())
            .unwrap_or_else(|| "live-reconcile".to_string());
        match m.live_status {
            LiveStatus::NotDeployed => {
                out.push(finding_from_not_deployed(&m.node_id, &m.evidence, &file));
            }
            LiveStatus::ConfirmedLive => {
                if let Some(node) = graph.nodes.get(&m.node_id) {
                    let contradicts = detect_contradiction(node, &m.evidence);
                    if contradicts {
                        graph.nodes.get_mut(&m.node_id).map(|n| {
                            n.live_status = LiveStatus::ContradictsIac;
                        });
                        out.push(finding_from_drift(
                            DRIFT_CONTRADICTS,
                            &m.node_id,
                            &format!("IaC/live contradiction: {}", m.evidence),
                            &file,
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn detect_contradiction(node: &super::graph_model::GraphNode, evidence: &str) -> bool {
    let ev = evidence.to_ascii_lowercase();
    if !node.internet_facing
        && (ev.contains("0.0.0.0/0")
            || ev.contains("publicly_accessible=true")
            || ev.contains("weak pab"))
    {
        return true;
    }
    if node.kind == NodeKind::S3Bucket
        && !node.internet_facing
        && (ev.contains("allusers") || ev.contains("authenticatedusers") || ev.contains("weak pab"))
    {
        return true;
    }
    false
}

#[must_use]
pub fn status_counts(matches: &[LiveReconcileMatch]) -> (u64, u64, u64) {
    let mut confirmed = 0u64;
    let mut not_deployed = 0u64;
    let mut skipped = 0u64;
    for m in matches {
        match m.live_status {
            LiveStatus::ConfirmedLive => confirmed += 1,
            LiveStatus::NotDeployed => not_deployed += 1,
            LiveStatus::Skipped | LiveStatus::NotChecked => skipped += 1,
            LiveStatus::ContradictsIac => confirmed += 1,
        }
    }
    (confirmed, not_deployed, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::live_blast::graph_model::{
        GraphNode, InfraGraph, LiveReconcileMatch, LiveStatus, NodeKind,
    };

    #[test]
    fn not_deployed_emits_drift_finding() {
        let mut g = InfraGraph::default();
        g.add_node(GraphNode {
            id: "s3:missing".into(),
            kind: NodeKind::S3Bucket,
            label: "missing".into(),
            file: "main.tf".into(),
            provider: "aws".into(),
            sensitive: true,
            internet_facing: false,
            live_status: LiveStatus::NotChecked,
            live_evidence: None,
            iac_address: Some("aws_s3_bucket.missing".into()),
            cloud_arn: None,
        });
        let m = LiveReconcileMatch {
            node_id: "s3:missing".into(),
            iac_address: "missing".into(),
            live_status: LiveStatus::NotDeployed,
            evidence: "not found".into(),
            api_called: "s3:ListBuckets".into(),
        };
        let findings = findings_from_matches(&mut g, &[m]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].policy.id, NOT_DEPLOYED.id);
    }
}
