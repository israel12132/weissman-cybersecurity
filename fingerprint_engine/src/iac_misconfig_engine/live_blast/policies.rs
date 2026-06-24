//! Live blast policies and findings — only emitted from proven graph paths or live API evidence.

use super::graph_model::{BlastRadiusReport, PermissionProof, ProvenAttackPath};
use crate::iac_misconfig_engine::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "live_blast", provider: "multi",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const LIVE_CONFIRMED: PolicyMeta = pol!(
    "WZ-LIVE-001",
    "IaC misconfiguration confirmed live in cloud account",
    Critical,
    "Static IaC analysis matched a resource that live cloud API calls (AWS STS/S3/EC2/RDS or Kubernetes API) confirm is deployed and exposed.",
    "Remediate in IaC and apply to live environment; verify with follow-up scan.",
    "T1190",
    "CWE-16",
    &["CNAPP-Live"],
    &["NIST-SI-2", "SOC2-CC8.1", "PCI-DSS-11.2"]
);
pub const PROVEN_PATH: PolicyMeta = pol!(
    "WZ-LIVE-PATH-001",
    "Mathematically proven multi-hop attack path in infrastructure graph",
    Critical,
    "Graph traversal proves a path from Internet to a sensitive asset through network/IAM/RBAC edges observed in IaC.",
    "Break the path: close ingress, scope IAM, enforce network segmentation and PSS restricted.",
    "T1190",
    "CWE-284",
    &["CNAPP-Graph"],
    &["NIST-SC-7", "PCI-DSS-1.3.6", "MITRE-T1190"]
);
pub const LIVE_PATH: PolicyMeta = pol!(
    "WZ-LIVE-PATH-002",
    "Proven attack path with live-confirmed hops",
    Critical,
    "A graph-proven attack path includes hops verified live via cloud API — exploitable now, not theoretical.",
    "Emergency remediation: isolate live resources, revoke IAM, rotate credentials.",
    "T1530",
    "CWE-16",
    &["CNAPP-Live"],
    &["NIST-SI-2", "SOC2-CC7.2"]
);
pub const IAM_PROVEN: PolicyMeta = pol!(
    "WZ-LIVE-IAM-001",
    "IAM SimulatePrincipalPolicy proves S3 exfiltration permission",
    Critical,
    "AWS IAM Policy Simulator mathematically proves the principal can perform S3 read actions on the target bucket — not heuristic wildcard matching.",
    "Scope IAM to least privilege; remove s3:GetObject/ListBucket from compromised roles; enable S3 Block Public Access.",
    "T1530",
    "CWE-269",
    &["CNAPP-IAM-Simulate"],
    &["NIST-AC-6", "PCI-DSS-7.1.2", "SOC2-CC6.3"]
);
pub const CROSS_PLANE: PolicyMeta = pol!(
    "WZ-LIVE-XPLANE-001",
    "Cross-plane attack path: Kubernetes workload → AWS IAM → data store",
    Critical,
    "Deterministic graph proves Internet/K8s ingress reaches a ServiceAccount bridged via IRSA to an AWS IAM role with data access.",
    "Break IRSA trust: scope role policies, enforce PSS restricted, network-policy ingress, rotate cloud credentials.",
    "T1190",
    "CWE-284",
    &["CNAPP-CrossPlane"],
    &["NIST-SC-7", "SOC2-CC6.6", "MITRE-T1190"]
);
pub const TOXIC_PATH: PolicyMeta = pol!(
    "WZ-LIVE-TOXIC-001",
    "Toxic combination — classified multi-hop blast path",
    Critical,
    "Graph path classified as high-toxicity (cross-plane exfil, IAM-proven exfil, secret exposure, or data breach pattern).",
    "Remediate per toxic class: close ingress, revoke IAM/RBAC, encrypt data at rest, segment networks.",
    "T1190",
    "CWE-284",
    &["CNAPP-Toxic"],
    &["NIST-SI-2", "PCI-DSS-1.3.6"]
);
pub const IAM_DATA_PROVEN: PolicyMeta = pol!(
    "WZ-LIVE-IAM-002",
    "IAM Simulator proves RDS/SecretsManager/KMS access",
    Critical,
    "SimulatePrincipalPolicy proves the principal can access RDS, Secrets Manager, or KMS — data-plane exfiltration risk.",
    "Apply least-privilege IAM; restrict security groups; enable encryption and rotation.",
    "T1530",
    "CWE-269",
    &["CNAPP-IAM-Simulate"],
    &["NIST-AC-6", "PCI-DSS-7.1.2", "HIPAA-164.312(a)(1)"]
);
pub const K8S_RBAC_PROVEN: PolicyMeta = pol!(
    "WZ-LIVE-RBAC-001",
    "Kubernetes SubjectAccessReview proves RBAC permission",
    Critical,
    "Live K8s authorization API confirms ServiceAccount can perform verb on resource (e.g. get secrets).",
    "Scope Role/ClusterRole bindings; automountServiceAccountToken=false; default-deny NetworkPolicy.",
    "T1552.007",
    "CWE-269",
    &["CNAPP-K8s-RBAC"],
    &["NIST-AC-6", "SOC2-CC6.3", "MITRE-T1552.007"]
);
pub const AUTOPILOT_FIX: PolicyMeta = pol!(
    "WZ-LIVE-AUTO-001",
    "Auto-Pilot remediation patch generated from proven attack path",
    High,
    "Deterministic code_fix patch generated to break a mathematically proven attack path — ready for PR or pipeline apply.",
    "Review autopilot patch; merge PR or apply via IaC pipeline; re-scan to verify path is broken.",
    "T1190",
    "CWE-16",
    &["CNAPP-AutoPilot"],
    &["NIST-SI-2", "SOC2-CC8.1"]
);
pub const NOT_DEPLOYED: PolicyMeta = pol!(
    "WZ-LIVE-DRIFT-001",
    "IaC resource not deployed in live environment",
    Medium,
    "Live cloud API confirms the IaC-defined resource does not exist in the target account/cluster — configuration drift or stale IaC.",
    "Remove stale IaC, or deploy the resource; reconcile Terraform state with live inventory.",
    "T1190",
    "CWE-16",
    &["CNAPP-Drift"],
    &["NIST-CM-8", "SOC2-CC8.1"]
);
pub const DRIFT_CONTRADICTS: PolicyMeta = pol!(
    "WZ-LIVE-DRIFT-002",
    "Live environment contradicts IaC security posture",
    Critical,
    "Live API evidence shows exposure (public ingress, weak PAB, public RDS) while IaC graph did not mark the resource internet-facing — active drift beyond IaC intent.",
    "Align IaC with reality or remediate live exposure immediately; re-run scan to verify.",
    "T1190",
    "CWE-16",
    &["CNAPP-Drift"],
    &["NIST-SI-2", "SOC2-CC7.2", "PCI-DSS-11.2"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        LIVE_CONFIRMED, PROVEN_PATH, LIVE_PATH, IAM_PROVEN, IAM_DATA_PROVEN, CROSS_PLANE, TOXIC_PATH,
        K8S_RBAC_PROVEN, AUTOPILOT_FIX, NOT_DEPLOYED, DRIFT_CONTRADICTS,
    ]
}

#[must_use]
pub fn finding_from_live_match(node_id: &str, evidence: &str, file: &str) -> Finding {
    Finding::new(LIVE_CONFIRMED, node_id, file).observed(evidence)
}

#[must_use]
pub fn finding_from_proven_path(path: &ProvenAttackPath) -> Finding {
    let has_data_target = path.hops.iter().any(|h| {
        matches!(
            h.kind.as_str(),
            "rds_instance" | "secretsmanager_secret" | "kms_key" | "k8s_secret"
        )
    });
    let pol = if path.toxic_class == "CROSS_PLANE_EXFIL" {
        CROSS_PLANE
    } else if path.permission_proven_hops > 0 && has_data_target {
        IAM_DATA_PROVEN
    } else if path.permission_proven_hops > 0 {
        IAM_PROVEN
    } else if path.toxic_class == "RBAC_PROVEN_SECRET" {
        K8S_RBAC_PROVEN
    } else if path.live_confirmed_hops > 0 {
        LIVE_PATH
    } else if path.toxic_class != "GENERIC_REACHABILITY" {
        TOXIC_PATH
    } else {
        PROVEN_PATH
    };
    Finding::new(pol, &path.id, "live-blast-graph")
        .observed(format!("{} — {}", path.toxic_class, path.narrative))
}

#[must_use]
pub fn finding_from_not_deployed(node_id: &str, evidence: &str, file: &str) -> Finding {
    Finding::new(NOT_DEPLOYED, node_id, file).observed(evidence)
}

#[must_use]
pub fn finding_from_drift(policy: PolicyMeta, node_id: &str, evidence: &str, file: &str) -> Finding {
    Finding::new(policy, node_id, file).observed(evidence)
}

#[must_use]
pub fn finding_from_iam_proof(p: &PermissionProof) -> Finding {
    let pol = if p.action.contains("rds") || p.action.contains("secretsmanager") || p.action.contains("kms") {
        IAM_DATA_PROVEN
    } else {
        IAM_PROVEN
    };
    Finding::new(pol, &p.principal_id, "live-iam-simulate").observed(p.evidence.clone())
}

#[must_use]
pub fn finding_from_k8s_rbac(p: &super::graph_model::K8sRbacProof) -> Finding {
    Finding::new(K8S_RBAC_PROVEN, &p.subject_id, "live-k8s-sar")
        .observed(p.evidence.clone())
}

/// Real Live Risk Score — static base + live confirmation + proven paths + blast quantification.
#[must_use]
pub fn real_live_risk_score(
    base_risk: u64,
    live_confirmed: u64,
    proven_paths: &[ProvenAttackPath],
    blast: &BlastRadiusReport,
) -> u64 {
    let path_boost: u64 = proven_paths
        .iter()
        .map(|p| p.severity_weight())
        .sum::<u64>()
        .min(40);
    let live_boost = live_confirmed.saturating_mul(8).min(35);
    let live_path_boost = proven_paths
        .iter()
        .filter(|p| p.live_confirmed_hops > 0)
        .count() as u64
        * 12;
    let blast_boost = blast.blast_score.min(30);
    let toxic_boost = proven_paths
        .iter()
        .filter(|p| p.toxic_class == "CROSS_PLANE_EXFIL" || p.permission_proven_hops > 0)
        .count() as u64
        * 8;
    (base_risk + path_boost + live_boost + live_path_boost + blast_boost + toxic_boost).min(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::live_blast::graph_model::PathHop;

    #[test]
    fn live_score_elevates_with_paths() {
        let path = ProvenAttackPath {
            id: "WZ-PATH-test".into(),
            title: "t".into(),
            hops: vec![PathHop {
                node_id: "internet".into(),
                kind: "internet".into(),
                label: "Internet".into(),
                edge_kind: None,
                evidence: None,
                live_status: "confirmed_live".into(),
            }],
            target_sensitive: true,
            live_confirmed_hops: 2,
            permission_proven_hops: 1,
            toxic_class: "IAM_PROVEN_EXFIL".into(),
            narrative: "Internet → S3".into(),
        };
        let blast = BlastRadiusReport {
            blast_score: 25,
            ..Default::default()
        };
        let score = real_live_risk_score(30, 2, &[path], &blast);
        assert!(score > 30);
        assert!(score <= 100);
    }
}
