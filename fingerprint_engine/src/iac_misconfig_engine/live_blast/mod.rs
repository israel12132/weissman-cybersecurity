//! Live blast orchestrator — graph, reconcile, IAM/RBAC proof, drift, autopilot.

pub mod auto_pilot;
pub mod aws_reconciler;
pub mod blast_quantifier;
pub mod cross_plane;
pub mod drift_engine;
pub mod graph_builder;
pub mod graph_model;
pub mod iam_proof;
pub mod k8s_rbac_proof;
pub mod k8s_reconciler;
pub mod kube_auth;
pub mod policies;

use crate::iac_misconfig_engine::model::{Finding, IacFile};
use auto_pilot::{bundle_json, findings_from_autopilot, run as run_autopilot, AutoPilotConfig, AutoPilotResult};
use aws_reconciler::{matches_json, reconcile_graph as reconcile_aws, AwsReconcileConfig};
use blast_quantifier::quantify;
use cross_plane::wire_cross_plane;
use drift_engine::{findings_from_matches, status_counts};
use graph_builder::build;
use graph_model::{BlastRadiusReport, InfraGraph, K8sRbacProof, LiveReconcileMatch, LiveStatus, PermissionProof, ProvenAttackPath};
use iam_proof::{
    apply_static_proofs, extract_static_proofs, prove_live_permissions, resolve_account_id, IamProofConfig,
};
use k8s_rbac_proof::prove_k8s_rbac;
use k8s_reconciler::{reconcile_graph as reconcile_k8s, K8sReconcileConfig};
use kube_auth::resolve_k8s_auth;
use policies::{
    finding_from_iam_proof, finding_from_k8s_rbac, finding_from_live_match, finding_from_proven_path,
    real_live_risk_score,
};
use serde_json::{json, Value};

pub struct LiveBlastConfig {
    pub enabled: bool,
    pub aws_role_arn: String,
    pub aws_external_id: String,
    pub aws_regions: Vec<String>,
    pub k8s_api_server: String,
    pub k8s_token: String,
    pub k8s_namespace: String,
    pub verify_tls: bool,
    pub timeout_ms: u64,
    pub iam_simulate: bool,
    pub k8s_rbac_prove: bool,
    pub autopilot: bool,
    pub autopilot_create_pr: bool,
    pub git_repo_url: String,
    pub git_base_branch: String,
    pub github_token: String,
}

pub struct LiveBlastResult {
    pub graph: InfraGraph,
    pub proven_paths: Vec<ProvenAttackPath>,
    pub findings: Vec<Finding>,
    pub real_live_risk_score: u64,
    pub live_confirmed_count: u64,
    pub blast_radius: BlastRadiusReport,
    pub cross_plane_bridges: u64,
    pub permission_proofs: Vec<PermissionProof>,
    pub k8s_rbac_proofs: Vec<K8sRbacProof>,
    pub live_matches: Vec<LiveReconcileMatch>,
    pub autopilot: Option<AutoPilotResult>,
    pub k8s_auth_source: Option<String>,
    pub notes: Vec<String>,
}

impl LiveBlastResult {
    #[must_use]
    pub fn summary_json(&self, base_risk: u64) -> Value {
        let mermaid: Vec<String> = self
            .proven_paths
            .iter()
            .take(5)
            .map(|p| p.mermaid())
            .collect();
        let (confirmed, not_deployed, skipped) = status_counts(&self.live_matches);
        let contradicts = self
            .graph
            .nodes
            .values()
            .filter(|n| n.live_status == LiveStatus::ContradictsIac)
            .count();
        json!({
            "engine": "weissman-live-blast",
            "engine_tier": "sovereign-autopilot-complete",
            "deterministic": true,
            "verification_status": if self.live_confirmed_count > 0 || !self.permission_proofs.is_empty() {
                "live_verified"
            } else if !self.notes.is_empty() {
                "graph_only"
            } else {
                "static_graph"
            },
            "graph": self.graph.summary_json(),
            "proven_attack_paths": self.proven_paths.iter().map(ProvenAttackPath::to_json).collect::<Vec<_>>(),
            "proven_path_count": self.proven_paths.len(),
            "live_confirmed_resources": self.live_confirmed_count,
            "live_blast_findings": self.findings.len(),
            "cross_plane_bridges": self.cross_plane_bridges,
            "live_reconcile_matches": matches_json(&self.live_matches),
            "live_status_counts": {
                "confirmed": confirmed,
                "not_deployed": not_deployed,
                "skipped": skipped,
                "contradicts_iac": contradicts,
            },
            "permission_proofs": self.permission_proofs.iter().map(|p| json!({
                "principal": p.principal_id,
                "resource": p.resource_id,
                "action": p.action,
                "allowed": p.allowed,
                "method": p.method,
                "evidence": p.evidence,
            })).collect::<Vec<_>>(),
            "k8s_rbac_proofs": self.k8s_rbac_proofs.iter().map(|p| json!({
                "subject": p.subject_id,
                "verb": p.verb,
                "resource": p.resource,
                "namespace": p.namespace,
                "allowed": p.allowed,
                "evidence": p.evidence,
            })).collect::<Vec<_>>(),
            "blast_radius": self.blast_radius,
            "autopilot": self.autopilot.as_ref().map(bundle_json),
            "k8s_auth_source": self.k8s_auth_source,
            "aws_assumed_role_arn": if self.notes.iter().any(|n| n.contains("assumed role")) {
                self.notes.iter().find(|n| n.contains("assumed role")).cloned()
            } else { None },
            "base_risk_score": base_risk,
            "real_live_risk_score": self.real_live_risk_score,
            "risk_elevation": self.real_live_risk_score.saturating_sub(base_risk),
            "attack_path_mermaid": mermaid,
            "notes": self.notes,
        })
    }
}

fn live_match_is_exposure(graph: &InfraGraph, m: &LiveReconcileMatch) -> bool {
    let Some(node) = graph.nodes.get(&m.node_id) else {
        return false;
    };
    if node.internet_facing || node.sensitive {
        return true;
    }
    let ev = m.evidence.to_ascii_lowercase();
    ev.contains("0.0.0.0/0")
        || ev.contains("public")
        || ev.contains("allusers")
        || ev.contains("weak pab")
        || ev.contains("publicly_accessible=true")
}

/// Build graph, prove permissions, drift, autopilot, attack paths.
pub async fn analyze(files: &[IacFile], cfg: &LiveBlastConfig, base_risk: u64) -> LiveBlastResult {
    let mut graph = build(files);
    let mut notes = Vec::new();
    let mut live_matches = Vec::new();
    let mut k8s_auth_source = None;

    let bridges = wire_cross_plane(files, &mut graph);
    let cross_plane_bridges = bridges.len() as u64;
    if cross_plane_bridges > 0 {
        notes.push(format!("cross-plane IRSA bridges wired: {cross_plane_bridges}"));
    }

    let static_proofs = extract_static_proofs(files, &graph);
    apply_static_proofs(&mut graph, &static_proofs);
    if !static_proofs.is_empty() {
        notes.push(format!(
            "static IAM policy proofs: {}",
            static_proofs.iter().filter(|p| p.allowed).count()
        ));
    }

    if cfg.enabled && !cfg.aws_role_arn.trim().is_empty() {
        let aws_cfg = AwsReconcileConfig {
            role_arn: cfg.aws_role_arn.clone(),
            external_id: cfg.aws_external_id.clone(),
            regions: cfg.aws_regions.clone(),
        };
        let (matches, aws_notes) = reconcile_aws(&mut graph, &aws_cfg).await;
        live_matches.extend(matches);
        notes.extend(aws_notes);
    } else if cfg.enabled {
        notes.push("live blast: enabled but no AWS role — graph-only AWS mode".to_string());
    }

    let mut permission_proofs = static_proofs;
    if cfg.enabled && cfg.iam_simulate && !cfg.aws_role_arn.trim().is_empty() {
        let iam_cfg = IamProofConfig {
            role_arn: cfg.aws_role_arn.clone(),
            external_id: cfg.aws_external_id.clone(),
            enabled: true,
        };
        let account_id = resolve_account_id(&iam_cfg).await.unwrap_or_else(|| "000000000000".into());
        let (live_proofs, iam_notes) = prove_live_permissions(&mut graph, &iam_cfg, &account_id).await;
        permission_proofs.extend(live_proofs);
        notes.extend(iam_notes);
    }

    let mut k8s_rbac_proofs = Vec::new();
    if cfg.enabled {
        if let Some(auth) = resolve_k8s_auth(&K8sReconcileConfig {
            api_server: cfg.k8s_api_server.clone(),
            token: cfg.k8s_token.clone(),
            default_namespace: cfg.k8s_namespace.clone(),
            verify_tls: cfg.verify_tls,
            timeout_ms: cfg.timeout_ms,
        }) {
            k8s_auth_source = Some(auth.source.clone());
            notes.push(format!("K8s auth source: {}", auth.source));
            let k8s_cfg = K8sReconcileConfig {
                api_server: auth.api_server,
                token: auth.token,
                default_namespace: cfg.k8s_namespace.clone(),
                verify_tls: cfg.verify_tls,
                timeout_ms: cfg.timeout_ms,
            };
            let (matches, k8s_notes) = reconcile_k8s(&mut graph, &k8s_cfg).await;
            live_matches.extend(matches);
            notes.extend(k8s_notes);
            if cfg.k8s_rbac_prove {
                let (rbac, rbac_notes) = prove_k8s_rbac(&mut graph, &k8s_cfg).await;
                k8s_rbac_proofs = rbac;
                notes.extend(rbac_notes);
            }
        } else {
            notes.push("live blast: no K8s credentials (explicit/kubeconfig/in-cluster)".to_string());
        }
    }

    let drift_findings = findings_from_matches(&mut graph, &live_matches);

    let proven_paths = graph.proven_paths_to_sensitive();
    let blast_radius = quantify(&graph, &proven_paths, &permission_proofs);

    let autopilot = if cfg.autopilot {
        let ap_cfg = AutoPilotConfig {
            enabled: true,
            create_pr: cfg.autopilot_create_pr,
            repo_url: cfg.git_repo_url.clone(),
            base_branch: cfg.git_base_branch.clone(),
            github_token: cfg.github_token.clone(),
        };
        let result = run_autopilot(files, &graph, &proven_paths, &ap_cfg).await;
        notes.extend(result.notes.clone());
        Some(result)
    } else {
        None
    };

    let live_confirmed_count = graph
        .nodes
        .values()
        .filter(|n| n.live_status == LiveStatus::ConfirmedLive)
        .count() as u64;

    let mut findings = drift_findings;
    for m in &live_matches {
        if m.live_status == LiveStatus::ConfirmedLive && live_match_is_exposure(&graph, m) {
            let file = graph
                .nodes
                .get(&m.node_id)
                .map(|n| n.file.clone())
                .unwrap_or_else(|| "live-cloud".to_string());
            findings.push(finding_from_live_match(&m.node_id, &m.evidence, &file));
        }
    }
    for p in &permission_proofs {
        if p.allowed && p.method == "iam:SimulatePrincipalPolicy" {
            findings.push(finding_from_iam_proof(p));
        }
    }
    for p in &k8s_rbac_proofs {
        if p.allowed {
            findings.push(finding_from_k8s_rbac(p));
        }
    }
    for path in &proven_paths {
        if path.hops.len() >= 2 {
            findings.push(finding_from_proven_path(path));
        }
    }
    if let Some(ref ap) = autopilot {
        findings.extend(findings_from_autopilot(&ap.patches));
    }

    let real_live_risk_score =
        real_live_risk_score(base_risk, live_confirmed_count, &proven_paths, &blast_radius);

    LiveBlastResult {
        graph,
        proven_paths,
        findings,
        real_live_risk_score,
        live_confirmed_count,
        blast_radius,
        cross_plane_bridges,
        permission_proofs,
        k8s_rbac_proofs,
        live_matches,
        autopilot,
        k8s_auth_source,
        notes,
    }
}

#[must_use]
pub fn live_matches_export(matches: &[graph_model::LiveReconcileMatch]) -> Value {
    matches_json(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::model::IacFile;

    #[tokio::test]
    async fn full_pipeline_graph_only() {
        let tf = r#"
resource "aws_security_group" "web" {
  ingress { cidr_blocks = ["0.0.0.0/0"] from_port = 443 to_port = 443 }
}
resource "aws_s3_bucket" "data" { bucket = "corp" acl = "public-read" }
"#;
        let files = vec![IacFile {
            name: "main.tf".into(),
            content: tf.into(),
            forced: None,
            origin: "inline".into(),
        }];
        let cfg = LiveBlastConfig {
            enabled: true,
            aws_role_arn: String::new(),
            aws_external_id: String::new(),
            aws_regions: vec![],
            k8s_api_server: String::new(),
            k8s_token: String::new(),
            k8s_namespace: "default".into(),
            verify_tls: true,
            timeout_ms: 5000,
            iam_simulate: false,
            k8s_rbac_prove: false,
            autopilot: true,
            autopilot_create_pr: false,
            git_repo_url: String::new(),
            git_base_branch: "main".into(),
            github_token: String::new(),
        };
        let r = analyze(&files, &cfg, 10).await;
        assert!(r.proven_paths.len() >= 1 || r.graph.nodes.len() >= 3);
        assert_eq!(r.summary_json(10).get("engine_tier").and_then(Value::as_str), Some("sovereign-autopilot-complete"));
    }
}
