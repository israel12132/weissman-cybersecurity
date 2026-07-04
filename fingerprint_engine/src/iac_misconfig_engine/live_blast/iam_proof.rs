//! IAM permission proof engine — static policy parse + live `SimulatePrincipalPolicy` (S3/RDS/SM/KMS).

use super::graph_model::{EdgeKind, InfraGraph, NodeKind, PermissionProof};
use crate::iac_misconfig_engine::model::IacFile;
use crate::iac_misconfig_engine::terraform::{parse_hcl, HclValue};

pub struct IamProofConfig {
    pub role_arn: String,
    pub external_id: String,
    pub enabled: bool,
}

struct SimSpec {
    kind: NodeKind,
    prefix: &'static str,
    actions: &'static [&'static str],
}

const SIM_SPECS: &[SimSpec] = &[
    SimSpec {
        kind: NodeKind::S3Bucket,
        prefix: "s3",
        actions: &["s3:GetObject", "s3:ListBucket", "s3:*"],
    },
    SimSpec {
        kind: NodeKind::RdsInstance,
        prefix: "rds",
        actions: &["rds-db:connect", "rds:Connect", "rds:*"],
    },
    SimSpec {
        kind: NodeKind::SecretsManagerSecret,
        prefix: "sm",
        actions: &[
            "secretsmanager:GetSecretValue",
            "secretsmanager:DescribeSecret",
            "secretsmanager:*",
        ],
    },
    SimSpec {
        kind: NodeKind::KmsKey,
        prefix: "kms",
        actions: &["kms:Decrypt", "kms:DescribeKey", "kms:*"],
    },
];

/// Parse explicit IAM policy statements from Terraform and link roles → resources when ARNs match.
#[must_use]
pub fn extract_static_proofs(files: &[IacFile], graph: &InfraGraph) -> Vec<PermissionProof> {
    let mut proofs = Vec::new();
    let targets: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| {
            matches!(
                n.kind,
                NodeKind::S3Bucket
                    | NodeKind::RdsInstance
                    | NodeKind::SecretsManagerSecret
                    | NodeKind::KmsKey
            )
        })
        .map(|n| (n.id.clone(), n.kind, n.label.clone()))
        .collect();
    let roles: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| n.kind == NodeKind::IamRole)
        .map(|n| (n.id.clone(), n.label.clone()))
        .collect();

    for f in files {
        if !(f.name.ends_with(".tf") || f.content.contains("resource \"")) {
            continue;
        }
        for b in parse_hcl(&f.content) {
            if b.typ != "resource" {
                continue;
            }
            let rtype = b.labels.first().map(String::as_str).unwrap_or("");
            if !matches!(
                rtype,
                "aws_iam_role_policy" | "aws_iam_policy" | "aws_iam_role_policy_attachment"
            ) {
                continue;
            }
            let role_name = b
                .attr_str("role")
                .or_else(|| b.labels.get(1).map(|s| s.to_string()))
                .map(|r| r.split('.').next_back().unwrap_or(&r).to_string());
            let Some(role_name) = role_name else { continue };
            let role_id = format!("iam:{role_name}");
            if !graph.nodes.contains_key(&role_id) {
                continue;
            }
            let policy_doc = b
                .attr("policy")
                .and_then(policy_doc_str)
                .unwrap_or_else(|| f.content.clone());
            let statements = parse_policy_actions_resources(&policy_doc);
            for (actions, resources) in statements {
                for action in &actions {
                    for (tid, kind, label) in &targets {
                        if !action_matches_kind(action, *kind) && *action != "*" {
                            continue;
                        }
                        for resource in &resources {
                            if resource_matches_target(resource, label, *kind) {
                                proofs.push(PermissionProof {
                                    principal_id: role_id.clone(),
                                    resource_id: tid.clone(),
                                    action: action.clone(),
                                    resource_arn: resource.clone(),
                                    allowed: true,
                                    method: "static_policy_parse".to_string(),
                                    evidence: format!(
                                        "IAM policy allows {action} on {resource} for role {role_name}"
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    proofs.sort_by(|a, b| {
        (&a.principal_id, &a.resource_id, &a.action).cmp(&(
            &b.principal_id,
            &b.resource_id,
            &b.action,
        ))
    });
    proofs.dedup_by(|a, b| {
        a.principal_id == b.principal_id && a.resource_id == b.resource_id && a.action == b.action
    });

    for (rid, _) in &roles {
        for (tid, kind, label) in &targets {
            if graph
                .edges
                .iter()
                .any(|e| e.from == *rid && e.to == *tid && e.kind == EdgeKind::IamAllows)
            {
                let action = match kind {
                    NodeKind::S3Bucket => "s3:*",
                    NodeKind::RdsInstance => "rds:*",
                    NodeKind::SecretsManagerSecret => "secretsmanager:*",
                    NodeKind::KmsKey => "kms:*",
                    _ => continue,
                };
                if !proofs
                    .iter()
                    .any(|p| p.principal_id == *rid && p.resource_id == *tid && p.action == action)
                {
                    proofs.push(PermissionProof {
                        principal_id: rid.clone(),
                        resource_id: tid.clone(),
                        action: action.to_string(),
                        resource_arn: resource_arns_for(*kind, label, "000000000000")
                            .first()
                            .cloned()
                            .unwrap_or_default(),
                        allowed: true,
                        method: "graph_iam_allows_edge".to_string(),
                        evidence: format!("Graph IamAllows edge role → {label}"),
                    });
                }
            }
        }
    }

    proofs
}

pub fn apply_static_proofs(graph: &mut InfraGraph, proofs: &[PermissionProof]) {
    graph.permission_proofs.extend(proofs.iter().cloned());
    for p in proofs {
        if !p.allowed {
            continue;
        }
        if p.method == "static_policy_parse" || p.method == "iam:SimulatePrincipalPolicy" {
            graph.add_edge(
                &p.principal_id,
                &p.resource_id,
                EdgeKind::IamProven,
                p.evidence.clone(),
            );
        }
    }
}

#[cfg(feature = "live-aws")]
mod imp {
    use super::*;
    use crate::cloud_integration_engine::{assume_role_sdk_config, CrossAccountAwsConfig};
    use aws_sdk_iam::types::EvaluationResult;

    pub async fn prove_live_permissions(
        graph: &mut InfraGraph,
        cfg: &IamProofConfig,
        account_id: &str,
    ) -> (Vec<PermissionProof>, Vec<String>) {
        let mut notes = Vec::new();
        let mut proofs = Vec::new();
        if !cfg.enabled || cfg.role_arn.trim().is_empty() {
            notes.push("IAM simulate skipped: disabled or no role".to_string());
            return (proofs, notes);
        }

        let cross = CrossAccountAwsConfig {
            role_arn: cfg.role_arn.clone(),
            external_id: cfg.external_id.clone(),
            session_name: String::new(),
        };
        let Ok((sdk, _)) = assume_role_sdk_config(&cross).await else {
            notes.push("IAM simulate failed: STS AssumeRole".to_string());
            return (proofs, notes);
        };

        let iam = aws_sdk_iam::Client::new(&sdk);
        let roles: Vec<_> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::IamRole)
            .map(|n| (n.id.clone(), n.cloud_arn.clone(), n.label.clone()))
            .collect();

        for spec in SIM_SPECS {
            let resources: Vec<_> = graph
                .nodes
                .values()
                .filter(|n| n.kind == spec.kind)
                .map(|n| (n.id.clone(), n.label.clone()))
                .collect();
            for (rid, role_arn, role_label) in &roles {
                let principal_arn = role_arn
                    .clone()
                    .unwrap_or_else(|| format!("arn:aws:iam::{account_id}:role/{role_label}"));
                for (target_id, label) in &resources {
                    let arns = resource_arns_for(spec.kind, label, account_id);
                    for action in spec.actions {
                        let Ok(out) = iam
                            .simulate_principal_policy()
                            .policy_source_arn(&principal_arn)
                            .action_names(*action)
                            .set_resource_arns(Some(arns.clone()))
                            .send()
                            .await
                        else {
                            continue;
                        };
                        if !out.evaluation_results().iter().any(eval_allowed) {
                            continue;
                        }
                        let evidence = format!(
                            "SimulatePrincipalPolicy: {principal_arn} allowed {action} on {} ({})",
                            label, spec.prefix
                        );
                        proofs.push(PermissionProof {
                            principal_id: rid.clone(),
                            resource_id: target_id.clone(),
                            action: (*action).to_string(),
                            resource_arn: arns.first().cloned().unwrap_or_default(),
                            allowed: true,
                            method: "iam:SimulatePrincipalPolicy".to_string(),
                            evidence: evidence.clone(),
                        });
                        graph.add_edge(rid, target_id, EdgeKind::IamProven, evidence);
                    }
                }
            }
        }

        notes.push(format!(
            "IAM SimulatePrincipalPolicy: {} proven permissions",
            proofs.len()
        ));
        graph.permission_proofs.extend(proofs.clone());
        (proofs, notes)
    }

    pub async fn resolve_account_id(cfg: &IamProofConfig) -> Option<String> {
        let cross = CrossAccountAwsConfig {
            role_arn: cfg.role_arn.clone(),
            external_id: cfg.external_id.clone(),
            session_name: String::new(),
        };
        let (sdk, _) = assume_role_sdk_config(&cross).await.ok()?;
        let sts = aws_sdk_sts::Client::new(&sdk);
        let out = sts.get_caller_identity().send().await.ok()?;
        out.account().map(str::to_string)
    }

    fn eval_allowed(r: &EvaluationResult) -> bool {
        matches!(
            r.eval_decision(),
            aws_sdk_iam::types::PolicyEvaluationDecisionType::Allowed
        )
    }
}

#[cfg(not(feature = "live-aws"))]
mod imp {
    use super::*;

    pub async fn prove_live_permissions(
        _graph: &mut InfraGraph,
        _cfg: &IamProofConfig,
        _account_id: &str,
    ) -> (Vec<PermissionProof>, Vec<String>) {
        (
            Vec::new(),
            vec!["IAM simulate stub (build with live-aws feature)".to_string()],
        )
    }

    pub async fn resolve_account_id(_cfg: &IamProofConfig) -> Option<String> {
        None
    }
}

pub use imp::{prove_live_permissions, resolve_account_id};

fn resource_arns_for(kind: NodeKind, label: &str, account_id: &str) -> Vec<String> {
    match kind {
        NodeKind::S3Bucket => vec![
            format!("arn:aws:s3:::{label}"),
            format!("arn:aws:s3:::{label}/*"),
        ],
        NodeKind::RdsInstance => vec![
            format!("arn:aws:rds:*:*:db:{label}"),
            format!("arn:aws:rds-db:*:*:dbuser:*/{label}"),
        ],
        NodeKind::SecretsManagerSecret => {
            vec![format!("arn:aws:secretsmanager:*:*:secret:{label}*")]
        }
        NodeKind::KmsKey => vec![format!("arn:aws:kms:*:*:key/{label}")],
        _ => vec![format!("arn:aws:iam::{account_id}:role/{label}")],
    }
}

fn action_matches_kind(action: &str, kind: NodeKind) -> bool {
    match kind {
        NodeKind::S3Bucket => action.contains("s3:"),
        NodeKind::RdsInstance => action.contains("rds"),
        NodeKind::SecretsManagerSecret => action.contains("secretsmanager:"),
        NodeKind::KmsKey => action.contains("kms:"),
        _ => false,
    }
}

fn resource_matches_target(resource: &str, label: &str, kind: NodeKind) -> bool {
    if resource == "*" {
        return true;
    }
    if resource.contains(label) {
        return true;
    }
    match kind {
        NodeKind::S3Bucket => resource.contains("arn:aws:s3:::"),
        NodeKind::RdsInstance => resource.contains(":db:") || resource.contains("rds"),
        NodeKind::SecretsManagerSecret => resource.contains(":secret:"),
        NodeKind::KmsKey => resource.contains(":key/"),
        _ => false,
    }
}

fn policy_doc_str(v: &HclValue) -> Option<String> {
    match v {
        HclValue::Str(s) | HclValue::Raw(s) => Some(s.clone()),
        _ => None,
    }
}

fn parse_policy_actions_resources(doc: &str) -> Vec<(Vec<String>, Vec<String>)> {
    let mut out = Vec::new();
    let lc = doc.to_ascii_lowercase();
    if !lc.contains("action") || !lc.contains("resource") {
        return out;
    }
    let actions = extract_quoted_list(doc, "Action");
    let resources = extract_quoted_list(doc, "Resource");
    if !actions.is_empty() && !resources.is_empty() {
        out.push((actions, resources));
    }
    out
}

fn extract_quoted_list(doc: &str, key: &str) -> Vec<String> {
    let mut items = Vec::new();
    let patterns = [format!("\"{key}\""), format!("'{key}'")];
    for pat in &patterns {
        if let Some(idx) = doc.find(pat) {
            let rest = &doc[idx + pat.len()..];
            if let Some(val) = rest.trim_start_matches([':', ' ', '\t']).strip_prefix('[') {
                for part in val.split(',') {
                    let t = part.trim().trim_matches(['[', ']', '"', '\'', ' ']);
                    if !t.is_empty() && t != key {
                        items.push(t.to_string());
                    }
                }
            } else if let Some(q) = rest.trim_start_matches([':', ' ', '\t']).chars().next() {
                if q == '"' || q == '\'' {
                    if let Some(start) = rest.find(q) {
                        let inner = rest[start + 1..].split(q).next().unwrap_or("");
                        if !inner.is_empty() {
                            items.push(inner.to_string());
                        }
                    }
                }
            }
        }
    }
    if items.is_empty() && doc.contains('*') {
        items.push("*".to_string());
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rds_arns_generated() {
        let arns = resource_arns_for(NodeKind::RdsInstance, "prod-db", "123");
        assert!(arns.iter().any(|a| a.contains("prod-db")));
    }
}
