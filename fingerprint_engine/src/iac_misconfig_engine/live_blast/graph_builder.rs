//! Builds a deterministic Resource + IAM + Network graph from scanned IaC artifacts.

use super::graph_model::{EdgeKind, GraphNode, InfraGraph, LiveStatus, NodeKind};
use crate::iac_misconfig_engine::model::IacFile;
use crate::iac_misconfig_engine::terraform::{parse_hcl, HclBlock, HclValue};
use serde_yaml::Value;
use std::collections::HashMap;

const INTERNET_ID: &str = "internet";

#[must_use]
pub fn build(files: &[IacFile]) -> InfraGraph {
    let mut g = InfraGraph::default();
    g.add_node(GraphNode {
        id: INTERNET_ID.to_string(),
        kind: NodeKind::Internet,
        label: "Internet".to_string(),
        file: "graph-root".to_string(),
        provider: "generic".to_string(),
        sensitive: false,
        internet_facing: true,
        live_status: LiveStatus::ConfirmedLive,
        live_evidence: Some("synthetic entry — attacker origin".to_string()),
        iac_address: None,
        cloud_arn: None,
    });

    let mut sg_open: HashMap<String, bool> = HashMap::new();
    let mut role_wildcard: HashMap<String, bool> = HashMap::new();
    let mut instance_sgs: Vec<(String, Vec<String>)> = Vec::new();
    let mut rds_sgs: Vec<(String, Vec<String>, bool)> = Vec::new();
    let mut bucket_ids: Vec<(String, String, bool)> = Vec::new();

    for f in files {
        if f.name.ends_with(".tf") || f.content.contains("resource \"") {
            ingest_terraform(f, &mut g, &mut sg_open, &mut role_wildcard, &mut instance_sgs, &mut rds_sgs, &mut bucket_ids);
        }
        if f.name.ends_with(".yaml") || f.name.ends_with(".yml") {
            ingest_k8s(f, &mut g);
        }
    }

    for (sg_id, open) in &sg_open {
        if *open {
            g.add_edge(INTERNET_ID, sg_id, EdgeKind::NetworkReachable, "ingress 0.0.0.0/0 or ::/0");
        }
    }
    for (inst_id, sgs) in &instance_sgs {
        for sg in sgs {
            let sg_nid = format!("sg:{sg}");
            if g.nodes.contains_key(&sg_nid) {
                g.add_edge(&sg_nid, inst_id, EdgeKind::NetworkReachable, "vpc_security_group_ids");
            }
        }
    }
    for (rds_id, sgs, public) in &rds_sgs {
        for sg in sgs {
            let sg_nid = format!("sg:{sg}");
            if g.nodes.contains_key(&sg_nid) {
                g.add_edge(&sg_nid, rds_id, EdgeKind::NetworkReachable, "RDS vpc_security_group_ids");
            }
        }
        if *public {
            g.add_edge(INTERNET_ID, rds_id, EdgeKind::NetworkReachable, "publicly_accessible = true");
        }
    }
    for (role_id, wild) in &role_wildcard {
        if *wild {
            for (bid, _, is_public) in &bucket_ids {
                if *is_public {
                    g.add_edge(role_id, bid, EdgeKind::IamAllows, "IAM Action */Resource * allows S3 access");
                }
            }
        }
    }

    g
}

fn ingest_terraform(
    f: &IacFile,
    g: &mut InfraGraph,
    sg_open: &mut HashMap<String, bool>,
    role_wildcard: &mut HashMap<String, bool>,
    instance_sgs: &mut Vec<(String, Vec<String>)>,
    rds_sgs: &mut Vec<(String, Vec<String>, bool)>,
    bucket_ids: &mut Vec<(String, String, bool)>,
) {
    for b in parse_hcl(&f.content) {
        if b.typ != "resource" {
            continue;
        }
        let rtype = b.labels.first().map(String::as_str).unwrap_or("");
        let rname = b.labels.get(1).map(String::as_str).unwrap_or("?");
        let addr = b.address();
        match rtype {
            "aws_security_group" => {
                let nid = format!("sg:{rname}");
                let mut open = false;
                for ing in b.nested("ingress") {
                    if rule_open(ing) {
                        open = true;
                    }
                }
                if block_has_open_cidr(&f.content, &addr) {
                    open = true;
                }
                sg_open.insert(nid.clone(), open);
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::SecurityGroup,
                    label: rname.to_string(),
                    file: f.name.clone(),
                    provider: "aws".to_string(),
                    sensitive: false,
                    internet_facing: open,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(addr),
                    cloud_arn: None,
                });
            }
            "aws_instance" => {
                let nid = format!("ec2:{rname}");
                let sgs = b
                    .attr("vpc_security_group_ids")
                    .map(|v| ref_list(v))
                    .unwrap_or_default();
                instance_sgs.push((nid.clone(), sgs));
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::Ec2Instance,
                    label: rname.to_string(),
                    file: f.name.clone(),
                    provider: "aws".to_string(),
                    sensitive: false,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(addr),
                    cloud_arn: None,
                });
            }
            "aws_db_instance" | "aws_rds_cluster_instance" => {
                let nid = format!("rds:{rname}");
                let sgs = b
                    .attr("vpc_security_group_ids")
                    .map(|v| ref_list(v))
                    .unwrap_or_default();
                let public = b.attr_bool("publicly_accessible").unwrap_or(false)
                    || b.attr_str("publicly_accessible").as_deref() == Some("true");
                rds_sgs.push((nid.clone(), sgs, public));
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::RdsInstance,
                    label: rname.to_string(),
                    file: f.name.clone(),
                    provider: "aws".to_string(),
                    sensitive: true,
                    internet_facing: public,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(addr),
                    cloud_arn: None,
                });
            }
            "aws_s3_bucket" => {
                let bucket_name = b.attr_str("bucket").unwrap_or_else(|| rname.to_string());
                let nid = format!("s3:{rname}");
                let lc = f.content.to_ascii_lowercase();
                let public = lc.contains("public-read") || lc.contains("public_read")
                    || lc.contains("acl = \"public");
                bucket_ids.push((nid.clone(), bucket_name.clone(), public));
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::S3Bucket,
                    label: bucket_name,
                    file: f.name.clone(),
                    provider: "aws".to_string(),
                    sensitive: true,
                    internet_facing: public,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(addr),
                    cloud_arn: None,
                });
                if public {
                    g.add_edge(INTERNET_ID, &format!("s3:{rname}"), EdgeKind::NetworkReachable, "public S3 ACL/policy");
                }
            }
            "aws_iam_role" => {
                let nid = format!("iam:{rname}");
                let wild = policy_document_wildcard(&b);
                role_wildcard.insert(nid.clone(), wild);
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::IamRole,
                    label: rname.to_string(),
                    file: f.name.clone(),
                    provider: "aws".to_string(),
                    sensitive: wild,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(addr),
                    cloud_arn: None,
                });
            }
            "aws_iam_role_policy" | "aws_iam_role_policy_attachment" | "aws_iam_policy" => {
                let wild = policy_document_wildcard(&b) || f.content.contains("Action") && f.content.contains('*');
                if wild {
                    if let Some(role) = b.attr_str("role").or_else(|| b.labels.get(1).map(|s| s.to_string())) {
                        let role_ref = role.split('.').last().unwrap_or(&role);
                        role_wildcard.insert(format!("iam:{role_ref}"), true);
                    }
                }
            }
            "aws_lb" | "aws_alb" | "aws_elb" => {
                let nid = format!("lb:{rname}");
                g.add_node(GraphNode {
                    id: nid.clone(),
                    kind: NodeKind::LoadBalancer,
                    label: rname.to_string(),
                    file: f.name.clone(),
                    provider: "aws".to_string(),
                    sensitive: false,
                    internet_facing: b.attr_str("internal").as_deref() != Some("true"),
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(addr),
                    cloud_arn: None,
                });
                if b.attr_str("internal").as_deref() != Some("true") {
                    g.add_edge(INTERNET_ID, &nid, EdgeKind::NetworkReachable, "internet-facing load balancer");
                }
            }
            "aws_secretsmanager_secret" => {
                let nid = format!("sm:{rname}");
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::SecretsManagerSecret,
                    label: rname.to_string(),
                    file: f.name.clone(),
                    provider: "aws".to_string(),
                    sensitive: true,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(addr),
                    cloud_arn: None,
                });
            }
            "aws_kms_key" => {
                let nid = format!("kms:{rname}");
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::KmsKey,
                    label: rname.to_string(),
                    file: f.name.clone(),
                    provider: "aws".to_string(),
                    sensitive: true,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(addr),
                    cloud_arn: None,
                });
            }
            _ => {}
        }
    }
}

fn ingest_k8s(f: &IacFile, g: &mut InfraGraph) {
    for doc in f.content.split("\n---\n") {
        let Ok(v) = serde_yaml::from_str::<Value>(doc.trim()) else { continue };
        let kind = v.get("kind").and_then(Value::as_str).unwrap_or("");
        let name = v
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("?");
        let ns = v
            .get("metadata")
            .and_then(|m| m.get("namespace"))
            .and_then(Value::as_str)
            .unwrap_or("default");
        let file = f.name.clone();
        match kind {
            "Ingress" => {
                let nid = format!("ing:{name}");
                let no_tls = v.get("spec").and_then(|s| s.get("tls")).is_none();
                g.add_node(GraphNode {
                    id: nid.clone(),
                    kind: NodeKind::K8sIngress,
                    label: name.to_string(),
                    file,
                    provider: "kubernetes".to_string(),
                    sensitive: false,
                    internet_facing: true,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(format!("{ns}/Ingress/{name}")),
                    cloud_arn: None,
                });
                g.add_edge(INTERNET_ID, &nid, EdgeKind::NetworkReachable, if no_tls { "Ingress without TLS" } else { "Ingress" });
                if let Some(rules) = v.get("spec").and_then(|s| s.get("rules")).and_then(Value::as_sequence) {
                    for rule in rules {
                        if let Some(svc) = rule
                            .get("http")
                            .and_then(|h| h.get("paths"))
                            .and_then(Value::as_sequence)
                            .and_then(|p| p.first())
                            .and_then(|p| p.get("backend"))
                            .and_then(|b| b.get("service"))
                            .and_then(|s| s.get("name"))
                            .and_then(Value::as_str)
                        {
                            let snid = format!("svc:{svc}");
                            g.add_edge(&nid, &snid, EdgeKind::K8sRoutesTo, "Ingress backend service");
                        }
                    }
                }
            }
            "Service" => {
                let st = v.get("spec").and_then(|s| s.get("type")).and_then(Value::as_str).unwrap_or("ClusterIP");
                let nid = format!("svc:{name}");
                let external = st == "LoadBalancer" || st == "NodePort";
                g.add_node(GraphNode {
                    id: nid.clone(),
                    kind: NodeKind::K8sService,
                    label: name.to_string(),
                    file: f.name.clone(),
                    provider: "kubernetes".to_string(),
                    sensitive: false,
                    internet_facing: external,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(format!("{ns}/Service/{name}")),
                    cloud_arn: None,
                });
                if external {
                    g.add_edge(INTERNET_ID, &nid, EdgeKind::NetworkReachable, format!("Service type {st}"));
                }
            }
            "Deployment" | "StatefulSet" | "DaemonSet" => {
                let nid = format!("pod:{name}");
                let sa = v
                    .get("spec")
                    .and_then(|s| s.get("template"))
                    .and_then(|t| t.get("spec"))
                    .and_then(|s| s.get("serviceAccountName"))
                    .and_then(Value::as_str)
                    .unwrap_or("default");
                let priv_pod = doc.to_ascii_lowercase().contains("privileged: true");
                g.add_node(GraphNode {
                    id: nid.clone(),
                    kind: NodeKind::K8sPod,
                    label: name.to_string(),
                    file: f.name.clone(),
                    provider: "kubernetes".to_string(),
                    sensitive: priv_pod,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(format!("{ns}/{kind}/{name}")),
                    cloud_arn: None,
                });
                let snid = format!("svc:{name}");
                if g.nodes.contains_key(&snid) {
                    g.add_edge(&snid, &nid, EdgeKind::K8sRoutesTo, "Service selector → workload");
                }
                let sanid = format!("sa:{sa}");
                if !g.nodes.contains_key(&sanid) {
                    g.add_node(GraphNode {
                        id: sanid.clone(),
                        kind: NodeKind::K8sServiceAccount,
                        label: sa.to_string(),
                        file: f.name.clone(),
                        provider: "kubernetes".to_string(),
                        sensitive: false,
                        internet_facing: false,
                        live_status: LiveStatus::NotChecked,
                        live_evidence: None,
                        iac_address: Some(format!("{ns}/ServiceAccount/{sa}")),
                        cloud_arn: None,
                    });
                }
                g.add_edge(&nid, &sanid, EdgeKind::K8sMountsSa, "serviceAccountName");
                wire_secret_volume_mounts(&v, &nid, ns, f.name.as_str(), g);
            }
            "ServiceAccount" => {
                let nid = format!("sa:{name}");
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::K8sServiceAccount,
                    label: name.to_string(),
                    file: f.name.clone(),
                    provider: "kubernetes".to_string(),
                    sensitive: false,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(format!("{ns}/ServiceAccount/{name}")),
                    cloud_arn: None,
                });
            }
            "Secret" => {
                let nid = format!("secret:{name}");
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::K8sSecret,
                    label: name.to_string(),
                    file: f.name.clone(),
                    provider: "kubernetes".to_string(),
                    sensitive: true,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(format!("{ns}/Secret/{name}")),
                    cloud_arn: None,
                });
            }
            "ClusterRoleBinding" | "RoleBinding" => {
                let ref_name = v
                    .get("roleRef")
                    .and_then(|r| r.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if ref_name == "cluster-admin" {
                    if let Some(subj) = v.get("subjects").and_then(Value::as_sequence) {
                        for s in subj {
                            if s.get("kind").and_then(Value::as_str) == Some("ServiceAccount") {
                                if let Some(sa) = s.get("name").and_then(Value::as_str) {
                                    let sanid = format!("sa:{sa}");
                                    if g.nodes.contains_key(&sanid) {
                                        g.add_edge(&sanid, &sanid, EdgeKind::RbacGrants, "cluster-admin binding");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "Role" | "ClusterRole" => {
                let nid = format!("role:{name}");
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::K8sServiceAccount,
                    label: name.to_string(),
                    file: f.name.clone(),
                    provider: "kubernetes".to_string(),
                    sensitive: false,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(if kind == "ClusterRole" {
                        format!("cluster/{kind}/{name}")
                    } else {
                        format!("{ns}/{kind}/{name}")
                    }),
                    cloud_arn: None,
                });
            }
            "NetworkPolicy" => {
                let nid = format!("netpol:{name}");
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::K8sPod,
                    label: name.to_string(),
                    file: f.name.clone(),
                    provider: "kubernetes".to_string(),
                    sensitive: false,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(format!("{ns}/NetworkPolicy/{name}")),
                    cloud_arn: None,
                });
            }
            "ConfigMap" => {
                let nid = format!("cm:{name}");
                g.add_node(GraphNode {
                    id: nid,
                    kind: NodeKind::K8sSecret,
                    label: name.to_string(),
                    file: f.name.clone(),
                    provider: "kubernetes".to_string(),
                    sensitive: false,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(format!("{ns}/ConfigMap/{name}")),
                    cloud_arn: None,
                });
            }
            _ => {}
        }
    }
}

fn wire_secret_volume_mounts(v: &Value, pod_id: &str, ns: &str, file: &str, g: &mut InfraGraph) {
    let spec = v
        .get("spec")
        .and_then(|s| s.get("template"))
        .and_then(|t| t.get("spec"));
    let Some(spec) = spec else { return };
    let secret_volumes: std::collections::HashMap<String, String> = spec
        .get("volumes")
        .and_then(Value::as_sequence)
        .map(|vols| {
            vols.iter()
                .filter_map(|vol| {
                    let vol_name = vol.get("name").and_then(Value::as_str)?;
                    let secret_name = vol
                        .get("secret")
                        .and_then(|s| s.get("secretName"))
                        .and_then(Value::as_str)?;
                    Some((vol_name.to_string(), secret_name.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let containers = spec
        .get("containers")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten();
    for c in containers {
        for vm in c.get("volumeMounts").and_then(Value::as_sequence).into_iter().flatten() {
            let vol_name = vm.get("name").and_then(Value::as_str).unwrap_or("");
            let Some(secret_name) = secret_volumes.get(vol_name) else {
                continue;
            };
            let snid = format!("secret:{secret_name}");
            if !g.nodes.contains_key(&snid) {
                g.add_node(GraphNode {
                    id: snid.clone(),
                    kind: NodeKind::K8sSecret,
                    label: secret_name.clone(),
                    file: file.to_string(),
                    provider: "kubernetes".to_string(),
                    sensitive: true,
                    internet_facing: false,
                    live_status: LiveStatus::NotChecked,
                    live_evidence: None,
                    iac_address: Some(format!("{ns}/Secret/{secret_name}")),
                    cloud_arn: None,
                });
            }
            g.add_edge(pod_id, &snid, EdgeKind::K8sRoutesTo, "volumeMount secret");
        }
    }
}

fn rule_open(b: &HclBlock) -> bool {
    for key in ["cidr_blocks", "ipv6_cidr_blocks", "cidr_block", "ipv6_cidr_block"] {
        if let Some(v) = b.attr(key) {
            for c in ref_list(v) {
                let c = c.trim_matches('"');
                if c == "0.0.0.0/0" || c == "::/0" {
                    return true;
                }
            }
        }
    }
    false
}

fn block_has_open_cidr(content: &str, addr: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("0.0.0.0/0") && lc.contains(&addr.to_ascii_lowercase())
}

fn ref_list(v: &HclValue) -> Vec<String> {
    match v {
        HclValue::List(items) => items.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        HclValue::Str(s) | HclValue::Raw(s) => vec![s.clone()],
        _ => vec![],
    }
}

fn policy_document_wildcard(b: &HclBlock) -> bool {
    if let Some(HclValue::Str(doc) | HclValue::Raw(doc)) = b.attr("policy") {
        let lc = doc.to_ascii_lowercase();
        return lc.contains("\"action\"") && lc.contains('*') && lc.contains("\"resource\"") && lc.contains('*');
    }
    false
}
