//! AWS live reconciliation — real API calls when `live-aws` feature enabled.

use super::graph_model::{InfraGraph, LiveReconcileMatch, LiveStatus, NodeKind};

pub struct AwsReconcileConfig {
    pub role_arn: String,
    pub external_id: String,
    pub regions: Vec<String>,
}

#[cfg(feature = "live-aws")]
mod imp {
    use super::*;
    use crate::cloud_integration_engine::{assume_role_sdk_config, CrossAccountAwsConfig};
    use crate::iac_misconfig_engine::live_blast::graph_model::NodeKind;
    use aws_config::Region;
    use serde_json::json;

    pub async fn reconcile_graph(
        graph: &mut InfraGraph,
        cfg: &AwsReconcileConfig,
    ) -> (Vec<LiveReconcileMatch>, Vec<String>) {
        let mut matches = Vec::new();
        let mut notes = Vec::new();

        if cfg.role_arn.trim().is_empty() {
            notes.push("live AWS reconcile skipped: no aws_cross_account_role_arn".to_string());
            skip_nodes(graph);
            return (matches, notes);
        }

        let cross = CrossAccountAwsConfig {
            role_arn: cfg.role_arn.clone(),
            external_id: cfg.external_id.clone(),
            session_name: String::new(),
        };

        let Ok((sdk, home_region)) = assume_role_sdk_config(&cross).await else {
            notes.push("live AWS reconcile failed: STS AssumeRole".to_string());
            return (matches, notes);
        };

        notes.push(format!("live AWS reconcile: assumed role {}", cfg.role_arn));
        let regions: Vec<String> = if cfg.regions.is_empty() {
            vec![home_region.to_string()]
        } else {
            cfg.regions.clone()
        };

        for (nid, bucket) in graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::S3Bucket)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect::<Vec<_>>()
        {
            if let Some(m) = check_s3_live(&sdk, &home_region, &nid, &bucket).await {
                apply_match(graph, &m);
                matches.push(m);
            }
        }

        for region in &regions {
            for (nid, label) in graph
                .nodes
                .values()
                .filter(|n| n.kind == NodeKind::SecurityGroup && n.provider == "aws")
                .map(|n| (n.id.clone(), n.label.clone()))
                .collect::<Vec<_>>()
            {
                if let Some(m) = check_sg_live(&sdk, region, &nid, &label).await {
                    apply_match(graph, &m);
                    matches.push(m);
                }
            }
            for (nid, id) in graph
                .nodes
                .values()
                .filter(|n| n.kind == NodeKind::RdsInstance)
                .map(|n| (n.id.clone(), n.label.clone()))
                .collect::<Vec<_>>()
            {
                if let Some(m) = check_rds_live(&sdk, region, &nid, &id).await {
                    apply_match(graph, &m);
                    matches.push(m);
                }
            }
            for (nid, label) in graph
                .nodes
                .values()
                .filter(|n| n.kind == NodeKind::Ec2Instance)
                .map(|n| (n.id.clone(), n.label.clone()))
                .collect::<Vec<_>>()
            {
                if let Some(m) = check_ec2_live(&sdk, region, &nid, &label).await {
                    apply_match(graph, &m);
                    matches.push(m);
                }
            }
            for (nid, label) in graph
                .nodes
                .values()
                .filter(|n| n.kind == NodeKind::LoadBalancer)
                .map(|n| (n.id.clone(), n.label.clone()))
                .collect::<Vec<_>>()
            {
                if let Some(m) = check_elb_live(&sdk, region, &nid, &label).await {
                    apply_match(graph, &m);
                    matches.push(m);
                }
            }
        }

        for (nid, name) in graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::SecretsManagerSecret)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect::<Vec<_>>()
        {
            if let Some(m) = check_sm_live(&sdk, &home_region, &nid, &name).await {
                apply_match(graph, &m);
                matches.push(m);
            }
        }
        for (nid, name) in graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::KmsKey)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect::<Vec<_>>()
        {
            if let Some(m) = check_kms_live(&sdk, &home_region, &nid, &name).await {
                apply_match(graph, &m);
                matches.push(m);
            }
        }
        for (nid, name, arn) in graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::IamRole)
            .map(|n| (n.id.clone(), n.label.clone(), n.cloud_arn.clone()))
            .collect::<Vec<_>>()
        {
            if let Some(m) = check_iam_role_live(&sdk, &nid, &name, arn.as_deref()).await {
                apply_match(graph, &m);
                matches.push(m);
            }
        }

        notes.push(format!(
            "live AWS reconcile: {} API matches, {} confirmed live",
            matches.len(),
            matches
                .iter()
                .filter(|m| m.live_status == LiveStatus::ConfirmedLive)
                .count()
        ));
        (matches, notes)
    }

    fn skip_nodes(graph: &mut InfraGraph) {
        for node in graph.nodes.values_mut() {
            if node.kind != NodeKind::Internet {
                node.live_status = LiveStatus::Skipped;
            }
        }
    }

    fn apply_match(graph: &mut InfraGraph, m: &LiveReconcileMatch) {
        if let Some(node) = graph.nodes.get_mut(&m.node_id) {
            node.live_status = m.live_status;
            node.live_evidence = Some(m.evidence.clone());
        }
    }

    async fn check_s3_live(
        sdk: &aws_types::SdkConfig,
        home_region: &Region,
        node_id: &str,
        bucket: &str,
    ) -> Option<LiveReconcileMatch> {
        let client = aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::from(sdk)
                .region(home_region.clone())
                .build(),
        );
        let list = client.list_buckets().send().await.ok()?;
        let exists = list.buckets().iter().any(|b| b.name() == Some(bucket));
        if !exists {
            return Some(LiveReconcileMatch {
                node_id: node_id.to_string(),
                iac_address: bucket.to_string(),
                live_status: LiveStatus::NotDeployed,
                evidence: "ListBuckets: bucket not found".to_string(),
                api_called: "s3:ListBuckets".to_string(),
            });
        }
        let mut public_reason: Option<String> = None;
        if let Ok(resp) = client.get_public_access_block().bucket(bucket).send().await {
            if let Some(pab) = resp.public_access_block_configuration() {
                if pab.block_public_acls() == Some(false)
                    || pab.ignore_public_acls() == Some(false)
                    || pab.block_public_policy() == Some(false)
                    || pab.restrict_public_buckets() == Some(false)
                {
                    public_reason = Some("GetPublicAccessBlock: weak PAB".to_string());
                }
            }
        }
        if public_reason.is_none() {
            if let Ok(acl) = client.get_bucket_acl().bucket(bucket).send().await {
                for g in acl.grants() {
                    let uri = g
                        .grantee()
                        .and_then(|gg| gg.uri())
                        .unwrap_or("")
                        .to_lowercase();
                    if uri.contains("allusers") || uri.contains("authenticatedusers") {
                        public_reason = Some(format!("GetBucketAcl: {uri}"));
                        break;
                    }
                }
            }
        }
        Some(LiveReconcileMatch {
            node_id: node_id.to_string(),
            iac_address: bucket.to_string(),
            live_status: LiveStatus::ConfirmedLive,
            evidence: public_reason.unwrap_or_else(|| "bucket exists in account".to_string()),
            api_called: "s3:ListBuckets,GetPublicAccessBlock,GetBucketAcl".to_string(),
        })
    }

    async fn check_sg_live(
        sdk: &aws_types::SdkConfig,
        region: &str,
        node_id: &str,
        tag_name: &str,
    ) -> Option<LiveReconcileMatch> {
        let ec2 = aws_sdk_ec2::Client::from_conf(
            aws_sdk_ec2::config::Builder::from(sdk)
                .region(Region::new(region.to_string()))
                .build(),
        );
        let resp = ec2.describe_security_groups().send().await.ok()?;
        let mut found_open = false;
        let mut sg_id = String::new();
        for sg in resp.security_groups() {
            let name_match = sg.group_name() == Some(tag_name)
                || sg
                    .tags()
                    .iter()
                    .any(|t| t.key() == Some("Name") && t.value() == Some(tag_name));
            if !name_match {
                continue;
            }
            sg_id = sg.group_id().unwrap_or("").to_string();
            for perm in sg.ip_permissions() {
                for cidr in perm.ip_ranges() {
                    if cidr.cidr_ip() == Some("0.0.0.0/0") {
                        found_open = true;
                    }
                }
            }
            break;
        }
        if sg_id.is_empty() {
            return Some(LiveReconcileMatch {
                node_id: node_id.to_string(),
                iac_address: tag_name.to_string(),
                live_status: LiveStatus::NotDeployed,
                evidence: "DescribeSecurityGroups: not found".to_string(),
                api_called: "ec2:DescribeSecurityGroups".to_string(),
            });
        }
        Some(LiveReconcileMatch {
            node_id: node_id.to_string(),
            iac_address: sg_id,
            live_status: LiveStatus::ConfirmedLive,
            evidence: if found_open {
                "DescribeSecurityGroups: 0.0.0.0/0 ingress live".to_string()
            } else {
                "DescribeSecurityGroups: SG exists".to_string()
            },
            api_called: "ec2:DescribeSecurityGroups".to_string(),
        })
    }

    async fn check_rds_live(
        sdk: &aws_types::SdkConfig,
        region: &str,
        node_id: &str,
        identifier: &str,
    ) -> Option<LiveReconcileMatch> {
        let rds = aws_sdk_rds::Client::from_conf(
            aws_sdk_rds::config::Builder::from(sdk)
                .region(Region::new(region.to_string()))
                .build(),
        );
        match rds
            .describe_db_instances()
            .db_instance_identifier(identifier)
            .send()
            .await
        {
            Ok(out) => {
                let inst = out.db_instances().first()?;
                Some(LiveReconcileMatch {
                    node_id: node_id.to_string(),
                    iac_address: identifier.to_string(),
                    live_status: LiveStatus::ConfirmedLive,
                    evidence: format!(
                        "DescribeDBInstances: publicly_accessible={}",
                        inst.publicly_accessible().unwrap_or(false)
                    ),
                    api_called: "rds:DescribeDBInstances".to_string(),
                })
            }
            Err(_) => Some(LiveReconcileMatch {
                node_id: node_id.to_string(),
                iac_address: identifier.to_string(),
                live_status: LiveStatus::NotDeployed,
                evidence: "DescribeDBInstances: not found".to_string(),
                api_called: "rds:DescribeDBInstances".to_string(),
            }),
        }
    }

    async fn check_ec2_live(
        sdk: &aws_types::SdkConfig,
        region: &str,
        node_id: &str,
        label: &str,
    ) -> Option<LiveReconcileMatch> {
        let ec2 = aws_sdk_ec2::Client::from_conf(
            aws_sdk_ec2::config::Builder::from(sdk)
                .region(Region::new(region.to_string()))
                .build(),
        );
        let resp = ec2.describe_instances().send().await.ok()?;
        let found = resp.reservations().iter().any(|res| {
            res.instances().iter().any(|inst| {
                inst.tags()
                    .iter()
                    .any(|t| t.key() == Some("Name") && t.value() == Some(label))
            })
        });
        Some(LiveReconcileMatch {
            node_id: node_id.to_string(),
            iac_address: label.to_string(),
            live_status: if found {
                LiveStatus::ConfirmedLive
            } else {
                LiveStatus::NotDeployed
            },
            evidence: if found {
                "DescribeInstances: found".to_string()
            } else {
                "DescribeInstances: not found".to_string()
            },
            api_called: "ec2:DescribeInstances".to_string(),
        })
    }

    async fn check_elb_live(
        sdk: &aws_types::SdkConfig,
        region: &str,
        node_id: &str,
        label: &str,
    ) -> Option<LiveReconcileMatch> {
        let elb = aws_sdk_elasticloadbalancingv2::Client::from_conf(
            aws_sdk_elasticloadbalancingv2::config::Builder::from(sdk)
                .region(Region::new(region.to_string()))
                .build(),
        );
        let resp = elb.describe_load_balancers().send().await.ok()?;
        let found = resp
            .load_balancers()
            .iter()
            .any(|lb| lb.load_balancer_name() == Some(label));
        Some(LiveReconcileMatch {
            node_id: node_id.to_string(),
            iac_address: label.to_string(),
            live_status: if found {
                LiveStatus::ConfirmedLive
            } else {
                LiveStatus::NotDeployed
            },
            evidence: if found {
                "elbv2:DescribeLoadBalancers: found".to_string()
            } else {
                "elbv2:DescribeLoadBalancers: not found".to_string()
            },
            api_called: "elasticloadbalancing:DescribeLoadBalancers".to_string(),
        })
    }

    async fn check_sm_live(
        sdk: &aws_types::SdkConfig,
        region: &Region,
        node_id: &str,
        name: &str,
    ) -> Option<LiveReconcileMatch> {
        let sm = aws_sdk_secretsmanager::Client::from_conf(
            aws_sdk_secretsmanager::config::Builder::from(sdk)
                .region(region.clone())
                .build(),
        );
        match sm.describe_secret().secret_id(name).send().await {
            Ok(_) => Some(LiveReconcileMatch {
                node_id: node_id.to_string(),
                iac_address: name.to_string(),
                live_status: LiveStatus::ConfirmedLive,
                evidence: "secretsmanager:DescribeSecret: exists".to_string(),
                api_called: "secretsmanager:DescribeSecret".to_string(),
            }),
            Err(_) => Some(LiveReconcileMatch {
                node_id: node_id.to_string(),
                iac_address: name.to_string(),
                live_status: LiveStatus::NotDeployed,
                evidence: "secretsmanager:DescribeSecret: not found".to_string(),
                api_called: "secretsmanager:DescribeSecret".to_string(),
            }),
        }
    }

    async fn check_kms_live(
        sdk: &aws_types::SdkConfig,
        region: &Region,
        node_id: &str,
        name: &str,
    ) -> Option<LiveReconcileMatch> {
        let kms = aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::config::Builder::from(sdk)
                .region(region.clone())
                .build(),
        );
        match kms.describe_key().key_id(name).send().await {
            Ok(_) => Some(LiveReconcileMatch {
                node_id: node_id.to_string(),
                iac_address: name.to_string(),
                live_status: LiveStatus::ConfirmedLive,
                evidence: "kms:DescribeKey: exists".to_string(),
                api_called: "kms:DescribeKey".to_string(),
            }),
            Err(_) => Some(LiveReconcileMatch {
                node_id: node_id.to_string(),
                iac_address: name.to_string(),
                live_status: LiveStatus::NotDeployed,
                evidence: "kms:DescribeKey: not found".to_string(),
                api_called: "kms:DescribeKey".to_string(),
            }),
        }
    }

    async fn check_iam_role_live(
        sdk: &aws_types::SdkConfig,
        node_id: &str,
        label: &str,
        arn: Option<&str>,
    ) -> Option<LiveReconcileMatch> {
        let iam = aws_sdk_iam::Client::new(sdk);
        let role_name = arn.and_then(|a| a.split('/').next_back()).unwrap_or(label);
        match iam.get_role().role_name(role_name).send().await {
            Ok(out) => {
                let role_arn = out.role().map(|r| r.arn().to_string()).unwrap_or_default();
                Some(LiveReconcileMatch {
                    node_id: node_id.to_string(),
                    iac_address: role_arn,
                    live_status: LiveStatus::ConfirmedLive,
                    evidence: format!("iam:GetRole: {role_name} exists"),
                    api_called: "iam:GetRole".to_string(),
                })
            }
            Err(_) => Some(LiveReconcileMatch {
                node_id: node_id.to_string(),
                iac_address: label.to_string(),
                live_status: LiveStatus::NotDeployed,
                evidence: "iam:GetRole: not found".to_string(),
                api_called: "iam:GetRole".to_string(),
            }),
        }
    }

    pub fn matches_json(matches: &[LiveReconcileMatch]) -> serde_json::Value {
        serde_json::Value::Array(
            matches
                .iter()
                .map(|m| {
                    json!({
                        "node_id": m.node_id,
                        "iac_address": m.iac_address,
                        "live_status": m.live_status.as_str(),
                        "evidence": m.evidence,
                        "api_called": m.api_called,
                    })
                })
                .collect(),
        )
    }
}

#[cfg(not(feature = "live-aws"))]
mod imp {
    use super::*;

    pub async fn reconcile_graph(
        graph: &mut InfraGraph,
        cfg: &AwsReconcileConfig,
    ) -> (Vec<LiveReconcileMatch>, Vec<String>) {
        let mut notes = vec!["live AWS API stub (build without live-aws feature)".to_string()];
        if !cfg.role_arn.is_empty() {
            notes.push(
                "graph-only mode: compile with --features live-aws for real API calls".to_string(),
            );
        }
        for node in graph.nodes.values_mut() {
            if node.kind != NodeKind::Internet {
                node.live_status = LiveStatus::Skipped;
            }
        }
        (Vec::new(), notes)
    }

    pub fn matches_json(matches: &[LiveReconcileMatch]) -> serde_json::Value {
        serde_json::Value::Array(
            matches
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "node_id": m.node_id,
                        "iac_address": m.iac_address,
                        "live_status": m.live_status.as_str(),
                        "evidence": m.evidence,
                        "api_called": m.api_called,
                    })
                })
                .collect(),
        )
    }
}

pub use imp::{matches_json, reconcile_graph};
