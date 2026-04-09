//! Phase 5: Autonomous incident containment — replace EC2 instance security groups with a forensic-only SG;
//! apply a deny-by-default Kubernetes `NetworkPolicy` via the API (Bearer token).

use crate::cloud_integration_engine::{assume_role_sdk_config, CrossAccountAwsConfig};
use aws_config::Region;
use aws_sdk_ec2::types::{IpPermission, IpRange};
use aws_types::SdkConfig;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

fn parse_ports_csv(csv: &str) -> Vec<i32> {
    csv.split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|s| s.trim().parse::<i32>().ok())
        .filter(|&p| p > 0 && p <= 65535)
        .collect()
}

/// Create a quarantine security group, lock ingress/egress to forensic CIDR + ports, attach to `instance_id`.
pub async fn quarantine_ec2_instance(
    sdk: &SdkConfig,
    region: &Region,
    instance_id: &str,
    forensic_cidr: &str,
    ports_csv: &str,
    allow_dns_egress: bool,
    vpc_dns_cidr: &str,
) -> Result<String, String> {
    let ports = parse_ports_csv(ports_csv);
    if ports.is_empty() {
        return Err("no valid forensic ports in forensic_ports_csv".into());
    }
    let cidr = forensic_cidr.trim();
    if cidr.is_empty() {
        return Err("forensic_source_cidr required".into());
    }

    let ec2_conf = aws_sdk_ec2::config::Builder::from(sdk)
        .region(region.clone())
        .build();
    let ec2 = aws_sdk_ec2::Client::from_conf(ec2_conf);

    let di = ec2
        .describe_instances()
        .instance_ids(instance_id)
        .send()
        .await
        .map_err(|e| format!("DescribeInstances: {}", e))?;
    let vpc_id = di
        .reservations()
        .first()
        .and_then(|r| r.instances().first())
        .and_then(|i| i.vpc_id())
        .ok_or_else(|| "instance or vpc not found".to_string())?
        .to_string();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let sg_name = format!("weissman-quarantine-{}", ts);
    let sg_desc =
        "Weissman auto-containment — forensic access only; replace via console when cleared.";

    let csg = ec2
        .create_security_group()
        .group_name(&sg_name)
        .description(sg_desc)
        .vpc_id(&vpc_id)
        .send()
        .await
        .map_err(|e| format!("CreateSecurityGroup: {}", e))?;
    let sg_id = csg
        .group_id()
        .ok_or_else(|| "CreateSecurityGroup missing group id".to_string())?
        .to_string();

    for &p in &ports {
        let ing = IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(p)
            .to_port(p)
            .ip_ranges(
                IpRange::builder()
                    .cidr_ip(cidr)
                    .description("Weissman forensic ingress")
                    .build(),
            )
            .build();
        ec2.authorize_security_group_ingress()
            .group_id(&sg_id)
            .ip_permissions(ing)
            .send()
            .await
            .map_err(|e| format!("AuthorizeSecurityGroupIngress: {}", e))?;
    }

    let open_world = IpPermission::builder()
        .ip_protocol("-1")
        .ip_ranges(
            IpRange::builder()
                .cidr_ip("0.0.0.0/0")
                .description("default all egress to revoke")
                .build(),
        )
        .build();
    let _ = ec2
        .revoke_security_group_egress()
        .group_id(&sg_id)
        .ip_permissions(open_world)
        .send()
        .await;

    for &p in &ports {
        let egr = IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(p)
            .to_port(p)
            .ip_ranges(
                IpRange::builder()
                    .cidr_ip(cidr)
                    .description("Weissman forensic egress")
                    .build(),
            )
            .build();
        ec2.authorize_security_group_egress()
            .group_id(&sg_id)
            .ip_permissions(egr)
            .send()
            .await
            .map_err(|e| format!("AuthorizeSecurityGroupEgress: {}", e))?;
    }

    if allow_dns_egress {
        let dns = vpc_dns_cidr.trim();
        if !dns.is_empty() {
            let udp53 = IpPermission::builder()
                .ip_protocol("udp")
                .from_port(53)
                .to_port(53)
                .ip_ranges(
                    IpRange::builder()
                        .cidr_ip(dns)
                        .description("VPC DNS resolver")
                        .build(),
                )
                .build();
            let _ = ec2
                .authorize_security_group_egress()
                .group_id(&sg_id)
                .ip_permissions(udp53)
                .send()
                .await;
        }
    }

    ec2.modify_instance_attribute()
        .instance_id(instance_id)
        .set_groups(Some(vec![sg_id.clone()]))
        .send()
        .await
        .map_err(|e| format!("ModifyInstanceAttribute groups: {}", e))?;

    Ok(format!(
        "instance {} attached to quarantine SG {} in {}",
        instance_id, sg_id, region
    ))
}

/// Apply a default-deny NetworkPolicy with narrow forensic ingress/egress (Kubernetes API).
pub async fn apply_k8s_quarantine_network_policy(
    api_server: &str,
    bearer_token: &str,
    namespace: &str,
    policy_name: &str,
    label_key: &str,
    label_value: &str,
    forensic_cidr: &str,
    ports: &[i32],
    insecure_tls: bool,
) -> Result<String, String> {
    let base = api_server.trim_end_matches('/');
    if base.is_empty() || bearer_token.trim().is_empty() {
        return Err("k8s_api_server and bearer token required".into());
    }
    if label_key.is_empty() || label_value.is_empty() {
        return Err("pod label selector required".into());
    }
    let mut ing_ports = Vec::new();
    let mut egr_ports = Vec::new();
    for &p in ports {
        ing_ports.push(json!({ "protocol": "TCP", "port": p }));
        egr_ports.push(json!({ "protocol": "TCP", "port": p }));
    }
    let body = json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": { "name": policy_name, "namespace": namespace, "labels": { "app.kubernetes.io/managed-by": "weissman" } },
        "spec": {
            "podSelector": { "matchLabels": { label_key: label_value } },
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{
                "from": [{ "ipBlock": { "cidr": forensic_cidr } }],
                "ports": ing_ports
            }],
            "egress": [{
                "to": [{ "ipBlock": { "cidr": forensic_cidr } }],
                "ports": egr_ports
            }]
        }
    });

    let url = format!(
        "{}/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies",
        base, namespace
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .danger_accept_invalid_certs(
            insecure_tls || weissman_core::tls_policy::danger_accept_invalid_certs(),
        )
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", bearer_token.trim()))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("K8s API: {}", e))?;
    let st = resp.status();
    if !st.is_success() {
        let t = resp.text().await.unwrap_or_default();
        return Err(format!(
            "K8s NetworkPolicy {}: {}",
            st,
            t.chars().take(800).collect::<String>()
        ));
    }
    Ok(format!(
        "NetworkPolicy {}/{} applied",
        namespace, policy_name
    ))
}

/// Assume tenant role and run EC2 quarantine using rule row fields.
pub async fn execute_aws_containment(
    aws_cfg: &CrossAccountAwsConfig,
    region_str: &str,
    instance_id: &str,
    forensic_cidr: &str,
    ports_csv: &str,
    allow_dns: bool,
    vpc_dns_cidr: &str,
) -> Result<String, String> {
    let (sdk, home) = assume_role_sdk_config(aws_cfg)
        .await
        .map_err(|e| e.to_string())?;
    let region = if region_str.trim().is_empty() {
        home
    } else {
        Region::new(region_str.trim().to_string())
    };
    quarantine_ec2_instance(
        &sdk,
        &region,
        instance_id,
        forensic_cidr,
        ports_csv,
        allow_dns,
        vpc_dns_cidr,
    )
    .await
}
