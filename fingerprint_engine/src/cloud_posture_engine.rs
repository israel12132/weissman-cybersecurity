//! Agentless AWS Cloud Security Posture Management (CSPM / CNAPP) engine.
//!
//! Wiz-style model: assume a customer-supplied, read-only cross-account IAM role, inventory the
//! account's resources via native AWS APIs (no agents on customer workloads), evaluate a comprehensive
//! rule catalog, build a Security Graph, and surface "toxic combination" attack paths (e.g.
//! internet-exposed compute that carries an over-privileged identity). Every finding is mapped to
//! compliance controls (CIS AWS Foundations, SOC 2, ISO 27001, PCI DSS, NIST CSF, GDPR) and carries
//! a numeric risk score and concrete remediation.
//!
//! All detection is real: live AWS API reads via STS AssumeRole. When no role is configured the scan
//! returns a clear error rather than fabricated findings.
#![allow(clippy::pedantic, clippy::nursery, clippy::too_many_lines)]

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::cloud_integration_engine::{assume_role_sdk_config, CrossAccountAwsConfig};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_result::{print_result, EngineResult};
use aws_config::Region;
use aws_types::SdkConfig;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const ENGINE_ID: &str = "cloud_posture";

/// Live AWS API planes in the agentless CNAPP catalog (complete round).
pub const CNAPP_SERVICE_PLANES: &[&str] = &[
    "iam", "s3", "account", "ec2", "vpc", "elb", "eks", "ecs", "lambda", "rds", "elasticache",
    "kms", "secrets", "messaging", "ssm", "cloudtrail", "config", "guardduty", "accessanalyzer",
    "ecr", "acm", "dynamodb", "apigateway", "opensearch", "cloudfront", "route53", "eventbridge",
    "wafv2", "logs", "redshift", "documentdb", "neptune", "memorydb", "backup", "organizations",
    "sfn", "sso",
];
pub const CNAPP_PLANE_COUNT: usize = 37;

/// Default regions scanned for regional services when the caller does not pin a set.
pub const DEFAULT_SCAN_REGIONS: &[&str] = &[
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
];

const DANGEROUS_PORTS: &[i32] = &[
    22, 23, 25, 135, 139, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5433, 5984, 6379, 8020, 9000,
    9042, 9200, 9300, 11211, 27017, 27018,
];

/// Severity ordering helper (higher = worse).
pub fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn sev_weight(sev: &str) -> f64 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 22.0,
        "high" => 12.0,
        "medium" => 5.0,
        "low" => 1.5,
        _ => 0.0,
    }
}

/// Per-scan options, parsed from the job parameters forwarded by the run handler.
#[derive(Clone, Debug)]
pub struct CloudScanOptions {
    pub role_arn: String,
    pub external_id: String,
    pub session_name: String,
    pub regions: Vec<String>,
    pub services: BTreeSet<String>,
    pub min_severity: String,
    pub frameworks: Vec<String>,
    pub include_attack_paths: bool,
    pub include_security_graph: bool,
    pub max_resources_per_service: usize,
    pub access_key_max_age_days: u64,
    pub check_root_account: bool,
    pub check_password_policy: bool,
    pub check_imds: bool,
    pub check_flow_logs: bool,
    pub check_ssm_public_params: bool,
    pub check_cloudtrail: bool,
    pub check_rds: bool,
    pub check_lambda: bool,
    pub check_public_snapshots: bool,
    pub check_s3_policy_public: bool,
    pub check_iam_wildcards: bool,
    pub check_access_analyzer: bool,
    pub check_guardduty: bool,
    pub check_config_recorder: bool,
    pub check_eks: bool,
    pub check_elb: bool,
    pub check_secrets_manager: bool,
    pub check_messaging: bool,
    pub check_account_s3_block: bool,
    pub check_ecs: bool,
    pub check_elasticache: bool,
    pub check_lambda_urls: bool,
    pub check_ecr: bool,
    pub check_acm: bool,
    pub check_default_sg: bool,
    pub check_graph_paths: bool,
    pub check_s3_versioning: bool,
    pub check_dynamodb: bool,
    pub check_apigateway: bool,
    pub check_opensearch: bool,
    pub check_cloudfront: bool,
    pub check_route53: bool,
    pub check_eventbridge: bool,
    pub check_wafv2: bool,
    pub check_cloudwatch_logs: bool,
    pub check_redshift: bool,
    pub check_documentdb: bool,
    pub check_s3_object_lock: bool,
    pub check_neptune: bool,
    pub check_memorydb: bool,
    pub check_backup: bool,
    pub check_organizations: bool,
    pub check_sfn: bool,
    pub check_sso: bool,
    pub acm_expiry_days: u64,
    pub intensity: Intensity,
}

impl Default for CloudScanOptions {
    fn default() -> Self {
        Self {
            role_arn: String::new(),
            external_id: String::new(),
            session_name: String::new(),
            regions: Vec::new(),
            services: BTreeSet::new(),
            min_severity: "info".to_string(),
            frameworks: vec![
                "CIS".into(),
                "SOC2".into(),
                "ISO27001".into(),
                "PCI".into(),
                "NIST".into(),
                "GDPR".into(),
            ],
            include_attack_paths: true,
            include_security_graph: true,
            max_resources_per_service: 300,
            access_key_max_age_days: 90,
            check_root_account: true,
            check_password_policy: true,
            check_imds: true,
            check_flow_logs: true,
            check_ssm_public_params: true,
            check_cloudtrail: true,
            check_rds: true,
            check_lambda: true,
            check_public_snapshots: true,
            check_s3_policy_public: true,
            check_iam_wildcards: true,
            check_access_analyzer: true,
            check_guardduty: true,
            check_config_recorder: true,
            check_eks: true,
            check_elb: true,
            check_secrets_manager: true,
            check_messaging: true,
            check_account_s3_block: true,
            check_ecs: true,
            check_elasticache: true,
            check_lambda_urls: true,
            check_ecr: true,
            check_acm: true,
            check_default_sg: true,
            check_graph_paths: true,
            check_s3_versioning: true,
            check_dynamodb: true,
            check_apigateway: true,
            check_opensearch: true,
            check_cloudfront: true,
            check_route53: true,
            check_eventbridge: true,
            check_wafv2: true,
            check_cloudwatch_logs: true,
            check_redshift: true,
            check_documentdb: true,
            check_s3_object_lock: true,
            check_neptune: true,
            check_memorydb: true,
            check_backup: true,
            check_organizations: true,
            check_sfn: true,
            check_sso: true,
            acm_expiry_days: 30,
            intensity: Intensity::Normal,
        }
    }
}

impl CloudScanOptions {
    pub fn from_ctx(ctx: &EngineRunContext) -> Self {
        Self::from_arsenal(&ArsenalConfig::from_ctx(ctx))
    }

    pub fn from_arsenal(c: &ArsenalConfig) -> Self {
        let mut o = Self::default();
        o.role_arn = c
            .string("aws_cross_account_role_arn")
            .or_else(|| c.string("aws_role_arn"))
            .unwrap_or_default();
        o.external_id = c.string_or("aws_external_id", "");
        o.session_name = c.string_or("aws_role_session_name", "");
        o.regions = c.string_list("regions");
        if o.regions.is_empty() {
            o.regions = c.string_list("aws_regions");
        }
        let svc = c.string_list("services");
        if !svc.is_empty() {
            o.services = svc.into_iter().map(|s| s.to_ascii_lowercase()).collect();
        }
        o.min_severity = c.string_or("min_severity", "info");
        let fw = c.string_list("frameworks");
        if !fw.is_empty() {
            o.frameworks = fw;
        }
        o.include_attack_paths = c.bool_or("include_attack_paths", true);
        o.include_security_graph = c.bool_or("include_security_graph", true);
        o.max_resources_per_service = c.usize_or("max_resources_per_service", 300).clamp(10, 5000);
        o.access_key_max_age_days = c.u64_or("access_key_max_age_days", 90).clamp(1, 3650);
        o.check_root_account = c.bool_or("check_root_account", true);
        o.check_password_policy = c.bool_or("check_password_policy", true);
        o.check_imds = c.bool_or("check_imds", true);
        o.check_flow_logs = c.bool_or("check_flow_logs", true);
        o.check_ssm_public_params = c.bool_or("check_ssm_public_params", true);
        o.check_cloudtrail = c.bool_or("check_cloudtrail", true);
        o.check_rds = c.bool_or("check_rds", true);
        o.check_lambda = c.bool_or("check_lambda", true);
        o.check_public_snapshots = c.bool_or("check_public_snapshots", true);
        o.check_s3_policy_public = c.bool_or("check_s3_policy_public", true);
        o.check_iam_wildcards = c.bool_or("check_iam_wildcards", true);
        o.check_access_analyzer = c.bool_or("check_access_analyzer", true);
        o.check_guardduty = c.bool_or("check_guardduty", true);
        o.check_config_recorder = c.bool_or("check_config_recorder", true);
        o.check_eks = c.bool_or("check_eks", true);
        o.check_elb = c.bool_or("check_elb", true);
        o.check_secrets_manager = c.bool_or("check_secrets_manager", true);
        o.check_messaging = c.bool_or("check_messaging", true);
        o.check_account_s3_block = c.bool_or("check_account_s3_block", true);
        o.check_ecs = c.bool_or("check_ecs", true);
        o.check_elasticache = c.bool_or("check_elasticache", true);
        o.check_lambda_urls = c.bool_or("check_lambda_urls", true);
        o.check_ecr = c.bool_or("check_ecr", true);
        o.check_acm = c.bool_or("check_acm", true);
        o.check_default_sg = c.bool_or("check_default_sg", true);
        o.check_graph_paths = c.bool_or("check_graph_paths", true);
        o.check_s3_versioning = c.bool_or("check_s3_versioning", true);
        o.check_dynamodb = c.bool_or("check_dynamodb", true);
        o.check_apigateway = c.bool_or("check_apigateway", true);
        o.check_opensearch = c.bool_or("check_opensearch", true);
        o.check_cloudfront = c.bool_or("check_cloudfront", true);
        o.check_route53 = c.bool_or("check_route53", true);
        o.check_eventbridge = c.bool_or("check_eventbridge", true);
        o.check_wafv2 = c.bool_or("check_wafv2", true);
        o.check_cloudwatch_logs = c.bool_or("check_cloudwatch_logs", true);
        o.check_redshift = c.bool_or("check_redshift", true);
        o.check_documentdb = c.bool_or("check_documentdb", true);
        o.check_s3_object_lock = c.bool_or("check_s3_object_lock", true);
        o.check_neptune = c.bool_or("check_neptune", true);
        o.check_memorydb = c.bool_or("check_memorydb", true);
        o.check_backup = c.bool_or("check_backup", true);
        o.check_organizations = c.bool_or("check_organizations", true);
        o.check_sfn = c.bool_or("check_sfn", true);
        o.check_sso = c.bool_or("check_sso", true);
        o.acm_expiry_days = c.u64_or("acm_expiry_days", 30).clamp(1, 365);
        o.intensity = c.intensity();
        o
    }

    fn wants(&self, service: &str) -> bool {
        self.services.is_empty() || self.services.contains(service)
    }

    fn effective_regions(&self) -> Vec<String> {
        if self.regions.is_empty() {
            DEFAULT_SCAN_REGIONS.iter().map(|s| s.to_string()).collect()
        } else {
            self.regions.clone()
        }
    }

    fn keep_severity(&self, sev: &str) -> bool {
        severity_rank(sev) >= severity_rank(&self.min_severity)
    }

    fn max_users(&self) -> usize {
        match self.intensity {
            Intensity::Light => 30,
            Intensity::Normal => 80,
            Intensity::Aggressive => 250,
        }
    }

    fn max_buckets(&self) -> usize {
        match self.intensity {
            Intensity::Light => 40,
            Intensity::Normal => 120,
            Intensity::Aggressive => self.max_resources_per_service,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Domain {
    Identity,
    Data,
    Network,
    Compute,
    Governance,
}

impl Domain {
    fn as_str(self) -> &'static str {
        match self {
            Domain::Identity => "identity",
            Domain::Data => "data",
            Domain::Network => "network",
            Domain::Compute => "compute",
            Domain::Governance => "governance",
        }
    }
}

#[derive(Clone, Debug)]
struct ComplianceRef {
    cis: &'static str,
    soc2: &'static str,
    iso27001: &'static str,
    pci: &'static str,
    nist: &'static str,
    gdpr: &'static str,
}

#[allow(clippy::too_many_arguments)]
fn posture_finding(
    domain: Domain,
    rule_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    compliance: &ComplianceRef,
    target: &str,
    confidence: f64,
    description: &str,
    remediation: &str,
    evidence: Evidence,
    resource_type: &str,
    resource_id: &str,
    region: &str,
) -> Value {
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        evidence,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("domain".to_string(), json!(domain.as_str()));
        obj.insert("category".to_string(), json!(domain.as_str()));
        obj.insert("rule_id".to_string(), json!(rule_id));
        obj.insert("remediation".to_string(), json!(remediation));
        obj.insert("resource_type".to_string(), json!(resource_type));
        obj.insert("resource_id".to_string(), json!(resource_id));
        obj.insert("region".to_string(), json!(region));
        obj.insert(
            "compliance".to_string(),
            json!({
                "cis_aws": compliance.cis,
                "soc2": compliance.soc2,
                "iso27001": compliance.iso27001,
                "pci_dss": compliance.pci,
                "nist_csf": compliance.nist,
                "gdpr": compliance.gdpr,
            }),
        );
        if !compliance.cis.is_empty() {
            obj.insert("cis_aws".to_string(), json!(compliance.cis));
        }
    }
    f
}

fn map_bucket_location(constraint: Option<&str>) -> String {
    match constraint.unwrap_or("").trim() {
        "" | "US" => "us-east-1".to_string(),
        "EU" => "eu-west-1".to_string(),
        other => other.to_string(),
    }
}

fn port_in_dangerous(from: Option<i32>, to: Option<i32>) -> bool {
    let start = from.unwrap_or(-1);
    let end = to.unwrap_or(start);
    DANGEROUS_PORTS.iter().any(|&p| p >= start && p <= end)
}

// ─── Security Graph (Wiz-style asset + relationship model) ─────────────────────

#[derive(Clone, Debug, Default)]
struct GraphNode {
    id: String,
    kind: String,
    region: String,
    exposure: String,
    risk_tags: Vec<String>,
}

#[derive(Clone, Debug)]
struct GraphEdge {
    from: String,
    to: String,
    rel: String,
}

#[derive(Default)]
struct SecurityGraph {
    nodes: BTreeMap<String, GraphNode>,
    edges: Vec<GraphEdge>,
}

impl SecurityGraph {
    fn upsert(&mut self, id: &str, kind: &str, region: &str, exposure: &str, tags: &[&str]) {
        let node = self.nodes.entry(id.to_string()).or_insert_with(|| GraphNode {
            id: id.to_string(),
            kind: kind.to_string(),
            region: region.to_string(),
            exposure: exposure.to_string(),
            risk_tags: Vec::new(),
        });
        for t in tags {
            if !node.risk_tags.iter().any(|x| x == t) {
                node.risk_tags.push((*t).to_string());
            }
        }
        if exposure == "internet" {
            node.exposure = "internet".to_string();
        }
    }

    fn link(&mut self, from: &str, to: &str, rel: &str) {
        self.edges.push(GraphEdge {
            from: from.to_string(),
            to: to.to_string(),
            rel: rel.to_string(),
        });
    }

    fn is_privileged_identity(node: &GraphNode) -> bool {
        node.kind.contains("iam")
            && node.risk_tags.iter().any(|t| {
                t.contains("admin")
                    || t.contains("wildcard")
                    || t.contains("privileged")
                    || t == "administrator_access"
                    || t == "permissive_trust"
            })
    }

    fn identity_edge_targets(&self, from: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|e| {
                e.from == from
                    && (e.rel == "assumes_role"
                        || e.rel == "execution_role"
                        || e.rel == "assumes")
            })
            .map(|e| e.to.as_str())
            .collect()
    }

    /// Follow identity edges from an internet-exposed asset to over-privileged IAM targets (1–2 hops).
    fn privileged_identity_peers(&self, from: &str) -> Vec<&GraphNode> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();

        for hop1 in self.identity_edge_targets(from) {
            if let Some(n) = self.nodes.get(hop1) {
                if Self::is_privileged_identity(n) && seen.insert(hop1.to_string()) {
                    out.push(n);
                }
            }
            for hop2 in self.identity_edge_targets(hop1) {
                if let Some(n) = self.nodes.get(hop2) {
                    if Self::is_privileged_identity(n) && seen.insert(hop2.to_string()) {
                        out.push(n);
                    }
                }
            }
        }
        out
    }

    fn internet_exposed_nodes(&self) -> Vec<&GraphNode> {
        self.nodes
            .values()
            .filter(|n| n.exposure == "internet")
            .collect()
    }

    fn to_json(&self) -> Value {
        json!({
            "node_count": self.nodes.len(),
            "edge_count": self.edges.len(),
            "nodes": self.nodes.values().map(|n| json!({
                "id": n.id,
                "kind": n.kind,
                "region": n.region,
                "exposure": n.exposure,
                "risk_tags": n.risk_tags,
            })).collect::<Vec<_>>(),
            "edges": self.edges.iter().map(|e| json!({
                "from": e.from,
                "to": e.to,
                "relationship": e.rel,
            })).collect::<Vec<_>>(),
        })
    }
}

// ─── IAM / CIEM ────────────────────────────────────────────────────────────────

async fn scan_iam(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    use aws_sdk_iam::types::{StatusType, SummaryKeyType};
    let iam = aws_sdk_iam::Client::new(sdk);
    let mut findings = Vec::new();
    let c_root = ComplianceRef {
        cis: "1.4",
        soc2: "CC6.1",
        iso27001: "A.9.2.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };
    let c_mfa = ComplianceRef {
        cis: "1.5",
        soc2: "CC6.1",
        iso27001: "A.9.4.2",
        pci: "8.3.1",
        nist: "PR.AC-7",
        gdpr: "Art.32",
    };
    let c_pwd = ComplianceRef {
        cis: "1.8",
        soc2: "CC6.1",
        iso27001: "A.9.4.3",
        pci: "8.2.3",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    if opts.check_root_account {
        if let Ok(out) = iam.get_account_summary().send().await {
            if let Some(m) = out.summary_map() {
                let get = |k: &SummaryKeyType| m.get(k).copied().unwrap_or(0);
                if get(&SummaryKeyType::AccountMfaEnabled) == 0 {
                    graph.upsert("aws:account:root", "identity", "global", "privileged", &["no_root_mfa"]);
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_root_no_mfa",
                        "Root account MFA is not enabled",
                        "critical",
                        "T1078.004",
                        &c_mfa,
                        target,
                        0.97,
                        "The AWS account root user has no MFA device. Root has unrestricted access; a stolen root password is full-account compromise.",
                        "Enable hardware/virtual MFA on the root user immediately. Prefer eliminating day-to-day root use entirely.",
                        Evidence::new()
                            .with("account_mfa_enabled", false)
                            .check("get_account_summary.AccountMFAEnabled", true, 0),
                        "aws_account",
                        "root",
                        "global",
                    ));
                }
                let root_keys = get(&SummaryKeyType::AccountAccessKeysPresent);
                if root_keys > 0 {
                    graph.upsert("aws:account:root", "identity", "global", "privileged", &["root_access_keys"]);
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_root_access_keys",
                        "Root account has active access keys",
                        "critical",
                        "T1078.004",
                        &c_root,
                        target,
                        0.97,
                        "Long-lived root access keys exist. Delete root keys entirely; use IAM roles/users for programmatic access.",
                        "Delete all root access keys. Use IAM roles with least privilege for automation.",
                        Evidence::new()
                            .with("root_access_keys_present", true)
                            .check("get_account_summary.AccountAccessKeysPresent", true, root_keys),
                        "aws_account",
                        "root",
                        "global",
                    ));
                }
            }
        }
    }

    if opts.check_password_policy {
        match iam.get_account_password_policy().send().await {
            Ok(out) => {
                if let Some(pp) = out.password_policy() {
                    let min_len = pp.minimum_password_length().unwrap_or(0);
                    if min_len < 14 {
                        findings.push(posture_finding(
                            Domain::Identity,
                            "iam_weak_password_length",
                            "Weak IAM password policy — minimum length",
                            "medium",
                            "T1110",
                            &c_pwd,
                            target,
                            0.9,
                            &format!("IAM password minimum length is {min_len} (CIS AWS Foundations requires ≥ 14)."),
                            "Set minimum_password_length to at least 14 and require all character classes.",
                            Evidence::new().with("minimum_password_length", min_len),
                            "aws_account",
                            "password_policy",
                            "global",
                        ));
                    }
                }
            }
            Err(e) => {
                let code = e.as_service_error().and_then(|se| se.meta().code()).unwrap_or("");
                if code == "NoSuchEntity" {
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_no_password_policy",
                        "No IAM account password policy configured",
                        "medium",
                        "T1110",
                        &c_pwd,
                        target,
                        0.9,
                        "The account has no IAM password policy, so console users can set trivially weak passwords.",
                        "Create an account password policy with length ≥ 14, complexity, and reuse prevention ≥ 24.",
                        Evidence::new().check("get_account_password_policy", false, "NoSuchEntity"),
                        "aws_account",
                        "password_policy",
                        "global",
                    ));
                }
            }
        }
    }

    let c_user_mfa = ComplianceRef {
        cis: "1.10",
        soc2: "CC6.1",
        iso27001: "A.9.4.2",
        pci: "8.3.1",
        nist: "PR.AC-7",
        gdpr: "Art.32",
    };
    let c_admin = ComplianceRef {
        cis: "1.16",
        soc2: "CC6.3",
        iso27001: "A.9.2.3",
        pci: "7.1.2",
        nist: "PR.AC-4",
        gdpr: "Art.32",
    };
    let c_stale_key = ComplianceRef {
        cis: "1.14",
        soc2: "CC6.1",
        iso27001: "A.9.4.3",
        pci: "8.2.4",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    if let Ok(out) = iam.list_users().send().await {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
        .unwrap_or(0);
        let max_age = i64::try_from(opts.access_key_max_age_days).unwrap_or(90);
        for u in out.users().iter().take(opts.max_users()) {
            let name = u.user_name().to_string();
            let node_id = format!("aws:iam:user:{name}");
            graph.upsert(&node_id, "iam_user", "global", "internal", &[]);

            let has_console = iam.get_login_profile().user_name(&name).send().await.is_ok();
            if has_console {
                let mfa_empty = iam
                    .list_mfa_devices()
                    .user_name(&name)
                    .send()
                    .await
                    .map(|r| r.mfa_devices().is_empty())
                    .unwrap_or(false);
                if mfa_empty {
                    graph.upsert(&node_id, "iam_user", "global", "internal", &["console_no_mfa"]);
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_console_user_no_mfa",
                        &format!("IAM console user without MFA: {name}"),
                        "high",
                        "T1078.004",
                        &c_user_mfa,
                        target,
                        0.92,
                        &format!("IAM user '{name}' has console access but no MFA device (CIS 1.10)."),
                        "Enforce MFA for all console users via an IAM policy or AWS Organizations SCP.",
                        Evidence::new()
                            .with("user", name.clone())
                            .check("list_mfa_devices", true, "empty"),
                        "iam_user",
                        &name,
                        "global",
                    ));
                }
            }

            if let Ok(keys) = iam.list_access_keys().user_name(&name).send().await {
                for k in keys.access_key_metadata() {
                    if !matches!(k.status(), Some(StatusType::Active)) {
                        continue;
                    }
                    if let Some(created) = k.create_date() {
                        let age_days = (now - created.secs()).max(0) / 86_400;
                        if age_days > max_age {
                            graph.upsert(&node_id, "iam_user", "global", "internal", &["stale_access_key"]);
                            findings.push(posture_finding(
                                Domain::Identity,
                                "iam_stale_access_key",
                                &format!("Stale IAM access key: {name}"),
                                "medium",
                                "T1552.001",
                                &c_stale_key,
                                target,
                                0.88,
                                &format!("Active access key for '{name}' is {age_days} days old (threshold {max_age})."),
                                "Rotate the access key and prefer IAM roles / SSO for programmatic access.",
                                Evidence::new()
                                    .with("user", name.clone())
                                    .with("key_age_days", age_days)
                                    .with("access_key_id", k.access_key_id().unwrap_or("")),
                                "iam_user",
                                &name,
                                "global",
                            ));
                        }
                    }
                }
            }

            if let Ok(att) = iam.list_attached_user_policies().user_name(&name).send().await {
                for p in att.attached_policies() {
                    let arn = p.policy_arn().unwrap_or("");
                    if arn.ends_with(":policy/AdministratorAccess") {
                        graph.upsert(&node_id, "iam_user", "global", "privileged", &["administrator_access"]);
                        findings.push(posture_finding(
                            Domain::Identity,
                            "iam_direct_admin_policy",
                            &format!("AdministratorAccess attached directly to user: {name}"),
                            "high",
                            "T1098",
                            &c_admin,
                            target,
                            0.92,
                            &format!("User '{name}' has AWS-managed AdministratorAccess attached directly."),
                            "Remove direct admin attachment; grant admin via a group/role with break-glass controls.",
                            Evidence::new().with("user", name.clone()).with("policy_arn", arn),
                            "iam_user",
                            &name,
                            "global",
                        ));
                    }
                }
            }
        }
    }

    if opts.check_iam_wildcards {
        let c_wild = ComplianceRef {
            cis: "1.16",
            soc2: "CC6.3",
            iso27001: "A.9.2.3",
            pci: "7.1.2",
            nist: "PR.AC-4",
            gdpr: "Art.32",
        };
        let mut policy_count = 0usize;
        let mut pag = iam
            .list_policies()
            .scope(aws_sdk_iam::types::PolicyScopeType::Local)
            .only_attached(true)
            .into_paginator()
            .send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for pol in page.policies() {
                if policy_count >= opts.max_resources_per_service {
                    break;
                }
                policy_count += 1;
                let arn = pol.arn().unwrap_or("").to_string();
                let name = pol.policy_name().unwrap_or("").to_string();
                let Some(default_ver) = pol.default_version_id() else {
                    continue;
                };
                let Ok(ver) = iam
                    .get_policy_version()
                    .policy_arn(&arn)
                    .version_id(default_ver)
                    .send()
                    .await
                else {
                    continue;
                };
                let Some(doc) = ver.policy_version().and_then(|pv| pv.document()) else {
                    continue;
                };
                let doc_decoded = urlencoding::decode(doc)
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|_| doc.to_string());
                let doc_l = doc_decoded.to_ascii_lowercase();
                let wildcard_action = doc_l.contains("\"action\":\"*\"")
                    || doc_l.contains("\"action\":[\"*\"]")
                    || doc_l.contains("\"action\":\"*:*\"")
                    || doc_l.contains("\"action\":[\"*:*\"]");
                let wildcard_resource = doc_l.contains("\"resource\":\"*\"")
                    || doc_l.contains("\"resource\":[\"*\"]");
                if wildcard_action || wildcard_resource {
                    graph.upsert(
                        &format!("aws:iam:policy:{name}"),
                        "iam_policy",
                        "global",
                        "privileged",
                        &["wildcard_policy"],
                    );
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_wildcard_policy",
                        &format!("Overly permissive IAM policy: {name}"),
                        if wildcard_action { "critical" } else { "high" },
                        "T1098",
                        &c_wild,
                        target,
                        0.9,
                        &format!(
                            "Policy '{name}' allows wildcard Action or Resource — violates least-privilege (CIS 1.16)."
                        ),
                        "Replace wildcard permissions with explicit actions/resources scoped to the minimum required.",
                        Evidence::new()
                            .with("policy_arn", arn.clone())
                            .with("wildcard_action", wildcard_action)
                            .with("wildcard_resource", wildcard_resource),
                        "iam_policy",
                        &name,
                        "global",
                    ));
                }
            }
        }
    }

    findings
}

// ─── S3 data security ──────────────────────────────────────────────────────────

async fn scan_s3(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    home_region: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.1.5",
        soc2: "CC6.6",
        iso27001: "A.8.2.3",
        pci: "1.3.1",
        nist: "PR.DS-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.1.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    let global = aws_sdk_s3::config::Builder::from(sdk)
        .region(Region::new(home_region.to_string()))
        .build();
    let s3 = aws_sdk_s3::Client::from_conf(global);
    let buckets = match s3.list_buckets().send().await {
        Ok(b) => b,
        Err(e) => {
            findings.push(posture_finding(
                Domain::Data,
                "s3_list_denied",
                "S3 ListBuckets denied",
                "info",
                "",
                &ComplianceRef {
                    cis: "",
                    soc2: "",
                    iso27001: "",
                    pci: "",
                    nist: "",
                    gdpr: "",
                },
                target,
                1.0,
                &format!("s3:ListAllMyBuckets failed ({e}); grant the scanner read-only S3 permissions."),
                "Attach a read-only policy with s3:ListAllMyBuckets and GetBucket* actions.",
                Evidence::new().with("error", e.to_string()),
                "s3",
                "*",
                "global",
            ));
            return findings;
        }
    };

    for b in buckets.buckets().iter().take(opts.max_buckets()) {
        let name = b.name().unwrap_or_default().to_string();
        if name.is_empty() {
            continue;
        }
        let node_id = format!("aws:s3:bucket:{name}");
        graph.upsert(&node_id, "s3_bucket", "pending", "internal", &[]);

        let loc = s3
            .get_bucket_location()
            .bucket(&name)
            .send()
            .await
            .ok()
            .and_then(|r| r.location_constraint().map(|x| x.as_str().to_string()));
        let region = map_bucket_location(loc.as_deref());
        let regional = aws_sdk_s3::config::Builder::from(sdk)
            .region(Region::new(region.clone()))
            .build();
        let rs3 = aws_sdk_s3::Client::from_conf(regional);

        let mut public_reason: Option<String> = None;
        match rs3.get_public_access_block().bucket(&name).send().await {
            Ok(resp) => {
                if let Some(pab) = resp.public_access_block_configuration() {
                    let weak = [
                        (pab.block_public_acls(), "block_public_acls=false"),
                        (pab.ignore_public_acls(), "ignore_public_acls=false"),
                        (pab.block_public_policy(), "block_public_policy=false"),
                        (pab.restrict_public_buckets(), "restrict_public_buckets=false"),
                    ];
                    for (flag, label) in weak {
                        if flag == Some(false) {
                            public_reason = Some(label.to_string());
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                let missing = e.as_service_error().and_then(|se| se.meta().code())
                    == Some("NoSuchPublicAccessBlockConfiguration");
                if missing {
                    public_reason = Some("no PublicAccessBlock configured".to_string());
                }
            }
        }

        let mut acl_public: Option<String> = None;
        if let Ok(acl) = rs3.get_bucket_acl().bucket(&name).send().await {
            for g in acl.grants() {
                let uri = g
                    .grantee()
                    .and_then(|gg| gg.uri())
                    .unwrap_or("")
                    .to_lowercase();
                if uri.contains("allusers") || uri.contains("authenticatedusers") {
                    acl_public = Some(uri);
                    break;
                }
            }
        }

        if let Some(uri) = acl_public {
            graph.upsert(&node_id, "s3_bucket", &region, "internet", &["public_acl"]);
            findings.push(posture_finding(
                Domain::Data,
                "s3_public_acl",
                &format!("S3 bucket world-readable via ACL: {name}"),
                "critical",
                "T1530",
                &c_public,
                target,
                0.94,
                &format!("Bucket '{name}' ({region}) grants access to a public grantee ({uri})."),
                "Remove public ACL grants; enable S3 Block Public Access at account and bucket level.",
                Evidence::new()
                    .with("bucket", name.clone())
                    .with("public_grantee", uri),
                "s3_bucket",
                &name,
                &region,
            ));
        } else if let Some(reason) = public_reason {
            graph.upsert(&node_id, "s3_bucket", &region, "internet", &["weak_public_access_block"]);
            findings.push(posture_finding(
                Domain::Data,
                "s3_weak_public_access_block",
                &format!("S3 bucket missing public-access protection: {name}"),
                "high",
                "T1530",
                &c_public,
                target,
                0.86,
                &format!("Bucket '{name}' ({region}) does not fully block public access ({reason})."),
                "Enable all four S3 Block Public Access settings on the bucket and account.",
                Evidence::new().with("bucket", name.clone()).with("reason", reason),
                "s3_bucket",
                &name,
                &region,
            ));
        }

        if let Err(e) = rs3.get_bucket_encryption().bucket(&name).send().await {
            let code = e.as_service_error().and_then(|se| se.meta().code()).unwrap_or("");
            if code == "ServerSideEncryptionConfigurationNotFoundError" {
                graph.upsert(&node_id, "s3_bucket", &region, "internal", &["no_default_encryption"]);
                findings.push(posture_finding(
                    Domain::Data,
                    "s3_no_default_encryption",
                    &format!("S3 bucket without default encryption: {name}"),
                    "medium",
                    "T1530",
                    &c_encrypt,
                    target,
                    0.85,
                    &format!("Bucket '{name}' ({region}) has no default server-side encryption."),
                    "Enable default SSE-S3 or SSE-KMS on the bucket.",
                    Evidence::new().with("bucket", name.clone()),
                    "s3_bucket",
                    &name,
                    &region,
                ));
            }
        }

        if opts.check_s3_policy_public {
            if let Ok(pol_resp) = rs3.get_bucket_policy().bucket(&name).send().await {
                if let Some(policy) = pol_resp.policy() {
                    let lower = policy.to_ascii_lowercase();
                    let wildcard_principal = lower.contains("\"principal\":\"*\"")
                        || lower.contains("\"principal\": \"*\"")
                        || lower.contains("\"aws\":\"*\"")
                        || lower.contains("allusers");
                    let allows_read = lower.contains("\"effect\":\"allow\"")
                        || lower.contains("\"effect\": \"allow\"");
                    let s3_read = lower.contains("s3:getobject")
                        || lower.contains("s3:listbucket")
                        || lower.contains("\"s3:*\"")
                        || lower.contains("\"action\":\"*\"")
                        || lower.contains("\"action\":[\"*\"]");
                    if wildcard_principal && allows_read && s3_read {
                        graph.upsert(&node_id, "s3_bucket", &region, "internet", &["public_bucket_policy"]);
                        findings.push(posture_finding(
                            Domain::Data,
                            "s3_public_bucket_policy",
                            &format!("S3 bucket world-readable via bucket policy: {name}"),
                            "critical",
                            "T1530",
                            &c_public,
                            target,
                            0.95,
                            &format!(
                                "Bucket '{name}' ({region}) bucket policy grants public read/list to anonymous or wildcard principals."
                            ),
                            "Remove wildcard principals from the bucket policy; enforce Block Public Access at account level.",
                            Evidence::new()
                                .with("bucket", name.clone())
                                .with("policy_excerpt", &policy[..policy.len().min(512)]),
                            "s3_bucket",
                            &name,
                            &region,
                        ));
                    }
                }
            }
        }

        if opts.check_s3_versioning {
            if let Ok(ver) = rs3.get_bucket_versioning().bucket(&name).send().await {
                let enabled = ver
                    .status()
                    .map(|s| s.as_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("Enabled"));
                if !enabled {
                    graph.upsert(&node_id, "s3_bucket", &region, "internal", &["no_versioning"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "s3_versioning_disabled",
                        &format!("S3 bucket versioning disabled: {name}"),
                        "medium",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.82,
                        &format!("Bucket '{name}' ({region}) has no versioning — ransomware or accidental delete is irreversible."),
                        "Enable S3 versioning and lifecycle rules; pair with MFA Delete for critical buckets.",
                        Evidence::new().with("bucket", name.clone()),
                        "s3_bucket",
                        &name,
                        &region,
                    ));
                }
            }
        }

        if opts.check_s3_object_lock {
            match rs3.get_object_lock_configuration().bucket(&name).send().await {
                Ok(cfg) => {
                    let enabled = cfg
                        .object_lock_configuration()
                        .and_then(|c| c.object_lock_enabled())
                        .map(|s| s.as_str())
                        .is_some_and(|s| s.eq_ignore_ascii_case("Enabled"));
                    if !enabled {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "s3_object_lock_disabled",
                            &format!("S3 bucket without Object Lock governance: {name}"),
                            "medium",
                            "T1485",
                            &c_encrypt,
                            target,
                            0.84,
                            &format!(
                                "Bucket '{name}' ({region}) has Object Lock disabled — WORM/immutable compliance unavailable."
                            ),
                            "Enable Object Lock in COMPLIANCE or GOVERNANCE mode on regulated buckets.",
                            Evidence::new().with("bucket", name.clone()),
                            "s3_bucket",
                            &name,
                            &region,
                        ));
                    }
                }
                Err(e) => {
                    let missing = e.as_service_error().and_then(|se| se.meta().code())
                        == Some("ObjectLockConfigurationNotFoundError");
                    if missing {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "s3_no_object_lock",
                            &format!("S3 bucket has no Object Lock configuration: {name}"),
                            "low",
                            "T1485",
                            &c_encrypt,
                            target,
                            0.78,
                            &format!(
                                "Bucket '{name}' ({region}) has no Object Lock — cannot enforce immutable retention."
                            ),
                            "Enable Object Lock at bucket creation for regulated data.",
                            Evidence::new().with("bucket", name.clone()),
                            "s3_bucket",
                            &name,
                            &region,
                        ));
                    }
                }
            }
        }
    }

    findings
}

async fn scan_ec2_vpc(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_sg = ComplianceRef {
        cis: "5.2",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.2",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_imds = ComplianceRef {
        cis: "5.6",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.7",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_flow = ComplianceRef {
        cis: "3.9",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.2.1",
        nist: "DE.AE-3",
        gdpr: "Art.32",
    };
    let c_ebs = ComplianceRef {
        cis: "2.2.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ec2 = aws_sdk_ec2::Client::from_conf(
            aws_sdk_ec2::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );

        let mut sg_count = 0usize;
        let mut sg_pag = ec2.describe_security_groups().into_paginator().send();
        while let Some(page) = sg_pag.next().await {
            let Ok(page) = page else { break };
            for sg in page.security_groups() {
                if sg_count >= opts.max_resources_per_service {
                    break;
                }
                sg_count += 1;
                let sg_id = sg.group_id().unwrap_or("").to_string();
                let sg_name = sg.group_name().unwrap_or("").to_string();
                let sg_node = format!("aws:ec2:sg:{sg_id}");
                graph.upsert(&sg_node, "security_group", r, "internal", &[]);
                let mut sg_open_world = false;

                for perm in sg.ip_permissions() {
                    let proto = perm.ip_protocol().unwrap_or("-1");
                    let open_world = perm
                        .ip_ranges()
                        .iter()
                        .any(|ipr| ipr.cidr_ip() == Some("0.0.0.0/0"));
                    if !open_world {
                        continue;
                    }
                    sg_open_world = true;
                    let all_traffic = proto == "-1";
                    if !all_traffic && !port_in_dangerous(perm.from_port(), perm.to_port()) {
                        continue;
                    }
                    let sev = if all_traffic { "critical" } else { "high" };
                    graph.upsert(&sg_node, "security_group", r, "internet", &["open_ingress"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "ec2_sg_open_ingress",
                        &format!("Security group open to the internet: {sg_id}"),
                        sev,
                        "T1190",
                        &c_sg,
                        target,
                        0.91,
                        &format!("Security group {sg_id} in {r} allows ingress from 0.0.0.0/0."),
                        "Restrict ingress to known CIDRs, a bastion host, or VPN-only access.",
                        Evidence::new()
                            .with("security_group", sg_id.clone())
                            .with("protocol", proto)
                            .with("from_port", perm.from_port().unwrap_or(-1))
                            .with("to_port", perm.to_port().unwrap_or(-1)),
                        "ec2_security_group",
                        &sg_id,
                        r,
                    ));
                }

                if opts.check_default_sg && sg_name == "default" && sg_open_world {
                    graph.upsert(&sg_node, "security_group", r, "internet", &["default_sg_open"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "ec2_default_sg_open",
                        &format!("Default VPC security group allows world ingress: {sg_id}"),
                        "high",
                        "T1190",
                        &c_sg,
                        target,
                        0.9,
                        &format!("Default security group {sg_id} in {r} permits 0.0.0.0/0 ingress — AWS best practice is to block all traffic on the default SG."),
                        "Remove all inbound/outbound rules from the default SG; attach purpose-built groups to instances.",
                        Evidence::new().with("security_group", sg_id.clone()).with("group_name", "default"),
                        "ec2_security_group",
                        &sg_id,
                        r,
                    ));
                }
            }
        }

        if opts.check_imds {
            let mut inst_count = 0usize;
            let mut inst_pag = ec2.describe_instances().into_paginator().send();
            while let Some(page) = inst_pag.next().await {
                let Ok(page) = page else { break };
                for res in page.reservations() {
                    for inst in res.instances() {
                        if inst_count >= opts.max_resources_per_service {
                            break;
                        }
                        inst_count += 1;
                        let iid = inst.instance_id().unwrap_or("").to_string();
                        let inst_node = format!("aws:ec2:instance:{iid}");
                        let public_ip = inst.public_ip_address().map(str::to_string);
                        let exposure = if public_ip.is_some() { "internet" } else { "internal" };
                        graph.upsert(&inst_node, "ec2_instance", r, exposure, &[]);

                        let imdsv1 = inst
                            .metadata_options()
                            .and_then(|m| m.http_tokens())
                            .map(|t| t.as_str().eq_ignore_ascii_case("optional"))
                            .unwrap_or(false);
                        let has_profile = inst.iam_instance_profile().is_some();
                        if let Some(profile) = inst.iam_instance_profile() {
                            if let Some(arn) = profile.arn() {
                                graph.link(&inst_node, arn, "assumes_role");
                                graph.upsert(arn, "iam_instance_profile", r, exposure, &[]);
                            }
                        }

                        if public_ip.is_some() && imdsv1 {
                            let sev = if has_profile { "high" } else { "medium" };
                            graph.upsert(&inst_node, "ec2_instance", r, "internet", &["imdsv1", "public_ip"]);
                            findings.push(posture_finding(
                                Domain::Compute,
                                "ec2_imdsv1_public",
                                &format!("Public EC2 instance allows IMDSv1: {iid}"),
                                sev,
                                "T1552.005",
                                &c_imds,
                                target,
                                0.89,
                                &format!("Instance {iid} ({r}) has a public IP and permits IMDSv1 — SSRF can steal instance-role credentials."),
                                "Set HttpTokens=required (IMDSv2 only) and prefer private subnets with egress via NAT.",
                                Evidence::new()
                                    .with("instance_id", iid.clone())
                                    .with("public_ip", public_ip.unwrap_or_default())
                                    .with("imdsv1_allowed", true)
                                    .with("has_instance_role", has_profile),
                                "ec2_instance",
                                &iid,
                                r,
                            ));
                        }
                    }
                }
            }
        }

        let mut vol_count = 0usize;
        let mut vol_pag = ec2.describe_volumes().into_paginator().send();
        while let Some(page) = vol_pag.next().await {
            let Ok(page) = page else { break };
            for v in page.volumes() {
                if vol_count >= opts.max_resources_per_service {
                    break;
                }
                vol_count += 1;
                if v.encrypted() == Some(false) {
                    let vid = v.volume_id().unwrap_or("").to_string();
                    graph.upsert(&format!("aws:ebs:volume:{vid}"), "ebs_volume", r, "internal", &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "ebs_unencrypted",
                        &format!("Unencrypted EBS volume: {vid}"),
                        "medium",
                        "T1530",
                        &c_ebs,
                        target,
                        0.84,
                        &format!("EBS volume {vid} in {r} is not encrypted at rest."),
                        "Enable EBS encryption by default in the region and encrypt existing volumes.",
                        Evidence::new().with("volume_id", vid.clone()),
                        "ebs_volume",
                        &vid,
                        r,
                    ));
                }
            }
        }

        if opts.check_flow_logs {
            let fl = ec2.describe_flow_logs().send().await;
            let has_flow = fl
                .ok()
                .map(|r| !r.flow_logs().is_empty())
                .unwrap_or(false);
            if !has_flow {
                findings.push(posture_finding(
                    Domain::Governance,
                    "vpc_no_flow_logs",
                    &format!("No VPC flow logs enabled in {r}"),
                    "medium",
                    "T1046",
                    &c_flow,
                    target,
                    0.8,
                    &format!("Region {r} has no VPC flow logs — network visibility and forensics are blind."),
                    "Enable VPC Flow Logs on all VPCs and ship to CloudWatch Logs or S3.",
                    Evidence::new().check("describe_flow_logs", true, "empty"),
                    "vpc",
                    "*",
                    r,
                ));
            }
        }

        if opts.check_public_snapshots {
            let mut snap_count = 0usize;
            let mut snap_pag = ec2
                .describe_snapshots()
                .owner_ids("self")
                .into_paginator()
                .send();
            while let Some(page) = snap_pag.next().await {
                let Ok(page) = page else { break };
                for snap in page.snapshots() {
                    if snap_count >= opts.max_resources_per_service {
                        break;
                    }
                    snap_count += 1;
                    let sid = snap.snapshot_id().unwrap_or("").to_string();
                    if sid.is_empty() {
                        continue;
                    }
                    let public = ec2
                        .describe_snapshot_attribute()
                        .snapshot_id(&sid)
                        .attribute(aws_sdk_ec2::types::SnapshotAttributeName::CreateVolumePermission)
                        .send()
                        .await
                        .ok()
                        .map(|attr| {
                            attr.create_volume_permissions().iter().any(|p| {
                                matches!(
                                    p.group(),
                                    Some(aws_sdk_ec2::types::PermissionGroup::All)
                                )
                            })
                        })
                        .unwrap_or(false);
                    if !public {
                        continue;
                    }
                    let sid = snap.snapshot_id().unwrap_or("").to_string();
                    let node_id = format!("aws:ebs:snapshot:{sid}");
                    graph.upsert(&node_id, "ebs_snapshot", r, "internet", &["public_snapshot"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "ebs_public_snapshot",
                        &format!("Public EBS snapshot: {sid}"),
                        "critical",
                        "T1530",
                        &c_ebs,
                        target,
                        0.93,
                        &format!(
                            "EBS snapshot {sid} in {r} is shared with group 'all' — any AWS account can create volumes from it."
                        ),
                        "Remove public snapshot permissions; use encrypted snapshots with IAM-scoped sharing only.",
                        Evidence::new().with("snapshot_id", sid.clone()),
                        "ebs_snapshot",
                        &sid,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── SSM governance ────────────────────────────────────────────────────────────

async fn scan_ssm(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !opts.check_ssm_public_params {
        return findings;
    }
    let c_ssm = ComplianceRef {
        cis: "3.2",
        soc2: "CC6.1",
        iso27001: "A.9.4.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ssm = aws_sdk_ssm::Client::from_conf(
            aws_sdk_ssm::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = ssm.describe_parameters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for p in page.parameters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = p.name().unwrap_or("").to_string();
                if name.starts_with("/aws/service/") {
                    continue;
                }
                let tier = p.tier().map(|t| t.as_str()).unwrap_or("");
                if tier.eq_ignore_ascii_case("Advanced") {
                    continue;
                }
                let node_id = format!("aws:ssm:param:{name}");
                graph.upsert(&node_id, "ssm_parameter", r, "internal", &[]);

                if let Ok(detail) = ssm.get_parameter().name(&name).with_decryption(false).send().await {
                    let param_type = detail.parameter().and_then(|pp| pp.r#type()).map(|t| t.as_str()).unwrap_or("");
                    if param_type.eq_ignore_ascii_case("String") {
                        graph.upsert(&node_id, "ssm_parameter", r, "internet", &["public_string_param"]);
                        findings.push(posture_finding(
                            Domain::Governance,
                            "ssm_public_string_param",
                            &format!("SSM String parameter (potentially public): {name}"),
                            "medium",
                            "T1552.001",
                            &c_ssm,
                            target,
                            0.75,
                            &format!("SSM parameter '{name}' in {r} is type String — verify it is not exposed via overly broad IAM."),
                            "Use SecureString for secrets; restrict ssm:GetParameter with resource-level IAM conditions.",
                            Evidence::new().with("parameter", name.clone()).with("type", param_type),
                            "ssm_parameter",
                            &name,
                            r,
                        ));
                    }
                }
            }
        }
    }

    findings
}

// ─── Lambda serverless posture ─────────────────────────────────────────────────

async fn scan_lambda(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_secrets = ComplianceRef {
        cis: "3.4",
        soc2: "CC6.1",
        iso27001: "A.9.4.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let lambda = aws_sdk_lambda::Client::from_conf(
            aws_sdk_lambda::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = lambda.list_functions().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for func in page.functions() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = func.function_name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let _arn = func.function_arn().unwrap_or("").to_string();
                let node_id = format!("aws:lambda:function:{name}");
                graph.upsert(&node_id, "lambda_function", r, "internal", &[]);

                if let Some(role) = func.role() {
                    graph.link(&node_id, role, "execution_role");
                    graph.upsert(role, "iam_role", r, "internal", &[]);
                }

                if let Ok(pol) = lambda.get_policy().function_name(&name).send().await {
                    if let Some(raw) = pol.policy() {
                        let lower = raw.to_ascii_lowercase();
                        let public_invoke = lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"principal\": \"*\"")
                            || lower.contains("\"aws\":\"*\"");
                        if public_invoke {
                            graph.upsert(&node_id, "lambda_function", r, "internet", &["public_invoke"]);
                            findings.push(posture_finding(
                                Domain::Compute,
                                "lambda_public_resource_policy",
                                &format!("Lambda function publicly invokable: {name}"),
                                "critical",
                                "T1190",
                                &c_public,
                                target,
                                0.93,
                                &format!(
                                    "Function '{name}' ({r}) has a resource-based policy allowing unauthenticated invocation."
                                ),
                                "Remove wildcard principals from the function resource policy; use IAM auth or API Gateway with authorizers.",
                                Evidence::new().with("function", name.clone()).with("policy_excerpt", &raw[..raw.len().min(512)]),
                                "lambda_function",
                                &name,
                                r,
                            ));
                        }
                    }
                }

                if let Ok(cfg) = lambda.get_function_configuration().function_name(&name).send().await {
                    let env_vars = cfg
                        .environment()
                        .and_then(|e| e.variables())
                        .map(|m| m.len())
                        .unwrap_or(0);
                    if env_vars > 0 {
                        let suspicious = ["password", "secret", "api_key", "apikey", "token", "private_key"];
                        if let Some(vars) = cfg.environment().and_then(|e| e.variables()) {
                            for (k, _v) in vars {
                                let kl = k.to_ascii_lowercase();
                                if suspicious.iter().any(|s| kl.contains(s)) {
                                    graph.upsert(&node_id, "lambda_function", r, "internal", &["env_secrets"]);
                                    findings.push(posture_finding(
                                        Domain::Governance,
                                        "lambda_env_secret_key",
                                        &format!("Lambda environment variable name suggests a secret: {name}"),
                                        "high",
                                        "T1552.001",
                                        &c_secrets,
                                        target,
                                        0.82,
                                        &format!(
                                            "Function '{name}' ({r}) defines environment variable '{k}' — secrets in plain env vars are visible to anyone with lambda:GetFunctionConfiguration."
                                        ),
                                        "Store secrets in AWS Secrets Manager or SSM Parameter Store (SecureString); reference by ARN at runtime.",
                                        Evidence::new().with("function", name.clone()).with("env_key", k.clone()),
                                        "lambda_function",
                                        &name,
                                        r,
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }

                if opts.check_lambda_urls {
                    if let Ok(url_cfg) = lambda.get_function_url_config().function_name(&name).send().await {
                        let auth = url_cfg.auth_type().as_str();
                        if auth.eq_ignore_ascii_case("NONE") {
                            graph.upsert(&node_id, "lambda_function", r, "internet", &["function_url_public"]);
                            findings.push(posture_finding(
                                Domain::Compute,
                                "lambda_function_url_no_auth",
                                &format!("Lambda Function URL without auth: {name}"),
                                "critical",
                                "T1190",
                                &c_public,
                                target,
                                0.94,
                                &format!(
                                    "Function '{name}' ({r}) exposes a Function URL with AuthType=NONE — unauthenticated HTTP access."
                                ),
                                "Set AuthType=AWS_IAM or front with Amazon CloudFront + WAF; disable the URL if unused.",
                                Evidence::new()
                                    .with("function", name.clone())
                                    .with("function_url", url_cfg.function_url()),
                                "lambda_function",
                                &name,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── RDS data-store posture ────────────────────────────────────────────────────

async fn scan_rds(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let rds = aws_sdk_rds::Client::from_conf(
            aws_sdk_rds::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = rds.describe_db_instances().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for db in page.db_instances() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = db.db_instance_identifier().unwrap_or("").to_string();
                let node_id = format!("aws:rds:instance:{id}");
                let exposure = if db.publicly_accessible() == Some(true) {
                    "internet"
                } else {
                    "internal"
                };
                graph.upsert(&node_id, "rds_instance", r, exposure, &[]);

                if db.publicly_accessible() == Some(true) {
                    graph.upsert(&node_id, "rds_instance", r, "internet", &["public_rds"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "rds_publicly_accessible",
                        &format!("RDS instance publicly accessible: {id}"),
                        "critical",
                        "T1190",
                        &c_public,
                        target,
                        0.94,
                        &format!(
                            "RDS instance '{id}' ({r}) has publicly_accessible=true — databases reachable from the internet."
                        ),
                        "Set publicly_accessible=false; place RDS in private subnets with security-group restrictions.",
                        Evidence::new()
                            .with("db_instance", id.clone())
                            .with("engine", db.engine().unwrap_or(""))
                            .with("endpoint", db.endpoint().and_then(|e| e.address()).unwrap_or("")),
                        "rds_instance",
                        &id,
                        r,
                    ));
                }

                if db.storage_encrypted() == Some(false) {
                    graph.upsert(&node_id, "rds_instance", r, exposure, &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "rds_unencrypted_storage",
                        &format!("RDS storage not encrypted: {id}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.88,
                        &format!("RDS instance '{id}' ({r}) does not have storage encryption enabled."),
                        "Enable storage_encrypted on new instances; migrate existing data to encrypted snapshots.",
                        Evidence::new().with("db_instance", id.clone()),
                        "rds_instance",
                        &id,
                        r,
                    ));
                }

                if db.backup_retention_period().unwrap_or(0) < 7 {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "rds_short_backup_retention",
                        &format!("RDS backup retention below 7 days: {id}"),
                        "medium",
                        "T1485",
                        &ComplianceRef {
                            cis: "2.3.1",
                            soc2: "CC7.2",
                            iso27001: "A.12.3.1",
                            pci: "9.5.1",
                            nist: "PR.IP-4",
                            gdpr: "Art.32",
                        },
                        target,
                        0.8,
                        &format!(
                            "RDS instance '{id}' ({r}) has backup retention of {} day(s) (CIS recommends ≥ 7).",
                            db.backup_retention_period().unwrap_or(0)
                        ),
                        "Increase backup_retention_period to at least 7 days; enable automated backups.",
                        Evidence::new().with("backup_retention_days", db.backup_retention_period().unwrap_or(0)),
                        "rds_instance",
                        &id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── KMS key governance ────────────────────────────────────────────────────────

async fn scan_kms(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_rotation = ComplianceRef {
        cis: "3.8",
        soc2: "CC6.1",
        iso27001: "A.10.1.2",
        pci: "3.6.4",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };
    let c_public = ComplianceRef {
        cis: "3.8",
        soc2: "CC6.6",
        iso27001: "A.9.4.1",
        pci: "3.5.1",
        nist: "PR.AC-4",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let kms = aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = kms.list_keys().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for key in page.keys() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                let key_id = key.key_id().unwrap_or("").to_string();
                if key_id.is_empty() {
                    continue;
                }
                count += 1;
                let node_id = format!("aws:kms:key:{key_id}");
                graph.upsert(&node_id, "kms_key", r, "internal", &[]);

                if let Ok(desc) = kms.describe_key().key_id(&key_id).send().await {
                    if let Some(meta) = desc.key_metadata() {
                        let customer_managed = meta
                            .key_manager()
                            .map(|m| *m == aws_sdk_kms::types::KeyManagerType::Customer)
                            .unwrap_or(false);
                        if customer_managed {
                            let rotation_on = kms
                                .get_key_rotation_status()
                                .key_id(&key_id)
                                .send()
                                .await
                                .ok()
                                .map(|s| s.key_rotation_enabled())
                                .unwrap_or(false);
                            if !rotation_on {
                            graph.upsert(&node_id, "kms_key", r, "internal", &["no_rotation"]);
                            findings.push(posture_finding(
                                Domain::Governance,
                                "kms_rotation_disabled",
                                &format!("Customer-managed KMS key without rotation: {key_id}"),
                                "medium",
                                "T1552.004",
                                &c_rotation,
                                target,
                                0.85,
                                &format!("KMS key '{key_id}' ({r}) is customer-managed but automatic key rotation is disabled."),
                                "Enable automatic key rotation for customer-managed CMKs (annual rotation is free).",
                                Evidence::new().with("key_id", key_id.clone()),
                                "kms_key",
                                &key_id,
                                r,
                            ));
                            }
                        }
                    }
                }

                if let Ok(pol) = kms.get_key_policy().key_id(&key_id).policy_name("default").send().await {
                    if let Some(raw) = pol.policy() {
                        let lower = raw.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"principal\": \"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            graph.upsert(&node_id, "kms_key", r, "internet", &["public_key_policy"]);
                            findings.push(posture_finding(
                                Domain::Governance,
                                "kms_public_key_policy",
                                &format!("KMS key policy allows wildcard principal: {key_id}"),
                                "critical",
                                "T1552.004",
                                &c_public,
                                target,
                                0.92,
                                &format!("KMS key '{key_id}' ({r}) default policy grants access to a wildcard principal."),
                                "Restrict key policy to specific AWS accounts, roles, and services; never use Principal \"*\".",
                                Evidence::new().with("key_id", key_id.clone()).with("policy_excerpt", &raw[..raw.len().min(512)]),
                                "kms_key",
                                &key_id,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── CloudTrail audit logging ──────────────────────────────────────────────────

async fn scan_cloudtrail(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_trail = ComplianceRef {
        cis: "3.1",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.2.1",
        nist: "DE.AE-3",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ct = aws_sdk_cloudtrail::Client::from_conf(
            aws_sdk_cloudtrail::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );

        let trails = match ct.describe_trails().include_shadow_trails(false).send().await {
            Ok(t) => t.trail_list().to_vec(),
            Err(_) => continue,
        };

        if trails.is_empty() {
            graph.upsert(&format!("aws:cloudtrail:{r}"), "cloudtrail", r, "internal", &["no_trail"]);
            findings.push(posture_finding(
                Domain::Governance,
                "cloudtrail_not_configured",
                &format!("No CloudTrail trail configured in {r}"),
                "high",
                "T1562.008",
                &c_trail,
                target,
                0.9,
                &format!("Region {r} has no CloudTrail trail — API activity is not audited."),
                "Create a multi-region CloudTrail trail logging to a dedicated, encrypted S3 bucket with log file validation.",
                Evidence::new().check("describe_trails", true, "empty"),
                "cloudtrail",
                "*",
                r,
            ));
            continue;
        }

        for trail in trails.iter().take(opts.max_resources_per_service) {
            let name = trail.name().unwrap_or("").to_string();
            let node_id = format!("aws:cloudtrail:trail:{name}");
            graph.upsert(&node_id, "cloudtrail_trail", r, "internal", &[]);

            let status = ct.get_trail_status().name(&name).send().await;
            let logging = status
                .ok()
                .and_then(|s| s.is_logging())
                .unwrap_or(false);
            if !logging {
                graph.upsert(&node_id, "cloudtrail_trail", r, "internal", &["not_logging"]);
                findings.push(posture_finding(
                    Domain::Governance,
                    "cloudtrail_not_logging",
                    &format!("CloudTrail trail not actively logging: {name}"),
                    "critical",
                    "T1562.008",
                    &c_trail,
                    target,
                    0.95,
                    &format!("Trail '{name}' in {r} exists but IsLogging=false — attackers can operate undetected."),
                    "Start logging on the trail; verify the S3 bucket policy and CloudWatch Logs integration.",
                    Evidence::new().with("trail", name.clone()).check("is_logging", true, false),
                    "cloudtrail_trail",
                    &name,
                    r,
                ));
            }

            if trail.log_file_validation_enabled() != Some(true) {
                findings.push(posture_finding(
                    Domain::Governance,
                    "cloudtrail_no_log_validation",
                    &format!("CloudTrail log file validation disabled: {name}"),
                    "medium",
                    "T1562.008",
                    &c_trail,
                    target,
                    0.85,
                    &format!("Trail '{name}' ({r}) does not enable log file validation — tampered logs may go undetected."),
                    "Enable log file validation on all CloudTrail trails.",
                    Evidence::new().with("trail", name.clone()),
                    "cloudtrail_trail",
                    &name,
                    r,
                ));
            }

            if trail.is_multi_region_trail() != Some(true) {
                findings.push(posture_finding(
                    Domain::Governance,
                    "cloudtrail_single_region",
                    &format!("CloudTrail trail is single-region: {name}"),
                    "medium",
                    "T1562.008",
                    &c_trail,
                    target,
                    0.8,
                    &format!("Trail '{name}' ({r}) is not multi-region — activity in other regions may be invisible."),
                    "Enable IsMultiRegionTrail on the organisation's primary audit trail.",
                    Evidence::new().with("trail", name.clone()),
                    "cloudtrail_trail",
                    &name,
                    r,
                ));
            }
        }
    }

    findings
}

// ─── IAM roles (CIEM extension) ────────────────────────────────────────────────

async fn scan_iam_roles(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let iam = aws_sdk_iam::Client::new(sdk);
    let mut findings = Vec::new();
    let c_trust = ComplianceRef {
        cis: "1.16",
        soc2: "CC6.3",
        iso27001: "A.9.2.3",
        pci: "7.1.2",
        nist: "PR.AC-4",
        gdpr: "Art.32",
    };
    let c_admin = ComplianceRef {
        cis: "1.16",
        soc2: "CC6.3",
        iso27001: "A.9.2.3",
        pci: "7.1.2",
        nist: "PR.AC-4",
        gdpr: "Art.32",
    };

    let mut count = 0usize;
    let mut pag = iam.list_roles().into_paginator().send();
    while let Some(page) = pag.next().await {
        let Ok(page) = page else { break };
        for role in page.roles() {
            if count >= opts.max_users() {
                break;
            }
            count += 1;
            let name = role.role_name().to_string();
            let arn = role.arn().to_string();
            let node_id = format!("aws:iam:role:{name}");
            graph.upsert(&node_id, "iam_role", "global", "internal", &[]);

            if let Ok(trust) = iam.get_role().role_name(&name).send().await {
                if let Some(doc) = trust.role().and_then(|r| r.assume_role_policy_document()) {
                    let lower = doc.to_ascii_lowercase();
                    // AWS returns URL-encoded JSON; wildcards survive encoding.
                    if lower.contains("\"principal\":\"*\"")
                        || lower.contains("\"aws\":\"*\"")
                        || lower.contains("root")
                    {
                        let sev = if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            "critical"
                        } else {
                            "high"
                        };
                        graph.upsert(&node_id, "iam_role", "global", "internet", &["permissive_trust"]);
                        findings.push(posture_finding(
                            Domain::Identity,
                            "iam_role_permissive_trust",
                            &format!("IAM role with permissive trust policy: {name}"),
                            sev,
                            "T1098",
                            &c_trust,
                            target,
                            0.9,
                            &format!("Role '{name}' allows assumption by a wildcard or overly broad principal."),
                            "Restrict AssumeRole to specific AWS account IDs and external IDs; remove Principal \"*\".",
                            Evidence::new().with("role", name.clone()).with("trust_excerpt", &doc[..doc.len().min(512)]),
                            "iam_role",
                            &name,
                            "global",
                        ));
                    }
                }
            }

            if let Ok(att) = iam.list_attached_role_policies().role_name(&name).send().await {
                for p in att.attached_policies() {
                    let pol_arn = p.policy_arn().unwrap_or("");
                    if pol_arn.ends_with(":policy/AdministratorAccess") {
                        graph.upsert(&node_id, "iam_role", "global", "privileged", &["administrator_access"]);
                        findings.push(posture_finding(
                            Domain::Identity,
                            "iam_role_admin_policy",
                            &format!("AdministratorAccess attached to role: {name}"),
                            "high",
                            "T1098",
                            &c_admin,
                            target,
                            0.91,
                            &format!("Role '{name}' ({arn}) has AWS-managed AdministratorAccess attached."),
                            "Replace with least-privilege inline/custom policies; use permission boundaries.",
                            Evidence::new().with("role", name.clone()).with("policy_arn", pol_arn),
                            "iam_role",
                            &name,
                            "global",
                        ));
                    }
                }
            }
        }
    }

    findings
}

// ─── IAM Access Analyzer (external access — Wiz-class zero-trust plane) ────────

async fn scan_access_analyzer(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_access_analyzer {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_ext = ComplianceRef {
        cis: "1.22",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let aa = aws_sdk_accessanalyzer::Client::from_conf(
            aws_sdk_accessanalyzer::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let analyzers = match aa.list_analyzers().send().await {
            Ok(a) => a.analyzers().to_vec(),
            Err(_) => continue,
        };
        if analyzers.is_empty() {
            findings.push(posture_finding(
                Domain::Governance,
                "access_analyzer_not_enabled",
                &format!("IAM Access Analyzer not enabled in {r}"),
                "medium",
                "T1580",
                &c_ext,
                target,
                0.85,
                &format!("Region {r} has no Access Analyzer — external-access paths to S3/IAM/Lambda may be invisible."),
                "Enable the account-level or organization-level IAM Access Analyzer in every active region.",
                Evidence::new().check("list_analyzers", true, "empty"),
                "access_analyzer",
                "*",
                r,
            ));
            continue;
        }

        let mut finding_count = 0usize;
        for analyzer in analyzers.iter().take(3) {
            let arn = analyzer.arn();
            let mut pag = aa
                .list_findings()
                .analyzer_arn(arn)
                .max_results(100)
                .into_paginator()
                .send();
            while let Some(page) = pag.next().await {
                let Ok(page) = page else { break };
                for f in page.findings() {
                    if finding_count >= opts.max_resources_per_service {
                        break;
                    }
                    finding_count += 1;
                    let fid = f.id().to_string();
                    let resource = f.resource().unwrap_or("").to_string();
                    let status = f.status().as_str();
                    if !status.eq_ignore_ascii_case("ACTIVE") {
                        continue;
                    }
                    let node_id = format!("aws:resource:{resource}");
                    graph.upsert(&node_id, "external_resource", r, "internet", &["access_analyzer_external"]);
                    let title = format!(
                        "External {} access: {}",
                        f.resource_type().as_str(),
                        resource
                    );
                    let sev = if title.to_ascii_lowercase().contains("public")
                        || title.to_ascii_lowercase().contains("external")
                    {
                        "high"
                    } else {
                        "medium"
                    };
                    findings.push(posture_finding(
                        Domain::Network,
                        "access_analyzer_external_access",
                        &format!("Access Analyzer: {title}"),
                        sev,
                        "T1530",
                        &c_ext,
                        target,
                        0.92,
                        &format!(
                            "IAM Access Analyzer ({r}) flagged active external access to `{resource}` — {title}."
                        ),
                        "Review the resource policy/ACL and remove public or cross-account access; validate with Access Analyzer archive after fix.",
                        Evidence::new()
                            .with("finding_id", fid)
                            .with("resource", resource.clone())
                            .with("analyzer", arn),
                        "access_analyzer_finding",
                        &resource,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── GuardDuty threat-detection plane ──────────────────────────────────────────

async fn scan_guardduty(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    _graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_guardduty {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_gd = ComplianceRef {
        cis: "4.15",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.6.1",
        nist: "DE.CM-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let gd = aws_sdk_guardduty::Client::from_conf(
            aws_sdk_guardduty::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let ids = match gd.list_detectors().send().await {
            Ok(d) => d.detector_ids().to_vec(),
            Err(_) => continue,
        };
        if ids.is_empty() {
            findings.push(posture_finding(
                Domain::Governance,
                "guardduty_not_enabled",
                &format!("GuardDuty not enabled in {r}"),
                "high",
                "T1562.001",
                &c_gd,
                target,
                0.9,
                &format!("No GuardDuty detector in {r} — malware, crypto-mining, and IAM anomaly detection are blind."),
                "Enable GuardDuty in all regions; centralize findings to Security Hub.",
                Evidence::new().check("list_detectors", true, "empty"),
                "guardduty",
                "*",
                r,
            ));
            continue;
        }
        for id in ids.iter().take(1) {
            if let Ok(desc) = gd.get_detector().detector_id(id).send().await {
                let status = desc.status().map(|s| s.as_str()).unwrap_or("");
                if !status.eq_ignore_ascii_case("ENABLED") {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "guardduty_disabled",
                        &format!("GuardDuty detector disabled in {r}"),
                        "high",
                        "T1562.001",
                        &c_gd,
                        target,
                        0.9,
                        &format!("GuardDuty detector {id} in {r} is not ENABLED."),
                        "Set detector status to ENABLED and enable S3/EKS/Lambda/RDS protection data sources.",
                        Evidence::new().with("detector_id", id.clone()).with("status", status),
                        "guardduty_detector",
                        id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── AWS Config recorder (drift / compliance plane) ────────────────────────────

async fn scan_config_recorder(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    _graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_config_recorder {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_cfg = ComplianceRef {
        cis: "3.5",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.5.1",
        nist: "DE.AE-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let cfg = aws_sdk_config::Client::from_conf(
            aws_sdk_config::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let recs = match cfg.describe_configuration_recorders().send().await {
            Ok(c) => c.configuration_recorders().to_vec(),
            Err(_) => continue,
        };
        if recs.is_empty() {
            findings.push(posture_finding(
                Domain::Governance,
                "config_recorder_missing",
                &format!("AWS Config recorder not configured in {r}"),
                "medium",
                "T1562.008",
                &c_cfg,
                target,
                0.85,
                &format!("No AWS Config recorder in {r} — configuration drift and compliance rules cannot run."),
                "Enable AWS Config recorder with an S3 delivery channel and SNS notifications.",
                Evidence::new().check("describe_configuration_recorders", true, "empty"),
                "config_recorder",
                "*",
                r,
            ));
            continue;
        }
        for rec in recs {
            let name = rec.name().unwrap_or("default").to_string();
            if let Ok(status) = cfg
                .describe_configuration_recorder_status()
                .configuration_recorder_names(&name)
                .send()
                .await
            {
                let recording = status
                    .configuration_recorders_status()
                    .first()
                    .map(|s| s.recording())
                    .unwrap_or(false);
                if !recording {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "config_recorder_not_recording",
                        &format!("AWS Config recorder not recording: {name}"),
                        "high",
                        "T1562.008",
                        &c_cfg,
                        target,
                        0.88,
                        &format!("Config recorder '{name}' in {r} exists but recording=false."),
                        "Start the configuration recorder and verify the delivery channel IAM role.",
                        Evidence::new().with("recorder", name.clone()),
                        "config_recorder",
                        &name,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── Account-level S3 public access block ──────────────────────────────────────

async fn scan_account_s3_public_block(
    sdk: &SdkConfig,
    account_id: &str,
    opts: &CloudScanOptions,
    target: &str,
    _graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_account_s3_block || account_id.is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_pab = ComplianceRef {
        cis: "2.1.5",
        soc2: "CC6.6",
        iso27001: "A.8.2.3",
        pci: "1.3.1",
        nist: "PR.DS-5",
        gdpr: "Art.32",
    };
    let s3c = aws_sdk_s3control::Client::from_conf(
        aws_sdk_s3control::config::Builder::from(sdk)
            .region(Region::new("us-east-1".to_string()))
            .build(),
    );
    match s3c
        .get_public_access_block()
        .account_id(account_id)
        .send()
        .await
    {
        Ok(resp) => {
            if let Some(pab) = resp.public_access_block_configuration() {
                let weak = [
                    (pab.block_public_acls(), "BlockPublicAcls"),
                    (pab.ignore_public_acls(), "IgnorePublicAcls"),
                    (pab.block_public_policy(), "BlockPublicPolicy"),
                    (pab.restrict_public_buckets(), "RestrictPublicBuckets"),
                ];
                for (flag, label) in weak {
                    if flag == Some(false) {
                        findings.push(posture_finding(
                            Domain::Data,
                            "account_s3_public_access_block_weak",
                            &format!("Account S3 Block Public Access incomplete: {label}"),
                            "critical",
                            "T1530",
                            &c_pab,
                            target,
                            0.95,
                            &format!(
                                "Account {account_id} has S3 Block Public Access setting `{label}=false` — new buckets can become public."
                            ),
                            "Enable all four account-level S3 Block Public Access settings immediately.",
                            Evidence::new().with("account_id", account_id).with("weak_setting", label),
                            "aws_account",
                            account_id,
                            "global",
                        ));
                        break;
                    }
                }
            }
        }
        Err(e) => {
            let missing = e.as_service_error().and_then(|se| se.meta().code())
                == Some("NoSuchPublicAccessBlockConfiguration");
            if missing {
                findings.push(posture_finding(
                    Domain::Data,
                    "account_s3_no_public_access_block",
                    "Account-level S3 Block Public Access not configured",
                    "critical",
                    "T1530",
                    &c_pab,
                    target,
                    0.94,
                    &format!("Account {account_id} has no account-level S3 Block Public Access — buckets can be made public by default."),
                    "Apply S3 Block Public Access at the account level before any bucket is created.",
                    Evidence::new().check("get_public_access_block", false, "NoSuchPublicAccessBlockConfiguration"),
                    "aws_account",
                    account_id,
                    "global",
                ));
            }
        }
    }

    findings
}

// ─── EKS Kubernetes control plane ──────────────────────────────────────────────

async fn scan_eks(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_eks {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_eks = ComplianceRef {
        cis: "5.4",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let eks = aws_sdk_eks::Client::from_conf(
            aws_sdk_eks::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let clusters = match eks.list_clusters().send().await {
            Ok(c) => c.clusters().to_vec(),
            Err(_) => continue,
        };
        let mut count = 0usize;
        for name in clusters {
            if count >= opts.max_resources_per_service {
                break;
            }
            count += 1;
            let node_id = format!("aws:eks:cluster:{name}");
            graph.upsert(&node_id, "eks_cluster", r, "internal", &[]);
            if let Ok(desc) = eks.describe_cluster().name(&name).send().await {
                if let Some(cluster) = desc.cluster() {
                    let public_api = cluster
                        .resources_vpc_config()
                        .map(|v| v.endpoint_public_access())
                        .unwrap_or(false);
                    if public_api {
                        graph.upsert(&node_id, "eks_cluster", r, "internet", &["public_api"]);
                        findings.push(posture_finding(
                            Domain::Compute,
                            "eks_public_api_endpoint",
                            &format!("EKS cluster public API endpoint: {name}"),
                            "high",
                            "T1190",
                            &c_eks,
                            target,
                            0.9,
                            &format!("EKS cluster '{name}' ({r}) has endpointPublicAccess=true — restrict to private + authorized CIDRs."),
                            "Disable public endpoint access or restrict publicAccessCidrs to known admin networks; use private endpoint + VPN/bastion.",
                            Evidence::new().with("cluster", name.clone()),
                            "eks_cluster",
                            &name,
                            r,
                        ));
                    }
                    let secrets_enc = cluster
                        .encryption_config()
                        .first()
                        .is_some();
                    if !secrets_enc {
                        findings.push(posture_finding(
                            Domain::Data,
                            "eks_secrets_not_encrypted",
                            &format!("EKS secrets envelope encryption disabled: {name}"),
                            "medium",
                            "T1552.004",
                            &c_eks,
                            target,
                            0.82,
                            &format!("EKS cluster '{name}' ({r}) has no encryptionConfig for Kubernetes secrets."),
                            "Enable envelope encryption for secrets using a KMS CMK.",
                            Evidence::new().with("cluster", name.clone()),
                            "eks_cluster",
                            &name,
                            r,
                        ));
                    }
                }
            }
        }
    }

    findings
}

// ─── Internet-facing load balancers ────────────────────────────────────────────

async fn scan_elbv2(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_elb {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_elb = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "4.1.1",
        nist: "PR.DS-2",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let elb = aws_sdk_elasticloadbalancingv2::Client::from_conf(
            aws_sdk_elasticloadbalancingv2::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = elb.describe_load_balancers().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for lb in page.load_balancers() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                let scheme = lb.scheme().map(|s| s.as_str()).unwrap_or("");
                if !scheme.eq_ignore_ascii_case("internet-facing") {
                    continue;
                }
                count += 1;
                let name = lb.load_balancer_name().unwrap_or("").to_string();
                let arn = lb.load_balancer_arn().unwrap_or("").to_string();
                let node_id = format!("aws:elbv2:{name}");
                graph.upsert(&node_id, "load_balancer", r, "internet", &["internet_facing"]);

                if let Ok(listeners) = elb.describe_listeners().load_balancer_arn(&arn).send().await {
                    for listener in listeners.listeners() {
                        let port = listener.port().unwrap_or(0);
                        let proto = listener.protocol().map(|p| p.as_str()).unwrap_or("");
                        if port == 80 && proto.eq_ignore_ascii_case("HTTP") {
                            findings.push(posture_finding(
                                Domain::Network,
                                "elb_http_cleartext_listener",
                                &format!("Internet-facing ALB cleartext HTTP listener: {name}"),
                                "medium",
                                "T1040",
                                &c_elb,
                                target,
                                0.86,
                                &format!("Load balancer '{name}' ({r}) exposes port 80/HTTP to the internet without TLS termination."),
                                "Redirect HTTP→HTTPS or terminate TLS on the ALB with a modern policy.",
                                Evidence::new().with("load_balancer", name.clone()).with("port", port),
                                "elbv2",
                                &name,
                                r,
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── Secrets Manager rotation ──────────────────────────────────────────────────

async fn scan_secrets_manager(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_secrets_manager {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_sec = ComplianceRef {
        cis: "3.4",
        soc2: "CC6.1",
        iso27001: "A.9.4.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let sm = aws_sdk_secretsmanager::Client::from_conf(
            aws_sdk_secretsmanager::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = sm.list_secrets().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for secret in page.secret_list() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = secret.name().unwrap_or("").to_string();
                let node_id = format!("aws:secretsmanager:{name}");
                graph.upsert(&node_id, "secret", r, "internal", &[]);
                if secret.rotation_enabled() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "secrets_manager_no_rotation",
                        &format!("Secret without automatic rotation: {name}"),
                        "medium",
                        "T1552.001",
                        &c_sec,
                        target,
                        0.8,
                        &format!("Secrets Manager secret '{name}' ({r}) has rotation disabled."),
                        "Enable automatic rotation with a Lambda rotator or migrate to dynamic secrets.",
                        Evidence::new().with("secret", name.clone()),
                        "secretsmanager_secret",
                        &name,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── SNS / SQS public messaging policies ───────────────────────────────────────

async fn scan_messaging(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_messaging {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_msg = ComplianceRef {
        cis: "2.1.5",
        soc2: "CC6.6",
        iso27001: "A.8.2.3",
        pci: "1.3.1",
        nist: "PR.DS-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let sns = aws_sdk_sns::Client::from_conf(
            aws_sdk_sns::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut topic_count = 0usize;
        let mut tpag = sns.list_topics().into_paginator().send();
        while let Some(page) = tpag.next().await {
            let Ok(page) = page else { break };
            for topic in page.topics() {
                if topic_count >= opts.max_resources_per_service / 2 {
                    break;
                }
                topic_count += 1;
                let arn = topic.topic_arn().unwrap_or("").to_string();
                if arn.is_empty() {
                    continue;
                }
                if let Ok(attrs) = sns.get_topic_attributes().topic_arn(&arn).send().await {
                    if let Some(policy) = attrs.attributes().and_then(|m| m.get("Policy"))
                    {
                        let lower = policy.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            graph.upsert(&format!("aws:sns:{arn}"), "sns_topic", r, "internet", &["public_policy"]);
                            findings.push(posture_finding(
                                Domain::Data,
                                "sns_public_topic_policy",
                                "SNS topic allows wildcard principal",
                                "high",
                                "T1530",
                                &c_msg,
                                target,
                                0.88,
                                &format!("SNS topic {arn} ({r}) policy grants access to a wildcard principal."),
                                "Restrict SNS topic policy to specific account principals and source ARNs.",
                                Evidence::new().with("topic_arn", arn.clone()),
                                "sns_topic",
                                &arn,
                                r,
                            ));
                        }
                    }
                }
            }
        }

        let sqs = aws_sdk_sqs::Client::from_conf(
            aws_sdk_sqs::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut q_count = 0usize;
        let mut qpag = sqs.list_queues().into_paginator().send();
        while let Some(page) = qpag.next().await {
            let Ok(page) = page else { break };
            for url in page.queue_urls() {
                if q_count >= opts.max_resources_per_service / 2 {
                    break;
                }
                q_count += 1;
                if let Ok(attrs) = sqs
                    .get_queue_attributes()
                    .queue_url(url)
                    .attribute_names(aws_sdk_sqs::types::QueueAttributeName::Policy)
                    .send()
                    .await
                {
                    if let Some(policy) = attrs
                        .attributes()
                        .and_then(|m| m.get(&aws_sdk_sqs::types::QueueAttributeName::Policy))
                    {
                        let lower = policy.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            graph.upsert(&format!("aws:sqs:{url}"), "sqs_queue", r, "internet", &["public_policy"]);
                            findings.push(posture_finding(
                                Domain::Data,
                                "sqs_public_queue_policy",
                                "SQS queue allows wildcard principal",
                                "high",
                                "T1530",
                                &c_msg,
                                target,
                                0.88,
                                &format!("SQS queue {url} ({r}) policy grants wildcard access."),
                                "Remove Principal \"*\" from the queue policy; use IAM conditions and VPC endpoints.",
                                Evidence::new().with("queue_url", url.clone()),
                                "sqs_queue",
                                url,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── ECS Fargate/EC2 public task IPs ───────────────────────────────────────────

async fn scan_ecs(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_ecs {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_ecs = ComplianceRef {
        cis: "5.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ecs = aws_sdk_ecs::Client::from_conf(
            aws_sdk_ecs::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let clusters = match ecs.list_clusters().send().await {
            Ok(c) => c.cluster_arns().to_vec(),
            Err(_) => continue,
        };
        let mut count = 0usize;
        for cluster_arn in clusters {
            if count >= opts.max_resources_per_service {
                break;
            }
            if let Ok(services) = ecs.list_services().cluster(&cluster_arn).send().await {
                for svc_arn in services.service_arns().iter().take(20) {
                    if count >= opts.max_resources_per_service {
                        break;
                    }
                    if let Ok(desc) = ecs.describe_services().cluster(&cluster_arn).services(svc_arn).send().await {
                        for svc in desc.services() {
                            count += 1;
                            let name = svc.service_name().unwrap_or("").to_string();
                            let public_ip = svc
                                .network_configuration()
                                .and_then(|n| n.awsvpc_configuration())
                                .map(|a| a.assign_public_ip() == Some(&aws_sdk_ecs::types::AssignPublicIp::Enabled))
                                .unwrap_or(false);
                            if public_ip {
                                let node_id = format!("aws:ecs:service:{name}");
                                graph.upsert(&node_id, "ecs_service", r, "internet", &["public_task_ip"]);
                                findings.push(posture_finding(
                                    Domain::Compute,
                                    "ecs_service_public_ip",
                                    &format!("ECS service assigns public IP: {name}"),
                                    "high",
                                    "T1190",
                                    &c_ecs,
                                    target,
                                    0.87,
                                    &format!("ECS service '{name}' in {r} has assignPublicIp=ENABLED on awsvpc tasks."),
                                    "Run tasks in private subnets with NAT gateway egress; remove public IP assignment.",
                                    Evidence::new().with("service", name.clone()).with("cluster", cluster_arn.clone()),
                                    "ecs_service",
                                    &name,
                                    r,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── ElastiCache encryption at rest ────────────────────────────────────────────

async fn scan_elasticache(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_elasticache {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_cache = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ec = aws_sdk_elasticache::Client::from_conf(
            aws_sdk_elasticache::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = ec.describe_replication_groups().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for rg in page.replication_groups() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = rg.replication_group_id().unwrap_or("").to_string();
                let node_id = format!("aws:elasticache:{id}");
                graph.upsert(&node_id, "elasticache", r, "internal", &[]);
                if rg.at_rest_encryption_enabled() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Data,
                        "elasticache_no_encryption_at_rest",
                        &format!("ElastiCache replication group unencrypted at rest: {id}"),
                        "high",
                        "T1530",
                        &c_cache,
                        target,
                        0.86,
                        &format!("ElastiCache group '{id}' ({r}) does not have at-rest encryption enabled."),
                        "Create a new encrypted replication group and migrate; enable transit encryption.",
                        Evidence::new().with("replication_group", id.clone()),
                        "elasticache_replication_group",
                        &id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── ECR container registry exposure ───────────────────────────────────────────

async fn scan_ecr(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_ecr {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_ecr = ComplianceRef {
        cis: "5.1",
        soc2: "CC6.6",
        iso27001: "A.8.2.3",
        pci: "6.5.3",
        nist: "PR.DS-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ecr = aws_sdk_ecr::Client::from_conf(
            aws_sdk_ecr::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = ecr.describe_repositories().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for repo in page.repositories() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = repo.repository_name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let node_id = format!("aws:ecr:repo:{name}");
                graph.upsert(&node_id, "ecr_repository", r, "internal", &[]);

                if let Ok(pol) = ecr.get_repository_policy().repository_name(&name).send().await {
                    if let Some(raw) = pol.policy_text() {
                        let lower = raw.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                            || lower.contains("allusers")
                        {
                            graph.upsert(&node_id, "ecr_repository", r, "internet", &["public_pull"]);
                            findings.push(posture_finding(
                                Domain::Data,
                                "ecr_public_repository_policy",
                                &format!("ECR repository allows public pull: {name}"),
                                "critical",
                                "T1530",
                                &c_ecr,
                                target,
                                0.93,
                                &format!("ECR repo '{name}' ({r}) repository policy grants anonymous or wildcard pull — supply-chain poisoning risk."),
                                "Remove public pull; use private ECR with IAM-scoped ecr:BatchGetImage and image scanning on push.",
                                Evidence::new().with("repository", name.clone()),
                                "ecr_repository",
                                &name,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── ACM certificate expiry (TLS posture plane) ──────────────────────────────

async fn scan_acm(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_acm {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_acm = ComplianceRef {
        cis: "2.1.1",
        soc2: "CC6.6",
        iso27001: "A.10.1.2",
        pci: "4.1",
        nist: "PR.DS-2",
        gdpr: "Art.32",
    };
    let threshold_days = i64::try_from(opts.acm_expiry_days).unwrap_or(30);
    let now_secs = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
    .unwrap_or(0);

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let acm = aws_sdk_acm::Client::from_conf(
            aws_sdk_acm::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = acm.list_certificates().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for summary in page.certificate_summary_list() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let arn = summary.certificate_arn().unwrap_or("").to_string();
                if arn.is_empty() {
                    continue;
                }
                let Ok(desc) = acm.describe_certificate().certificate_arn(&arn).send().await else {
                    continue;
                };
                let Some(cert) = desc.certificate() else { continue };
                let domain = cert.domain_name().unwrap_or("").to_string();
                let node_id = format!("aws:acm:{arn}");
                graph.upsert(&node_id, "acm_certificate", r, "internal", &[]);

                if let Some(not_after) = cert.not_after() {
                    let exp_secs = i64::try_from(not_after.secs()).unwrap_or(now_secs);
                    let days_left = (exp_secs - now_secs) / 86_400;
                    if days_left < 0 {
                        let days_expired = days_left.unsigned_abs();
                        graph.upsert(&node_id, "acm_certificate", r, "internet", &["expired_cert"]);
                        findings.push(posture_finding(
                            Domain::Network,
                            "acm_certificate_expired",
                            &format!("ACM certificate expired: {domain}"),
                            "critical",
                            "T1587",
                            &c_acm,
                            target,
                            0.96,
                            &format!("Certificate for '{domain}' ({r}) expired {days_expired} days ago — TLS interception or outage."),
                            "Renew or replace the certificate immediately; automate renewal via ACM DNS validation.",
                            Evidence::new().with("domain", domain.clone()).with("certificate_arn", arn.clone()),
                            "acm_certificate",
                            &domain,
                            r,
                        ));
                    } else if days_left <= threshold_days {
                        findings.push(posture_finding(
                            Domain::Network,
                            "acm_certificate_expiring",
                            &format!("ACM certificate expiring soon: {domain}"),
                            "high",
                            "T1587",
                            &c_acm,
                            target,
                            0.9,
                            &format!("Certificate for '{domain}' ({r}) expires in {days_left} days (threshold {threshold_days})."),
                            "Renew before expiry; enable ACM managed renewal with Route53 DNS validation.",
                            Evidence::new()
                                .with("domain", domain.clone())
                                .with("days_until_expiry", days_left)
                                .with("certificate_arn", arn),
                            "acm_certificate",
                            &domain,
                            r,
                        ));
                    }
                }
            }
        }
    }

    findings
}

// ─── DynamoDB data-plane posture ───────────────────────────────────────────────

async fn scan_dynamodb(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_dynamodb {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };
    let c_pitr = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC7.2",
        iso27001: "A.12.3.1",
        pci: "10.2.1",
        nist: "PR.IP-4",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ddb = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = ddb.list_tables().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for table_name in page.table_names() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = table_name.to_string();
                let node_id = format!("aws:dynamodb:{name}");
                graph.upsert(&node_id, "dynamodb_table", r, "internal", &[]);

                let Ok(desc) = ddb.describe_table().table_name(&name).send().await else {
                    continue;
                };
                let Some(table) = desc.table() else { continue };

                let sse_on = table
                    .sse_description()
                    .and_then(|s| s.status())
                    .map(|s| s.as_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("ENABLED"));
                if !sse_on {
                    graph.upsert(&node_id, "dynamodb_table", r, "internal", &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "dynamodb_no_encryption",
                        &format!("DynamoDB table without encryption at rest: {name}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.9,
                        &format!("Table '{name}' ({r}) does not have SSE enabled."),
                        "Enable encryption at rest with AWS-owned or CMK keys on all DynamoDB tables.",
                        Evidence::new().with("table", name.clone()),
                        "dynamodb_table",
                        &name,
                        r,
                    ));
                }

                if let Ok(pitr) = ddb
                    .describe_continuous_backups()
                    .table_name(&name)
                    .send()
                    .await
                {
                    let pitr_on = pitr
                        .continuous_backups_description()
                        .and_then(|c| c.point_in_time_recovery_description())
                        .and_then(|p| p.point_in_time_recovery_status())
                        .map(|s| s.as_str())
                        .is_some_and(|s| s.eq_ignore_ascii_case("ENABLED"));
                    if !pitr_on {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "dynamodb_pitr_disabled",
                            &format!("DynamoDB PITR disabled: {name}"),
                            "medium",
                            "T1485",
                            &c_pitr,
                            target,
                            0.85,
                            &format!("Table '{name}' ({r}) has Point-in-Time Recovery disabled — no granular restore after ransomware/delete."),
                            "Enable PITR on all production DynamoDB tables.",
                            Evidence::new().with("table", name.clone()),
                            "dynamodb_table",
                            &name,
                            r,
                        ));
                    }
                }

                if let Some(arn) = table.table_arn() {
                    if let Ok(pol) = ddb.get_resource_policy().resource_arn(arn).send().await {
                        if let Some(raw) = pol.policy() {
                            let lower = raw.to_ascii_lowercase();
                            if lower.contains("\"principal\":\"*\"")
                                || lower.contains("\"aws\":\"*\"")
                            {
                                graph.upsert(&node_id, "dynamodb_table", r, "internet", &["public_resource_policy"]);
                                findings.push(posture_finding(
                                    Domain::Data,
                                    "dynamodb_public_resource_policy",
                                    &format!("DynamoDB table resource policy is public: {name}"),
                                    "critical",
                                    "T1530",
                                    &c_encrypt,
                                    target,
                                    0.94,
                                    &format!("Table '{name}' ({r}) resource policy grants wildcard access."),
                                    "Remove Principal \"*\"; scope to specific IAM roles and source VPC endpoints.",
                                    Evidence::new().with("table", name.clone()),
                                    "dynamodb_table",
                                    &name,
                                    r,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── API Gateway (REST + HTTP) exposure ────────────────────────────────────────

async fn scan_apigateway(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_apigateway {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_api = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }

        // REST APIs (v1) — public resource policy
        let apigw = aws_sdk_apigateway::Client::from_conf(
            aws_sdk_apigateway::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut rest_count = 0usize;
        let mut rpag = apigw.get_rest_apis().into_paginator().send();
        while let Some(page) = rpag.next().await {
            let Ok(page) = page else { break };
            for api in page.items() {
                if rest_count >= opts.max_resources_per_service / 2 {
                    break;
                }
                rest_count += 1;
                let id = api.id().unwrap_or("").to_string();
                let name = api.name().unwrap_or("").to_string();
                let node_id = format!("aws:apigateway:rest:{id}");
                graph.upsert(&node_id, "apigateway_rest", r, "internal", &[]);

                if let Ok(api_detail) = apigw.get_rest_api().rest_api_id(&id).send().await {
                    if let Some(raw) = api_detail.policy() {
                        if !raw.is_empty() {
                            let lower = raw.to_ascii_lowercase();
                            if lower.contains("\"principal\":\"*\"")
                                || lower.contains("\"aws\":\"*\"")
                            {
                                graph.upsert(&node_id, "apigateway_rest", r, "internet", &["public_policy"]);
                                findings.push(posture_finding(
                                    Domain::Network,
                                    "apigateway_rest_public_policy",
                                    &format!("API Gateway REST API public policy: {name}"),
                                    "critical",
                                    "T1190",
                                    &c_api,
                                    target,
                                    0.93,
                                    &format!("REST API '{name}' ({id}, {r}) resource policy allows wildcard invoke."),
                                    "Remove public Principal; require IAM auth, Cognito, or Lambda authorizers.",
                                    Evidence::new().with("api_id", id.clone()).with("api_name", name.clone()),
                                    "apigateway_rest",
                                    &id,
                                    r,
                                ));
                            }
                        }
                    }
                }
            }
        }

        // HTTP/WebSocket APIs (v2) — routes without authorization
        let apigwv2 = aws_sdk_apigatewayv2::Client::from_conf(
            aws_sdk_apigatewayv2::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut v2_count = 0usize;
        if let Ok(apis_page) = apigwv2.get_apis().send().await {
            for api in apis_page.items() {
                if v2_count >= opts.max_resources_per_service / 2 {
                    break;
                }
                v2_count += 1;
                let id = api.api_id().unwrap_or("").to_string();
                let name = api.name().unwrap_or("").to_string();
                let endpoint = api.api_endpoint().unwrap_or("").to_string();
                let node_id = format!("aws:apigatewayv2:{id}");
                graph.upsert(&node_id, "apigateway_http", r, "internet", &[]);

                let mut open_routes = 0u32;
                if let Ok(routes_page) = apigwv2.get_routes().api_id(&id).send().await {
                    for route in routes_page.items() {
                        let auth = route
                            .authorization_type()
                            .map(|a| a.as_str())
                            .unwrap_or("NONE");
                        if auth.eq_ignore_ascii_case("NONE") {
                            open_routes += 1;
                        }
                    }
                }
                if open_routes > 0 {
                    graph.upsert(&node_id, "apigateway_http", r, "internet", &["open_routes"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "apigateway_http_no_auth_routes",
                        &format!("API Gateway HTTP API has unauthenticated routes: {name}"),
                        "high",
                        "T1190",
                        &c_api,
                        target,
                        0.9,
                        &format!(
                            "HTTP API '{name}' ({id}, {r}) exposes {open_routes} route(s) with AuthorizationType=NONE at {endpoint}."
                        ),
                        "Add JWT/Cognito/IAM authorizers; disable unused routes and the default execute-api endpoint if not needed.",
                        Evidence::new()
                            .with("api_id", id.clone())
                            .with("open_routes", open_routes)
                            .with("api_endpoint", endpoint),
                        "apigateway_http",
                        &id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── OpenSearch / Elasticsearch domain exposure ──────────────────────────────

async fn scan_opensearch(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_opensearch {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_os = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let os = aws_sdk_opensearch::Client::from_conf(
            aws_sdk_opensearch::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let domains = match os.list_domain_names().send().await {
            Ok(d) => d.domain_names().to_vec(),
            Err(_) => continue,
        };
        let mut count = 0usize;
        for entry in domains {
            if count >= opts.max_resources_per_service {
                break;
            }
            count += 1;
            let name = entry.domain_name().unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let Ok(desc) = os.describe_domain().domain_name(&name).send().await else {
                continue;
            };
            let Some(status) = desc.domain_status() else { continue };
            let node_id = format!("aws:opensearch:{name}");
            let in_vpc = status.vpc_options().is_some();
            let exposure = if in_vpc { "internal" } else { "internet" };
            graph.upsert(&node_id, "opensearch_domain", r, exposure, &[]);

            if !in_vpc {
                graph.upsert(&node_id, "opensearch_domain", r, "internet", &["public_endpoint"]);
                findings.push(posture_finding(
                    Domain::Data,
                    "opensearch_public_domain",
                    &format!("OpenSearch domain without VPC isolation: {name}"),
                    "critical",
                    "T1530",
                    &c_os,
                    target,
                    0.94,
                    &format!("Domain '{name}' ({r}) is not deployed inside a VPC — endpoint is internet-reachable."),
                    "Redeploy into a VPC with restrictive security groups; use fine-grained access control.",
                    Evidence::new().with("domain", name.clone()),
                    "opensearch_domain",
                    &name,
                    r,
                ));
            }

            if status
                .encryption_at_rest_options()
                .and_then(|e| e.enabled())
                != Some(true)
            {
                findings.push(posture_finding(
                    Domain::Data,
                    "opensearch_no_encryption_at_rest",
                    &format!("OpenSearch domain without encryption at rest: {name}"),
                    "high",
                    "T1530",
                    &c_os,
                    target,
                    0.88,
                    &format!("Domain '{name}' ({r}) does not encrypt data at rest."),
                    "Enable encryption at rest with a CMK on all OpenSearch domains.",
                    Evidence::new().with("domain", name.clone()),
                    "opensearch_domain",
                    &name,
                    r,
                ));
            }

            if let Some(opts_ep) = status.domain_endpoint_options() {
                if opts_ep.enforce_https() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Network,
                        "opensearch_no_https_enforced",
                        &format!("OpenSearch domain allows cleartext HTTPS: {name}"),
                        "high",
                        "T1040",
                        &c_os,
                        target,
                        0.86,
                        &format!("Domain '{name}' ({r}) does not enforce HTTPS on the endpoint."),
                        "Set enforce_https=true and use a modern TLSSecurityPolicy.",
                        Evidence::new().with("domain", name.clone()),
                        "opensearch_domain",
                        &name,
                        r,
                    ));
                }
            }

            if let Some(pol) = status.access_policies() {
                let lower = pol.to_ascii_lowercase();
                if lower.contains("\"principal\":\"*\"")
                    || lower.contains("\"aws\":\"*\"")
                {
                    graph.upsert(&node_id, "opensearch_domain", r, "internet", &["public_access_policy"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "opensearch_public_access_policy",
                        &format!("OpenSearch domain access policy is public: {name}"),
                        "critical",
                        "T1530",
                        &c_os,
                        target,
                        0.95,
                        &format!("Domain '{name}' ({r}) access policy grants wildcard principals."),
                        "Replace with IP-based or IAM fine-grained policies; never use Principal \"*\".",
                        Evidence::new().with("domain", name.clone()),
                        "opensearch_domain",
                        &name,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── CloudFront edge delivery posture (global, us-east-1 API) ────────────────

fn s3_origin_missing_oac(origin: &aws_sdk_cloudfront::types::Origin) -> bool {
    let domain = origin.domain_name().to_ascii_lowercase();
    if !domain.contains(".s3.")
        && !domain.contains(".s3-website.")
        && !domain.contains(".s3.amazonaws.com")
    {
        return false;
    }
    let oac = origin
        .origin_access_control_id()
        .map(str::trim)
        .unwrap_or("");
    if !oac.is_empty() {
        return false;
    }
    let oai = origin
        .s3_origin_config()
        .map(|s| s.origin_access_identity().trim())
        .unwrap_or("");
    oai.is_empty()
}

async fn scan_cloudfront(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_cloudfront {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_edge = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let cf = aws_sdk_cloudfront::Client::from_conf(
        aws_sdk_cloudfront::config::Builder::from(sdk)
            .region(Region::new("us-east-1"))
            .build(),
    );
    let mut count = 0usize;
    let mut pag = cf.list_distributions().into_paginator().send();
    while let Some(page) = pag.next().await {
        let Ok(page) = page else { break };
        let Some(list) = page.distribution_list() else { continue };
        for dist in list.items() {
            if count >= opts.max_resources_per_service {
                break;
            }
            if !dist.enabled() {
                continue;
            }
            count += 1;
            let id = dist.id().to_string();
            let domain = dist.domain_name().to_string();
            let node_id = format!("aws:cloudfront:{id}");
            graph.upsert(&node_id, "cloudfront_distribution", "global", "internet", &[]);

            if let Some(origins) = dist.origins() {
                for origin in origins.items() {
                    let odom = origin.domain_name().to_string();
                    if !odom.is_empty() {
                        graph.link(&node_id, &format!("origin:{odom}"), "origin");
                    }
                    if s3_origin_missing_oac(origin) {
                        graph.upsert(
                            &node_id,
                            "cloudfront_distribution",
                            "global",
                            "internet",
                            &["s3_origin_no_oac"],
                        );
                        findings.push(posture_finding(
                            Domain::Data,
                            "cloudfront_s3_origin_no_oac",
                            &format!("CloudFront S3 origin without OAC/OAI: {domain}"),
                            "critical",
                            "T1530",
                            &c_edge,
                            target,
                            0.94,
                            &format!(
                                "Distribution '{domain}' ({id}) origin '{odom}' points at S3 without Origin Access Control — bucket may be directly reachable bypassing CloudFront auth."
                            ),
                            "Attach an Origin Access Control (OAC) and lock the S3 bucket policy to the distribution only.",
                            Evidence::new()
                                .with("distribution_id", id.clone())
                                .with("distribution_domain", domain.clone())
                                .with("origin_domain", odom),
                            "cloudfront_distribution",
                            &id,
                            "global",
                        ));
                    }
                }
            }

            if let Some(behavior) = dist.default_cache_behavior() {
                let vpp = behavior.viewer_protocol_policy().as_str();
                if vpp.eq_ignore_ascii_case("allow-all") {
                    graph.upsert(
                        &node_id,
                        "cloudfront_distribution",
                        "global",
                        "internet",
                        &["allows_http"],
                    );
                    findings.push(posture_finding(
                        Domain::Network,
                        "cloudfront_allows_http",
                        &format!("CloudFront distribution allows cleartext HTTP: {domain}"),
                        "high",
                        "T1040",
                        &c_edge,
                        target,
                        0.9,
                        &format!(
                            "Distribution '{domain}' ({id}) default cache behavior uses ViewerProtocolPolicy=allow-all — credentials and session tokens may traverse HTTP."
                        ),
                        "Set ViewerProtocolPolicy to redirect-to-https or https-only on all cache behaviors.",
                        Evidence::new()
                            .with("distribution_id", id.clone())
                            .with("viewer_protocol_policy", vpp),
                        "cloudfront_distribution",
                        &id,
                        "global",
                    ));
                }
            }

            let waf = dist.web_acl_id().trim();
            if waf.is_empty() {
                findings.push(posture_finding(
                    Domain::Network,
                    "cloudfront_no_waf",
                    &format!("CloudFront distribution without WAF: {domain}"),
                    "medium",
                    "T1190",
                    &c_edge,
                    target,
                    0.82,
                    &format!(
                        "Distribution '{domain}' ({id}) has no AWS WAF web ACL attached — edge lacks OWASP/bot/rate-limit protection."
                    ),
                    "Associate a WAFv2 web ACL (CloudFront scope) with logging to a dedicated CloudWatch log group.",
                    Evidence::new()
                        .with("distribution_id", id.clone())
                        .with("distribution_domain", domain.clone()),
                    "cloudfront_distribution",
                    &id,
                    "global",
                ));
            }
        }
    }

    findings
}

// ─── Route53 DNS governance (global) ─────────────────────────────────────────

async fn scan_route53(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_route53 {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_dns = ComplianceRef {
        cis: "3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.DS-6",
        gdpr: "Art.32",
    };
    let r53 = aws_sdk_route53::Client::new(sdk);
    let mut public_zones: Vec<(String, String)> = Vec::new();
    let mut pag = r53.list_hosted_zones().into_paginator().send();
    while let Some(page) = pag.next().await {
        let Ok(page) = page else { break };
        for zone in page.hosted_zones() {
            if public_zones.len() >= opts.max_resources_per_service {
                break;
            }
            let private = zone.config().map(|c| c.private_zone()).unwrap_or(false);
            if private {
                continue;
            }
            let id = zone.id().to_string();
            let name = zone.name().trim_end_matches('.').to_string();
            let node_id = format!("aws:route53:{id}");
            graph.upsert(&node_id, "route53_public_zone", "global", "internet", &[]);
            public_zones.push((id.clone(), name.clone()));

            if let Ok(dnssec) = r53.get_dnssec().hosted_zone_id(&id).send().await {
                let signing = dnssec.key_signing_keys().iter().any(|k| {
                    k.status()
                        .is_some_and(|s| s.eq_ignore_ascii_case("ACTIVE"))
                });
                if !signing {
                    findings.push(posture_finding(
                        Domain::Network,
                        "route53_dnssec_disabled",
                        &format!("Public Route53 zone without DNSSEC: {name}"),
                        "high",
                        "T1557",
                        &c_dns,
                        target,
                        0.88,
                        &format!(
                            "Public hosted zone '{name}' ({id}) has no active DNSSEC key signing keys — vulnerable to DNS hijacking/cache poisoning at resolvers."
                        ),
                        "Enable DNSSEC signing on the hosted zone and establish DS records at the registrar.",
                        Evidence::new().with("zone_id", id).with("zone_name", name.clone()),
                        "route53_zone",
                        &name,
                        "global",
                    ));
                }
            }
        }
    }

    if !public_zones.is_empty() {
        let mut logged_zones = BTreeSet::new();
        let mut qpag = r53.list_query_logging_configs().into_paginator().send();
        while let Some(page) = qpag.next().await {
            let Ok(page) = page else { break };
            for cfg in page.query_logging_configs() {
                logged_zones.insert(cfg.hosted_zone_id().to_string());
            }
        }
        for (id, name) in public_zones {
            let short_id = id.trim_start_matches("/hostedzone/");
            if logged_zones.contains(short_id) {
                continue;
            }
            findings.push(posture_finding(
                Domain::Governance,
                "route53_query_logging_disabled",
                &format!("Route53 query logging disabled: {name}"),
                "medium",
                "T1562.002",
                &c_dns,
                target,
                0.8,
                &format!(
                    "Public hosted zone '{name}' ({id}) has no Route53 Resolver query logging — DNS exfiltration and tunneling may go undetected."
                ),
                "Create a query logging configuration shipping to a dedicated, encrypted CloudWatch log group with alerting.",
                Evidence::new()
                    .with("zone_id", id.clone())
                    .with("zone_name", name.clone()),
                "route53_zone",
                &name,
                "global",
            ));
        }
    }

    findings
}

// ─── EventBridge event bus policy posture (regional) ─────────────────────────

async fn scan_eventbridge(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_eventbridge {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_bus = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let eb = aws_sdk_eventbridge::Client::from_conf(
            aws_sdk_eventbridge::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let buses = match eb.list_event_buses().send().await {
            Ok(b) => b.event_buses().to_vec(),
            Err(_) => continue,
        };
        let mut bus_count = 0usize;
        for bus in buses {
            if bus_count >= opts.max_resources_per_service / 4 {
                break;
            }
            bus_count += 1;
            let name = bus.name().unwrap_or("default").to_string();
            let arn = bus.arn().unwrap_or("").to_string();
            let node_id = format!("aws:eventbridge:{r}:{name}");
            graph.upsert(&node_id, "eventbridge_bus", r, "internal", &[]);

            let Ok(desc) = eb.describe_event_bus().name(&name).send().await else {
                continue;
            };
            if let Some(raw) = desc.policy() {
                let lower = raw.to_ascii_lowercase();
                if lower.contains("\"principal\":\"*\"")
                    || lower.contains("\"aws\":\"*\"")
                    || lower.contains("\"principal\":{\"aws\":\"*\"}")
                {
                    graph.upsert(&node_id, "eventbridge_bus", r, "internet", &["public_policy"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "eventbridge_public_bus_policy",
                        &format!("EventBridge bus allows wildcard principal: {name}"),
                        "critical",
                        "T1190",
                        &c_bus,
                        target,
                        0.93,
                        &format!(
                            "Event bus '{name}' ({r}) resource policy grants wildcard PutEvents/Invoke access — cross-account event injection risk."
                        ),
                        "Remove Principal \"*\"; scope to specific account IDs and use aws:SourceArn conditions.",
                        Evidence::new().with("event_bus", name.clone()).with("event_bus_arn", arn),
                        "eventbridge_bus",
                        &name,
                        r,
                    ));
                }
            }

            // Rules forwarding to Lambda — link graph for toxic-path correlation
            if let Ok(rules_page) = eb.list_rules().event_bus_name(&name).send().await {
                for rule in rules_page.rules().iter().take(50) {
                    let rule_name = rule.name().unwrap_or("").to_string();
                    if rule_name.is_empty() {
                        continue;
                    }
                    if let Ok(targets) = eb
                        .list_targets_by_rule()
                        .rule(&rule_name)
                        .event_bus_name(&name)
                        .send()
                        .await
                    {
                        for t in targets.targets() {
                            let lambda_arn = t.arn();
                            if lambda_arn.contains(":lambda:") {
                                graph.link(&node_id, lambda_arn, "targets_lambda");
                                graph.upsert(lambda_arn, "lambda_function", r, "internal", &[]);
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── WAFv2 edge + regional protection posture ──────────────────────────────────

async fn scan_wafv2_acl_scope(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
    scope: aws_sdk_wafv2::types::Scope,
    region: &str,
    count: &mut usize,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if *count >= opts.max_resources_per_service {
        return findings;
    }
    let c_waf = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let reg = if scope == aws_sdk_wafv2::types::Scope::Cloudfront {
        "us-east-1".to_string()
    } else {
        region.to_string()
    };
    let waf = aws_sdk_wafv2::Client::from_conf(
        aws_sdk_wafv2::config::Builder::from(sdk)
            .region(Region::new(reg.clone()))
            .build(),
    );
    let scope_label = if scope == aws_sdk_wafv2::types::Scope::Cloudfront {
        "cloudfront"
    } else {
        "regional"
    };
    let mut marker: Option<String> = None;
    loop {
        if *count >= opts.max_resources_per_service {
            break;
        }
        let mut req = waf.list_web_acls().scope(scope.clone());
        if let Some(m) = &marker {
            req = req.next_marker(m);
        }
        let Ok(page) = req.send().await else { break };
        for acl in page.web_acls() {
            if *count >= opts.max_resources_per_service {
                break;
            }
            *count += 1;
            let name = acl.name().unwrap_or("").to_string();
            let id = acl.id().unwrap_or("").to_string();
            let arn = acl.arn().unwrap_or("").to_string();
            if name.is_empty() || arn.is_empty() {
                continue;
            }
            let node_id = format!("aws:wafv2:{scope_label}:{name}");
            graph.upsert(&node_id, "wafv2_web_acl", &reg, "internal", &[]);

            let has_logging = waf
                .get_logging_configuration()
                .resource_arn(&arn)
                .send()
                .await
                .is_ok();
            if !has_logging {
                findings.push(posture_finding(
                    Domain::Governance,
                    "wafv2_no_logging",
                    &format!("WAFv2 web ACL without logging ({scope_label}): {name}"),
                    "medium",
                    "T1562.002",
                    &c_waf,
                    target,
                    0.84,
                    &format!(
                        "Web ACL '{name}' ({scope_label}, {reg}) has no logging configuration — blocked attacks leave no forensic trail."
                    ),
                    "Enable WAF logging to S3, CloudWatch Logs, or Firehose with at least 90-day retention.",
                    Evidence::new()
                        .with("web_acl", name.clone())
                        .with("scope", scope_label)
                        .with("arn", arn.clone()),
                    "wafv2_web_acl",
                    &name,
                    &reg,
                ));
            }

            if let Ok(detail) = waf
                .get_web_acl()
                .name(&name)
                .id(&id)
                .scope(scope.clone())
                .send()
                .await
            {
                let rule_count = detail
                    .web_acl()
                    .map(|w| w.rules().len())
                    .unwrap_or(0);
                if rule_count == 0 {
                    graph.upsert(&node_id, "wafv2_web_acl", &reg, "internet", &["no_rules"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "wafv2_no_rules",
                        &format!("WAFv2 web ACL has zero rules ({scope_label}): {name}"),
                        "high",
                        "T1190",
                        &c_waf,
                        target,
                        0.9,
                        &format!(
                            "Web ACL '{name}' ({scope_label}, {reg}) defines no rules — attached resources get pass-through protection only."
                        ),
                        "Add AWSManagedRules or custom rules; never rely on default Allow action alone.",
                        Evidence::new()
                            .with("web_acl", name)
                            .with("scope", scope_label)
                            .with("rule_count", rule_count),
                        "wafv2_web_acl",
                        &id,
                        &reg,
                    ));
                }
            }
        }
        marker = page.next_marker().map(str::to_string);
        if marker.is_none() {
            break;
        }
    }
    findings
}

async fn scan_wafv2(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_wafv2 {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let mut count = 0usize;
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        findings.extend(
            scan_wafv2_acl_scope(
                sdk,
                opts,
                target,
                graph,
                aws_sdk_wafv2::types::Scope::Regional,
                r,
                &mut count,
            )
            .await,
        );
    }
    findings.extend(
        scan_wafv2_acl_scope(
            sdk,
            opts,
            target,
            graph,
            aws_sdk_wafv2::types::Scope::Cloudfront,
            "global",
            &mut count,
        )
        .await,
    );
    findings
}

// ─── CloudWatch Logs retention & resource-policy posture ───────────────────────

async fn scan_cloudwatch_logs(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_cloudwatch_logs {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_logs = ComplianceRef {
        cis: "3.1",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.2.1",
        nist: "PR.PT-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let logs = aws_sdk_cloudwatchlogs::Client::from_conf(
            aws_sdk_cloudwatchlogs::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut lg_count = 0usize;
        let mut pag = logs.describe_log_groups().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for lg in page.log_groups() {
                if lg_count >= opts.max_resources_per_service {
                    break;
                }
                lg_count += 1;
                let name = lg.log_group_name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let node_id = format!("aws:logs:{name}");
                graph.upsert(&node_id, "cloudwatch_log_group", r, "internal", &[]);

                if lg.retention_in_days().is_none() {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "logs_no_retention",
                        &format!("CloudWatch log group without retention: {name}"),
                        "medium",
                        "T1562.002",
                        &c_logs,
                        target,
                        0.82,
                        &format!(
                            "Log group '{name}' ({r}) has no retention policy — logs persist indefinitely, increasing breach blast radius and cost."
                        ),
                        "Set retention (30–365 days) on all log groups; ship security logs to a centralized immutable store.",
                        Evidence::new().with("log_group", name.clone()),
                        "cloudwatch_log_group",
                        &name,
                        r,
                    ));
                }
            }
        }

        if let Ok(pols) = logs.describe_resource_policies().send().await {
            for pol in pols.resource_policies() {
                let Some(raw) = pol.policy_document() else { continue };
                let lower = raw.to_ascii_lowercase();
                if lower.contains("\"principal\":\"*\"")
                    || lower.contains("\"aws\":\"*\"")
                    || lower.contains("\"principal\":{\"aws\":\"*\"}")
                {
                    let pname = pol.policy_name().unwrap_or("").to_string();
                    graph.upsert(
                        &format!("aws:logs:policy:{pname}"),
                        "cloudwatch_resource_policy",
                        r,
                        "internet",
                        &["public_policy"],
                    );
                    findings.push(posture_finding(
                        Domain::Governance,
                        "logs_public_resource_policy",
                        &format!("CloudWatch Logs resource policy allows wildcard: {pname}"),
                        "high",
                        "T1530",
                        &c_logs,
                        target,
                        0.88,
                        &format!(
                            "Account/region {r} CloudWatch Logs resource policy '{pname}' grants wildcard principals — cross-account log injection or exfiltration."
                        ),
                        "Remove Principal \"*\"; scope log group access to specific roles and source accounts.",
                        Evidence::new().with("policy_name", pname.clone()),
                        "cloudwatch_resource_policy",
                        &pname,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── Redshift data warehouse exposure ────────────────────────────────────────

async fn scan_redshift(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_redshift {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let rs = aws_sdk_redshift::Client::from_conf(
            aws_sdk_redshift::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = rs.describe_clusters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for cluster in page.clusters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = cluster.cluster_identifier().unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                let node_id = format!("aws:redshift:{id}");
                let exposure = if cluster.publicly_accessible() == Some(true) {
                    "internet"
                } else {
                    "internal"
                };
                graph.upsert(&node_id, "redshift_cluster", r, exposure, &[]);

                if cluster.publicly_accessible() == Some(true) {
                    graph.upsert(&node_id, "redshift_cluster", r, "internet", &["public_warehouse"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "redshift_publicly_accessible",
                        &format!("Redshift cluster publicly accessible: {id}"),
                        "critical",
                        "T1190",
                        &c_public,
                        target,
                        0.95,
                        &format!(
                            "Redshift cluster '{id}' ({r}) has publicly_accessible=true — analytics warehouse reachable from the internet."
                        ),
                        "Disable public access; use VPC endpoints, PrivateLink, or VPN-only connectivity.",
                        Evidence::new()
                            .with("cluster", id.clone())
                            .with("endpoint", cluster.endpoint().and_then(|e| e.address()).unwrap_or("")),
                        "redshift_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.encrypted() == Some(false) {
                    graph.upsert(&node_id, "redshift_cluster", r, exposure, &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "redshift_unencrypted",
                        &format!("Redshift cluster without encryption: {id}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.9,
                        &format!("Redshift cluster '{id}' ({r}) is not encrypted at rest."),
                        "Enable encryption at rest with a CMK; migrate to an encrypted cluster.",
                        Evidence::new().with("cluster", id.clone()),
                        "redshift_cluster",
                        &id,
                        r,
                    ));
                }

                let audit_on = rs
                    .describe_logging_status()
                    .cluster_identifier(&id)
                    .send()
                    .await
                    .ok()
                    .and_then(|l| l.logging_enabled())
                    .unwrap_or(false);
                if !audit_on {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "redshift_audit_logging_disabled",
                        &format!("Redshift audit logging disabled: {id}"),
                        "medium",
                        "T1562.002",
                        &c_encrypt,
                        target,
                        0.83,
                        &format!(
                            "Redshift cluster '{id}' ({r}) does not ship audit logs to S3/CloudWatch — SQL exfiltration may go undetected."
                        ),
                        "Enable Redshift audit logging to a dedicated, encrypted, retention-bounded log destination.",
                        Evidence::new().with("cluster", id.clone()),
                        "redshift_cluster",
                        &id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── Amazon DocumentDB (Mongo-compatible) posture ────────────────────────────

async fn scan_documentdb(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_documentdb {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let docdb = aws_sdk_docdb::Client::from_conf(
            aws_sdk_docdb::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = docdb.describe_db_clusters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for cluster in page.db_clusters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = cluster.db_cluster_identifier().unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                let node_id = format!("aws:documentdb:{id}");
                graph.upsert(&node_id, "documentdb_cluster", r, "internal", &[]);

                if cluster.storage_encrypted() == Some(false) {
                    graph.upsert(&node_id, "documentdb_cluster", r, "internal", &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "documentdb_unencrypted",
                        &format!("DocumentDB cluster without encryption: {id}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.89,
                        &format!("DocumentDB cluster '{id}' ({r}) does not encrypt storage at rest."),
                        "Enable storage encryption with a CMK on all DocumentDB clusters.",
                        Evidence::new().with("cluster", id.clone()),
                        "documentdb_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.backup_retention_period() == Some(0) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "documentdb_no_backups",
                        &format!("DocumentDB cluster without backups: {id}"),
                        "medium",
                        "T1485",
                        &c_encrypt,
                        target,
                        0.8,
                        &format!(
                            "DocumentDB cluster '{id}' ({r}) has backup_retention_period=0 — no point-in-time recovery after ransomware."
                        ),
                        "Set backup retention ≥ 7 days; test restore procedures regularly.",
                        Evidence::new().with("cluster", id.clone()),
                        "documentdb_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster
                    .enabled_cloudwatch_logs_exports()
                    .is_empty()
                {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "documentdb_no_audit_logs",
                        &format!("DocumentDB cluster without CloudWatch audit logs: {id}"),
                        "medium",
                        "T1562.002",
                        &c_encrypt,
                        target,
                        0.81,
                        &format!(
                            "DocumentDB cluster '{id}' ({r}) exports no CloudWatch log types — audit/Profiler logs disabled."
                        ),
                        "Enable audit and profiler log exports to CloudWatch Logs with retention and alerting.",
                        Evidence::new().with("cluster", id.clone()),
                        "documentdb_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.deletion_protection() == Some(false) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "documentdb_no_deletion_protection",
                        &format!("DocumentDB cluster without deletion protection: {id}"),
                        "low",
                        "T1485",
                        &c_encrypt,
                        target,
                        0.75,
                        &format!("DocumentDB cluster '{id}' ({r}) can be deleted in a single API call — ransomware/insider risk."),
                        "Enable deletion_protection on production DocumentDB clusters.",
                        Evidence::new().with("cluster", id.clone()),
                        "documentdb_cluster",
                        &id,
                        r,
                    ));
                }
            }
        }

        let mut inst_count = 0usize;
        let mut ipag = docdb.describe_db_instances().into_paginator().send();
        while let Some(page) = ipag.next().await {
            let Ok(page) = page else { break };
            for inst in page.db_instances() {
                if inst_count >= opts.max_resources_per_service {
                    break;
                }
                inst_count += 1;
                if inst.publicly_accessible() != Some(true) {
                    continue;
                }
                let id = inst.db_instance_identifier().unwrap_or("").to_string();
                let cluster_id = inst.db_cluster_identifier().unwrap_or("").to_string();
                let node_id = format!("aws:documentdb:instance:{id}");
                graph.upsert(&node_id, "documentdb_instance", r, "internet", &["public_docdb"]);
                findings.push(posture_finding(
                    Domain::Data,
                    "documentdb_publicly_accessible",
                    &format!("DocumentDB instance publicly accessible: {id}"),
                    "critical",
                    "T1190",
                    &c_public,
                    target,
                    0.94,
                    &format!(
                        "DocumentDB instance '{id}' (cluster '{cluster_id}', {r}) has publicly_accessible=true."
                    ),
                    "Set publicly_accessible=false; restrict to private subnets and security groups.",
                    Evidence::new()
                        .with("instance", id.clone())
                        .with("cluster", cluster_id),
                    "documentdb_instance",
                    &id,
                    r,
                ));
            }
        }
    }

    findings
}

// ─── Neptune graph database posture ────────────────────────────────────────────

async fn scan_neptune(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_neptune {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let nep = aws_sdk_neptune::Client::from_conf(
            aws_sdk_neptune::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = nep.describe_db_clusters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for cluster in page.db_clusters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = cluster.db_cluster_identifier().unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                let node_id = format!("aws:neptune:{id}");
                graph.upsert(&node_id, "neptune_cluster", r, "internal", &[]);

                if cluster.storage_encrypted() == Some(false) {
                    graph.upsert(&node_id, "neptune_cluster", r, "internal", &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "neptune_unencrypted",
                        &format!("Neptune cluster without encryption: {id}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.9,
                        &format!("Neptune cluster '{id}' ({r}) does not encrypt storage at rest."),
                        "Enable storage encryption with a CMK on all Neptune clusters.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.backup_retention_period() == Some(0) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "neptune_no_backups",
                        &format!("Neptune cluster without backups: {id}"),
                        "medium",
                        "T1485",
                        &c_encrypt,
                        target,
                        0.81,
                        &format!(
                            "Neptune cluster '{id}' ({r}) has backup_retention_period=0 — no point-in-time recovery after ransomware."
                        ),
                        "Set backup retention ≥ 7 days; test restore procedures regularly.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.enabled_cloudwatch_logs_exports().is_empty() {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "neptune_no_audit_logs",
                        &format!("Neptune cluster without CloudWatch audit logs: {id}"),
                        "medium",
                        "T1562.002",
                        &c_encrypt,
                        target,
                        0.82,
                        &format!(
                            "Neptune cluster '{id}' ({r}) exports no CloudWatch log types — Gremlin/audit logs disabled."
                        ),
                        "Enable audit and slow-query log exports to CloudWatch Logs with retention and alerting.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.deletion_protection() == Some(false) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "neptune_no_deletion_protection",
                        &format!("Neptune cluster without deletion protection: {id}"),
                        "low",
                        "T1485",
                        &c_encrypt,
                        target,
                        0.76,
                        &format!("Neptune cluster '{id}' ({r}) can be deleted in a single API call — ransomware/insider risk."),
                        "Enable deletion_protection on production Neptune clusters.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.iam_database_authentication_enabled() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Identity,
                        "neptune_no_iam_auth",
                        &format!("Neptune cluster without IAM DB authentication: {id}"),
                        "medium",
                        "T1078.004",
                        &c_encrypt,
                        target,
                        0.78,
                        &format!(
                            "Neptune cluster '{id}' ({r}) does not enforce IAM database authentication — static credentials may persist."
                        ),
                        "Enable IAM DB authentication and rotate away from static master passwords.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }
            }
        }

        let mut inst_count = 0usize;
        let mut ipag = nep.describe_db_instances().into_paginator().send();
        while let Some(page) = ipag.next().await {
            let Ok(page) = page else { break };
            for inst in page.db_instances() {
                if inst_count >= opts.max_resources_per_service {
                    break;
                }
                inst_count += 1;
                if inst.publicly_accessible() != Some(true) {
                    continue;
                }
                let id = inst.db_instance_identifier().unwrap_or("").to_string();
                let cluster_id = inst.db_cluster_identifier().unwrap_or("").to_string();
                let node_id = format!("aws:neptune:instance:{id}");
                graph.upsert(&node_id, "neptune_instance", r, "internet", &["public_graph"]);
                graph.upsert(
                    &format!("aws:neptune:{cluster_id}"),
                    "neptune_cluster",
                    r,
                    "internet",
                    &["public_graph"],
                );
                findings.push(posture_finding(
                    Domain::Data,
                    "neptune_publicly_accessible",
                    &format!("Neptune instance publicly accessible: {id}"),
                    "critical",
                    "T1190",
                    &c_public,
                    target,
                    0.95,
                    &format!(
                        "Neptune instance '{id}' (cluster '{cluster_id}', {r}) has publicly_accessible=true — graph DB reachable from the internet."
                    ),
                    "Set publicly_accessible=false; use private subnets and security groups only.",
                    Evidence::new()
                        .with("instance", id.clone())
                        .with("cluster", cluster_id),
                    "neptune_instance",
                    &id,
                    r,
                ));
            }
        }
    }
    findings
}

// ─── MemoryDB (Redis-compatible) posture ───────────────────────────────────────

async fn scan_memorydb(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_memorydb {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_data = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let mdb = aws_sdk_memorydb::Client::from_conf(
            aws_sdk_memorydb::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = mdb.describe_clusters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for cluster in page.clusters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = cluster.name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let node_id = format!("aws:memorydb:{name}");
                graph.upsert(&node_id, "memorydb_cluster", r, "internal", &[]);
                if cluster.tls_enabled() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Data,
                        "memorydb_tls_disabled",
                        &format!("MemoryDB cluster without TLS in transit: {name}"),
                        "high",
                        "T1040",
                        &c_data,
                        target,
                        0.88,
                        &format!("MemoryDB cluster '{name}' ({r}) does not enforce TLS in transit."),
                        "Enable in-transit encryption (TLS) on all MemoryDB clusters.",
                        Evidence::new().with("cluster", name.clone()),
                        "memorydb_cluster",
                        &name,
                        r,
                    ));
                }
                if let Some(acl) = cluster.acl_name() {
                    if acl.eq_ignore_ascii_case("open-access") {
                            graph.upsert(&node_id, "memorydb_cluster", r, "internet", &["open_acl"]);
                            findings.push(posture_finding(
                                Domain::Network,
                                "memorydb_open_acl",
                                &format!("MemoryDB cluster uses open-access ACL: {name}"),
                                "critical",
                                "T1190",
                                &c_data,
                                target,
                                0.93,
                                &format!("MemoryDB cluster '{name}' ({r}) uses the open-access ACL — reachable beyond intended principals."),
                                "Replace open-access ACL with a restrictive custom ACL scoped to application security groups.",
                                Evidence::new().with("cluster", name.clone()).with("acl", acl),
                                "memorydb_cluster",
                                &name,
                                r,
                            ));
                    }
                }
            }
        }
    }
    findings
}

// ─── AWS Backup vault posture ──────────────────────────────────────────────────

async fn scan_backup(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_backup {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_backup = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.12.3.1",
        pci: "3.4.1",
        nist: "PR.IP-4",
        gdpr: "Art.32",
    };
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let backup = aws_sdk_backup::Client::from_conf(
            aws_sdk_backup::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = backup.list_backup_vaults().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for vault in page.backup_vault_list() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = vault.backup_vault_name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let node_id = format!("aws:backup:vault:{name}");
                graph.upsert(&node_id, "backup_vault", r, "internal", &[]);
                if vault.encryption_key_arn().is_none() {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "backup_vault_no_cmk",
                        &format!("AWS Backup vault without CMK encryption: {name}"),
                        "medium",
                        "T1530",
                        &c_backup,
                        target,
                        0.83,
                        &format!("Backup vault '{name}' ({r}) uses default encryption — no customer-managed key for backup isolation."),
                        "Configure a dedicated KMS CMK for the backup vault with least-privilege key policies.",
                        Evidence::new().with("vault", name.clone()),
                        "backup_vault",
                        &name,
                        r,
                    ));
                }
                if let Ok(pol) = backup.get_backup_vault_access_policy().backup_vault_name(&name).send().await {
                    if let Some(raw) = pol.policy() {
                        let lower = raw.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            graph.upsert(&node_id, "backup_vault", r, "internet", &["public_policy"]);
                            findings.push(posture_finding(
                                Domain::Governance,
                                "backup_vault_public_policy",
                                &format!("AWS Backup vault allows wildcard principal: {name}"),
                                "critical",
                                "T1530",
                                &c_backup,
                                target,
                                0.94,
                                &format!("Backup vault '{name}' ({r}) access policy grants wildcard access — cross-account backup exfiltration."),
                                "Remove Principal \"*\"; scope backup vault access to specific accounts and roles.",
                                Evidence::new().with("vault", name.clone()),
                                "backup_vault",
                                &name,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }
    findings
}

// ─── AWS Organizations / SCP governance ────────────────────────────────────────

async fn scan_organizations(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_organizations {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_org = ComplianceRef {
        cis: "1.1",
        soc2: "CC6.1",
        iso27001: "A.9.2.1",
        pci: "7.1.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };
    let org = aws_sdk_organizations::Client::new(sdk);
    let Ok(desc) = org.describe_organization().send().await else {
        return findings;
    };
    let org_id = desc
        .organization()
        .and_then(|o| o.id())
        .unwrap_or("")
        .to_string();
    if org_id.is_empty() {
        return findings;
    }
    graph.upsert(
        &format!("aws:organizations:{org_id}"),
        "aws_organization",
        "global",
        "internal",
        &[],
    );
    let roots = match org.list_roots().send().await {
        Ok(r) => r.roots().to_vec(),
        Err(_) => return findings,
    };
    for root in roots {
        let root_id = root.id().unwrap_or("").to_string();
        if root_id.is_empty() {
            continue;
        }
        let attached = match org
            .list_policies_for_target()
            .target_id(&root_id)
            .filter(aws_sdk_organizations::types::PolicyType::ServiceControlPolicy)
            .send()
            .await
        {
            Ok(a) => a.policies().to_vec(),
            Err(_) => continue,
        };
        for pol in attached {
            let pid = pol.id().unwrap_or("").to_string();
            let pname = pol.name().unwrap_or("").to_string();
            if pname.eq_ignore_ascii_case("FullAWSAccess") {
                findings.push(posture_finding(
                    Domain::Governance,
                    "organizations_full_aws_access_scp",
                    &format!("Organization root has FullAWSAccess SCP attached: {pname}"),
                    "high",
                    "T1078.004",
                    &c_org,
                    target,
                    0.87,
                    &format!(
                        "Root target in org {org_id} has the default FullAWSAccess SCP — no org-wide guardrail beyond account boundaries."
                    ),
                    "Attach restrictive SCPs at the root/OU level; use FullAWSAccess only as baseline and layer deny SCPs for sensitive services.",
                    Evidence::new().with("policy_id", pid.clone()).with("policy_name", pname.clone()),
                    "organizations_scp",
                    &pname,
                    "global",
                ));
            }
            if let Ok(doc) = org.describe_policy().policy_id(&pid).send().await {
                if let Some(content) = doc.policy().and_then(|p| p.content()) {
                    let lower = content.to_ascii_lowercase();
                    if lower.contains("\"effect\":\"allow\"")
                        && lower.contains("\"action\":\"*\"")
                        && lower.contains("\"resource\":\"*\"")
                        && !pname.eq_ignore_ascii_case("FullAWSAccess")
                    {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "organizations_permissive_scp",
                            &format!("Organization SCP allows wildcard actions: {pname}"),
                            "medium",
                            "T1078.004",
                            &c_org,
                            target,
                            0.8,
                            &format!("SCP '{pname}' attached to root {root_id} contains Allow * on * — weak org guardrail."),
                            "Replace wildcard Allow SCPs with explicit service/action allow-lists and deny SCPs for sensitive APIs.",
                            Evidence::new().with("policy_id", pid).with("policy_name", pname.clone()),
                            "organizations_scp",
                            &pname,
                            "global",
                        ));
                    }
                }
            }
        }
    }
    findings
}

// ─── Step Functions audit posture ──────────────────────────────────────────────

async fn scan_sfn(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_sfn {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_sfn = ComplianceRef {
        cis: "3.1",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.2.1",
        nist: "PR.PT-1",
        gdpr: "Art.32",
    };
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let sfn = aws_sdk_sfn::Client::from_conf(
            aws_sdk_sfn::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = sfn.list_state_machines().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for sm in page.state_machines() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = sm.name().to_string();
                let arn = sm.state_machine_arn().to_string();
                if name.is_empty() || arn.is_empty() {
                    continue;
                }
                let node_id = format!("aws:sfn:{name}");
                graph.upsert(&node_id, "sfn_state_machine", r, "internal", &[]);
                if let Ok(detail) = sfn.describe_state_machine().state_machine_arn(&arn).send().await {
                    let logging = detail
                        .logging_configuration()
                        .and_then(|l| l.level())
                        .map(|l| l.as_str())
                        .unwrap_or("OFF");
                    if logging.eq_ignore_ascii_case("OFF") {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "sfn_logging_disabled",
                            &format!("Step Functions state machine logging disabled: {name}"),
                            "medium",
                            "T1562.002",
                            &c_sfn,
                            target,
                            0.82,
                            &format!("State machine '{name}' ({r}) has CloudWatch logging level OFF — workflow abuse is invisible."),
                            "Enable logging at ERROR or ALL level to CloudWatch Logs with retention and alerting.",
                            Evidence::new().with("state_machine", name.clone()).with("arn", arn),
                            "sfn_state_machine",
                            &name,
                            r,
                        ));
                    }
                }
            }
        }
    }
    findings
}

// ─── IAM Identity Center (SSO) posture ───────────────────────────────────────

async fn scan_sso(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_sso {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_sso = ComplianceRef {
        cis: "1.1",
        soc2: "CC6.1",
        iso27001: "A.9.2.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };
    let sso = aws_sdk_ssoadmin::Client::from_conf(
        aws_sdk_ssoadmin::config::Builder::from(sdk)
            .region(Region::new("us-east-1"))
            .build(),
    );
    let instances = match sso.list_instances().send().await {
        Ok(i) => i.instances().to_vec(),
        Err(_) => return findings,
    };
    if instances.is_empty() {
        findings.push(posture_finding(
            Domain::Identity,
            "sso_not_configured",
            "IAM Identity Center (SSO) not enabled",
            "medium",
            "T1078.004",
            &c_sso,
            target,
            0.8,
            "No IAM Identity Center instance found — long-lived IAM users may proliferate without centralized federation.",
            "Enable IAM Identity Center; federate human access via IdP with MFA and short-lived credentials.",
            Evidence::new().check("list_instances", true, "empty"),
            "iam_identity_center",
            "*",
            "global",
        ));
        return findings;
    }
    for inst in instances.iter().take(3) {
        let arn = inst.instance_arn().unwrap_or("").to_string();
        if arn.is_empty() {
            continue;
        }
        graph.upsert(&format!("aws:sso:{arn}"), "iam_identity_center", "global", "internal", &[]);
        let psets = match sso
            .list_permission_sets()
            .instance_arn(&arn)
            .send()
            .await
        {
            Ok(p) => p.permission_sets().to_vec(),
            Err(_) => continue,
        };
        if psets.is_empty() {
            findings.push(posture_finding(
                Domain::Identity,
                "sso_no_permission_sets",
                "IAM Identity Center has no permission sets",
                "low",
                "T1078.004",
                &c_sso,
                target,
                0.75,
                "Identity Center instance exists but defines no permission sets — federation plane is unused.",
                "Define least-privilege permission sets and assign to accounts via SSO.",
                Evidence::new().with("instance_arn", arn.clone()),
                "iam_identity_center",
                &arn,
                "global",
            ));
        }
    }
    findings
}

// ─── Attack paths & compliance scoring ───────────────────────────────────────

fn finding_title(f: &Value) -> &str {
    f.get("title").and_then(Value::as_str).unwrap_or("")
}

fn finding_sev(f: &Value) -> String {
    f.get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info")
        .to_ascii_lowercase()
}

fn has_title_contains(findings: &[Value], needle: &str) -> bool {
    findings.iter().any(|f| finding_title(f).contains(needle))
}

fn attack_path_finding(
    title: &str,
    severity: &str,
    target: &str,
    steps: &[&str],
    mitre: &str,
    description: &str,
    toxic_combo: &str,
) -> Value {
    let ev = Evidence::new()
        .with("kind", "attack_path")
        .with("toxic_combination", toxic_combo)
        .with("steps", json!(steps))
        .check("correlation", true, format!("{}-step chain", steps.len()));
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        0.88,
        ev,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!("attack_path"));
        obj.insert("attack_path".to_string(), json!(true));
        obj.insert("steps".to_string(), json!(steps));
        obj.insert("toxic_combination".to_string(), json!(toxic_combo));
        obj.insert("domain".to_string(), json!("posture"));
    }
    f
}

fn synthesize_attack_paths(findings: &[Value], target: &str, account_id: Option<&str>) -> Vec<Value> {
    let mut paths = Vec::new();
    let acct = account_id.unwrap_or("the account");

    if has_title_contains(findings, "Root account MFA is not enabled")
        || has_title_contains(findings, "Root account has active access keys")
    {
        paths.push(attack_path_finding(
            "Toxic combination: root identity unprotected → full account takeover",
            "critical",
            target,
            &[
                "Phish or brute-force the root password / steal a root access key",
                "No MFA or long-lived root key blocks the attacker",
                "Assume unrestricted control of the entire AWS organisation",
            ],
            "T1078.004",
            &format!("The root identity of {acct} lacks MFA or has active access keys — a single credential theft yields irreversible account-wide compromise (Wiz-class toxic combination)."),
            "unprotected_root",
        ));
    }

    if has_title_contains(findings, "Public EC2 instance allows IMDSv1")
        && has_title_contains(findings, "AdministratorAccess")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public IMDSv1 + over-privileged instance role → cloud admin",
            "critical",
            target,
            &[
                "Exploit SSRF/RCE on a public-facing workload",
                "Query 169.254.169.254 (IMDSv1, no session token)",
                "Steal instance-role credentials with AdministratorAccess",
                "Full cloud control from an unauthenticated internet attacker",
            ],
            "T1552.005",
            "Internet-exposed compute with IMDSv1 and an admin-capable instance role creates a direct external-to-admin breach chain.",
            "imdsv1_admin_role",
        ));
    }

    if has_title_contains(findings, "S3 bucket world-readable")
        && has_title_contains(findings, "Stale IAM access key")
    {
        paths.push(attack_path_finding(
            "Toxic combination: stale long-lived keys + public data store",
            "high",
            target,
            &[
                "Discover or leak a stale IAM access key (no rotation)",
                "Enumerate publicly readable S3 buckets",
                "Exfiltrate sensitive data at scale",
            ],
            "T1530",
            &format!("Stale IAM keys combined with public S3 exposure in {acct} enables persistent, undetected data exfiltration."),
            "stale_keys_public_s3",
        ));
    }

    if has_title_contains(findings, "Security group open to the internet")
        && has_title_contains(findings, "Unencrypted EBS volume")
    {
        paths.push(attack_path_finding(
            "Toxic combination: internet-open management port + unencrypted disk",
            "high",
            target,
            &[
                "Scan for world-open SSH/RDP/database ports",
                "Compromise the instance via credential spray or known CVE",
                "Attach/detach unencrypted EBS snapshot for offline data theft",
            ],
            "T1190",
            "Wide-open security groups on sensitive ports paired with unencrypted EBS volumes amplify blast radius after initial access.",
            "open_sg_unencrypted_ebs",
        ));
    }

    if has_title_contains(findings, "Lambda function publicly invokable")
        && has_title_contains(findings, "AdministratorAccess")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public Lambda + admin execution role",
            "critical",
            target,
            &[
                "Invoke the publicly accessible Lambda function without authentication",
                "Abuse the over-privileged execution role via SSRF or code injection",
                "Pivot to full AWS account control",
            ],
            "T1190",
            &format!("Public Lambda with AdministratorAccess execution role in {acct} enables unauthenticated cloud takeover."),
            "public_lambda_admin_role",
        ));
    }

    if has_title_contains(findings, "RDS instance publicly accessible")
        && has_title_contains(findings, "RDS storage not encrypted")
    {
        paths.push(attack_path_finding(
            "Toxic combination: internet-exposed unencrypted database",
            "critical",
            target,
            &[
                "Discover publicly accessible RDS endpoint via port scan",
                "Brute-force or spray database credentials",
                "Exfiltrate plaintext data at rest and in transit",
            ],
            "T1190",
            &format!("Public RDS without encryption in {acct} — direct internet path to sensitive data."),
            "public_rds_unencrypted",
        ));
    }

    if has_title_contains(findings, "No CloudTrail trail configured")
        || has_title_contains(findings, "CloudTrail trail not actively logging")
    {
        paths.push(attack_path_finding(
            "Toxic combination: blind audit plane + any identity gap",
            "high",
            target,
            &[
                "Exploit any IAM/network misconfiguration for initial access",
                "Operate without CloudTrail visibility — defenders cannot correlate API abuse",
                "Maintain persistence while evading SIEM detection",
            ],
            "T1562.008",
            &format!("Missing or disabled CloudTrail in {acct} means toxic identity/network combinations may go undetected for weeks."),
            "blind_audit_plane",
        ));
    }

    if has_title_contains(findings, "Public EBS snapshot")
        && has_title_contains(findings, "Unencrypted EBS volume")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public snapshot + unencrypted volumes",
            "critical",
            target,
            &[
                "Locate a publicly shared EBS snapshot (group: all)",
                "Create a volume in an attacker account from the snapshot",
                "Mount offline and extract sensitive data without touching production",
            ],
            "T1530",
            &format!("Public EBS snapshots combined with unencrypted volumes in {acct} enable cross-account data theft."),
            "public_snapshot_unencrypted",
        ));
    }

    if has_title_contains(findings, "Access Analyzer")
        && (has_title_contains(findings, "GuardDuty not enabled")
            || has_title_contains(findings, "CloudTrail trail not actively logging"))
    {
        paths.push(attack_path_finding(
            "Toxic combination: proven external access + no runtime/audit detection",
            "critical",
            target,
            &[
                "Access Analyzer confirms an externally reachable resource",
                "GuardDuty/CloudTrail blind spots prevent detection of exploitation",
                "Attacker exfiltrates or pivots while SOC has no correlated signal",
            ],
            "T1562.008",
            &format!("Confirmed external-access findings in {acct} without GuardDuty/CloudTrail coverage — high-confidence breach with low detection probability."),
            "external_access_blind_detection",
        ));
    }

    if has_title_contains(findings, "EKS cluster public API endpoint")
        && has_title_contains(findings, "AdministratorAccess")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public Kubernetes API + cluster-admin-equivalent IAM",
            "critical",
            target,
            &[
                "Reach the public EKS API endpoint from the internet",
                "Authenticate with stolen/over-permissive IAM or leaked kubeconfig",
                "Deploy privileged workloads or steal cluster secrets",
            ],
            "T1190",
            &format!("Public EKS control plane in {acct} combined with admin-capable IAM enables full cluster takeover."),
            "public_eks_admin_iam",
        ));
    }

    if has_title_contains(findings, "Lambda Function URL without auth")
        && has_title_contains(findings, "Secrets Manager secret")
    {
        paths.push(attack_path_finding(
            "Toxic combination: unauthenticated Lambda URL + long-lived secrets",
            "high",
            target,
            &[
                "Invoke the public Lambda Function URL without credentials",
                "Abuse application logic to read environment or call Secrets Manager",
                "Harvest database/API credentials at scale",
            ],
            "T1552.001",
            "Public Lambda URLs in the same account as rotatable-but-exposed secrets amplify credential theft blast radius.",
            "public_lambda_url_secrets",
        ));
    }

    if has_title_contains(findings, "OpenSearch domain without VPC isolation")
        && has_title_contains(findings, "OpenSearch domain access policy is public")
    {
        paths.push(attack_path_finding(
            "Toxic combination: internet OpenSearch + wildcard access policy → full index exfiltration",
            "critical",
            target,
            &[
                "Reach the public OpenSearch endpoint from the internet",
                "Authenticate with anonymous/wildcard policy (no fine-grained control)",
                "Dump all indices — PII, logs, secrets indexed in Elasticsearch",
            ],
            "T1530",
            &format!("Public OpenSearch domain with wildcard access policy in {acct} — direct data warehouse breach."),
            "public_opensearch_wildcard",
        ));
    }

    if has_title_contains(findings, "API Gateway HTTP API has unauthenticated routes")
        && has_title_contains(findings, "Lambda function publicly invokable")
    {
        paths.push(attack_path_finding(
            "Toxic combination: open API Gateway routes → serverless entry chain",
            "critical",
            target,
            &[
                "Hit unauthenticated HTTP API routes (AuthorizationType=NONE)",
                "Chain to publicly invokable Lambda backends",
                "Abuse execution roles for lateral movement",
            ],
            "T1190",
            &format!("Unauthenticated API Gateway surface combined with public Lambda in {acct} creates a layered serverless attack chain."),
            "apigw_lambda_chain",
        ));
    }

    if has_title_contains(findings, "DynamoDB table resource policy is public")
        && has_title_contains(findings, "GuardDuty not enabled")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public DynamoDB + no threat detection",
            "critical",
            target,
            &[
                "Scan/exfiltrate a publicly policy-accessible DynamoDB table",
                "No GuardDuty anomaly detection on API abuse patterns",
                "Maintain persistent data theft without SOC alert",
            ],
            "T1530",
            &format!("Public DynamoDB resource policy in {acct} without GuardDuty — high-impact exfil with low detection."),
            "public_dynamodb_blind",
        ));
    }

    if has_title_contains(findings, "CloudFront S3 origin without OAC")
        && has_title_contains(findings, "S3 bucket world-readable")
    {
        paths.push(attack_path_finding(
            "Toxic combination: CloudFront origin bypass + public S3 bucket",
            "critical",
            target,
            &[
                "Bypass CloudFront and request the S3 origin directly (no OAC/OAI)",
                "Hit a world-readable bucket confirmed by S3 posture checks",
                "Exfiltrate objects without touching the CDN edge logs",
            ],
            "T1530",
            &format!("CloudFront distribution with unprotected S3 origin plus public bucket in {acct} — dual-path data exfiltration."),
            "cloudfront_s3_bypass",
        ));
    }

    if has_title_contains(findings, "CloudFront distribution allows cleartext HTTP")
        && has_title_contains(findings, "CloudFront distribution without WAF")
    {
        paths.push(attack_path_finding(
            "Toxic combination: HTTP-only CloudFront edge + no WAF",
            "high",
            target,
            &[
                "Intercept session tokens on cleartext HTTP cache behaviors",
                "No WAF to block credential stuffing, SSRF probes, or bot abuse",
                "Pivot into origin via stolen cookies or forged headers",
            ],
            "T1040",
            &format!("CloudFront edge in {acct} accepts HTTP and lacks WAF — classic session hijack + unfiltered attack surface."),
            "cloudfront_http_no_waf",
        ));
    }

    if has_title_contains(findings, "Public Route53 zone without DNSSEC")
        && has_title_contains(findings, "Access Analyzer")
    {
        paths.push(attack_path_finding(
            "Toxic combination: DNSSEC gap + proven external AWS access",
            "critical",
            target,
            &[
                "Poison or hijack DNS for a zone without DNSSEC validation",
                "Redirect users to attacker-controlled endpoints",
                "Leverage Access Analyzer–confirmed external resources for payload delivery",
            ],
            "T1557",
            &format!("Unsigned public DNS zone in {acct} combined with external-access findings — supply-chain grade redirect attack."),
            "dnssec_external_access",
        ));
    }

    if has_title_contains(findings, "EventBridge bus allows wildcard principal")
        && has_title_contains(findings, "Lambda function publicly invokable")
    {
        paths.push(attack_path_finding(
            "Toxic combination: open EventBridge bus → inject events → public Lambda",
            "critical",
            target,
            &[
                "PutEvents from any principal allowed by the bus policy",
                "Trigger rules targeting publicly invokable Lambda functions",
                "Execute arbitrary serverless code without authentication",
            ],
            "T1190",
            &format!("Wildcard EventBridge bus policy chained to public Lambda in {acct} — event-driven serverless takeover."),
            "eventbridge_lambda_injection",
        ));
    }

    if has_title_contains(findings, "Redshift cluster publicly accessible")
        && has_title_contains(findings, "GuardDuty not enabled")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public Redshift warehouse + no threat detection",
            "critical",
            target,
            &[
                "Connect to the internet-exposed Redshift endpoint",
                "Dump analytics/PII tables via SQL",
                "No GuardDuty to correlate anomalous data-plane API activity",
            ],
            "T1530",
            &format!("Public Redshift in {acct} without GuardDuty — high-value warehouse exfil with minimal SOC signal."),
            "public_redshift_blind",
        ));
    }

    if has_title_contains(findings, "WAFv2 web ACL has zero rules")
        && has_title_contains(findings, "Internet-facing ALB cleartext HTTP")
    {
        paths.push(attack_path_finding(
            "Toxic combination: pass-through WAF + cleartext internet ALB",
            "critical",
            target,
            &[
                "Hit the internet-facing ALB over unencrypted HTTP",
                "WAF ACL attached (if any) has zero rules — no OWASP/bot filtering",
                "Reach backend workloads without meaningful edge or transport protection",
            ],
            "T1190",
            &format!("Empty WAF rules combined with cleartext ALB in {acct} — layered edge controls are effectively absent."),
            "empty_waf_cleartext_alb",
        ));
    }

    if has_title_contains(findings, "CloudWatch Logs resource policy allows wildcard")
        && has_title_contains(findings, "Secrets Manager secret")
    {
        paths.push(attack_path_finding(
            "Toxic combination: open log policy + rotatable secrets plane",
            "high",
            target,
            &[
                "Inject or read logs via wildcard CloudWatch Logs resource policy",
                "Harvest secret access patterns from application log streams",
                "Target Secrets Manager entries flagged without rotation",
            ],
            "T1552.001",
            &format!("Permissive CloudWatch Logs policy plus Secrets Manager exposure in {acct} — credential harvesting via telemetry."),
            "logs_policy_secrets",
        ));
    }

    if has_title_contains(findings, "DocumentDB instance publicly accessible")
        && has_title_contains(findings, "DocumentDB cluster without encryption")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public unencrypted DocumentDB → full database dump",
            "critical",
            target,
            &[
                "Connect to the public DocumentDB endpoint from anywhere",
                "No encryption at rest — snapshots and storage are plaintext-equivalent",
                "Exfiltrate entire Mongo-compatible collections",
            ],
            "T1530",
            &format!("Public, unencrypted DocumentDB in {acct} — worst-case NoSQL data breach chain."),
            "public_docdb_unencrypted",
        ));
    }

    if (has_title_contains(findings, "Neptune instance publicly accessible")
        || has_title_contains(findings, "Neptune cluster publicly accessible"))
        && (has_title_contains(findings, "Neptune cluster without encryption")
            || has_title_contains(findings, "GuardDuty not enabled"))
    {
        paths.push(attack_path_finding(
            "Toxic combination: internet-exposed graph DB + weak detection/encryption",
            "critical",
            target,
            &[
                "Reach the public Neptune endpoint from the internet",
                "Query or dump the property graph without VPC isolation",
                "Exfiltrate relationship data while GuardDuty/encryption gaps reduce detection",
            ],
            "T1190",
            &format!("Public Neptune cluster in {acct} with encryption or GuardDuty gaps — graph-native data breach."),
            "public_neptune_blind",
        ));
    }

    if has_title_contains(findings, "MemoryDB cluster uses open-access ACL")
        && has_title_contains(findings, "MemoryDB cluster without TLS")
    {
        paths.push(attack_path_finding(
            "Toxic combination: open MemoryDB ACL + cleartext in transit",
            "critical",
            target,
            &[
                "Connect to MemoryDB from any principal allowed by open-access ACL",
                "Intercept or replay Redis-compatible commands without TLS",
                "Harvest session tokens and cache secrets in plaintext",
            ],
            "T1040",
            &format!("Open-access MemoryDB without TLS in {acct} — cache plane becomes a credential vault for attackers."),
            "memorydb_open_no_tls",
        ));
    }

    if has_title_contains(findings, "AWS Backup vault allows wildcard principal")
        && has_title_contains(findings, "S3 bucket")
    {
        paths.push(attack_path_finding(
            "Toxic combination: cross-account backup vault + exposed object store",
            "critical",
            target,
            &[
                "Use wildcard backup vault policy to copy recovery points cross-account",
                "Restore backups into attacker-controlled account",
                "Combine with any S3 exposure finding for staged exfiltration",
            ],
            "T1530",
            &format!("Public backup vault policy in {acct} chained with S3 data exposure — ransomware recovery becomes attacker asset."),
            "backup_vault_s3_chain",
        ));
    }

    if has_title_contains(findings, "Organization SCP allows wildcard actions")
        && has_title_contains(findings, "AdministratorAccess")
    {
        paths.push(attack_path_finding(
            "Toxic combination: permissive org SCP + account admin plane",
            "high",
            target,
            &[
                "Org SCP allows wildcard actions — weak guardrail at the management account",
                "Compromised admin IAM in member account bypasses intended org denies",
                "Lateral movement across OU boundaries via over-privileged roles",
            ],
            "T1078.004",
            &format!("Wildcard org SCP plus admin attachments in {acct} — governance plane fails to contain blast radius."),
            "org_scp_admin_combo",
        ));
    }

    if has_title_contains(findings, "Step Functions state machine logging disabled")
        && has_title_contains(findings, "Lambda Function URL without auth")
    {
        paths.push(attack_path_finding(
            "Toxic combination: blind serverless workflow + public Lambda entry",
            "high",
            target,
            &[
                "Invoke unauthenticated Lambda Function URL for initial access",
                "Trigger Step Functions workflows with logging disabled",
                "Operate orchestration abuse without CloudWatch audit trail",
            ],
            "T1562.002",
            &format!("Public Lambda URL plus unlogged Step Functions in {acct} — invisible serverless attack chain."),
            "sfn_blind_lambda_url",
        ));
    }

    if has_title_contains(findings, "IAM Identity Center (SSO) not enabled")
        && has_title_contains(findings, "IAM access key")
    {
        paths.push(attack_path_finding(
            "Toxic combination: no SSO federation + long-lived access keys",
            "high",
            target,
            &[
                "Human operators rely on long-lived IAM access keys without centralized IdP",
                "No IAM Identity Center means no session-bound federation or permission-set governance",
                "Stolen keys provide persistent account access outside SOC visibility",
            ],
            "T1078.004",
            &format!("Missing IAM Identity Center with stale access keys in {acct} — identity sprawl without federation guardrails."),
            "no_sso_long_lived_keys",
        ));
    }

    paths
}

/// Graph-native toxic paths — correlates live SecurityGraph edges (not just title matching).
fn synthesize_graph_attack_paths(
    graph: &SecurityGraph,
    target: &str,
    account_id: Option<&str>,
) -> Vec<Value> {
    let mut paths = Vec::new();
    let acct = account_id.unwrap_or("the account");

    for node in graph.internet_exposed_nodes() {
        let peers = graph.privileged_identity_peers(node.id.as_str());
        for peer in peers {
            let combo = format!("graph_{}_{}", node.kind, peer.kind);
            if paths.iter().any(|p: &Value| {
                p.get("toxic_combination")
                    .and_then(Value::as_str)
                    == Some(combo.as_str())
            }) {
                continue;
            }
            let title = format!(
                "Graph path: internet-exposed {} → privileged {} ({})",
                node.kind, peer.kind, peer.id
            );
            paths.push(attack_path_finding(
                &title,
                "critical",
                target,
                &[
                    "Reach the internet-exposed asset from an unauthenticated attacker",
                    "Abuse execution_role or instance profile to obtain cloud credentials",
                    "Pivot with over-privileged IAM permissions across the account",
                ],
                "T1078.004",
                &format!(
                    "Security graph in {acct} links internet-exposed `{}` ({}) to privileged identity `{}` — a Wiz-class lateral movement chain validated by live asset relationships.",
                    node.id, node.region, peer.id
                ),
                &combo,
            ));
        }
    }

    paths
}

fn detective_coverage_score(findings: &[Value]) -> i64 {
    let planes = [
        !has_title_contains(findings, "No CloudTrail trail configured"),
        !has_title_contains(findings, "CloudTrail trail not actively logging"),
        !has_title_contains(findings, "GuardDuty not enabled"),
        !has_title_contains(findings, "AWS Config recorder not configured")
            && !has_title_contains(findings, "AWS Config recorder not recording"),
        !has_title_contains(findings, "Access Analyzer not enabled"),
    ];
    let active = planes.iter().filter(|&&p| p).count();
    (active * 100 / planes.len().max(1)) as i64
}

fn domain_score(findings: &[Value], domain: &str) -> f64 {
    let penalty: f64 = findings
        .iter()
        .filter(|f| {
            f.get("domain").and_then(Value::as_str) == Some(domain)
                && f.get("attack_path").and_then(Value::as_bool) != Some(true)
        })
        .map(|f| sev_weight(&finding_sev(f)))
        .sum();
    (100.0 - penalty).clamp(0.0, 100.0)
}

fn posture_score(findings: &[Value]) -> f64 {
    let penalty: f64 = findings
        .iter()
        .filter(|f| f.get("attack_path").and_then(Value::as_bool) != Some(true))
        .map(|f| sev_weight(&finding_sev(f)))
        .sum();
    (100.0 - penalty).clamp(0.0, 100.0)
}

fn letter_grade(score: f64) -> &'static str {
    match score.round() as i64 {
        95..=100 => "A+",
        90..=94 => "A",
        85..=89 => "A-",
        75..=84 => "B",
        65..=74 => "C",
        50..=64 => "D",
        _ => "F",
    }
}

fn compliance_scores(findings: &[Value], frameworks: &[String]) -> Map<String, Value> {
    let mut out = Map::new();
    let actionable: Vec<&Value> = findings
        .iter()
        .filter(|f| f.get("attack_path").and_then(Value::as_bool) != Some(true))
        .filter(|f| severity_rank(&finding_sev(f)) >= severity_rank("low"))
        .collect();

    for fw in frameworks {
        let fw_upper = fw.to_ascii_uppercase();
        let key = match fw_upper.as_str() {
            "CIS" => "cis_aws",
            "SOC2" => "soc2",
            "ISO27001" | "ISO" => "iso27001",
            "PCI" => "pci_dss",
            "NIST" => "nist_csf",
            "GDPR" => "gdpr",
            other => other,
        };
        let failed: BTreeSet<String> = actionable
            .iter()
            .filter_map(|f| {
                f.get("compliance")
                    .and_then(|c| c.get(key))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
            .collect();
        let score = (100.0 - (failed.len() as f64 * 4.5)).clamp(0.0, 100.0);
        out.insert(
            fw.clone(),
            json!({
                "score": score.round() as i64,
                "grade": letter_grade(score),
                "failed_controls": failed.len(),
                "sample_controls": failed.iter().take(8).collect::<Vec<_>>(),
            }),
        );
    }
    out
}

fn remediation_roadmap(findings: &[Value]) -> Vec<Value> {
    let mut ranked: Vec<&Value> = findings
        .iter()
        .filter(|f| f.get("attack_path").and_then(Value::as_bool) != Some(true))
        .filter(|f| f.get("category").and_then(Value::as_str) != Some("summary"))
        .filter(|f| !f.get("remediation").and_then(Value::as_str).unwrap_or("").is_empty())
        .filter(|f| severity_rank(&finding_sev(f)) >= severity_rank("medium"))
        .collect();
    ranked.sort_by_key(|f| std::cmp::Reverse(severity_rank(&finding_sev(f))));
    ranked
        .into_iter()
        .take(12)
        .map(|f| {
            json!({
                "title": f.get("title").and_then(Value::as_str).unwrap_or(""),
                "severity": finding_sev(f),
                "domain": f.get("domain").and_then(Value::as_str).unwrap_or(""),
                "rule_id": f.get("rule_id").and_then(Value::as_str).unwrap_or(""),
                "remediation": f.get("remediation").and_then(Value::as_str).unwrap_or(""),
                "resource_id": f.get("resource_id").and_then(Value::as_str).unwrap_or(""),
                "region": f.get("region").and_then(Value::as_str).unwrap_or(""),
            })
        })
        .collect()
}

fn cnapp_risk_register(findings: &[Value]) -> Vec<Value> {
    use std::collections::HashMap;
    let mut scores: HashMap<String, (f64, String, String, String, String)> = HashMap::new();
    for f in findings {
        if f.get("category").and_then(Value::as_str) == Some("summary")
            || f.get("attack_path").and_then(Value::as_bool) == Some(true)
        {
            continue;
        }
        let rid = f.get("resource_id").and_then(Value::as_str).unwrap_or("");
        if rid.is_empty() {
            continue;
        }
        let sev = finding_sev(f);
        let entry = scores.entry(rid.to_string()).or_insert((
            0.0,
            f.get("resource_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            f.get("domain").and_then(Value::as_str).unwrap_or("").to_string(),
            f.get("region").and_then(Value::as_str).unwrap_or("").to_string(),
            sev.clone(),
        ));
        entry.0 += sev_weight(&sev);
        if severity_rank(&sev) > severity_rank(&entry.4) {
            entry.4 = sev;
        }
    }
    let mut ranked: Vec<_> = scores.into_iter().collect();
    ranked.sort_by(|a, b| b.1.0.partial_cmp(&a.1.0).unwrap_or(std::cmp::Ordering::Equal));
    ranked
        .into_iter()
        .take(15)
        .map(|(resource_id, (score, resource_type, domain, region, peak_sev))| {
            json!({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "domain": domain,
                "region": region,
                "risk_score": score.round() as i64,
                "peak_severity": peak_sev,
            })
        })
        .collect()
}

fn count_rule(findings: &[Value], rule_id: &str) -> usize {
    findings
        .iter()
        .filter(|f| f.get("rule_id").and_then(Value::as_str) == Some(rule_id))
        .count()
}

fn observability_posture(findings: &[Value]) -> Value {
    json!({
        "logs_no_retention": count_rule(findings, "logs_no_retention"),
        "logs_public_policy": count_rule(findings, "logs_public_resource_policy"),
        "waf_no_logging": count_rule(findings, "wafv2_no_logging"),
        "waf_no_rules": count_rule(findings, "wafv2_no_rules"),
        "redshift_audit_off": count_rule(findings, "redshift_audit_logging_disabled"),
    })
}

fn warehouse_exposure(findings: &[Value]) -> Value {
    json!({
        "public_redshift": count_rule(findings, "redshift_publicly_accessible"),
        "public_rds": count_rule(findings, "rds_publicly_accessible"),
        "public_documentdb": count_rule(findings, "documentdb_publicly_accessible"),
        "public_opensearch": count_rule(findings, "opensearch_public_domain"),
        "public_neptune": count_rule(findings, "neptune_publicly_accessible"),
        "memorydb_open_acl": count_rule(findings, "memorydb_open_acl"),
        "unencrypted_warehouses": count_rule(findings, "redshift_unencrypted")
            + count_rule(findings, "documentdb_unencrypted")
            + count_rule(findings, "rds_unencrypted_storage"),
    })
}

fn cnapp_catalog_status(opts: &CloudScanOptions) -> Value {
    let enabled: Vec<String> = if opts.services.is_empty() {
        CNAPP_SERVICE_PLANES.iter().map(|s| (*s).to_string()).collect()
    } else {
        opts.services.iter().cloned().collect()
    };
    json!({
        "plane_count": CNAPP_PLANE_COUNT,
        "catalog_status": "complete",
        "verification": {
            "live_api_only": true,
            "requires_cross_account_role": true,
            "dispatch_planes_wired": CNAPP_PLANE_COUNT,
            "intelligence_layers": [
                "security_graph",
                "toxic_combination_paths",
                "graph_native_2hop_paths",
                "cnapp_risk_register",
                "data_perimeter",
                "warehouse_exposure",
                "observability_posture",
                "detective_coverage",
                "compliance_scoring",
                "remediation_roadmap",
                "blast_radius_index",
            ],
            "frameworks": opts.frameworks,
        },
        "planes": CNAPP_SERVICE_PLANES,
        "services_enabled": enabled,
        "all_planes_by_default": opts.services.is_empty(),
    })
}

fn data_perimeter_status(findings: &[Value]) -> Value {
    let external = findings
        .iter()
        .filter(|f| f.get("rule_id").and_then(Value::as_str) == Some("access_analyzer_external_access"))
        .count();
    let public_data = findings
        .iter()
        .filter(|f| {
            f.get("domain").and_then(Value::as_str) == Some("data")
                && severity_rank(&finding_sev(f)) >= severity_rank("high")
        })
        .count();
    json!({
        "access_analyzer_external": external,
        "high_severity_data_findings": public_data,
        "perimeter_status": if external == 0 && public_data == 0 { "contained" } else if external > 3 { "breached" } else { "degraded" },
    })
}

fn exposure_metrics(graph: &SecurityGraph) -> Value {
    let internet = graph
        .nodes
        .values()
        .filter(|n| n.exposure == "internet")
        .count();
    let privileged = graph
        .nodes
        .values()
        .filter(|n| {
            n.risk_tags.iter().any(|t| {
                t.contains("admin")
                    || t.contains("privileged")
                    || t.contains("wildcard")
            })
        })
        .count();
    let blast = (internet.saturating_mul(4) + privileged.saturating_mul(6)).min(100);
    json!({
        "total_assets": graph.nodes.len(),
        "relationships": graph.edges.len(),
        "internet_exposed": internet,
        "privileged_assets": privileged,
        "blast_radius_index": blast,
    })
}

fn build_summary(
    target: &str,
    account_id: Option<&str>,
    principal_arn: Option<&str>,
    findings: &[Value],
    attack_paths: &[Value],
    graph: &SecurityGraph,
    opts: &CloudScanOptions,
) -> Value {
    let score = posture_score(findings);
    let grade = letter_grade(score);
    let crit = findings.iter().filter(|f| finding_sev(f) == "critical").count();
    let high = findings.iter().filter(|f| finding_sev(f) == "high").count();
    let med = findings.iter().filter(|f| finding_sev(f) == "medium").count();
    let low = findings.iter().filter(|f| finding_sev(f) == "low").count();
    let compliance = compliance_scores(findings, &opts.frameworks);

    let mut ev = Evidence::new()
        .with("engine", ENGINE_ID)
        .with("scan_mode", "agentless_cross_account")
        .with("regions", json!(opts.effective_regions()))
        .with("services", json!(opts.services.iter().collect::<Vec<_>>()))
        .check("posture_score", true, score.round() as i64);

    if opts.include_security_graph {
        ev = ev.with("security_graph", graph.to_json());
    }

    let mut v = finding_rich(
        ENGINE_ID,
        &format!("AWS Cloud Posture Summary — grade {grade} ({score:.0}/100)"),
        if score >= 85.0 { "info" } else if score >= 65.0 { "medium" } else { "high" },
        "",
        &format!(
            "Agentless CSPM/CNAPP scan of {} scored {:.0}/100 (grade {grade}) with {crit} critical, {high} high, {med} medium findings and {} toxic-combination attack path(s).",
            account_id.unwrap_or(target),
            score,
            attack_paths.len()
        ),
        target,
        1.0,
        ev,
    );

    if let Some(obj) = v.as_object_mut() {
        obj.insert("category".to_string(), json!("summary"));
        obj.insert("posture_score".to_string(), json!(score.round() as i64));
        obj.insert("grade".to_string(), json!(grade));
        obj.insert(
            "subscores".to_string(),
            json!({
                "identity": domain_score(findings, "identity").round() as i64,
                "data": domain_score(findings, "data").round() as i64,
                "network": domain_score(findings, "network").round() as i64,
                "compute": domain_score(findings, "compute").round() as i64,
                "governance": domain_score(findings, "governance").round() as i64,
            }),
        );
        obj.insert(
            "severity_counts".to_string(),
            json!({ "critical": crit, "high": high, "medium": med, "low": low }),
        );
        obj.insert("attack_path_count".to_string(), json!(attack_paths.len()));
        obj.insert("compliance_scores".to_string(), Value::Object(compliance));
        obj.insert("exposure_metrics".to_string(), exposure_metrics(graph));
        obj.insert(
            "detective_coverage".to_string(),
            json!({
                "score": detective_coverage_score(findings),
                "planes": ["cloudtrail", "guardduty", "config", "access_analyzer", "waf_logging", "log_retention"],
            }),
        );
        obj.insert("remediation_roadmap".to_string(), json!(remediation_roadmap(findings)));
        obj.insert("cnapp_risk_register".to_string(), json!(cnapp_risk_register(findings)));
        obj.insert("data_perimeter".to_string(), data_perimeter_status(findings));
        obj.insert("observability_posture".to_string(), observability_posture(findings));
        obj.insert("warehouse_exposure".to_string(), warehouse_exposure(findings));
        obj.insert("cnapp_catalog".to_string(), cnapp_catalog_status(opts));
        obj.insert(
            "rules_triggered".to_string(),
            json!(findings.iter().filter(|f| {
                f.get("category").and_then(Value::as_str) != Some("summary")
                    && f.get("attack_path").and_then(Value::as_bool) != Some(true)
                    && f.get("rule_id").is_some()
            }).count()),
        );
        if opts.include_security_graph {
            obj.insert("security_graph".to_string(), graph.to_json());
        }
        if let Some(a) = account_id {
            obj.insert("account_id".to_string(), json!(a));
        }
        if let Some(p) = principal_arn {
            obj.insert("principal_arn".to_string(), json!(p));
        }
        obj.insert("frameworks".to_string(), json!(opts.frameworks));
    }
    v
}

// ─── Entry points ──────────────────────────────────────────────────────────────

pub async fn run_cloud_posture_result(target: &str) -> EngineResult {
    run_cloud_posture_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_cloud_posture_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let opts = CloudScanOptions::from_ctx(ctx);
    let role = opts.role_arn.trim();

    if role.is_empty() {
        return EngineResult::ok(
            vec![finding_rich(
                ENGINE_ID,
                "Cross-account IAM role required for agentless CSPM",
                "info",
                "",
                "Configure aws_cross_account_role_arn (Wiz-style read-only connector role) in the scan parameters. \
                 This engine performs live AWS API inventory via STS AssumeRole — it never fabricates findings without credentials.",
                target,
                1.0,
                Evidence::new()
                    .with("required_parameter", "aws_cross_account_role_arn")
                    .with(
                        "setup_hint",
                        "Create a read-only IAM role in the customer account trusting the Weissman platform principal with sts:ExternalId.",
                    ),
            )],
            format!("{ENGINE_ID}: cross-account role required"),
        );
    }

    let cac = CrossAccountAwsConfig {
        role_arn: role.to_string(),
        external_id: opts.external_id.clone(),
        session_name: opts.session_name.clone(),
    };

    let (sdk, home_region) = match assume_role_sdk_config(&cac).await {
        Ok(v) => v,
        Err(e) => {
            return EngineResult::error(format!("STS AssumeRole failed: {e}"));
        }
    };

    let sts = aws_sdk_sts::Client::new(&sdk);
    let (account_id, principal_arn) = match sts.get_caller_identity().send().await {
        Ok(id) => (
            id.account().map(str::to_string),
            id.arn().map(str::to_string),
        ),
        Err(e) => {
            return EngineResult::error(format!("GetCallerIdentity failed after AssumeRole: {e}"));
        }
    };

    let mut graph = SecurityGraph::default();
    let mut findings: Vec<Value> = Vec::new();

    findings.push(finding_rich(
        ENGINE_ID,
        "Agentless CSPM plane authenticated",
        "info",
        "",
        &format!(
            "STS AssumeRole succeeded — scanning account {} as {} via live AWS APIs (no agents on workloads).",
            account_id.clone().unwrap_or_default(),
            principal_arn.clone().unwrap_or_default()
        ),
        target,
        1.0,
        Evidence::new()
            .with("account_id", account_id.clone().unwrap_or_default())
            .with("principal_arn", principal_arn.clone().unwrap_or_default())
            .with("home_region", home_region.as_ref())
            .check("sts_assume_role", true, "ok"),
    ));

    if opts.wants("iam") {
        findings.extend(scan_iam(&sdk, &opts, target, &mut graph).await);
        findings.extend(scan_iam_roles(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("s3") {
        findings.extend(
            scan_s3(
                &sdk,
                &opts,
                target,
                home_region.as_ref(),
                &mut graph,
            )
            .await,
        );
    }
    if opts.wants("ec2") || opts.wants("vpc") {
        findings.extend(scan_ec2_vpc(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("ssm") {
        findings.extend(scan_ssm(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("lambda") && opts.check_lambda {
        findings.extend(scan_lambda(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("rds") && opts.check_rds {
        findings.extend(scan_rds(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("kms") {
        findings.extend(scan_kms(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("cloudtrail") && opts.check_cloudtrail {
        findings.extend(scan_cloudtrail(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("accessanalyzer") {
        findings.extend(scan_access_analyzer(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("guardduty") {
        findings.extend(scan_guardduty(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("config") {
        findings.extend(scan_config_recorder(&sdk, &opts, target, &mut graph).await);
    }
    if let Some(ref acct) = account_id {
        if opts.wants("account") {
            findings.extend(
                scan_account_s3_public_block(&sdk, acct, &opts, target, &mut graph).await,
            );
        }
    }
    if opts.wants("eks") {
        findings.extend(scan_eks(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("elb") {
        findings.extend(scan_elbv2(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("secrets") {
        findings.extend(scan_secrets_manager(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("messaging") {
        findings.extend(scan_messaging(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("ecs") {
        findings.extend(scan_ecs(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("elasticache") {
        findings.extend(scan_elasticache(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("ecr") {
        findings.extend(scan_ecr(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("acm") {
        findings.extend(scan_acm(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("dynamodb") {
        findings.extend(scan_dynamodb(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("apigateway") {
        findings.extend(scan_apigateway(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("opensearch") {
        findings.extend(scan_opensearch(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("cloudfront") {
        findings.extend(scan_cloudfront(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("route53") {
        findings.extend(scan_route53(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("eventbridge") {
        findings.extend(scan_eventbridge(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("wafv2") {
        findings.extend(scan_wafv2(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("logs") {
        findings.extend(scan_cloudwatch_logs(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("redshift") {
        findings.extend(scan_redshift(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("documentdb") {
        findings.extend(scan_documentdb(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("neptune") {
        findings.extend(scan_neptune(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("memorydb") {
        findings.extend(scan_memorydb(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("backup") {
        findings.extend(scan_backup(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("organizations") {
        findings.extend(scan_organizations(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("sfn") {
        findings.extend(scan_sfn(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("sso") {
        findings.extend(scan_sso(&sdk, &opts, target, &mut graph).await);
    }

    findings.retain(|f| {
        f.get("category").and_then(Value::as_str) == Some("summary")
            || opts.keep_severity(&finding_sev(f))
    });

    let mut attack_paths = if opts.include_attack_paths {
        synthesize_attack_paths(&findings, target, account_id.as_deref())
    } else {
        Vec::new()
    };
    if opts.include_attack_paths && opts.check_graph_paths {
        attack_paths.extend(synthesize_graph_attack_paths(
            &graph,
            target,
            account_id.as_deref(),
        ));
    }

    let summary = build_summary(
        target,
        account_id.as_deref(),
        principal_arn.as_deref(),
        &findings,
        &attack_paths,
        &graph,
        &opts,
    );

    findings.extend(attack_paths);
    findings.push(summary);

    EngineResult::ok(findings, format!("{ENGINE_ID}: scan complete"))
}

pub async fn run_cloud_posture(target: &str) {
    print_result(run_cloud_posture_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_rank_ordering() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("info") < severity_rank("low"));
    }

    #[test]
    fn options_default_frameworks() {
        let o = CloudScanOptions::default();
        assert!(o.frameworks.contains(&"CIS".to_string()));
        assert!(o.include_attack_paths);
    }

    #[test]
    fn letter_grade_boundaries() {
        assert_eq!(letter_grade(96.0), "A+");
        assert_eq!(letter_grade(50.0), "D");
    }

    #[test]
    fn cnapp_risk_register_ranks_by_severity() {
        let findings = vec![
            json!({
                "resource_id": "bucket-a",
                "resource_type": "s3_bucket",
                "domain": "data",
                "region": "us-east-1",
                "severity": "high",
            }),
            json!({
                "resource_id": "bucket-a",
                "resource_type": "s3_bucket",
                "domain": "data",
                "region": "us-east-1",
                "severity": "critical",
            }),
            json!({
                "category": "summary",
                "posture_score": 50,
            }),
        ];
        let reg = cnapp_risk_register(&findings);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg[0]["peak_severity"], "critical");
        assert!(reg[0]["risk_score"].as_i64().unwrap_or(0) >= 9);
    }

    #[test]
    fn cnapp_catalog_has_37_planes() {
        assert_eq!(CNAPP_PLANE_COUNT, 37);
        assert_eq!(CNAPP_SERVICE_PLANES.len(), CNAPP_PLANE_COUNT);
        let opts = CloudScanOptions::default();
        let catalog = cnapp_catalog_status(&opts);
        assert_eq!(catalog["catalog_status"], "complete");
        assert_eq!(catalog["plane_count"], 37);
        assert_eq!(catalog["planes"].as_array().unwrap().len(), 37);
    }
}
