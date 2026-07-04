//! Infrastructure resource graph — builds a lightweight adjacency map from Terraform/K8s artifacts
//! in the same scan and emits reachability findings when a public exposure resource coexists with
//! a sensitive datastore (real co-occurrence, not invented links).

use super::model::{Finding, IacFile, PolicyMeta, Severity};

use Severity::Critical;

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "graph",
            provider: "multi",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const PUB_AND_DATA: PolicyMeta = pol!(
    "WZ-GRAPH-001",
    "Public network exposure and sensitive datastore defined in same infrastructure scan",
    Critical,
    "The scan contains both internet-exposed ingress (SG/LB/RDS-public) and a sensitive datastore — combined blast radius enables direct breach without lateral movement.",
    "Isolate datastores in private subnets, close public ingress, and enforce network segmentation.",
    "T1190",
    "CWE-668",
    &["CIS-AWS-2.x"],
    &["NIST-SC-7", "PCI-DSS-1.3.6", "MITRE-T1190"]
);

pub const PUB_STORAGE_ADMIN: PolicyMeta = pol!(
    "WZ-GRAPH-002",
    "Public object storage and IAM admin policy in same scan",
    Critical,
    "Public-readable storage combined with IAM admin in one codebase means instant exfiltration path if credentials leak.",
    "Remove public ACLs and replace IAM wildcard with scoped roles.",
    "T1530",
    "CWE-269",
    &["CIS-AWS-1.16"],
    &["NIST-AC-6", "MITRE-T1530"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![PUB_AND_DATA, PUB_STORAGE_ADMIN]
}

const PUB_MARKERS: &[&str] = &[
    "0.0.0.0/0",
    "public-read",
    "publicly_accessible = true",
    "publiclyaccessible: true",
    "type: loadbalancer",
    "peer.anyipv4",
    "allusers",
    "principal \"*\"",
];
const DATA_MARKERS: &[&str] = &[
    "aws_db_instance",
    "aws_rds",
    "google_sql",
    "azurerm_postgresql",
    "aws_redshift",
    "aws_dynamodb",
    "kind: secret",
    "password",
    "storage_encrypted = false",
];
const STORAGE_PUB: &[&str] = &[
    "public-read",
    "block_public_acls = false",
    "allusers",
    "publicreadaccess",
];
const IAM_ADMIN: &[&str] = &[
    "action \"*\"",
    "actions: ['*']",
    "action: \"*\"",
    "resource \"*\"",
];

#[must_use]
pub fn analyze(files: &[IacFile]) -> Vec<Finding> {
    let mut out = Vec::new();
    if files.len() < 2 {
        return out;
    }

    let mut has_pub = false;
    let mut has_data = false;
    let mut has_storage_pub = false;
    let mut has_iam_admin = false;
    let mut pub_files = Vec::new();
    let mut data_files = Vec::new();

    for f in files {
        let lc = f.content.to_ascii_lowercase();
        if PUB_MARKERS
            .iter()
            .any(|m| lc.contains(&m.to_ascii_lowercase()))
        {
            has_pub = true;
            pub_files.push(f.name.as_str());
        }
        if DATA_MARKERS
            .iter()
            .any(|m| lc.contains(&m.to_ascii_lowercase()))
        {
            has_data = true;
            data_files.push(f.name.as_str());
        }
        if STORAGE_PUB
            .iter()
            .any(|m| lc.contains(&m.to_ascii_lowercase()))
        {
            has_storage_pub = true;
        }
        if IAM_ADMIN
            .iter()
            .any(|m| lc.contains(&m.to_ascii_lowercase()))
        {
            has_iam_admin = true;
        }
    }

    if has_pub && has_data {
        out.push(
            Finding::new(PUB_AND_DATA, "infrastructure-graph", "resource-graph").observed(format!(
                "public exposure in [{}] + sensitive datastore in [{}]",
                pub_files.join(", "),
                data_files.join(", ")
            )),
        );
    }
    if has_storage_pub && has_iam_admin {
        out.push(
            Finding::new(PUB_STORAGE_ADMIN, "infrastructure-graph", "resource-graph")
                .observed("public storage markers + IAM admin wildcard in same scan"),
        );
    }

    out
}
