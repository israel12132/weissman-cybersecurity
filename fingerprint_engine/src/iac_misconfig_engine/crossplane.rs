//! Crossplane analyzer — XRDs, Compositions, Claims and ProviderConfigs. Detects real misconfigurations
//! in `spec.forProvider` patches and composition pipelines (public S3, wildcard IAM, privileged pods).

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "crossplane", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const S3_PUBLIC: PolicyMeta = pol!(
    "WZ-XP-001",
    "Crossplane S3 XR allows public access",
    Critical,
    "Bucket forProvider sets acl public-read or blockPublicAccess BLOCK_NONE.",
    "Set acl private and blockPublicAccess BLOCK_ALL in the XR spec.forProvider.",
    "T1530",
    "CWE-732",
    &["CIS-AWS-2.1.5"],
    &["NIST-AC-3", "PCI-DSS-1.2.1", "SOC2-CC6.1"]
);
pub const IAM_WILDCARD: PolicyMeta = pol!(
    "WZ-XP-002",
    "Crossplane IAM policy grants wildcard admin",
    Critical,
    "forProvider policy document contains Effect Allow with Action * and Resource *.",
    "Scope IAM actions/resources to least privilege in the XR spec.",
    "T1098",
    "CWE-732",
    &["CIS-AWS-1.16"],
    &["NIST-AC-6", "PCI-DSS-7.1.2"]
);
pub const COMP_PRIV: PolicyMeta = pol!(
    "WZ-XP-003",
    "Crossplane Composition propagates privileged container",
    Critical,
    "Composition patch sets securityContext.privileged: true on workload templates.",
    "Remove privileged patches; enforce Pod Security restricted profile in compositions.",
    "T1610",
    "CWE-250",
    &["CIS-K8S-5.2.1"],
    &["NIST-AC-6", "SOC2-CC6.1"]
);
pub const CREDS_INLINE: PolicyMeta = pol!(
    "WZ-XP-004",
    "Crossplane ProviderConfig embeds cloud credentials inline",
    High,
    "ProviderConfig spec.credentials contains accessKey/secretKey literals instead of secretRef.",
    "Store credentials in a Kubernetes Secret and reference via spec.credentials.secretRef.",
    "T1552.001",
    "CWE-798",
    &["CIS-K8S-5.4.1"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const SG_OPEN: PolicyMeta = pol!(
    "WZ-XP-005",
    "Crossplane SecurityGroup allows 0.0.0.0/0 ingress",
    High,
    "forProvider ingress rule uses cidrBlocks 0.0.0.0/0.",
    "Restrict ingress CIDRs to application-tier networks only.",
    "T1190",
    "CWE-284",
    &["CIS-AWS-5.2"],
    &["NIST-SC-7", "PCI-DSS-1.3.1"]
);
pub const RDS_PUBLIC: PolicyMeta = pol!(
    "WZ-XP-006",
    "Crossplane RDS XR publicly accessible",
    High,
    "forProvider publiclyAccessible: true on RDS Instance/Cluster XR.",
    "Set publiclyAccessible: false and place databases in private subnets.",
    "T1190",
    "CWE-668",
    &["CIS-AWS-2.3.1"],
    &["NIST-SC-7", "PCI-DSS-1.3.6"]
);
pub const NO_FINALIZER: PolicyMeta = pol!(
    "WZ-XP-007",
    "Crossplane managed resource lacks deletion protection",
    Medium,
    "Critical XR (database/storage) has deletionPolicy: Delete without backup/finalizer safeguards.",
    "Use deletionPolicy: Orphan for stateful resources or add backup retention policies before delete.",
    "T1485",
    "CWE-404",
    &["CIS-K8S-5.1.1"],
    &["NIST-CP-9", "SOC2-A1.2"]
);
pub const CLAIM_NO_SELECTOR: PolicyMeta = pol!(
    "WZ-XP-008",
    "Crossplane Claim missing compositionSelector",
    High,
    "CompositeResourceClaim without compositionSelector may bind to unintended Composition revisions.",
    "Set compositionSelector.matchLabels to pin the intended Composition template.",
    "T1195",
    "CWE-693",
    &["CIS-K8S-5.1.1"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const STORE_PLAINTEXT: PolicyMeta = pol!(
    "WZ-XP-009",
    "Crossplane StoreConfig allows unencrypted secret store",
    High,
    "StoreConfig defaultScope or type enables plaintext secret persistence.",
    "Use Kubernetes Secret store with encryption at rest; enable KMS for etcd.",
    "T1552.001",
    "CWE-312",
    &["CIS-K8S-5.4.1"],
    &["NIST-SC-28", "PCI-DSS-3.4"]
);
pub const PROVIDER_REVISION: PolicyMeta = pol!(
    "WZ-XP-010",
    "Crossplane Provider installed without pinned package revision",
    Medium,
    "Provider manifest lacks package revision pin — upgrades can change CRD schemas silently.",
    "Pin Provider package to a specific version/revision; test in staging before upgrade.",
    "T1195.001",
    "CWE-1104",
    &["CIS-K8S-5.1.1"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);
pub const XP_SA_AUTO: PolicyMeta = pol!(
    "WZ-XP-011",
    "Crossplane Composition enables automountServiceAccountToken on workloads",
    High,
    "Composition patch sets automountServiceAccountToken: true — expands token theft blast radius.",
    "Set automountServiceAccountToken: false; use bound tokens with short TTL.",
    "T1528",
    "CWE-269",
    &["CIS-K8S-5.1.6"],
    &["NIST-AC-6", "SOC2-CC6.3"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        S3_PUBLIC, IAM_WILDCARD, COMP_PRIV, CREDS_INLINE, SG_OPEN, RDS_PUBLIC, NO_FINALIZER,
        CLAIM_NO_SELECTOR, STORE_PLAINTEXT, PROVIDER_REVISION, XP_SA_AUTO,
    ]
}

fn is_crossplane(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.contains("crossplane") || n.contains("/xrds/") || n.contains("/compositions/")
        || lc.contains("apiversion: apiextensions.crossplane.io")
        || lc.contains("apiversion: pkg.crossplane.io")
        || lc.contains("kind: composition")
        || lc.contains("kind: providerconfig")
        || lc.contains("kind: compositeresourcedefinition")
        || lc.contains("spec:")
            && lc.contains("forprovider:")
            && (lc.contains("s3.aws") || lc.contains("iam.aws") || lc.contains("ec2.aws"))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_crossplane(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if (lc.contains("public-read") || lc.contains("blockpublicaccess: block_none") || lc.contains("blockpublicaccess: \"block_none\""))
        && (lc.contains("s3") || lc.contains("bucket"))
    {
        out.push(Finding::new(S3_PUBLIC, file, file).observed("public S3 forProvider settings"));
    }
    if lc.contains("\"action\": \"*\"") && lc.contains("\"resource\": \"*\"")
        || lc.contains("action: '*'") && lc.contains("resource: '*'")
        || lc.contains("action: \"*\"") && lc.contains("resource: \"*\"")
    {
        out.push(Finding::new(IAM_WILDCARD, file, file).observed("IAM wildcard Action/Resource"));
    }
    if (lc.contains("privileged: true") || (lc.contains(".privileged") && lc.contains("value: true")))
        && (lc.contains("composition") || lc.contains("crossplane"))
    {
        out.push(Finding::new(COMP_PRIV, file, file).observed("Composition patches privileged: true"));
    }
    if (lc.contains("accesskey") || lc.contains("secretkey") || lc.contains("aws_access_key_id"))
        && !lc.contains("secretref")
        && lc.contains("providerconfig")
    {
        out.push(Finding::new(CREDS_INLINE, file, file).observed("inline credentials in ProviderConfig"));
    }
    if lc.contains("0.0.0.0/0") && (lc.contains("cidrblocks") || lc.contains("cidr_blocks") || lc.contains("securitygroup")) {
        out.push(Finding::new(SG_OPEN, file, file).observed("ingress cidrBlocks 0.0.0.0/0"));
    }
    if lc.contains("publiclyaccessible: true") && lc.contains("rds") {
        out.push(Finding::new(RDS_PUBLIC, file, file).observed("publiclyAccessible: true"));
    }
    if lc.contains("deletionpolicy: delete")
        && (lc.contains("rds") || lc.contains("database") || lc.contains("bucket"))
        && !lc.contains("finalizers:")
    {
        out.push(Finding::new(NO_FINALIZER, file, file).observed("deletionPolicy Delete without finalizers"));
    }
    if lc.contains("kind: compositeresourceclaim") && !lc.contains("compositionselector") {
        out.push(Finding::new(CLAIM_NO_SELECTOR, file, file).observed("Claim without compositionSelector"));
    }
    if lc.contains("kind: storeconfig") && !lc.contains("encryption") && !lc.contains("kubernetes") {
        out.push(Finding::new(STORE_PLAINTEXT, file, file).observed("StoreConfig without encryption"));
    }
    if lc.contains("kind: provider") && lc.contains("pkg.crossplane.io") && !lc.contains("revision:") && !lc.contains("package:") {
        out.push(Finding::new(PROVIDER_REVISION, file, file).observed("Provider without pinned revision"));
    }
    if lc.contains("automountserviceaccounttoken: true") && lc.contains("composition") {
        out.push(Finding::new(XP_SA_AUTO, file, file).observed("automountServiceAccountToken: true in Composition"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_public_s3_xr() {
        let y = r#"apiVersion: s3.aws.upbound.io/v1beta1
kind: Bucket
spec:
  forProvider:
    acl: public-read
"#;
        assert!(evaluate("bucket-xr.yaml", y).iter().any(|f| f.policy.id == S3_PUBLIC.id));
    }

    #[test]
    fn flags_composition_privileged() {
        let y = r#"apiVersion: apiextensions.crossplane.io/v1
kind: Composition
spec:
  resources:
    - patches:
        - toFieldPath: spec.template.spec.containers[0].securityContext.privileged
          value: true
"#;
        assert!(evaluate("comp.yaml", y).iter().any(|f| f.policy.id == COMP_PRIV.id));
    }
}
