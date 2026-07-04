//! Velero backup/DR analyzer — public backup storage, inline credentials, and unencrypted snapshots.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "velero",
            provider: "kubernetes",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const PUBLIC_BSL: PolicyMeta = pol!(
    "WZ-VEL-001",
    "Velero BackupStorageLocation allows public object storage",
    Critical,
    "backupStorageLocation configURL points to public S3/GCS bucket or s3Url without access controls.",
    "Use private buckets with IAM; enable object lock and encryption; restrict BSL credentials.",
    "T1530",
    "CWE-284",
    &["CIS-Backup"],
    &["NIST-CP-9", "PCI-DSS-3.4", "SOC2-CC6.1"]
);
pub const INLINE_CREDS: PolicyMeta = pol!(
    "WZ-VEL-002",
    "Velero credentials embedded in BackupStorageLocation",
    Critical,
    "credential.secretRef missing — accessKey/secretKey literals in velero config.",
    "Use secretRef to Kubernetes Secret; prefer IRSA/workload identity for Velero.",
    "T1552.001",
    "CWE-798",
    &["CIS-Backup"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const NO_ENCRYPTION: PolicyMeta = pol!(
    "WZ-VEL-003",
    "Velero backup storage encryption disabled",
    High,
    "serverSideEncryption or customerKeyEncryption absent on S3-compatible BSL.",
    "Enable SSE-KMS on backup bucket; use CMEK for GCS.",
    "T1530",
    "CWE-311",
    &["CIS-Backup"],
    &["NIST-SC-28", "PCI-DSS-3.4"]
);
pub const FS_BACKUP_SECRETS: PolicyMeta = pol!(
    "WZ-VEL-004",
    "Velero schedule backs up secrets cluster-wide without filter",
    High,
    "Schedule includes secrets/default or no excludedNamespaces — full secret dump to backup target.",
    "Exclude kube-system/secrets; use namespace-scoped schedules; encrypt backup storage.",
    "T1552",
    "CWE-200",
    &["CIS-Backup"],
    &["NIST-AC-3", "HIPAA-164.312(a)(1)"]
);
pub const INSECURE_URL: PolicyMeta = pol!(
    "WZ-VEL-005",
    "Velero backup storage uses cleartext HTTP endpoint",
    Medium,
    "config.storage.config.s3Url or provider URL uses http://.",
    "Use https:// endpoints with TLS and signed requests.",
    "T1040",
    "CWE-319",
    &["CIS-Backup"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        PUBLIC_BSL,
        INLINE_CREDS,
        NO_ENCRYPTION,
        FS_BACKUP_SECRETS,
        INSECURE_URL,
    ]
}

fn is_velero(content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("velero.io")
        || lc.contains("backupstoragelocation")
        || lc.contains("kind: schedule") && lc.contains("velero")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_velero(content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("publicaccess")
        || lc.contains("acl: public")
        || lc.contains("blockpublicaccess: false")
    {
        out.push(Finding::new(PUBLIC_BSL, file, file).observed("public backup storage"));
    }
    if lc.contains("accesskey") || lc.contains("secretkey") || lc.contains("aws_access_key_id") {
        out.push(Finding::new(INLINE_CREDS, file, file).observed("inline Velero credentials"));
    }
    if lc.contains("s3url:") && !lc.contains("serversideencryption") && !lc.contains("kmskeyid") {
        out.push(Finding::new(NO_ENCRYPTION, file, file).observed("no backup encryption"));
    }
    if lc.contains("includedresources:")
        && lc.contains("secrets")
        && !lc.contains("excludednamespaces")
    {
        out.push(Finding::new(FS_BACKUP_SECRETS, file, file).observed("schedule backs up secrets"));
    }
    if lc.contains("s3url: http://") || lc.contains("configurl: http://") {
        out.push(Finding::new(INSECURE_URL, file, file).observed("http backup endpoint"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_public_bsl() {
        let y = "apiVersion: velero.io/v1\nkind: BackupStorageLocation\nspec:\n  config:\n    s3Url: https://s3.amazonaws.com\n    publicAccess: true";
        let f = evaluate("velero/bsl.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == PUBLIC_BSL.id));
    }
}
