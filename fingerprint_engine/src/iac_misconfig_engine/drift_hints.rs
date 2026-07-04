//! Security posture drift — detects when the same logical resource appears in multiple scanned files
//! with **conflicting** security settings. Only emits when both states are observed in real content.

use super::detect;
use super::model::{Finding, Framework, IacFile, PolicyMeta, Severity};
use serde::Deserialize;
use std::collections::HashMap;

use Severity::High;

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "drift",
            provider: "generic",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const S3_ACL_DRIFT: PolicyMeta = pol!(
    "WZ-DRIFT-001",
    "Same S3 bucket name with conflicting ACL across Terraform files",
    High,
    "Multiple Terraform files define the same bucket identifier with different ACL/public settings — indicates environment drift or partial remediation.",
    "Normalize bucket ACL to private across all modules; enforce aws_s3_bucket_public_access_block.",
    "T1530",
    "CWE-693",
    &["CIS-AWS-2.1.5"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const SG_CIDR_DRIFT: PolicyMeta = pol!(
    "WZ-DRIFT-002",
    "Same security group with conflicting ingress CIDR across files",
    High,
    "A security group resource name appears in multiple files with both open (0.0.0.0/0) and restricted ingress — partial fix leaving exploitable paths.",
    "Consolidate SG rules into one module; remove all 0.0.0.0/0 ingress on management ports.",
    "T1190",
    "CWE-693",
    &["CIS-AWS-5.2"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const K8S_PRIV_DRIFT: PolicyMeta = pol!(
    "WZ-DRIFT-003",
    "Same Deployment name with conflicting privileged setting across manifests",
    High,
    "The same Deployment name is declared in multiple YAML files with different privileged securityContext values — cluster may run the insecure variant.",
    "Single source of truth for workload manifests; enforce privileged: false via admission policy.",
    "T1610",
    "CWE-693",
    &["CIS-K8S-5.2.1"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const RDS_ENC_DRIFT: PolicyMeta = pol!(
    "WZ-DRIFT-004",
    "Same RDS instance with conflicting encryption setting across Terraform files",
    High,
    "Multiple files define the same RDS resource with different storage_encrypted values — data may be unencrypted in one environment.",
    "Enforce storage_encrypted = true in all modules and environments.",
    "T1530",
    "CWE-693",
    &["CIS-AWS-2.3.1"],
    &["NIST-SC-28", "PCI-DSS-3.4"]
);
pub const IAM_SCOPE_DRIFT: PolicyMeta = pol!(
    "WZ-DRIFT-005",
    "Same IAM policy name with wildcard vs scoped permissions across files",
    High,
    "IAM policy resource appears in multiple files with both wildcard admin and scoped permissions — partial least-privilege rollout.",
    "Consolidate IAM into one module; remove Action */Resource * everywhere.",
    "T1098",
    "CWE-693",
    &["CIS-AWS-1.16"],
    &["NIST-AC-6", "SOC2-CC6.3"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        S3_ACL_DRIFT,
        SG_CIDR_DRIFT,
        K8S_PRIV_DRIFT,
        RDS_ENC_DRIFT,
        IAM_SCOPE_DRIFT,
    ]
}

#[derive(Default)]
struct S3State {
    public_files: Vec<String>,
    private_files: Vec<String>,
}

#[derive(Default)]
struct SgState {
    open_files: Vec<String>,
    closed_files: Vec<String>,
}

#[derive(Default)]
struct DepState {
    priv_files: Vec<String>,
    unpriv_files: Vec<String>,
}

/// Analyze all files for cross-file security drift. Requires ≥2 files.
#[must_use]
pub fn analyze(files: &[IacFile]) -> Vec<Finding> {
    let mut out = Vec::new();
    if files.len() < 2 {
        return out;
    }

    let mut s3: HashMap<String, S3State> = HashMap::new();
    let mut sg: HashMap<String, SgState> = HashMap::new();
    let mut dep: HashMap<String, DepState> = HashMap::new();
    let mut rds_enc: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
    let mut iam_scope: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();

    for file in files {
        let fw = detect::detect(&file.name, &file.content, file.forced);
        match fw {
            Framework::Terraform | Framework::Terragrunt => scan_terraform(
                &file.name,
                &file.content,
                &mut s3,
                &mut sg,
                &mut rds_enc,
                &mut iam_scope,
            ),
            Framework::Kubernetes | Framework::Helm => {
                scan_k8s(&file.name, &file.content, &mut dep)
            }
            _ => {}
        }
    }

    for (bucket, st) in &s3 {
        if !st.public_files.is_empty() && !st.private_files.is_empty() {
            let obs = format!(
                "bucket={bucket}: public in [{}] vs private in [{}]",
                st.public_files.join(", "),
                st.private_files.join(", ")
            );
            out.push(Finding::new(S3_ACL_DRIFT, bucket, &st.public_files[0]).observed(obs));
        }
    }
    for (name, st) in &sg {
        if !st.open_files.is_empty() && !st.closed_files.is_empty() {
            let obs = format!(
                "sg={name}: open 0.0.0.0/0 in [{}] vs restricted in [{}]",
                st.open_files.join(", "),
                st.closed_files.join(", ")
            );
            out.push(Finding::new(SG_CIDR_DRIFT, name, &st.open_files[0]).observed(obs));
        }
    }
    for (name, st) in &dep {
        if !st.priv_files.is_empty() && !st.unpriv_files.is_empty() {
            let obs = format!(
                "deployment={name}: privileged in [{}] vs non-privileged in [{}]",
                st.priv_files.join(", "),
                st.unpriv_files.join(", ")
            );
            out.push(Finding::new(K8S_PRIV_DRIFT, name, &st.priv_files[0]).observed(obs));
        }
    }
    for (name, (enc_on, enc_off)) in &rds_enc {
        if !enc_on.is_empty() && !enc_off.is_empty() {
            let obs = format!(
                "rds={name}: encrypted in [{}] vs unencrypted in [{}]",
                enc_on.join(", "),
                enc_off.join(", ")
            );
            out.push(Finding::new(RDS_ENC_DRIFT, name, &enc_off[0]).observed(obs));
        }
    }
    for (name, (wild, scoped)) in &iam_scope {
        if !wild.is_empty() && !scoped.is_empty() {
            let obs = format!(
                "iam={name}: wildcard in [{}] vs scoped in [{}]",
                wild.join(", "),
                scoped.join(", ")
            );
            out.push(Finding::new(IAM_SCOPE_DRIFT, name, &wild[0]).observed(obs));
        }
    }

    out
}

fn scan_terraform(
    file: &str,
    content: &str,
    s3: &mut HashMap<String, S3State>,
    sg: &mut HashMap<String, SgState>,
    rds_enc: &mut HashMap<String, (Vec<String>, Vec<String>)>,
    iam_scope: &mut HashMap<String, (Vec<String>, Vec<String>)>,
) {
    let mut current_type = String::new();
    let mut current_name = String::new();
    let mut in_block = false;

    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("resource \"") {
            let parts: Vec<&str> = t.split('"').collect();
            if parts.len() >= 4 {
                current_type = parts[1].to_string();
                current_name = parts[3].to_string();
                in_block = true;
            }
            scan_tf_line(
                t,
                &current_type,
                &current_name,
                file,
                s3,
                sg,
                rds_enc,
                iam_scope,
            );
            continue;
        }
        if !in_block {
            continue;
        }
        if t == "}" {
            in_block = false;
            continue;
        }
        scan_tf_line(
            t,
            &current_type,
            &current_name,
            file,
            s3,
            sg,
            rds_enc,
            iam_scope,
        );
    }
}

fn scan_tf_line(
    t: &str,
    current_type: &str,
    current_name: &str,
    file: &str,
    s3: &mut HashMap<String, S3State>,
    sg: &mut HashMap<String, SgState>,
    rds_enc: &mut HashMap<String, (Vec<String>, Vec<String>)>,
    iam_scope: &mut HashMap<String, (Vec<String>, Vec<String>)>,
) {
    let tl = t.to_ascii_lowercase();
    if current_type == "aws_s3_bucket" {
        if tl.contains("acl")
            && (tl.contains("public")
                || tl.contains("\"public-read\"")
                || tl.contains("public-read"))
        {
            s3.entry(current_name.to_string())
                .or_default()
                .public_files
                .push(file.to_string());
        } else if tl.contains("acl") && (tl.contains("private") || tl.contains("\"private\"")) {
            s3.entry(current_name.to_string())
                .or_default()
                .private_files
                .push(file.to_string());
        }
    }
    if current_type == "aws_security_group" || current_type == "aws_security_group_rule" {
        if tl.contains("0.0.0.0/0") {
            sg.entry(current_name.to_string())
                .or_default()
                .open_files
                .push(file.to_string());
        } else if tl.contains("cidr") && !tl.contains("0.0.0.0/0") {
            sg.entry(current_name.to_string())
                .or_default()
                .closed_files
                .push(file.to_string());
        }
    }
    if current_type == "aws_db_instance" || current_type == "aws_rds_cluster" {
        let entry = rds_enc
            .entry(current_name.to_string())
            .or_insert_with(|| (Vec::new(), Vec::new()));
        if tl.contains("storage_encrypted") && (tl.contains("true") || tl.contains("\"true\"")) {
            entry.0.push(file.to_string());
        } else if tl.contains("storage_encrypted")
            && (tl.contains("false") || tl.contains("\"false\""))
        {
            entry.1.push(file.to_string());
        }
    }
    if current_type.starts_with("aws_iam_") {
        let entry = iam_scope
            .entry(current_name.to_string())
            .or_insert_with(|| (Vec::new(), Vec::new()));
        if tl.contains("action") && tl.contains("*") && tl.contains("resource") {
            entry.0.push(file.to_string());
        } else if tl.contains("action") && !tl.contains("\"*\"") {
            entry.1.push(file.to_string());
        }
    }
}

fn scan_k8s(file: &str, content: &str, dep: &mut HashMap<String, DepState>) {
    for de in serde_yaml::Deserializer::from_str(content) {
        let Ok(doc) = serde_yaml::Value::deserialize(de) else {
            continue;
        };
        if doc.get("kind").and_then(|k| k.as_str()) != Some("Deployment") {
            continue;
        }
        let name = doc
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unnamed")
            .to_string();
        let raw = serde_yaml::to_string(&doc).unwrap_or_default();
        let lc = raw.to_ascii_lowercase();
        if lc.contains("privileged: true") {
            dep.entry(name)
                .or_default()
                .priv_files
                .push(file.to_string());
        } else if lc.contains("privileged: false") || lc.contains("securitycontext:") {
            dep.entry(name)
                .or_default()
                .unpriv_files
                .push(file.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_s3_acl_drift() {
        let a = IacFile {
            name: "a.tf".into(),
            content: r#"resource "aws_s3_bucket" "assets" { acl = "public-read" }"#.into(),
            forced: Some(Framework::Terraform),
            origin: "inline".into(),
        };
        let b = IacFile {
            name: "b.tf".into(),
            content: r#"resource "aws_s3_bucket" "assets" { acl = "private" }"#.into(),
            forced: Some(Framework::Terraform),
            origin: "inline".into(),
        };
        let f = analyze(&[a, b]);
        assert!(f.iter().any(|x| x.policy.id == S3_ACL_DRIFT.id));
    }
}
