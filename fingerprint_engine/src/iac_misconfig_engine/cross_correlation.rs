//! Cross-file correlation — synthesizes findings that only exist when multiple IaC artifacts from
//! the same scan are considered together (e.g. workloads in a namespace with no NetworkPolicy).

use super::detect;
use super::model::{Finding, Framework, IacFile, PolicyMeta, Severity};
use serde::Deserialize;
use std::collections::HashMap;

use Severity::High;

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "correlation", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const NS_NO_NETPOL: PolicyMeta = pol!(
    "WZ-CORR-K8S-001",
    "Namespace has workloads but no NetworkPolicy defined in repository",
    High,
    "One or more namespaced workloads were found but no NetworkPolicy targets that namespace anywhere in the scanned artifacts — east-west traffic is unrestricted by default.",
    "Add a default-deny NetworkPolicy per namespace and explicit allow rules for required traffic only.",
    "T1021",
    "CWE-284",
    &["CIS-K8S-5.3.2"],
    &["CIS-K8S-5.3.2", "NIST-SC-7", "SOC2-CC6.6"]
);

pub const REPO_SECRET_AND_PUBLIC: PolicyMeta = pol!(
    "WZ-CORR-SEC-001",
    "Hard-coded secret and public cloud exposure in same repository scan",
    High,
    "The same repository contains both a secret/credential finding and a public-exposure cloud misconfiguration — combined risk of immediate credential abuse.",
    "Rotate exposed secrets, remove public access, and migrate secrets to a vault/CI secret store.",
    "T1552.001",
    "CWE-798",
    &["MITRE-T1552"],
    &["NIST-IA-5", "PCI-DSS-8.2.1", "MITRE-T1552.001"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![NS_NO_NETPOL, REPO_SECRET_AND_PUBLIC]
}

#[derive(Default)]
struct NsState {
    workloads: Vec<String>,
    has_netpol: bool,
}

/// Correlate across all scanned files. Only emits findings backed by observed file content.
#[must_use]
pub fn correlate(files: &[IacFile], per_file_findings: &[Finding]) -> Vec<Finding> {
    let mut out = Vec::new();
    if files.len() < 2 {
        return out;
    }

    let mut ns_map: HashMap<String, NsState> = HashMap::new();

    for file in files {
        let fw = detect::detect(&file.name, &file.content, file.forced);
        if fw != Framework::Kubernetes && fw != Framework::Helm {
            continue;
        }
        for de in serde_yaml::Deserializer::from_str(&file.content) {
            let Ok(doc) = serde_yaml::Value::deserialize(de) else { continue };
            let kind = doc.get("kind").and_then(|k| k.as_str()).unwrap_or("");
            let name = doc.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()).unwrap_or("unnamed");
            let ns = doc.get("metadata").and_then(|m| m.get("namespace")).and_then(|n| n.as_str()).unwrap_or("default").to_string();

            match kind {
                "NetworkPolicy" => {
                    let targets = netpol_namespaces(&doc);
                    if targets.is_empty() {
                        ns_map.entry(ns.clone()).or_default().has_netpol = true;
                    } else {
                        for t in targets {
                            ns_map.entry(t).or_default().has_netpol = true;
                        }
                    }
                }
                "Deployment" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob" | "Pod" => {
                    ns_map.entry(ns.clone()).or_default().workloads.push(format!("{kind}/{name}"));
                }
                _ => {}
            }
        }
    }

    for (ns, state) in &ns_map {
        if !state.workloads.is_empty() && !state.has_netpol {
            out.push(
                Finding::new(NS_NO_NETPOL, &format!("namespace/{ns}"), "cross-file-correlation")
                    .observed(format!(
                        "namespace '{}' has {} workload(s) [{}] but zero NetworkPolicy in scan",
                        ns,
                        state.workloads.len(),
                        state.workloads.join(", ")
                    ))
                    .fix(format!(
                        "# k8s/network-policy-{ns}.yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny\n  namespace: {ns}\nspec:\n  podSelector: {{}}\n  policyTypes: [Ingress, Egress]"
                    )),
            );
        }
    }

    // Secret + public cloud in same repo
    let has_secret = per_file_findings.iter().any(|f| f.policy.framework == "secrets");
    let public_cloud = per_file_findings.iter().any(|f| {
        matches!(
            f.policy.id,
            "WZ-TF-AWS-S3-001" | "WZ-TF-AWS-S3-002" | "WZ-TF-AWS-RDS-001" | "WZ-TF-AWS-SG-001"
                | "WZ-TF-GCP-GCS-001" | "WZ-CFN-S3-001" | "WZ-CFN-RDS-001"
        )
    });
    if has_secret && public_cloud {
        out.push(
            Finding::new(REPO_SECRET_AND_PUBLIC, "repository", "cross-file-correlation")
                .observed("secret scanner + public cloud misconfiguration in same repository scan"),
        );
    }

    out
}

fn netpol_namespaces(doc: &serde_yaml::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ns) = doc.get("metadata").and_then(|m| m.get("namespace")).and_then(|n| n.as_str()) {
        out.push(ns.to_string());
    }
    if doc.get("spec").and_then(|s| s.get("podSelector")).is_some() {
        if out.is_empty() {
            // applies to default if no ns in metadata
            out.push("default".to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_namespace_without_netpol() {
        let files = vec![
            IacFile {
                name: "deploy.yaml".into(),
                content: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: payments\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: app:1\n".into(),
                forced: None,
                origin: "inline".into(),
            },
            IacFile {
                name: "other.yaml".into(),
                content: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n".into(),
                forced: None,
                origin: "inline".into(),
            },
        ];
        let f = correlate(&files, &[]);
        assert!(f.iter().any(|x| x.policy.id == NS_NO_NETPOL.id));
    }
}
