//! Kustomize (`kustomization.yaml`) analyzer — detects overlays that weaken security (privileged
//! patches, `:latest` image overrides, removal of resource limits).

use super::model::{Finding, PolicyMeta, Severity};
use serde_yaml::Value;

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "kustomize",
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

pub const PATCH_PRIV: PolicyMeta = pol!(
    "WZ-KUS-001",
    "Kustomize patch enables privileged container",
    High,
    "A JSON6902/strategic patch sets privileged: true on a workload.",
    "Remove the patch; enforce Pod Security Standards restricted in the base.",
    "T1610",
    "CWE-250",
    &["CIS-K8S-5.2.1"],
    &["NIST-AC-6", "MITRE-T1610"]
);
pub const PATCH_LATEST: PolicyMeta = pol!(
    "WZ-KUS-002",
    "Kustomize images override uses mutable tag",
    Medium,
    "The images list sets a :latest or untagged image, breaking immutability.",
    "Pin to a digest or fixed semver tag in kustomization images.",
    "T1525",
    "CWE-494",
    &["CIS-K8S-5.x"],
    &["NIST-CM-2", "SOC2-CC8.1"]
);
pub const PATCH_DROP_LIMITS: PolicyMeta = pol!(
    "WZ-KUS-003",
    "Kustomize patch removes resource limits",
    Medium,
    "A patch removes CPU/memory limits, enabling resource exhaustion DoS.",
    "Keep limits in the base; never strip resources.limits in overlays.",
    "T1499",
    "CWE-770",
    &["CIS-K8S-5.x"],
    &["NIST-SC-6"]
);
pub const PATCH_HOST_NETWORK: PolicyMeta = pol!(
    "WZ-KUS-004",
    "Kustomize patch enables hostNetwork",
    High,
    "Overlay patch sets hostNetwork: true — bypasses network policies and exposes node network.",
    "Remove hostNetwork patch; use ClusterIP Services and NetworkPolicy.",
    "T1611",
    "CWE-668",
    &["CIS-K8S-5.2.4"],
    &["NIST-AC-4", "ISO27001-A.8.20"]
);
pub const PATCH_SECCOMP_UNCONFINED: PolicyMeta = pol!(
    "WZ-KUS-005",
    "Kustomize patch sets seccomp Unconfined",
    High,
    "Patch sets seccompProfile.type: Unconfined — disables syscall filtering.",
    "Use RuntimeDefault or Localhost profile; never weaken seccomp in overlays.",
    "T1610",
    "CWE-250",
    &["CIS-K8S-5.2.6"],
    &["NIST-CM-7", "SOC2-CC6.8"]
);
pub const NAMESPACE_ESCAPE: PolicyMeta = pol!(
    "WZ-KUS-006",
    "Kustomize overlay targets kube-system namespace",
    Critical,
    "namespace: kube-system in kustomization — prod overlay deploys into system namespace.",
    "Scope overlays to app namespaces; use kustomize components for shared bases only.",
    "T1098",
    "CWE-668",
    &["CIS-K8S-5.2.1"],
    &["NIST-AC-6", "PCI-DSS-7.1"]
);
pub const SECRET_LITERAL: PolicyMeta = pol!(
    "WZ-KUS-007",
    "Kustomize secretGenerator uses literal password",
    Critical,
    "secretGenerator literals/envs contain password/token literals committed to Git.",
    "Use external secrets or SOPS-encrypted generators; never commit secret literals.",
    "T1552.001",
    "CWE-798",
    &["CIS-Secrets"],
    &["NIST-IA-5", "PCI-DSS-8.2.1", "ISO27001-A.8.24"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        PATCH_PRIV,
        PATCH_LATEST,
        PATCH_DROP_LIMITS,
        PATCH_HOST_NETWORK,
        PATCH_SECCOMP_UNCONFINED,
        NAMESPACE_ESCAPE,
        SECRET_LITERAL,
    ]
}

fn is_kustomization(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("kustomization.yaml")
        || n.ends_with("kustomization.yml")
        || content.contains("apiVersion: kustomize.config.k8s.io")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_kustomization(file, content) {
        return out;
    }
    let Ok(doc): Result<Value, _> = serde_yaml::from_str(content) else {
        return out;
    };
    let lc = content.to_ascii_lowercase();

    if lc.contains("privileged: true") || lc.contains("privileged:true") {
        out.push(Finding::new(PATCH_PRIV, file, file).observed("patch sets privileged: true"));
    }
    if lc.contains("hostnetwork: true") || lc.contains("hostnetwork:true") {
        out.push(
            Finding::new(PATCH_HOST_NETWORK, file, file).observed("patch sets hostNetwork: true"),
        );
    }
    if lc.contains("seccompprofile") && lc.contains("unconfined") {
        out.push(
            Finding::new(PATCH_SECCOMP_UNCONFINED, file, file)
                .observed("seccompProfile Unconfined"),
        );
    }
    if lc.contains("namespace: kube-system") || lc.contains("namespace:kube-system") {
        out.push(
            Finding::new(NAMESPACE_ESCAPE, file, file).observed("namespace kube-system in overlay"),
        );
    }
    if lc.contains("secretgenerator")
        && (lc.contains("password:")
            || lc.contains("password=")
            || lc.contains("token:")
            || lc.contains("apikey:"))
    {
        out.push(
            Finding::new(SECRET_LITERAL, file, file).observed("secretGenerator literal secret"),
        );
    }
    if lc.contains("limits:")
        && (lc.contains("remove:") || lc.contains("op: remove"))
        && lc.contains("resources")
    {
        out.push(
            Finding::new(PATCH_DROP_LIMITS, file, file).observed("patch removes resources.limits"),
        );
    }

    if let Some(images) = doc.get("images").and_then(Value::as_sequence) {
        for img in images {
            let name = img.get("name").and_then(Value::as_str).unwrap_or("image");
            let new_name = img.get("newName").and_then(Value::as_str).unwrap_or("");
            let new_tag = img.get("newTag").and_then(Value::as_str).unwrap_or("");
            let target = if !new_name.is_empty() {
                format!("{name} -> {new_name}")
            } else {
                name.to_string()
            };
            if new_tag == "latest" || (new_tag.is_empty() && !new_name.contains('@')) {
                out.push(
                    Finding::new(PATCH_LATEST, &target, file)
                        .observed(format!("images override: {target} tag={new_tag}")),
                );
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_latest_image_override() {
        let y = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nimages:\n  - name: app\n    newTag: latest\n";
        let f = evaluate("kustomization.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == PATCH_LATEST.id));
    }

    #[test]
    fn flags_secret_literal() {
        let y = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nsecretGenerator:\n  - name: db\n    literals:\n      - password=supersecret\n";
        let f = evaluate("kustomization.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == SECRET_LITERAL.id));
    }
}
