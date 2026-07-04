//! Helm chart analyzer — Chart.yaml dependency pinning, values.yaml secret detection, and template
//! pattern checks for dangerous K8s constructs embedded in Helm templates (without requiring `helm
//! template` rendering — we analyze the raw chart sources deterministically).

use super::kubernetes;
use super::model::{Finding, PolicyMeta, Severity};
use serde_yaml::Value;

use Severity::{Critical, High, Low};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "helm",
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

pub const DEP_UNPINNED: PolicyMeta = pol!("WZ-HELM-001", "Helm chart dependency without pinned version", High, "A Chart.yaml dependency has no version constraint, allowing mutable chart pulls that can introduce supply-chain implants.", "Pin every dependency to an exact semver version (e.g. version: 1.2.3).", "T1195.001", "CWE-494", &["CIS-K8S-5.x"], &["NIST-SA-12", "SOC2-CC8.1"]);
pub const VALUES_SECRET: PolicyMeta = pol!("WZ-HELM-002", "Secret hard-coded in Helm values.yaml", High, "values.yaml embeds a credential literal that will be rendered into Kubernetes secrets/configmaps.", "Use Helm secrets plugin, SOPS, or external-secrets; never commit plaintext credentials.", "T1552.001", "CWE-798", &["CIS-K8S-5.x"], &["NIST-IA-5", "PCI-DSS-8.2.1"]);
pub const TEMPLATE_PRIV: PolicyMeta = pol!("WZ-HELM-003", "Helm template enables privileged container", Critical, "A Helm template sets securityContext.privileged or hostPath to the Docker socket.", "Fix the template to enforce Pod Security Standards restricted; upgrade the upstream chart if vendor-maintained.", "T1610", "CWE-250", &["CIS-K8S-5.2.1"], &["NIST-AC-6", "MITRE-T1610"]);
pub const CHART_APP_OLD: PolicyMeta = pol!("WZ-HELM-004", "Helm chart uses deprecated apiVersion", Low, "Chart templates use deprecated Kubernetes API versions that may break on upgrade and hide security defaults.", "Bump apiVersion to current stable (e.g. apps/v1, networking.k8s.io/v1).", "T1525", "CWE-1104", &["CIS-K8S-5.x"], &["NIST-CM-2"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![DEP_UNPINNED, VALUES_SECRET, TEMPLATE_PRIV, CHART_APP_OLD]
}

fn secretish_key(key: &str) -> bool {
    let up = key.to_ascii_uppercase();
    [
        "PASSWORD",
        "SECRET",
        "API_KEY",
        "TOKEN",
        "PRIVATE_KEY",
        "CREDENTIAL",
    ]
    .iter()
    .any(|k| up.contains(k))
}

fn is_chart_yaml(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("chart.yaml") || n.ends_with("chart.yml")
}

fn is_values_yaml(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("values.yaml") || n.ends_with("values.yml")
}

fn is_helm_template(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("/templates/")
        && (n.ends_with(".yaml") || n.ends_with(".yml") || n.ends_with(".tpl"))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if is_chart_yaml(file) {
        out.extend(eval_chart(file, content));
    } else if is_values_yaml(file) {
        out.extend(eval_values(file, content));
    } else if is_helm_template(file) {
        out.extend(eval_template(file, content));
    }
    out
}

fn eval_chart(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(doc): Result<Value, _> = serde_yaml::from_str(content) else {
        return out;
    };
    if let Some(deps) = doc.get("dependencies").and_then(Value::as_sequence) {
        for dep in deps {
            let name = dep
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("dependency");
            let ver = dep
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if ver.is_empty() {
                out.push(
                    Finding::new(DEP_UNPINNED, name, file)
                        .observed(format!("dependency '{}' has no version pin", name))
                        .fix(format!("  - name: {}\n    version: \"x.y.z\"", name)),
                );
            }
        }
    }
    out
}

fn eval_values(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(doc): Result<Value, _> = serde_yaml::from_str(content) else {
        return out;
    };
    walk_values(&doc, "", file, &mut out);
    out
}

fn walk_values(v: &Value, path: &str, file: &str, out: &mut Vec<Finding>) {
    match v {
        Value::Mapping(m) => {
            for (k, val) in m {
                let key = k.as_str().unwrap_or("");
                let p = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{}.{}", path, key)
                };
                if secretish_key(key) {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() && !s.starts_with('$') && !s.contains("{{") {
                            out.push(
                                Finding::new(VALUES_SECRET, &p, file)
                                    .observed(format!("{} = <redacted>", p))
                                    .fix("# use external-secrets or SOPS-encrypted values"),
                            );
                        }
                    }
                }
                walk_values(val, &p, file, out);
            }
        }
        Value::Sequence(seq) => {
            for (i, item) in seq.iter().enumerate() {
                walk_values(item, &format!("{}[{}]", path, i), file, out);
            }
        }
        _ => {}
    }
}

fn eval_template(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();
    if lc.contains("privileged: true") || lc.contains("privileged:true") {
        out.push(
            Finding::new(TEMPLATE_PRIV, file, file)
                .observed("privileged: true in template")
                .fix("privileged: false"),
        );
    }
    if lc.contains("docker.sock") || lc.contains("/var/run/docker.sock") {
        out.push(
            Finding::new(TEMPLATE_PRIV, file, file).observed("hostPath docker.sock in template"),
        );
    }
    if lc.contains("apiversion: extensions/v1beta1") || lc.contains("apiversion: apps/v1beta") {
        out.push(
            Finding::new(CHART_APP_OLD, file, file).observed("deprecated apiVersion in template"),
        );
    }
    // Re-use K8s policies on template YAML that looks like a rendered manifest.
    if lc.contains("kind:") && lc.contains("apiversion:") {
        out.extend(kubernetes::evaluate(file, content));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unpinned_dependency() {
        let y = "apiVersion: v2\nname: app\ndependencies:\n  - name: nginx\n    repository: https://charts.bitnami.com/bitnami\n";
        let f = evaluate("Chart.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == DEP_UNPINNED.id));
    }

    #[test]
    fn flags_values_secret() {
        let y = "database:\n  password: SuperSecret123!\n";
        let f = evaluate("values.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == VALUES_SECRET.id));
    }
}
