//! Tekton CI/CD pipeline analyzer — privileged tasks, secret literals in params, and mutable task images.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "tekton",
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

pub const PRIVILEGED_TASK: PolicyMeta = pol!(
    "WZ-TKN-001",
    "Tekton task runs privileged container",
    Critical,
    "task spec steps securityContext.privileged: true — pipeline step has node-level capabilities.",
    "Remove privileged; use minimal base images and non-root users.",
    "T1610",
    "CWE-250",
    &["CIS-CI"],
    &["NIST-AC-6", "SOC2-CC6.1"]
);
pub const PARAM_SECRET: PolicyMeta = pol!(
    "WZ-TKN-002",
    "Tekton Pipeline param embeds secret literal",
    Critical,
    "params default or PipelineRun param value contains password/token literal.",
    "Use Tekton secrets / Workspaces with secret volume; never default secrets in YAML.",
    "T1552.001",
    "CWE-798",
    &["CIS-CI"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const LATEST_IMAGE: PolicyMeta = pol!(
    "WZ-TKN-003",
    "Tekton task step uses mutable image tag",
    High,
    "step image uses :latest or untagged reference.",
    "Pin step images to digest; use internal registry mirrors.",
    "T1195.001",
    "CWE-494",
    &["CIS-Supply"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);
pub const WILDCARD_SA: PolicyMeta = pol!(
    "WZ-TKN-004",
    "Tekton PipelineRun uses cluster-admin service account",
    High,
    "serviceAccountName: default or pipeline-sa with cluster-admin binding referenced.",
    "Dedicated least-privilege SA per pipeline; scope RBAC to namespace.",
    "T1098",
    "CWE-732",
    &["CIS-CI"],
    &["NIST-AC-6", "SOC2-CC6.3"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![PRIVILEGED_TASK, PARAM_SECRET, LATEST_IMAGE, WILDCARD_SA]
}

fn is_tekton(content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("tekton.dev")
        || (lc.contains("kind: pipeline") && lc.contains("tekton"))
        || (lc.contains("kind: pipelinerun") && lc.contains("tekton"))
        || (lc.contains("kind: task") && lc.contains("tekton"))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_tekton(content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("privileged: true") {
        out.push(Finding::new(PRIVILEGED_TASK, file, file).observed("privileged Tekton step"));
    }
    if lc.contains("params:")
        && (lc.contains("password:") || lc.contains("token:") || lc.contains("apikey:"))
    {
        out.push(Finding::new(PARAM_SECRET, file, file).observed("secret literal in params"));
    }
    if lc.contains("image:") && lc.contains(":latest") {
        out.push(Finding::new(LATEST_IMAGE, file, file).observed(":latest task image"));
    }
    if lc.contains("serviceaccountname: default") || lc.contains("cluster-admin") {
        out.push(Finding::new(WILDCARD_SA, file, file).observed("overprivileged pipeline SA"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_privileged_step() {
        let y = "apiVersion: tekton.dev/v1\nkind: Task\nspec:\n  steps:\n    - name: build\n      image: ubuntu:latest\n      securityContext:\n        privileged: true";
        let f = evaluate("tekton/task.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == PRIVILEGED_TASK.id));
    }
}
