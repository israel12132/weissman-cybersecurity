//! Argo Rollouts analyzer — canary without analysis, disabled rollback, privileged analysis pods,
//! and unauthenticated header-based traffic splitting.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "argo_rollouts",
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

pub const CANARY_NO_ANALYSIS: PolicyMeta = pol!(
    "WZ-ARO-001",
    "Argo Rollout canary step without analysis template",
    High,
    "canary.steps lacks analysis templates — blind progressive delivery to prod.",
    "Add AnalysisTemplate with success-rate/latency metrics before each canary step.",
    "T1195.002",
    "CWE-754",
    &["CIS-CD"],
    &["NIST-CM-3", "SOC2-CC8.1", "ISO27001-A.8.32"]
);
pub const ROLLBACK_DISABLED: PolicyMeta = pol!(
    "WZ-ARO-002",
    "Argo Rollout abort/rollback policy disabled",
    Medium,
    "spec.strategy.canary.abortScaleDownDelaySeconds: 0 with no autoRollback — failed deploy persists.",
    "Enable automatic rollback on analysis failure; set min ready replicas during canary.",
    "T1499",
    "CWE-754",
    &["CIS-CD"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const PRIV_ANALYSIS: PolicyMeta = pol!(
    "WZ-ARO-003",
    "Argo Rollout analysis pod runs privileged",
    Critical,
    "AnalysisTemplate pod spec sets privileged: true or hostPID/hostNetwork.",
    "Run analysis jobs non-privileged; use dedicated observability SA with minimal RBAC.",
    "T1610",
    "CWE-250",
    &["CIS-K8S-5.2.1"],
    &["NIST-AC-6", "PCI-DSS-2.2.4"]
);
pub const HEADER_TRAFFIC_NO_AUTH: PolicyMeta = pol!(
    "WZ-ARO-004",
    "Argo Rollout header-based traffic routing without auth filter",
    High,
    "canary.trafficRouting.managedRoutes or header routes lack authentication — spoofable canary steering.",
    "Require signed headers or mesh authz; avoid client-controlled canary headers on public ingress.",
    "T1190",
    "CWE-306",
    &["CIS-K8S-5.7.2"],
    &["NIST-AC-3", "SOC2-CC6.6"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        CANARY_NO_ANALYSIS,
        ROLLBACK_DISABLED,
        PRIV_ANALYSIS,
        HEADER_TRAFFIC_NO_AUTH,
    ]
}

fn is_argo_rollout(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.contains("rollout")
        || lc.contains("argoproj.io") && lc.contains("kind: rollout")
        || lc.contains("kind: analysistemplate")
        || lc.contains("kind: clusteranalysistemplate")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_argo_rollout(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("strategy:")
        && lc.contains("canary:")
        && lc.contains("steps:")
        && !lc.contains("analysis:")
    {
        out.push(Finding::new(CANARY_NO_ANALYSIS, file, file).observed("canary without analysis"));
    }
    if lc.contains("abortscaledowndelayseconds: 0") && !lc.contains("autorollback: true") {
        out.push(Finding::new(ROLLBACK_DISABLED, file, file).observed("rollback policy weak"));
    }
    if lc.contains("privileged: true")
        || lc.contains("hostpid: true")
        || lc.contains("hostnetwork: true")
    {
        out.push(Finding::new(PRIV_ANALYSIS, file, file).observed("privileged analysis pod"));
    }
    if lc.contains("trafficrouting:") && lc.contains("header") && !lc.contains("authentication") {
        out.push(
            Finding::new(HEADER_TRAFFIC_NO_AUTH, file, file)
                .observed("header traffic without auth"),
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_canary_without_analysis() {
        let y = "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nspec:\n  strategy:\n    canary:\n      steps:\n        - setWeight: 20\n        - pause: {}";
        let f = evaluate("rollouts/api.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == CANARY_NO_ANALYSIS.id));
    }
}
