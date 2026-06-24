//! Argo CD Application / AppProject analyzer — GitOps sync policies, orphaned resources,
//! cluster-admin project scopes, and auto-sync without prune/self-heal guardrails.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "argocd", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const SYNC_WILDCARD: PolicyMeta = pol!("WZ-ARGO-001", "Argo CD Application syncs from mutable ref (*)", Critical, "source.targetRevision or ref is * / HEAD — any commit to the repo deploys immediately.", "Pin targetRevision to a tag, branch name, or commit SHA; enable signature verification.", "T1195.002", "CWE-494", &["CIS-K8S-5.1.1"], &["NIST-SA-12", "SOC2-CC8.1"]);
pub const PROJECT_CLUSTER_ADMIN: PolicyMeta = pol!("WZ-ARGO-002", "Argo CD AppProject grants cluster-admin destinations", Critical, "AppProject clusterResourceWhitelist or destinations include cluster-wide admin resources.", "Scope AppProject to namespaces and resource kinds required only.", "T1098", "CWE-732", &["CIS-K8S-5.1.1"], &["NIST-AC-6", "SOC2-CC6.3"]);
pub const ORPHANED_RESOURCES: PolicyMeta = pol!("WZ-ARGO-003", "Argo CD allows orphaned resources", High, "syncPolicy.orphanedResources.warn / allow lets drifted cluster objects persist outside Git.", "Set orphanedResources: {} with deny policy or enable automatic pruning.", "T1098", "CWE-693", &["CIS-K8S-5.1.1"], &["NIST-CM-3", "SOC2-CC8.1"]);
pub const AUTO_SYNC_NO_PRUNE: PolicyMeta = pol!("WZ-ARGO-004", "Argo CD automated sync without prune", Medium, "automated.selfHeal or automated enabled without prune — stale compromised resources remain.", "Enable automated.prune with selfHeal; use sync windows for production.", "T1098", "CWE-693", &["CIS-K8S-5.1.1"], &["NIST-CM-3", "SOC2-CC8.1"]);
pub const INSECURE_REPO: PolicyMeta = pol!("WZ-ARGO-005", "Argo CD repo URL uses insecure HTTP or embeds credentials", High, "repoURL uses http:// or contains user:pass@ in the URL.", "Use https:// with deploy keys or OIDC; store credentials in Argo CD secrets.", "T1552.001", "CWE-319", &["CIS-K8S-5.4.1"], &["NIST-SC-8", "PCI-DSS-4.1"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![SYNC_WILDCARD, PROJECT_CLUSTER_ADMIN, ORPHANED_RESOURCES, AUTO_SYNC_NO_PRUNE, INSECURE_REPO]
}

fn is_argocd(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.contains("argocd") || lc.contains("argoproj.io") || lc.contains("kind: application") && lc.contains("syncpolicy")
        || lc.contains("kind: appproject")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_argocd(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("targetrevision: '*'") || lc.contains("targetrevision: head") || lc.contains("ref: head") {
        out.push(Finding::new(SYNC_WILDCARD, file, file).observed("mutable targetRevision/ref"));
    }
    if lc.contains("clusterresourcewhitelist") || lc.contains("destinations:") && lc.contains("namespace: '*'") && lc.contains("server: '*'") {
        out.push(Finding::new(PROJECT_CLUSTER_ADMIN, file, file).observed("cluster-wide AppProject scope"));
    }
    if lc.contains("orphanedresources") && !lc.contains("orphanedresources: {}") {
        out.push(Finding::new(ORPHANED_RESOURCES, file, file).observed("orphanedResources policy"));
    }
    if lc.contains("automated:") && lc.contains("selfheal: true") && !lc.contains("prune: true") {
        out.push(Finding::new(AUTO_SYNC_NO_PRUNE, file, file).observed("automated sync without prune"));
    }
    if lc.contains("repourl:") && (lc.contains("http://") || lc.contains("@") && lc.contains("://")) {
        out.push(Finding::new(INSECURE_REPO, file, file).observed("insecure or credentialed repoURL"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_wildcard_sync() {
        let y = "apiVersion: argoproj.io/v1alpha1\nkind: Application\nspec:\n  source:\n    targetRevision: HEAD\n";
        assert!(evaluate("app.yaml", y).iter().any(|f| f.policy.id == SYNC_WILDCARD.id));
    }
}
