//! Plan ↔ code reconciliation — when both static Terraform and a plan JSON are supplied,
//! detects gaps where code looks clean but plan will deploy risk, or code flags issues plan ignores.

use super::model::{Finding, PolicyMeta, Severity};
use super::{terraform, tfplan};
use std::collections::HashSet;

use Severity::High;

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "reconcile",
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

pub const PLAN_WORSE: PolicyMeta = pol!(
    "WZ-RECON-001",
    "Terraform plan introduces risk not visible in static HCL scan",
    High,
    "Plan JSON shows high-risk creates/updates but static analysis of submitted .tf files did not flag equivalent resources — possible generated/module-expanded risk.",
    "Inspect module outputs; block apply; extend scan to full module tree.",
    "T1190",
    "CWE-693",
    &["CIS-IaC"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const CODE_WORSE: PolicyMeta = pol!(
    "WZ-RECON-002",
    "Static HCL flags issues absent from Terraform plan",
    High,
    "Static files contain violations but the supplied plan does not include matching resource changes — stale plan or partial workspace.",
    "Regenerate plan from current code; ensure same workspace/root module.",
    "T1195",
    "CWE-693",
    &["CIS-IaC"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const PLAN_STATIC_GAP: PolicyMeta = pol!(
    "WZ-RECON-003",
    "Plan and static analysis disagree on IAM/S3 posture",
    High,
    "Combined S3/IAM policy IDs differ between plan analysis and static HCL — reconciliation required before merge.",
    "Align plan generation with scanned paths; fail CI on mismatch.",
    "T1190",
    "CWE-693",
    &["CIS-IaC"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![PLAN_WORSE, CODE_WORSE, PLAN_STATIC_GAP]
}

const PLAN_IDS: &[&str] = &["WZ-PLAN-001", "WZ-PLAN-002", "WZ-PLAN-003", "WZ-PLAN-004"];
const STATIC_S3_IAM: &[&str] = &[
    "WZ-TF-AWS-S3-001",
    "WZ-TF-AWS-S3-002",
    "WZ-TF-AWS-IAM-001",
    "WZ-TF-AWS-SG-001",
    "WZ-TF-AWS-SG-002",
];

/// Reconcile static terraform findings against plan findings.
#[must_use]
pub fn reconcile(static_findings: &[Finding], plan_findings: &[Finding]) -> Vec<Finding> {
    let mut out = Vec::new();
    if plan_findings.is_empty() {
        return out;
    }

    let static_ids: HashSet<&str> = static_findings.iter().map(|f| f.policy.id).collect();
    let plan_ids: HashSet<&str> = plan_findings.iter().map(|f| f.policy.id).collect();

    let plan_risk: Vec<&Finding> = plan_findings
        .iter()
        .filter(|f| PLAN_IDS.contains(&f.policy.id))
        .collect();
    if !plan_risk.is_empty() && plan_risk.iter().all(|f| !static_ids.contains(f.policy.id)) {
        let obs = plan_risk
            .iter()
            .map(|f| f.policy.id)
            .collect::<Vec<_>>()
            .join(", ");
        out.push(
            Finding::new(PLAN_WORSE, "plan-vs-static", "reconcile")
                .observed(format!("plan policies [{obs}] not in static scan")),
        );
    }

    let static_only: Vec<&Finding> = static_findings
        .iter()
        .filter(|f| f.policy.framework == "terraform" && !plan_ids.contains(f.policy.id))
        .collect();
    if static_only.len() >= 2 && !plan_findings.is_empty() {
        let obs = static_only
            .iter()
            .take(4)
            .map(|f| f.policy.id)
            .collect::<Vec<_>>()
            .join(", ");
        out.push(
            Finding::new(CODE_WORSE, "static-vs-plan", "reconcile")
                .observed(format!("static-only policies [{obs}]")),
        );
    }

    let static_s3_iam = static_ids
        .iter()
        .filter(|id| STATIC_S3_IAM.contains(id))
        .count();
    let plan_s3_iam = plan_ids.iter().filter(|id| PLAN_IDS.contains(id)).count();
    if static_s3_iam > 0 && plan_s3_iam > 0 && static_s3_iam != plan_s3_iam {
        out.push(
            Finding::new(PLAN_STATIC_GAP, "s3-iam-reconcile", "reconcile").observed(format!(
                "static_s3_iam={static_s3_iam} plan_risk={plan_s3_iam}"
            )),
        );
    }

    let _ = terraform::policies();
    let _ = tfplan::policies();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::tfplan::PLAN_S3_PUBLIC;

    #[test]
    fn detects_plan_worse_than_static() {
        let plan = vec![Finding::new(PLAN_S3_PUBLIC, "aws_s3_bucket.b", "plan.json")];
        let out = reconcile(&[], &plan);
        assert!(out.iter().any(|f| f.policy.id == PLAN_WORSE.id));
    }
}
