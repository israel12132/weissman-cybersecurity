//! Terraform plan JSON analyzer — validates **planned** infrastructure changes (terraform show -json)
//! for destructive or high-risk creates/updates that static HCL may not catch post-refactor.

use super::model::{Finding, PolicyMeta, Severity};
use serde_json::Value;

use Severity::{Critical, High};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "tfplan", provider: "aws",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const PLAN_S3_PUBLIC: PolicyMeta = pol!("WZ-PLAN-001", "Terraform plan creates/updates public S3 ACL", Critical, "resource_changes plans aws_s3_bucket* with public-read ACL or public access block disabled.", "Abort apply; set private ACL and enable public access block.", "T1530", "CWE-732", &["CIS-AWS-2.1.5"], &["NIST-AC-3", "PCI-DSS-1.2.1"]);
pub const PLAN_SG_OPEN: PolicyMeta = pol!("WZ-PLAN-002", "Terraform plan opens security group to 0.0.0.0/0", Critical, "planned SG ingress includes 0.0.0.0/0.", "Restrict CIDR before apply.", "T1190", "CWE-284", &["CIS-AWS-5.2"], &["NIST-SC-7", "PCI-DSS-1.3.1"]);
pub const PLAN_IAM_ADMIN: PolicyMeta = pol!("WZ-PLAN-003", "Terraform plan attaches IAM wildcard admin", Critical, "planned IAM policy Statement with Action * Resource *.", "Scope IAM before apply.", "T1098", "CWE-732", &["CIS-AWS-1.16"], &["NIST-AC-6", "PCI-DSS-7.1.2"]);
pub const PLAN_RDS_PUBLIC: PolicyMeta = pol!("WZ-PLAN-004", "Terraform plan makes RDS publicly accessible", High, "aws_db_instance planned change sets publicly_accessible true.", "Set publicly_accessible false before apply.", "T1190", "CWE-668", &["CIS-AWS-2.3.1"], &["NIST-SC-7", "PCI-DSS-1.3.6"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![PLAN_S3_PUBLIC, PLAN_SG_OPEN, PLAN_IAM_ADMIN, PLAN_RDS_PUBLIC]
}

#[must_use]
pub fn evaluate_plan(plan_json: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(plan_json) else {
        return out;
    };
    let changes = v
        .get("resource_changes")
        .or_else(|| v.get("planned_values").and_then(|p| p.get("resource_changes")))
        .and_then(Value::as_array);
    let Some(changes) = changes else { return out };

    for ch in changes {
        let rtype = ch.get("type").and_then(Value::as_str).unwrap_or("");
        let addr = ch.get("address").and_then(Value::as_str).unwrap_or("unknown");
        let actions = ch.get("change").and_then(|c| c.get("actions")).and_then(Value::as_array);
        let is_planned = actions.map(|a| a.iter().any(|x| x.as_str() == Some("create") || x.as_str() == Some("update"))).unwrap_or(true);
        if !is_planned {
            continue;
        }
        let after = ch
            .get("change")
            .and_then(|c| c.get("after"))
            .cloned()
            .or_else(|| ch.get("after").cloned())
            .unwrap_or(Value::Null);
        let raw = after.to_string().to_ascii_lowercase();

        if rtype.contains("aws_s3_bucket") && (raw.contains("public-read") || raw.contains("\"block_public_acls\":false")) {
            out.push(Finding::new(PLAN_S3_PUBLIC, addr, "terraform.plan.json").observed("planned public S3"));
        }
        if rtype.contains("aws_security_group") && raw.contains("0.0.0.0/0") {
            out.push(Finding::new(PLAN_SG_OPEN, addr, "terraform.plan.json").observed("planned open SG"));
        }
        if rtype.contains("aws_iam") && raw.contains("\"*\"") && raw.contains("allow") {
            out.push(Finding::new(PLAN_IAM_ADMIN, addr, "terraform.plan.json").observed("planned IAM wildcard"));
        }
        if rtype.contains("aws_db_instance") && raw.contains("publicly_accessible") && raw.contains("true") {
            out.push(Finding::new(PLAN_RDS_PUBLIC, addr, "terraform.plan.json").observed("planned public RDS"));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_planned_public_s3() {
        let plan = r#"{"resource_changes":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","change":{"actions":["create"],"after":{"acl":"public-read"}}}]}"#;
        assert!(evaluate_plan(plan).iter().any(|f| f.policy.id == PLAN_S3_PUBLIC.id));
    }
}
