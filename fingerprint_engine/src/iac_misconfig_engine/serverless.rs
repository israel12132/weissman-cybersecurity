//! Serverless Framework (`serverless.yml`) analyzer — IAM wildcards, public HTTP events without
//! authorizers, and deprecated runtimes.

use super::model::{Finding, PolicyMeta, Severity};
use serde_yaml::Value;

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "serverless", provider: "aws",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const IAM_WILDCARD: PolicyMeta = pol!("WZ-SLS-001", "Serverless IAM role statement grants wildcard", Critical, "provider.iamRoleStatements allows Action * on Resource *, granting Lambdas full account access.", "Scope iamRoleStatements to the minimum actions and ARNs required per function.", "T1098", "CWE-269", &["CIS-AWS-1.16"], &["CIS-AWS-1.16", "NIST-AC-6", "MITRE-T1098"]);
pub const PUBLIC_HTTP: PolicyMeta = pol!("WZ-SLS-002", "Serverless HTTP event is public without authorizer", High, "An httpApi/http event exposes a Lambda without an authorizer or Cognito/JWT guard.", "Add an authorizer (JWT/Cognito/IAM) or restrict to private API Gateway.", "T1190", "CWE-306", &["OWASP-API2"], &["NIST-AC-3", "SOC2-CC6.1"]);
pub const DEPRECATED_RUNTIME: PolicyMeta = pol!("WZ-SLS-003", "Serverless function uses deprecated Node/Python runtime", Medium, "The function runtime is end-of-life, missing security patches.", "Upgrade to a supported runtime (nodejs20.x, python3.12, etc.).", "T1525", "CWE-1104", &["CIS-AWS-Lambda"], &["NIST-SI-2", "SOC2-CC7.1"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![IAM_WILDCARD, PUBLIC_HTTP, DEPRECATED_RUNTIME]
}

const EOL_RUNTIMES: &[&str] = &[
    "nodejs14.x", "nodejs12.x", "nodejs10.x", "python3.7", "python3.6", "ruby2.7", "go1.x",
];

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(doc): Result<Value, _> = serde_yaml::from_str(content) else { return out };
    if doc.get("service").is_none() && doc.get("functions").is_none() {
        return out;
    }

    // provider.iamRoleStatements
    if let Some(stmts) = doc
        .get("provider")
        .and_then(|p| p.get("iamRoleStatements").or_else(|| p.get("iam").and_then(|i| i.get("role")).and_then(|r| r.get("statements"))))
        .and_then(Value::as_sequence)
    {
        for stmt in stmts {
            let actions: Vec<String> = stmt.get("Action")
                .and_then(Value::as_sequence)
                .map(|s| s.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .or_else(|| stmt.get("Action").and_then(Value::as_str).map(|s| vec![s.to_string()]))
                .unwrap_or_default();
            let resources: Vec<String> = stmt.get("Resource")
                .and_then(Value::as_sequence)
                .map(|s| s.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .or_else(|| stmt.get("Resource").and_then(Value::as_str).map(|s| vec![s.to_string()]))
                .unwrap_or_default();
            if actions.iter().any(|a| a == "*") && resources.iter().any(|r| r == "*") {
                out.push(Finding::new(IAM_WILDCARD, "provider.iamRoleStatements", file).observed("Action * Resource *"));
            }
        }
    }

    if let Some(functions) = doc.get("functions").and_then(Value::as_mapping) {
        for (fname, fdef) in functions {
            let name = fname.as_str().unwrap_or("function");
            if let Some(rt) = fdef.get("runtime").and_then(Value::as_str) {
                if EOL_RUNTIMES.contains(&rt) {
                    out.push(Finding::new(DEPRECATED_RUNTIME, name, file).observed(format!("runtime = {rt}")));
                }
            }
            if let Some(events) = fdef.get("events").and_then(Value::as_sequence) {
                for ev in events {
                    let http = ev.get("http").or_else(|| ev.get("httpApi"));
                    if let Some(h) = http {
                        if h.get("authorizer").is_none() && h.get("private").and_then(Value::as_bool) != Some(true) {
                            out.push(
                                Finding::new(PUBLIC_HTTP, name, file)
                                    .observed(format!("{name} http event without authorizer")),
                            );
                        }
                    }
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_wildcard_iam() {
        let y = "service: app\nprovider:\n  iamRoleStatements:\n    - Effect: Allow\n      Action: '*'\n      Resource: '*'\nfunctions:\n  api:\n    handler: h.handler\n";
        let f = evaluate("serverless.yml", y);
        assert!(f.iter().any(|x| x.policy.id == IAM_WILDCARD.id));
    }
}
