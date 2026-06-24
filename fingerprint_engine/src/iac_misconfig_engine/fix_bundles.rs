//! Fix-as-code bundle exporter — aggregates every concrete code_fix from findings into an
//! apply-ready artifact grouped by file (Terraform/K8s/Ansible patches).

use super::model::Finding;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[must_use]
pub fn export_bundle(findings: &[Finding], target: &str, gate_evidence: Option<&Value>) -> Value {
    let mut by_file: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut count = 0u64;

    for f in findings {
        let Some(fix) = &f.code_fix else { continue };
        if fix.trim().is_empty() {
            continue;
        }
        count += 1;
        by_file.entry(f.file.clone()).or_default().push(json!({
            "policy_id": f.policy.id,
            "severity": f.policy.severity.as_str(),
            "resource": f.resource,
            "line": f.line,
            "fix": fix,
            "remediation": f.policy.remediation,
        }));
    }

    let files: Vec<Value> = by_file
        .into_iter()
        .map(|(file, fixes)| json!({ "file": file, "fixes": fixes, "fix_count": fixes.len() }))
        .collect();

    let mut bundle = json!({
        "target": target,
        "fix_count": count,
        "file_count": files.len(),
        "files": files,
        "format": "weissman-iac-fix-bundle-v2",
        "shell_script": render_shell_script(&files),
    });
    if let Some(evidence) = gate_evidence {
        if let Some(obj) = bundle.as_object_mut() {
            obj.insert("gate_evidence".to_string(), evidence.clone());
        }
    }
    bundle
}

fn render_shell_script(files: &[Value]) -> String {
    let mut lines = vec![
        "#!/usr/bin/env bash".to_string(),
        "# Weissman IaC auto-fix bundle — review before applying".to_string(),
        "set -euo pipefail".to_string(),
    ];
    for f in files {
        let file = f.get("file").and_then(Value::as_str).unwrap_or("unknown");
        lines.push(format!("\n# --- {file} ---"));
        if let Some(fixes) = f.get("fixes").and_then(Value::as_array) {
            for fix in fixes {
                let pol = fix.get("policy_id").and_then(Value::as_str).unwrap_or("?");
                let snippet = fix.get("fix").and_then(Value::as_str).unwrap_or("");
                lines.push(format!("# [{pol}]"));
                for l in snippet.lines() {
                    lines.push(format!("#   {l}"));
                }
            }
        }
    }
    lines.push("\necho 'Review fixes above — apply manually or via your IaC pipeline'".to_string());
    lines.join("\n")
}
