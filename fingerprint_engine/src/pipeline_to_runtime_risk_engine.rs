//! **Pipeline-to-Runtime Risk** — live fusion of IaC misconfig + supply chain + CI/CD pipeline.
//!
//! Traces misconfigurations from commit through build artifacts to runtime exposure.
//! Evidence-only synthesis — no stub findings.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

const ENGINE_ID: &str = "pipeline_to_runtime_risk";

fn pbool(params: &Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn finding_severity(f: &Value) -> &str {
    f.get("severity").and_then(Value::as_str).unwrap_or("info")
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn haystack(f: &Value) -> String {
    format!(
        "{} {} {} {}",
        f.get("title").and_then(Value::as_str).unwrap_or(""),
        f.get("description").and_then(Value::as_str).unwrap_or(""),
        f.get("category").and_then(Value::as_str).unwrap_or(""),
        f.get("resource").and_then(Value::as_str).unwrap_or(""),
    )
    .to_lowercase()
}

fn has_signal(findings: &[Value], keywords: &[&str]) -> bool {
    findings
        .iter()
        .any(|f| keywords.iter().any(|k| haystack(f).contains(k)))
}

fn ingest_source(
    merged: &mut Vec<Value>,
    penalty: &mut u32,
    label: &str,
    result: &EngineResult,
) -> bool {
    if !result.success || result.findings.is_empty() {
        return false;
    }
    for mut f in result.findings.clone() {
        if let Some(obj) = f.as_object_mut() {
            obj.entry("source_engine".to_string())
                .or_insert(json!(label));
            obj.entry("fusion_engine".to_string())
                .or_insert(json!(ENGINE_ID));
        }
        *penalty += match severity_rank(finding_severity(&f)) {
            4 => 14,
            3 => 8,
            2 => 4,
            1 => 2,
            _ => 0,
        };
        merged.push(f);
    }
    true
}

pub async fn run_pipeline_to_runtime_risk_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let params = &ctx.job_params;
    let include_iac = pbool(params, "include_iac", true);
    let include_supply = pbool(params, "include_supply_chain", true);
    let include_cicd = pbool(params, "include_cicd", true);
    let synthesis = pbool(params, "pipeline_synthesis", true);

    let (iac_r, supply_r, cicd_r) = tokio::join!(
        async {
            if include_iac {
                crate::iac_misconfig_engine::run_iac_misconfig_result(target, ctx).await
            } else {
                EngineResult::ok(vec![], "iac skipped")
            }
        },
        async {
            if include_supply {
                crate::supply_chain_engine::run_supply_chain_result(target, ctx.stealth.as_ref())
                    .await
            } else {
                EngineResult::ok(vec![], "supply_chain skipped")
            }
        },
        async {
            if include_cicd {
                crate::cicd_pipeline_engine::run_cicd_pipeline_result_ctx(target, ctx).await
            } else {
                EngineResult::ok(vec![], "cicd skipped")
            }
        },
    );

    let mut merged = Vec::new();
    let mut sources = Vec::new();
    let mut penalty = 0u32;

    if ingest_source(&mut merged, &mut penalty, "iac_misconfig", &iac_r) {
        sources.push("iac_misconfig");
    }
    if ingest_source(&mut merged, &mut penalty, "supply_chain", &supply_r) {
        sources.push("supply_chain");
    }
    if ingest_source(&mut merged, &mut penalty, "cicd_pipeline", &cicd_r) {
        sources.push("cicd_pipeline");
    }

    if synthesis {
        let iac_public = has_signal(
            &merged,
            &["public", "0.0.0.0/0", "internet", "s3 bucket", "security group"],
        );
        let supply_vuln = has_signal(
            &merged,
            &["cve", "vulnerable", "malicious", "typosquat", "dependency"],
        );
        let cicd_secret = has_signal(
            &merged,
            &["secret", "token", "pipeline", "github actions", "workflow"],
        );

        if iac_public && supply_vuln {
            merged.push(finding(
                ENGINE_ID,
                "Pipeline chain — public IaC + vulnerable dependency",
                "critical",
                "T1195",
                "Misconfigured infrastructure deploys supply-chain-vulnerable artifact — runtime blast radius elevated.",
                &host,
            ));
            penalty += 22;
        }
        if cicd_secret && (iac_public || supply_vuln) {
            merged.push(finding(
                ENGINE_ID,
                "Pipeline chain — CI secret exposure + deploy risk",
                "critical",
                "T1552",
                "CI/CD credential or workflow weakness combined with deployable misconfig — prioritize secret rotation and pipeline hardening.",
                &host,
            ));
            penalty += 20;
        }
    }

    let grade = (100u32).saturating_sub(penalty.min(95));
    merged.push(finding(
        ENGINE_ID,
        &format!("Pipeline-to-runtime grade: {grade}/100"),
        if grade < 40 {
            "critical"
        } else if grade < 60 {
            "high"
        } else if grade < 80 {
            "medium"
        } else {
            "info"
        },
        "T1195",
        &format!(
            "Fused {} source(s): [{}]. Grade reflects commit→build→runtime correlation.",
            sources.len(),
            sources.join(", ")
        ),
        &host,
    ));

    if merged.is_empty() {
        return empty_ok(ENGINE_ID, "Pipeline-to-runtime: no correlated signals");
    }
    let count = merged.len();
    EngineResult::ok(
        merged,
        format!(
            "Pipeline-to-runtime: {count} finding(s) from [{}]",
            sources.join(", ")
        ),
    )
}

pub async fn run_pipeline_to_runtime_risk(target: &str) {
    print_result(
        run_pipeline_to_runtime_risk_result(target, &EngineRunContext::default()).await,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_signal_detects_cicd_secret() {
        let findings = vec![json!({
            "title": "GitHub Actions secret in workflow",
            "description": "pipeline token exposed",
            "severity": "high"
        })];
        assert!(has_signal(&findings, &["secret", "pipeline"]));
    }
}
