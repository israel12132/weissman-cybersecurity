//! External Exposure Supreme — live fusion of ASM + email/DNS posture + cloud posture.
//!
//! Runs three real probe pipelines in parallel, merges evidence-only findings, synthesises
//! toxic external attack paths (spoof + public cloud, takeover + admin, etc.), and emits a
//! single 0–100 exposure grade. No simulated or hardcoded findings.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

const ENGINE_ID: &str = "external_exposure_supreme";

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
        f.get("observed").and_then(Value::as_str).unwrap_or(""),
        f.get("category").and_then(Value::as_str).unwrap_or(""),
    )
    .to_lowercase()
}

fn has_signal(findings: &[Value], keywords: &[&str]) -> bool {
    findings
        .iter()
        .any(|f| keywords.iter().any(|k| haystack(f).contains(k)))
}

fn compute_grade(score: u32) -> &'static str {
    match score {
        0..=10 => "A+",
        11..=25 => "A",
        26..=40 => "B",
        41..=55 => "C",
        56..=70 => "D",
        71..=85 => "E",
        _ => "F",
    }
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
            4 => 15,
            3 => 8,
            2 => 4,
            1 => 2,
            _ => 0,
        };
        merged.push(f);
    }
    true
}

pub async fn run_external_exposure_supreme_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let params = &ctx.job_params;
    let include_asm = pbool(params, "include_asm", true);
    let include_email = pbool(params, "include_email_dns", true);
    let include_cloud = pbool(params, "include_cloud", true);
    let synthesis = pbool(params, "attack_path_synthesis", true);
    let stealth = ctx.stealth.as_ref();

    let (asm_r, email_r, cloud_r) = tokio::join!(
        async {
            if include_asm {
                crate::asm_engine::run_asm_result_ctx(target, ctx, stealth).await
            } else {
                EngineResult::ok(vec![], "asm skipped")
            }
        },
        async {
            if include_email {
                crate::email_dns_posture_engine::run_email_dns_posture_result(target, ctx).await
            } else {
                EngineResult::ok(vec![], "email_dns_posture skipped")
            }
        },
        async {
            if include_cloud {
                crate::cloud_posture_engine::run_cloud_posture_result_ctx(target, ctx).await
            } else {
                EngineResult::ok(vec![], "cloud_posture skipped")
            }
        },
    );

    let mut merged = Vec::new();
    let mut sources = Vec::new();
    let mut penalty = 0u32;

    if ingest_source(&mut merged, &mut penalty, "asm", &asm_r) {
        sources.push("asm");
    }
    if ingest_source(&mut merged, &mut penalty, "email_dns_posture", &email_r) {
        sources.push("email_dns_posture");
    }
    if ingest_source(&mut merged, &mut penalty, "cloud_posture", &cloud_r) {
        sources.push("cloud_posture");
    }

    if synthesis {
        let spoofable = has_signal(
            &merged,
            &[
                "dmarc",
                "spf fail",
                "no dmarc",
                "spoof",
                "p=none",
                "alignment fail",
            ],
        );
        let exposed_cloud = has_signal(
            &merged,
            &[
                "public",
                "s3",
                "blob",
                "open bucket",
                "anonymous",
                "listable",
                "world-readable",
            ],
        );
        let admin_exposed = has_signal(
            &merged,
            &[
                "admin",
                "jenkins",
                "kubernetes",
                "dashboard",
                "3389",
                "management",
                "webgui",
                "grafana",
            ],
        );
        let takeover = has_signal(
            &merged,
            &["takeover", "dangling", "unclaimed", "cname", "subdomain"],
        );

        if spoofable && exposed_cloud {
            merged.push(finding(
                ENGINE_ID,
                "Toxic chain: weak email auth + public cloud exposure",
                "critical",
                "T1566",
                "Live fusion: spoofable email posture combined with externally reachable cloud storage — credible phishing with staging for exfiltration.",
                target,
            ));
            penalty += 20;
        }
        if takeover && admin_exposed {
            merged.push(finding(
                ENGINE_ID,
                "Toxic chain: subdomain takeover + exposed management plane",
                "critical",
                "T1190",
                "Live fusion: dangling subdomain risk plus reachable admin or management surfaces — accelerated takeover-to-compromise.",
                target,
            ));
            penalty += 18;
        }
        if spoofable && admin_exposed {
            merged.push(finding(
                ENGINE_ID,
                "Toxic chain: spoofable domain + exposed admin login",
                "high",
                "T1078",
                "Live fusion: weak SPF/DMARC plus exposed admin panels increases credential-theft success rate.",
                target,
            ));
            penalty += 12;
        }
    }

    if sources.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let score = penalty.min(100);
    let grade = compute_grade(score);
    merged.push(json!({
        "type": ENGINE_ID,
        "category": "exposure_grade",
        "severity": if score >= 56 { "high" } else if score >= 26 { "medium" } else { "info" },
        "title": format!("External exposure supreme grade: {} ({}/100)", grade, score),
        "description": format!(
            "Fused {} live engines ({}) with toxic-combination synthesis.",
            sources.len(),
            sources.join(" + ")
        ),
        "grade": grade,
        "score": score,
        "sources": sources,
        "target": extract_host(target),
        "attack_path_synthesis": synthesis,
    }));

    let merged_count = merged.len();
    EngineResult::ok(
        merged,
        format!(
            "{}: {} findings from {} (grade {})",
            ENGINE_ID,
            merged_count,
            sources.join("+"),
            grade
        ),
    )
}

pub async fn run_external_exposure_supreme(target: &str) {
    print_result(run_external_exposure_supreme_result(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_buckets() {
        assert_eq!(compute_grade(5), "A+");
        assert_eq!(compute_grade(30), "B");
        assert_eq!(compute_grade(90), "F");
    }

    #[test]
    fn toxic_synthesis_detects_combo() {
        let findings = vec![
            json!({
                "title": "DMARC policy p=none",
                "description": "domain is spoofable",
                "severity": "high"
            }),
            json!({
                "title": "Public S3 bucket listable",
                "description": "anonymous list allowed",
                "severity": "critical"
            }),
        ];
        assert!(has_signal(&findings, &["dmarc", "spoof"]));
        assert!(has_signal(&findings, &["public", "s3"]));
    }
}
