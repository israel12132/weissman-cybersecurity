//! **Threat Surface Intelligence Fusion** — correlated threat intel + ASM + DNS + typosquat.
//!
//! Fuses four live probe pipelines in parallel:
//! - `threat_intel_fusion` (URLhaus + ThreatFox + CT footprint)
//! - `attack_surface_quantify` (ASM quantification)
//! - `passive_dns_forensics` (live DNS snapshot)
//! - `typosquatting_monitor` (lookalike domain/package risk)
//!
//! Emits a unified 0–100 threat-surface intelligence grade and toxic-combination chains.
//! Evidence-only — empty inputs yield honest empty results.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

const ENGINE_ID: &str = "threat_surface_intelligence_fusion";
const MITRE: &str = "T1597";

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
            4 => 18,
            3 => 10,
            2 => 5,
            1 => 2,
            _ => 0,
        };
        merged.push(f);
    }
    true
}

pub async fn run_threat_surface_intelligence_fusion_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let params = &ctx.job_params;
    let include_intel = pbool(params, "include_threat_intel", true);
    let include_asm = pbool(params, "include_attack_surface", true);
    let include_dns = pbool(params, "include_passive_dns", true);
    let include_typosquat = pbool(params, "include_typosquat", true);
    let synthesis = pbool(params, "toxic_chain_synthesis", true);

    let (intel_r, asm_r, dns_r, typo_r) = tokio::join!(
        async {
            if include_intel {
                crate::advanced_recon_engines::run_threat_intel_fusion_result(target).await
            } else {
                EngineResult::ok(vec![], "threat_intel_fusion skipped")
            }
        },
        async {
            if include_asm {
                crate::advanced_recon_engines::run_attack_surface_quantify_result(target).await
            } else {
                EngineResult::ok(vec![], "attack_surface_quantify skipped")
            }
        },
        async {
            if include_dns {
                crate::advanced_recon_engines::run_passive_dns_forensics_result(target).await
            } else {
                EngineResult::ok(vec![], "passive_dns_forensics skipped")
            }
        },
        async {
            if include_typosquat {
                crate::typosquatting_monitor_engine::run_typosquatting_monitor_result_ctx(
                    target, ctx,
                )
                .await
            } else {
                EngineResult::ok(vec![], "typosquatting_monitor skipped")
            }
        },
    );

    let mut merged = Vec::new();
    let mut sources = Vec::new();
    let mut penalty = 0u32;

    if ingest_source(&mut merged, &mut penalty, "threat_intel_fusion", &intel_r) {
        sources.push("threat_intel_fusion");
    }
    if ingest_source(&mut merged, &mut penalty, "attack_surface_quantify", &asm_r) {
        sources.push("attack_surface_quantify");
    }
    if ingest_source(&mut merged, &mut penalty, "passive_dns_forensics", &dns_r) {
        sources.push("passive_dns_forensics");
    }
    if ingest_source(&mut merged, &mut penalty, "typosquatting_monitor", &typo_r) {
        sources.push("typosquatting_monitor");
    }

    if synthesis {
        let malware_listed = has_signal(
            &merged,
            &["urlhaus", "threatfox", "malicious", "ioc"],
        );
        let wide_asm = has_signal(
            &merged,
            &["attack-surface", "quantification", "indicators", "discoverable"],
        );
        let typosquat_hit = has_signal(
            &merged,
            &["typosquat", "lookalike", "levenshtein", "impersonation"],
        );
        let ct_sprawl = has_signal(&merged, &["certificate transparency", "crt.sh", "distinct names"]);

        if malware_listed && wide_asm {
            merged.push(finding(
                ENGINE_ID,
                "Toxic chain: threat-intel listing + quantified attack surface",
                "critical",
                "T1190",
                "Live fusion: domain appears on abuse feeds while ASM reports broad discoverable assets — prioritize containment and hunt for active C2 staging.",
                target,
            ));
            penalty += 22;
        }
        if typosquat_hit && malware_listed {
            merged.push(finding(
                ENGINE_ID,
                "Toxic chain: typosquat presence + threat-intel hits",
                "critical",
                "T1566",
                "Live fusion: lookalike domains/packages plus URLhaus/ThreatFox IOCs — high phishing and brand-abuse risk.",
                target,
            ));
            penalty += 20;
        }
        if ct_sprawl && wide_asm {
            merged.push(finding(
                ENGINE_ID,
                "Toxic chain: CT sprawl + expanded ASM",
                "high",
                "T1595",
                "Live fusion: large Certificate Transparency footprint combined with quantified external assets — shadow infrastructure may be attacker-discoverable before defenders.",
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
        "category": "threat_surface_grade",
        "severity": if score >= 56 { "high" } else if score >= 26 { "medium" } else { "info" },
        "title": format!("Threat surface intelligence grade: {} ({}/100)", grade, score),
        "description": format!(
            "Fused {} live engines ({}) with toxic-chain synthesis.",
            sources.len(),
            sources.join(" + ")
        ),
        "grade": grade,
        "score": score,
        "sources": sources,
        "target": extract_host(target),
        "toxic_chain_synthesis": synthesis,
    }));

    let merged_count = merged.len();
    EngineResult::ok(
        merged,
        format!(
            "{ENGINE_ID}: {merged_count} findings from {} (grade {grade})",
            sources.join("+")
        ),
    )
}

pub async fn run_threat_surface_intelligence_fusion(target: &str, ctx: &EngineRunContext) {
    print_result(run_threat_surface_intelligence_fusion_result(target, ctx).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_monotonic() {
        assert_eq!(compute_grade(5), "A+");
        assert_eq!(compute_grade(30), "B");
        assert_eq!(compute_grade(90), "F");
    }
}
