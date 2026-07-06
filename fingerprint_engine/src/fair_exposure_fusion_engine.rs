//! **Fair Exposure Fusion** — technical exposure grade × FAIR financial blast-radius.
//!
//! Fuses live `external_exposure_supreme` probes with persisted FAIR SLE/ALE computation
//! from the risk graph + vulnerability intel (CVSS, EPSS, KEV). Board-ready dollar-at-risk
//! correlated with external attack-surface grade — no LLM, no simulated findings.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use crate::financial_risk;
use serde_json::{json, Value};

const ENGINE_ID: &str = "fair_exposure_fusion";
const MITRE: &str = "T1595";

fn pbool(params: &Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn exposure_grade_from_findings(findings: &[Value]) -> Option<&str> {
    findings.iter().find_map(|f| {
        let title = f.get("title").and_then(|v| v.as_str()).unwrap_or("");
        if title.contains("exposure grade") || title.contains("Exposure grade") {
            title.split(':').nth(1).map(str::trim)
        } else {
            None
        }
    })
}

pub async fn run_fair_exposure_fusion_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let include_exposure = pbool(&ctx.job_params, "include_external_exposure", true);
    let include_fair = pbool(&ctx.job_params, "include_fair_model", true);
    let host = extract_host(target);
    let mut merged = Vec::new();

    if include_exposure {
        let exposure = crate::external_exposure_supreme::run_external_exposure_supreme_result(
            target, ctx,
        )
        .await;
        if exposure.success {
            for mut f in exposure.findings {
                if let Some(obj) = f.as_object_mut() {
                    obj.insert("fusion_engine".into(), json!(ENGINE_ID));
                    obj.insert("source_engine".into(), json!("external_exposure_supreme"));
                }
                merged.push(f);
            }
        }
    }

    let grade = exposure_grade_from_findings(&merged)
        .unwrap_or("unknown")
        .to_string();

    if include_fair {
        let (pool, tenant_id, client_id) = match (
            ctx.app_pool.as_ref(),
            ctx.tenant_id,
            ctx.client_id,
        ) {
            (Some(p), Some(t), Some(c)) => (p.as_ref(), t, c),
            _ => {
                merged.push(finding(
                    ENGINE_ID,
                    "FAIR model skipped — client context required",
                    "info",
                    MITRE,
                    "Select a client in Command Center to fuse live exposure with dollar-at-risk (ALE/SLE).",
                    &host,
                ));
                if merged.is_empty() {
                    return empty_ok(ENGINE_ID, target);
                }
                return EngineResult::ok(merged, format!("{ENGINE_ID}: partial fusion (no client)"));
            }
        };

        match financial_risk::compute_and_store(pool, tenant_id, client_id).await {
            Ok(risk) => {
                let severity = if risk.ale_annualised_usd >= 5_000_000 {
                    "critical"
                } else if risk.ale_annualised_usd >= 1_000_000 {
                    "high"
                } else if risk.ale_annualised_usd >= 250_000 {
                    "medium"
                } else {
                    "low"
                };

                merged.push(finding(
                    ENGINE_ID,
                    &format!(
                        "FAIR roll-up: ${} ALE / ${} worst-case SLE",
                        format_usd(risk.ale_annualised_usd),
                        format_usd(risk.sle_worst_usd),
                    ),
                    severity,
                    MITRE,
                    &format!(
                        "Live FAIR model from risk graph + open findings (CVSS×EPSS×KEV). Total asset value ${}; crown jewels ${}.",
                        format_usd(risk.total_asset_value_usd),
                        format_usd(risk.crown_jewel_value_usd),
                    ),
                    &host,
                ));

                if grade == "F" || grade == "E" || grade == "D" {
                    if risk.ale_annualised_usd >= 1_000_000 {
                        merged.push(finding(
                            ENGINE_ID,
                            "Toxic fusion: poor external grade + high dollar-at-risk",
                            "critical",
                            "T1566",
                            &format!(
                                "External exposure grade {grade} combined with ${} annualised loss expectancy — prioritize remediation of internet-exposed crown jewels.",
                                format_usd(risk.ale_annualised_usd)
                            ),
                            &host,
                        ));
                    }
                }

                if !risk.top_contributors.is_empty() {
                    let top = &risk.top_contributors[0];
                    merged.push(finding(
                        ENGINE_ID,
                        &format!("Top FAIR contributor: {}", top.label),
                        if top.kev_present { "critical" } else { "high" },
                        MITRE,
                        &format!(
                            "Node `{}` ({}) — SLE ${}, ALE ${}, max CVSS {:.1}, EPSS {:.3}{}",
                            top.graph_key,
                            top.node_type,
                            format_usd(top.sle_usd),
                            format_usd(top.ale_usd),
                            top.max_cvss,
                            top.max_epss,
                            if top.kev_present { ", KEV-listed" } else { "" },
                        ),
                        &host,
                    ));
                }
            }
            Err(e) => {
                merged.push(finding(
                    ENGINE_ID,
                    "FAIR computation unavailable",
                    "info",
                    MITRE,
                    &format!("Financial model could not run: {e}"),
                    &host,
                ));
            }
        }
    }

    merged.push(finding(
        ENGINE_ID,
        &format!("Fair exposure fusion summary — surface grade {grade}"),
        "info",
        MITRE,
        "Correlates live external exposure probes with persisted FAIR dollar-at-risk — board-ready evidence.",
        &host,
    ));

    if merged.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let count = merged.len();
    EngineResult::ok(
        merged,
        format!(
            "{ENGINE_ID}: {} finding(s), exposure grade {grade}",
            count,
        ),
    )
}

fn format_usd(n: i64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

pub async fn run_fair_exposure_fusion(target: &str) {
    print_result(run_fair_exposure_fusion_result(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_usd_commas() {
        assert_eq!(format_usd(1_000_000), "1,000,000");
    }
}
