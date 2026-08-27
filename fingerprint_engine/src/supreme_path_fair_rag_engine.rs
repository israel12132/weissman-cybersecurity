//! **Supreme Path × FAIR × RAG** — attack-path inference fused with dollar-at-risk
//! and pentest memory. Live graph + FAIR snapshots + winning-path stats only.
//! Empty client / empty graph yields an honest informational finding (no fakes).

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use crate::{attack_path, financial_risk, pentest_memory};
use serde_json::{json, Value};

const ENGINE_ID: &str = "supreme_path_fair_rag";
const MITRE: &str = "T1595";

fn pbool(params: &Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(Value::as_bool).unwrap_or(default)
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

pub async fn run_supreme_path_fair_rag_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let include_paths = pbool(&ctx.job_params, "include_attack_paths", true);
    let include_fair = pbool(&ctx.job_params, "include_fair_model", true);
    let include_rag = pbool(&ctx.job_params, "include_pentest_memory", true);
    let recompute = pbool(&ctx.job_params, "recompute", true);
    let top_k = ctx
        .job_params
        .get("attack_path_top_k")
        .and_then(Value::as_u64)
        .unwrap_or(15)
        .clamp(1, 200) as usize;

    let (pool, tenant_id, client_id) = match (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id) {
        (Some(p), Some(t), Some(c)) => (p.as_ref(), t, c),
        _ => {
            return EngineResult::ok(
                vec![finding(
                    ENGINE_ID,
                    "Supreme path/FAIR/RAG skipped — client context required",
                    "info",
                    MITRE,
                    "Select a client so Dijkstra can run over the live risk graph and FAIR snapshots.",
                    &host,
                )],
                format!("{ENGINE_ID}: no client context"),
            );
        }
    };

    let mut merged = Vec::new();

    if include_paths {
        let snap = if recompute {
            attack_path::compute_and_store(pool, tenant_id, client_id, Some(top_k)).await
        } else {
            match attack_path::latest_snapshot(pool, tenant_id, client_id).await {
                Ok(Some(s)) => Ok(s),
                Ok(None) => attack_path::compute_and_store(pool, tenant_id, client_id, Some(top_k)).await,
                Err(e) => Err(e),
            }
        };
        match snap {
            Ok(s) => {
                let sev = if s.max_path_score >= 80 {
                    "critical"
                } else if s.max_path_score >= 50 {
                    "high"
                } else if s.paths.is_empty() {
                    "info"
                } else {
                    "medium"
                };
                merged.push(finding(
                    ENGINE_ID,
                    &format!(
                        "Attack-path inference: {} paths, score {}, ${} path ALE",
                        s.paths.len(),
                        s.max_path_score,
                        format_usd(s.total_path_ale_usd),
                    ),
                    sev,
                    MITRE,
                    &format!(
                        "Dijkstra (milli-cost heap) internet_exposed → crown_jewel. Entries {} / jewels {}. Choke-points {}. Graph dirty={}.",
                        s.entry_count,
                        s.jewel_count,
                        s.choke_points.len(),
                        s.graph_dirty,
                    ),
                    &host,
                ));
                if let Some(top) = s.paths.first() {
                    let mitre_id = if top.mitre_technique_id.is_empty() {
                        MITRE.to_string()
                    } else {
                        top.mitre_technique_id.clone()
                    };
                    let title = format!(
                        "Critical path score {} · {} hops · ${} ALE",
                        top.path_score,
                        top.hops,
                        format_usd(top.ale_usd),
                    );
                    let desc = format!(
                        "Root cause: {}. Steps: {}.",
                        top.root_cause,
                        top.steps
                            .iter()
                            .map(|st| st.label.as_str())
                            .collect::<Vec<_>>()
                            .join(" → "),
                    );
                    let sev = if top.kev_hops > 0 { "critical" } else { "high" };
                    merged.push(finding(ENGINE_ID, &title, sev, &mitre_id, &desc, &host));
                }
                if let Some(cp) = s.choke_points.first() {
                    merged.push(finding(
                        ENGINE_ID,
                        &format!(
                            "Top choke-point {} ({}% of paths, blast ${})",
                            cp.label,
                            cp.coverage_pct,
                            format_usd(cp.blast_radius_ale_usd),
                        ),
                        if cp.kev_present { "critical" } else { "high" },
                        MITRE,
                        "Closing this node breaks the largest share of internet → crown-jewel paths.",
                        &host,
                    ));
                }
            }
            Err(e) => {
                merged.push(finding(
                    ENGINE_ID,
                    "Attack-path inference unavailable",
                    "info",
                    MITRE,
                    &format!("Graph search could not run: {e}"),
                    &host,
                ));
            }
        }
    }

    if include_fair {
        match financial_risk::compute_and_store(pool, tenant_id, client_id).await {
            Ok(fin) => {
                let sev = if fin.ale_annualised_usd >= 5_000_000 {
                    "critical"
                } else if fin.ale_annualised_usd >= 1_000_000 {
                    "high"
                } else if fin.ale_annualised_usd >= 250_000 {
                    "medium"
                } else {
                    "low"
                };
                merged.push(finding(
                    ENGINE_ID,
                    &format!(
                        "FAIR blast radius ${} ALE / ${}/day delay · concentration {}%",
                        format_usd(fin.ale_annualised_usd),
                        format_usd(fin.delay_cost_usd_per_day),
                        fin.concentration_pct,
                    ),
                    sev,
                    MITRE,
                    &format!(
                        "SLE worst ${}. Agent-protected ALE ${}. Path-linked ALE ${}. Currency {}.",
                        format_usd(fin.sle_worst_usd),
                        format_usd(fin.agent_protected_ale_usd),
                        format_usd(fin.path_ale_usd),
                        fin.currency,
                    ),
                    &host,
                ));
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

    if include_rag {
        match pentest_memory::memory_stats(pool, tenant_id).await {
            Ok(st) => {
                merged.push(finding(
                    ENGINE_ID,
                    &format!(
                        "Pentest memory: {} winning paths across {} engines (hit-rate {:.0}%)",
                        st.winning_paths,
                        st.engines,
                        st.avg_replay_hit_rate * 100.0,
                    ),
                    if st.winning_paths == 0 { "info" } else { "low" },
                    MITRE,
                    "pgvector HNSW (m=16, ef_construction=64) cosine recall with decay + diversity sampling. Live tenant memory only.",
                    &host,
                ));
            }
            Err(e) => {
                merged.push(finding(
                    ENGINE_ID,
                    "Pentest memory unavailable",
                    "info",
                    MITRE,
                    &format!("RAG stats could not run: {e}"),
                    &host,
                ));
            }
        }
    }

    merged.push(finding(
        ENGINE_ID,
        "Supreme path × FAIR × RAG fusion summary",
        "info",
        MITRE,
        "Live Dijkstra paths priced with FAIR SLE/ARO/ALE and ranked against tenant pentest memory. No simulated findings.",
        &host,
    ));

    if merged.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    let n = merged.len();
    EngineResult::ok(merged, format!("{ENGINE_ID}: {n} finding(s)"))
}

pub async fn run_supreme_path_fair_rag(target: &str) {
    print_result(run_supreme_path_fair_rag_result(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_usd_commas() {
        assert_eq!(format_usd(1_000_000), "1,000,000");
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_supreme_path_fair_rag_result("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }

    #[tokio::test]
    async fn no_client_is_honest_info() {
        let r = run_supreme_path_fair_rag_result("https://example.com", &EngineRunContext::default())
            .await;
        assert!(r.success);
        assert!(r.findings.iter().any(|f| f["title"]
            .as_str()
            .unwrap_or("")
            .contains("client context")));
    }
}
