//! **Sovereign Active Defense Fusion** — MTD + cognitive starvation + deception + CHRONOS telemetry.
//!
//! World-first fusion: correlates live Moving Target Defense epochs, offensive-AI poison sessions,
//! deception trigger hits, and CHRONOS freeze events into a single active-defense maturity grade.
//! Evidence-only — no simulated findings.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use sqlx::Row;

const ENGINE_ID: &str = "sovereign_active_defense_fusion";
const MITRE: &str = "T1599";

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

fn ingest_source(
    merged: &mut Vec<Value>,
    score: &mut u32,
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
        *score += match severity_rank(finding_severity(&f)) {
            4 => 12,
            3 => 7,
            2 => 4,
            1 => 2,
            _ => 1,
        };
        merged.push(f);
    }
    true
}

#[derive(Debug, Default)]
struct DefenseTelemetry {
    #[allow(dead_code)] // loaded from telemetry query; not read in current dashboard
    chronos_events_24h: i64,
    chronos_freezes_24h: i64,
    cognitive_sessions_24h: i64,
    deception_triggers_24h: i64,
    honey_route_sessions_24h: i64,
    agents_online: i64,
    mtd_epoch_active: bool,
}

async fn load_defense_telemetry(ctx: &EngineRunContext) -> DefenseTelemetry {
    let (pool, tenant_id, client_id) = match (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id) {
        (Some(p), Some(t), Some(c)) => (p.as_ref(), t, c),
        _ => return DefenseTelemetry::default(),
    };
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return DefenseTelemetry::default();
    };

    let chronos_events_24h: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM chronos_events
            WHERE client_id = $1 AND created_at > now() - interval '24 hours'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let chronos_freezes_24h: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM chronos_events
            WHERE client_id = $1 AND event_type = 'freeze' AND created_at > now() - interval '24 hours'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let cognitive_sessions_24h: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM cognitive_starvation_sessions
            WHERE client_id = $1 AND created_at > now() - interval '24 hours'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let deception_triggers_24h: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM deception_triggers
            WHERE client_id = $1 AND created_at > now() - interval '24 hours'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let honey_route_sessions_24h: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM honey_route_sessions
            WHERE client_id = $1 AND last_payload_at > now() - interval '24 hours'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let agents_online: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM endpoint_agents
            WHERE client_id = $1 AND last_seen_at > now() - interval '5 minutes'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let _ = tx.commit().await;

    DefenseTelemetry {
        chronos_events_24h,
        chronos_freezes_24h,
        cognitive_sessions_24h,
        deception_triggers_24h,
        honey_route_sessions_24h,
        agents_online,
        mtd_epoch_active: false,
    }
}

fn maturity_grade(score: u32) -> &'static str {
    match score {
        0..=15 => "Nascent",
        16..=35 => "Developing",
        36..=55 => "Operational",
        56..=75 => "Hardened",
        _ => "Sovereign",
    }
}

pub async fn run_sovereign_active_defense_fusion_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let params = &ctx.job_params;
    let include_mtd = pbool(params, "include_liquid_matrix", true);
    let include_cognitive = pbool(params, "include_cognitive_starvation", true);
    let include_telemetry = pbool(params, "include_defense_telemetry", true);
    let synthesize_chains = pbool(params, "synthesize_defense_chains", true);

    let host = extract_host(target);
    let mut merged = Vec::new();
    let mut maturity = 0u32;
    let mut sources: Vec<&str> = Vec::new();

    let (liquid_r, cognitive_r, mut telemetry) = tokio::join!(
        async {
            if include_mtd {
                crate::liquid_matrix_engine::run_liquid_matrix_result(target, ctx).await
            } else {
                EngineResult::ok(vec![], "liquid_matrix skipped")
            }
        },
        async {
            if include_cognitive {
                crate::cognitive_starvation_engine::run_cognitive_starvation_result(target, ctx)
                    .await
            } else {
                EngineResult::ok(vec![], "cognitive_starvation skipped")
            }
        },
        async {
            if include_telemetry {
                load_defense_telemetry(ctx).await
            } else {
                DefenseTelemetry::default()
            }
        },
    );

    if ingest_source(&mut merged, &mut maturity, "liquid_matrix", &liquid_r) {
        sources.push("liquid_matrix");
        telemetry.mtd_epoch_active = liquid_r.success && !liquid_r.findings.is_empty();
    }
    if ingest_source(
        &mut merged,
        &mut maturity,
        "cognitive_starvation",
        &cognitive_r,
    ) {
        sources.push("cognitive_starvation");
    }

    if include_telemetry {
        sources.push("defense_telemetry");
        if telemetry.chronos_freezes_24h > 0 {
            maturity += 10;
            merged.push(finding(
                ENGINE_ID,
                "CHRONOS autonomous freeze events (24h)",
                "medium",
                "T1055",
                &format!(
                    "{} CHRONOS freeze event(s) in the last 24h — temporal rollback layer is actively containing process anomalies.",
                    telemetry.chronos_freezes_24h
                ),
                &host,
            ));
        }
        if telemetry.deception_triggers_24h > 0 {
            maturity += 8;
            merged.push(finding(
                ENGINE_ID,
                "Deception layer engaged — live trigger hits",
                "high",
                "T1204",
                &format!(
                    "{} deception trigger(s) in 24h — attackers interacted with canary/shadow assets.",
                    telemetry.deception_triggers_24h
                ),
                &host,
            ));
        }
        if telemetry.honey_route_sessions_24h > 0 {
            maturity += 10;
            merged.push(finding(
                ENGINE_ID,
                "Honey-routing gateway engaged — live attacker sessions",
                "high",
                "T1599",
                &format!(
                    "{} honey-route session(s) in 24h — scanners were transparently diverted into the honeynet.",
                    telemetry.honey_route_sessions_24h
                ),
                &host,
            ));
        }
        if telemetry.cognitive_sessions_24h > 0 {
            maturity += 6;
            merged.push(finding(
                ENGINE_ID,
                "Cognitive starvation sessions active",
                "medium",
                "T1566",
                &format!(
                    "{} cognitive-starvation session(s) in 24h — automated/LLM scanners received poison payloads.",
                    telemetry.cognitive_sessions_24h
                ),
                &host,
            ));
        }
        if telemetry.agents_online == 0 {
            merged.push(finding(
                ENGINE_ID,
                "No endpoint agents online — CHRONOS/UEBA layer degraded",
                "medium",
                "T1059",
                "Sovereign active defense requires enrolled agents for temporal rollback and host-resident validation. Enrol agents to reach Hardened maturity.",
                &host,
            ));
        } else {
            maturity += 5;
        }
    }

    if synthesize_chains {
        let mtd = telemetry.mtd_epoch_active;
        let deception = telemetry.deception_triggers_24h > 0;
        let cognitive = telemetry.cognitive_sessions_24h > 0 || !cognitive_r.findings.is_empty();
        let chronos = telemetry.chronos_freezes_24h > 0;

        if mtd && cognitive && deception {
            maturity += 15;
            merged.push(finding(
                ENGINE_ID,
                "Sovereign stack: MTD + AI starvation + deception correlation",
                "info",
                MITRE,
                "Live fusion: moving-target routing epoch published, cognitive poison sessions observed, and deception triggers fired — full active-defense loop engaged.",
                &host,
            ));
        } else if !mtd && !deception && cognitive {
            merged.push(finding(
                ENGINE_ID,
                "Gap: cognitive poison without MTD or deception backstop",
                "high",
                MITRE,
                "Bot/LLM scanners are being poisoned but moving-target routing and deception canaries are inactive — attackers may pivot once poison budgets exhaust.",
                &host,
            ));
            maturity = maturity.saturating_sub(5);
        } else if !chronos && telemetry.agents_online > 0 {
            merged.push(finding(
                ENGINE_ID,
                "Gap: agents online but no CHRONOS freeze telemetry",
                "medium",
                "T1055",
                "Endpoint agents are present but no temporal-rollback events in 24h — verify CHRONOS eBPF/agent pipeline is armed for this client.",
                &host,
            ));
        }
    }

    let grade = maturity_grade(maturity);
    merged.push(finding(
        ENGINE_ID,
        &format!("Active defense maturity: {grade} ({maturity}/100)"),
        if maturity >= 56 {
            "info"
        } else if maturity >= 36 {
            "low"
        } else {
            "medium"
        },
        MITRE,
        &format!(
            "Fusion of {} source layer(s): liquid MTD, cognitive starvation, deception triggers, CHRONOS telemetry. Grade derived from live evidence only.",
            sources.len()
        ),
        &host,
    ));

    if merged.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let count = merged.len();
    EngineResult::ok(
        merged,
        format!(
            "{ENGINE_ID}: {} finding(s) from [{}] — maturity {grade}",
            count,
            sources.join(", ")
        ),
    )
}

pub async fn run_sovereign_active_defense_fusion(target: &str) {
    print_result(
        run_sovereign_active_defense_fusion_result(target, &EngineRunContext::default()).await,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maturity_grade_buckets() {
        assert_eq!(maturity_grade(10), "Nascent");
        assert_eq!(maturity_grade(40), "Operational");
        assert_eq!(maturity_grade(80), "Sovereign");
    }
}
