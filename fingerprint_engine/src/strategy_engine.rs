//! **General** — vLLM-driven mission planning and chained execution: ASM → LLM refinement → semantic fuzz.
//! Optional self-audit: security telemetry + schema snapshot → LLM recommendations → audit log (no silent RLS mutation).

use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::asm_engine;
use crate::db;
use crate::pipeline_context;
use crate::semantic_fuzzer::{self, SemanticConfig};
use crate::stealth_engine;

#[derive(Debug, Deserialize)]
pub(crate) struct LlmMissionPlan {
    #[serde(default)]
    phases: Vec<String>,
    #[serde(default)]
    primary_target: String,
    #[serde(default)]
    run_osint: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LlmRefineFuzz {
    #[serde(default)]
    priority_paths: Vec<String>,
    #[serde(default)]
    tech_summary: String,
    #[serde(default)]
    fuzzer_focus: String,
}

fn normalize_target(domain: &str) -> String {
    let t = domain.trim();
    if t.is_empty() {
        return String::new();
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t.trim_start_matches('/'))
    }
}

fn host_from_target(target: &str) -> String {
    let t = target
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    t.split('/').next().unwrap_or(t).to_string()
}

fn extract_json_object(text: &str) -> Option<&str> {
    let t = text.trim();
    let start = t.find('{')?;
    let end = t.rfind('}')?;
    if end >= start {
        Some(&t[start..=end])
    } else {
        None
    }
}

async fn cfg_string(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    key: &str,
) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = $2",
    )
    .bind(tenant_id)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten()
    .filter(|s| !s.trim().is_empty())
}

async fn load_stealth(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<stealth_engine::StealthConfig, String> {
    let mut tx = db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let proxy_swarm = cfg_string(&mut tx, tenant_id, "proxy_swarm")
        .await
        .unwrap_or_default();
    let proxy_list = stealth_engine::StealthConfig::parse_proxy_swarm(&proxy_swarm);
    let jitter_min_ms = cfg_string(&mut tx, tenant_id, "jitter_min_ms")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let jitter_max_ms = cfg_string(&mut tx, tenant_id, "jitter_max_ms")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(800);
    let identity_morphing = cfg_string(&mut tx, tenant_id, "enable_identity_morphing")
        .await
        .map(|s| s.to_lowercase() == "true" || s == "1")
        .unwrap_or(true);
    let _ = tx.commit().await;
    Ok(stealth_engine::StealthConfig {
        proxy_list,
        jitter_min_ms,
        jitter_max_ms,
        identity_morphing,
    })
}

async fn load_semantic_cfg_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> SemanticConfig {
    let llm_base_url = cfg_string(tx, tenant_id, "llm_base_url")
        .await
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
    let llm_temperature: f64 = cfg_string(tx, tenant_id, "llm_temperature")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.2);
    let llm_model = cfg_string(tx, tenant_id, "llm_model")
        .await
        .unwrap_or_default();
    let max_depth: usize = cfg_string(tx, tenant_id, "semantic_max_sequence_depth")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    SemanticConfig {
        llm_base_url,
        llm_temperature,
        llm_model,
        max_sequence_depth: max_depth,
    }
}

fn default_mission_plan(target: &str) -> LlmMissionPlan {
    LlmMissionPlan {
        phases: vec!["asm".into(), "semantic_fuzz".into()],
        primary_target: target.to_string(),
        run_osint: false,
    }
}

/// vLLM breaks a domain into ordered phases (asm, semantic_fuzz, osint).
pub(crate) async fn fetch_mission_plan(
    llm_base_url: &str,
    llm_model: &str,
    tenant_id: i64,
    domain: &str,
) -> LlmMissionPlan {
    if llm_base_url.trim().is_empty() {
        return default_mission_plan(&normalize_target(domain));
    }
    let base = weissman_engines::openai_chat::normalize_openai_base_url(llm_base_url.trim());
    let user = format!(
        "Authorized red-team mission planning for target (single tenant):\n{}\n\n\
         Output ONLY minified JSON with keys:\n\
         - phases: array of strings, subset of [\"osint\",\"asm\",\"semantic_fuzz\"] in execution order (required: include asm before semantic_fuzz when both used)\n\
         - primary_target: canonical URL or https://hostname to attack\n\
         - run_osint: boolean\n\
         No markdown.",
        domain.trim()
    );
    let client = weissman_engines::openai_chat::llm_http_client(90);
    let model = weissman_engines::openai_chat::resolve_llm_model(llm_model);
    let Ok(text) = weissman_engines::openai_chat::chat_completion_text(
        &client,
        base.as_str(),
        model.as_str(),
        Some("You output JSON only for defensive security orchestration."),
        &user,
        0.15,
        512,
        Some(tenant_id),
        "general_mission_plan",
        true,
    )
    .await
    else {
        warn!(target: "strategy_engine", "mission plan LLM failed; using defaults");
        return default_mission_plan(&normalize_target(domain));
    };
    let Some(slice) = extract_json_object(&text) else {
        return default_mission_plan(&normalize_target(domain));
    };
    serde_json::from_str::<LlmMissionPlan>(slice).unwrap_or_else(|_| {
        warn!(target: "strategy_engine", "mission plan JSON parse failed; using defaults");
        default_mission_plan(&normalize_target(domain))
    })
}

fn paths_from_asm_fingerprint_findings(findings: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for f in findings {
        if f.get("asset").and_then(|a| a.as_str()) != Some("fingerprint") {
            continue;
        }
        let Some(url_s) = f.get("value").and_then(|v| v.as_str()) else {
            continue;
        };
        if let Ok(u) = url::Url::parse(url_s) {
            let p = u.path().to_string();
            if p != "/" && !p.is_empty() {
                out.push(if p.starts_with('/') {
                    p
                } else {
                    format!("/{}", p)
                });
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Feed ASM summary back into vLLM to prioritize paths and fuzzing focus.
pub(crate) async fn refine_fuzz_with_asm_summary(
    llm_base_url: &str,
    llm_model: &str,
    tenant_id: i64,
    asm_excerpt: &str,
) -> LlmRefineFuzz {
    let empty = LlmRefineFuzz {
        priority_paths: vec![],
        tech_summary: String::new(),
        fuzzer_focus: String::new(),
    };
    if llm_base_url.trim().is_empty() {
        return empty;
    }
    let base = weissman_engines::openai_chat::normalize_openai_base_url(llm_base_url.trim());
    let user = format!(
        "ASM phase completed. Findings excerpt (JSON, may be truncated):\n```\n{}\n```\n\n\
         Output ONLY minified JSON: {{\"priority_paths\":[\"/path\",...],\"tech_summary\":\"...\",\"fuzzer_focus\":\"...\"}}\n\
         priority_paths: high-value relative paths for semantic/HTTP fuzzing.\n\
         No markdown.",
        asm_excerpt.chars().take(12_000).collect::<String>()
    );
    let client = weissman_engines::openai_chat::llm_http_client(120);
    let model = weissman_engines::openai_chat::resolve_llm_model(llm_model);
    let Ok(text) = weissman_engines::openai_chat::chat_completion_text(
        &client,
        base.as_str(),
        model.as_str(),
        Some("You refine fuzz targets from ASM output. JSON only."),
        &user,
        0.2,
        1024,
        Some(tenant_id),
        "general_asm_fuzz_refine",
        true,
    )
    .await
    else {
        return empty;
    };
    let Some(slice) = extract_json_object(&text) else {
        return empty;
    };
    serde_json::from_str::<LlmRefineFuzz>(slice).unwrap_or(empty)
}

fn telemetry_send(tx: Option<&Arc<broadcast::Sender<String>>>, payload: Value) {
    if let Some(t) = tx {
        let _ = t.send(payload.to_string());
    }
}

/// Run full General pipeline: plan → ASM → LLM path refinement → semantic fuzz (recursive feedback).
pub async fn execute_general_mission(
    app_pool: Arc<PgPool>,
    tenant_id: i64,
    client_id: Option<i64>,
    domain: &str,
    telemetry: Option<&Arc<broadcast::Sender<String>>>,
) -> Result<Value, String> {
    let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let llm_base = cfg_string(&mut tx, tenant_id, "llm_base_url")
        .await
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
    let llm_model = cfg_string(&mut tx, tenant_id, "llm_model")
        .await
        .unwrap_or_default();
    let sem_cfg = load_semantic_cfg_tx(&mut tx, tenant_id).await;
    let _ = tx.commit().await;

    let norm_base = weissman_engines::openai_chat::normalize_openai_base_url(llm_base.trim());

    let plan = fetch_mission_plan(
        norm_base.as_str(),
        llm_model.as_str(),
        tenant_id,
        domain,
    )
    .await;

    let target = if plan.primary_target.trim().is_empty() {
        normalize_target(domain)
    } else {
        normalize_target(plan.primary_target.trim())
    };
    if target.is_empty() {
        return Err("empty target".into());
    }

    telemetry_send(
        telemetry,
        json!({
            "event": "general_mission",
            "severity": "info",
            "message": format!("General mission planned: {:?}", plan.phases),
            "target": target,
        }),
    );

    let stealth = load_stealth(app_pool.as_ref(), tenant_id).await?;

    let edge = crate::edge_swarm_intel::resolve_edge_swarm_for_target(
        app_pool.as_ref().clone(),
        tenant_id,
        &target,
        norm_base.as_str(),
        llm_model.as_str(),
        Some(tenant_id),
    )
    .await;

    let run_osint = plan.run_osint
        || plan
            .phases
            .iter()
            .any(|p| p.eq_ignore_ascii_case("osint"));
    let osint_block = if run_osint {
        let r = crate::osint_engine::run_osint_result(&target, Some(&stealth)).await;
        telemetry_send(
            telemetry,
            json!({
                "event": "general_mission",
                "severity": "info",
                "message": "OSINT phase complete",
                "findings_count": r.findings.len(),
            }),
        );
        Some(json!({
            "status": r.status,
            "findings_count": r.findings.len(),
            "message": r.message,
        }))
    } else {
        None
    };

    let asm_result = asm_engine::run_asm_result_with_ports_and_subdomains(
        &target,
        &asm_engine::TOP_PORTS,
        None,
        Some(&stealth),
    )
    .await;

    let findings = asm_result.findings.clone();
    let host = host_from_target(&target);
    let mut ports = pipeline_context::open_ports_from_asm_findings(&findings);
    if ports.is_empty() {
        ports = vec![443, 80];
    }
    let web_bases = pipeline_context::web_bases_for_host(&host, &ports);
    let primary_semantic = web_bases
        .iter()
        .find(|u| u.starts_with("https://"))
        .cloned()
        .or_else(|| web_bases.first().cloned())
        .unwrap_or_else(|| target.clone());

    let asm_excerpt = serde_json::to_string(&findings).unwrap_or_else(|_| "[]".into());
    let refined = refine_fuzz_with_asm_summary(
        norm_base.as_str(),
        llm_model.as_str(),
        tenant_id,
        &asm_excerpt,
    )
    .await;

    let mut discovered: Vec<String> = paths_from_asm_fingerprint_findings(&findings);
    for p in refined.priority_paths {
        let q = p.trim().to_string();
        if q.is_empty() {
            continue;
        }
        let n = if q.starts_with('/') { q } else { format!("/{}", q) };
        discovered.push(n);
    }
    discovered.sort();
    discovered.dedup();

    telemetry_send(
        telemetry,
        json!({
            "event": "general_mission",
            "severity": "info",
            "message": "ASM complete; semantic fuzz starting with LLM-refined paths",
            "semantic_target": primary_semantic,
            "path_count": discovered.len(),
            "tech_summary": refined.tech_summary,
        }),
    );

    let run_semantic = plan
        .phases
        .iter()
        .any(|p| p.eq_ignore_ascii_case("semantic_fuzz"));
    let fuzzy = if run_semantic {
        semantic_fuzzer::run_semantic_fuzz_result(
            &primary_semantic,
            Some(&stealth),
            &sem_cfg,
            if discovered.is_empty() {
                None
            } else {
                Some(discovered.as_slice())
            },
            Some(tenant_id),
        )
        .await
    } else {
        semantic_fuzzer::run_semantic_fuzz_result(
            &primary_semantic,
            Some(&stealth),
            &sem_cfg,
            None,
            Some(tenant_id),
        )
        .await
    };

    if let Some(cid) = client_id {
        if let Ok(mut tx) = db::begin_tenant_tx(app_pool.as_ref(), tenant_id).await {
            let log = fuzzy.reasoning_log.chars().take(120_000).collect::<String>();
            let _ = sqlx::query(
                "INSERT INTO semantic_fuzz_log (tenant_id, client_id, run_id, log_text) VALUES ($1, $2, NULL, $3)",
            )
            .bind(tenant_id)
            .bind(cid)
            .bind(&log)
            .execute(&mut *tx)
            .await;
            let _ = tx.commit().await;
        }
    }

    info!(
        target: "strategy_engine",
        tenant_id,
        "general mission finished for {}",
        primary_semantic
    );

    Ok(json!({
        "mission_phases": plan.phases,
        "target": target,
        "edge_swarm": edge,
        "osint": osint_block,
        "asm": {
            "status": asm_result.status,
            "findings_count": findings.len(),
            "message": asm_result.message,
        },
        "llm_refine": {
            "tech_summary": refined.tech_summary,
            "fuzzer_focus": refined.fuzzer_focus,
            "priority_paths_merged": discovered.len(),
        },
        "semantic": {
            "target": primary_semantic,
            "status": fuzzy.result.status,
            "findings": fuzzy.result.findings,
            "message": fuzzy.result.message,
            "reasoning_log": fuzzy.reasoning_log,
        },
    }))
}

/// LLM-assisted self-audit: security_events + public schema snapshot. Writes `audit_logs` row; does not alter RLS.
pub async fn run_self_defense_audit(
    pool: &PgPool,
    tenant_id: i64,
    actor_user_id: Option<i64>,
    actor_label: &str,
    ip: &str,
) -> Result<Value, String> {
    let mut tx = db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let llm_base = cfg_string(&mut tx, tenant_id, "llm_base_url")
        .await
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
    let llm_model = cfg_string(&mut tx, tenant_id, "llm_model")
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;

    let event_rows = sqlx::query(
        r#"SELECT COALESCE(event_type, '') AS et, COALESCE(details::text, '{}') AS dt
           FROM security_events
           WHERE created_at >= NOW() - INTERVAL '48 hours'
           ORDER BY id DESC
           LIMIT 80"#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let mut events = Vec::with_capacity(event_rows.len());
    for r in event_rows {
        let et: String = r.try_get::<String, _>("et").unwrap_or_default();
        let dt: String = r.try_get::<String, _>("dt").unwrap_or_default();
        events.push((et, dt));
    }

    let table_count: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

    let policy_count: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM pg_policies WHERE schemaname = 'public'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let snapshot = json!({
        "security_events_sample": events.iter().take(40).cloned().collect::<Vec<_>>(),
        "public_table_count": table_count,
        "public_rls_policy_count": policy_count,
    });
    let snap_s = snapshot.to_string();

    let mut recommendation = Value::String("LLM unavailable".into());
    if !llm_base.trim().is_empty() {
        let user = format!(
            "Tenant self-audit snapshot (defensive):\n```json\n{}\n```\n\n\
             Assess anomalies (auth bypass attempts, RLS policy count unexpectedly zero, burst patterns). \
             Output ONLY minified JSON: {{\"severity\":\"low\"|\"medium\"|\"high\",\"findings\":[\"...\"],\"recommended_actions\":[\"...\"]}} \
             recommended_actions must be human-executable (e.g. review security_events, enable stricter rate limits) — not SQL to disable RLS.",
            snap_s.chars().take(14_000).collect::<String>()
        );
        let client = weissman_engines::openai_chat::llm_http_client(90);
        let model = weissman_engines::openai_chat::resolve_llm_model(llm_model.as_str());
        if let Ok(text) = weissman_engines::openai_chat::chat_completion_text(
            &client,
            weissman_engines::openai_chat::normalize_openai_base_url(llm_base.trim()).as_str(),
            model.as_str(),
            Some("You assist defensive security audits. JSON only."),
            &user,
            0.1,
            900,
            Some(tenant_id),
            "general_self_audit",
            true,
        )
        .await
        {
            if let Some(slice) = extract_json_object(&text) {
                if let Ok(v) = serde_json::from_str::<Value>(slice) {
                    recommendation = v;
                }
            }
        }
    }

    let detail = serde_json::to_string(&recommendation).unwrap_or_else(|_| "{}".into());
    let mut tx = db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let _ = crate::audit_log::insert_audit(
        &mut tx,
        tenant_id,
        actor_user_id,
        actor_label,
        "general_self_audit",
        &detail.chars().take(8000).collect::<String>(),
        ip,
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;

    Ok(json!({
        "snapshot": snapshot,
        "llm_assessment": recommendation,
    }))
}
