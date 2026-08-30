//! Owner-only tool bus: enqueue existing job kinds, retune from failure_class,
//! race waves under RoE, and HITL self-improve proposals (never mutates main).

use super::log_stream;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use weissman_core::models::engine::is_production_engine_id;

pub const ALLOWED_JOB_KINDS: &[&str] = &[
    "command_center_engine",
    "scan_all_engines",
    "tenant_full_scan",
    "council_debate",
    "general_mission",
    "swarm_run",
    "pipeline_scan",
    "top_tier_health_probe",
];

pub const RACE_CONFIRM: &str = "AUTHORIZED";

#[derive(Debug, Clone)]
pub struct ToolOutcome {
    pub ok: bool,
    pub name: String,
    pub detail: String,
    pub payload: Value,
}

pub fn is_allowed_job_kind(kind: &str) -> bool {
    ALLOWED_JOB_KINDS.iter().any(|k| *k == kind)
}

/// job_params overlay that makes the next run more aggressive under safe_proofs.
pub fn params_for_failure_class(class: &str) -> Value {
    match class.trim().to_ascii_lowercase().as_str() {
        "waf" => json!({
            "stealth_mode": true,
            "ghost_network": true,
            "force_ghost_network": true,
            "identity_morphing": true,
            "jitter_min_ms": 200,
            "jitter_max_ms": 1200,
            "roe_mode": "safe_proofs",
        }),
        "timeout" => json!({
            "timeout_ms": 120_000,
            "concurrency": 2,
            "roe_mode": "safe_proofs",
        }),
        "dns" => json!({
            "try_www_toggle": true,
            "roe_mode": "safe_proofs",
        }),
        "conn_reset" => json!({
            "stealth_mode": true,
            "jitter_min_ms": 400,
            "jitter_max_ms": 2000,
            "roe_mode": "safe_proofs",
        }),
        _ => json!({
            "stealth_mode": true,
            "intensity": "high",
            "roe_mode": "safe_proofs",
        }),
    }
}

pub fn wave_plan(shift: &str) -> Vec<(&'static str, &'static [&'static str])> {
    match shift.trim().to_ascii_lowercase().as_str() {
        "blue" => vec![
            ("observe", &["osint", "asm", "leak_hunter"]),
            ("detect", &["supply_chain", "cloud_posture"]),
        ],
        "cloud" => vec![
            ("observe", &["asm", "supply_chain"]),
            (
                "cloud",
                &[
                    "aws_attack",
                    "azure_attack",
                    "gcp_attack",
                    "k8s_container",
                    "iac_misconfig",
                ],
            ),
        ],
        "grc" => vec![
            ("observe", &["osint", "asm"]),
            ("control", &["compliance_gap_scan", "supply_chain"]),
        ],
        "hunter" => vec![
            ("observe", &["osint", "leak_hunter", "asm"]),
            ("identity", &["jwt_attack", "oauth_oidc", "bola_idor"]),
        ],
        _ => vec![
            ("observe", &["osint", "asm", "leak_hunter"]),
            ("identity", &["bola_idor", "jwt_attack", "oauth_oidc"]),
            (
                "proof",
                &["llm_path_fuzz", "semantic_ai_fuzz", "ssrf_advanced", "xxe"],
            ),
        ],
    }
}

pub fn production_wave(shift: &str) -> Vec<(String, Vec<String>)> {
    wave_plan(shift)
        .into_iter()
        .map(|(name, engines)| {
            let ids: Vec<String> = engines
                .iter()
                .filter(|id| is_production_engine_id(id))
                .map(|s| (*s).to_string())
                .collect();
            (name.to_string(), ids)
        })
        .filter(|(_, ids)| !ids.is_empty())
        .collect()
}

pub async fn execute_tool(
    pool: &PgPool,
    tenant_id: i64,
    actor_user_id: i64,
    trace_id: Option<String>,
    name: &str,
    args: &Value,
) -> ToolOutcome {
    match name.trim() {
        "enqueue" => tool_enqueue(pool, tenant_id, trace_id, args).await,
        "tune" => tool_tune(pool, tenant_id, trace_id, args).await,
        "race" => tool_race(pool, tenant_id, trace_id, args).await,
        "self_improve" => tool_self_improve(pool, tenant_id, actor_user_id, args).await,
        other => ToolOutcome {
            ok: false,
            name: other.to_string(),
            detail: "unknown tool".into(),
            payload: json!({}),
        },
    }
}

async fn tool_enqueue(
    pool: &PgPool,
    tenant_id: i64,
    trace_id: Option<String>,
    args: &Value,
) -> ToolOutcome {
    let kind = args
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("command_center_engine")
        .trim()
        .to_string();
    if !is_allowed_job_kind(&kind) {
        return ToolOutcome {
            ok: false,
            name: "enqueue".into(),
            detail: format!("job kind '{kind}' is not on the operator allow-list"),
            payload: json!({ "allowed": ALLOWED_JOB_KINDS }),
        };
    }
    let mut payload = args.get("payload").cloned().unwrap_or(json!({}));
    if !payload.is_object() {
        payload = json!({});
    }
    if kind == "command_center_engine" {
        let engine = args
            .get("engine")
            .and_then(Value::as_str)
            .or_else(|| payload.get("engine").and_then(Value::as_str))
            .unwrap_or("")
            .trim()
            .to_string();
        if engine.is_empty() || !is_production_engine_id(&engine) {
            return ToolOutcome {
                ok: false,
                name: "enqueue".into(),
                detail: "command_center_engine requires a production engine id".into(),
                payload: json!({}),
            };
        }
        payload
            .as_object_mut()
            .unwrap()
            .insert("engine".into(), json!(engine));
        if payload
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        {
            if let Some(client_id) = client_id_arg(args).or_else(|| client_id_arg(&payload)) {
                match first_client_target(pool, tenant_id, client_id).await {
                    Ok(Some(t)) => {
                        payload
                            .as_object_mut()
                            .unwrap()
                            .insert("target".into(), json!(t));
                        payload
                            .as_object_mut()
                            .unwrap()
                            .insert("client_id".into(), json!(client_id));
                    }
                    Ok(None) => {
                        return ToolOutcome {
                            ok: false,
                            name: "enqueue".into(),
                            detail: "client has no live target/domain".into(),
                            payload: json!({ "client_id": client_id }),
                        };
                    }
                    Err(e) => {
                        return ToolOutcome {
                            ok: false,
                            name: "enqueue".into(),
                            detail: e,
                            payload: json!({}),
                        };
                    }
                }
            }
        }
        if payload
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        {
            return ToolOutcome {
                ok: false,
                name: "enqueue".into(),
                detail: "target required".into(),
                payload: json!({}),
            };
        }
        payload
            .as_object_mut()
            .unwrap()
            .entry("roe_mode".to_string())
            .or_insert(json!("safe_proofs"));
    }
    if let Some(cid) = client_id_arg(args) {
        payload
            .as_object_mut()
            .unwrap()
            .entry("client_id".to_string())
            .or_insert(json!(cid));
    }
    match crate::async_jobs::enqueue(pool, tenant_id, &kind, payload.clone(), trace_id).await {
        Ok(id) => ToolOutcome {
            ok: true,
            name: "enqueue".into(),
            detail: format!("enqueued {kind} {id}"),
            payload: json!({ "job_id": id.to_string(), "kind": kind, "payload": payload }),
        },
        Err(e) => ToolOutcome {
            ok: false,
            name: "enqueue".into(),
            detail: e.to_string(),
            payload: json!({}),
        },
    }
}

async fn tool_tune(
    pool: &PgPool,
    tenant_id: i64,
    trace_id: Option<String>,
    args: &Value,
) -> ToolOutcome {
    let engine_filter = args
        .get("engine")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let class_override = args
        .get("failure_class")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "tune".into(),
                detail: e.to_string(),
                payload: json!({}),
            };
        }
    };
    let row = sqlx::query(
        r#"SELECT engine_id, target, client_id, job_id, failure_class, detail
           FROM weissman_sovereign_engine_logs
           WHERE phase IN ('failed','retry')
             AND ($1::text IS NULL OR engine_id = $1)
           ORDER BY id DESC
           LIMIT 1"#,
    )
    .bind(engine_filter.as_deref())
    .fetch_optional(&mut *tx)
    .await;
    let _ = tx.commit().await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return ToolOutcome {
                ok: false,
                name: "tune".into(),
                detail: "no failed/retry engine log to tune from".into(),
                payload: json!({}),
            };
        }
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "tune".into(),
                detail: e.to_string(),
                payload: json!({}),
            };
        }
    };
    let engine_id: String = row.try_get("engine_id").unwrap_or_default();
    let target: String = row.try_get("target").unwrap_or_default();
    let client_id: Option<i64> = row.try_get("client_id").ok();
    let class: String = class_override.unwrap_or_else(|| {
        row.try_get::<Option<String>, _>("failure_class")
            .ok()
            .flatten()
            .unwrap_or_else(|| "generic".into())
    });
    let params = params_for_failure_class(&class);
    let mut payload = json!({
        "engine": engine_id,
        "target": target,
        "roe_mode": "safe_proofs",
    });
    if let Some(obj) = payload.as_object_mut() {
        if let Some(cid) = client_id {
            obj.insert("client_id".into(), json!(cid));
        }
        if let Some(pmap) = params.as_object() {
            for (k, v) in pmap {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    match crate::async_jobs::enqueue(
        pool,
        tenant_id,
        "command_center_engine",
        payload.clone(),
        trace_id,
    )
    .await
    {
        Ok(id) => ToolOutcome {
            ok: true,
            name: "tune".into(),
            detail: format!("re-dispatched {engine_id} with {class} aggression overlay as {id}"),
            payload: json!({
                "job_id": id.to_string(),
                "failure_class": class,
                "job_params": params,
                "engine": engine_id,
                "target": target,
            }),
        },
        Err(e) => ToolOutcome {
            ok: false,
            name: "tune".into(),
            detail: e.to_string(),
            payload: json!({ "job_params": params }),
        },
    }
}

async fn tool_race(
    pool: &PgPool,
    tenant_id: i64,
    trace_id: Option<String>,
    args: &Value,
) -> ToolOutcome {
    let confirmation = args
        .get("confirmation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if confirmation != RACE_CONFIRM {
        return ToolOutcome {
            ok: false,
            name: "race".into(),
            detail: format!("full-authorization requires confirmation={RACE_CONFIRM}"),
            payload: json!({}),
        };
    }
    let Some(client_id) = client_id_arg(args) else {
        return ToolOutcome {
            ok: false,
            name: "race".into(),
            detail: "client_id required".into(),
            payload: json!({}),
        };
    };
    let target = match first_client_target(pool, tenant_id, client_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return ToolOutcome {
                ok: false,
                name: "race".into(),
                detail: "client has no live domain/target".into(),
                payload: json!({ "client_id": client_id }),
            };
        }
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "race".into(),
                detail: e,
                payload: json!({}),
            };
        }
    };
    let shift = args
        .get("shift")
        .and_then(Value::as_str)
        .unwrap_or("red")
        .trim()
        .to_ascii_lowercase();
    let waves = production_wave(&shift);
    let mut enqueued = Vec::new();
    let mut errors = Vec::new();
    for (wave_name, engines) in &waves {
        for engine in engines {
            let payload = json!({
                "engine": engine,
                "target": target,
                "client_id": client_id,
                "roe_mode": "safe_proofs",
                "sovereign_wave": wave_name,
                "sovereign_shift": shift,
                "stealth_mode": true,
            });
            match crate::async_jobs::enqueue(
                pool,
                tenant_id,
                "command_center_engine",
                payload,
                trace_id.clone(),
            )
            .await
            {
                Ok(id) => enqueued.push(json!({
                    "wave": wave_name,
                    "engine": engine,
                    "job_id": id.to_string(),
                })),
                Err(e) => errors.push(json!({ "engine": engine, "error": e.to_string() })),
            }
        }
    }
    ToolOutcome {
        ok: !enqueued.is_empty(),
        name: "race".into(),
        detail: format!(
            "race shift={shift} target={target} jobs={} errors={}",
            enqueued.len(),
            errors.len()
        ),
        payload: json!({
            "client_id": client_id,
            "target": target,
            "shift": shift,
            "roe_mode": "safe_proofs",
            "waves": waves.iter().map(|(n, e)| json!({"wave": n, "engines": e})).collect::<Vec<_>>(),
            "jobs": enqueued,
            "errors": errors,
        }),
    }
}

async fn tool_self_improve(
    pool: &PgPool,
    tenant_id: i64,
    _actor_user_id: i64,
    args: &Value,
) -> ToolOutcome {
    let title = args
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Sovereign engine improvement")
        .trim();
    let rationale = args
        .get("rationale")
        .and_then(Value::as_str)
        .unwrap_or("Proposed from live engine logs by the Sovereign Operator.")
        .trim();
    let category = args
        .get("category")
        .and_then(Value::as_str)
        .unwrap_or("improve_engine")
        .trim();
    let proposal = crate::self_improve::ImprovementProposal {
        category: category.to_string(),
        title: title.to_string(),
        rationale: rationale.to_string(),
        risk: "medium".into(),
        impact: "high".into(),
        effort: "medium".into(),
        proposed_diff_summary: args
            .get("diff_summary")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        affected_files: vec![],
        source: "sovereign_operator".into(),
    };
    let cycle_id = Uuid::new_v4();
    match crate::self_improve::insert_proposals(pool, tenant_id, cycle_id, &[proposal]).await {
        Ok(n) => ToolOutcome {
            ok: true,
            name: "self_improve".into(),
            detail: format!("{n} PENDING_APPROVAL proposal(s) — no in-process code mutation"),
            payload: json!({ "cycle_id": cycle_id.to_string(), "inserted": n }),
        },
        Err(e) => ToolOutcome {
            ok: false,
            name: "self_improve".into(),
            detail: e.to_string(),
            payload: json!({}),
        },
    }
}

fn client_id_arg(args: &Value) -> Option<i64> {
    args.get("client_id").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
    })
}

pub async fn first_client_target(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Option<String>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query("SELECT domains FROM clients WHERE id = $1")
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    let Some(r) = row else {
        return Ok(None);
    };
    let domains: Value = r.try_get("domains").unwrap_or(json!([]));
    let target = match &domains {
        Value::Array(arr) => arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .find(|s| !s.is_empty())
            .map(ToOwned::to_owned),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        _ => None,
    };
    Ok(target)
}

pub async fn last_hour_failures(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<Vec<(String, String, Option<i64>, String)>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT DISTINCT ON (engine_id, target)
                  engine_id, target, client_id, COALESCE(failure_class, 'generic') AS failure_class
           FROM weissman_sovereign_engine_logs
           WHERE phase IN ('failed','retry')
             AND created_at > now() - interval '1 hour'
           ORDER BY engine_id, target, id DESC
           LIMIT 12"#,
    )
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let engine: String = r.try_get("engine_id").ok()?;
            let target: String = r.try_get("target").ok()?;
            if engine.is_empty() || target.is_empty() {
                return None;
            }
            let client_id: Option<i64> = r.try_get("client_id").ok();
            let class: String = r
                .try_get("failure_class")
                .unwrap_or_else(|_| "generic".into());
            Some((engine, target, client_id, class))
        })
        .collect())
}

/// Used by hourly loop — re-dispatch failed engines with aggression overlay (cap 6).
pub async fn hourly_tune_cycle(pool: &PgPool, tenant_id: i64) -> Result<Value, String> {
    let fails = last_hour_failures(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let mut jobs = Vec::new();
    for (engine, target, client_id, class) in fails.into_iter().take(6) {
        if !is_production_engine_id(&engine) {
            continue;
        }
        let mut payload = json!({
            "engine": engine,
            "target": target,
            "roe_mode": "safe_proofs",
            "sovereign_hourly_tune": true,
        });
        if let Some(obj) = payload.as_object_mut() {
            if let Some(cid) = client_id {
                obj.insert("client_id".into(), json!(cid));
            }
            if let Some(pmap) = params_for_failure_class(&class).as_object() {
                for (k, v) in pmap {
                    obj.insert(k.clone(), v.clone());
                }
            }
        }
        match crate::async_jobs::enqueue(pool, tenant_id, "command_center_engine", payload, None)
            .await
        {
            Ok(id) => jobs.push(json!({
                "job_id": id.to_string(),
                "engine": engine,
                "failure_class": class,
            })),
            Err(e) => jobs.push(json!({ "engine": engine, "error": e.to_string() })),
        }
    }
    let logs = log_stream::list_recent(pool, tenant_id, 30)
        .await
        .unwrap_or_default();
    Ok(json!({
        "tuned_jobs": jobs,
        "log_sample_count": logs.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_rejects_auto_heal() {
        assert!(is_allowed_job_kind("command_center_engine"));
        assert!(!is_allowed_job_kind("auto_heal"));
        assert!(!is_allowed_job_kind("self_improvement_apply"));
    }

    #[test]
    fn waf_params_enable_ghost() {
        let p = params_for_failure_class("waf");
        assert_eq!(p["force_ghost_network"], true);
        assert_eq!(p["roe_mode"], "safe_proofs");
    }

    #[test]
    fn red_wave_only_production_ids() {
        let waves = production_wave("red");
        assert!(!waves.is_empty());
        for (_, engines) in waves {
            assert!(!engines.is_empty());
            for e in engines {
                assert!(is_production_engine_id(&e), "{e}");
            }
        }
    }

    #[test]
    fn race_confirm_token_is_explicit() {
        assert_eq!(RACE_CONFIRM, "AUTHORIZED");
    }
}
