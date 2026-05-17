//! **General** (Ascension): dynamic mission map from `clients` + `asm_graph_nodes`, risk scoring,
//! and autonomous enqueue of high-value engine jobs. vLLM optionally re-ranks targets.
//!
//! **Not implemented here (infeasible or unsafe for this stack):**
//! - Lock-free shared memory to stock vLLM (requires a custom inference IPC server).
//! - Rotating PostgreSQL passwords every 30s (breaks pooling; use IAM auth + vault off-process if required).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct MissionNode {
    pub client_id: i64,
    pub client_name: String,
    pub target_hint: String,
    pub risk_score: f64,
    pub reasons: Vec<String>,
    pub asm_node_types: Vec<String>,
}

fn risk_heuristic(node_type: &str, status: &str, label: &str, cname: Option<&str>) -> (f64, Vec<String>) {
    let mut score = 10.0_f64;
    let mut reasons = Vec::new();
    let nt = node_type.to_lowercase();
    let st = status.to_lowercase();
    let lb = label.to_lowercase();

    if nt.contains("s3") || nt.contains("azure") || nt.contains("bucket") || nt.contains("storage") {
        score += 35.0;
        reasons.push("cloud_exposure_surface".into());
    }
    if nt.contains("takeover") || nt.contains("cname") || cname.is_some() {
        score += 25.0;
        reasons.push("dns_takeover_or_cname".into());
    }
    if st.contains("open") || st.contains("exposed") || st.contains("vuln") {
        score += 18.0;
        reasons.push("status_indicates_exposure".into());
    }
    if lb.contains("admin") || lb.contains("api") || lb.contains("internal") {
        score += 12.0;
        reasons.push("high_value_label".into());
    }
    (score.min(100.0), reasons)
}

/// Build mission candidates from latest ASM graph + client registry (tenant RLS).
pub async fn build_dynamic_mission_map(pool: &PgPool, tenant_id: i64) -> Result<Vec<MissionNode>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let clients = sqlx::query(
        "SELECT id, name, COALESCE(domains,'[]') AS domains FROM clients WHERE tenant_id = $1 ORDER BY id",
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let mut client_domains: HashMap<i64, Vec<String>> = HashMap::new();
    let mut client_names: HashMap<i64, String> = HashMap::new();
    for r in clients {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let name: String = r.try_get("name").unwrap_or_default();
        let dom_raw: String = r.try_get("domains").unwrap_or_else(|_| "[]".into());
        client_names.insert(id, name);
        let parsed: Value = serde_json::from_str(&dom_raw).unwrap_or(json!([]));
        let mut ds = Vec::new();
        if let Some(arr) = parsed.as_array() {
            for x in arr {
                if let Some(s) = x.as_str() {
                    let t = s.trim();
                    if !t.is_empty() {
                        ds.push(t.to_string());
                    }
                }
            }
        }
        client_domains.insert(id, ds);
    }

    let rows = sqlx::query(
        r#"SELECT client_id, node_type, status, label, cname_target
           FROM asm_graph_nodes
           WHERE tenant_id = $1
           ORDER BY id DESC
           LIMIT 400"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await.map_err(|e| e.to_string())?;

    let mut by_client: HashMap<i64, MissionNode> = HashMap::new();
    for r in rows {
        let cid: i64 = r.try_get("client_id").unwrap_or(0);
        if cid == 0 {
            continue;
        }
        let node_type: String = r.try_get("node_type").unwrap_or_default();
        let status: String = r.try_get("status").unwrap_or_default();
        let label: String = r.try_get("label").unwrap_or_default();
        let cname: Option<String> = r.try_get("cname_target").ok();
        let (add, mut reasons) = risk_heuristic(
            &node_type,
            &status,
            &label,
            cname.as_deref(),
        );
        let hint = if !label.trim().is_empty() {
            label.clone()
        } else if let Some(d) = client_domains.get(&cid).and_then(|v| v.first()) {
            if d.starts_with("http://") || d.starts_with("https://") {
                d.clone()
            } else {
                format!("https://{}", d.trim_start_matches('/'))
            }
        } else {
            continue;
        };

        by_client
            .entry(cid)
            .and_modify(|m| {
                m.risk_score += add * 0.35;
                m.risk_score = m.risk_score.min(100.0);
                m.reasons.append(&mut reasons);
                if !m.asm_node_types.contains(&node_type) {
                    m.asm_node_types.push(node_type.clone());
                }
                if m.target_hint.len() < hint.len() {
                    m.target_hint = hint.clone();
                }
            })
            .or_insert_with(|| MissionNode {
                client_id: cid,
                client_name: client_names.get(&cid).cloned().unwrap_or_else(|| format!("client {}", cid)),
                target_hint: hint,
                risk_score: add,
                reasons,
                asm_node_types: vec![node_type],
            });
    }

    let mut out: Vec<MissionNode> = by_client.into_values().collect();
    out.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(out)
}

#[derive(Deserialize)]
struct LlmRankOut {
    #[serde(default)]
    client_ids: Vec<i64>,
}

async fn llm_rank_clients(
    pool: &PgPool,
    tenant_id: i64,
    candidates: &[MissionNode],
) -> Option<Vec<i64>> {
    if candidates.len() < 2 {
        return None;
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await.ok()?;
    let base: String = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()??;
    let base = weissman_engines::openai_chat::normalize_openai_base_url(base.trim());
    if base.is_empty() {
        let _ = tx.commit().await.ok();
        return None;
    }
    let model: String = sqlx::query_scalar("SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'")
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let _ = tx.commit().await.ok()?;

    let catalog: Value = Value::Array(
        candidates
            .iter()
            .take(24)
            .map(|m| {
                json!({
                    "client_id": m.client_id,
                    "risk_score": m.risk_score,
                    "target_hint": m.target_hint,
                    "reasons": m.reasons,
                    "node_types": m.asm_node_types,
                })
            })
            .collect(),
    );
    let user = format!(
        "Pick up to 8 client_id values to scan next for authorized red-team (highest breach probability first).\n\
         Candidates JSON:\n{}\n\
         Output ONLY: {{\"client_ids\":[...]}} — no markdown.",
        serde_json::to_string_pretty(&catalog).unwrap_or_else(|_| "[]".into())
    );
    let client = weissman_engines::openai_chat::llm_http_client(75);
    let m = weissman_engines::openai_chat::resolve_llm_model(model.as_str());
    let text = weissman_engines::openai_chat::chat_completion_text(
        &client,
        base.as_str(),
        m.as_str(),
        Some("You rank security scan targets. JSON only."),
        &user,
        0.1,
        400,
        Some(tenant_id),
        "general_mission_rank",
        true,
    )
    .await
    .ok()?;
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    let slice = text.get(start..=end)?;
    let out: LlmRankOut = serde_json::from_str(slice).ok()?;
    if out.client_ids.is_empty() {
        None
    } else {
        Some(out.client_ids)
    }
}

fn ascension_autonomous_enabled() -> bool {
    matches!(
        std::env::var("WEISSMAN_ASCENSION_AUTONOMOUS_ENQUEUE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) && matches!(
        std::env::var("WEISSMAN_ASCENSION_AUTONOMOUS_I_ACKNOWLEDGE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Enqueue engine jobs for top-risk mission nodes (ASM → BOLA → path fuzz). Respects `WEISSMAN_ASCENSION_MAX_JOBS` (default 6).
pub async fn run_ascension_wave(
    pool: Arc<PgPool>,
    tenant_id: i64,
    telemetry: Option<&Arc<broadcast::Sender<String>>>,
) -> Result<Value, String> {
    if !ascension_autonomous_enabled() {
        return Err(
            "ascension autonomous enqueue disabled (set WEISSMAN_ASCENSION_AUTONOMOUS_ENQUEUE=1 and WEISSMAN_ASCENSION_AUTONOMOUS_I_ACKNOWLEDGE=1)"
                .into(),
        );
    }
    let max_jobs: usize = std::env::var("WEISSMAN_ASCENSION_MAX_JOBS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6)
        .clamp(1, 24);

    let mut map = build_dynamic_mission_map(pool.as_ref(), tenant_id).await?;
    if map.is_empty() {
        return Ok(json!({
            "ok": true,
            "message": "no asm_graph_nodes yet — run ASM / tenant scan first",
            "enqueued": [],
        }));
    }

    if matches!(
        std::env::var("WEISSMAN_ASCENSION_LLM_RANK").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) {
        if let Some(order) = llm_rank_clients(pool.as_ref(), tenant_id, &map).await {
            let rank: HashMap<i64, usize> = order
                .into_iter()
                .enumerate()
                .map(|(i, id)| (id, i))
                .collect();
            map.sort_by(|a, b| {
                let ra = rank.get(&a.client_id).copied().unwrap_or(1000);
                let rb = rank.get(&b.client_id).copied().unwrap_or(1000);
                ra.cmp(&rb).then_with(|| {
                    b.risk_score
                        .partial_cmp(&a.risk_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            });
        }
    }

    let mut enqueued = Vec::new();
    let mut seen = HashSet::new();

    for node in map.into_iter().take(max_jobs * 3) {
        if enqueued.len() >= max_jobs {
            break;
        }
        let key = (node.client_id, node.target_hint.clone());
        if !seen.insert(key) {
            continue;
        }
        let target = node.target_hint.trim().to_string();
        if target.is_empty() {
            continue;
        }

        let trace = Some(format!("ascension-{}", Uuid::new_v4()));
        for (kind, payload) in [
            (
                "command_center_engine",
                json!({ "engine": "asm", "target": &target, "client_id": node.client_id }),
            ),
            (
                "command_center_engine",
                json!({ "engine": "bola_idor", "target": &target, "client_id": node.client_id }),
            ),
            (
                "command_center_engine",
                json!({ "engine": "llm_path_fuzz", "target": &target, "client_id": node.client_id }),
            ),
        ] {
            if enqueued.len() >= max_jobs {
                break;
            }
            let mut p = payload;
            crate::fuzz_oob::enrich_job_payload_with_oast_scan_binding(&mut p);
            crate::edge_swarm_intel::enrich_scan_payload_with_edge_node(
                pool.as_ref(),
                tenant_id,
                &target,
                &mut p,
            )
            .await;
            match crate::async_jobs::enqueue(pool.as_ref(), tenant_id, kind, p, trace.clone()).await {
                Ok(jid) => {
                    enqueued.push(json!({
                        "job_id": jid.to_string(),
                        "kind": kind,
                        "target": target,
                        "client_id": node.client_id,
                        "risk_score": node.risk_score,
                    }));
                    if let Some(tx) = telemetry {
                        let _ = tx.send(
                            json!({
                                "event": "ascension_enqueue",
                                "severity": "info",
                                "message": format!("Enqueued {} for client {}", kind, node.client_id),
                                "target": target,
                            })
                            .to_string(),
                        );
                    }
                }
                Err(e) => warn!(target: "general", "enqueue failed: {}", e),
            }
        }
    }

    info!(
        target: "general",
        tenant_id,
        "ascension wave enqueued {} jobs",
        enqueued.len()
    );

    Ok(json!({
        "ok": true,
        "enqueued": enqueued,
        "message": "ascension wave queued; poll /api/jobs/:id",
    }))
}
