//! Phase 5: Multi-agent swarm — Recon → Exploitation → Stealth via `flume` (lock-free MPMC-style paths).
//! Events broadcast as JSON for WebSocket `/ws/swarm` and persisted to `swarm_events` for durability.

use crate::ai_redteam_engine::{self, AiRedteamConfig};
use crate::db;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

const CHANNEL_CAP: usize = 256;

#[derive(Debug, Clone)]
pub struct ReconTarget {
    pub url: String,
    pub client_id: i64,
    pub tenant_id: i64,
}

#[derive(Debug, Clone)]
pub struct ExploitTask {
    pub target: ReconTarget,
    pub user_agent: String,
}

#[derive(Debug)]
pub struct StealthCheck {
    pub task: ExploitTask,
    pub payload_preview: Vec<u8>,
}

#[derive(Debug)]
pub enum StealthVerdict {
    Proceed {
        user_agent: String,
    },
    SoftenPayload {
        reason: String,
        suggested_padding: String,
    },
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Max ASM HTTP(S) targets loaded per swarm run (env override; default scales beyond legacy 40 cap).
fn asm_graph_target_limit() -> i64 {
    std::env::var("WEISSMAN_SWARM_ASM_TARGET_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(10_000)
}

async fn persist_swarm_event(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    agent: &str,
    event: &str,
    detail: Value,
    ts_ms: i64,
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    db::set_tenant_conn(&mut *conn, tenant_id).await?;
    sqlx::query(
        r#"INSERT INTO swarm_events (tenant_id, client_id, agent, event, detail_json, ts_ms)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(agent)
    .bind(event)
    .bind(sqlx::types::Json(detail))
    .bind(ts_ms)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn emit_swarm(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    broadcast: &broadcast::Sender<String>,
    agent: &str,
    event: &str,
    detail: Value,
) {
    let ts = now_ms();
    let msg = json!({
        "type": "swarm",
        "agent": agent,
        "event": event,
        "detail": detail.clone(),
        "ts": ts,
    })
    .to_string();
    let _ = broadcast.send(msg);
    if let Err(e) =
        persist_swarm_event(pool, tenant_id, client_id, agent, event, detail, ts).await
    {
        tracing::error!(
            target: "swarm_orchestrator",
            error = %e,
            agent,
            event,
            "persist swarm event failed"
        );
    }
}

/// Shannon entropy in bits per byte; high values suggest random/WAF-triggering payloads.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

async fn load_asm_targets(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Vec<String>, sqlx::Error> {
    let mut tx = db::begin_tenant_tx(pool, tenant_id).await?;
    let lim = asm_graph_target_limit();
    let rows = sqlx::query(
        r#"SELECT DISTINCT label FROM asm_graph_nodes
           WHERE client_id = $1 AND (label LIKE 'http://%' OR label LIKE 'https://%')
           ORDER BY label LIMIT $2"#,
    )
    .bind(client_id)
    .bind(lim)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.try_get::<String, _>("label").ok())
        .collect())
}

async fn recon_agent(
    rx: flume::Receiver<(i64, i64)>,
    exploit_tx: flume::Sender<ExploitTask>,
    broadcast: Arc<broadcast::Sender<String>>,
    pool: Arc<PgPool>,
) {
    while let Ok((tenant_id, client_id)) = rx.recv_async().await {
        emit_swarm(
            pool.as_ref(),
            tenant_id,
            Some(client_id),
            &broadcast,
            "ReconAgent",
            "job_started",
            json!({ "tenant_id": tenant_id, "client_id": client_id }),
        )
        .await;
        let urls = match load_asm_targets(pool.as_ref(), tenant_id, client_id).await {
            Ok(u) => u,
            Err(e) => {
                emit_swarm(
                    pool.as_ref(),
                    tenant_id,
                    Some(client_id),
                    &broadcast,
                    "ReconAgent",
                    "error",
                    json!({ "message": e.to_string() }),
                )
                .await;
                continue;
            }
        };
        emit_swarm(
            pool.as_ref(),
            tenant_id,
            Some(client_id),
            &broadcast,
            "ReconAgent",
            "targets_discovered",
            json!({ "count": urls.len() }),
        )
        .await;
        for url in urls {
            let url_emit = url.clone();
            let t = ReconTarget {
                url,
                client_id,
                tenant_id,
            };
            let task = ExploitTask {
                target: t,
                user_agent: "WeissmanSwarm/1.0".into(),
            };
            if exploit_tx.send_async(task).await.is_err() {
                emit_swarm(
                    pool.as_ref(),
                    tenant_id,
                    Some(client_id),
                    &broadcast,
                    "ReconAgent",
                    "pipeline_closed",
                    json!({}),
                )
                .await;
                return;
            }
            emit_swarm(
                pool.as_ref(),
                tenant_id,
                Some(client_id),
                &broadcast,
                "ReconAgent",
                "delegated_to_exploitation",
                json!({ "url": url_emit }),
            )
            .await;
        }
    }
}

async fn stealth_agent(
    rx: flume::Receiver<StealthCheck>,
    verdict_tx: flume::Sender<StealthVerdict>,
    broadcast: Arc<broadcast::Sender<String>>,
    pool: Arc<PgPool>,
) {
    const ENTROPY_WARN: f64 = 6.8;
    while let Ok(check) = rx.recv_async().await {
        let tid = check.task.target.tenant_id;
        let cid = check.task.target.client_id;
        let ent = shannon_entropy(&check.payload_preview);
        emit_swarm(
            pool.as_ref(),
            tid,
            Some(cid),
            &broadcast,
            "StealthAgent",
            "entropy_measured",
            json!({
                "entropy_bits_per_byte": ent,
                "bytes": check.payload_preview.len(),
                "url": check.task.target.url,
            }),
        )
        .await;
        let verdict = if ent > ENTROPY_WARN {
            StealthVerdict::SoftenPayload {
                reason: format!("high entropy {:.2} — WAF risk", ent),
                suggested_padding: "[]{}\"role\":\"user\"".into(),
            }
        } else {
            StealthVerdict::Proceed {
                user_agent: format!(
                    "Mozilla/5.0 (compatible; WeissmanSwarm/1.0; +https://weissman.local) {}",
                    check.task.target.client_id
                ),
            }
        };
        if verdict_tx.send_async(verdict).await.is_err() {
            return;
        }
    }
}

async fn exploitation_agent(
    rx: flume::Receiver<ExploitTask>,
    stealth_tx: flume::Sender<StealthCheck>,
    verdict_rx: flume::Receiver<StealthVerdict>,
    broadcast: Arc<broadcast::Sender<String>>,
    pool: Arc<PgPool>,
) {
    while let Ok(mut task) = rx.recv_async().await {
        let tid = task.target.tenant_id;
        let cid = task.target.client_id;
        let payload_preview = task
            .target
            .url
            .as_bytes()
            .iter()
            .chain(b"|probe|")
            .copied()
            .take(512)
            .collect::<Vec<u8>>();
        let check = StealthCheck {
            task: task.clone(),
            payload_preview,
        };
        if stealth_tx.send_async(check).await.is_err() {
            return;
        }
        let verdict = match verdict_rx.recv_async().await {
            Ok(v) => v,
            Err(_) => return,
        };
        match verdict {
            StealthVerdict::SoftenPayload {
                reason,
                suggested_padding,
            } => {
                emit_swarm(
                    pool.as_ref(),
                    tid,
                    Some(cid),
                    &broadcast,
                    "ExploitationAgent",
                    "stealth_adjustment",
                    json!({ "reason": reason, "padding": suggested_padding }),
                )
                .await;
            }
            StealthVerdict::Proceed { user_agent } => {
                task.user_agent = user_agent;
            }
        }

        let tenant_id = task.target.tenant_id;
        let mut tx = match db::begin_tenant_tx(pool.as_ref(), tenant_id).await {
            Ok(t) => t,
            Err(e) => {
                emit_swarm(
                    pool.as_ref(),
                    tid,
                    Some(cid),
                    &broadcast,
                    "ExploitationAgent",
                    "error",
                    json!({ "message": e.to_string() }),
                )
                .await;
                continue;
            }
        };
        let llm_base_url = sqlx::query_scalar::<_, String>(
            "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
        let temp: f64 = sqlx::query_scalar::<_, String>(
            "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_temperature'",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.25);
        let llm_model = sqlx::query_scalar::<_, String>(
            "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
        let endpoint = sqlx::query_scalar::<_, String>(
            "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'ai_redteam_endpoint'",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
        let strategy = sqlx::query_scalar::<_, String>(
            "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'adversarial_strategy'",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "data_leak".to_string());
        let _ = tx.commit().await;

        let cfg = AiRedteamConfig {
            llm_base_url,
            llm_temperature: temp,
            llm_model,
            ai_redteam_endpoint: endpoint,
            adversarial_strategy: strategy,
        };

        emit_swarm(
            pool.as_ref(),
            tid,
            Some(cid),
            &broadcast,
            "ExploitationAgent",
            "attack_started",
            json!({ "url": task.target.url, "ua_tail": task.user_agent.chars().rev().take(24).collect::<String>().chars().rev().collect::<String>() }),
        )
        .await;

        let result = ai_redteam_engine::run_ai_redteam_attack(
            &task.target.url,
            None,
            &cfg,
            None,
            Some(tenant_id),
        )
        .await;
        emit_swarm(
            pool.as_ref(),
            tid,
            Some(cid),
            &broadcast,
            "ExploitationAgent",
            "attack_finished",
            json!({
                "url": task.target.url,
                "findings": result.findings.len(),
            }),
        )
        .await;
    }
}

/// Spawn recon → exploitation → stealth pipeline for one client; fan-out via flume.
pub fn spawn_swarm_run(
    pool: Arc<PgPool>,
    tenant_id: i64,
    client_id: i64,
    broadcast: Arc<broadcast::Sender<String>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (recon_tx, recon_rx) = flume::bounded::<(i64, i64)>(8);
        let (exploit_tx, exploit_rx) = flume::bounded::<ExploitTask>(CHANNEL_CAP);
        let (stealth_tx, stealth_rx) = flume::bounded::<StealthCheck>(CHANNEL_CAP);
        let (verdict_tx, verdict_rx) = flume::bounded::<StealthVerdict>(CHANNEL_CAP);

        let b1 = broadcast.clone();
        let b2 = broadcast.clone();
        let b3 = broadcast.clone();
        let p = pool.clone();
        let h_recon = tokio::spawn(recon_agent(recon_rx, exploit_tx, b1, p.clone()));
        let h_stealth = tokio::spawn(stealth_agent(stealth_rx, verdict_tx, b2, p.clone()));
        let h_exploit = tokio::spawn(exploitation_agent(
            exploit_rx, stealth_tx, verdict_rx, b3, p,
        ));

        if recon_tx
            .send_async((tenant_id, client_id))
            .await
            .is_err()
        {
            emit_swarm(
                pool.as_ref(),
                tenant_id,
                Some(client_id),
                &broadcast,
                "SwarmCoordinator",
                "error",
                json!({ "message": "failed to queue recon job" }),
            )
            .await;
        }

        drop(recon_tx);

        let _ = tokio::time::timeout(Duration::from_secs(3600), async {
            let _ = h_recon.await;
            let _ = h_stealth.await;
            let _ = h_exploit.await;
        })
        .await;

        emit_swarm(
            pool.as_ref(),
            tenant_id,
            Some(client_id),
            &broadcast,
            "SwarmCoordinator",
            "job_complete",
            json!({ "tenant_id": tenant_id, "client_id": client_id }),
        )
        .await;
    })
}
