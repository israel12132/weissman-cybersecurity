//! Desired HPC split (DB). **Effective** routing = `WEISSMAN_WORKER_POOL` on each worker unit (honest model).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpcPolicyRow {
    pub tenant_id: i64,
    pub research_core_share_percent: i16,
    pub research_cpu_affinity: String,
    pub client_scan_cpu_affinity: String,
    pub routing_note: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct HpcPolicyView {
    pub desired: HpcPolicyRow,
    pub effective_routing: Value,
}

pub async fn get_hpc_policy(pool: &PgPool, tenant_id: i64) -> Result<HpcPolicyView, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT tenant_id, research_core_share_percent, research_cpu_affinity,
                  client_scan_cpu_affinity, routing_note, updated_at
           FROM ceo_hpc_policy
           LIMIT 1"#,
    )
    .fetch_optional(&mut *tx)
    .await?;
    let desired = if let Some(r) = row {
        HpcPolicyRow {
            tenant_id: r.try_get("tenant_id")?,
            research_core_share_percent: r.try_get("research_core_share_percent")?,
            research_cpu_affinity: r.try_get("research_cpu_affinity")?,
            client_scan_cpu_affinity: r.try_get("client_scan_cpu_affinity")?,
            routing_note: r.try_get("routing_note")?,
            updated_at: r.try_get("updated_at")?,
        }
    } else {
        HpcPolicyRow {
            tenant_id,
            research_core_share_percent: 50,
            research_cpu_affinity: std::env::var("WEISSMAN_GENESIS_RESEARCH_CPU_AFFINITY")
                .unwrap_or_else(|_| "0-15".into()),
            client_scan_cpu_affinity: std::env::var("WEISSMAN_GENESIS_CLIENT_SCAN_CPU_AFFINITY")
                .unwrap_or_else(|_| "16-31".into()),
            routing_note: "No row yet — defaults from environment. Run PUT to persist CEO policy.".into(),
            updated_at: chrono::Utc::now(),
        }
    };
    let _ = tx.commit().await?;

    const RESEARCH_KINDS: &[&str] = &[
        "genesis_eternal_fuzz",
        "genesis_knowledge_match",
        "sovereign_learning_feedback",
        "council_debate",
        "poe_synthesis_run",
    ];

    let running_rows = sqlx::query(
        r#"SELECT kind, count(*)::bigint AS c
           FROM weissman_async_jobs
           WHERE tenant_id = $1 AND status = 'running'
           GROUP BY kind"#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut by_kind: Vec<Value> = Vec::new();
    let mut research_running: i64 = 0;
    let mut client_running: i64 = 0;
    for r in running_rows {
        let k: String = r.try_get("kind").unwrap_or_default();
        let c: i64 = r.try_get("c").unwrap_or(0);
        by_kind.push(json!({ "kind": k, "count": c }));
        if RESEARCH_KINDS.iter().any(|x| *x == k.as_str()) {
            research_running = research_running.saturating_add(c);
        } else {
            client_running = client_running.saturating_add(c);
        }
    }
    let total_rc = research_running.saturating_add(client_running);
    let actual_research_share_percent = (total_rc > 0).then_some(
        ((research_running.saturating_mul(100)) / total_rc) as i16,
    );

    let worker_pool = std::env::var("WEISSMAN_WORKER_POOL").unwrap_or_default();
    let effective_routing = json!({
        "worker_pool_env": worker_pool,
        "research_job_kinds": RESEARCH_KINDS,
        "running_jobs_by_kind": by_kind,
        "running_research_jobs": research_running,
        "running_client_jobs": client_running,
        "actual_research_share_percent_of_running": actual_research_share_percent,
        "explanation": "Workers with WEISSMAN_WORKER_POOL=research only claim research_job_kinds; client workers claim the complement; mixed claims all. Scale-out: run N research + M client units with counts proportional to desired.research_core_share_percent.",
        "tokio_affinity_note": "Tokio thread CPU affinity is fixed at process start; changing affinity strings requires restarting worker processes — use systemd Environment= updates after saving policy.",
    });

    Ok(HpcPolicyView {
        desired,
        effective_routing,
    })
}

#[derive(Deserialize)]
pub struct HpcPolicyPutBody {
    pub research_core_share_percent: i16,
    #[serde(default)]
    pub research_cpu_affinity: String,
    #[serde(default)]
    pub client_scan_cpu_affinity: String,
    #[serde(default)]
    pub routing_note: String,
}

pub async fn put_hpc_policy(
    pool: &PgPool,
    tenant_id: i64,
    body: &HpcPolicyPutBody,
) -> Result<HpcPolicyRow, String> {
    let p = body.research_core_share_percent.clamp(0, 100);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"INSERT INTO ceo_hpc_policy (
            tenant_id, research_core_share_percent, research_cpu_affinity,
            client_scan_cpu_affinity, routing_note, updated_at
        ) VALUES ($1, $2, $3, $4, $5, now())
        ON CONFLICT (tenant_id) DO UPDATE SET
            research_core_share_percent = EXCLUDED.research_core_share_percent,
            research_cpu_affinity = EXCLUDED.research_cpu_affinity,
            client_scan_cpu_affinity = EXCLUDED.client_scan_cpu_affinity,
            routing_note = EXCLUDED.routing_note,
            updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(p)
    .bind(body.research_cpu_affinity.trim())
    .bind(body.client_scan_cpu_affinity.trim())
    .bind(body.routing_note.trim())
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT tenant_id, research_core_share_percent, research_cpu_affinity,
                  client_scan_cpu_affinity, routing_note, updated_at
           FROM ceo_hpc_policy WHERE tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await.map_err(|e| e.to_string())?;
    Ok(HpcPolicyRow {
        tenant_id: row.try_get("tenant_id").map_err(|e| e.to_string())?,
        research_core_share_percent: row
            .try_get("research_core_share_percent")
            .map_err(|e| e.to_string())?,
        research_cpu_affinity: row
            .try_get("research_cpu_affinity")
            .map_err(|e| e.to_string())?,
        client_scan_cpu_affinity: row
            .try_get("client_scan_cpu_affinity")
            .map_err(|e| e.to_string())?,
        routing_note: row.try_get("routing_note").map_err(|e| e.to_string())?,
        updated_at: row.try_get("updated_at").map_err(|e| e.to_string())?,
    })
}
