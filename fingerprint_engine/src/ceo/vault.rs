//! CEO CRUD for `genesis_vaccine_vault` / `genesis_suspended_graphs` + remediation match (Rust, same queries as Python module).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

#[derive(Debug, Serialize)]
pub struct VaultRowOut {
    pub id: i64,
    pub tech_fingerprint: String,
    pub component_ref: String,
    pub attack_chain_json: Value,
    pub remediation_patch: String,
    pub detection_signature: String,
    pub severity: String,
    pub preemptive_validated: bool,
    pub simulation_feedback: Value,
    pub council_transcript: Value,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct VaultInsertBody {
    pub tech_fingerprint: String,
    #[serde(default)]
    pub component_ref: String,
    #[serde(default)]
    pub attack_chain_json: Value,
    #[serde(default)]
    pub remediation_patch: String,
    #[serde(default)]
    pub detection_signature: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub preemptive_validated: bool,
    #[serde(default)]
    pub simulation_feedback: Value,
    #[serde(default)]
    pub council_transcript: Value,
}

fn row_to_vault(r: &PgRow) -> Result<VaultRowOut, sqlx::Error> {
    let created: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
    Ok(VaultRowOut {
        id: r.try_get("id")?,
        tech_fingerprint: r.try_get("tech_fingerprint")?,
        component_ref: r.try_get("component_ref")?,
        attack_chain_json: r.try_get("attack_chain_json")?,
        remediation_patch: r.try_get("remediation_patch")?,
        detection_signature: r.try_get("detection_signature")?,
        severity: r.try_get("severity")?,
        preemptive_validated: r.try_get("preemptive_validated")?,
        simulation_feedback: r.try_get("simulation_feedback")?,
        council_transcript: r.try_get("council_transcript")?,
        created_at: created.to_rfc3339(),
    })
}

pub async fn list_vault_rows(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
    offset: i64,
) -> Result<Vec<VaultRowOut>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, tech_fingerprint, component_ref, attack_chain_json, remediation_patch,
                  detection_signature, severity, preemptive_validated, simulation_feedback,
                  council_transcript, created_at
           FROM genesis_vaccine_vault
           ORDER BY id DESC
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit.min(500).max(1))
    .bind(offset.max(0))
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let mut out = Vec::new();
    for r in rows {
        out.push(row_to_vault(&r)?);
    }
    Ok(out)
}

pub async fn get_vault_row(
    pool: &PgPool,
    tenant_id: i64,
    id: i64,
) -> Result<Option<VaultRowOut>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT id, tech_fingerprint, component_ref, attack_chain_json, remediation_patch,
                  detection_signature, severity, preemptive_validated, simulation_feedback,
                  council_transcript, created_at
           FROM genesis_vaccine_vault WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    row.as_ref().map(row_to_vault).transpose()
}

pub async fn post_vault_row(
    pool: &PgPool,
    tenant_id: i64,
    body: &VaultInsertBody,
) -> Result<i64, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO genesis_vaccine_vault (
            tenant_id, tech_fingerprint, component_ref, attack_chain_json,
            remediation_patch, detection_signature, severity, preemptive_validated,
            simulation_feedback, council_transcript
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(body.tech_fingerprint.trim())
    .bind(body.component_ref.trim())
    .bind(&body.attack_chain_json)
    .bind(body.remediation_patch.trim())
    .bind(body.detection_signature.trim())
    .bind(
        body.severity
            .trim()
            .to_lowercase()
            .chars()
            .take(32)
            .collect::<String>(),
    )
    .bind(body.preemptive_validated)
    .bind(&body.simulation_feedback)
    .bind(&body.council_transcript)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Same logic as Python `remediation_engine.knowledge_match_sync` — executed in Rust against live DB.
pub async fn match_vault_row(pool: &PgPool, tenant_id: i64, vault_id: i64) -> Result<Value, String> {
    let row = get_vault_row(pool, tenant_id, vault_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "vault row not found".to_string())?;
    let fp = row.tech_fingerprint.trim();
    if fp.is_empty() {
        return Err("vault row has empty tech_fingerprint".into());
    }
    crate::council_synthesis::genesis_knowledge_match(pool, tenant_id, fp)
        .await
        .map_err(|e| e.to_string())
}

pub async fn export_vault_criticals_csv(pool: &PgPool, tenant_id: i64) -> Result<String, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, tech_fingerprint, component_ref, severity, detection_signature,
                  LEFT(remediation_patch, 2000) AS patch_excerpt, created_at
           FROM genesis_vaccine_vault
           WHERE lower(trim(severity)) = 'critical'
           ORDER BY id DESC
           LIMIT 2000"#,
    )
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let mut w = String::from("id,tech_fingerprint,component_ref,severity,detection_signature,patch_excerpt,created_at\n");
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let tf: String = r.try_get("tech_fingerprint").unwrap_or_default();
        let cr: String = r.try_get("component_ref").unwrap_or_default();
        let sev: String = r.try_get("severity").unwrap_or_default();
        let det: String = r.try_get("detection_signature").unwrap_or_default();
        let pe: String = r.try_get("patch_excerpt").unwrap_or_default();
        let ct: chrono::DateTime<chrono::Utc> = r.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now());
        let esc = |s: &str| {
            let x = s.replace('"', "\"\"");
            format!("\"{}\"", x.replace('\n', " "))
        };
        w.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            id,
            esc(&tf),
            esc(&cr),
            esc(&sev),
            esc(&det),
            esc(&pe),
            esc(&ct.to_rfc3339())
        ));
    }
    Ok(w)
}

#[derive(Debug, Serialize)]
pub struct SuspendedRowOut {
    pub id: i64,
    pub status: String,
    pub max_depth: i64,
    pub root_index: i64,
    pub ram_budget_bytes: i64,
    pub created_at: String,
}

pub async fn list_suspended_graphs(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> Result<Vec<SuspendedRowOut>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, status, max_depth, root_index, ram_budget_bytes, created_at
           FROM genesis_suspended_graphs
           ORDER BY id DESC
           LIMIT $1"#,
    )
    .bind(limit.min(200).max(1))
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let mut out = Vec::new();
    for r in rows {
        let ct: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
        out.push(SuspendedRowOut {
            id: r.try_get("id")?,
            status: r.try_get("status")?,
            max_depth: r.try_get("max_depth")?,
            root_index: r.try_get("root_index")?,
            ram_budget_bytes: r.try_get("ram_budget_bytes")?,
            created_at: ct.to_rfc3339(),
        });
    }
    Ok(out)
}

pub async fn get_suspended_graph(
    pool: &PgPool,
    tenant_id: i64,
    id: i64,
) -> Result<Option<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT id, status, graph_snapshot, dfs_stack, visited_nodes, seeds_json,
                  max_depth, root_index, paths_found_json, ram_budget_bytes, created_at, updated_at
           FROM genesis_suspended_graphs WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let Some(r) = row else {
        return Ok(None);
    };
    let ct: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
    let ut: chrono::DateTime<chrono::Utc> = r.try_get("updated_at")?;
    let idv: i64 = r.try_get("id")?;
    let st: String = r.try_get("status")?;
    let gs: Value = r.try_get("graph_snapshot")?;
    let ds: Value = r.try_get("dfs_stack")?;
    let vn: Value = r.try_get("visited_nodes")?;
    let sj: Value = r.try_get("seeds_json")?;
    let md: i64 = r.try_get("max_depth")?;
    let ri: i64 = r.try_get("root_index")?;
    let pj: Value = r.try_get("paths_found_json")?;
    let rb: i64 = r.try_get("ram_budget_bytes")?;
    Ok(Some(json!({
        "id": idv,
        "status": st,
        "graph_snapshot": gs,
        "dfs_stack": ds,
        "visited_nodes": vn,
        "seeds_json": sj,
        "max_depth": md,
        "root_index": ri,
        "paths_found_json": pj,
        "ram_budget_bytes": rb,
        "created_at": ct.to_rfc3339(),
        "updated_at": ut.to_rfc3339(),
    })))
}

pub async fn post_resume_suspended_job(
    pool: &PgPool,
    tenant_id: i64,
    suspended_id: i64,
    trace: Option<&str>,
) -> Result<uuid::Uuid, String> {
    let body = json!({ "resume_suspended_id": suspended_id });
    weissman_db::job_queue::enqueue(pool, tenant_id, "genesis_eternal_fuzz", body, trace)
        .await
        .map_err(|e| e.to_string())
}
