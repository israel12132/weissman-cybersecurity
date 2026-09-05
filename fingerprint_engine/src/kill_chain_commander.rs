//! Live Kill-Chain Commander — compose recon→impact from persisted findings only.
//! Empty corpus is a visible failure. Executive dollars come only from
//! [`crate::financial_risk::latest_snapshot`].

use crate::financial_risk;
use crate::micro_severity;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

const STAGES: [&str; 5] = ["recon", "foothold", "identity", "privilege", "impact"];

#[derive(Debug, Clone, Deserialize)]
pub struct ComposeRequest {
    pub client_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KillChainSnapshot {
    pub ok: bool,
    pub live: bool,
    pub client_id: Option<i64>,
    pub client_name: Option<String>,
    pub primary_domain: Option<String>,
    pub stages: Vec<Value>,
    pub empty_reason: Option<String>,
    pub fair_ale_usd: Option<i64>,
    pub fair_sle_usd: Option<i64>,
    pub micro_severity_points: i64,
    pub findings_considered: i64,
}

pub fn snapshot_json(snap: &KillChainSnapshot) -> Value {
    serde_json::to_value(snap).unwrap_or_else(|_| json!({"ok": false, "live": false}))
}

pub fn compose_or_conflict(snap: &KillChainSnapshot) -> Result<(), String> {
    if snap.findings_considered == 0 {
        return Err(snap
            .empty_reason
            .clone()
            .unwrap_or_else(|| {
                "no persisted findings for this client — run a live scan first".into()
            }));
    }
    Ok(())
}

pub async fn load_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<KillChainSnapshot, String> {
    let Some(cid) = client_id else {
        return Ok(KillChainSnapshot {
            ok: false,
            live: true,
            client_id: None,
            client_name: None,
            primary_domain: None,
            stages: empty_stages(),
            empty_reason: Some("select a client — kill-chain is never invented".into()),
            fair_ale_usd: None,
            fair_sle_usd: None,
            micro_severity_points: 0,
            findings_considered: 0,
        });
    };

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let meta = sqlx::query(
        r#"SELECT name FROM clients WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(cid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let (client_name, primary_domain) = match meta {
        Some(r) => (r.try_get::<String, _>("name").ok(), None),
        None => {
            let _ = tx.commit().await;
            return Err("client not found in this tenant".into());
        }
    };

    let rows = sqlx::query(
        r#"SELECT title, severity, COALESCE(source, '') AS engine_id,
                  COALESCE(raw_data->>'mitre_attack', '') AS mitre,
                  COALESCE(raw_data->>'target', '') AS target
             FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2
              AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
            ORDER BY created_at DESC
            LIMIT 400"#,
    )
    .bind(tenant_id)
    .bind(cid)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    let mut buckets: [Vec<Value>; 5] = Default::default();
    let mut points: i64 = 0;
    for r in &rows {
        let title: String = r.try_get("title").unwrap_or_default();
        let severity: String = r.try_get("severity").unwrap_or_else(|_| "medium".into());
        let engine: String = r.try_get("engine_id").unwrap_or_default();
        let mitre: String = r.try_get("mitre").unwrap_or_default();
        let target: String = r.try_get("target").unwrap_or_default();
        let idx = stage_index(&engine, &mitre, &title);
        points += micro_severity::severity_weight(&severity.to_ascii_lowercase()) as i64;
        buckets[idx].push(json!({
            "title": title,
            "severity": severity,
            "engine_id": engine,
            "mitre": mitre,
            "target": target,
        }));
    }

    let fair = financial_risk::latest_snapshot(pool, tenant_id, cid)
        .await
        .ok()
        .flatten();
    let empty = rows.is_empty();
    Ok(KillChainSnapshot {
        ok: !empty,
        live: true,
        client_id: Some(cid),
        client_name,
        primary_domain,
        stages: STAGES
            .iter()
            .enumerate()
            .map(|(i, s)| {
                json!({
                    "stage": s,
                    "label": stage_label(s),
                    "finding_count": buckets[i].len(),
                    "findings": buckets[i],
                })
            })
            .collect(),
        empty_reason: empty.then(|| {
            "no persisted findings — Commander will not fabricate an APT path".into()
        }),
        fair_ale_usd: fair.as_ref().map(|f| f.ale_annualised_usd),
        fair_sle_usd: fair.as_ref().map(|f| f.sle_worst_usd),
        micro_severity_points: points,
        findings_considered: rows.len() as i64,
    })
}

fn empty_stages() -> Vec<Value> {
    STAGES
        .iter()
        .map(|s| json!({"stage": s, "label": stage_label(s), "finding_count": 0, "findings": []}))
        .collect()
}

fn stage_label(s: &str) -> &'static str {
    match s {
        "recon" => "Recon",
        "foothold" => "Foothold",
        "identity" => "Identity",
        "privilege" => "Privilege",
        "impact" => "Impact",
        _ => "Stage",
    }
}

fn stage_index(engine: &str, mitre: &str, title: &str) -> usize {
    let blob = format!("{engine} {mitre} {title}").to_ascii_lowercase();
    if blob.contains("osint") || blob.contains("asm") || blob.contains("recon") || blob.contains("t1595")
    {
        0
    } else if blob.contains("identity")
        || blob.contains("kerberos")
        || blob.contains("saml")
        || blob.contains("t1078")
    {
        2
    } else if blob.contains("privilege") || blob.contains("t1068") || blob.contains("cred") {
        3
    } else if blob.contains("ransom") || blob.contains("exfil") || blob.contains("t1486") {
        4
    } else {
        1
    }
}
