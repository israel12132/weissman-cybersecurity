//! Live PDF intelligence — compose a board pack from persisted findings only.
//! Empty corpus is a visible failure, never a fake PDF.

use crate::pdf_report;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, Deserialize)]
pub struct ComposeRequest {
    pub client_id: Option<i64>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PdfSnapshot {
    pub ok: bool,
    pub live: bool,
    pub client_id: Option<i64>,
    pub client_name: Option<String>,
    pub org_name: String,
    pub corpus: Vec<serde_json::Value>,
    pub findings: FindingCounts,
    pub frameworks: Vec<serde_json::Value>,
    pub empty_reason: Option<String>,
}

pub fn default_section_catalog() -> Vec<serde_json::Value> {
    vec![
        json!({"id": "exec", "label": "Executive summary"}),
        json!({"id": "findings", "label": "Live findings"}),
        json!({"id": "fair", "label": "FAIR blast-radius"}),
    ]
}

pub async fn load_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<PdfSnapshot, String> {
    let Some(cid) = client_id else {
        return Ok(PdfSnapshot {
            ok: false,
            live: true,
            client_id: None,
            client_name: None,
            org_name: "Weissman".into(),
            corpus: vec![],
            findings: FindingCounts {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                total: 0,
            },
            frameworks: vec![],
            empty_reason: Some("select a client — PDF intelligence never invents a pack".into()),
        });
    };

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let name: Option<String> = sqlx::query_scalar(
        "SELECT name FROM clients WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(cid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let rows = sqlx::query(
        r#"SELECT COALESCE(severity, 'info') AS severity, COUNT(*)::bigint AS n
             FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2
              AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
            GROUP BY 1"#,
    )
    .bind(tenant_id)
    .bind(cid)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    let mut counts = FindingCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
    };
    for r in rows {
        let sev: String = r.try_get("severity").unwrap_or_default();
        let n: i64 = r.try_get("n").unwrap_or(0);
        counts.total += n;
        match sev.to_ascii_lowercase().as_str() {
            "critical" => counts.critical = n,
            "high" => counts.high = n,
            "medium" => counts.medium = n,
            "low" => counts.low = n,
            _ => {}
        }
    }

    let empty = counts.total == 0;
    Ok(PdfSnapshot {
        ok: !empty,
        live: true,
        client_id: Some(cid),
        client_name: name,
        org_name: "Weissman".into(),
        corpus: if empty {
            vec![]
        } else {
            vec![json!({
                "id": "live-findings",
                "kind": "findings",
                "title": "Persisted findings",
                "finding_count": counts.total,
            })]
        },
        findings: counts,
        frameworks: vec![],
        empty_reason: empty.then(|| {
            "no persisted findings — will not emit a fabricated board PDF".into()
        }),
    })
}

pub fn compose_bytes(snap: &PdfSnapshot, req: &ComposeRequest) -> Result<Vec<u8>, String> {
    if snap.findings.total == 0 {
        return Err(snap
            .empty_reason
            .clone()
            .unwrap_or_else(|| "pdf corpus empty".into()));
    }
    let title = req
        .title
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("Weissman intelligence pack");
    let name = snap
        .client_name
        .as_deref()
        .unwrap_or("client");
    let mut pdf = pdf_report::build_minimal_pdf(name, snap.findings.total as usize);
    if pdf.is_empty() {
        return Err(format!("{title}: PDF builder returned empty bytes"));
    }
    Ok(pdf)
}
