//! Blast-radius evaluation against client topology / financial risk graph.

use serde_json::json;
use sqlx::{PgPool, Row};

use super::types::BlastRadiusReport;

/// Max aggregate $ exposure before blocking destructive SOAR (override via env).
fn blast_radius_ceiling_usd() -> i64 {
    std::env::var("WEISSMAN_SOAR_BLAST_RADIUS_CEILING_USD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500_000)
        .max(10_000)
}

#[derive(Debug, Clone)]
pub struct BlastRadiusInput {
    pub tenant_id: i64,
    pub client_id: Option<i64>,
    pub target_id: String,
    pub force_approved: bool,
    pub expected_vpc_tag: Option<String>,
}

pub async fn evaluate(pool: &PgPool, input: &BlastRadiusInput) -> BlastRadiusReport {
    let mut report = BlastRadiusReport::default();
    let Some(client_id) = input.client_id else {
        report.block_reason = "no client_id — cannot evaluate topology".into();
        if !input.force_approved {
            report.blocked = true;
        }
        return report;
    };

    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, input.tenant_id).await else {
        report.block_reason = "database unavailable".into();
        report.blocked = !input.force_approved;
        return report;
    };

    let target_norm = input.target_id.trim().to_lowercase();
    let rows = sqlx::query(
        r#"SELECT id, label, business_value_usd, crown_jewel, tags, metadata
           FROM risk_graph_nodes
           WHERE client_id = $1
             AND (
               lower(label) = $2
               OR lower(COALESCE(metadata, '')) LIKE '%' || $2 || '%'
               OR $2 = ANY (SELECT lower(unnest(tags)))
             )
           LIMIT 32"#,
    )
    .bind(client_id)
    .bind(&target_norm)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    for r in &rows {
        let val: i64 = r.try_get("business_value_usd").ok().flatten().unwrap_or(0);
        report.target_asset_value_usd = report.target_asset_value_usd.saturating_add(val);
        let crown: bool = r.try_get("crown_jewel").unwrap_or(false);
        if crown {
            report.crown_jewel_touched = true;
        }
        if let Some(exp_vpc) = input.expected_vpc_tag.as_deref() {
            let tags: Vec<String> = r.try_get("tags").unwrap_or_default();
            let has_vpc = tags.iter().any(|t| t.eq_ignore_ascii_case(exp_vpc));
            if !has_vpc && !exp_vpc.is_empty() {
                report.vpc_tag_mismatch = true;
            }
        }
    }

    let neighbor_rows = sqlx::query(
        r#"SELECT DISTINCT n.id, n.business_value_usd, n.crown_jewel
           FROM risk_graph_edges e
           JOIN risk_graph_nodes n ON n.id IN (e.from_node_id, e.to_node_id)
           JOIN risk_graph_nodes t ON t.client_id = $1
             AND lower(t.label) = $2
           WHERE e.tenant_id = $3
             AND (e.from_node_id = t.id OR e.to_node_id = t.id)
             AND n.id <> t.id
           LIMIT 64"#,
    )
    .bind(client_id)
    .bind(&target_norm)
    .bind(input.tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    report.neighbor_count = neighbor_rows.len() as u32;
    for r in neighbor_rows {
        let val: i64 = r.try_get("business_value_usd").ok().flatten().unwrap_or(0);
        report.neighbor_asset_value_usd = report.neighbor_asset_value_usd.saturating_add(val);
        if r.try_get::<bool, _>("crown_jewel").unwrap_or(false) {
            report.crown_jewel_touched = true;
        }
    }
    let _ = tx.commit().await;

    let total = report
        .target_asset_value_usd
        .saturating_add(report.neighbor_asset_value_usd);
    let ceiling = blast_radius_ceiling_usd();

    if input.force_approved {
        report.blocked = false;
        report.block_reason = "operator pre_approved in playbook params".into();
        return report;
    }
    if report.vpc_tag_mismatch {
        report.blocked = true;
        report.block_reason =
            "target VPC/tag does not match expected topology — wrong isolation scope".into();
        return report;
    }
    if report.crown_jewel_touched && total > ceiling / 2 {
        report.blocked = true;
        report.block_reason =
            format!("crown-jewel asset in blast radius (${total} exposure > ceiling/2)");
        return report;
    }
    if total > ceiling {
        report.blocked = true;
        report.block_reason = format!("aggregate blast radius ${total} exceeds ceiling ${ceiling}");
        return report;
    }
    report.blocked = false;
    report
}

impl BlastRadiusReport {
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "target_asset_value_usd": self.target_asset_value_usd,
            "neighbor_asset_value_usd": self.neighbor_asset_value_usd,
            "crown_jewel_touched": self.crown_jewel_touched,
            "neighbor_count": self.neighbor_count,
            "vpc_tag_mismatch": self.vpc_tag_mismatch,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
        })
    }
}
