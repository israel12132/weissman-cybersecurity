//! Portfolio (fleet-wide) security posture — the MSSP / multi-client view.
//!
//! Every other posture endpoint answers for one client. An MSSP or enterprise security lead running
//! many clients in one tenant needs the portfolio question: "across all my clients, how many are
//! failing, which are worst, and how much KEV risk is overdue fleet-wide?" This module computes each
//! client's posture from the same [`crate::posture_score`] engine and rolls them into one summary.
//!
//! The per-client scoring is a pure reuse of the tested engines; only the roll-up (`summarize`) is
//! new, and it is pure/deterministic. The DB loader is read-only and RLS-scoped.

use serde::Serialize;
use serde_json::{json, Value};

/// One client's headline posture within the portfolio.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ClientPosture {
    pub client_id: i64,
    pub name: String,
    pub score: f64,
    pub grade: char,
    pub action_count: usize,
    pub kev_actions: usize,
    pub overdue_now: usize,
    pub total_findings: usize,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Roll per-client postures into a portfolio summary. Pure/deterministic: clients are ordered
/// worst-first (score asc, then name) so the riskiest surface immediately.
#[must_use]
pub fn summarize(clients: &[ClientPosture]) -> Value {
    let mut sorted: Vec<ClientPosture> = clients.to_vec();
    sorted.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.name.cmp(&b.name))
    });

    let count = sorted.len();
    let mut dist = std::collections::BTreeMap::new();
    for g in ['A', 'B', 'C', 'D', 'F'] {
        dist.insert(g.to_string(), 0usize);
    }
    let mut total_findings = 0usize;
    let mut kev_actions = 0usize;
    let mut overdue_now = 0usize;
    let mut score_sum = 0.0;
    for c in &sorted {
        *dist.entry(c.grade.to_string()).or_insert(0) += 1;
        total_findings += c.total_findings;
        kev_actions += c.kev_actions;
        overdue_now += c.overdue_now;
        score_sum += c.score;
    }
    let average_score = if count > 0 { round1(score_sum / count as f64) } else { 100.0 };
    let clients_at_risk = sorted.iter().filter(|c| matches!(c.grade, 'D' | 'F')).count();
    let worst: Vec<&ClientPosture> = sorted.iter().take(5).collect();

    json!({
        "client_count": count,
        "average_score": average_score,
        "grade_distribution": dist,
        "clients_at_risk": clients_at_risk,
        "fleet": {
            "total_findings": total_findings,
            "kev_actions": kev_actions,
            "overdue_now": overdue_now,
        },
        "worst_clients": worst,
        "clients": sorted,
    })
}

/// Compute the portfolio posture across all clients in the tenant. Read-only; RLS-scoped.
///
/// Runs one findings query per client, bounded by `max_clients` — intended for a periodically
/// refreshed MSSP dashboard, not a hot path.
pub async fn load_portfolio(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    max_clients: i64,
    per_client_limit: i64,
) -> Result<Value, String> {
    use sqlx::Row;

    let max_clients = max_clients.clamp(1, 500);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT id, COALESCE(name, '') AS name
             FROM clients
            WHERE tenant_id = $1
            ORDER BY id
            LIMIT $2"#,
    )
    .bind(tenant_id)
    .bind(max_clients)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    let client_rows: Vec<(i64, String)> = rows
        .iter()
        .filter_map(|r| Some((r.try_get::<i64, _>("id").ok()?, r.try_get::<String, _>("name").unwrap_or_default())))
        .collect();

    let mut postures: Vec<ClientPosture> = Vec::with_capacity(client_rows.len());
    for (client_id, name) in client_rows {
        let findings =
            crate::remediation_priority::load_findings(pool, tenant_id, client_id, per_client_limit)
                .await?;
        let total_findings = findings.len();
        let program = crate::remediation_priority::rank(&findings);
        let posture = crate::posture_score::score(&program, total_findings);
        let overdue_now = crate::sla_forecast::overdue_now(&program);
        let kev_actions = program.iter().filter(|i| i.kev).count();
        postures.push(ClientPosture {
            client_id,
            name,
            score: posture.score,
            grade: posture.grade,
            action_count: program.len(),
            kev_actions,
            overdue_now,
            total_findings,
        });
    }

    let mut summary = summarize(&postures);
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("ok".to_string(), json!(true));
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(id: i64, name: &str, score: f64, grade: char) -> ClientPosture {
        ClientPosture {
            client_id: id,
            name: name.to_string(),
            score,
            grade,
            action_count: 1,
            kev_actions: if grade == 'F' { 2 } else { 0 },
            overdue_now: if grade == 'F' { 1 } else { 0 },
            total_findings: 3,
        }
    }

    #[test]
    fn empty_portfolio_is_well_formed() {
        let s = summarize(&[]);
        assert_eq!(s["client_count"].as_u64().unwrap(), 0);
        assert_eq!(s["average_score"].as_f64().unwrap(), 100.0);
        assert_eq!(s["clients_at_risk"].as_u64().unwrap(), 0);
        assert!(s["clients"].as_array().unwrap().is_empty());
    }

    #[test]
    fn clients_are_ordered_worst_first() {
        let s = summarize(&[
            cp(1, "alpha", 95.0, 'A'),
            cp(2, "bravo", 40.0, 'F'),
            cp(3, "charlie", 72.0, 'C'),
        ]);
        let clients = s["clients"].as_array().unwrap();
        assert_eq!(clients[0]["name"], "bravo"); // lowest score first
        assert_eq!(clients[2]["name"], "alpha");
        assert_eq!(s["worst_clients"].as_array().unwrap()[0]["name"], "bravo");
    }

    #[test]
    fn distribution_and_fleet_totals() {
        let s = summarize(&[
            cp(1, "a", 95.0, 'A'),
            cp(2, "b", 85.0, 'B'),
            cp(3, "c", 40.0, 'F'),
            cp(4, "d", 30.0, 'F'),
        ]);
        assert_eq!(s["grade_distribution"]["F"].as_u64().unwrap(), 2);
        assert_eq!(s["grade_distribution"]["A"].as_u64().unwrap(), 1);
        assert_eq!(s["clients_at_risk"].as_u64().unwrap(), 2); // two F
        assert_eq!(s["fleet"]["kev_actions"].as_u64().unwrap(), 4); // 2 per F client
        assert_eq!(s["fleet"]["overdue_now"].as_u64().unwrap(), 2);
        assert_eq!(s["fleet"]["total_findings"].as_u64().unwrap(), 12);
    }

    #[test]
    fn average_score_is_the_mean_rounded() {
        let s = summarize(&[cp(1, "a", 90.0, 'A'), cp(2, "b", 60.0, 'D')]);
        assert_eq!(s["average_score"].as_f64().unwrap(), 75.0);
    }

    #[test]
    fn worst_clients_capped_at_five() {
        let clients: Vec<ClientPosture> = (0..8)
            .map(|i| cp(i, &format!("c{i}"), 50.0 + i as f64, 'F'))
            .collect();
        let s = summarize(&clients);
        assert_eq!(s["worst_clients"].as_array().unwrap().len(), 5);
        assert_eq!(s["clients"].as_array().unwrap().len(), 8);
    }
}
