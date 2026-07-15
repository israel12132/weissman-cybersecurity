//! Evaluates enabled `weissman_alert_rules` against recent findings and records fires.
//! Enable with `WEISSMAN_ALERT_EVAL_CRON=1` (default on in production).

use crate::alert_delivery::{deliver_alert, AlertFindingInfo, AlertRuleInfo};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;

fn poll_interval_secs() -> u64 {
    std::env::var("WEISSMAN_ALERT_EVAL_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n >= 30)
        .unwrap_or(60)
}

fn cron_enabled() -> bool {
    if let Ok(v) = std::env::var("WEISSMAN_ALERT_EVAL_CRON") {
        return v == "1" || v.eq_ignore_ascii_case("true");
    }
    weissman_core::tls_policy::is_production_environment()
}

fn severity_matches(condition: &Value, finding_sev: &str) -> bool {
    let sev = finding_sev.to_ascii_lowercase();
    if let Some(arr) = condition.get("severity").and_then(|v| v.as_array()) {
        return arr.iter().any(|s| {
            s.as_str()
                .map(|x| x.eq_ignore_ascii_case(&sev))
                .unwrap_or(false)
        });
    }
    if let Some(s) = condition.get("min_severity").and_then(|v| v.as_str()) {
        let rank = |x: &str| match x.to_ascii_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        return rank(&sev) >= rank(s);
    }
    true
}

fn engine_matches(condition: &Value, source: &str) -> bool {
    let engines = condition
        .get("engines")
        .or_else(|| condition.get("engine"))
        .and_then(|v| v.as_array());
    let Some(arr) = engines else {
        return true;
    };
    let src = source.to_ascii_lowercase();
    arr.iter().any(|e| {
        e.as_str()
            .map(|x| src.contains(&x.to_ascii_lowercase()))
            .unwrap_or(false)
    })
}

fn cve_matches(condition: &Value, title: &str, desc: &str) -> bool {
    let pattern = condition
        .get("cve_pattern")
        .or_else(|| condition.get("cve"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if pattern.is_empty() {
        return true;
    }
    let hay = format!("{title} {desc}").to_ascii_lowercase();
    hay.contains(&pattern.to_ascii_lowercase())
}

async fn evaluate_tenant(app_pool: &PgPool, tenant_id: i64) -> Result<u32, String> {
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rules = sqlx::query(
        r#"SELECT id, name, condition, actions FROM weissman_alert_rules WHERE enabled = true"#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    if rules.is_empty() {
        let _ = tx.rollback().await;
        return Ok(0);
    }

    let findings = sqlx::query(
        r#"SELECT id, severity, title, description, source
           FROM vulnerabilities
           WHERE created_at >= now() - interval '5 minutes'
           ORDER BY id DESC
           LIMIT 200"#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let mut fired = 0u32;
    for finding in findings {
        let fid: i64 = finding.try_get("id").unwrap_or(0);
        let severity: String = finding.try_get("severity").unwrap_or_default();
        let title: String = finding.try_get("title").unwrap_or_default();
        let description: String = finding.try_get("description").unwrap_or_default();
        let source: String = finding.try_get("source").unwrap_or_default();

        for rule in &rules {
            let rule_id: i64 = rule.try_get("id").unwrap_or(0);
            let condition: Value = rule.try_get("condition").unwrap_or(json!({}));
            let actions: Value = rule.try_get("actions").unwrap_or(json!({}));

            if !severity_matches(&condition, &severity) {
                continue;
            }
            if !engine_matches(&condition, &source) {
                continue;
            }
            if !cve_matches(&condition, &title, &description) {
                continue;
            }

            let already: Option<i64> = sqlx::query_scalar(
                r#"SELECT id FROM weissman_alert_rule_fires
                   WHERE rule_id = $1 AND finding_id = $2 LIMIT 1"#,
            )
            .bind(rule_id)
            .bind(fid)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
            if already.is_some() {
                continue;
            }

            let channels: Vec<String> = actions
                .get("channels")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|c| c.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let rule_name: String = rule.try_get("name").unwrap_or_default();
            let rule_info = AlertRuleInfo {
                id: rule_id,
                name: rule_name,
            };
            let finding_info = AlertFindingInfo {
                id: fid,
                severity: severity.clone(),
                title: title.clone(),
                description: description.clone(),
                source: source.clone(),
            };

            let fire_id: Option<i64> = sqlx::query_scalar(
                r#"INSERT INTO weissman_alert_rule_fires
                   (tenant_id, rule_id, finding_id, channels, delivered)
                   VALUES ($1, $2, $3, $4, false)
                   RETURNING id"#,
            )
            .bind(tenant_id)
            .bind(rule_id)
            .bind(fid)
            .bind(json!(channels))
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();

            let delivered =
                deliver_alert(app_pool, tenant_id, &rule_info, &finding_info, &channels).await;

            if delivered {
                if let Some(id) = fire_id {
                    let _ = sqlx::query(
                        "UPDATE weissman_alert_rule_fires SET delivered = true WHERE id = $1",
                    )
                    .bind(id)
                    .execute(&mut *tx)
                    .await;
                }
            }

            fired += 1;
            tracing::info!(
                target: "alert_evaluator",
                tenant_id,
                rule_id,
                finding_id = fid,
                delivered,
                "alert rule fired"
            );
        }
    }
    let _ = tx.commit().await;
    Ok(fired)
}

async fn tick(app_pool: &PgPool, auth_pool: &PgPool) {
    let tenants: Vec<i64> = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true")
        .fetch_all(auth_pool)
        .await
        .unwrap_or_default();
    for tid in tenants {
        if let Err(e) = evaluate_tenant(app_pool, tid).await {
            tracing::warn!(target: "alert_evaluator", tenant_id = tid, error = %e, "eval failed");
        }
    }
}

pub fn spawn_alert_evaluator_worker(app_pool: Arc<PgPool>, auth_pool: Arc<PgPool>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(poll_interval_secs()));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if !cron_enabled() {
                continue;
            }
            tick(app_pool.as_ref(), auth_pool.as_ref()).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_matches_explicit_array_is_case_insensitive() {
        let cond = json!({ "severity": ["High", "Critical"] });
        assert!(severity_matches(&cond, "high"));
        assert!(severity_matches(&cond, "CRITICAL"));
        assert!(!severity_matches(&cond, "low"));
        assert!(!severity_matches(&cond, "medium"));
    }

    #[test]
    fn severity_matches_min_severity_ranking() {
        let cond = json!({ "min_severity": "high" });
        // rank: critical=4, high=3, medium=2, low=1, other=0
        assert!(severity_matches(&cond, "critical")); // 4 >= 3
        assert!(severity_matches(&cond, "High")); // 3 >= 3
        assert!(!severity_matches(&cond, "medium")); // 2 >= 3
        assert!(!severity_matches(&cond, "low")); // 1 >= 3
        assert!(!severity_matches(&cond, "informational")); // 0 >= 3
    }

    #[test]
    fn severity_matches_defaults_to_true_without_condition() {
        assert!(severity_matches(&json!({}), "anything"));
        assert!(severity_matches(&json!({ "unrelated": 1 }), "low"));
    }

    #[test]
    fn engine_matches_absent_engines_is_true() {
        assert!(engine_matches(&json!({}), "nuclei_http"));
    }

    #[test]
    fn engine_matches_uses_substring_and_case_insensitivity() {
        let cond = json!({ "engines": ["Nuclei", "zap"] });
        assert!(engine_matches(&cond, "nuclei_http_engine"));
        assert!(engine_matches(&cond, "OWASP-ZAP"));
        assert!(!engine_matches(&cond, "nmap"));
    }

    #[test]
    fn engine_matches_falls_back_to_singular_engine_key() {
        let cond = json!({ "engine": ["trivy"] });
        assert!(engine_matches(&cond, "trivy-scan"));
        assert!(!engine_matches(&cond, "grype"));
    }

    #[test]
    fn cve_matches_empty_pattern_is_true() {
        assert!(cve_matches(&json!({}), "any title", "any desc"));
        assert!(cve_matches(&json!({ "cve_pattern": "" }), "t", "d"));
    }

    #[test]
    fn cve_matches_searches_title_and_description() {
        let cond = json!({ "cve_pattern": "CVE-2021-44228" });
        assert!(cve_matches(&cond, "Log4Shell cve-2021-44228", "unrelated"));
        assert!(cve_matches(&cond, "unrelated", "affected by CVE-2021-44228 here"));
        assert!(!cve_matches(&cond, "nothing", "here"));
    }

    #[test]
    fn cve_matches_falls_back_to_singular_cve_key() {
        let cond = json!({ "cve": "log4j" });
        assert!(cve_matches(&cond, "Apache Log4J RCE", "d"));
        assert!(!cve_matches(&cond, "nginx", "d"));
    }
}
