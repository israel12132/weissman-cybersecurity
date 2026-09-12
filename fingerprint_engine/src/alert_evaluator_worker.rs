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

fn epss_matches(condition: &Value, epss: f64) -> bool {
    let Some(min) = condition
        .get("min_epss")
        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
    else {
        return true;
    };
    epss + f64::EPSILON >= min
}

fn kev_matches(condition: &Value, kev: bool) -> bool {
    match condition.get("kev_only").or_else(|| condition.get("kev")) {
        Some(Value::Bool(true)) => kev,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("true") || s == "1" => kev,
        _ => true,
    }
}

fn cvss_matches(condition: &Value, cvss: f64) -> bool {
    let Some(min) = condition
        .get("min_cvss")
        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
    else {
        return true;
    };
    cvss + f64::EPSILON >= min
}

fn crown_jewel_matches(condition: &Value, touches: bool) -> bool {
    match condition
        .get("crown_jewel")
        .or_else(|| condition.get("crown_jewel_on_path"))
    {
        Some(Value::Bool(true)) => touches,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("true") || s == "1" => touches,
        _ => true,
    }
}

fn cvss_from_raw(raw: &Value) -> f64 {
    for key in ["cvss_score", "cvss", "cvssScore", "score"] {
        if let Some(n) = raw.get(key).and_then(Value::as_f64) {
            return n;
        }
        if let Some(s) = raw.get(key).and_then(Value::as_str) {
            if let Ok(n) = s.parse::<f64>() {
                return n;
            }
        }
    }
    0.0
}

fn cve_from_raw(raw: &Value, title: &str, desc: &str) -> String {
    for key in ["cve", "cve_id", "cveId"] {
        if let Some(s) = raw.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if t.to_ascii_uppercase().starts_with("CVE-") {
                return t.to_string();
            }
        }
    }
    let hay = format!("{title} {desc}");
    if let Some(idx) = hay.to_ascii_uppercase().find("CVE-") {
        let slice = &hay[idx..];
        let cve: String = slice
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if cve.len() >= 8 {
            return cve;
        }
    }
    String::new()
}

fn target_from_raw(raw: &Value) -> String {
    raw.get("target")
        .or_else(|| raw.get("host"))
        .or_else(|| raw.get("url"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn cve_matches(condition: &Value, title: &str, desc: &str, cve: &str) -> bool {
    let pattern = condition
        .get("cve_pattern")
        .or_else(|| condition.get("cve"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if pattern.is_empty() {
        return true;
    }
    let needle = pattern.replace('*', "").to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }
    let hay = format!("{title} {desc} {cve}").to_ascii_lowercase();
    hay.contains(&needle)
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
        r#"SELECT v.id, v.severity, v.title, v.description, v.source, v.client_id,
                  COALESCE(v.epss_score, 0)::float8 AS epss_score,
                  COALESCE(v.kev_listed, false) AS kev_listed,
                  COALESCE(v.proof, '') AS proof,
                  COALESCE(v.raw_data, '{}'::jsonb) AS raw_data,
                  EXISTS (
                    SELECT 1 FROM risk_graph_nodes n
                     WHERE n.tenant_id = v.tenant_id
                       AND n.client_id = v.client_id
                       AND n.crown_jewel = TRUE
                       AND COALESCE(n.honey_node, FALSE) IS NOT TRUE
                       AND NULLIF(n.label, '') IS NOT NULL
                       AND (
                            COALESCE(v.raw_data->>'target','') ILIKE '%' || n.label || '%'
                         OR COALESCE(v.raw_data->>'host','') ILIKE '%' || n.label || '%'
                         OR v.title ILIKE '%' || n.label || '%'
                       )
                  ) AS crown_jewel_touch
           FROM vulnerabilities v
           WHERE v.created_at >= now() - interval '15 minutes'
             AND COALESCE(v.status, 'OPEN') NOT IN ('FALSE_POSITIVE', 'FP')
           ORDER BY v.id DESC
           LIMIT 500"#,
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
        let client_id: i64 = finding.try_get("client_id").unwrap_or(0);
        let epss: f64 = finding.try_get("epss_score").unwrap_or(0.0);
        let kev: bool = finding.try_get("kev_listed").unwrap_or(false);
        let proof: String = finding.try_get("proof").unwrap_or_default();
        let raw: Value = finding.try_get("raw_data").unwrap_or(json!({}));
        let crown_jewel: bool = finding.try_get("crown_jewel_touch").unwrap_or(false);
        let cvss = cvss_from_raw(&raw);
        let cve = cve_from_raw(&raw, &title, &description);
        let target = target_from_raw(&raw);

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
            if !cve_matches(&condition, &title, &description, &cve) {
                continue;
            }
            if !epss_matches(&condition, epss) {
                continue;
            }
            if !kev_matches(&condition, kev) {
                continue;
            }
            if !cvss_matches(&condition, cvss) {
                continue;
            }
            if !crown_jewel_matches(&condition, crown_jewel) {
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
                cve: cve.clone(),
                epss,
                kev,
                cvss,
                client_id,
                proof: proof.clone(),
                target: target.clone(),
                crown_jewel,
                deep_link: crate::alert_delivery::finding_deep_link(fid),
            };

            // The INSERT itself is the dedup gate: the (rule_id, finding_id) unique index makes a
            // duplicate a no-op via ON CONFLICT DO NOTHING (no RETURNING row), which avoids the
            // unique-violation that would otherwise poison the transaction and fail the dedup open.
            let fire_id: Option<i64> = sqlx::query_scalar(
                r#"INSERT INTO weissman_alert_rule_fires
                   (tenant_id, rule_id, finding_id, channels, delivered)
                   VALUES ($1, $2, $3, $4, false)
                   ON CONFLICT (rule_id, finding_id) DO NOTHING
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

            // No row returned ⇒ this (rule, finding) already fired ⇒ skip delivery.
            let Some(fire_id) = fire_id else {
                continue;
            };

            let delivered =
                deliver_alert(app_pool, tenant_id, &rule_info, &finding_info, &channels).await;

            if delivered {
                let _ = sqlx::query(
                    "UPDATE weissman_alert_rule_fires SET delivered = true WHERE id = $1",
                )
                .bind(fire_id)
                .execute(&mut *tx)
                .await;
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
        assert!(cve_matches(&json!({}), "any title", "any desc", ""));
        assert!(cve_matches(&json!({ "cve_pattern": "" }), "t", "d", ""));
    }

    #[test]
    fn cve_matches_searches_title_and_description() {
        let cond = json!({ "cve_pattern": "CVE-2021-44228" });
        assert!(cve_matches(&cond, "Log4Shell cve-2021-44228", "unrelated", ""));
        assert!(cve_matches(
            &cond,
            "unrelated",
            "affected by CVE-2021-44228 here",
            ""
        ));
        assert!(cve_matches(&cond, "nothing", "here", "CVE-2021-44228"));
        assert!(!cve_matches(&cond, "nothing", "here", ""));
    }

    #[test]
    fn cve_matches_falls_back_to_singular_cve_key() {
        let cond = json!({ "cve": "log4j" });
        assert!(cve_matches(&cond, "Apache Log4J RCE", "d", ""));
        assert!(!cve_matches(&cond, "nginx", "d", ""));
    }

    #[test]
    fn epss_kev_cvss_crown_jewel_gates() {
        let epss = json!({ "min_epss": 0.7 });
        assert!(epss_matches(&epss, 0.91));
        assert!(!epss_matches(&epss, 0.1));
        assert!(epss_matches(&json!({}), 0.0));

        let kev = json!({ "kev_only": true });
        assert!(kev_matches(&kev, true));
        assert!(!kev_matches(&kev, false));
        assert!(kev_matches(&json!({}), false));

        let cvss = json!({ "min_cvss": 9.0 });
        assert!(cvss_matches(&cvss, 9.8));
        assert!(!cvss_matches(&cvss, 4.0));

        let jewel = json!({ "crown_jewel": true });
        assert!(crown_jewel_matches(&jewel, true));
        assert!(!crown_jewel_matches(&jewel, false));
    }

    #[test]
    fn cvss_and_cve_from_raw_data() {
        let raw = json!({ "cvss_score": 9.8, "cve": "CVE-2024-1234", "target": "https://app.example" });
        assert!((cvss_from_raw(&raw) - 9.8).abs() < f64::EPSILON);
        assert_eq!(cve_from_raw(&raw, "", ""), "CVE-2024-1234");
        assert_eq!(target_from_raw(&raw), "https://app.example");
        assert_eq!(
            cve_from_raw(&json!({}), "Log4Shell CVE-2021-44228", ""),
            "CVE-2021-44228"
        );
    }
}
