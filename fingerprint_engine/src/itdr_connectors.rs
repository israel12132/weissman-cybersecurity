//! IdP connectors for ITDR — pull Entra / Okta / Google Workspace sign-in logs
//! into `itdr_auth_events`. Missing tokens fail visibly; no synthetic events.

use crate::itdr::AuthEvent;
use crate::soar::integrations::config_str;
use serde_json::{json, Value};
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct ConnectorPull {
    pub provider: String,
    pub ingested: usize,
    pub detail: String,
}

pub async fn load_connector_config(pool: &PgPool, tenant_id: i64) -> Value {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return json!({});
    };
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'itdr_connectors'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    raw.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

pub async fn save_connector_config(
    pool: &PgPool,
    tenant_id: i64,
    value: &Value,
) -> Result<(), String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("database unavailable".into());
    };
    sqlx::query(
        r#"INSERT INTO system_configs (tenant_id, key, value, description)
           VALUES ($1, 'itdr_connectors', $2, 'ITDR IdP connectors')
           ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value"#,
    )
    .bind(tenant_id)
    .bind(value.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn persist_events(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    events: &[AuthEvent],
) -> Result<usize, String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("database unavailable".into());
    };
    let mut n = 0usize;
    for e in events {
        if e.user.trim().is_empty() || e.ip.trim().is_empty() {
            continue;
        }
        let res = sqlx::query(
            r#"INSERT INTO itdr_auth_events
                 (tenant_id, client_id, ts, username, ip, country, success, mfa_prompted)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(e.ts)
        .bind(&e.user)
        .bind(&e.ip)
        .bind(&e.country)
        .bind(e.success)
        .bind(e.mfa_prompted)
        .execute(&mut *tx)
        .await;
        if res.is_ok() {
            n += 1;
        }
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(n)
}

fn graph_events(body: &Value) -> Vec<AuthEvent> {
    let mut out = Vec::new();
    let Some(arr) = body.get("value").and_then(Value::as_array) else {
        return out;
    };
    for item in arr {
        let user = item
            .get("userPrincipalName")
            .or_else(|| item.get("userDisplayName"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let ip = item
            .pointer("/ipAddress")
            .or_else(|| item.pointer("/location/ip"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let country = item
            .pointer("/location/countryOrRegion")
            .and_then(Value::as_str)
            .unwrap_or("");
        let status = item
            .pointer("/status/errorCode")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let mfa = item
            .get("authenticationRequirement")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("multi");
        let ts = chrono_ts(item.get("createdDateTime").and_then(Value::as_str));
        if !user.is_empty() && !ip.is_empty() {
            out.push(AuthEvent::new(ts, user, ip, country, status == 0, mfa));
        }
    }
    out
}

fn okta_events(body: &Value) -> Vec<AuthEvent> {
    let mut out = Vec::new();
    let arr = match body {
        Value::Array(a) => a.clone(),
        other => other
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    };
    for item in arr {
        let user = item
            .pointer("/actor/alternateId")
            .and_then(Value::as_str)
            .unwrap_or("");
        let ip = item
            .pointer("/client/ipAddress")
            .and_then(Value::as_str)
            .unwrap_or("");
        let country = item
            .pointer("/client/geographicalContext/country")
            .and_then(Value::as_str)
            .unwrap_or("");
        let outcome = item
            .pointer("/outcome/result")
            .and_then(Value::as_str)
            .unwrap_or("");
        let ts = chrono_ts(item.get("published").and_then(Value::as_str));
        if !user.is_empty() && !ip.is_empty() {
            out.push(AuthEvent::new(
                ts,
                user,
                ip,
                country,
                outcome.eq_ignore_ascii_case("SUCCESS"),
                item.pointer("/debugContext/debugData/factor")
                    .and_then(Value::as_str)
                    .is_some(),
            ));
        }
    }
    out
}

fn chrono_ts(raw: Option<&str>) -> i64 {
    let Some(s) = raw else {
        return 0;
    };
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.timestamp())
        .unwrap_or(0)
}

/// Pull one provider. Requires live credentials in connector config.
pub async fn pull_provider(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    provider: &str,
    cfg: &Value,
) -> Result<ConnectorPull, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let p = provider.trim().to_ascii_lowercase();
    match p.as_str() {
        "entra" | "azuread" | "microsoft" => {
            let token = config_str(cfg, &["access_token", "token", "graph_token"])
                .ok_or_else(|| "Entra connector missing access_token (Graph)".to_string())?;
            let url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100";
            let resp = client
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|e| format!("Graph unreachable: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("Graph HTTP {}", resp.status()));
            }
            let body: Value = resp.json().await.map_err(|e| e.to_string())?;
            let events = graph_events(&body);
            let n = persist_events(pool, tenant_id, client_id, &events).await?;
            Ok(ConnectorPull {
                provider: "entra".into(),
                ingested: n,
                detail: format!("graph signIns ingested={n}"),
            })
        }
        "okta" => {
            let token = config_str(cfg, &["api_token", "token", "ssws"])
                .ok_or_else(|| "Okta connector missing api_token".to_string())?;
            let domain = config_str(cfg, &["domain", "okta_domain", "org_url"])
                .ok_or_else(|| "Okta connector missing domain".to_string())?;
            let base = domain.trim().trim_end_matches('/');
            let url = if base.starts_with("http") {
                format!("{base}/api/v1/logs?limit=100")
            } else {
                format!("https://{base}/api/v1/logs?limit=100")
            };
            let resp = client
                .get(&url)
                .header("Authorization", format!("SSWS {token}"))
                .send()
                .await
                .map_err(|e| format!("Okta unreachable: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("Okta HTTP {}", resp.status()));
            }
            let body: Value = resp.json().await.map_err(|e| e.to_string())?;
            let events = okta_events(&body);
            let n = persist_events(pool, tenant_id, client_id, &events).await?;
            Ok(ConnectorPull {
                provider: "okta".into(),
                ingested: n,
                detail: format!("okta logs ingested={n}"),
            })
        }
        "google" | "workspace" => {
            let token = config_str(cfg, &["access_token", "token"])
                .ok_or_else(|| "Google connector missing access_token".to_string())?;
            let url = "https://www.googleapis.com/admin/reports/v1/activity/users/all/applications/login?maxResults=100";
            let resp = client
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|e| format!("Google reports unreachable: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("Google HTTP {}", resp.status()));
            }
            let body: Value = resp.json().await.map_err(|e| e.to_string())?;
            let mut events = Vec::new();
            if let Some(arr) = body.get("items").and_then(Value::as_array) {
                for item in arr {
                    let user = item
                        .pointer("/actor/email")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let ip = item
                        .pointer("/ipAddress")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let ts = chrono_ts(item.get("id").and_then(|v| v.get("time")).and_then(Value::as_str));
                    if !user.is_empty() && !ip.is_empty() {
                        events.push(AuthEvent::new(ts, user, ip, "", true, false));
                    }
                }
            }
            let n = persist_events(pool, tenant_id, client_id, &events).await?;
            Ok(ConnectorPull {
                provider: "google".into(),
                ingested: n,
                detail: format!("workspace login activity ingested={n}"),
            })
        }
        other => Err(format!("unknown ITDR provider {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_parser_reads_signins() {
        let body = json!({
            "value": [{
                "userPrincipalName": "ada@contoso.com",
                "ipAddress": "1.2.3.4",
                "location": { "countryOrRegion": "IL" },
                "status": { "errorCode": 0 },
                "authenticationRequirement": "multiFactorAuthentication",
                "createdDateTime": "2026-01-01T00:00:00Z"
            }]
        });
        let ev = graph_events(&body);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].user, "ada@contoso.com");
        assert!(ev[0].success);
        assert!(ev[0].mfa_prompted);
    }
}
