//! ServiceNow Table API incident creation (POST /api/now/table/<table>).
//!
//! Basic auth is the ServiceNow norm (an integration user + password/token); a Bearer
//! token is also accepted for OAuth deployments. The vendor returns the created record
//! under `result` with `sys_id` (opaque id) and `number` (e.g. INC0010001).

use super::{
    read_body_bounded, severity_rank, truncate, AuthScheme, CreatedTicket, FindingTicketInput,
    ItsmConnector, ItsmError,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct SnowIncidentRequest {
    short_description: String,
    description: String,
    /// ServiceNow urgency: "1" High, "2" Medium, "3" Low.
    urgency: String,
    /// ServiceNow impact: same scale as urgency.
    impact: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    category: String,
}

#[derive(Debug, Deserialize)]
struct SnowIncidentResult {
    #[serde(default)]
    sys_id: String,
    #[serde(default)]
    number: String,
}

#[derive(Debug, Deserialize)]
struct SnowEnvelope {
    result: SnowIncidentResult,
}

fn snow_urgency(severity: &str) -> String {
    match severity_rank(severity) {
        1 | 2 => "1".to_string(),
        3 => "2".to_string(),
        _ => "3".to_string(),
    }
}

pub async fn create_incident(
    connector: &ItsmConnector,
    finding: &FindingTicketInput,
    client: &reqwest::Client,
) -> Result<CreatedTicket, ItsmError> {
    let table = {
        let t = connector.project_or_table.trim();
        if t.is_empty() {
            "incident"
        } else {
            t
        }
    };
    let base = connector.base_url.trim().trim_end_matches('/');
    let url = format!("{base}/api/now/table/{table}");

    let urgency = snow_urgency(&finding.severity);
    let category = connector
        .default_fields
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("security")
        .to_string();
    let body = SnowIncidentRequest {
        short_description: truncate(
            &format!(
                "[Weissman {}] {}",
                finding.severity.to_uppercase(),
                finding.summary
            ),
            160,
        ),
        description: format!(
            "Finding: {}\nSeverity: {}\n\n{}",
            finding.finding_ref, finding.severity, finding.details
        ),
        impact: urgency.clone(),
        urgency,
        category,
    };

    let mut req = client
        .post(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&body);
    req = match connector.credential.scheme {
        AuthScheme::Basic => req.basic_auth(
            connector.credential.username.trim(),
            Some(connector.credential.secret.trim()),
        ),
        AuthScheme::Bearer => req.bearer_auth(connector.credential.secret.trim()),
    };
    let resp = req
        .send()
        .await
        .map_err(|e| ItsmError::Request(e.to_string()))?;
    let status = resp.status();
    // MINOR-3: cap the response body (both the error and success paths) so a hostile endpoint
    // cannot stream an unbounded body into memory. read_body_bounded rejects over the cap.
    let raw = read_body_bounded(resp).await;
    if !status.is_success() {
        let body = raw
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        return Err(ItsmError::Status {
            status: status.as_u16(),
            body: truncate(&body, 500),
        });
    }
    let env: SnowEnvelope =
        serde_json::from_slice(&raw?).map_err(|e| ItsmError::Decode(e.to_string()))?;
    let external_url = if env.result.sys_id.is_empty() {
        String::new()
    } else {
        // ServiceNow classic deep-link to the created incident record.
        format!(
            "{base}/nav_to.do?uri=incident.do?sys_id={}",
            env.result.sys_id
        )
    };
    Ok(CreatedTicket {
        external_id: env.result.sys_id,
        external_key: env.result.number,
        external_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urgency_maps_severity() {
        assert_eq!(snow_urgency("critical"), "1");
        assert_eq!(snow_urgency("high"), "1");
        assert_eq!(snow_urgency("medium"), "2");
        assert_eq!(snow_urgency("low"), "3");
    }

    #[test]
    fn request_body_serializes_without_empty_category() {
        let b = SnowIncidentRequest {
            short_description: "s".into(),
            description: "d".into(),
            urgency: "2".into(),
            impact: "2".into(),
            category: String::new(),
        };
        let j = serde_json::to_value(&b).unwrap();
        assert!(j.get("category").is_none());
        assert_eq!(j["urgency"], "2");
    }
}
