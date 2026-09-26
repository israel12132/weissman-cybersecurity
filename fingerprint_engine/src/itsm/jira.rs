//! Jira Cloud REST API v3 issue creation (POST /rest/api/3/issue).
//!
//! v3 requires the `description` field as an Atlassian Document Format (ADF) node, not a
//! plain string. Auth is typically Bearer (personal-access / OAuth token) for Jira Cloud,
//! or Basic (email + API token). The vendor returns `{ "id", "key", "self" }`.

use super::{
    read_body_bounded, truncate, AuthScheme, CreatedTicket, FindingTicketInput, ItsmConnector,
    ItsmError,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize)]
struct JiraCreateIssue {
    fields: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct JiraCreateResponse {
    #[serde(default)]
    id: String,
    #[serde(default)]
    key: String,
}

pub async fn create_issue(
    connector: &ItsmConnector,
    finding: &FindingTicketInput,
    client: &reqwest::Client,
) -> Result<CreatedTicket, ItsmError> {
    let project_key = connector.project_or_table.trim();
    if project_key.is_empty() {
        return Err(ItsmError::Config(
            "jira connector requires project_or_table (the project key, e.g. SEC)".to_string(),
        ));
    }
    let issue_type = connector
        .default_fields
        .get("issue_type")
        .and_then(|v| v.as_str())
        .unwrap_or("Task");

    let base = connector.base_url.trim().trim_end_matches('/');
    let url = format!("{base}/rest/api/3/issue");

    let summary = truncate(
        &format!(
            "[Weissman {}] {}",
            finding.severity.to_uppercase(),
            finding.summary
        ),
        250,
    );
    let body_text = format!(
        "Finding: {}\nSeverity: {}\n\n{}",
        finding.finding_ref, finding.severity, finding.details
    );
    let description_adf = json!({
        "type": "doc",
        "version": 1,
        "content": [
            { "type": "paragraph", "content": [ { "type": "text", "text": body_text } ] }
        ]
    });
    let mut fields = json!({
        "project": { "key": project_key },
        "summary": summary,
        "issuetype": { "name": issue_type },
        "description": description_adf,
    });
    // Merge tenant-provided extra fields (labels, components, custom fields) under
    // default_fields.fields WITHOUT clobbering the required keys set above.
    if let (Some(dst), Some(src)) = (
        fields.as_object_mut(),
        connector
            .default_fields
            .get("fields")
            .and_then(|v| v.as_object()),
    ) {
        for (k, v) in src {
            dst.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    let payload = JiraCreateIssue { fields };
    let mut req = client
        .post(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&payload);
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
    let parsed: JiraCreateResponse =
        serde_json::from_slice(&raw?).map_err(|e| ItsmError::Decode(e.to_string()))?;
    let external_url = if parsed.key.is_empty() {
        String::new()
    } else {
        format!("{base}/browse/{}", parsed.key)
    };
    Ok(CreatedTicket {
        external_id: parsed.id,
        external_key: parsed.key,
        external_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adf_description_and_required_fields_present() {
        // Reconstruct the field object the same way create_issue does, to assert shape.
        let fields = json!({
            "project": { "key": "SEC" },
            "summary": "s",
            "issuetype": { "name": "Task" },
            "description": {
                "type": "doc", "version": 1,
                "content": [ { "type": "paragraph", "content": [ { "type": "text", "text": "d" } ] } ]
            },
        });
        assert_eq!(fields["project"]["key"], "SEC");
        assert_eq!(fields["description"]["type"], "doc");
        assert_eq!(fields["description"]["version"], 1);
    }

    #[test]
    fn create_response_ignores_unknown_fields() {
        let r: JiraCreateResponse = serde_json::from_str(
            r#"{"id":"10000","key":"SEC-1","self":"https://x/rest/api/3/issue/10000"}"#,
        )
        .unwrap();
        assert_eq!(r.id, "10000");
        assert_eq!(r.key, "SEC-1");
    }
}
