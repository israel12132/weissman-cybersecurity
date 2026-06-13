//! `POST /api/agents/enroll` — exchange the bootstrap token for a per-agent session JWT.

use crate::protocol::Enrollment;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Serialize)]
struct EnrollRequest<'a> {
    enrollment_token: &'a str,
    hostname: &'a str,
    device_name: String,
    os: &'a str,
    arch: &'a str,
    agent_version: &'a str,
    client_id: Option<i64>,
    capabilities: Vec<&'a str>,
}

pub async fn enroll(
    server_url: &str,
    enrollment_token: &str,
    client_id: Option<i64>,
    hostname: &str,
    device_name: String,
    os: &str,
    arch: &str,
    agent_version: &str,
) -> anyhow::Result<Enrollment> {
    let url = format!("{}/api/agents/enroll", server_url.trim_end_matches('/'));
    let body = EnrollRequest {
        enrollment_token,
        hostname,
        device_name,
        os,
        arch,
        agent_version,
        client_id,
        capabilities: crate::detections::all_capability_ids(),
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(format!("weissman-agent/{}", agent_version))
        .build()?;
    let resp = client.post(&url).json(&body).send().await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("enrollment failed (HTTP {}): {}", status, text);
    }
    let enrollment: Enrollment = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("invalid enrollment response: {} (body={})", e, text))?;
    if enrollment.session_jwt.trim().is_empty() {
        anyhow::bail!("enrollment response missing session_jwt");
    }
    Ok(enrollment)
}
