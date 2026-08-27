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
    let date = resp
        .headers()
        .get(reqwest::header::DATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    crate::detections::note_http_date(date.as_deref());
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

/// Exchange a persisted renewal secret for a fresh session JWT.
///
/// This is what makes an agent survive. Enrollment tokens are single-use and the session JWT
/// expires (default 4h), so without a renewal path an agent had exactly one session in its entire
/// lifetime — and any restart re-enrolled with an already-consumed token, got 401 and exited.
pub async fn renew_session(
    server_url: &str,
    agent_id: &str,
    agent_secret: &str,
    agent_version: &str,
) -> anyhow::Result<String> {
    #[derive(Serialize)]
    struct Body<'a> {
        agent_id: &'a str,
        agent_secret: &'a str,
    }
    #[derive(serde::Deserialize)]
    struct Resp {
        session_jwt: String,
    }
    let url = format!("{}/api/agents/session", server_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(format!("weissman-agent/{}", agent_version))
        .build()?;
    let resp = client
        .post(&url)
        .json(&Body {
            agent_id,
            agent_secret,
        })
        .send()
        .await?;
    let date = resp
        .headers()
        .get(reqwest::header::DATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    crate::detections::note_http_date(date.as_deref());
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("session renewal failed (HTTP {}): {}", status, text);
    }
    let parsed: Resp = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("invalid session response: {} (body={})", e, text))?;
    if parsed.session_jwt.trim().is_empty() {
        anyhow::bail!("session response missing session_jwt");
    }
    Ok(parsed.session_jwt)
}
