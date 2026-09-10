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

#[derive(Debug)]
pub struct AgentHttpError {
    pub status: u16,
    pub retry_after_secs: Option<u64>,
    pub body: String,
}

impl std::fmt::Display for AgentHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HTTP {}{}",
            self.status,
            if self.body.is_empty() {
                String::new()
            } else {
                format!(": {}", self.body.chars().take(240).collect::<String>())
            }
        )
    }
}

impl std::error::Error for AgentHttpError {}

impl AgentHttpError {
    pub fn is_unauthorized(&self) -> bool {
        self.status == 401
    }

    pub fn is_rate_limited(&self) -> bool {
        self.status == 429
    }

    pub fn wait(&self, fallback: Duration) -> Duration {
        self.retry_after_secs
            .map(|s| Duration::from_secs(s.max(1)))
            .unwrap_or(fallback)
    }
}

fn retry_after_from(resp: &reqwest::Response) -> Option<u64> {
    resp.headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
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
    let retry_after = retry_after_from(&resp);
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(AgentHttpError {
            status: status.as_u16(),
            retry_after_secs: retry_after,
            body: text,
        }
        .into());
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
    let retry_after = retry_after_from(&resp);
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(AgentHttpError {
            status: status.as_u16(),
            retry_after_secs: retry_after,
            body: text,
        }
        .into());
    }
    let parsed: Resp = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("invalid session response: {} (body={})", e, text))?;
    if parsed.session_jwt.trim().is_empty() {
        anyhow::bail!("session response missing session_jwt");
    }
    Ok(parsed.session_jwt)
}

/// Keep retrying session renewal. Never falls back to a consumed enrollment token.
pub async fn renew_session_with_backoff(
    server_url: &str,
    agent_id: &str,
    agent_secret: &str,
    agent_version: &str,
) -> anyhow::Result<String> {
    let mut delay = Duration::from_secs(2);
    loop {
        match renew_session(server_url, agent_id, agent_secret, agent_version).await {
            Ok(jwt) => return Ok(jwt),
            Err(e) => {
                let http = e.downcast_ref::<AgentHttpError>();
                if let Some(http) = http {
                    let wait = http.wait(delay);
                    tracing::warn!(
                        target: "agent",
                        status = http.status,
                        retry_after_secs = wait.as_secs(),
                        "session renewal HTTP {}; sleeping (will not re-enroll)",
                        http.status
                    );
                    tokio::time::sleep(wait).await;
                    delay = delay.saturating_mul(2).min(Duration::from_secs(120));
                    continue;
                }
                tracing::warn!(target: "agent", error = %e, "session renewal transport error; backing off");
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(60));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_honours_header_seconds() {
        let e = AgentHttpError {
            status: 429,
            retry_after_secs: Some(17),
            body: String::new(),
        };
        assert!(e.is_rate_limited());
        assert_eq!(e.wait(Duration::from_secs(2)), Duration::from_secs(17));
        assert!(AgentHttpError {
            status: 401,
            retry_after_secs: None,
            body: String::new(),
        }
        .is_unauthorized());
    }
}
