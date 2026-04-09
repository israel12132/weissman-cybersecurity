//! Webhook + optional SMTP alerts for critical PoE findings.

use reqwest::Client;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

fn ascension_auto_poe_enabled() -> bool {
    matches!(
        std::env::var("WEISSMAN_ASCENSION_AUTO_POE_SYNTHESIS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) && matches!(
        std::env::var("WEISSMAN_ASCENSION_AUTO_POE_I_ACKNOWLEDGE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// After confirmed feedback-fuzz findings, optionally enqueue a follow-up `poe_synthesis_run` (duplicate PoE pass for richer patch text).
pub fn spawn_ascension_poe_followup(pool: Arc<PgPool>, tenant_id: i64, target: String) {
    if !ascension_auto_poe_enabled() {
        return;
    }
    let t = target.trim().to_string();
    if t.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let payload = json!({ "target": t });
        if let Err(e) = crate::async_jobs::enqueue(
            pool.as_ref(),
            tenant_id,
            "poe_synthesis_run",
            payload,
            Some("ascension-poe-followup".to_string()),
        )
        .await
        {
            tracing::warn!(target: "notifications", "ascension PoE enqueue failed: {}", e);
        }
    });
}

async fn webhook_url_from_db(pool: &PgPool, tenant_id: i64) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'alert_webhook_url'",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .filter(|s| !s.trim().is_empty())
}

async fn webhook_url_effective(pool: Option<(&PgPool, i64)>) -> Option<String> {
    if let Some((p, tid)) = pool {
        if let Some(u) = webhook_url_from_db(p, tid).await {
            return Some(u);
        }
    }
    std::env::var("WEISSMAN_ALERT_WEBHOOK_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

fn poc_has_curl(poc: &str) -> bool {
    let p = poc.to_lowercase();
    p.contains("curl")
}

/// Fire-and-forget: notify if severity is critical and PoC looks like cURL.
pub fn spawn_critical_poe_alert(
    pool: Arc<PgPool>,
    tenant_id: i64,
    client_id: &str,
    finding_id: &str,
    title: &str,
    severity: &str,
    poc_exploit: &str,
) {
    if !severity.trim().eq_ignore_ascii_case("critical") {
        return;
    }
    if !poc_has_curl(poc_exploit) {
        return;
    }
    let client_id = client_id.to_string();
    let finding_id = finding_id.to_string();
    let title = title.to_string();
    let poc = poc_exploit.to_string();
    tokio::spawn(async move {
        let webhook = webhook_url_effective(Some((pool.as_ref(), tenant_id))).await;
        let Some(url) = webhook else {
            return;
        };
        let payload = json!({
            "text": format!(
                "[Weissman] CRITICAL finding with PoE\nclient_id={}\nfinding_id={}\ntitle={}\npoc_exploit={}",
                client_id, finding_id, title, poc.chars().take(4000).collect::<String>()
            ),
            "content": format!(
                "**Weissman CRITICAL**\nclient `{}`\n`{}`\n{}\n```\n{}\n```",
                client_id,
                finding_id,
                title,
                poc.chars().take(3500).collect::<String>()
            ),
            "weissman": {
                "severity": "critical",
                "client_id": &client_id,
                "finding_id": &finding_id,
                "title": &title,
                "poc_exploit": poc.chars().take(8000).collect::<String>(),
            }
        });
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());
        if let Err(e) = client.post(&url).json(&payload).send().await {
            eprintln!("[Weissman][Notify] Webhook failed: {}", e);
        }
        let _ = send_smtp_critical_optional(title, client_id, finding_id, poc).await;
    });
}

async fn send_smtp_critical_optional(
    title: String,
    client_id: String,
    finding_id: String,
    poc: String,
) -> Result<(), String> {
    let enabled = matches!(
        std::env::var("WEISSMAN_SMTP_ENABLED").ok().as_deref(),
        Some("true") | Some("1")
    );
    if !enabled {
        return Ok(());
    }
    let host = std::env::var("WEISSMAN_SMTP_HOST")
        .map_err(|_| "WEISSMAN_SMTP_HOST missing".to_string())?;
    let port: u16 = std::env::var("WEISSMAN_SMTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(587);
    let user = std::env::var("WEISSMAN_SMTP_USER").unwrap_or_default();
    let pass = std::env::var("WEISSMAN_SMTP_PASSWORD").unwrap_or_default();
    let from = std::env::var("WEISSMAN_SMTP_FROM")
        .map_err(|_| "WEISSMAN_SMTP_FROM missing".to_string())?;
    let to =
        std::env::var("WEISSMAN_SMTP_TO").map_err(|_| "WEISSMAN_SMTP_TO missing".to_string())?;
    let body = format!(
        "Weissman CRITICAL finding\nclient_id={}\nfinding_id={}\ntitle={}\n\nPoE (cURL):\n{}\n",
        client_id,
        finding_id,
        title,
        poc.chars().take(12000).collect::<String>()
    );
    let subject = format!(
        "[Weissman] CRITICAL: {}",
        title.chars().take(80).collect::<String>()
    );
    tokio::task::spawn_blocking(move || {
        use lettre::message::{header::ContentType, Mailbox, Message};
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{SmtpTransport, Transport};
        let from_m: Mailbox = from
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?;
        let to_m: Mailbox = to
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?;
        let email = Message::builder()
            .from(from_m)
            .to(to_m)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|e| e.to_string())?;
        let mailer = {
            let mut b = SmtpTransport::relay(&host).map_err(|e| e.to_string())?;
            b = b.port(port);
            if user.is_empty() {
                b.build()
            } else {
                b.credentials(Credentials::new(user, pass)).build()
            }
        };
        mailer.send(&email).map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Optional Telegram alert for Genesis Protocol critical preemptive chains (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`).
pub fn spawn_genesis_telegram_alert(text: &str) {
    let token = std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default();
    let chat = std::env::var("TELEGRAM_CHAT_ID").unwrap_or_default();
    let token = token.trim().to_string();
    let chat = chat.trim().to_string();
    if token.is_empty() || chat.is_empty() {
        return;
    }
    let msg = format!("[Weissman Genesis] {}", text.chars().take(3500).collect::<String>());
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    tokio::spawn(async move {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(12))
            .build()
            .unwrap_or_else(|_| Client::new());
        let _ = client
            .post(&url)
            .json(&json!({ "chat_id": chat, "text": msg }))
            .send()
            .await;
    });
}
