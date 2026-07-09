//! Alert rule fire notification delivery (webhook, Slack, PagerDuty, email).

use reqwest::Client;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AlertRuleInfo {
    pub id: i64,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct AlertFindingInfo {
    pub id: i64,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source: String,
}

struct DeliveryConfig {
    alert_webhook_url: Option<String>,
    slack_webhook_url: Option<String>,
    pagerduty_routing_key: Option<String>,
    integrations: Vec<Value>,
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|x| !x.trim().is_empty())
}

async fn config_value(pool: &PgPool, tenant_id: i64, key: &str) -> Option<String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await.ok()?;
    let val = sqlx::query_scalar::<_, String>(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = $2",
    )
    .bind(tenant_id)
    .bind(key)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    non_empty(val)
}

async fn load_delivery_config(pool: &PgPool, tenant_id: i64) -> DeliveryConfig {
    let alert_webhook_url = config_value(pool, tenant_id, "alert_webhook_url")
        .await
        .or_else(|| non_empty(std::env::var("WEISSMAN_ALERT_WEBHOOK_URL").ok()));
    let slack_webhook_url = config_value(pool, tenant_id, "slack_webhook_url")
        .await
        .or_else(|| non_empty(std::env::var("SLACK_WEBHOOK_URL").ok()));
    let pagerduty_routing_key = config_value(pool, tenant_id, "pagerduty_routing_key")
        .await
        .or_else(|| non_empty(std::env::var("PAGERDUTY_ROUTING_KEY").ok()));

    let integrations = config_value(pool, tenant_id, "integrations_registry")
        .await
        .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
        .unwrap_or_default();

    DeliveryConfig {
        alert_webhook_url,
        slack_webhook_url,
        pagerduty_routing_key,
        integrations,
    }
}

fn integration_config<'a>(integrations: &'a [Value], id: &str) -> Option<&'a Value> {
    integrations
        .iter()
        .find(|i| i.get("id").and_then(Value::as_str) == Some(id))
        .and_then(|item| item.get("config"))
}

fn config_str(config: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = config.get(*key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn resolve_webhook_url(config: &DeliveryConfig, integration_id: &str) -> Option<String> {
    integration_config(&config.integrations, integration_id)
        .and_then(|c| config_str(c, &["url", "webhook_url"]))
        .or_else(|| {
            if integration_id == "alert_webhook" {
                config.alert_webhook_url.clone()
            } else if integration_id == "slack" {
                config.slack_webhook_url.clone()
            } else {
                None
            }
        })
}

fn resolve_pagerduty_key(config: &DeliveryConfig) -> Option<String> {
    integration_config(&config.integrations, "pagerduty")
        .and_then(|c| config_str(c, &["routing_key", "key"]))
        .or_else(|| config.pagerduty_routing_key.clone())
}

fn alert_payload(channel: &str, rule: &AlertRuleInfo, finding: &AlertFindingInfo) -> Value {
    json!({
        "channel": channel,
        "event": "alert_rule_fired",
        "rule": {
            "id": rule.id,
            "name": rule.name,
        },
        "finding": {
            "id": finding.id,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "source": finding.source,
        },
        "text": format!(
            "[Weissman][{}] rule \"{}\" fired on {} finding: {}",
            channel, rule.name, finding.severity, finding.title
        ),
    })
}

fn pagerduty_severity(severity: &str) -> &str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "error",
        "medium" => "warning",
        "low" => "info",
        _ => "error",
    }
}

async fn post_json(client: &Client, url: &str, payload: &Value) -> bool {
    match client.post(url).json(payload).send().await {
        Ok(resp) if resp.status().is_success() => true,
        Ok(resp) => {
            tracing::warn!(
                target: "alert_delivery",
                status = %resp.status(),
                "webhook delivery failed"
            );
            false
        }
        Err(e) => {
            tracing::warn!(target: "alert_delivery", error = %e, "webhook delivery error");
            false
        }
    }
}

fn smtp_enabled() -> bool {
    matches!(
        std::env::var("WEISSMAN_SMTP_ENABLED").ok().as_deref(),
        Some("true") | Some("1")
    )
}

async fn deliver_email(rule: &AlertRuleInfo, finding: &AlertFindingInfo) -> bool {
    tracing::info!(
        target: "alert_delivery",
        rule_id = rule.id,
        finding_id = finding.id,
        "email alert channel requested"
    );
    if !smtp_enabled() {
        tracing::warn!(
            target: "alert_delivery",
            rule_id = rule.id,
            finding_id = finding.id,
            "email delivery skipped: SMTP not configured"
        );
        return false;
    }
    let subject = format!(
        "[Weissman] {} — {}",
        finding.severity,
        finding.title.chars().take(80).collect::<String>()
    );
    let body = format!(
        "Alert rule \"{}\" fired.\n\nFinding #{}\nSeverity: {}\nSource: {}\nTitle: {}\n\n{}",
        rule.name, finding.id, finding.severity, finding.source, finding.title, finding.description
    );
    tokio::task::spawn_blocking(move || send_smtp_sync(subject, body))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
}

fn send_smtp_sync(subject: String, body: String) -> Result<(), String> {
    use lettre::message::{header::ContentType, Mailbox, Message};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{SmtpTransport, Transport};

    let host = std::env::var("WEISSMAN_SMTP_HOST").map_err(|_| "missing host".to_string())?;
    let port: u16 = std::env::var("WEISSMAN_SMTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(587);
    let user = std::env::var("WEISSMAN_SMTP_USER").unwrap_or_default();
    let pass = std::env::var("WEISSMAN_SMTP_PASSWORD").unwrap_or_default();
    let from = std::env::var("WEISSMAN_SMTP_FROM").map_err(|_| "missing from".to_string())?;
    let to = std::env::var("WEISSMAN_SMTP_TO").map_err(|_| "missing to".to_string())?;

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
    Ok(())
}

async fn deliver_channel(
    client: &Client,
    config: &DeliveryConfig,
    channel: &str,
    rule: &AlertRuleInfo,
    finding: &AlertFindingInfo,
) -> bool {
    match channel {
        "webhook" => {
            let Some(url) = resolve_webhook_url(config, "alert_webhook") else {
                tracing::warn!(target: "alert_delivery", "webhook channel: no URL configured");
                return false;
            };
            post_json(client, &url, &alert_payload("webhook", rule, finding)).await
        }
        "slack" | "teams" => {
            let Some(url) = resolve_webhook_url(config, "slack") else {
                tracing::warn!(target: "alert_delivery", channel, "no webhook URL configured");
                return false;
            };
            let payload = json!({
                "text": alert_payload(channel, rule, finding)
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("[Weissman] alert"),
            });
            post_json(client, &url, &payload).await
        }
        "pagerduty" => {
            let Some(routing_key) = resolve_pagerduty_key(config) else {
                tracing::warn!(target: "alert_delivery", "pagerduty channel: no routing key");
                return false;
            };
            let payload = json!({
                "routing_key": routing_key,
                "event_action": "trigger",
                "dedup_key": format!("weissman:rule:{}:finding:{}", rule.id, finding.id),
                "payload": {
                    "summary": format!(
                        "[pagerduty] {} — {}",
                        finding.severity, finding.title
                    ).chars().take(1024).collect::<String>(),
                    "severity": pagerduty_severity(&finding.severity),
                    "source": finding.source.chars().take(255).collect::<String>(),
                    "custom_details": {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "finding_id": finding.id,
                    }
                }
            });
            post_json(client, "https://events.pagerduty.com/v2/enqueue", &payload).await
        }
        "email" => deliver_email(rule, finding).await,
        other => {
            tracing::warn!(target: "alert_delivery", channel = other, "unknown alert channel");
            false
        }
    }
}

/// Attempt delivery on configured channels. Returns true if at least one channel succeeds.
pub async fn deliver_alert(
    pool: &PgPool,
    tenant_id: i64,
    rule: &AlertRuleInfo,
    finding: &AlertFindingInfo,
    channels: &[String],
) -> bool {
    if channels.is_empty() {
        return false;
    }

    let config = load_delivery_config(pool, tenant_id).await;
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| Client::new());

    let mut any_ok = false;
    for channel in channels {
        let ch = channel.to_ascii_lowercase();
        if deliver_channel(&client, &config, &ch, rule, finding).await {
            any_ok = true;
            tracing::info!(
                target: "alert_delivery",
                tenant_id,
                rule_id = rule.id,
                finding_id = finding.id,
                channel = %ch,
                "alert delivered"
            );
        }
    }
    any_ok
}

/// Fire tenant alert channels when SOAR playbook dispatch fails after finding persist.
pub async fn notify_soar_dispatch_failure(
    pool: &PgPool,
    tenant_id: i64,
    finding_id: i64,
    summary: &str,
    results: &[crate::soar_playbook::PlaybookRunResult],
) {
    let config = load_delivery_config(pool, tenant_id).await;
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| Client::new());

    let payload = json!({
        "event": "soar_dispatch_failure",
        "tenant_id": tenant_id,
        "finding_id": finding_id,
        "summary": summary,
        "results": results,
        "text": format!(
            "[Weissman][SOAR] playbook dispatch failure on finding #{finding_id}: {summary}"
        ),
    });

    let mut delivered = false;
    if let Some(url) = config.alert_webhook_url.as_deref() {
        delivered |= post_json(&client, url, &payload).await;
    }
    if let Some(url) = config.slack_webhook_url.as_deref() {
        delivered |= post_json(&client, url, &payload).await;
    }
    if let Some(key) = resolve_pagerduty_key(&config) {
        let pd = json!({
            "routing_key": key,
            "event_action": "trigger",
            "payload": {
                "summary": format!("SOAR dispatch failure finding #{finding_id}"),
                "severity": "error",
                "source": "weissman-soar",
                "custom_details": payload,
            }
        });
        delivered |= post_json(&client, "https://events.pagerduty.com/v2/enqueue", &pd).await;
    }

    if !delivered {
        tracing::warn!(
            target: "alert_delivery",
            tenant_id,
            finding_id,
            "SOAR dispatch failure alert not delivered (no channels configured)"
        );
    }
}

/// Fire tenant alert channels when an auto-heal run reaches a terminal outcome. Best-effort:
/// posts to webhook/Slack always, and pages on-call only for failures / `broke_app`.
#[allow(clippy::too_many_arguments)]
pub async fn notify_heal_completed(
    pool: &PgPool,
    tenant_id: i64,
    finding_id: &str,
    verdict: &str,
    channel: &str,
    attempts: i32,
    pr_url: Option<&str>,
    ok: bool,
) {
    let config = load_delivery_config(pool, tenant_id).await;
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| Client::new());

    let icon = if ok { "✅" } else { "⚠️" };
    let link = pr_url.map(|u| format!(" — {u}")).unwrap_or_default();
    let text = format!(
        "[Weissman][Auto-Heal] {icon} finding {finding_id}: verdict={verdict} via {channel} ({attempts} attempt(s)){link}"
    );
    let payload = json!({
        "event": "heal_completed",
        "tenant_id": tenant_id,
        "finding_id": finding_id,
        "verdict": verdict,
        "channel": channel,
        "attempts": attempts,
        "pr_url": pr_url,
        "ok": ok,
        "text": text,
    });

    let mut delivered = false;
    if let Some(url) = config.alert_webhook_url.as_deref() {
        delivered |= post_json(&client, url, &payload).await;
    }
    if let Some(url) = config.slack_webhook_url.as_deref() {
        delivered |= post_json(&client, url, &payload).await;
    }
    if (!ok || verdict == "broke_app") {
        if let Some(key) = resolve_pagerduty_key(&config) {
            let pd = json!({
                "routing_key": key,
                "event_action": "trigger",
                "payload": {
                    "summary": format!("Auto-heal {verdict} on finding {finding_id}"),
                    "severity": if ok { "warning" } else { "error" },
                    "source": "weissman-auto-heal",
                    "custom_details": payload,
                }
            });
            delivered |= post_json(&client, "https://events.pagerduty.com/v2/enqueue", &pd).await;
        }
    }

    if !delivered {
        tracing::debug!(
            target: "alert_delivery",
            tenant_id,
            "heal completion alert not delivered (no channels configured)"
        );
    }
}

/// Fire tenant alert channels when closed-loop verification finds a previously-fixed vulnerability
/// has REGRESSED (reopened). Best-effort; pages on-call so the regression is re-remediated.
pub async fn notify_regression(
    pool: &PgPool,
    tenant_id: i64,
    finding_id: &str,
    engine: &str,
    target: &str,
) {
    let config = load_delivery_config(pool, tenant_id).await;
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| Client::new());
    let text = format!(
        "[Weissman][Auto-Heal] ♻️ REGRESSION: finding {finding_id} reopened on {target} (engine {engine}) — re-remediation needed"
    );
    let payload = json!({
        "event": "remediation_regression",
        "tenant_id": tenant_id,
        "finding_id": finding_id,
        "engine": engine,
        "target": target,
        "text": text,
    });
    let mut delivered = false;
    if let Some(url) = config.alert_webhook_url.as_deref() {
        delivered |= post_json(&client, url, &payload).await;
    }
    if let Some(url) = config.slack_webhook_url.as_deref() {
        delivered |= post_json(&client, url, &payload).await;
    }
    if let Some(key) = resolve_pagerduty_key(&config) {
        let pd = json!({
            "routing_key": key,
            "event_action": "trigger",
            "payload": {
                "summary": format!("Remediation regression: {finding_id} reopened"),
                "severity": "warning",
                "source": "weissman-auto-heal",
                "custom_details": payload,
            }
        });
        delivered |= post_json(&client, "https://events.pagerduty.com/v2/enqueue", &pd).await;
    }
    if !delivered {
        tracing::debug!(target: "alert_delivery", tenant_id, "regression alert not delivered (no channels configured)");
    }
}
