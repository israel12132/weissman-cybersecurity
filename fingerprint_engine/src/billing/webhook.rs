//! Paddle Billing webhook signature verification (HMAC-SHA256) and event application to Postgres.
//!
//! Signature format: `Paddle-Signature: ts=<unix>;h1=<hex>` — signed payload is `ts` + `:` + raw body bytes.
//! See: https://developer.paddle.com/webhooks/signature-verification

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::{
    apply_paddle_subscription_to_tenant, paddle_api_base, paddle_http_get_json,
    update_subscription_status_by_paddle_id, upsert_paddle_customer,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum PaddleWebhookError {
    #[error("webhook secret not configured")]
    SecretMissing,
    #[error("invalid webhook secret")]
    SecretInvalid,
    #[error("signature: {0}")]
    Signature(String),
    #[error("payload json: {0}")]
    Json(String),
    #[error("event missing id")]
    MissingEventId,
    #[error("handler: {0}")]
    Apply(String),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}

fn webhook_hmac_key(secret: &str) -> &[u8] {
    secret.trim().as_bytes()
}

/// Verifies `Paddle-Signature` and returns the parsed JSON notification body.
pub fn verify_paddle_payload(signature_header: &str, body: &[u8]) -> Result<Value, PaddleWebhookError> {
    let secret = std::env::var("PADDLE_WEBHOOK_SECRET").map_err(|_| PaddleWebhookError::SecretMissing)?;
    let key = webhook_hmac_key(secret.trim());
    if key.is_empty() {
        return Err(PaddleWebhookError::SecretInvalid);
    }

    let mut ts_val: Option<String> = None;
    let mut signatures_hex: Vec<String> = Vec::new();
    for part in signature_header.split(';') {
        let part = part.trim();
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        match k.trim() {
            "ts" => ts_val = Some(v.trim().to_string()),
            "h1" => signatures_hex.push(v.trim().to_string()),
            _ => {}
        }
    }
    let ts = ts_val
        .ok_or_else(|| PaddleWebhookError::Signature("Missing ts in Paddle-Signature".into()))?;
    if signatures_hex.is_empty() {
        return Err(PaddleWebhookError::Signature(
            "Missing h1 in Paddle-Signature".into(),
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| PaddleWebhookError::Signature(e.to_string()))?
        .as_secs() as i64;
    let tsi: i64 = ts
        .parse()
        .map_err(|_| PaddleWebhookError::Signature("Invalid timestamp in Paddle-Signature".into()))?;
    if (now - tsi).abs() > 600 {
        return Err(PaddleWebhookError::Signature(
            "Paddle webhook timestamp outside tolerance".into(),
        ));
    }

    let mut signed = Vec::with_capacity(ts.len() + 1 + body.len());
    signed.extend_from_slice(ts.as_bytes());
    signed.push(b':');
    signed.extend_from_slice(body);

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| PaddleWebhookError::SecretInvalid)?;
    mac.update(&signed);
    let expected = mac.finalize().into_bytes();

    let mut ok = false;
    for sig_hex in &signatures_hex {
        if let Ok(sb) = hex::decode(sig_hex.trim()) {
            if sb.len() == expected.len() && sb.ct_eq(&expected).into() {
                ok = true;
                break;
            }
        }
    }
    if !ok {
        return Err(PaddleWebhookError::Signature(
            "Paddle signature mismatch".into(),
        ));
    }

    serde_json::from_slice(body).map_err(|e| PaddleWebhookError::Json(e.to_string()))
}

fn event_id_from_payload(event: &Value) -> Option<String> {
    event
        .get("event_id")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            event
                .get("notification_id")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
}

fn tenant_id_from_custom(obj: &Value) -> Option<i64> {
    let cd = obj.get("custom_data")?;
    let v = cd.get("tenant_id")?;
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    if let Some(n) = v.as_u64() {
        return i64::try_from(n).ok();
    }
    v.as_str()?.trim().parse().ok()
}

async fn tenant_id_by_paddle_customer(pool: &PgPool, customer_id: &str) -> Option<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT tenant_id FROM tenant_paddle_customers WHERE paddle_customer_id = $1",
    )
    .bind(customer_id)
    .fetch_optional(pool)
    .await
    .ok()?
}

async fn resolve_tenant_for_subscription(pool: &PgPool, sub: &Value) -> Option<i64> {
    if let Some(t) = tenant_id_from_custom(sub) {
        return Some(t);
    }
    let cust = sub.get("customer_id").and_then(|x| x.as_str())?;
    tenant_id_by_paddle_customer(pool, cust).await
}

pub async fn handle_paddle_webhook(
    pool: &PgPool,
    signature_header: &str,
    body: &[u8],
) -> Result<(), PaddleWebhookError> {
    let event = verify_paddle_payload(signature_header, body)?;
    let event_id = event_id_from_payload(&event).ok_or(PaddleWebhookError::MissingEventId)?;
    let event_type = event
        .get("event_type")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    let new_row: Option<String> = sqlx::query_scalar(
        r#"INSERT INTO paddle_webhook_events (id, event_type, processed_ok, error_detail)
           VALUES ($1, $2, false, NULL)
           ON CONFLICT (id) DO NOTHING
           RETURNING id"#,
    )
    .bind(&event_id)
    .bind(&event_type)
    .fetch_optional(pool)
    .await?;

    if new_row.is_none() {
        let done: bool = sqlx::query_scalar(
            "SELECT COALESCE(processed_ok, false) FROM paddle_webhook_events WHERE id = $1",
        )
        .bind(&event_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or(true);
        if done {
            tracing::info!(
                target: "paddle_webhook",
                event_id = %event_id,
                "duplicate paddle event ignored (idempotent)"
            );
            return Ok(());
        }
    }

    match apply_event(pool, &event_type, &event).await {
        Ok(()) => {
            sqlx::query(
                "UPDATE paddle_webhook_events SET processed_ok = true, error_detail = NULL WHERE id = $1",
            )
            .bind(&event_id)
            .execute(pool)
            .await?;
            Ok(())
        }
        Err(e) => {
            let _ = sqlx::query(
                "UPDATE paddle_webhook_events SET processed_ok = false, error_detail = $2 WHERE id = $1",
            )
            .bind(&event_id)
            .bind(&e)
            .execute(pool)
            .await;
            Err(PaddleWebhookError::Apply(e))
        }
    }
}

async fn apply_event(pool: &PgPool, event_type: &str, event: &Value) -> Result<(), String> {
    let data = event
        .get("data")
        .cloned()
        .ok_or_else(|| "Event missing data".to_string())?;

    let et = event_type.trim().to_lowercase();
    match et.as_str() {
        "subscription.created"
        | "subscription.updated"
        | "subscription.activated"
        | "subscription.trialing"
        | "subscription.paused"
        | "subscription.past_due"
        | "subscription.resumed" => handle_subscription_upsert(pool, &data).await,
        "subscription.canceled" => {
            let sub_id = data
                .get("id")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "subscription id missing".to_string())?;
            update_subscription_status_by_paddle_id(pool, sub_id, "canceled")
                .await
                .map_err(|e| e.to_string())
        }
        "transaction.completed" | "transaction.paid" => handle_transaction_payment(pool, &data).await,
        _ => Ok(()),
    }
}

async fn handle_transaction_payment(pool: &PgPool, txn: &Value) -> Result<(), String> {
    if let Some(tenant_id) = tenant_id_from_custom(txn) {
        if let Some(cust) = txn.get("customer_id").and_then(|x| x.as_str()) {
            upsert_paddle_customer(pool, tenant_id, cust)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    let sub_id = txn
        .get("subscription_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty());
    let Some(sid) = sub_id else {
        return Ok(());
    };
    let sub_json = fetch_paddle_subscription(sid).await?;
    handle_subscription_upsert(pool, &sub_json).await
}

async fn fetch_paddle_subscription(sub_id: &str) -> Result<Value, String> {
    let base = paddle_api_base()?;
    let path = format!("/subscriptions/{}", urlencoding::encode(sub_id));
    paddle_http_get_json(&path, &base).await
}

async fn handle_subscription_upsert(pool: &PgPool, sub: &Value) -> Result<(), String> {
    let sub_id = sub
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "subscription id missing".to_string())?;

    if let Some(tid) = resolve_tenant_for_subscription(pool, sub).await {
        return handle_subscription_upsert_inner(pool, tid, sub).await;
    }

    let sub_json = fetch_paddle_subscription(sub_id).await?;
    let Some(tid) = resolve_tenant_for_subscription(pool, &sub_json).await else {
        return Err(
            "Cannot resolve tenant: set custom_data.tenant_id on checkout or link paddle customer"
                .to_string(),
        );
    };
    handle_subscription_upsert_inner(pool, tid, &sub_json).await
}

async fn handle_subscription_upsert_inner(
    pool: &PgPool,
    tenant_id: i64,
    sub: &Value,
) -> Result<(), String> {
    apply_paddle_subscription_to_tenant(pool, tenant_id, sub).await
}
