//! EventBridge / custom forwarder webhook: HMAC + canary access-key correlation (`lookup_deception_by_canary`).

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::PgPool;
use sqlx::Row;
use tokio::sync::broadcast::Sender;

use crate::db;

type HmacSha256 = Hmac<Sha256>;

fn hex_lower(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

pub fn verify_webhook_hmac(secret: &str, body: &[u8], sig_header: Option<&str>) -> bool {
    let Some(sig_raw) = sig_header else {
        return false;
    };
    let sig = sig_raw.trim();
    let sig = sig.strip_prefix("sha256=").unwrap_or(sig);
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    let expected = hex_lower(&mac.finalize().into_bytes());
    expected.eq_ignore_ascii_case(sig)
}

pub fn collect_access_key_ids(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                let kl = k.to_lowercase();
                if kl.contains("accesskeyid") {
                    if let Some(s) = val.as_str() {
                        if s.starts_with("AKIA") && s.len() >= 16 {
                            out.push(s.to_string());
                        }
                    }
                }
                collect_access_key_ids(val, out);
            }
        }
        Value::Array(a) => {
            for x in a {
                collect_access_key_ids(x, out);
            }
        }
        _ => {}
    }
}

/// Shared handler for `POST /api/deception/aws-events` and `POST /api/v1/alerts/aws-canary`.
pub async fn handle_aws_canary_eventbridge(
    app_pool: &PgPool,
    telemetry_broadcast_tx: &Sender<String>,
    headers: &HeaderMap,
    body: &[u8],
    source_tag: &'static str,
) -> Response {
    let secret = std::env::var("WEISSMAN_DECEPTION_WEBHOOK_SECRET").unwrap_or_default();
    if secret.trim().is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "WEISSMAN_DECEPTION_WEBHOOK_SECRET not set"})),
        )
            .into_response();
    }
    let sig = headers
        .get("x-weissman-signature")
        .and_then(|h| h.to_str().ok());
    if !verify_webhook_hmac(&secret, body, sig) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false}))).into_response();
    }
    let payload: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "detail": "invalid json"})),
            )
                .into_response();
        }
    };
    let mut keys = Vec::new();
    collect_access_key_ids(&payload, &mut keys);
    keys.sort();
    keys.dedup();
    let n_keys = keys.len();
    let mut triggered = 0u32;
    for ak in keys {
        let rows = sqlx::query("SELECT id, tenant_id, client_id FROM lookup_deception_by_canary($1)")
            .bind(&ak)
            .fetch_all(app_pool)
            .await
            .unwrap_or_default();
        for r in rows {
            let aid: i64 = r.try_get("id").unwrap_or(0);
            let tid: i64 = r.try_get("tenant_id").unwrap_or(0);
            let cid: i64 = r.try_get("client_id").unwrap_or(0);
            if aid == 0 || tid == 0 {
                continue;
            }
            let Ok(mut tx) = db::begin_tenant_tx(app_pool, tid).await else {
                continue;
            };
            let meta = serde_json::to_string(&json!({
                "source": source_tag,
                "access_key_id": ak,
                "payload_excerpt": serde_json::to_string(&payload).unwrap_or_default().chars().take(4000).collect::<String>()
            }))
            .unwrap_or_else(|_| "{}".to_string());
            let _ = sqlx::query(
                r#"INSERT INTO deception_triggers (tenant_id, asset_id, client_id, fingerprint, request_meta)
                   VALUES ($1, $2, $3, $4, $5)"#,
            )
            .bind(tid)
            .bind(aid)
            .bind(cid)
            .bind("cloudtrail_guardduty_correlation")
            .bind(&meta)
            .execute(&mut *tx)
            .await;
            let _ = sqlx::query("UPDATE deception_assets SET status = 'triggered' WHERE id = $1")
                .bind(aid)
                .execute(&mut *tx)
                .await;
            let _ = tx.commit().await;
            triggered += 1;
            let _ = telemetry_broadcast_tx.send(
                serde_json::json!({
                    "event": "deception_triggered",
                    "severity": "critical",
                    "client_id": cid.to_string(),
                    "asset_id": aid,
                    "message": format!("Canary AWS key {} observed via {} (EventBridge forwarder)", ak, source_tag)
                })
                .to_string(),
            );
        }
    }
    if triggered > 0 {
        let ip = crate::deception_cf_blackhole::sniff_ipv4_from_json(&payload, 0)
            .map(std::net::IpAddr::V4);
        let pay = payload.clone();
        tokio::spawn(async move {
            crate::deception_cf_blackhole::maybe_blackhole_from_canary_payload(&pay, ip).await;
        });
    }
    (
        StatusCode::OK,
        Json(json!({"ok": true, "matched_keys": n_keys, "triggers_recorded": triggered })),
    )
        .into_response()
}
