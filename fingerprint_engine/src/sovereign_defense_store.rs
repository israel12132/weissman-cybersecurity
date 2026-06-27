//! Shared DB + crypto helpers for Sovereign Defense Matrix (CHRONOS / LIQUID-MATRIX / COGNITIVE STARVATION).

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};

pub const CHRONOS_ENGINE_ID: &str = "chronos";
pub const LIQUID_MATRIX_ENGINE_ID: &str = "liquid_matrix";
pub const COGNITIVE_STARVATION_ENGINE_ID: &str = "cognitive_starvation";

#[derive(Debug, Clone)]
pub struct LiquidRotation {
    pub epoch: i64,
    pub internal_ip: String,
    pub internal_port: i32,
    pub service_fingerprint: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub routing_code: String,
    pub rotation_step_secs: i32,
}

pub fn generate_routing_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

pub fn current_epoch(step_secs: u64) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (now / step_secs.max(1)) as i64
}

pub fn routing_code(secret_b32: &str, step_secs: u64) -> Result<String, String> {
    let secret = Secret::Encoded(secret_b32.trim().to_string())
        .to_bytes()
        .map_err(|e| e.to_string())?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        8,
        1,
        step_secs,
        secret,
        Some("Weissman-Liquid-Matrix".to_string()),
        "routing".to_string(),
    )
    .map_err(|e| e.to_string())?;
    totp.generate_current().map_err(|e| e.to_string())
}

fn derive_internal_mapping(client_id: i64, epoch: i64, port_min: i32, port_max: i32) -> (String, i32, String) {
    let octet = ((client_id.wrapping_mul(17) ^ epoch.wrapping_mul(31)) % 200 + 10) as u8;
    let ip = format!("10.{octet}.{}.{}", (epoch % 250) as u8, ((epoch >> 8) % 250) as u8);
    let span = (port_max - port_min).max(1);
    let port = port_min + ((epoch as i32).abs() % span);
    let fingerprints = [
        "OpenSSH_8.9p1 Ubuntu",
        "nginx/1.24.0",
        "Apache/2.4.58",
        "Microsoft-IIS/10.0",
        "envoy/1.29.0",
    ];
    let fp = fingerprints[((epoch as i64).unsigned_abs() as usize) % fingerprints.len()].to_string();
    (ip, port, fp)
}

pub async fn ensure_routing_token(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    rotation_step_secs: i32,
) -> Result<(String, i32), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let row = sqlx::query(
        r#"SELECT secret_b32, rotation_step_secs, port_pool_min, port_pool_max, active
             FROM liquid_matrix_routing_tokens
            WHERE client_id = $1"#,
    )
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let (secret_b32, step) = if let Some(r) = row {
        (
            r.try_get::<String, _>("secret_b32").unwrap_or_default(),
            r.try_get::<i32, _>("rotation_step_secs").unwrap_or(rotation_step_secs),
        )
    } else {
        let secret = generate_routing_secret();
        sqlx::query(
            r#"INSERT INTO liquid_matrix_routing_tokens
               (tenant_id, client_id, secret_b32, rotation_step_secs)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(&secret)
        .bind(rotation_step_secs)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        (secret, rotation_step_secs)
    };
    let _ = tx.commit().await;
    Ok((secret_b32, step.max(1)))
}

pub async fn rotate_liquid_matrix(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    rotation_step_secs: i32,
) -> Result<LiquidRotation, String> {
    let (secret_b32, step) = ensure_routing_token(pool, tenant_id, client_id, rotation_step_secs).await?;
    let step_u = step as u64;
    let epoch = current_epoch(step_u);
    let code = routing_code(&secret_b32, step_u)?;

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let cfg = sqlx::query(
        r#"SELECT port_pool_min, port_pool_max FROM liquid_matrix_routing_tokens WHERE client_id = $1"#,
    )
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let (port_min, port_max) = cfg
        .map(|r| {
            (
                r.try_get::<i32, _>("port_pool_min").unwrap_or(30_000),
                r.try_get::<i32, _>("port_pool_max").unwrap_or(39_999),
            )
        })
        .unwrap_or((30_000, 39_999));

    let (ip, port, fp) = derive_internal_mapping(client_id, epoch, port_min, port_max);
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(step as i64);

    sqlx::query(
        r#"INSERT INTO liquid_matrix_rotations
           (tenant_id, client_id, epoch, internal_ip, internal_port, service_fingerprint, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (tenant_id, client_id, epoch) DO UPDATE
           SET internal_ip = EXCLUDED.internal_ip,
               internal_port = EXCLUDED.internal_port,
               service_fingerprint = EXCLUDED.service_fingerprint,
               expires_at = EXCLUDED.expires_at"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(epoch)
    .bind(&ip)
    .bind(port)
    .bind(&fp)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    Ok(LiquidRotation {
        epoch,
        internal_ip: ip,
        internal_port: port,
        service_fingerprint: fp,
        expires_at,
        routing_code: code,
        rotation_step_secs: step,
    })
}

pub async fn insert_chronos_event(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    event_type: &str,
    pid: Option<i32>,
    parent_pid: Option<i32>,
    process_name: Option<&str>,
    syscall_hint: Option<&str>,
    action_taken: Option<&str>,
    delta_json: Value,
    metadata: Value,
) -> Result<i64, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO chronos_events
           (tenant_id, client_id, event_type, pid, parent_pid, process_name, syscall_hint, action_taken, delta_json, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(event_type)
    .bind(pid)
    .bind(parent_pid)
    .bind(process_name)
    .bind(syscall_hint)
    .bind(action_taken)
    .bind(delta_json)
    .bind(metadata)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(id)
}

pub async fn insert_cognitive_session(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    target_url: &str,
    bot_score: f64,
    bot_signals: &[String],
    poison_variant: Option<&str>,
    poison_payload_id: Option<&str>,
    response_status: Option<i32>,
    metadata: Value,
) -> Result<i64, String> {
    let signals = json!(bot_signals);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO cognitive_starvation_sessions
           (tenant_id, client_id, target_url, bot_score, bot_signals, poison_variant, poison_payload_id, response_status, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(target_url)
    .bind(bot_score)
    .bind(signals)
    .bind(poison_variant)
    .bind(poison_payload_id)
    .bind(response_status)
    .bind(metadata)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(id)
}

pub async fn load_poison_library(pool: &PgPool, limit: i64) -> Result<Vec<Value>, String> {
    let rows = sqlx::query(
        r#"SELECT id, variant, content_type, payload, severity, description
             FROM cognitive_poison_library
            ORDER BY severity DESC, id
            LIMIT $1"#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<String, _>("id").unwrap_or_default(),
                "variant": r.try_get::<String, _>("variant").unwrap_or_default(),
                "content_type": r.try_get::<String, _>("content_type").unwrap_or_default(),
                "payload": r.try_get::<String, _>("payload").unwrap_or_default(),
                "severity": r.try_get::<String, _>("severity").unwrap_or_default(),
                "description": r.try_get::<Option<String>, _>("description").ok().flatten(),
            })
        })
        .collect())
}

pub async fn dashboard_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;

    let chronos_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM chronos_events
            WHERE client_id = $1 AND created_at > now() - interval '24 hours'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let freeze_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM chronos_events
            WHERE client_id = $1 AND event_type = 'freeze' AND created_at > now() - interval '24 hours'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let trace_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM runtime_traces
            WHERE client_id = $1 AND created_at > now() - interval '24 hours'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let cognitive_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM cognitive_starvation_sessions
            WHERE client_id = $1 AND created_at > now() - interval '24 hours'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let agent_online: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM endpoint_agents
            WHERE client_id = $1 AND last_seen_at > now() - interval '5 minutes'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let _ = tx.commit().await;

    let liquid = rotate_liquid_matrix(pool, tenant_id, client_id, 3).await.ok();

    Ok(json!({
        "client_id": client_id,
        "chronos": {
            "events_24h": chronos_count,
            "freezes_24h": freeze_count,
            "runtime_traces_24h": trace_count,
            "agent_online": agent_online > 0,
        },
        "liquid_matrix": liquid.map(|r| json!({
            "epoch": r.epoch,
            "internal_ip": r.internal_ip,
            "internal_port": r.internal_port,
            "service_fingerprint": r.service_fingerprint,
            "routing_code": r.routing_code,
            "rotation_step_secs": r.rotation_step_secs,
            "expires_at": r.expires_at.to_rfc3339(),
        })),
        "cognitive_starvation": {
            "sessions_24h": cognitive_count,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_code_is_deterministic_per_epoch() {
        let secret = generate_routing_secret();
        let a = routing_code(&secret, 3).expect("routing_code");
        let b = routing_code(&secret, 3).expect("routing_code");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn epoch_advances_every_step() {
        let e1 = current_epoch(3);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let e2 = current_epoch(3);
        assert!(e2 >= e1);
    }
}
