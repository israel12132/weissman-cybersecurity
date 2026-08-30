//! Persist MessagePack decode failures as quarantine blobs + SOC events.
//!
//! Decode errors must never vanish into a warn log. The raw body is hex-encoded
//! and stored in `cem_dago_telemetry_quarantine` when a usable tenant GUC can
//! be set. If `tenant_id` is missing/invalid, or the RLS insert fails (OR-01 /
//! WITH CHECK), the blob is spilled to the system-global buffer
//! (`cem_dago_telemetry_quarantine_global` + Redis `weissman:quarantine:global`
//! + structured admin logs). The mesh never aborts on persist failure.

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::time::Duration;

use super::redis_pool::acquire_redis_connection_with_timeout;

const RAW_HEX_CAP: usize = 16_384;
const GLOBAL_REDIS_KEY: &str = "weissman:quarantine:global";
const GLOBAL_REDIS_OP: Duration = Duration::from_millis(50);

/// Tenant ids that can drive `app.current_tenant_id` + RLS WITH CHECK.
#[must_use]
pub fn tenant_scope_usable(tenant_id: i64) -> bool {
    tenant_id > 0
}

pub const FALLBACK_INVALID_TENANT: &str = "invalid_tenant";
pub const FALLBACK_RLS_PERSIST_FAILED: &str = "rls_persist_failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantinePersistTarget {
    Tenant,
    GlobalInvalidTenant,
}

#[must_use]
pub fn quarantine_persist_target(tenant_id: i64) -> QuarantinePersistTarget {
    if tenant_scope_usable(tenant_id) {
        QuarantinePersistTarget::Tenant
    } else {
        QuarantinePersistTarget::GlobalInvalidTenant
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineBlob {
    pub kind: String,
    pub field_key: String,
    pub codec_byte: Option<i32>,
    pub raw_hex: String,
    pub decode_error: String,
}

#[must_use]
pub fn encode_raw_hex(raw: &[u8]) -> String {
    let slice = if raw.len() > RAW_HEX_CAP {
        &raw[..RAW_HEX_CAP]
    } else {
        raw
    };
    let mut out = String::with_capacity(slice.len() * 2 + 16);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in slice {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    if raw.len() > RAW_HEX_CAP {
        out.push_str("...truncated");
    }
    out
}

#[must_use]
pub fn blob_from_raw(kind: &str, field_key: &str, raw: &[u8], error: &str) -> QuarantineBlob {
    QuarantineBlob {
        kind: kind.to_string(),
        field_key: field_key.to_string(),
        codec_byte: raw.first().map(|&b| i32::from(b)),
        raw_hex: encode_raw_hex(raw),
        decode_error: error.chars().take(512).collect(),
    }
}

fn log_admin_hex(tenant_id: i64, client_id: i64, scan_id: &str, b: &QuarantineBlob, reason: &str) {
    tracing::error!(
        target: "cem_dago",
        tenant_id,
        client_id,
        scan_id,
        kind = %b.kind,
        field_key = %b.field_key,
        codec_byte = ?b.codec_byte,
        raw_hex = %b.raw_hex,
        decode_error = %b.decode_error,
        fallback_reason = reason,
        "TELEMETRY INTEGRITY VIOLATION — admin quarantine buffer retained raw hex"
    );
}

/// Insert quarantine rows. Tenant-scoped when `tenant_id > 0`; otherwise, or on
/// RLS/tx failure, spill to the system-global buffer. Never panics the caller.
pub async fn persist_quarantine(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    scan_id: &str,
    blobs: &[QuarantineBlob],
) -> usize {
    if blobs.is_empty() {
        return 0;
    }
    for b in blobs {
        log_admin_hex(tenant_id, client_id, scan_id, b, "received");
    }
    if quarantine_persist_target(tenant_id) == QuarantinePersistTarget::Tenant {
        if let Ok(wrote) = persist_tenant_scoped(pool, tenant_id, client_id, scan_id, blobs).await {
            if wrote == blobs.len() {
                return wrote;
            }
        }
        return persist_global_buffer(
            pool,
            tenant_id,
            client_id,
            scan_id,
            blobs,
            FALLBACK_RLS_PERSIST_FAILED,
        )
        .await;
    }
    persist_global_buffer(
        pool,
        tenant_id,
        client_id,
        scan_id,
        blobs,
        FALLBACK_INVALID_TENANT,
    )
    .await
}

async fn persist_tenant_scoped(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    scan_id: &str,
    blobs: &[QuarantineBlob],
) -> Result<usize, ()> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| {
            tracing::error!(
                target: "cem_dago",
                tenant_id,
                error = %e,
                "telemetry quarantine persist: tenant tx failed — spilling to global buffer"
            );
        })?;
    let mut wrote = 0usize;
    for b in blobs {
        let ins = sqlx::query(
            r#"INSERT INTO cem_dago_telemetry_quarantine
                  (tenant_id, client_id, scan_id, kind, field_key, codec_byte, raw_hex, decode_error)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(scan_id)
        .bind(&b.kind)
        .bind(&b.field_key)
        .bind(b.codec_byte)
        .bind(&b.raw_hex)
        .bind(&b.decode_error)
        .execute(&mut *tx)
        .await;
        if ins.is_err() {
            let _ = tx.rollback().await;
            return Err(());
        }
        wrote += 1;
        let meta = serde_json::json!({
            "scan_id": scan_id,
            "kind": b.kind,
            "field_key": b.field_key,
            "codec_byte": b.codec_byte,
            "raw_hex_prefix": b.raw_hex.chars().take(32).collect::<String>(),
        });
        let _ = sqlx::query(
            r#"INSERT INTO elite_hardening_events (tenant_id, client_id, kind, detail, metadata)
               VALUES ($1, $2, 'telemetry_integrity_violation', $3, $4)"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(format!(
            "CEM-DAGO telemetry integrity violation on {}/{}: {}",
            b.kind, b.field_key, b.decode_error
        ))
        .bind(meta)
        .execute(&mut *tx)
        .await;
    }
    if tx.commit().await.is_err() {
        return Err(());
    }
    if wrote > 0 {
        tracing::error!(
            target: "cem_dago",
            tenant_id,
            client_id,
            scan_id,
            count = wrote,
            "TELEMETRY INTEGRITY VIOLATION — RLS quarantine blobs persisted for SOC"
        );
        metrics::counter!("weissman_cem_dago_telemetry_integrity_persisted_total")
            .increment(wrote as u64);
    }
    Ok(wrote)
}

async fn persist_global_buffer(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    scan_id: &str,
    blobs: &[QuarantineBlob],
    reason: &str,
) -> usize {
    let claimed = if tenant_scope_usable(tenant_id) {
        Some(tenant_id)
    } else {
        None
    };
    let mut wrote = 0usize;
    match pool.begin().await {
        Ok(mut tx) => {
            for b in blobs {
                let ins = sqlx::query(
                    r#"INSERT INTO cem_dago_telemetry_quarantine_global
                          (claimed_tenant_id, client_id, scan_id, kind, field_key,
                           codec_byte, raw_hex, decode_error, fallback_reason)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
                )
                .bind(claimed)
                .bind(client_id)
                .bind(scan_id)
                .bind(&b.kind)
                .bind(&b.field_key)
                .bind(b.codec_byte)
                .bind(&b.raw_hex)
                .bind(&b.decode_error)
                .bind(reason)
                .execute(&mut *tx)
                .await;
                if ins.is_ok() {
                    wrote += 1;
                }
            }
            if tx.commit().await.is_err() {
                wrote = 0;
            }
        }
        Err(e) => {
            tracing::error!(
                target: "cem_dago",
                error = %e,
                "global quarantine postgres begin failed — Redis + admin logs still retain blobs"
            );
        }
    }
    spill_global_redis(blobs).await;
    if wrote > 0 {
        tracing::error!(
            target: "cem_dago",
            claimed_tenant_id = ?claimed,
            client_id,
            scan_id,
            count = wrote,
            fallback_reason = reason,
            "TELEMETRY INTEGRITY VIOLATION — system-global quarantine buffer persisted"
        );
        metrics::counter!("weissman_cem_dago_telemetry_integrity_global_total")
            .increment(wrote as u64);
    }
    wrote
}

async fn spill_global_redis(blobs: &[QuarantineBlob]) {
    let Ok(mut conn) = acquire_redis_connection_with_timeout(GLOBAL_REDIS_KEY).await else {
        return;
    };
    let _ = tokio::time::timeout(GLOBAL_REDIS_OP, async {
        for b in blobs {
            let payload = serde_json::to_vec(b).unwrap_or_default();
            let _: () = conn.rpush(GLOBAL_REDIS_KEY, payload.as_slice()).await?;
        }
        let _: () = conn
            .expire(GLOBAL_REDIS_KEY, super::BLACKBOARD_TTL_SECS)
            .await?;
        Ok::<(), redis::RedisError>(())
    })
    .await;
}

/// RLS-scoped read of quarantine blobs for a scan (Command Center).
pub async fn load_quarantine_for_scan(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    scan_id: &str,
) -> Vec<QuarantineBlob> {
    if !tenant_scope_usable(tenant_id) {
        return Vec::new();
    }
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Vec::new();
    };
    let rows = sqlx::query(
        r#"SELECT kind, field_key, codec_byte, raw_hex, decode_error
             FROM cem_dago_telemetry_quarantine
            WHERE tenant_id = $1 AND client_id = $2 AND scan_id = $3
            ORDER BY id DESC
            LIMIT 100"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(scan_id)
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.rollback().await;
    let Ok(rows) = rows else {
        return Vec::new();
    };
    rows.iter()
        .map(|r| QuarantineBlob {
            kind: r.try_get::<String, _>("kind").unwrap_or_default(),
            field_key: r.try_get::<String, _>("field_key").unwrap_or_default(),
            codec_byte: r.try_get::<Option<i32>, _>("codec_byte").ok().flatten(),
            raw_hex: r.try_get::<String, _>("raw_hex").unwrap_or_default(),
            decode_error: r.try_get::<String, _>("decode_error").unwrap_or_default(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_prefix() {
        let h = encode_raw_hex(&[0xc1, 0x01, 0x83]);
        assert_eq!(h, "c10183");
        let blob = blob_from_raw("evidence", "web_port_active", &[0xff, 0x00], "boom");
        assert_eq!(blob.codec_byte, Some(255));
        assert_eq!(blob.raw_hex, "ff00");
        assert_eq!(blob.kind, "evidence");
    }

    #[test]
    fn corrupt_payload_without_tenant_routes_to_global_buffer() {
        assert_eq!(
            quarantine_persist_target(0),
            QuarantinePersistTarget::GlobalInvalidTenant
        );
        assert_eq!(
            quarantine_persist_target(-1),
            QuarantinePersistTarget::GlobalInvalidTenant
        );
        assert!(!tenant_scope_usable(0));
        assert_eq!(
            quarantine_persist_target(7),
            QuarantinePersistTarget::Tenant
        );
        assert!(tenant_scope_usable(7));
    }
}
