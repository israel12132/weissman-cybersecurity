//! Persist MessagePack decode failures as RLS-scoped quarantine blobs + SOC events.
//!
//! Decode errors must never vanish into a warn log. The raw body is hex-encoded
//! and stored in `cem_dago_telemetry_quarantine`; a matching
//! `elite_hardening_events` row (`telemetry_integrity_violation`) is the
//! operator-visible critical alert.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

const RAW_HEX_CAP: usize = 16_384;

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

/// Insert quarantine rows + integrity-violation events. Fail-open on DB errors
/// (scan continues); callers still keep the in-memory / Redis copy.
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
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        tracing::error!(
            target: "cem_dago",
            tenant_id,
            "telemetry quarantine persist: tenant tx failed"
        );
        return 0;
    };
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
            continue;
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
        return 0;
    }
    if wrote > 0 {
        tracing::error!(
            target: "cem_dago",
            tenant_id,
            client_id,
            scan_id,
            count = wrote,
            "TELEMETRY INTEGRITY VIOLATION — quarantine blobs persisted for SOC"
        );
        metrics::counter!("weissman_cem_dago_telemetry_integrity_persisted_total")
            .increment(wrote as u64);
    }
    wrote
}

/// RLS-scoped read of quarantine blobs for a scan (Command Center).
pub async fn load_quarantine_for_scan(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    scan_id: &str,
) -> Vec<QuarantineBlob> {
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
}
