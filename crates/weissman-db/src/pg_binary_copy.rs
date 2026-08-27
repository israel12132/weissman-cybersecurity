//! PostgreSQL binary COPY protocol encoder + schema-drift contract.
//!
//! Builds a `COPY … FROM STDIN WITH (FORMAT binary)` payload by hand so high-volume
//! ingest can stream tuples over the socket without per-row INSERT parse/plan/lock
//! overhead. Layout matches the on-disk COPY BINARY file format:
//!
//! 1. 11-byte signature `PGCOPY\n\xff\r\n\0`
//! 2. 4-byte flags (0 — no OIDs)
//! 3. 4-byte header-extension length (0)
//! 4. For each tuple: `int16` field count, then per field `int32` length + bytes
//!    (`length == -1` is NULL)
//! 5. Trailer `0xFFFF`
//!
//! Field bytes are the type's `typsend` payload (big-endian integers, UTF-8 text,
//! JSONB version-1 + JSON text, timestamptz microseconds since 2000-01-01 UTC).
//!
//! # Schema-drift protection
//!
//! Binary COPY is position-and-type rigid. [`AGENT_METRIC_SAMPLES_COPY_COLUMNS`] is
//! the single contract: encoder field order, generated COPY SQL, and the runtime
//! `pg_attribute` assertion all read it. A future migration that reorders, renames,
//! drops, or changes the type of a v1 column fails the assertion before any COPY
//! stream starts. Trailing columns with defaults are allowed (named COPY).

use std::sync::OnceLock;

/// Signature required at the start of every PostgreSQL binary COPY stream.
pub const PGCOPY_SIGNATURE: &[u8] = b"PGCOPY\n\xff\r\n\0";

/// Trailer that terminates a binary COPY stream (`int16` -1 / 0xFFFF).
pub const PGCOPY_TRAILER: u16 = 0xFFFF;

/// Unix microseconds of 2000-01-01 00:00:00 UTC, the PostgreSQL timestamp epoch.
pub const PG_EPOCH_UNIX_MICROS: i64 = 946_684_800_000_000;

/// Version of the `agent_metric_samples` binary COPY contract.
///
/// Bump together with [`AGENT_METRIC_SAMPLES_COPY_COLUMNS`] and the table COMMENT
/// written by migration `20260827180000_agent_metric_samples_copy_schema_v1`.
pub const AGENT_METRIC_SAMPLES_SCHEMA_VERSION: u32 = 1;

/// One column in the binary COPY stream (name + PostgreSQL `pg_type.typname`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyColumn {
    pub name: &'static str,
    pub pg_type: &'static str,
}

/// Hermetic column contract: encoder order == COPY SQL list == catalog types.
pub const AGENT_METRIC_SAMPLES_COPY_COLUMNS: &[CopyColumn] = &[
    CopyColumn {
        name: "id",
        pg_type: "int8",
    },
    CopyColumn {
        name: "tenant_id",
        pg_type: "int8",
    },
    CopyColumn {
        name: "agent_id",
        pg_type: "text",
    },
    CopyColumn {
        name: "client_id",
        pg_type: "int8",
    },
    CopyColumn {
        name: "sampled_at",
        pg_type: "timestamptz",
    },
    CopyColumn {
        name: "hour_of_week",
        pg_type: "int2",
    },
    CopyColumn {
        name: "metrics",
        pg_type: "jsonb",
    },
    CopyColumn {
        name: "raw_size_bytes",
        pg_type: "int4",
    },
];

const _: () = assert!(AGENT_METRIC_SAMPLES_COPY_COLUMNS.len() == 8);
const _: () = assert!(AGENT_METRIC_SAMPLES_SCHEMA_VERSION == 1);

/// Convert Unix-epoch microseconds to PostgreSQL `timestamptz` binary (µs since 2000-01-01 UTC).
#[must_use]
pub fn unix_micros_to_pg_timestamptz(unix_micros: i64) -> i64 {
    unix_micros.saturating_sub(PG_EPOCH_UNIX_MICROS)
}

/// Convert a PostgreSQL `timestamptz` binary value back to Unix-epoch microseconds.
#[must_use]
pub fn pg_timestamptz_to_unix_micros(pg_micros: i64) -> i64 {
    pg_micros.saturating_add(PG_EPOCH_UNIX_MICROS)
}

/// `COPY … FROM STDIN WITH (FORMAT binary)` generated from [`AGENT_METRIC_SAMPLES_COPY_COLUMNS`].
#[must_use]
pub fn agent_metric_samples_copy_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let cols: Vec<&str> = AGENT_METRIC_SAMPLES_COPY_COLUMNS
            .iter()
            .map(|c| c.name)
            .collect();
        format!(
            "COPY agent_metric_samples ({}) FROM STDIN WITH (FORMAT binary)",
            cols.join(", ")
        )
    })
    .as_str()
}

/// Named columns in encoder / COPY-SQL order.
#[must_use]
pub fn agent_metric_samples_copy_column_names() -> Vec<&'static str> {
    AGENT_METRIC_SAMPLES_COPY_COLUMNS
        .iter()
        .map(|c| c.name)
        .collect()
}

/// Growing buffer that emits a well-formed PostgreSQL binary COPY stream.
#[derive(Debug, Default)]
pub struct PgBinaryCopyBuf {
    buf: Vec<u8>,
    tuples: usize,
}

impl PgBinaryCopyBuf {
    /// Start a new stream with the required header (signature + zero flags + zero extension).
    #[must_use]
    pub fn new() -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(PGCOPY_SIGNATURE);
        buf.extend_from_slice(&0u32.to_be_bytes()); // flags
        buf.extend_from_slice(&0u32.to_be_bytes()); // header extension length
        Self { buf, tuples: 0 }
    }

    /// Begin a tuple with `nfields` columns. Must be followed by exactly that many field writes.
    pub fn start_tuple(&mut self, nfields: i16) {
        self.buf.extend_from_slice(&nfields.to_be_bytes());
        self.tuples += 1;
    }

    /// Write a SQL NULL field (`length == -1`, no payload).
    pub fn write_null(&mut self) {
        self.buf.extend_from_slice(&(-1i32).to_be_bytes());
    }

    /// Write a raw field: 4-byte length prefix plus `data`.
    pub fn write_bytes(&mut self, data: &[u8]) {
        let len = i32::try_from(data.len()).unwrap_or(i32::MAX);
        let take = len as usize;
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(&data[..take]);
    }

    /// `int2` / `SMALLINT`.
    pub fn write_i16(&mut self, value: i16) {
        self.write_bytes(&value.to_be_bytes());
    }

    /// `int4` / `INTEGER`.
    pub fn write_i32(&mut self, value: i32) {
        self.write_bytes(&value.to_be_bytes());
    }

    /// `int8` / `BIGINT`.
    pub fn write_i64(&mut self, value: i64) {
        self.write_bytes(&value.to_be_bytes());
    }

    /// `float8` / `DOUBLE PRECISION` (IEEE-754 bits, big-endian).
    pub fn write_f64(&mut self, value: f64) {
        self.write_bytes(&value.to_bits().to_be_bytes());
    }

    /// `text` / `varchar` — UTF-8 bytes, no terminator.
    pub fn write_text(&mut self, value: &str) {
        self.write_bytes(value.as_bytes());
    }

    /// `jsonb` binary: version byte `1` followed by JSON text (jsonb_recv).
    pub fn write_jsonb_utf8(&mut self, json_utf8: &[u8]) {
        let mut field = Vec::with_capacity(1 + json_utf8.len());
        field.push(1u8);
        field.extend_from_slice(json_utf8);
        self.write_bytes(&field);
    }

    /// `jsonb` from a [`serde_json::Value`]. Invalid serialisation falls back to `{}`.
    pub fn write_jsonb_value(&mut self, value: &serde_json::Value) {
        let json = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        self.write_jsonb_utf8(&json);
    }

    /// `timestamptz` from Unix-epoch microseconds.
    pub fn write_timestamptz_unix_micros(&mut self, unix_micros: i64) {
        self.write_i64(unix_micros_to_pg_timestamptz(unix_micros));
    }

    /// Number of tuples started so far (does not include the trailer).
    #[must_use]
    pub fn tuple_count(&self) -> usize {
        self.tuples
    }

    /// Current payload size in bytes (header + tuples, no trailer until [`finish`](Self::finish)).
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True when only the 19-byte header has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tuples == 0
    }

    /// Append the trailer and return the finished COPY stream.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.extend_from_slice(&PGCOPY_TRAILER.to_be_bytes());
        self.buf
    }

    /// Borrow the unfinished buffer (tests / diagnostics). Does not include the trailer.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Encode one `agent_metric_samples` row. Field count is the contract length, not a magic 8.
pub fn encode_agent_metric_sample(
    buf: &mut PgBinaryCopyBuf,
    id: i64,
    tenant_id: i64,
    agent_id: &str,
    client_id: i64,
    sampled_at_unix_micros: i64,
    hour_of_week: i16,
    metrics: &serde_json::Value,
    raw_size_bytes: i32,
) {
    let nfields = i16::try_from(AGENT_METRIC_SAMPLES_COPY_COLUMNS.len()).unwrap_or(i16::MAX);
    buf.start_tuple(nfields);
    buf.write_i64(id);
    buf.write_i64(tenant_id);
    buf.write_text(agent_id);
    buf.write_i64(client_id);
    buf.write_timestamptz_unix_micros(sampled_at_unix_micros);
    buf.write_i16(hour_of_week);
    buf.write_jsonb_value(metrics);
    buf.write_i32(raw_size_bytes);
}

static SCHEMA_OK: OnceLock<()> = OnceLock::new();

/// Verify live `pg_attribute` types match [`AGENT_METRIC_SAMPLES_COPY_COLUMNS`].
///
/// Extra physical columns are allowed (named COPY). Missing names or type
/// mismatches fail. Successful checks are cached for the process lifetime;
/// failures are not cached so a mid-boot migration can still succeed.
pub async fn assert_agent_metric_samples_schema(
    conn: &mut sqlx::PgConnection,
) -> Result<(), String> {
    if SCHEMA_OK.get().is_some() {
        return Ok(());
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT a.attname::text, t.typname::text
             FROM pg_attribute a
             JOIN pg_class c ON c.oid = a.attrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             JOIN pg_type t ON t.oid = a.atttypid
            WHERE n.nspname = 'public'
              AND c.relname = 'agent_metric_samples'
              AND a.attnum > 0
              AND NOT a.attisdropped
            ORDER BY a.attnum"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("agent_metric_samples catalog: {e}"))?;

    if rows.is_empty() {
        return Err("public.agent_metric_samples is missing from the catalog".into());
    }

    for col in AGENT_METRIC_SAMPLES_COPY_COLUMNS {
        match rows.iter().find(|(name, _)| name == col.name) {
            None => {
                return Err(format!(
                    "schema drift (v{AGENT_METRIC_SAMPLES_SCHEMA_VERSION}): column {} missing from agent_metric_samples",
                    col.name
                ));
            }
            Some((_, typ)) if typ != col.pg_type => {
                return Err(format!(
                    "schema drift (v{AGENT_METRIC_SAMPLES_SCHEMA_VERSION}): column {} has type {typ}, encoder expects {}",
                    col.name, col.pg_type
                ));
            }
            Some(_) => {}
        }
    }

    let _ = SCHEMA_OK.set(());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn header_is_the_postgres_binary_signature_plus_zero_flags() {
        let buf = PgBinaryCopyBuf::new();
        let h = buf.as_slice();
        assert_eq!(&h[..11], PGCOPY_SIGNATURE);
        assert_eq!(&h[11..15], &[0, 0, 0, 0]); // flags
        assert_eq!(&h[15..19], &[0, 0, 0, 0]); // extension
        assert_eq!(h.len(), 19);
    }

    #[test]
    fn finish_appends_ffff_trailer() {
        let bytes = PgBinaryCopyBuf::new().finish();
        assert_eq!(&bytes[bytes.len() - 2..], &[0xFF, 0xFF]);
    }

    #[test]
    fn timestamptz_epoch_roundtrip() {
        // 2000-01-01 00:00:00 UTC ↔ 0 in PG binary.
        assert_eq!(unix_micros_to_pg_timestamptz(PG_EPOCH_UNIX_MICROS), 0);
        assert_eq!(pg_timestamptz_to_unix_micros(0), PG_EPOCH_UNIX_MICROS);
        let unix = 1_700_000_000_000_000i64; // 2023-ish
        assert_eq!(
            pg_timestamptz_to_unix_micros(unix_micros_to_pg_timestamptz(unix)),
            unix
        );
    }

    #[test]
    fn int_and_text_fields_are_length_prefixed_big_endian() {
        let mut buf = PgBinaryCopyBuf::new();
        buf.start_tuple(3);
        buf.write_i16(167);
        buf.write_i64(42);
        buf.write_text("cpu");
        let body = &buf.as_slice()[19..];
        // field count
        assert_eq!(&body[0..2], &3i16.to_be_bytes());
        // int2 length 2 + value 167
        assert_eq!(&body[2..6], &2i32.to_be_bytes());
        assert_eq!(&body[6..8], &167i16.to_be_bytes());
        // int8 length 8 + 42
        assert_eq!(&body[8..12], &8i32.to_be_bytes());
        assert_eq!(&body[12..20], &42i64.to_be_bytes());
        // text "cpu" length 3
        assert_eq!(&body[20..24], &3i32.to_be_bytes());
        assert_eq!(&body[24..27], b"cpu");
    }

    #[test]
    fn jsonb_field_is_version_1_then_json_text() {
        let mut buf = PgBinaryCopyBuf::new();
        buf.start_tuple(1);
        buf.write_jsonb_value(&json!({"open_port_count": 3}));
        let body = &buf.as_slice()[19..];
        let len = i32::from_be_bytes(body[2..6].try_into().unwrap()) as usize;
        let field = &body[6..6 + len];
        assert_eq!(field[0], 1u8, "jsonb version byte");
        assert_eq!(&field[1..], br#"{"open_port_count":3}"#);
    }

    #[test]
    fn float64_uses_ieee754_be_bits() {
        let mut buf = PgBinaryCopyBuf::new();
        buf.start_tuple(1);
        buf.write_f64(1.5);
        let body = &buf.as_slice()[19..];
        assert_eq!(&body[2..6], &8i32.to_be_bytes());
        assert_eq!(&body[6..14], &1.5f64.to_bits().to_be_bytes());
    }

    #[test]
    fn null_is_minus_one_length_and_no_payload() {
        let mut buf = PgBinaryCopyBuf::new();
        buf.start_tuple(1);
        buf.write_null();
        let body = &buf.as_slice()[19..];
        assert_eq!(&body[2..6], &(-1i32).to_be_bytes());
        assert_eq!(body.len(), 6); // 2 byte count + 4 byte length, no data
    }

    #[test]
    fn encode_agent_metric_sample_writes_contract_field_count() {
        let mut buf = PgBinaryCopyBuf::new();
        encode_agent_metric_sample(
            &mut buf,
            9,
            1,
            "agent-uuid",
            4,
            PG_EPOCH_UNIX_MICROS,
            16,
            &json!({"n": 1}),
            12,
        );
        assert_eq!(buf.tuple_count(), 1);
        let body = &buf.as_slice()[19..];
        let nfields = i16::try_from(AGENT_METRIC_SAMPLES_COPY_COLUMNS.len()).unwrap();
        assert_eq!(&body[0..2], &nfields.to_be_bytes());
        let finished = buf.finish();
        assert_eq!(&finished[finished.len() - 2..], &[0xFF, 0xFF]);
    }

    #[test]
    fn copy_sql_is_generated_from_the_column_contract() {
        let sql = agent_metric_samples_copy_sql();
        assert!(sql.contains("agent_metric_samples"));
        assert!(sql.contains("FORMAT binary"));
        let expected = format!(
            "COPY agent_metric_samples ({}) FROM STDIN WITH (FORMAT binary)",
            AGENT_METRIC_SAMPLES_COPY_COLUMNS
                .iter()
                .map(|c| c.name)
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert_eq!(sql, expected);
        assert_eq!(
            agent_metric_samples_copy_column_names(),
            AGENT_METRIC_SAMPLES_COPY_COLUMNS
                .iter()
                .map(|c| c.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn create_table_in_ueba_baseline_migration_matches_v1_contract() {
        let sql = include_str!("../migrations/20260608140200_ueba_baseline.sql");
        let cols = parse_create_table_columns(sql, "agent_metric_samples");
        let contract: Vec<&str> = AGENT_METRIC_SAMPLES_COPY_COLUMNS
            .iter()
            .map(|c| c.name)
            .collect();
        assert!(
            cols.len() >= contract.len(),
            "migration has fewer columns than the COPY contract: {cols:?}"
        );
        assert_eq!(
            &cols[..contract.len()],
            contract.as_slice(),
            "CREATE TABLE column order must match the binary COPY contract"
        );
        assert_eq!(
            infer_pg_types(sql, "agent_metric_samples")[..contract.len()],
            AGENT_METRIC_SAMPLES_COPY_COLUMNS
                .iter()
                .map(|c| c.pg_type)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn copy_schema_v1_migration_records_the_same_version() {
        let sql = include_str!("../migrations/20260827180000_agent_metric_samples_copy_schema_v1.sql");
        assert!(sql.contains(&format!(
            "weissman:copy-schema-version={AGENT_METRIC_SAMPLES_SCHEMA_VERSION}"
        )));
        for col in AGENT_METRIC_SAMPLES_COPY_COLUMNS {
            assert!(
                sql.contains(col.name),
                "schema-version migration missing {}",
                col.name
            );
        }
    }

    fn parse_create_table_columns(sql: &str, table: &str) -> Vec<String> {
        let marker = format!("CREATE TABLE IF NOT EXISTS {table}");
        let start = sql.find(&marker).expect("CREATE TABLE");
        let rest = &sql[start..];
        let open = rest.find('(').expect("(");
        let close = rest.find("\n);").expect("closing );");
        rest[open + 1..close]
            .lines()
            .filter_map(|line| {
                let t = line.trim();
                if t.is_empty() || t.starts_with("--") {
                    return None;
                }
                let name = t.split_whitespace().next()?;
                if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    fn infer_pg_types(sql: &str, table: &str) -> Vec<&'static str> {
        let marker = format!("CREATE TABLE IF NOT EXISTS {table}");
        let start = sql.find(&marker).expect("CREATE TABLE");
        let rest = &sql[start..];
        let open = rest.find('(').expect("(");
        let close = rest.find("\n);").expect("closing );");
        rest[open + 1..close]
            .lines()
            .filter_map(|line| {
                let t = line.trim();
                if t.is_empty() || t.starts_with("--") {
                    return None;
                }
                let mut parts = t.split_whitespace();
                let name = parts.next()?;
                if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return None;
                }
                let ty = parts.next()?.trim_end_matches(',').to_ascii_uppercase();
                Some(match ty.as_str() {
                    "BIGSERIAL" | "BIGINT" => "int8",
                    "SMALLINT" => "int2",
                    "INTEGER" | "INT" => "int4",
                    "TEXT" => "text",
                    "TIMESTAMPTZ" => "timestamptz",
                    "JSONB" => "jsonb",
                    other => panic!("unmapped SQL type {other} for {name}"),
                })
            })
            .collect()
    }
}
