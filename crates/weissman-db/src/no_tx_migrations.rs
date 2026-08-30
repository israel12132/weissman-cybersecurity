//! Out-of-transaction migration runner — bridges SQLx's "always wrap in BEGIN/COMMIT"
//! default with Postgres statements that physically cannot run inside a transaction
//! (CREATE INDEX CONCURRENTLY, DROP INDEX CONCURRENTLY, REINDEX CONCURRENTLY,
//! VACUUM FULL, ALTER SYSTEM, …).
//!
//! Contract — to opt a `.sql` migration file out of SQLx's transaction wrapper, the
//! **very first line** must be exactly:
//!
//!   ```text
//!   -- weissman:no-transaction
//!   ```
//!
//! Whitespace-only lines BEFORE the header are not tolerated — the header must be
//! line 1 (a leading UTF-8 BOM is fine). This keeps detection cheap and unambiguous
//! and prevents accidental "I forgot to scroll" mistakes.
//!
//! Algorithm:
//!   1. List every `*.sql` file in the migrations directory.
//!   2. Sort by filename (== `<yyyymmddHHMMSS>` version timestamp prefix).
//!   3. For each file whose first line is the header: compute the SQLx-compatible
//!      checksum (SHA-384 of the file bytes) and read the file's version /
//!      description from its name (`<timestamp>_<description>.sql`).
//!   4. Look up `_sqlx_migrations` by version:
//!      - matching checksum  → already applied successfully, skip.
//!      - mismatching        → refuse to start (file was edited after release;
//!                              operator must restore or supersede).
//!      - missing            → execute every statement of the file directly on
//!                              a single connection (no transaction), record
//!                              execution time, and insert a row into
//!                              `_sqlx_migrations` with the correct checksum so
//!                              the regular `sqlx::migrate!()` runner sees it as
//!                              already applied.
//!   5. The caller then runs `sqlx::migrate!()` as usual for the rest of the files.
//!
//! The caller must pass the on-disk migrations directory. In production containers use
//! `WEISSMAN_MIGRATIONS_DIR` (see [`crate::migrations_dir`]); the compile-time
//! `CARGO_MANIFEST_DIR` path is not present in slim runtime images.
//!
//! No fallback / no fake. If a no-tx migration partially succeeds and crashes
//! mid-flight, the next process boot will:
//!   * NOT insert the `_sqlx_migrations` row (we only insert after success),
//!   * Re-attempt the whole file. Idempotency is the file author's responsibility
//!     — we recommend `DROP … IF EXISTS; CREATE … IF NOT EXISTS` pairs as in
//!     the CONCURRENTLY index migration that ships with the bootstrap.

use sha2::{Digest, Sha384};
use sqlx::postgres::PgConnection;
use sqlx::{Executor, PgPool};
use std::fs;
use std::path::Path;
use std::time::Instant;

const HEADER_DIRECTIVE: &str = "-- weissman:no-transaction";

#[derive(Debug, Clone)]
struct NoTxMigration {
    /// Version derived from the leading digits of the filename. Must fit in i64
    /// (SQLx schema constraint). Format `yyyymmddHHMMSS` — 14 digits, < 2^63.
    version: i64,
    description: String,
    sql: String,
    checksum: Vec<u8>,
}

/// Errors specific to the no-tx pre-runner. Distinct from SQLx errors so the
/// caller can render a clear "your migration file was modified" diagnostic.
#[derive(Debug, thiserror::Error)]
pub enum NoTxMigrateError {
    #[error("failed to read migrations directory '{path}': {source}")]
    ReadDir {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to read migration file '{path}': {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid migration filename '{name}': expected <timestamp>_<description>.sql")]
    BadFilename { name: String },
    #[error(
        "migration #{version} ({description}) was previously applied with a different checksum; \
         the file has been edited since release. Restore the original content or supersede with a new migration."
    )]
    ChecksumMismatch { version: i64, description: String },
    #[error("Postgres rejected no-tx migration #{version} ({description}): {source}")]
    Execute {
        version: i64,
        description: String,
        source: sqlx::Error,
    },
    #[error("could not record no-tx migration #{version} in _sqlx_migrations: {source}")]
    Record { version: i64, source: sqlx::Error },
}

/// No-tx migrations that could not be built in the pre-pass because a dependency
/// (typically a table created by a *later, regular* migration) did not exist yet.
///
/// They are recorded in `_sqlx_migrations` as a placeholder so the embedded
/// `sqlx::migrate!()` runner does **not** re-attempt them inside a transaction
/// (which would fail for `CREATE INDEX CONCURRENTLY`). The caller MUST pass this
/// back to [`apply_deferred_no_tx_migrations`] *after* `sqlx::migrate!().run()` so
/// the statements are actually executed once the dependency exists. Empty on any
/// already-migrated database (the common production / incremental-upgrade case),
/// where every no-tx migration builds normally in the pre-pass.
#[derive(Debug, Default)]
pub struct DeferredNoTx(Vec<NoTxMigration>);

impl DeferredNoTx {
    /// No migrations were deferred.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Number of deferred no-tx migrations awaiting a post-pass build.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Apply every no-tx migration found in `migrations_dir` that isn't already in
/// `_sqlx_migrations`. Must be called BEFORE `sqlx::migrate!().run()`.
///
/// Returns the set of migrations that were **deferred** because a dependency was
/// not present yet (e.g. an index on a table created by a later regular
/// migration). On a fresh database the regular table-creating migration runs in
/// `sqlx::migrate!()` *after* this pre-pass, so the index build is deferred and
/// must be finalized with [`apply_deferred_no_tx_migrations`] once the table
/// exists. On an already-migrated database nothing is deferred.
pub async fn apply_no_tx_migrations<P: AsRef<Path>>(
    pool: &PgPool,
    migrations_dir: P,
) -> Result<DeferredNoTx, NoTxMigrateError> {
    let dir = migrations_dir.as_ref();
    let entries = fs::read_dir(dir).map_err(|e| NoTxMigrateError::ReadDir {
        path: dir.display().to_string(),
        source: e,
    })?;
    let mut candidates: Vec<NoTxMigration> = Vec::new();
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("sql") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let bytes = fs::read(&path).map_err(|e| NoTxMigrateError::ReadFile {
            path: path.display().to_string(),
            source: e,
        })?;
        if !has_no_tx_header(&bytes) {
            continue;
        }
        let (version, description) = parse_version_and_description(&name)
            .ok_or_else(|| NoTxMigrateError::BadFilename { name: name.clone() })?;
        candidates.push(NoTxMigration {
            version,
            description,
            sql: String::from_utf8_lossy(&bytes).into_owned(),
            checksum: sqlx_sha384(&bytes),
        });
    }
    candidates.sort_by_key(|m| m.version);

    // Ensure `_sqlx_migrations` exists. SQLx creates it on its first run; we
    // create it idempotently here so a brand-new database doesn't blow up on
    // the SELECT below.
    ensure_sqlx_migrations_table(pool).await?;

    // One batched SELECT for all no-tx versions (typical boot: all already applied).
    // Per-file SELECTs used to add tens of milliseconds of serial latency.
    let versions: Vec<i64> = candidates.iter().map(|m| m.version).collect();
    let recorded = load_recorded_checksums(pool, &versions).await?;

    let mut deferred: Vec<NoTxMigration> = Vec::new();
    for m in &candidates {
        match recorded.get(&m.version) {
            Some(existing) if existing == &m.checksum => {
                tracing::debug!(
                    target: "weissman_db::no_tx",
                    version = m.version,
                    description = %m.description,
                    "already applied — skip"
                );
                continue;
            }
            Some(_) => {
                return Err(NoTxMigrateError::ChecksumMismatch {
                    version: m.version,
                    description: m.description.clone(),
                });
            }
            None => {}
        }
        match run_no_tx_statements(pool, m).await {
            Ok(elapsed_ms) => record_no_tx_applied(pool, m, elapsed_ms).await?,
            // Dependency not present yet — on a fresh database the table this
            // migration targets is created by a *later* regular migration in
            // `sqlx::migrate!()`. Record a placeholder (so SQLx won't re-run the
            // CONCURRENTLY statement inside a transaction) and finalize it in the
            // post-pass once the dependency exists.
            Err(e) if is_missing_dependency(&e) => {
                tracing::warn!(
                    target: "weissman_db::no_tx",
                    version = m.version,
                    description = %m.description,
                    error = %e,
                    "no-tx migration deferred: dependency not present yet (will build after regular migrations)"
                );
                record_no_tx_applied(pool, m, 0).await?;
                deferred.push(m.clone());
            }
            Err(e) => {
                return Err(NoTxMigrateError::Execute {
                    version: m.version,
                    description: m.description.clone(),
                    source: e,
                })
            }
        }
    }

    Ok(DeferredNoTx(deferred))
}

/// Finalize no-tx migrations that were deferred by [`apply_no_tx_migrations`].
/// Call AFTER `sqlx::migrate!().run()` so the dependency (e.g. the target table)
/// now exists. On success the placeholder row's execution time is updated; on
/// failure the placeholder is removed so the next boot re-attempts the build,
/// then the error is surfaced. Returns the number of migrations built.
pub async fn apply_deferred_no_tx_migrations(
    pool: &PgPool,
    deferred: DeferredNoTx,
) -> Result<usize, NoTxMigrateError> {
    let mut built = 0usize;
    for m in &deferred.0 {
        match run_no_tx_statements(pool, m).await {
            Ok(elapsed_ms) => {
                record_no_tx_applied(pool, m, elapsed_ms).await?;
                built += 1;
            }
            Err(e) => {
                // Building still failed even after regular migrations ran. Remove
                // the placeholder so a later boot retries from scratch (the file's
                // DROP … IF EXISTS / CREATE … IF NOT EXISTS pairs keep it idempotent).
                if let Err(del) = delete_no_tx_record(pool, m.version).await {
                    tracing::error!(
                        target: "weissman_db::no_tx",
                        version = m.version,
                        error = %del,
                        "failed to roll back deferred no-tx placeholder row"
                    );
                }
                return Err(NoTxMigrateError::Execute {
                    version: m.version,
                    description: m.description.clone(),
                    source: e,
                });
            }
        }
    }
    Ok(built)
}

fn has_no_tx_header(file: &[u8]) -> bool {
    // We only accept the directive when it's literally the first line of the
    // file (after an optional UTF-8 BOM). Anything else — even a leading blank
    // line — is rejected to avoid "scrolling-blindness" mistakes.
    let trimmed: &[u8] = file.strip_prefix(b"\xef\xbb\xbf").unwrap_or(file);
    let first_line_end = trimmed
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(trimmed.len());
    let first_line = &trimmed[..first_line_end];
    let first_line = first_line.strip_suffix(b"\r").unwrap_or(first_line);
    first_line.eq_ignore_ascii_case(HEADER_DIRECTIVE.as_bytes())
}

fn parse_version_and_description(name: &str) -> Option<(i64, String)> {
    // Expected: `<digits>_<description>.sql`.
    let stem = name.strip_suffix(".sql")?;
    let underscore = stem.find('_')?;
    let (digits, rest) = stem.split_at(underscore);
    let version: i64 = digits.parse().ok()?;
    let description = rest.trim_start_matches('_').to_string();
    if description.is_empty() {
        return None;
    }
    Some((version, description))
}

/// SQLx-compatible SHA-384 (48 bytes). Used for `_sqlx_migrations.checksum`.
#[must_use]
pub fn sqlx_sha384(bytes: &[u8]) -> Vec<u8> {
    Sha384::digest(bytes).to_vec()
}

async fn load_recorded_checksums(
    pool: &PgPool,
    versions: &[i64],
) -> Result<std::collections::HashMap<i64, Vec<u8>>, NoTxMigrateError> {
    let mut map = std::collections::HashMap::new();
    if versions.is_empty() {
        return Ok(map);
    }
    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT version, checksum FROM _sqlx_migrations WHERE success = true AND version = ANY($1)",
    )
    .bind(versions)
    .fetch_all(pool)
    .await
    .map_err(|e| NoTxMigrateError::Record {
        version: 0,
        source: e,
    })?;
    for (v, c) in rows {
        map.insert(v, c);
    }
    Ok(map)
}

async fn ensure_sqlx_migrations_table(pool: &PgPool) -> Result<(), NoTxMigrateError> {
    pool.execute(
        r#"CREATE TABLE IF NOT EXISTS _sqlx_migrations (
            version        BIGINT      PRIMARY KEY,
            description    TEXT        NOT NULL,
            installed_on   TIMESTAMPTZ NOT NULL DEFAULT now(),
            success        BOOLEAN     NOT NULL,
            checksum       BYTEA       NOT NULL,
            execution_time BIGINT      NOT NULL
        )"#,
    )
    .await
    .map_err(|e| NoTxMigrateError::Record {
        version: 0,
        source: e,
    })?;
    Ok(())
}

/// Execute the migration SQL outside any transaction. Statements are split on
/// `;` boundaries that aren't inside string literals or dollar-quoted blocks.
/// Returns the wall-clock execution time (ms). The raw SQLx error is preserved
/// (not wrapped) so the caller can inspect its SQLSTATE — see
/// [`is_missing_dependency`].
///
/// HNSW / `CREATE INDEX CONCURRENTLY` files pin a **single** connection so
/// `SET maintenance_work_mem` survives for the whole build (`SET LOCAL` is a
/// no-op outside a transaction, and CONCURRENTLY cannot run inside one).
/// Invalid leftover indexes are dropped before the build and again if a
/// statement fails, so a crashed CONCURRENTLY run cannot leak disk.
async fn run_no_tx_statements(pool: &PgPool, m: &NoTxMigration) -> Result<i64, sqlx::Error> {
    let started = Instant::now();
    let statements = split_sql_statements(&m.sql);
    if needs_pinned_index_connection(&m.sql) {
        let mut conn = pool.acquire().await?;
        let hnsw = sql_has_hnsw_concurrent_create(&m.sql);
        if hnsw {
            apply_hnsw_maintenance_work_mem(&mut conn).await?;
        }
        let exec = match drop_invalid_indexes(&mut conn).await {
            Ok(_) => exec_no_tx_statements(&mut conn, m, &statements).await,
            Err(e) => Err(e),
        };
        if exec.is_err() {
            if let Err(e) = drop_invalid_indexes(&mut conn).await {
                tracing::warn!(
                    target: "weissman_db::no_tx",
                    version = m.version,
                    error = %e,
                    "could not drop INVALID leftover indexes after failed no-tx build"
                );
            }
        }
        if hnsw {
            if let Err(e) = reset_maintenance_work_mem(&mut conn).await {
                tracing::warn!(
                    target: "weissman_db::no_tx",
                    version = m.version,
                    error = %e,
                    "could not RESET maintenance_work_mem after HNSW build"
                );
            }
        }
        exec?;
        return Ok(started.elapsed().as_millis() as i64);
    }
    for (i, stmt) in statements.iter().enumerate() {
        let trimmed = stmt.trim();
        if trimmed.is_empty() {
            continue;
        }
        tracing::info!(
            target: "weissman_db::no_tx",
            version = m.version,
            description = %m.description,
            statement_index = i,
            "executing no-tx statement"
        );
        pool.execute(trimmed).await?;
    }
    Ok(started.elapsed().as_millis() as i64)
}

async fn exec_no_tx_statements(
    conn: &mut PgConnection,
    m: &NoTxMigration,
    statements: &[String],
) -> Result<(), sqlx::Error> {
    for (i, stmt) in statements.iter().enumerate() {
        let trimmed = stmt.trim();
        if trimmed.is_empty() {
            continue;
        }
        tracing::info!(
            target: "weissman_db::no_tx",
            version = m.version,
            description = %m.description,
            statement_index = i,
            "executing no-tx statement"
        );
        conn.execute(trimmed).await?;
    }
    Ok(())
}

fn needs_pinned_index_connection(sql: &str) -> bool {
    let u = sql.to_ascii_uppercase();
    u.contains("CREATE INDEX CONCURRENTLY") || u.contains("DROP INDEX CONCURRENTLY")
}

fn sql_has_hnsw_concurrent_create(sql: &str) -> bool {
    let u = sql.to_ascii_uppercase();
    u.contains("CREATE INDEX CONCURRENTLY") && u.contains("USING HNSW")
}

/// Allowlisted `maintenance_work_mem` for HNSW CONCURRENTLY builds.
///
/// `SET` cannot take a bind parameter, so the value MUST come from this
/// allowlist — never interpolate operator input verbatim.
fn hnsw_maintenance_work_mem() -> &'static str {
    parse_hnsw_maintenance_work_mem(
        std::env::var("WEISSMAN_HNSW_MAINTENANCE_WORK_MEM")
            .ok()
            .as_deref(),
    )
}

fn parse_hnsw_maintenance_work_mem(raw: Option<&str>) -> &'static str {
    const DEFAULT: &str = "256MB";
    match raw.map(str::trim) {
        None | Some("") => DEFAULT,
        Some("64MB") => "64MB",
        Some("128MB") => "128MB",
        Some("256MB") => "256MB",
        Some("512MB") => "512MB",
        Some("1GB") => "1GB",
        Some(other) => {
            tracing::warn!(
                target: "weissman_db::no_tx",
                value = other,
                "invalid WEISSMAN_HNSW_MAINTENANCE_WORK_MEM (allow 64MB|128MB|256MB|512MB|1GB); using 256MB"
            );
            DEFAULT
        }
    }
}

async fn apply_hnsw_maintenance_work_mem(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    let mem = hnsw_maintenance_work_mem();
    tracing::info!(
        target: "weissman_db::no_tx",
        maintenance_work_mem = mem,
        "HNSW CONCURRENTLY build: session maintenance_work_mem (SET LOCAL is invalid outside a transaction)"
    );
    sqlx::query(&format!("SET maintenance_work_mem = '{mem}'"))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn reset_maintenance_work_mem(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("RESET maintenance_work_mem")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

fn pg_quote_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

/// Drop leftover INVALID indexes (crashed `CREATE INDEX CONCURRENTLY`) so they
/// cannot consume production disk until the next successful rebuild.
async fn drop_invalid_indexes(conn: &mut PgConnection) -> Result<usize, sqlx::Error> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT n.nspname, c.relname
           FROM pg_class c
           JOIN pg_index i ON i.indexrelid = c.oid
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE c.relkind = 'i'
             AND NOT i.indisvalid
             AND n.nspname NOT IN ('pg_catalog', 'information_schema')"#,
    )
    .fetch_all(&mut *conn)
    .await?;
    let n = rows.len();
    for (schema, name) in &rows {
        let ident = format!("{}.{}", pg_quote_ident(schema), pg_quote_ident(name));
        tracing::warn!(
            target: "weissman_db::no_tx",
            index = %ident,
            "dropping INVALID leftover index before/after CONCURRENTLY build"
        );
        sqlx::query(&format!("DROP INDEX CONCURRENTLY IF EXISTS {ident}"))
            .execute(&mut *conn)
            .await?;
    }
    Ok(n)
}

/// Record a no-tx migration as applied in `_sqlx_migrations` with its
/// SQLx-compatible SHA-384 checksum. Idempotent via `ON CONFLICT` so a deferred
/// placeholder row can be re-stamped when it is finalized.
async fn record_no_tx_applied(
    pool: &PgPool,
    m: &NoTxMigration,
    elapsed_ms: i64,
) -> Result<(), NoTxMigrateError> {
    sqlx::query(
        r#"INSERT INTO _sqlx_migrations
              (version, description, installed_on, success, checksum, execution_time)
           VALUES ($1, $2, now(), true, $3, $4)
           ON CONFLICT (version) DO UPDATE
              SET success = true,
                  checksum = EXCLUDED.checksum,
                  execution_time = EXCLUDED.execution_time"#,
    )
    .bind(m.version)
    .bind(&m.description)
    .bind(&m.checksum)
    .bind(elapsed_ms)
    .execute(pool)
    .await
    .map_err(|e| NoTxMigrateError::Record {
        version: m.version,
        source: e,
    })?;
    tracing::info!(
        target: "weissman_db::no_tx",
        version = m.version,
        description = %m.description,
        elapsed_ms,
        "no-tx migration applied"
    );
    Ok(())
}

/// Remove a no-tx migration's row from `_sqlx_migrations` (used to roll back a
/// deferred placeholder when its post-pass build fails, so the next boot retries).
async fn delete_no_tx_record(pool: &PgPool, version: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
        .bind(version)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Whether a SQLx error indicates a *missing dependency* — an object the
/// migration references hasn't been created yet (it will be by a later regular
/// migration in `sqlx::migrate!()`). Such failures are deferred and retried in a
/// post-pass rather than aborting the boot. Any other error is a hard failure.
///
/// SQLSTATE: `42P01` undefined_table, `42703` undefined_column, `3F000`
/// invalid_schema_name, `42704` undefined_object, `42883` undefined_function.
fn is_missing_dependency(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db) = e {
        if let Some(code) = db.code() {
            return matches!(
                code.as_ref(),
                "42P01" | "42703" | "3F000" | "42704" | "42883"
            );
        }
    }
    false
}

/// Split a SQL string on `;` boundaries while respecting single-quoted strings,
/// double-quoted identifiers, line/block comments, and dollar-quoted blocks
/// (`$tag$ … $tag$`). Conservative — when in doubt, treats the input as one
/// statement so we never accidentally chop a multi-line CREATE FUNCTION body.
fn split_sql_statements(sql: &str) -> Vec<String> {
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // Line comment — skip to end-of-line.
        if c == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            while i < bytes.len() && bytes[i] != b'\n' {
                cur.push(bytes[i] as char);
                i += 1;
            }
            continue;
        }
        // Block comment — skip until `*/` (no nesting per Postgres).
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            cur.push('/');
            cur.push('*');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                cur.push(bytes[i] as char);
                i += 1;
            }
            if i + 1 < bytes.len() {
                cur.push('*');
                cur.push('/');
                i += 2;
            }
            continue;
        }
        // Single-quoted string — doubled '' is an escape, not a terminator.
        if c == b'\'' {
            cur.push('\'');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\'' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                        cur.push('\'');
                        cur.push('\'');
                        i += 2;
                        continue;
                    }
                    cur.push('\'');
                    i += 1;
                    break;
                }
                cur.push(bytes[i] as char);
                i += 1;
            }
            continue;
        }
        // Double-quoted identifier.
        if c == b'"' {
            cur.push('"');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'"' {
                    cur.push('"');
                    i += 1;
                    break;
                }
                cur.push(bytes[i] as char);
                i += 1;
            }
            continue;
        }
        // Dollar-quoted block — $tag$ … $tag$ (tag may be empty).
        if c == b'$' {
            if let Some(close_rel) = bytes[i + 1..].iter().position(|&b| b == b'$') {
                let tag = &bytes[i..=i + 1 + close_rel];
                cur.push_str(std::str::from_utf8(tag).unwrap_or(""));
                i += tag.len();
                let mut found = false;
                while i + tag.len() <= bytes.len() {
                    if &bytes[i..i + tag.len()] == tag {
                        cur.push_str(std::str::from_utf8(tag).unwrap_or(""));
                        i += tag.len();
                        found = true;
                        break;
                    }
                    cur.push(bytes[i] as char);
                    i += 1;
                }
                if !found {
                    while i < bytes.len() {
                        cur.push(bytes[i] as char);
                        i += 1;
                    }
                }
                continue;
            }
        }
        // Statement terminator.
        if c == b';' {
            out.push(std::mem::take(&mut cur));
            i += 1;
            continue;
        }
        cur.push(c as char);
        i += 1;
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_detected_on_first_line() {
        let s = b"-- weissman:no-transaction\nCREATE INDEX CONCURRENTLY foo ON bar(x);";
        assert!(has_no_tx_header(s));
    }
    #[test]
    fn header_rejected_when_not_first_line() {
        let s = b"\n-- weissman:no-transaction\nCREATE INDEX CONCURRENTLY foo ON bar(x);";
        assert!(!has_no_tx_header(s));
    }
    #[test]
    fn header_case_insensitive() {
        let s = b"-- Weissman:No-Transaction\n";
        assert!(has_no_tx_header(s));
    }
    #[test]
    fn header_ignores_bom() {
        let s = b"\xef\xbb\xbf-- weissman:no-transaction\n";
        assert!(has_no_tx_header(s));
    }
    #[test]
    fn header_rejects_unrelated_first_line() {
        let s = b"BEGIN;\n-- weissman:no-transaction\n";
        assert!(!has_no_tx_header(s));
    }
    #[test]
    fn filename_parser_extracts_version_and_description() {
        let (v, d) =
            parse_version_and_description("20260608150000_async_jobs_pending.sql").unwrap();
        assert_eq!(v, 20260608150000_i64);
        assert_eq!(d, "async_jobs_pending");
    }
    #[test]
    fn filename_parser_rejects_missing_description() {
        assert!(parse_version_and_description("20260608150000.sql").is_none());
        assert!(parse_version_and_description("foo.sql").is_none());
    }
    #[test]
    fn split_respects_dollar_quoted_function_body() {
        let sql = "CREATE OR REPLACE FUNCTION f() RETURNS VOID AS $$
                   BEGIN RAISE NOTICE 'a; b; c'; END $$ LANGUAGE plpgsql;
                   CREATE INDEX i ON t (x);";
        let parts = split_sql_statements(sql);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("RAISE NOTICE 'a; b; c'"));
        assert!(parts[1].contains("CREATE INDEX"));
    }
    #[test]
    fn split_handles_doubled_quote_escape() {
        let sql = "INSERT INTO t (x) VALUES ('it''s ok; really'); SELECT 1;";
        let parts = split_sql_statements(sql);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("it''s ok; really"));
    }
    #[test]
    fn split_handles_line_comment_with_semicolon() {
        let sql = "SELECT 1 -- not; the end\n; SELECT 2;";
        let parts = split_sql_statements(sql);
        assert_eq!(parts.len(), 2);
    }
    #[test]
    fn checksum_matches_known_sha384_for_empty_input() {
        // Sanity: SHA-384 of empty input is the well-known FIPS 180-4 constant.
        let d = sqlx_sha384(b"");
        let hex = d.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(
            hex,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        );
        assert_eq!(d, Sha384::digest(b"").to_vec());
        assert_eq!(d.len(), 48, "SHA-384 digest is 48 bytes (SQLx BYTEA width)");
    }

    #[test]
    fn pgvector_hnsw_no_tx_migration_pins_m16_ef64() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260827120000_pgvector_hnsw_m16_ef64.sql"
        );
        let sql = std::fs::read_to_string(path).expect("hnsw migration");
        assert!(
            sql.starts_with("-- weissman:no-transaction"),
            "must be a no-tx pre-runner file"
        );
        assert!(sql.contains("m = 16"));
        assert!(sql.contains("ef_construction = 64"));
        assert!(sql.contains("ix_supreme_council_mem_embedding_hnsw"));
        assert!(sql.contains("ix_pwp_embedding_hnsw"));
        assert!(sql.contains("CREATE INDEX CONCURRENTLY"));
    }

    #[test]
    fn hnsw_sql_is_detected_as_pinned_concurrent_build() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260827120000_pgvector_hnsw_m16_ef64.sql"
        );
        let sql = std::fs::read_to_string(path).expect("hnsw migration");
        assert!(sql_has_hnsw_concurrent_create(&sql));
        assert!(needs_pinned_index_connection(&sql));
        assert!(!sql_has_hnsw_concurrent_create(
            "CREATE INDEX CONCURRENTLY ix ON t(x)"
        ));
        assert!(needs_pinned_index_connection(
            "DROP INDEX CONCURRENTLY IF EXISTS ix_async_jobs_pending"
        ));
    }

    #[test]
    fn hnsw_maintenance_work_mem_is_allowlisted() {
        assert_eq!(parse_hnsw_maintenance_work_mem(None), "256MB");
        assert_eq!(parse_hnsw_maintenance_work_mem(Some("")), "256MB");
        assert_eq!(parse_hnsw_maintenance_work_mem(Some("512MB")), "512MB");
        assert_eq!(parse_hnsw_maintenance_work_mem(Some("1GB")), "1GB");
        assert_eq!(parse_hnsw_maintenance_work_mem(Some("64MB")), "64MB");
        assert_eq!(
            parse_hnsw_maintenance_work_mem(Some("'; DROP TABLE students; --")),
            "256MB"
        );
    }

    #[test]
    fn pg_quote_ident_escapes_double_quotes() {
        assert_eq!(
            pg_quote_ident("ix_pwp_embedding_hnsw"),
            "\"ix_pwp_embedding_hnsw\""
        );
        assert_eq!(pg_quote_ident("odd\"name"), "\"odd\"\"name\"");
    }

    #[test]
    fn hermetic_roles_migration_grants_thirteen_ro_tables() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260827120100_hermetic_db_roles.sql"
        );
        let sql = std::fs::read_to_string(path).expect("roles migration");
        assert!(sql.contains("NOBYPASSRLS"));
        assert!(sql.contains("ALTER ROLE weissman_auth"));
        assert!(sql.contains("BYPASSRLS"));
        assert!(sql.contains("statement_timeout = '15s'"));
        for table in crate::role_guard::RO_SELECT_TABLES {
            assert!(
                sql.contains(table),
                "weissman_ro grant list must include {table}"
            );
        }
        assert!(!sql.contains("weissman_async_jobs"));
    }

    #[test]
    fn analytics_worker_roles_migration_matches_role_guard_lists() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260829120000_hermetic_analytics_worker_roles.sql"
        );
        let sql = std::fs::read_to_string(path).expect("analytics/worker roles migration");
        assert!(sql.contains("BYPASSRLS"));
        assert!(sql.contains("weissman_analytics"));
        assert!(sql.contains("weissman_worker"));
        // Historical file granted raw meter tables; do not point ANALYTICS_SELECT_TABLES at it.
        for table in [
            "billing_plans",
            "tenant_usage_counters",
            "weissman_tenant_quota_usage",
            "tenant_llm_usage",
        ] {
            assert!(
                sql.contains(table),
                "legacy analytics grants must include {table}"
            );
        }
        for table in crate::role_guard::WORKER_JOB_BUS_TABLES {
            assert!(sql.contains(table), "worker grants must include {table}");
        }
        assert!(!sql.contains("vulnerabilities"));
        assert!(!sql.contains("agent_anomalies"));
        let fail_closed = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260829120100_job_bus_tenant_fail_closed.sql"
        );
        let pol = std::fs::read_to_string(fail_closed).expect("job-bus fail-closed");
        assert!(pol.contains("app_current_tenant_id()"));
        assert!(!pol.contains("NULLIF(current_setting('app.current_tenant_id'"));
    }

    #[test]
    fn billing_usage_snapshot_migration_matches_current_analytics_grants() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260830120000_billing_usage_snapshot_15s.sql"
        );
        let sql = std::fs::read_to_string(path).expect("billing snapshot migration");
        assert!(sql.contains("statement_timeout = '15s'"));
        assert!(sql.contains("weissman_billing_usage_snapshot"));
        assert!(sql.contains("weissman_refresh_billing_usage_snapshot"));
        assert!(
            sql.contains("REVOKE SELECT ON public.tenant_usage_counters FROM weissman_analytics")
        );
        for table in crate::role_guard::ANALYTICS_SELECT_TABLES {
            assert!(
                sql.contains(table),
                "current analytics grants must include {table}"
            );
        }
        assert!(!sql.contains("GRANT SELECT ON public.tenant_usage_counters TO weissman_analytics"));
    }

    #[test]
    fn client_scope_isolation_migration_is_frozen_at_original_sha384() {
        // 2a960be edited this file after live volumes had applied it. sqlx then
        // refused to boot. The file is restored to 389751f; new SQL belongs in
        // 20260826180000_*.sql. Do not edit this file — the checksum is the
        // integrity record in `_sqlx_migrations`.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260826120000_client_scope_isolation.sql"
        );
        let bytes = std::fs::read(path).expect("read frozen client-scope migration");
        let hex: String = Sha384::digest(&bytes)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            hex,
            "1f1b1e01015d4698971987fde08bd819835e879ebd5a293441e09f151edfbcf1832ac009298a15cf6b0b433bd1f7c628",
            "20260826120000_client_scope_isolation.sql is frozen; add a new migration file instead of editing it"
        );
    }

    #[test]
    fn client_scope_insert_only_followup_migration_exists() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260826180000_client_scope_insert_only_policies.sql"
        );
        let sql = std::fs::read_to_string(path).expect("read follow-up client-scope migration");
        assert!(
            sql.contains("only WITH CHECK expression allowed"),
            "follow-up must document the INSERT-only ALTER POLICY rule"
        );
        assert!(
            sql.contains("IF r.qual IS NOT NULL"),
            "follow-up must not synthesize USING on INSERT-only policies"
        );
        assert!(
            sql.contains("CREATE POLICY risk_graph_nodes_insert"),
            "follow-up must recreate the INSERT policies dropped by 20260826115900"
        );
    }
}
