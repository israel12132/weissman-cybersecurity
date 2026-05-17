//! Production PostgreSQL logical backups via `pg_dump`, optional gzip, retention pruning, and background scheduling.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn backup_dir_from_env() -> Option<PathBuf> {
    match std::env::var("WEISSMAN_PG_BACKUP_DIR") {
        Ok(s) if !s.trim().is_empty() => Some(PathBuf::from(s.trim())),
        _ => None,
    }
}

fn retention_days() -> u64 {
    std::env::var("WEISSMAN_BACKUP_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(14)
        .max(1)
}

fn max_backup_files() -> usize {
    std::env::var("WEISSMAN_BACKUP_MAX_FILES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .max(5)
}

fn compress_backups() -> bool {
    matches!(
        std::env::var("WEISSMAN_BACKUP_COMPRESS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true),
        true
    )
}

/// If `WEISSMAN_PG_BACKUP_DIR` is set, run `pg_dump` against `DATABASE_URL` and write a timestamped `.sql` file.
/// `WEISSMAN_PG_DUMP_PATH` overrides the `pg_dump` binary (default: `pg_dump` from PATH).
/// Returns `Ok(None)` when backup is skipped (no directory env).
pub fn backup_postgres_if_configured() -> Result<Option<PathBuf>, String> {
    let backups_dir = match backup_dir_from_env() {
        Some(p) => p,
        None => return Ok(None),
    };
    let path = backup_postgres_to_dir(&backups_dir)?;
    let final_path = if compress_backups() {
        gzip_sql_file(&path)?
    } else {
        path
    };
    prune_old_backups(&backups_dir)?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as f64)
        .unwrap_or(0.0);
    metrics::gauge!("weissman_backup_last_success_unix_timestamp").set(ts);
    metrics::counter!("weissman_backup_success_total").increment(1);
    Ok(Some(final_path))
}

/// Run `pg_dump` to the given directory (creates a timestamped `.sql` file). Uses `DATABASE_URL`.
pub fn backup_postgres_to_dir(backups_dir: &std::path::Path) -> Result<PathBuf, String> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL required for pg_dump backup".to_string())?;
    std::fs::create_dir_all(backups_dir).map_err(|e| e.to_string())?;
    let pg_dump = std::env::var("WEISSMAN_PG_DUMP_PATH").unwrap_or_else(|_| "pg_dump".to_string());
    let stamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let dest_path = backups_dir.join(format!("weissman_pg_{}.sql", stamp));
    let dest_str = dest_path.to_str().ok_or("invalid backup path")?.to_string();
    let status = Command::new(&pg_dump)
        .args([
            "--dbname",
            database_url.as_str(),
            "--format",
            "plain",
            "--file",
            dest_str.as_str(),
            "--no-owner",
        ])
        .status()
        .map_err(|e| format!("pg_dump spawn failed ({}): {}", pg_dump, e))?;
    if !status.success() {
        metrics::counter!("weissman_backup_failure_total").increment(1);
        return Err(format!("pg_dump exited with {:?}", status.code()));
    }
    Ok(dest_path)
}

fn gzip_sql_file(sql_path: &Path) -> Result<PathBuf, String> {
    let gz_path = sql_path.with_extension("sql.gz");
    let mut raw = fs::File::open(sql_path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    raw.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let out = fs::File::create(&gz_path).map_err(|e| e.to_string())?;
    let mut enc = flate2::write::GzEncoder::new(out, flate2::Compression::default());
    enc.write_all(&buf).map_err(|e| e.to_string())?;
    enc.finish().map_err(|e| e.to_string())?;
    fs::remove_file(sql_path).map_err(|e| e.to_string())?;
    Ok(gz_path)
}

fn prune_old_backups(dir: &Path) -> Result<(), String> {
    let retention = retention_days();
    let max_files = max_backup_files();
    let cutoff = SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(retention.saturating_mul(86_400)))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut entries: Vec<(PathBuf, SystemTime)> = Vec::new();
    let read = fs::read_dir(dir).map_err(|e| e.to_string())?;
    for ent in read.flatten() {
        let name = ent.file_name();
        let name_owned = name.to_string_lossy().to_string();
        if !name_owned.starts_with("weissman_pg_")
            || (!name_owned.ends_with(".sql") && !name_owned.ends_with(".sql.gz"))
        {
            continue;
        }
        let meta = ent.metadata().map_err(|e| e.to_string())?;
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        entries.push((ent.path(), modified));
    }
    entries.sort_by_key(|(_, t)| *t);
    let mut removed_age = 0u64;
    for (path, mtime) in &entries {
        if *mtime < cutoff {
            let _ = fs::remove_file(path);
            removed_age += 1;
        }
    }
    if removed_age > 0 {
        metrics::counter!("weissman_backup_pruned_age_total").increment(removed_age);
    }
    let read2 = fs::read_dir(dir).map_err(|e| e.to_string())?;
    let mut remaining: Vec<PathBuf> = read2
        .flatten()
        .filter(|e| {
            let s = e.file_name().to_string_lossy().to_string();
            s.starts_with("weissman_pg_") && (s.ends_with(".sql") || s.ends_with(".sql.gz"))
        })
        .map(|e| e.path())
        .collect();
    remaining.sort();
    let excess = remaining.len().saturating_sub(max_files);
    if excess > 0 {
        for p in remaining.into_iter().take(excess) {
            let _ = fs::remove_file(&p);
        }
        metrics::counter!("weissman_backup_pruned_count_total").increment(excess as u64);
    }
    Ok(())
}

/// One blocking job: backup (if configured) + metrics on failure. Intended for `spawn_blocking`.
pub fn run_scheduled_backup_job() {
    match backup_postgres_if_configured() {
        Ok(Some(p)) => eprintln!("[Weissman][Backup] completed: {}", p.display()),
        Ok(None) => {}
        Err(e) => {
            eprintln!("[Weissman][Backup] failed: {}", e);
            metrics::counter!("weissman_backup_failure_total").increment(1);
        }
    }
}

/// Production loop: reads `backup_interval_secs` from default tenant config (same as legacy inline task), then runs pg_dump off the async runtime.
pub fn spawn_database_backup_scheduler(auth_pool: Arc<sqlx::PgPool>, app_pool: Arc<sqlx::PgPool>) {
    tokio::spawn(async move {
        loop {
            let interval_secs: u64 = if let Some(tid) = sqlx::query_scalar::<_, i64>(
                "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
            )
            .fetch_optional(auth_pool.as_ref())
            .await
            .ok()
            .flatten()
            {
                if let Ok(mut tx) = crate::db::begin_tenant_tx(app_pool.as_ref(), tid).await {
                    let v = sqlx::query_scalar::<_, String>(
                        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'backup_interval_secs'",
                    )
                    .bind(tid)
                    .fetch_optional(&mut *tx)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(86_400);
                    let _ = tx.commit().await;
                    v
                } else {
                    86_400
                }
            } else {
                86_400
            };
            if interval_secs == 0 {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                continue;
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            let res = tokio::task::spawn_blocking(run_scheduled_backup_job).await;
            if let Err(e) = res {
                eprintln!("[Weissman][Backup] scheduler join error: {}", e);
            }
        }
    });
}
