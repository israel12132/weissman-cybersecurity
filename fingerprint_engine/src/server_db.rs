//! Legacy SQLite bootstrap removed — schema comes from sqlx migrations only.

use std::path::Path;

/// No-op: PostgreSQL schema is applied via `crate::db::run_migrations`.
pub fn init_db(_db_path: &Path) {}
