//! Optional rotation of the `weissman_auth` database password using a maintenance (owner) connection.
//!
//! - `WEISSMAN_AUTH_DB_ROTATION_URL` — superuser or `CREATEROLE` URL (short-lived in CI).
//! - `WEISSMAN_AUTH_ROTATED_PASSWORD` — new password to apply (`ALTER ROLE weissman_auth PASSWORD ...`).
//!
//! Peer auth: set `WEISSMAN_AUTH_DATABASE_URL` to a DSN without password, e.g.
//! `postgresql://weissman_auth@/dbname?host=/var/run/postgresql`.

use sqlx::postgres::PgPoolOptions;

fn pg_quote_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Apply `ALTER ROLE weissman_auth PASSWORD ...` when rotation env vars are set.
pub async fn rotate_weissman_auth_password_on_boot() -> Result<(), sqlx::Error> {
    let Some(url) = std::env::var("WEISSMAN_AUTH_DB_ROTATION_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        return Ok(());
    };
    let Some(pw) = std::env::var("WEISSMAN_AUTH_ROTATED_PASSWORD")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        tracing::info!(
            target: "auth_rotation",
            "WEISSMAN_AUTH_DB_ROTATION_URL set but WEISSMAN_AUTH_ROTATED_PASSWORD empty; skipping"
        );
        return Ok(());
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    let stmt = format!(
        "ALTER ROLE weissman_auth PASSWORD {}",
        pg_quote_literal(&pw)
    );
    sqlx::query(&stmt).execute(&pool).await?;
    tracing::info!(target: "auth_rotation", "weissman_auth password rotated via maintenance URL");
    Ok(())
}
