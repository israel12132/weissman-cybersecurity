//! Optional rotation of the `weissman_auth` database password using a maintenance (owner) connection.
//!
//! - `WEISSMAN_AUTH_DB_ROTATION_URL` — superuser or `CREATEROLE` URL (short-lived in CI).
//! - `WEISSMAN_AUTH_ROTATED_PASSWORD` — new password to apply (`ALTER ROLE weissman_auth PASSWORD ...`).
//!
//! Docker / zero-touch deploy: [`sync_role_passwords_from_env_on_boot`] aligns `weissman_app` and
//! `weissman_auth` passwords with `DATABASE_URL` / `WEISSMAN_AUTH_DATABASE_URL` using
//! `WEISSMAN_MIGRATE_URL` (postgres superuser) immediately after migrations.
//!
//! Peer auth: set `WEISSMAN_AUTH_DATABASE_URL` to a DSN without password, e.g.
//! `postgresql://weissman_auth@/dbname?host=/var/run/postgresql`.

use sqlx::postgres::PgPoolOptions;

fn pg_quote_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Parse `postgresql://user:password@host/db` userinfo (password may contain `:`).
fn parse_pg_user_password(url: &str) -> Option<(String, String)> {
    let rest = url
        .trim()
        .strip_prefix("postgres://")
        .or_else(|| url.trim().strip_prefix("postgresql://"))?;
    let at = rest.find('@')?;
    let userinfo = &rest[..at];
    if userinfo.is_empty() {
        return None;
    }
    let colon = userinfo.find(':')?;
    let user = userinfo[..colon].to_string();
    let password = percent_decode(&userinfo[colon + 1..]);
    if user.is_empty() || password.is_empty() {
        return None;
    }
    Some((user, password))
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(char::from(v));
                i += 3;
                continue;
            }
        }
        out.push(char::from(bytes[i]));
        i += 1;
    }
    out
}

async fn alter_role_password(
    pool: &sqlx::PgPool,
    role: &str,
    password: &str,
) -> Result<(), sqlx::Error> {
    if !role.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Ok(());
    }
    let stmt = format!(
        "ALTER ROLE {} PASSWORD {}",
        role,
        pg_quote_literal(password)
    );
    sqlx::query(&stmt).execute(pool).await?;
    tracing::info!(target: "auth_rotation", role, "database role password synced from env URL");
    Ok(())
}

/// After sqlx migrations, align role passwords with the DSNs the app will use (Docker zero-touch).
pub async fn sync_role_passwords_from_env_on_boot() -> Result<(), sqlx::Error> {
    let Some(migrate_url) = std::env::var("WEISSMAN_MIGRATE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        return Ok(());
    };

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&migrate_url)
        .await?;

    if let Ok(app_url) = std::env::var("DATABASE_URL") {
        if let Some((user, pw)) = parse_pg_user_password(&app_url) {
            alter_role_password(&pool, &user, &pw).await?;
        }
    }

    if let Some(auth_url) = std::env::var("WEISSMAN_AUTH_DATABASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        if let Some((user, pw)) = parse_pg_user_password(&auth_url) {
            alter_role_password(&pool, &user, &pw).await?;
        }
    }

    // Read-only NL→SQL role (weissman_ro). The migration creates it with a dev-default
    // password; align it here so production never keeps the shipped default. Mirrors the
    // app/auth handling above — no-op when the DSN carries no password.
    let ro_url = std::env::var("WEISSMAN_READ_ONLY_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match ro_url.as_deref().and_then(parse_pg_user_password) {
        Some((user, pw)) => {
            alter_role_password(&pool, &user, &pw).await?;
        }
        None => {
            // No read-only DSN configured. /api/ask is disabled anyway (no ro pool), so the
            // weissman_ro role is unused. In production, defence-in-depth: strip LOGIN so the
            // shipped dev-default password can never be used even if the DB port is exposed.
            let is_production = std::env::var("WEISSMAN_ENV")
                .map(|v| v.trim().eq_ignore_ascii_case("production"))
                .unwrap_or(false);
            if is_production {
                if let Err(e) = sqlx::query("ALTER ROLE weissman_ro NOLOGIN")
                    .execute(&pool)
                    .await
                {
                    tracing::warn!(
                        target: "auth_rotation",
                        error = %e,
                        "could not disable login on unused weissman_ro role (role may not exist yet)"
                    );
                } else {
                    tracing::info!(
                        target: "auth_rotation",
                        "weissman_ro has no read-only DSN in production; login disabled (defence-in-depth)"
                    );
                }
            }
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pg_user_password_handles_colons_and_encoding() {
        let (u, p) =
            parse_pg_user_password("postgresql://weissman_app:sec:ret@postgres:5432/weissman")
                .unwrap();
        assert_eq!(u, "weissman_app");
        assert_eq!(p, "sec:ret");
        let (_, p2) =
            parse_pg_user_password("postgres://weissman_auth:hel%2Blo@localhost/weissman").unwrap();
        assert_eq!(p2, "hel+lo");
    }
}
