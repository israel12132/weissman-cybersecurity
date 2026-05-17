//! Enterprise Weissman HTTP entry: **only** supported production server — CORS, security headers,
//! global rate limits, tuned pools via `fingerprint_engine::db`.

pub mod api;
pub mod database;
pub mod middleware;

use std::path::PathBuf;

/// Static assets for `/command-center/` (React).
pub fn resolve_static_dir() -> Option<PathBuf> {
    std::env::var("WEISSMAN_STATIC")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .or_else(|| {
            let cwd = std::env::current_dir().ok()?;
            let mut p = cwd.clone();
            p.push("frontend");
            p.push("dist");
            if p.exists() {
                return Some(p);
            }
            let mut p = cwd;
            p.push("..");
            p.push("frontend");
            p.push("dist");
            if p.exists() {
                return Some(p.canonicalize().unwrap_or(p));
            }
            None
        })
}

pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fingerprint_engine::auth_jwt::init_jwt_secret_from_env().map_err(|msg| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
    })?;
    let database_url = std::env::var("DATABASE_URL").unwrap_or_default();
    if database_url.trim().is_empty() {
        return Err("DATABASE_URL is not set (check EnvironmentFile= and weissman_db::env_bootstrap::load_process_environment)".into());
    }
    weissman_db::env_bootstrap::validate_database_url(database_url.trim())
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    if let Ok(migrate_url) = std::env::var("WEISSMAN_MIGRATE_URL") {
        let u = migrate_url.trim();
        if !u.is_empty() {
            weissman_db::env_bootstrap::validate_database_url(u).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "WEISSMAN_MIGRATE_URL: {} (missing user before @ makes libpq use OS user, e.g. root)",
                        e
                    ),
                )
            })?;
            fingerprint_engine::db::run_migrations(u).await?;
        }
    }
    let pools = database::connect_pools().await?;
    weissman_db::auth_rotation::rotate_weissman_auth_password_on_boot()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    fingerprint_engine::db::ensure_admin_user(&pools.auth).await?;
    fingerprint_engine::db::ensure_master_bootstrap_user(&pools.auth).await?;
    let intel_pool = match weissman_db::connect_intel_from_env().await {
        Ok(p) => std::sync::Arc::new(p),
        Err(e) => {
            tracing::warn!(
                target: "weissman_db",
                error = %e,
                "intel pool failed; falling back to app pool (set WEISSMAN_INTEL_DATABASE_URL or fix DB)"
            );
            pools.app.clone()
        }
    };
    let state = fingerprint_engine::http::new_app_state(
        pools.app.clone(),
        pools.auth.clone(),
        intel_pool,
    );
    fingerprint_engine::http::spawn_http_background_tasks(&state);
    let static_dir = resolve_static_dir();
    let router = api::routes::build_full_router(state, static_dir).await;
    let router = middleware::cors::apply(router);
    let router = middleware::security_headers::apply(router);
    let router = middleware::rate_limiter::apply_global_rate_limit(router);
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);
    fingerprint_engine::http::run_http_tcp_listener(router, port).await;
    Ok(())
}
