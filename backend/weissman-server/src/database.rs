//! PostgreSQL pools — [`fingerprint_engine::db`] re-exports [`weissman_db`] pool builders.
//!
//! **Sizing (do not hold connections across slow I/O):**
//! - App: `WEISSMAN_APP_POOL_MAX` (default **48**), `WEISSMAN_APP_POOL_MIN` (default **2**), 30s acquire timeout.
//! - Auth: `WEISSMAN_AUTH_POOL_MAX` (default **12**), 15s acquire timeout.
//! - Intel (optional): `WEISSMAN_INTEL_POOL_MAX` (default **12**); see `weissman_server::run` fallback to app pool.
//!
//! Handlers must **not** keep a `Transaction` open while awaiting external LLM, SSE fan-out, or long HTTP
//! clients — that starves the pool. Short `begin` → query → `commit` scopes (as in war-room SSE polling) are OK.

use sqlx::PgPool;
use std::sync::Arc;

pub struct Pools {
    pub app: Arc<PgPool>,
    pub auth: Arc<PgPool>,
}

pub async fn connect_pools() -> Result<Pools, sqlx::Error> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_default();
    if let Err(msg) = weissman_db::env_bootstrap::validate_database_url(&database_url) {
        return Err(sqlx::Error::Configuration(format!("DATABASE_URL: {}", msg).into()));
    }
    let app = fingerprint_engine::db::connect_app(database_url.trim()).await?;
    let auth_url =
        std::env::var("WEISSMAN_AUTH_DATABASE_URL").unwrap_or_else(|_| database_url.clone());
    if let Err(msg) = weissman_db::env_bootstrap::validate_database_url(auth_url.trim()) {
        return Err(sqlx::Error::Configuration(
            format!("WEISSMAN_AUTH_DATABASE_URL: {}", msg).into(),
        ));
    }
    let auth = fingerprint_engine::db::connect_auth(auth_url.trim()).await?;
    Ok(Pools {
        app: Arc::new(app),
        auth: Arc::new(auth),
    })
}
