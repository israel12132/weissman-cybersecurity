//! PostgreSQL pools — [`fingerprint_engine::db`] re-exports [`weissman_db`] pool builders.
//!
//! **Sizing (do not hold connections across slow I/O):**
//! - App: `WEISSMAN_APP_POOL_MAX` (default **48**), `WEISSMAN_APP_POOL_MIN` (default **2**), 30s acquire timeout.
//! - Auth: `WEISSMAN_AUTH_POOL_MAX` (default **12**), 15s acquire timeout.
//! - Intel (optional): `WEISSMAN_INTEL_POOL_MAX` (default **12**); see `weissman_server::run` fallback to app pool.
//!
//! Pools are created **once** at process start via `connect_*_from_env`. The
//! returned [`PgPool`] (stored on [`Pools`] / `AppState`) is the long-lived
//! handle and does not expose the original DSN. [`weissman_db::SecretUrl`] lives
//! only inside those helpers and is wiped when they return. Do **not** rebuild
//! a pool on an incoming API request.
//!
//! Handlers must **not** keep a `Transaction` open while awaiting external LLM, SSE fan-out, or long HTTP
//! clients — that starves the pool. Short `begin` → query → `commit` scopes (as in war-room SSE polling) are OK.

use sqlx::PgPool;
use std::sync::Arc;

/// Process-lifetime SQLx pools. Clone the `Arc`, never the DSN.
pub struct Pools {
    pub app: Arc<PgPool>,
    pub auth: Arc<PgPool>,
}

pub async fn connect_pools() -> Result<Pools, sqlx::Error> {
    if std::env::var("WEISSMAN_AUTH_DATABASE_URL")
        .ok()
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
    {
        // Surface the fallback: silently reusing DATABASE_URL runs login/user-management as
        // `weissman_app` instead of `weissman_auth`, discarding the role separation the migrations
        // construct — with no other signal that it happened.
        tracing::warn!(
            target: "weissman_db",
            "WEISSMAN_AUTH_DATABASE_URL unset — auth pool reusing DATABASE_URL; weissman_app/weissman_auth role separation disabled"
        );
    }
    let app = fingerprint_engine::db::connect_app_from_env().await?;
    let auth = fingerprint_engine::db::connect_auth_from_env().await?;
    // app 48 + auth 12 + intel 12 (intel is opened in lib.rs). See
    // warn_if_pool_budget_exceeds_server for why this warns at boot rather than only failing
    // under the load the pools exist to survive.
    weissman_db::warn_if_pool_budget_exceeds_server(&app, "backend", 48 + 12 + 12).await;
    Ok(Pools {
        app: Arc::new(app),
        auth: Arc::new(auth),
    })
}
