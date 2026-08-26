//! PostgreSQL: pooled connections, sqlx migrations, RLS session variable `app.current_tenant_id`.
//! App role (`weissman_app`) is subject to RLS. Auth role (`weissman_auth`) bypasses RLS for login / IdP resolution only.
//!
//! [`database_url_from_env`] and pool helpers read configuration from the process environment at runtime.

#![forbid(unsafe_code)]

pub mod advisory_lock;
pub mod auth_access;
pub mod auth_rotation;
pub mod env_bootstrap;
pub mod job_queue;
pub mod llm_usage;
pub mod no_tx_migrations;

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use std::time::Duration;

/// Primary application database URL (role `weissman_app`, RLS). Read from `DATABASE_URL` when the process starts each call.
pub fn database_url_from_env() -> Result<String, std::env::VarError> {
    std::env::var("DATABASE_URL")
}

/// Optional separate auth URL (`weissman_auth`). When unset, callers typically use the same URL as the app pool.
pub fn auth_database_url_from_env() -> Option<String> {
    std::env::var("WEISSMAN_AUTH_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve the URL used for the auth pool: `WEISSMAN_AUTH_DATABASE_URL` or `DATABASE_URL`.
pub fn resolve_auth_database_url() -> Result<String, std::env::VarError> {
    if let Some(u) = auth_database_url_from_env() {
        Ok(u)
    } else {
        database_url_from_env()
    }
}

/// Compile-time crate migrations path (valid in dev / CI where the crate tree exists).
const COMPILE_TIME_MIGRATIONS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");

/// Resolve the on-disk migrations directory for the no-tx pre-runner.
///
/// Production containers bake `CARGO_MANIFEST_DIR` at build time (`/build/crates/...`) but do
/// not ship that tree at runtime. Set `WEISSMAN_MIGRATIONS_DIR` (Docker: `/srv/migrations`) to
/// point at the copied SQL files; when unset, fall back to the compile-time crate path.
pub fn migrations_dir() -> std::path::PathBuf {
    std::env::var("WEISSMAN_MIGRATIONS_DIR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(COMPILE_TIME_MIGRATIONS_DIR))
}

/// Superuser or owner URL to run embedded migrations (optional at runtime).
///
/// Two-phase application:
///   1. [`no_tx_migrations::apply_no_tx_migrations`] handles any file whose first
///      line is `-- weissman:no-transaction` — these are executed OUTSIDE a
///      transaction (CREATE INDEX CONCURRENTLY etc.) and their rows are recorded
///      in `_sqlx_migrations` manually with the SQLx-compatible SHA-384 checksum.
///   2. `sqlx::migrate!()` then runs as usual; it sees the no-tx files as
///      already applied and skips them.
///
/// On a CI/CD pipeline this means: zero downtime, zero manual intervention,
/// zero "did we remember to apply the index" tickets. Failure modes:
///   - DB unreachable → propagated as `MigrateError::Database`.
///   - File checksum drift → propagated with a clear "edit detected" message.
///   - Concurrent index creation failure → the row is NOT inserted; next boot
///     re-attempts (the file uses `IF NOT EXISTS` / `IF EXISTS` for idempotency).
pub async fn run_migrations(database_url: &str) -> Result<(), sqlx::migrate::MigrateError> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url)
        .await
        .map_err(sqlx::migrate::MigrateError::from)?;

    // Phase 1 — no-transaction migrations (CONCURRENTLY index builds, etc.).
    // Reads from disk via [`migrations_dir`] (runtime `WEISSMAN_MIGRATIONS_DIR` or compile-time
    // crate path). Phase 2 embeds SQL at compile time via `sqlx::migrate!`.
    let migrations_dir = migrations_dir();
    let deferred = match no_tx_migrations::apply_no_tx_migrations(&pool, &migrations_dir).await {
        Ok(d) => {
            if !d.is_empty() {
                tracing::info!(
                    target: "weissman_db",
                    deferred = d.len(),
                    "no-tx migrations deferred until their dependencies are created by regular migrations"
                );
            }
            d
        }
        Err(e) => {
            tracing::error!(target: "weissman_db", error = %e, "no-tx migration failed");
            // Surface as a generic MigrateError so the caller's error path is unchanged.
            return Err(sqlx::migrate::MigrateError::Source(Box::new(e)));
        }
    };

    // Phase 2 — standard transactional migrations (these create the tables that
    // any deferred no-tx index builds depend on).
    sqlx::migrate!("./migrations").run(&pool).await?;

    // Phase 3 — finalize no-tx migrations deferred in phase 1 now that phase 2 has
    // created their dependencies (e.g. CREATE INDEX CONCURRENTLY on a table that a
    // regular migration just created). No-op on already-migrated databases.
    if !deferred.is_empty() {
        if let Err(e) = no_tx_migrations::apply_deferred_no_tx_migrations(&pool, deferred).await {
            tracing::error!(target: "weissman_db", error = %e, "deferred no-tx migration failed");
            return Err(sqlx::migrate::MigrateError::Source(Box::new(e)));
        }
    }
    Ok(())
}

/// Warn loudly when this process's configured pool ceilings cannot all fit in the server's
/// connection budget.
///
/// The deployment was found configured to open up to 152 connections (backend 72 + worker 80)
/// against a server `max_connections` of 100, with no pooler in front. Nothing detected that,
/// because it only manifests under the concurrent load the pools exist to survive: past ~97
/// in-use slots every further connect fails with SQLSTATE 53300, and the first casualty is
/// whichever pool happens to be opening a connection at that moment — including the worker's
/// control-plane pool, which exists precisely so job-state writes can never be starved.
///
/// This warns rather than refuses to start. A process that declines to boot because the *other*
/// process might also be busy would turn a capacity smell into an outage, and the safe reading
/// ("how many connections is the rest of the fleet actually holding?") is not knowable from here.
/// The point is to make the condition visible at boot instead of at 3am under load.
pub async fn warn_if_pool_budget_exceeds_server(
    pool: &PgPool,
    process_label: &str,
    configured: u32,
) {
    let Ok(max_conn) = sqlx::query_scalar::<_, String>("SHOW max_connections")
        .fetch_one(pool)
        .await
    else {
        return;
    };
    let reserved = sqlx::query_scalar::<_, String>("SHOW superuser_reserved_connections")
        .fetch_one(pool)
        .await
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(3);
    let Ok(max_conn) = max_conn.parse::<u32>() else {
        return;
    };
    let usable = max_conn.saturating_sub(reserved);
    // A single process claiming more than half the budget cannot coexist with its sibling.
    if configured * 2 > usable {
        tracing::warn!(
            target: "db_pool_budget",
            process = process_label,
            configured_max_connections = configured,
            server_max_connections = max_conn,
            usable_after_reserved = usable,
            "connection pool ceiling is too large for this Postgres: two processes at this size \
             over-subscribe the server and will hit SQLSTATE 53300 under load. Raise \
             max_connections (compose and deploy/k8s/postgres-ha.yaml both set 200) or lower \
             WEISSMAN_{{APP,AUTH,INTEL,CONTROL}}_POOL_MAX."
        );
    }
}

fn env_u32(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

fn env_u64(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

fn duration_from_ms_env(var: &str, default_ms: u64, floor_ms: u64) -> Duration {
    Duration::from_millis(env_u64(var, default_ms).max(floor_ms))
}

fn worker_pool_floor() -> Option<u32> {
    let heavy = std::env::var("WEISSMAN_WORKER_HEAVY_CONCURRENCY")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)?;
    let light = std::env::var("WEISSMAN_WORKER_LIGHT_CONCURRENCY")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(8);
    // Heavy jobs are the pool-hungry path (engine execution + persistence + follow-up writes). Keep
    // enough headroom for them plus a few light jobs so raising heavy concurrency never silently
    // under-provisions the worker app pool.
    Some(
        heavy
            .saturating_mul(10)
            .saturating_add(light.min(4).saturating_mul(2)),
    )
}

fn worker_pool_warm_min(max: u32) -> u32 {
    let heavy = std::env::var("WEISSMAN_WORKER_HEAVY_CONCURRENCY")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(2);
    env_u32("WEISSMAN_APP_POOL_MIN", heavy.saturating_mul(2).max(8)).min(max)
}

fn is_transient_acquire_error(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => true,
        sqlx::Error::Io(_) => true,
        sqlx::Error::Database(db) => matches!(db.code().as_deref(), Some("53300" | "57P03")),
        _ => false,
    }
}

fn acquire_retry_attempts() -> u32 {
    env_u32("WEISSMAN_DB_ACQUIRE_RETRIES", 3).max(1)
}

fn acquire_retry_backoff(attempt: u32) -> Duration {
    let base_ms = env_u64("WEISSMAN_DB_ACQUIRE_BACKOFF_MS", 200).max(25);
    let cap_ms = env_u64("WEISSMAN_DB_ACQUIRE_BACKOFF_CAP_MS", 2_000).max(base_ms);
    let shift = attempt.saturating_sub(1).min(6);
    Duration::from_millis(base_ms.saturating_mul(1_u64 << shift).min(cap_ms))
}

async fn connect_app_with_pool_tuning(
    database_url: &str,
    max: u32,
    min: u32,
    acquire_timeout: Duration,
    stmt_ms: u64,
) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max)
        .min_connections(min)
        .acquire_timeout(acquire_timeout)
        .after_connect(move |conn, _| {
            Box::pin(async move {
                // Server-side statement timeout bulkheads a pathological/blocked query so it
                // can't pin a pooled connection indefinitely and exhaust the pool.
                sqlx::query(&format!("SET statement_timeout = {stmt_ms}"))
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
}

/// App pool: `WEISSMAN_APP_POOL_MAX` (default 48), `WEISSMAN_APP_POOL_MIN` (default 2).
/// Avoid holding a tenant transaction across `.await` to unrelated work — release connections quickly.
pub async fn connect_app(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let max = env_u32("WEISSMAN_APP_POOL_MAX", 48);
    let min = env_u32("WEISSMAN_APP_POOL_MIN", 2).min(max);
    let stmt_ms = statement_timeout_ms("WEISSMAN_APP_STATEMENT_TIMEOUT_MS", 120_000);
    connect_app_with_pool_tuning(database_url, max, min, Duration::from_secs(30), stmt_ms).await
}

/// Worker app pool: auto-raises undersized ceilings when heavy concurrency is increased, keeps a
/// warm minimum so long-lived scans do not cold-open connections on the hot path, and uses shorter
/// per-attempt acquire timeouts so retry/backoff can react before a 30s wall-clock stall accrues.
pub async fn connect_worker_app(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let requested = env_u32("WEISSMAN_APP_POOL_MAX", 48);
    let floor = worker_pool_floor().unwrap_or(requested);
    let max = requested.max(floor);
    if max > requested {
        tracing::info!(
            target: "weissman_db",
            requested_max = requested,
            raised_max = max,
            heavy_concurrency = std::env::var("WEISSMAN_WORKER_HEAVY_CONCURRENCY").ok(),
            light_concurrency = std::env::var("WEISSMAN_WORKER_LIGHT_CONCURRENCY").ok(),
            "raising worker app pool ceiling to match configured concurrency"
        );
    }
    let min = worker_pool_warm_min(max);
    let acquire_timeout = duration_from_ms_env("WEISSMAN_WORKER_DB_ACQUIRE_TIMEOUT_MS", 8_000, 250);
    let stmt_ms = statement_timeout_ms("WEISSMAN_APP_STATEMENT_TIMEOUT_MS", 120_000);
    connect_app_with_pool_tuning(database_url, max, min, acquire_timeout, stmt_ms).await
}

/// Per-connection `statement_timeout` in milliseconds (0 disables). Tunable per pool via env.
fn statement_timeout_ms(var: &str, default_ms: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default_ms)
}

/// Control-plane pool: `WEISSMAN_CONTROL_POOL_MAX` (default 8). Dedicated to durable job-queue
/// state operations (claim/reserve, heartbeat, completion/failure projection) so they can never
/// be starved by the engine-execution `app` pool. Engine scans acquire many `app` connections for
/// the duration of a run; routing the worker's job-STATE writes through a separate, tiny pool keeps
/// the control plane responsive even while the data plane (a running scan) holds every app slot.
/// Short statement timeout — these are all fast single-row UPDATEs / event appends.
pub async fn connect_control(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let max: u32 = std::env::var("WEISSMAN_CONTROL_POOL_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(8);
    let stmt_ms = statement_timeout_ms("WEISSMAN_CONTROL_STATEMENT_TIMEOUT_MS", 30_000);
    PgPoolOptions::new()
        .max_connections(max)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .after_connect(move |conn, _| {
            Box::pin(async move {
                sqlx::query(&format!("SET statement_timeout = {stmt_ms}"))
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
}

/// Connect app pool using `DATABASE_URL` from the environment.
pub async fn connect_app_from_env() -> Result<PgPool, sqlx::Error> {
    let url = database_url_from_env()
        .map_err(|e| sqlx::Error::Configuration(format!("DATABASE_URL: {}", e).into()))?;
    let t = url.trim();
    if t.is_empty() {
        return Err(sqlx::Error::Configuration(
            "DATABASE_URL is set but empty".into(),
        ));
    }
    // Guard against a DSN with no `user@` (libpq would silently fall back to the OS user, e.g.
    // `root` under systemd) — the same check `connect_intel_from_env` applies.
    env_bootstrap::validate_database_url(t)
        .map_err(|msg| sqlx::Error::Configuration(format!("DATABASE_URL: {}", msg).into()))?;
    connect_app(t).await
}

/// Auth pool: `WEISSMAN_AUTH_POOL_MAX` (default 12). Smaller than app pool; login/bootstrap only.
pub async fn connect_auth(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let max: u32 = std::env::var("WEISSMAN_AUTH_POOL_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let stmt_ms = statement_timeout_ms("WEISSMAN_AUTH_STATEMENT_TIMEOUT_MS", 30_000);
    PgPoolOptions::new()
        .max_connections(max)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(15))
        .after_connect(move |conn, _| {
            Box::pin(async move {
                sqlx::query(&format!("SET statement_timeout = {stmt_ms}"))
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
}

/// Connect auth pool using `WEISSMAN_AUTH_DATABASE_URL` or `DATABASE_URL`.
pub async fn connect_auth_from_env() -> Result<PgPool, sqlx::Error> {
    let url = resolve_auth_database_url()
        .map_err(|e| sqlx::Error::Configuration(format!("auth database URL: {}", e).into()))?;
    let t = url.trim();
    if t.is_empty() {
        return Err(sqlx::Error::Configuration(
            "resolved auth database URL is empty".into(),
        ));
    }
    // Same OS-user fallback guard as the app/intel pools (peer-auth DSNs with `user@/db?host=…`
    // still pass — they carry a non-empty userinfo before `@`).
    env_bootstrap::validate_database_url(t)
        .map_err(|msg| sqlx::Error::Configuration(format!("auth database URL: {}", msg).into()))?;
    connect_auth(t).await
}

/// URL for the intel / global-payload pool. Defaults to `DATABASE_URL` when unset.
pub fn intel_database_url_from_env() -> Result<String, std::env::VarError> {
    std::env::var("WEISSMAN_INTEL_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))
}

/// Pool with `search_path = intel, public` so global payload tables stay isolated from tenant-heavy `public` usage.
pub async fn connect_intel(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let max: u32 = std::env::var("WEISSMAN_INTEL_POOL_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    PgPoolOptions::new()
        .max_connections(max)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .after_connect(move |conn, _| {
            let stmt_ms = statement_timeout_ms("WEISSMAN_INTEL_STATEMENT_TIMEOUT_MS", 120_000);
            Box::pin(async move {
                sqlx::query("SET search_path TO intel, public")
                    .execute(&mut *conn)
                    .await?;
                sqlx::query(&format!("SET statement_timeout = {stmt_ms}"))
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
}

pub async fn connect_intel_from_env() -> Result<PgPool, sqlx::Error> {
    let url = intel_database_url_from_env().map_err(|e| {
        sqlx::Error::Configuration(
            format!("WEISSMAN_INTEL_DATABASE_URL / DATABASE_URL: {}", e).into(),
        )
    })?;
    let t = url.trim();
    if t.is_empty() {
        return Err(sqlx::Error::Configuration(
            "intel database URL is empty".into(),
        ));
    }
    env_bootstrap::validate_database_url(t).map_err(|msg| {
        sqlx::Error::Configuration(format!("WEISSMAN_INTEL_DATABASE_URL: {}", msg).into())
    })?;
    connect_intel(t).await
}

/// Set the RLS GUC **and** the lock-wait bound for this transaction only (`true` =
/// transaction-local, reverted automatically at commit/rollback — it cannot leak onto a pooled
/// connection).
///
/// # Why `lock_timeout` is set here
///
/// Every tenant transaction in the workspace funnels through this call, which makes it the one
/// place where "no wait in this transaction is unbounded" can be established for present *and*
/// future call sites, instead of relying on each one to remember.
///
/// The bound matters because `SELECT … FOR UPDATE` waits forever by default, exactly like the
/// advisory locks in [`advisory_lock`] — and for exactly the same reason it went unnoticed: the
/// product pools set `statement_timeout`, so the wait dies (crudely) in production, while every
/// test pool is a bare `PgPoolOptions::new()` with `lock_timeout = 0` and
/// `statement_timeout = 0`, i.e. *infinite*. A contended row lock under `cargo test` therefore
/// hung the whole test binary with no diagnostic — the failure documented in
/// `docs/TECH_DEBT_flaky_db_test_hang.md`.
///
/// Both GUCs go in **one** `SELECT`, so this costs no extra round trip over the RLS GUC alone.
/// `set_config` is used rather than `SET LOCAL` precisely because it composes into that single
/// statement and takes its value as a bind parameter.
///
/// This does not weaken serialization: a contended lock now fails fast with SQLSTATE `55P03`
/// and the transaction aborts, so the protected work is never performed unserialized.
pub async fn set_tenant_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
) -> Result<(), sqlx::Error> {
    set_tenant_tx_scoped(tx, tenant_id, None).await
}

/// Stamp tenant + optional customer-client RLS GUCs on an open transaction.
///
/// `client_id = None` (or empty GUC) means owner/staff/worker: every client in
/// the tenant remains visible. A concrete id locks portal users to that customer.
pub async fn set_tenant_tx_scoped(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<(), sqlx::Error> {
    let client_guc = client_id.map(|id| id.to_string()).unwrap_or_default();
    sqlx::query(
        "SELECT set_config('app.current_tenant_id', $1, true), \
                set_config('app.current_client_id', $2, true), \
                set_config('lock_timeout', $3, true)",
    )
    .bind(tenant_id.to_string())
    .bind(client_guc)
    .bind(advisory_lock::lock_timeout_setting())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn begin_tenant_tx(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    begin_tenant_tx_scoped(pool, tenant_id, None).await
}

pub async fn begin_tenant_tx_scoped(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    set_tenant_tx_scoped(&mut tx, tenant_id, client_id).await?;
    Ok(tx)
}

/// Ids of all active tenants, for background workers that must sweep every tenant.
///
/// **Do not** open-code `SELECT id FROM tenants WHERE active = true` for this. `tenants` is FORCE
/// ROW LEVEL SECURITY with `USING (id = <current tenant>)`, so that query on an RLS-subject pool
/// silently returns only the connection's current tenant — and nothing at all once the tenant GUC
/// is unset, which is the correct default state. A worker written that way does not fail; it
/// iterates an empty list and reports success, which is how three sweeps (`self_improve`,
/// `sovereign_self_scan`, `predictive_analyzer`) came to run against exactly one tenant.
///
/// Backed by the `public.active_tenant_ids()` SECURITY DEFINER function (migration
/// `20260811000200`), which returns ids only — never tenant names or slugs — so a worker that
/// needs to enumerate does not have to be handed a BYPASSRLS connection.
pub async fn active_tenant_ids(pool: &PgPool) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar("SELECT * FROM public.active_tenant_ids()")
        .fetch_all(pool)
        .await
}

/// Like [`begin_tenant_tx`], but takes an owned [`Arc`] so the returned future is [`Send`] when used
/// from long-lived tasks (e.g. panic-shielded orchestrator cycles) without capturing `&PgPool`.
pub async fn begin_tenant_tx_arc(
    pool: Arc<PgPool>,
    tenant_id: i64,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    begin_tenant_tx_arc_scoped(pool, tenant_id, None).await
}

pub async fn begin_tenant_tx_arc_scoped(
    pool: Arc<PgPool>,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    set_tenant_tx_scoped(&mut tx, tenant_id, client_id).await?;
    Ok(tx)
}

/// Acquire a tenant transaction with bounded retry/backoff on transient pool-acquisition failures.
///
/// Worker-heavy code should prefer this over open-coded `pool.begin()` retries so the backoff
/// policy stays consistent across engines and queue executors.
pub async fn begin_tenant_tx_arc_retrying(
    pool: Arc<PgPool>,
    tenant_id: i64,
    op: &str,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let attempts = acquire_retry_attempts();
    let mut last_err: Option<sqlx::Error> = None;
    for attempt in 1..=attempts {
        match begin_tenant_tx_arc(pool.clone(), tenant_id).await {
            Ok(tx) => return Ok(tx),
            Err(e) if is_transient_acquire_error(&e) => {
                last_err = Some(e);
                if attempt < attempts {
                    let backoff = acquire_retry_backoff(attempt);
                    tracing::warn!(
                        target: "weissman_db",
                        tenant_id,
                        op,
                        attempt,
                        attempts,
                        backoff_ms = backoff.as_millis() as u64,
                        error = %last_err.as_ref().expect("just set last_err"),
                        "transient DB acquire failure; backing off before retry"
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| sqlx::Error::Protocol("retry loop exhausted".into())))
}

/// Bootstrap admin from env into `default` tenant (auth pool; BYPASSRLS).
/// Password material is never hardcoded unless `WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=1` (dev only).
pub async fn ensure_admin_user(auth_pool: &PgPool) -> Result<(), sqlx::Error> {
    let email =
        std::env::var("WEISSMAN_ADMIN_EMAIL").unwrap_or_else(|_| "admin@localhost".to_string());
    let hash_opt = std::env::var("WEISSMAN_ADMIN_BCRYPT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("WEISSMAN_ADMIN_PASSWORD")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .and_then(|p| bcrypt::hash(&p, bcrypt::DEFAULT_COST).ok())
        })
        .or_else(|| {
            if matches!(
                std::env::var("WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD").as_deref(),
                Ok("1") | Ok("true") | Ok("yes")
            ) {
                bcrypt::hash("changeme", bcrypt::DEFAULT_COST).ok()
            } else {
                None
            }
        });
    let Some(hash) = hash_opt else {
        tracing::debug!(
            target: "security_audit",
            "ensure_admin_user skipped: set WEISSMAN_ADMIN_PASSWORD, WEISSMAN_ADMIN_BCRYPT, or WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=1 (dev)"
        );
        return Ok(());
    };
    let tid: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
    )
    .fetch_optional(auth_pool)
    .await?;
    let Some(tenant_id) = tid else {
        return Ok(());
    };
    auth_access::record_auth_access(auth_pool, tenant_id, "ensure_admin_user").await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth.v_user_lookup WHERE tenant_id = $1 AND lower(trim(email)) = lower(trim($2)))",
    )
    .bind(tenant_id)
    .bind(&email)
    .fetch_one(auth_pool)
    .await?;
    if exists {
        return Ok(());
    }
    auth_access::insert_user_auth(auth_pool, tenant_id, &email, Some(&hash), "admin").await?;
    Ok(())
}

/// One-time bootstrap admin in `default` tenant when **`WEISSMAN_MASTER_BOOTSTRAP_EMAIL`** is set together with
/// `WEISSMAN_MASTER_BOOTSTRAP_PASSWORD` or `WEISSMAN_MASTER_BOOTSTRAP_BCRYPT`. No hardcoded identity in source.
pub async fn ensure_master_bootstrap_user(auth_pool: &PgPool) -> Result<(), sqlx::Error> {
    let email = std::env::var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(email) = email else {
        tracing::debug!(
            target: "security_audit",
            "master bootstrap skipped: set WEISSMAN_MASTER_BOOTSTRAP_EMAIL (and password or bcrypt hash env)"
        );
        return Ok(());
    };
    let hash_opt = std::env::var("WEISSMAN_MASTER_BOOTSTRAP_BCRYPT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("WEISSMAN_MASTER_BOOTSTRAP_PASSWORD")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .and_then(|p| bcrypt::hash(&p, bcrypt::DEFAULT_COST).ok())
        });
    let Some(hash) = hash_opt else {
        tracing::debug!(
            target: "security_audit",
            "master bootstrap skipped: set WEISSMAN_MASTER_BOOTSTRAP_PASSWORD or WEISSMAN_MASTER_BOOTSTRAP_BCRYPT"
        );
        return Ok(());
    };
    let tid: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
    )
    .fetch_optional(auth_pool)
    .await?;
    let Some(tenant_id) = tid else {
        return Ok(());
    };
    auth_access::record_auth_access(auth_pool, tenant_id, "ensure_master_bootstrap_user").await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth.v_user_lookup WHERE tenant_id = $1 AND lower(trim(email)) = lower(trim($2)))",
    )
    .bind(tenant_id)
    .bind(&email)
    .fetch_one(auth_pool)
    .await?;
    if exists {
        return Ok(());
    }
    auth_access::insert_user_auth(auth_pool, tenant_id, &email, Some(&hash), "admin").await?;
    tracing::info!(
        target: "security_audit",
        email = %email,
        "master bootstrap admin user created (credentials from env only)"
    );
    Ok(())
}

#[cfg(test)]
mod url_and_path_helper_tests {
    use super::{
        acquire_retry_backoff, auth_database_url_from_env, database_url_from_env, migrations_dir,
        resolve_auth_database_url, worker_pool_floor, worker_pool_warm_min,
    };
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    #[test]
    fn migrations_dir_is_always_a_non_empty_path() {
        // With WEISSMAN_MIGRATIONS_DIR set we get that path; unset, we fall back to the
        // compile-time crate path. Either way the resolved directory is non-empty — a caller
        // can always attempt to read migrations from it.
        let dir = migrations_dir();
        assert!(!dir.as_os_str().is_empty());
    }

    #[test]
    fn url_resolvers_execute_and_stay_consistent() {
        // Env-agnostic: the runner may set any combination of DATABASE_URL /
        // WEISSMAN_AUTH_DATABASE_URL. Exercise every resolver body without asserting a specific
        // URL, then check the one invariant that holds for any environment: when no explicit auth
        // URL is configured, the auth resolver mirrors the app URL resolution (Ok/Err alike).
        let _ = database_url_from_env();
        let explicit_auth = auth_database_url_from_env();
        let resolved = resolve_auth_database_url();
        match explicit_auth {
            Some(u) => assert_eq!(resolved.ok().as_deref(), Some(u.as_str())),
            None => assert_eq!(resolved.is_ok(), database_url_from_env().is_ok()),
        }
    }

    #[test]
    fn worker_pool_floor_tracks_concurrency() {
        let _guard = env_lock();
        std::env::set_var("WEISSMAN_WORKER_HEAVY_CONCURRENCY", "4");
        std::env::set_var("WEISSMAN_WORKER_LIGHT_CONCURRENCY", "8");
        assert_eq!(worker_pool_floor(), Some(48));
        std::env::remove_var("WEISSMAN_WORKER_HEAVY_CONCURRENCY");
        std::env::remove_var("WEISSMAN_WORKER_LIGHT_CONCURRENCY");
    }

    #[test]
    fn worker_pool_warm_min_is_bounded_by_pool_ceiling() {
        let _guard = env_lock();
        std::env::remove_var("WEISSMAN_APP_POOL_MIN");
        std::env::set_var("WEISSMAN_WORKER_HEAVY_CONCURRENCY", "4");
        assert_eq!(worker_pool_warm_min(6), 6);
        assert_eq!(worker_pool_warm_min(64), 8);
        std::env::remove_var("WEISSMAN_WORKER_HEAVY_CONCURRENCY");
    }

    #[test]
    fn acquire_retry_backoff_grows_and_caps() {
        let _guard = env_lock();
        std::env::remove_var("WEISSMAN_DB_ACQUIRE_BACKOFF_MS");
        std::env::remove_var("WEISSMAN_DB_ACQUIRE_BACKOFF_CAP_MS");
        assert_eq!(
            acquire_retry_backoff(1),
            std::time::Duration::from_millis(200)
        );
        assert_eq!(
            acquire_retry_backoff(2),
            std::time::Duration::from_millis(400)
        );
        assert_eq!(
            acquire_retry_backoff(20),
            std::time::Duration::from_millis(2_000)
        );
    }
}
