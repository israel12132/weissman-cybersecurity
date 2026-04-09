//! DB-first Genesis strategy (`system_configs` keys). Env is fallback when a key is unset.

use serde_json::{json, Value};
use sqlx::PgPool;

/// Keys writable via `PATCH /api/ceo/strategy` (tenant `system_configs`).
pub const STRATEGY_KEYS: &[&str] = &[
    "genesis_protocol_enabled",
    "genesis_kill_switch",
    "genesis_ram_budget_mb",
    "genesis_dfs_max_depth",
    "genesis_dfs_max_steps",
    "genesis_seed_repos",
    "genesis_seed_npm",
    "genesis_seed_crates",
    "genesis_seed_pypi",
    "genesis_seed_images",
];

fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key).as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

async fn cfg_get_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM system_configs WHERE key = $1",
    )
    .bind(key)
    .fetch_optional(&mut **tx)
    .await
}

/// Effective Genesis parameters for engines (DB overrides env).
#[derive(Debug, Clone)]
pub struct GenesisRuntimeParams {
    pub protocol_enabled: bool,
    pub kill_switch: bool,
    pub ram_budget_mb: u64,
    pub dfs_max_depth: usize,
    pub dfs_max_steps: usize,
    pub seed_repos: String,
    pub seed_npm: String,
    pub seed_crates: String,
    pub seed_pypi: String,
    pub seed_images: String,
}

impl GenesisRuntimeParams {
    #[must_use]
    pub fn ram_budget_bytes(&self) -> u64 {
        self.ram_budget_mb.saturating_mul(1024 * 1024)
    }

    #[must_use]
    pub fn ram_soft_limit_bytes(&self) -> u64 {
        self.ram_budget_bytes().saturating_mul(85) / 100
    }
}

async fn load_inner_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<GenesisRuntimeParams, sqlx::Error> {
    let protocol_enabled = cfg_get_tx(tx, "genesis_protocol_enabled")
        .await?
        .map(|s| matches!(s.trim(), "1" | "true" | "yes"))
        .unwrap_or_else(|| env_truthy("WEISSMAN_GENESIS_PROTOCOL"));

    let kill_switch = cfg_get_tx(tx, "genesis_kill_switch")
        .await?
        .map(|s| matches!(s.trim(), "1" | "true" | "yes"))
        .unwrap_or(false);

    let ram_budget_mb = cfg_get_tx(tx, "genesis_ram_budget_mb")
        .await?
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| {
            std::env::var("WEISSMAN_GENESIS_RAM_BUDGET_MB")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(4096)
        .max(64);

    let dfs_max_depth = cfg_get_tx(tx, "genesis_dfs_max_depth")
        .await?
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| {
            std::env::var("WEISSMAN_GENESIS_DFS_MAX_DEPTH")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(8);

    let dfs_max_steps = cfg_get_tx(tx, "genesis_dfs_max_steps")
        .await?
        .map(|s| {
            let t = s.trim();
            if t.is_empty() {
                usize::MAX
            } else {
                t.parse().unwrap_or(usize::MAX)
            }
        })
        .or_else(|| {
            std::env::var("WEISSMAN_GENESIS_DFS_MAX_STEPS")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(usize::MAX);

    let seed_repos = cfg_get_tx(tx, "genesis_seed_repos")
        .await?
        .or_else(|| std::env::var("WEISSMAN_GENESIS_SEED_REPOS").ok())
        .unwrap_or_default();
    let seed_npm = cfg_get_tx(tx, "genesis_seed_npm")
        .await?
        .or_else(|| std::env::var("WEISSMAN_GENESIS_SEED_NPM").ok())
        .unwrap_or_default();
    let seed_crates = cfg_get_tx(tx, "genesis_seed_crates")
        .await?
        .or_else(|| std::env::var("WEISSMAN_GENESIS_SEED_CRATES").ok())
        .unwrap_or_default();
    let seed_pypi = cfg_get_tx(tx, "genesis_seed_pypi")
        .await?
        .or_else(|| std::env::var("WEISSMAN_GENESIS_SEED_PYPI").ok())
        .unwrap_or_default();
    let seed_images = cfg_get_tx(tx, "genesis_seed_images")
        .await?
        .or_else(|| std::env::var("WEISSMAN_GENESIS_SEED_IMAGES").ok())
        .unwrap_or_default();

    Ok(GenesisRuntimeParams {
        protocol_enabled,
        kill_switch,
        ram_budget_mb,
        dfs_max_depth,
        dfs_max_steps,
        seed_repos,
        seed_npm,
        seed_crates,
        seed_pypi,
        seed_images,
    })
}

/// Env-only strategy (no tenant DB / sync callers).
pub fn load_env_fallback() -> GenesisRuntimeParams {
    GenesisRuntimeParams {
        protocol_enabled: env_truthy("WEISSMAN_GENESIS_PROTOCOL"),
        kill_switch: false,
        ram_budget_mb: std::env::var("WEISSMAN_GENESIS_RAM_BUDGET_MB")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4096)
            .max(64),
        dfs_max_depth: std::env::var("WEISSMAN_GENESIS_DFS_MAX_DEPTH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8),
        dfs_max_steps: std::env::var("WEISSMAN_GENESIS_DFS_MAX_STEPS")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .and_then(|s| s.parse().ok())
            .unwrap_or(usize::MAX),
        seed_repos: std::env::var("WEISSMAN_GENESIS_SEED_REPOS").unwrap_or_default(),
        seed_npm: std::env::var("WEISSMAN_GENESIS_SEED_NPM").unwrap_or_default(),
        seed_crates: std::env::var("WEISSMAN_GENESIS_SEED_CRATES").unwrap_or_default(),
        seed_pypi: std::env::var("WEISSMAN_GENESIS_SEED_PYPI").unwrap_or_default(),
        seed_images: std::env::var("WEISSMAN_GENESIS_SEED_IMAGES").unwrap_or_default(),
    }
}

/// Load merged strategy for `tenant_id` (RLS tenant transaction).
pub async fn load_genesis_runtime_params(pool: &PgPool, tenant_id: i64) -> GenesisRuntimeParams {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return load_env_fallback();
    };
    let inner = match load_inner_tx(&mut tx).await {
        Ok(p) => p,
        Err(_) => load_env_fallback(),
    };
    let _ = tx.commit().await;
    inner
}

/// JSON view for `GET /api/ceo/strategy` (includes env snapshot for transparency).
pub async fn get_ceo_strategy_json(pool: &PgPool, tenant_id: i64) -> Value {
    let p = load_genesis_runtime_params(pool, tenant_id).await;
    json!({
        "effective": {
            "genesis_protocol_enabled": p.protocol_enabled,
            "genesis_kill_switch": p.kill_switch,
            "genesis_ram_budget_mb": p.ram_budget_mb,
            "genesis_dfs_max_depth": p.dfs_max_depth,
            "genesis_dfs_max_steps": p.dfs_max_steps,
            "genesis_seed_repos": p.seed_repos,
            "genesis_seed_npm": p.seed_npm,
            "genesis_seed_crates": p.seed_crates,
            "genesis_seed_pypi": p.seed_pypi,
            "genesis_seed_images": p.seed_images,
        },
        "env_fallback_snapshot": {
            "WEISSMAN_GENESIS_PROTOCOL": std::env::var("WEISSMAN_GENESIS_PROTOCOL").unwrap_or_default(),
            "WEISSMAN_GENESIS_RAM_BUDGET_MB": std::env::var("WEISSMAN_GENESIS_RAM_BUDGET_MB").unwrap_or_default(),
            "WEISSMAN_GENESIS_DFS_MAX_DEPTH": std::env::var("WEISSMAN_GENESIS_DFS_MAX_DEPTH").unwrap_or_default(),
            "WEISSMAN_GENESIS_DFS_MAX_STEPS": std::env::var("WEISSMAN_GENESIS_DFS_MAX_STEPS").unwrap_or_default(),
            "WEISSMAN_WORKER_POOL": std::env::var("WEISSMAN_WORKER_POOL").unwrap_or_default(),
        },
    })
}

/// Merge `{ "configs": { key: value } }` into `system_configs` (whitelist only).
pub async fn patch_ceo_strategy(
    pool: &PgPool,
    tenant_id: i64,
    body: &Value,
) -> Result<(), String> {
    let obj = body
        .get("configs")
        .and_then(Value::as_object)
        .ok_or_else(|| "body.configs object required".to_string())?;
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    for (k, v) in obj {
        if !STRATEGY_KEYS.contains(&k.as_str()) {
            return Err(format!("unknown or forbidden strategy key: {k}"));
        }
        let val = if v.is_string() {
            v.as_str().unwrap_or("").to_string()
        } else if v.is_number() || v.is_boolean() {
            v.to_string()
        } else {
            return Err(format!("invalid value type for key {k}"));
        };
        sqlx::query(
            r#"INSERT INTO system_configs (tenant_id, key, value, description)
               VALUES ($1, $2, $3, 'CEO Command Center strategy')
               ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value"#,
        )
        .bind(tenant_id)
        .bind(k.as_str())
        .bind(&val)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}
