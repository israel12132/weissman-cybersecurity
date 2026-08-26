//! Classified platform key cockpit — catalog, encrypted persistence, live env overlay.
//!
//! GET never returns secret values. PUT encrypts with the CEO vault cipher (`wzv1:`),
//! writes `platform_keyring`, applies `std::env::set_var` so LLM/intel/SMTP pick the
//! value up immediately when they read process env, and mirrors a handful of tenant
//! `system_configs` keys that engines already load from the DB.

use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};

use super::vault::{decrypt_secret, encrypt_secret};

const VAULT_PREFIX: &str = "wzv1:";

#[derive(Clone, Copy, Debug)]
pub struct KeySpec {
    pub env_name: &'static str,
    pub aliases: &'static [&'static str],
    pub category: &'static str,
    pub is_secret: bool,
    pub requires_restart: bool,
    pub tier: &'static str,
    pub system_config_key: Option<&'static str>,
}

const fn spec(
    env_name: &'static str,
    aliases: &'static [&'static str],
    category: &'static str,
    is_secret: bool,
    requires_restart: bool,
    tier: &'static str,
    system_config_key: Option<&'static str>,
) -> KeySpec {
    KeySpec {
        env_name,
        aliases,
        category,
        is_secret,
        requires_restart,
        tier,
        system_config_key,
    }
}

/// Every known deployment key the classified cockpit surfaces.
pub static CATALOG: &[KeySpec] = &[
    // ── Core / bootstrap ──────────────────────────────────────────────────
    spec("DATABASE_URL", &[], "core", true, true, "required", None),
    spec(
        "WEISSMAN_AUTH_DATABASE_URL",
        &[],
        "core",
        true,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_READ_ONLY_DATABASE_URL",
        &[],
        "core",
        true,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_INTEL_DATABASE_URL",
        &[],
        "core",
        true,
        true,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_MIGRATE_URL",
        &[],
        "core",
        true,
        true,
        "required",
        None,
    ),
    spec("REDIS_URL", &[], "core", true, true, "required", None),
    spec("REDIS_PASSWORD", &[], "core", true, true, "optional", None),
    spec(
        "WEISSMAN_JWT_SECRET",
        &[],
        "core",
        true,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_JOB_ORCHESTRATOR_SECRET",
        &[],
        "core",
        true,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_PUBLIC_URL",
        &[],
        "core",
        false,
        false,
        "recommended",
        None,
    ),
    spec(
        "WEISSMAN_PUBLIC_BASE_URL",
        &[],
        "core",
        false,
        false,
        "recommended",
        None,
    ),
    // ── Auth bootstrap ────────────────────────────────────────────────────
    spec(
        "WEISSMAN_ADMIN_EMAIL",
        &[],
        "auth",
        false,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_ADMIN_PASSWORD",
        &[],
        "auth",
        true,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_MASTER_BOOTSTRAP_EMAIL",
        &[],
        "auth",
        false,
        true,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_MASTER_BOOTSTRAP_PASSWORD",
        &[],
        "auth",
        true,
        true,
        "optional",
        None,
    ),
    // ── LLM / Ask Weissman / Council ──────────────────────────────────────
    spec(
        "WEISSMAN_LLM_BASE_URL",
        &["OPENAI_BASE_URL", "LLM_BASE_URL"],
        "llm",
        false,
        false,
        "required",
        Some("llm_base_url"),
    ),
    spec(
        "WEISSMAN_LLM_API_KEY",
        &["OPENAI_API_KEY"],
        "llm",
        true,
        false,
        "recommended",
        None,
    ),
    spec(
        "WEISSMAN_LLM_MODEL",
        &[],
        "llm",
        false,
        false,
        "required",
        Some("llm_model"),
    ),
    spec(
        "WEISSMAN_NL_QUERY_MODEL",
        &[],
        "llm",
        false,
        false,
        "recommended",
        None,
    ),
    spec(
        "HUGGING_FACE_HUB_TOKEN",
        &[],
        "llm",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_LLM_HANDSHAKE_SECRET",
        &[],
        "llm",
        true,
        false,
        "optional",
        None,
    ),
    // ── Threat intel feeds ────────────────────────────────────────────────
    spec(
        "NVD_API_KEY",
        &[],
        "intel",
        true,
        false,
        "recommended",
        None,
    ),
    spec(
        "GITHUB_TOKEN",
        &["WEISSMAN_GITHUB_TOKEN"],
        "intel",
        true,
        false,
        "recommended",
        Some("github_token"),
    ),
    spec(
        "SHODAN_API_KEY",
        &[],
        "intel",
        true,
        false,
        "optional",
        None,
    ),
    spec("CENSYS_API_ID", &[], "intel", true, false, "optional", None),
    spec(
        "CENSYS_API_SECRET",
        &[],
        "intel",
        true,
        false,
        "optional",
        None,
    ),
    // ── Billing ───────────────────────────────────────────────────────────
    spec(
        "PADDLE_API_KEY",
        &[],
        "billing",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "PADDLE_WEBHOOK_SECRET",
        &[],
        "billing",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "PADDLE_ENVIRONMENT",
        &[],
        "billing",
        false,
        false,
        "optional",
        None,
    ),
    // ── Notifications ─────────────────────────────────────────────────────
    spec(
        "WEISSMAN_ALERT_WEBHOOK_URL",
        &["NOTIFY_URL"],
        "notify",
        true,
        false,
        "recommended",
        None,
    ),
    spec(
        "SLACK_WEBHOOK_URL",
        &[],
        "notify",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_SLACK_SIGNING_SECRET",
        &[],
        "notify",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_SMTP_HOST",
        &["SMTP_HOST"],
        "notify",
        false,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_SMTP_PORT",
        &["SMTP_PORT"],
        "notify",
        false,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_SMTP_USER",
        &["SMTP_USER"],
        "notify",
        false,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_SMTP_PASSWORD",
        &["SMTP_PASSWORD"],
        "notify",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_SMTP_FROM",
        &[],
        "notify",
        false,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_SMTP_TO",
        &["ALERT_EMAIL_TO"],
        "notify",
        false,
        false,
        "optional",
        None,
    ),
    // ── CI/CD ─────────────────────────────────────────────────────────────
    spec(
        "WEISSMAN_CICD_WEBHOOK_SECRET",
        &[],
        "cicd",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_CICD_BEARER_TOKEN",
        &[],
        "cicd",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_GITLAB_TOKEN",
        &[],
        "cicd",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_GITLAB_WEBHOOK_SECRET",
        &[],
        "cicd",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_GITLAB_BASE_URL",
        &[],
        "cicd",
        false,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_BITBUCKET_WEBHOOK_SECRET",
        &[],
        "cicd",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_BITBUCKET_USER",
        &[],
        "cicd",
        false,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_BITBUCKET_APP_PASSWORD",
        &[],
        "cicd",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_DECEPTION_WEBHOOK_SECRET",
        &[],
        "cicd",
        true,
        false,
        "optional",
        None,
    ),
    // ── Cloud ─────────────────────────────────────────────────────────────
    spec(
        "AWS_ACCESS_KEY_ID",
        &[],
        "cloud",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "AWS_SECRET_ACCESS_KEY",
        &[],
        "cloud",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "AWS_SESSION_TOKEN",
        &[],
        "cloud",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "AWS_REGION",
        &["AWS_DEFAULT_REGION"],
        "cloud",
        false,
        false,
        "optional",
        None,
    ),
    // ── OAST ──────────────────────────────────────────────────────────────
    spec(
        "WEISSMAN_OAST_DOMAIN",
        &[],
        "oast",
        false,
        false,
        "optional",
        Some("oast_domain"),
    ),
    spec(
        "WEISSMAN_OAST_API_KEY",
        &[],
        "oast",
        true,
        false,
        "optional",
        Some("oast_api_key"),
    ),
    spec(
        "WEISSMAN_OAST_LISTENER_URL",
        &[],
        "oast",
        false,
        false,
        "optional",
        Some("oast_listener_url"),
    ),
    // ── Crypto / vault / production guards ────────────────────────────────
    spec(
        "WEISSMAN_VAULT_KEY",
        &[],
        "crypto",
        true,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_INTEGRATIONS_VAULT_KEY",
        &[],
        "crypto",
        true,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_EXPLOIT_MASTER_KEY",
        &[],
        "crypto",
        true,
        false,
        "optional",
        None,
    ),
    spec(
        "WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET",
        &[],
        "crypto",
        true,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_DUAL_APPROVAL_SECRET",
        &[],
        "crypto",
        true,
        true,
        "recommended",
        None,
    ),
    spec(
        "WEISSMAN_METRICS_TOKEN",
        &[],
        "crypto",
        true,
        true,
        "required",
        None,
    ),
    spec(
        "WEISSMAN_AUDIT_CHECKPOINT_SECRET",
        &[],
        "crypto",
        true,
        true,
        "recommended",
        None,
    ),
    spec(
        "GRAFANA_ADMIN_PASSWORD",
        &[],
        "ops",
        true,
        true,
        "optional",
        None,
    ),
];

const DENYLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "PWD",
    "OLDPWD",
    "TERM",
    "LANG",
    "LC_ALL",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "NODE_PATH",
    "RUSTC",
    "RUSTFLAGS",
    "CARGO_HOME",
    "SSLKEYLOGFILE",
    "GIT_CONFIG",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "IFS",
    "CDPATH",
    "HOSTNAME",
    "SHLVL",
];

#[derive(Debug, Clone, Serialize)]
pub struct KeyStatus {
    pub env_name: String,
    pub aliases: Vec<String>,
    pub category: String,
    pub is_secret: bool,
    pub requires_restart: bool,
    pub tier: String,
    pub custom: bool,
    pub configured: bool,
    pub sources: Vec<String>,
    pub last4: Option<String>,
    pub value_len: Option<usize>,
    pub preview: Option<String>,
    pub in_keyring: bool,
    pub updated_at: Option<String>,
    pub updated_by: Option<String>,
}

#[derive(Debug, Clone)]
struct KeyringRow {
    env_name: String,
    ciphertext: String,
    last4: String,
    value_len: i32,
    category: String,
    is_secret: bool,
    custom: bool,
    updated_at: String,
    updated_by: String,
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn last4(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    let n = chars.len().min(4);
    chars[chars.len() - n..].iter().collect()
}

fn preview_non_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 120 {
        return value.to_string();
    }
    chars[..120].iter().collect::<String>() + "…"
}

/// Uppercase `A-Z0-9_` env names; reject OS / loader hijack variables.
pub fn validate_env_name(raw: &str) -> Result<String, String> {
    let name = raw.trim().to_string();
    if name.len() < 2 || name.len() > 128 {
        return Err("env_name must be 2–128 characters".into());
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_uppercase() {
        return Err("env_name must start with A–Z".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err("env_name must match [A-Z][A-Z0-9_]*".into());
    }
    if DENYLIST.iter().any(|d| *d == name) {
        return Err(format!("{name} cannot be set from the key cockpit"));
    }
    Ok(name)
}

pub fn spec_for(name: &str) -> Option<&'static KeySpec> {
    CATALOG
        .iter()
        .find(|s| s.env_name == name || s.aliases.iter().any(|a| *a == name))
}

pub fn canonical_name(name: &str) -> String {
    spec_for(name)
        .map(|s| s.env_name.to_string())
        .unwrap_or_else(|| name.to_string())
}

fn apply_live(name: &str, value: &str) {
    std::env::set_var(name, value);
    if let Some(spec) = spec_for(name) {
        for alias in spec.aliases {
            if env_nonempty(alias).is_none() {
                std::env::set_var(*alias, value);
            }
        }
        if spec.env_name != name {
            std::env::set_var(spec.env_name, value);
        }
        // LLM model → NL query model when the latter is empty.
        if spec.env_name == "WEISSMAN_LLM_MODEL"
            && env_nonempty("WEISSMAN_NL_QUERY_MODEL").is_none()
        {
            std::env::set_var("WEISSMAN_NL_QUERY_MODEL", value);
        }
        if spec.env_name == "WEISSMAN_LLM_API_KEY" && env_nonempty("OPENAI_API_KEY").is_none() {
            std::env::set_var("OPENAI_API_KEY", value);
        }
        if spec.env_name == "WEISSMAN_LLM_BASE_URL" {
            if env_nonempty("OPENAI_BASE_URL").is_none() {
                std::env::set_var("OPENAI_BASE_URL", value);
            }
            if env_nonempty("LLM_BASE_URL").is_none() {
                std::env::set_var("LLM_BASE_URL", value);
            }
        }
    }
}

fn first_live_value(spec: &KeySpec) -> Option<String> {
    env_nonempty(spec.env_name).or_else(|| spec.aliases.iter().find_map(|a| env_nonempty(a)))
}

fn decrypt_or_skip(stored: &str) -> Option<String> {
    let pt = decrypt_secret(stored);
    if pt.starts_with(VAULT_PREFIX) {
        return None;
    }
    if pt.trim().is_empty() {
        return None;
    }
    Some(pt)
}

async fn load_keyring(pool: &PgPool) -> Result<Vec<KeyringRow>, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT env_name, ciphertext, last4, value_len, category, is_secret, custom,
                  updated_at::text AS updated_at, updated_by
           FROM platform_keyring
           ORDER BY env_name"#,
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        use sqlx::Row;
        out.push(KeyringRow {
            env_name: r.try_get("env_name")?,
            ciphertext: r.try_get("ciphertext")?,
            last4: r.try_get("last4")?,
            value_len: r.try_get("value_len")?,
            category: r.try_get("category")?,
            is_secret: r.try_get("is_secret")?,
            custom: r.try_get("custom")?,
            updated_at: r
                .try_get::<Option<String>, _>("updated_at")?
                .unwrap_or_default(),
            updated_by: r.try_get("updated_by")?,
        });
    }
    Ok(out)
}

async fn load_system_configs(pool: &PgPool, tenant_id: i64) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return map;
    };
    let keys: Vec<String> = CATALOG
        .iter()
        .filter_map(|s| s.system_config_key.map(str::to_string))
        .collect();
    if keys.is_empty() {
        let _ = tx.commit().await;
        return map;
    }
    if let Ok(rows) = sqlx::query(
        r#"SELECT key, value FROM system_configs
           WHERE tenant_id = $1 AND key = ANY($2)"#,
    )
    .bind(tenant_id)
    .bind(&keys)
    .fetch_all(&mut *tx)
    .await
    {
        use sqlx::Row;
        for r in rows {
            if let (Ok(k), Ok(v)) = (
                r.try_get::<String, _>("key"),
                r.try_get::<String, _>("value"),
            ) {
                let v = v.trim().to_string();
                if !v.is_empty() {
                    map.insert(k, v);
                }
            }
        }
    }
    let _ = tx.commit().await;
    map
}

fn status_for_spec(
    spec: &KeySpec,
    keyring: &HashMap<String, &KeyringRow>,
    syscfg: &HashMap<String, String>,
) -> KeyStatus {
    let kr = keyring.get(spec.env_name).copied();
    let env_val = first_live_value(spec);
    let sys_val = spec.system_config_key.and_then(|k| syscfg.get(k).cloned());
    let mut sources = Vec::new();
    if env_val.is_some() {
        sources.push("env".into());
    }
    if kr.is_some() {
        sources.push("keyring".into());
    }
    if sys_val.is_some() {
        sources.push("system_config".into());
    }
    let configured = env_val.is_some() || kr.is_some() || sys_val.is_some();
    let live = env_val
        .as_deref()
        .or(sys_val.as_deref())
        .map(str::to_string);
    let (last4_out, value_len, preview) = if !configured {
        (None, None, None)
    } else if spec.is_secret {
        let l4 = kr
            .map(|r| r.last4.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| live.as_ref().map(|v| last4(v)));
        let len = kr
            .map(|r| r.value_len as usize)
            .or_else(|| live.as_ref().map(|v| v.chars().count()));
        (l4, len, None)
    } else {
        let shown = live.as_deref().or(sys_val.as_deref()).unwrap_or("");
        (
            None,
            Some(shown.chars().count()),
            Some(preview_non_secret(shown)),
        )
    };
    KeyStatus {
        env_name: spec.env_name.to_string(),
        aliases: spec.aliases.iter().map(|s| (*s).to_string()).collect(),
        category: spec.category.to_string(),
        is_secret: spec.is_secret,
        requires_restart: spec.requires_restart,
        tier: spec.tier.to_string(),
        custom: false,
        configured,
        sources,
        last4: last4_out,
        value_len,
        preview,
        in_keyring: kr.is_some(),
        updated_at: kr.map(|r| r.updated_at.clone()).filter(|s| !s.is_empty()),
        updated_by: kr.map(|r| r.updated_by.clone()).filter(|s| !s.is_empty()),
    }
}

fn assemble(keyring_rows: &[KeyringRow], syscfg: &HashMap<String, String>) -> Vec<KeyStatus> {
    let kr_map: HashMap<String, &KeyringRow> = keyring_rows
        .iter()
        .map(|r| (r.env_name.clone(), r))
        .collect();
    let catalog_names: HashSet<&str> = CATALOG.iter().map(|s| s.env_name).collect();
    let mut out: Vec<KeyStatus> = CATALOG
        .iter()
        .map(|s| status_for_spec(s, &kr_map, syscfg))
        .collect();
    for row in keyring_rows {
        if catalog_names.contains(row.env_name.as_str()) {
            continue;
        }
        let env_val = env_nonempty(&row.env_name);
        let mut sources = vec!["keyring".to_string()];
        if env_val.is_some() {
            sources.insert(0, "env".into());
        }
        let configured = true;
        let (last4_out, value_len, preview) = if row.is_secret {
            (
                Some(row.last4.clone()).filter(|s| !s.is_empty()),
                Some(row.value_len as usize),
                None,
            )
        } else {
            let shown = env_val.clone().unwrap_or_default();
            (
                None,
                Some(row.value_len as usize),
                if shown.is_empty() {
                    None
                } else {
                    Some(preview_non_secret(&shown))
                },
            )
        };
        out.push(KeyStatus {
            env_name: row.env_name.clone(),
            aliases: vec![],
            category: if row.category.is_empty() {
                "custom".into()
            } else {
                row.category.clone()
            },
            is_secret: row.is_secret,
            requires_restart: false,
            tier: "optional".into(),
            custom: row.custom,
            configured,
            sources,
            last4: last4_out,
            value_len,
            preview,
            in_keyring: true,
            updated_at: Some(row.updated_at.clone()).filter(|s| !s.is_empty()),
            updated_by: Some(row.updated_by.clone()).filter(|s| !s.is_empty()),
        });
    }
    out.sort_by(|a, b| {
        category_rank(&a.category)
            .cmp(&category_rank(&b.category))
            .then(a.env_name.cmp(&b.env_name))
    });
    out
}

fn category_rank(c: &str) -> u8 {
    match c {
        "core" => 0,
        "auth" => 1,
        "llm" => 2,
        "intel" => 3,
        "notify" => 4,
        "crypto" => 5,
        "oast" => 6,
        "cicd" => 7,
        "cloud" => 8,
        "billing" => 9,
        "ops" => 10,
        _ => 20,
    }
}

fn summary_json(keys: &[KeyStatus]) -> Value {
    let total = keys.len();
    let armed = keys.iter().filter(|k| k.configured).count();
    let missing = total.saturating_sub(armed);
    let required_missing = keys
        .iter()
        .filter(|k| k.tier == "required" && !k.configured)
        .count();
    let custom = keys.iter().filter(|k| k.custom).count();
    json!({
        "total": total,
        "armed": armed,
        "missing": missing,
        "required_missing": required_missing,
        "custom": custom,
    })
}

pub async fn list_platform_keys(pool: &PgPool, tenant_id: i64) -> Value {
    let rows = load_keyring(pool).await.unwrap_or_default();
    let syscfg = load_system_configs(pool, tenant_id).await;
    let keys = assemble(&rows, &syscfg);
    json!({
        "ok": true,
        "summary": summary_json(&keys),
        "keys": keys,
    })
}

/// Load keyring into process env so workers and a restarted API honor CEO-set keys.
pub async fn overlay_from_db(pool: &PgPool) {
    let rows = match load_keyring(pool).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                target: "platform_keys",
                error = %e,
                "platform_keyring overlay skipped (table missing or unreadable)"
            );
            return;
        }
    };
    let mut applied = 0u32;
    for row in rows {
        if validate_env_name(&row.env_name).is_err() {
            continue;
        }
        let Some(pt) = decrypt_or_skip(&row.ciphertext) else {
            tracing::warn!(
                target: "platform_keys",
                env_name = %row.env_name,
                "could not decrypt keyring row — skipped"
            );
            continue;
        };
        apply_live(&row.env_name, &pt);
        applied += 1;
    }
    if applied > 0 {
        tracing::info!(
            target: "platform_keys",
            applied,
            "overlaid classified platform keys from keyring into process env"
        );
    }
}

async fn upsert_keyring(
    pool: &PgPool,
    env_name: &str,
    ciphertext: &str,
    last4: &str,
    value_len: i32,
    category: &str,
    is_secret: bool,
    custom: bool,
    updated_by: &str,
    tenant_id: i64,
) -> Result<(), String> {
    sqlx::query(
        r#"INSERT INTO platform_keyring
               (env_name, ciphertext, last4, value_len, category, is_secret, custom,
                updated_at, updated_by, writer_tenant_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9)
           ON CONFLICT (env_name) DO UPDATE SET
               ciphertext = EXCLUDED.ciphertext,
               last4 = EXCLUDED.last4,
               value_len = EXCLUDED.value_len,
               category = EXCLUDED.category,
               is_secret = EXCLUDED.is_secret,
               custom = EXCLUDED.custom,
               updated_at = now(),
               updated_by = EXCLUDED.updated_by,
               writer_tenant_id = EXCLUDED.writer_tenant_id"#,
    )
    .bind(env_name)
    .bind(ciphertext)
    .bind(last4)
    .bind(value_len)
    .bind(category)
    .bind(is_secret)
    .bind(custom)
    .bind(updated_by)
    .bind(tenant_id)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

async fn mirror_system_config(
    pool: &PgPool,
    tenant_id: i64,
    key: &str,
    value: &str,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"INSERT INTO system_configs (tenant_id, key, value, description)
           VALUES ($1, $2, $3, 'CEO classified key cockpit')
           ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value"#,
    )
    .bind(tenant_id)
    .bind(key)
    .bind(value)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn audit_action(
    pool: &PgPool,
    auth_pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    action: &str,
    details: &str,
    client_ip: &str,
) {
    let actor = crate::audit_log::user_email_for_id(auth_pool, user_id).await;
    if let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await {
        let _ = crate::audit_log::insert_audit(
            &mut tx,
            tenant_id,
            Some(user_id),
            &actor,
            action,
            details,
            client_ip,
        )
        .await;
        let _ = tx.commit().await;
    }
}

pub async fn put_platform_key(
    pool: &PgPool,
    auth_pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    client_ip: &str,
    actor_label: &str,
    env_name_raw: &str,
    value: &str,
) -> Result<Value, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("value must not be empty".into());
    }
    if value.len() > 16 * 1024 {
        return Err("value exceeds 16 KiB".into());
    }
    let validated = validate_env_name(env_name_raw)?;
    let canonical = canonical_name(&validated);
    let spec = spec_for(&canonical);
    let is_secret = spec.map(|s| s.is_secret).unwrap_or(true);
    let category = spec.map(|s| s.category).unwrap_or("custom");
    let custom = spec.is_none();
    let ciphertext = encrypt_secret(value);
    upsert_keyring(
        pool,
        &canonical,
        &ciphertext,
        &last4(value),
        value.chars().count() as i32,
        category,
        is_secret,
        custom,
        actor_label,
        tenant_id,
    )
    .await?;
    apply_live(&canonical, value);
    if let Some(cfg_key) = spec.and_then(|s| s.system_config_key) {
        if let Err(e) = mirror_system_config(pool, tenant_id, cfg_key, value).await {
            tracing::warn!(
                target: "platform_keys",
                env_name = %canonical,
                error = %e,
                "system_configs mirror failed"
            );
        }
    }
    audit_action(
        pool,
        auth_pool,
        tenant_id,
        user_id,
        "ceo_platform_key_put",
        &format!("env_name={canonical} len={}", value.chars().count()),
        client_ip,
    )
    .await;
    Ok(list_platform_keys(pool, tenant_id).await)
}

pub async fn delete_platform_key(
    pool: &PgPool,
    auth_pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    client_ip: &str,
    env_name_raw: &str,
) -> Result<Value, String> {
    let validated = validate_env_name(env_name_raw)?;
    let canonical = canonical_name(&validated);
    let res = sqlx::query("DELETE FROM platform_keyring WHERE env_name = $1")
        .bind(&canonical)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
    if res.rows_affected() == 0 {
        return Err("not in keyring".into());
    }
    audit_action(
        pool,
        auth_pool,
        tenant_id,
        user_id,
        "ceo_platform_key_delete",
        &format!("env_name={canonical}"),
        client_ip,
    )
    .await;
    Ok(list_platform_keys(pool, tenant_id).await)
}

pub async fn reveal_platform_key(
    pool: &PgPool,
    auth_pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    client_ip: &str,
    env_name_raw: &str,
) -> Result<Value, String> {
    let validated = validate_env_name(env_name_raw)?;
    let canonical = canonical_name(&validated);
    let spec = spec_for(&canonical);
    if let Ok(row) = sqlx::query("SELECT ciphertext FROM platform_keyring WHERE env_name = $1")
        .bind(&canonical)
        .fetch_optional(pool)
        .await
    {
        if let Some(r) = row {
            use sqlx::Row;
            let ct: String = r.try_get("ciphertext").map_err(|e| e.to_string())?;
            if let Some(pt) = decrypt_or_skip(&ct) {
                audit_action(
                    pool,
                    auth_pool,
                    tenant_id,
                    user_id,
                    "ceo_platform_key_reveal",
                    &format!("env_name={canonical} source=keyring"),
                    client_ip,
                )
                .await;
                return Ok(json!({
                    "ok": true,
                    "env_name": canonical,
                    "value": pt,
                    "source": "keyring",
                }));
            }
        }
    }
    let live = env_nonempty(&canonical)
        .or_else(|| spec.and_then(|s| s.aliases.iter().find_map(|a| env_nonempty(a))));
    if let Some(pt) = live {
        audit_action(
            pool,
            auth_pool,
            tenant_id,
            user_id,
            "ceo_platform_key_reveal",
            &format!("env_name={canonical} source=env"),
            client_ip,
        )
        .await;
        return Ok(json!({
            "ok": true,
            "env_name": canonical,
            "value": pt,
            "source": "env",
        }));
    }
    Err("key is not configured".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_env_names_unique() {
        let mut seen = HashSet::new();
        for k in CATALOG {
            assert!(
                seen.insert(k.env_name),
                "duplicate catalog env_name {}",
                k.env_name
            );
        }
        assert!(CATALOG.len() >= 40, "catalog too small: {}", CATALOG.len());
    }

    #[test]
    fn catalog_aliases_do_not_collide_with_canonical_names() {
        let names: HashSet<&str> = CATALOG.iter().map(|s| s.env_name).collect();
        for k in CATALOG {
            for a in k.aliases {
                assert!(
                    !names.contains(a),
                    "alias {a} collides with a canonical catalog name"
                );
            }
        }
    }

    #[test]
    fn validate_env_name_accepts_canonical_keys() {
        assert_eq!(validate_env_name("NVD_API_KEY").unwrap(), "NVD_API_KEY");
        assert_eq!(
            validate_env_name("WEISSMAN_LLM_API_KEY").unwrap(),
            "WEISSMAN_LLM_API_KEY"
        );
    }

    #[test]
    fn validate_env_name_rejects_dangerous_and_malformed() {
        assert!(validate_env_name("LD_PRELOAD").is_err());
        assert!(validate_env_name("PATH").is_err());
        assert!(validate_env_name("nvd_api_key").is_err());
        assert!(validate_env_name("NVD-API-KEY").is_err());
        assert!(validate_env_name("1ABC").is_err());
        assert!(validate_env_name("A").is_err());
    }

    #[test]
    fn last4_and_preview_helpers() {
        assert_eq!(last4("supersecretvalue123"), "e123");
        assert_eq!(last4("ab"), "ab");
        assert_eq!(last4(""), "");
        let long = "x".repeat(200);
        let p = preview_non_secret(&long);
        assert!(p.ends_with('…'));
        assert!(p.chars().count() <= 121);
    }

    #[test]
    fn canonical_name_resolves_aliases() {
        assert_eq!(canonical_name("OPENAI_API_KEY"), "WEISSMAN_LLM_API_KEY");
        assert_eq!(canonical_name("OPENAI_BASE_URL"), "WEISSMAN_LLM_BASE_URL");
        assert_eq!(canonical_name("WEISSMAN_GITHUB_TOKEN"), "GITHUB_TOKEN");
        assert_eq!(canonical_name("CUSTOM_THING"), "CUSTOM_THING");
    }

    #[test]
    fn assemble_masks_secret_values() {
        std::env::set_var("NVD_API_KEY", "supersecretvalue123");
        let keys = assemble(&[], &HashMap::new());
        let nvd = keys
            .iter()
            .find(|k| k.env_name == "NVD_API_KEY")
            .expect("NVD in catalog");
        assert!(nvd.configured);
        assert_eq!(nvd.last4.as_deref(), Some("e123"));
        assert!(nvd.preview.is_none());
        assert!(nvd.is_secret);
        let dump = serde_json::to_string(nvd).unwrap();
        assert!(
            !dump.contains("supersecretvalue123"),
            "list JSON leaked the secret: {dump}"
        );
        std::env::remove_var("NVD_API_KEY");
    }

    #[test]
    fn assemble_shows_preview_for_non_secrets() {
        std::env::set_var("WEISSMAN_LLM_BASE_URL", "http://127.0.0.1:11434/v1");
        let keys = assemble(&[], &HashMap::new());
        let llm = keys
            .iter()
            .find(|k| k.env_name == "WEISSMAN_LLM_BASE_URL")
            .expect("llm url");
        assert!(llm.configured);
        assert_eq!(llm.preview.as_deref(), Some("http://127.0.0.1:11434/v1"));
        assert!(!llm.is_secret);
        std::env::remove_var("WEISSMAN_LLM_BASE_URL");
    }

    #[test]
    fn missing_required_counted() {
        let keys = assemble(&[], &HashMap::new());
        let required = keys.iter().filter(|k| k.tier == "required").count();
        assert!(required >= 8);
        let summary = summary_json(&keys);
        assert!(summary["total"].as_u64().unwrap() >= 40);
    }
}
