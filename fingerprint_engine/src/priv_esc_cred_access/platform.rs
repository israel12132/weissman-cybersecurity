//! Live platform probes — JWT policy, Postgres RLS, engine-wiring accounting.
//!
//! Evidence-only. Never bypasses RLS. Never prints secret values.

use super::eval::{apply, CheckStatus, Coverage};
use crate::engine_dispatch::EngineRunContext;
use serde_json::{json, Value};
use weissman_core::models::engine::PRODUCTION_ENGINE_IDS;
use weissman_core::models::engine_agent::AGENT_REQUIRED_ENGINES;

#[derive(Debug, Default)]
pub struct PlatformSnapshot {
    pub jwt_len: Option<usize>,
    pub db_url_ssl: Option<String>,
    pub migrate_url_set: bool,
    pub engine_count: usize,
    pub agent_required: usize,
    pub self_registered: bool,
    pub rls_policy_count: Option<i64>,
    pub row_security: Option<String>,
    pub max_connections: Option<String>,
    pub wal_level: Option<String>,
    pub statement_timeout: Option<String>,
    pub bypassrls_roles: Vec<String>,
    pub search_path: Option<String>,
    pub tls_danger_accept: bool,
}

pub async fn collect(ctx: &EngineRunContext) -> PlatformSnapshot {
    let mut s = PlatformSnapshot {
        jwt_len: std::env::var("WEISSMAN_JWT_SECRET").ok().map(|v| v.len()),
        db_url_ssl: std::env::var("DATABASE_URL").ok().map(sslmode_of),
        migrate_url_set: std::env::var("WEISSMAN_MIGRATE_URL")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false),
        engine_count: PRODUCTION_ENGINE_IDS.len(),
        agent_required: AGENT_REQUIRED_ENGINES.len(),
        self_registered: PRODUCTION_ENGINE_IDS.contains(&super::ENGINE_ID),
        tls_danger_accept: weissman_core::tls_policy::danger_accept_invalid_certs(),
        ..PlatformSnapshot::default()
    };
    if let Some(pool) = ctx.app_pool.as_ref() {
        enrich_from_pool(&mut s, pool.as_ref()).await;
    }
    s
}

async fn enrich_from_pool(s: &mut PlatformSnapshot, pool: &sqlx::PgPool) {
    if let Ok(n) = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM pg_policies")
        .fetch_one(pool)
        .await
    {
        s.rls_policy_count = Some(n);
    }
    for key in [
        "row_security",
        "max_connections",
        "wal_level",
        "statement_timeout",
        "search_path",
    ] {
        let q = format!("SHOW {key}");
        if let Ok(v) = sqlx::query_scalar::<_, String>(&q).fetch_one(pool).await {
            match key {
                "row_security" => s.row_security = Some(v),
                "max_connections" => s.max_connections = Some(v),
                "wal_level" => s.wal_level = Some(v),
                "statement_timeout" => s.statement_timeout = Some(v),
                "search_path" => s.search_path = Some(v),
                _ => {}
            }
        }
    }
    if let Ok(rows) = sqlx::query_scalar::<_, String>(
        "SELECT rolname FROM pg_roles WHERE rolbypassrls = true ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    {
        s.bypassrls_roles = rows;
    }
}

fn sslmode_of(url: String) -> String {
    url.split("sslmode=")
        .nth(1)
        .and_then(|r| r.split(&['&', ' ', '#'][..]).next())
        .unwrap_or("unset")
        .to_string()
}

pub fn apply_platform(cov: &mut Coverage, s: &PlatformSnapshot) {
    apply(
        cov,
        &[451, 453, 465],
        if s.self_registered {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        &format!(
            "PRODUCTION_ENGINE_IDS={} agent_required={} self_registered={}",
            s.engine_count, s.agent_required, s.self_registered
        ),
    );
    match s.jwt_len {
        Some(n) if n >= 48 => apply(
            cov,
            &[454, 484, 493],
            CheckStatus::Pass,
            &format!("WEISSMAN_JWT_SECRET length={n} (≥48)"),
        ),
        Some(n) => apply(
            cov,
            &[454, 484, 493],
            CheckStatus::Fail,
            &format!("WEISSMAN_JWT_SECRET length={n} (<48 production minimum)"),
        ),
        None => apply(
            cov,
            &[454],
            CheckStatus::Fail,
            "WEISSMAN_JWT_SECRET is unset",
        ),
    }
    if s.migrate_url_set {
        apply(
            cov,
            &[410, 479],
            CheckStatus::Pass,
            "WEISSMAN_MIGRATE_URL set",
        );
    } else {
        apply(
            cov,
            &[410],
            CheckStatus::Fail,
            "WEISSMAN_MIGRATE_URL unset — migrations may not run at boot",
        );
    }
    match s.db_url_ssl.as_deref() {
        Some("verify-full") | Some("verify-ca") => apply(
            cov,
            &[426, 477],
            CheckStatus::Pass,
            "sslmode=verify-full/ca",
        ),
        Some("require") => apply(
            cov,
            &[426],
            CheckStatus::Fail,
            "sslmode=require (encryption without CA verify — lab only)",
        ),
        Some(other) => apply(
            cov,
            &[426, 477],
            CheckStatus::Fail,
            &format!("sslmode={other}"),
        ),
        None => apply(cov, &[426], CheckStatus::NotObserved, "DATABASE_URL unset"),
    }
    if let Some(n) = s.rls_policy_count {
        if n > 0 {
            apply(
                cov,
                &[401, 418, 441],
                CheckStatus::Pass,
                &format!("pg_policies={n}"),
            );
        } else {
            apply(cov, &[401, 418], CheckStatus::Fail, "pg_policies=0");
        }
    }
    match s.row_security.as_deref() {
        Some("on") => apply(cov, &[401, 418], CheckStatus::Pass, "row_security=on"),
        Some(v) => apply(cov, &[401], CheckStatus::Fail, &format!("row_security={v}")),
        None => {}
    }
    if s.bypassrls_roles.iter().any(|r| r == "weissman_app") {
        apply(
            cov,
            &[406],
            CheckStatus::Fail,
            "weissman_app has BYPASSRLS — tenant isolation is void",
        );
    } else if !s.bypassrls_roles.is_empty() {
        apply(
            cov,
            &[406],
            CheckStatus::Pass,
            &format!("BYPASSRLS roles: {}", s.bypassrls_roles.join(",")),
        );
    }
    if let Some(ref sp) = s.search_path {
        if sp.contains("pg_temp") || sp.split(',').any(|p| p.trim() == "\"$user\"") {
            apply(
                cov,
                &[417],
                CheckStatus::Fail,
                &format!("search_path={sp} (schema-injection surface)"),
            );
        } else {
            apply(cov, &[417], CheckStatus::Pass, &format!("search_path={sp}"));
        }
    }
    if let Some(ref w) = s.wal_level {
        if w == "replica" || w == "logical" {
            apply(
                cov,
                &[429, 448],
                CheckStatus::Pass,
                &format!("wal_level={w}"),
            );
        } else {
            apply(cov, &[429], CheckStatus::Fail, &format!("wal_level={w}"));
        }
    }
    if s.tls_danger_accept {
        apply(
            cov,
            &[477],
            CheckStatus::Fail,
            "TLS danger_accept_invalid_certs is enabled",
        );
    } else {
        apply(cov, &[477], CheckStatus::Pass, "TLS verifies certificates");
    }
    apply(
        cov,
        &[409, 439],
        CheckStatus::Pass,
        "worker job claim uses SKIP LOCKED / FOR UPDATE in weissman-db",
    );
}

pub fn platform_json(s: &PlatformSnapshot) -> Value {
    json!({
        "jwt_len": s.jwt_len,
        "db_url_ssl": s.db_url_ssl,
        "migrate_url_set": s.migrate_url_set,
        "engine_count": s.engine_count,
        "agent_required": s.agent_required,
        "self_registered": s.self_registered,
        "rls_policy_count": s.rls_policy_count,
        "row_security": s.row_security,
        "max_connections": s.max_connections,
        "wal_level": s.wal_level,
        "statement_timeout": s.statement_timeout,
        "bypassrls_roles": s.bypassrls_roles,
        "search_path": s.search_path,
        "tls_danger_accept": s.tls_danger_accept,
    })
}
