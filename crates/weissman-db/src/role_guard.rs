//! Hermetic Postgres role split for runtime SQLx pools.
//!
//! | Role                 | DSN                                      | Privileges                                      |
//! |----------------------|------------------------------------------|-------------------------------------------------|
//! | `weissman_app`       | `DATABASE_URL`                           | DML subject to FORCE RLS (`NOBYPASSRLS`)        |
//! | `weissman_auth`      | `WEISSMAN_AUTH_DATABASE_URL`             | Login plane only (`BYPASSRLS`)                  |
//! | `weissman_ro`        | `WEISSMAN_READ_ONLY_DATABASE_URL`        | SELECT on [`RO_SELECT_TABLES`], 15s timeout     |
//! | `weissman_worker`    | `WEISSMAN_WORKER_DATABASE_URL`           | Job-bus DML (`BYPASSRLS`), no tenant tables     |
//! | `weissman_analytics` | `WEISSMAN_ANALYTICS_DATABASE_URL`        | SELECT on [`ANALYTICS_SELECT_TABLES`] (`BYPASSRLS`) |
//!
//! Superuser / table-owner DSNs belong in `WEISSMAN_MIGRATE_URL` only. A runtime
//! pool that connects as `postgres` silently bypasses every RLS policy.

use sqlx::PgPool;

use crate::env_bootstrap::{is_production_env, postgres_user_from_url};

/// Application pool role — every tenant-scoped SQLx query.
pub const APP_ROLE: &str = "weissman_app";
/// Auth / IdP pool role — credential lookup only.
pub const AUTH_ROLE: &str = "weissman_auth";
/// Ask Weissman NL→SQL pool role — SELECT-only.
pub const RO_ROLE: &str = "weissman_ro";
/// Job-bus control-plane role — claim/heartbeat across tenants.
pub const WORKER_ROLE: &str = "weissman_worker";
/// Global billing / quota aggregation role — metrics SELECT only.
pub const ANALYTICS_ROLE: &str = "weissman_analytics";

/// Tables `weissman_ro` may `SELECT`. Keep in lock-step with
/// `20260827115800_hermetic_db_roles.sql` (core 13) plus
/// `20260827165000_ot_ics_hardening_safety.sql` (4 OT/ICS tables).
pub const RO_SELECT_TABLES: &[&str] = &[
    "vulnerabilities",
    "weissman_finding_clusters",
    "clients",
    "risk_graph_nodes",
    "risk_graph_edges",
    "attack_path_snapshots",
    "client_financial_risk_snapshots",
    "agent_anomalies",
    "endpoint_agents",
    "epss_intel",
    "kev_intel",
    "audit_logs",
    "report_runs",
    "ot_ics_fingerprints",
    "ot_ics_safety_events",
    "ot_ics_protocol_baselines",
    "ot_ics_asset_ranges",
];

/// Ask Weissman hard statement timeout (milliseconds).
pub const RO_STATEMENT_TIMEOUT_MS: u64 = 15_000;
/// Analytics statement timeout (milliseconds). Hard cap so a heavy meter scan
/// cannot pin pool connections; live aggregation belongs on the snapshot table.
pub const ANALYTICS_STATEMENT_TIMEOUT_MS: u64 = 15_000;

/// Tables `weissman_analytics` may `SELECT`. Keep in lock-step with
/// `20260830120000_billing_usage_snapshot_15s.sql`.
/// Never include `vulnerabilities`, `agent_anomalies`, job-bus tables, or raw
/// meter heaps (`tenant_usage_counters`, `weissman_tenant_quota_usage`,
/// `tenant_llm_usage`) — those are rolled into the snapshot asynchronously.
pub const ANALYTICS_SELECT_TABLES: &[&str] = &["billing_plans", "weissman_billing_usage_snapshot"];

/// Job-bus tables `weissman_worker` may DML. Keep in lock-step with
/// `20260829120050_hermetic_analytics_worker_roles.sql`.
pub const WORKER_JOB_BUS_TABLES: &[&str] = &[
    "weissman_async_jobs",
    "weissman_job_events",
    "weissman_job_forensic_dlq",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolKind {
    App,
    Auth,
    ReadOnly,
    Worker,
    Analytics,
}

impl PoolKind {
    #[must_use]
    pub fn expected_role(self) -> &'static str {
        match self {
            Self::App => APP_ROLE,
            Self::Auth => AUTH_ROLE,
            Self::ReadOnly => RO_ROLE,
            Self::Worker => WORKER_ROLE,
            Self::Analytics => ANALYTICS_ROLE,
        }
    }

    #[must_use]
    pub fn expects_bypassrls(self) -> bool {
        matches!(self, Self::Auth | Self::Worker | Self::Analytics)
    }
}

fn e2e_or_allow_superuser_dsn() -> bool {
    env_flag("WEISSMAN_E2E_STACK") || env_flag("WEISSMAN_ALLOW_SUPERUSER_DSN")
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Production-only: refuse runtime DSNs that are not the dedicated role.
///
/// `WEISSMAN_MIGRATE_URL` is intentionally unchecked (owner/superuser). Dev and
/// `WEISSMAN_E2E_STACK=1` skip so local/CI postgres-superuser fixtures still boot.
pub fn enforce_production_dsn_roles() -> Result<(), String> {
    if !is_production_env() || e2e_or_allow_superuser_dsn() {
        return Ok(());
    }
    let app = std::env::var("DATABASE_URL").unwrap_or_default();
    require_dsn_role("DATABASE_URL", app.trim(), APP_ROLE)?;

    let auth = std::env::var("WEISSMAN_AUTH_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(auth) = auth else {
        return Err(
            "WEISSMAN_AUTH_DATABASE_URL must be set in production to the weissman_auth role \
             (BYPASSRLS login plane). Sharing DATABASE_URL would run login as weissman_app \
             or a superuser and collapse the three-role split"
                .into(),
        );
    };
    require_dsn_role("WEISSMAN_AUTH_DATABASE_URL", &auth, AUTH_ROLE)?;

    if let Ok(ro) = std::env::var("WEISSMAN_READ_ONLY_DATABASE_URL") {
        let t = ro.trim();
        if !t.is_empty() {
            require_dsn_role("WEISSMAN_READ_ONLY_DATABASE_URL", t, RO_ROLE)?;
        }
    }
    if let Ok(intel) = std::env::var("WEISSMAN_INTEL_DATABASE_URL") {
        let t = intel.trim();
        if !t.is_empty() {
            require_dsn_role("WEISSMAN_INTEL_DATABASE_URL", t, APP_ROLE)?;
        }
    }

    let worker = std::env::var("WEISSMAN_WORKER_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(worker) = worker else {
        return Err(
            "WEISSMAN_WORKER_DATABASE_URL must be set in production to the weissman_worker role \
             (BYPASSRLS job-bus claim plane). Sharing DATABASE_URL would let weissman_app claim \
             across tenants or see zero rows under fail-closed job-bus RLS"
                .into(),
        );
    };
    require_dsn_role("WEISSMAN_WORKER_DATABASE_URL", &worker, WORKER_ROLE)?;

    if let Ok(analytics) = std::env::var("WEISSMAN_ANALYTICS_DATABASE_URL") {
        let t = analytics.trim();
        if !t.is_empty() {
            require_dsn_role("WEISSMAN_ANALYTICS_DATABASE_URL", t, ANALYTICS_ROLE)?;
        }
    }
    Ok(())
}

/// Worker process: global billing aggregation requires the analytics DSN.
pub fn enforce_production_analytics_dsn() -> Result<(), String> {
    if !is_production_env() || e2e_or_allow_superuser_dsn() {
        return Ok(());
    }
    let analytics = std::env::var("WEISSMAN_ANALYTICS_DATABASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(analytics) = analytics else {
        return Err(
            "WEISSMAN_ANALYTICS_DATABASE_URL must be set on the worker in production to the \
             weissman_analytics role (BYPASSRLS SELECT on metrics tables only). Global quota \
             aggregation must not run as weissman_app (FORCE RLS sees one tenant) or weissman_auth"
                .into(),
        );
    };
    require_dsn_role(
        "WEISSMAN_ANALYTICS_DATABASE_URL",
        &analytics,
        ANALYTICS_ROLE,
    )
}

/// Validate a DSN's userinfo against the expected role. Always errors on a
/// mismatch when `strict` is true; otherwise logs and returns Ok.
pub fn require_dsn_role(var: &str, url: &str, expected: &str) -> Result<(), String> {
    let Some(user) = postgres_user_from_url(url) else {
        return Err(format!("{var} has no postgres user before @"));
    };
    if user != expected {
        return Err(format!(
            "{var} must connect as role `{expected}` (got `{user}`). Superuser/owner DSNs \
             belong only in WEISSMAN_MIGRATE_URL so RLS cannot be bypassed by runtime SQLx"
        ));
    }
    Ok(())
}

/// Warn (dev) or refuse (production) when a connected session is not the expected role.
pub async fn assert_pool_role(pool: &PgPool, kind: PoolKind) -> Result<(), sqlx::Error> {
    let expected = kind.expected_role();
    let row: Option<(String, bool, bool)> = sqlx::query_as(
        r#"SELECT current_user::text,
                  COALESCE(r.rolsuper, false),
                  COALESCE(r.rolbypassrls, false)
           FROM pg_roles r
           WHERE r.rolname = current_user"#,
    )
    .fetch_optional(pool)
    .await?;
    let Some((current, is_super, bypassrls)) = row else {
        return Err(sqlx::Error::Configuration(
            format!("could not resolve current_user for {} pool", expected).into(),
        ));
    };

    let strict = is_production_env() && !e2e_or_allow_superuser_dsn();
    if current != expected {
        let msg = format!(
            "{} pool connected as `{current}` (super={is_super}, bypassrls={bypassrls}); \
             expected `{expected}`",
            match kind {
                PoolKind::App => "app",
                PoolKind::Auth => "auth",
                PoolKind::ReadOnly => "read-only",
                PoolKind::Worker => "worker",
                PoolKind::Analytics => "analytics",
            }
        );
        if strict {
            return Err(sqlx::Error::Configuration(msg.into()));
        }
        tracing::warn!(target: "weissman_db::role_guard", "{msg}");
        return Ok(());
    }

    if is_super {
        let msg = format!(
            "role `{current}` is a superuser; runtime SQLx would bypass FORCE RLS. \
             Use `{expected}` (NOBYPASSRLS) and keep the owner DSN in WEISSMAN_MIGRATE_URL"
        );
        if strict {
            return Err(sqlx::Error::Configuration(msg.into()));
        }
        tracing::warn!(target: "weissman_db::role_guard", "{msg}");
    }

    if bypassrls != kind.expects_bypassrls() {
        let msg = format!(
            "role `{current}` rolbypassrls={bypassrls}, expected {} for the {} pool",
            kind.expects_bypassrls(),
            expected
        );
        if strict {
            return Err(sqlx::Error::Configuration(msg.into()));
        }
        tracing::warn!(target: "weissman_db::role_guard", "{msg}");
    }

    if matches!(kind, PoolKind::ReadOnly) {
        let timeout: String = sqlx::query_scalar("SHOW statement_timeout")
            .fetch_one(pool)
            .await
            .unwrap_or_default();
        if timeout != "15s" && timeout != "15000ms" && timeout != "00:00:15" {
            tracing::warn!(
                target: "weissman_db::role_guard",
                statement_timeout = %timeout,
                "weissman_ro statement_timeout is not 15s (Ask Weissman budget)"
            );
        }
    }

    Ok(())
}

/// Non-production: warn when `DATABASE_URL` is not `weissman_app` so operators notice
/// RLS is not being exercised. Production uses [`enforce_production_dsn_roles`].
pub fn warn_if_runtime_dsn_not_app_role(url: &str) {
    if is_production_env() {
        return;
    }
    match postgres_user_from_url(url) {
        Some(u) if u == APP_ROLE => {}
        Some(u) => tracing::warn!(
            target: "weissman_db::role_guard",
            user = %u,
            "DATABASE_URL is not weissman_app — FORCE RLS will not apply if this role is \
             superuser/owner. Dev/CI fixtures may do this; production refuses."
        ),
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ro_select_list_is_exactly_seventeen() {
        assert_eq!(RO_SELECT_TABLES.len(), 17);
        let mut seen = std::collections::HashSet::new();
        for t in RO_SELECT_TABLES {
            assert!(seen.insert(*t), "duplicate {t}");
        }
        assert!(!RO_SELECT_TABLES.contains(&"weissman_async_jobs"));
        assert!(!RO_SELECT_TABLES.contains(&"users"));
    }

    #[test]
    fn analytics_select_list_excludes_customer_detail_and_job_bus() {
        assert_eq!(ANALYTICS_SELECT_TABLES.len(), 2);
        assert!(ANALYTICS_SELECT_TABLES.contains(&"weissman_billing_usage_snapshot"));
        assert!(!ANALYTICS_SELECT_TABLES.contains(&"tenant_usage_counters"));
        assert!(!ANALYTICS_SELECT_TABLES.contains(&"weissman_tenant_quota_usage"));
        assert!(!ANALYTICS_SELECT_TABLES.contains(&"tenant_llm_usage"));
        for forbidden in [
            "vulnerabilities",
            "agent_anomalies",
            "clients",
            "users",
            "weissman_async_jobs",
            "weissman_job_events",
        ] {
            assert!(
                !ANALYTICS_SELECT_TABLES.contains(&forbidden),
                "analytics must not SELECT {forbidden}"
            );
        }
        assert_eq!(WORKER_JOB_BUS_TABLES.len(), 3);
        assert!(!WORKER_JOB_BUS_TABLES.contains(&"vulnerabilities"));
    }

    #[test]
    fn require_dsn_role_accepts_matching_user() {
        assert!(require_dsn_role(
            "DATABASE_URL",
            "postgres://weissman_app:secret@db/weissman",
            APP_ROLE
        )
        .is_ok());
        assert!(require_dsn_role(
            "WEISSMAN_AUTH_DATABASE_URL",
            "postgresql://weissman_auth@/weissman?host=/var/run/postgresql",
            AUTH_ROLE
        )
        .is_ok());
        assert!(require_dsn_role(
            "WEISSMAN_READ_ONLY_DATABASE_URL",
            "postgres://weissman_ro:x@127.0.0.1:5432/weissman",
            RO_ROLE
        )
        .is_ok());
    }

    #[test]
    fn require_dsn_role_rejects_superuser_and_cross_role() {
        let err = require_dsn_role(
            "DATABASE_URL",
            "postgres://postgres:postgres@127.0.0.1:5432/weissman",
            APP_ROLE,
        )
        .unwrap_err();
        assert!(err.contains("weissman_app"), "{err}");
        assert!(err.contains("postgres"), "{err}");

        let err = require_dsn_role(
            "DATABASE_URL",
            "postgres://weissman_auth:x@db/weissman",
            APP_ROLE,
        )
        .unwrap_err();
        assert!(err.contains("weissman_app"), "{err}");
    }

    #[test]
    fn pool_kind_flags() {
        assert_eq!(PoolKind::App.expected_role(), APP_ROLE);
        assert!(!PoolKind::App.expects_bypassrls());
        assert!(PoolKind::Auth.expects_bypassrls());
        assert!(!PoolKind::ReadOnly.expects_bypassrls());
        assert_eq!(PoolKind::Worker.expected_role(), WORKER_ROLE);
        assert!(PoolKind::Worker.expects_bypassrls());
        assert_eq!(PoolKind::Analytics.expected_role(), ANALYTICS_ROLE);
        assert!(PoolKind::Analytics.expects_bypassrls());
        assert_eq!(RO_STATEMENT_TIMEOUT_MS, 15_000);
        assert_eq!(ANALYTICS_STATEMENT_TIMEOUT_MS, 15_000);
    }
}
