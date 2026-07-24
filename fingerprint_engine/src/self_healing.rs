//! Platform self-healing — diagnose the platform's OWN health from observability signals and
//! decide bounded recovery actions.
//!
//! The 10s health loop ([`crate::observability::spawn_pool_metrics_loop`]) already DETECTS raw
//! signals — DB-pool utilization, async-job backlog, agent staleness, dependency up/down. This
//! module is the DIAGNOSE + decide-RECOVERY brain on top: it turns a [`HealthSnapshot`] into
//! structured [`Diagnosis`]es, each carrying a [`Severity`] and a recommended [`RecoveryAction`],
//! and records them as self-heal metrics for dashboards/alerts.
//!
//! Execution of the heavier actions (reconnect, restart) rides the existing recovery primitives
//! ([`crate::resilience::CircuitBreaker`] + jittered backoff, the agent presence pruner) and is
//! layered on in follow-ups; this milestone ships the detect→diagnose→signal brain and its
//! metric so the platform continuously self-diagnoses using the observability it already has.
//!
//! `diagnose` is **pure** (same snapshot ⇒ same diagnoses) and unit-tested exhaustively without
//! a live stack.

/// A point-in-time snapshot of the platform's own health, sampled by the metrics loop.
#[derive(Debug, Clone)]
pub struct HealthSnapshot {
    pub postgres_up: bool,
    /// Whether Redis is a hard dependency in this deployment (distributed rate-limit state).
    pub redis_required: bool,
    pub redis_up: bool,
    /// Connections the busiest DB pool has grown to.
    pub db_pool_size: u32,
    /// Idle connections in that pool (0 with a grown pool ⇒ saturation).
    pub db_pool_idle: u32,
    pub agents_registered: u32,
    pub agents_online: u32,
    pub async_jobs_pending: u64,
}

/// Tunable thresholds (env-overridable) that turn raw numbers into diagnoses.
#[derive(Debug, Clone)]
pub struct Thresholds {
    /// Fraction of registered agents allowed stale before flagging (0.0..=1.0).
    pub stale_agent_ratio: f64,
    /// Async-job backlog that flags a throughput problem (warning).
    pub async_backlog_warn: u64,
    /// Async-job backlog that flags a critical worker stall.
    pub async_backlog_critical: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            stale_agent_ratio: 0.5,
            async_backlog_warn: 500,
            async_backlog_critical: 5_000,
        }
    }
}

impl Thresholds {
    /// Load from `WEISSMAN_SELFHEAL_*` env, falling back to [`Thresholds::default`].
    #[must_use]
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            stale_agent_ratio: env_f64("WEISSMAN_SELFHEAL_STALE_AGENT_RATIO", d.stale_agent_ratio)
                .clamp(0.0, 1.0),
            async_backlog_warn: env_u64("WEISSMAN_SELFHEAL_ASYNC_WARN", d.async_backlog_warn),
            async_backlog_critical: env_u64(
                "WEISSMAN_SELFHEAL_ASYNC_CRITICAL",
                d.async_backlog_critical,
            ),
        }
    }
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// How urgent a diagnosis is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Critical,
}

impl Severity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// The platform subsystem a diagnosis is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subsystem {
    Postgres,
    Redis,
    DbPool,
    Agents,
    AsyncJobs,
}

impl Subsystem {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Subsystem::Postgres => "postgres",
            Subsystem::Redis => "redis",
            Subsystem::DbPool => "db_pool",
            Subsystem::Agents => "agents",
            Subsystem::AsyncJobs => "async_jobs",
        }
    }
}

/// The bounded recovery action a diagnosis recommends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Transient pressure — apply exponential backoff (via `resilience`).
    Backoff,
    /// Dependency blip — trip its circuit and let the pool re-establish.
    ReconnectDependency,
    /// Reap agents past their presence TTL.
    PruneStaleAgents,
    /// Saturation — shed or queue new work rather than pile on.
    ShedLoad,
}

impl RecoveryAction {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryAction::Backoff => "backoff",
            RecoveryAction::ReconnectDependency => "reconnect_dependency",
            RecoveryAction::PruneStaleAgents => "prune_stale_agents",
            RecoveryAction::ShedLoad => "shed_load",
        }
    }
}

/// One diagnosed problem plus the recovery action it recommends.
#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub subsystem: Subsystem,
    pub severity: Severity,
    pub action: RecoveryAction,
    pub detail: String,
}

/// Diagnose the platform's health. **Pure**: same snapshot ⇒ same diagnoses. An empty vec means
/// every monitored subsystem is healthy.
#[must_use]
pub fn diagnose(s: &HealthSnapshot, t: &Thresholds) -> Vec<Diagnosis> {
    let mut out = Vec::new();

    if !s.postgres_up {
        out.push(Diagnosis {
            subsystem: Subsystem::Postgres,
            severity: Severity::Critical,
            action: RecoveryAction::ReconnectDependency,
            detail: "postgres unreachable".to_string(),
        });
    }

    if s.redis_required && !s.redis_up {
        out.push(Diagnosis {
            subsystem: Subsystem::Redis,
            severity: Severity::Critical,
            action: RecoveryAction::ReconnectDependency,
            detail: "redis required for distributed state but unreachable".to_string(),
        });
    }

    // A grown pool with zero idle connections is saturated: shed/queue rather than block.
    if s.db_pool_size > 0 && s.db_pool_idle == 0 {
        out.push(Diagnosis {
            subsystem: Subsystem::DbPool,
            severity: Severity::Warning,
            action: RecoveryAction::ShedLoad,
            detail: format!("db pool saturated ({} conns, 0 idle)", s.db_pool_size),
        });
    }

    if s.agents_registered > 0 {
        let stale = s.agents_registered.saturating_sub(s.agents_online);
        let ratio = f64::from(stale) / f64::from(s.agents_registered);
        if ratio >= t.stale_agent_ratio {
            out.push(Diagnosis {
                subsystem: Subsystem::Agents,
                severity: Severity::Warning,
                action: RecoveryAction::PruneStaleAgents,
                detail: format!("{stale}/{} agents stale", s.agents_registered),
            });
        }
    }

    if s.async_jobs_pending >= t.async_backlog_critical {
        out.push(Diagnosis {
            subsystem: Subsystem::AsyncJobs,
            severity: Severity::Critical,
            action: RecoveryAction::ShedLoad,
            detail: format!(
                "async backlog {} at/above critical {}",
                s.async_jobs_pending, t.async_backlog_critical
            ),
        });
    } else if s.async_jobs_pending >= t.async_backlog_warn {
        out.push(Diagnosis {
            subsystem: Subsystem::AsyncJobs,
            severity: Severity::Warning,
            action: RecoveryAction::Backoff,
            detail: format!(
                "async backlog {} at/above warn {}",
                s.async_jobs_pending, t.async_backlog_warn
            ),
        });
    }

    out
}

/// Record diagnoses as self-heal metrics so dashboards/alerts can see what the platform
/// diagnosed about itself and which recovery each round recommended.
pub fn record_diagnoses(diags: &[Diagnosis]) {
    for d in diags {
        metrics::counter!(
            "weissman_self_heal_diagnosis_total",
            "subsystem" => d.subsystem.as_str(),
            "severity" => d.severity.as_str(),
            "action" => d.action.as_str(),
        )
        .increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> HealthSnapshot {
        HealthSnapshot {
            postgres_up: true,
            redis_required: false,
            redis_up: true,
            db_pool_size: 10,
            db_pool_idle: 4,
            agents_registered: 10,
            agents_online: 10,
            async_jobs_pending: 0,
        }
    }

    #[test]
    fn healthy_platform_has_no_diagnoses() {
        assert!(diagnose(&healthy(), &Thresholds::default()).is_empty());
    }

    #[test]
    fn postgres_down_is_critical_reconnect() {
        let mut s = healthy();
        s.postgres_up = false;
        let d = diagnose(&s, &Thresholds::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].subsystem, Subsystem::Postgres);
        assert_eq!(d[0].severity, Severity::Critical);
        assert_eq!(d[0].action, RecoveryAction::ReconnectDependency);
    }

    #[test]
    fn redis_down_only_flags_when_required() {
        let mut s = healthy();
        s.redis_up = false;
        s.redis_required = false;
        assert!(diagnose(&s, &Thresholds::default()).is_empty());
        s.redis_required = true;
        let d = diagnose(&s, &Thresholds::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].subsystem, Subsystem::Redis);
    }

    #[test]
    fn saturated_pool_sheds_load() {
        let mut s = healthy();
        s.db_pool_size = 20;
        s.db_pool_idle = 0;
        let d = diagnose(&s, &Thresholds::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].subsystem, Subsystem::DbPool);
        assert_eq!(d[0].action, RecoveryAction::ShedLoad);
    }

    #[test]
    fn empty_pool_is_not_saturation() {
        // size 0 (pool not yet grown) with 0 idle must NOT be flagged.
        let mut s = healthy();
        s.db_pool_size = 0;
        s.db_pool_idle = 0;
        assert!(diagnose(&s, &Thresholds::default()).is_empty());
    }

    #[test]
    fn stale_agents_over_ratio_prunes() {
        let mut s = healthy();
        s.agents_registered = 10;
        s.agents_online = 4; // 6 stale = 60% >= 50%
        let d = diagnose(&s, &Thresholds::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].subsystem, Subsystem::Agents);
        assert_eq!(d[0].action, RecoveryAction::PruneStaleAgents);
    }

    #[test]
    fn agents_under_ratio_are_healthy() {
        let mut s = healthy();
        s.agents_registered = 10;
        s.agents_online = 8; // 20% stale < 50%
        assert!(diagnose(&s, &Thresholds::default()).is_empty());
    }

    #[test]
    fn async_backlog_warn_then_critical() {
        let t = Thresholds::default();
        let mut s = healthy();
        s.async_jobs_pending = t.async_backlog_warn;
        let warn = diagnose(&s, &t);
        assert_eq!(warn.len(), 1);
        assert_eq!(warn[0].severity, Severity::Warning);
        assert_eq!(warn[0].action, RecoveryAction::Backoff);

        s.async_jobs_pending = t.async_backlog_critical;
        let crit = diagnose(&s, &t);
        assert_eq!(crit.len(), 1);
        assert_eq!(crit[0].severity, Severity::Critical);
        assert_eq!(crit[0].action, RecoveryAction::ShedLoad);
    }

    #[test]
    fn multiple_problems_all_reported() {
        let mut s = healthy();
        s.postgres_up = false;
        s.db_pool_size = 5;
        s.db_pool_idle = 0;
        let d = diagnose(&s, &Thresholds::default());
        assert_eq!(d.len(), 2);
    }
}
