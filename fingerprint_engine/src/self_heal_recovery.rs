//! Platform self-healing — EXECUTE the recovery actions [`crate::self_healing::diagnose`]
//! recommends, behind bounded per-action safety guards.
//!
//! [`crate::self_healing`] is the DIAGNOSE brain: it turns a [`HealthSnapshot`] into
//! [`Diagnosis`]es, each naming a [`RecoveryAction`]. This module is the RECOVER hand: it takes
//! those diagnoses and actually *acts* on the platform's own state —
//!
//! | Action | Effect (bounded, reversible) |
//! |---|---|
//! | `shed_load` | engage a process-wide **load-shed gate** ([`load_shed_active`]) that heavy intake can consult to reject/queue new work; auto-expires after a TTL. |
//! | `backoff` | engage a softer **backoff gate** ([`backoff_active`]) for transient pressure; auto-expires. |
//! | `reconnect_dependency` | drive a per-dependency **circuit breaker** ([`dependency_available`]) so callers fail fast during an outage and the breaker auto-probes (half-open) once cooldown elapses — i.e. lets the pool re-establish without a thundering herd. |
//! | `prune_stale_agents` | raise a **prune request** signal ([`prune_requests`]); the presence pruner reaps on its own cadence. |
//!
//! # Safety
//! Every effect is bounded and self-clearing, and every action is **cooldown-gated** per
//! `(subsystem, action)` so a sustained fault engages recovery *once per cooldown*, not every 10s
//! round. A master switch (`WEISSMAN_SELFHEAL_RECOVERY_ENABLED`) disables execution entirely.
//! Lock poisoning is **fail-open** (recovery must never wedge the health loop). The whole thing
//! operates on process-wide platform signals, never tenant data, so it is tenant-agnostic and safe.
//!
//! # Testability
//! The decision core [`plan_recovery`] is **pure** (diagnoses + last-fired map + clock ⇒ plan) and
//! the controller's effects take an injected `now`, so the entire state machine is unit-tested
//! without a live stack or real wall-clock.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use dashmap::DashMap;

use crate::resilience::CircuitBreaker;
use crate::self_healing::{Diagnosis, HealthSnapshot, RecoveryAction, Subsystem};

/// A hard dependency whose reachability is guarded by a self-heal circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dependency {
    Postgres,
    Redis,
}

/// What happened to a recovery action this round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// The effect was applied this round.
    Executed,
    /// Suppressed because the same `(subsystem, action)` fired within the cooldown window.
    Cooldown,
}

impl RecoveryOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryOutcome::Executed => "executed",
            RecoveryOutcome::Cooldown => "cooldown",
        }
    }
}

/// One recovery the planner considered this round, plus whether it fires (vs cooldown-suppressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedRecovery {
    pub subsystem: Subsystem,
    pub action: RecoveryAction,
    /// `true` ⇒ execute the effect now; `false` ⇒ suppressed by the per-action cooldown.
    pub fired: bool,
}

/// Tunables (env-overridable) that bound recovery execution.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Master switch — when false, no effects run and all gates read "healthy".
    pub enabled: bool,
    /// Minimum seconds between the same `(subsystem, action)` firing.
    pub cooldown_secs: u64,
    /// How long a `shed_load` engagement stays active before auto-clearing.
    pub shed_ttl_secs: u64,
    /// How long a `backoff` engagement stays active before auto-clearing.
    pub backoff_ttl_secs: u64,
    /// Consecutive failures before a dependency circuit opens (fail-fast).
    pub dep_threshold: u64,
    /// Seconds an open dependency circuit waits before probing (half-open).
    pub dep_cooldown_secs: u64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_secs: 60,
            shed_ttl_secs: 30,
            backoff_ttl_secs: 20,
            dep_threshold: 3,
            dep_cooldown_secs: 15,
        }
    }
}

impl RecoveryConfig {
    /// Load from `WEISSMAN_SELFHEAL_*` env, falling back to [`RecoveryConfig::default`].
    #[must_use]
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            enabled: env_bool("WEISSMAN_SELFHEAL_RECOVERY_ENABLED", d.enabled),
            cooldown_secs: env_u64("WEISSMAN_SELFHEAL_ACTION_COOLDOWN_SECS", d.cooldown_secs),
            shed_ttl_secs: env_u64("WEISSMAN_SELFHEAL_SHED_TTL_SECS", d.shed_ttl_secs),
            backoff_ttl_secs: env_u64("WEISSMAN_SELFHEAL_BACKOFF_TTL_SECS", d.backoff_ttl_secs),
            dep_threshold: env_u64("WEISSMAN_SELFHEAL_DEP_CIRCUIT_THRESHOLD", d.dep_threshold)
                .max(1),
            dep_cooldown_secs: env_u64(
                "WEISSMAN_SELFHEAL_DEP_CIRCUIT_COOLDOWN_SECS",
                d.dep_cooldown_secs,
            ),
        }
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => default,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decide which recoveries fire this round. **Pure**: `(diagnoses, last-fired map, now, cooldown)`
/// fully determine the plan. Deduplicates by `(subsystem, action)` so one round yields at most one
/// plan entry per distinct action; `fired` is `false` when that key fired within `cooldown`.
#[must_use]
pub fn plan_recovery(
    diags: &[Diagnosis],
    last_fired: &HashMap<(&'static str, &'static str), u64>,
    now: u64,
    cooldown: u64,
) -> Vec<PlannedRecovery> {
    let mut seen: Vec<(&'static str, &'static str)> = Vec::new();
    let mut out = Vec::new();
    for d in diags {
        let key = (d.subsystem.as_str(), d.action.as_str());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let fired = last_fired
            .get(&key)
            .is_none_or(|&t| now.saturating_sub(t) >= cooldown);
        out.push(PlannedRecovery {
            subsystem: d.subsystem,
            action: d.action,
            fired,
        });
    }
    out
}

/// Process-wide recovery state: the load-shed / backoff gates, dependency circuits, and the
/// per-action cooldown ledger.
struct RecoveryController {
    /// Epoch-secs until which the load-shed gate is engaged (0 ⇒ off).
    shed_until: AtomicU64,
    /// Epoch-secs until which the soft-backoff gate is engaged (0 ⇒ off).
    backoff_until: AtomicU64,
    /// Monotonic count of prune requests raised (the presence pruner reaps independently).
    prune_requests: AtomicU64,
    pg_circuit: CircuitBreaker,
    redis_circuit: CircuitBreaker,
    /// Last epoch-secs each `(subsystem, action)` fired, for cooldown gating.
    last_fired: DashMap<(&'static str, &'static str), u64>,
}

impl RecoveryController {
    fn new(cfg: &RecoveryConfig) -> Self {
        Self {
            shed_until: AtomicU64::new(0),
            backoff_until: AtomicU64::new(0),
            prune_requests: AtomicU64::new(0),
            pg_circuit: CircuitBreaker::new(cfg.dep_threshold, cfg.dep_cooldown_secs),
            redis_circuit: CircuitBreaker::new(cfg.dep_threshold, cfg.dep_cooldown_secs),
            last_fired: DashMap::new(),
        }
    }

    /// Feed live dependency health into the circuits every round (idempotent): success closes the
    /// breaker, failure trips it toward fail-fast. Redis is only tracked when it is a hard dep.
    fn feed_dependencies(&self, snapshot: &HealthSnapshot) {
        if snapshot.postgres_up {
            self.pg_circuit.record_success();
        } else {
            self.pg_circuit.record_failure();
        }
        if snapshot.redis_required {
            if snapshot.redis_up {
                self.redis_circuit.record_success();
            } else {
                self.redis_circuit.record_failure();
            }
        }
    }

    /// Plan + apply recovery effects for this round's diagnoses. Returns each considered action and
    /// its outcome (for metrics). Fail-open on lock poison.
    fn apply(
        &self,
        diags: &[Diagnosis],
        now: u64,
        cfg: &RecoveryConfig,
    ) -> Vec<(PlannedRecovery, RecoveryOutcome)> {
        let snapshot: HashMap<(&'static str, &'static str), u64> = self
            .last_fired
            .iter()
            .map(|e| (*e.key(), *e.value()))
            .collect();
        let planned = plan_recovery(diags, &snapshot, now, cfg.cooldown_secs);
        let mut results = Vec::with_capacity(planned.len());
        for p in planned {
            if p.fired {
                self.execute_effect(p.action, now, cfg);
                self.last_fired
                    .insert((p.subsystem.as_str(), p.action.as_str()), now);
                results.push((p, RecoveryOutcome::Executed));
            } else {
                results.push((p, RecoveryOutcome::Cooldown));
            }
        }
        results
    }

    fn execute_effect(&self, action: RecoveryAction, now: u64, cfg: &RecoveryConfig) {
        match action {
            RecoveryAction::ShedLoad => self
                .shed_until
                .store(now.saturating_add(cfg.shed_ttl_secs), Ordering::SeqCst),
            RecoveryAction::Backoff => self
                .backoff_until
                .store(now.saturating_add(cfg.backoff_ttl_secs), Ordering::SeqCst),
            RecoveryAction::PruneStaleAgents => {
                self.prune_requests.fetch_add(1, Ordering::SeqCst);
            }
            // The dependency circuit is already driven by `feed_dependencies`; the recovery event
            // here is that fail-fast is now in effect. No extra mutation to apply.
            RecoveryAction::ReconnectDependency => {}
        }
    }

    fn shed_active_at(&self, now: u64) -> bool {
        self.shed_until.load(Ordering::SeqCst) > now
    }

    fn backoff_active_at(&self, now: u64) -> bool {
        self.backoff_until.load(Ordering::SeqCst) > now
    }

    fn evict_stale_last_fired(&self, now: u64, keep_secs: u64) -> usize {
        let mut dropped = 0usize;
        self.last_fired.retain(|_, ts| {
            if now.saturating_sub(*ts) > keep_secs {
                dropped += 1;
                false
            } else {
                true
            }
        });
        dropped
    }
}

fn config() -> &'static RecoveryConfig {
    static C: OnceLock<RecoveryConfig> = OnceLock::new();
    C.get_or_init(RecoveryConfig::from_env)
}

fn controller() -> &'static RecoveryController {
    static R: OnceLock<RecoveryController> = OnceLock::new();
    R.get_or_init(|| RecoveryController::new(config()))
}

/// Execute recovery for one health round: feed dependency circuits, apply cooldown-gated effects
/// for the diagnoses, and record `weissman_self_heal_recovery_total{subsystem,action,outcome}`.
/// No-op when disabled by env.
/// Drop `(subsystem, action)` last-fired rows older than 4× cooldown (floor 1h).
pub fn evict_stale_last_fired() -> usize {
    let cfg = config();
    let keep = cfg.cooldown_secs.saturating_mul(4).max(3600);
    controller().evict_stale_last_fired(now_secs(), keep)
}

pub fn run_recovery(snapshot: &HealthSnapshot, diags: &[Diagnosis]) {
    let cfg = config();
    if !cfg.enabled {
        return;
    }
    let ctrl = controller();
    ctrl.feed_dependencies(snapshot);
    let results = ctrl.apply(diags, now_secs(), cfg);
    for (p, outcome) in &results {
        metrics::counter!(
            "weissman_self_heal_recovery_total",
            "subsystem" => p.subsystem.as_str(),
            "action" => p.action.as_str(),
            "outcome" => outcome.as_str(),
        )
        .increment(1);
    }
}

/// Whether heavy new work should be shed/queued right now (a `shed_load` recovery is engaged).
/// Intake paths consult this to protect a saturated platform. Reads "off" when recovery is disabled.
///
/// ORs in the **fleet** gate ([`crate::self_heal_shared::shed_active`]): when cross-replica
/// coordination is enabled, load-shed engaged on *any* replica sheds intake here too. The recovery
/// master switch stays the outer kill switch — disabled ⇒ this replica neither honors the local nor
/// the fleet gate — and the shared reader is itself off unless coordination is enabled, so this is
/// exactly today's local behavior by default.
#[must_use]
pub fn load_shed_active() -> bool {
    if !config().enabled {
        return false;
    }
    controller().shed_active_at(now_secs()) || crate::self_heal_shared::shed_active()
}

/// Whether a soft backoff is engaged (transient pressure). Reads "off" when recovery is disabled.
/// ORs in the fleet backoff gate ([`crate::self_heal_shared::backoff_active`]) — see
/// [`load_shed_active`].
#[must_use]
pub fn backoff_active() -> bool {
    if !config().enabled {
        return false;
    }
    controller().backoff_active_at(now_secs()) || crate::self_heal_shared::backoff_active()
}

/// Absolute epoch-secs the **local** load-shed gate is engaged until (0 ⇒ off). Feeds the
/// cross-replica publisher ([`crate::self_heal_shared::publish_gates`]); independent of the
/// shared-state flag, but still 0 when recovery itself is disabled.
#[must_use]
pub fn local_shed_until() -> u64 {
    if !config().enabled {
        return 0;
    }
    controller().shed_until.load(Ordering::SeqCst)
}

/// Absolute epoch-secs the **local** backoff gate is engaged until (0 ⇒ off). See
/// [`local_shed_until`].
#[must_use]
pub fn local_backoff_until() -> u64 {
    if !config().enabled {
        return 0;
    }
    controller().backoff_until.load(Ordering::SeqCst)
}

/// Whether a dependency is currently allowed (circuit closed/half-open) vs failing fast (open).
/// Always `true` when recovery is disabled, so gating callers degrade to normal behavior.
#[must_use]
pub fn dependency_available(dep: Dependency) -> bool {
    if !config().enabled {
        return true;
    }
    let ctrl = controller();
    match dep {
        Dependency::Postgres => ctrl.pg_circuit.allow_request(),
        Dependency::Redis => ctrl.redis_circuit.allow_request(),
    }
}

/// Monotonic count of `prune_stale_agents` recoveries raised so far. The presence pruner reaps on
/// its own cadence; this lets an operator or the pruner see how often recovery asked for a sweep.
/// Reads `0` when recovery is disabled.
#[must_use]
pub fn prune_requests() -> u64 {
    if !config().enabled {
        return 0;
    }
    controller().prune_requests.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_healing::Severity;

    fn diag(subsystem: Subsystem, action: RecoveryAction) -> Diagnosis {
        Diagnosis {
            subsystem,
            severity: Severity::Warning,
            action,
            detail: String::new(),
        }
    }

    fn test_cfg() -> RecoveryConfig {
        RecoveryConfig {
            enabled: true,
            cooldown_secs: 60,
            shed_ttl_secs: 30,
            backoff_ttl_secs: 20,
            dep_threshold: 3,
            dep_cooldown_secs: 15,
        }
    }

    fn healthy_snapshot() -> HealthSnapshot {
        HealthSnapshot {
            postgres_up: true,
            redis_required: false,
            redis_up: true,
            db_pool_size: 10,
            db_pool_idle: 4,
            agents_registered: 0,
            agents_online: 0,
            async_jobs_pending: 0,
        }
    }

    #[test]
    fn empty_diagnoses_plan_nothing() {
        let plan = plan_recovery(&[], &HashMap::new(), 1_000, 60);
        assert!(plan.is_empty());
    }

    #[test]
    fn fresh_diagnoses_all_fire() {
        let diags = vec![
            diag(Subsystem::Postgres, RecoveryAction::ReconnectDependency),
            diag(Subsystem::DbPool, RecoveryAction::ShedLoad),
        ];
        let plan = plan_recovery(&diags, &HashMap::new(), 1_000, 60);
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|p| p.fired));
    }

    #[test]
    fn duplicate_action_keys_are_deduped() {
        // Two diagnoses with the SAME (subsystem, action) collapse to one plan entry.
        let diags = vec![
            diag(Subsystem::AsyncJobs, RecoveryAction::ShedLoad),
            diag(Subsystem::AsyncJobs, RecoveryAction::ShedLoad),
        ];
        let plan = plan_recovery(&diags, &HashMap::new(), 1_000, 60);
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn same_action_different_subsystem_both_fire() {
        // db_pool/shed_load and async_jobs/shed_load are distinct keys — both plan.
        let diags = vec![
            diag(Subsystem::DbPool, RecoveryAction::ShedLoad),
            diag(Subsystem::AsyncJobs, RecoveryAction::ShedLoad),
        ];
        let plan = plan_recovery(&diags, &HashMap::new(), 1_000, 60);
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn cooldown_suppresses_then_reallows() {
        let mut last = HashMap::new();
        last.insert(("db_pool", "shed_load"), 1_000u64);
        let diags = vec![diag(Subsystem::DbPool, RecoveryAction::ShedLoad)];
        // 30s later, within the 60s cooldown ⇒ suppressed.
        let plan = plan_recovery(&diags, &last, 1_030, 60);
        assert_eq!(plan.len(), 1);
        assert!(!plan[0].fired);
        // 60s later, cooldown elapsed ⇒ fires again.
        let plan = plan_recovery(&diags, &last, 1_060, 60);
        assert!(plan[0].fired);
    }

    #[test]
    fn shed_load_engages_gate_and_auto_expires() {
        let cfg = test_cfg();
        let ctrl = RecoveryController::new(&cfg);
        let diags = vec![diag(Subsystem::DbPool, RecoveryAction::ShedLoad)];
        let now = 1_000;
        let results = ctrl.apply(&diags, now, &cfg);
        assert_eq!(results[0].1, RecoveryOutcome::Executed);
        assert!(ctrl.shed_active_at(now)); // engaged now
        assert!(ctrl.shed_active_at(now + cfg.shed_ttl_secs - 1)); // still engaged before TTL
        assert!(!ctrl.shed_active_at(now + cfg.shed_ttl_secs)); // auto-cleared at TTL
    }

    #[test]
    fn backoff_engages_its_own_gate() {
        let cfg = test_cfg();
        let ctrl = RecoveryController::new(&cfg);
        let diags = vec![diag(Subsystem::AsyncJobs, RecoveryAction::Backoff)];
        let now = 2_000;
        ctrl.apply(&diags, now, &cfg);
        assert!(ctrl.backoff_active_at(now));
        assert!(!ctrl.backoff_active_at(now + cfg.backoff_ttl_secs));
        // shed gate untouched by a backoff action
        assert!(!ctrl.shed_active_at(now));
    }

    #[test]
    fn second_round_within_cooldown_is_cooldown_outcome() {
        let cfg = test_cfg();
        let ctrl = RecoveryController::new(&cfg);
        let diags = vec![diag(Subsystem::DbPool, RecoveryAction::ShedLoad)];
        assert_eq!(
            ctrl.apply(&diags, 1_000, &cfg)[0].1,
            RecoveryOutcome::Executed
        );
        // 10s later (next health round) — still in cooldown.
        assert_eq!(
            ctrl.apply(&diags, 1_010, &cfg)[0].1,
            RecoveryOutcome::Cooldown
        );
        // past cooldown — executes again.
        assert_eq!(
            ctrl.apply(&diags, 1_100, &cfg)[0].1,
            RecoveryOutcome::Executed
        );
    }

    #[test]
    fn prune_action_raises_request_signal() {
        let cfg = test_cfg();
        let ctrl = RecoveryController::new(&cfg);
        let diags = vec![diag(Subsystem::Agents, RecoveryAction::PruneStaleAgents)];
        ctrl.apply(&diags, 1_000, &cfg);
        assert_eq!(ctrl.prune_requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dependency_circuit_trips_on_sustained_failure_then_recovers() {
        let cfg = test_cfg(); // threshold 3, cooldown 15
        let ctrl = RecoveryController::new(&cfg);
        let mut down = healthy_snapshot();
        down.postgres_up = false;
        // Healthy while below threshold.
        ctrl.feed_dependencies(&down);
        ctrl.feed_dependencies(&down);
        assert!(ctrl.pg_circuit.allow_request());
        // Third failure trips it open ⇒ fail fast.
        ctrl.feed_dependencies(&down);
        assert!(!ctrl.pg_circuit.allow_request());
        // A healthy round resets it closed ⇒ available again.
        ctrl.feed_dependencies(&healthy_snapshot());
        assert!(ctrl.pg_circuit.allow_request());
    }

    #[test]
    fn redis_circuit_untouched_when_not_required() {
        let cfg = test_cfg();
        let ctrl = RecoveryController::new(&cfg);
        let mut s = healthy_snapshot();
        s.redis_required = false;
        s.redis_up = false; // down but not a hard dep
        for _ in 0..10 {
            ctrl.feed_dependencies(&s);
        }
        assert!(ctrl.redis_circuit.allow_request()); // never tripped
    }

    #[test]
    fn config_from_env_defaults_are_sane() {
        let d = RecoveryConfig::default();
        assert!(d.enabled);
        assert!(d.dep_threshold >= 1);
        assert!(d.shed_ttl_secs > 0);
    }
}
