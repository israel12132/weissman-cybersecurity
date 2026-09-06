//! Operator-facing job diagnostics: live lease / heartbeat / remap / hang reasons.
//!
//! Classification is a pure function of DB row + Redis inspect + engine registry. No hardcoded
//! job statuses are returned as telemetry — every field is derived from live state.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;
use weissman_core::models::engine::resolve_engine_id;
use weissman_core::models::engine_agent::is_agent_required_engine;
use weissman_job_bus::{inspect_orchestration, LeaseView, LiveOrchestrationView};

/// Heartbeat older than this while `running` is a hang (matches supreme nerve center).
pub const STUCK_HEARTBEAT_SECS: i64 = 120;
/// Pending with no claim for this long is a hang (worker down / queue wedged).
pub const STUCK_PENDING_SECS: i64 = 180;
/// In-process engine phase with no update for this long is a hang.
pub const STUCK_PHASE_SECS: i64 = 300;

pub const OPERATOR_ERROR: &str = "error";
pub const OPERATOR_RUNNING: &str = "running";
pub const OPERATOR_STUCK: &str = "stuck";
pub const OPERATOR_BLOCKED_BY_AGENT: &str = "blocked_by_agent";
pub const OPERATOR_ROE_BLOCKED: &str = "roe_blocked";
pub const OPERATOR_QUEUED: &str = "queued";
pub const OPERATOR_COMPLETED: &str = "completed";
pub const OPERATOR_CANCELLED: &str = "cancelled";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EngineRemap {
    pub requested_engine: String,
    pub canonical_engine: String,
    pub was_remapped: bool,
}

#[derive(Debug, Clone, Default)]
pub struct JobFacts {
    pub id: Uuid,
    pub kind: String,
    pub status: String,
    pub last_error: Option<String>,
    pub result_message: Option<String>,
    pub result_agent_required: bool,
    pub result_agent_live_dispatched: bool,
    pub result_roe_blocked: bool,
    pub worker_id: Option<String>,
    /// Seconds since last heartbeat. `None` if the row has never heartbeated.
    pub heartbeat_stale_secs: Option<i64>,
    /// Seconds since `locked_until` elapsed. `None` if no lock or still in the future.
    pub lock_expired_secs: Option<i64>,
    /// Seconds until `run_after`. Positive = still held. `None` if claimable now.
    pub run_after_secs: Option<i64>,
    pub age_secs: Option<i64>,
    pub engine: Option<String>,
    pub lease: Option<LeaseView>,
    pub lease_inspect_ok: bool,
    pub redis_configured: bool,
    pub swarm_worker_alive: Option<bool>,
    pub live_phase: Option<String>,
    pub live_phase_idle_secs: Option<i64>,
    pub heartbeat_at: Option<String>,
    pub locked_until: Option<String>,
    pub run_after: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobDiagnostics {
    pub operator_state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stuck_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_owner: Option<String>,
    pub lease_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_ttl_secs: Option<i64>,
    pub lease_inspect_ok: bool,
    pub redis_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_stale_secs: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swarm_worker_alive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remap: Option<EngineRemap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_phase_idle_secs: Option<i64>,
}

#[must_use]
pub fn engine_remap(requested: Option<&str>) -> Option<EngineRemap> {
    let req = requested.map(str::trim).filter(|s| !s.is_empty())?;
    let canonical = resolve_engine_id(req);
    Some(EngineRemap {
        requested_engine: req.to_string(),
        canonical_engine: canonical.to_string(),
        was_remapped: canonical != req,
    })
}

#[must_use]
pub fn looks_like_roe(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("roe violation")
        || t.contains("rules of engagement")
        || t.contains("roe_blocked")
        || (t.contains("roe") && t.contains("blocked"))
}

#[must_use]
pub fn looks_like_agent_block(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    if t.contains("dispatched to online agent") || t.contains("task dispatched to online") {
        return false;
    }
    t.contains("requires an enrolled endpoint agent")
        || t.contains("requires endpoint agent")
        || t.contains("agent_required")
        || t.contains("queued for next online agent")
        || t.contains("no enrolled agent")
        || t.contains("endpoint agent")
}

#[must_use]
pub fn inspect_result_signals(result: Option<&Value>) -> (Option<String>, bool, bool, bool) {
    let Some(r) = result else {
        return (None, false, false, false);
    };
    let msg = r
        .get("message")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let mut agent_req = false;
    let mut live = false;
    if let Some(arr) = r.get("findings").and_then(Value::as_array) {
        for f in arr {
            if f.get("agent_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || f.get("category").and_then(Value::as_str) == Some("agent_required")
            {
                agent_req = true;
            }
            if f.get("live_dispatched")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                live = true;
            }
            let title = f.get("title").and_then(Value::as_str).unwrap_or("");
            let title_lc = title.to_ascii_lowercase();
            if title_lc.contains("dispatched to online agent") {
                live = true;
            }
            if title_lc.contains("queued for next online agent") {
                agent_req = true;
            }
        }
    }
    if let Some(ref m) = msg {
        if looks_like_agent_block(m) {
            agent_req = true;
        }
        if m.to_ascii_lowercase()
            .contains("dispatched to online agent")
        {
            live = true;
        }
    }
    let roe = r.get("status").and_then(Value::as_str) == Some("roe_blocked")
        || r.get("roe_blocked").and_then(Value::as_bool).unwrap_or(false)
        || msg.as_deref().is_some_and(looks_like_roe);
    (msg, agent_req, live, roe)
}

fn haystack(facts: &JobFacts) -> String {
    let mut s = String::new();
    if let Some(e) = &facts.last_error {
        s.push_str(e);
        s.push(' ');
    }
    if let Some(m) = &facts.result_message {
        s.push_str(m);
    }
    s
}

fn is_inflight(status: &str) -> bool {
    matches!(
        status.to_ascii_lowercase().as_str(),
        "pending" | "running" | "queued"
    )
}

fn stuck_reasons(facts: &JobFacts) -> Vec<String> {
    let mut reasons = Vec::new();
    let status = facts.status.to_ascii_lowercase();
    if status == "running" {
        match facts.heartbeat_stale_secs {
            None => reasons.push("running with no worker heartbeat".into()),
            Some(s) if s > STUCK_HEARTBEAT_SECS => {
                reasons.push(format!("worker heartbeat stale {s}s"));
            }
            _ => {}
        }
        if let Some(exp) = facts.lock_expired_secs {
            if exp > 0 {
                reasons.push(format!("postgres lock expired {exp}s ago"));
            }
        }
        if facts.redis_configured && facts.lease_inspect_ok {
            match &facts.lease {
                Some(l) if l.present => {
                    if l.ttl_secs < 0 {
                        reasons.push("redis lease has no TTL (wedge risk)".into());
                    }
                    if let (Some(owner), Some(wid)) = (&l.worker_id, &facts.worker_id) {
                        if owner != wid {
                            reasons.push(format!("lease owner mismatch: redis={owner} db={wid}"));
                        }
                    }
                }
                Some(l) if !l.present => {
                    reasons.push("redis lease missing".into());
                }
                None => reasons.push("redis lease missing".into()),
                _ => {}
            }
        }
        if facts.swarm_worker_alive == Some(false) {
            let wid = facts.worker_id.as_deref().unwrap_or("unknown");
            reasons.push(format!("swarm liveness expired for worker {wid}"));
        }
        if let Some(idle) = facts.live_phase_idle_secs {
            if idle > STUCK_PHASE_SECS {
                let phase = facts.live_phase.as_deref().unwrap_or("unknown");
                reasons.push(format!(
                    "no engine phase update for {idle}s (phase={phase})"
                ));
            }
        }
    } else if status == "pending" || status == "queued" {
        if facts.run_after_secs.map(|s| s > 0).unwrap_or(false) {
            return reasons;
        }
        if let Some(age) = facts.age_secs {
            if age > STUCK_PENDING_SECS {
                reasons.push(format!("queued with no worker claim for {age}s"));
            }
        }
    }
    reasons
}

/// Pure classifier — unit-tested without Redis/DB.
#[must_use]
pub fn classify(facts: &JobFacts) -> JobDiagnostics {
    let remap = engine_remap(facts.engine.as_deref());
    let canonical = remap
        .as_ref()
        .map(|r| r.canonical_engine.clone())
        .unwrap_or_default();
    let agent_engine = (!canonical.is_empty() && is_agent_required_engine(&canonical))
        || facts
            .engine
            .as_deref()
            .map(is_agent_required_engine)
            .unwrap_or(false);

    let hay = haystack(facts);
    let roe = looks_like_roe(&hay) || facts.result_roe_blocked;
    let agent_text = looks_like_agent_block(&hay) || facts.result_agent_required;
    let live_dispatch = facts.result_agent_live_dispatched;
    let status = facts.status.to_ascii_lowercase();

    let lease_owner = facts
        .lease
        .as_ref()
        .and_then(|l| l.worker_id.clone())
        .or_else(|| facts.worker_id.clone());
    let lease_present = if facts.lease_inspect_ok {
        Some(facts.lease.as_ref().map(|l| l.present).unwrap_or(false))
    } else {
        None
    };
    let lease_ttl_secs = facts.lease.as_ref().and_then(|l| {
        if l.ttl_secs >= 0 {
            Some(l.ttl_secs)
        } else {
            None
        }
    });

    let pack = |operator_state: &'static str, stuck_reason: Option<String>| JobDiagnostics {
        operator_state,
        stuck_reason,
        lease_owner,
        lease_present,
        lease_ttl_secs,
        lease_inspect_ok: facts.lease_inspect_ok,
        redis_configured: facts.redis_configured,
        heartbeat_stale_secs: facts.heartbeat_stale_secs,
        swarm_worker_alive: facts.swarm_worker_alive,
        remap,
        live_phase: facts.live_phase.clone(),
        live_phase_idle_secs: facts.live_phase_idle_secs,
    };

    if roe {
        return pack(
            OPERATOR_ROE_BLOCKED,
            Some(
                facts
                    .last_error
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "Rules of Engagement blocked this job".into()),
            ),
        );
    }

    // Running hangs beat agent-blocked: a claimed worker that stopped heartbeating is stuck
    // even when the engine happens to be agent-required.
    if status == "running" {
        let reasons = stuck_reasons(facts);
        if !reasons.is_empty() {
            return pack(OPERATOR_STUCK, Some(reasons.join("; ")));
        }
    }

    let agent_waiting = !live_dispatch && agent_text;
    // Completed agent-required engine with an honest "requires agent" finding, or queued
    // for the next online agent, is not a successful host scan.
    let agent_completed_unserviced = agent_engine
        && status == "completed"
        && !live_dispatch
        && (agent_text || facts.result_agent_required);

    if agent_waiting || agent_completed_unserviced {
        let reason = facts
            .last_error
            .clone()
            .or_else(|| facts.result_message.clone())
            .unwrap_or_else(|| {
                format!(
                    "engine {} requires an enrolled endpoint agent",
                    facts.engine.as_deref().unwrap_or(canonical.as_str())
                )
            });
        return pack(OPERATOR_BLOCKED_BY_AGENT, Some(reason));
    }

    if is_inflight(&status) {
        let reasons = stuck_reasons(facts);
        if !reasons.is_empty() {
            return pack(OPERATOR_STUCK, Some(reasons.join("; ")));
        }
        if status == "running" {
            return pack(OPERATOR_RUNNING, None);
        }
        let queued_reason = facts.run_after_secs.and_then(|s| {
            if s > 0 {
                Some(format!("retry/backoff: run_after in {s}s"))
            } else {
                None
            }
        });
        return pack(OPERATOR_QUEUED, queued_reason);
    }

    match status.as_str() {
        "completed" => pack(OPERATOR_COMPLETED, None),
        "cancelled" => pack(OPERATOR_CANCELLED, None),
        "failed" | "dead" => pack(
            OPERATOR_ERROR,
            facts
                .last_error
                .clone()
                .or_else(|| facts.result_message.clone()),
        ),
        _ => pack(OPERATOR_QUEUED, None),
    }
}

impl JobDiagnostics {
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(json!({}))
    }
}

/// Merge diagnostic fields onto a job JSON object.
pub fn merge_into_job(job: &mut Value, diag: &JobDiagnostics) {
    let Some(obj) = job.as_object_mut() else {
        return;
    };
    if let Ok(Value::Object(map)) = serde_json::to_value(diag) {
        for (k, v) in map {
            obj.insert(k, v);
        }
    }
}

pub async fn apply_live_orchestration(facts: &mut [JobFacts]) {
    if facts.is_empty() {
        return;
    }
    let ids: Vec<Uuid> = facts.iter().map(|f| f.id).collect();
    let workers: Vec<String> = facts.iter().filter_map(|f| f.worker_id.clone()).collect();
    let live: LiveOrchestrationView = inspect_orchestration(&ids, &workers).await;
    for f in facts.iter_mut() {
        f.redis_configured = live.redis_configured;
        f.lease_inspect_ok = live.inspect_ok;
        if live.inspect_ok {
            f.lease = live.leases.get(&f.id).cloned();
            if let Some(wid) = &f.worker_id {
                f.swarm_worker_alive = live.workers.get(wid).map(|w| w.present);
            }
        }
        if let Some((phase, idle)) = crate::supreme_nerve_center::live_run_phase(&f.id.to_string())
        {
            f.live_phase = Some(phase);
            f.live_phase_idle_secs = Some(idle);
        }
    }
}

#[must_use]
pub fn stale_secs(ts: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<i64> {
    ts.map(|t| now.signed_duration_since(t).num_seconds().max(0))
}

#[must_use]
pub fn expired_secs(until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<i64> {
    until.and_then(|t| {
        let d = now.signed_duration_since(t).num_seconds();
        if d > 0 {
            Some(d)
        } else {
            None
        }
    })
}

#[must_use]
pub fn until_secs(until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<i64> {
    until.and_then(|t| {
        let d = t.signed_duration_since(now).num_seconds();
        if d > 0 {
            Some(d)
        } else {
            None
        }
    })
}

impl JobFacts {
    #[must_use]
    pub fn from_status_view(
        view: &weissman_db::job_queue::JobStatusView,
        now: DateTime<Utc>,
    ) -> Self {
        let engine = view
            .payload
            .get("engine")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let (result_message, result_agent_required, result_agent_live_dispatched, result_roe_blocked) =
            inspect_result_signals(view.result.as_ref());
        Self {
            id: view.id,
            kind: view.kind.clone(),
            status: view.status.clone(),
            last_error: view.last_error.clone(),
            result_message,
            result_agent_required,
            result_agent_live_dispatched,
            result_roe_blocked,
            worker_id: view.worker_id.clone(),
            heartbeat_stale_secs: stale_secs(view.heartbeat_at, now),
            lock_expired_secs: expired_secs(view.locked_until, now),
            run_after_secs: until_secs(view.run_after, now),
            age_secs: stale_secs(Some(view.created_at), now),
            engine,
            heartbeat_at: view.heartbeat_at.map(|d| d.to_rfc3339()),
            locked_until: view.locked_until.map(|d| d.to_rfc3339()),
            run_after: view.run_after.map(|d| d.to_rfc3339()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn base_running() -> JobFacts {
        JobFacts {
            id: Uuid::nil(),
            kind: "command_center_engine".into(),
            status: "running".into(),
            worker_id: Some("box:1".into()),
            heartbeat_stale_secs: Some(5),
            age_secs: Some(30),
            engine: Some("osint".into()),
            lease_inspect_ok: true,
            redis_configured: true,
            lease: Some(LeaseView {
                job_id: Uuid::nil(),
                present: true,
                ttl_secs: 200,
                worker_id: Some("box:1".into()),
            }),
            swarm_worker_alive: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn healthy_running_is_running() {
        let d = classify(&base_running());
        assert_eq!(d.operator_state, OPERATOR_RUNNING);
        assert!(d.stuck_reason.is_none());
        assert_eq!(d.lease_owner.as_deref(), Some("box:1"));
        assert_eq!(d.lease_present, Some(true));
    }

    #[test]
    fn stale_heartbeat_is_stuck() {
        let mut f = base_running();
        f.heartbeat_stale_secs = Some(400);
        let d = classify(&f);
        assert_eq!(d.operator_state, OPERATOR_STUCK);
        assert!(d
            .stuck_reason
            .as_deref()
            .unwrap_or("")
            .contains("heartbeat stale"));
    }

    #[test]
    fn missing_redis_lease_is_stuck_when_inspect_ok() {
        let mut f = base_running();
        f.lease = Some(LeaseView {
            job_id: Uuid::nil(),
            present: false,
            ttl_secs: -2,
            worker_id: None,
        });
        let d = classify(&f);
        assert_eq!(d.operator_state, OPERATOR_STUCK);
        assert!(d
            .stuck_reason
            .as_deref()
            .unwrap_or("")
            .contains("lease missing"));
    }

    #[test]
    fn missing_lease_not_stuck_when_inspect_failed() {
        let mut f = base_running();
        f.lease = None;
        f.lease_inspect_ok = false;
        let d = classify(&f);
        assert_eq!(d.operator_state, OPERATOR_RUNNING);
    }

    #[test]
    fn roe_failed_job_is_distinct() {
        let f = JobFacts {
            status: "failed".into(),
            last_error: Some("RoE VIOLATION: target not on whitelist".into()),
            engine: Some("triconex_tristation".into()),
            ..Default::default()
        };
        let d = classify(&f);
        assert_eq!(d.operator_state, OPERATOR_ROE_BLOCKED);
        assert!(d.stuck_reason.as_deref().unwrap_or("").contains("RoE"));
    }

    #[test]
    fn agent_required_completed_is_blocked_by_agent() {
        let f = JobFacts {
            status: "completed".into(),
            engine: Some("process_inventory".into()),
            result_agent_required: true,
            result_message: Some("process_inventory: requires endpoint agent".into()),
            ..Default::default()
        };
        let d = classify(&f);
        assert_eq!(d.operator_state, OPERATOR_BLOCKED_BY_AGENT);
        assert_eq!(
            d.remap.as_ref().map(|r| r.canonical_engine.as_str()),
            Some("process_inventory")
        );
    }

    #[test]
    fn live_agent_dispatch_stays_completed() {
        let f = JobFacts {
            status: "completed".into(),
            engine: Some("process_inventory".into()),
            result_agent_live_dispatched: true,
            result_message: Some("process_inventory: task dispatched to online agent".into()),
            ..Default::default()
        };
        let d = classify(&f);
        assert_eq!(d.operator_state, OPERATOR_COMPLETED);
    }

    #[test]
    fn pending_without_claim_becomes_stuck() {
        let f = JobFacts {
            status: "pending".into(),
            age_secs: Some(600),
            engine: Some("osint".into()),
            ..Default::default()
        };
        let d = classify(&f);
        assert_eq!(d.operator_state, OPERATOR_STUCK);
        assert!(d
            .stuck_reason
            .as_deref()
            .unwrap_or("")
            .contains("no worker claim"));
    }

    #[test]
    fn pending_with_run_after_is_queued_not_stuck() {
        let f = JobFacts {
            status: "pending".into(),
            age_secs: Some(600),
            run_after_secs: Some(45),
            engine: Some("osint".into()),
            ..Default::default()
        };
        let d = classify(&f);
        assert_eq!(d.operator_state, OPERATOR_QUEUED);
        assert!(d
            .stuck_reason
            .as_deref()
            .unwrap_or("")
            .contains("run_after"));
    }

    #[test]
    fn remap_reports_alias_to_canonical() {
        let r = engine_remap(Some("active_directory")).expect("remap");
        assert!(r.was_remapped);
        assert_eq!(r.requested_engine, "active_directory");
        assert_eq!(r.canonical_engine, "kerberos_attack_suite");
    }

    #[test]
    fn failed_without_roe_is_error() {
        let f = JobFacts {
            status: "dead".into(),
            last_error: Some("timeout after 300s".into()),
            ..Default::default()
        };
        let d = classify(&f);
        assert_eq!(d.operator_state, OPERATOR_ERROR);
    }

    #[test]
    fn inspect_result_signals_agent_finding() {
        let v = json!({
            "message": "usb_enumeration: requires endpoint agent",
            "findings": [{"agent_required": true, "category": "agent_required"}]
        });
        let (msg, req, live, roe) = inspect_result_signals(Some(&v));
        assert!(msg.unwrap().contains("usb_enumeration"));
        assert!(req);
        assert!(!live);
        assert!(!roe);
    }

    #[test]
    fn inspect_result_signals_roe_blocked_status() {
        let v = json!({
            "status": "roe_blocked",
            "roe_blocked": true,
            "message": "RoE blocked: industrial_ot_enabled is false",
            "findings": []
        });
        let (_msg, req, live, roe) = inspect_result_signals(Some(&v));
        assert!(!req);
        assert!(!live);
        assert!(roe);
    }
}
