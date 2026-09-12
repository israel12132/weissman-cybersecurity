//! Budgeted HTTP fuzz campaigns — live progress, cooperative cancellation, evidence-backed findings.
//!
//! Production hang (live evidence):
//! * `http_feedback_fuzz` remapped to `feedback_fuzz` (30 min job) waited forever on the LLM
//!   mutation channel, hit the worker wall, was requeued, and stayed `running`.
//! * XSS / CSRF / race / open-redirect aliases ran under `command_center_engine` with a 45s
//!   resilience attempt that escalated to a **fake 180s timeout finding** instead of returning
//!   the HTTP probes that had already executed.
//!
//! Contract:
//! * A campaign **always returns** before its wall-clock budget (or the job timeout).
//! * Findings include HTTP proof (status / excerpt / Location) — never placeholder JSON.
//! * Empty results are honest: they list what was tried.
//! * Postgres job leases are heartbeated while the campaign runs so a live worker cannot be
//!   reclaimed as stale. Spawned LLM producers are aborted on drop so a cancelled job cannot
//!   outlive its lease.

use fuzz_core::ValidatedAnomaly;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use uuid::Uuid;

/// Job kinds whose executor arm runs an HTTP fuzz campaign.
pub const FEEDBACK_FUZZ_JOB_KIND: &str = "feedback_fuzz";

/// `command_center_engine` wall is 15 minutes; campaign must finish inside it.
pub const COMMAND_CENTER_JOB_SECS: u64 = 15 * 60;
/// `feedback_fuzz` job wall is 30 minutes.
pub const FEEDBACK_FUZZ_JOB_SECS: u64 = 30 * 60;

/// Default campaign wall for alias engines under `command_center_engine` (10 min).
pub const DEFAULT_ALIAS_CAMPAIGN_SECS: u64 = 10 * 60;
/// Default campaign wall for the dedicated `feedback_fuzz` job (28 min).
pub const DEFAULT_FEEDBACK_CAMPAIGN_SECS: u64 = 28 * 60;

/// Resilience attempt timeout must exceed the campaign wall so the engine returns live
/// evidence instead of `attempt timed out after 180000ms`.
pub const FUZZ_RESILIENCE_SLACK_SECS: u64 = 90;

/// Wall for a fuzz alias inside a multi-engine batch (`scan_all_engines`, 45 min job).
/// Specialized probes + capped static fuzz; generative LLM is skipped. Must **not** be 180s
/// (that was the fake timeout finding).
pub const BATCH_FUZZ_CAMPAIGN_SECS: u64 = 90;
pub const BATCH_FUZZ_RESILIENCE_SLACK_SECS: u64 = 25;

/// Postgres lock extension used when the campaign heartbeats the job row (matches worker LOCK_SECS).
pub const CAMPAIGN_LEASE_SECS: i64 = 300;

/// Engines that share the HTTP feedback-fuzz campaign path (canonical + aliases).
#[must_use]
pub fn is_fuzz_campaign_engine(engine_id: &str) -> bool {
    matches!(
        engine_id.trim(),
        "http_feedback_fuzz"
            | "xss_advanced"
            | "csrf_exploit"
            | "race_condition_web"
            | "open_redirect"
            | "sqli_advanced"
            | "api_fuzzing"
            | "nosql_injection"
    )
}

fn env_u64(key: &str, default: u64, min: u64, max: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

/// Wall-clock budget for one campaign. Always strictly less than the matching job timeout.
#[must_use]
pub fn campaign_wall_secs(_engine_id: &str, job_kind: Option<&str>) -> u64 {
    if job_kind == Some(FEEDBACK_FUZZ_JOB_KIND) {
        return env_u64(
            "WEISSMAN_FEEDBACK_FUZZ_WALL_SECS",
            DEFAULT_FEEDBACK_CAMPAIGN_SECS,
            60,
            FEEDBACK_FUZZ_JOB_SECS.saturating_sub(60),
        );
    }
    env_u64(
        "WEISSMAN_FUZZ_CAMPAIGN_WALL_SECS",
        DEFAULT_ALIAS_CAMPAIGN_SECS,
        15,
        COMMAND_CENTER_JOB_SECS.saturating_sub(90),
    )
}

/// Per-attempt resilience timeout for a fuzz-family engine. Must be **greater than 180s**
/// (the previous fake-timeout cap) and greater than the campaign wall.
#[must_use]
pub fn fuzz_resilience_timeout(engine_id: &str) -> Duration {
    if !is_fuzz_campaign_engine(engine_id) {
        return crate::engine_resilience::DEFAULT_ATTEMPT_TIMEOUT;
    }
    let wall = campaign_wall_secs(engine_id, None);
    Duration::from_secs(wall.saturating_add(FUZZ_RESILIENCE_SLACK_SECS))
}

/// Per-attempt timeout when a fuzz engine is one of many in `scan_all_engines`.
#[must_use]
pub fn batch_fuzz_resilience_timeout() -> Duration {
    Duration::from_secs(BATCH_FUZZ_CAMPAIGN_SECS.saturating_add(BATCH_FUZZ_RESILIENCE_SLACK_SECS))
}

/// Live campaign handle shared by specialized probes, static waves, and the generative producer.
#[derive(Clone)]
pub struct FuzzCampaignCtl {
    pub engine_id: String,
    pub wall: Duration,
    pub started: Instant,
    pub cancel: Arc<AtomicBool>,
    pub probes: Arc<AtomicU64>,
    last_url: Arc<Mutex<String>>,
    stages: Arc<Mutex<Vec<String>>>,
    coverage: Arc<Mutex<Vec<String>>>,
    pub job_id: Option<String>,
    pub tenant_id: Option<i64>,
    pub app_pool: Option<std::sync::Arc<sqlx::PgPool>>,
    pub swarm: Option<std::sync::Arc<tokio::sync::broadcast::Sender<String>>>,
    last_heartbeat: Arc<Mutex<Option<Instant>>>,
}

impl FuzzCampaignCtl {
    #[must_use]
    pub fn new(engine_id: impl Into<String>, wall: Duration) -> Self {
        Self {
            engine_id: engine_id.into(),
            wall,
            started: Instant::now(),
            cancel: Arc::new(AtomicBool::new(false)),
            probes: Arc::new(AtomicU64::new(0)),
            last_url: Arc::new(Mutex::new(String::new())),
            stages: Arc::new(Mutex::new(Vec::new())),
            coverage: Arc::new(Mutex::new(Vec::new())),
            job_id: None,
            tenant_id: None,
            app_pool: None,
            swarm: None,
            last_heartbeat: Arc::new(Mutex::new(None)),
        }
    }

    /// Optional operator override (`fuzz_budget_secs` on the scan body) for E2E windows.
    #[must_use]
    pub fn with_optional_budget_override(mut self, secs: Option<u64>) -> Self {
        if let Some(b) = secs {
            self.wall = Duration::from_secs(b.clamp(5, 2400));
        }
        self
    }

    pub fn bind_job(
        &mut self,
        job_id: Option<String>,
        tenant_id: Option<i64>,
        app_pool: Option<std::sync::Arc<sqlx::PgPool>>,
        swarm: Option<std::sync::Arc<tokio::sync::broadcast::Sender<String>>>,
    ) {
        self.job_id = job_id;
        self.tenant_id = tenant_id;
        self.app_pool = app_pool;
        self.swarm = swarm;
    }

    #[must_use]
    pub fn for_job(
        engine_id: &str,
        job_kind: Option<&str>,
        budget_override_secs: Option<u64>,
        job_id: Option<String>,
        tenant_id: Option<i64>,
        app_pool: Option<std::sync::Arc<sqlx::PgPool>>,
        swarm: Option<std::sync::Arc<tokio::sync::broadcast::Sender<String>>>,
    ) -> Self {
        let mut ctl = Self::new(
            engine_id,
            Duration::from_secs(campaign_wall_secs(engine_id, job_kind)),
        );
        ctl = ctl.with_optional_budget_override(budget_override_secs);
        ctl.bind_job(job_id, tenant_id, app_pool, swarm);
        ctl
    }

    #[must_use]
    pub fn expired(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || self.started.elapsed() >= self.wall
    }

    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.wall.saturating_sub(self.started.elapsed())
    }

    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn note_probe(&self, url: &str) {
        self.probes.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.last_url.lock() {
            *g = url.to_string();
        }
    }

    pub fn add_stage(&self, stage: &str) {
        if let Ok(mut g) = self.stages.lock() {
            if !g.iter().any(|s| s == stage) {
                g.push(stage.to_string());
            }
        }
    }

    pub fn add_coverage(&self, item: &str) {
        if let Ok(mut g) = self.coverage.lock() {
            if !g.iter().any(|s| s == item) {
                g.push(item.to_string());
            }
        }
    }

    #[must_use]
    pub fn last_url(&self) -> String {
        self.last_url.lock().map(|g| g.clone()).unwrap_or_default()
    }

    #[must_use]
    pub fn stages(&self) -> Vec<String> {
        self.stages.lock().map(|g| g.clone()).unwrap_or_default()
    }

    #[must_use]
    pub fn coverage(&self) -> Vec<String> {
        self.coverage.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Emit live progress (nerve center + swarm + Postgres lease heartbeat).
    pub async fn emit_progress(&self, phase: &str, findings_so_far: usize) {
        self.add_stage(phase);
        let probes = self.probes.load(Ordering::Relaxed);
        let last = self.last_url();
        let elapsed_ms = self.started.elapsed().as_millis() as u64;
        let payload = json!({
            "type": "fuzz_campaign_progress",
            "engine_id": self.engine_id,
            "job_id": self.job_id,
            "phase": phase,
            "probes_attempted": probes,
            "findings_so_far": findings_so_far,
            "last_url": last,
            "elapsed_ms": elapsed_ms,
            "budget_secs": self.wall.as_secs(),
            "remaining_ms": self.remaining().as_millis() as u64,
            "coverage": self.coverage(),
            "status": "running",
        });
        info!(
            target: "fuzz_campaign",
            engine = %self.engine_id,
            phase,
            probes,
            findings_so_far,
            elapsed_ms,
            "campaign progress"
        );
        if let Some(jid) = self.job_id.as_deref() {
            crate::supreme_nerve_center::run_phase(
                jid,
                phase,
                Some(&format!(
                    "probes={probes} findings={findings_so_far} last={last}"
                )),
            );
        }
        if let Some(tx) = self.swarm.as_ref() {
            let _ = tx.send(payload.to_string());
        }
        self.heartbeat_lease().await;
    }

    async fn heartbeat_lease(&self) {
        let due = {
            let Ok(g) = self.last_heartbeat.lock() else {
                return;
            };
            match *g {
                None => true,
                Some(t) => t.elapsed() >= Duration::from_secs(20),
            }
        };
        if !due {
            return;
        }
        let (Some(pool), Some(jid)) = (self.app_pool.as_ref(), self.job_id.as_deref()) else {
            return;
        };
        let Ok(uuid) = Uuid::parse_str(jid) else {
            return;
        };
        if let Err(e) =
            weissman_db::job_queue::heartbeat(pool.as_ref(), uuid, CAMPAIGN_LEASE_SECS).await
        {
            warn!(
                target: "fuzz_campaign",
                error = %e,
                job_id = %jid,
                "campaign lease heartbeat failed"
            );
        } else if let Ok(mut g) = self.last_heartbeat.lock() {
            *g = Some(Instant::now());
        }
    }
}

/// Guard that aborts a spawned producer when the campaign future is dropped (timeout/cancel).
pub struct AbortOnDrop(pub Option<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

#[derive(Debug, Clone)]
pub struct CampaignOutcome {
    pub anomalies: Vec<ValidatedAnomaly>,
    pub probes_attempted: u64,
    pub stages: Vec<String>,
    pub coverage: Vec<String>,
    pub budget_exhausted: bool,
    pub last_url: String,
    pub elapsed_ms: u64,
}

impl CampaignOutcome {
    #[must_use]
    pub fn message(&self, engine_id: &str, verified_oob: usize) -> String {
        let stages = if self.stages.is_empty() {
            "none".to_string()
        } else {
            self.stages.join(",")
        };
        let coverage = if self.coverage.is_empty() {
            "none".to_string()
        } else {
            self.coverage.join(",")
        };
        let budget = if self.budget_exhausted {
            "budget_exhausted"
        } else {
            "completed"
        };
        if self.anomalies.is_empty() {
            format!(
                "{engine_id}: no live signal after {} HTTP probes (stages [{stages}]; coverage [{coverage}]; last_url={}; {budget}; {}ms)",
                self.probes_attempted,
                self.last_url,
                self.elapsed_ms
            )
        } else {
            format!(
                "{engine_id}: {} validated anomalies ({} OOB-verified) after {} HTTP probes (stages [{stages}]; coverage [{coverage}]; {budget}; {}ms)",
                self.anomalies.len(),
                verified_oob,
                self.probes_attempted,
                self.elapsed_ms
            )
        }
    }
}

/// Map a validated anomaly to an engine finding. HTTP proof is required for `verified=true`
/// unless OAST correlated; never emit a timeout placeholder.
#[must_use]
pub fn anomaly_to_finding(
    engine_id: &str,
    a: &ValidatedAnomaly,
    category: &str,
    mitre: &str,
    target: &str,
) -> Value {
    let oob = a.oob_token.clone().filter(|s| !s.trim().is_empty());
    let has_http = a.http_status.is_some();
    let verified = oob.is_some() || has_http;
    let verification_method = if oob.is_some() {
        "oob_oast_callback"
    } else if has_http {
        "http_response_proof"
    } else {
        "behavioral_feedback_validation"
    };
    let mut http_proof = json!({});
    if let Some(st) = a.http_status {
        http_proof["status"] = json!(st);
    }
    if let Some(ref m) = a.http_method {
        http_proof["method"] = json!(m);
    }
    if let Some(ref ex) = a.response_excerpt {
        http_proof["response_excerpt"] = json!(ex);
    }
    if let Some(ref loc) = a.location_header {
        http_proof["location"] = json!(loc);
    }
    if let Some(lat) = a.latency_ms {
        http_proof["latency_ms"] = json!((lat * 10.0).round() / 10.0);
    }
    json!({
        "type": engine_id,
        "source_engine": engine_id,
        "engine_id": engine_id,
        "canonical_engine": "http_feedback_fuzz",
        "alias_engine_id": engine_id,
        "canonical_engine_id": "http_feedback_fuzz",
        "probe_fidelity": "http_campaign_live",
        "alias_category": category,
        "category": category,
        "title": a.anomaly_type.chars().take(500).collect::<String>(),
        "severity": if oob.is_some() { "critical" } else { "high" },
        "mitre_attack": mitre,
        "description": format!("{} — {}", engine_id, a.baseline_vs_anomaly),
        "url": a.target_url,
        "payload": a.payload,
        "poc": a.payload,
        "verified": verified,
        "verification_method": verification_method,
        "oob_token": oob,
        "llm_user_prompt": a.llm_user_prompt,
        "target": target,
        "evidence_kind": a.evidence_kind,
        "http_proof": http_proof,
        "evidence": {
            "http_status": a.http_status,
            "http_method": a.http_method,
            "response_excerpt": a.response_excerpt,
            "location": a.location_header,
            "latency_ms": a.latency_ms,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_family_ids_recognized() {
        for id in [
            "http_feedback_fuzz",
            "xss_advanced",
            "csrf_exploit",
            "race_condition_web",
            "open_redirect",
            "sqli_advanced",
            "api_fuzzing",
            "nosql_injection",
        ] {
            assert!(is_fuzz_campaign_engine(id), "{id}");
        }
        assert!(!is_fuzz_campaign_engine("osint"));
        assert!(!is_fuzz_campaign_engine(""));
    }

    #[test]
    fn alias_campaign_fits_inside_command_center_job() {
        let wall = campaign_wall_secs("xss_advanced", Some("command_center_engine"));
        assert!(
            wall + FUZZ_RESILIENCE_SLACK_SECS < COMMAND_CENTER_JOB_SECS,
            "campaign {wall}s + slack must finish before the 15min job"
        );
        assert!(
            wall >= 15,
            "campaign must be long enough for real staged probes"
        );
    }

    #[test]
    fn feedback_job_campaign_fits_inside_30min() {
        let wall = campaign_wall_secs("http_feedback_fuzz", Some(FEEDBACK_FUZZ_JOB_KIND));
        assert!(wall < FEEDBACK_FUZZ_JOB_SECS);
        assert!(wall >= 60);
        assert!(
            wall >= 20 * 60,
            "dedicated feedback_fuzz must keep a long real campaign, not a dummy 45s run; got {wall}"
        );
    }

    #[test]
    fn resilience_timeout_exceeds_fake_180s_cap() {
        let t = fuzz_resilience_timeout("xss_advanced");
        assert!(
            t > Duration::from_secs(180),
            "fuzz aliases must not use the 180s fake-timeout cap; got {:?}",
            t
        );
        assert!(t > Duration::from_secs(campaign_wall_secs("xss_advanced", None)));
        assert_eq!(
            fuzz_resilience_timeout("osint"),
            crate::engine_resilience::DEFAULT_ATTEMPT_TIMEOUT
        );
        let batch = batch_fuzz_resilience_timeout();
        assert_ne!(
            batch,
            Duration::from_secs(180),
            "batch fuzz timeout must not equal the fake 180s cap"
        );
        assert!(batch > Duration::from_secs(BATCH_FUZZ_CAMPAIGN_SECS));
        assert!(batch < Duration::from_secs(180));
    }

    #[test]
    fn campaign_ctl_expires_on_cancel_and_wall() {
        let ctl = FuzzCampaignCtl::new("xss_advanced", Duration::from_millis(50));
        assert!(!ctl.expired());
        ctl.request_cancel();
        assert!(ctl.expired());
        let ctl2 = FuzzCampaignCtl::new("xss_advanced", Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(ctl2.expired());
    }

    #[test]
    fn anomaly_finding_requires_http_proof_for_verified() {
        let a = ValidatedAnomaly::new("https://t", "p", "title", "base vs");
        let f = anomaly_to_finding("xss_advanced", &a, "xss", "T1189", "https://t");
        assert_eq!(f["verified"], false);
        assert_eq!(f["verification_method"], "behavioral_feedback_validation");
        let proved = a.with_http_proof("GET", 200, "<svg>weissman_xss_prb_9f3a</svg>", 12.0);
        let f2 = anomaly_to_finding("xss_advanced", &proved, "xss", "T1189", "https://t");
        assert_eq!(f2["verified"], true);
        assert_eq!(f2["verification_method"], "http_response_proof");
        assert_eq!(f2["http_proof"]["status"], 200);
        assert_eq!(f2["http_proof"]["method"], "GET");
        assert!(f2["http_proof"]["response_excerpt"]
            .as_str()
            .unwrap()
            .contains("weissman_xss_prb_9f3a"));
        assert_eq!(f2["canonical_engine"], "http_feedback_fuzz");
    }

    #[test]
    fn timeout_placeholder_is_not_a_finding_shape() {
        // Guard: campaign findings must never look like the old "timed out (180s)" error row.
        let a = ValidatedAnomaly::new("https://t", "", "engine timed out (180s)", "timeout");
        let f = anomaly_to_finding("xss_advanced", &a, "xss", "T1189", "https://t");
        assert_eq!(f["verified"], false);
        assert!(f["http_proof"].as_object().unwrap().is_empty());
    }

    #[test]
    fn honest_empty_message_lists_coverage() {
        let out = CampaignOutcome {
            anomalies: vec![],
            probes_attempted: 12,
            stages: vec!["surface".into(), "xss".into()],
            coverage: vec!["query_q".into(), "form_csrf".into()],
            budget_exhausted: true,
            last_url: "https://example.com/?q=x".into(),
            elapsed_ms: 1500,
        };
        let msg = out.message("xss_advanced", 0);
        assert!(msg.contains("no live signal"));
        assert!(msg.contains("12 HTTP probes"));
        assert!(msg.contains("budget_exhausted"));
        assert!(msg.contains("query_q"));
        assert!(!msg.contains("timed out (180s)"));
    }

    #[tokio::test]
    async fn abort_on_drop_cancels_spawned_producer() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        {
            let h = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let _ = tx.send(());
            });
            let _guard = AbortOnDrop(Some(h));
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            rx.await.is_err(),
            "LLM producer must die with the campaign future"
        );
    }
}
