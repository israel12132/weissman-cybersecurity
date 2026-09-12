//! Live scan → finding → evidence spine for operators and attached agents.
//!
//! Joins tenant scan jobs with persisted vulnerabilities so Command Center can
//! show whether attack/scan/finding work is actually live: evidence-backed,
//! live-verified, MITRE-mapped, or stuck. No fabricated findings.

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};

/// Job kinds that represent attack-surface / scan / discovery work.
pub const SCAN_KINDS: &[&str] = &[
    "tenant_full_scan",
    "onboarding_tenant_scan",
    "scan_all_engines",
    "scan_discovered_domains",
    "command_center_engine",
    "pipeline_scan",
    "cloud_scan_run",
    "poe_synthesis_run",
    "deep_fuzz",
    "timing_scan",
];

const STUCK_AFTER: Duration = Duration::minutes(15);

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpineKpis {
    pub findings_total: i64,
    pub open_findings: i64,
    pub high_critical: i64,
    pub evidence: i64,
    pub proven: i64,
    pub verified: i64,
    pub unverified_critical: i64,
    pub mitre: i64,
    pub open_without_evidence: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EngineRollup {
    pub source: String,
    pub findings: i64,
    pub open_findings: i64,
    pub high_critical: i64,
    pub evidence: i64,
    pub proven: i64,
    pub verified: i64,
    pub unverified_critical: i64,
    pub mitre: i64,
    pub reality_kind: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanJobView {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub last_error: Option<String>,
    pub attempt_count: i32,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub heartbeat_at: Option<DateTime<Utc>>,
    pub engine: Option<String>,
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpineGap {
    pub id: &'static str,
    pub severity: &'static str,
    pub count: i64,
    pub detail: String,
}

#[must_use]
pub fn is_scan_kind(kind: &str) -> bool {
    SCAN_KINDS.iter().any(|k| *k == kind)
}

#[must_use]
pub fn proven_verdict(verdict: &str) -> bool {
    matches!(verdict, "CONFIRMED" | "LIKELY_VALID")
}

#[must_use]
pub fn job_is_stuck(job: &ScanJobView, now: DateTime<Utc>) -> bool {
    if job.status != "running" {
        return false;
    }
    let age_from = job.heartbeat_at.or(job.updated_at).or(job.created_at);
    match age_from {
        Some(ts) => now.signed_duration_since(ts) >= STUCK_AFTER,
        None => true,
    }
}

#[must_use]
pub fn classify_gaps(
    kpis: &SpineKpis,
    latest_completed: Option<&ScanJobView>,
    failed_recent: i64,
    stuck: i64,
) -> Vec<SpineGap> {
    let mut gaps = Vec::new();
    if let Some(job) = latest_completed {
        if kpis.findings_total == 0 {
            gaps.push(SpineGap {
                id: "completed_scan_zero_findings",
                severity: "high",
                count: 1,
                detail: format!(
                    "Latest completed {} ({}) produced zero persisted findings",
                    job.kind, job.id
                ),
            });
        }
    }
    if kpis.unverified_critical > 0 {
        gaps.push(SpineGap {
            id: "unverified_critical",
            severity: "critical",
            count: kpis.unverified_critical,
            detail: format!(
                "{} open critical/high findings have no live verification",
                kpis.unverified_critical
            ),
        });
    }
    if kpis.open_without_evidence > 0 {
        gaps.push(SpineGap {
            id: "open_without_evidence",
            severity: "high",
            count: kpis.open_without_evidence,
            detail: format!(
                "{} open findings are not evidence-sealed (poc_sealed)",
                kpis.open_without_evidence
            ),
        });
    }
    if failed_recent > 0 {
        gaps.push(SpineGap {
            id: "failed_scans",
            severity: "high",
            count: failed_recent,
            detail: format!("{failed_recent} recent scan jobs failed or are dead"),
        });
    }
    if stuck > 0 {
        gaps.push(SpineGap {
            id: "stuck_scans",
            severity: "high",
            count: stuck,
            detail: format!("{stuck} scan jobs still running with stale heartbeat"),
        });
    }
    gaps
}

#[must_use]
pub fn build_spine_payload(
    kpis: SpineKpis,
    engines: Vec<EngineRollup>,
    scans: Vec<ScanJobView>,
    generated_at: DateTime<Utc>,
) -> Value {
    let now = generated_at;
    let running = scans.iter().filter(|j| j.status == "running").count() as i64;
    let failed_recent = scans
        .iter()
        .filter(|j| j.status == "failed" || j.status == "dead")
        .count() as i64;
    let stuck = scans.iter().filter(|j| job_is_stuck(j, now)).count() as i64;
    let latest = scans.first();
    let latest_completed = scans.iter().find(|j| j.status == "completed");
    let gaps = classify_gaps(&kpis, latest_completed, failed_recent, stuck);

    json!({
        "ok": true,
        "live": true,
        "generated_at": generated_at.to_rfc3339(),
        "kpis": {
            "findings_total": kpis.findings_total,
            "open_findings": kpis.open_findings,
            "high_critical": kpis.high_critical,
            "evidence": kpis.evidence,
            "proven": kpis.proven,
            "verified": kpis.verified,
            "unverified_critical": kpis.unverified_critical,
            "mitre": kpis.mitre,
            "open_without_evidence": kpis.open_without_evidence,
            "scans_running": running,
            "scans_failed": failed_recent,
            "scans_stuck": stuck,
            "engines_with_findings": engines.len(),
        },
        "latest_scan": latest.map(scan_job_json),
        "gaps": gaps.iter().map(|g| json!({
            "id": g.id,
            "severity": g.severity,
            "count": g.count,
            "detail": g.detail,
        })).collect::<Vec<_>>(),
        "engines": engines.iter().map(|e| json!({
            "source": e.source,
            "findings": e.findings,
            "open_findings": e.open_findings,
            "high_critical": e.high_critical,
            "evidence": e.evidence,
            "proven": e.proven,
            "verified": e.verified,
            "unverified_critical": e.unverified_critical,
            "mitre": e.mitre,
            "reality_kind": e.reality_kind,
        })).collect::<Vec<_>>(),
        "scans": scans.iter().map(scan_job_json).collect::<Vec<_>>(),
    })
}

fn scan_job_json(job: &ScanJobView) -> Value {
    json!({
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "last_error": job.last_error,
        "attempt_count": job.attempt_count,
        "created_at": job.created_at.map(|d| d.to_rfc3339()),
        "updated_at": job.updated_at.map(|d| d.to_rfc3339()),
        "heartbeat_at": job.heartbeat_at.map(|d| d.to_rfc3339()),
        "engine": job.engine,
        "target": job.target,
        "stuck": job_is_stuck(job, Utc::now()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_kinds_cover_tenant_and_onboarding() {
        assert!(is_scan_kind("tenant_full_scan"));
        assert!(is_scan_kind("onboarding_tenant_scan"));
        assert!(!is_scan_kind("noop"));
    }

    #[test]
    fn proven_verdicts_are_strict() {
        assert!(proven_verdict("CONFIRMED"));
        assert!(proven_verdict("LIKELY_VALID"));
        assert!(!proven_verdict("NOISE"));
        assert!(!proven_verdict("INCONCLUSIVE"));
    }

    #[test]
    fn stuck_when_running_without_heartbeat() {
        let job = ScanJobView {
            id: "j1".into(),
            kind: "tenant_full_scan".into(),
            status: "running".into(),
            last_error: None,
            attempt_count: 1,
            created_at: None,
            updated_at: None,
            heartbeat_at: None,
            engine: None,
            target: None,
        };
        assert!(job_is_stuck(&job, Utc::now()));
        let mut done = job.clone();
        done.status = "completed".into();
        assert!(!job_is_stuck(&done, Utc::now()));
    }

    #[test]
    fn gaps_flag_zero_findings_and_unverified() {
        let kpis = SpineKpis {
            findings_total: 0,
            unverified_critical: 4,
            open_without_evidence: 2,
            ..SpineKpis::default()
        };
        let completed = ScanJobView {
            id: "abc".into(),
            kind: "tenant_full_scan".into(),
            status: "completed".into(),
            last_error: None,
            attempt_count: 1,
            created_at: None,
            updated_at: None,
            heartbeat_at: None,
            engine: None,
            target: None,
        };
        let gaps = classify_gaps(&kpis, Some(&completed), 1, 1);
        let ids: Vec<_> = gaps.iter().map(|g| g.id).collect();
        assert!(ids.contains(&"completed_scan_zero_findings"));
        assert!(ids.contains(&"unverified_critical"));
        assert!(ids.contains(&"open_without_evidence"));
        assert!(ids.contains(&"failed_scans"));
        assert!(ids.contains(&"stuck_scans"));
    }

    #[test]
    fn spine_payload_is_live_and_ok() {
        let kpis = SpineKpis {
            findings_total: 3,
            open_findings: 2,
            evidence: 1,
            ..SpineKpis::default()
        };
        let engines = vec![EngineRollup {
            source: "asm".into(),
            findings: 3,
            open_findings: 2,
            high_critical: 1,
            evidence: 1,
            proven: 0,
            verified: 1,
            unverified_critical: 1,
            mitre: 1,
            reality_kind: "real_probe".into(),
        }];
        let body = build_spine_payload(kpis, engines, Vec::new(), Utc::now());
        assert_eq!(body["ok"], true);
        assert_eq!(body["live"], true);
        assert_eq!(body["kpis"]["findings_total"], 3);
        assert_eq!(body["engines"][0]["source"], "asm");
        assert!(body["gaps"].as_array().unwrap().is_empty());
    }

    #[test]
    fn spine_route_is_mounted() {
        let routes = include_str!("http/serve_route_groups.rs");
        assert!(
            routes.contains("/api/scan-finding-spine"),
            "GET /api/scan-finding-spine must be mounted"
        );
        let handlers = include_str!("server_handlers_jobs.inc");
        assert!(
            handlers.contains("async fn api_scan_finding_spine"),
            "api_scan_finding_spine handler must exist"
        );
    }
}
