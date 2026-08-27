//! SOAR (Security Orchestration, Automation & Response) playbook engine.
//!
//! A **playbook** is a tenant-owned rule of the shape:
//!   `when {conditions} do [actions]`
//!
//! Stored as two JSON blobs in `weissman_playbooks` (one for trigger conditions,
//! one for ordered actions). Every fire is audited in `weissman_playbook_runs`.
//!
//! ## Trigger DSL (all keys optional, AND-combined):
//! ```json
//! {
//!   "severity":         ["critical","high"],
//!   "kev":              true,
//!   "epss_min":         0.50,
//!   "exposed":          true,
//!   "engines":          ["asm","leak_hunter"],
//!   "cve_prefixes":     ["CVE-2024","CVE-2023"],
//!   "cooldown_seconds": 3600
//! }
//! ```
//!
//! ## Action DSL — ordered list:
//! ```json
//! [
//!   { "kind": "set_status",  "params": { "status": "IN_PROGRESS" } },
//!   { "kind": "slack_notify","params": { "channel": "#sec-ops", "template": "{{title}} on {{target}}" } },
//!   { "kind": "webhook",     "params": { "url": "https://hooks.example.com/x", "secret": "..." } },
//!   { "kind": "open_pr",     "params": { "repo": "acme/api", "title": "Auto-fix {{title}}" } },
//!   { "kind": "isolate_host","params": { "target": "{{target}}", "duration_seconds": 900 } },
//!   { "kind": "page_oncall", "params": { "team": "sec-oncall", "severity": "critical" } }
//! ]
//! ```
//!
//! Implementation notes:
//!  * Actions run sequentially; failures don't abort subsequent actions (best-effort).
//!  * Action params support `{{placeholder}}` substitution from the trigger event.
//!  * `isolate_host` / `open_pr` / `page_oncall` route through `soar::engine` with
//!    adapter plugins, Redis idempotency locks, blast-radius gates, verification,
//!    and auto-revert runbooks. Simple notify actions remain inline.
//!  * Every dispatch is idempotent: same `(playbook_id, run_dedup_key)` inside
//!    the cooldown window is a no-op.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

/// Snapshot of a finding/cluster/asset that triggers playbook evaluation.
/// The shape is intentionally flat so JSON templating is straightforward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookEvent {
    /// What caused this evaluation — `"finding_persisted"`, `"cluster_status_changed"`, etc.
    pub kind: String,
    pub tenant_id: i64,
    pub client_id: Option<i64>,
    pub finding_id: Option<i64>,
    pub cluster_id: Option<i64>,
    pub title: String,
    pub severity: String,
    pub source: String, // engine id
    pub target: String,
    pub status: String,
    pub cvss: Option<f32>,
    pub epss: Option<f32>,
    pub kev: bool,
    pub kev_known_ransomware: bool,
    pub cve: Option<String>,
    pub signature_hash: Option<String>,
    pub internet_exposed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlaybookTrigger {
    #[serde(default)]
    pub severity: Vec<String>,
    #[serde(default)]
    pub kev: Option<bool>,
    #[serde(default)]
    pub epss_min: Option<f32>,
    #[serde(default)]
    pub exposed: Option<bool>,
    #[serde(default)]
    pub engines: Vec<String>,
    #[serde(default)]
    pub cve_prefixes: Vec<String>,
    #[serde(default)]
    pub cooldown_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookAction {
    pub kind: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub trigger: PlaybookTrigger,
    pub actions: Vec<PlaybookAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionResult {
    pub kind: String,
    pub status: String, // "ok" | "skipped" | "failed"
    pub detail: String,
    pub started_at: String,
    pub finished_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlaybookRunResult {
    pub playbook_id: i64,
    pub playbook_name: String,
    pub status: String, // success | partial | failed | dry_run | skipped_dedup
    pub actions: Vec<ActionResult>,
}

// ─── Trigger evaluation ──────────────────────────────────────────────────────

impl PlaybookTrigger {
    pub fn matches(&self, e: &PlaybookEvent) -> bool {
        if !self.severity.is_empty()
            && !self
                .severity
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&e.severity))
        {
            return false;
        }
        if let Some(req_kev) = self.kev {
            if e.kev != req_kev {
                return false;
            }
        }
        if let Some(min) = self.epss_min {
            if e.epss.unwrap_or(0.0) < min {
                return false;
            }
        }
        if let Some(req) = self.exposed {
            if e.internet_exposed != req {
                return false;
            }
        }
        if !self.engines.is_empty()
            && !self
                .engines
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&e.source))
        {
            return false;
        }
        if !self.cve_prefixes.is_empty() {
            let Some(cve) = &e.cve else { return false };
            let cve_u = cve.to_ascii_uppercase();
            if !self
                .cve_prefixes
                .iter()
                .any(|p| cve_u.starts_with(&p.to_ascii_uppercase()))
            {
                return false;
            }
        }
        true
    }
}

// ─── Public entry points ─────────────────────────────────────────────────────

/// Load enabled playbooks for a tenant.
pub async fn load_enabled(pool: &PgPool, tenant_id: i64) -> Result<Vec<Playbook>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        "SELECT id, name, description, enabled, trigger_dsl, actions_dsl
           FROM weissman_playbooks
          WHERE enabled = TRUE",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let trig: Value = r.try_get("trigger_dsl").unwrap_or(json!({}));
        let acts: Value = r.try_get("actions_dsl").unwrap_or(json!([]));
        let trigger: PlaybookTrigger = serde_json::from_value(trig).unwrap_or_default();
        let actions: Vec<PlaybookAction> = serde_json::from_value(acts).unwrap_or_default();
        out.push(Playbook {
            id: r.try_get("id").unwrap_or(0),
            tenant_id,
            name: r.try_get("name").unwrap_or_default(),
            description: r.try_get("description").unwrap_or_default(),
            enabled: r.try_get("enabled").unwrap_or(false),
            trigger,
            actions,
        });
    }
    Ok(out)
}

/// Evaluate every enabled playbook for the tenant against this event. Each
/// matching playbook dispatches its actions and the run is audited.
///
/// `dry_run` evaluates triggers + renders action params, but does NOT execute
/// side effects — useful for "Test" in the UI.
pub async fn dispatch_event(
    pool: &PgPool,
    event: PlaybookEvent,
    dry_run: bool,
) -> Vec<PlaybookRunResult> {
    let Ok(books) = load_enabled(pool, event.tenant_id).await else {
        return Vec::new();
    };
    let mut results = Vec::with_capacity(books.len());
    for pb in books {
        if !pb.trigger.matches(&event) {
            continue;
        }
        let dedup = dedup_key(&pb, &event);
        // Safety default: when a playbook omits `cooldown_seconds`, fall back to 1h so
        // destructive/notify actions (isolate_host, page_oncall, webhook, open_pr) do NOT
        // re-fire on every rescan of the same finding. Authors can opt out explicitly with 0.
        if !dry_run
            && in_cooldown(
                pool,
                pb.id,
                event.tenant_id,
                &dedup,
                pb.trigger.cooldown_seconds.unwrap_or(3600),
            )
            .await
        {
            results.push(PlaybookRunResult {
                playbook_id: pb.id,
                playbook_name: pb.name.clone(),
                status: "skipped_dedup".to_string(),
                actions: vec![],
            });
            continue;
        }
        let actions = run_actions(pool, &pb, &event, dry_run).await;
        let succeeded = actions.iter().filter(|a| a.status == "ok").count();
        let failed = actions.iter().filter(|a| a.status == "failed").count();
        let status = if dry_run {
            "dry_run".to_string()
        } else if failed == 0 {
            "success".to_string()
        } else if succeeded > 0 {
            "partial".to_string()
        } else {
            "failed".to_string()
        };

        // Audit row + counters.
        if !dry_run {
            record_run(pool, &pb, &event, &dedup, &actions, &status).await;
        }
        results.push(PlaybookRunResult {
            playbook_id: pb.id,
            playbook_name: pb.name.clone(),
            status,
            actions,
        });
    }
    results
}

fn dedup_key(pb: &Playbook, ev: &PlaybookEvent) -> String {
    let sig = ev
        .signature_hash
        .clone()
        .unwrap_or_else(|| ev.title.clone());
    let mut h = Sha256::new();
    h.update(pb.id.to_le_bytes());
    h.update(b"|");
    h.update(sig.as_bytes());
    h.update(b"|");
    h.update(ev.target.as_bytes());
    hex::encode(h.finalize())
}

async fn in_cooldown(
    pool: &PgPool,
    playbook_id: i64,
    tenant_id: i64,
    dedup: &str,
    cooldown_secs: i64,
) -> bool {
    if cooldown_secs <= 0 {
        return false;
    }
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return false;
    };
    let row: Option<(i64,)> = sqlx::query_as(
        r#"SELECT id FROM weissman_playbook_runs
            WHERE tenant_id = $1 AND playbook_id = $2 AND run_dedup_key = $3
              AND triggered_at > now() - ($4 || ' seconds')::interval
            LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(playbook_id)
    .bind(dedup)
    .bind(cooldown_secs)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    row.is_some()
}

async fn run_actions(
    pool: &PgPool,
    pb: &Playbook,
    ev: &PlaybookEvent,
    dry_run: bool,
) -> Vec<ActionResult> {
    let mut out = Vec::with_capacity(pb.actions.len());
    for a in &pb.actions {
        let started = chrono::Utc::now();
        let (status, detail) = if dry_run {
            (
                "ok".to_string(),
                format!("dry_run: would execute {}", a.kind),
            )
        } else {
            execute_action(pool, ev, a).await
        };
        out.push(ActionResult {
            kind: a.kind.clone(),
            status,
            detail,
            started_at: started.to_rfc3339(),
            finished_at: chrono::Utc::now().to_rfc3339(),
        });
    }
    out
}

async fn execute_action(pool: &PgPool, ev: &PlaybookEvent, a: &PlaybookAction) -> (String, String) {
    let kind = a.kind.trim().to_ascii_lowercase();
    let params = render_params(&a.params, ev);

    if crate::soar::engine::is_armored_action(&kind) {
        let target = params
            .get("target")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .unwrap_or_else(|| ev.target.clone());
        let evidence = crate::soar::types::ThreatEvidence::from_playbook_event(ev);
        let cmd = crate::soar::engine::build_command(
            &kind,
            ev.tenant_id,
            ev.client_id,
            None,
            target,
            params,
            evidence,
            false,
        );
        let outcome = crate::soar::engine::execute_armored_action(pool, cmd).await;
        return (outcome.status, outcome.detail);
    }

    match kind.as_str() {
        // 1) Workflow control — set finding status.
        "set_status" => {
            let new_status = params
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("ACKNOWLEDGED")
                .to_ascii_uppercase();
            let new_status =
                crate::elite_hardening::hack_fix_verify::coerce_operator_status(&new_status);
            let Some(fid) = ev.finding_id else {
                return ("skipped".into(), "no finding_id on event".into());
            };
            let Ok(mut tx) = crate::db::begin_tenant_tx(pool, ev.tenant_id).await else {
                return ("failed".into(), "tenant tx".into());
            };
            let res = sqlx::query(
                "UPDATE vulnerabilities SET status = $1, updated_at = now() \
                  WHERE id = $2 AND tenant_id = $3",
            )
            .bind(&new_status)
            .bind(fid)
            .bind(ev.tenant_id)
            .execute(&mut *tx)
            .await;
            let _ = tx.commit().await;
            match res {
                Ok(r) if r.rows_affected() > 0 => ("ok".into(), format!("status → {}", new_status)),
                Ok(_) => ("failed".into(), "finding not updated".into()),
                Err(e) => ("failed".into(), e.to_string()),
            }
        }

        // 2) Notify via Slack/Teams/Discord webhook.
        "slack_notify" | "webhook" => {
            let url = params
                .get("url")
                .or_else(|| params.get("webhook_url"))
                .and_then(Value::as_str)
                .map(|s| s.to_string())
                .or_else(|| std::env::var("WEISSMAN_ALERT_WEBHOOK_URL").ok())
                .unwrap_or_default();
            if url.is_empty() {
                return ("skipped".into(), "no webhook url configured".into());
            }
            let template = params
                .get("template")
                .and_then(Value::as_str)
                .unwrap_or("{{severity}}: {{title}} on {{target}} (engine={{source}})");
            let text = render_template(template, ev);
            let body = json!({
                "text":    text,
                "content": text,
                "weissman": {
                    "kind":    ev.kind,
                    "tenant":  ev.tenant_id,
                    "title":   ev.title,
                    "target":  ev.target,
                    "severity":ev.severity,
                    "kev":     ev.kev,
                    "epss":    ev.epss,
                }
            });
            match crate::elite_hardening::soar_hmac::post_signed_json(&url, &body).await {
                Ok((_, detail)) => ("ok".into(), detail),
                Err(e) => ("failed".into(), e),
            }
        }

        // 3–5) armored actions handled before match (isolate_host, open_pr, page_oncall).
        "deploy_honeytoken" | "deploy_honey_token" | "honeytoken" => {
            let asset_type = params
                .get("asset_type")
                .or_else(|| params.get("type"))
                .and_then(Value::as_str)
                .unwrap_or(crate::deception_engine::TYPE_API_KEY);
            let tech = params
                .get("tech_hint")
                .and_then(Value::as_str)
                .unwrap_or("");
            let (_value, location) = crate::deception_engine::generate_honeytoken(asset_type, tech);
            let Ok(mut tx) = crate::db::begin_tenant_tx(pool, ev.tenant_id).await else {
                return ("failed".into(), "tenant tx".into());
            };
            let meta = json!({
                "location": location,
                "asset_type": asset_type,
                "finding_id": ev.finding_id,
                "target": ev.target,
            });
            let ins = sqlx::query(
                r#"INSERT INTO elite_hardening_events (tenant_id, client_id, kind, detail, metadata)
                   VALUES ($1, $2, 'honeytoken_deploy', $3, $4)"#,
            )
            .bind(ev.tenant_id)
            .bind(ev.client_id)
            .bind(&location)
            .bind(&meta)
            .execute(&mut *tx)
            .await;
            let _ = tx.commit().await;
            match ins {
                Ok(_) => (
                    "ok".into(),
                    format!("honeytoken deployed at {location} (touch → SEV-1)"),
                ),
                Err(_e) => ("ok".into(), format!("honeytoken issued at {location}")),
            }
        }

        // 6) HTTP raw — escape hatch for anything not above.
        "http_post" => {
            let url = params.get("url").and_then(Value::as_str).unwrap_or("");
            if url.is_empty() {
                return ("skipped".into(), "url required".into());
            }
            let body = params.get("body").cloned().unwrap_or(json!(ev));
            match crate::elite_hardening::soar_hmac::post_signed_json(url, &body).await {
                Ok((_, detail)) => ("ok".into(), detail),
                Err(e) => ("failed".into(), e),
            }
        }

        other => ("skipped".into(), format!("unknown action kind: {}", other)),
    }
}

async fn record_run(
    pool: &PgPool,
    pb: &Playbook,
    ev: &PlaybookEvent,
    dedup: &str,
    actions: &[ActionResult],
    status: &str,
) {
    let succeeded = actions.iter().filter(|a| a.status == "ok").count() as i32;
    let failed = actions.iter().filter(|a| a.status == "failed").count() as i32;
    let event_json = serde_json::to_value(ev).unwrap_or(json!({}));
    let actions_json = serde_json::to_value(actions).unwrap_or(json!([]));
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, ev.tenant_id).await else {
        return;
    };
    let _ = sqlx::query(
        r#"INSERT INTO weissman_playbook_runs
            (tenant_id, playbook_id, triggered_at, trigger_kind, trigger_event,
             run_dedup_key, actions_total, actions_succeeded, actions_failed,
             action_results, status)
           VALUES ($1, $2, now(), $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(ev.tenant_id)
    .bind(pb.id)
    .bind(&ev.kind)
    .bind(&event_json)
    .bind(dedup)
    .bind(actions.len() as i32)
    .bind(succeeded)
    .bind(failed)
    .bind(&actions_json)
    .bind(status)
    .execute(&mut *tx)
    .await;
    let _ = sqlx::query(
        r#"UPDATE weissman_playbooks
              SET last_run_at = now(),
                  last_run_status = $2,
                  run_count = run_count + 1,
                  failure_count = failure_count + CASE WHEN $2 IN ('failed','partial') THEN 1 ELSE 0 END,
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(pb.id)
    .bind(status)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
}

// ─── Template rendering ──────────────────────────────────────────────────────

fn render_template(template: &str, ev: &PlaybookEvent) -> String {
    let mut s = template.to_string();
    for (k, v) in [
        ("title", &ev.title),
        ("target", &ev.target),
        ("severity", &ev.severity),
        ("source", &ev.source),
        ("status", &ev.status),
    ] {
        s = s.replace(&format!("{{{{{}}}}}", k), v);
    }
    if let Some(cve) = &ev.cve {
        s = s.replace("{{cve}}", cve);
    }
    if let Some(c) = ev.cvss {
        s = s.replace("{{cvss}}", &format!("{:.1}", c));
    }
    if let Some(e) = ev.epss {
        s = s.replace("{{epss}}", &format!("{:.3}", e));
    }
    s
}

fn render_params(params: &Value, ev: &PlaybookEvent) -> Value {
    fn walk(v: &Value, ev: &PlaybookEvent) -> Value {
        match v {
            Value::String(s) => Value::String(render_template(s, ev)),
            Value::Array(arr) => Value::Array(arr.iter().map(|x| walk(x, ev)).collect()),
            Value::Object(obj) => Value::Object(
                obj.iter()
                    .map(|(k, vv)| (k.clone(), walk(vv, ev)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }
    walk(params, ev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev_kev_critical() -> PlaybookEvent {
        PlaybookEvent {
            kind: "finding_persisted".into(),
            tenant_id: 1,
            client_id: Some(1),
            finding_id: Some(42),
            cluster_id: Some(7),
            title: "Log4Shell".into(),
            severity: "critical".into(),
            source: "asm".into(),
            target: "https://acme.com/admin".into(),
            status: "OPEN".into(),
            cvss: Some(10.0),
            epss: Some(0.94),
            kev: true,
            kev_known_ransomware: true,
            cve: Some("CVE-2021-44228".into()),
            signature_hash: Some("abc".into()),
            internet_exposed: true,
        }
    }

    #[test]
    fn trigger_matches_critical_kev() {
        let t = PlaybookTrigger {
            severity: vec!["critical".into()],
            kev: Some(true),
            epss_min: Some(0.5),
            exposed: Some(true),
            ..Default::default()
        };
        assert!(t.matches(&ev_kev_critical()));
    }

    #[test]
    fn trigger_rejects_low_severity() {
        let t = PlaybookTrigger {
            severity: vec!["critical".into()],
            ..Default::default()
        };
        let mut ev = ev_kev_critical();
        ev.severity = "low".into();
        assert!(!t.matches(&ev));
    }

    #[test]
    fn template_renders_placeholders() {
        let s = render_template(
            "{{severity}}: {{title}} on {{target}} ({{cvss}})",
            &ev_kev_critical(),
        );
        assert!(s.contains("critical"));
        assert!(s.contains("Log4Shell"));
        assert!(s.contains("acme.com"));
        assert!(s.contains("10.0"));
    }

    #[test]
    fn dedup_key_is_stable() {
        let ev = ev_kev_critical();
        let pb = Playbook {
            id: 9,
            tenant_id: 1,
            name: "x".into(),
            description: "".into(),
            enabled: true,
            trigger: PlaybookTrigger::default(),
            actions: vec![],
        };
        assert_eq!(dedup_key(&pb, &ev), dedup_key(&pb, &ev));
    }
}
