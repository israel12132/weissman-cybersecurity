//! **First-Mover Surface Delta** — find new internet-facing assets before weekly scanners.
//!
//! Continuous ASM products inventory hosts. This engine diffs the *live* DNS/HTTP
//! surface against the last persisted snapshot for the same client, then probes
//! only what appeared or changed. Findings are evidence-gated:
//! dangling CNAME / takeover signatures / new HTTP exposure / A-record flips.
//!
//! First run establishes a baseline (info). No previous snapshot → no invented vulns.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    dns_a, dns_cname, empty_ok, extract_host, finding, http_client, http_get,
};
use crate::engine_result::EngineResult;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};

pub const ENGINE_ID: &str = "first_mover_surface_delta";
const MITRE: &str = "T1595";
/// Web engines fired on each *added* FQDN (enqueue from first-mover, inline from delta fusion).
pub const DELTA_FOLLOW_ON_ENGINES: &[&str] = &[
    "subdomain_takeover",
    "leak_hunter",
    "bola_idor",
    "jwt_attack",
];
const MAX_CHAIN_HOSTS: usize = 6;
const MAX_DISCOVERY: usize = 40;
const MAX_TOTAL_HOSTS: usize = 80;
const MAX_NEW_HTTP: usize = 20;
const MAX_WATCH_HTTP: usize = 10;
const PROBE_CONCURRENCY: usize = 16;
const SNAPSHOT_KEEP: i64 = 20;

const TAKEOVER_SIGNATURES: &[(&str, &str)] = &[
    ("there isn't a github pages site here", "GitHub Pages"),
    ("nosuchbucket", "AWS S3"),
    ("the specified bucket does not exist", "AWS S3"),
    ("heroku | no such app", "Heroku"),
    ("project not found", "Vercel"),
    ("repository not found", "GitHub Pages"),
    ("no such app", "Heroku"),
    ("fastly error: unknown domain", "Fastly"),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SurfaceAsset {
    pub fqdn: String,
    #[serde(default)]
    pub a: Vec<String>,
    #[serde(default)]
    pub cname: Option<String>,
    #[serde(default)]
    pub http_status: Option<u16>,
    #[serde(default)]
    pub http_server: Option<String>,
    #[serde(default)]
    pub takeover_vendor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SurfaceSnapshot {
    pub apex: String,
    pub assets: Vec<SurfaceAsset>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetDeltaKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetDelta {
    pub kind: AssetDeltaKind,
    pub fqdn: String,
    pub previous: Option<SurfaceAsset>,
    pub current: Option<SurfaceAsset>,
    pub evidence: String,
}

fn pbool(params: &Value, key: &str, default: bool) -> bool {
    params
        .get(key)
        .and_then(|v| {
            v.as_bool()
                .or_else(|| v.as_str().map(|s| s == "true" || s == "1"))
        })
        .unwrap_or(default)
}

/// True when `fqdn` is the authorized apex or a subdomain of it (RoE).
#[must_use]
pub fn in_authorized_scope(apex: &str, fqdn: &str) -> bool {
    let apex = apex.trim().trim_end_matches('.').to_ascii_lowercase();
    let fqdn = fqdn.trim().trim_end_matches('.').to_ascii_lowercase();
    if apex.is_empty() || fqdn.is_empty() {
        return false;
    }
    fqdn == apex || fqdn.ends_with(&format!(".{apex}"))
}

#[must_use]
pub fn diff_assets(previous: &[SurfaceAsset], current: &[SurfaceAsset]) -> Vec<AssetDelta> {
    let prev_map: BTreeMap<&str, &SurfaceAsset> =
        previous.iter().map(|a| (a.fqdn.as_str(), a)).collect();
    let cur_map: BTreeMap<&str, &SurfaceAsset> =
        current.iter().map(|a| (a.fqdn.as_str(), a)).collect();
    let mut keys: BTreeSet<&str> = BTreeSet::new();
    keys.extend(prev_map.keys().copied());
    keys.extend(cur_map.keys().copied());
    let mut out = Vec::new();
    for k in keys {
        match (prev_map.get(k), cur_map.get(k)) {
            (None, Some(cur)) => out.push(AssetDelta {
                kind: AssetDeltaKind::Added,
                fqdn: k.to_string(),
                previous: None,
                current: Some((*cur).clone()),
                evidence: format!(
                    "new host {k} A={:?} CNAME={:?} HTTP={:?}",
                    cur.a, cur.cname, cur.http_status
                ),
            }),
            (Some(prev), None) => out.push(AssetDelta {
                kind: AssetDeltaKind::Removed,
                fqdn: k.to_string(),
                previous: Some((*prev).clone()),
                current: None,
                evidence: format!(
                    "host {k} disappeared (was A={:?} CNAME={:?})",
                    prev.a, prev.cname
                ),
            }),
            (Some(prev), Some(cur)) => {
                if prev.a != cur.a || prev.cname != cur.cname || prev.http_status != cur.http_status
                {
                    out.push(AssetDelta {
                        kind: AssetDeltaKind::Changed,
                        fqdn: k.to_string(),
                        previous: Some((*prev).clone()),
                        current: Some((*cur).clone()),
                        evidence: format!(
                            "host {k} changed A {:?}→{:?} CNAME {:?}→{:?} HTTP {:?}→{:?}",
                            prev.a, cur.a, prev.cname, cur.cname, prev.http_status, cur.http_status
                        ),
                    });
                }
            }
            (None, None) => {}
        }
    }
    out
}

fn live_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    proof: &str,
    category: &str,
) -> Value {
    let mut f = finding(ENGINE_ID, title, severity, MITRE, description, target);
    if let Some(obj) = f.as_object_mut() {
        obj.insert(
            "evidence".into(),
            json!({
                "proof": proof,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "engine_id": ENGINE_ID,
                "method": "dns+http+snapshot-diff",
            }),
        );
        obj.insert("proof".into(), json!(proof));
        obj.insert("category".into(), json!(category));
        obj.insert("asset".into(), json!("first_mover"));
        obj.insert("value".into(), json!(target));
    }
    f
}

fn takeover_vendor_from_body(body: &str) -> Option<&'static str> {
    let low = body.to_ascii_lowercase();
    TAKEOVER_SIGNATURES
        .iter()
        .find(|(sig, _)| low.contains(sig))
        .map(|(_, vendor)| *vendor)
}

async fn probe_host(fqdn: &str, include_http: bool) -> SurfaceAsset {
    let mut asset = SurfaceAsset {
        fqdn: fqdn.trim_end_matches('.').to_ascii_lowercase(),
        ..SurfaceAsset::default()
    };
    let mut a = dns_a(&asset.fqdn).await;
    a.sort();
    a.dedup();
    asset.a = a;
    let cnames = dns_cname(&asset.fqdn).await;
    asset.cname = cnames.into_iter().next();

    if include_http {
        let client = http_client().await;
        let url = format!("https://{}", asset.fqdn);
        if let Some(p) = http_get(&client, &url).await {
            asset.http_status = Some(p.status);
            asset.http_server = p
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                .map(|(_, v)| v.clone());
            asset.takeover_vendor = takeover_vendor_from_body(&p.body).map(str::to_string);
        } else {
            let http_url = format!("http://{}", asset.fqdn);
            if let Some(p) = http_get(&client, &http_url).await {
                asset.http_status = Some(p.status);
                asset.http_server = p
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                    .map(|(_, v)| v.clone());
                asset.takeover_vendor = takeover_vendor_from_body(&p.body).map(str::to_string);
            }
        }
    }
    asset
}

async fn crt_sh_names(apex: &str) -> Vec<String> {
    let client = http_client().await;
    let url = format!("https://crt.sh/?q={}&output=json", apex);
    let Some(probe) = http_get(&client, &url).await else {
        return vec![];
    };
    if probe.status != 200 {
        return vec![];
    }
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&probe.body) else {
        return vec![];
    };
    let mut names = BTreeSet::new();
    for row in arr.iter().take(80) {
        if let Some(nv) = row.get("name_value").and_then(Value::as_str) {
            for part in nv.split(['\n', ',']) {
                let n = part
                    .trim()
                    .trim_start_matches("*.")
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if in_authorized_scope(apex, &n) {
                    names.insert(n);
                }
            }
        }
        if names.len() >= MAX_DISCOVERY {
            break;
        }
    }
    names.into_iter().collect()
}

#[must_use]
pub(crate) fn extra_hosts_from_params(params: &Value) -> Vec<String> {
    match params.get("extra_hosts") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Some(Value::String(s)) => s
            .split([',', ' ', '\n'])
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn merge_host_list(
    apex: &str,
    ct: Vec<String>,
    previous: &[SurfaceAsset],
    extra: &[String],
) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    fn push(raw: &str, apex: &str, seen: &mut BTreeSet<String>, out: &mut Vec<String>) {
        let h = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() || !in_authorized_scope(apex, &h) {
            return;
        }
        if seen.insert(h.clone()) {
            out.push(h);
        }
    }
    push(apex, apex, &mut seen, &mut out);
    push(&format!("www.{apex}"), apex, &mut seen, &mut out);
    // Certstream / operator-pushed names first so they win the HTTP budget.
    for n in extra {
        push(n, apex, &mut seen, &mut out);
    }
    // Always re-probe the last snapshot so missing crt.sh rows are not false removals.
    for a in previous {
        push(&a.fqdn, apex, &mut seen, &mut out);
    }
    let room = MAX_TOTAL_HOSTS.saturating_sub(out.len()).min(MAX_DISCOVERY);
    for n in ct.into_iter().take(room) {
        if out.len() >= MAX_TOTAL_HOSTS {
            break;
        }
        push(&n, apex, &mut seen, &mut out);
    }
    out
}

/// Decide which selected hosts get an HTTP GET. Budget is assigned in list order
/// (new hosts first via `merge_host_list`) so concurrency cannot steal the cap.
#[must_use]
fn plan_host_probes(
    selected: &[String],
    include_http: bool,
    prev_all: &BTreeSet<&str>,
    prev_watch: &BTreeSet<&str>,
) -> Vec<(String, bool)> {
    let mut http_new = 0usize;
    let mut http_watch = 0usize;
    selected
        .iter()
        .map(|host| {
            let known = prev_all.contains(host.as_str());
            let want_http = if !include_http {
                false
            } else if !known && http_new < MAX_NEW_HTTP {
                http_new += 1;
                true
            } else if known && prev_watch.contains(host.as_str()) && http_watch < MAX_WATCH_HTTP {
                http_watch += 1;
                true
            } else {
                false
            };
            (host.clone(), want_http)
        })
        .collect()
}

async fn enumerate_live(
    apex: &str,
    include_ct: bool,
    include_http: bool,
    previous: Option<&SurfaceSnapshot>,
    extra: &[String],
) -> SurfaceSnapshot {
    let ct = if include_ct {
        crt_sh_names(apex).await
    } else {
        vec![]
    };
    let prev_assets = previous.map(|p| p.assets.as_slice()).unwrap_or(&[]);
    let selected = merge_host_list(apex, ct, prev_assets, extra);
    let prev_watch: BTreeSet<&str> = prev_assets
        .iter()
        .filter(|a| a.cname.is_some() || a.a.is_empty() || a.http_status.is_some())
        .map(|a| a.fqdn.as_str())
        .collect();
    let prev_all: BTreeSet<&str> = prev_assets.iter().map(|a| a.fqdn.as_str()).collect();
    let jobs = plan_host_probes(&selected, include_http, &prev_all, &prev_watch);
    let assets: Vec<SurfaceAsset> = stream::iter(jobs)
        .map(|(host, want_http)| async move { probe_host(&host, want_http).await })
        .buffered(PROBE_CONCURRENCY)
        .collect()
        .await;
    SurfaceSnapshot {
        apex: apex.to_string(),
        assets,
    }
}

fn findings_from_delta(apex: &str, deltas: &[AssetDelta], baseline: bool) -> Vec<Value> {
    let mut out = Vec::new();
    if baseline {
        out.push(live_finding(
            &format!("First-mover baseline established for {apex}"),
            "info",
            &format!(
                "Live DNS/HTTP snapshot stored ({} assets). The next scan diffs against this baseline — no vulnerability claimed on first sight."
            , deltas.len()),
            apex,
            &format!("baseline asset count={}", deltas.len()),
            "baseline",
        ));
        return out;
    }

    let added = deltas
        .iter()
        .filter(|d| d.kind == AssetDeltaKind::Added)
        .count();
    let removed = deltas
        .iter()
        .filter(|d| d.kind == AssetDeltaKind::Removed)
        .count();
    let changed = deltas
        .iter()
        .filter(|d| d.kind == AssetDeltaKind::Changed)
        .count();

    if added + removed + changed == 0 {
        out.push(live_finding(
            &format!("No attack-surface drift on {apex}"),
            "info",
            "Live DNS/HTTP matches the previous snapshot for this client.",
            apex,
            "diff empty — current snapshot equals previous",
            "stable",
        ));
        return out;
    }

    out.push(live_finding(
        &format!("Attack-surface drift on {apex}: +{added} / -{removed} / Δ{changed}"),
        if added > 0 || changed > 0 {
            "medium"
        } else {
            "info"
        },
        "First-mover delta versus last persisted snapshot. Investigate new and changed hosts before they appear in weekly scanners.",
        apex,
        &format!("added={added} removed={removed} changed={changed}"),
        "summary",
    ));

    for d in deltas {
        match d.kind {
            AssetDeltaKind::Added => {
                let cur = d.current.as_ref();
                let dangling = cur
                    .map(|c| c.cname.is_some() && c.a.is_empty())
                    .unwrap_or(false);
                let vendor = cur.and_then(|c| c.takeover_vendor.as_deref());
                let (sev, title) = if let Some(v) = vendor {
                    (
                        "critical",
                        format!("New host {} matches {v} takeover signature", d.fqdn),
                    )
                } else if dangling {
                    ("high", format!("New dangling CNAME on {}", d.fqdn))
                } else if cur.and_then(|c| c.http_status).unwrap_or(0) > 0 {
                    ("medium", format!("New internet-facing host {}", d.fqdn))
                } else {
                    ("low", format!("New DNS name {}", d.fqdn))
                };
                out.push(live_finding(
                    &title,
                    sev,
                    &d.evidence,
                    &d.fqdn,
                    &d.evidence,
                    "added",
                ));
            }
            AssetDeltaKind::Changed => {
                out.push(live_finding(
                    &format!("DNS/HTTP change on {}", d.fqdn),
                    "high",
                    &d.evidence,
                    &d.fqdn,
                    &d.evidence,
                    "changed",
                ));
            }
            AssetDeltaKind::Removed => {
                out.push(live_finding(
                    &format!("Host disappeared: {}", d.fqdn),
                    "info",
                    &d.evidence,
                    &d.fqdn,
                    &d.evidence,
                    "removed",
                ));
            }
        }
    }
    out
}

async fn load_previous_snapshot(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Option<SurfaceSnapshot>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT snapshot_json FROM surface_snapshots
           WHERE tenant_id = $1 AND client_id = $2
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    let Some(row) = row else {
        return Ok(None);
    };
    let raw: Value = row.try_get("snapshot_json").map_err(|e| e.to_string())?;
    serde_json::from_value(raw)
        .map(Some)
        .map_err(|e| e.to_string())
}

async fn persist_snapshot(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    snap: &SurfaceSnapshot,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let payload = serde_json::to_value(snap).map_err(|e| e.to_string())?;
    sqlx::query(
        r#"INSERT INTO surface_snapshots (tenant_id, client_id, snapshot_json, asset_count)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&payload)
    .bind(snap.assets.len() as i32)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"WITH ranked AS (
             SELECT id,
                    row_number() OVER (ORDER BY created_at DESC) AS rn
               FROM surface_snapshots
              WHERE tenant_id = $1 AND client_id = $2
           )
           DELETE FROM surface_snapshots
            WHERE tenant_id = $1 AND client_id = $2
              AND id IN (SELECT id FROM ranked WHERE rn > $3)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(SNAPSHOT_KEEP)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Hosts that receive the immediate BOLA/JWT/takeover/leak kill-chain.
/// Baseline snapshots do not chain the whole surface — only Certstream `extra_hosts`
/// (a newly issued name is new even if this is the client's first snapshot).
#[must_use]
pub fn hosts_for_follow_on(
    apex: &str,
    deltas: &[AssetDelta],
    baseline: bool,
    extra: &[String],
) -> Vec<String> {
    let extra: Vec<String> = extra
        .iter()
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty() && h.contains('.') && in_authorized_scope(apex, h))
        .collect();
    if baseline {
        return extra;
    }
    let mut added: Vec<String> = deltas
        .iter()
        .filter(|d| d.kind == AssetDeltaKind::Added)
        .map(|d| d.fqdn.clone())
        .collect();
    for h in extra {
        if !added.iter().any(|x| x == &h) {
            added.push(h);
        }
    }
    added
}

#[must_use]
pub fn follow_on_payloads(client_id: i64, added_fqdns: &[String]) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for host in added_fqdns.iter().take(MAX_CHAIN_HOSTS) {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() || !h.contains('.') {
            continue;
        }
        for eng in DELTA_FOLLOW_ON_ENGINES {
            out.push((
                (*eng).to_string(),
                json!({
                    "engine": *eng,
                    "target": format!("https://{h}"),
                    "client_id": client_id,
                    "trigger": "first_mover_delta",
                    "parent_fqdn": h,
                    "chain_web_engines": false,
                }),
            ));
        }
    }
    out
}

async fn enqueue_delta_follow_ons(
    ctx: &EngineRunContext,
    apex: &str,
    deltas: &[AssetDelta],
    baseline: bool,
) {
    if !pbool(&ctx.job_params, "chain_web_engines", true) {
        return;
    }
    let (Some(pool), Some(tid), Some(cid)) = (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id)
    else {
        return;
    };
    let extra = extra_hosts_from_params(&ctx.job_params);
    let added = hosts_for_follow_on(apex, deltas, baseline, &extra);
    if added.is_empty() {
        return;
    }
    for (_eng, payload) in follow_on_payloads(cid, &added) {
        if let Err(e) =
            crate::async_jobs::enqueue(pool.as_ref(), tid, "command_center_engine", payload, None)
                .await
        {
            tracing::warn!(target: "first_mover", error = %e, "delta follow-on enqueue failed");
        }
    }
}

/// Live JSON for GET /api/clients/:id/surface-diff (no new probes).
/// Read failures use [`surface_diff_unavailable_json`] (HTTP 200) so `apiFetch` does not throw.
#[must_use]
pub fn surface_diff_unavailable_json(client_id: i64) -> Value {
    json!({
        "client_id": client_id,
        "unavailable": true,
        "message": "surface diff temporarily unavailable",
        "added": [],
        "removed": [],
        "changed": [],
        "current_count": 0,
        "previous_count": 0,
        "current_at": Value::Null,
        "previous_at": Value::Null,
        "baseline_only": false,
    })
}

pub async fn api_surface_diff_json(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT id, snapshot_json, asset_count, created_at
           FROM surface_snapshots
           WHERE tenant_id = $1 AND client_id = $2
           ORDER BY created_at DESC
           LIMIT 2"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    if rows.is_empty() {
        return Ok(json!({
            "client_id": client_id,
            "unavailable": false,
            "message": "No first-mover snapshot yet — run first_mover_surface_delta against an authorized domain.",
            "added": [],
            "removed": [],
            "changed": [],
            "current_count": 0,
            "previous_count": 0,
            "current_at": Value::Null,
            "previous_at": Value::Null,
            "baseline_only": false,
        }));
    }

    let current_json: Value = rows[0]
        .try_get("snapshot_json")
        .map_err(|e| e.to_string())?;
    let current: SurfaceSnapshot = serde_json::from_value(current_json.clone()).unwrap_or_default();
    let current_at: chrono::DateTime<chrono::Utc> = rows[0]
        .try_get("created_at")
        .unwrap_or_else(|_| chrono::Utc::now());
    let current_count: i32 = rows[0].try_get("asset_count").unwrap_or(0);

    let (previous, previous_at, previous_count, deltas) = if rows.len() > 1 {
        let prev_json: Value = rows[1]
            .try_get("snapshot_json")
            .map_err(|e| e.to_string())?;
        let prev: SurfaceSnapshot = serde_json::from_value(prev_json).unwrap_or_default();
        let prev_at: chrono::DateTime<chrono::Utc> = rows[1]
            .try_get("created_at")
            .unwrap_or_else(|_| chrono::Utc::now());
        let prev_count: i32 = rows[1].try_get("asset_count").unwrap_or(0);
        let deltas = diff_assets(&prev.assets, &current.assets);
        (Some(prev), Some(prev_at), prev_count, deltas)
    } else {
        (None, None, 0, vec![])
    };

    let added: Vec<Value> = deltas
        .iter()
        .filter(|d| d.kind == AssetDeltaKind::Added)
        .map(|d| json!({"fqdn": d.fqdn, "evidence": d.evidence, "current": d.current}))
        .collect();
    let removed: Vec<Value> = deltas
        .iter()
        .filter(|d| d.kind == AssetDeltaKind::Removed)
        .map(|d| json!({"fqdn": d.fqdn, "evidence": d.evidence, "previous": d.previous}))
        .collect();
    let changed: Vec<Value> = deltas
        .iter()
        .filter(|d| d.kind == AssetDeltaKind::Changed)
        .map(|d| {
            json!({
                "fqdn": d.fqdn,
                "evidence": d.evidence,
                "previous": d.previous,
                "current": d.current
            })
        })
        .collect();

    Ok(json!({
        "client_id": client_id,
        "unavailable": false,
        "apex": current.apex,
        "message": if previous.is_none() {
            "Baseline only — next hunt will emit drift."
        } else {
            "Live snapshot diff versus previous first-mover run."
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "current_count": current_count,
        "previous_count": previous_count,
        "current_at": current_at.to_rfc3339(),
        "previous_at": previous_at.map(|t| t.to_rfc3339()),
        "baseline_only": previous.is_none(),
    }))
}

pub async fn run_first_mover_surface_delta_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let apex = extract_host(target)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if apex.is_empty() {
        return EngineResult::error("could not extract host from target");
    }

    let include_ct = pbool(&ctx.job_params, "include_ct", true);
    let include_http = pbool(&ctx.job_params, "include_http", true);
    let extra = extra_hosts_from_params(&ctx.job_params);

    let previous = match (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id) {
        (Some(pool), Some(tid), Some(cid)) => match load_previous_snapshot(pool, tid, cid).await {
            Ok(p) => p,
            Err(e) => {
                return EngineResult::error(format!("surface snapshot read failed: {e}"));
            }
        },
        _ => None,
    };

    let current = enumerate_live(&apex, include_ct, include_http, previous.as_ref(), &extra).await;
    if current.assets.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let (deltas, baseline) = match &previous {
        None => {
            let synthetic: Vec<AssetDelta> = current
                .assets
                .iter()
                .map(|a| AssetDelta {
                    kind: AssetDeltaKind::Added,
                    fqdn: a.fqdn.clone(),
                    previous: None,
                    current: Some(a.clone()),
                    evidence: format!("baseline {}", a.fqdn),
                })
                .collect();
            (synthetic, true)
        }
        Some(prev) => (diff_assets(&prev.assets, &current.assets), false),
    };

    if let (Some(pool), Some(tid), Some(cid)) =
        (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id)
    {
        if let Err(e) = persist_snapshot(pool, tid, cid, &current).await {
            return EngineResult::error(format!("surface snapshot persist failed: {e}"));
        }
    }

    let findings = findings_from_delta(&apex, &deltas, baseline);
    enqueue_delta_follow_ons(ctx, &apex, &deltas, baseline).await;
    if findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    EngineResult::ok(
        findings,
        format!(
            "{ENGINE_ID}: {} live assets, baseline={baseline}",
            current.assets.len()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_rejects_out_of_domain() {
        assert!(in_authorized_scope("example.com", "example.com"));
        assert!(in_authorized_scope("example.com", "api.example.com"));
        assert!(!in_authorized_scope("example.com", "example.com.evil.test"));
        assert!(!in_authorized_scope("example.com", "notexample.com"));
        assert!(!in_authorized_scope("", "example.com"));
    }

    #[test]
    fn diff_detects_added_removed_and_ip_flip() {
        let prev = vec![
            SurfaceAsset {
                fqdn: "www.example.com".into(),
                a: vec!["1.1.1.1".into()],
                ..SurfaceAsset::default()
            },
            SurfaceAsset {
                fqdn: "gone.example.com".into(),
                a: vec!["9.9.9.9".into()],
                ..SurfaceAsset::default()
            },
        ];
        let cur = vec![
            SurfaceAsset {
                fqdn: "www.example.com".into(),
                a: vec!["8.8.8.8".into()],
                ..SurfaceAsset::default()
            },
            SurfaceAsset {
                fqdn: "new.example.com".into(),
                cname: Some("unclaimed.github.io".into()),
                ..SurfaceAsset::default()
            },
        ];
        let d = diff_assets(&prev, &cur);
        assert_eq!(d.len(), 3);
        assert!(d
            .iter()
            .any(|x| x.kind == AssetDeltaKind::Added && x.fqdn == "new.example.com"));
        assert!(d
            .iter()
            .any(|x| x.kind == AssetDeltaKind::Removed && x.fqdn == "gone.example.com"));
        assert!(d.iter().any(|x| x.kind == AssetDeltaKind::Changed
            && x.fqdn == "www.example.com"
            && x.evidence.contains("1.1.1.1")
            && x.evidence.contains("8.8.8.8")));
    }

    #[test]
    fn findings_baseline_are_info_only() {
        let deltas = vec![AssetDelta {
            kind: AssetDeltaKind::Added,
            fqdn: "example.com".into(),
            previous: None,
            current: Some(SurfaceAsset {
                fqdn: "example.com".into(),
                a: vec!["1.2.3.4".into()],
                ..SurfaceAsset::default()
            }),
            evidence: "baseline".into(),
        }];
        let f = findings_from_delta("example.com", &deltas, true);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0]["severity"], "info");
        assert!(f[0]["title"].as_str().unwrap().contains("baseline"));
    }

    #[test]
    fn merge_keeps_previous_hosts_even_without_ct() {
        let prev = vec![SurfaceAsset {
            fqdn: "shop.example.com".into(),
            a: vec!["1.1.1.1".into()],
            ..SurfaceAsset::default()
        }];
        let merged = merge_host_list("example.com", vec![], &prev, &[]);
        assert!(merged.contains(&"example.com".into()));
        assert!(merged.contains(&"www.example.com".into()));
        assert!(merged.contains(&"shop.example.com".into()));
        assert!(!merged.iter().any(|h| h.ends_with("evil.test")));
    }

    #[test]
    fn dangling_new_host_is_high() {
        let deltas = vec![AssetDelta {
            kind: AssetDeltaKind::Added,
            fqdn: "shop.example.com".into(),
            previous: None,
            current: Some(SurfaceAsset {
                fqdn: "shop.example.com".into(),
                cname: Some("unclaimed.github.io".into()),
                a: vec![],
                ..SurfaceAsset::default()
            }),
            evidence:
                "new host shop.example.com A=[] CNAME=Some(\"unclaimed.github.io\") HTTP=None"
                    .into(),
        }];
        let f = findings_from_delta("example.com", &deltas, false);
        assert!(f
            .iter()
            .any(|x| x["severity"] == "high" && x["title"].as_str().unwrap().contains("dangling")));
    }

    #[test]
    fn extra_hosts_win_scope_and_merge() {
        let extra =
            extra_hosts_from_params(&json!({"extra_hosts": ["api.example.com", "evil.test"]}));
        assert_eq!(extra, vec!["api.example.com", "evil.test"]);
        let merged = merge_host_list("example.com", vec![], &[], &extra);
        assert!(merged.contains(&"api.example.com".into()));
        assert!(!merged.iter().any(|h| h == "evil.test"));
    }

    #[test]
    fn baseline_chains_only_certstream_extra_hosts() {
        let deltas = vec![AssetDelta {
            kind: AssetDeltaKind::Added,
            fqdn: "www.example.com".into(),
            previous: None,
            current: None,
            evidence: "baseline".into(),
        }];
        let extra = vec!["api.example.com".into(), "evil.test".into()];
        let h = hosts_for_follow_on("example.com", &deltas, true, &extra);
        assert_eq!(h, vec!["api.example.com"]);
        assert!(hosts_for_follow_on("example.com", &deltas, true, &[]).is_empty());
    }

    #[test]
    fn drift_chains_added_plus_in_scope_extra() {
        let deltas = vec![AssetDelta {
            kind: AssetDeltaKind::Added,
            fqdn: "shop.example.com".into(),
            previous: None,
            current: None,
            evidence: "new".into(),
        }];
        let extra = vec!["api.example.com".into()];
        let h = hosts_for_follow_on("example.com", &deltas, false, &extra);
        assert_eq!(h, vec!["shop.example.com", "api.example.com"]);
    }

    #[test]
    fn follow_on_payloads_cover_kill_chain_per_host() {
        let p = follow_on_payloads(7, &["shop.acme.test".into()]);
        assert_eq!(p.len(), DELTA_FOLLOW_ON_ENGINES.len());
        assert!(p.iter().all(|(_, v)| v["client_id"] == 7));
        assert!(p
            .iter()
            .all(|(_, v)| v["target"] == "https://shop.acme.test"));
        assert!(p.iter().any(|(e, _)| e == "bola_idor"));
        assert!(p.iter().any(|(e, _)| e == "jwt_attack"));
    }

    #[test]
    fn http_probe_plan_caps_new_and_watch() {
        let selected: Vec<String> = (0..25).map(|i| format!("n{i}.example.com")).collect();
        let prev_all = BTreeSet::new();
        let prev_watch = BTreeSet::new();
        let plan = plan_host_probes(&selected, true, &prev_all, &prev_watch);
        assert_eq!(plan.iter().filter(|(_, http)| *http).count(), MAX_NEW_HTTP);
        let off = plan_host_probes(&selected, false, &prev_all, &prev_watch);
        assert!(off.iter().all(|(_, http)| !*http));
    }

    #[test]
    fn unavailable_surface_diff_is_stable_schema() {
        let v = surface_diff_unavailable_json(42);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["client_id"], 42);
        assert_eq!(v["added"], json!([]));
        assert_eq!(v["removed"], json!([]));
        assert_eq!(v["changed"], json!([]));
        assert_eq!(v["current_count"], 0);
    }
}
